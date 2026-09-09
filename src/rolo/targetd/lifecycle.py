"""Durable, fail-closed lifecycle primitives for targetd workers.

This module deliberately separates *requesting* an interrupt from proving
that a worker stopped.  A controller can request CANCEL/STOP for one exact
call identity, but only the worker holding the live lease token can append the
acknowledgement that terminalizes the call.  Expired or orphaned leases become
``UNKNOWN`` and are never reclaimed automatically, because the previous
worker may already have crossed a provider side-effect boundary.

``LeasedWorkerRuntime`` is a small offline/in-process integration harness.  It
runs work on a dedicated daemon thread so the supervisor can exercise the
state machine and cooperative interrupt path.  It is not an OS-process safety
boundary and is intentionally not wired into the production stdio daemon yet.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, model_validator

from rolo.core.hashing import canonical_json_sha256
from rolo.core.persistence import atomic_write_text, interprocess_lock
from rolo.dsl.parser import loads_unique_json

from .protocol import ExecutionRequestLike, ProtocolError, validate_execution_request

_IDENTIFIER = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"
_SHA256 = r"^[0-9a-f]{64}$"
_TOKEN = re.compile(r"^[A-Za-z0-9_-]{22,128}$")
_OUTCOME_CODE = re.compile(r"^[A-Z][A-Z0-9_]{0,127}$")
_MAX_INTERRUPT_ACK_S = 15.0
MAX_WORKER_LEASES = 2_048
MAX_WORKER_LEASE_STATE_BYTES = 4_194_304
MAX_WORKER_PREPARED_RESULT_BYTES = 65_536

WorkerLeaseState = Literal[
    "CLAIMED",
    "RUNNING",
    "CANCEL_REQUESTED",
    "STOP_REQUESTED",
    "CANCELLED",
    "STOPPED",
    "SUCCEEDED",
    "FAILED",
    "UNKNOWN",
]
WorkerInterruptIntent = Literal["CANCEL", "STOP"]
WorkerTerminalStatus = Literal["CANCELLED", "STOPPED", "SUCCEEDED", "FAILED", "UNKNOWN"]
WorkerPreparedStatus = Literal["CANCELLED", "STOPPED", "SUCCEEDED", "FAILED"]

_ACTIVE_STATES = frozenset({"CLAIMED", "RUNNING", "CANCEL_REQUESTED", "STOP_REQUESTED"})
_INTERRUPT_STATES = frozenset({"CANCEL_REQUESTED", "STOP_REQUESTED"})
_TERMINAL_STATES = frozenset({"CANCELLED", "STOPPED", "SUCCEEDED", "FAILED", "UNKNOWN"})


class WorkerLifecycleError(ProtocolError):
    """A stable, non-secret lifecycle error code."""


class WorkerCallKey(BaseModel):
    """The complete identity required to address one targetd invocation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    target_id: str = Field(pattern=_IDENTIFIER)
    session_id: str = Field(pattern=_IDENTIFIER)
    idempotency_key: str = Field(pattern=_IDENTIFIER)
    request_digest: str = Field(pattern=_SHA256)

    @classmethod
    def from_request(cls, request: ExecutionRequestLike) -> WorkerCallKey:
        request = validate_execution_request(request)
        return cls(
            target_id=request.target_id,
            session_id=request.session_id,
            idempotency_key=request.idempotency_key,
            request_digest=request.request_digest(),
        )

    def digest(self) -> str:
        return canonical_json_sha256(
            {
                "schema_version": "rolo-targetd-worker-call-key/v1",
                **self.model_dump(mode="json"),
            }
        )


class WorkerStopAcknowledgement(BaseModel):
    """Proof that one exact interrupt reached a safe boundary.

    ``WORKER_CONFIRMED`` is worker-authored. ``NOT_STARTED`` is a supervisor
    acknowledgement that the provider boundary was never crossed.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["rolo-targetd-worker-stop-ack/v1"]
    call_key: WorkerCallKey
    call_key_digest: str = Field(pattern=_SHA256)
    intent: WorkerInterruptIntent
    worker_id: str = Field(pattern=_IDENTIFIER)
    generation: int = Field(ge=1)
    disposition: Literal["NOT_STARTED", "WORKER_CONFIRMED"]
    outcome_code: str
    acknowledged_at: datetime

    @model_validator(mode="after")
    def validate_acknowledgement(self) -> WorkerStopAcknowledgement:
        _require_aware(self.acknowledged_at, "stop acknowledgement")
        _require_outcome_code(self.outcome_code)
        if self.call_key_digest != self.call_key.digest():
            raise ValueError("worker stop acknowledgement call key digest mismatch")
        return self


class WorkerLeaseRecord(BaseModel):
    """Persisted lease state; the bearer token itself is never persisted."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["rolo-targetd-worker-lease/v1"]
    call_key: WorkerCallKey
    call_key_digest: str = Field(pattern=_SHA256)
    supervisor_id: str = Field(pattern=_IDENTIFIER)
    worker_id: str = Field(pattern=_IDENTIFIER)
    generation: int = Field(ge=1)
    lease_token_digest: str = Field(pattern=_SHA256)
    lease_ttl_s: float = Field(ge=0.1, le=300.0)
    state: WorkerLeaseState
    claimed_at: datetime
    heartbeat_at: datetime
    expires_at: datetime
    deadline_at: datetime | None = None
    provider_started_at: datetime | None = None
    interrupt_requested_at: datetime | None = None
    finished_at: datetime | None = None
    heartbeat_count: int = Field(default=0, ge=0)
    outcome_code: str | None = None
    stop_acknowledgement: WorkerStopAcknowledgement | None = None
    prepared_status: WorkerPreparedStatus | None = None
    prepared_outcome_code: str | None = None
    prepared_result: dict[str, object] | None = None
    prepared_result_digest: str | None = Field(default=None, pattern=_SHA256)
    result_prepared_at: datetime | None = None
    result_committed_at: datetime | None = None
    armed_zero: dict[str, object] | None = None
    armed_zero_digest: str | None = Field(default=None, pattern=_SHA256)
    armed_at: datetime | None = None
    physical_execution_subject_digest: str | None = Field(
        default=None,
        pattern=r"^sha256:[0-9a-f]{64}$",
    )
    physical_runtime_sha256: str | None = Field(default=None, pattern=_SHA256)

    @model_validator(mode="after")
    def validate_record(self) -> WorkerLeaseRecord:
        for name in (
            "claimed_at",
            "heartbeat_at",
            "expires_at",
            "deadline_at",
            "provider_started_at",
            "interrupt_requested_at",
            "finished_at",
            "result_prepared_at",
            "result_committed_at",
            "armed_at",
        ):
            value = getattr(self, name)
            if value is not None:
                _require_aware(value, f"worker lease {name}")
        if self.call_key_digest != self.call_key.digest():
            raise ValueError("worker lease call key digest mismatch")
        if self.heartbeat_at < self.claimed_at or self.expires_at <= self.heartbeat_at:
            raise ValueError("worker lease timing is invalid")
        if self.deadline_at is not None:
            if self.deadline_at <= self.claimed_at or self.expires_at > self.deadline_at:
                raise ValueError("worker lease deadline is invalid")
        if self.provider_started_at is not None and self.provider_started_at < self.claimed_at:
            raise ValueError("worker provider start precedes lease claim")
        if self.interrupt_requested_at is not None and self.interrupt_requested_at < self.claimed_at:
            raise ValueError("worker interrupt precedes lease claim")
        if self.finished_at is not None and self.finished_at < self.claimed_at:
            raise ValueError("worker finish precedes lease claim")

        if self.state == "CLAIMED" and self.provider_started_at is not None:
            raise ValueError("claimed worker lease cannot have a provider start")
        if self.state in {"RUNNING", "CANCEL_REQUESTED", "STOP_REQUESTED", "SUCCEEDED", "FAILED"}:
            if self.provider_started_at is None:
                raise ValueError("worker lease state requires a provider start")
        if self.state in _INTERRUPT_STATES and self.interrupt_requested_at is None:
            raise ValueError("worker interrupt state requires a request timestamp")
        if self.state in _ACTIVE_STATES and self.finished_at is not None:
            raise ValueError("active worker lease cannot have a finish timestamp")
        if self.state in _TERMINAL_STATES:
            if self.finished_at is None or self.outcome_code is None:
                raise ValueError("terminal worker lease requires outcome and finish")
            _require_outcome_code(self.outcome_code)
        elif self.outcome_code is not None:
            raise ValueError("active worker lease cannot have a terminal outcome")

        if self.state in {"CANCELLED", "STOPPED"}:
            if self.stop_acknowledgement is None:
                raise ValueError("interrupt terminal state requires a stop acknowledgement")
            expected_intent = "CANCEL" if self.state == "CANCELLED" else "STOP"
            if (
                self.stop_acknowledgement.intent != expected_intent
                or self.stop_acknowledgement.call_key != self.call_key
                or self.stop_acknowledgement.call_key_digest != self.call_key_digest
                or self.stop_acknowledgement.worker_id != self.worker_id
                or self.stop_acknowledgement.generation != self.generation
                or self.stop_acknowledgement.outcome_code != self.outcome_code
                or self.stop_acknowledgement.acknowledged_at != self.finished_at
            ):
                raise ValueError("worker stop acknowledgement identity mismatch")
            if self.interrupt_requested_at is None:
                raise ValueError("interrupt terminal state requires a request timestamp")
            if self.stop_acknowledgement.acknowledged_at < self.interrupt_requested_at:
                raise ValueError("worker stop acknowledgement precedes interrupt request")
            if self.stop_acknowledgement.disposition == "NOT_STARTED" and self.provider_started_at is not None:
                raise ValueError("not-started acknowledgement cannot follow provider start")
            if self.stop_acknowledgement.disposition == "WORKER_CONFIRMED" and self.provider_started_at is None:
                raise ValueError("worker acknowledgement requires provider start")
        elif self.stop_acknowledgement is not None:
            raise ValueError("non-interrupt terminal state cannot carry a stop acknowledgement")

        prepared = (
            self.prepared_status,
            self.prepared_outcome_code,
            self.prepared_result,
            self.prepared_result_digest,
            self.result_prepared_at,
        )
        if any(value is not None for value in prepared):
            if any(value is None for value in prepared):
                raise ValueError("worker prepared result is incomplete")
            assert self.prepared_status is not None
            assert self.prepared_outcome_code is not None
            assert self.prepared_result is not None
            assert self.prepared_result_digest is not None
            assert self.result_prepared_at is not None
            _require_outcome_code(self.prepared_outcome_code)
            if self.result_prepared_at < self.claimed_at:
                raise ValueError("worker result prepare precedes lease claim")
            if self.prepared_result_digest != _prepared_result_digest(
                self.call_key,
                status=self.prepared_status,
                outcome_code=self.prepared_outcome_code,
                result=self.prepared_result,
            ):
                raise ValueError("worker prepared result digest mismatch")
            _require_bounded_result(self.prepared_result)
        elif self.result_committed_at is not None:
            raise ValueError("worker result commit requires a prepared result")
        if self.result_committed_at is not None:
            assert self.result_prepared_at is not None
            if self.result_committed_at < self.result_prepared_at:
                raise ValueError("worker result commit precedes prepare")
            if self.state != self.prepared_status or self.outcome_code != self.prepared_outcome_code:
                raise ValueError("worker committed result does not match terminal lease")
        armed = (self.armed_zero, self.armed_zero_digest, self.armed_at)
        physical_expectations = (
            self.physical_execution_subject_digest,
            self.physical_runtime_sha256,
        )
        if any(value is not None for value in physical_expectations) and any(value is None for value in physical_expectations):
            raise ValueError("worker physical expectations are incomplete")
        if any(value is not None for value in armed):
            if any(value is None for value in armed):
                raise ValueError("worker armed-zero record is incomplete")
            assert self.armed_zero is not None
            assert self.armed_zero_digest is not None
            assert self.armed_at is not None
            if self.armed_at < self.claimed_at:
                raise ValueError("worker armed-zero time precedes lease claim")
            bounded_arm = _require_bounded_result(self.armed_zero)
            if self.armed_zero_digest != canonical_json_sha256(
                {
                    "schema_version": "rolo-targetd-worker-armed-zero/v1",
                    "call_key_digest": self.call_key_digest,
                    "armed_zero": bounded_arm,
                }
            ):
                raise ValueError("worker armed-zero digest mismatch")
        return self


@dataclass(frozen=True)
class WorkerLeaseClaim:
    """In-memory worker capability; repr deliberately omits the bearer token."""

    lease: WorkerLeaseRecord
    lease_token: str = field(repr=False)


@dataclass(frozen=True)
class WorkerCompletion:
    status: Literal["CANCELLED", "STOPPED", "SUCCEEDED", "FAILED"]
    outcome_code: str

    def __post_init__(self) -> None:
        if self.status not in {"CANCELLED", "STOPPED", "SUCCEEDED", "FAILED"}:
            raise ValueError("worker completion status is invalid")
        _require_outcome_code(self.outcome_code)


class _PersistedRejection(Exception):
    def __init__(self, record: WorkerLeaseRecord, code: str) -> None:
        super().__init__(code)
        self.record = record
        self.code = code


class WorkerLeaseStore:
    """Atomic durable store for exact-call worker leases.

    A lease is single-use.  Once it expires or becomes orphaned, its call is
    ``UNKNOWN`` forever; ``claim`` never increments the generation to replay
    the same call key.
    """

    def __init__(
        self,
        root: str | Path,
        *,
        max_leases: int = MAX_WORKER_LEASES,
        max_state_bytes: int = MAX_WORKER_LEASE_STATE_BYTES,
    ) -> None:
        if isinstance(max_leases, bool) or not isinstance(max_leases, int) or not 1 <= max_leases <= MAX_WORKER_LEASES:
            raise WorkerLifecycleError("WORKER_LEASE_CAPACITY_INVALID")
        if isinstance(max_state_bytes, bool) or not isinstance(max_state_bytes, int) or not 128 <= max_state_bytes <= MAX_WORKER_LEASE_STATE_BYTES:
            raise WorkerLifecycleError("WORKER_LEASE_STATE_LIMIT_INVALID")
        supplied = Path(os.path.abspath(Path(root)))
        # The state root is an authority boundary. Reject both a direct
        # symlink and a symlink in any existing ancestor rather than resolving
        # through it and persisting leases outside that boundary.
        self.root = supplied
        self.path = self.root / "worker-leases.json"
        self.max_leases = max_leases
        self.max_state_bytes = max_state_bytes
        self._require_safe_path()

    def claim(
        self,
        call_key: WorkerCallKey,
        *,
        supervisor_id: str,
        worker_id: str,
        lease_ttl_s: float = 15.0,
        deadline_at: datetime | None = None,
        physical_execution_subject_digest: str | None = None,
        physical_runtime_sha256: str | None = None,
        now: datetime | None = None,
    ) -> WorkerLeaseClaim:
        call_key = WorkerCallKey.model_validate(call_key.model_dump(mode="python"))
        _require_identifier(supervisor_id, "WORKER_SUPERVISOR_ID_INVALID")
        _require_identifier(worker_id, "WORKER_ID_INVALID")
        ttl = _require_ttl(lease_ttl_s)
        current_time = _coerce_now(now)
        absolute_deadline = _coerce_deadline(deadline_at, current_time)
        if (physical_execution_subject_digest is None) != (physical_runtime_sha256 is None):
            raise WorkerLifecycleError("WORKER_PHYSICAL_EXPECTATIONS_INVALID")
        if physical_execution_subject_digest is not None and (
            re.fullmatch(r"sha256:[0-9a-f]{64}", physical_execution_subject_digest) is None or not isinstance(physical_runtime_sha256, str) or re.fullmatch(_SHA256, physical_runtime_sha256) is None
        ):
            raise WorkerLifecycleError("WORKER_PHYSICAL_EXPECTATIONS_INVALID")
        token = _new_token()
        token_digest = _token_digest(token)
        key_digest = call_key.digest()

        def transition(leases: dict[str, WorkerLeaseRecord]) -> WorkerLeaseRecord:
            existing = leases.get(key_digest)
            if existing is not None:
                self._require_exact_key(existing, call_key)
                if existing.state in _ACTIVE_STATES and current_time < existing.heartbeat_at:
                    rollback = self._to_unknown(existing, current_time, "WORKER_CLOCK_ROLLBACK")
                    raise _PersistedRejection(rollback, "WORKER_LEASE_RECONCILIATION_REQUIRED")
                if existing.state in _ACTIVE_STATES and current_time >= existing.expires_at:
                    expired = self._to_unknown(existing, current_time, "WORKER_LEASE_EXPIRED")
                    raise _PersistedRejection(expired, "WORKER_LEASE_RECONCILIATION_REQUIRED")
                raise WorkerLifecycleError("WORKER_LEASE_ALREADY_ACTIVE" if existing.state in _ACTIVE_STATES else "WORKER_CALL_ALREADY_TERMINAL")
            return WorkerLeaseRecord(
                schema_version="rolo-targetd-worker-lease/v1",
                call_key=call_key,
                call_key_digest=key_digest,
                supervisor_id=supervisor_id,
                worker_id=worker_id,
                generation=1,
                lease_token_digest=token_digest,
                lease_ttl_s=ttl,
                state="CLAIMED",
                claimed_at=current_time,
                heartbeat_at=current_time,
                expires_at=_lease_expiry(current_time, ttl, absolute_deadline),
                deadline_at=absolute_deadline,
                physical_execution_subject_digest=physical_execution_subject_digest,
                physical_runtime_sha256=physical_runtime_sha256,
            )

        record = self._mutate_one(key_digest, transition)
        return WorkerLeaseClaim(lease=record, lease_token=token)

    def start(
        self,
        claim: WorkerLeaseClaim,
        *,
        now: datetime | None = None,
    ) -> WorkerLeaseRecord:
        current_time = _coerce_now(now)

        def transition(leases: dict[str, WorkerLeaseRecord]) -> WorkerLeaseRecord:
            record = self._authorize_claim(leases, claim, current_time)
            if record.state == "RUNNING":
                return record
            if record.state != "CLAIMED":
                raise WorkerLifecycleError("WORKER_LEASE_CANNOT_START")
            return record.model_copy(
                update={
                    "state": "RUNNING",
                    "provider_started_at": current_time,
                    "heartbeat_at": current_time,
                    "expires_at": _lease_expiry(
                        current_time,
                        record.lease_ttl_s,
                        record.deadline_at,
                    ),
                }
            )

        return self._mutate_one(claim.lease.call_key_digest, transition)

    def heartbeat(
        self,
        claim: WorkerLeaseClaim,
        *,
        now: datetime | None = None,
    ) -> WorkerLeaseRecord:
        current_time = _coerce_now(now)

        def transition(leases: dict[str, WorkerLeaseRecord]) -> WorkerLeaseRecord:
            record = self._authorize_claim(leases, claim, current_time)
            if record.state not in _ACTIVE_STATES:
                raise WorkerLifecycleError("WORKER_LEASE_NOT_ACTIVE")
            expires_at = record.expires_at
            if record.state not in _INTERRUPT_STATES:
                expires_at = _lease_expiry(
                    current_time,
                    record.lease_ttl_s,
                    record.deadline_at,
                )
            return record.model_copy(
                update={
                    "heartbeat_at": current_time,
                    # An interrupt request is a bounded stop window, not a new
                    # renewable lease. A live-but-stuck worker must not keep a
                    # CANCEL/STOP request pending forever by heartbeating.
                    "expires_at": expires_at,
                    "heartbeat_count": record.heartbeat_count + 1,
                }
            )

        return self._mutate_one(claim.lease.call_key_digest, transition)

    def record_armed_zero(
        self,
        claim: WorkerLeaseClaim,
        *,
        armed_zero: dict[str, object],
        now: datetime | None = None,
    ) -> WorkerLeaseRecord:
        """Durably bind a zero-only physical handle before PREPARE returns."""

        bounded = _require_bounded_result(armed_zero)
        current_time = _coerce_now(now)
        digest = canonical_json_sha256(
            {
                "schema_version": "rolo-targetd-worker-armed-zero/v1",
                "call_key_digest": claim.lease.call_key_digest,
                "armed_zero": bounded,
            }
        )

        def transition(
            leases: dict[str, WorkerLeaseRecord],
        ) -> WorkerLeaseRecord:
            record = self._authorize_claim(leases, claim, current_time)
            if record.state != "RUNNING":
                raise WorkerLifecycleError("WORKER_ARMED_ZERO_STATE_INVALID")
            if record.armed_zero_digest is not None:
                if record.armed_zero == bounded and record.armed_zero_digest == digest:
                    return record
                raise WorkerLifecycleError("WORKER_ARMED_ZERO_CONFLICT")
            return record.model_copy(
                update={
                    "armed_zero": bounded,
                    "armed_zero_digest": digest,
                    "armed_at": current_time,
                }
            )

        return self._mutate_one(claim.lease.call_key_digest, transition)

    def prepare_result(
        self,
        claim: WorkerLeaseClaim,
        *,
        completion: WorkerCompletion,
        result: dict[str, object],
        now: datetime | None = None,
    ) -> WorkerLeaseRecord:
        """Durably stage one bounded worker outcome before terminalization."""

        if not isinstance(completion, WorkerCompletion):
            raise WorkerLifecycleError("WORKER_PREPARED_COMPLETION_INVALID")
        bounded_result = _require_bounded_result(result)
        current_time = _coerce_now(now)
        result_digest = _prepared_result_digest(
            claim.lease.call_key,
            status=completion.status,
            outcome_code=completion.outcome_code,
            result=bounded_result,
        )

        def transition(leases: dict[str, WorkerLeaseRecord]) -> WorkerLeaseRecord:
            record = self._authorize_claim(leases, claim, current_time)
            expected_state = {
                "CANCELLED": "CANCEL_REQUESTED",
                "STOPPED": "STOP_REQUESTED",
                "SUCCEEDED": "RUNNING",
                "FAILED": "RUNNING",
            }[completion.status]
            if record.state != expected_state:
                raise WorkerLifecycleError("WORKER_RESULT_PREPARE_STATE_INVALID")
            if record.prepared_result_digest is not None:
                if (
                    record.prepared_status == completion.status
                    and record.prepared_outcome_code == completion.outcome_code
                    and record.prepared_result == bounded_result
                    and record.prepared_result_digest == result_digest
                ):
                    return record
                raise WorkerLifecycleError("WORKER_RESULT_PREPARE_CONFLICT")
            return record.model_copy(
                update={
                    "prepared_status": completion.status,
                    "prepared_outcome_code": completion.outcome_code,
                    "prepared_result": bounded_result,
                    "prepared_result_digest": result_digest,
                    "result_prepared_at": current_time,
                }
            )

        return self._mutate_one(claim.lease.call_key_digest, transition)

    def commit_prepared_result(
        self,
        call_key: WorkerCallKey,
        *,
        result_digest: str,
        now: datetime | None = None,
    ) -> WorkerLeaseRecord:
        """Mark a prepared result committed after target receipt persistence."""

        call_key = WorkerCallKey.model_validate(call_key.model_dump(mode="python"))
        if not isinstance(result_digest, str) or re.fullmatch(_SHA256, result_digest) is None:
            raise WorkerLifecycleError("WORKER_PREPARED_RESULT_DIGEST_INVALID")
        current_time = _coerce_now(now)

        def transition(leases: dict[str, WorkerLeaseRecord]) -> WorkerLeaseRecord:
            record = self._load_exact(leases, call_key)
            if record.prepared_result_digest != result_digest:
                raise WorkerLifecycleError("WORKER_PREPARED_RESULT_DIGEST_MISMATCH")
            if record.state != record.prepared_status or record.outcome_code != record.prepared_outcome_code or record.finished_at is None or record.result_prepared_at is None:
                raise WorkerLifecycleError("WORKER_PREPARED_RESULT_NOT_COMMITTABLE")
            if record.result_committed_at is not None:
                return record
            return record.model_copy(
                update={
                    "result_committed_at": max(
                        current_time,
                        record.result_prepared_at,
                        record.finished_at,
                    )
                }
            )

        return self._mutate_one(call_key.digest(), transition)

    def request_interrupt(
        self,
        call_key: WorkerCallKey,
        *,
        intent: WorkerInterruptIntent,
        now: datetime | None = None,
    ) -> WorkerLeaseRecord:
        call_key = WorkerCallKey.model_validate(call_key.model_dump(mode="python"))
        if intent not in {"CANCEL", "STOP"}:
            raise WorkerLifecycleError("WORKER_INTERRUPT_INTENT_INVALID")
        current_time = _coerce_now(now)
        key_digest = call_key.digest()
        requested_state = "CANCEL_REQUESTED" if intent == "CANCEL" else "STOP_REQUESTED"
        terminal_state = "CANCELLED" if intent == "CANCEL" else "STOPPED"

        def transition(leases: dict[str, WorkerLeaseRecord]) -> WorkerLeaseRecord:
            record = self._load_exact(leases, call_key)
            if record.state in _TERMINAL_STATES:
                return record
            if current_time < record.heartbeat_at:
                rollback = self._to_unknown(record, current_time, "WORKER_CLOCK_ROLLBACK")
                raise _PersistedRejection(rollback, "WORKER_LEASE_RECONCILIATION_REQUIRED")
            if current_time >= record.expires_at:
                expired = self._to_unknown(record, current_time, "WORKER_LEASE_EXPIRED")
                raise _PersistedRejection(expired, "WORKER_LEASE_RECONCILIATION_REQUIRED")
            if record.state == "CLAIMED":
                acknowledgement = WorkerStopAcknowledgement(
                    schema_version="rolo-targetd-worker-stop-ack/v1",
                    call_key=record.call_key,
                    call_key_digest=record.call_key_digest,
                    intent=intent,
                    worker_id=record.worker_id,
                    generation=record.generation,
                    disposition="NOT_STARTED",
                    outcome_code="PROVIDER_NOT_STARTED",
                    acknowledged_at=current_time,
                )
                return record.model_copy(
                    update={
                        "state": terminal_state,
                        "interrupt_requested_at": current_time,
                        "finished_at": current_time,
                        "outcome_code": acknowledgement.outcome_code,
                        "stop_acknowledgement": acknowledgement,
                    }
                )
            if record.state == requested_state:
                return record
            if record.state in _INTERRUPT_STATES:
                raise WorkerLifecycleError("WORKER_INTERRUPT_INTENT_CONFLICT")
            if record.state != "RUNNING":
                raise WorkerLifecycleError("WORKER_LEASE_NOT_INTERRUPTIBLE")
            return record.model_copy(
                update={
                    "state": requested_state,
                    "interrupt_requested_at": current_time,
                    "expires_at": min(
                        record.expires_at,
                        current_time + timedelta(seconds=_MAX_INTERRUPT_ACK_S),
                    ),
                }
            )

        return self._mutate_one(key_digest, transition)

    def acknowledge_interrupt(
        self,
        claim: WorkerLeaseClaim,
        *,
        intent: WorkerInterruptIntent,
        outcome_code: str,
        now: datetime | None = None,
    ) -> WorkerLeaseRecord:
        if intent not in {"CANCEL", "STOP"}:
            raise WorkerLifecycleError("WORKER_INTERRUPT_INTENT_INVALID")
        _require_outcome_code(outcome_code)
        current_time = _coerce_now(now)
        expected_state = "CANCEL_REQUESTED" if intent == "CANCEL" else "STOP_REQUESTED"
        terminal_state = "CANCELLED" if intent == "CANCEL" else "STOPPED"

        def transition(leases: dict[str, WorkerLeaseRecord]) -> WorkerLeaseRecord:
            record = self._authorize_claim(leases, claim, current_time)
            if record.state == terminal_state:
                return record
            if record.state != expected_state:
                raise WorkerLifecycleError("WORKER_INTERRUPT_ACK_WITHOUT_REQUEST")
            acknowledgement = WorkerStopAcknowledgement(
                schema_version="rolo-targetd-worker-stop-ack/v1",
                call_key=record.call_key,
                call_key_digest=record.call_key_digest,
                intent=intent,
                worker_id=record.worker_id,
                generation=record.generation,
                disposition="WORKER_CONFIRMED",
                outcome_code=outcome_code,
                acknowledged_at=current_time,
            )
            return record.model_copy(
                update={
                    "state": terminal_state,
                    "finished_at": current_time,
                    "outcome_code": outcome_code,
                    "stop_acknowledgement": acknowledgement,
                }
            )

        return self._mutate_one(claim.lease.call_key_digest, transition)

    def complete(
        self,
        claim: WorkerLeaseClaim,
        *,
        status: Literal["SUCCEEDED", "FAILED"],
        outcome_code: str,
        now: datetime | None = None,
    ) -> WorkerLeaseRecord:
        if status not in {"SUCCEEDED", "FAILED"}:
            raise WorkerLifecycleError("WORKER_COMPLETION_STATUS_INVALID")
        _require_outcome_code(outcome_code)
        current_time = _coerce_now(now)

        def transition(leases: dict[str, WorkerLeaseRecord]) -> WorkerLeaseRecord:
            record = self._authorize_claim(leases, claim, current_time)
            if record.state == status:
                return record
            if record.state in _INTERRUPT_STATES:
                raise WorkerLifecycleError("WORKER_INTERRUPT_ACK_REQUIRED")
            if record.state != "RUNNING":
                raise WorkerLifecycleError("WORKER_LEASE_CANNOT_COMPLETE")
            return record.model_copy(
                update={
                    "state": status,
                    "finished_at": current_time,
                    "outcome_code": outcome_code,
                }
            )

        return self._mutate_one(claim.lease.call_key_digest, transition)

    def mark_worker_crashed(
        self,
        claim: WorkerLeaseClaim,
        *,
        outcome_code: str = "WORKER_CRASH_OBSERVED",
        now: datetime | None = None,
    ) -> WorkerLeaseRecord:
        _require_outcome_code(outcome_code)
        current_time = _coerce_now(now)

        def transition(leases: dict[str, WorkerLeaseRecord]) -> WorkerLeaseRecord:
            record = self._authorize_claim(leases, claim, current_time, allow_expired=True)
            if record.state in _TERMINAL_STATES:
                return record
            return self._to_unknown(record, current_time, outcome_code)

        return self._mutate_one(claim.lease.call_key_digest, transition)

    def fail_close(
        self,
        call_key: WorkerCallKey,
        *,
        supervisor_id: str,
        outcome_code: str,
        now: datetime | None = None,
    ) -> WorkerLeaseRecord:
        """Let the owning supervisor downgrade an active call to UNKNOWN.

        This operation never creates success or a stop acknowledgement. It is
        used when a cross-store integration invariant cannot be proven after
        the worker has already been admitted.
        """

        call_key = WorkerCallKey.model_validate(call_key.model_dump(mode="python"))
        _require_identifier(supervisor_id, "WORKER_SUPERVISOR_ID_INVALID")
        _require_outcome_code(outcome_code)
        current_time = _coerce_now(now)
        key_digest = call_key.digest()

        def transition(leases: dict[str, WorkerLeaseRecord]) -> WorkerLeaseRecord:
            record = self._load_exact(leases, call_key)
            if record.state in _TERMINAL_STATES:
                return record
            if record.supervisor_id != supervisor_id:
                raise WorkerLifecycleError("WORKER_SUPERVISOR_ID_MISMATCH")
            return self._to_unknown(record, current_time, outcome_code)

        return self._mutate_one(key_digest, transition)

    def reconcile(
        self,
        call_key: WorkerCallKey,
        *,
        supervisor_id: str,
        now: datetime | None = None,
    ) -> WorkerLeaseRecord:
        """Reconcile one query without ever replaying an in-flight call."""

        call_key = WorkerCallKey.model_validate(call_key.model_dump(mode="python"))
        _require_identifier(supervisor_id, "WORKER_SUPERVISOR_ID_INVALID")
        current_time = _coerce_now(now)
        key_digest = call_key.digest()

        def transition(leases: dict[str, WorkerLeaseRecord]) -> WorkerLeaseRecord:
            record = self._load_exact(leases, call_key)
            if record.state in _TERMINAL_STATES:
                return record
            if record.supervisor_id != supervisor_id:
                return self._to_unknown(record, current_time, "WORKER_SUPERVISOR_RESTARTED")
            if current_time < record.heartbeat_at:
                return self._to_unknown(record, current_time, "WORKER_CLOCK_ROLLBACK")
            if current_time >= record.expires_at:
                return self._to_unknown(record, current_time, "WORKER_LEASE_EXPIRED")
            return record

        return self._mutate_one(key_digest, transition)

    def reconcile_all(
        self,
        *,
        supervisor_id: str,
        now: datetime | None = None,
    ) -> tuple[WorkerLeaseRecord, ...]:
        """Fail-close all expired or previous-supervisor active leases."""

        _require_identifier(supervisor_id, "WORKER_SUPERVISOR_ID_INVALID")
        current_time = _coerce_now(now)

        with interprocess_lock(self.path):
            leases = self._read_unlocked()
            changed = False
            for key_digest, record in tuple(leases.items()):
                if record.state not in _ACTIVE_STATES:
                    continue
                code: str | None = None
                if record.supervisor_id != supervisor_id:
                    code = "WORKER_SUPERVISOR_RESTARTED"
                elif current_time < record.heartbeat_at:
                    code = "WORKER_CLOCK_ROLLBACK"
                elif current_time >= record.expires_at:
                    code = "WORKER_LEASE_EXPIRED"
                if code is not None:
                    leases[key_digest] = self._to_unknown(record, current_time, code)
                    changed = True
            if changed:
                self._write_unlocked(leases)
            return tuple(leases[key] for key in sorted(leases))

    def load(self, call_key: WorkerCallKey) -> WorkerLeaseRecord | None:
        call_key = WorkerCallKey.model_validate(call_key.model_dump(mode="python"))
        leases = self._read_unlocked()
        record = leases.get(call_key.digest())
        if record is not None:
            self._require_exact_key(record, call_key)
        return record

    def list_records(self) -> tuple[WorkerLeaseRecord, ...]:
        leases = self._read_unlocked()
        return tuple(leases[key] for key in sorted(leases))

    def _mutate_one(
        self,
        key_digest: str,
        transition: Callable[[dict[str, WorkerLeaseRecord]], WorkerLeaseRecord],
    ) -> WorkerLeaseRecord:
        with interprocess_lock(self.path):
            leases = self._read_unlocked()
            try:
                record = transition(leases)
            except _PersistedRejection as exc:
                leases[key_digest] = WorkerLeaseRecord.model_validate(exc.record.model_dump(mode="python"))
                self._write_unlocked(leases)
                raise WorkerLifecycleError(exc.code) from None
            leases[key_digest] = WorkerLeaseRecord.model_validate(record.model_dump(mode="python"))
            self._write_unlocked(leases)
            return leases[key_digest]

    def _read_unlocked(self) -> dict[str, WorkerLeaseRecord]:
        self._require_safe_path()
        try:
            if self.path.stat().st_size > self.max_state_bytes:
                raise WorkerLifecycleError("WORKER_LEASE_STATE_TOO_LARGE")
            with self.path.open("rb") as stream:
                encoded = stream.read(self.max_state_bytes + 1)
            if len(encoded) > self.max_state_bytes:
                raise WorkerLifecycleError("WORKER_LEASE_STATE_TOO_LARGE")
            raw = loads_unique_json(encoded.decode("utf-8"))
        except FileNotFoundError:
            return {}
        except WorkerLifecycleError:
            raise
        except (OSError, ValueError) as exc:
            raise WorkerLifecycleError("WORKER_LEASE_STATE_UNREADABLE") from exc
        if not isinstance(raw, dict) or set(raw) != {"schema_version", "leases"}:
            raise WorkerLifecycleError("WORKER_LEASE_STATE_INVALID")
        if raw.get("schema_version") != "rolo-targetd-worker-leases/v1" or not isinstance(raw.get("leases"), dict):
            raise WorkerLifecycleError("WORKER_LEASE_STATE_INVALID")
        if len(raw["leases"]) > self.max_leases:
            raise WorkerLifecycleError("WORKER_LEASE_CAPACITY_EXCEEDED")
        records: dict[str, WorkerLeaseRecord] = {}
        try:
            for key_digest, payload in raw["leases"].items():
                if not isinstance(key_digest, str):
                    raise ValueError("lease key is not a string")
                record = WorkerLeaseRecord.model_validate(payload)
                if key_digest != record.call_key_digest:
                    raise ValueError("lease index does not match call key")
                records[key_digest] = record
        except (TypeError, ValueError) as exc:
            raise WorkerLifecycleError("WORKER_LEASE_STATE_INVALID") from exc
        return records

    def _write_unlocked(self, leases: dict[str, WorkerLeaseRecord]) -> None:
        self._require_safe_path()
        if len(leases) > self.max_leases:
            raise WorkerLifecycleError("WORKER_LEASE_CAPACITY_EXCEEDED")
        payload = {
            "schema_version": "rolo-targetd-worker-leases/v1",
            "leases": {key: leases[key].model_dump(mode="json") for key in sorted(leases)},
        }
        serialized = json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
        if len(serialized.encode("utf-8")) > self.max_state_bytes:
            raise WorkerLifecycleError("WORKER_LEASE_STATE_TOO_LARGE")
        atomic_write_text(
            self.path,
            serialized,
            acquire_lock=False,
        )

    def _require_safe_path(self) -> None:
        # Recheck on every read/write as well as construction. This catches a
        # state directory replaced by a symlink after the store was created.
        for component in (self.root, *self.root.parents):
            if component.is_symlink():
                raise WorkerLifecycleError("WORKER_LEASE_ROOT_SYMLINK_REJECTED")
        if self.path.is_symlink():
            raise WorkerLifecycleError("WORKER_LEASE_STATE_SYMLINK_REJECTED")

    @staticmethod
    def _require_exact_key(record: WorkerLeaseRecord, call_key: WorkerCallKey) -> None:
        if record.call_key != call_key or record.call_key_digest != call_key.digest():
            raise WorkerLifecycleError("WORKER_CALL_KEY_MISMATCH")

    def _load_exact(
        self,
        leases: dict[str, WorkerLeaseRecord],
        call_key: WorkerCallKey,
    ) -> WorkerLeaseRecord:
        record = leases.get(call_key.digest())
        if record is None:
            raise WorkerLifecycleError("WORKER_CALL_NOT_FOUND")
        self._require_exact_key(record, call_key)
        return record

    def _authorize_claim(
        self,
        leases: dict[str, WorkerLeaseRecord],
        claim: WorkerLeaseClaim,
        now: datetime,
        *,
        allow_expired: bool = False,
    ) -> WorkerLeaseRecord:
        record = self._load_exact(leases, claim.lease.call_key)
        if (
            record.supervisor_id != claim.lease.supervisor_id
            or record.worker_id != claim.lease.worker_id
            or record.generation != claim.lease.generation
            or not hmac.compare_digest(record.lease_token_digest, _token_digest(claim.lease_token))
        ):
            raise WorkerLifecycleError("WORKER_LEASE_CLAIM_MISMATCH")
        if record.state in _ACTIVE_STATES and now < record.heartbeat_at:
            rollback = self._to_unknown(record, now, "WORKER_CLOCK_ROLLBACK")
            raise _PersistedRejection(rollback, "WORKER_LEASE_RECONCILIATION_REQUIRED")
        if not allow_expired and record.state in _ACTIVE_STATES and now >= record.expires_at:
            expired = self._to_unknown(record, now, "WORKER_LEASE_EXPIRED")
            raise _PersistedRejection(expired, "WORKER_LEASE_RECONCILIATION_REQUIRED")
        return record

    @staticmethod
    def _to_unknown(
        record: WorkerLeaseRecord,
        now: datetime,
        outcome_code: str,
    ) -> WorkerLeaseRecord:
        _require_outcome_code(outcome_code)
        if record.state in _TERMINAL_STATES:
            return record
        finished_at = max(
            candidate
            for candidate in (
                now,
                record.claimed_at,
                record.heartbeat_at,
                record.provider_started_at,
                record.interrupt_requested_at,
            )
            if candidate is not None
        )
        return record.model_copy(
            update={
                "state": "UNKNOWN",
                "finished_at": finished_at,
                "outcome_code": outcome_code,
            }
        )


class WorkerControl:
    """Narrow cooperative API given to one leased work function."""

    def __init__(self, store: WorkerLeaseStore, claim: WorkerLeaseClaim) -> None:
        self._store = store
        self._claim = claim

    @property
    def call_key(self) -> WorkerCallKey:
        return self._claim.lease.call_key

    def heartbeat(self) -> WorkerLeaseRecord:
        return self._store.heartbeat(self._claim)

    def prepare_result(
        self,
        *,
        completion: WorkerCompletion,
        result: dict[str, object],
    ) -> WorkerLeaseRecord:
        return self._store.prepare_result(
            self._claim,
            completion=completion,
            result=result,
        )

    def complete(
        self,
        *,
        status: Literal["SUCCEEDED", "FAILED"],
        outcome_code: str,
    ) -> WorkerLeaseRecord:
        return self._store.complete(
            self._claim,
            status=status,
            outcome_code=outcome_code,
        )

    def acknowledge_interrupt(
        self,
        *,
        intent: WorkerInterruptIntent,
        outcome_code: str,
    ) -> WorkerLeaseRecord:
        return self._store.acknowledge_interrupt(
            self._claim,
            intent=intent,
            outcome_code=outcome_code,
        )

    def interrupt_intent(self) -> WorkerInterruptIntent | None:
        record = self._store.load(self.call_key)
        if record is None:
            raise WorkerLifecycleError("WORKER_CALL_NOT_FOUND")
        if record.state == "CANCEL_REQUESTED":
            return "CANCEL"
        if record.state == "STOP_REQUESTED":
            return "STOP"
        return None


WorkerFunction = Callable[[WorkerControl], WorkerCompletion]
WorkerStopSignal = Callable[[WorkerInterruptIntent], None]


class LeasedWorkerRuntime:
    """Dedicated-thread harness for the durable lease protocol.

    ``supervisor_id`` is only a human-readable configuration prefix. Every
    runtime creates a fresh UUID-suffixed incarnation and stores that exact
    identity in its leases, so even a restart with unchanged configuration
    turns prior-process leases UNKNOWN during startup reconciliation.
    Work must cooperate by heartbeating and by returning CANCELLED/STOPPED
    only after it has actually reached a safe provider boundary.  The runtime
    then writes the worker-authored acknowledgement with the lease capability.
    """

    def __init__(self, store: WorkerLeaseStore, *, supervisor_id: str) -> None:
        _require_identifier(supervisor_id, "WORKER_SUPERVISOR_ID_INVALID")
        self.store = store
        self.supervisor_name = supervisor_id
        self.supervisor_id = new_worker_supervisor_incarnation(supervisor_id)
        self.store.reconcile_all(supervisor_id=self.supervisor_id)
        self._threads: dict[str, threading.Thread] = {}
        self._claims: dict[str, WorkerLeaseClaim] = {}
        self._stoppers: dict[str, WorkerStopSignal] = {}
        self._lock = threading.Lock()

    def submit(
        self,
        call_key: WorkerCallKey,
        *,
        worker_id: str,
        work: WorkerFunction,
        lease_ttl_s: float = 15.0,
        deadline_at: datetime | None = None,
        stop_signal: WorkerStopSignal | None = None,
    ) -> WorkerLeaseClaim:
        claim = self.reserve(
            call_key,
            worker_id=worker_id,
            lease_ttl_s=lease_ttl_s,
            deadline_at=deadline_at,
        )
        self.start_reserved(claim, work=work, stop_signal=stop_signal)
        return claim

    def reserve(
        self,
        call_key: WorkerCallKey,
        *,
        worker_id: str,
        lease_ttl_s: float = 15.0,
        deadline_at: datetime | None = None,
    ) -> WorkerLeaseClaim:
        """Persist one lease before any provider-start boundary is reachable."""

        return self.store.claim(
            call_key,
            supervisor_id=self.supervisor_id,
            worker_id=worker_id,
            lease_ttl_s=lease_ttl_s,
            deadline_at=deadline_at,
        )

    def start_reserved(
        self,
        claim: WorkerLeaseClaim,
        *,
        work: WorkerFunction,
        stop_signal: WorkerStopSignal | None = None,
    ) -> None:
        if claim.lease.supervisor_id != self.supervisor_id or claim.lease.state != "CLAIMED":
            raise WorkerLifecycleError("WORKER_LEASE_RESERVATION_INVALID")
        call_key = claim.lease.call_key
        key_digest = call_key.digest()
        thread = threading.Thread(
            target=self._run,
            args=(claim, work),
            name=f"rolo-targetd-{key_digest[:12]}",
            daemon=True,
        )
        with self._lock:
            self._threads[key_digest] = thread
            self._claims[key_digest] = claim
            if stop_signal is not None:
                self._stoppers[key_digest] = stop_signal
        try:
            thread.start()
        except Exception as exc:
            try:
                self.store.mark_worker_crashed(
                    claim,
                    outcome_code="WORKER_THREAD_START_FAILED",
                )
            except WorkerLifecycleError:
                pass
            finally:
                with self._lock:
                    self._threads.pop(key_digest, None)
                    self._claims.pop(key_digest, None)
                    self._stoppers.pop(key_digest, None)
            raise WorkerLifecycleError("WORKER_THREAD_START_FAILED") from exc

    def request_interrupt(
        self,
        call_key: WorkerCallKey,
        *,
        intent: WorkerInterruptIntent,
    ) -> WorkerLeaseRecord:
        record = self.store.request_interrupt(call_key, intent=intent)
        if record.state in _INTERRUPT_STATES:
            with self._lock:
                stop_signal = self._stoppers.get(call_key.digest())
            if stop_signal is not None:
                try:
                    stop_signal(intent)
                except Exception as exc:
                    raise WorkerLifecycleError("WORKER_STOP_SIGNAL_FAILED") from exc
        return record

    def join(self, call_key: WorkerCallKey, timeout_s: float | None = None) -> WorkerLeaseRecord:
        with self._lock:
            thread = self._threads.get(call_key.digest())
        if thread is None:
            raise WorkerLifecycleError("WORKER_CALL_NOT_LOCAL")
        thread.join(timeout_s)
        if thread.is_alive():
            raise WorkerLifecycleError("WORKER_JOIN_TIMEOUT")
        record = self.store.load(call_key)
        if record is None:
            raise WorkerLifecycleError("WORKER_CALL_NOT_FOUND")
        if record.state in _ACTIVE_STATES:
            with self._lock:
                claim = self._claims.get(call_key.digest())
            if claim is None:
                raise WorkerLifecycleError("WORKER_EXIT_RECONCILIATION_FAILED")
            try:
                record = self.store.mark_worker_crashed(
                    claim,
                    outcome_code="WORKER_EXITED_WITHOUT_TERMINAL_STATE",
                )
            except WorkerLifecycleError as exc:
                raise WorkerLifecycleError("WORKER_EXIT_RECONCILIATION_FAILED") from exc
        return record

    def _run(self, claim: WorkerLeaseClaim, work: WorkerFunction) -> None:
        try:
            self.store.start(claim)
            completion = work(WorkerControl(self.store, claim))
            if not isinstance(completion, WorkerCompletion):
                raise TypeError("worker did not return WorkerCompletion")
            if completion.status in {"CANCELLED", "STOPPED"}:
                intent: WorkerInterruptIntent = "CANCEL" if completion.status == "CANCELLED" else "STOP"
                self.store.acknowledge_interrupt(
                    claim,
                    intent=intent,
                    outcome_code=completion.outcome_code,
                )
            else:
                self.store.complete(
                    claim,
                    status=completion.status,
                    outcome_code=completion.outcome_code,
                )
        except WorkerLifecycleError:
            # The durable state already records a conflicting interrupt,
            # expiry, or terminal outcome.  Never overwrite it from the
            # worker thread.
            pass
        except Exception:
            try:
                # An exception after provider start does not prove whether a
                # side effect occurred. Only an explicit trusted
                # WorkerCompletion(FAILED) may terminalize as FAILED.
                self.store.mark_worker_crashed(
                    claim,
                    outcome_code="WORKER_EXCEPTION_AMBIGUOUS",
                )
            except WorkerLifecycleError:
                pass
        except BaseException:
            try:
                self.store.mark_worker_crashed(claim)
            except WorkerLifecycleError:
                pass
        finally:
            try:
                record = self.store.load(claim.lease.call_key)
                if record is not None and record.state in _ACTIVE_STATES:
                    self.store.mark_worker_crashed(
                        claim,
                        outcome_code="WORKER_EXITED_WITHOUT_TERMINAL_STATE",
                    )
            except WorkerLifecycleError:
                # join() performs the same fail-closed check and refuses to
                # return an active record if reconciliation itself failed.
                pass
            with self._lock:
                self._stoppers.pop(claim.lease.call_key_digest, None)


def new_worker_supervisor_incarnation(supervisor_name: str) -> str:
    """Create a fresh lease owner identity from a reusable config prefix."""

    _require_identifier(supervisor_name, "WORKER_SUPERVISOR_ID_INVALID")
    # WorkerLeaseRecord identifiers are capped at 128 characters. Keep a
    # useful configuration prefix while reserving one separator and the
    # complete 128-bit UUID for the non-reusable process incarnation.
    return f"{supervisor_name[:95]}:{uuid4().hex}"


def _require_identifier(value: str, code: str) -> None:
    if not isinstance(value, str) or re.fullmatch(_IDENTIFIER, value) is None:
        raise WorkerLifecycleError(code)


def _require_outcome_code(value: str) -> None:
    if not isinstance(value, str) or _OUTCOME_CODE.fullmatch(value) is None:
        raise ValueError("worker outcome code is invalid")


def _require_bounded_result(value: dict[str, object]) -> dict[str, object]:
    if not isinstance(value, dict):
        raise WorkerLifecycleError("WORKER_PREPARED_RESULT_INVALID")
    try:
        encoded = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise WorkerLifecycleError("WORKER_PREPARED_RESULT_INVALID") from exc
    if len(encoded) > MAX_WORKER_PREPARED_RESULT_BYTES:
        raise WorkerLifecycleError("WORKER_PREPARED_RESULT_TOO_LARGE")
    return dict(value)


def _prepared_result_digest(
    call_key: WorkerCallKey,
    *,
    status: WorkerPreparedStatus,
    outcome_code: str,
    result: dict[str, object],
) -> str:
    return canonical_json_sha256(
        {
            "schema_version": "rolo-targetd-worker-prepared-result/v1",
            "call_key_digest": call_key.digest(),
            "status": status,
            "outcome_code": outcome_code,
            "result": result,
        }
    )


def _require_ttl(value: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise WorkerLifecycleError("WORKER_LEASE_TTL_INVALID")
    ttl = float(value)
    if not 0.1 <= ttl <= 300.0:
        raise WorkerLifecycleError("WORKER_LEASE_TTL_INVALID")
    return ttl


def _require_aware(value: datetime, label: str) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} timestamp must include timezone")


def _coerce_now(value: datetime | None) -> datetime:
    now = value or datetime.now(timezone.utc)
    _require_aware(now, "worker lifecycle")
    return now.astimezone(timezone.utc)


def _coerce_deadline(value: datetime | None, now: datetime) -> datetime | None:
    if value is None:
        return None
    _require_aware(value, "worker lifecycle deadline")
    deadline = value.astimezone(timezone.utc)
    if deadline <= now:
        raise WorkerLifecycleError("WORKER_CALL_DEADLINE_EXPIRED")
    return deadline


def _lease_expiry(now: datetime, ttl_s: float, deadline: datetime | None) -> datetime:
    expires_at = now + timedelta(seconds=ttl_s)
    return min(expires_at, deadline) if deadline is not None else expires_at


def _new_token() -> str:
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii").rstrip("=")


def _token_digest(token: str) -> str:
    if not isinstance(token, str) or _TOKEN.fullmatch(token) is None:
        raise WorkerLifecycleError("WORKER_LEASE_TOKEN_INVALID")
    return hashlib.sha256(token.encode("ascii")).hexdigest()
