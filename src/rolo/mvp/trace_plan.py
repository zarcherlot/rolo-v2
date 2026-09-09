"""Canonical, crash-recoverable Trace plans and a targetd receipt bridge.

The ordinary :mod:`rolo.mvp.trace` service remains useful for in-process
diagnostics.  This module adds the stronger boundary used by Release-bound
Trace: an immutable plan is published before the first CALL, every state
transition is appended to a hash-chained journal, and an interrupted CALL can
advance only after querying an exact target-owned receipt.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Callable, Mapping, MutableMapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Lock
from typing import Any, Literal

from pydantic import Field, model_validator

from rolo.core.persistence import atomic_write_text, interprocess_lock
from rolo.dsl.admission import MappingAdmissionIdentity
from rolo.dsl.models import StrictModel
from rolo.dsl.parser import loads_unique_json
from rolo.mvp.artifacts import ArtifactIndex, build_artifact_index
from rolo.mvp.certify import write_new_artifact
from rolo.mvp.contracts import RunMode, SessionState, TraceCall, TraceEvent, TraceSession
from rolo.targetd.protocol import (
    ExecutionRequest,
    ExecutionRequestLike,
    ExecutionRequestV3,
    FrameKind,
    ProtocolError,
    ProtocolFrame,
    TargetdCallReceipt,
    TargetdExecutionAuthority,
    provider_fence_digest,
    requires_motion_safety,
    validate_execution_request,
)

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_HEX = re.compile(r"^[0-9a-f]{64}$")
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_SAFE_REF = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]{1,31}://[A-Za-z0-9][A-Za-z0-9._:/-]{0,511}$")
_SENSITIVE = re.compile(r"token|secret|password|authorization|credential|private[_-]?key", re.IGNORECASE)
_TERMINAL = frozenset({"SUCCEEDED", "FAILED", "STOPPED", "CANCELLED", "UNKNOWN", "NOT_ACCEPTED"})
_MAX_JOURNAL_BYTES = 64 * 1024 * 1024


def _canonical_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    except (TypeError, ValueError) as exc:
        raise ValueError("TRACE_CANONICAL_JSON_INVALID") from exc


def _sha256(value: Any, *, prefixed: bool = True) -> str:
    digest = hashlib.sha256(_canonical_bytes(value)).hexdigest()
    return f"sha256:{digest}" if prefixed else digest


def _is_reparse(path: Path) -> bool:
    try:
        attributes = getattr(path.lstat(), "st_file_attributes", 0)
    except FileNotFoundError:
        return False
    return bool(attributes & getattr(__import__("stat"), "FILE_ATTRIBUTE_REPARSE_POINT", 0))


def _assert_safe_directory(path: Path) -> None:
    if path.exists() and (path.is_symlink() or _is_reparse(path) or not path.is_dir()):
        raise ValueError("TRACE_STORE_DIRECTORY_UNSAFE")


class TracePlanCall(StrictModel):
    sequence: int = Field(ge=1, le=10_000)
    tool_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
    arguments: dict[str, Any] = Field(default_factory=dict)
    arguments_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    idempotency_key: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
    timeout_s: float = Field(gt=0, le=300)
    call_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")

    def unsigned_payload(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude={"call_digest"})

    @model_validator(mode="after")
    def validate_digests(self) -> TracePlanCall:
        if self.arguments_digest != _sha256(self.arguments):
            raise ValueError("Trace plan arguments digest mismatch")
        if self.call_digest != _sha256(self.unsigned_payload()):
            raise ValueError("Trace plan call digest mismatch")
        return self

    @classmethod
    def build(
        cls,
        *,
        sequence: int,
        call: TraceCall,
        timeout_s: float,
        session_id: str,
    ) -> TracePlanCall:
        arguments_digest = _sha256(call.arguments)
        key = call.idempotency_key
        if key is None:
            session_hash = hashlib.sha256(session_id.encode("utf-8")).hexdigest()[:16]
            key = f"trace:{session_hash}:{sequence}:{arguments_digest[7:27]}"
        payload = {
            "sequence": sequence,
            "tool_id": call.tool_id,
            "arguments": dict(call.arguments),
            "arguments_digest": arguments_digest,
            "idempotency_key": key,
            "timeout_s": timeout_s,
        }
        return cls.model_validate({**payload, "call_digest": _sha256(payload)})

    def trace_call(self) -> TraceCall:
        return TraceCall(
            tool_id=self.tool_id,
            arguments=dict(self.arguments),
            idempotency_key=self.idempotency_key,
        )


class TracePlan(StrictModel):
    schema_version: Literal["rolo-release-bound-trace-plan/v1"] = "rolo-release-bound-trace-plan/v1"
    plan_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
    session_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
    target_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
    catalog_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    task: str = Field(min_length=1, max_length=2_000)
    mode: RunMode
    max_calls: int = Field(ge=1, le=10_000)
    operator_id: str | None = Field(default=None, max_length=128)
    safety_confirmed: bool = False
    scope: tuple[str, ...] = Field(default=(), max_length=32)
    created_at: datetime
    expires_at: datetime
    release_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    compile_context_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    target_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    evidence_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    mapping_confirmation_receipt_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    mapping_admission: MappingAdmissionIdentity
    mapping_identity_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    targetd_authority_head_digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    targetd_catalog_head_digest: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    calls: tuple[TracePlanCall, ...] = Field(min_length=1, max_length=10_000)
    plan_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")

    def unsigned_payload(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude={"plan_digest"})

    @model_validator(mode="after")
    def validate_identity(self) -> TracePlan:
        if self.created_at.tzinfo is None or self.expires_at.tzinfo is None or self.expires_at <= self.created_at:
            raise ValueError("Trace plan time window is invalid")
        if self.plan_id != self.session_id:
            raise ValueError("Trace plan id must equal session id")
        if len(self.calls) > self.max_calls:
            raise ValueError("Trace plan exceeds session call budget")
        if [call.sequence for call in self.calls] != list(range(1, len(self.calls) + 1)):
            raise ValueError("Trace plan call sequence is not contiguous")
        if len({call.idempotency_key for call in self.calls}) != len(self.calls):
            raise ValueError("Trace plan contains duplicate idempotency keys")
        lineage = self.mapping_admission
        if (
            lineage.target_id != self.target_id
            or lineage.target_fingerprint != self.target_fingerprint
            or lineage.context_digest != self.compile_context_digest
            or lineage.evidence_digest != self.evidence_digest
            or any(call.tool_id != lineage.scope.tool_id for call in self.calls)
        ):
            raise ValueError("Trace plan Mapping identity mismatch")
        if self.mapping_identity_digest != _sha256(lineage.model_dump(mode="json")):
            raise ValueError("Trace plan Mapping identity digest mismatch")
        if self.plan_digest != _sha256(self.unsigned_payload()):
            raise ValueError("Trace plan digest mismatch")
        return self

    @classmethod
    def build(
        cls,
        *,
        session: TraceSession,
        calls: Sequence[TraceCall],
        timeouts: Mapping[str, float],
        release_digest: str,
        evidence_digest: str,
        mapping_confirmation_receipt_digest: str,
        mapping_admission: MappingAdmissionIdentity,
        targetd_authority: TargetdExecutionAuthority | None = None,
    ) -> TracePlan:
        if session.compile_context_digest is None or session.target_fingerprint in (None, "UNKNOWN"):
            raise ValueError("TRACE_PLAN_RELEASE_IDENTITY_INCOMPLETE")
        planned = tuple(
            TracePlanCall.build(
                sequence=index,
                call=call,
                timeout_s=float(timeouts[call.tool_id]),
                session_id=session.session_id,
            )
            for index, call in enumerate(calls, 1)
        )
        payload = {
            "schema_version": "rolo-release-bound-trace-plan/v1",
            "plan_id": session.session_id,
            "session_id": session.session_id,
            "target_id": session.target_id,
            "catalog_digest": session.catalog_digest,
            "task": session.task,
            "mode": session.mode,
            "max_calls": session.max_calls,
            "operator_id": session.operator_id,
            "safety_confirmed": session.safety_confirmed,
            "scope": tuple(session.scope),
            "created_at": session.created_at,
            "expires_at": session.expires_at,
            "release_digest": release_digest,
            "compile_context_digest": session.compile_context_digest,
            "target_fingerprint": session.target_fingerprint,
            "evidence_digest": evidence_digest,
            "mapping_confirmation_receipt_digest": mapping_confirmation_receipt_digest,
            "mapping_admission": mapping_admission,
            "mapping_identity_digest": _sha256(mapping_admission.model_dump(mode="json")),
            "targetd_authority_head_digest": targetd_authority.authority_head_digest if targetd_authority else None,
            "targetd_catalog_head_digest": targetd_authority.catalog_head_digest if targetd_authority else None,
            "calls": planned,
        }
        canonical = {key: (value.model_dump(mode="json") if hasattr(value, "model_dump") else value) for key, value in payload.items()}
        canonical["calls"] = [call.model_dump(mode="json") for call in planned]
        canonical["mapping_admission"] = mapping_admission.model_dump(mode="json")
        canonical["mode"] = session.mode.value
        canonical["created_at"] = session.created_at.isoformat().replace("+00:00", "Z")
        canonical["expires_at"] = session.expires_at.isoformat().replace("+00:00", "Z")
        return cls.model_validate({**payload, "plan_digest": _sha256(canonical)})


class TraceJournalRecord(StrictModel):
    schema_version: Literal["rolo-release-bound-trace-journal/v1"] = "rolo-release-bound-trace-journal/v1"
    revision: int = Field(ge=1)
    previous_record_digest: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    plan_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    state: SessionState
    calls: int = Field(ge=0, le=10_000)
    evidence_ids: tuple[str, ...] = Field(default=(), max_length=20_000)
    limitations: tuple[str, ...] = Field(default=(), max_length=20_000)
    operation_ids: tuple[str, ...] = Field(default=(), max_length=10_000)
    artifact_index_ref: str | None = Field(default=None, max_length=1_024)
    diagnosis_attempts: int = Field(ge=0, le=8)
    recovery_attempts: int = Field(ge=0, le=8)
    resume_count: int = Field(ge=0)
    event: TraceEvent
    record_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")

    def unsigned_payload(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude={"record_digest"})

    @model_validator(mode="after")
    def validate_digest(self) -> TraceJournalRecord:
        if self.event.sequence != self.revision:
            raise ValueError("Trace journal event sequence mismatch")
        if self.record_digest != _sha256(self.unsigned_payload()):
            raise ValueError("Trace journal record digest mismatch")
        return self

    @classmethod
    def build(
        cls,
        session: TraceSession,
        *,
        plan_digest: str,
        previous_record_digest: str | None,
    ) -> TraceJournalRecord:
        event = session.events[-1]
        payload = {
            "schema_version": "rolo-release-bound-trace-journal/v1",
            "revision": event.sequence,
            "previous_record_digest": previous_record_digest,
            "plan_digest": plan_digest,
            "state": session.state,
            "calls": session.calls,
            "evidence_ids": tuple(session.evidence_ids),
            "limitations": tuple(session.limitations),
            "operation_ids": tuple(session.operation_ids),
            "artifact_index_ref": session.artifact_index_ref,
            "diagnosis_attempts": session.diagnosis_attempts,
            "recovery_attempts": session.recovery_attempts,
            "resume_count": session.resume_count,
            "event": event,
        }
        canonical = {key: (value.model_dump(mode="json") if hasattr(value, "model_dump") else value) for key, value in payload.items()}
        canonical["state"] = session.state.value
        return cls.model_validate({**payload, "record_digest": _sha256(canonical)})


class TargetdTraceReceiptSidecar(StrictModel):
    schema_version: Literal["rolo-targetd-trace-receipt-sidecar/v1"] = "rolo-targetd-trace-receipt-sidecar/v1"
    plan_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    call_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    session_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
    target_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
    idempotency_key: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
    receipt: TargetdCallReceipt
    sidecar_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")

    def unsigned_payload(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude={"sidecar_digest"})

    @model_validator(mode="after")
    def validate_identity(self) -> TargetdTraceReceiptSidecar:
        if (
            self.receipt.session_id != self.session_id
            or self.receipt.target_id != self.target_id
            or self.receipt.idempotency_key != self.idempotency_key
        ):
            raise ValueError("targetd Trace sidecar identity mismatch")
        if self.sidecar_digest != _sha256(self.unsigned_payload()):
            raise ValueError("targetd Trace sidecar digest mismatch")
        return self

    @classmethod
    def build(
        cls,
        plan: TracePlan,
        call: TracePlanCall,
        receipt: TargetdCallReceipt,
    ) -> TargetdTraceReceiptSidecar:
        payload = {
            "schema_version": "rolo-targetd-trace-receipt-sidecar/v1",
            "plan_digest": plan.plan_digest,
            "call_digest": call.call_digest,
            "session_id": plan.session_id,
            "target_id": plan.target_id,
            "idempotency_key": call.idempotency_key,
            "receipt": receipt,
        }
        canonical = {**payload, "receipt": receipt.model_dump(mode="json")}
        return cls.model_validate({**payload, "sidecar_digest": _sha256(canonical)})

    @property
    def canonical_text(self) -> str:
        return _canonical_bytes(self.model_dump(mode="json")).decode("ascii") + "\n"


class DurableTraceStore:
    """Append-only Trace plan/journal/receipt store with immutable snapshots."""

    def __init__(self, root: str | Path) -> None:
        self.root = Path(os.path.abspath(os.fspath(root)))
        _assert_safe_directory(self.root)
        self.root.mkdir(parents=True, exist_ok=True)
        _assert_safe_directory(self.root)

    def _directory(self, target_id: str, session_id: str) -> Path:
        if _ID.fullmatch(target_id) is None or _ID.fullmatch(session_id) is None:
            raise ValueError("TRACE_STORE_IDENTITY_INVALID")
        target = self.root / target_id
        directory = target / session_id
        _assert_safe_directory(target)
        _assert_safe_directory(directory)
        return directory

    def create_plan(self, plan: TracePlan) -> Path:
        plan = TracePlan.model_validate(plan.model_dump(mode="python"))
        directory = self._directory(plan.target_id, plan.session_id)
        path = directory / "trace-plan.json"
        with interprocess_lock(directory / "trace-store", stale_after_s=None):
            directory.mkdir(parents=True, exist_ok=True)
            if path.exists():
                existing = self.load_plan(plan.target_id, plan.session_id)
                if existing != plan:
                    raise ValueError("TRACE_PLAN_IDENTITY_COLLISION")
                return path
            atomic_write_text(path, plan.model_dump_json(indent=2) + "\n", acquire_lock=False, require_absent=True)
        return path

    def load_plan(self, target_id: str, session_id: str) -> TracePlan:
        path = self._directory(target_id, session_id) / "trace-plan.json"
        if path.is_symlink() or _is_reparse(path) or not path.is_file() or path.stat().st_size > 4 * 1024 * 1024:
            raise ValueError("TRACE_PLAN_ARTIFACT_INVALID")
        try:
            return TracePlan.model_validate(loads_unique_json(path.read_text(encoding="utf-8")))
        except (OSError, TypeError, ValueError) as exc:
            raise ValueError("TRACE_PLAN_ARTIFACT_INVALID") from exc

    def checkpoint(self, session: TraceSession, *, plan_digest: str) -> None:
        if not session.events:
            raise ValueError("TRACE_JOURNAL_EVENT_REQUIRED")
        directory = self._directory(session.target_id, session.session_id)
        lock = directory / "trace-store"
        journal = directory / "trace-journal.jsonl"
        with interprocess_lock(lock, stale_after_s=None):
            plan = self.load_plan(session.target_id, session.session_id)
            if plan.plan_digest != plan_digest:
                raise ValueError("TRACE_JOURNAL_PLAN_MISMATCH")
            records = self._load_journal_unlocked(plan, journal)
            if len(session.events) == len(records):
                if records and records[-1].event == session.events[-1]:
                    return
                raise ValueError("TRACE_JOURNAL_REVISION_COLLISION")
            if len(session.events) != len(records) + 1:
                raise ValueError("TRACE_JOURNAL_REVISION_GAP")
            record = TraceJournalRecord.build(
                session,
                plan_digest=plan_digest,
                previous_record_digest=records[-1].record_digest if records else None,
            )
            encoded = record.model_dump_json() + "\n"
            size = journal.stat().st_size if journal.exists() else 0
            if size + len(encoded.encode("utf-8")) > _MAX_JOURNAL_BYTES:
                raise ValueError("TRACE_JOURNAL_SIZE_LIMIT")
            if journal.is_symlink() or _is_reparse(journal):
                raise ValueError("TRACE_JOURNAL_ARTIFACT_UNSAFE")
            with journal.open("a", encoding="utf-8", newline="") as stream:
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())

    def load_session(self, target_id: str, session_id: str) -> tuple[TracePlan, TraceSession]:
        plan = self.load_plan(target_id, session_id)
        journal = self._directory(target_id, session_id) / "trace-journal.jsonl"
        with interprocess_lock(self._directory(target_id, session_id) / "trace-store", stale_after_s=None):
            records = self._load_journal_unlocked(plan, journal)
        if not records:
            raise ValueError("TRACE_JOURNAL_EMPTY")
        last = records[-1]
        session = TraceSession(
            session_id=plan.session_id,
            target_id=plan.target_id,
            catalog_digest=plan.catalog_digest,
            task=plan.task,
            mode=plan.mode,
            state=last.state,
            created_at=plan.created_at,
            expires_at=plan.expires_at,
            max_calls=plan.max_calls,
            operator_id=plan.operator_id,
            safety_confirmed=plan.safety_confirmed,
            calls=last.calls,
            events=[record.event for record in records],
            evidence_ids=list(last.evidence_ids),
            limitations=list(last.limitations),
            release_digest=plan.release_digest,
            compile_context_digest=plan.compile_context_digest,
            target_fingerprint=plan.target_fingerprint,
            scope=plan.scope,
            operation_ids=list(last.operation_ids),
            artifact_index_ref=last.artifact_index_ref,
            diagnosis_attempts=last.diagnosis_attempts,
            recovery_attempts=last.recovery_attempts,
            resume_count=last.resume_count,
        )
        return plan, session

    def _load_journal_unlocked(self, plan: TracePlan, path: Path) -> list[TraceJournalRecord]:
        if not path.exists():
            return []
        if path.is_symlink() or _is_reparse(path) or not path.is_file() or path.stat().st_size > _MAX_JOURNAL_BYTES:
            raise ValueError("TRACE_JOURNAL_ARTIFACT_INVALID")
        records: list[TraceJournalRecord] = []
        previous: str | None = None
        try:
            with path.open("r", encoding="utf-8") as stream:
                for revision, line in enumerate(stream, 1):
                    if not line.endswith("\n"):
                        raise ValueError("truncated record")
                    record = TraceJournalRecord.model_validate(loads_unique_json(line))
                    if (
                        record.revision != revision
                        or record.plan_digest != plan.plan_digest
                        or record.previous_record_digest != previous
                        or record.event.session_id != plan.session_id
                        or record.event.run_id != plan.session_id
                        or record.event.target_id != plan.target_id
                    ):
                        raise ValueError("journal chain mismatch")
                    records.append(record)
                    previous = record.record_digest
        except (OSError, TypeError, ValueError) as exc:
            raise ValueError("TRACE_JOURNAL_ARTIFACT_INVALID") from exc
        return records

    def persist_receipt(self, plan: TracePlan, sidecar: TargetdTraceReceiptSidecar) -> Path:
        plan = TracePlan.model_validate(plan.model_dump(mode="python"))
        sidecar = TargetdTraceReceiptSidecar.model_validate(sidecar.model_dump(mode="python"))
        if sidecar.plan_digest != plan.plan_digest or sidecar.session_id != plan.session_id or sidecar.target_id != plan.target_id:
            raise ValueError("TRACE_RECEIPT_PLAN_MISMATCH")
        name = hashlib.sha256(sidecar.idempotency_key.encode("utf-8")).hexdigest() + ".json"
        directory = self._directory(plan.target_id, plan.session_id) / "receipts"
        path = directory / name
        with interprocess_lock(self._directory(plan.target_id, plan.session_id) / "trace-store", stale_after_s=None):
            directory.mkdir(parents=True, exist_ok=True)
            if path.exists():
                existing = TargetdTraceReceiptSidecar.model_validate(loads_unique_json(path.read_text(encoding="utf-8")))
                if existing != sidecar:
                    raise ValueError("TRACE_RECEIPT_IDENTITY_COLLISION")
                return path
            atomic_write_text(path, sidecar.canonical_text, acquire_lock=False, require_absent=True)
        return path

    def receipts(self, plan: TracePlan) -> tuple[tuple[TargetdTraceReceiptSidecar, Path], ...]:
        directory = self._directory(plan.target_id, plan.session_id) / "receipts"
        if not directory.exists():
            return ()
        _assert_safe_directory(directory)
        result: list[tuple[TargetdTraceReceiptSidecar, Path]] = []
        for path in sorted(directory.iterdir(), key=lambda item: item.name):
            if not re.fullmatch(r"[0-9a-f]{64}\.json", path.name) or path.is_symlink() or _is_reparse(path) or not path.is_file():
                raise ValueError("TRACE_RECEIPT_ARTIFACT_INVALID")
            sidecar = TargetdTraceReceiptSidecar.model_validate(loads_unique_json(path.read_text(encoding="utf-8")))
            if sidecar.plan_digest != plan.plan_digest:
                raise ValueError("TRACE_RECEIPT_PLAN_MISMATCH")
            result.append((sidecar, path))
        if len({sidecar.idempotency_key for sidecar, _ in result}) != len(result):
            raise ValueError("TRACE_RECEIPT_DUPLICATE")
        return tuple(result)

    def snapshot(self, plan: TracePlan, session: TraceSession, *, binding: Mapping[str, Any]) -> dict[str, Path]:
        loaded_plan, loaded_session = self.load_session(plan.target_id, plan.session_id)
        if loaded_plan != plan or loaded_session != session:
            raise ValueError("TRACE_SNAPSHOT_JOURNAL_MISMATCH")
        revision = len(session.events)
        directory = self._directory(plan.target_id, plan.session_id) / "snapshots" / f"{revision:08d}"
        index_path = directory / "artifact-index.json"
        if index_path.exists():
            return self._verify_snapshot(directory, plan, session)
        directory.mkdir(parents=True, exist_ok=False)
        session = session.model_copy(update={"artifact_index_ref": f"artifact://{index_path.as_posix()}"})
        files: dict[str, Path] = {
            "plan": directory / "trace-plan.json",
            "session": directory / "trace-session.json",
            "events": directory / "trace-events.jsonl",
            "evidence": directory / "trace-evidence-bundle.json",
            "binding": directory / "release-binding.json",
        }
        write_new_artifact(files["plan"], plan.model_dump_json(indent=2) + "\n")
        write_new_artifact(files["session"], session.model_dump_json(indent=2) + "\n")
        write_new_artifact(
            files["events"],
            "".join(_canonical_bytes(event.model_dump(mode="json")).decode("ascii") + "\n" for event in session.events),
        )
        write_new_artifact(
            files["evidence"],
            json.dumps(
                {
                    "schema_version": "rolo-release-bound-trace-evidence/v1",
                    "plan_digest": plan.plan_digest,
                    "session_id": session.session_id,
                    "target_id": session.target_id,
                    "state": session.state.value,
                    "evidence_ids": session.evidence_ids,
                    "limitations": session.limitations,
                },
                ensure_ascii=True,
                sort_keys=True,
                indent=2,
            )
            + "\n",
        )
        write_new_artifact(files["binding"], json.dumps(dict(binding), ensure_ascii=True, sort_keys=True, indent=2) + "\n")
        for sidecar, _ in self.receipts(plan):
            name = f"targetd-receipt-{sidecar.call_digest[7:23]}.json"
            path = directory / name
            write_new_artifact(path, sidecar.canonical_text)
            files[f"receipt:{sidecar.idempotency_key}"] = path
        index = build_artifact_index(
            run_id=session.session_id,
            target_id=session.target_id,
            files=list(files.values()),
            root=directory,
        )
        write_new_artifact(index_path, index.model_dump_json(indent=2) + "\n")
        files["index"] = index_path
        return files

    def _verify_snapshot(self, directory: Path, plan: TracePlan, session: TraceSession) -> dict[str, Path]:
        index_path = directory / "artifact-index.json"
        if index_path.is_symlink() or _is_reparse(index_path):
            raise ValueError("TRACE_SNAPSHOT_INDEX_INVALID")
        try:
            index = ArtifactIndex.model_validate(loads_unique_json(index_path.read_text(encoding="utf-8")))
            index.verify()
        except (OSError, TypeError, ValueError) as exc:
            raise ValueError("TRACE_SNAPSHOT_INDEX_INVALID") from exc
        if index.run_id != session.session_id or index.target_id != plan.target_id:
            raise ValueError("TRACE_SNAPSHOT_INDEX_IDENTITY_MISMATCH")
        paths: dict[str, Path] = {"index": index_path}
        aliases = {
            "trace-plan.json": "plan",
            "trace-session.json": "session",
            "trace-events.jsonl": "events",
            "trace-evidence-bundle.json": "evidence",
            "release-binding.json": "binding",
        }
        for artifact in index.artifacts:
            relative = artifact.get("path")
            digest = artifact.get("sha256")
            if not isinstance(relative, str) or not isinstance(digest, str) or Path(relative).name != relative:
                raise ValueError("TRACE_SNAPSHOT_INDEX_PATH_INVALID")
            path = directory / relative
            if path.is_symlink() or _is_reparse(path) or not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
                raise ValueError("TRACE_SNAPSHOT_ARTIFACT_INVALID")
            paths[aliases.get(relative, f"receipt:{relative}")] = path
        required = {"plan", "session", "events", "evidence", "binding", "index"}
        if not required <= set(paths):
            raise ValueError("TRACE_SNAPSHOT_INCOMPLETE")
        return paths


@dataclass(frozen=True)
class TargetdTraceResponse:
    frame: ProtocolFrame
    sequence_correlated: bool


@dataclass(frozen=True)
class TargetdTraceRequestRecord:
    request_json: bytes
    content_digest: str
    request_digest: str
    created_at: datetime
    timeout_s: float


class TargetdTraceAdapter:
    """Trace adapter that accepts only exact current targetd receipts.

    Read-only R0 calls are constructed as v2 requests.  A physical authority
    can be used only when a caller supplies a factory that returns a complete
    v3 request with independently produced motion-safety evidence.  The
    adapter never manufactures, downgrades, or bypasses that admission.
    """

    formal_targetd_trace = True

    def __init__(
        self,
        authority: TargetdExecutionAuthority,
        *,
        authority_resolver: Callable[[str], TargetdExecutionAuthority],
        call: Callable[[ExecutionRequest], TargetdTraceResponse],
        query: Callable[[str], TargetdTraceResponse] | None = None,
        clock: Callable[[], datetime] | None = None,
        request_store: MutableMapping[str, TargetdTraceRequestRecord] | None = None,
        physical_request_factory: Callable[
            [TracePlan, TracePlanCall, TargetdExecutionAuthority, datetime],
            ExecutionRequestV3,
        ]
        | None = None,
    ) -> None:
        self.authority = TargetdExecutionAuthority.model_validate(authority.model_dump(mode="python"))
        self.physical = requires_motion_safety(self.authority)
        if self.physical and physical_request_factory is None:
            raise ProtocolError("TARGETD_TRACE_V3_REQUEST_FACTORY_REQUIRED")
        self.authority_resolver = authority_resolver
        self.call = call
        self.query = query
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.request_store = request_store if request_store is not None else {}
        if not bool(getattr(self.request_store, "durable_targetd_request_store", False)):
            raise ProtocolError("TARGETD_TRACE_DURABLE_REQUEST_STORE_REQUIRED")
        self.physical_request_factory = physical_request_factory
        self._request_lock = Lock()
        self._plans: dict[str, TracePlan] = {}
        self._receipt_sink: Callable[[TracePlan, TargetdTraceReceiptSidecar], Any] | None = None

    @classmethod
    def from_journey_client(
        cls,
        authority: TargetdExecutionAuthority,
        client: Any,
        *,
        authority_resolver: Callable[[str], TargetdExecutionAuthority],
        clock: Callable[[], datetime] | None = None,
        request_store: MutableMapping[str, TargetdTraceRequestRecord] | None = None,
        physical_request_factory: Callable[
            [TracePlan, TracePlanCall, TargetdExecutionAuthority, datetime],
            ExecutionRequestV3,
        ]
        | None = None,
    ) -> TargetdTraceAdapter:
        from rolo.targetd.transport import JourneySessionClient

        if not isinstance(client, JourneySessionClient):
            raise TypeError("client must be a JourneySessionClient")

        def call(request: ExecutionRequest) -> TargetdTraceResponse:
            return TargetdTraceResponse(client.call_remote(request), True)

        def query(key: str) -> TargetdTraceResponse:
            return TargetdTraceResponse(client.query_call(key), True)

        return cls(
            authority,
            authority_resolver=authority_resolver,
            call=call,
            query=query,
            clock=clock,
            request_store=request_store,
            physical_request_factory=physical_request_factory,
        )

    def bind_plan(
        self,
        plan: TracePlan,
        *,
        receipt_sink: Callable[[TracePlan, TargetdTraceReceiptSidecar], Any],
    ) -> None:
        self._require_current_authority()
        if (
            plan.session_id != self.authority.mapping_admission.journey_session_id
            or plan.target_id != self.authority.target_id
            or plan.release_digest != self.authority.release_digest
            or plan.compile_context_digest != self.authority.context_digest
            or plan.target_fingerprint != self.authority.target_fingerprint
            or plan.mapping_confirmation_receipt_digest != self.authority.mapping_confirmation_receipt_digest
            or plan.mapping_admission != self.authority.mapping_admission
            or plan.targetd_authority_head_digest != self.authority.authority_head_digest
            or plan.targetd_catalog_head_digest != self.authority.catalog_head_digest
            or any(call.tool_id != self.authority.tool_id for call in plan.calls)
        ):
            raise ProtocolError("TARGETD_TRACE_PLAN_IDENTITY_MISMATCH")
        if self.physical and (
            plan.mode != RunMode.SUPERVISED_FIELD_DEBUG
            or not plan.safety_confirmed
            or not plan.operator_id
        ):
            raise ProtocolError("TARGETD_TRACE_SUPERVISED_PLAN_REQUIRED")
        self._plans[plan.session_id] = plan
        self._receipt_sink = receipt_sink
        # Materialize every exact request, including signed v3 motion
        # evidence, before the first CALL crosses the transport boundary.
        for planned_call in plan.calls:
            self._request_for(plan, planned_call)

    def validate_current_plan(self, plan: TracePlan) -> None:
        bound = self._plans.get(plan.session_id)
        if bound is not None and bound != plan:
            raise ProtocolError("TARGETD_TRACE_PLAN_IDENTITY_COLLISION")
        self._require_current_authority()
        if plan.targetd_authority_head_digest != self.authority.authority_head_digest:
            raise ProtocolError("TARGETD_TRACE_AUTHORITY_HEAD_CHANGED")

    def __call__(
        self,
        tool_id: str,
        arguments: Mapping[str, Any],
        session_id: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        plan, call = self._context(tool_id, arguments, session_id, idempotency_key)
        request = self._request_for(plan, call)
        try:
            response = self.call(request)
            receipt = self._receipt(response, request, expected_kind=FrameKind.CALL)
        except Exception as exc:
            raise TimeoutError("TARGETD_TRACE_OUTCOME_UNKNOWN") from exc
        sidecar = TargetdTraceReceiptSidecar.build(plan, call, receipt)
        if self._receipt_sink is None:
            raise ProtocolError("TARGETD_TRACE_RECEIPT_SINK_REQUIRED")
        self._receipt_sink(plan, sidecar)
        return self._safe_result(receipt)

    def reconcile(self, plan: TracePlan, call: TracePlanCall) -> tuple[dict[str, Any], str, str] | None:
        self.validate_current_plan(plan)
        if self.query is None:
            raise ProtocolError("TARGETD_TRACE_RECEIPT_RECONCILER_REQUIRED")
        request = self._load_request(plan, call)
        response = self.query(call.idempotency_key)
        if (
            not isinstance(response, TargetdTraceResponse)
            or response.sequence_correlated is not True
            or response.frame.payload.get("receipt") is None
        ):
            return None
        receipt = self._receipt(response, request, expected_kind=FrameKind.QUERY_CALL)
        sidecar = TargetdTraceReceiptSidecar.build(plan, call, receipt)
        if self._receipt_sink is None:
            raise ProtocolError("TARGETD_TRACE_RECEIPT_SINK_REQUIRED")
        self._receipt_sink(plan, sidecar)
        return self._safe_result(receipt), receipt.status, f"targetd-trace-receipt:{sidecar.sidecar_digest}"

    def _context(
        self,
        tool_id: str,
        arguments: Mapping[str, Any],
        session_id: str,
        idempotency_key: str,
    ) -> tuple[TracePlan, TracePlanCall]:
        self._require_current_authority()
        plan = self._plans.get(session_id)
        if plan is None:
            raise ProtocolError("TARGETD_TRACE_PLAN_REQUIRED")
        matches = [call for call in plan.calls if call.idempotency_key == idempotency_key]
        if len(matches) != 1 or matches[0].tool_id != tool_id or matches[0].arguments != dict(arguments):
            raise ProtocolError("TARGETD_TRACE_CALL_NOT_PLANNED")
        return plan, matches[0]

    def _require_current_authority(self) -> None:
        try:
            current = self.authority_resolver(self.authority.tool_id)
            current = TargetdExecutionAuthority.model_validate(current.model_dump(mode="python"))
        except Exception as exc:
            raise ProtocolError("TARGETD_TRACE_CURRENT_AUTHORITY_UNAVAILABLE") from exc
        if current != self.authority:
            raise ProtocolError("TARGETD_TRACE_AUTHORITY_NOT_CURRENT")

    def _request_for(self, plan: TracePlan, call: TracePlanCall) -> ExecutionRequest:
        with self._request_lock:
            record = self.request_store.get(call.idempotency_key)
            if record is not None:
                return self._validate_record(record, plan, call)
            now = self.clock()
            if now.tzinfo is None or now.utcoffset() != timedelta(0):
                raise ProtocolError("TARGETD_TRACE_CLOCK_INVALID")
            if self.physical:
                assert self.physical_request_factory is not None
                produced = self.physical_request_factory(plan, call, self.authority, now)
                try:
                    request = validate_execution_request(produced)
                except (TypeError, ValueError) as exc:
                    raise ProtocolError("TARGETD_TRACE_V3_REQUEST_INVALID") from exc
                if not isinstance(request, ExecutionRequestV3):
                    raise ProtocolError("TARGETD_TRACE_V3_REQUEST_REQUIRED")
            else:
                request = ExecutionRequest(
                    schema_version="rolo-execution-request/v2",
                    run_id=plan.plan_id,
                    session_id=plan.session_id,
                    target_id=plan.target_id,
                    idempotency_key=call.idempotency_key,
                    bundle_digest=self.authority.bundle_digest,
                    binding_digest=self.authority.binding_digest,
                    surface_digest=self.authority.surface_digest,
                    release_digest=plan.release_digest,
                    context_digest=plan.compile_context_digest,
                    mapping_confirmation_receipt_digest=plan.mapping_confirmation_receipt_digest,
                    authority_head_digest=self.authority.authority_head_digest,
                    fence_epoch=self.authority.fence_epoch,
                    provider_id=self.authority.provider_id,
                    provider_operation=self.authority.provider_operation,
                    authority=self.authority,
                    arguments=dict(call.arguments),
                    mode=self.authority.mode,
                    deadline=now + timedelta(seconds=call.timeout_s),
                )
            self._validate_request_identity(request, plan, call)
            encoded = _canonical_bytes(request.model_dump(mode="json"))
            self.request_store[call.idempotency_key] = TargetdTraceRequestRecord(
                request_json=encoded,
                content_digest=hashlib.sha256(encoded).hexdigest(),
                request_digest=request.request_digest(),
                created_at=now,
                timeout_s=call.timeout_s,
            )
            return request

    def _load_request(self, plan: TracePlan, call: TracePlanCall) -> ExecutionRequestLike:
        with self._request_lock:
            record = self.request_store.get(call.idempotency_key)
            if record is None:
                raise ProtocolError("TARGETD_TRACE_REQUEST_RECORD_MISSING")
            return self._validate_record(record, plan, call)

    def _validate_record(self, value: Any, plan: TracePlan, call: TracePlanCall) -> ExecutionRequestLike:
        if not isinstance(value, TargetdTraceRequestRecord):
            raise ProtocolError("TARGETD_TRACE_REQUEST_STORE_INVALID")
        try:
            if hashlib.sha256(value.request_json).hexdigest() != value.content_digest or value.timeout_s != call.timeout_s:
                raise ValueError
            request = validate_execution_request(loads_unique_json(value.request_json.decode("ascii")))
            if request.request_digest() != value.request_digest or request.deadline != value.created_at + timedelta(seconds=value.timeout_s):
                raise ValueError
        except (TypeError, ValueError):
            raise ProtocolError("TARGETD_TRACE_REQUEST_STORE_INVALID") from None
        self._validate_request_identity(request, plan, call)
        return request

    def _validate_request_identity(
        self,
        request: ExecutionRequestLike,
        plan: TracePlan,
        call: TracePlanCall,
    ) -> None:
        expected = {
            "run_id": plan.plan_id,
            "session_id": plan.session_id,
            "target_id": plan.target_id,
            "idempotency_key": call.idempotency_key,
            "release_digest": plan.release_digest,
            "context_digest": plan.compile_context_digest,
            "mapping_confirmation_receipt_digest": plan.mapping_confirmation_receipt_digest,
            "authority_head_digest": self.authority.authority_head_digest,
            "arguments": dict(call.arguments),
            "authority": self.authority,
        }
        if any(getattr(request, field) != expected_value for field, expected_value in expected.items()):
            raise ProtocolError("TARGETD_TRACE_REQUEST_STORE_COLLISION")
        if request.deadline.tzinfo is None or request.deadline > plan.expires_at:
            raise ProtocolError("TARGETD_TRACE_REQUEST_DEADLINE_INVALID")
        if self.physical != isinstance(request, ExecutionRequestV3):
            raise ProtocolError("TARGETD_TRACE_REQUEST_VERSION_MISMATCH")

    @staticmethod
    def _receipt(
        response: TargetdTraceResponse,
        request: ExecutionRequestLike,
        *,
        expected_kind: FrameKind,
    ) -> TargetdCallReceipt:
        if not isinstance(response, TargetdTraceResponse) or response.sequence_correlated is not True:
            raise ProtocolError("TARGETD_TRACE_RESPONSE_METADATA_REQUIRED")
        frame = ProtocolFrame.model_validate(response.frame.model_dump(mode="python"))
        if (
            frame.kind != FrameKind.RESULT
            or frame.session_id != request.session_id
            or (expected_kind == FrameKind.CALL and frame.run_id != request.run_id)
            or (expected_kind == FrameKind.QUERY_CALL and frame.run_id is not None)
            or frame.payload.get("request_kind") != expected_kind.value
            or frame.payload.get("ok") is not True
        ):
            raise ProtocolError("TARGETD_TRACE_RESPONSE_IDENTITY_MISMATCH")
        raw = frame.payload.get("receipt")
        try:
            receipt = TargetdCallReceipt.model_validate(raw)
        except (TypeError, ValueError):
            raise ProtocolError("TARGETD_TRACE_RECEIPT_INVALID") from None
        expected = {
            "idempotency_key": request.idempotency_key,
            "session_id": request.session_id,
            "target_id": request.target_id,
            "bundle_digest": request.bundle_digest,
            "request_digest": request.request_digest(),
            "release_digest": request.release_digest,
            "context_digest": request.context_digest,
            "mapping_confirmation_receipt_digest": request.mapping_confirmation_receipt_digest,
            "authority_head_digest": request.authority_head_digest,
            "fence_epoch": request.fence_epoch,
            "provider_id": request.provider_id,
            "provider_operation": request.provider_operation,
            "provider_fence_digest": provider_fence_digest(request),
        }
        if receipt.status not in _TERMINAL or any(getattr(receipt, field) != value for field, value in expected.items()):
            raise ProtocolError("TARGETD_TRACE_RECEIPT_IDENTITY_MISMATCH")
        if receipt.status == "SUCCEEDED" and receipt.provider_started_at is None:
            raise ProtocolError("TARGETD_TRACE_RECEIPT_TIME_INVALID")
        if receipt.provider_started_at is not None and receipt.updated_at < receipt.provider_started_at:
            raise ProtocolError("TARGETD_TRACE_RECEIPT_TIME_INVALID")
        if any(_SAFE_REF.fullmatch(ref) is None for ref in (*receipt.evidence_refs, *receipt.artifact_refs)):
            raise ProtocolError("TARGETD_TRACE_RECEIPT_REF_INVALID")
        return receipt

    @classmethod
    def _safe_result(cls, receipt: TargetdCallReceipt) -> dict[str, Any]:
        raw = receipt.result or {}
        if not isinstance(raw, dict):
            raise ProtocolError("TARGETD_TRACE_RESULT_INVALID")
        cls._validate_value(raw)
        status = raw.get("status")
        if status is not None and str(status).upper() != receipt.status:
            raise ProtocolError("TARGETD_TRACE_RESULT_STATUS_MISMATCH")
        result = {**raw, "status": receipt.status}
        if len(_canonical_bytes(result)) > 512 * 1024:
            raise ProtocolError("TARGETD_TRACE_RESULT_TOO_LARGE")
        return result

    def trace_receipt_evidence(self, session_id: str, idempotency_key: str) -> tuple[str, ...]:
        """Return the durable exact-receipt evidence id for a completed CALL."""

        plan = self._plans.get(session_id)
        if plan is None or self._receipt_sink is None:
            return ()
        # The sink is authoritative; adapter-local result state is
        # intentionally not used for restart recovery.  Implementations may
        # expose a lookup method (DurableTraceStore does) through this bound
        # method's owner.
        owner = getattr(self._receipt_sink, "__self__", None)
        if not isinstance(owner, DurableTraceStore):
            return ()
        matches = [
            sidecar
            for sidecar, _ in owner.receipts(plan)
            if sidecar.idempotency_key == idempotency_key
        ]
        if len(matches) != 1:
            return ()
        return (f"targetd-trace-receipt:{matches[0].sidecar_digest}",)

    @classmethod
    def _validate_value(cls, value: Any) -> None:
        if isinstance(value, Mapping):
            if len(value) > 128:
                raise ProtocolError("TARGETD_TRACE_RESULT_TOO_LARGE")
            for key, item in value.items():
                if not isinstance(key, str) or _SENSITIVE.search(key):
                    raise ProtocolError("TARGETD_TRACE_RESULT_SENSITIVE")
                cls._validate_value(item)
            return
        if isinstance(value, (list, tuple)):
            if len(value) > 256:
                raise ProtocolError("TARGETD_TRACE_RESULT_TOO_LARGE")
            for item in value:
                cls._validate_value(item)
            return
        if value is not None and not isinstance(value, (str, int, float, bool)):
            raise ProtocolError("TARGETD_TRACE_RESULT_INVALID")
        if isinstance(value, str) and len(value) > 4096:
            raise ProtocolError("TARGETD_TRACE_RESULT_TOO_LARGE")


__all__ = [
    "DurableTraceStore",
    "TargetdTraceAdapter",
    "TargetdTraceReceiptSidecar",
    "TargetdTraceRequestRecord",
    "TargetdTraceResponse",
    "TraceJournalRecord",
    "TracePlan",
    "TracePlanCall",
]
