"""Reviewable integration seam between targetd calls and leased workers.

The current targetd stdio protocol is request/response synchronous: while a
CALL is executing, the same channel cannot deliver CANCEL/STOP.  Wiring a
background thread into that daemon would therefore create the appearance of
realtime cancellation without a process or protocol boundary that can uphold
it.  This module exposes the narrow backend contract needed for a future
daemon v3/isolated-process implementation while making the lifecycle
invariants executable in offline tests today.

The seam is deliberately opt-in and admits only one sealed read-only
capability: ``ros2-readonly/odom.sample`` with no arguments. Existing R0 CALL
behavior is untouched. A concrete backend must revalidate target authority at
``begin_provider`` and persist the targetd receipt at every boundary.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

from .lifecycle import (
    LeasedWorkerRuntime,
    WorkerCallKey,
    WorkerCompletion,
    WorkerControl,
    WorkerInterruptIntent,
    WorkerLeaseRecord,
    WorkerLeaseStore,
    WorkerStopSignal,
)
from .protocol import (
    ExecutionBundleManifest,
    ExecutionRequestLike,
    ProtocolError,
    TargetdCallReceipt,
    requires_motion_safety,
    validate_execution_request,
)

_OUTCOME_CODE = re.compile(r"^[A-Z][A-Z0-9_]{0,127}$")
_TERMINAL_RECEIPTS = frozenset({"SUCCEEDED", "FAILED", "STOPPED", "CANCELLED", "UNKNOWN", "NOT_ACCEPTED"})
_ACTIVE_RECEIPTS = frozenset({"ACCEPTED", "STARTED"})
_ACTIVE_LEASES = frozenset({"CLAIMED", "RUNNING", "CANCEL_REQUESTED", "STOP_REQUESTED"})
_LEASE_TO_RECEIPT = {
    "SUCCEEDED": "SUCCEEDED",
    "FAILED": "FAILED",
    "STOPPED": "STOPPED",
    "CANCELLED": "CANCELLED",
    "UNKNOWN": "UNKNOWN",
}
_MAX_RESULT_BYTES = 65_536
_SEALED_TOOL_ID = "app.observe.odom"
_SEALED_PROVIDER_ID = "ros2-readonly"
_SEALED_PROVIDER_OPERATION = "odom.sample"
_SEALED_MODE = "READ_ONLY"
_SEALED_OBSERVATION_CONTRACT = {
    "provider": _SEALED_PROVIDER_ID,
    "operation": _SEALED_PROVIDER_OPERATION,
    "mode": _SEALED_MODE,
}


class LeasedCallIntegrationError(ProtocolError):
    """Stable failure at the service/worker integration boundary."""


@dataclass(frozen=True)
class LeasedProviderOutcome:
    """Explicit outcome returned by the opt-in read-only test seam.

    Constructing this value does not imply process isolation or make an
    otherwise untrusted provider result authoritative.
    """

    completion: WorkerCompletion
    result: dict

    def __post_init__(self) -> None:
        if not isinstance(self.completion, WorkerCompletion) or not isinstance(self.result, dict):
            raise ValueError("leased provider outcome is invalid")
        try:
            encoded = json.dumps(
                self.result,
                allow_nan=False,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        except (TypeError, ValueError, UnicodeError) as exc:
            raise ValueError("leased provider result is not canonical JSON") from exc
        if len(encoded) > _MAX_RESULT_BYTES:
            raise ValueError("leased provider result exceeds 64 KiB")


@dataclass(frozen=True)
class LeasedCallSubmission:
    receipt: TargetdCallReceipt
    lease: WorkerLeaseRecord
    worker_started: bool
    replayed: bool


@dataclass(frozen=True)
class LeasedCallSnapshot:
    receipt: TargetdCallReceipt
    lease: WorkerLeaseRecord


@dataclass(frozen=True)
class LeasedInterruptResult:
    call_key: WorkerCallKey
    intent: WorkerInterruptIntent
    lease: WorkerLeaseRecord
    requested: bool
    acknowledged: bool


class LeasedCallBackend(Protocol):
    """Minimal durable TargetdService adapter required by the seam.

    Implementations must use compare-and-set transitions and must revalidate
    Mapping/current Release/provider fences in ``begin_provider``.  None of
    these methods may execute the provider itself.
    """

    def accept_call(
        self,
        request: ExecutionRequestLike,
        manifest: ExecutionBundleManifest,
        *,
        provider_id: str,
    ) -> TargetdCallReceipt: ...

    def begin_provider(
        self,
        request: ExecutionRequestLike,
        manifest: ExecutionBundleManifest,
        *,
        provider_id: str,
        lease: WorkerLeaseRecord,
    ) -> TargetdCallReceipt: ...

    def complete_provider(
        self,
        request: ExecutionRequestLike,
        manifest: ExecutionBundleManifest,
        *,
        provider_id: str,
        lease: WorkerLeaseRecord,
        outcome: LeasedProviderOutcome,
    ) -> TargetdCallReceipt: ...

    def query_receipt(self, call_key: WorkerCallKey) -> TargetdCallReceipt | None: ...

    def mark_unknown(
        self,
        call_key: WorkerCallKey,
        *,
        outcome_code: str,
    ) -> TargetdCallReceipt | None: ...


LeasedProviderFunction = Callable[[WorkerControl], LeasedProviderOutcome]


def validate_sealed_odom_r0_call(
    request: ExecutionRequestLike,
    manifest: ExecutionBundleManifest,
) -> tuple[ExecutionRequestLike, ExecutionBundleManifest]:
    """Validate the sole call shape admitted by experimental worker seams.

    This is a structural fence, not authorization to execute an arbitrary
    callback. Callers must still use a trusted read-only adapter and recheck
    target-owned authority at their provider boundary.
    """

    request = validate_execution_request(request)
    try:
        manifest = ExecutionBundleManifest.model_validate(manifest.model_dump(mode="python"))
    except (AttributeError, ValueError) as exc:
        raise LeasedCallIntegrationError("LEASED_MANIFEST_INVALID") from exc
    if requires_motion_safety(request.authority):
        raise LeasedCallIntegrationError("LEASED_PHYSICAL_PROCESS_ISOLATION_REQUIRED")
    authority = request.authority
    scope = authority.mapping_admission.scope
    if (
        request.provider_id != _SEALED_PROVIDER_ID
        or request.provider_operation != _SEALED_PROVIDER_OPERATION
        or request.mode != _SEALED_MODE
        or authority.mode != _SEALED_MODE
        or scope.operation_kind.value != "OBSERVE"
        or scope.access != "read"
        or scope.risk != "R0"
        or scope.operations != (_SEALED_PROVIDER_OPERATION,)
        or request.arguments != {}
        or manifest.observation_contract != _SEALED_OBSERVATION_CONTRACT
        or authority.tool_id != _SEALED_TOOL_ID
        or scope.tool_id != _SEALED_TOOL_ID
        or manifest.tool_id != _SEALED_TOOL_ID
        or request.bundle_digest != manifest.bundle_digest
        or request.binding_digest != manifest.binding_digest
        or request.target_id != authority.target_id
    ):
        raise LeasedCallIntegrationError("LEASED_READ_ONLY_CAPABILITY_REQUIRED")
    return request, manifest


class TargetdLeasedCallCoordinator:
    """Coordinate the one sealed R0 odometry CALL across durable stores.

    Provider execution occurs only after ``reserve`` durably writes a lease
    and the worker transitions it to RUNNING. CANCEL/STOP only modifies the
    lease request state; it never calls ``backend.mark_unknown`` or fabricates
    a terminal receipt as an acknowledgement. This in-process coordinator is
    not a generic provider host and is never a physical-motion capability.
    """

    def __init__(
        self,
        backend: LeasedCallBackend,
        lease_store: WorkerLeaseStore,
        *,
        supervisor_id: str,
        provider_id: str = "ros2-readonly",
        lease_ttl_s: float = 15.0,
        allow_in_process_readonly_test_seam: bool = False,
    ) -> None:
        # The current runtime is a cooperative thread, not an OS isolation
        # boundary. Requiring an exact opt-in prevents a caller from assuming
        # that merely constructing this test seam changes the default service
        # lifecycle or provides realtime physical STOP.
        if allow_in_process_readonly_test_seam is not True:
            raise LeasedCallIntegrationError("LEASED_IN_PROCESS_READONLY_TEST_SEAM_OPT_IN_REQUIRED")
        if provider_id != _SEALED_PROVIDER_ID:
            raise LeasedCallIntegrationError("LEASED_PROVIDER_NOT_SEALED_READ_ONLY")
        self.backend = backend
        self.lease_store = lease_store
        self.provider_id = provider_id
        self.lease_ttl_s = lease_ttl_s
        self.runtime = LeasedWorkerRuntime(
            lease_store,
            supervisor_id=supervisor_id,
        )
        # All store mutations must use the UUID-suffixed runtime incarnation,
        # never the reusable configuration prefix supplied by the caller.
        self.supervisor_id = self.runtime.supervisor_id
        self.reconcile_startup()

    def submit(
        self,
        request: ExecutionRequestLike,
        manifest: ExecutionBundleManifest,
        *,
        worker_id: str,
        execute: LeasedProviderFunction,
        stop_signal: WorkerStopSignal | None = None,
    ) -> LeasedCallSubmission:
        request, manifest = self._require_generic_identity(request, manifest)
        call_key = self._call_key(request)
        existing = self.lease_store.load(call_key)
        if existing is not None:
            snapshot = self.query(call_key)
            return LeasedCallSubmission(
                receipt=snapshot.receipt,
                lease=snapshot.lease,
                worker_started=False,
                replayed=True,
            )

        # Reserve before TargetdService can persist STARTED or expose any
        # provider boundary. Concurrent submissions race on this durable CAS.
        claim = self.runtime.reserve(
            call_key,
            worker_id=worker_id,
            lease_ttl_s=self.lease_ttl_s,
            deadline_at=request.deadline,
        )
        try:
            receipt = self.backend.accept_call(
                request,
                manifest,
                provider_id=self.provider_id,
            )
            self._require_receipt_identity(receipt, call_key)
        except Exception:
            self.lease_store.fail_close(
                call_key,
                supervisor_id=self.supervisor_id,
                outcome_code="CALL_ADMISSION_FAILED",
            )
            raise

        if receipt.status != "ACCEPTED":
            lease = self.lease_store.fail_close(
                call_key,
                supervisor_id=self.supervisor_id,
                outcome_code="CALL_NOT_ACCEPTED_FOR_LEASE",
            )
            return LeasedCallSubmission(
                receipt=receipt,
                lease=lease,
                worker_started=False,
                replayed=True,
            )

        def run(control: WorkerControl) -> WorkerCompletion:
            # A heartbeat immediately before begin_provider rechecks both the
            # renewable lease and immutable request deadline.
            control.heartbeat()
            started = self.backend.begin_provider(
                request,
                manifest,
                provider_id=self.provider_id,
                lease=self._require_live_lease(call_key),
            )
            self._require_receipt_identity(started, call_key)
            if started.status != "STARTED" or started.provider_started_at is None:
                raise LeasedCallIntegrationError("LEASED_PROVIDER_START_NOT_PERSISTED")

            persisted_started = self.backend.query_receipt(call_key)
            if persisted_started is None:
                raise LeasedCallIntegrationError("LEASED_PROVIDER_START_NOT_PERSISTED")
            self._require_receipt_identity(persisted_started, call_key)
            if persisted_started.status != "STARTED" or persisted_started.provider_started_at is None:
                raise LeasedCallIntegrationError("LEASED_PROVIDER_START_NOT_PERSISTED")

            # begin_provider may have blocked long enough for the immutable
            # request deadline or lease heartbeat window to expire. Recheck
            # after its durable STARTED write and immediately before handing
            # control to the callback. This reduces the gap but is not atomic
            # with callback entry; that stronger boundary needs a duplex
            # protocol and an isolated process, so physical calls stay denied.
            callback_lease = control.heartbeat()
            if callback_lease.state != "RUNNING":
                raise LeasedCallIntegrationError("LEASED_PROVIDER_CALLBACK_FENCE_NOT_LIVE")

            outcome = execute(control)
            if not isinstance(outcome, LeasedProviderOutcome):
                raise LeasedCallIntegrationError("LEASED_PROVIDER_OUTCOME_INVALID")
            completion = outcome.completion
            if completion.status == "CANCELLED":
                terminal_lease = control.acknowledge_interrupt(
                    intent="CANCEL",
                    outcome_code=completion.outcome_code,
                )
            elif completion.status == "STOPPED":
                terminal_lease = control.acknowledge_interrupt(
                    intent="STOP",
                    outcome_code=completion.outcome_code,
                )
            else:
                terminal_lease = control.complete(
                    status=completion.status,
                    outcome_code=completion.outcome_code,
                )

            completed = self.backend.complete_provider(
                request,
                manifest,
                provider_id=self.provider_id,
                lease=terminal_lease,
                outcome=outcome,
            )
            self._require_receipt_identity(completed, call_key)
            if completed.status != completion.status:
                raise LeasedCallIntegrationError("LEASED_PROVIDER_TERMINAL_STATUS_MISMATCH")
            return completion

        try:
            self.runtime.start_reserved(
                claim,
                work=run,
                stop_signal=stop_signal,
            )
        except Exception:
            self._mark_receipt_unknown_if_active(
                call_key,
                outcome_code="WORKER_START_FAILED",
            )
            raise
        return LeasedCallSubmission(
            receipt=receipt,
            lease=claim.lease,
            worker_started=True,
            replayed=False,
        )

    def request_interrupt(
        self,
        call_key: WorkerCallKey,
        *,
        intent: WorkerInterruptIntent,
    ) -> LeasedInterruptResult:
        record = self.runtime.request_interrupt(call_key, intent=intent)
        acknowledgement = record.stop_acknowledgement
        requested_state = "CANCEL_REQUESTED" if intent == "CANCEL" else "STOP_REQUESTED"
        terminal_state = "CANCELLED" if intent == "CANCEL" else "STOPPED"
        return LeasedInterruptResult(
            call_key=call_key,
            intent=intent,
            lease=record,
            requested=record.state in {requested_state, terminal_state},
            acknowledged=(acknowledgement is not None and acknowledgement.intent == intent and acknowledgement.call_key == call_key),
        )

    def query(self, call_key: WorkerCallKey) -> LeasedCallSnapshot:
        lease = self.lease_store.reconcile(
            call_key,
            supervisor_id=self.supervisor_id,
        )
        receipt = self.backend.query_receipt(call_key)
        if receipt is None:
            raise LeasedCallIntegrationError("LEASED_CALL_RECEIPT_MISSING")
        self._require_receipt_identity(receipt, call_key)

        if lease.state in _ACTIVE_LEASES and receipt.status in _TERMINAL_RECEIPTS:
            lease = self.lease_store.fail_close(
                call_key,
                supervisor_id=self.supervisor_id,
                outcome_code="RECEIPT_TERMINAL_LEASE_ACTIVE",
            )
        if lease.state not in _ACTIVE_LEASES and receipt.status in _ACTIVE_RECEIPTS:
            receipt = self._mark_receipt_unknown_if_active(
                call_key,
                outcome_code="LEASE_TERMINAL_RECEIPT_UNFINALIZED",
            )
            if receipt is None:
                raise LeasedCallIntegrationError("LEASED_CALL_RECEIPT_MISSING")

        expected = _LEASE_TO_RECEIPT.get(lease.state)
        if expected is not None and receipt.status in _TERMINAL_RECEIPTS and receipt.status not in {expected, "NOT_ACCEPTED", "UNKNOWN"}:
            raise LeasedCallIntegrationError("LEASED_CALL_TERMINAL_STATE_MISMATCH")
        return LeasedCallSnapshot(receipt=receipt, lease=lease)

    def join(self, call_key: WorkerCallKey, *, timeout_s: float | None = None) -> LeasedCallSnapshot:
        self.runtime.join(call_key, timeout_s)
        return self.query(call_key)

    def reconcile_startup(self) -> tuple[LeasedCallSnapshot, ...]:
        """Project orphan/expired leases to UNKNOWN targetd receipts."""

        snapshots: list[LeasedCallSnapshot] = []
        for lease in self.lease_store.list_records():
            receipt = self.backend.query_receipt(lease.call_key)
            # A crash between reserve and accept has no receipt and no
            # provider boundary. Keep the UNKNOWN lease as the audit record.
            if receipt is None:
                continue
            snapshots.append(self.query(lease.call_key))
        return tuple(snapshots)

    def _mark_receipt_unknown_if_active(
        self,
        call_key: WorkerCallKey,
        *,
        outcome_code: str,
    ) -> TargetdCallReceipt | None:
        if _OUTCOME_CODE.fullmatch(outcome_code) is None:
            raise LeasedCallIntegrationError("LEASED_CALL_OUTCOME_CODE_INVALID")
        receipt = self.backend.query_receipt(call_key)
        if receipt is None or receipt.status not in _ACTIVE_RECEIPTS:
            return receipt
        updated = self.backend.mark_unknown(call_key, outcome_code=outcome_code)
        if updated is not None:
            self._require_receipt_identity(updated, call_key)
            if updated.status != "UNKNOWN":
                raise LeasedCallIntegrationError("LEASED_CALL_UNKNOWN_NOT_PERSISTED")
        return updated

    def _require_live_lease(self, call_key: WorkerCallKey) -> WorkerLeaseRecord:
        lease = self.lease_store.load(call_key)
        if lease is None or lease.state != "RUNNING":
            raise LeasedCallIntegrationError("LEASED_PROVIDER_START_WITHOUT_RUNNING_LEASE")
        return lease

    def _require_generic_identity(
        self,
        request: ExecutionRequestLike,
        manifest: ExecutionBundleManifest,
    ) -> tuple[ExecutionRequestLike, ExecutionBundleManifest]:
        if self.provider_id != _SEALED_PROVIDER_ID:
            raise LeasedCallIntegrationError("LEASED_PROVIDER_NOT_SEALED_READ_ONLY")
        return validate_sealed_odom_r0_call(request, manifest)

    @staticmethod
    def _call_key(request: ExecutionRequestLike) -> WorkerCallKey:
        return WorkerCallKey.from_request(request)

    @staticmethod
    def _require_receipt_identity(
        receipt: TargetdCallReceipt,
        call_key: WorkerCallKey,
    ) -> None:
        try:
            receipt = TargetdCallReceipt.model_validate(receipt.model_dump(mode="python"))
        except (AttributeError, ValueError) as exc:
            raise LeasedCallIntegrationError("LEASED_CALL_RECEIPT_INVALID") from exc
        if (
            receipt.target_id != call_key.target_id
            or receipt.session_id != call_key.session_id
            or receipt.idempotency_key != call_key.idempotency_key
            or receipt.request_digest != call_key.request_digest
            or receipt.provider_id != _SEALED_PROVIDER_ID
            or receipt.provider_operation != _SEALED_PROVIDER_OPERATION
        ):
            raise LeasedCallIntegrationError("LEASED_CALL_RECEIPT_IDENTITY_MISMATCH")
