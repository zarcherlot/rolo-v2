"""Opt-in OS-process worker substrate for one sealed read-only call.

The production daemon can wire this substrate only through an explicit
``--process-readonly-worker`` opt-in. It admits only ``app.observe.odom`` through
``ros2-readonly/odom.sample`` in ``READ_ONLY`` mode with no arguments. The
spawned process is an isolation and liveness boundary, not authorization for
an arbitrary callback and not a physical-motion safety mechanism.

Control messages use bounded canonical JSON over ``Connection.send_bytes``;
``Connection.send``/``recv`` pickle transport is never used. Multiprocessing
still uses local pickle for the trusted spawn bootstrap, so workers must be
explicitly marked, bounded and spawn-picklable.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import multiprocessing
import pickle
import queue
import re
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from multiprocessing.connection import Connection
from pathlib import Path
from typing import Literal, Protocol

from rolo.dsl.parser import loads_unique_json

from .lifecycle import (
    WorkerCallKey,
    WorkerCompletion,
    WorkerControl,
    WorkerInterruptIntent,
    WorkerLeaseClaim,
    WorkerLeaseRecord,
    WorkerLeaseStore,
    WorkerLifecycleError,
    new_worker_supervisor_incarnation,
)
from .lifecycle_integration import LeasedProviderOutcome, validate_sealed_odom_r0_call
from .protocol import ExecutionBundleManifest, ExecutionRequestLike

_IPC_SCHEMA = "rolo-targetd-process-worker-ipc/v1"
_MAX_IPC_BYTES = 65_536
_MAX_SPAWN_WORKER_BYTES = 65_536
_MAX_PROCESS_WORKERS = 32
_SEALED_PROVIDER_ID = "ros2-readonly"
_SEALED_PROVIDER_OPERATION = "odom.sample"
_SEALED_MODE = "READ_ONLY"
_OUTCOME_CODE = re.compile(r"^[A-Z][A-Z0-9_]{0,127}$")
_ACTIVE_STATES = frozenset({"CLAIMED", "RUNNING", "CANCEL_REQUESTED", "STOP_REQUESTED"})
_PHYSICAL_GATE_URI = re.compile(r"^artifact://targetd/physical-provider-gates/[0-9a-f]{64}/[0-9a-f]{64}$")
_PHYSICAL_GATE_DIGEST_URI = re.compile(r"^digest://sha256/[0-9a-f]{64}$")
_PHYSICAL_STOP_WAIT_S = 6.0


class ProcessWorkerError(WorkerLifecycleError):
    """Stable failure at the local process/IPC boundary."""


class SealedOdomProcessWorker(Protocol):
    """Spawn-safe adapter marker required by the experimental substrate."""

    provider_id: str
    provider_operation: str
    mode: str
    physical_capable: bool

    def __call__(self, control: ProcessWorkerControl) -> LeasedProviderOutcome: ...


class PreparedPhysicalProcessWork(Protocol):
    """Child-owned ARMED_ZERO provider handle."""

    def arm_receipt(self) -> dict[str, object]: ...

    def execute(self, control: ProcessWorkerControl) -> LeasedProviderOutcome: ...

    def stop(
        self,
        control: ProcessWorkerControl,
        *,
        intent: WorkerInterruptIntent,
    ) -> LeasedProviderOutcome: ...


class SealedPhysicalProcessWorker(Protocol):
    """Exact two-stage physical adapter accepted only by explicit runtime."""

    provider_id: str
    provider_operation: str
    mode: str
    physical_capable: bool
    requires_armed_zero: bool
    sealed_profile: str
    expected_call_key_digest: str
    request_digest: str
    target_id: str
    call_id: str
    session_id: str
    execution_subject_digest: str
    runtime_sha256: str

    def prepare(
        self,
        control: ProcessWorkerControl,
    ) -> PreparedPhysicalProcessWork: ...


class ProcessWorkerControl:
    """Cooperative child-process view of heartbeat and duplex interrupts."""

    def __init__(self, durable: WorkerControl) -> None:
        self._durable = durable
        self._interrupt_event = threading.Event()
        self._abort_event = threading.Event()
        self._interrupt: WorkerInterruptIntent | None = None
        self._lock = threading.Lock()

    @property
    def call_key(self) -> WorkerCallKey:
        return self._durable.call_key

    def heartbeat(self) -> WorkerLeaseRecord:
        return self._durable.heartbeat()

    def interrupt_intent(self) -> WorkerInterruptIntent | None:
        with self._lock:
            observed = self._interrupt
        return observed or self._durable.interrupt_intent()

    def wait_for_interrupt(self, timeout_s: float | None = None) -> WorkerInterruptIntent | None:
        timeout_s = _require_wait_timeout(timeout_s)
        self._interrupt_event.wait(timeout_s)
        return self.interrupt_intent()

    def aborted(self) -> bool:
        """Report that the process supervisor is leaving fail-closed."""

        return self._abort_event.is_set()

    def _signal_interrupt(self, intent: WorkerInterruptIntent) -> None:
        with self._lock:
            if self._interrupt is not None and self._interrupt != intent:
                raise ProcessWorkerError("PROCESS_WORKER_INTERRUPT_CONFLICT")
            self._interrupt = intent
            self._interrupt_event.set()

    def _signal_abort(self) -> None:
        self._abort_event.set()
        self._interrupt_event.set()


ProcessWorkerFunction = Callable[[ProcessWorkerControl], LeasedProviderOutcome]


@dataclass(frozen=True)
class ProcessWorkerSubmission:
    call_key: WorkerCallKey
    lease: WorkerLeaseRecord
    process_id: int


@dataclass(frozen=True)
class PhysicalProcessWorkerPreparation:
    """Live zero-only child awaiting one target-owned START decision."""

    call_key: WorkerCallKey
    lease: WorkerLeaseRecord
    process_id: int
    armed_zero: object


@dataclass(frozen=True)
class ProcessWorkerInterruptResult:
    call_key: WorkerCallKey
    intent: WorkerInterruptIntent
    lease: WorkerLeaseRecord
    requested: bool
    acknowledged: bool


@dataclass(frozen=True)
class ProcessWorkerSnapshot:
    lease: WorkerLeaseRecord
    outcome: LeasedProviderOutcome | None
    process_exit_code: int | None
    ipc_outcome_code: str | None


@dataclass
class _ProcessHandle:
    call_key: WorkerCallKey
    claim: WorkerLeaseClaim
    process: multiprocessing.Process
    connection: Connection
    next_sequence: int = 1
    send_lock: threading.Lock = field(default_factory=threading.Lock)
    done: threading.Event = field(default_factory=threading.Event)
    outcome: LeasedProviderOutcome | None = None
    ipc_outcome_code: str | None = None
    monitor: threading.Thread | None = None
    terminal_commit: Callable[[ProcessWorkerSnapshot], None] | None = None
    physical: bool = False
    armed_zero: object | None = None
    phase: Literal["RUNNING", "ARMED_ZERO", "START_SENT", "TERMINAL"] = "RUNNING"
    work_started: threading.Event = field(default_factory=threading.Event)
    interrupt_sent: WorkerInterruptIntent | None = None


class LeasedProcessWorkerRuntime:
    """Spawn one bounded child process for an exact sealed odometry call.

    The caller must opt in explicitly. The child main loop owns automatic
    lease heartbeats and duplex control while a daemon thread runs the trusted
    read-only adapter. Only that child, holding the lease token, writes normal
    completion or stop acknowledgement. Parent-side crash observation can
    only downgrade an active call to ``UNKNOWN``.
    """

    def __init__(
        self,
        store: WorkerLeaseStore,
        *,
        supervisor_id: str,
        allow_spawn_readonly_substrate: bool = False,
        allow_spawn_physical_substrate: bool = False,
        physical_start_gate: Callable[[WorkerLeaseClaim, object], object] | None = None,
        physical_container: str = "MentorPi",
        physical_container_user: str = "ubuntu",
        max_processes: int = 8,
    ) -> None:
        if (allow_spawn_readonly_substrate is True) == (allow_spawn_physical_substrate is True):
            raise ProcessWorkerError("PROCESS_WORKER_EXPLICIT_OPT_IN_REQUIRED")
        if isinstance(max_processes, bool) or not isinstance(max_processes, int) or not 1 <= max_processes <= _MAX_PROCESS_WORKERS:
            raise ProcessWorkerError("PROCESS_WORKER_CAPACITY_INVALID")
        if physical_start_gate is not None and (allow_spawn_physical_substrate is not True or not callable(physical_start_gate)):
            raise ProcessWorkerError("PROCESS_WORKER_START_GATE_INVALID")
        if (
            not isinstance(physical_container, str)
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", physical_container)
            or not isinstance(physical_container_user, str)
            or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,63}", physical_container_user)
        ):
            raise ProcessWorkerError("PROCESS_WORKER_PHYSICAL_CONTAINER_INVALID")
        self.store = store
        self.supervisor_name = supervisor_id
        self.supervisor_id = new_worker_supervisor_incarnation(supervisor_id)
        self.max_processes = max_processes
        self.allow_spawn_readonly_substrate = allow_spawn_readonly_substrate
        self.allow_spawn_physical_substrate = allow_spawn_physical_substrate
        self.physical_start_gate = physical_start_gate
        self.physical_container = physical_container
        self.physical_container_user = physical_container_user
        self._context = multiprocessing.get_context("spawn")
        self._handles: dict[str, _ProcessHandle] = {}
        self._lock = threading.RLock()
        self._slots_in_use = 0
        recovery_failed = False
        if self.allow_spawn_physical_substrate:
            try:
                from .physical_worker import recover_persisted_armed_zero

                for record in self.store.list_records():
                    if (
                        record.armed_zero is not None
                        and record.result_committed_at is None
                        and record.state in _ACTIVE_STATES | {"UNKNOWN"}
                        and not recover_persisted_armed_zero(
                            record.armed_zero,
                            expected_call_key_digest=record.call_key_digest,
                            expected_target_id=record.call_key.target_id,
                            expected_call_id=record.call_key.idempotency_key,
                            expected_session_id=record.call_key.session_id,
                            expected_request_digest=record.call_key.request_digest,
                            expected_execution_subject_digest=(record.physical_execution_subject_digest or ""),
                            expected_runtime_sha256=(record.physical_runtime_sha256 or ""),
                            container=self.physical_container,
                            container_user=self.physical_container_user,
                        )
                    ):
                        recovery_failed = True
            except Exception:
                recovery_failed = True
        self.store.reconcile_all(supervisor_id=self.supervisor_id)
        if recovery_failed:
            raise ProcessWorkerError("PROCESS_WORKER_PHYSICAL_RECOVERY_UNPROVED")

    def bind_physical_start_gate(
        self,
        gate: Callable[[WorkerLeaseClaim, object], object],
    ) -> None:
        """One-time bind the targetd-owned START transaction callback."""

        if self.allow_spawn_physical_substrate is not True or not callable(gate):
            raise ProcessWorkerError("PROCESS_WORKER_START_GATE_INVALID")
        with self._lock:
            if self.physical_start_gate is not None or self._handles or self._slots_in_use != 0:
                raise ProcessWorkerError("PROCESS_WORKER_START_GATE_ALREADY_BOUND")
            self.physical_start_gate = gate

    def submit(
        self,
        request: ExecutionRequestLike,
        manifest: ExecutionBundleManifest,
        *,
        worker_id: str,
        work: ProcessWorkerFunction,
        lease_ttl_s: float = 2.0,
        heartbeat_interval_s: float = 0.1,
        startup_timeout_s: float = 10.0,
        start_gate: Callable[[WorkerLeaseClaim], None] | None = None,
        terminal_commit: Callable[[ProcessWorkerSnapshot], None] | None = None,
    ) -> ProcessWorkerSubmission:
        if self.allow_spawn_readonly_substrate is not True:
            raise ProcessWorkerError("PROCESS_WORKER_READONLY_PROFILE_REQUIRED")
        request, manifest = validate_sealed_odom_r0_call(request, manifest)
        self._require_sealed_worker(work)
        self._require_timing(
            lease_ttl_s=lease_ttl_s,
            heartbeat_interval_s=heartbeat_interval_s,
            startup_timeout_s=startup_timeout_s,
        )
        try:
            encoded_worker = pickle.dumps(work, protocol=pickle.HIGHEST_PROTOCOL)
        except (AttributeError, pickle.PickleError, TypeError) as exc:
            raise ProcessWorkerError("PROCESS_WORKER_NOT_SPAWN_PICKLABLE") from exc
        if len(encoded_worker) > _MAX_SPAWN_WORKER_BYTES:
            raise ProcessWorkerError("PROCESS_WORKER_SPAWN_SPEC_TOO_LARGE")

        call_key = WorkerCallKey.from_request(request)
        self._reserve_capacity_slot()
        slot_owned_by_monitor = False
        try:
            claim = self.store.claim(
                call_key,
                supervisor_id=self.supervisor_id,
                worker_id=worker_id,
                lease_ttl_s=lease_ttl_s,
                deadline_at=request.deadline,
            )
            try:
                parent_connection, child_connection = self._context.Pipe(duplex=True)
                process = self._context.Process(
                    target=_child_process_main,
                    args=(
                        child_connection,
                        str(self.store.root),
                        self.store.max_leases,
                        self.store.max_state_bytes,
                        claim,
                        work,
                        heartbeat_interval_s,
                        startup_timeout_s,
                    ),
                    name=f"rolo-odom-{call_key.digest()[:12]}",
                    daemon=True,
                )
            except BaseException as exc:
                self._mark_crashed(claim, "PROCESS_WORKER_STARTUP_FAILED")
                raise ProcessWorkerError("PROCESS_WORKER_STARTUP_FAILED") from exc

            try:
                process.start()
                child_connection.close()
                ready = _receive_message(parent_connection, startup_timeout_s)
                _require_message(
                    ready,
                    kind="READY",
                    sequence=0,
                    call_key=call_key,
                    auth_key=claim.lease_token,
                )
                lease = self.store.reconcile(call_key, supervisor_id=self.supervisor_id)
                if lease.state != "RUNNING":
                    raise ProcessWorkerError("PROCESS_WORKER_NOT_RUNNING_AT_START_GATE")
                if start_gate is not None:
                    # The in-memory bearer claim lets a target-owned service
                    # prove this is the exact runtime lease; a caller-supplied
                    # RUNNING record is not a process-start capability.
                    start_gate(claim)
                _send_message(
                    parent_connection,
                    _message(
                        "START",
                        sequence=0,
                        call_key=call_key,
                        auth_key=claim.lease_token,
                    ),
                )
                work_started = _receive_message(parent_connection, startup_timeout_s)
                _require_message(
                    work_started,
                    kind="WORK_STARTED",
                    sequence=1,
                    call_key=call_key,
                    auth_key=claim.lease_token,
                )
            except BaseException as exc:
                child_connection.close()
                parent_connection.close()
                _terminate_process(process)
                self._mark_crashed(claim, "PROCESS_WORKER_STARTUP_FAILED")
                if isinstance(exc, ProcessWorkerError):
                    raise
                raise ProcessWorkerError("PROCESS_WORKER_STARTUP_FAILED") from exc

            if process.pid is None:
                parent_connection.close()
                _terminate_process(process)
                self._mark_crashed(claim, "PROCESS_WORKER_STARTUP_FAILED")
                raise ProcessWorkerError("PROCESS_WORKER_STARTUP_FAILED")
            handle = _ProcessHandle(
                call_key=call_key,
                claim=claim,
                process=process,
                connection=parent_connection,
                terminal_commit=terminal_commit,
            )
            monitor = threading.Thread(
                target=self._monitor,
                args=(handle,),
                name=f"rolo-odom-monitor-{call_key.digest()[:12]}",
                daemon=True,
            )
            handle.monitor = monitor
            with self._lock:
                self._handles[call_key.digest()] = handle
            try:
                monitor.start()
            except BaseException as exc:
                with self._lock:
                    if self._handles.get(call_key.digest()) is handle:
                        self._handles.pop(call_key.digest(), None)
                parent_connection.close()
                _terminate_process(process)
                self._mark_crashed(claim, "PROCESS_WORKER_MONITOR_START_FAILED")
                raise ProcessWorkerError("PROCESS_WORKER_MONITOR_START_FAILED") from exc
            slot_owned_by_monitor = True
            return ProcessWorkerSubmission(
                call_key=call_key,
                lease=lease,
                process_id=process.pid,
            )
        finally:
            if not slot_owned_by_monitor:
                self._release_capacity_slot()

    def prepare_physical(
        self,
        request: ExecutionRequestLike,
        manifest: ExecutionBundleManifest,
        *,
        worker_id: str,
        work: SealedPhysicalProcessWorker,
        lease_ttl_s: float = 15.0,
        heartbeat_interval_s: float = 0.1,
        startup_timeout_s: float = 15.0,
        terminal_commit: Callable[[ProcessWorkerSnapshot], None] | None = None,
    ) -> PhysicalProcessWorkerPreparation:
        """Spawn one sealed worker and stop at authenticated ARMED_ZERO."""

        if self.allow_spawn_physical_substrate is not True:
            raise ProcessWorkerError("PROCESS_WORKER_PHYSICAL_PROFILE_REQUIRED")
        try:
            from .physical_worker import validate_landerpi_rotate_process_call

            request, manifest = validate_landerpi_rotate_process_call(
                request,
                manifest,
            )
        except Exception as exc:
            if isinstance(exc, ProcessWorkerError):
                raise
            raise ProcessWorkerError("PROCESS_WORKER_PHYSICAL_CALL_NOT_SEALED") from exc
        self._require_physical_worker(work, request, manifest)
        self._require_timing(
            lease_ttl_s=lease_ttl_s,
            heartbeat_interval_s=heartbeat_interval_s,
            startup_timeout_s=startup_timeout_s,
        )
        try:
            encoded_worker = pickle.dumps(work, protocol=pickle.HIGHEST_PROTOCOL)
        except (AttributeError, pickle.PickleError, TypeError) as exc:
            raise ProcessWorkerError("PROCESS_WORKER_NOT_SPAWN_PICKLABLE") from exc
        if len(encoded_worker) > _MAX_SPAWN_WORKER_BYTES:
            raise ProcessWorkerError("PROCESS_WORKER_SPAWN_SPEC_TOO_LARGE")

        call_key = WorkerCallKey.from_request(request)
        self._reserve_capacity_slot()
        slot_owned_by_monitor = False
        try:
            claim = self.store.claim(
                call_key,
                supervisor_id=self.supervisor_id,
                worker_id=worker_id,
                lease_ttl_s=lease_ttl_s,
                deadline_at=request.deadline,
                physical_execution_subject_digest=request.execution_subject_digest,
                physical_runtime_sha256=manifest.observation_contract["provider_runtime_sha256"],
            )
            try:
                parent_connection, child_connection = self._context.Pipe(duplex=True)
                process = self._context.Process(
                    target=_child_physical_process_main,
                    args=(
                        child_connection,
                        str(self.store.root),
                        self.store.max_leases,
                        self.store.max_state_bytes,
                        claim,
                        work,
                        heartbeat_interval_s,
                        startup_timeout_s,
                    ),
                    name=f"rolo-physical-{call_key.digest()[:12]}",
                    daemon=True,
                )
            except BaseException as exc:
                self._mark_crashed(claim, "PROCESS_WORKER_STARTUP_FAILED")
                raise ProcessWorkerError("PROCESS_WORKER_STARTUP_FAILED") from exc
            armed_zero = None
            try:
                process.start()
                child_connection.close()
                armed_message = _receive_message(
                    parent_connection,
                    startup_timeout_s,
                )
                if (
                    armed_message is not None
                    and armed_message.get("kind") == "FAULT"
                ):
                    _require_message(
                        armed_message,
                        kind="FAULT",
                        sequence=2,
                        call_key=call_key,
                        auth_key=claim.lease_token,
                    )
                    raise ProcessWorkerError(
                        _require_outcome_code(armed_message.get("outcome_code"))
                    )
                _require_message(
                    armed_message,
                    kind="ARMED_ZERO",
                    sequence=0,
                    call_key=call_key,
                    auth_key=claim.lease_token,
                )
                assert armed_message is not None
                armed_zero = _parse_physical_armed_zero(
                    armed_message["armed_zero"],
                    work=work,
                )
                armed_payload = armed_zero.as_dict()
                lease = self.store.record_armed_zero(
                    claim,
                    armed_zero=armed_payload,
                )
                if lease.state != "RUNNING":
                    raise ProcessWorkerError("PROCESS_WORKER_NOT_RUNNING_AT_ARM")
            except BaseException as exc:
                child_connection.close()
                parent_connection.close()
                recovered = armed_zero is not None and self._recover_authenticated_physical_arm(
                    armed_zero,
                    claim.lease,
                )
                _terminate_process(process)
                self._mark_crashed(
                    claim,
                    ("PROCESS_WORKER_PREPARE_FAILED" if armed_zero is None or recovered else "PROCESS_WORKER_PHYSICAL_RECOVERY_UNPROVED"),
                )
                if isinstance(exc, ProcessWorkerError):
                    raise
                raise ProcessWorkerError("PROCESS_WORKER_PREPARE_FAILED") from exc
            if process.pid is None:
                parent_connection.close()
                self._recover_authenticated_physical_arm(armed_zero, claim.lease)
                _terminate_process(process)
                self._mark_crashed(claim, "PROCESS_WORKER_PREPARE_FAILED")
                raise ProcessWorkerError("PROCESS_WORKER_PREPARE_FAILED")
            handle = _ProcessHandle(
                call_key=call_key,
                claim=claim,
                process=process,
                connection=parent_connection,
                terminal_commit=terminal_commit,
                physical=True,
                armed_zero=armed_zero,
                phase="ARMED_ZERO",
            )
            monitor = threading.Thread(
                target=self._monitor,
                args=(handle,),
                name=f"rolo-physical-monitor-{call_key.digest()[:12]}",
                daemon=True,
            )
            handle.monitor = monitor
            with self._lock:
                self._handles[call_key.digest()] = handle
            try:
                monitor.start()
            except BaseException as exc:
                with self._lock:
                    if self._handles.get(call_key.digest()) is handle:
                        self._handles.pop(call_key.digest(), None)
                parent_connection.close()
                recovered = self._recover_persisted_physical_arm(handle)
                _terminate_process(process)
                self._mark_crashed(
                    claim,
                    ("PROCESS_WORKER_MONITOR_START_FAILED" if recovered else "PROCESS_WORKER_PHYSICAL_RECOVERY_UNPROVED"),
                )
                raise ProcessWorkerError("PROCESS_WORKER_MONITOR_START_FAILED") from exc
            slot_owned_by_monitor = True
            return PhysicalProcessWorkerPreparation(
                call_key=call_key,
                lease=lease,
                process_id=process.pid,
                armed_zero=armed_zero,
            )
        finally:
            if not slot_owned_by_monitor:
                self._release_capacity_slot()

    def start_prepared(
        self,
        call_key: WorkerCallKey,
        *,
        timeout_s: float = 10.0,
    ) -> ProcessWorkerSubmission:
        """Consume target gates, then release the same ARMED_ZERO child once."""

        timeout_s = _require_wait_timeout(timeout_s)
        if timeout_s is None or timeout_s <= 0:
            raise ProcessWorkerError("PROCESS_WORKER_START_GATE_INVALID")
        handle = self._require_handle(call_key)
        if not handle.physical or handle.armed_zero is None:
            raise ProcessWorkerError("PROCESS_WORKER_PREPARED_CALL_REQUIRED")
        start_gate = self.physical_start_gate
        if not callable(start_gate):
            self._stop_prepared_fail_closed(handle)
            raise ProcessWorkerError("PROCESS_WORKER_START_GATE_INVALID")
        try:
            with handle.send_lock:
                lease = self.store.reconcile(
                    call_key,
                    supervisor_id=self.supervisor_id,
                )
                if handle.phase != "ARMED_ZERO" or lease.state != "RUNNING":
                    raise ProcessWorkerError("PROCESS_WORKER_PREPARED_CALL_NOT_LIVE")
                start_attestation = start_gate(handle.claim, handle.armed_zero)
                self._require_target_start_attestation(
                    start_attestation,
                    call_key=call_key,
                    armed_zero=handle.armed_zero,
                )
                lease = self.store.heartbeat(handle.claim)
                if lease.state != "RUNNING":
                    raise ProcessWorkerError("PROCESS_WORKER_PREPARED_CALL_NOT_LIVE")
                _send_message(
                    handle.connection,
                    _message(
                        "START",
                        sequence=0,
                        call_key=call_key,
                        auth_key=handle.claim.lease_token,
                    ),
                )
                handle.phase = "START_SENT"
        except BaseException:
            # The inner worker is still zero-only if START was not sent. A
            # failed/burned target gate is always followed by authenticated
            # STOP rather than abandoning an armed process.
            self._stop_prepared_fail_closed(handle)
            raise
        deadline = time.monotonic() + timeout_s
        while not handle.work_started.is_set():
            if handle.done.is_set():
                snapshot = self.join(call_key, timeout_s=0.0)
                if snapshot.lease.state in {"STOPPED", "CANCELLED"}:
                    raise ProcessWorkerError("PROCESS_WORKER_START_ACK_LOST_STOP_CONFIRMED")
                raise ProcessWorkerError("PROCESS_WORKER_START_NOT_ACKNOWLEDGED")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                snapshot = self._stop_prepared_fail_closed(handle)
                if snapshot is not None and snapshot.lease.state in {"STOPPED", "CANCELLED"} and snapshot.lease.stop_acknowledgement is not None:
                    raise ProcessWorkerError("PROCESS_WORKER_START_ACK_LOST_STOP_CONFIRMED")
                raise ProcessWorkerError("PROCESS_WORKER_START_ACK_RECOVERY_REQUIRED")
            handle.work_started.wait(min(0.05, remaining))
        return ProcessWorkerSubmission(
            call_key=call_key,
            lease=self.store.reconcile(
                call_key,
                supervisor_id=self.supervisor_id,
            ),
            process_id=handle.process.pid or 0,
        )

    @staticmethod
    def _require_target_start_attestation(
        value: object,
        *,
        call_key: WorkerCallKey,
        armed_zero: object,
    ) -> None:
        """Accept only the service-owned, durable one-shot START artifact."""

        try:
            from .landerpi_motion_target import (
                DebugUserAttestedProviderGateReceipt,
            )
            from .motion_acceptance import ProviderGateConsumptionReceipt
            from .service import TargetdPhysicalProcessStart

            if type(value) is not TargetdPhysicalProcessStart:
                raise TypeError
            receipt = value.receipt
            gate = value.provider_gate
            artifact = gate.consume_artifact
            raw_arm = armed_zero.as_dict() if callable(getattr(armed_zero, "as_dict", None)) else armed_zero
            if not isinstance(raw_arm, Mapping):
                raise TypeError
            inner = raw_arm.get("inner_process_identity")
            gids = raw_arm.get("publisher_endpoint_gids")
            if not isinstance(inner, Mapping) or not isinstance(gids, list) or len(gids) != 1:
                raise TypeError
            expected_binding = {
                "schema_version": "rolo-landerpi-armed-zero-provider-binding/v1",
                "call_id": call_key.idempotency_key,
                "session_id": call_key.session_id,
                "execution_subject_digest": raw_arm.get("execution_subject_digest"),
                "publisher_identity": raw_arm.get("publisher_identity"),
                "publisher_gid": gids[0],
                "provider_pid": inner.get("pid"),
                "provider_start_time_ticks": inner.get("start_ticks"),
                "provider_runtime_sha256": raw_arm.get("provider_runtime_sha256"),
                "provider_cmdline_sha256": raw_arm.get("provider_cmdline_sha256"),
                "provider_runtime_identity_digest": raw_arm.get("provider_runtime_identity_digest"),
            }
            gate_refs = [ref for ref in receipt.evidence_refs if _PHYSICAL_GATE_URI.fullmatch(ref)]
            digest_refs = [ref for ref in receipt.evidence_refs if _PHYSICAL_GATE_DIGEST_URI.fullmatch(ref)]
            common_invalid = (
                receipt.status != "STARTED"
                or receipt.provider_started_at is None
                or receipt.target_id != call_key.target_id
                or receipt.session_id != call_key.session_id
                or receipt.idempotency_key != call_key.idempotency_key
                or receipt.request_digest != call_key.request_digest
                or receipt.provider_id != "ros-container"
                or receipt.provider_operation != "base.rotate"
                or len(gate_refs) != 1
                or len(digest_refs) != 1
                or gate.call_id != call_key.idempotency_key
                or gate.session_id != call_key.session_id
                or gate.target_id != call_key.target_id
                or artifact is None
                or artifact.kind != "PROVIDER_GATE_CONSUMED"
                or artifact.claims.get("provider_invocation_count") != 0
                or artifact.claims.get("armed_zero_provider_binding") != expected_binding
            )
            if isinstance(gate, ProviderGateConsumptionReceipt):
                gate_invalid = (
                    gate.status != "CONSUMED" or gate.consumed is not True or gate.provider_boundary_open is not True or gate.provider_invocation_limit != 1 or gate.motion_authorized is not False
                )
            elif isinstance(gate, DebugUserAttestedProviderGateReceipt):
                gate_invalid = (
                    gate.status != "DEBUG_CONSUMED"
                    or gate.report_status != "PASS_WITH_USER_ATTESTED_SITE_SAFETY"
                    or gate.debug_provider_boundary_open is not True
                    or gate.production_provider_boundary_open is not False
                    or gate.production_ready is not False
                    or gate.production_authority_verified is not False
                    or gate.fresh_estop_challenge_verified is not False
                    or gate.debug_motion_authorized is not True
                    or gate.provider_invocation_limit != 1
                    or gate.max_abs_rotation_degrees != 1.0
                    or gate.max_abs_linear_meters != 0.03
                    or artifact.claims.get("debug_gate_binding") is None
                )
            else:
                gate_invalid = True
            if common_invalid or gate_invalid:
                raise TypeError
        except Exception as exc:
            raise ProcessWorkerError("PROCESS_WORKER_START_GATE_REJECTED") from exc

    def _stop_prepared_fail_closed(
        self,
        handle: _ProcessHandle,
    ) -> ProcessWorkerSnapshot | None:
        """Request STOP, wait for proof, then exact-reap or persist UNKNOWN."""

        try:
            self.request_interrupt(handle.call_key, intent="STOP")
        except (ProcessWorkerError, WorkerLifecycleError):
            pass
        if handle.done.wait(_PHYSICAL_STOP_WAIT_S):
            try:
                return self.join(handle.call_key, timeout_s=0.0)
            except (ProcessWorkerError, WorkerLifecycleError):
                pass

        recovered = self._recover_persisted_physical_arm(handle)
        _terminate_process(handle.process)
        try:
            record = self._mark_crashed(
                handle.claim,
                ("PROCESS_WORKER_START_ACK_LOST_REAPED" if recovered else "PROCESS_WORKER_PHYSICAL_RECOVERY_UNPROVED"),
            )
        except ProcessWorkerError:
            return None
        return ProcessWorkerSnapshot(
            lease=record,
            outcome=_prepared_outcome(record),
            process_exit_code=handle.process.exitcode,
            ipc_outcome_code=record.outcome_code,
        )

    def request_interrupt(
        self,
        call_key: WorkerCallKey,
        *,
        intent: WorkerInterruptIntent,
    ) -> ProcessWorkerInterruptResult:
        handle = self._require_handle(call_key)
        with handle.send_lock:
            record = self.store.request_interrupt(call_key, intent=intent)
            acknowledgement = record.stop_acknowledgement
            if record.state in {"CANCEL_REQUESTED", "STOP_REQUESTED"} and handle.interrupt_sent is None:
                message = _message(
                    "INTERRUPT",
                    sequence=handle.next_sequence,
                    call_key=call_key,
                    auth_key=handle.claim.lease_token,
                    intent=intent,
                )
                try:
                    _send_message(handle.connection, message)
                except (OSError, ProcessWorkerError) as exc:
                    self._mark_crashed(handle.claim, "PROCESS_CONTROL_CHANNEL_FAILED")
                    _terminate_process(handle.process)
                    raise ProcessWorkerError("PROCESS_CONTROL_CHANNEL_FAILED") from exc
                handle.next_sequence += 1
                handle.interrupt_sent = intent
            elif record.state in {"CANCEL_REQUESTED", "STOP_REQUESTED"} and handle.interrupt_sent != intent:
                raise ProcessWorkerError("PROCESS_WORKER_INTERRUPT_CONFLICT")
        expected_terminal = "CANCELLED" if intent == "CANCEL" else "STOPPED"
        expected_requested = "CANCEL_REQUESTED" if intent == "CANCEL" else "STOP_REQUESTED"
        return ProcessWorkerInterruptResult(
            call_key=call_key,
            intent=intent,
            lease=record,
            requested=record.state in {expected_requested, expected_terminal},
            acknowledged=(acknowledgement is not None and acknowledgement.intent == intent and acknowledgement.call_key == call_key),
        )

    def join(
        self,
        call_key: WorkerCallKey,
        *,
        timeout_s: float | None = None,
    ) -> ProcessWorkerSnapshot:
        timeout_s = _require_wait_timeout(timeout_s)
        handle = self._require_handle(call_key)
        if not handle.done.wait(timeout_s):
            raise ProcessWorkerError("PROCESS_WORKER_JOIN_TIMEOUT")
        lease = self.store.reconcile(call_key, supervisor_id=self.supervisor_id)
        if lease.state in _ACTIVE_STATES:
            lease = self._mark_crashed(handle.claim, "PROCESS_WORKER_EXITED_WITHOUT_TERMINAL_STATE")
        if handle.outcome is not None and handle.outcome.completion.status != lease.state:
            raise ProcessWorkerError("PROCESS_WORKER_TERMINAL_STATE_MISMATCH")
        return ProcessWorkerSnapshot(
            lease=lease,
            outcome=handle.outcome,
            process_exit_code=handle.process.exitcode,
            ipc_outcome_code=handle.ipc_outcome_code,
        )

    def reconcile_snapshot(self, call_key: WorkerCallKey) -> ProcessWorkerSnapshot:
        """Read/reconcile a call without replaying it or waiting for exit."""

        call_key = WorkerCallKey.model_validate(call_key.model_dump(mode="python"))
        lease = self.store.reconcile(
            call_key,
            supervisor_id=self.supervisor_id,
        )
        with self._lock:
            handle = self._handles.get(call_key.digest())
        outcome = handle.outcome if handle is not None else None
        if outcome is None:
            outcome = _prepared_outcome(lease)
        return ProcessWorkerSnapshot(
            lease=lease,
            outcome=outcome,
            process_exit_code=(handle.process.exitcode if handle is not None else None),
            ipc_outcome_code=(handle.ipc_outcome_code if handle is not None else None),
        )

    def _monitor(self, handle: _ProcessHandle) -> None:
        fault_code: str | None = None
        record: WorkerLeaseRecord | None = None
        try:
            while True:
                if handle.connection.poll(0.05):
                    message = _receive_message(handle.connection, 0.0)
                    kind = message.get("kind")
                    if kind == "WORK_STARTED" and handle.physical:
                        _require_message(
                            message,
                            kind="WORK_STARTED",
                            sequence=1,
                            call_key=handle.call_key,
                            auth_key=handle.claim.lease_token,
                        )
                        with handle.send_lock:
                            if handle.phase != "START_SENT":
                                raise ProcessWorkerError("PROCESS_WORKER_START_ACK_INVALID")
                            handle.phase = "RUNNING"
                            handle.work_started.set()
                        continue
                    if kind == "TERMINAL":
                        _require_message(
                            message,
                            kind="TERMINAL",
                            sequence=2,
                            call_key=handle.call_key,
                            auth_key=handle.claim.lease_token,
                        )
                        completion = WorkerCompletion(
                            status=message["status"],
                            outcome_code=message["outcome_code"],
                        )
                        outcome = LeasedProviderOutcome(
                            completion=completion,
                            result=message["result"],
                        )
                        prepared = self.store.load(handle.call_key)
                        if _prepared_outcome(prepared) != outcome:
                            raise ProcessWorkerError("PROCESS_WORKER_PREPARED_RESULT_MISMATCH")
                        handle.outcome = outcome
                        handle.phase = "TERMINAL"
                        break
                    if kind == "FAULT":
                        _require_message(
                            message,
                            kind="FAULT",
                            sequence=2,
                            call_key=handle.call_key,
                            auth_key=handle.claim.lease_token,
                        )
                        fault_code = _require_outcome_code(message.get("outcome_code"))
                        break
                    raise ProcessWorkerError("PROCESS_WORKER_IPC_MESSAGE_INVALID")
                if not handle.process.is_alive():
                    fault_code = "PROCESS_WORKER_EXITED"
                    break
        except (EOFError, OSError, UnicodeError, ValueError, ProcessWorkerError):
            fault_code = "PROCESS_WORKER_IPC_INVALID"
            if not handle.physical:
                _terminate_process(handle.process)
        finally:
            handle.process.join(_PHYSICAL_STOP_WAIT_S if handle.physical else 1.0)
            if handle.process.is_alive():
                if handle.physical and self._recover_persisted_physical_arm(handle):
                    fault_code = fault_code or "PROCESS_WORKER_PHYSICAL_INNER_REAPED"
                _terminate_process(handle.process)
                fault_code = fault_code or "PROCESS_WORKER_DID_NOT_EXIT"
            try:
                record = self.store.load(handle.call_key)
                if record is not None and record.state in _ACTIVE_STATES:
                    record = self._mark_crashed(
                        handle.claim,
                        fault_code or "PROCESS_WORKER_EXITED_WITHOUT_TERMINAL_STATE",
                    )
                if handle.outcome is None:
                    handle.outcome = _prepared_outcome(record)
                if handle.terminal_commit is not None and record is not None:
                    snapshot = ProcessWorkerSnapshot(
                        lease=record,
                        outcome=handle.outcome,
                        process_exit_code=handle.process.exitcode,
                        ipc_outcome_code=fault_code,
                    )
                    try:
                        handle.terminal_commit(snapshot)
                        if record.prepared_result_digest is not None and handle.outcome is not None and record.state == handle.outcome.completion.status:
                            record = self.store.commit_prepared_result(
                                handle.call_key,
                                result_digest=record.prepared_result_digest,
                            )
                    except Exception:
                        fault_code = fault_code or "PROCESS_WORKER_RECEIPT_COMMIT_PENDING"
            except WorkerLifecycleError:
                # Corrupt or unavailable durable state must not strand join()
                # behind a dead monitor thread. join() will re-read the store
                # and fail closed instead of returning a guessed lifecycle.
                fault_code = fault_code or "PROCESS_WORKER_DURABLE_STATE_INVALID"
            finally:
                handle.ipc_outcome_code = fault_code
                handle.phase = "TERMINAL"
                handle.connection.close()
                self._release_capacity_slot()
                handle.done.set()

    def _recover_persisted_physical_arm(self, handle: _ProcessHandle) -> bool:
        raw_arm = handle.armed_zero.as_dict() if callable(getattr(handle.armed_zero, "as_dict", None)) else handle.armed_zero
        if raw_arm is None:
            record = self.store.load(handle.call_key)
            raw_arm = record.armed_zero if record is not None else None
        if raw_arm is None:
            return False
        record = self.store.load(handle.call_key)
        return self._recover_physical_arm_value(raw_arm, record=record)

    def _recover_physical_arm_value(
        self,
        raw_arm: object,
        *,
        record: WorkerLeaseRecord | None,
    ) -> bool:
        """Exact-reap one authenticated ARM using fixed runtime deployment."""

        try:
            from .physical_worker import recover_persisted_armed_zero

            as_dict = getattr(raw_arm, "as_dict", None)
            if callable(as_dict):
                raw_arm = as_dict()
            if record is None or record.physical_execution_subject_digest is None or record.physical_runtime_sha256 is None:
                return False

            return recover_persisted_armed_zero(
                raw_arm,
                expected_call_key_digest=record.call_key_digest,
                expected_target_id=record.call_key.target_id,
                expected_call_id=record.call_key.idempotency_key,
                expected_session_id=record.call_key.session_id,
                expected_request_digest=record.call_key.request_digest,
                expected_execution_subject_digest=(record.physical_execution_subject_digest),
                expected_runtime_sha256=record.physical_runtime_sha256,
                container=self.physical_container,
                container_user=self.physical_container_user,
            )
        except Exception:
            return False

    def _recover_authenticated_physical_arm(
        self,
        armed_zero: object,
        record: WorkerLeaseRecord,
    ) -> bool:
        """Reap a child ARM already authenticated against request/manifest."""

        try:
            from .physical_worker import recover_armed_zero_process

            arm_call_key_digest = getattr(armed_zero, "call_key_digest", None)
            arm_receipt_digest = getattr(armed_zero, "arm_receipt_digest", None)
            if (
                record.call_key_digest != arm_call_key_digest
                or not isinstance(arm_receipt_digest, str)
            ):
                return False
            return recover_armed_zero_process(
                armed_zero,
                expected_call_key_digest=record.call_key_digest,
                expected_arm_receipt_digest=arm_receipt_digest,
                container=self.physical_container,
                container_user=self.physical_container_user,
            )
        except Exception:
            return False

    def _reserve_capacity_slot(self) -> None:
        with self._lock:
            if self._slots_in_use >= self.max_processes:
                raise ProcessWorkerError("PROCESS_WORKER_CAPACITY_EXCEEDED")
            self._slots_in_use += 1

    def _release_capacity_slot(self) -> None:
        with self._lock:
            if self._slots_in_use > 0:
                self._slots_in_use -= 1

    def _require_handle(self, call_key: WorkerCallKey) -> _ProcessHandle:
        call_key = WorkerCallKey.model_validate(call_key.model_dump(mode="python"))
        with self._lock:
            handle = self._handles.get(call_key.digest())
        if handle is None or handle.call_key != call_key:
            raise ProcessWorkerError("PROCESS_WORKER_CALL_NOT_LOCAL")
        return handle

    def _mark_crashed(self, claim: WorkerLeaseClaim, outcome_code: str) -> WorkerLeaseRecord:
        try:
            record = self.store.mark_worker_crashed(claim, outcome_code=outcome_code)
        except WorkerLifecycleError:
            record = self.store.load(claim.lease.call_key)
            if record is None or record.state in _ACTIVE_STATES:
                raise ProcessWorkerError("PROCESS_WORKER_CRASH_RECONCILIATION_FAILED") from None
        if record.state in _ACTIVE_STATES:
            raise ProcessWorkerError("PROCESS_WORKER_CRASH_RECONCILIATION_FAILED")
        return record

    @staticmethod
    def _require_sealed_worker(work: ProcessWorkerFunction) -> None:
        if (
            not callable(work)
            or getattr(work, "provider_id", None) != _SEALED_PROVIDER_ID
            or getattr(work, "provider_operation", None) != _SEALED_PROVIDER_OPERATION
            or getattr(work, "mode", None) != _SEALED_MODE
            or getattr(work, "physical_capable", None) is not False
        ):
            raise ProcessWorkerError("PROCESS_WORKER_NOT_SEALED_ODOM_READONLY")

    @staticmethod
    def _require_physical_worker(
        work: SealedPhysicalProcessWorker,
        request: ExecutionRequestLike,
        manifest: ExecutionBundleManifest,
    ) -> None:
        call_key = WorkerCallKey.from_request(request)
        runtime_sha256 = manifest.observation_contract.get("provider_runtime_sha256")
        if (
            not callable(getattr(work, "prepare", None))
            or type(work).__module__ != "rolo.targetd.physical_worker"
            or type(work).__name__ != "LanderPiRotateProcessWorker"
            or getattr(work, "provider_id", None) != "ros-container"
            or getattr(work, "provider_operation", None) != "base.rotate"
            or getattr(work, "mode", None) != "SUPERVISED_FIELD_DEBUG"
            or getattr(work, "physical_capable", None) is not True
            or getattr(work, "requires_armed_zero", None) is not True
            or getattr(work, "sealed_profile", None) != "landerpi-bounded-rotate-v1"
            or getattr(work, "expected_call_key_digest", None) != call_key.digest()
            or getattr(work, "request_digest", None) != request.request_digest()
            or getattr(work, "target_id", None) != request.target_id
            or getattr(work, "call_id", None) != request.idempotency_key
            or getattr(work, "session_id", None) != request.session_id
            or getattr(work, "execution_subject_digest", None) != getattr(request, "execution_subject_digest", None)
            or not isinstance(runtime_sha256, str)
            or getattr(work, "runtime_sha256", None) != runtime_sha256
        ):
            raise ProcessWorkerError("PROCESS_WORKER_PHYSICAL_ADAPTER_NOT_SEALED")

    @staticmethod
    def _require_timing(
        *,
        lease_ttl_s: float,
        heartbeat_interval_s: float,
        startup_timeout_s: float,
    ) -> None:
        for value in (lease_ttl_s, heartbeat_interval_s, startup_timeout_s):
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ProcessWorkerError("PROCESS_WORKER_TIMING_INVALID")
        if not 0.1 <= float(lease_ttl_s) <= 300.0 or not 0.02 <= float(heartbeat_interval_s) < float(lease_ttl_s) / 2 or not 0.1 <= float(startup_timeout_s) <= 30.0:
            raise ProcessWorkerError("PROCESS_WORKER_TIMING_INVALID")


def _child_process_main(
    connection: Connection,
    store_root: str,
    max_leases: int,
    max_state_bytes: int,
    claim: WorkerLeaseClaim,
    work: ProcessWorkerFunction,
    heartbeat_interval_s: float,
    startup_timeout_s: float,
) -> None:
    store = WorkerLeaseStore(
        Path(store_root),
        max_leases=max_leases,
        max_state_bytes=max_state_bytes,
    )
    durable = WorkerControl(store, claim)
    control = ProcessWorkerControl(durable)
    call_key = claim.lease.call_key
    fault_sequence = 1
    provider: threading.Thread | None = None
    try:
        store.start(claim)
        _send_message(
            connection,
            _message(
                "READY",
                sequence=0,
                call_key=call_key,
                auth_key=claim.lease_token,
            ),
        )
        _child_wait_for_start(
            connection,
            control,
            call_key,
            heartbeat_interval_s=heartbeat_interval_s,
            startup_timeout_s=startup_timeout_s,
            auth_key=claim.lease_token,
        )
        running = control.heartbeat()
        if running.state != "RUNNING":
            raise ProcessWorkerError("PROCESS_WORKER_START_FENCE_NOT_LIVE")

        results: queue.Queue[tuple[str, object]] = queue.Queue(maxsize=1)
        callback_entered = threading.Event()
        callback_gate = threading.Event()

        def invoke() -> None:
            callback_entered.set()
            callback_gate.wait()
            try:
                results.put_nowait(("OUTCOME", work(control)))
            except Exception:
                results.put_nowait(("FAULT", "PROCESS_WORKER_EXCEPTION_AMBIGUOUS"))
            except BaseException:
                results.put_nowait(("FAULT", "PROCESS_WORKER_CRASH_OBSERVED"))

        provider = threading.Thread(
            target=invoke,
            name=f"rolo-odom-provider-{call_key.digest()[:12]}",
            daemon=True,
        )
        provider.start()
        if not callback_entered.wait(startup_timeout_s):
            raise ProcessWorkerError("PROCESS_WORKER_CALLBACK_THREAD_NOT_READY")
        _send_message(
            connection,
            _message(
                "WORK_STARTED",
                sequence=1,
                call_key=call_key,
                auth_key=claim.lease_token,
            ),
        )
        fault_sequence = 2
        callback_gate.set()
        _child_run_loop(
            connection,
            store,
            claim,
            control,
            call_key,
            results,
            heartbeat_interval_s=heartbeat_interval_s,
            terminal_sequence=2,
            auth_key=claim.lease_token,
        )
    except (EOFError, OSError, UnicodeError, ValueError, WorkerLifecycleError):
        control._signal_abort()
        _child_fail_closed(
            connection,
            store,
            claim,
            outcome_code="PROCESS_WORKER_CONTROL_OR_LIVENESS_FAILED",
            sequence=fault_sequence,
            auth_key=claim.lease_token,
        )
    except BaseException:
        control._signal_abort()
        _child_fail_closed(
            connection,
            store,
            claim,
            outcome_code="PROCESS_WORKER_CRASH_OBSERVED",
            sequence=fault_sequence,
            auth_key=claim.lease_token,
        )
    finally:
        if provider is not None and provider.is_alive():
            # The sealed production adapter observes ``aborted()`` and reaps
            # its ROS CLI child. A non-cooperative test adapter is bounded by
            # this process boundary and is never waited indefinitely.
            provider.join(1.5)
        connection.close()


def _child_physical_process_main(
    connection: Connection,
    store_root: str,
    max_leases: int,
    max_state_bytes: int,
    claim: WorkerLeaseClaim,
    work: SealedPhysicalProcessWorker,
    heartbeat_interval_s: float,
    startup_timeout_s: float,
) -> None:
    """Prepare at zero, then await authenticated START or interrupt."""

    store = WorkerLeaseStore(
        Path(store_root),
        max_leases=max_leases,
        max_state_bytes=max_state_bytes,
    )
    durable = WorkerControl(store, claim)
    control = ProcessWorkerControl(durable)
    call_key = claim.lease.call_key
    provider: threading.Thread | None = None
    prepared: PreparedPhysicalProcessWork | None = None
    results: queue.Queue[tuple[str, object]] | None = None
    callback_gate: threading.Event | None = None
    try:
        store.start(claim)
        prepared = _prepare_physical_with_heartbeats(
            connection,
            control,
            work,
            heartbeat_interval_s=heartbeat_interval_s,
            startup_timeout_s=startup_timeout_s,
        )
        arm_receipt = prepared.arm_receipt()
        if not isinstance(arm_receipt, dict):
            raise ProcessWorkerError("PROCESS_WORKER_ARM_RECEIPT_INVALID")
        # Encode before announcing ARMED so an oversized receipt never leaves
        # a parent believing the child is controllable.
        armed_message = _message(
            "ARMED_ZERO",
            sequence=0,
            call_key=call_key,
            auth_key=claim.lease_token,
            armed_zero=arm_receipt,
        )
        _encode_message(armed_message)
        _send_message(connection, armed_message)
        command, intent = _child_wait_for_physical_start(
            connection,
            store,
            claim,
            control,
            call_key,
            heartbeat_interval_s=heartbeat_interval_s,
            auth_key=claim.lease_token,
        )
        results = queue.Queue(maxsize=1)
        callback_entered = threading.Event()
        callback_gate = threading.Event()

        def invoke() -> None:
            callback_entered.set()
            callback_gate.wait()
            try:
                if command == "START":
                    value = prepared.execute(control)
                else:
                    assert intent is not None
                    value = prepared.stop(control, intent=intent)
                results.put_nowait(("OUTCOME", value))
            except Exception:
                results.put_nowait(("FAULT", "PROCESS_WORKER_EXCEPTION_AMBIGUOUS"))
            except BaseException:
                results.put_nowait(("FAULT", "PROCESS_WORKER_CRASH_OBSERVED"))

        provider = threading.Thread(
            target=invoke,
            name=f"rolo-physical-provider-{call_key.digest()[:12]}",
            daemon=True,
        )
        provider.start()
        if not callback_entered.wait(startup_timeout_s):
            raise ProcessWorkerError("PROCESS_WORKER_CALLBACK_THREAD_NOT_READY")
        if command == "START":
            _send_message(
                connection,
                _message(
                    "WORK_STARTED",
                    sequence=1,
                    call_key=call_key,
                    auth_key=claim.lease_token,
                ),
            )
        callback_gate.set()
        _child_run_loop(
            connection,
            store,
            claim,
            control,
            call_key,
            results,
            heartbeat_interval_s=heartbeat_interval_s,
            terminal_sequence=2,
            auth_key=claim.lease_token,
        )
    except (EOFError, OSError, UnicodeError, ValueError, WorkerLifecycleError) as exc:
        if not _child_stop_or_reap_physical(
            connection,
            store,
            claim,
            control,
            prepared,
            provider,
            results,
            callback_gate,
            auth_key=claim.lease_token,
        ):
            control._signal_abort()
            _child_fail_closed(
                connection,
                store,
                claim,
                outcome_code=_stable_physical_prepare_error(
                    exc,
                    fallback="PROCESS_WORKER_CONTROL_OR_LIVENESS_FAILED",
                ),
                sequence=2,
                auth_key=claim.lease_token,
            )
    except BaseException as exc:
        if not _child_stop_or_reap_physical(
            connection,
            store,
            claim,
            control,
            prepared,
            provider,
            results,
            callback_gate,
            auth_key=claim.lease_token,
        ):
            control._signal_abort()
            _child_fail_closed(
                connection,
                store,
                claim,
                outcome_code=_stable_physical_prepare_error(
                    exc,
                    fallback="PROCESS_WORKER_CRASH_OBSERVED",
                ),
                sequence=2,
                auth_key=claim.lease_token,
            )
    finally:
        if provider is not None and provider.is_alive():
            provider.join(3.5)
        connection.close()


def _child_stop_or_reap_physical(
    connection: Connection,
    store: WorkerLeaseStore,
    claim: WorkerLeaseClaim,
    control: ProcessWorkerControl,
    prepared: PreparedPhysicalProcessWork | None,
    provider: threading.Thread | None,
    results: queue.Queue[tuple[str, object]] | None,
    callback_gate: threading.Event | None,
    *,
    auth_key: str,
) -> bool:
    """Turn a post-ARM control fault into a proved safe terminal when possible."""

    if prepared is None:
        return False
    try:
        record = store.load(claim.lease.call_key)
        intent: WorkerInterruptIntent = "CANCEL" if record is not None and record.state == "CANCEL_REQUESTED" else "STOP"
        record = store.request_interrupt(claim.lease.call_key, intent=intent)
        expected = "CANCEL_REQUESTED" if intent == "CANCEL" else "STOP_REQUESTED"
        if record.state not in {expected, "CANCELLED", "STOPPED"}:
            return False
        control._signal_interrupt(intent)
        if provider is None:
            outcome = prepared.stop(control, intent=intent)
        else:
            if callback_gate is not None:
                callback_gate.set()
            if results is None:
                return False
            deadline = time.monotonic() + _PHYSICAL_STOP_WAIT_S
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                try:
                    kind, value = results.get(timeout=min(0.05, remaining))
                except queue.Empty:
                    continue
                if kind != "OUTCOME" or not isinstance(value, LeasedProviderOutcome):
                    return False
                outcome = value
                break
        expected_terminal = "CANCELLED" if intent == "CANCEL" else "STOPPED"
        if outcome.completion.status != expected_terminal:
            return False
        try:
            _child_complete(
                connection,
                control,
                claim.lease.call_key,
                outcome,
                sequence=2,
                auth_key=auth_key,
            )
        except (OSError, ProcessWorkerError):
            persisted = store.load(claim.lease.call_key)
            return persisted is not None and persisted.state == expected_terminal
        return True
    except Exception:
        return False


def _prepare_physical_with_heartbeats(
    connection: Connection,
    control: ProcessWorkerControl,
    work: SealedPhysicalProcessWorker,
    *,
    heartbeat_interval_s: float,
    startup_timeout_s: float,
) -> PreparedPhysicalProcessWork:
    results: queue.Queue[tuple[str, object]] = queue.Queue(maxsize=1)

    def prepare() -> None:
        try:
            results.put_nowait(("PREPARED", work.prepare(control)))
        except BaseException as exc:
            results.put_nowait(("FAULT", exc))

    thread = threading.Thread(
        target=prepare,
        name=f"rolo-physical-prepare-{control.call_key.digest()[:12]}",
        daemon=True,
    )
    thread.start()
    deadline = time.monotonic() + startup_timeout_s
    next_heartbeat = time.monotonic() + heartbeat_interval_s
    while True:
        try:
            kind, value = results.get_nowait()
        except queue.Empty:
            pass
        else:
            if kind == "FAULT":
                raise ProcessWorkerError(
                    _stable_physical_prepare_error(
                        value,
                        fallback="PROCESS_WORKER_PREPARE_FAILED",
                    )
                ) from (value if isinstance(value, BaseException) else None)
            if kind != "PREPARED" or not callable(getattr(value, "arm_receipt", None)):
                raise ProcessWorkerError("PROCESS_WORKER_PREPARE_FAILED")
            return value  # type: ignore[return-value]
        now = time.monotonic()
        if now >= deadline:
            control._signal_abort()
            raise ProcessWorkerError("PROCESS_WORKER_PREPARE_TIMEOUT")
        if now >= next_heartbeat:
            control.heartbeat()
            next_heartbeat = now + heartbeat_interval_s
        # Parent channel failure must abort preparation even before ARMED.
        if connection.poll(0.0):
            try:
                unexpected = _receive_message(connection, 0.0)
            except EOFError:
                control._signal_abort()
                raise
            if unexpected is not None:
                raise ProcessWorkerError("PROCESS_WORKER_PREARM_CONTROL_INVALID")
        time.sleep(
            min(
                0.02,
                max(0.0, deadline - now),
                max(0.0, next_heartbeat - now),
            )
        )


def _child_wait_for_physical_start(
    connection: Connection,
    store: WorkerLeaseStore,
    claim: WorkerLeaseClaim,
    control: ProcessWorkerControl,
    call_key: WorkerCallKey,
    *,
    heartbeat_interval_s: float,
    auth_key: str,
) -> tuple[Literal["START", "INTERRUPT"], WorkerInterruptIntent | None]:
    next_heartbeat = time.monotonic() + heartbeat_interval_s
    while True:
        now = time.monotonic()
        if now >= next_heartbeat:
            control.heartbeat()
            next_heartbeat = now + heartbeat_interval_s
        message = _receive_message(
            connection,
            min(0.05, max(0.0, next_heartbeat - now)),
        )
        if message is None:
            continue
        kind = message.get("kind")
        if kind == "START":
            _require_message(
                message,
                kind="START",
                sequence=0,
                call_key=call_key,
                auth_key=auth_key,
            )
            running = store.load(call_key)
            if running is None or running.state != "RUNNING":
                raise ProcessWorkerError("PROCESS_WORKER_START_FENCE_NOT_LIVE")
            return "START", None
        if kind == "INTERRUPT":
            _require_message(
                message,
                kind="INTERRUPT",
                sequence=1,
                call_key=call_key,
                auth_key=auth_key,
            )
            intent = message.get("intent")
            if intent not in {"CANCEL", "STOP"}:
                raise ProcessWorkerError("PROCESS_WORKER_INTERRUPT_INVALID")
            record = store.load(call_key)
            expected = "CANCEL_REQUESTED" if intent == "CANCEL" else "STOP_REQUESTED"
            if record is None or record.state != expected:
                raise ProcessWorkerError("PROCESS_WORKER_INTERRUPT_NOT_DURABLE")
            control._signal_interrupt(intent)
            return "INTERRUPT", intent
        raise ProcessWorkerError("PROCESS_WORKER_IPC_MESSAGE_INVALID")


def _child_wait_for_start(
    connection: Connection,
    control: ProcessWorkerControl,
    call_key: WorkerCallKey,
    *,
    heartbeat_interval_s: float,
    startup_timeout_s: float,
    auth_key: str,
) -> None:
    deadline = time.monotonic() + startup_timeout_s
    next_heartbeat = time.monotonic() + heartbeat_interval_s
    while True:
        now = time.monotonic()
        if now >= deadline:
            raise ProcessWorkerError("PROCESS_WORKER_START_GATE_TIMEOUT")
        if now >= next_heartbeat:
            control.heartbeat()
            next_heartbeat = now + heartbeat_interval_s
        wait_s = min(0.05, deadline - now, max(0.0, next_heartbeat - now))
        message = _receive_message(connection, wait_s)
        if message is None:
            continue
        _require_message(
            message,
            kind="START",
            sequence=0,
            call_key=call_key,
            auth_key=auth_key,
        )
        return


def _child_run_loop(
    connection: Connection,
    store: WorkerLeaseStore,
    claim: WorkerLeaseClaim,
    control: ProcessWorkerControl,
    call_key: WorkerCallKey,
    results: queue.Queue[tuple[str, object]],
    *,
    heartbeat_interval_s: float,
    terminal_sequence: int,
    auth_key: str,
) -> None:
    next_heartbeat = time.monotonic() + heartbeat_interval_s
    expected_sequence = 1
    while True:
        try:
            result_kind, value = results.get_nowait()
        except queue.Empty:
            pass
        else:
            if result_kind == "FAULT":
                _child_fail_closed(
                    connection,
                    store,
                    claim,
                    outcome_code=str(value),
                    sequence=terminal_sequence,
                    auth_key=auth_key,
                )
                return
            _child_complete(
                connection,
                control,
                call_key,
                value,
                sequence=terminal_sequence,
                auth_key=auth_key,
            )
            return

        now = time.monotonic()
        if now >= next_heartbeat:
            control.heartbeat()
            next_heartbeat = now + heartbeat_interval_s
        wait_s = min(0.05, max(0.0, next_heartbeat - now))
        message = _receive_message(connection, wait_s)
        if message is None:
            continue
        _require_message(
            message,
            kind="INTERRUPT",
            sequence=expected_sequence,
            call_key=call_key,
            auth_key=auth_key,
        )
        intent = message.get("intent")
        if intent not in {"CANCEL", "STOP"}:
            raise ProcessWorkerError("PROCESS_WORKER_INTERRUPT_INVALID")
        record = store.load(call_key)
        expected_state = "CANCEL_REQUESTED" if intent == "CANCEL" else "STOP_REQUESTED"
        if record is None or record.state != expected_state:
            raise ProcessWorkerError("PROCESS_WORKER_INTERRUPT_NOT_DURABLE")
        control._signal_interrupt(intent)
        expected_sequence += 1


def _child_complete(
    connection: Connection,
    control: ProcessWorkerControl,
    call_key: WorkerCallKey,
    value: object,
    *,
    sequence: int,
    auth_key: str,
) -> None:
    if not isinstance(value, LeasedProviderOutcome):
        raise ProcessWorkerError("PROCESS_WORKER_OUTCOME_INVALID")
    outcome = LeasedProviderOutcome(
        completion=value.completion,
        result=dict(value.result),
    )
    completion = outcome.completion
    message = _message(
        "TERMINAL",
        sequence=sequence,
        call_key=call_key,
        auth_key=auth_key,
        status=completion.status,
        outcome_code=completion.outcome_code,
        result=outcome.result,
    )
    encoded = _encode_message(message)
    control._durable.prepare_result(
        completion=completion,
        result=outcome.result,
    )
    if completion.status in {"CANCELLED", "STOPPED"}:
        intent: WorkerInterruptIntent = "CANCEL" if completion.status == "CANCELLED" else "STOP"
        terminal = control._durable.acknowledge_interrupt(
            intent=intent,
            outcome_code=completion.outcome_code,
        )
    else:
        terminal = control._durable.complete(
            status=completion.status,
            outcome_code=completion.outcome_code,
        )
    if terminal.state != completion.status:
        raise ProcessWorkerError("PROCESS_WORKER_TERMINAL_STATE_MISMATCH")
    connection.send_bytes(encoded)


def _child_fail_closed(
    connection: Connection,
    store: WorkerLeaseStore,
    claim: WorkerLeaseClaim,
    *,
    outcome_code: str,
    sequence: int,
    auth_key: str,
) -> None:
    outcome_code = _require_outcome_code(outcome_code)
    try:
        record = store.mark_worker_crashed(claim, outcome_code=outcome_code)
    except WorkerLifecycleError:
        record = store.load(claim.lease.call_key)
    persisted_code = record.outcome_code if record is not None and record.state not in _ACTIVE_STATES and record.outcome_code is not None else outcome_code
    try:
        _send_message(
            connection,
            _message(
                "FAULT",
                sequence=sequence,
                call_key=claim.lease.call_key,
                auth_key=auth_key,
                outcome_code=persisted_code,
            ),
        )
    except (OSError, ProcessWorkerError):
        pass


def _message(
    kind: Literal[
        "ARMED_ZERO",
        "READY",
        "START",
        "WORK_STARTED",
        "INTERRUPT",
        "TERMINAL",
        "FAULT",
    ],
    *,
    sequence: int,
    call_key: WorkerCallKey,
    auth_key: str,
    **extra: object,
) -> dict[str, object]:
    unsigned: dict[str, object] = {
        "schema_version": _IPC_SCHEMA,
        "kind": kind,
        "sequence": sequence,
        "call_key": call_key.model_dump(mode="json"),
        "call_key_digest": call_key.digest(),
        **extra,
    }
    return {
        **unsigned,
        "auth_tag": _message_auth_tag(unsigned, auth_key),
    }


def _encode_message(message: dict[str, object]) -> bytes:
    try:
        encoded = json.dumps(
            message,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ProcessWorkerError("PROCESS_WORKER_IPC_MESSAGE_INVALID") from exc
    if not encoded or len(encoded) > _MAX_IPC_BYTES:
        raise ProcessWorkerError("PROCESS_WORKER_IPC_MESSAGE_TOO_LARGE")
    return encoded


def _send_message(connection: Connection, message: dict[str, object]) -> None:
    connection.send_bytes(_encode_message(message))


def _receive_message(
    connection: Connection,
    timeout_s: float,
) -> dict[str, object] | None:
    if not connection.poll(max(0.0, timeout_s)):
        return None
    try:
        encoded = connection.recv_bytes(_MAX_IPC_BYTES)
        raw = loads_unique_json(encoded.decode("utf-8"))
    except EOFError:
        raise
    except (OSError, UnicodeError, ValueError) as exc:
        raise ProcessWorkerError("PROCESS_WORKER_IPC_MESSAGE_INVALID") from exc
    if not isinstance(raw, dict):
        raise ProcessWorkerError("PROCESS_WORKER_IPC_MESSAGE_INVALID")
    return raw


def _require_message(
    message: dict[str, object] | None,
    *,
    kind: str,
    sequence: int,
    call_key: WorkerCallKey,
    auth_key: str,
) -> None:
    required = {
        "schema_version",
        "kind",
        "sequence",
        "call_key",
        "call_key_digest",
        "auth_tag",
    }
    extras = {
        "ARMED_ZERO": {"armed_zero"},
        "INTERRUPT": {"intent"},
        "TERMINAL": {"status", "outcome_code", "result"},
        "FAULT": {"outcome_code"},
    }.get(kind, set())
    if message is None or set(message) != required | extras:
        raise ProcessWorkerError("PROCESS_WORKER_IPC_MESSAGE_INVALID")
    auth_tag = message.get("auth_tag")
    unsigned = {key: value for key, value in message.items() if key != "auth_tag"}
    if not isinstance(auth_tag, str) or not hmac.compare_digest(
        auth_tag,
        _message_auth_tag(unsigned, auth_key),
    ):
        raise ProcessWorkerError("PROCESS_WORKER_IPC_AUTHENTICATION_FAILED")
    if (
        message.get("schema_version") != _IPC_SCHEMA
        or message.get("kind") != kind
        or isinstance(message.get("sequence"), bool)
        or message.get("sequence") != sequence
        or message.get("call_key_digest") != call_key.digest()
    ):
        raise ProcessWorkerError("PROCESS_WORKER_IPC_MESSAGE_INVALID")
    try:
        observed = WorkerCallKey.model_validate(message.get("call_key"))
    except ValueError as exc:
        raise ProcessWorkerError("PROCESS_WORKER_IPC_MESSAGE_INVALID") from exc
    if observed != call_key:
        raise ProcessWorkerError("PROCESS_WORKER_IPC_CALL_IDENTITY_MISMATCH")
    if kind == "TERMINAL":
        if message.get("status") not in {"CANCELLED", "STOPPED", "SUCCEEDED", "FAILED"}:
            raise ProcessWorkerError("PROCESS_WORKER_IPC_MESSAGE_INVALID")
        _require_outcome_code(message.get("outcome_code"))
        if not isinstance(message.get("result"), dict):
            raise ProcessWorkerError("PROCESS_WORKER_IPC_MESSAGE_INVALID")
    elif kind == "FAULT":
        _require_outcome_code(message.get("outcome_code"))


def _parse_physical_armed_zero(
    value: object,
    *,
    work: SealedPhysicalProcessWorker,
) -> object:
    try:
        from .physical_worker import parse_physical_worker_armed_zero

        return parse_physical_worker_armed_zero(
            value,
            expected_call_key_digest=work.expected_call_key_digest,
            expected_request_digest=work.request_digest,
            expected_execution_subject_digest=work.execution_subject_digest,
            expected_runtime_sha256=work.runtime_sha256,
            expected_target_id=work.target_id,
            expected_call_id=work.call_id,
            expected_session_id=work.session_id,
        )
    except Exception as exc:
        raise ProcessWorkerError("PROCESS_WORKER_ARM_RECEIPT_INVALID") from exc


def _message_auth_tag(message: dict[str, object], auth_key: str) -> str:
    if not isinstance(auth_key, str) or not auth_key:
        raise ProcessWorkerError("PROCESS_WORKER_IPC_AUTHENTICATION_FAILED")
    try:
        encoded = json.dumps(
            message,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ProcessWorkerError("PROCESS_WORKER_IPC_MESSAGE_INVALID") from exc
    return hmac.new(auth_key.encode("ascii"), encoded, hashlib.sha256).hexdigest()


def _require_outcome_code(value: object) -> str:
    if not isinstance(value, str) or _OUTCOME_CODE.fullmatch(value) is None:
        raise ProcessWorkerError("PROCESS_WORKER_OUTCOME_CODE_INVALID")
    return value


def _stable_physical_prepare_error(value: object, *, fallback: str) -> str:
    """Expose only code-shaped physical pre-arm failures across process IPC."""

    fallback = _require_outcome_code(fallback)
    candidate = str(value)
    if (
        _OUTCOME_CODE.fullmatch(candidate) is not None
        and candidate.startswith(("PHYSICAL_WORKER_", "PROCESS_WORKER_"))
    ):
        return candidate
    return fallback


def _prepared_outcome(record: WorkerLeaseRecord | None) -> LeasedProviderOutcome | None:
    if (
        record is None
        or record.prepared_status is None
        or record.prepared_outcome_code is None
        or record.prepared_result is None
        or record.prepared_result_digest is None
        or record.state != record.prepared_status
        or record.outcome_code != record.prepared_outcome_code
    ):
        return None
    return LeasedProviderOutcome(
        completion=WorkerCompletion(
            record.prepared_status,
            record.prepared_outcome_code,
        ),
        result=dict(record.prepared_result),
    )


def _require_wait_timeout(value: float | None) -> float | None:
    if value is None:
        return None
    # Compare integers before converting to float: ``float(10**10000)``
    # raises a platform OverflowError that must not escape this boundary.
    if type(value) not in {int, float} or value < 0 or value > threading.TIMEOUT_MAX:
        raise ProcessWorkerError("PROCESS_WORKER_JOIN_TIMEOUT_INVALID")
    normalized = float(value)
    if not math.isfinite(normalized):
        raise ProcessWorkerError("PROCESS_WORKER_JOIN_TIMEOUT_INVALID")
    return normalized


def _terminate_process(process: multiprocessing.Process) -> None:
    try:
        if process.pid is not None and process.is_alive():
            process.terminate()
            process.join(1.0)
            if process.is_alive():
                process.kill()
                process.join(1.0)
    except (AssertionError, OSError, ValueError):
        pass
