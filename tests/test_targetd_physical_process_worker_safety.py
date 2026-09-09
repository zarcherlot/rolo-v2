from __future__ import annotations

import json
import threading
import time

import pytest

from rolo.targetd.lifecycle import (
    WorkerCallKey,
    WorkerCompletion,
    WorkerLeaseStore,
    WorkerLifecycleError,
)
from rolo.targetd.physical_worker import LanderPiRotateProcessWorker
from rolo.targetd.process_worker import (
    LeasedProcessWorkerRuntime,
    ProcessWorkerError,
    _message,
    _ProcessHandle,
    _stable_physical_prepare_error,
)
from tests.test_targetd_process_service import _physical_service


class _MemoryConnection:
    def __init__(self) -> None:
        self.sent: list[dict[str, object]] = []
        self.closed = False

    def send_bytes(self, encoded: bytes) -> None:
        self.sent.append(json.loads(encoded.decode("ascii")))

    def close(self) -> None:
        self.closed = True


def test_physical_prepare_error_codes_are_safely_bounded() -> None:
    assert (
        _stable_physical_prepare_error(
            ValueError("PHYSICAL_WORKER_ARMED_ZERO_TOPOLOGY_UNAVAILABLE"),
            fallback="PROCESS_WORKER_PREPARE_FAILED",
        )
        == "PHYSICAL_WORKER_ARMED_ZERO_TOPOLOGY_UNAVAILABLE"
    )
    assert (
        _stable_physical_prepare_error(
            ValueError("contains sensitive free-form detail"),
            fallback="PROCESS_WORKER_PREPARE_FAILED",
        )
        == "PROCESS_WORKER_PREPARE_FAILED"
    )


class _ExitedProcess:
    pid = 4242
    exitcode = 0

    @staticmethod
    def is_alive() -> bool:
        return False

    @staticmethod
    def join(_timeout: float | None = None) -> None:
        return None


class _ArmConnection:
    def __init__(self) -> None:
        self._encoded: bytes | None = None
        self.closed = False

    def set_arm(self, *, claim, armed_zero: dict[str, object]) -> None:
        message = _message(
            "ARMED_ZERO",
            sequence=0,
            call_key=claim.lease.call_key,
            auth_key=claim.lease_token,
            armed_zero=armed_zero,
        )
        self._encoded = json.dumps(
            message,
            allow_nan=False,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")

    def poll(self, _timeout: float = 0.0) -> bool:
        return self._encoded is not None

    def recv_bytes(self, _max_size: int | None = None) -> bytes:
        assert self._encoded is not None
        encoded = self._encoded
        self._encoded = None
        return encoded

    def close(self) -> None:
        self.closed = True


class _ArmChildConnection:
    def __init__(self) -> None:
        self.closed = False

    def close(self) -> None:
        self.closed = True


class _ArmProcess:
    def __init__(self, parent: _ArmConnection, store, claim, armed_zero) -> None:
        self.parent = parent
        self.store = store
        self.claim = claim
        self.armed_zero = armed_zero
        self.pid = 5252
        self.exitcode: int | None = None
        self._alive = False

    def start(self) -> None:
        self._alive = True
        self.store.start(self.claim)
        self.parent.set_arm(claim=self.claim, armed_zero=self.armed_zero)

    def is_alive(self) -> bool:
        return self._alive

    def terminate(self) -> None:
        self._alive = False
        self.exitcode = -15

    def kill(self) -> None:
        self._alive = False
        self.exitcode = -9

    def join(self, _timeout: float | None = None) -> None:
        return None


class _ArmProcessContext:
    def __init__(self, store, armed_zero: dict[str, object]) -> None:
        self.store = store
        self.armed_zero = armed_zero
        self.parent = _ArmConnection()
        self.child = _ArmChildConnection()
        self.process: _ArmProcess | None = None

    def Pipe(self, *, duplex: bool):
        assert duplex is True
        return self.parent, self.child

    def Process(self, *, target, args, name: str, daemon: bool):
        assert callable(target)
        assert name.startswith("rolo-physical-")
        assert daemon is True
        claim = args[4]
        self.process = _ArmProcess(self.parent, self.store, claim, self.armed_zero)
        return self.process


class _ParsedArm:
    def __init__(self, value: dict[str, object]) -> None:
        self.value = value

    def as_dict(self) -> dict[str, object]:
        return dict(self.value)

    @property
    def call_key_digest(self) -> object:
        return self.value["call_key_digest"]

    @property
    def arm_receipt_digest(self) -> object:
        return self.value["arm_receipt_digest"]


def _call_key(suffix: str = "one") -> WorkerCallKey:
    return WorkerCallKey(
        target_id="landerpi",
        session_id=f"physical-{suffix}",
        idempotency_key=f"rotate-{suffix}",
        request_digest=("a" if suffix == "one" else "b") * 64,
    )


def _armed_zero(call_key: WorkerCallKey) -> dict[str, object]:
    return {
        "schema_version": "rolo-test-armed-zero/v1",
        "call_key_digest": call_key.digest(),
        "arm_receipt_digest": "c" * 64,
        "provider_pid": 777,
        "provider_start_time_ticks": 12345,
        "provider_cmdline_sha256": "d" * 64,
    }


def _runtime_with_armed_handle(
    tmp_path,
    suffix: str = "one",
    *,
    physical_start_gate=None,
):
    store = WorkerLeaseStore(tmp_path / f"leases-{suffix}")
    runtime = LeasedProcessWorkerRuntime(
        store,
        supervisor_id="targetd-physical",
        allow_spawn_physical_substrate=True,
        physical_start_gate=physical_start_gate,
    )
    call_key = _call_key(suffix)
    claim = store.claim(
        call_key,
        supervisor_id=runtime.supervisor_id,
        worker_id="physical-worker",
    )
    store.start(claim)
    arm = _armed_zero(call_key)
    lease = store.record_armed_zero(claim, armed_zero=arm)
    connection = _MemoryConnection()
    handle = _ProcessHandle(
        call_key=call_key,
        claim=claim,
        process=_ExitedProcess(),  # type: ignore[arg-type]
        connection=connection,  # type: ignore[arg-type]
        physical=True,
        armed_zero=arm,
        phase="ARMED_ZERO",
    )
    runtime._handles[call_key.digest()] = handle
    return runtime, store, call_key, claim, lease, handle, connection


def _make_fail_closed_stop_immediate(monkeypatch) -> None:
    monkeypatch.setattr("rolo.targetd.process_worker._PHYSICAL_STOP_WAIT_S", 0.0)
    monkeypatch.setattr(
        "rolo.targetd.physical_worker.recover_persisted_armed_zero",
        lambda _value, **_kwargs: True,
    )


def test_noop_start_gate_is_rejected_without_start_message(tmp_path, monkeypatch):
    _make_fail_closed_stop_immediate(monkeypatch)
    runtime, store, call_key, _, _, _, connection = _runtime_with_armed_handle(
        tmp_path,
        physical_start_gate=lambda _claim, _armed_zero: None,
    )

    with pytest.raises(ProcessWorkerError, match="PROCESS_WORKER_START_GATE_REJECTED"):
        runtime.start_prepared(call_key, timeout_s=0.1)

    assert [message["kind"] for message in connection.sent] == ["INTERRUPT"]
    assert connection.sent[0]["intent"] == "STOP"
    record = store.load(call_key)
    assert record is not None
    assert record.state == "UNKNOWN"


def test_missing_start_gate_is_rejected_and_stops_armed_child(tmp_path, monkeypatch):
    _make_fail_closed_stop_immediate(monkeypatch)
    runtime, _, call_key, _, _, _, connection = _runtime_with_armed_handle(tmp_path)

    with pytest.raises(ProcessWorkerError, match="PROCESS_WORKER_START_GATE_INVALID"):
        runtime.start_prepared(call_key, timeout_s=0.1)

    assert [message["kind"] for message in connection.sent] == ["INTERRUPT"]
    assert connection.sent[0]["intent"] == "STOP"


def test_untyped_start_gate_result_is_rejected_without_start_message(
    tmp_path,
    monkeypatch,
):
    _make_fail_closed_stop_immediate(monkeypatch)
    runtime, store, call_key, _, _, _, connection = _runtime_with_armed_handle(
        tmp_path,
        physical_start_gate=lambda _claim, _armed_zero: object(),
    )

    with pytest.raises(ProcessWorkerError, match="PROCESS_WORKER_START_GATE_REJECTED"):
        runtime.start_prepared(call_key, timeout_s=0.1)

    assert [message["kind"] for message in connection.sent] == ["INTERRUPT"]
    assert connection.sent[0]["intent"] == "STOP"
    record = store.load(call_key)
    assert record is not None
    assert record.state == "UNKNOWN"


def test_pre_start_stop_is_durable_and_never_emits_start(tmp_path):
    runtime, store, call_key, _, _, _, connection = _runtime_with_armed_handle(tmp_path)

    interrupted = runtime.request_interrupt(call_key, intent="STOP")

    assert interrupted.requested is True
    assert interrupted.acknowledged is False
    assert interrupted.lease.state == "STOP_REQUESTED"
    assert [message["kind"] for message in connection.sent] == ["INTERRUPT"]
    assert connection.sent[0]["intent"] == "STOP"
    persisted = store.load(call_key)
    assert persisted is not None
    assert persisted.state == "STOP_REQUESTED"


def test_repeated_pre_start_stop_is_idempotent_on_ipc(tmp_path):
    runtime, _, call_key, _, _, _, connection = _runtime_with_armed_handle(tmp_path)

    first = runtime.request_interrupt(call_key, intent="STOP")
    second = runtime.request_interrupt(call_key, intent="STOP")

    assert first.lease.state == "STOP_REQUESTED"
    assert second.lease.state == "STOP_REQUESTED"
    assert [message["kind"] for message in connection.sent] == ["INTERRUPT"]
    assert connection.sent[0]["sequence"] == 1


def test_terminal_without_work_started_remains_fail_closed(tmp_path):
    runtime, store, call_key, claim, _, handle, _ = _runtime_with_armed_handle(tmp_path)
    handle.phase = "START_SENT"
    result = {"status": "SUCCEEDED", "motion_command_emitted": True}
    completion = WorkerCompletion("SUCCEEDED", "ROTATE_SUCCEEDED")
    store.prepare_result(claim, completion=completion, result=result)
    store.complete(claim, status="SUCCEEDED", outcome_code="ROTATE_SUCCEEDED")

    terminal = _message(
        "TERMINAL",
        sequence=2,
        call_key=call_key,
        auth_key=claim.lease_token,
        status="SUCCEEDED",
        outcome_code="ROTATE_SUCCEEDED",
        result=result,
    )
    encoded = json.dumps(
        terminal,
        allow_nan=False,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")

    class _TerminalConnection(_MemoryConnection):
        def __init__(self) -> None:
            super().__init__()
            self._encoded = encoded

        def poll(self, _timeout: float = 0.0) -> bool:
            return self._encoded is not None

        def recv_bytes(self, _max_size: int | None = None) -> bytes:
            assert self._encoded is not None
            value = self._encoded
            self._encoded = None
            return value

    handle.connection = _TerminalConnection()  # type: ignore[assignment]
    runtime._monitor(handle)

    assert handle.done.is_set()
    assert not handle.work_started.is_set()
    assert handle.phase == "TERMINAL"
    assert handle.outcome is not None
    assert handle.outcome.completion.status == "SUCCEEDED"
    snapshot = runtime.join(call_key, timeout_s=0.1)
    assert snapshot.lease.state == "SUCCEEDED"


def test_start_waits_for_terminal_when_work_started_ack_is_lost(tmp_path, monkeypatch):
    sentinel = object()
    runtime, store, call_key, claim, _, handle, connection = _runtime_with_armed_handle(
        tmp_path,
        "lost-ack",
        physical_start_gate=lambda _claim, _armed_zero: sentinel,
    )

    # This test isolates the post-attestation IPC race. Exact attestation shape
    # is covered separately above; bypassing only that validator lets an
    # in-memory connection deterministically drop WORK_STARTED.
    monkeypatch.setattr(
        LeasedProcessWorkerRuntime,
        "_require_target_start_attestation",
        staticmethod(lambda value, **_kwargs: value is sentinel or pytest.fail()),
    )

    def terminalize_without_start_ack() -> None:
        while not any(message["kind"] == "START" for message in connection.sent):
            time.sleep(0.001)
        store.mark_worker_crashed(
            claim,
            outcome_code="PROCESS_WORKER_START_ACK_LOST",
        )
        handle.done.set()

    observer = threading.Thread(target=terminalize_without_start_ack, daemon=True)
    observer.start()
    with pytest.raises(
        ProcessWorkerError,
        match="PROCESS_WORKER_START_NOT_ACKNOWLEDGED",
    ):
        runtime.start_prepared(call_key, timeout_s=0.5)
    observer.join(1.0)

    assert not observer.is_alive()
    assert not handle.work_started.is_set()
    assert [message["kind"] for message in connection.sent] == ["START"]
    record = store.load(call_key)
    assert record is not None
    assert record.state == "UNKNOWN"


def test_restart_reaps_exact_persisted_arm_before_fail_close(tmp_path, monkeypatch):
    store = WorkerLeaseStore(tmp_path / "leases-restart")
    first = LeasedProcessWorkerRuntime(
        store,
        supervisor_id="targetd-physical",
        allow_spawn_physical_substrate=True,
    )
    call_key = _call_key("restart")
    claim = store.claim(
        call_key,
        supervisor_id=first.supervisor_id,
        worker_id="physical-worker",
        physical_execution_subject_digest="sha256:" + "e" * 64,
        physical_runtime_sha256="f" * 64,
    )
    store.start(claim)
    arm = _armed_zero(call_key)
    store.record_armed_zero(claim, armed_zero=arm)
    recovered: list[object] = []

    def recover_exact(value: object, **kwargs: object) -> bool:
        recovered.append((value, kwargs))
        return True

    monkeypatch.setattr(
        "rolo.targetd.physical_worker.recover_persisted_armed_zero",
        recover_exact,
    )

    second = LeasedProcessWorkerRuntime(
        store,
        supervisor_id="targetd-physical",
        allow_spawn_physical_substrate=True,
    )

    assert first.supervisor_id != second.supervisor_id
    assert recovered == [
        (
            arm,
            {
                "expected_call_key_digest": call_key.digest(),
                "expected_target_id": call_key.target_id,
                "expected_call_id": call_key.idempotency_key,
                "expected_session_id": call_key.session_id,
                "expected_request_digest": call_key.request_digest,
                "expected_execution_subject_digest": "sha256:" + "e" * 64,
                "expected_runtime_sha256": "f" * 64,
                "container": "MentorPi",
                "container_user": "ubuntu",
            },
        )
    ]
    record = store.load(call_key)
    assert record is not None
    assert record.state == "UNKNOWN"
    assert record.outcome_code == "WORKER_SUPERVISOR_RESTARTED"


def test_mark_crashed_never_returns_an_active_fallback(tmp_path, monkeypatch):
    runtime, store, call_key, claim, _, _, _ = _runtime_with_armed_handle(tmp_path)

    def reject_crash(*_args, **_kwargs):
        raise WorkerLifecycleError("SIMULATED_CRASH_WRITE_FAILURE")

    monkeypatch.setattr(store, "mark_worker_crashed", reject_crash)

    with pytest.raises(
        ProcessWorkerError,
        match="PROCESS_WORKER_CRASH_RECONCILIATION_FAILED",
    ):
        runtime._mark_crashed(claim, "PROCESS_WORKER_EXITED")

    record = store.load(call_key)
    assert record is not None
    assert record.state == "RUNNING"


def _physical_prepare_fixture(tmp_path, monkeypatch):
    _, _, request, manifest = _physical_service(tmp_path / "request")
    armed_payload = _armed_zero(WorkerCallKey.from_request(request))
    parsed = _ParsedArm(armed_payload)
    store = WorkerLeaseStore(tmp_path / "physical-leases")
    runtime = LeasedProcessWorkerRuntime(
        store,
        supervisor_id="targetd-physical-fault",
        allow_spawn_physical_substrate=True,
    )
    context = _ArmProcessContext(store, armed_payload)
    runtime._context = context  # type: ignore[assignment]
    monkeypatch.setattr(
        "rolo.targetd.process_worker._parse_physical_armed_zero",
        lambda _value, *, work: parsed,
    )
    work = LanderPiRotateProcessWorker(request, manifest)
    return runtime, store, request, manifest, work, armed_payload, parsed, context


def test_arm_durable_write_failure_exact_reaps_and_never_leaves_active(
    tmp_path,
    monkeypatch,
):
    runtime, store, request, manifest, work, armed_payload, parsed, context = (
        _physical_prepare_fixture(tmp_path, monkeypatch)
    )
    recovered: list[tuple[object, dict[str, object]]] = []

    def fail_record(*_args, **_kwargs):
        raise WorkerLifecycleError("SIMULATED_ARM_DURABLE_WRITE_FAILURE")

    def fail_recovery(value: object, **kwargs: object) -> bool:
        recovered.append((value, kwargs))
        return False

    monkeypatch.setattr(store, "record_armed_zero", fail_record)
    monkeypatch.setattr(
        "rolo.targetd.physical_worker.recover_armed_zero_process",
        fail_recovery,
    )

    with pytest.raises(ProcessWorkerError, match="PROCESS_WORKER_PREPARE_FAILED"):
        runtime.prepare_physical(
            request,
            manifest,
            worker_id="physical-worker",
            work=work,
        )

    assert recovered == [
        (
            parsed,
            {
                "expected_call_key_digest": WorkerCallKey.from_request(
                    request
                ).digest(),
                "expected_arm_receipt_digest": "c" * 64,
                "container": "MentorPi",
                "container_user": "ubuntu",
            },
        )
    ]
    record = store.load(WorkerCallKey.from_request(request))
    assert record is not None
    assert record.state == "UNKNOWN"
    assert record.outcome_code == "PROCESS_WORKER_PHYSICAL_RECOVERY_UNPROVED"
    assert runtime._slots_in_use == 0
    assert runtime._handles == {}
    assert context.parent.closed is True
    assert context.child.closed is True
    assert context.process is not None and context.process.is_alive() is False


def test_monitor_start_failure_exact_reaps_and_never_leaves_active(
    tmp_path,
    monkeypatch,
):
    runtime, store, request, manifest, work, armed_payload, _parsed, context = (
        _physical_prepare_fixture(tmp_path, monkeypatch)
    )
    recovered: list[tuple[object, dict[str, object]]] = []

    def fail_recovery(value: object, **kwargs: object) -> bool:
        recovered.append((value, kwargs))
        return False

    class _MonitorThatCannotStart:
        def __init__(self, **_kwargs) -> None:
            pass

        def start(self) -> None:
            raise RuntimeError("simulated monitor start failure")

    monkeypatch.setattr(
        "rolo.targetd.physical_worker.recover_persisted_armed_zero",
        fail_recovery,
    )
    monkeypatch.setattr(
        "rolo.targetd.process_worker.threading.Thread",
        _MonitorThatCannotStart,
    )

    with pytest.raises(
        ProcessWorkerError,
        match="PROCESS_WORKER_MONITOR_START_FAILED",
    ):
        runtime.prepare_physical(
            request,
            manifest,
            worker_id="physical-worker",
            work=work,
        )

    assert recovered == [
        (
            armed_payload,
            {
                "expected_call_key_digest": WorkerCallKey.from_request(
                    request
                ).digest(),
                "expected_target_id": request.target_id,
                "expected_call_id": request.idempotency_key,
                "expected_session_id": request.session_id,
                "expected_request_digest": request.request_digest(),
                "expected_execution_subject_digest": request.execution_subject_digest,
                "expected_runtime_sha256": manifest.observation_contract[
                    "provider_runtime_sha256"
                ],
                "container": "MentorPi",
                "container_user": "ubuntu",
            },
        )
    ]
    record = store.load(WorkerCallKey.from_request(request))
    assert record is not None
    assert record.armed_zero == armed_payload
    assert record.state == "UNKNOWN"
    assert record.outcome_code == "PROCESS_WORKER_PHYSICAL_RECOVERY_UNPROVED"
    assert runtime._slots_in_use == 0
    assert runtime._handles == {}
    assert context.parent.closed is True
    assert context.child.closed is True
    assert context.process is not None and context.process.is_alive() is False
