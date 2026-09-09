from __future__ import annotations

import os
import threading
import time
from datetime import datetime, timedelta, timezone

import pytest

from rolo.targetd.lifecycle import WorkerCompletion, WorkerControl, WorkerLeaseStore, WorkerLifecycleError
from rolo.targetd.lifecycle_integration import LeasedCallIntegrationError, LeasedProviderOutcome
from rolo.targetd.process_worker import LeasedProcessWorkerRuntime, ProcessWorkerControl, ProcessWorkerError
from tests.test_targetd_worker_integration import _physical_call, _readonly_call


class SuccessfulOdomWorker:
    provider_id = "ros2-readonly"
    provider_operation = "odom.sample"
    mode = "READ_ONLY"
    physical_capable = False

    def __call__(self, _control):
        return LeasedProviderOutcome(
            WorkerCompletion("SUCCEEDED", "ODOM_SAMPLE_SUCCEEDED"),
            {"status": "SUCCEEDED", "worker_pid": os.getpid()},
        )


class InterruptibleOdomWorker:
    provider_id = "ros2-readonly"
    provider_operation = "odom.sample"
    mode = "READ_ONLY"
    physical_capable = False

    def __call__(self, control):
        intent = control.wait_for_interrupt(10)
        if intent == "CANCEL":
            completion = WorkerCompletion("CANCELLED", "ODOM_CANCEL_CONFIRMED")
        elif intent == "STOP":
            completion = WorkerCompletion("STOPPED", "ODOM_STOP_CONFIRMED")
        else:
            completion = WorkerCompletion("FAILED", "ODOM_INTERRUPT_NOT_RECEIVED")
        return LeasedProviderOutcome(
            completion,
            {"status": completion.status, "worker_pid": os.getpid()},
        )


class CrashingOdomWorker:
    provider_id = "ros2-readonly"
    provider_operation = "odom.sample"
    mode = "READ_ONLY"
    physical_capable = False

    def __call__(self, _control):
        os._exit(23)


class BlockingOdomWorker:
    provider_id = "ros2-readonly"
    provider_operation = "odom.sample"
    mode = "READ_ONLY"
    physical_capable = False

    def __call__(self, _control):
        while True:
            time.sleep(0.05)


class OversizedOutcomeOdomWorker:
    provider_id = "ros2-readonly"
    provider_operation = "odom.sample"
    mode = "READ_ONLY"
    physical_capable = False

    def __call__(self, _control):
        return LeasedProviderOutcome(
            WorkerCompletion("SUCCEEDED", "ODOM_SAMPLE_SUCCEEDED"),
            {"payload": "x" * 65_400},
        )


class ExceptionalOdomWorker:
    provider_id = "ros2-readonly"
    provider_operation = "odom.sample"
    mode = "READ_ONLY"
    physical_capable = False

    def __call__(self, _control):
        raise RuntimeError("provider details must not escape the child")


class OversizedSpawnSpecOdomWorker(SuccessfulOdomWorker):
    def __init__(self):
        self.padding = b"x" * 65_536


class FalselyPhysicalWorker(SuccessfulOdomWorker):
    physical_capable = True


def _runtime(tmp_path, *, store=None, supervisor_id="targetd-process"):
    store = store or WorkerLeaseStore(tmp_path / "leases")
    return (
        LeasedProcessWorkerRuntime(
            store,
            supervisor_id=supervisor_id,
            allow_spawn_readonly_substrate=True,
        ),
        store,
    )


def test_process_runtime_requires_explicit_opt_in(tmp_path):
    store = WorkerLeaseStore(tmp_path / "leases")
    with pytest.raises(ProcessWorkerError, match="PROCESS_WORKER_EXPLICIT_OPT_IN_REQUIRED"):
        LeasedProcessWorkerRuntime(store, supervisor_id="targetd-process")
    assert store.list_records() == ()


def test_sealed_odom_worker_runs_in_spawned_process(tmp_path):
    request, manifest = _readonly_call(tmp_path)
    runtime, _ = _runtime(tmp_path)

    submission = runtime.submit(
        request,
        manifest,
        worker_id="odom-worker-1",
        work=SuccessfulOdomWorker(),
    )
    snapshot = runtime.join(submission.call_key, timeout_s=10)

    assert submission.process_id != os.getpid()
    assert submission.lease.state == "RUNNING"
    assert snapshot.lease.state == "SUCCEEDED"
    assert snapshot.outcome is not None
    assert snapshot.outcome.result["worker_pid"] == submission.process_id
    assert snapshot.process_exit_code == 0


@pytest.mark.parametrize(
    ("intent", "requested_state", "terminal_state", "outcome_code"),
    [
        ("CANCEL", "CANCEL_REQUESTED", "CANCELLED", "ODOM_CANCEL_CONFIRMED"),
        ("STOP", "STOP_REQUESTED", "STOPPED", "ODOM_STOP_CONFIRMED"),
    ],
)
def test_duplex_interrupt_requires_child_process_ack(
    tmp_path,
    intent,
    requested_state,
    terminal_state,
    outcome_code,
):
    request, manifest = _readonly_call(tmp_path)
    runtime, _ = _runtime(tmp_path)
    submission = runtime.submit(
        request,
        manifest,
        worker_id="odom-worker-1",
        work=InterruptibleOdomWorker(),
    )

    requested = runtime.request_interrupt(submission.call_key, intent=intent)
    assert requested.lease.state == requested_state
    assert requested.requested is True
    assert requested.acknowledged is False

    snapshot = runtime.join(submission.call_key, timeout_s=10)
    assert snapshot.lease.state == terminal_state
    assert snapshot.lease.outcome_code == outcome_code
    assert snapshot.lease.stop_acknowledgement is not None
    assert snapshot.lease.stop_acknowledgement.call_key == submission.call_key
    assert snapshot.lease.stop_acknowledgement.worker_id == "odom-worker-1"
    assert snapshot.lease.stop_acknowledgement.disposition == "WORKER_CONFIRMED"


def test_hard_process_crash_is_unknown_and_never_retried(tmp_path):
    request, manifest = _readonly_call(tmp_path)
    runtime, _ = _runtime(tmp_path)
    submission = runtime.submit(
        request,
        manifest,
        worker_id="odom-worker-1",
        work=CrashingOdomWorker(),
    )

    snapshot = runtime.join(submission.call_key, timeout_s=10)
    assert snapshot.lease.state == "UNKNOWN"
    assert snapshot.lease.outcome_code in {
        "PROCESS_WORKER_EXITED",
        "PROCESS_WORKER_IPC_INVALID",
    }
    assert snapshot.outcome is None
    assert snapshot.process_exit_code == 23

    with pytest.raises(WorkerLifecycleError, match="WORKER_CALL_ALREADY_TERMINAL"):
        runtime.submit(
            request,
            manifest,
            worker_id="odom-worker-2",
            work=SuccessfulOdomWorker(),
        )


def test_same_parent_configuration_restart_orphans_old_process(tmp_path):
    request, manifest = _readonly_call(
        tmp_path,
        deadline=datetime.now(timezone.utc) + timedelta(seconds=20),
    )
    store = WorkerLeaseStore(tmp_path / "leases")
    first, _ = _runtime(tmp_path, store=store, supervisor_id="targetd-process")
    submission = first.submit(
        request,
        manifest,
        worker_id="odom-worker-1",
        work=BlockingOdomWorker(),
        lease_ttl_s=2,
        heartbeat_interval_s=0.05,
    )

    second, _ = _runtime(tmp_path, store=store, supervisor_id="targetd-process")
    assert first.supervisor_id != second.supervisor_id
    reconciled = store.load(submission.call_key)
    assert reconciled is not None
    assert reconciled.state == "UNKNOWN"
    assert reconciled.outcome_code == "WORKER_SUPERVISOR_RESTARTED"

    snapshot = first.join(submission.call_key, timeout_s=10)
    assert snapshot.lease.state == "UNKNOWN"
    assert snapshot.outcome is None


def test_request_deadline_stops_blocked_child_process_unknown(tmp_path):
    request, manifest = _readonly_call(
        tmp_path,
        deadline=datetime.now(timezone.utc) + timedelta(seconds=3),
    )
    runtime, _ = _runtime(tmp_path)
    submission = runtime.submit(
        request,
        manifest,
        worker_id="odom-worker-1",
        work=BlockingOdomWorker(),
        lease_ttl_s=5,
        heartbeat_interval_s=0.05,
    )

    snapshot = runtime.join(submission.call_key, timeout_s=10)
    assert snapshot.lease.state == "UNKNOWN"
    assert snapshot.lease.outcome_code == "WORKER_LEASE_EXPIRED"
    assert snapshot.outcome is None


def test_oversized_child_ipc_result_fails_closed(tmp_path):
    request, manifest = _readonly_call(tmp_path)
    runtime, _ = _runtime(tmp_path)
    submission = runtime.submit(
        request,
        manifest,
        worker_id="odom-worker-1",
        work=OversizedOutcomeOdomWorker(),
    )

    snapshot = runtime.join(submission.call_key, timeout_s=10)
    assert snapshot.lease.state == "UNKNOWN"
    assert snapshot.outcome is None


def test_generic_child_exception_is_ambiguous_unknown(tmp_path):
    request, manifest = _readonly_call(tmp_path)
    runtime, _ = _runtime(tmp_path)
    submission = runtime.submit(
        request,
        manifest,
        worker_id="odom-worker-1",
        work=ExceptionalOdomWorker(),
    )

    snapshot = runtime.join(submission.call_key, timeout_s=10)
    assert snapshot.lease.state == "UNKNOWN"
    assert snapshot.lease.outcome_code == "PROCESS_WORKER_EXCEPTION_AMBIGUOUS"
    assert snapshot.ipc_outcome_code == "PROCESS_WORKER_EXCEPTION_AMBIGUOUS"
    assert snapshot.outcome is None


def test_future_heartbeat_clock_rollback_fails_closed(tmp_path):
    request, manifest = _readonly_call(
        tmp_path,
        deadline=datetime.now(timezone.utc) + timedelta(seconds=20),
    )
    runtime, store = _runtime(tmp_path)
    submission = runtime.submit(
        request,
        manifest,
        worker_id="odom-worker-1",
        work=BlockingOdomWorker(),
        lease_ttl_s=10,
        heartbeat_interval_s=0.05,
    )
    handle = runtime._require_handle(submission.call_key)
    store.heartbeat(
        handle.claim,
        now=datetime.now(timezone.utc) + timedelta(seconds=5),
    )

    snapshot = runtime.join(submission.call_key, timeout_s=10)
    assert snapshot.lease.state == "UNKNOWN"
    assert snapshot.lease.outcome_code == "WORKER_CLOCK_ROLLBACK"
    assert snapshot.outcome is None


def test_process_substrate_rejects_unsealed_or_physical_before_lease(tmp_path):
    request, manifest = _readonly_call(tmp_path)
    runtime, store = _runtime(tmp_path)
    with pytest.raises(ProcessWorkerError, match="PROCESS_WORKER_NOT_SEALED_ODOM_READONLY"):
        runtime.submit(
            request,
            manifest,
            worker_id="odom-worker-1",
            work=FalselyPhysicalWorker(),
        )
    assert store.list_records() == ()

    with pytest.raises(ProcessWorkerError, match="PROCESS_WORKER_SPAWN_SPEC_TOO_LARGE"):
        runtime.submit(
            request,
            manifest,
            worker_id="odom-worker-1",
            work=OversizedSpawnSpecOdomWorker(),
        )
    assert store.list_records() == ()

    physical_request, physical_manifest = _physical_call(tmp_path / "physical")
    with pytest.raises(
        LeasedCallIntegrationError,
        match="LEASED_PHYSICAL_PROCESS_ISOLATION_REQUIRED",
    ):
        runtime.submit(
            physical_request,
            physical_manifest,
            worker_id="physical-worker",
            work=SuccessfulOdomWorker(),
        )
    assert store.list_records() == ()


def test_wrong_exact_call_key_cannot_interrupt_process(tmp_path):
    request, manifest = _readonly_call(tmp_path)
    runtime, _ = _runtime(tmp_path)
    submission = runtime.submit(
        request,
        manifest,
        worker_id="odom-worker-1",
        work=InterruptibleOdomWorker(),
    )
    wrong = submission.call_key.model_copy(update={"target_id": "another-robot"})

    with pytest.raises(ProcessWorkerError, match="PROCESS_WORKER_CALL_NOT_LOCAL"):
        runtime.request_interrupt(wrong, intent="STOP")

    runtime.request_interrupt(submission.call_key, intent="STOP")
    snapshot = runtime.join(submission.call_key, timeout_s=10)
    assert snapshot.lease.state == "STOPPED"


def test_join_and_interrupt_wait_reject_non_finite_timeouts(tmp_path):
    request, manifest = _readonly_call(tmp_path)
    runtime, store = _runtime(tmp_path)
    submission = runtime.submit(
        request,
        manifest,
        worker_id="odom-worker-1",
        work=InterruptibleOdomWorker(),
    )
    handle = runtime._require_handle(submission.call_key)
    control = ProcessWorkerControl(WorkerControl(store, handle.claim))

    for invalid in (
        float("nan"),
        float("inf"),
        float("-inf"),
        threading.TIMEOUT_MAX + 1,
        10**10000,
    ):
        with pytest.raises(ProcessWorkerError, match="PROCESS_WORKER_JOIN_TIMEOUT_INVALID"):
            runtime.join(submission.call_key, timeout_s=invalid)
        with pytest.raises(ProcessWorkerError, match="PROCESS_WORKER_JOIN_TIMEOUT_INVALID"):
            control.wait_for_interrupt(invalid)

    runtime.request_interrupt(submission.call_key, intent="STOP")
    assert runtime.join(submission.call_key, timeout_s=10).lease.state == "STOPPED"


def test_concurrent_submit_cannot_bypass_single_process_capacity(tmp_path, monkeypatch):
    first_request, first_manifest = _readonly_call(
        tmp_path / "first",
        session_id="capacity-first",
    )
    second_request, second_manifest = _readonly_call(
        tmp_path / "second",
        session_id="capacity-second",
    )
    store = WorkerLeaseStore(tmp_path / "leases")
    runtime = LeasedProcessWorkerRuntime(
        store,
        supervisor_id="targetd-process",
        allow_spawn_readonly_substrate=True,
        max_processes=1,
    )
    original_claim = store.claim
    claim_entered = threading.Barrier(2)
    release_claim = threading.Barrier(2)

    def gated_claim(*args, **kwargs):
        claim_entered.wait(timeout=5)
        release_claim.wait(timeout=5)
        return original_claim(*args, **kwargs)

    monkeypatch.setattr(store, "claim", gated_claim)
    submissions = []
    errors = []

    def submit(request, manifest, worker_id):
        try:
            submissions.append(
                runtime.submit(
                    request,
                    manifest,
                    worker_id=worker_id,
                    work=SuccessfulOdomWorker(),
                )
            )
        except Exception as exc:
            errors.append(exc)

    first = threading.Thread(
        target=submit,
        args=(first_request, first_manifest, "odom-worker-1"),
    )
    first.start()
    claim_entered.wait(timeout=5)

    second = threading.Thread(
        target=submit,
        args=(second_request, second_manifest, "odom-worker-2"),
    )
    second.start()
    second.join(timeout=5)
    assert not second.is_alive()
    assert len(errors) == 1
    assert isinstance(errors[0], ProcessWorkerError)
    assert str(errors[0]) == "PROCESS_WORKER_CAPACITY_EXCEEDED"

    release_claim.wait(timeout=5)
    first.join(timeout=10)
    assert not first.is_alive()
    assert len(submissions) == 1
    runtime.join(submissions[0].call_key, timeout_s=10)

    monkeypatch.setattr(store, "claim", original_claim)
    second_submission = runtime.submit(
        second_request,
        second_manifest,
        worker_id="odom-worker-2",
        work=SuccessfulOdomWorker(),
    )
    assert runtime.join(second_submission.call_key, timeout_s=10).lease.state == "SUCCEEDED"
