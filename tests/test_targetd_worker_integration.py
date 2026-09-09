from __future__ import annotations

import threading
from datetime import datetime, timedelta, timezone

import pytest

from rolo.dsl.models import OperationKind
from rolo.targetd.lifecycle import (
    WorkerCallKey,
    WorkerCompletion,
    WorkerLeaseStore,
    WorkerLifecycleError,
)
from rolo.targetd.lifecycle_integration import (
    LeasedCallIntegrationError,
    LeasedProviderOutcome,
    TargetdLeasedCallCoordinator,
)
from rolo.targetd.protocol import (
    ExecutionBundleManifest,
    TargetdCallReceipt,
    TargetdExecutionAuthority,
    provider_fence_digest,
)
from tests.test_targetd_protocol import (
    _execution_request,
    _execution_session,
    _execution_setup,
)


def _readonly_call(
    tmp_path,
    *,
    session_id="leased-r0",
    deadline=None,
    tool_id="app.observe.odom",
    mode="READ_ONLY",
    observation_contract=None,
):
    source = b"raise RuntimeError('bundle source is not used by this seam')"
    manifest = ExecutionBundleManifest.build(
        tool_id=tool_id,
        source=source,
        binding_digest="a" * 64,
        signer_key_id="rolo-dev",
        signing_key=b"secret",
        observation_contract=(
            observation_contract
            if observation_contract is not None
            else {
                "provider": "ros2-readonly",
                "operation": "odom.sample",
                "mode": mode,
            }
        ),
    )
    service, authority, _, _ = _execution_setup(
        tmp_path,
        manifest,
        source,
        provider_id="ros2-readonly",
        provider_operation="odom.sample",
        operation_kind=OperationKind.OBSERVE,
        journey_session_id=session_id,
    )
    authority = TargetdExecutionAuthority.build(
        **authority.model_dump(
            mode="python",
            exclude={"schema_version", "authority_head_digest", "mode"},
        ),
        mode=mode,
    )
    session = _execution_session(service, authority, session_id)
    request = _execution_request(
        authority,
        session,
        deadline=deadline,
    )
    return request, manifest


class MemoryLeasedCallBackend:
    """Receipt-only backend used to verify the integration ordering contract."""

    def __init__(self, store: WorkerLeaseStore) -> None:
        self.store = store
        self.receipts: dict[str, TargetdCallReceipt] = {}
        self.events: list[str] = []
        self.fail_completion = False
        self._lock = threading.RLock()

    @staticmethod
    def _key(request) -> WorkerCallKey:
        return WorkerCallKey.from_request(request)

    def accept_call(self, request, manifest, *, provider_id):
        key = self._key(request)
        lease = self.store.load(key)
        assert lease is not None
        assert lease.state == "CLAIMED"
        with self._lock:
            existing = self.receipts.get(key.digest())
            if existing is not None:
                return existing
            receipt = TargetdCallReceipt(
                schema_version="rolo-targetd-call-receipt/v2",
                idempotency_key=request.idempotency_key,
                session_id=request.session_id,
                target_id=request.target_id,
                bundle_digest=request.bundle_digest,
                request_digest=request.request_digest(),
                release_digest=request.release_digest,
                context_digest=request.context_digest,
                mapping_confirmation_receipt_digest=request.mapping_confirmation_receipt_digest,
                authority_head_digest=request.authority_head_digest,
                fence_epoch=request.fence_epoch,
                provider_id=provider_id,
                provider_operation=request.provider_operation,
                provider_fence_digest=provider_fence_digest(request),
                status="ACCEPTED",
                updated_at=datetime.now(timezone.utc),
            )
            self.receipts[key.digest()] = receipt
            self.events.append(f"accept:{lease.state}")
            return receipt

    def begin_provider(self, request, manifest, *, provider_id, lease):
        key = self._key(request)
        assert manifest.bundle_digest == request.bundle_digest
        assert provider_id == request.provider_id
        assert lease.call_key == key
        assert lease.state == "RUNNING"
        with self._lock:
            current = self.receipts[key.digest()]
            started = current.model_copy(
                update={
                    "status": "STARTED",
                    "provider_started_at": datetime.now(timezone.utc),
                    "updated_at": datetime.now(timezone.utc),
                }
            )
            self.receipts[key.digest()] = started
            self.events.append(f"begin:{lease.state}")
            return started

    def complete_provider(self, request, manifest, *, provider_id, lease, outcome):
        if self.fail_completion:
            raise RuntimeError("simulated receipt persistence failure")
        key = self._key(request)
        assert manifest.bundle_digest == request.bundle_digest
        assert provider_id == request.provider_id
        assert lease.call_key == key
        assert lease.state == outcome.completion.status
        if lease.state in {"CANCELLED", "STOPPED"}:
            assert lease.stop_acknowledgement is not None
            assert lease.stop_acknowledgement.call_key == key
        with self._lock:
            current = self.receipts[key.digest()]
            completed = current.model_copy(
                update={
                    "status": outcome.completion.status,
                    "result": dict(outcome.result),
                    "updated_at": datetime.now(timezone.utc),
                }
            )
            self.receipts[key.digest()] = completed
            self.events.append(f"complete:{lease.state}")
            return completed

    def query_receipt(self, call_key):
        with self._lock:
            return self.receipts.get(call_key.digest())

    def mark_unknown(self, call_key, *, outcome_code):
        with self._lock:
            current = self.receipts.get(call_key.digest())
            if current is None or current.status not in {"ACCEPTED", "STARTED"}:
                return current
            unknown = current.model_copy(
                update={
                    "status": "UNKNOWN",
                    "result": {"code": outcome_code},
                    "updated_at": datetime.now(timezone.utc),
                }
            )
            self.receipts[call_key.digest()] = unknown
            self.events.append("receipt:UNKNOWN")
            return unknown


def _coordinator(tmp_path, *, backend=None, store=None, supervisor_id="targetd-instance-1"):
    store = store or WorkerLeaseStore(tmp_path / "leases")
    backend = backend or MemoryLeasedCallBackend(store)
    return (
        TargetdLeasedCallCoordinator(
            backend,
            store,
            supervisor_id=supervisor_id,
            provider_id="ros2-readonly",
            allow_in_process_readonly_test_seam=True,
        ),
        backend,
        store,
    )


def test_in_process_seam_requires_explicit_nonphysical_opt_in(tmp_path):
    store = WorkerLeaseStore(tmp_path / "leases")
    backend = MemoryLeasedCallBackend(store)

    with pytest.raises(
        LeasedCallIntegrationError,
        match="LEASED_IN_PROCESS_READONLY_TEST_SEAM_OPT_IN_REQUIRED",
    ):
        TargetdLeasedCallCoordinator(
            backend,
            store,
            supervisor_id="targetd-instance-1",
        )

    assert backend.events == []
    assert store.list_records() == ()


def test_in_process_seam_rejects_provider_override_at_construction(tmp_path):
    store = WorkerLeaseStore(tmp_path / "leases")
    backend = MemoryLeasedCallBackend(store)

    with pytest.raises(
        LeasedCallIntegrationError,
        match="LEASED_PROVIDER_NOT_SEALED_READ_ONLY",
    ):
        TargetdLeasedCallCoordinator(
            backend,
            store,
            supervisor_id="targetd-instance-1",
            provider_id="ros-container",
            allow_in_process_readonly_test_seam=True,
        )

    assert backend.events == []
    assert store.list_records() == ()


def test_leased_call_persists_claim_and_running_before_provider(tmp_path):
    request, manifest = _readonly_call(tmp_path)
    coordinator, backend, _ = _coordinator(tmp_path)

    submission = coordinator.submit(
        request,
        manifest,
        worker_id="worker-1",
        execute=lambda _control: LeasedProviderOutcome(
            WorkerCompletion("SUCCEEDED", "PROVIDER_SUCCEEDED"),
            {"status": "SUCCEEDED", "sha256": "sha256:" + "a" * 64, "byte_count": 16},
        ),
    )
    snapshot = coordinator.join(WorkerCallKey.from_request(request), timeout_s=2)

    assert submission.worker_started is True
    assert submission.replayed is False
    assert snapshot.lease.state == "SUCCEEDED"
    assert snapshot.receipt.status == "SUCCEEDED"
    assert backend.events == ["accept:CLAIMED", "begin:RUNNING", "complete:SUCCEEDED"]


@pytest.mark.parametrize(
    ("intent", "terminal_status", "outcome_code"),
    [
        ("CANCEL", "CANCELLED", "PROVIDER_CANCEL_CONFIRMED"),
        ("STOP", "STOPPED", "PROVIDER_STOP_CONFIRMED"),
    ],
)
def test_interrupt_request_is_not_stop_ack(intent, terminal_status, outcome_code, tmp_path):
    request, manifest = _readonly_call(tmp_path)
    coordinator, backend, _ = _coordinator(tmp_path)
    provider_running = threading.Event()
    stop_signalled = threading.Event()
    allow_ack = threading.Event()

    def execute(control):
        provider_running.set()
        assert stop_signalled.wait(2)
        assert allow_ack.wait(2)
        control.heartbeat()
        assert control.interrupt_intent() == intent
        return LeasedProviderOutcome(
            WorkerCompletion(terminal_status, outcome_code),
            {"status": terminal_status},
        )

    coordinator.submit(
        request,
        manifest,
        worker_id="worker-1",
        execute=execute,
        stop_signal=lambda observed: stop_signalled.set() if observed == intent else None,
    )
    assert provider_running.wait(2)
    interrupted = coordinator.request_interrupt(
        WorkerCallKey.from_request(request),
        intent=intent,
    )

    assert interrupted.requested is True
    assert interrupted.acknowledged is False
    assert interrupted.lease.state == f"{intent}_REQUESTED"
    assert backend.query_receipt(interrupted.call_key).status == "STARTED"

    allow_ack.set()
    snapshot = coordinator.join(interrupted.call_key, timeout_s=2)
    assert snapshot.lease.state == terminal_status
    assert snapshot.lease.stop_acknowledgement is not None
    assert snapshot.receipt.status == terminal_status


def test_provider_exception_is_reconciled_unknown_without_replay(tmp_path):
    request, manifest = _readonly_call(tmp_path)
    coordinator, backend, _ = _coordinator(tmp_path)

    def execute(_control):
        raise RuntimeError("provider crossed an unknown boundary")

    coordinator.submit(request, manifest, worker_id="worker-1", execute=execute)
    snapshot = coordinator.join(WorkerCallKey.from_request(request), timeout_s=2)
    assert snapshot.lease.state == "UNKNOWN"
    assert snapshot.lease.outcome_code == "WORKER_EXCEPTION_AMBIGUOUS"
    assert snapshot.receipt.status == "UNKNOWN"
    assert backend.events.count("begin:RUNNING") == 1

    replay = coordinator.submit(request, manifest, worker_id="worker-2", execute=execute)
    assert replay.replayed is True
    assert replay.worker_started is False
    assert backend.events.count("begin:RUNNING") == 1


def test_explicit_failed_outcome_is_the_only_failed_terminal(tmp_path):
    request, manifest = _readonly_call(tmp_path)
    coordinator, _, _ = _coordinator(tmp_path)
    coordinator.submit(
        request,
        manifest,
        worker_id="worker-1",
        execute=lambda _control: LeasedProviderOutcome(
            WorkerCompletion("FAILED", "PROVIDER_REPORTED_FAILURE"),
            {"status": "FAILED", "error": "SAFE_PROVIDER_FAILURE"},
        ),
    )
    snapshot = coordinator.join(WorkerCallKey.from_request(request), timeout_s=2)
    assert snapshot.lease.state == "FAILED"
    assert snapshot.receipt.status == "FAILED"


def test_deadline_rejects_before_receipt_or_provider(tmp_path):
    request, manifest = _readonly_call(
        tmp_path,
        deadline=datetime.now(timezone.utc) - timedelta(seconds=1),
    )
    coordinator, backend, store = _coordinator(tmp_path)

    with pytest.raises(WorkerLifecycleError, match="WORKER_CALL_DEADLINE_EXPIRED"):
        coordinator.submit(
            request,
            manifest,
            worker_id="worker-1",
            execute=lambda _control: LeasedProviderOutcome(
                WorkerCompletion("SUCCEEDED", "PROVIDER_SUCCEEDED"),
                {},
            ),
        )
    assert backend.events == []
    assert store.list_records() == ()


def test_deadline_expiring_during_begin_prevents_provider_callback(
    tmp_path,
    monkeypatch,
):
    request, manifest = _readonly_call(tmp_path)
    coordinator, backend, store = _coordinator(tmp_path)
    original_heartbeat = store.heartbeat
    heartbeat_calls = 0
    provider_calls = 0

    def heartbeat(claim, *, now=None):
        nonlocal heartbeat_calls
        heartbeat_calls += 1
        forced_now = request.deadline if heartbeat_calls == 2 else now
        return original_heartbeat(claim, now=forced_now)

    def execute(_control):
        nonlocal provider_calls
        provider_calls += 1
        return LeasedProviderOutcome(
            WorkerCompletion("SUCCEEDED", "PROVIDER_SUCCEEDED"),
            {"status": "SUCCEEDED"},
        )

    monkeypatch.setattr(store, "heartbeat", heartbeat)
    coordinator.submit(
        request,
        manifest,
        worker_id="worker-1",
        execute=execute,
    )
    snapshot = coordinator.join(WorkerCallKey.from_request(request), timeout_s=2)

    assert heartbeat_calls == 2
    assert provider_calls == 0
    assert snapshot.lease.state == "UNKNOWN"
    assert snapshot.lease.outcome_code == "WORKER_LEASE_EXPIRED"
    assert snapshot.receipt.status == "UNKNOWN"
    assert backend.events == ["accept:CLAIMED", "begin:RUNNING", "receipt:UNKNOWN"]


def test_seam_rejects_nonempty_readonly_arguments_before_lease(tmp_path):
    request, manifest = _readonly_call(tmp_path)
    request = request.model_copy(update={"arguments": {"topic": "/cmd_vel"}})
    coordinator, backend, store = _coordinator(tmp_path)

    with pytest.raises(
        LeasedCallIntegrationError,
        match="LEASED_READ_ONLY_CAPABILITY_REQUIRED",
    ):
        coordinator.submit(
            request,
            manifest,
            worker_id="worker-1",
            execute=lambda _control: pytest.fail("provider must not run"),
        )
    assert backend.events == []
    assert store.list_records() == ()


def test_seam_rejects_tool_alias_for_odom_operation_before_lease(tmp_path):
    request, manifest = _readonly_call(
        tmp_path,
        tool_id="app.observe.odom-alias",
    )
    coordinator, backend, store = _coordinator(tmp_path)

    with pytest.raises(
        LeasedCallIntegrationError,
        match="LEASED_READ_ONLY_CAPABILITY_REQUIRED",
    ):
        coordinator.submit(
            request,
            manifest,
            worker_id="worker-1",
            execute=lambda _control: pytest.fail("provider must not run"),
        )
    assert backend.events == []
    assert store.list_records() == ()


@pytest.mark.parametrize(
    ("mode", "contract"),
    [
        (
            "SUPERVISED_FIELD_DEBUG",
            {
                "provider": "ros2-readonly",
                "operation": "odom.sample",
                "mode": "SUPERVISED_FIELD_DEBUG",
            },
        ),
        (
            "READ_ONLY",
            {
                "provider": "ros2-readonly",
                "operation": "odom.sample",
                "mode": "READ_ONLY",
                "unreviewed_extension": True,
            },
        ),
    ],
)
def test_seam_requires_exact_readonly_mode_and_manifest_contract(
    tmp_path,
    mode,
    contract,
):
    request, manifest = _readonly_call(
        tmp_path,
        mode=mode,
        observation_contract=contract,
    )
    coordinator, backend, store = _coordinator(tmp_path)

    with pytest.raises(
        LeasedCallIntegrationError,
        match="LEASED_READ_ONLY_CAPABILITY_REQUIRED",
    ):
        coordinator.submit(
            request,
            manifest,
            worker_id="worker-1",
            execute=lambda _control: pytest.fail("provider must not run"),
        )
    assert backend.events == []
    assert store.list_records() == ()


def test_same_supervisor_configuration_restart_reconciles_started_call_unknown(tmp_path):
    request, manifest = _readonly_call(tmp_path)
    store = WorkerLeaseStore(tmp_path / "leases")
    backend = MemoryLeasedCallBackend(store)
    first, _, _ = _coordinator(
        tmp_path,
        backend=backend,
        store=store,
        supervisor_id="targetd-instance-1",
    )
    key = WorkerCallKey.from_request(request)
    claim = first.runtime.reserve(
        key,
        worker_id="worker-1",
        deadline_at=request.deadline,
    )
    backend.accept_call(request, manifest, provider_id="ros2-readonly")
    store.start(claim)
    backend.begin_provider(
        request,
        manifest,
        provider_id="ros2-readonly",
        lease=store.load(key),
    )

    second, _, _ = _coordinator(
        tmp_path,
        backend=backend,
        store=store,
        supervisor_id="targetd-instance-1",
    )
    assert second.supervisor_id != first.supervisor_id
    snapshot = second.query(key)
    assert snapshot.lease.state == "UNKNOWN"
    assert snapshot.lease.outcome_code == "WORKER_SUPERVISOR_RESTARTED"
    assert snapshot.receipt.status == "UNKNOWN"


def test_receipt_finalization_gap_fails_closed_instead_of_replaying(tmp_path):
    request, manifest = _readonly_call(tmp_path)
    coordinator, backend, _ = _coordinator(tmp_path)
    backend.fail_completion = True
    coordinator.submit(
        request,
        manifest,
        worker_id="worker-1",
        execute=lambda _control: LeasedProviderOutcome(
            WorkerCompletion("SUCCEEDED", "PROVIDER_SUCCEEDED"),
            {"status": "SUCCEEDED"},
        ),
    )

    snapshot = coordinator.join(WorkerCallKey.from_request(request), timeout_s=2)
    assert snapshot.lease.state == "SUCCEEDED"
    assert snapshot.receipt.status == "UNKNOWN"
    assert snapshot.receipt.result == {"code": "LEASE_TERMINAL_RECEIPT_UNFINALIZED"}

    replay = coordinator.submit(
        request,
        manifest,
        worker_id="worker-2",
        execute=lambda _control: pytest.fail("provider must not replay"),
    )
    assert replay.replayed is True
    assert replay.worker_started is False


def _physical_call(tmp_path, *, force_v2=False):
    source = b"def execute(arguments): return arguments"
    manifest = ExecutionBundleManifest.build(
        tool_id="app.generic",
        source=source,
        binding_digest="a" * 64,
        signer_key_id="rolo-dev",
        signing_key=b"secret",
    )
    service, authority, _, _ = _execution_setup(
        tmp_path,
        manifest,
        source,
        journey_session_id="physical-v2",
    )
    session = _execution_session(service, authority, "physical-v2")
    request = _execution_request(authority, session, force_v2=force_v2)
    return request, manifest


def test_physical_v2_request_is_rejected_before_lease(tmp_path):
    request, manifest = _physical_call(tmp_path, force_v2=True)
    coordinator, backend, store = _coordinator(tmp_path)

    with pytest.raises(ValueError, match="PHYSICAL_MOTION_EXECUTION_REQUEST_V3_REQUIRED"):
        coordinator.submit(
            request,
            manifest,
            worker_id="worker-1",
            execute=lambda _control: pytest.fail("provider must not run"),
        )
    assert backend.events == []
    assert store.list_records() == ()


def test_physical_v3_request_is_rejected_without_process_isolation(tmp_path):
    request, manifest = _physical_call(tmp_path)
    coordinator, backend, store = _coordinator(tmp_path)

    with pytest.raises(
        LeasedCallIntegrationError,
        match="LEASED_PHYSICAL_PROCESS_ISOLATION_REQUIRED",
    ):
        coordinator.submit(
            request,
            manifest,
            worker_id="worker-1",
            execute=lambda _control: pytest.fail("provider must not run"),
        )
    assert backend.events == []
    assert store.list_records() == ()
