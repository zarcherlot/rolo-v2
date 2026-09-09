from __future__ import annotations

import json
import threading
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from rolo.targetd.lifecycle import (
    MAX_WORKER_LEASE_STATE_BYTES,
    MAX_WORKER_LEASES,
    LeasedWorkerRuntime,
    WorkerCallKey,
    WorkerCompletion,
    WorkerLeaseClaim,
    WorkerLeaseStore,
    WorkerLifecycleError,
)

NOW = datetime(2026, 9, 8, 12, 0, tzinfo=timezone.utc)


def _key(
    *,
    target_id: str = "mentorpi",
    session_id: str = "session-1",
    idempotency_key: str = "call-1",
    request_digest: str = "a" * 64,
) -> WorkerCallKey:
    return WorkerCallKey(
        target_id=target_id,
        session_id=session_id,
        idempotency_key=idempotency_key,
        request_digest=request_digest,
    )


def test_worker_lease_heartbeat_and_terminal_completion_are_durable(tmp_path):
    store = WorkerLeaseStore(tmp_path / "state")
    key = _key()
    claim = store.claim(
        key,
        supervisor_id="targetd-1",
        worker_id="worker-1",
        lease_ttl_s=5,
        now=NOW,
    )

    assert claim.lease.state == "CLAIMED"
    assert claim.lease.generation == 1
    assert claim.lease_token not in store.path.read_text(encoding="utf-8")

    started = store.start(claim, now=NOW + timedelta(seconds=1))
    assert started.state == "RUNNING"
    assert started.provider_started_at == NOW + timedelta(seconds=1)

    heartbeat = store.heartbeat(claim, now=NOW + timedelta(seconds=2))
    assert heartbeat.heartbeat_count == 1
    assert heartbeat.expires_at == NOW + timedelta(seconds=7)

    completed = store.complete(
        claim,
        status="SUCCEEDED",
        outcome_code="PROVIDER_SUCCEEDED",
        now=NOW + timedelta(seconds=3),
    )
    assert completed.state == "SUCCEEDED"
    assert completed.finished_at == NOW + timedelta(seconds=3)
    assert WorkerLeaseStore(tmp_path / "state").load(key) == completed

    with pytest.raises(WorkerLifecycleError, match="WORKER_CALL_ALREADY_TERMINAL"):
        store.claim(
            key,
            supervisor_id="targetd-1",
            worker_id="worker-2",
            now=NOW + timedelta(seconds=4),
        )


def test_interrupt_is_scoped_to_complete_call_key(tmp_path):
    store = WorkerLeaseStore(tmp_path / "state")
    first = _key(session_id="session-a", idempotency_key="same-key", request_digest="a" * 64)
    second = _key(session_id="session-b", idempotency_key="same-key", request_digest="b" * 64)
    other_target = _key(
        target_id="another-robot",
        session_id="session-a",
        idempotency_key="same-key",
        request_digest="a" * 64,
    )
    store.claim(first, supervisor_id="targetd-1", worker_id="worker-a", now=NOW)
    store.claim(second, supervisor_id="targetd-1", worker_id="worker-b", now=NOW)
    store.claim(other_target, supervisor_id="targetd-1", worker_id="worker-c", now=NOW)

    cancelled = store.request_interrupt(first, intent="CANCEL", now=NOW + timedelta(seconds=1))
    assert cancelled.state == "CANCELLED"
    assert cancelled.stop_acknowledgement is not None
    assert cancelled.stop_acknowledgement.disposition == "NOT_STARTED"
    assert cancelled.stop_acknowledgement.outcome_code == "PROVIDER_NOT_STARTED"
    assert store.load(second).state == "CLAIMED"
    assert store.load(other_target).state == "CLAIMED"

    mismatched = first.model_copy(update={"request_digest": "c" * 64})
    with pytest.raises(WorkerLifecycleError, match="WORKER_CALL_NOT_FOUND"):
        store.request_interrupt(mismatched, intent="CANCEL", now=NOW + timedelta(seconds=1))


def test_running_interrupt_requires_same_worker_acknowledgement(tmp_path):
    store = WorkerLeaseStore(tmp_path / "state")
    key = _key()
    claim = store.claim(
        key,
        supervisor_id="targetd-1",
        worker_id="worker-1",
        now=NOW,
    )
    store.start(claim, now=NOW + timedelta(seconds=1))

    requested = store.request_interrupt(key, intent="STOP", now=NOW + timedelta(seconds=2))
    assert requested.state == "STOP_REQUESTED"
    assert requested.stop_acknowledgement is None

    with pytest.raises(WorkerLifecycleError, match="WORKER_INTERRUPT_ACK_REQUIRED"):
        store.complete(
            claim,
            status="SUCCEEDED",
            outcome_code="PROVIDER_SUCCEEDED",
            now=NOW + timedelta(seconds=3),
        )
    with pytest.raises(WorkerLifecycleError, match="WORKER_INTERRUPT_INTENT_CONFLICT"):
        store.request_interrupt(key, intent="CANCEL", now=NOW + timedelta(seconds=3))

    wrong_claim = replace(claim, lease_token="A" * 43)
    with pytest.raises(WorkerLifecycleError, match="WORKER_LEASE_CLAIM_MISMATCH"):
        store.acknowledge_interrupt(
            wrong_claim,
            intent="STOP",
            outcome_code="PROVIDER_STOP_CONFIRMED",
            now=NOW + timedelta(seconds=3),
        )

    stopped = store.acknowledge_interrupt(
        claim,
        intent="STOP",
        outcome_code="PROVIDER_STOP_CONFIRMED",
        now=NOW + timedelta(seconds=3),
    )
    assert stopped.state == "STOPPED"
    assert stopped.stop_acknowledgement is not None
    assert stopped.stop_acknowledgement.disposition == "WORKER_CONFIRMED"
    assert stopped.stop_acknowledgement.worker_id == "worker-1"
    assert stopped.stop_acknowledgement.call_key.target_id == "mentorpi"
    assert stopped.stop_acknowledgement.call_key_digest == key.digest()


def test_interrupt_ack_window_cannot_be_extended_by_heartbeat(tmp_path):
    store = WorkerLeaseStore(tmp_path / "state")
    key = _key()
    claim = store.claim(
        key,
        supervisor_id="targetd-1",
        worker_id="worker-1",
        lease_ttl_s=5,
        now=NOW,
    )
    store.start(claim, now=NOW + timedelta(seconds=1))
    requested = store.request_interrupt(
        key,
        intent="CANCEL",
        now=NOW + timedelta(seconds=2),
    )
    original_deadline = requested.expires_at

    heartbeat = store.heartbeat(claim, now=NOW + timedelta(seconds=3))
    assert heartbeat.heartbeat_count == 1
    assert heartbeat.expires_at == original_deadline

    reconciled = store.reconcile(
        key,
        supervisor_id="targetd-1",
        now=NOW + timedelta(seconds=6),
    )
    assert reconciled.state == "UNKNOWN"
    assert reconciled.outcome_code == "WORKER_LEASE_EXPIRED"


def test_request_deadline_is_a_nonrenewable_lease_ceiling(tmp_path):
    store = WorkerLeaseStore(tmp_path / "state")
    key = _key()
    deadline = NOW + timedelta(seconds=3)
    claim = store.claim(
        key,
        supervisor_id="targetd-1",
        worker_id="worker-1",
        lease_ttl_s=10,
        deadline_at=deadline,
        now=NOW,
    )
    assert claim.lease.expires_at == deadline
    store.start(claim, now=NOW + timedelta(seconds=1))
    heartbeat = store.heartbeat(claim, now=NOW + timedelta(seconds=2))
    assert heartbeat.expires_at == deadline

    reconciled = store.reconcile(
        key,
        supervisor_id="targetd-1",
        now=NOW + timedelta(seconds=3),
    )
    assert reconciled.state == "UNKNOWN"
    assert reconciled.outcome_code == "WORKER_LEASE_EXPIRED"

    with pytest.raises(WorkerLifecycleError, match="WORKER_CALL_DEADLINE_EXPIRED"):
        WorkerLeaseStore(tmp_path / "other").claim(
            _key(idempotency_key="expired-call"),
            supervisor_id="targetd-1",
            worker_id="worker-2",
            deadline_at=NOW,
            now=NOW,
        )


def test_expired_lease_becomes_unknown_and_is_never_reclaimed(tmp_path):
    store = WorkerLeaseStore(tmp_path / "state")
    key = _key()
    claim = store.claim(
        key,
        supervisor_id="targetd-1",
        worker_id="worker-1",
        lease_ttl_s=1,
        now=NOW,
    )
    store.start(claim, now=NOW + timedelta(milliseconds=100))

    with pytest.raises(WorkerLifecycleError, match="WORKER_LEASE_RECONCILIATION_REQUIRED"):
        store.heartbeat(claim, now=NOW + timedelta(seconds=2))
    unknown = store.load(key)
    assert unknown is not None
    assert unknown.state == "UNKNOWN"
    assert unknown.outcome_code == "WORKER_LEASE_EXPIRED"

    with pytest.raises(WorkerLifecycleError, match="WORKER_CALL_ALREADY_TERMINAL"):
        store.claim(
            key,
            supervisor_id="targetd-1",
            worker_id="worker-2",
            now=NOW + timedelta(seconds=3),
        )


def test_new_supervisor_reconciles_live_orphan_to_unknown(tmp_path):
    store = WorkerLeaseStore(tmp_path / "state")
    key = _key()
    claim = store.claim(
        key,
        supervisor_id="targetd-old",
        worker_id="worker-1",
        lease_ttl_s=30,
        now=NOW,
    )
    store.start(claim, now=NOW + timedelta(seconds=1))

    records = store.reconcile_all(
        supervisor_id="targetd-new",
        now=NOW + timedelta(seconds=2),
    )
    assert len(records) == 1
    assert records[0].state == "UNKNOWN"
    assert records[0].outcome_code == "WORKER_SUPERVISOR_RESTARTED"


def test_wall_clock_rollback_fail_closes_active_lease(tmp_path):
    store = WorkerLeaseStore(tmp_path / "state")
    key = _key()
    claim = store.claim(
        key,
        supervisor_id="targetd-1",
        worker_id="worker-1",
        lease_ttl_s=30,
        now=NOW,
    )
    store.start(claim, now=NOW + timedelta(seconds=2))
    store.heartbeat(claim, now=NOW + timedelta(seconds=3))

    record = store.reconcile(
        key,
        supervisor_id="targetd-1",
        now=NOW + timedelta(seconds=2),
    )
    assert record.state == "UNKNOWN"
    assert record.outcome_code == "WORKER_CLOCK_ROLLBACK"
    # Persisted UTC wall-clock time cannot move backwards. The heartbeat
    # counter is the monotonic ordering signal inside one lease generation.
    assert record.finished_at == NOW + timedelta(seconds=3)
    assert record.heartbeat_count == 1


def test_reconcile_keeps_current_nonexpired_worker_running(tmp_path):
    store = WorkerLeaseStore(tmp_path / "state")
    key = _key()
    claim = store.claim(
        key,
        supervisor_id="targetd-1",
        worker_id="worker-1",
        lease_ttl_s=30,
        now=NOW,
    )
    store.start(claim, now=NOW + timedelta(seconds=1))

    record = store.reconcile(
        key,
        supervisor_id="targetd-1",
        now=NOW + timedelta(seconds=2),
    )
    assert record.state == "RUNNING"


def test_leased_runtime_cooperatively_cancels_and_appends_worker_ack(tmp_path):
    store = WorkerLeaseStore(tmp_path / "state")
    runtime = LeasedWorkerRuntime(store, supervisor_id="targetd-1")
    key = _key()
    running = threading.Event()
    stop_signalled = threading.Event()

    def work(control):
        running.set()
        assert stop_signalled.wait(2)
        control.heartbeat()
        assert control.interrupt_intent() == "CANCEL"
        return WorkerCompletion("CANCELLED", "PROVIDER_CANCEL_CONFIRMED")

    runtime.submit(
        key,
        worker_id="worker-1",
        work=work,
        stop_signal=lambda intent: stop_signalled.set(),
    )
    assert running.wait(2)
    requested = runtime.request_interrupt(key, intent="CANCEL")
    assert requested.state == "CANCEL_REQUESTED"

    terminal = runtime.join(key, timeout_s=2)
    assert terminal.state == "CANCELLED"
    assert terminal.outcome_code == "PROVIDER_CANCEL_CONFIRMED"
    assert terminal.stop_acknowledgement is not None
    assert terminal.stop_acknowledgement.disposition == "WORKER_CONFIRMED"


def test_runtime_restart_with_same_configuration_gets_fresh_incarnation(tmp_path):
    store = WorkerLeaseStore(tmp_path / "state")
    first = LeasedWorkerRuntime(store, supervisor_id="targetd-config")
    key = _key()
    claim = first.reserve(key, worker_id="worker-1")
    store.start(claim)

    second = LeasedWorkerRuntime(store, supervisor_id="targetd-config")
    reconciled = store.load(key)

    assert first.supervisor_name == second.supervisor_name == "targetd-config"
    assert first.supervisor_id != second.supervisor_id
    assert claim.lease.supervisor_id == first.supervisor_id
    assert reconciled is not None
    assert reconciled.state == "UNKNOWN"
    assert reconciled.outcome_code == "WORKER_SUPERVISOR_RESTARTED"


def test_leased_runtime_observed_worker_crash_is_unknown(tmp_path):
    store = WorkerLeaseStore(tmp_path / "state")
    runtime = LeasedWorkerRuntime(store, supervisor_id="targetd-1")
    key = _key()

    def crash(_control):
        raise SystemExit(17)

    runtime.submit(key, worker_id="worker-1", work=crash)
    terminal = runtime.join(key, timeout_s=2)
    assert terminal.state == "UNKNOWN"
    assert terminal.outcome_code == "WORKER_CRASH_OBSERVED"


def test_worker_exception_is_unknown_without_persisting_exception_detail(tmp_path):
    store = WorkerLeaseStore(tmp_path / "state")
    runtime = LeasedWorkerRuntime(store, supervisor_id="targetd-1")
    key = _key()

    def fail(_control):
        raise RuntimeError("secret-provider-detail")

    runtime.submit(key, worker_id="worker-1", work=fail)
    terminal = runtime.join(key, timeout_s=2)
    assert terminal.state == "UNKNOWN"
    assert terminal.outcome_code == "WORKER_EXCEPTION_AMBIGUOUS"
    assert "secret-provider-detail" not in store.path.read_text(encoding="utf-8")


def test_only_explicit_worker_completion_can_report_failed(tmp_path):
    store = WorkerLeaseStore(tmp_path / "state")
    runtime = LeasedWorkerRuntime(store, supervisor_id="targetd-1")
    key = _key()

    runtime.submit(
        key,
        worker_id="worker-1",
        work=lambda _control: WorkerCompletion("FAILED", "PROVIDER_REPORTED_FAILURE"),
    )
    terminal = runtime.join(key, timeout_s=2)
    assert terminal.state == "FAILED"
    assert terminal.outcome_code == "PROVIDER_REPORTED_FAILURE"


def test_worker_thread_exit_with_active_record_is_unknown(tmp_path):
    store = WorkerLeaseStore(tmp_path / "state")
    runtime = LeasedWorkerRuntime(store, supervisor_id="targetd-1")
    key = _key()

    # A worker cannot claim CANCELLED without a matching interrupt request and
    # worker acknowledgement. The thread has nevertheless exited, so join
    # must not return the leftover RUNNING record as though it were alive.
    runtime.submit(
        key,
        worker_id="worker-1",
        work=lambda _control: WorkerCompletion("CANCELLED", "PROVIDER_CANCEL_CONFIRMED"),
    )
    terminal = runtime.join(key, timeout_s=2)
    assert terminal.state == "UNKNOWN"
    assert terminal.outcome_code == "WORKER_EXITED_WITHOUT_TERMINAL_STATE"


def test_concurrent_claim_has_exactly_one_winner(tmp_path):
    store = WorkerLeaseStore(tmp_path / "state")
    key = _key()
    barrier = threading.Barrier(5)
    outcomes: list[str] = []
    outcomes_lock = threading.Lock()

    def claim(worker_number: int) -> None:
        barrier.wait()
        try:
            store.claim(
                key,
                supervisor_id="targetd-1",
                worker_id=f"worker-{worker_number}",
                now=NOW,
            )
        except WorkerLifecycleError as exc:
            outcome = str(exc)
        else:
            outcome = "CLAIMED"
        with outcomes_lock:
            outcomes.append(outcome)

    threads = [threading.Thread(target=claim, args=(index,)) for index in range(4)]
    for thread in threads:
        thread.start()
    barrier.wait()
    for thread in threads:
        thread.join(2)
        assert not thread.is_alive()

    assert outcomes.count("CLAIMED") == 1
    assert outcomes.count("WORKER_LEASE_ALREADY_ACTIVE") == 3
    assert len(store.list_records()) == 1


def test_interrupt_and_completion_race_never_fabricates_stop_ack(tmp_path):
    store = WorkerLeaseStore(tmp_path / "state")
    key = _key()
    claim = store.claim(
        key,
        supervisor_id="targetd-1",
        worker_id="worker-1",
        now=NOW,
    )
    store.start(claim, now=NOW + timedelta(seconds=1))
    barrier = threading.Barrier(3)

    def complete() -> None:
        barrier.wait()
        try:
            store.complete(
                claim,
                status="SUCCEEDED",
                outcome_code="PROVIDER_SUCCEEDED",
                now=NOW + timedelta(seconds=2),
            )
        except WorkerLifecycleError:
            pass

    def cancel() -> None:
        barrier.wait()
        store.request_interrupt(
            key,
            intent="CANCEL",
            now=NOW + timedelta(seconds=2),
        )

    threads = [threading.Thread(target=complete), threading.Thread(target=cancel)]
    for thread in threads:
        thread.start()
    barrier.wait()
    for thread in threads:
        thread.join(2)
        assert not thread.is_alive()

    raced = store.load(key)
    assert raced is not None
    assert raced.state in {"SUCCEEDED", "CANCEL_REQUESTED"}
    assert raced.stop_acknowledgement is None
    if raced.state == "CANCEL_REQUESTED":
        raced = store.acknowledge_interrupt(
            claim,
            intent="CANCEL",
            outcome_code="PROVIDER_CANCEL_CONFIRMED",
            now=NOW + timedelta(seconds=3),
        )
        assert raced.state == "CANCELLED"
        assert raced.stop_acknowledgement is not None


def test_worker_lease_store_rejects_duplicate_json_members(tmp_path):
    store = WorkerLeaseStore(tmp_path / "state")
    store.path.parent.mkdir(parents=True)
    store.path.write_text(
        '{"schema_version":"rolo-targetd-worker-leases/v1","leases":{},"leases":{}}',
        encoding="utf-8",
    )
    with pytest.raises(WorkerLifecycleError, match="WORKER_LEASE_STATE_UNREADABLE"):
        store.list_records()


def test_worker_lease_store_rejects_oversized_file_before_parsing(tmp_path):
    store = WorkerLeaseStore(tmp_path / "state", max_state_bytes=128)
    store.path.parent.mkdir(parents=True)
    store.path.write_bytes(b"{" + b"x" * 128)

    with pytest.raises(WorkerLifecycleError, match="WORKER_LEASE_STATE_TOO_LARGE"):
        store.list_records()


def test_worker_lease_store_enforces_serialized_write_limit(tmp_path):
    store = WorkerLeaseStore(tmp_path / "state", max_state_bytes=128)
    with pytest.raises(WorkerLifecycleError, match="WORKER_LEASE_STATE_TOO_LARGE"):
        store.claim(
            _key(),
            supervisor_id="targetd-1",
            worker_id="worker-1",
            now=NOW,
        )
    assert not store.path.exists()


def test_worker_lease_store_enforces_record_capacity_without_overwrite(tmp_path):
    store = WorkerLeaseStore(tmp_path / "state", max_leases=1)
    first = _key(idempotency_key="call-1")
    second = _key(idempotency_key="call-2", request_digest="b" * 64)
    store.claim(first, supervisor_id="targetd-1", worker_id="worker-1", now=NOW)

    with pytest.raises(WorkerLifecycleError, match="WORKER_LEASE_CAPACITY_EXCEEDED"):
        store.claim(second, supervisor_id="targetd-1", worker_id="worker-2", now=NOW)
    assert [record.call_key for record in store.list_records()] == [first]


def test_worker_lease_store_rejects_persisted_count_above_local_limit(tmp_path):
    root = tmp_path / "state"
    writer = WorkerLeaseStore(root, max_leases=2)
    writer.claim(_key(idempotency_key="call-1"), supervisor_id="targetd-1", worker_id="worker-1", now=NOW)
    writer.claim(
        _key(idempotency_key="call-2", request_digest="b" * 64),
        supervisor_id="targetd-1",
        worker_id="worker-2",
        now=NOW,
    )

    with pytest.raises(WorkerLifecycleError, match="WORKER_LEASE_CAPACITY_EXCEEDED"):
        WorkerLeaseStore(root, max_leases=1).list_records()


@pytest.mark.parametrize(
    ("field", "value", "error"),
    [
        ("max_leases", MAX_WORKER_LEASES + 1, "WORKER_LEASE_CAPACITY_INVALID"),
        (
            "max_state_bytes",
            MAX_WORKER_LEASE_STATE_BYTES + 1,
            "WORKER_LEASE_STATE_LIMIT_INVALID",
        ),
    ],
)
def test_worker_lease_store_limits_cannot_exceed_hard_caps(tmp_path, field, value, error):
    with pytest.raises(WorkerLifecycleError, match=error):
        WorkerLeaseStore(tmp_path / "state", **{field: value})


def test_worker_lease_store_rejects_index_tampering(tmp_path):
    store = WorkerLeaseStore(tmp_path / "state")
    store.claim(
        _key(),
        supervisor_id="targetd-1",
        worker_id="worker-1",
        now=NOW,
    )
    payload = json.loads(store.path.read_text(encoding="utf-8"))
    record = next(iter(payload["leases"].values()))
    payload["leases"] = {"f" * 64: record}
    store.path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(WorkerLifecycleError, match="WORKER_LEASE_STATE_INVALID"):
        store.list_records()


def test_worker_lease_root_rejects_symlink_component(tmp_path, monkeypatch):
    outside = tmp_path / "outside"
    outside.mkdir()
    link = tmp_path / "linked-state"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except OSError:
        original = Path.is_symlink
        monkeypatch.setattr(
            Path,
            "is_symlink",
            lambda path: path == link or original(path),
        )

    with pytest.raises(WorkerLifecycleError, match="WORKER_LEASE_ROOT_SYMLINK_REJECTED"):
        WorkerLeaseStore(link / "nested")


def test_worker_lease_state_rejects_symlink_without_touching_target(tmp_path, monkeypatch):
    root = tmp_path / "state"
    root.mkdir()
    store = WorkerLeaseStore(root)
    outside = tmp_path / "outside.json"
    outside.write_text("outside", encoding="utf-8")
    state_path = root / "worker-leases.json"
    try:
        state_path.symlink_to(outside)
    except OSError:
        original = Path.is_symlink
        monkeypatch.setattr(
            Path,
            "is_symlink",
            lambda path: path == state_path or original(path),
        )

    with pytest.raises(WorkerLifecycleError, match="WORKER_LEASE_STATE_SYMLINK_REJECTED"):
        store.claim(
            _key(),
            supervisor_id="targetd-1",
            worker_id="worker-1",
            now=NOW,
        )
    assert outside.read_text(encoding="utf-8") == "outside"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("session_id", "../outside"),
        ("idempotency_key", "call/../../outside"),
        ("idempotency_key", r"call\..\outside"),
    ],
)
def test_worker_call_key_rejects_path_traversal(field, value):
    payload = _key().model_dump(mode="python")
    payload[field] = value
    with pytest.raises(ValueError):
        WorkerCallKey.model_validate(payload)


def test_worker_lease_claim_repr_omits_bearer_token(tmp_path):
    claim = WorkerLeaseStore(tmp_path / "state").claim(
        _key(),
        supervisor_id="targetd-1",
        worker_id="worker-1",
        now=NOW,
    )
    assert claim.lease_token not in repr(claim)
    assert isinstance(claim, WorkerLeaseClaim)
