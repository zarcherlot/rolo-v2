from __future__ import annotations

import hashlib
import json
import threading
import time
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from rolo.core.hashing import canonical_json_sha256
from rolo.dsl.models import OperationKind
from rolo.targetd.daemon import Ros2ReadOnlyProvider, TargetdDaemon
from rolo.targetd.lifecycle import WorkerCallKey, WorkerLeaseStore
from rolo.targetd.motion_acceptance import (
    ProviderGateConsumptionReceipt,
    SignedZeroMotionArtifact,
    compute_armed_zero_provider_identity_digest,
)
from rolo.targetd.physical_gate import (
    PhysicalProviderGateReceiptStore,
    ZeroMotionPhysicalProviderGate,
)
from rolo.targetd.physical_worker import (
    landerpi_bounded_twist_runtime_sha256,
    parse_physical_worker_armed_zero,
)
from rolo.targetd.process_worker import (
    LeasedProcessWorkerRuntime,
    PhysicalProcessWorkerPreparation,
    ProcessWorkerSnapshot,
    ProcessWorkerSubmission,
)
from rolo.targetd.protocol import (
    ExecutionBundleManifest,
    FrameKind,
    JourneySession,
    ProtocolError,
    ProtocolFrame,
    TargetdExecutionAuthority,
    physical_gate_query_auth_tag,
    physical_prepared_start_auth_tag,
    process_control_auth_tag,
)
from rolo.targetd.ros2_runtime import Ros2RuntimeResolver, Ros2RuntimeSnapshot, Ros2Topic
from rolo.targetd.runtime_backend import ros2_registry
from rolo.targetd.service import TargetdService
from rolo.targetd.transport import JourneySessionClient
from rolo.targetd.worker import RosContainerProvider
from tests.test_targetd_process_worker import InterruptibleOdomWorker, SuccessfulOdomWorker
from tests.test_targetd_protocol import (
    _execution_request,
    _execution_session,
    _execution_setup,
)
from tests.test_targetd_worker_integration import _physical_call


def _physical_service(tmp_path):
    source = b"def execute(arguments, provider): return provider.invoke('base.rotate', arguments)"
    runtime_sha256 = landerpi_bounded_twist_runtime_sha256()
    manifest = ExecutionBundleManifest.build(
        tool_id="app.base.rotate",
        source=source,
        binding_digest="a" * 64,
        signer_key_id="rolo-dev",
        signing_key=b"secret",
        observation_contract={
            "provider": "ros-container",
            "operation": "base.rotate",
            "command_endpoint": "/cmd_vel",
            "feedback_endpoints": ["/odom_raw", "/odom"],
            "independent_feedback_endpoints": [
                "/imu",
                "/imu_corrected",
                "/ros_robot_controller/imu_raw",
            ],
            "interface_type": "geometry_msgs/msg/Twist",
            "stop_strategy": "zero_velocity",
            "provider_runtime_sha256": runtime_sha256,
        },
        limits={"max_duration_s": 60, "max_output_bytes": 65_536},
    )
    service, authority, _, _ = _execution_setup(
        tmp_path,
        manifest,
        source,
        provider_id="ros-container",
        provider_operation="base.rotate",
        journey_session_id="physical-process",
    )
    session = _execution_session(service, authority, "physical-process")
    request = _execution_request(
        authority,
        session,
        arguments={"angle_degrees": 1.0, "max_speed_rad_s": 0.03},
    )
    # This service seam test uses a deployment-owned gate stub, but the
    # request/ARM identities must still be the production LanderPi route.
    intent = request.motion_safety_admission.intent.model_copy(
        update={
            "command_route": "/cmd_vel",
            "publisher_identity": "/rolo_bounded_twist",
            "direct_motor_route": "/ros_robot_controller/set_motor",
            "direct_motor_interface": "ros_robot_controller_msgs/msg/MotorsState",
            "direct_motor_publisher_identity": "/odom_publisher",
        }
    )
    request = request.model_copy(update={"motion_safety_admission": request.motion_safety_admission.model_copy(update={"intent": intent})})
    return service, authority, request, manifest


def _armed_zero(request, manifest):
    call_key = WorkerCallKey.from_request(request)
    runtime_sha256 = manifest.observation_contract["provider_runtime_sha256"]
    publisher_gid = "ab" * 16
    pid = 8721
    start_ticks = 443322
    cmdline_sha256 = "d" * 64
    registry_issued_at = datetime.now(timezone.utc).timestamp() - 0.25
    registry_expires_at = registry_issued_at + 4.0
    runtime_identity = compute_armed_zero_provider_identity_digest(
        call_id=request.idempotency_key,
        session_id=request.session_id,
        execution_subject_digest=request.execution_subject_digest,
        publisher_identity="/rolo_bounded_twist",
        publisher_gid=publisher_gid,
        provider_pid=pid,
        provider_start_time_ticks=start_ticks,
        provider_runtime_sha256="sha256:" + runtime_sha256,
        provider_cmdline_sha256="sha256:" + cmdline_sha256,
    )
    registry_binding = (
        "sha256:"
        + hashlib.sha256(
            json.dumps(
                {
                    "schema_version": "rolo-targetd-physical-worker-registry-binding/v1",
                    "target_id": request.target_id,
                    "call_key_digest": call_key.digest(),
                    "call_id": request.idempotency_key,
                    "session_id": request.session_id,
                    "execution_subject_digest": request.execution_subject_digest,
                    "publisher_identity": "/rolo_bounded_twist",
                    "publisher_gid": publisher_gid,
                    "provider_pid": pid,
                    "provider_start_time_ticks": start_ticks,
                    "provider_runtime_sha256": "sha256:" + runtime_sha256,
                    "provider_cmdline_sha256": "sha256:" + cmdline_sha256,
                    "issued_at_epoch_s": registry_issued_at,
                    "expires_at_epoch_s": registry_expires_at,
                },
                ensure_ascii=True,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("ascii")
        ).hexdigest()
    )
    unsigned = {
        "schema_version": "rolo-targetd-physical-worker-arm-receipt/v1",
        "call_key_digest": call_key.digest(),
        "target_id": request.target_id,
        "call_id": request.idempotency_key,
        "session_id": request.session_id,
        "request_digest": request.request_digest(),
        "execution_subject_digest": request.execution_subject_digest,
        "runtime_sha256": runtime_sha256,
        "command_endpoint": "/cmd_vel",
        "publisher_identity": "/rolo_bounded_twist",
        "publisher_endpoint_gids": [publisher_gid],
        "publisher_endpoint_count": 1,
        "competing_publisher_count": 0,
        "direct_motor_publisher_identities": ["/odom_publisher"],
        "zeros_published": 5,
        "independent_stationary_sources": ["/imu"],
        "independent_stationary_sample_counts": {"/imu": 3},
        "independent_stationary_last_sample_age_s": {"/imu": 0.01},
        "independent_stationary_max_abs_rad_s": {"/imu": 0.001},
        "independent_stationary_window_s": 0.2,
        "motion_command_emitted": False,
        "motion_enabled": False,
        "inner_process_identity": {
            "schema_version": "rolo-targetd-inner-process-identity/v1",
            "pid": pid,
            "start_ticks": start_ticks,
            "cmdline_sha256": cmdline_sha256,
        },
        "target_monotonic_s": 123.5,
        "provider_runtime_sha256": "sha256:" + runtime_sha256,
        "provider_cmdline_sha256": "sha256:" + cmdline_sha256,
        "provider_runtime_identity_digest": runtime_identity,
        "registry_issued_at_epoch_s": registry_issued_at,
        "registry_expires_at_epoch_s": registry_expires_at,
        "registry_binding_digest": registry_binding,
    }
    digest = hashlib.sha256(
        json.dumps(
            unsigned,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    ).hexdigest()
    return parse_physical_worker_armed_zero(
        {**unsigned, "arm_receipt_digest": digest},
        expected_call_key_digest=call_key.digest(),
        expected_call_id=request.idempotency_key,
        expected_session_id=request.session_id,
        expected_request_digest=request.request_digest(),
        expected_execution_subject_digest=request.execution_subject_digest,
        expected_runtime_sha256=runtime_sha256,
        expected_target_id=request.target_id,
    )


def _consumed_gate_receipt(request, armed_zero):
    now = datetime.now(timezone.utc)
    intent = request.motion_safety_admission.intent
    challenge_digest = "sha256:" + "c" * 64
    provider_fence_digest = "sha256:" + "f" * 64
    armed_binding = {
        "schema_version": "rolo-landerpi-armed-zero-provider-binding/v1",
        "call_id": request.idempotency_key,
        "session_id": request.session_id,
        "execution_subject_digest": request.execution_subject_digest,
        "publisher_identity": armed_zero.publisher_identity,
        "publisher_gid": armed_zero.publisher_endpoint_gids[0],
        "provider_pid": armed_zero.inner_process_identity.pid,
        "provider_start_time_ticks": armed_zero.inner_process_identity.start_ticks,
        "provider_runtime_sha256": armed_zero.provider_runtime_sha256,
        "provider_cmdline_sha256": armed_zero.provider_cmdline_sha256,
        "provider_runtime_identity_digest": armed_zero.provider_runtime_identity_digest,
    }
    artifact = SignedZeroMotionArtifact.build(
        artifact_id="physical-provider-gate-consumed",
        kind="PROVIDER_GATE_CONSUMED",
        issuer_id="targetd:test-gate",
        acceptance_id="physical-acceptance",
        intent=intent,
        issued_at=now,
        expires_at=now + timedelta(seconds=30),
        claims={
            "consumed": True,
            "one_shot": True,
            "challenge_artifact_digest": challenge_digest,
            "provider_fence_digest": provider_fence_digest,
            "graph_compare_and_set": True,
            "fence_compare_and_set": True,
            "motion_enabled": False,
            "provider_invocation_count": 0,
            "armed_zero_provider_binding": armed_binding,
        },
        signing_key=b"g" * 32,
    )
    return ProviderGateConsumptionReceipt(
        status="CONSUMED",
        reasons=(),
        evaluated_at=now,
        acceptance_id="physical-acceptance",
        call_id=request.idempotency_key,
        session_id=request.session_id,
        target_id=request.target_id,
        target_identity=intent.target_identity,
        operator_id=intent.operator_id,
        execution_subject_digest=request.execution_subject_digest,
        ros_graph_digest=intent.ros_graph_digest,
        command_route=intent.command_route,
        command_interface=intent.command_interface,
        publisher_identity=intent.publisher_identity,
        direct_motor_route=intent.direct_motor_route,
        direct_motor_interface=intent.direct_motor_interface,
        direct_motor_publisher_identity=intent.direct_motor_publisher_identity,
        challenge_artifact_digest=challenge_digest,
        provider_fence_digest=provider_fence_digest,
        consume_artifact=artifact,
        provider_boundary_open=True,
    )


class _TwoPhaseRuntimeStub:
    """Deterministic runtime seam: no child and no physical provider call."""

    allow_spawn_physical_substrate = True
    allow_spawn_readonly_substrate = False
    max_processes = 1
    physical_container = "MentorPi"
    physical_container_user = "ubuntu"

    def __init__(self, store, armed_zero):
        self.store = store
        self.armed_zero = armed_zero
        self.start_gate = None
        self.claim = None
        self.start_calls = 0
        self.interrupt_calls = 0
        self.after_start_gate = None

    def bind_physical_start_gate(self, callback):
        assert self.start_gate is None
        self.start_gate = callback

    def prepare_physical(
        self,
        request,
        manifest,
        *,
        worker_id,
        work,
        terminal_commit,
    ):
        del work, terminal_commit
        call_key = WorkerCallKey.from_request(request)
        self.claim = self.store.claim(
            call_key,
            supervisor_id="targetd-physical-test",
            worker_id=worker_id,
            deadline_at=request.deadline,
            physical_execution_subject_digest=request.execution_subject_digest,
            physical_runtime_sha256=manifest.observation_contract["provider_runtime_sha256"],
        )
        self.store.start(self.claim)
        lease = self.store.record_armed_zero(
            self.claim,
            armed_zero=self.armed_zero.as_dict(),
        )
        return PhysicalProcessWorkerPreparation(
            call_key=call_key,
            lease=lease,
            process_id=4242,
            armed_zero=self.armed_zero,
        )

    def start_prepared(self, call_key):
        assert self.claim is not None
        assert callable(self.start_gate)
        assert call_key == self.claim.lease.call_key
        self.start_gate(self.claim, self.armed_zero)
        if self.after_start_gate is not None:
            self.after_start_gate()
        self.start_calls += 1
        lease = self.store.load(call_key)
        assert lease is not None
        return ProcessWorkerSubmission(
            call_key=call_key,
            lease=lease,
            process_id=4242,
        )

    def reconcile_snapshot(self, call_key):
        lease = self.store.reconcile(
            call_key,
            supervisor_id="targetd-physical-restarted-test",
        )
        return ProcessWorkerSnapshot(
            lease=lease,
            outcome=None,
            process_exit_code=None,
            ipc_outcome_code="PROCESS_WORKER_RESTART_RECONCILED",
        )


def _configured_process_daemon(tmp_path, *, work=None, live_fence=None):
    source = b"raise AssertionError('the process path must not execute bundle source')"
    manifest = ExecutionBundleManifest.build(
        tool_id="app.observe.odom",
        source=source,
        binding_digest="a" * 64,
        signer_key_id="rolo-dev",
        signing_key=b"secret",
        observation_contract={
            "provider": "ros2-readonly",
            "operation": "odom.sample",
            "mode": "READ_ONLY",
        },
    )
    service, authority, _, authority_store = _execution_setup(
        tmp_path,
        manifest,
        source,
        provider_id="ros2-readonly",
        provider_operation="odom.sample",
        operation_kind=OperationKind.OBSERVE,
        journey_session_id="process-session",
    )
    authority = TargetdExecutionAuthority.build(
        **authority.model_dump(
            mode="python",
            exclude={
                "schema_version",
                "authority_head_digest",
                "fence_epoch",
                "mode",
            },
        ),
        fence_epoch=authority.fence_epoch + 1,
        mode="READ_ONLY",
    )
    authority_store.publish(authority)
    session = _execution_session(service, authority, "process-session")
    request = _execution_request(authority, session)
    snapshot = Ros2RuntimeSnapshot(
        distro="humble",
        ros2_path="ros2",
        topics=(Ros2Topic("/odom", "nav_msgs/msg/Odometry"),),
    )
    provider = Ros2ReadOnlyProvider(
        ros2_registry(Ros2RuntimeResolver(snapshot)),
    )
    runtime = LeasedProcessWorkerRuntime(
        WorkerLeaseStore(tmp_path / "process-leases"),
        supervisor_id="targetd-mentorpi",
        allow_spawn_readonly_substrate=True,
    )
    fence_events: list[tuple[str, str]] = []

    def default_live_fence(observed_request, observed_authority):
        call_key = WorkerCallKey.from_request(observed_request)
        lease = runtime.store.load(call_key)
        receipt = service.state.load_receipt(
            observed_request.session_id,
            observed_request.idempotency_key,
        )
        assert lease is not None and lease.state == "RUNNING"
        assert receipt is not None and receipt.status == "ACCEPTED"
        assert observed_authority == authority
        fence_events.append((lease.state, receipt.status))

    daemon = TargetdDaemon(
        service,
        execute_calls=True,
        provider=provider,
        process_runtime=runtime,
        process_work=work or SuccessfulOdomWorker(),
        process_live_fence=live_fence or default_live_fence,
    )
    daemon._session = session
    return daemon, service, runtime, request, manifest, session, fence_events


def _call_frame(request, *, sequence=0):
    return ProtocolFrame.create(
        kind=FrameKind.CALL,
        sequence=sequence,
        session_id=request.session_id,
        run_id=request.run_id,
        payload=request.model_dump(mode="json"),
    )


def _query_until_terminal(daemon, request, *, start_sequence=10):
    terminal = {"SUCCEEDED", "FAILED", "STOPPED", "CANCELLED", "UNKNOWN", "NOT_ACCEPTED"}
    for sequence in range(start_sequence, start_sequence + 200):
        response = daemon._handle(
            ProtocolFrame.create(
                kind=FrameKind.QUERY_CALL,
                sequence=sequence,
                session_id=request.session_id,
                run_id=request.run_id,
                payload={"call_id": request.idempotency_key},
            )
        )
        assert response.payload["ok"] is True
        receipt = response.payload["receipt"]
        if receipt["status"] in terminal:
            return receipt
        time.sleep(0.02)
    raise AssertionError("process call did not reach a terminal receipt")


def test_process_call_persists_live_fence_and_target_start_before_callback(tmp_path):
    daemon, service, runtime, request, _, _, fence_events = _configured_process_daemon(tmp_path)

    response = daemon._handle(_call_frame(request))

    assert response.payload["ok"] is True
    assert response.payload["call_started"] is True
    assert response.payload["provider_invocation_count"] == 1
    assert fence_events == [("RUNNING", "ACCEPTED")]
    receipt = _query_until_terminal(daemon, request)
    assert receipt["status"] == "SUCCEEDED"
    call_key = WorkerCallKey.from_request(request)
    lease = runtime.store.load(call_key)
    assert lease is not None
    assert lease.prepared_status == "SUCCEEDED"
    assert lease.prepared_result_digest is not None
    assert lease.result_committed_at is not None
    persisted = service.state.load_receipt(request.session_id, request.idempotency_key)
    assert persisted is not None and persisted.status == "SUCCEEDED"


def test_process_stop_requires_exact_authenticated_call_and_worker_ack(tmp_path):
    daemon, _, runtime, request, _, session, _ = _configured_process_daemon(
        tmp_path,
        work=InterruptibleOdomWorker(),
    )
    started = daemon._handle(_call_frame(request))
    assert started.payload["ok"] is True
    assert started.payload["receipt"]["status"] == "STARTED"

    tampered = daemon._handle(
        ProtocolFrame.create(
            kind=FrameKind.STOP,
            sequence=1,
            session_id=request.session_id,
            run_id=request.run_id,
            payload={
                "call_id": request.idempotency_key,
                "request_digest": request.request_digest(),
                "control_auth": "0" * 64,
            },
        )
    )
    assert tampered.payload == {
        "request_kind": "STOP",
        "ok": False,
        "error": "TARGETD_PROCESS_CONTROL_AUTHENTICATION_FAILED",
    }
    assert runtime.store.load(WorkerCallKey.from_request(request)).state == "RUNNING"

    sequence = 2
    stopped = daemon._handle(
        ProtocolFrame.create(
            kind=FrameKind.STOP,
            sequence=sequence,
            session_id=request.session_id,
            run_id=request.run_id,
            payload={
                "call_id": request.idempotency_key,
                "request_digest": request.request_digest(),
                "control_auth": process_control_auth_tag(
                    session.resume_token,
                    kind="STOP",
                    session_id=request.session_id,
                    call_id=request.idempotency_key,
                    request_digest=request.request_digest(),
                    sequence=sequence,
                ),
            },
        )
    )
    assert stopped.payload["ok"] is True
    assert stopped.payload["interrupt"] == {
        "intent": "STOP",
        "requested": True,
        "acknowledged": False,
        "lease_state": "STOP_REQUESTED",
    }
    # A request response is not an acknowledgement. Only the child holding
    # the exact lease token can persist STOPPED plus stop_acknowledgement.
    receipt = _query_until_terminal(daemon, request, start_sequence=20)
    assert receipt["status"] == "STOPPED"
    lease = runtime.store.load(WorkerCallKey.from_request(request))
    assert lease is not None and lease.stop_acknowledgement is not None
    assert lease.stop_acknowledgement.disposition == "WORKER_CONFIRMED"
    assert lease.result_committed_at is not None


def test_live_fence_failure_is_zero_callback_unknown(tmp_path):
    def reject_live_fence(_request, _authority):
        raise ProtocolError("ROS2_ODOM_LIVE_FENCE_MISMATCH")

    daemon, service, runtime, request, _, _, _ = _configured_process_daemon(
        tmp_path,
        live_fence=reject_live_fence,
    )

    response = daemon._handle(_call_frame(request))

    assert response.payload["ok"] is False
    assert response.payload["provider_invocation_count"] == 0
    receipt = service.state.load_receipt(request.session_id, request.idempotency_key)
    assert receipt is not None and receipt.status == "UNKNOWN"
    lease = runtime.store.load(WorkerCallKey.from_request(request))
    assert lease is not None and lease.state == "UNKNOWN"


def test_restart_commits_prepared_result_without_replaying_provider(tmp_path, monkeypatch):
    daemon, service, runtime, request, _, _, _ = _configured_process_daemon(tmp_path)
    original_commit = daemon._commit_process_snapshot
    commit_attempts = 0

    def lose_first_receipt_commit(_call_key, _snapshot):
        nonlocal commit_attempts
        commit_attempts += 1
        raise OSError("simulated receipt persistence outage")

    monkeypatch.setattr(daemon, "_commit_process_snapshot", lose_first_receipt_commit)
    response = daemon._handle(_call_frame(request))
    assert response.payload["ok"] is True
    call_key = WorkerCallKey.from_request(request)
    snapshot = runtime.join(call_key, timeout_s=10)
    assert snapshot.lease.state == "SUCCEEDED"
    assert snapshot.lease.prepared_result_digest is not None
    assert snapshot.lease.result_committed_at is None
    assert snapshot.ipc_outcome_code == "PROCESS_WORKER_RECEIPT_COMMIT_PENDING"
    assert commit_attempts == 1
    receipt = service.state.load_receipt(request.session_id, request.idempotency_key)
    assert receipt is not None and receipt.status == "STARTED"

    monkeypatch.setattr(daemon, "_commit_process_snapshot", original_commit)
    restarted_runtime = LeasedProcessWorkerRuntime(
        runtime.store,
        supervisor_id="targetd-mentorpi",
        allow_spawn_readonly_substrate=True,
    )
    restarted = TargetdDaemon(
        service,
        execute_calls=True,
        provider=daemon.worker.provider,
        process_runtime=restarted_runtime,
        process_work=SuccessfulOdomWorker(),
        process_live_fence=daemon.process_live_fence,
    )

    reconciled = service.state.load_receipt(request.session_id, request.idempotency_key)
    assert reconciled is not None and reconciled.status == "SUCCEEDED"
    lease = restarted_runtime.store.load(call_key)
    assert lease is not None and lease.result_committed_at is not None
    assert restarted._provider_invocation_count == 0


def test_same_status_wrong_target_receipt_never_commits_prepared_result(tmp_path, monkeypatch):
    daemon, service, runtime, request, _, _, _ = _configured_process_daemon(tmp_path)

    def lose_receipt_commit(_call_key, _snapshot):
        raise OSError("simulated receipt persistence outage")

    monkeypatch.setattr(daemon, "_commit_process_snapshot", lose_receipt_commit)
    assert daemon._handle(_call_frame(request)).payload["ok"] is True
    call_key = WorkerCallKey.from_request(request)
    snapshot = runtime.join(call_key, timeout_s=10)
    assert snapshot.lease.prepared_result is not None
    service.state.update_receipt(
        request.session_id,
        request.idempotency_key,
        lambda receipt: receipt.model_copy(update={"status": "SUCCEEDED", "result": {"status": "forged"}}),
    )

    with pytest.raises(ProtocolError, match="TARGETD_PROCESS_RESULT_TERMINAL_MISMATCH"):
        service.commit_process_result(call_key, snapshot.lease)

    lease = runtime.store.load(call_key)
    assert lease is not None and lease.result_committed_at is None


def test_process_service_seam_never_accepts_physical_request(tmp_path):
    daemon, service, runtime, _, _, _, _ = _configured_process_daemon(tmp_path / "readonly")
    request, manifest = _physical_call(tmp_path / "physical")

    with pytest.raises(ProtocolError, match="LEASED_PHYSICAL_PROCESS_ISOLATION_REQUIRED"):
        service.start_process_call(
            request,
            manifest,
            provider_id="ros-container",
            lease_probe=lambda: pytest.fail("physical lease must not be read"),
            live_fence=lambda _request, _authority: pytest.fail("physical fence must not open"),
        )

    assert runtime.store.list_records() == ()
    assert daemon.provider_id == "ros2-readonly"


def test_physical_process_start_rejects_claim_from_untrusted_store(tmp_path):
    service, authority, request, manifest = _physical_service(tmp_path)
    trusted_store = WorkerLeaseStore(tmp_path / "trusted-physical-leases")
    gate_store = PhysicalProviderGateReceiptStore(tmp_path / "physical-gates")
    armed_zero = _armed_zero(request, manifest)
    consumed = _consumed_gate_receipt(request, armed_zero)
    consume_calls = 0

    class Gate:
        def validate_request(self, observed_request, observed_authority):
            assert observed_request == request and observed_authority == authority

        def consume(self, _request, _authority):
            nonlocal consume_calls
            consume_calls += 1
            return consumed

        def revalidate_consumption(self, observed, call_key, *, at):
            assert observed == consumed
            assert call_key == WorkerCallKey.from_request(request)
            assert at.tzinfo is not None

    service.physical_motion_gate = Gate()
    service.physical_worker_store = trusted_store
    service.physical_gate_receipt_store = gate_store
    assert (
        service.accept_call(
            request,
            manifest,
            provider_id="ros-container",
        ).status
        == "ACCEPTED"
    )
    untrusted_store = WorkerLeaseStore(tmp_path / "untrusted-physical-leases")
    claim = untrusted_store.claim(
        WorkerCallKey.from_request(request),
        supervisor_id="untrusted-runtime",
        worker_id="untrusted-worker",
        deadline_at=request.deadline,
    )
    untrusted_store.start(claim)
    untrusted_store.record_armed_zero(claim, armed_zero=armed_zero.as_dict())

    with pytest.raises(
        ProtocolError,
        match="TARGETD_PHYSICAL_PROCESS_WORKER_LEASE_NOT_LIVE",
    ):
        service.start_physical_process_call(
            request,
            manifest,
            provider_id="ros-container",
            lease_claim=claim,
            armed_zero=armed_zero,
        )

    assert consume_calls == 0
    receipt = service.state.load_receipt(request.session_id, request.idempotency_key)
    assert receipt is not None and receipt.status == "ACCEPTED"


def test_physical_gate_sidecar_failure_sends_no_start(tmp_path, monkeypatch):
    service, authority, request, manifest = _physical_service(tmp_path)
    worker_store = WorkerLeaseStore(tmp_path / "trusted-physical-leases")
    gate_store = PhysicalProviderGateReceiptStore(tmp_path / "physical-gates")
    armed_zero = _armed_zero(request, manifest)
    consumed = _consumed_gate_receipt(request, armed_zero)
    consume_calls = 0

    class Gate:
        def validate_request(self, observed_request, observed_authority):
            assert observed_request == request and observed_authority == authority

        def consume(self, _request, _authority):
            nonlocal consume_calls
            consume_calls += 1
            return consumed

        def revalidate_consumption(self, observed, call_key, *, at):
            assert observed == consumed
            assert call_key == WorkerCallKey.from_request(request)
            assert at.tzinfo is not None

    service.physical_motion_gate = Gate()
    service.physical_worker_store = worker_store
    service.physical_gate_receipt_store = gate_store
    assert (
        service.accept_call(
            request,
            manifest,
            provider_id="ros-container",
        ).status
        == "ACCEPTED"
    )
    claim = worker_store.claim(
        WorkerCallKey.from_request(request),
        supervisor_id="trusted-runtime",
        worker_id="physical-worker",
        deadline_at=request.deadline,
    )
    worker_store.start(claim)
    worker_store.record_armed_zero(claim, armed_zero=armed_zero.as_dict())

    def fail_persist(*_args, **_kwargs):
        raise OSError("simulated durable gate receipt outage")

    monkeypatch.setattr(gate_store, "persist", fail_persist)
    with pytest.raises(OSError, match="durable gate receipt outage"):
        service.start_physical_process_call(
            request,
            manifest,
            provider_id="ros-container",
            lease_claim=claim,
            armed_zero=armed_zero,
        )

    assert consume_calls == 1
    receipt = service.state.load_receipt(request.session_id, request.idempotency_key)
    assert receipt is not None and receipt.status == "ACCEPTED"
    assert receipt.provider_started_at is None


def test_physical_gate_sidecar_is_content_addressed_and_queryable(tmp_path):
    service, authority, request, manifest = _physical_service(tmp_path)
    worker_store = WorkerLeaseStore(tmp_path / "trusted-physical-leases")
    gate_store = PhysicalProviderGateReceiptStore(tmp_path / "physical-gates")
    armed_zero = _armed_zero(request, manifest)
    consumed = _consumed_gate_receipt(request, armed_zero)
    revalidation_times = []

    class Gate:
        def validate_request(self, observed_request, observed_authority):
            assert observed_request == request and observed_authority == authority

        def consume(self, _request, _authority):
            return consumed

        def revalidate_consumption(self, observed, call_key, *, at):
            assert observed == consumed
            assert call_key == WorkerCallKey.from_request(request)
            revalidation_times.append(at)

    service.physical_motion_gate = Gate()
    service.physical_worker_store = worker_store
    service.physical_gate_receipt_store = gate_store
    assert service.accept_call(request, manifest, provider_id="ros-container").status == "ACCEPTED"
    call_key = WorkerCallKey.from_request(request)
    claim = worker_store.claim(
        call_key,
        supervisor_id="trusted-runtime",
        worker_id="physical-worker",
        deadline_at=request.deadline,
    )
    worker_store.start(claim)
    worker_store.record_armed_zero(claim, armed_zero=armed_zero.as_dict())
    started = service.start_physical_process_call(
        request,
        manifest,
        provider_id="ros-container",
        lease_claim=claim,
        armed_zero=armed_zero,
    ).receipt
    assert started.status == "STARTED"
    assert len(started.evidence_refs) == 2
    reference = gate_store.load(call_key)
    assert reference is not None
    assert (
        gate_store.resolve(
            reference.uri,
            call_key=call_key,
            digest_uri=reference.digest_uri,
        )
        == reference
    )
    assert gate_store.revalidate(reference) == reference

    session = service.state.load_session(request.session_id)
    daemon = TargetdDaemon(service)
    daemon.physical_process_runtime = SimpleNamespace(store=worker_store)
    daemon._session = session
    sequence = 7
    query = ProtocolFrame.create(
        kind=FrameKind.QUERY_CALL,
        sequence=sequence,
        session_id=request.session_id,
        payload={
            "call_id": request.idempotency_key,
            "target_id": request.target_id,
            "request_digest": request.request_digest(),
            "gate_uri": reference.uri,
            "gate_digest_uri": reference.digest_uri,
            "query_gate_auth": physical_gate_query_auth_tag(
                session.resume_token,
                target_id=request.target_id,
                session_id=request.session_id,
                call_id=request.idempotency_key,
                request_digest=request.request_digest(),
                gate_uri=reference.uri,
                gate_digest_uri=reference.digest_uri,
                sequence=sequence,
            ),
        },
    )
    response = daemon._handle(query)
    assert response.payload["ok"] is True
    returned = response.payload["physical_provider_gate"]
    assert returned["uri"] == reference.uri
    assert returned["digest_uri"] == reference.digest_uri
    assert returned["sidecar"] == reference.sidecar.model_dump(mode="json")
    still_started = service.state.load_receipt(
        request.session_id,
        request.idempotency_key,
    )
    assert still_started is not None and still_started.status == "STARTED"
    # Historical validation is pinned to persistence time, not query time.
    assert revalidation_times[-1] == reference.sidecar.persisted_at

    # A generic terminal transition cannot bypass physical proof validation.
    with pytest.raises(ProtocolError, match="TARGETD_PHYSICAL_PROCESS_COMMIT_REQUIRED"):
        service.complete_call(
            request.session_id,
            request.idempotency_key,
            status="STOPPED",
            result={"status": "STOPPED"},
        )
    assert service.resolve_physical_provider_gate(call_key).sidecar == reference.sidecar

    class DifferentCallGate:
        def revalidate_consumption(self, *_args, **_kwargs):
            raise AssertionError("a later call's gate must not verify this call")

    service.physical_motion_gate = DifferentCallGate()
    assert service.resolve_physical_provider_gate(call_key).sidecar == reference.sidecar

    # A daemon restart has no live callback object. The target-owned START
    # receipt and content-addressed sidecar remain a reconstructable
    # historical proof and must not crash reconciliation or QUERY.
    restarted = TargetdService(
        target_id=service.target_id,
        state_root=service.state.root,
        physical_worker_store=worker_store,
        physical_gate_receipt_store=gate_store,
    )
    assert restarted.resolve_physical_provider_gate(call_key).sidecar == reference.sidecar
    restarted_runtime = _TwoPhaseRuntimeStub(worker_store, armed_zero)
    restarted_daemon = TargetdDaemon(
        restarted,
        execute_calls=True,
        provider=RosContainerProvider(),
        physical_process_runtime=restarted_runtime,
        physical_process_work_factory=lambda *_args: object(),
        physical_gate_factory=lambda *_args: object(),
    )
    reconciled = restarted.state.load_receipt(
        request.session_id,
        request.idempotency_key,
    )
    assert reconciled is not None and reconciled.status == "UNKNOWN"
    assert restarted_daemon._provider_invocation_count == 0


def test_physical_gate_query_auth_and_index_path_are_fail_closed(tmp_path):
    service, authority, request, manifest = _physical_service(tmp_path)
    worker_store = WorkerLeaseStore(tmp_path / "trusted-physical-leases")
    gate_store = PhysicalProviderGateReceiptStore(tmp_path / "physical-gates")
    armed_zero = _armed_zero(request, manifest)
    consumed = _consumed_gate_receipt(request, armed_zero)

    class Gate:
        def validate_request(self, _request, _authority):
            return None

        def consume(self, _request, _authority):
            return consumed

        def revalidate_consumption(self, _observed, _call_key, *, at):
            assert at.tzinfo is not None

    service.physical_motion_gate = Gate()
    service.physical_worker_store = worker_store
    service.physical_gate_receipt_store = gate_store
    service.accept_call(request, manifest, provider_id="ros-container")
    call_key = WorkerCallKey.from_request(request)
    claim = worker_store.claim(
        call_key,
        supervisor_id="trusted-runtime",
        worker_id="physical-worker",
        deadline_at=request.deadline,
    )
    worker_store.start(claim)
    worker_store.record_armed_zero(claim, armed_zero=armed_zero.as_dict())
    service.start_physical_process_call(
        request,
        manifest,
        provider_id="ros-container",
        lease_claim=claim,
        armed_zero=armed_zero,
    )
    reference = gate_store.load(call_key)
    assert reference is not None

    session = service.state.load_session(request.session_id)
    daemon = TargetdDaemon(service)
    daemon._session = session
    bad_query = ProtocolFrame.create(
        kind=FrameKind.QUERY_CALL,
        sequence=0,
        session_id=request.session_id,
        payload={
            "call_id": request.idempotency_key,
            "target_id": request.target_id,
            "request_digest": request.request_digest(),
            "gate_uri": None,
            "gate_digest_uri": None,
            "query_gate_auth": "0" * 64,
        },
    )
    response = daemon._handle(bad_query)
    assert response.payload == {
        "request_kind": "QUERY_CALL",
        "ok": False,
        "error": "TARGETD_PHYSICAL_GATE_QUERY_AUTHENTICATION_FAILED",
    }

    index = gate_store.index_path.read_text(encoding="utf-8")
    digest = reference.sidecar.sidecar_digest
    gate_store.index_path.write_text(
        index.replace(digest, "sha256:../../" + "a" * 57),
        encoding="utf-8",
    )
    with pytest.raises(ProtocolError, match="TARGETD_PHYSICAL_GATE_INDEX_INVALID"):
        gate_store.load(call_key)


def test_direct_synchronous_service_cannot_bypass_physical_process_gate(tmp_path):
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
        journey_session_id="direct-physical",
    )
    session = _execution_session(service, authority, "direct-physical")
    request = _execution_request(authority, session)
    validations = 0
    consumes = 0
    callbacks = 0

    class PreflightOnlyGate:
        def validate_request(self, observed_request, observed_authority):
            nonlocal validations
            validations += 1
            assert observed_request == request
            assert observed_authority == authority

        def consume(self, _request, _authority):
            nonlocal consumes
            consumes += 1
            raise AssertionError("synchronous service must not consume the gate")

    service.physical_motion_gate = PreflightOnlyGate()
    assert (
        service.accept_call(
            request,
            manifest,
            provider_id="targetd-python",
        ).status
        == "ACCEPTED"
    )
    with pytest.raises(ProtocolError, match="TARGETD_PHYSICAL_PROCESS_WORKER_REQUIRED"):
        service.start_call(
            request,
            manifest,
            provider_id="targetd-python",
        )

    def execute():
        nonlocal callbacks
        callbacks += 1
        return "SUCCEEDED", {"status": "SUCCEEDED"}

    receipt = service.execute_provider(
        request,
        manifest,
        provider_id="targetd-python",
        execute=execute,
    )
    assert receipt.status == "ACCEPTED"
    assert validations == 2
    assert consumes == 0
    assert callbacks == 0


def test_daemon_two_phase_physical_start_is_authenticated_and_query_is_observational(
    tmp_path,
    monkeypatch,
):
    service, authority, request, manifest = _physical_service(tmp_path)
    worker_store = WorkerLeaseStore(tmp_path / "physical-leases")
    gate_store = PhysicalProviderGateReceiptStore(tmp_path / "physical-gates")
    armed_zero = _armed_zero(request, manifest)
    consumed = _consumed_gate_receipt(request, armed_zero)
    runtime = _TwoPhaseRuntimeStub(worker_store, armed_zero)
    service.physical_worker_store = worker_store
    service.physical_gate_receipt_store = gate_store

    gate = object.__new__(ZeroMotionPhysicalProviderGate)
    gate_calls = []

    def validate_gate(_self, observed_request, observed_authority):
        assert observed_request == request
        assert observed_authority == authority

    def consume_gate(_self, observed_request, observed_authority):
        validate_gate(_self, observed_request, observed_authority)
        gate_calls.append("consume")
        return consumed

    def revalidate_gate(_self, observed, call_key, *, at):
        assert observed == consumed
        assert call_key == WorkerCallKey.from_request(request)
        assert at.tzinfo is not None
        gate_calls.append("revalidate")

    monkeypatch.setattr(ZeroMotionPhysicalProviderGate, "validate_request", validate_gate)
    monkeypatch.setattr(ZeroMotionPhysicalProviderGate, "consume", consume_gate)
    monkeypatch.setattr(
        ZeroMotionPhysicalProviderGate,
        "revalidate_consumption",
        revalidate_gate,
    )
    monkeypatch.setattr(
        "rolo.targetd.physical_worker.read_target_physical_worker_registry",
        lambda **_kwargs: SimpleNamespace(armed_zero=armed_zero),
    )

    raw_gate = {
        "schema_version": "rolo-test-physical-gate-envelope/v1",
        "acceptance_id": consumed.acceptance_id,
    }
    gate_digest = canonical_json_sha256(raw_gate)
    daemon = TargetdDaemon(
        service,
        execute_calls=True,
        provider=RosContainerProvider(),
        physical_process_runtime=runtime,
        physical_process_work_factory=lambda observed_request, observed_manifest: (
            observed_request,
            observed_manifest,
        ),
        physical_gate_factory=lambda *_args: gate,
    )
    session = service.state.load_session(request.session_id)
    daemon._session = session

    # The ordinary CALL route never selects the physical runtime, even when
    # the opt-in composition is present.
    generic = daemon._handle(_call_frame(request))
    assert generic.payload == {
        "request_kind": "CALL",
        "ok": False,
        "error": "TARGETD_PHYSICAL_PROCESS_WORKER_REQUIRED",
        "provider_invocation_count": 0,
    }
    assert runtime.claim is None

    prepared = daemon._handle(
        ProtocolFrame.create(
            kind=FrameKind.PREPARE_PHYSICAL_CALL,
            sequence=1,
            session_id=request.session_id,
            run_id=request.run_id,
            payload=request.model_dump(mode="json"),
        )
    )
    assert prepared.payload["ok"] is True
    assert prepared.payload["prepared"] is True
    assert prepared.payload["receipt"]["status"] == "ACCEPTED"
    assert prepared.payload["receipt"]["provider_started_at"] is None
    assert prepared.payload["provider_invocation_count"] == 0

    bad_start = daemon._handle(
        ProtocolFrame.create(
            kind=FrameKind.START_PREPARED_CALL,
            sequence=2,
            session_id=request.session_id,
            run_id=request.run_id,
            payload={
                "call_id": request.idempotency_key,
                "target_id": request.target_id,
                "request_digest": request.request_digest(),
                "armed_zero_receipt_digest": armed_zero.arm_receipt_digest,
                "provider_gate": raw_gate,
                "provider_gate_payload_digest": gate_digest,
                "start_auth": "0" * 64,
            },
        )
    )
    assert bad_start.payload["ok"] is False
    assert bad_start.payload["error"] == "TARGETD_PHYSICAL_PREPARED_START_AUTHENTICATION_FAILED"
    assert bad_start.payload["provider_invocation_count"] == 0
    assert runtime.start_calls == 0
    assert gate_calls == []
    accepted = service.state.load_receipt(request.session_id, request.idempotency_key)
    assert accepted is not None and accepted.status == "ACCEPTED"

    start_sequence = 3
    started = daemon._handle(
        ProtocolFrame.create(
            kind=FrameKind.START_PREPARED_CALL,
            sequence=start_sequence,
            session_id=request.session_id,
            run_id=request.run_id,
            payload={
                "call_id": request.idempotency_key,
                "target_id": request.target_id,
                "request_digest": request.request_digest(),
                "armed_zero_receipt_digest": armed_zero.arm_receipt_digest,
                "provider_gate": raw_gate,
                "provider_gate_payload_digest": gate_digest,
                "start_auth": physical_prepared_start_auth_tag(
                    session.resume_token,
                    target_id=request.target_id,
                    session_id=request.session_id,
                    call_id=request.idempotency_key,
                    request_digest=request.request_digest(),
                    armed_zero_receipt_digest=armed_zero.arm_receipt_digest,
                    provider_gate_payload_digest=gate_digest,
                    sequence=start_sequence,
                ),
            },
        )
    )
    assert started.payload["ok"] is True
    assert started.payload["call_started"] is True
    assert started.payload["receipt"]["status"] == "STARTED"
    assert started.payload["provider_invocation_count"] == 1
    assert runtime.start_calls == 1
    assert gate_calls.count("consume") == 1
    reference = gate_store.load(WorkerCallKey.from_request(request))
    assert reference is not None

    # Omission cannot downgrade a target-owned physical call into generic
    # QUERY/reconcile, which could otherwise terminalize the live worker.
    omitted = daemon._handle(
        ProtocolFrame.create(
            kind=FrameKind.QUERY_CALL,
            sequence=4,
            session_id=request.session_id,
            run_id=request.run_id,
            payload={"call_id": request.idempotency_key},
        )
    )
    assert omitted.payload == {
        "request_kind": "QUERY_CALL",
        "ok": False,
        "error": "TARGETD_PHYSICAL_GATE_QUERY_IDENTITY_INVALID",
    }
    assert service.state.load_receipt(request.session_id, request.idempotency_key).status == "STARTED"

    query_sequence = 5
    queried = daemon._handle(
        ProtocolFrame.create(
            kind=FrameKind.QUERY_CALL,
            sequence=query_sequence,
            session_id=request.session_id,
            run_id=request.run_id,
            payload={
                "call_id": request.idempotency_key,
                "target_id": request.target_id,
                "request_digest": request.request_digest(),
                "gate_uri": reference.uri,
                "gate_digest_uri": reference.digest_uri,
                "query_gate_auth": physical_gate_query_auth_tag(
                    session.resume_token,
                    target_id=request.target_id,
                    session_id=request.session_id,
                    call_id=request.idempotency_key,
                    request_digest=request.request_digest(),
                    gate_uri=reference.uri,
                    gate_digest_uri=reference.digest_uri,
                    sequence=query_sequence,
                ),
            },
        )
    )
    assert queried.payload["ok"] is True
    assert queried.payload["receipt"]["status"] == "STARTED"
    assert queried.payload["physical_provider_gate"]["uri"] == reference.uri
    assert queried.payload["physical_worker_lease"]["call_key"] == (
        WorkerCallKey.from_request(request).model_dump(mode="json")
    )
    assert "lease_token" not in queried.payload["physical_worker_lease"]
    assert service.state.load_receipt(request.session_id, request.idempotency_key).status == "STARTED"


def test_daemon_start_accepts_fast_terminal_only_through_strict_revalidation(
    tmp_path,
    monkeypatch,
):
    service, _authority, request, manifest = _physical_service(tmp_path)
    worker_store = WorkerLeaseStore(tmp_path / "physical-leases")
    gate_store = PhysicalProviderGateReceiptStore(tmp_path / "physical-gates")
    armed_zero = _armed_zero(request, manifest)
    consumed = _consumed_gate_receipt(request, armed_zero)
    runtime = _TwoPhaseRuntimeStub(worker_store, armed_zero)
    service.physical_worker_store = worker_store
    service.physical_gate_receipt_store = gate_store
    gate = object.__new__(ZeroMotionPhysicalProviderGate)
    monkeypatch.setattr(
        ZeroMotionPhysicalProviderGate,
        "validate_request",
        lambda *_args: None,
    )
    monkeypatch.setattr(
        ZeroMotionPhysicalProviderGate,
        "consume",
        lambda *_args: consumed,
    )
    monkeypatch.setattr(
        ZeroMotionPhysicalProviderGate,
        "revalidate_consumption",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        "rolo.targetd.physical_worker.read_target_physical_worker_registry",
        lambda **_kwargs: SimpleNamespace(armed_zero=armed_zero),
    )
    daemon = TargetdDaemon(
        service,
        execute_calls=True,
        provider=RosContainerProvider(),
        physical_process_runtime=runtime,
        physical_process_work_factory=lambda *_args: object(),
        physical_gate_factory=lambda *_args: gate,
    )
    session = service.state.load_session(request.session_id)
    daemon._session = session
    prepared = daemon._handle(
        ProtocolFrame.create(
            kind=FrameKind.PREPARE_PHYSICAL_CALL,
            sequence=0,
            session_id=request.session_id,
            run_id=request.run_id,
            payload=request.model_dump(mode="json"),
        )
    )
    assert prepared.payload["ok"] is True

    terminal_receipt = None

    def complete_before_start_returns():
        nonlocal terminal_receipt
        terminal_receipt = service.state.update_receipt(
            request.session_id,
            request.idempotency_key,
            lambda receipt: receipt.model_copy(
                update={
                    "status": "FAILED",
                    "result": {"status": "FAILED", "error": "SAFE_FAST_FAILURE"},
                    "updated_at": datetime.now(timezone.utc),
                }
            ),
        )

    runtime.after_start_gate = complete_before_start_returns
    strict_calls = []

    def strict_terminal(call_key, lease):
        assert call_key == WorkerCallKey.from_request(request)
        assert lease.call_key == call_key
        strict_calls.append(call_key)
        assert terminal_receipt is not None
        return terminal_receipt

    monkeypatch.setattr(
        service,
        "revalidate_physical_process_terminal",
        strict_terminal,
    )
    raw_gate = {"schema_version": "rolo-test-physical-gate-envelope/v1"}
    gate_digest = canonical_json_sha256(raw_gate)
    sequence = 1
    response = daemon._handle(
        ProtocolFrame.create(
            kind=FrameKind.START_PREPARED_CALL,
            sequence=sequence,
            session_id=request.session_id,
            run_id=request.run_id,
            payload={
                "call_id": request.idempotency_key,
                "target_id": request.target_id,
                "request_digest": request.request_digest(),
                "armed_zero_receipt_digest": armed_zero.arm_receipt_digest,
                "provider_gate": raw_gate,
                "provider_gate_payload_digest": gate_digest,
                "start_auth": physical_prepared_start_auth_tag(
                    session.resume_token,
                    target_id=request.target_id,
                    session_id=request.session_id,
                    call_id=request.idempotency_key,
                    request_digest=request.request_digest(),
                    armed_zero_receipt_digest=armed_zero.arm_receipt_digest,
                    provider_gate_payload_digest=gate_digest,
                    sequence=sequence,
                ),
            },
        )
    )
    assert response.payload["ok"] is True
    assert response.payload["call_started"] is True
    assert response.payload["receipt"]["status"] == "FAILED"
    assert strict_calls == [WorkerCallKey.from_request(request)]


def test_process_control_auth_sequence_is_atomic_with_channel_exchange():
    session = JourneySession.create(
        session_id="process-control-session",
        target_id="mentorpi",
        profile_id="landerpi",
    )

    class BlockingChannel:
        def __init__(self):
            self.sent = []
            self.query_sent = threading.Event()
            self.release_query = threading.Event()
            self.response_sequence = 0

        def send(self, frame):
            self.sent.append(frame)
            if frame.kind == FrameKind.QUERY_CALL:
                self.query_sent.set()

        def receive(self):
            request = self.sent[-1]
            if request.kind == FrameKind.QUERY_CALL:
                assert self.release_query.wait(2)
            response = ProtocolFrame.create(
                kind=FrameKind.RESULT,
                sequence=self.response_sequence,
                session_id=session.session_id,
                run_id=request.run_id,
                payload={"request_kind": request.kind.value, "ok": True},
            )
            self.response_sequence += 1
            return response

        def close(self):
            return None

    channel = BlockingChannel()
    client = JourneySessionClient(channel, session)
    failures = []
    query = threading.Thread(
        target=lambda: client.query_call("call-1"),
    )
    query.start()
    assert channel.query_sent.wait(2)

    def stop():
        try:
            client.interrupt_process_remote(
                "call-1",
                "a" * 64,
                intent="STOP",
            )
        except Exception as exc:  # pragma: no cover - asserted below
            failures.append(exc)

    interrupt = threading.Thread(target=stop)
    interrupt.start()
    time.sleep(0.05)
    assert len(channel.sent) == 1
    channel.release_query.set()
    query.join(2)
    interrupt.join(2)
    assert not query.is_alive() and not interrupt.is_alive()
    assert failures == []
    stop_frame = channel.sent[1]
    assert stop_frame.kind == FrameKind.STOP
    assert stop_frame.sequence == 1
    assert stop_frame.payload["control_auth"] == process_control_auth_tag(
        session.resume_token,
        kind="STOP",
        session_id=session.session_id,
        call_id="call-1",
        request_digest="a" * 64,
        sequence=1,
    )
