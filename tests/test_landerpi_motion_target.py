import base64
import hashlib
import inspect
import json
import os
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
from jsonschema import Draft202012Validator, FormatChecker, ValidationError

from rolo.targetd.landerpi_motion_target import (
    ArmedZeroProviderBinding,
    AtomicLanderPiMotionStateStore,
    DebugOnlyUserAttestedAdmission,
    DebugPinnedPeerBootstrapReplayStore,
    DebugPinnedTargetdPeerBootstrapReceipt,
    FreshZeroMotionEvidence,
    LanderPiArmedRegistrySnapshot,
    LanderPiTargetMotionState,
    LanderPiZeroMotionStatus,
    LanderPiZeroMotionTarget,
    PinnedKeyOnlyLanderPiMotionRpc,
    PinnedLanderPiRpcSecurity,
    PinnedTargetdPeerCapability,
    TargetdDockerPinnedReadControlTransport,
    TargetPhysicalWorkerRegistryRecord,
    TargetSigningKey,
    compose_landerpi_zero_motion_target,
    compute_armed_zero_provider_identity_digest,
    consume_debug_pinned_targetd_peer_bootstrap,
    consume_debug_user_attested_provider_gate,
    revalidate_debug_user_attested_provider_gate,
    run_debug_user_attested_zero_motion_acceptance,
)
from rolo.targetd.motion_acceptance import SignedZeroMotionArtifact
from rolo.targetd.motion_safety import (
    MotionSafetyIntent,
    MotionSafetyPolicy,
    MotionSafetyTrustStore,
    compute_direct_motor_fence_digest,
    compute_motion_payload_digest,
    compute_stop_action_digest,
)

NOW = datetime(2026, 9, 9, 8, 0, tzinfo=timezone.utc)
TARGET_ID = "mentorpi"
TARGET_IDENTITY = "sha256:mentorpi-device-key"
COMMAND_ROUTE = "/cmd_vel"
COMMAND_INTERFACE = "geometry_msgs/msg/Twist"
COMPETING_ROUTE = "/controller/cmd_vel"
PUBLISHER = "/rolo_bounded_twist"
ODOM = "/odom_publisher"
MOTOR_ROUTE = "/ros_robot_controller/set_motor"
MOTOR_INTERFACE = "ros_robot_controller_msgs/msg/MotorsState"
GRAPH_AUTHORITY = "authority:graph"
TARGET_AUTHORITY = "authority:target"
GRAPH_KEY = b"g" * 32
TARGET_KEY = b"t" * 32
SHA_A = "sha256:" + "a" * 64
RUNTIME_SHA = "sha256:" + "b" * 64
CMDLINE_SHA = "sha256:" + "c" * 64
WORKER_GID = "10" * 16
CALL_KEY_DIGEST = "1" * 64
REQUEST_DIGEST = "2" * 64
HOST_KEY = "sha256:" + "1" * 64
CLIENT_KEY = "sha256:" + "6" * 64
KNOWN_HOSTS = "sha256:" + "7" * 64
CHANNEL_BINDING = "sha256:" + "8" * 64
BOOTSTRAP_KEY = b"p" * 32


def _fresh_zero_evidence(
    *,
    ended_at: datetime = NOW,
    imu_stream: str = "/imu",
) -> FreshZeroMotionEvidence:
    unsigned = {
        "schema_version": "rolo-landerpi-fresh-zero-motion-evidence/v1",
        "window_started_at": ended_at - timedelta(seconds=0.4),
        "window_ended_at": ended_at,
        "command_sample_count": 8,
        "command_latest_sample_at": ended_at - timedelta(seconds=0.01),
        "command_max_abs_component": 0.0,
        "command_samples_digest": "sha256:" + "3" * 64,
        "motor_sample_count": 8,
        "motor_latest_sample_at": ended_at - timedelta(seconds=0.01),
        "motor_value_count": 32,
        "motor_max_abs_rps": 0.0,
        "motor_samples_digest": "sha256:" + "4" * 64,
        "imu_stream": imu_stream,
        "imu_sample_count": 8,
        "imu_latest_sample_at": ended_at - timedelta(seconds=0.01),
        "imu_sample_rate_hz": 20.0,
        "imu_max_abs_angular_z_rad_s": 0.002,
        "imu_max_abs_z_bias_residual_rad_s": 0.001,
        "imu_samples_digest": "sha256:" + "5" * 64,
    }
    return FreshZeroMotionEvidence(
        **unsigned,
        evidence_sha256=compute_motion_payload_digest(unsigned),
    )


def _policy() -> MotionSafetyPolicy:
    return MotionSafetyPolicy(
        target_id=TARGET_ID,
        target_identity=TARGET_IDENTITY,
        site_id="site:lab-1",
        safe_zone_id="zone:motion-pad-a",
        command_route=COMMAND_ROUTE,
        command_interface=COMMAND_INTERFACE,
        allowed_publisher_identity=PUBLISHER,
        direct_motor_route=MOTOR_ROUTE,
        direct_motor_interface=MOTOR_INTERFACE,
        allowed_direct_motor_publisher_identity=ODOM,
        operator_authority_id="authority:operator",
        presence_authority_id="authority:presence",
        safety_authority_id="authority:safety",
        graph_authority_id=GRAPH_AUTHORITY,
        target_authority_id=TARGET_AUTHORITY,
        max_graph_age_s=5,
        max_attestation_age_s=30,
    )


def _debug_peer_receipt(**overrides) -> DebugPinnedTargetdPeerBootstrapReceipt:
    values = {
        "capability_id": "peer-capability-1",
        "bootstrap_authority_id": "debug-bootstrap:runner",
        "target_id": TARGET_ID,
        "target_identity": TARGET_IDENTITY,
        "call_id": "call-motion-1",
        "session_id": "session-motion-1",
        "execution_subject_digest": SHA_A,
        "ssh_host": "landerpi",
        "ssh_port": 22,
        "pinned_host_key_sha256": HOST_KEY,
        "client_public_key_sha256": CLIENT_KEY,
        "known_hosts_sha256": KNOWN_HOSTS,
        "channel_binding_sha256": CHANNEL_BINDING,
        "bootstrap_nonce": b"n" * 32,
        "issued_at": NOW - timedelta(seconds=1),
        "expires_at": NOW + timedelta(seconds=30),
        "signing_key": TargetSigningKey.from_bytes(BOOTSTRAP_KEY),
    }
    values.update(overrides)
    return DebugPinnedTargetdPeerBootstrapReceipt.build(**values)


def _consume_debug_peer(tmp_path: Path) -> PinnedTargetdPeerCapability:
    return consume_debug_pinned_targetd_peer_bootstrap(
        _debug_peer_receipt(),
        verification_key=TargetSigningKey.from_bytes(BOOTSTRAP_KEY),
        replay_store=DebugPinnedPeerBootstrapReplayStore((tmp_path / "peer-replay").resolve()),
        expected_bootstrap_authority_id="debug-bootstrap:runner",
        expected_target_id=TARGET_ID,
        expected_target_identity=TARGET_IDENTITY,
        expected_call_id="call-motion-1",
        expected_session_id="session-motion-1",
        expected_execution_subject_digest=SHA_A,
        expected_ssh_host="landerpi",
        expected_ssh_port=22,
        expected_pinned_host_key_sha256=HOST_KEY,
        expected_client_public_key_sha256=CLIENT_KEY,
        expected_known_hosts_sha256=KNOWN_HOSTS,
        expected_channel_binding_sha256=CHANNEL_BINDING,
        at=NOW,
    )


def _intent(*, epoch: int = 7) -> MotionSafetyIntent:
    fence = compute_direct_motor_fence_digest(
        execution_subject_digest=SHA_A,
        call_id="call-motion-1",
        session_id="session-motion-1",
        target_id=TARGET_ID,
        target_identity=TARGET_IDENTITY,
        ros_graph_digest=SHA_A,
        command_route=COMMAND_ROUTE,
        publisher_identity=PUBLISHER,
        direct_motor_route=MOTOR_ROUTE,
        direct_motor_interface=MOTOR_INTERFACE,
        direct_motor_publisher_identity=ODOM,
        fence_epoch=epoch,
    )
    stop = compute_stop_action_digest(
        execution_subject_digest=SHA_A,
        call_id="call-motion-1",
        session_id="session-motion-1",
        target_id=TARGET_ID,
        target_identity=TARGET_IDENTITY,
        ros_graph_digest=SHA_A,
        command_route=COMMAND_ROUTE,
        publisher_identity=PUBLISHER,
        direct_motor_route=MOTOR_ROUTE,
        direct_motor_interface=MOTOR_INTERFACE,
        direct_motor_publisher_identity=ODOM,
        direct_motor_fence_digest=fence,
    )
    return MotionSafetyIntent(
        call_id="call-motion-1",
        session_id="session-motion-1",
        target_id=TARGET_ID,
        target_identity=TARGET_IDENTITY,
        operator_id="operator:field-1",
        execution_subject_digest=SHA_A,
        requested_at=NOW,
        ros_graph_digest=SHA_A,
        command_route=COMMAND_ROUTE,
        command_interface=COMMAND_INTERFACE,
        publisher_identity=PUBLISHER,
        direct_motor_route=MOTOR_ROUTE,
        direct_motor_interface=MOTOR_INTERFACE,
        direct_motor_publisher_identity=ODOM,
        direct_motor_fence_digest=fence,
        stop_action_digest=stop,
    )


def _topic_info(
    interface: str,
    *,
    publishers: list[tuple[str, str]],
    subscribers: list[tuple[str, str]],
) -> str:
    lines = [f"Type: {interface}", f"Publisher count: {len(publishers)}"]
    for endpoint_type, endpoints in (("PUBLISHER", publishers), ("SUBSCRIPTION", subscribers)):
        if endpoint_type == "SUBSCRIPTION":
            lines.append(f"Subscription count: {len(subscribers)}")
        for identity, gid in endpoints:
            namespace, _, name = identity.rpartition("/")
            lines.extend(
                [
                    f"Node name: {name}",
                    f"Node namespace: {namespace or '/'}",
                    f"Endpoint type: {endpoint_type}",
                    f"GID: {gid}",
                ]
            )
    return "\n".join(lines) + "\n"


class _PinnedRpc:
    def __init__(self) -> None:
        self.armed = False
        self.command_publishers: list[tuple[str, str]] = []
        self.competing_publishers: list[tuple[str, str]] = []
        self.motor_publishers: list[tuple[str, str]] = [(ODOM, "30.00000001")]
        self.security: object = PinnedLanderPiRpcSecurity(
            target_id=TARGET_ID,
            target_identity=TARGET_IDENTITY,
            pinned_host_key_sha256=HOST_KEY,
            observed_host_key_sha256=HOST_KEY,
        )
        self.status_override: object | None = None
        self.provider_pid = 4242
        self.provider_start_time_ticks = 123456
        self.provider_runtime_sha256 = RUNTIME_SHA
        self.provider_cmdline_sha256 = CMDLINE_SHA
        self.topic_calls: list[tuple[str, str]] = []

    def arm(self) -> None:
        self.armed = True
        self.command_publishers = [(PUBLISHER, "10.00000001")]

    def security_context(self):
        return self.security

    def topic_info_verbose(self, *, route: str, expected_interface: str) -> str:
        self.topic_calls.append((route, expected_interface))
        if route == COMMAND_ROUTE:
            return _topic_info(
                COMMAND_INTERFACE,
                publishers=self.command_publishers,
                subscribers=[(ODOM, "10.00000002")],
            )
        if route == COMPETING_ROUTE:
            return _topic_info(
                COMMAND_INTERFACE,
                publishers=self.competing_publishers,
                subscribers=[(ODOM, "20.00000001")],
            )
        if route == MOTOR_ROUTE:
            return _topic_info(MOTOR_INTERFACE, publishers=self.motor_publishers, subscribers=[])
        raise AssertionError(f"unexpected route: {route}")

    def zero_motion_status(self):
        if self.status_override is not None:
            return self.status_override
        if not self.armed:
            return LanderPiZeroMotionStatus(observed_at=NOW, provider_process_state="ABSENT")
        runtime_digest = compute_armed_zero_provider_identity_digest(
            call_id="call-motion-1",
            session_id="session-motion-1",
            execution_subject_digest=SHA_A,
            publisher_identity=PUBLISHER,
            publisher_gid=self.command_publishers[0][1],
            provider_pid=self.provider_pid,
            provider_start_time_ticks=self.provider_start_time_ticks,
            provider_runtime_sha256=self.provider_runtime_sha256,
            provider_cmdline_sha256=self.provider_cmdline_sha256,
        )
        return LanderPiZeroMotionStatus(
            observed_at=NOW,
            provider_process_state="ARMED_ZERO",
            publisher_identity=PUBLISHER,
            publisher_gid=self.command_publishers[0][1],
            call_id="call-motion-1",
            session_id="session-motion-1",
            execution_subject_digest=SHA_A,
            provider_pid=self.provider_pid,
            provider_start_time_ticks=self.provider_start_time_ticks,
            provider_runtime_sha256=self.provider_runtime_sha256,
            provider_cmdline_sha256=self.provider_cmdline_sha256,
            provider_runtime_identity_digest=runtime_digest,
            last_command_is_zero=True,
            motor_output_zero=True,
            motors_stopped=True,
            zero_velocity_verified=True,
            fresh_zero_evidence=_fresh_zero_evidence(),
            fresh_zero_evidence_digest=_fresh_zero_evidence().evidence_sha256,
        )


def _target(tmp_path: Path):
    policy = _policy()
    intent = _intent()
    rpc = _PinnedRpc()
    store = AtomicLanderPiMotionStateStore(tmp_path.resolve())
    store.provision(LanderPiTargetMotionState.initial(intent, fence_epoch=7, now=NOW))
    target = LanderPiZeroMotionTarget(
        policy=policy,
        rpc=rpc,
        store=store,
        graph_signing_key=TargetSigningKey.from_bytes(GRAPH_KEY),
        target_signing_key=TargetSigningKey.from_bytes(TARGET_KEY),
        clock=lambda: NOW,
    )
    return target, rpc, store, policy, intent


def _debug_admission(intent: MotionSafetyIntent, policy: MotionSafetyPolicy) -> DebugOnlyUserAttestedAdmission:
    return DebugOnlyUserAttestedAdmission.build(
        attestation_id="user-site-safety-1",
        acceptance_id="acceptance-motion-1",
        intent=intent,
        policy=policy,
        basis_text="用户明确确认现场人员、独立急停和安全区已妥善安排，本轮不重复演练。",
        requested_rotation_degrees=1.0,
        requested_linear_meters=0.03,
        issued_at=NOW,
        expires_at=NOW + timedelta(seconds=5),
    )


class _PinnedReadControlTransport:
    def __init__(self, snapshot: LanderPiArmedRegistrySnapshot) -> None:
        self.snapshot: object = snapshot
        self.security: object = PinnedLanderPiRpcSecurity(
            target_id=TARGET_ID,
            target_identity=TARGET_IDENTITY,
            pinned_host_key_sha256=HOST_KEY,
            observed_host_key_sha256=HOST_KEY,
        )
        self.topic_reads: list[tuple[str, str]] = []
        self.registry_reads = 0

    def security_context(self):
        return self.security

    def read_topic_info_verbose(self, *, route: str, expected_interface: str) -> str:
        self.topic_reads.append((route, expected_interface))
        if route == COMMAND_ROUTE:
            return _topic_info(
                COMMAND_INTERFACE,
                publishers=[(PUBLISHER, "10.00000001")],
                subscribers=[(ODOM, "10.00000002")],
            )
        if route == COMPETING_ROUTE:
            return _topic_info(
                COMMAND_INTERFACE,
                publishers=[],
                subscribers=[(ODOM, "20.00000001")],
            )
        if route == MOTOR_ROUTE:
            return _topic_info(MOTOR_INTERFACE, publishers=[(ODOM, "30.00000001")], subscribers=[])
        raise AssertionError(route)

    def read_and_verify_armed_registry_snapshot(self):
        self.registry_reads += 1
        return self.snapshot


def _concrete_rpc_fixture():
    from rolo.targetd.physical_worker import _canonical_bytes, _registry_binding_digest

    cmdline = b"python3\0-m\0rolo.targetd.physical_worker\0"
    cmdline_sha = "sha256:" + hashlib.sha256(cmdline).hexdigest()
    binding_digest = compute_armed_zero_provider_identity_digest(
        call_id="call-motion-1",
        session_id="session-motion-1",
        execution_subject_digest=SHA_A,
        publisher_identity=PUBLISHER,
        publisher_gid=WORKER_GID,
        provider_pid=4242,
        provider_start_time_ticks=123456,
        provider_runtime_sha256=RUNTIME_SHA,
        provider_cmdline_sha256=cmdline_sha,
    )
    issued_at = NOW.timestamp() - 1
    expires_at = NOW.timestamp() + 4
    registry_binding_digest = _registry_binding_digest(
        target_id=TARGET_ID,
        call_key_digest=CALL_KEY_DIGEST,
        call_id="call-motion-1",
        session_id="session-motion-1",
        execution_subject_digest=SHA_A,
        publisher_identity=PUBLISHER,
        publisher_gid=WORKER_GID,
        provider_pid=4242,
        provider_start_time_ticks=123456,
        provider_runtime_sha256=RUNTIME_SHA,
        provider_cmdline_sha256=cmdline_sha,
        issued_at_epoch_s=issued_at,
        expires_at_epoch_s=expires_at,
    )
    arm_receipt = {
        "schema_version": "rolo-targetd-physical-worker-arm-receipt/v1",
        "call_key_digest": CALL_KEY_DIGEST,
        "target_id": TARGET_ID,
        "call_id": "call-motion-1",
        "session_id": "session-motion-1",
        "request_digest": REQUEST_DIGEST,
        "execution_subject_digest": SHA_A,
        "runtime_sha256": RUNTIME_SHA.removeprefix("sha256:"),
        "command_endpoint": COMMAND_ROUTE,
        "publisher_identity": PUBLISHER,
        "publisher_endpoint_gids": [WORKER_GID],
        "publisher_endpoint_count": 1,
        "competing_publisher_count": 0,
        "direct_motor_publisher_identities": [ODOM],
        "zeros_published": 5,
        "independent_stationary_sources": ["/imu"],
        "independent_stationary_sample_counts": {"/imu": 4},
        "independent_stationary_last_sample_age_s": {"/imu": 0.01},
        "independent_stationary_max_abs_rad_s": {"/imu": 0.002},
        "independent_stationary_window_s": 0.2,
        "motion_command_emitted": False,
        "motion_enabled": False,
        "inner_process_identity": {
            "schema_version": "rolo-targetd-inner-process-identity/v1",
            "pid": 4242,
            "start_ticks": 123456,
            "cmdline_sha256": cmdline_sha.removeprefix("sha256:"),
        },
        "target_monotonic_s": 123.0,
        "provider_runtime_sha256": RUNTIME_SHA,
        "provider_cmdline_sha256": cmdline_sha,
        "provider_runtime_identity_digest": binding_digest,
        "registry_issued_at_epoch_s": issued_at,
        "registry_expires_at_epoch_s": expires_at,
        "registry_binding_digest": registry_binding_digest,
    }
    arm_receipt["arm_receipt_digest"] = hashlib.sha256(_canonical_bytes(arm_receipt)).hexdigest()
    record = TargetPhysicalWorkerRegistryRecord(
        schema_version="rolo-targetd-physical-worker-registry/v1",
        state="ACTIVE",
        arm_receipt=arm_receipt,
        updated_at_epoch_s=NOW.timestamp() - 0.05,
        zero_refresh_count=4,
        last_zero_at_epoch_s=NOW.timestamp() - 0.05,
        terminal_reason=None,
        registry_auth_tag="hmac-sha256:" + "a" * 64,
    )
    command_info = _topic_info(
        COMMAND_INTERFACE,
        publishers=[(PUBLISHER, WORKER_GID)],
        subscribers=[(ODOM, "10.00000002")],
    )
    snapshot = LanderPiArmedRegistrySnapshot(
        observed_at=NOW,
        registry_present=True,
        process_match_count=1,
        registry_json=record.model_dump_json(),
        live_pid=4242,
        live_start_time_ticks=123456,
        live_cmdline_base64=base64.b64encode(cmdline).decode("ascii"),
        live_runtime_sha256=RUNTIME_SHA,
        command_topic_info_verbose=command_info,
        competing_topic_info_verbose=_topic_info(
            COMMAND_INTERFACE,
            publishers=[],
            subscribers=[(ODOM, "20.00000001")],
        ),
        direct_motor_topic_info_verbose=_topic_info(
            MOTOR_INTERFACE,
            publishers=[(ODOM, "30.00000001")],
            subscribers=[],
        ),
        fresh_zero_evidence=_fresh_zero_evidence(),
    )
    transport = _PinnedReadControlTransport(snapshot)
    rpc = PinnedKeyOnlyLanderPiMotionRpc(
        policy=_policy(),
        transport=transport,
        expected_call_key_digest=CALL_KEY_DIGEST,
        expected_request_digest=REQUEST_DIGEST,
        expected_call_id="call-motion-1",
        expected_session_id="session-motion-1",
        expected_execution_subject_digest=SHA_A,
        manifest_provider_runtime_sha256=RUNTIME_SHA,
        clock=lambda: NOW,
    )
    return rpc, transport, record, snapshot


def _full_sequence(tmp_path: Path, *, consume: bool = True):
    target, rpc, store, policy, intent = _target(tmp_path)
    initial = target.verify_initial_isolation()
    assert initial.command.publisher_count == 0
    rpc.arm()
    acceptance_id = "acceptance-motion-1"
    pre = target.observe_isolation(
        acceptance_id=acceptance_id,
        intent=intent,
        policy=policy,
        phase="PRE_CAS",
        fence_binding_digest=None,
    )
    cas = target.compare_and_set_fence(
        acceptance_id=acceptance_id,
        intent=intent,
        policy=policy,
        snapshot_artifact_digest=pre.payload_sha256,
    )
    start = target.acknowledge_zero_motion_start(
        acceptance_id=acceptance_id,
        intent=intent,
        fence_cas_artifact_digest=cas.payload_sha256,
    )
    stop = target.acknowledge_zero_motion_stop(
        acceptance_id=acceptance_id,
        intent=intent,
        fence_cas_artifact_digest=cas.payload_sha256,
        start_ack_artifact_digest=start.payload_sha256,
    )
    post = target.observe_isolation(
        acceptance_id=acceptance_id,
        intent=intent,
        policy=policy,
        phase="POST_STOP",
        fence_binding_digest=cas.claims["fence_lease_digest"],
    )
    release = target.release_fence(
        acceptance_id=acceptance_id,
        intent=intent,
        fence_cas_artifact_digest=cas.payload_sha256,
        stop_ack_artifact_digest=stop.payload_sha256,
        post_snapshot_artifact_digest=post.payload_sha256,
    )
    challenge = target.issue_provider_gate_challenge(
        acceptance_id=acceptance_id,
        intent=intent,
        release_artifact_digest=release.payload_sha256,
        post_snapshot_artifact_digest=post.payload_sha256,
        released_fence_digest=release.claims["restored_fence_digest"],
        released_fence_epoch=release.claims["restored_fence_epoch"],
        expected_graph_revision=post.claims["graph_revision"],
    )
    artifacts = (pre, cas, start, stop, post, release, challenge)
    if consume:
        consumed = target.compare_and_set_provider_gate(
            acceptance_id=acceptance_id,
            intent=intent,
            policy=policy,
            challenge_artifact_digest=challenge.payload_sha256,
            consume_token_digest=challenge.claims["consume_token_digest"],
        )
        artifacts = (*artifacts, consumed)
    return target, rpc, store, policy, intent, artifacts


def test_driver_runs_initial_zero_then_prearmed_rehearsal_and_one_shot_consume(tmp_path):
    target, _, store, policy, intent, artifacts = _full_sequence(tmp_path)
    assert [item.kind for item in artifacts] == [
        "LIVE_ISOLATION_SNAPSHOT",
        "LIVE_FENCE_CAS",
        "ZERO_MOTION_START_ACK",
        "ZERO_MOTION_STOP_ACK",
        "LIVE_ISOLATION_SNAPSHOT",
        "LIVE_FENCE_RELEASE",
        "PROVIDER_GATE_CHALLENGE",
        "PROVIDER_GATE_CONSUMED",
    ]
    state = store.load()
    assert (state.phase, state.state_revision, state.fence_epoch) == ("PROVIDER_FENCE", 8, 10)
    assert state.fence_digest == artifacts[-1].claims["provider_fence_digest"]
    binding = artifacts[-1].claims["armed_zero_provider_binding"]
    assert binding == artifacts[-2].claims["armed_zero_provider_binding"]
    assert binding["publisher_gid"] == "10.00000001"
    assert binding["provider_pid"] == 4242
    assert binding["provider_runtime_sha256"] == RUNTIME_SHA
    assert binding["provider_cmdline_sha256"] == CMDLINE_SHA
    trust = MotionSafetyTrustStore({GRAPH_AUTHORITY: GRAPH_KEY, TARGET_AUTHORITY: TARGET_KEY})
    for artifact in artifacts:
        assert store.get_artifact(artifact.payload_sha256) == artifact
        assert trust.verify_payload_signature(
            issuer_id=artifact.issuer_id,
            payload_sha256=artifact.payload_sha256,
            signature_hmac_sha256=artifact.signature_hmac_sha256,
        )
        assert artifact.call_id == intent.call_id
        assert artifact.session_id == intent.session_id
        assert artifact.target_id == policy.target_id
        if "motion_enabled" in artifact.claims:
            assert artifact.claims["motion_enabled"] is False
        else:
            assert artifact.claims["motion_command_emitted"] is False
        assert artifact.claims["provider_invocation_count"] == 0

    with pytest.raises(RuntimeError, match="ALREADY_USED_OR_INVALID"):
        target.compare_and_set_provider_gate(
            acceptance_id="acceptance-motion-1",
            intent=intent,
            policy=policy,
            challenge_artifact_digest=artifacts[-2].payload_sha256,
            consume_token_digest=artifacts[-2].claims["consume_token_digest"],
        )
    assert store.load() == state


def test_abort_advances_epoch_and_clears_owner_without_motion(tmp_path):
    target, _, store, _, intent, _ = _full_sequence(tmp_path)

    target.abort_zero_motion(acceptance_id="acceptance-motion-1", intent=intent)

    state = store.load()
    assert (state.phase, state.fence_epoch, state.state_revision) == ("SAFE_BASELINE", 11, 9)
    assert state.acceptance_id is None
    artifact = store.get_artifact(state.last_artifact_digest)
    assert artifact is not None and artifact.kind == "ZERO_MOTION_ABORT_ACK"
    assert artifact.claims["motion_enabled"] is False
    assert artifact.claims["provider_invocation_count"] == 0


def test_debug_user_attested_path_is_explicit_bounded_persisted_and_one_shot(tmp_path):
    target, rpc, store, policy, intent = _target(tmp_path)
    assert target.verify_initial_isolation().command.publisher_count == 0
    rpc.arm()
    admission = _debug_admission(intent, policy)
    trust = MotionSafetyTrustStore({GRAPH_AUTHORITY: GRAPH_KEY, TARGET_AUTHORITY: TARGET_KEY})

    acceptance = run_debug_user_attested_zero_motion_acceptance(
        admission,
        intent=intent,
        policy=policy,
        trust_store=trust,
        target=target,
        now=NOW,
    )
    consumption = consume_debug_user_attested_provider_gate(
        admission,
        acceptance,
        intent=intent,
        policy=policy,
        trust_store=trust,
        target=target,
        now=NOW,
    )

    assert acceptance.status == "DEBUG_ACCEPTED"
    assert acceptance.report_status == "PASS_WITH_USER_ATTESTED_SITE_SAFETY"
    assert acceptance.production_ready is False
    assert acceptance.production_authority_verified is False
    assert acceptance.fresh_estop_challenge_verified is False
    assert acceptance.provider_boundary_open is False
    assert acceptance.motion_authorized is False
    assert acceptance.debug_attestation_artifact is not None
    claims = acceptance.debug_attestation_artifact.claims
    assert claims["basis_digest"] == admission.basis_digest
    assert claims["debug_admission_digest"] == admission.payload_sha256
    assert claims["max_abs_rotation_degrees"] == 1.0
    assert claims["max_abs_linear_meters"] == 0.03
    assert claims["production_ready"] is False
    marker = store.debug_admission_root / (admission.payload_sha256.removeprefix("sha256:") + ".json")
    assert marker.is_file()

    assert consumption.status == "DEBUG_CONSUMED"
    assert consumption.report_status == "PASS_WITH_USER_ATTESTED_SITE_SAFETY"
    assert consumption.debug_provider_boundary_open is True
    assert consumption.production_provider_boundary_open is False
    assert consumption.debug_motion_authorized is True
    assert consumption.provider_invocation_limit == 1
    assert consumption.production_authority_verified is False
    assert consumption.fresh_estop_challenge_verified is False
    assert store.load().phase == "PROVIDER_FENCE"

    replay = consume_debug_user_attested_provider_gate(
        admission,
        acceptance,
        intent=intent,
        policy=policy,
        trust_store=trust,
        target=target,
        now=NOW,
    )
    assert replay.status == "DEBUG_BLOCKED"
    assert replay.reasons == ("DEBUG_PROVIDER_GATE_FRESH_CAS_UNAVAILABLE",)
    assert replay.debug_provider_boundary_open is False
    assert store.load().phase == "PROVIDER_FENCE"


def test_debug_gate_uses_incrementing_target_time_and_detached_service_revalidation(tmp_path):
    target, rpc, _, policy, intent = _target(tmp_path)
    rpc.arm()
    admission = _debug_admission(intent, policy)
    trust = MotionSafetyTrustStore({GRAPH_AUTHORITY: GRAPH_KEY, TARGET_AUTHORITY: TARGET_KEY})

    class IncrementingClock:
        def __init__(self) -> None:
            self.current = NOW

        def __call__(self) -> datetime:
            self.current += timedelta(milliseconds=5)
            return self.current

    clock = IncrementingClock()
    target.clock = clock
    acceptance = run_debug_user_attested_zero_motion_acceptance(
        admission,
        intent=intent,
        policy=policy,
        trust_store=trust,
        target=target,
        now=NOW,
    )
    assert acceptance.status == "DEBUG_ACCEPTED"
    consumption = consume_debug_user_attested_provider_gate(
        admission,
        acceptance,
        intent=intent,
        policy=policy,
        trust_store=trust,
        target=target,
        now=acceptance.evaluated_at,
    )
    assert consumption.status == "DEBUG_CONSUMED"
    validation = revalidate_debug_user_attested_provider_gate(
        admission,
        consumption,
        intent=intent,
        policy=policy,
        trust_store=trust,
        at=consumption.evaluated_at,
    )

    assert validation.status == "VALID"
    assert validation.production_ready is False
    assert validation.debug_provider_boundary_open is True
    assert validation.armed_zero_provider_binding.provider_runtime_sha256 == RUNTIME_SHA
    assert consumption.consume_artifact.issued_at > NOW

    tampered = consumption.model_copy(
        update={
            "debug_admission_digest": "sha256:" + "f" * 64,
        }
    )
    with pytest.raises(ValueError, match="IDENTITY_OR_EXPIRY_MISMATCH"):
        revalidate_debug_user_attested_provider_gate(
            admission,
            tampered,
            intent=intent,
            policy=policy,
            trust_store=trust,
            at=consumption.evaluated_at,
        )
    with pytest.raises(ValueError, match="IDENTITY_OR_EXPIRY_MISMATCH"):
        revalidate_debug_user_attested_provider_gate(
            admission,
            consumption,
            intent=intent,
            policy=policy,
            trust_store=trust,
            at=admission.expires_at,
        )


def test_debug_receipt_cannot_validate_as_a_production_acceptance(tmp_path):
    from rolo.targetd.motion_acceptance import ZeroMotionAcceptanceReceipt

    target, rpc, _, policy, intent = _target(tmp_path)
    rpc.arm()
    trust = MotionSafetyTrustStore({GRAPH_AUTHORITY: GRAPH_KEY, TARGET_AUTHORITY: TARGET_KEY})
    receipt = run_debug_user_attested_zero_motion_acceptance(
        _debug_admission(intent, policy),
        intent=intent,
        policy=policy,
        trust_store=trust,
        target=target,
        now=NOW,
    )

    with pytest.raises(ValueError):
        ZeroMotionAcceptanceReceipt.model_validate(receipt.model_dump(mode="python"))


@pytest.mark.parametrize(
    ("rotation", "linear", "expiry_seconds"),
    [(1.000001, 0.0, 5), (0.0, 0.030001, 5), (0.0, 0.0, 31)],
)
def test_debug_user_attestation_rejects_excess_motion_or_expiry(rotation, linear, expiry_seconds):
    intent = _intent()
    with pytest.raises(ValueError):
        DebugOnlyUserAttestedAdmission.build(
            attestation_id="user-site-safety-invalid",
            acceptance_id="acceptance-motion-1",
            intent=intent,
            policy=_policy(),
            basis_text="explicit session-only site safety assertion",
            requested_rotation_degrees=rotation,
            requested_linear_meters=linear,
            issued_at=NOW,
            expires_at=NOW + timedelta(seconds=expiry_seconds),
        )


def test_debug_user_attestation_identity_drift_and_live_graph_failure_block(tmp_path):
    target, rpc, store, policy, intent = _target(tmp_path)
    rpc.arm()
    admission = _debug_admission(intent, policy)
    trust = MotionSafetyTrustStore({GRAPH_AUTHORITY: GRAPH_KEY, TARGET_AUTHORITY: TARGET_KEY})
    drifted_intent = intent.model_copy(update={"call_id": "call-motion-other"})

    identity_blocked = run_debug_user_attested_zero_motion_acceptance(
        admission,
        intent=drifted_intent,
        policy=policy,
        trust_store=trust,
        target=target,
        now=NOW,
    )
    assert identity_blocked.status == "DEBUG_BLOCKED"
    assert store.load().state_revision == 0

    rpc.competing_publishers = [("/hand_gesture", "20.00000009")]
    graph_blocked = run_debug_user_attested_zero_motion_acceptance(
        admission,
        intent=intent,
        policy=policy,
        trust_store=trust,
        target=target,
        now=NOW,
    )
    assert graph_blocked.status == "DEBUG_BLOCKED"
    assert graph_blocked.reasons == ("DEBUG_USER_ATTESTED_LIVE_GATE_FAILED",)
    assert (store.load().phase, store.load().state_revision) == ("SAFE_BASELINE", 2)
    assert store.reserve_debug_admission(admission.payload_sha256) is False


def test_debug_admission_digest_reservation_is_durable_and_not_reusable(tmp_path):
    store = AtomicLanderPiMotionStateStore(tmp_path.resolve())
    admission = _debug_admission(_intent(), _policy())

    assert store.reserve_debug_admission(admission.payload_sha256) is True
    assert AtomicLanderPiMotionStateStore(tmp_path.resolve()).reserve_debug_admission(admission.payload_sha256) is False


def test_concrete_pinned_rpc_revalidates_authenticated_registry_proc_runtime_cmdline_and_gid():
    rpc, transport, record, _ = _concrete_rpc_fixture()

    status = rpc.zero_motion_status()
    topic = rpc.topic_info_verbose(route=COMMAND_ROUTE, expected_interface=COMMAND_INTERFACE)

    assert status.provider_process_state == "ARMED_ZERO"
    assert status.binding().provider_runtime_identity_digest == record.arm_receipt["provider_runtime_identity_digest"]
    assert status.fresh_zero_evidence_digest == transport.snapshot.fresh_zero_evidence.evidence_sha256
    assert transport.registry_reads == 1
    assert transport.topic_reads == [(COMMAND_ROUTE, COMMAND_INTERFACE)]
    assert "Publisher count: 1" in topic
    assert not any(hasattr(rpc, name) for name in ("run", "shell", "publish", "motor", "invoke_provider"))


def test_concrete_pinned_rpc_accepts_an_exact_absent_registry_snapshot():
    absent = LanderPiArmedRegistrySnapshot(
        observed_at=NOW,
        registry_present=False,
        process_match_count=0,
    )
    transport = _PinnedReadControlTransport(absent)
    rpc = PinnedKeyOnlyLanderPiMotionRpc(
        policy=_policy(),
        transport=transport,
        expected_call_key_digest=CALL_KEY_DIGEST,
        expected_request_digest=REQUEST_DIGEST,
        expected_call_id="call-motion-1",
        expected_session_id="session-motion-1",
        expected_execution_subject_digest=SHA_A,
        manifest_provider_runtime_sha256=RUNTIME_SHA,
        clock=lambda: NOW,
    )

    status = rpc.zero_motion_status()

    assert status.provider_process_state == "ABSENT"
    assert status.publisher_identity is None


def test_concrete_pinned_rpc_rejects_forged_or_stale_registry():
    rpc, transport, record, snapshot = _concrete_rpc_fixture()
    forged_arm = dict(record.arm_receipt)
    forged_arm["runtime_sha256"] = "f" * 64
    forged = record.model_copy(update={"arm_receipt": forged_arm})
    transport.snapshot = snapshot.model_copy(update={"registry_json": forged.model_dump_json()})
    with pytest.raises(RuntimeError, match="RECORD_INVALID"):
        rpc.zero_motion_status()

    transport.snapshot = snapshot.model_copy(update={"observed_at": NOW - timedelta(seconds=2)})
    with pytest.raises(RuntimeError, match="SNAPSHOT_STALE"):
        rpc.zero_motion_status()


@pytest.mark.parametrize(
    ("snapshot_update", "error"),
    [
        ({"fresh_zero_evidence": None}, "SNAPSHOT_INVALID"),
        ({"fresh_zero_evidence": _fresh_zero_evidence(ended_at=NOW - timedelta(seconds=2))}, "LIVE_REVALIDATION_FAILED"),
        (
            {"fresh_zero_evidence": _fresh_zero_evidence().model_copy(update={"imu_max_abs_angular_z_rad_s": 0.031})},
            "SNAPSHOT_INVALID",
        ),
        (
            {"fresh_zero_evidence": _fresh_zero_evidence().model_copy(update={"motor_max_abs_rps": 0.01})},
            "SNAPSHOT_INVALID",
        ),
        (
            {"fresh_zero_evidence": _fresh_zero_evidence(imu_stream="/imu_corrected")},
            "LIVE_REVALIDATION_FAILED",
        ),
    ],
)
def test_concrete_pinned_rpc_rejects_missing_stale_moving_or_nonzero_motor_evidence(
    snapshot_update,
    error,
):
    rpc, transport, _, snapshot = _concrete_rpc_fixture()
    transport.snapshot = snapshot.model_copy(update=snapshot_update)

    with pytest.raises(RuntimeError, match=error):
        rpc.zero_motion_status()


def test_armed_status_cannot_default_zero_proof_to_true():
    with pytest.raises(ValueError, match="fresh-zero|exact provider binding"):
        LanderPiZeroMotionStatus(
            observed_at=NOW,
            provider_process_state="ARMED_ZERO",
            publisher_identity=PUBLISHER,
            publisher_gid=WORKER_GID,
            call_id="call-motion-1",
            session_id="session-motion-1",
            execution_subject_digest=SHA_A,
            provider_pid=4242,
            provider_start_time_ticks=123456,
            provider_runtime_sha256=RUNTIME_SHA,
            provider_cmdline_sha256=CMDLINE_SHA,
            provider_runtime_identity_digest="sha256:" + "d" * 64,
        )


@pytest.mark.parametrize(
    ("update", "error"),
    [
        ({"zero_refresh_count": 0}, "IDENTITY_OR_EXPIRY_MISMATCH"),
        (
            {
                "updated_at_epoch_s": NOW.timestamp() - 0.6,
                "last_zero_at_epoch_s": NOW.timestamp() - 0.6,
            },
            "IDENTITY_OR_EXPIRY_MISMATCH",
        ),
    ],
)
def test_concrete_pinned_rpc_rejects_missing_or_stale_worker_zero_heartbeat(update, error):
    rpc, transport, record, snapshot = _concrete_rpc_fixture()
    transport.snapshot = snapshot.model_copy(update={"registry_json": record.model_copy(update=update).model_dump_json()})

    with pytest.raises(RuntimeError, match=error):
        rpc.zero_motion_status()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("live_pid", 4243),
        ("live_start_time_ticks", 123457),
        ("live_runtime_sha256", "sha256:" + "f" * 64),
        ("live_cmdline_base64", base64.b64encode(b"python3\0-m\0other.module\0").decode("ascii")),
    ],
)
def test_concrete_pinned_rpc_rejects_live_process_identity_drift(field, value):
    rpc, transport, _, snapshot = _concrete_rpc_fixture()
    transport.snapshot = snapshot.model_copy(update={field: value})

    with pytest.raises(RuntimeError, match="LIVE_REVALIDATION_FAILED"):
        rpc.zero_motion_status()


def test_concrete_pinned_rpc_rejects_gid_drift_ambiguous_process_and_non_key_security():
    rpc, transport, _, snapshot = _concrete_rpc_fixture()
    changed_topic = _topic_info(
        COMMAND_INTERFACE,
        publishers=[(PUBLISHER, "10.00000009")],
        subscribers=[(ODOM, "10.00000002")],
    )
    transport.snapshot = snapshot.model_copy(update={"command_topic_info_verbose": changed_topic})
    with pytest.raises(RuntimeError, match="LIVE_REVALIDATION_FAILED"):
        rpc.zero_motion_status()

    transport.snapshot = snapshot.model_copy(update={"process_match_count": 2})
    with pytest.raises(RuntimeError, match="SNAPSHOT_INVALID"):
        rpc.zero_motion_status()

    transport.snapshot = snapshot
    transport.security = {
        "target_id": TARGET_ID,
        "target_identity": TARGET_IDENTITY,
        "pinned_host_key_sha256": HOST_KEY,
        "observed_host_key_sha256": HOST_KEY,
        "password_used": True,
    }
    reads = transport.registry_reads
    with pytest.raises(RuntimeError, match="TRANSPORT_REQUIRED"):
        rpc.zero_motion_status()
    assert transport.registry_reads == reads


def test_concrete_pinned_rpc_rejects_non_allowlisted_reads():
    rpc, transport, _, _ = _concrete_rpc_fixture()

    with pytest.raises(RuntimeError, match="OUTSIDE_FIXED_ALLOWLIST"):
        rpc.topic_info_verbose(route="/other", expected_interface=COMMAND_INTERFACE)

    assert transport.topic_reads == []


def test_targetd_docker_transport_uses_fixed_shell_free_helper_and_strict_output(monkeypatch, tmp_path):
    calls = []
    outputs = {
        COMMAND_ROUTE: _topic_info(
            COMMAND_INTERFACE,
            publishers=[(PUBLISHER, WORKER_GID)],
            subscribers=[(ODOM, "10.00000002")],
        ),
        COMPETING_ROUTE: _topic_info(
            COMMAND_INTERFACE,
            publishers=[],
            subscribers=[(ODOM, "20.00000001")],
        ),
        MOTOR_ROUTE: _topic_info(
            MOTOR_INTERFACE,
            publishers=[(ODOM, "30.00000001")],
            subscribers=[],
        ),
    }

    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        payload = {
            "schema_version": "rolo-targetd-fixed-isolation-graph/v1",
            "outputs": outputs,
        }
        return SimpleNamespace(
            returncode=0,
            stdout=json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("ascii"),
            stderr=b"",
        )

    monkeypatch.setattr("rolo.targetd.landerpi_motion_target.subprocess.run", run)
    transport = TargetdDockerPinnedReadControlTransport(peer_capability=_consume_debug_peer(tmp_path))

    assert transport.read_isolation_topic_info_bundle() == outputs
    argv, kwargs = calls[0]
    assert argv[:10] == (
        "docker",
        "exec",
        "--user",
        "ubuntu",
        "-i",
        "MentorPi",
        "/bin/bash",
        "--noprofile",
        "--norc",
        "-c",
    )
    assert argv[10].startswith("set -e; export HOME=/home/ubuntu;")
    assert argv[10].endswith('set -u; exec "$@"')
    assert argv[11:14] == (
        "rolo-targetd-read-control",
        "/usr/bin/python3",
        "-c",
    )
    compile(argv[14], "<target-motion-helper>", "exec")
    assert argv[15:] == ("graph",)
    assert kwargs["shell"] is False
    assert kwargs["input"] == b""
    assert "registry_read_active()" in argv[14]
    assert "registry_auth_tag" in argv[14]
    assert ".registry.key" in argv[14]
    assert TARGET_KEY.decode("ascii") not in "\0".join(argv)
    assert transport.security_context().peer_provenance == "DEBUG_ONLY_FIXED_PEER"
    assert transport.security_context().production_peer_verified is False


def test_targetd_docker_transport_rejects_forged_security_and_peer_replay(tmp_path):
    forged = PinnedLanderPiRpcSecurity(
        target_id=TARGET_ID,
        target_identity=TARGET_IDENTITY,
        pinned_host_key_sha256=HOST_KEY,
        observed_host_key_sha256=HOST_KEY,
    )
    with pytest.raises(TypeError):
        TargetdDockerPinnedReadControlTransport(security=forged)  # type: ignore[call-arg]
    with pytest.raises(TypeError, match="factory-only"):
        PinnedTargetdPeerCapability(object(), _debug_peer_receipt())

    replay_store = DebugPinnedPeerBootstrapReplayStore((tmp_path / "replay").resolve())
    kwargs = {
        "verification_key": TargetSigningKey.from_bytes(BOOTSTRAP_KEY),
        "replay_store": replay_store,
        "expected_bootstrap_authority_id": "debug-bootstrap:runner",
        "expected_target_id": TARGET_ID,
        "expected_target_identity": TARGET_IDENTITY,
        "expected_call_id": "call-motion-1",
        "expected_session_id": "session-motion-1",
        "expected_execution_subject_digest": SHA_A,
        "expected_ssh_host": "landerpi",
        "expected_ssh_port": 22,
        "expected_pinned_host_key_sha256": HOST_KEY,
        "expected_client_public_key_sha256": CLIENT_KEY,
        "expected_known_hosts_sha256": KNOWN_HOSTS,
        "expected_channel_binding_sha256": CHANNEL_BINDING,
        "at": NOW,
    }
    receipt = _debug_peer_receipt()
    capability = consume_debug_pinned_targetd_peer_bootstrap(receipt, **kwargs)
    with pytest.raises(RuntimeError, match="REPLAYED"):
        consume_debug_pinned_targetd_peer_bootstrap(receipt, **kwargs)
    TargetdDockerPinnedReadControlTransport(peer_capability=capability)
    with pytest.raises(RuntimeError, match="ALREADY_CONSUMED"):
        TargetdDockerPinnedReadControlTransport(peer_capability=capability)


@pytest.mark.parametrize(
    ("update", "reason"),
    [
        ({"call_id": "call-other"}, "IDENTITY_MISMATCH"),
        ({"expires_at": NOW}, "EXPIRED"),
        ({"signature_hmac_sha256": "hmac-sha256:" + "f" * 64}, "SIGNATURE_INVALID"),
    ],
)
def test_debug_peer_bootstrap_rejects_wrong_identity_expiry_or_signature(tmp_path, update, reason):
    receipt = _debug_peer_receipt().model_copy(update=update) if "signature_hmac_sha256" in update else _debug_peer_receipt(**update)
    with pytest.raises(RuntimeError, match=reason):
        consume_debug_pinned_targetd_peer_bootstrap(
            receipt,
            verification_key=TargetSigningKey.from_bytes(BOOTSTRAP_KEY),
            replay_store=DebugPinnedPeerBootstrapReplayStore((tmp_path / reason).resolve()),
            expected_bootstrap_authority_id="debug-bootstrap:runner",
            expected_target_id=TARGET_ID,
            expected_target_identity=TARGET_IDENTITY,
            expected_call_id="call-motion-1",
            expected_session_id="session-motion-1",
            expected_execution_subject_digest=SHA_A,
            expected_ssh_host="landerpi",
            expected_ssh_port=22,
            expected_pinned_host_key_sha256=HOST_KEY,
            expected_client_public_key_sha256=CLIENT_KEY,
            expected_known_hosts_sha256=KNOWN_HOSTS,
            expected_channel_binding_sha256=CHANNEL_BINDING,
            at=NOW,
        )


def test_debug_peer_bootstrap_schema_preserves_nonproduction_boundary():
    schema_path = Path(__file__).parents[1] / "schemas" / "TargetdDebugPinnedPeerBootstrap.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    payload = _debug_peer_receipt().model_dump(mode="json")

    validator.validate(payload)
    assert payload["local_subprocess_shell_used"] is False
    assert payload["remote_login_shell_used"] is True
    assert "outer_shell_used" not in payload
    for field, forged_value in (
        ("local_subprocess_shell_used", True),
        ("remote_login_shell_used", False),
    ):
        forged_shell_semantics = dict(payload)
        forged_shell_semantics[field] = forged_value
        with pytest.raises(ValidationError):
            validator.validate(forged_shell_semantics)
    forged_production = dict(payload)
    forged_production["production_peer_verified"] = True
    with pytest.raises(ValidationError):
        validator.validate(forged_production)
    extra = dict(payload)
    extra["generic_command"] = "docker exec"
    with pytest.raises(ValidationError):
        validator.validate(extra)


@pytest.mark.parametrize(
    ("field", "forged_value"),
    [
        ("local_subprocess_shell_used", True),
        ("local_subprocess_shell_used", 0),
        ("remote_login_shell_used", False),
        ("remote_login_shell_used", 1),
        ("outer_shell_used", False),
    ],
)
def test_debug_peer_bootstrap_consumer_rejects_false_shell_semantics(tmp_path, field, forged_value):
    payload = _debug_peer_receipt().model_dump(mode="python")
    if field == "outer_shell_used":
        payload.pop("local_subprocess_shell_used")
        payload.pop("remote_login_shell_used")
    payload[field] = forged_value

    with pytest.raises(ValueError):
        consume_debug_pinned_targetd_peer_bootstrap(
            payload,
            verification_key=TargetSigningKey.from_bytes(BOOTSTRAP_KEY),
            replay_store=DebugPinnedPeerBootstrapReplayStore((tmp_path / field).resolve()),
            expected_bootstrap_authority_id="debug-bootstrap:runner",
            expected_target_id=TARGET_ID,
            expected_target_identity=TARGET_IDENTITY,
            expected_call_id="call-motion-1",
            expected_session_id="session-motion-1",
            expected_execution_subject_digest=SHA_A,
            expected_ssh_host="landerpi",
            expected_ssh_port=22,
            expected_pinned_host_key_sha256=HOST_KEY,
            expected_client_public_key_sha256=CLIENT_KEY,
            expected_known_hosts_sha256=KNOWN_HOSTS,
            expected_channel_binding_sha256=CHANNEL_BINDING,
            at=NOW,
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("provider_runtime_sha256", "sha256:" + "d" * 64),
        ("provider_cmdline_sha256", "sha256:" + "e" * 64),
    ],
)
def test_fresh_consume_rejects_runtime_or_cmdline_identity_bit_flip(tmp_path, field, value):
    target, rpc, store, policy, intent, artifacts = _full_sequence(tmp_path, consume=False)
    setattr(rpc, field, value)
    challenge = artifacts[-1]

    with pytest.raises(RuntimeError, match="ARMED_ZERO_PROVIDER_CHANGED"):
        target.compare_and_set_provider_gate(
            acceptance_id="acceptance-motion-1",
            intent=intent,
            policy=policy,
            challenge_artifact_digest=challenge.payload_sha256,
            consume_token_digest=challenge.claims["consume_token_digest"],
        )

    assert (store.load().phase, store.load().fence_epoch) == ("CHALLENGE_PENDING", 9)


def test_armed_binding_digest_covers_runtime_and_cmdline_hashes():
    digest = compute_armed_zero_provider_identity_digest(
        call_id="call-motion-1",
        session_id="session-motion-1",
        execution_subject_digest=SHA_A,
        publisher_identity=PUBLISHER,
        publisher_gid="10.00000001",
        provider_pid=4242,
        provider_start_time_ticks=123456,
        provider_runtime_sha256=RUNTIME_SHA,
        provider_cmdline_sha256=CMDLINE_SHA,
    )
    payload = {
        "call_id": "call-motion-1",
        "session_id": "session-motion-1",
        "execution_subject_digest": SHA_A,
        "publisher_identity": PUBLISHER,
        "publisher_gid": "10.00000001",
        "provider_pid": 4242,
        "provider_start_time_ticks": 123456,
        "provider_runtime_sha256": RUNTIME_SHA,
        "provider_cmdline_sha256": CMDLINE_SHA,
        "provider_runtime_identity_digest": digest,
    }
    ArmedZeroProviderBinding.model_validate(payload)
    for field in ("provider_runtime_sha256", "provider_cmdline_sha256"):
        changed = dict(payload)
        changed[field] = "sha256:" + "f" * 64
        with pytest.raises(ValueError, match="runtime identity digest mismatch"):
            ArmedZeroProviderBinding.model_validate(changed)


@pytest.mark.parametrize(
    ("field", "endpoints"),
    [
        ("command_publishers", [(PUBLISHER, "10.00000001"), (PUBLISHER, "10.00000009")]),
        ("competing_publishers", [("/hand_gesture", "20.00000009")]),
        ("motor_publishers", [(ODOM, "30.00000001"), (ODOM, "30.00000009")]),
    ],
)
def test_prearm_rejects_duplicate_or_competing_endpoint_before_state_change(tmp_path, field, endpoints):
    target, rpc, store, policy, intent = _target(tmp_path)
    rpc.arm()
    setattr(rpc, field, endpoints)

    with pytest.raises((RuntimeError, ValueError), match="ISOLATED|GID"):
        target.observe_isolation(
            acceptance_id="acceptance-motion-1",
            intent=intent,
            policy=policy,
            phase="PRE_CAS",
            fence_binding_digest=None,
        )

    assert (store.load().phase, store.load().state_revision) == ("SAFE_BASELINE", 0)


def test_duplicate_gid_across_routes_is_rejected_before_state_change(tmp_path):
    target, rpc, store, policy, intent = _target(tmp_path)
    rpc.arm()
    rpc.competing_publishers = [("/rogue", "10.00000001")]

    with pytest.raises(ValueError, match="duplicated endpoint GID"):
        target.observe_isolation(
            acceptance_id="acceptance-motion-1",
            intent=intent,
            policy=policy,
            phase="PRE_CAS",
            fence_binding_digest=None,
        )

    assert store.load().state_revision == 0


@pytest.mark.parametrize(
    "security",
    [
        {
            "target_id": TARGET_ID,
            "target_identity": TARGET_IDENTITY,
            "pinned_host_key_sha256": HOST_KEY,
            "observed_host_key_sha256": "sha256:" + "2" * 64,
        },
        {
            "target_id": TARGET_ID,
            "target_identity": TARGET_IDENTITY,
            "pinned_host_key_sha256": HOST_KEY,
            "observed_host_key_sha256": HOST_KEY,
            "password_used": True,
        },
    ],
)
def test_rpc_must_be_key_only_and_host_key_pinned_before_graph_reads(tmp_path, security):
    target, rpc, store, _, _ = _target(tmp_path)
    rpc.security = security

    with pytest.raises(RuntimeError, match="PINNED_KEY_ONLY_RPC_REQUIRED"):
        target.verify_initial_isolation()

    assert rpc.topic_calls == []
    assert store.load().state_revision == 0


def test_stale_or_nonzero_runtime_status_blocks_ack_and_preserves_lease(tmp_path):
    target, rpc, store, policy, intent = _target(tmp_path)
    rpc.arm()
    pre = target.observe_isolation(
        acceptance_id="acceptance-motion-1",
        intent=intent,
        policy=policy,
        phase="PRE_CAS",
        fence_binding_digest=None,
    )
    cas = target.compare_and_set_fence(
        acceptance_id="acceptance-motion-1",
        intent=intent,
        policy=policy,
        snapshot_artifact_digest=pre.payload_sha256,
    )
    rpc.status_override = rpc.zero_motion_status().model_copy(update={"observed_at": NOW - timedelta(seconds=2)})

    with pytest.raises(RuntimeError, match="STATUS_NOT_CURRENT"):
        target.acknowledge_zero_motion_start(
            acceptance_id="acceptance-motion-1",
            intent=intent,
            fence_cas_artifact_digest=cas.payload_sha256,
        )

    assert (store.load().phase, store.load().fence_epoch) == ("REHEARSAL_LEASE", 8)


def test_atomic_store_is_durable_and_allows_only_one_compare_and_set(tmp_path):
    intent = _intent()
    initial = LanderPiTargetMotionState.initial(intent, fence_epoch=7, now=NOW)
    root = tmp_path.resolve()
    first_store = AtomicLanderPiMotionStateStore(root)
    second_store = AtomicLanderPiMotionStateStore(root)
    first_store.provision(initial)

    def candidate(label: str):
        artifact = SignedZeroMotionArtifact.build(
            artifact_id=f"artifact-{label}",
            kind="ZERO_MOTION_ABORT_ACK",
            issuer_id=TARGET_AUTHORITY,
            acceptance_id="acceptance-motion-1",
            intent=intent,
            issued_at=NOW,
            expires_at=NOW + timedelta(seconds=5),
            claims={"candidate": label, "motion_enabled": False, "provider_invocation_count": 0},
            signing_key=TARGET_KEY,
        )
        replacement = initial.model_copy(
            update={
                "state_revision": 1,
                "last_artifact_digest": artifact.payload_sha256,
                "updated_at": NOW,
            }
        )
        return artifact, replacement

    first = candidate("first")
    second = candidate("second")
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(
            pool.map(
                lambda args: args[0].compare_and_set(expected=initial, replacement=args[2], artifact=args[1]),
                [(first_store, *first), (second_store, *second)],
            )
        )

    assert sorted(results) == [False, True]
    reopened = AtomicLanderPiMotionStateStore(root)
    winner = reopened.load()
    assert winner.state_revision == 1
    assert reopened.get_artifact(winner.last_artifact_digest) is not None


def test_signing_keys_accept_only_memory_file_or_fd_and_never_render_secret(tmp_path):
    key = b"secret-material-that-is-at-least-32-bytes"
    memory = TargetSigningKey.from_bytes(key)
    key_path = tmp_path / "target.key"
    key_path.write_bytes(key)
    if os.name != "nt":
        key_path.chmod(0o600)
    from_file = TargetSigningKey.from_file(key_path)
    descriptor = os.open(key_path, os.O_RDONLY)
    try:
        from_fd = TargetSigningKey.from_fd(descriptor)
        assert os.fstat(descriptor).st_size == len(key)
    finally:
        os.close(descriptor)

    assert repr(memory) == "TargetSigningKey(<redacted>)"
    assert key.decode() not in repr((memory, from_file, from_fd))
    assert set(inspect.signature(LanderPiZeroMotionTarget).parameters) == {
        "policy",
        "rpc",
        "store",
        "graph_signing_key",
        "target_signing_key",
        "clock",
        "artifact_ttl_s",
    }
    with pytest.raises(ValueError, match="safe bounds"):
        TargetSigningKey.from_bytes(b"x" * 4097)


def test_composition_uses_absolute_target_local_store_and_exposes_no_motion_api(tmp_path):
    target = compose_landerpi_zero_motion_target(
        policy=_policy(),
        rpc=_PinnedRpc(),
        state_root=tmp_path.resolve(),
        graph_signing_key=TargetSigningKey.from_bytes(GRAPH_KEY),
        target_signing_key=TargetSigningKey.from_bytes(TARGET_KEY),
        clock=lambda: NOW,
    )

    assert isinstance(target.store, AtomicLanderPiMotionStateStore)
    assert not any(hasattr(target, name) for name in ("publish", "velocity", "motor", "invoke_provider", "execute"))
    with pytest.raises(ValueError, match="absolute"):
        AtomicLanderPiMotionStateStore("relative-state")


def test_tampered_state_and_artifact_fail_closed(tmp_path):
    target, _, store, _, _, artifacts = _full_sequence(tmp_path)
    artifact = artifacts[0]
    artifact_path = store.artifact_root / (artifact.payload_sha256.removeprefix("sha256:") + ".json")
    payload = json.loads(artifact_path.read_text(encoding="utf-8"))
    payload["claims"]["motion_enabled"] = True
    artifact_path.write_text(json.dumps(payload), encoding="utf-8")
    assert store.get_artifact(artifact.payload_sha256) is None

    store.state_path.write_text("{}", encoding="utf-8")
    with pytest.raises(RuntimeError, match="STATE_INVALID"):
        store.load()
    assert target.store is store
