from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import os
import shutil
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from rolo.dsl.admission import mapping_digest
from rolo.mvp import (
    CatalogTool,
    DurableTraceRequestStore,
    TargetCatalog,
    ToolState,
)
from rolo.mvp.artifacts import ArtifactIndex
from rolo.mvp.contracts import SessionState, TraceCall, TraceSessionRequest
from rolo.mvp.trace_plan import TargetdTraceResponse
from rolo.releases import ReleaseBoundTrace, ToolRelease, tool_release_digest
from rolo.targetd.landerpi_motion_target import (
    DebugOnlyUserAttestedAdmission,
    DebugPinnedTargetdPeerBootstrapReceipt,
    DebugUserAttestedAcceptanceReceipt,
    FreshZeroMotionEvidence,
)
from rolo.targetd.lifecycle import WorkerCallKey, WorkerCompletion, WorkerLeaseStore
from rolo.targetd.motion_acceptance import (
    ProviderGateConsumptionReceipt,
    SignedZeroMotionArtifact,
    ZeroMotionAcceptanceReceipt,
    ZeroMotionArtifactDigests,
    compute_armed_zero_provider_identity_digest,
    compute_provider_fence_digest,
    compute_provider_gate_consume_token_digest,
)
from rolo.targetd.motion_safety import (
    MotionSafetyAdmissionRequest,
    MotionSafetyEvidenceBundle,
    MotionSafetyIntent,
    MotionSafetyPolicy,
    MotionSafetyTrustStore,
    compute_direct_motor_fence_digest,
    compute_motion_payload_digest,
    compute_ros_graph_digest,
    compute_stop_action_digest,
)
from rolo.targetd.physical_acceptance import DebugPhysicalAcceptanceStore
from rolo.targetd.physical_gate import PhysicalProviderGateReceiptStore
from rolo.targetd.physical_worker import (
    InnerProcessIdentity,
    PhysicalWorkerArmedZero,
    parse_physical_worker_armed_zero,
    validate_landerpi_rotate_process_call,
)
from rolo.targetd.protocol import (
    ExecutionBundleManifest,
    ExecutionRequestV3,
    FrameKind,
    ProtocolFrame,
    TargetdCallReceipt,
    TargetdExecutionAuthority,
    execution_subject_digest,
    provider_fence_digest,
)
from scripts.landerpi_n7_physical_trace import (
    _HOST_TARGETD_STAGE_SOURCE,
    _REMOTE_CONTROL_SOURCE,
    _ROS_CONTAINER_EXEC_WRAPPER,
    BASELINE_COMPETING_PUBLISHERS,
    BASELINE_DIRECT_MOTOR_PUBLISHERS,
    COMMAND_INTERFACE,
    COMMAND_ROUTE,
    COMPETING_COMMAND_ROUTE,
    CONTAINER,
    CONTROLLED_SUBSCRIBERS,
    DIRECT_MOTOR_ROUTE,
    DIRECT_MOTOR_SUBSCRIBERS,
    ISOLATED_DIRECT_MOTOR_PUBLISHERS,
    PUBLISHER_PROCESS_ALLOWLIST,
    SENSOR_HEALTH_ROUTES,
    AuthenticatedStopReceipt,
    ControlGraphSnapshot,
    FreshSensorHealthReceipt,
    HostTargetdBootstrapKeys,
    MotionSpec,
    N7PhysicalBlocked,
    N7PhysicalTraceInputs,
    N7PhysicalTraceRunner,
    PinnedHostTargetdStdioChannel,
    PinnedLanderPiSshChannel,
    PinnedSshConfiguration,
    PrearmedProviderReceipt,
    PreparedPhysicalTargetdTraceAdapter,
    PreparedPhysicalTraceBridge,
    PreparedPhysicalTraceDispatch,
    PublisherProcessIdentity,
    ReleaseBoundPhysicalTraceDriver,
    TargetdPhysicalProofVerifier,
    TraceAttempt,
    _digest,
    _RpcResult,
    build_host_targetd_bootstrap,
    build_host_targetd_finalize_payload,
    build_host_targetd_source_archive,
    create_sealed_live_composition_descriptor,
    execute_sealed_live_composition_once,
    load_sealed_live_composition_descriptor,
    main,
    run_read_only_live_preflight,
    stage_root_for,
    target_compatible_graph_revision,
    validate_host_targetd_bootstrap_payload,
    verify_host_targetd_finalize_receipt,
)

NOW = datetime(2026, 9, 9, 8, 0, tzinfo=timezone.utc)
SESSION_ID = "n7-physical-session"
CALL_ID = "n7-physical-call"
RUN_ID = "n7-physical-run"
SHA = "sha256:" + "a" * 64


def _ssh_public_key_line(*, key_byte: bytes = b"k", comment: str = "test") -> str:
    key_type = b"ssh-ed25519"
    key_material = key_byte * 32
    blob = (
        len(key_type).to_bytes(4, "big")
        + key_type
        + len(key_material).to_bytes(4, "big")
        + key_material
    )
    return f"ssh-ed25519 {base64.b64encode(blob).decode('ascii')} {comment}\n"


def _known_host_line(
    host: str = "192.168.10.167",
    *,
    port: int = 22,
    key_byte: bytes = b"h",
) -> str:
    public_key = _ssh_public_key_line(
        key_byte=key_byte,
        comment="host-key",
    ).split()
    endpoint = host if port == 22 else f"[{host}]:{port}"
    return f"{endpoint} {public_key[0]} {public_key[1]}\n"


def _descriptor_ssh_configuration(tmp_path: Path) -> PinnedSshConfiguration:
    known_hosts = tmp_path / "landerpi-known-hosts"
    identity = tmp_path / "landerpi-ed25519"
    public = _ssh_public_key_line(comment="n7-descriptor-controller")
    known_hosts.write_text(_known_host_line(), encoding="ascii")
    identity.write_text("test-only-private-key-placeholder\n", encoding="ascii")
    identity.with_suffix(".pub").write_text(public, encoding="ascii")
    return PinnedSshConfiguration(
        host="192.168.10.167",
        user="pi",
        known_hosts=known_hosts,
        identity_file=identity,
        public_key_deriver=lambda _path: public,
    )


def _host_controller_fixture(tmp_path: Path):
    from tests.test_targetd_protocol import (
        _execution_request,
        _execution_session,
        _execution_setup,
    )

    source = (
        b"def execute(arguments, provider):\n"
        b"    return provider.invoke('base.rotate', arguments)\n"
    )
    bundle_key = b"B" * 32
    manifest = ExecutionBundleManifest.build(
        tool_id="app.base.rotate",
        source=source,
        binding_digest="a" * 64,
        signer_key_id="n7-test-bundle",
        signing_key=bundle_key,
        observation_contract={
            "provider": "ros-container",
            "operation": "base.rotate",
            "command_endpoint": COMMAND_ROUTE,
            "feedback_endpoints": ["/odom_raw", "/odom"],
            "independent_feedback_endpoints": [
                "/imu",
                "/imu_corrected",
                "/ros_robot_controller/imu_raw",
            ],
            "interface_type": COMMAND_INTERFACE,
            "stop_strategy": "zero_velocity",
            "provider_runtime_sha256": "f" * 64,
        },
        limits={"max_duration_s": 60, "max_output_bytes": 65_536},
    )
    service, authority, confirmations, _ = _execution_setup(
        tmp_path / "host-execution",
        manifest,
        source,
        provider_id="ros-container",
        provider_operation="base.rotate",
        journey_session_id=SESSION_ID,
    )
    session = _execution_session(service, authority, SESSION_ID)
    point = datetime.now(timezone.utc)
    synthetic = _execution_request(
        authority,
        session,
        run_id=RUN_ID,
        idempotency_key=CALL_ID,
        arguments=MotionSpec().arguments(),
        deadline=point + timedelta(seconds=120),
        motion_now=point,
    )
    execution_digest = execution_subject_digest(synthetic)
    target_identity = authority.mapping_admission.target_identity_digest
    graph_digest = compute_ros_graph_digest(
        target_id=authority.target_id,
        target_identity=target_identity,
        observed_at=point,
        command_route=COMMAND_ROUTE,
        command_interface=COMMAND_INTERFACE,
        publisher_identities=["/rolo_bounded_twist"],
        direct_motor_route=DIRECT_MOTOR_ROUTE,
        direct_motor_interface="ros_robot_controller_msgs/msg/MotorsState",
        direct_motor_publisher_identities=["/odom_publisher"],
    )
    fence_digest = compute_direct_motor_fence_digest(
        execution_subject_digest=execution_digest,
        call_id=CALL_ID,
        session_id=SESSION_ID,
        target_id=authority.target_id,
        target_identity=target_identity,
        ros_graph_digest=graph_digest,
        command_route=COMMAND_ROUTE,
        publisher_identity="/rolo_bounded_twist",
        direct_motor_route=DIRECT_MOTOR_ROUTE,
        direct_motor_interface="ros_robot_controller_msgs/msg/MotorsState",
        direct_motor_publisher_identity="/odom_publisher",
        fence_epoch=authority.fence_epoch,
    )
    stop_digest = compute_stop_action_digest(
        execution_subject_digest=execution_digest,
        call_id=CALL_ID,
        session_id=SESSION_ID,
        target_id=authority.target_id,
        target_identity=target_identity,
        ros_graph_digest=graph_digest,
        command_route=COMMAND_ROUTE,
        publisher_identity="/rolo_bounded_twist",
        direct_motor_route=DIRECT_MOTOR_ROUTE,
        direct_motor_interface="ros_robot_controller_msgs/msg/MotorsState",
        direct_motor_publisher_identity="/odom_publisher",
        direct_motor_fence_digest=fence_digest,
    )
    intent = MotionSafetyIntent(
        call_id=CALL_ID,
        session_id=SESSION_ID,
        target_id=authority.target_id,
        target_identity=target_identity,
        operator_id="operator:n7-onsite",
        execution_subject_digest=execution_digest,
        requested_at=point,
        ros_graph_digest=graph_digest,
        command_route=COMMAND_ROUTE,
        command_interface=COMMAND_INTERFACE,
        publisher_identity="/rolo_bounded_twist",
        direct_motor_route=DIRECT_MOTOR_ROUTE,
        direct_motor_interface="ros_robot_controller_msgs/msg/MotorsState",
        direct_motor_publisher_identity="/odom_publisher",
        direct_motor_fence_digest=fence_digest,
        stop_action_digest=stop_digest,
    )
    request = ExecutionRequestV3.model_validate(
        {
            **synthetic.model_dump(
                mode="python",
                exclude={"motion_safety_admission"},
            ),
            "motion_safety_admission": MotionSafetyAdmissionRequest(
                intent=intent,
                evidence=MotionSafetyEvidenceBundle(),
            ),
        }
    )
    policy = MotionSafetyPolicy(
        target_id=request.target_id,
        target_identity=target_identity,
        site_id="site:n7-field",
        safe_zone_id="zone:n7-pad",
        command_route=COMMAND_ROUTE,
        command_interface=COMMAND_INTERFACE,
        allowed_publisher_identity="/rolo_bounded_twist",
        direct_motor_route=DIRECT_MOTOR_ROUTE,
        direct_motor_interface="ros_robot_controller_msgs/msg/MotorsState",
        allowed_direct_motor_publisher_identity="/odom_publisher",
        operator_authority_id="authority:n7-operator",
        presence_authority_id="authority:n7-presence",
        safety_authority_id="authority:n7-safety",
        graph_authority_id="authority:n7-graph",
        target_authority_id="authority:n7-target",
    )
    known_hosts = tmp_path / "known_hosts"
    identity = tmp_path / "id_ed25519"
    known_hosts.write_text(_known_host_line(), encoding="ascii")
    identity.write_text("test-private-placeholder\n", encoding="ascii")
    public = _ssh_public_key_line(comment="n7-controller")
    identity.with_suffix(".pub").write_text(public, encoding="ascii")
    config = PinnedSshConfiguration(
        host="192.168.10.167",
        user="pi",
        known_hosts=known_hosts,
        identity_file=identity,
        public_key_deriver=lambda _path: public,
    )
    archive = build_host_targetd_source_archive(Path(__file__).parents[1])
    channel = PinnedHostTargetdStdioChannel(
        config,
        run_id=RUN_ID,
        archive=archive,
    )
    channel._stage_receipt = {"status": "STAGED"}
    keys = HostTargetdBootstrapKeys.generate(
        bundle_verification=bundle_key,
    )
    receipt = confirmations.resolve(
        authority.mapping_confirmation_receipt_digest
    )
    return channel, request, manifest, source, policy, receipt, keys


def _processes() -> list[dict[str, object]]:
    return [
        {
            "node_id": node,
            "executable": executable,
            "launch_argv_prefix": ["/usr/bin/python3", executable],
            "pid": 2000 + index,
            "start_ticks": 90000 + index,
            "argv_sha256": "sha256:" + f"{index + 1:064x}",
        }
        for index, (node, executable) in enumerate(sorted(PUBLISHER_PROCESS_ALLOWLIST.items()))
    ]


def _snapshot(phase: str, *, isolated: bool, prearmed: bool = False) -> dict[str, object]:
    command_publishers = ["/rolo_bounded_twist"] if prearmed else []
    command_subscribers = list(CONTROLLED_SUBSCRIBERS)
    competing_publishers = [] if isolated else list(BASELINE_COMPETING_PUBLISHERS)
    competing_subscribers = list(CONTROLLED_SUBSCRIBERS)
    direct_motor_publishers = (
        list(ISOLATED_DIRECT_MOTOR_PUBLISHERS)
        if isolated
        else list(BASELINE_DIRECT_MOTOR_PUBLISHERS)
    )
    direct_motor_subscribers = list(DIRECT_MOTOR_SUBSCRIBERS)
    gid_counter = iter(f"{index:032x}" for index in range(1, 64))

    def gids(values: list[str]) -> list[str]:
        return [next(gid_counter) for _ in values]

    value: dict[str, object] = {
        "schema_version": "rolo-n7-control-graph/v1",
        "phase": phase,
        "observed_at": NOW.isoformat().replace("+00:00", "Z"),
        "command_route": COMMAND_ROUTE,
        "command_interface": COMMAND_INTERFACE,
        "command_publishers": command_publishers,
        "command_publisher_gids": gids(command_publishers),
        "command_subscribers": command_subscribers,
        "command_subscriber_gids": gids(command_subscribers),
        "competing_command_route": COMPETING_COMMAND_ROUTE,
        "competing_publishers": competing_publishers,
        "competing_publisher_gids": gids(competing_publishers),
        "competing_subscribers": competing_subscribers,
        "competing_subscriber_gids": gids(competing_subscribers),
        "direct_motor_route": DIRECT_MOTOR_ROUTE,
        "direct_motor_publishers": direct_motor_publishers,
        "direct_motor_publisher_gids": gids(direct_motor_publishers),
        "direct_motor_subscribers": direct_motor_subscribers,
        "direct_motor_subscriber_gids": gids(direct_motor_subscribers),
        "processes": [] if isolated else _processes(),
    }
    value["graph_revision"] = "sha256:" + hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return value


def _fixture_digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(
        json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    ).hexdigest()


def _sensor_health(
    *,
    phase: str,
    stage_root: str,
    graph_topology_digest: str,
    unhealthy_routes: set[str] | None = None,
) -> dict[str, object]:
    unhealthy_routes = unhealthy_routes or set()
    started = NOW
    ended = NOW + timedelta(seconds=3)
    topics: list[dict[str, object]] = []
    identities = {
        "/ros_robot_controller/imu_raw": "/ros_robot_controller",
        "/imu": "/imu_filter",
        "/odom_raw": "/odom_publisher",
        "/odom": "/ekf_filter_node",
    }
    for index, (route, interface) in enumerate(SENSOR_HEALTH_ROUTES.items(), start=1):
        unhealthy = route in unhealthy_routes
        topics.append(
            {
                "route": route,
                "interface": interface,
                "publisher_identities": [identities[route]],
                "publisher_gids": [f"{100 + index:032x}"],
                "sample_count": 0 if unhealthy else 10,
                "first_sample_at": None if unhealthy else (started + timedelta(seconds=0.1)).isoformat().replace("+00:00", "Z"),
                "last_sample_at": None if unhealthy else (ended - timedelta(seconds=0.1)).isoformat().replace("+00:00", "Z"),
                "sample_rate_hz": 0.0 if unhealthy else 3.2,
                "max_gap_s": None if unhealthy else 0.35,
                "last_sample_age_s": None if unhealthy else 0.1,
                "arrival_digest": "sha256:" + f"{200 + index:064x}",
            }
        )
    unsigned: dict[str, object] = {
        "schema_version": "rolo-n7-fresh-sensor-health/v1",
        "ok": True,
        "phase": phase,
        "stage_root": stage_root,
        "window_started_at": started.isoformat().replace("+00:00", "Z"),
        "window_ended_at": ended.isoformat().replace("+00:00", "Z"),
        "sample_window_s": 3.0,
        "graph_topology_digest": graph_topology_digest,
        "pre_sample_graph_revision": "sha256:" + "5" * 64,
        "post_sample_graph_revision": "sha256:" + "6" * 64,
        "topics": topics,
        "healthy": not unhealthy_routes,
    }
    return {**unsigned, "evidence_digest": _fixture_digest(unsigned)}


def _bringup_group(leader: int) -> dict[str, object]:
    member = {
        "pid": leader,
        "start_ticks": leader * 100,
        "argv_sha256": "sha256:" + f"{leader:064x}",
        "executable": "/usr/bin/python3",
        "pgid": leader,
        "sid": leader,
    }
    unsigned: dict[str, object] = {
        "leader_pid": leader,
        "pgid": leader,
        "sid": leader,
        "members": [member],
    }
    return {**unsigned, "group_digest": _fixture_digest(unsigned)}


def _fresh_zero_claims(*, ended_at: datetime) -> dict[str, object]:
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
        "imu_stream": "/imu",
        "imu_sample_count": 8,
        "imu_latest_sample_at": ended_at - timedelta(seconds=0.01),
        "imu_sample_rate_hz": 20.0,
        "imu_max_abs_angular_z_rad_s": 0.002,
        "imu_max_abs_z_bias_residual_rad_s": 0.001,
        "imu_samples_digest": "sha256:" + "5" * 64,
    }
    evidence = FreshZeroMotionEvidence(
        **unsigned,
        evidence_sha256=compute_motion_payload_digest(unsigned),
    )
    return {
        "last_command_is_zero": True,
        "motor_output_zero": True,
        "motors_stopped": True,
        "zero_velocity_verified": True,
        "fresh_zero_evidence_digest": evidence.evidence_sha256,
        "fresh_zero_evidence": evidence.model_dump(mode="json"),
    }


def _provider_gate_artifact() -> SignedZeroMotionArtifact:
    unsigned = {
        "schema_version": "rolo-targetd-zero-motion-artifact/v1",
        "artifact_id": "gate-challenge",
        "kind": "PROVIDER_GATE_CHALLENGE",
        "issuer_id": "target-authority",
        "acceptance_id": "acceptance-1",
        "call_id": CALL_ID,
        "session_id": SESSION_ID,
        "target_id": "mentorpi",
        "target_identity": "target-identity",
        "operator_id": "operator-1",
        "execution_subject_digest": SHA,
        "ros_graph_digest": "sha256:" + "b" * 64,
        "command_route": COMMAND_ROUTE,
        "command_interface": COMMAND_INTERFACE,
        "publisher_identity": "/rolo_bounded_twist",
        "direct_motor_route": DIRECT_MOTOR_ROUTE,
        "direct_motor_interface": "ros_robot_controller_msgs/msg/MotorsState",
        "direct_motor_publisher_identity": "/odom_publisher",
        "issued_at": NOW,
        "expires_at": NOW + timedelta(seconds=5),
        "claims": {
            "one_shot": True,
            "consumed": False,
            **_fresh_zero_claims(ended_at=NOW),
        },
    }
    return SignedZeroMotionArtifact.model_validate(
        {
            **unsigned,
            "payload_sha256": compute_motion_payload_digest(unsigned),
            "signature_hmac_sha256": "hmac-sha256:" + "c" * 64,
        }
    )


def _ready_receipt() -> ZeroMotionAcceptanceReceipt:
    gate = _provider_gate_artifact()
    return ZeroMotionAcceptanceReceipt(
        status="READY_FOR_PROVIDER_GATE",
        reasons=(),
        evaluated_at=NOW,
        acceptance_id="acceptance-1",
        call_id=CALL_ID,
        session_id=SESSION_ID,
        target_id="mentorpi",
        target_identity="target-identity",
        operator_id="operator-1",
        execution_subject_digest=SHA,
        ros_graph_digest="sha256:" + "b" * 64,
        command_route=COMMAND_ROUTE,
        command_interface=COMMAND_INTERFACE,
        publisher_identity="/rolo_bounded_twist",
        direct_motor_route=DIRECT_MOTOR_ROUTE,
        direct_motor_interface="ros_robot_controller_msgs/msg/MotorsState",
        direct_motor_publisher_identity="/odom_publisher",
        static_decision_digest="sha256:" + "d" * 64,
        static_evidence_digests=tuple(f"sha256:{index:064x}" for index in range(1, 8)),
        artifacts=ZeroMotionArtifactDigests(
            pre_isolation_snapshot="sha256:" + "1" * 64,
            fence_cas="sha256:" + "2" * 64,
            start_ack="sha256:" + "3" * 64,
            stop_ack="sha256:" + "4" * 64,
            post_stop_isolation_snapshot="sha256:" + "5" * 64,
            fence_release="sha256:" + "6" * 64,
            provider_gate_challenge=gate.payload_sha256,
        ),
        provider_gate=gate,
    )


def _armed_zero(request, manifest, *, gid: str = "d" * 32) -> PhysicalWorkerArmedZero:
    call_key = WorkerCallKey.from_request(request)
    runtime_sha256 = manifest.observation_contract["provider_runtime_sha256"]
    identity = InnerProcessIdentity(
        pid=4321,
        start_ticks=8765,
        cmdline_sha256="e" * 64,
    )
    provider_runtime_sha256 = "sha256:" + runtime_sha256
    provider_cmdline_sha256 = "sha256:" + identity.cmdline_sha256
    provider_identity_digest = compute_armed_zero_provider_identity_digest(
        call_id=request.idempotency_key,
        session_id=request.session_id,
        execution_subject_digest=request.execution_subject_digest,
        publisher_identity="/rolo_bounded_twist",
        publisher_gid=gid,
        provider_pid=identity.pid,
        provider_start_time_ticks=identity.start_ticks,
        provider_runtime_sha256=provider_runtime_sha256,
        provider_cmdline_sha256=provider_cmdline_sha256,
    )
    registry_issued_at = 1_789_000_000.0
    registry_expires_at = registry_issued_at + 4.0
    registry_binding = {
        "schema_version": "rolo-targetd-physical-worker-registry-binding/v1",
        "target_id": request.target_id,
        "call_key_digest": call_key.digest(),
        "call_id": request.idempotency_key,
        "session_id": request.session_id,
        "execution_subject_digest": request.execution_subject_digest,
        "publisher_identity": "/rolo_bounded_twist",
        "publisher_gid": gid,
        "provider_pid": identity.pid,
        "provider_start_time_ticks": identity.start_ticks,
        "provider_runtime_sha256": provider_runtime_sha256,
        "provider_cmdline_sha256": provider_cmdline_sha256,
        "issued_at_epoch_s": registry_issued_at,
        "expires_at_epoch_s": registry_expires_at,
    }
    registry_binding_digest = "sha256:" + hashlib.sha256(
        json.dumps(
            registry_binding,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    ).hexdigest()
    unsigned = {
        "schema_version": "rolo-targetd-physical-worker-arm-receipt/v1",
        "call_key_digest": call_key.digest(),
        "target_id": request.target_id,
        "call_id": request.idempotency_key,
        "session_id": request.session_id,
        "request_digest": request.request_digest(),
        "execution_subject_digest": request.execution_subject_digest,
        "runtime_sha256": runtime_sha256,
        "command_endpoint": COMMAND_ROUTE,
        "publisher_identity": "/rolo_bounded_twist",
        "publisher_endpoint_gids": [gid],
        "publisher_endpoint_count": 1,
        "competing_publisher_count": 0,
        "direct_motor_publisher_identities": ["/odom_publisher"],
        "zeros_published": 5,
        "independent_stationary_sources": [
            "/imu",
            "/imu_corrected",
            "/ros_robot_controller/imu_raw",
        ],
        "independent_stationary_sample_counts": {
            "/imu": 3,
            "/imu_corrected": 3,
            "/ros_robot_controller/imu_raw": 3,
        },
        "independent_stationary_last_sample_age_s": {
            "/imu": 0.01,
            "/imu_corrected": 0.01,
            "/ros_robot_controller/imu_raw": 0.01,
        },
        "independent_stationary_max_abs_rad_s": {
            "/imu": 0.0,
            "/imu_corrected": 0.0,
            "/ros_robot_controller/imu_raw": 0.0,
        },
        "independent_stationary_window_s": 0.2,
        "motion_command_emitted": False,
        "motion_enabled": False,
        "inner_process_identity": identity.as_dict(),
        "target_monotonic_s": 10.0,
        "provider_runtime_sha256": provider_runtime_sha256,
        "provider_cmdline_sha256": provider_cmdline_sha256,
        "provider_runtime_identity_digest": provider_identity_digest,
        "registry_issued_at_epoch_s": registry_issued_at,
        "registry_expires_at_epoch_s": registry_expires_at,
        "registry_binding_digest": registry_binding_digest,
    }
    raw = {
        **unsigned,
        "arm_receipt_digest": hashlib.sha256(
            json.dumps(
                unsigned,
                ensure_ascii=True,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("ascii")
        ).hexdigest(),
    }
    return parse_physical_worker_armed_zero(
        raw,
        expected_call_key_digest=call_key.digest(),
        expected_request_digest=request.request_digest(),
        expected_execution_subject_digest=request.execution_subject_digest,
        expected_runtime_sha256=runtime_sha256,
        expected_target_id=request.target_id,
        expected_call_id=request.idempotency_key,
        expected_session_id=request.session_id,
    )


def _debug_acceptance_bundle(tmp_path, request, armed, *, point):
    intent = request.motion_safety_admission.intent
    policy = MotionSafetyPolicy(
        target_id=intent.target_id,
        target_identity=intent.target_identity,
        site_id="site:n7-field",
        safe_zone_id="zone:n7-pad",
        command_route=intent.command_route,
        command_interface=intent.command_interface,
        allowed_publisher_identity=intent.publisher_identity,
        direct_motor_route=intent.direct_motor_route,
        direct_motor_interface=intent.direct_motor_interface,
        allowed_direct_motor_publisher_identity=(
            intent.direct_motor_publisher_identity
        ),
        operator_authority_id="authority:n7-operator",
        presence_authority_id="authority:n7-presence",
        safety_authority_id="authority:n7-safety",
        graph_authority_id="authority:n7-graph",
        target_authority_id="authority:n7-target",
    )
    admission = DebugOnlyUserAttestedAdmission.build(
        attestation_id="n7-user-attestation",
        acceptance_id="n7-debug-acceptance",
        intent=intent,
        policy=policy,
        basis_text="现场急停、人员、安全区已妥善安排，本轮不演练。",
        requested_rotation_degrees=1.0,
        requested_linear_meters=0.0,
        issued_at=point - timedelta(milliseconds=100),
        expires_at=min(request.deadline, point + timedelta(seconds=10)),
    )
    signing_key = b"n7-debug-target-signing-key-32b!"
    debug_claims = {
        "debug_only": True,
        "report_status": "PASS_WITH_USER_ATTESTED_SITE_SAFETY",
        "debug_admission_digest": admission.payload_sha256,
        "basis": admission.basis,
        "basis_digest": admission.basis_digest,
        "site_id": admission.site_id,
        "safe_zone_id": admission.safe_zone_id,
        "requested_rotation_degrees": 1.0,
        "requested_linear_meters": 0.0,
        "max_abs_rotation_degrees": 1.0,
        "max_abs_linear_meters": 0.03,
        "onsite_operator_asserted": True,
        "independent_estop_available_asserted": True,
        "safe_zone_clear_asserted": True,
        "production_authority_verified": False,
        "fresh_estop_challenge_verified": False,
        "production_ready": False,
        "one_shot": True,
        "motion_enabled": False,
        "provider_invocation_count": 0,
    }
    debug_artifact = SignedZeroMotionArtifact.build(
        artifact_id="n7-debug-attestation-artifact",
        kind="DEBUG_USER_ATTESTED_ADMISSION",
        issuer_id="authority:n7-target",
        acceptance_id=admission.acceptance_id,
        intent=intent,
        issued_at=point,
        expires_at=point + timedelta(seconds=9),
        claims=debug_claims,
        signing_key=signing_key,
    )
    debug_binding = {
        "debug_admission_digest": admission.payload_sha256,
        "debug_attestation_artifact_digest": debug_artifact.payload_sha256,
        "basis_digest": admission.basis_digest,
        "requested_rotation_degrees": 1.0,
        "requested_linear_meters": 0.0,
        "max_abs_rotation_degrees": 1.0,
        "max_abs_linear_meters": 0.03,
        "production_authority_verified": False,
        "fresh_estop_challenge_verified": False,
        "production_ready": False,
        "report_status": "PASS_WITH_USER_ATTESTED_SITE_SAFETY",
    }
    challenge = SignedZeroMotionArtifact.build(
        artifact_id="n7-debug-provider-challenge",
        kind="PROVIDER_GATE_CHALLENGE",
        issuer_id="authority:n7-target",
        acceptance_id=admission.acceptance_id,
        intent=intent,
        issued_at=point + timedelta(milliseconds=10),
        expires_at=point + timedelta(seconds=9),
        claims={
            "one_shot": True,
            "consumed": False,
            "armed_zero_provider_binding": armed.provider_binding().model_dump(
                mode="json"
            ),
            "debug_gate_binding": debug_binding,
            "motion_enabled": False,
            "provider_invocation_count": 0,
            **_fresh_zero_claims(ended_at=point),
        },
        signing_key=signing_key,
    )
    receipt = DebugUserAttestedAcceptanceReceipt(
        status="DEBUG_ACCEPTED",
        report_status="PASS_WITH_USER_ATTESTED_SITE_SAFETY",
        reasons=(),
        evaluated_at=point + timedelta(milliseconds=20),
        acceptance_id=admission.acceptance_id,
        call_id=admission.call_id,
        session_id=admission.session_id,
        target_id=admission.target_id,
        target_identity=admission.target_identity,
        operator_id=admission.operator_id,
        execution_subject_digest=admission.execution_subject_digest,
        debug_admission_digest=admission.payload_sha256,
        debug_attestation_artifact=debug_artifact,
        artifacts=ZeroMotionArtifactDigests(
            pre_isolation_snapshot="sha256:" + "1" * 64,
            fence_cas="sha256:" + "2" * 64,
            start_ack="sha256:" + "3" * 64,
            stop_ack="sha256:" + "4" * 64,
            post_stop_isolation_snapshot="sha256:" + "5" * 64,
            fence_release="sha256:" + "6" * 64,
            provider_gate_challenge=challenge.payload_sha256,
        ),
        provider_gate=challenge,
        debug_gate_ready=True,
    )
    reference = DebugPhysicalAcceptanceStore(tmp_path / "debug-acceptances").persist(
        WorkerCallKey.from_request(request),
        receipt,
        armed_zero=armed,
        debug_admission=admission,
        now=point + timedelta(milliseconds=30),
    )
    start = {
        "schema_version": "rolo-targetd-debug-zero-motion-acceptance-reference/v1",
        "authority_class": "DEBUG_ONLY_USER_ATTESTED",
        "production_authority": False,
        "target_id": request.target_id,
        "session_id": request.session_id,
        "call_id": request.idempotency_key,
        "request_digest": request.request_digest(),
        "armed_zero_receipt_digest": armed.arm_receipt_digest,
        "debug_admission_digest": admission.payload_sha256,
        "acceptance_uri": reference.uri,
        "acceptance_digest_uri": reference.digest_uri,
        "acceptance_sidecar_digest": reference.sidecar.sidecar_digest,
    }
    lifecycle = _lifecycle_receipt(request, "ACCEPTED").model_copy(
        update={"artifact_refs": [reference.uri, reference.digest_uri]}
    )
    frame = ProtocolFrame.create(
        kind=FrameKind.RESULT,
        sequence=1,
        session_id=request.session_id,
        payload={
            "request_kind": FrameKind.ACCEPT_DEBUG_ZERO_MOTION.value,
            "ok": True,
            "receipt": lifecycle.model_dump(mode="json"),
            "accepted": True,
            "start_eligible": True,
            "acceptance_receipt": receipt.model_dump(mode="json"),
            "debug_acceptance": {
                "uri": reference.uri,
                "digest_uri": reference.digest_uri,
                "sidecar": reference.sidecar.model_dump(mode="json"),
            },
            "provider_gate_start": start,
            "provider_invocation_count": 0,
        },
    )
    return admission, receipt, frame, start


def _with_landerpi_motion_endpoints(request):
    """Bind a synthetic targetd request to the real sealed LanderPi routes."""

    intent = request.motion_safety_admission.intent.model_copy(
        update={
            "command_route": "/cmd_vel",
            "publisher_identity": "/rolo_bounded_twist",
            "direct_motor_route": "/ros_robot_controller/set_motor",
            "direct_motor_interface": (
                "ros_robot_controller_msgs/msg/MotorsState"
            ),
            "direct_motor_publisher_identity": "/odom_publisher",
        }
    )
    return request.model_copy(
        update={
            "motion_safety_admission": request.motion_safety_admission.model_copy(
                update={"intent": intent}
            )
        }
    )


def _lifecycle_receipt(request, status: str) -> TargetdCallReceipt:
    terminal = status in {"SUCCEEDED", "FAILED", "STOPPED", "CANCELLED", "UNKNOWN"}
    return TargetdCallReceipt(
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
        provider_id=request.provider_id,
        provider_operation=request.provider_operation,
        provider_fence_digest=provider_fence_digest(request),
        status=status,
        result={"status": status} if terminal else None,
        evidence_refs=(
            ["artifact://physical/gate.json", "artifact-digest://physical/gate.sha256"]
            if status != "ACCEPTED"
            else []
        ),
        provider_started_at=(
            datetime.now(timezone.utc) if status != "ACCEPTED" else None
        ),
        updated_at=datetime.now(timezone.utc),
    )


def _lifecycle_frame(request, kind: FrameKind, status: str, **payload) -> ProtocolFrame:
    return ProtocolFrame.create(
        kind=FrameKind.RESULT,
        sequence=1,
        session_id=request.session_id,
        run_id=request.run_id if kind == FrameKind.PREPARE_PHYSICAL_CALL else None,
        payload={
            "request_kind": kind.value,
            "ok": True,
            "receipt": _lifecycle_receipt(request, status).model_dump(mode="json"),
            **payload,
        },
    )


class _SealedGatePayloadFactory:
    sealed_physical_gate_payload_factory = True

    def __call__(self, receipt, armed_zero):
        return {
            "schema_version": "rolo-test-sealed-physical-gate/v1",
            "call_id": receipt.call_id,
            "armed_zero_receipt_digest": armed_zero.arm_receipt_digest,
        }


class _PreparedLifecycleClient:
    def __init__(
        self,
        request,
        armed,
        *,
        lose_start_response: bool = False,
        debug_acceptance_frame=None,
    ):
        self.request = request
        self.armed = armed
        self.lose_start_response = lose_start_response
        self.debug_acceptance_frame = debug_acceptance_frame
        self.kinds: list[str] = []
        self.provider_gates: list[dict[str, object]] = []

    def prepare_physical_call_remote(self, request):
        assert request == self.request
        self.kinds.append("PREPARE_PHYSICAL_CALL")
        return _lifecycle_frame(
            request,
            FrameKind.PREPARE_PHYSICAL_CALL,
            "ACCEPTED",
            prepared=True,
            armed_zero=self.armed.as_dict(),
            provider_invocation_count=0,
        )

    def accept_debug_zero_motion_remote(self, **kwargs):
        assert kwargs["call_id"] == self.request.idempotency_key
        assert kwargs["request_digest"] == self.request.request_digest()
        assert kwargs["armed_zero_receipt_digest"] == self.armed.arm_receipt_digest
        assert kwargs["debug_admission"].call_id == self.request.idempotency_key
        assert self.debug_acceptance_frame is not None
        self.kinds.append("ACCEPT_DEBUG_ZERO_MOTION")
        return self.debug_acceptance_frame

    def start_prepared_physical_call_remote(self, **kwargs):
        assert kwargs["call_id"] == self.request.idempotency_key
        assert kwargs["request_digest"] == self.request.request_digest()
        assert kwargs["armed_zero_receipt_digest"] == self.armed.arm_receipt_digest
        assert kwargs["provider_gate"]["call_id"] == self.request.idempotency_key
        self.provider_gates.append(dict(kwargs["provider_gate"]))
        self.kinds.append("START_PREPARED_CALL")
        if self.lose_start_response:
            raise TimeoutError("response lost after complete START_PREPARED delivery")
        return _lifecycle_frame(
            self.request,
            FrameKind.START_PREPARED_CALL,
            "STARTED",
            call_started=True,
            process_id="physical-process-1",
            provider_invocation_count=1,
        )

    def query_physical_gate_remote(
        self,
        call_id,
        request_digest,
        *,
        gate_uri=None,
        gate_digest_uri=None,
    ):
        assert (call_id, request_digest) == (
            self.request.idempotency_key,
            self.request.request_digest(),
        )
        assert gate_uri is None and gate_digest_uri is None
        self.kinds.append("QUERY_CALL_PHYSICAL")
        return _lifecycle_frame(
            self.request,
            FrameKind.QUERY_CALL,
            "SUCCEEDED",
            physical_provider_gate={"typed": True},
        )


def _physical_release_fixture(tmp_path, mapping_confirmation_factory, manifest):
    fingerprint = "a" * 64
    evidence_digest = "sha256:" + "e" * 64
    source_digest = "sha256:" + hashlib.sha256(b"physical-test").hexdigest()
    dsl = {
        "tool_id": "app.base.rotate",
        "kind": "EXECUTE",
        "target": {"robot_id": "mentorpi", "evidence_digest": evidence_digest},
        "implementation": {
            "source_bundle_digest": source_digest,
            "entrypoint": "main:run",
            "runtime": "python3.11",
            "implementation_contract": "v1",
        },
    }
    context = {
        "robot_id": "mentorpi",
        "target_fingerprint": fingerprint,
        "evidence_digest": evidence_digest,
    }
    confirmed = mapping_confirmation_factory(
        dsl,
        context,
        journey_session_id="physical-worker-session",
        operations=("base.rotate",),
        access="experimental_write",
        risk="R3",
    )
    identity = confirmed.receipt.admission_identity()
    release = ToolRelease(
        tool_id=identity.scope.tool_id,
        target_id=identity.target_id,
        operation_kind="EXECUTE",
        dsl_digest=identity.dsl_digest,
        ir_digest=mapping_digest({"kind": "physical-ir"}),
        probe_evidence_digest=identity.evidence_digest,
        compiler_version="test-compiler/v1",
        generated_bundle_digest="sha256:" + manifest.bundle_digest,
        conformance_digest=mapping_digest({"kind": "physical-conformance"}),
        target_fingerprint=identity.target_fingerprint,
        compile_context_digest=identity.context_digest,
        target_conformance_digest=mapping_digest(
            {"kind": "physical-target-conformance"}
        ),
        mapping_confirmation_receipt_digest=confirmed.receipt.receipt_digest,
        mapping_admission=identity,
    )
    release_digest = tool_release_digest(release)

    class Publisher:
        root = tmp_path / "physical-catalog"
        confirmation_store = confirmed.store

        @staticmethod
        def current(tool_id):
            return (release_digest, release) if tool_id == release.tool_id else None

    catalog = TargetCatalog(
        target_id="mentorpi",
        target_fingerprint=fingerprint,
        snapshot_digest="2" * 64,
        generated_at=datetime.now(timezone.utc),
        freshness="fresh",
        tools=[
            CatalogTool(
                tool_id="app.base.rotate",
                target_id="mentorpi",
                state=ToolState.CALLABLE,
                agent_callable=True,
                access="experimental_write",
                experimental_write=True,
                parameters={
                    "angle_degrees": {"required": True},
                    "max_speed_rad_s": {"required": True},
                },
                timeout_s=30,
            )
        ],
    ).with_digest()
    return Publisher(), catalog, release_digest, identity, evidence_digest


def _typed_proof_fixture(tmp_path: Path):
    from tests.test_targetd_physical_worker import _call

    request, manifest = _call(tmp_path / "request")
    call_key = WorkerCallKey.from_request(request)
    armed = _armed_zero(request, manifest)
    armed_binding = armed.provider_binding().model_dump(mode="json")
    point = datetime.now(timezone.utc)
    intent = request.motion_safety_admission.intent
    key = b"g" * 32
    acceptance_id = "n7-typed-acceptance"
    release_digest = "sha256:" + "1" * 64
    post_digest = "sha256:" + "2" * 64
    expected_fence = "sha256:" + "3" * 64
    graph_revision = "sha256:" + "4" * 64
    expected_epoch = 7
    challenge_expires = point + timedelta(seconds=20)
    consume_token = compute_provider_gate_consume_token_digest(
        acceptance_id=acceptance_id,
        intent=intent,
        release_artifact_digest=release_digest,
        post_snapshot_artifact_digest=post_digest,
        expected_fence_digest=expected_fence,
        expected_fence_epoch=expected_epoch,
        expected_graph_revision=graph_revision,
        expires_at=challenge_expires,
    )
    challenge = SignedZeroMotionArtifact.build(
        artifact_id="n7-typed-challenge",
        kind="PROVIDER_GATE_CHALLENGE",
        issuer_id="targetd:n7-authority",
        acceptance_id=acceptance_id,
        intent=intent,
        issued_at=point,
        expires_at=challenge_expires,
        claims={
            "one_shot": True,
            "consumed": False,
            "release_artifact_digest": release_digest,
            "post_snapshot_artifact_digest": post_digest,
            "expected_fence_digest": expected_fence,
            "expected_fence_epoch": expected_epoch,
            "expected_graph_revision": graph_revision,
            "consume_token_digest": consume_token,
            "motion_enabled": False,
            "provider_invocation_count": 0,
            "armed_zero_provider_binding": armed_binding,
            **_fresh_zero_claims(ended_at=point),
        },
        signing_key=key,
    )
    acceptance = ZeroMotionAcceptanceReceipt(
        status="READY_FOR_PROVIDER_GATE",
        reasons=(),
        evaluated_at=point,
        acceptance_id=acceptance_id,
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
        static_decision_digest="sha256:" + "5" * 64,
        static_evidence_digests=tuple(
            f"sha256:{index:064x}" for index in range(10, 17)
        ),
        artifacts=ZeroMotionArtifactDigests(
            pre_isolation_snapshot="sha256:" + "6" * 64,
            fence_cas="sha256:" + "7" * 64,
            start_ack="sha256:" + "8" * 64,
            stop_ack="sha256:" + "9" * 64,
            post_stop_isolation_snapshot="sha256:" + "a" * 64,
            fence_release="sha256:" + "b" * 64,
            provider_gate_challenge=challenge.payload_sha256,
        ),
        provider_gate=challenge,
    )
    live_isolation_digest = "sha256:" + "c" * 64
    provider_epoch = expected_epoch + 1
    fresh_provider_fence = compute_provider_fence_digest(
        acceptance_id=acceptance_id,
        intent=intent,
        challenge_artifact_digest=challenge.payload_sha256,
        consume_token_digest=consume_token,
        live_isolation_digest=live_isolation_digest,
        graph_revision=graph_revision,
        expected_fence_digest=expected_fence,
        fence_epoch=provider_epoch,
    )
    consumed_artifact = SignedZeroMotionArtifact.build(
        artifact_id="n7-typed-consume",
        kind="PROVIDER_GATE_CONSUMED",
        issuer_id="targetd:n7-authority",
        acceptance_id=acceptance_id,
        intent=intent,
        issued_at=point + timedelta(milliseconds=100),
        expires_at=point + timedelta(seconds=20),
        claims={
            "consumed": True,
            "one_shot": True,
            "challenge_artifact_digest": challenge.payload_sha256,
            "consume_token_digest": consume_token,
            "expected_fence_digest": expected_fence,
            "expected_fence_epoch": expected_epoch,
            "expected_graph_revision": graph_revision,
            "observed_fence_digest": expected_fence,
            "observed_fence_epoch": expected_epoch,
            "observed_graph_revision": graph_revision,
            "live_isolation_digest": live_isolation_digest,
            "graph_compare_and_set": True,
            "fence_compare_and_set": True,
            "provider_fence_digest": fresh_provider_fence,
            "provider_fence_epoch": provider_epoch,
            "motion_enabled": False,
            "provider_invocation_count": 0,
            "armed_zero_provider_binding": armed_binding,
            **_fresh_zero_claims(ended_at=point + timedelta(milliseconds=100)),
        },
        signing_key=key,
    )
    consumed = ProviderGateConsumptionReceipt(
        status="CONSUMED",
        reasons=(),
        evaluated_at=point + timedelta(milliseconds=100),
        acceptance_id=acceptance_id,
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
        challenge_artifact_digest=challenge.payload_sha256,
        provider_fence_digest=fresh_provider_fence,
        consume_artifact=consumed_artifact,
        provider_boundary_open=True,
    )
    gate_store = PhysicalProviderGateReceiptStore(tmp_path / "gate-store")
    reference = gate_store.persist(
        call_key,
        consumed,
        armed_zero=armed,
        now=point + timedelta(milliseconds=200),
    )
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
        provider_id=request.provider_id,
        provider_operation=request.provider_operation,
        provider_fence_digest=provider_fence_digest(request),
        status="STARTED",
        evidence_refs=[reference.uri, reference.digest_uri],
        provider_started_at=point + timedelta(milliseconds=200),
        updated_at=point + timedelta(milliseconds=200),
    )

    def gate_query(call_id, request_digest, gate_uri, gate_digest_uri):
        assert call_id == request.idempotency_key
        assert request_digest == request.request_digest()
        assert gate_uri == reference.uri
        assert gate_digest_uri == reference.digest_uri
        frame = ProtocolFrame.create(
            kind=FrameKind.RESULT,
            sequence=4,
            session_id=request.session_id,
            payload={
                "request_kind": "QUERY_CALL",
                "ok": True,
                "receipt": receipt.model_dump(mode="json"),
                "physical_provider_gate": {
                    "uri": reference.uri,
                    "digest_uri": reference.digest_uri,
                    "sidecar": reference.sidecar.model_dump(mode="json"),
                },
            },
        )
        return TargetdTraceResponse(frame=frame, sequence_correlated=True)

    verifier = TargetdPhysicalProofVerifier(
        request,
        manifest=manifest,
        manifest_verification_key=b"secret",
        trust_store=MotionSafetyTrustStore({"targetd:n7-authority": key}),
        target_authority_id="targetd:n7-authority",
        query_physical_remote=gate_query,
        load_lease=lambda _call_key: None,
        stop_remote=lambda _call_id, _digest: pytest.fail("STOP not expected"),
    )
    return verifier, request, manifest, acceptance, reference, receipt, armed


def _already_terminal_stop_fixture(
    tmp_path: Path,
    *,
    omit_inner_process_gone: bool = False,
):
    base, request, manifest, _, _, started_receipt, armed = _typed_proof_fixture(
        tmp_path
    )
    call_key = WorkerCallKey.from_request(request)
    store = WorkerLeaseStore(tmp_path / "terminal-worker-leases")
    point = datetime.now(timezone.utc)
    claim = store.claim(
        call_key,
        supervisor_id="n7-supervisor",
        worker_id="n7-worker",
        lease_ttl_s=15.0,
        deadline_at=request.deadline,
        physical_execution_subject_digest=request.execution_subject_digest,
        physical_runtime_sha256=manifest.observation_contract[
            "provider_runtime_sha256"
        ],
        now=point,
    )
    store.start(claim, now=point + timedelta(milliseconds=1))
    store.record_armed_zero(
        claim,
        armed_zero=armed.as_dict(),
        now=point + timedelta(milliseconds=2),
    )
    stop_acknowledgement = {
        "kind": "PREMOTION_BLOCK_FINAL_ZERO",
        "call_key_digest": call_key.digest(),
        "inner_process_gone": True,
        "verified": True,
    }
    if omit_inner_process_gone:
        stop_acknowledgement.pop("inner_process_gone")
    result = {
        "status": "FAILED",
        "target_status": "FAILED",
        "motion_started": False,
        "motion_command_emitted": False,
        "request_digest": request.request_digest(),
        "execution_subject_digest": request.execution_subject_digest,
        "worker_call_key_digest": call_key.digest(),
        "armed_zero_receipt_digest": armed.arm_receipt_digest,
        "runtime_sha256": manifest.observation_contract[
            "provider_runtime_sha256"
        ],
        "provider_runtime_sha256": armed.provider_runtime_sha256,
        "provider_cmdline_sha256": armed.provider_cmdline_sha256,
        "provider_runtime_identity_digest": (
            armed.provider_runtime_identity_digest
        ),
        "provider_process_identity": armed.inner_process_identity.as_dict(),
        "provider_invocation_count": 1,
        "final_zero_verified": True,
        "stop_acknowledged": True,
        "stop_published": True,
        "physical_stop_verified": True,
        "stopped_observed": True,
        "control_graph_isolated": True,
        "independent_motion_evidence": {
            "independent_of_odom": True,
            "settled": True,
        },
        "stop_acknowledgement": stop_acknowledgement,
    }
    completion = WorkerCompletion(
        "FAILED",
        "ROTATE_BLOCKED_BEFORE_MOTION",
    )
    prepared = store.prepare_result(
        claim,
        completion=completion,
        result=result,
        now=point + timedelta(milliseconds=3),
    )
    store.complete(
        claim,
        status="FAILED",
        outcome_code=completion.outcome_code,
        now=point + timedelta(milliseconds=4),
    )
    assert prepared.prepared_result_digest is not None
    store.commit_prepared_result(
        call_key,
        result_digest=prepared.prepared_result_digest,
        now=point + timedelta(milliseconds=5),
    )
    terminal_receipt = TargetdCallReceipt.model_validate(
        {
            **started_receipt.model_dump(mode="python"),
            "status": "FAILED",
            "result": result,
            "updated_at": point + timedelta(milliseconds=5),
        }
    )
    stop_frame = ProtocolFrame.create(
        kind=FrameKind.RESULT,
        sequence=8,
        session_id=request.session_id,
        payload={
            "request_kind": FrameKind.STOP.value,
            "ok": True,
            "receipt": terminal_receipt.model_dump(mode="json"),
            "interrupt": {
                "intent": "STOP",
                "status": "ALREADY_TERMINAL",
                "requested": False,
                "acknowledged": True,
                "lease_state": "FAILED",
            },
        },
    )

    def stop_remote(call_id, request_digest):
        assert call_id == request.idempotency_key
        assert request_digest == request.request_digest()
        return TargetdTraceResponse(frame=stop_frame, sequence_correlated=True)

    verifier = TargetdPhysicalProofVerifier(
        request,
        manifest=manifest,
        manifest_verification_key=b"secret",
        trust_store=base.trust_store,
        target_authority_id=base.target_authority_id,
        query_physical_remote=lambda *_args: pytest.fail("QUERY not expected"),
        load_lease=store.load,
        stop_remote=stop_remote,
    )
    return verifier, request


class _Acceptance:
    def __init__(self, receipt=None) -> None:
        self.receipt = receipt or _ready_receipt()
        self.calls = 0

    def run(self):
        self.calls += 1
        return self.receipt


class _Channel:
    channel_id = "fake-key-only-channel"

    def __init__(
        self,
        *,
        unsafe_baseline: bool = False,
        restore_failure: bool = False,
        baseline_health_failures: int = 0,
        prearm_health_failure: bool = False,
    ) -> None:
        self.events: list[str] = []
        self.isolated = False
        self.unsafe_baseline = unsafe_baseline
        self.restore_failure = restore_failure
        self.stage_root: str | None = None
        self.baseline_health_failures = baseline_health_failures
        self.prearm_health_failure = prearm_health_failure
        self.restart_count = 0

    def stage(self, *, run_id, stage_root):
        self.events.append("STAGE")
        self.stage_root = stage_root
        return {
            "schema_version": "rolo-n7-stage-receipt/v1",
            "ok": True,
            "run_id": run_id,
            "container": CONTAINER,
            "stage_root": stage_root,
            "stage_nonce_digest": "sha256:" + "e" * 64,
        }

    def snapshot(self, *, stage_root, phase):
        assert stage_root == self.stage_root
        self.events.append(f"SNAPSHOT:{phase}")
        snapshot = _snapshot(
            phase,
            isolated=self.isolated,
            prearmed=phase == "PREARMED",
        )
        if self.unsafe_baseline and phase == "BASELINE":
            snapshot["command_publishers"] = ["/unexpected"]
            snapshot["command_publisher_gids"] = ["f" * 32]
        return snapshot

    def isolate(self, *, stage_root, expected_processes):
        assert stage_root == self.stage_root
        self.events.append("ISOLATE")
        assert tuple(item.as_dict() for item in expected_processes) == tuple(_processes())
        self.isolated = True
        return {
            "schema_version": "rolo-n7-isolation-receipt/v1",
            "ok": True,
            "stage_root": stage_root,
            "terminated_processes": _processes(),
            "snapshot": _snapshot("ISOLATED", isolated=True),
        }

    def sample_health(self, *, stage_root, phase, graph_topology_digest):
        assert stage_root == self.stage_root
        self.events.append(f"SAMPLE_HEALTH:{phase}")
        unhealthy: set[str] = set()
        if phase == "BASELINE" and self.baseline_health_failures:
            self.baseline_health_failures -= 1
            unhealthy.add("/imu")
        if phase == "PREARMED" and self.prearm_health_failure:
            unhealthy.add("/odom")
        return _sensor_health(
            phase=phase,
            stage_root=stage_root,
            graph_topology_digest=graph_topology_digest,
            unhealthy_routes=unhealthy,
        )

    def restart_bringup_once(self, *, stage_root, expected_processes):
        assert stage_root == self.stage_root
        assert tuple(item.as_dict() for item in expected_processes) == tuple(_processes())
        self.restart_count += 1
        self.events.append("PREFLIGHT_RESTART")
        return {
            "schema_version": "rolo-n7-bringup-preflight-restart/v1",
            "ok": True,
            "stage_root": stage_root,
            "restart_count": self.restart_count,
            "stop_signal": "SIGINT_THEN_SIGTERM",
            "previous_group": _bringup_group(621),
            "replacement_group": _bringup_group(721),
            "snapshot": _snapshot("BASELINE", isolated=False),
        }

    def restore(self, *, stage_root):
        assert stage_root == self.stage_root
        self.events.append("RESTORE")
        if self.restore_failure:
            raise RuntimeError("injected")
        self.isolated = False
        return {
            "schema_version": "rolo-n7-bringup-restore/v1",
            "ok": True,
            "stage_root": stage_root,
            "stop_signal": "SIGINT",
            "previous_group": _bringup_group(721),
            "replacement_group": _bringup_group(821),
            "snapshot": _snapshot("RESTORED", isolated=False),
        }

    def cleanup(self, *, stage_root):
        assert stage_root == self.stage_root
        self.events.append("CLEANUP")
        return {
            "schema_version": "rolo-n7-stage-cleanup/v1",
            "ok": True,
            "stage_root": stage_root,
            "residual_count": 0,
        }


class _HostFinalizingChannel(_Channel):
    def __init__(self, *, finalize_failure: bool = False) -> None:
        super().__init__()
        self.finalize_failure = finalize_failure

    def finalize_before_restore(
        self,
        *,
        stage_root,
        inputs,
        attempt,
        authenticated_stop,
        post_snapshot,
    ):
        assert stage_root == self.stage_root
        assert self.isolated is True
        assert attempt is not None and attempt.status == "SUCCEEDED"
        assert authenticated_stop is None
        post_snapshot.require_isolated()
        self.events.append("HOST_FINALIZE")
        if self.finalize_failure:
            raise N7PhysicalBlocked(
                "N7_PHYSICAL_HOST_FINALIZE_RECEIPT_INVALID",
                "injected host finalize failure",
            )
        return {
            "schema_version": "rolo-n7-targetd-host-finalize-receipt/v1",
            "status": "SAFE_TO_CLEANUP",
            "run_id": inputs.run_id,
            "stage_root": "/dev/shm/rolo-n7-targetd-" + "a" * 20,
            "target_id": inputs.target_id,
            "session_id": inputs.session_id,
            "call_id": inputs.call_id,
            "final_zero_verified": True,
            "stop_acknowledged": True,
            "provider_terminated": True,
            "post_isolated": True,
            "post_isolated_graph_revision": "sha256:" + "1" * 64,
            "post_isolated_topology_digest": post_snapshot.topology_digest(),
            "worker_terminal_revalidated": True,
            "stage_cleanup_authorized": True,
            "receipt_payload_sha256": "sha256:" + "2" * 64,
            "receipt_auth_tag": "hmac-sha256:" + "3" * 64,
        }


class _Trace:
    def __init__(
        self,
        artifact: Path,
        *,
        first_status="SUCCEEDED",
        query_status="SUCCEEDED",
        start_raises: bool = False,
        stop_safe: bool = True,
    ) -> None:
        self.artifact = artifact
        self.first_status = first_status
        self.query_status = query_status
        self.start_raises = start_raises
        self.stop_safe = stop_safe
        self.events: list[str] = []

    def preflight_provider_gate(self, receipt):
        assert receipt.ready_for_provider_gate
        self.events.append("PREFLIGHT_GATE")

    def prepare_zero_motion(self, spec):
        assert spec.arguments() == {"angle_degrees": 1.0, "max_speed_rad_s": 0.03}
        self.events.append("PREPARE_ZERO_MOTION")
        return PrearmedProviderReceipt(
            session_id=SESSION_ID,
            call_id=CALL_ID,
            publisher_identities=("/rolo_bounded_twist",),
            provider_invocation_count=0,
            motion_command_emitted=False,
            motion_enabled=False,
            worker_lease_digest="sha256:" + "7" * 64,
            receipt_digest="sha256:" + "8" * 64,
            receipt={"target_owned": True},
        )

    def _attempt(self, status, queries):
        success = status == "SUCCEEDED"
        return TraceAttempt(
            status=status,
            session_id=SESSION_ID,
            call_id=CALL_ID,
            call_attempt_count=1,
            query_attempt_count=queries,
            provider_invocation_count=1 if status != "BLOCKED" else 0,
            provider_gate_consumed=status != "BLOCKED",
            provider_gate_receipt={
                "schema_version": "rolo-targetd-provider-gate-consumption/v1",
                "status": "CONSUMED" if status != "BLOCKED" else "BLOCKED",
                "consumed": status != "BLOCKED",
                "provider_invocation_count": 1 if status != "BLOCKED" else 0,
                "final_zero_verified": success,
                "stop_acknowledged": success,
                "controlled_publisher_identities": ["/rolo_bounded_twist"] if success else [],
            },
            controlled_publisher_identities=("/rolo_bounded_twist",) if success else (),
            final_zero_verified=success,
            stop_acknowledged=success,
            provider_terminated=success,
            trace_artifacts={"index": self.artifact},
            result={"status": status},
        )

    def start_once(self, receipt, spec):
        assert receipt.call_id == CALL_ID
        assert spec.arguments() == {"angle_degrees": 1.0, "max_speed_rad_s": 0.03}
        self.events.append("CALL")
        if self.start_raises:
            raise TimeoutError("response lost after dispatch")
        return self._attempt(self.first_status, 0)

    def query_once(self, call_id):
        assert call_id == CALL_ID
        self.events.append("QUERY_CALL")
        return self._attempt(self.query_status, 1)

    def stop_once(self, call_id):
        assert call_id == CALL_ID
        self.events.append("STOP")
        return AuthenticatedStopReceipt(
            status="STOPPED" if self.stop_safe else "UNKNOWN",
            session_id=SESSION_ID,
            call_id=CALL_ID,
            stop_request_count=1,
            control_auth_verified=self.stop_safe,
            final_zero_verified=self.stop_safe,
            target_stop_acknowledged=self.stop_safe,
            provider_terminated=self.stop_safe,
            receipt_digest="sha256:" + "9" * 64,
            receipt={"target_owned": True},
        )


def _runner(tmp_path: Path) -> N7PhysicalTraceRunner:
    return N7PhysicalTraceRunner(
        tmp_path / "artifacts",
        artifact_signing_key=b"artifact-signing-key-32-bytes!!!",
        clock=lambda: NOW,
    )


def _inputs() -> N7PhysicalTraceInputs:
    return N7PhysicalTraceInputs(
        run_id=RUN_ID,
        session_id=SESSION_ID,
        call_id=CALL_ID,
        user_attestation="现场急停、人员、安全区已妥善安排，本轮不演练。",
    )


def test_stage_root_and_motion_defaults_are_bounded() -> None:
    assert stage_root_for(RUN_ID) == stage_root_for(RUN_ID)
    assert stage_root_for(RUN_ID).startswith("/dev/shm/rolo-n7-physical-")
    assert MotionSpec().arguments() == {"angle_degrees": 1.0, "max_speed_rad_s": 0.03}
    with pytest.raises(N7PhysicalBlocked, match="run id"):
        stage_root_for("../../unsafe")
    with pytest.raises(ValueError, match="angle"):
        MotionSpec(angle_degrees=6)
    with pytest.raises(ValueError, match="max_speed"):
        MotionSpec(max_speed_rad_s=0.06)


def test_exact_baseline_and_isolation_topology_reject_extra_publishers() -> None:
    baseline = ControlGraphSnapshot.parse(_snapshot("BASELINE", isolated=False), phase="BASELINE")
    baseline.require_baseline()
    isolated = ControlGraphSnapshot.parse(_snapshot("ISOLATED", isolated=True), phase="ISOLATED")
    isolated.require_isolated()

    unsafe = _snapshot("ISOLATED", isolated=True)
    unsafe["competing_publishers"] = ["/joystick_control"]
    unsafe["competing_publisher_gids"] = ["f" * 32]
    with pytest.raises(N7PhysicalBlocked, match="not isolated"):
        ControlGraphSnapshot.parse(unsafe, phase="ISOLATED").require_isolated()

    changed = _snapshot("BASELINE", isolated=False)
    changed["processes"][0]["start_ticks"] = 0  # type: ignore[index]
    with pytest.raises(N7PhysicalBlocked, match="allowlist"):
        ControlGraphSnapshot.parse(changed, phase="BASELINE")

    duplicate_gid = _snapshot("BASELINE", isolated=False)
    duplicate_gid["competing_publisher_gids"][1] = duplicate_gid[  # type: ignore[index]
        "competing_publisher_gids"
    ][0]
    with pytest.raises(N7PhysicalBlocked, match="GID|duplicates"):
        ControlGraphSnapshot.parse(duplicate_gid, phase="BASELINE")


def test_endpoint_identity_gid_pairs_are_canonicalized_together() -> None:
    canonical_raw = _snapshot("BASELINE", isolated=False)
    canonical = ControlGraphSnapshot.parse(canonical_raw, phase="BASELINE")

    shuffled = json.loads(json.dumps(canonical_raw))
    shuffled["competing_publishers"].reverse()
    shuffled["competing_publisher_gids"].reverse()
    shuffled_parsed = ControlGraphSnapshot.parse(shuffled, phase="BASELINE")
    assert shuffled_parsed.topology_digest() == canonical.topology_digest()
    assert tuple(
        zip(
            shuffled_parsed.competing_publishers,
            shuffled_parsed.competing_publisher_gids,
            strict=True,
        )
    ) == tuple(
        zip(
            canonical.competing_publishers,
            canonical.competing_publisher_gids,
            strict=True,
        )
    )

    tampered = json.loads(json.dumps(canonical_raw))
    gids = tampered["competing_publisher_gids"]
    gids[0], gids[1] = gids[1], gids[0]
    assert (
        ControlGraphSnapshot.parse(tampered, phase="BASELINE").topology_digest()
        != canonical.topology_digest()
    )


def test_sensor_health_digest_preserves_endpoint_identity_gid_pairs() -> None:
    stage_root = stage_root_for(RUN_ID)
    graph_digest = "sha256:" + "7" * 64
    canonical_raw = _sensor_health(
        phase="BASELINE",
        stage_root=stage_root,
        graph_topology_digest=graph_digest,
    )
    topic = canonical_raw["topics"][1]
    topic["publisher_identities"] = ["/imu_filter", "/imu_relay"]
    topic["publisher_gids"] = ["a" * 32, "b" * 32]
    canonical_raw["evidence_digest"] = _fixture_digest(
        {key: value for key, value in canonical_raw.items() if key != "evidence_digest"}
    )
    canonical = FreshSensorHealthReceipt.parse(
        canonical_raw,
        phase="BASELINE",
        stage_root=stage_root,
        graph_topology_digest=graph_digest,
    )

    shuffled = json.loads(json.dumps(canonical_raw))
    shuffled_topic = shuffled["topics"][1]
    shuffled_topic["publisher_identities"].reverse()
    shuffled_topic["publisher_gids"].reverse()
    assert FreshSensorHealthReceipt.parse(
        shuffled,
        phase="BASELINE",
        stage_root=stage_root,
        graph_topology_digest=graph_digest,
    ).evidence_digest == canonical.evidence_digest

    tampered = json.loads(json.dumps(canonical_raw))
    tampered_gids = tampered["topics"][1]["publisher_gids"]
    tampered_gids[0], tampered_gids[1] = tampered_gids[1], tampered_gids[0]
    with pytest.raises(N7PhysicalBlocked, match="digest"):
        FreshSensorHealthReceipt.parse(
            tampered,
            phase="BASELINE",
            stage_root=stage_root,
            graph_topology_digest=graph_digest,
        )


def test_sensor_health_rejects_negative_age_and_wall_clock_boundary_drift() -> None:
    stage_root = stage_root_for(RUN_ID)
    graph_digest = "sha256:" + "7" * 64
    raw = _sensor_health(
        phase="BASELINE",
        stage_root=stage_root,
        graph_topology_digest=graph_digest,
    )
    raw["topics"][0]["last_sample_age_s"] = -0.001
    raw["evidence_digest"] = _fixture_digest(
        {key: value for key, value in raw.items() if key != "evidence_digest"}
    )
    with pytest.raises(N7PhysicalBlocked, match="gap or age"):
        FreshSensorHealthReceipt.parse(
            raw,
            phase="BASELINE",
            stage_root=stage_root,
            graph_topology_digest=graph_digest,
        )

    raw = _sensor_health(
        phase="BASELINE",
        stage_root=stage_root,
        graph_topology_digest=graph_digest,
    )
    raw["topics"][0]["last_sample_at"] = (
        NOW + timedelta(seconds=3, milliseconds=1)
    ).isoformat().replace("+00:00", "Z")
    raw["evidence_digest"] = _fixture_digest(
        {key: value for key, value in raw.items() if key != "evidence_digest"}
    )
    with pytest.raises(N7PhysicalBlocked, match="monotonic sampling window"):
        FreshSensorHealthReceipt.parse(
            raw,
            phase="BASELINE",
            stage_root=stage_root,
            graph_topology_digest=graph_digest,
        )


def test_live_joystick_process_allowlist_matches_peripherals_install() -> None:
    assert PUBLISHER_PROCESS_ALLOWLIST["/joystick_control"] == (
        "/home/ubuntu/ros2_ws/install/peripherals/lib/peripherals/joystick_control"
    )


def test_read_only_live_preflight_has_no_isolation_or_motion(tmp_path: Path) -> None:
    channel = _Channel()
    report = run_read_only_live_preflight(channel, run_id=RUN_ID)

    assert report["status"] == "PASS"
    assert report["motion_capability_present"] is False
    assert report["cleanup"]["residual_count"] == 0
    assert channel.events == [
        "STAGE",
        "SNAPSHOT:BASELINE",
        "SAMPLE_HEALTH:BASELINE",
        "CLEANUP",
    ]


def test_typed_gate_query_recomputes_signed_consume_and_runtime(tmp_path: Path) -> None:
    verifier, _, manifest, acceptance, reference, receipt, armed = _typed_proof_fixture(
        tmp_path
    )
    resolved = verifier._query_gate_reference(
        receipt,
        gate_uri=reference.uri,
        gate_digest_uri=reference.digest_uri,
    )
    verifier._verify_gate_reference(resolved, receipt, acceptance, armed)
    verifier._require_armed_zero(armed)

    changed = PhysicalWorkerArmedZero(
        **{**armed.__dict__, "runtime_sha256": "0" * 64}
    )
    assert manifest.observation_contract["provider_runtime_sha256"] != "0" * 64
    with pytest.raises(N7PhysicalBlocked, match="runtime"):
        verifier._require_armed_zero(changed)


def test_typed_gate_query_rejects_untrusted_target_signature(tmp_path: Path) -> None:
    verifier, request, manifest, acceptance, reference, receipt, armed = _typed_proof_fixture(
        tmp_path
    )
    untrusted = TargetdPhysicalProofVerifier(
        request,
        manifest=manifest,
        manifest_verification_key=b"secret",
        trust_store=MotionSafetyTrustStore(
            {"targetd:n7-authority": b"x" * 32}
        ),
        target_authority_id="targetd:n7-authority",
        query_physical_remote=verifier.query_physical_remote,
        load_lease=lambda _call_key: None,
        stop_remote=lambda _call_id, _digest: pytest.fail("STOP not expected"),
    )
    resolved = untrusted._query_gate_reference(
        receipt,
        gate_uri=reference.uri,
        gate_digest_uri=reference.digest_uri,
    )
    with pytest.raises(N7PhysicalBlocked, match="signed provider-gate"):
        untrusted._verify_gate_reference(resolved, receipt, acceptance, armed)


def test_authenticated_stop_accepts_strict_failed_already_terminal_proof(
    tmp_path: Path,
) -> None:
    verifier, request = _already_terminal_stop_fixture(tmp_path)

    stop = verifier.authenticated_stop(request.idempotency_key)

    assert stop.status == "ALREADY_TERMINAL"
    assert stop.stop_request_count == 1
    assert stop.control_auth_verified is True
    assert stop.final_zero_verified is True
    assert stop.target_stop_acknowledged is True
    assert stop.provider_terminated is True
    assert stop.safe_to_restore is True


def test_authenticated_stop_rejects_incomplete_failed_terminal_proof(
    tmp_path: Path,
) -> None:
    verifier, request = _already_terminal_stop_fixture(
        tmp_path,
        omit_inner_process_gone=True,
    )

    stop = verifier.authenticated_stop(request.idempotency_key)

    assert stop.status == "UNKNOWN"
    assert stop.control_auth_verified is True
    assert stop.final_zero_verified is True
    assert stop.target_stop_acknowledged is True
    assert stop.provider_terminated is False
    assert stop.safe_to_restore is False


def test_authenticated_stop_waits_before_each_nonterminal_physical_query(
    tmp_path: Path,
) -> None:
    base, request = _already_terminal_stop_fixture(tmp_path)
    original_terminal = base.stop_remote(
        request.idempotency_key,
        request.request_digest(),
    )
    terminal_receipt = TargetdCallReceipt.model_validate(
        original_terminal.frame.payload["receipt"]
    )
    pending_receipt = _lifecycle_receipt(request, "STARTED")
    events: list[object] = []

    def stop_remote(call_id, request_digest):
        assert call_id == request.idempotency_key
        assert request_digest == request.request_digest()
        events.append("STOP")
        return TargetdTraceResponse(
            frame=ProtocolFrame.create(
                kind=FrameKind.RESULT,
                sequence=11,
                session_id=request.session_id,
                payload={
                    "request_kind": FrameKind.STOP.value,
                    "ok": True,
                    "receipt": pending_receipt.model_dump(mode="json"),
                    "interrupt": {
                        "intent": "STOP",
                        "status": "STOP_REQUESTED",
                        "requested": True,
                        "acknowledged": False,
                        "lease_state": "STOP_REQUESTED",
                    },
                },
            ),
            sequence_correlated=True,
        )

    query_receipts = iter((pending_receipt, terminal_receipt))

    def query_remote(call_id, request_digest, gate_uri, gate_digest_uri):
        assert (call_id, request_digest, gate_uri, gate_digest_uri) == (
            request.idempotency_key,
            request.request_digest(),
            None,
            None,
        )
        events.append("QUERY")
        receipt = next(query_receipts)
        return TargetdTraceResponse(
            frame=ProtocolFrame.create(
                kind=FrameKind.RESULT,
                sequence=12 + events.count("QUERY"),
                session_id=request.session_id,
                payload={
                    "request_kind": FrameKind.QUERY_CALL.value,
                    "ok": True,
                    "receipt": receipt.model_dump(mode="json"),
                },
            ),
            sequence_correlated=True,
        )

    verifier = TargetdPhysicalProofVerifier(
        request,
        manifest=base.manifest,
        manifest_verification_key=b"secret",
        trust_store=base.trust_store,
        target_authority_id=base.target_authority_id,
        query_physical_remote=query_remote,
        load_lease=base.load_lease,
        stop_remote=stop_remote,
        stop_query_budget=3,
        stop_poll_sleeper=lambda interval: events.append(("SLEEP", interval)),
    )

    stop = verifier.authenticated_stop(request.idempotency_key)

    assert events == [
        "STOP",
        ("SLEEP", 0.3),
        "QUERY",
        ("SLEEP", 0.3),
        "QUERY",
    ]
    assert stop.status == "UNKNOWN"
    assert stop.receipt["stop_query_count"] == 2


@pytest.mark.parametrize(
    "interval",
    [True, "0.3", math.nan, math.inf, 0.0, 0.049, 2.001],
)
def test_authenticated_stop_rejects_unsafe_poll_interval(
    tmp_path: Path,
    interval: object,
) -> None:
    base, request, manifest, _acceptance, _reference, _receipt, _armed = (
        _typed_proof_fixture(tmp_path)
    )

    with pytest.raises(ValueError, match="STOP poll interval"):
        TargetdPhysicalProofVerifier(
            request,
            manifest=manifest,
            manifest_verification_key=b"secret",
            trust_store=base.trust_store,
            target_authority_id=base.target_authority_id,
            query_physical_remote=base.query_physical_remote,
            load_lease=base.load_lease,
            stop_remote=base.stop_remote,
            stop_poll_interval_s=interval,  # type: ignore[arg-type]
            stop_poll_sleeper=lambda _interval: None,
        )


def test_authenticated_stop_rejects_noncallable_poll_sleeper(
    tmp_path: Path,
) -> None:
    base, request, manifest, _acceptance, _reference, _receipt, _armed = (
        _typed_proof_fixture(tmp_path)
    )

    with pytest.raises(ValueError, match="STOP poll interval"):
        TargetdPhysicalProofVerifier(
            request,
            manifest=manifest,
            manifest_verification_key=b"secret",
            trust_store=base.trust_store,
            target_authority_id=base.target_authority_id,
            query_physical_remote=base.query_physical_remote,
            load_lease=base.load_lease,
            stop_remote=base.stop_remote,
            stop_poll_sleeper=None,  # type: ignore[arg-type]
        )


def test_runner_accepts_only_exact_typed_debug_user_attestation(tmp_path: Path) -> None:
    from rolo.targetd.landerpi_motion_target import (
        run_debug_user_attested_zero_motion_acceptance,
    )
    from tests.test_landerpi_motion_target import (
        GRAPH_AUTHORITY,
        GRAPH_KEY,
        TARGET_AUTHORITY,
        TARGET_KEY,
        _debug_admission,
        _target,
    )
    from tests.test_landerpi_motion_target import (
        NOW as MOTION_NOW,
    )

    target, rpc, _, policy, intent = _target(tmp_path)
    rpc.arm()
    admission = _debug_admission(intent, policy)
    receipt = run_debug_user_attested_zero_motion_acceptance(
        admission,
        intent=intent,
        policy=policy,
        trust_store=MotionSafetyTrustStore(
            {
                GRAPH_AUTHORITY: GRAPH_KEY,
                TARGET_AUTHORITY: TARGET_KEY,
            }
        ),
        target=target,
        now=MOTION_NOW,
    )
    inputs = N7PhysicalTraceInputs(
        run_id=RUN_ID,
        session_id=intent.session_id,
        call_id=intent.call_id,
        user_attestation=(
            "用户明确确认现场人员、独立急停和安全区已妥善安排，本轮不重复演练。"
        ),
    )
    inputs = N7PhysicalTraceInputs(
        run_id=inputs.run_id,
        session_id=inputs.session_id,
        call_id=inputs.call_id,
        user_attestation="用户明确确认现场人员、独立急停和安全区已妥善安排，本轮不重复演练。",
    )
    inputs = N7PhysicalTraceInputs(
        run_id=inputs.run_id,
        session_id=inputs.session_id,
        call_id=inputs.call_id,
        user_attestation=(
            "\u7528\u6237\u660e\u786e\u786e\u8ba4\u73b0\u573a\u4eba\u5458\u3001"
            "\u72ec\u7acb\u6025\u505c\u548c\u5b89\u5168\u533a\u5df2\u59a5\u5584"
            "\u5b89\u6392\uff0c\u672c\u8f6e\u4e0d\u91cd\u590d\u6f14\u7ec3\u3002"
        ),
    )
    N7PhysicalTraceRunner._validate_acceptance(receipt, inputs)

    changed = N7PhysicalTraceInputs(
        run_id=RUN_ID,
        session_id=intent.session_id,
        call_id=intent.call_id,
        user_attestation="different statement",
    )
    with pytest.raises(N7PhysicalBlocked, match="debug acceptance"):
        N7PhysicalTraceRunner._validate_acceptance(receipt, changed)


def test_pinned_ssh_is_key_only_and_host_key_pinned(tmp_path: Path) -> None:
    known_hosts = tmp_path / "known_hosts"
    identity = tmp_path / "id_ed25519"
    known_hosts.write_text(_known_host_line(), encoding="ascii")
    identity.write_text("test-only-private-key-placeholder\n", encoding="ascii")
    actual_public = _ssh_public_key_line(comment="derived")
    identity.with_suffix(".pub").write_text(
        " \t" + _ssh_public_key_line(comment="declared-comment").strip() + "  \n",
        encoding="ascii",
    )
    config = PinnedSshConfiguration(
        host="192.168.10.167",
        user="pi",
        known_hosts=known_hosts,
        identity_file=identity,
        public_key_deriver=lambda path: actual_public,
    )
    argv = config.argv(["true"])
    joined = " ".join(argv)
    assert "BatchMode=yes" in argv
    assert "PasswordAuthentication=no" in argv
    assert "KbdInteractiveAuthentication=no" in argv
    assert "PreferredAuthentications=publickey" in argv
    assert "StrictHostKeyChecking=yes" in argv
    assert "IdentitiesOnly=yes" in argv
    assert argv[argv.index("-i") + 1] == str(identity.resolve())
    assert str(identity.resolve()) in argv
    assert "password=" not in joined.casefold()


def test_sealed_live_descriptor_builder_round_trip_is_secret_minimal(
    tmp_path: Path,
) -> None:
    config = _descriptor_ssh_configuration(tmp_path)
    descriptor_path = tmp_path / "composition.json"
    bundle_key = b"B" * 32
    artifact_key = b"A" * 32

    composition = create_sealed_live_composition_descriptor(
        config,
        output_path=descriptor_path,
        key_root=tmp_path / "composition-keys",
        artifact_root=tmp_path / "acceptance-artifacts",
        run_id="n7-live-roundtrip",
        session_id="n7-live-session",
        call_id="n7-live-call",
        now=NOW,
        bundle_signing_key=bundle_key,
        artifact_signing_key=artifact_key,
    )
    reloaded = load_sealed_live_composition_descriptor(
        descriptor_path,
        config=config,
        expected_run_id="n7-live-roundtrip",
        now=NOW + timedelta(seconds=1),
    )

    assert reloaded == composition
    assert composition.manifest.limits == {
        "max_duration_s": 75,
        "max_output_bytes": 65_536,
    }
    validate_landerpi_rotate_process_call(
        composition.request,
        composition.manifest,
    )
    tool = next(
        item for item in composition.catalog.tools if item.tool_id == "app.base.rotate"
    )
    assert tool.timeout_s == 300.0
    assert composition.request.deadline - timedelta(seconds=tool.timeout_s) == NOW
    assert composition.request.run_id == composition.session_id
    assert composition.request.arguments == {
        "angle_degrees": 1.0,
        "max_speed_rad_s": 0.03,
    }
    descriptor_text = descriptor_path.read_text(encoding="ascii")
    assert base64.b64encode(bundle_key).decode("ascii") not in descriptor_text
    assert base64.b64encode(artifact_key).decode("ascii") not in descriptor_text
    assert "resume_token" not in descriptor_text
    assert "targetd_signing_base64" not in descriptor_text
    assert "peer_bootstrap_verification_base64" not in descriptor_text
    assert composition.bundle_verification_key_path.read_bytes() == bundle_key
    assert composition.artifact_signing_key_path.read_bytes() == artifact_key


def test_sealed_live_descriptor_mid_creation_failure_removes_only_new_keys(
    tmp_path: Path,
) -> None:
    config = _descriptor_ssh_configuration(tmp_path)
    key_root = tmp_path / "composition-keys"
    key_root.mkdir()
    existing = key_root / "n7-live-partial.artifact-signing.key"
    existing.write_bytes(b"existing-owner-material")

    with pytest.raises(N7PhysicalBlocked) as raised:
        create_sealed_live_composition_descriptor(
            config,
            output_path=tmp_path / "composition.json",
            key_root=key_root,
            artifact_root=tmp_path / "acceptance-artifacts",
            run_id="n7-live-partial",
            session_id="n7-live-partial-session",
            call_id="n7-live-partial-call",
            now=NOW,
            bundle_signing_key=b"B" * 32,
            artifact_signing_key=b"A" * 32,
        )

    assert raised.value.code == "N7_PHYSICAL_DESCRIPTOR_KEY_EXISTS"
    assert not (key_root / "n7-live-partial.bundle-verification.key").exists()
    assert existing.read_bytes() == b"existing-owner-material"
    assert not (tmp_path / "composition.json").exists()


def test_execute_rejects_tampered_descriptor_before_constructing_channels(
    tmp_path: Path,
) -> None:
    config = _descriptor_ssh_configuration(tmp_path)
    descriptor_path = tmp_path / "composition.json"
    create_sealed_live_composition_descriptor(
        config,
        output_path=descriptor_path,
        key_root=tmp_path / "composition-keys",
        artifact_root=tmp_path / "acceptance-artifacts",
        run_id="n7-live-tamper",
        session_id="n7-live-tamper-session",
        call_id="n7-live-tamper-call",
        now=NOW,
        bundle_signing_key=b"B" * 32,
        artifact_signing_key=b"A" * 32,
    )
    tampered = json.loads(descriptor_path.read_text(encoding="ascii"))
    tampered["user_attestation"] = "substituted site statement"
    descriptor_path.write_text(
        json.dumps(tampered, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="ascii",
    )
    calls: list[str] = []

    with pytest.raises(N7PhysicalBlocked) as raised:
        execute_sealed_live_composition_once(
            config,
            descriptor_path=descriptor_path,
            run_id="n7-live-tamper",
            clock=lambda: NOW + timedelta(seconds=1),
            source_archive_factory=lambda _root: calls.append("archive"),
            container_channel_factory=lambda _config: calls.append("container"),
            host_channel_factory=lambda _config, _run_id, _archive: calls.append(
                "host"
            ),
        )

    assert raised.value.code == "N7_PHYSICAL_COMPOSITION_DESCRIPTOR_IDENTITY_MISMATCH"
    assert calls == []


def test_execute_composes_integral_current_time_trace_window_without_live_io(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _descriptor_ssh_configuration(tmp_path)
    descriptor_path = tmp_path / "composition.json"
    composition = create_sealed_live_composition_descriptor(
        config,
        output_path=descriptor_path,
        key_root=tmp_path / "composition-keys",
        artifact_root=tmp_path / "acceptance-artifacts",
        run_id="n7-live-compose",
        session_id="n7-live-compose-session",
        call_id="n7-live-compose-call",
        now=NOW,
        bundle_signing_key=b"B" * 32,
        artifact_signing_key=b"A" * 32,
    )
    observed: dict[str, object] = {}

    class InertContainer:
        channel_id = "sha256:" + "1" * 64

    class InertHost:
        channel_binding_sha256 = "sha256:" + "2" * 64
        stage_root = "/dev/shm/rolo-n7-targetd-" + "3" * 20

        def abort_preserve(self) -> None:
            observed["aborted"] = True

    class InspectingRunner:
        def __init__(self, artifact_root, *, artifact_signing_key, clock) -> None:
            assert artifact_root == composition.artifact_root
            assert artifact_signing_key == b"A" * 32
            assert clock() == NOW + timedelta(seconds=1)

        def run(self, inputs, *, channel, acceptance, trace):
            assert inputs.run_id == composition.run_id
            assert not hasattr(channel, "call_remote")
            assert trace.request.session_id == composition.session_id
            # The pydantic schema stores ttl_s as float, but the controller
            # supplies an integral ceil-bounded value.
            assert trace.request.ttl_s.is_integer()
            assert trace.request.ttl_s == 329
            assert trace.call.idempotency_key == composition.call_id
            assert acceptance.composition == composition
            observed["composed"] = True
            return {
                "status": "PASS_WITH_USER_ATTESTED_SITE_SAFETY",
                "host_finalize_verified": True,
                "restore_verified": True,
                "stage_cleanup_verified": True,
            }

    monkeypatch.setitem(
        execute_sealed_live_composition_once.__globals__,
        "N7PhysicalTraceRunner",
        InspectingRunner,
    )
    report = execute_sealed_live_composition_once(
        config,
        descriptor_path=descriptor_path,
        run_id=composition.run_id,
        clock=lambda: NOW + timedelta(seconds=1),
        source_archive_factory=lambda _root: object(),
        container_channel_factory=lambda _config: InertContainer(),
        host_channel_factory=lambda _config, _run_id, _archive: InertHost(),
    )

    assert observed == {"composed": True}
    assert report["status"] == "PASS_WITH_USER_ATTESTED_SITE_SAFETY"


def test_execute_once_cli_accepts_user_attested_success_status(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setitem(
        main.__globals__,
        "_live_ssh_configuration",
        lambda _args: object(),
    )
    monkeypatch.setitem(
        main.__globals__,
        "execute_sealed_live_composition_once",
        lambda _config, **_kwargs: {
            "schema_version": "rolo-landerpi-n7-physical-trace/v1",
            "status": "PASS_WITH_USER_ATTESTED_SITE_SAFETY",
            "production_authority": False,
        },
    )

    code = main(
        [
            "--execute-once",
            "--live",
            "--target",
            "192.168.10.167",
            "--known-hosts",
            "known-hosts",
            "--identity",
            "id-ed25519",
            "--identity-public",
            "id-ed25519.pub",
            "--run-id",
            "n7-cli-live",
            "--composition",
            "composition.json",
        ]
    )
    payload = json.loads(capsys.readouterr().out)

    assert code == 0
    assert payload["status"] == "PASS_WITH_USER_ATTESTED_SITE_SAFETY"
    assert payload["production_authority"] is False


def test_host_source_archive_round_trips_nested_rolo_packages(
    tmp_path: Path,
) -> None:
    repository_root = Path(__file__).parents[1]
    archive = build_host_targetd_source_archive(repository_root)
    archive_path = tmp_path / "source.tar"
    archive_path.write_bytes(archive.payload)

    definitions = _HOST_TARGETD_STAGE_SOURCE.split("\nstage = None", 1)[0]
    namespace: dict[str, object] = {}
    exec(compile(definitions, "<host-stage-fixture>", "exec"), namespace)
    extract = namespace["extract"]
    destination = tmp_path / "expanded"
    destination.mkdir()
    extract(
        destination,
        archive_path,
        archive.expanded_bytes,
        archive.member_count,
    )

    assert (
        destination / "repo/src/rolo/targetd/landerpi_motion_target.py"
    ).is_file()
    assert (
        destination / "repo/scripts/landerpi_n7_targetd_host.py"
    ).is_file()


def test_host_bootstrap_binds_full_v3_request_peer_and_call_key(
    tmp_path: Path,
) -> None:
    channel, request, manifest, source, policy, receipt, keys = (
        _host_controller_fixture(tmp_path)
    )
    bootstrap_now = request.motion_safety_admission.intent.requested_at
    payload = build_host_targetd_bootstrap(
        channel,
        request=request,
        manifest=manifest,
        bundle_source=source,
        policy=policy,
        mapping_confirmation_receipt=receipt,
        keys=keys,
        now=bootstrap_now,
    )

    unsigned = dict(payload)
    payload_digest = unsigned.pop("payload_sha256")
    assert payload_digest == _digest(unsigned)
    assert ExecutionRequestV3.model_validate(payload["execution_request"]) == request
    assert payload["expected_call"] == {
        "id": request.idempotency_key,
        "session": request.session_id,
        "execution_subject_digest": request.execution_subject_digest,
        "motion_fence_epoch": request.authority.fence_epoch,
        "request_digest": request.request_digest(),
        "call_key_digest": WorkerCallKey.from_request(request).digest(),
    }
    peer_receipt = DebugPinnedTargetdPeerBootstrapReceipt.model_validate(
        payload["peer_bootstrap_receipt"]
    )
    # A freshly issued capability must tolerate the bounded negative clock
    # skew measured between the controller and Pi while remaining short-lived.
    assert peer_receipt.issued_at == bootstrap_now - timedelta(seconds=5)
    assert peer_receipt.expires_at == bootstrap_now + timedelta(seconds=45)
    assert peer_receipt.expires_at - peer_receipt.issued_at == timedelta(
        seconds=50
    )
    assert payload["authority"] == request.authority.model_dump(mode="json")
    assert payload["motion_intent"] == (
        request.motion_safety_admission.intent.model_dump(mode="json")
    )
    expected_peer = payload["expected_peer"]
    assert expected_peer["pinned_host_key_sha256"] == (
        channel.config.pinned_host_key_fingerprint
    )
    assert expected_peer["client_public_key_sha256"] == (
        channel.config.public_key_fingerprint
    )
    assert expected_peer["channel_binding_sha256"] == (
        channel.channel_binding_sha256
    )
    peer = payload["peer_bootstrap_receipt"]
    assert peer["local_subprocess_shell_used"] is False
    assert peer["remote_login_shell_used"] is True
    assert peer["production_peer_verified"] is False

    assert validate_host_targetd_bootstrap_payload(channel, payload) == payload
    drifted = json.loads(json.dumps(payload))
    drifted["expected_call"]["request_digest"] = "sha256:" + "0" * 64
    drifted_unsigned = dict(drifted)
    drifted_unsigned.pop("payload_sha256")
    drifted["payload_sha256"] = _digest(drifted_unsigned)
    with pytest.raises(N7PhysicalBlocked) as raised:
        validate_host_targetd_bootstrap_payload(channel, drifted)
    assert raised.value.code == "N7_PHYSICAL_HOST_BOOTSTRAP_PAYLOAD_INVALID"


def test_host_bootstrap_rejects_shared_graph_target_signing_identity(
    tmp_path: Path,
) -> None:
    channel, request, manifest, source, policy, receipt, keys = (
        _host_controller_fixture(tmp_path)
    )
    unsafe_policy = policy.model_copy(
        update={"graph_authority_id": policy.target_authority_id}
    )

    with pytest.raises(N7PhysicalBlocked) as raised:
        build_host_targetd_bootstrap(
            channel,
            request=request,
            manifest=manifest,
            bundle_source=source,
            policy=unsafe_policy,
            mapping_confirmation_receipt=receipt,
            keys=keys,
        )
    assert raised.value.code == "N7_PHYSICAL_HOST_BOOTSTRAP_IDENTITY_MISMATCH"


def test_host_finalize_uses_target_graph_domain_and_rejects_extra_fields(
    tmp_path: Path,
) -> None:
    channel, request, manifest, source, policy, receipt, keys = (
        _host_controller_fixture(tmp_path)
    )
    bootstrap = build_host_targetd_bootstrap(
        channel,
        request=request,
        manifest=manifest,
        bundle_source=source,
        policy=policy,
        mapping_confirmation_receipt=receipt,
        keys=keys,
    )
    channel._ready_receipt = {
        "bootstrap_payload_sha256": bootstrap["payload_sha256"]
    }
    post = ControlGraphSnapshot.parse(
        _snapshot("POST_TRACE", isolated=True),
        phase="POST_TRACE",
    )
    terminal = _lifecycle_receipt(request, "SUCCEEDED")
    finalize = build_host_targetd_finalize_payload(
        channel,
        request=request,
        terminal_receipt=terminal,
        final_zero_verified=True,
        stop_acknowledged=True,
        provider_terminated=True,
        post_isolated=post,
        provider_invocation_count=1,
        signing_key=keys.targetd_signing,
    )

    assert finalize["post_isolated_graph_revision"] == (
        target_compatible_graph_revision(
            post,
            target_id=request.target_id,
            target_identity=(
                request.authority.mapping_admission.target_identity_digest
            ),
            direct_motor_interface=(
                request.motion_safety_admission.intent.direct_motor_interface
            ),
        )
    )
    assert finalize["post_isolated_graph_revision"] != post.graph_revision
    assert finalize["post_isolated_topology_digest"] == post.topology_digest()

    core = {
        key: value
        for key, value in finalize.items()
        if key
        not in {
            "schema_version",
            "finalize_payload_sha256",
            "finalize_auth_tag",
        }
    }
    response_unsigned = {
        "schema_version": "rolo-n7-targetd-host-finalize-receipt/v1",
        "status": "SAFE_TO_CLEANUP",
        **core,
        "worker_terminal_revalidated": True,
        "stage_cleanup_authorized": True,
    }
    response_digest = compute_motion_payload_digest(response_unsigned)
    response_tag = hmac.new(
        keys.targetd_signing,
        response_digest.encode("ascii"),
        hashlib.sha256,
    ).hexdigest()
    response = {
        **response_unsigned,
        "receipt_payload_sha256": response_digest,
        "receipt_auth_tag": "hmac-sha256:" + response_tag,
    }
    assert verify_host_targetd_finalize_receipt(
        response,
        request_payload=finalize,
        signing_key=keys.targetd_signing,
    ) == response

    with pytest.raises(N7PhysicalBlocked):
        verify_host_targetd_finalize_receipt(
            {**response, "unexpected": True},
            request_payload=finalize,
            signing_key=keys.targetd_signing,
        )


def test_pinned_ssh_rejects_private_public_identity_mismatch(tmp_path: Path) -> None:
    known_hosts = tmp_path / "known_hosts"
    identity = tmp_path / "id_ed25519"
    known_hosts.write_text(_known_host_line(), encoding="ascii")
    identity.write_text("test-only-private-key-placeholder\n", encoding="ascii")
    identity.with_suffix(".pub").write_text(
        _ssh_public_key_line(key_byte=b"b", comment="declared"),
        encoding="ascii",
    )
    with pytest.raises(ValueError, match="private/public"):
        PinnedSshConfiguration(
            host="192.168.10.167",
            user="pi",
            known_hosts=known_hosts,
            identity_file=identity,
            public_key_deriver=lambda path: _ssh_public_key_line(
                key_byte=b"a",
                comment="derived",
            ),
        )


@pytest.mark.parametrize(
    "known_hosts_payload",
    [
        _known_host_line(host="another-host"),
        "|1|hashed-host|hashed-value ssh-ed25519 "
        + _ssh_public_key_line(key_byte=b"h").split()[1]
        + "\n",
        _known_host_line(key_byte=b"h") + _known_host_line(key_byte=b"i"),
    ],
)
def test_pinned_ssh_rejects_ambiguous_or_nonliteral_host_pin(
    tmp_path: Path,
    known_hosts_payload: str,
) -> None:
    known_hosts = tmp_path / "known_hosts"
    identity = tmp_path / "id_ed25519"
    known_hosts.write_text(known_hosts_payload, encoding="ascii")
    identity.write_text("placeholder\n", encoding="ascii")
    public = _ssh_public_key_line()
    identity.with_suffix(".pub").write_text(public, encoding="ascii")

    with pytest.raises(ValueError, match="known-hosts"):
        PinnedSshConfiguration(
            host="192.168.10.167",
            user="pi",
            known_hosts=known_hosts,
            identity_file=identity,
            public_key_deriver=lambda _path: public,
        )


def test_pinned_channel_rpc_uses_exact_tmpfs_stage_and_fixed_remote_action(tmp_path: Path) -> None:
    known_hosts = tmp_path / "known_hosts"
    identity = tmp_path / "id_ed25519"
    known_hosts.write_text(_known_host_line(), encoding="ascii")
    identity.write_text("placeholder\n", encoding="ascii")
    actual_public = _ssh_public_key_line(comment="derived")
    identity.with_suffix(".pub").write_text(
        _ssh_public_key_line(comment="declared"),
        encoding="ascii",
    )
    seen: list[tuple[list[str], dict]] = []

    def rpc(argv, payload, timeout):
        request = json.loads(payload)
        seen.append((argv, request))
        assert timeout == 60
        response = {
            "schema_version": "rolo-n7-stage-receipt/v1",
            "ok": True,
            "run_id": request["run_id"],
            "container": CONTAINER,
            "stage_root": request["stage_root"],
            "stage_nonce_digest": "sha256:" + hashlib.sha256(request["nonce"].encode()).hexdigest(),
        }
        return _RpcResult(0, json.dumps(response).encode(), b"")

    channel = PinnedLanderPiSshChannel(
        PinnedSshConfiguration(
            host="192.168.10.167",
            user="pi",
            known_hosts=known_hosts,
            identity_file=identity,
            public_key_deriver=lambda path: actual_public,
        ),
        runner=rpc,
    )
    root = stage_root_for(RUN_ID)
    receipt = channel.stage(run_id=RUN_ID, stage_root=root)
    assert receipt["stage_root"] == root
    assert seen[0][1]["action"] == "STAGE"
    assert seen[0][1]["stage_root"].startswith("/dev/shm/rolo-n7-physical-")
    assert seen[0][0][0] == "ssh"
    assert "docker" in seen[0][0]
    assert "MentorPi" in seen[0][0]
    wrapper_index = seen[0][0].index("-c") + 1
    assert seen[0][0][wrapper_index].strip("'") == _ROS_CONTAINER_EXEC_WRAPPER
    assert _ROS_CONTAINER_EXEC_WRAPPER.startswith("set -e;")
    assert "set -u; exec" in _ROS_CONTAINER_EXEC_WRAPPER
    assert "set -eu" not in _ROS_CONTAINER_EXEC_WRAPPER


def test_ros_wrapper_sources_setup_before_enabling_nounset(tmp_path: Path) -> None:
    bash = shutil.which("bash")
    if os.name == "nt":
        git_bash = Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "Git/bin/bash.exe"
        bash = str(git_bash) if git_bash.is_file() else None
    if bash is None:
        pytest.skip("bash is unavailable")
    first = tmp_path / "first-setup.bash"
    second = tmp_path / "second-setup.bash"
    robotrc = tmp_path / "robotrc.bash"
    first.write_text(
        'test -z "${AMENT_TRACE_SETUP_FILES}"\nexport ROS_DISTRO=humble\n',
        encoding="utf-8",
    )
    second.write_text(
        'test -z "${COLCON_TRACE}"\nexport ROLO_SETUP_COMPLETE=yes\n',
        encoding="utf-8",
    )
    robotrc.write_text(
        'printf "robot environment banner\\n"\ntest "$HOME" = /home/ubuntu\n'
        'test -z "${ROLO_ROBOTRC_TRACE}"\nexport MACHINE_TYPE=LanderPi_Mecanum\n',
        encoding="utf-8",
    )
    wrapper = _ROS_CONTAINER_EXEC_WRAPPER.replace(
        "/opt/ros/humble/setup.bash",
        "./first-setup.bash",
    ).replace(
        "/home/ubuntu/ros2_ws/install/setup.bash",
        "./second-setup.bash",
    ).replace(
        "/home/ubuntu/ros2_ws/.robotrc",
        "./robotrc.bash",
    )
    environment = dict(os.environ)
    environment.pop("AMENT_TRACE_SETUP_FILES", None)
    environment.pop("COLCON_TRACE", None)
    environment.pop("ROLO_ROBOTRC_TRACE", None)
    completed = subprocess.run(
        [
            bash,
            "--noprofile",
            "--norc",
            "-c",
            wrapper,
            "rolo-wrapper-fixture",
            bash,
            "-c",
            'test "$ROS_DISTRO" = humble && test "$ROLO_SETUP_COMPLETE" = yes && test "$MACHINE_TYPE" = LanderPi_Mecanum',
        ],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        check=False,
        shell=False,
        timeout=10,
    )
    assert completed.returncode == 0, completed.stderr.decode(errors="replace")
    assert completed.stdout == b""


def test_pinned_channel_preserves_bounded_sanitized_remote_failure(tmp_path: Path) -> None:
    known_hosts = tmp_path / "known_hosts"
    identity = tmp_path / "id_ed25519"
    known_hosts.write_text(_known_host_line(), encoding="ascii")
    identity.write_text("placeholder\n", encoding="ascii")
    identity.with_suffix(".pub").write_text(_ssh_public_key_line(), encoding="ascii")

    def rpc(argv, payload, timeout):
        del argv, payload, timeout
        return _RpcResult(23, b"", b"setup failed\x00\n" + (b"x" * 4096))

    channel = PinnedLanderPiSshChannel(
        PinnedSshConfiguration(
            host="192.168.10.167",
            user="pi",
            known_hosts=known_hosts,
            identity_file=identity,
            public_key_deriver=lambda path: _ssh_public_key_line(),
        ),
        runner=rpc,
    )
    with pytest.raises(N7PhysicalBlocked) as raised:
        channel.stage(run_id=RUN_ID, stage_root=stage_root_for(RUN_ID))
    assert raised.value.code == "N7_PHYSICAL_SSH_REMOTE_EXIT"
    assert "rc=23" in raised.value.message
    assert "setup failed" in raised.value.message
    assert "sha256:" in raised.value.message
    assert len(raised.value.message) < 700


def test_success_writes_signed_immutable_artifact_index_and_restores(tmp_path: Path) -> None:
    trace_artifact = tmp_path / "formal-trace-index.json"
    trace_artifact.write_text('{"trace":"immutable"}\n', encoding="utf-8")
    channel = _Channel()
    acceptance = _Acceptance()
    trace = _Trace(trace_artifact)
    runner = _runner(tmp_path)

    report = runner.run(_inputs(), channel=channel, acceptance=acceptance, trace=trace)

    assert report["status"] == "PASS_WITH_USER_ATTESTED_SITE_SAFETY"
    assert report["report_status"] == "PASS_WITH_USER_ATTESTED_SITE_SAFETY"
    assert report["production_authority"] is False
    assert report["fresh_estop_challenge_verified"] is False
    assert report["call_attempt_count"] == 1
    assert report["query_attempt_count"] == 0
    assert report["provider_invocation_count"] == 1
    assert report["restore_verified"] is True
    assert report["stage_cleanup_verified"] is True
    assert trace.events == ["PREPARE_ZERO_MOTION", "PREFLIGHT_GATE", "CALL"]
    assert channel.events == [
        "STAGE",
        "SNAPSHOT:BASELINE",
        "SAMPLE_HEALTH:BASELINE",
        "ISOLATE",
        "SNAPSHOT:PREARMED",
        "SAMPLE_HEALTH:PREARMED",
        "SNAPSHOT:POST_TRACE",
        "RESTORE",
        "CLEANUP",
    ]
    index = ArtifactIndex.model_validate_json(Path(report["artifact_index"]).read_text(encoding="utf-8"))
    index.verify(b"artifact-signing-key-32-bytes!!!")
    names = {Path(item["path"]).name for item in index.artifacts}
    assert {
        "zero-motion-acceptance.json",
        "trace-attempt.json",
        "post-trace.json",
        "restore.json",
        "cleanup.json",
        "outcome.json",
    } <= names

    with pytest.raises(N7PhysicalBlocked, match="immutable"):
        runner.run(_inputs(), channel=_Channel(), acceptance=_Acceptance(), trace=_Trace(trace_artifact))


def test_host_finalize_is_verified_before_publishers_are_restored(
    tmp_path: Path,
) -> None:
    trace_artifact = tmp_path / "formal-trace-index.json"
    trace_artifact.write_text("{}\n", encoding="utf-8")
    channel = _HostFinalizingChannel()

    report = _runner(tmp_path).run(
        _inputs(),
        channel=channel,
        acceptance=_Acceptance(),
        trace=_Trace(trace_artifact),
    )

    assert report["status"] == "PASS_WITH_USER_ATTESTED_SITE_SAFETY"
    assert report["host_finalize_verified"] is True
    assert channel.events.index("HOST_FINALIZE") < channel.events.index("RESTORE")


def test_host_finalize_failure_preserves_isolation_and_both_stages(
    tmp_path: Path,
) -> None:
    trace_artifact = tmp_path / "formal-trace-index.json"
    trace_artifact.write_text("{}\n", encoding="utf-8")
    channel = _HostFinalizingChannel(finalize_failure=True)

    report = _runner(tmp_path).run(
        _inputs(),
        channel=channel,
        acceptance=_Acceptance(),
        trace=_Trace(trace_artifact),
    )

    assert report["status"] == "UNKNOWN"
    assert report["blockers"] == [
        "N7_PHYSICAL_HOST_FINALIZE_RECEIPT_INVALID"
    ]
    assert channel.isolated is True
    assert "RESTORE" not in channel.events
    assert "CLEANUP" not in channel.events
    assert report["stage_preserved_for_recovery"] is True


def test_ambiguous_call_is_queried_once_and_never_replayed(tmp_path: Path) -> None:
    trace_artifact = tmp_path / "formal-trace-index.json"
    trace_artifact.write_text("{}\n", encoding="utf-8")
    trace = _Trace(trace_artifact, first_status="UNKNOWN", query_status="SUCCEEDED")

    report = _runner(tmp_path).run(
        _inputs(),
        channel=_Channel(),
        acceptance=_Acceptance(),
        trace=trace,
    )

    assert report["status"] == "PASS_WITH_USER_ATTESTED_SITE_SAFETY"
    assert report["call_attempt_count"] == 1
    assert report["query_attempt_count"] == 1
    assert trace.events == ["PREPARE_ZERO_MOTION", "PREFLIGHT_GATE", "CALL", "QUERY_CALL"]


def test_blocked_acceptance_never_calls_provider_and_still_restores(tmp_path: Path) -> None:
    trace_artifact = tmp_path / "formal-trace-index.json"
    trace_artifact.write_text("{}\n", encoding="utf-8")
    trace = _Trace(trace_artifact)
    acceptance = _Acceptance(
        ZeroMotionAcceptanceReceipt(
            status="BLOCKED",
            reasons=("LIVE_GRAPH_UNSAFE",),
            evaluated_at=NOW,
        )
    )
    channel = _Channel()

    report = _runner(tmp_path).run(
        _inputs(),
        channel=channel,
        acceptance=acceptance,
        trace=trace,
    )

    assert report["status"] == "BLOCKED"
    assert report["call_attempt_count"] == 0
    assert report["provider_invocation_count"] == 0
    assert report["blockers"] == ["N7_PHYSICAL_ZERO_MOTION_ACCEPTANCE_BLOCKED"]
    assert trace.events == ["PREPARE_ZERO_MOTION", "STOP"]
    assert channel.events[-2:] == ["RESTORE", "CLEANUP"]


def test_unsafe_baseline_never_mutates_processes_or_calls_provider(tmp_path: Path) -> None:
    trace_artifact = tmp_path / "formal-trace-index.json"
    trace_artifact.write_text("{}\n", encoding="utf-8")
    channel = _Channel(unsafe_baseline=True)
    trace = _Trace(trace_artifact)

    report = _runner(tmp_path).run(
        _inputs(),
        channel=channel,
        acceptance=_Acceptance(),
        trace=trace,
    )

    assert report["status"] == "BLOCKED"
    assert report["blockers"] == ["N7_PHYSICAL_BASELINE_TOPOLOGY_MISMATCH"]
    assert "ISOLATE" not in channel.events
    assert "RESTORE" not in channel.events
    assert channel.events[-1] == "CLEANUP"
    assert trace.events == []


def test_dead_baseline_streams_restart_bringup_once_before_isolation(tmp_path: Path) -> None:
    trace_artifact = tmp_path / "formal-trace-index.json"
    trace_artifact.write_text("{}\n", encoding="utf-8")
    channel = _Channel(baseline_health_failures=1)

    report = _runner(tmp_path).run(
        _inputs(),
        channel=channel,
        acceptance=_Acceptance(),
        trace=_Trace(trace_artifact),
    )

    assert report["status"] == "PASS_WITH_USER_ATTESTED_SITE_SAFETY"
    assert channel.restart_count == 1
    assert channel.events.count("PREFLIGHT_RESTART") == 1
    assert channel.events.index("PREFLIGHT_RESTART") < channel.events.index("ISOLATE")
    run_root = Path(report["artifact_index"]).parent
    assert (run_root / "baseline-liveness-initial.json").is_file()
    assert (run_root / "bringup-preflight-restart.json").is_file()
    assert (run_root / "baseline-after-restart.json").is_file()
    assert (run_root / "baseline-liveness.json").is_file()


def test_dead_streams_after_single_restart_never_isolate_or_start(tmp_path: Path) -> None:
    trace_artifact = tmp_path / "formal-trace-index.json"
    trace_artifact.write_text("{}\n", encoding="utf-8")
    channel = _Channel(baseline_health_failures=2)
    trace = _Trace(trace_artifact)

    report = _runner(tmp_path).run(
        _inputs(),
        channel=channel,
        acceptance=_Acceptance(),
        trace=trace,
    )

    assert report["status"] == "BLOCKED"
    assert report["blockers"] == ["N7_PHYSICAL_SENSOR_STREAMS_NOT_FRESH"]
    assert channel.restart_count == 1
    assert "ISOLATE" not in channel.events
    assert "RESTORE" not in channel.events
    assert trace.events == []


def test_dead_prearm_stream_stops_worker_before_restore(tmp_path: Path) -> None:
    trace_artifact = tmp_path / "formal-trace-index.json"
    trace_artifact.write_text("{}\n", encoding="utf-8")
    channel = _Channel(prearm_health_failure=True)
    trace = _Trace(trace_artifact)

    report = _runner(tmp_path).run(
        _inputs(),
        channel=channel,
        acceptance=_Acceptance(),
        trace=trace,
    )

    assert report["status"] == "BLOCKED"
    assert report["blockers"] == ["N7_PHYSICAL_SENSOR_STREAMS_NOT_FRESH"]
    assert trace.events == ["PREPARE_ZERO_MOTION", "STOP"]
    assert channel.events.index("SAMPLE_HEALTH:PREARMED") < channel.events.index("RESTORE")


def test_restore_remote_stops_and_verifies_the_full_bringup_process_group() -> None:
    sigint = '_REMOTE_CONTROL_SOURCE'  # keep assertion failure output compact
    del sigint
    assert 'os.killpg(group["pgid"], signal.SIGINT)' in _REMOTE_CONTROL_SOURCE
    assert 'os.killpg(group["pgid"], signal.SIGTERM)' in _REMOTE_CONTROL_SOURCE
    assert _REMOTE_CONTROL_SOURCE.index('signal.SIGINT)') < _REMOTE_CONTROL_SOURCE.index('signal.SIGTERM)')
    assert 'current != expected' in _REMOTE_CONTROL_SOURCE
    assert 'N7_PHYSICAL_BRINGUP_GROUP_RESIDUAL' in _REMOTE_CONTROL_SOURCE

    invalid = {
        "schema_version": "rolo-n7-bringup-restore/v1",
        "ok": True,
        "stage_root": stage_root_for(RUN_ID),
        "stop_signal": "SIGINT",
        "previous_group": _bringup_group(621),
        "replacement_group": _bringup_group(721),
        "snapshot": _snapshot("RESTORED", isolated=False),
    }
    invalid["previous_group"]["members"][0]["executable"] = "/tmp/untrusted-child"
    with pytest.raises(N7PhysicalBlocked, match="process group member identity"):
        N7PhysicalTraceRunner._validate_restore(
            invalid,
            stage_root=stage_root_for(RUN_ID),
        )


def test_restore_failure_after_call_forces_unknown(tmp_path: Path) -> None:
    trace_artifact = tmp_path / "formal-trace-index.json"
    trace_artifact.write_text("{}\n", encoding="utf-8")
    channel = _Channel(restore_failure=True)
    report = _runner(tmp_path).run(
        _inputs(),
        channel=channel,
        acceptance=_Acceptance(),
        trace=_Trace(trace_artifact),
    )
    assert report["status"] == "UNKNOWN"
    assert report["blockers"] == ["N7_PHYSICAL_RESTORE_NOT_VERIFIED"]
    assert report["stage_cleanup_verified"] is False
    assert report["stage_preserved_for_recovery"] is True
    assert "CLEANUP" not in channel.events


def test_start_response_loss_uses_authenticated_stop_before_restore(tmp_path: Path) -> None:
    trace_artifact = tmp_path / "formal-trace-index.json"
    trace_artifact.write_text("{}\n", encoding="utf-8")
    trace = _Trace(trace_artifact, start_raises=True)
    channel = _Channel()

    report = _runner(tmp_path).run(
        _inputs(),
        channel=channel,
        acceptance=_Acceptance(),
        trace=trace,
    )

    assert report["status"] == "UNKNOWN"
    assert trace.events == ["PREPARE_ZERO_MOTION", "PREFLIGHT_GATE", "CALL", "STOP"]
    assert channel.events[-3:] == ["SNAPSHOT:POST_STOP", "RESTORE", "CLEANUP"]
    assert channel.events.index("SNAPSHOT:POST_STOP") < channel.events.index("RESTORE")
    assert report["authenticated_stop"]["target_stop_acknowledged"] is True


def test_unresolved_query_stops_once_and_never_replays_call(tmp_path: Path) -> None:
    trace_artifact = tmp_path / "formal-trace-index.json"
    trace_artifact.write_text("{}\n", encoding="utf-8")
    trace = _Trace(trace_artifact, first_status="UNKNOWN", query_status="UNKNOWN")

    report = _runner(tmp_path).run(
        _inputs(),
        channel=_Channel(),
        acceptance=_Acceptance(),
        trace=trace,
    )

    assert report["status"] == "UNKNOWN"
    assert report["call_attempt_count"] == 1
    assert report["query_attempt_count"] == 1
    assert trace.events == [
        "PREPARE_ZERO_MOTION",
        "PREFLIGHT_GATE",
        "CALL",
        "QUERY_CALL",
        "STOP",
    ]


def test_unverified_stop_preserves_isolation_and_stage_for_manual_recovery(tmp_path: Path) -> None:
    trace_artifact = tmp_path / "formal-trace-index.json"
    trace_artifact.write_text("{}\n", encoding="utf-8")
    trace = _Trace(
        trace_artifact,
        first_status="UNKNOWN",
        query_status="UNKNOWN",
        stop_safe=False,
    )
    channel = _Channel()

    report = _runner(tmp_path).run(
        _inputs(),
        channel=channel,
        acceptance=_Acceptance(),
        trace=trace,
    )

    assert report["status"] == "UNKNOWN"
    assert report["blockers"] == ["N7_PHYSICAL_STOP_NOT_VERIFIED"]
    assert report["manual_intervention_required"] is True
    assert report["control_publishers_left_isolated"] is True
    assert report["stage_preserved_for_recovery"] is True
    assert "RESTORE" not in channel.events
    assert "CLEANUP" not in channel.events
    assert channel.isolated is True


def test_release_bound_driver_reconciles_unknown_with_resume_only(tmp_path: Path) -> None:
    from tests.test_targetd_physical_worker import _call

    execution_request, manifest = _call(tmp_path / "physical-call")
    session_id = execution_request.session_id
    call_id = execution_request.idempotency_key
    artifact = tmp_path / "trace-index.json"
    artifact.write_text("{}\n", encoding="utf-8")
    call_event = SimpleNamespace(
        event="TOOL_CALL",
        idempotency_key=call_id,
        result=None,
    )
    result_event = SimpleNamespace(
        event="TOOL_RESULT_RECONCILED",
        idempotency_key=call_id,
        result={"status": "SUCCEEDED"},
    )

    class FormalTrace:
        def __init__(self):
            self.run_calls = 0
            self.resume_calls = 0

        def run(self, request, calls):
            self.run_calls += 1
            assert len(calls) == 1
            return (
                SimpleNamespace(
                    session_id=session_id,
                    state=SessionState.UNKNOWN,
                    events=[call_event],
                ),
                {"index": artifact},
            )

        def resume(self, session_id):
            self.resume_calls += 1
            assert session_id == execution_request.session_id
            return (
                SimpleNamespace(
                    session_id=execution_request.session_id,
                    state=SessionState.COMPLETED,
                    events=[call_event, result_event],
                ),
                {"index": artifact},
            )

    formal = FormalTrace()
    request = TraceSessionRequest(
        target_id="mentorpi",
        catalog_digest="f" * 64,
        task="rotate the chassis by one bounded degree",
        mode="SUPERVISED_FIELD_DEBUG",
        ttl_s=60,
        max_calls=1,
        operator_id="operator-1",
        safety_confirmed=True,
        session_id=session_id,
    )
    call = TraceCall(
        tool_id="app.base.rotate",
        arguments=MotionSpec().arguments(),
        idempotency_key=call_id,
    )

    armed = _armed_zero(execution_request, manifest, gid="1" * 32)

    class TypedProofDouble(TargetdPhysicalProofVerifier):
        def __init__(self):
            self.request = execution_request
            self.runtime_sha256 = manifest.observation_contract[
                "provider_runtime_sha256"
            ]

        def verify_trace(self, session, paths, *, acceptance, armed_zero, query_count):
            assert acceptance.call_id == call_id
            assert armed_zero is armed
            success = session.state == SessionState.COMPLETED
            return TraceAttempt(
                status="SUCCEEDED" if success else "UNKNOWN",
                session_id=session.session_id,
                call_id=call_id,
                call_attempt_count=1,
                query_attempt_count=query_count,
                provider_invocation_count=1 if success else 0,
                provider_gate_consumed=success,
                provider_gate_receipt=None,
                controlled_publisher_identities=("/rolo_bounded_twist",) if success else (),
                final_zero_verified=success,
                stop_acknowledged=success,
                provider_terminated=success,
                trace_artifacts=dict(paths),
                result={"status": "SUCCEEDED"} if success else {},
            )

        def authenticated_stop(self, call_id):
            raise AssertionError("successful reconcile must not STOP")

    driver = ReleaseBoundPhysicalTraceDriver(
        formal,
        request,
        call,
        prepare_provider=lambda spec: armed,
        proof_verifier=TypedProofDouble(),
        provider_gate_preflight=lambda receipt: None,
    )
    driver.prepare_zero_motion(MotionSpec())
    acceptance = _ready_receipt().model_copy(
        update={"call_id": call_id, "session_id": session_id}
    )
    first = driver.start_once(acceptance, MotionSpec())
    assert first.status == "UNKNOWN"
    second = driver.query_once(call_id)
    assert second.status == "SUCCEEDED"
    assert formal.run_calls == 1
    assert formal.resume_calls == 1
    with pytest.raises(N7PhysicalBlocked, match="QUERY_CALL"):
        driver.query_once(call_id)


@pytest.mark.parametrize("lose_start_response", [False, True])
def test_prepared_trace_bridge_never_uses_generic_call_and_queries_ambiguity_only(
    tmp_path: Path,
    lose_start_response: bool,
) -> None:
    from tests.test_targetd_physical_worker import _call

    request, manifest = _call(tmp_path / "prepared-bridge")
    armed = _armed_zero(request, manifest)
    client = _PreparedLifecycleClient(
        request,
        armed,
        lose_start_response=lose_start_response,
    )
    bridge = PreparedPhysicalTraceBridge(
        request,
        manifest,
        client,
        gate_payload_factory=_SealedGatePayloadFactory(),
        terminal_query_budget=2,
        poll_interval_s=0,
    )

    assert bridge.prepare_zero_motion(MotionSpec()) == armed
    bridge.bind_provider_gate(SimpleNamespace(call_id=request.idempotency_key))
    dispatch = bridge.call_for_trace(request)

    assert isinstance(dispatch, PreparedPhysicalTraceDispatch)
    assert (
        dispatch.start_response is None
        if lose_start_response
        else dispatch.start_response.frame.payload["request_kind"]
        == "START_PREPARED_CALL"
    )
    assert dispatch.terminal_response.frame.payload["request_kind"] == "QUERY_CALL"
    assert client.kinds == [
        "PREPARE_PHYSICAL_CALL",
        "START_PREPARED_CALL",
        "QUERY_CALL_PHYSICAL",
    ]
    assert "CALL" not in client.kinds
    with pytest.raises(N7PhysicalBlocked, match="already dispatched"):
        bridge.call_for_trace(request)


def test_debug_acceptance_binds_only_target_owned_reference_before_start(
    tmp_path: Path,
) -> None:
    from tests.test_targetd_physical_worker import _call

    point = datetime.now(timezone.utc)
    request, manifest = _call(
        tmp_path / "debug-prepared-bridge",
        deadline=point + timedelta(seconds=30),
    )
    request = _with_landerpi_motion_endpoints(request)
    armed = _armed_zero(request, manifest)
    admission, receipt, frame, start = _debug_acceptance_bundle(
        tmp_path,
        request,
        armed,
        point=point,
    )
    client = _PreparedLifecycleClient(
        request,
        armed,
        debug_acceptance_frame=frame,
    )
    bridge = PreparedPhysicalTraceBridge(
        request,
        manifest,
        client,
        terminal_query_budget=2,
        poll_interval_s=0,
        clock=lambda: point,
    )

    assert bridge.prepare_zero_motion(MotionSpec()) == armed
    assert bridge.accept_debug_zero_motion(admission) == receipt
    substituted = receipt.model_copy(update={"debug_gate_ready": False})
    with pytest.raises(N7PhysicalBlocked, match="target-owned acceptance reference"):
        bridge.bind_provider_gate(substituted)
    bridge.bind_provider_gate(receipt)
    with pytest.raises(N7PhysicalBlocked, match="one-shot"):
        bridge.bind_provider_gate(receipt)
    dispatch = bridge.call_for_trace(request)

    assert dispatch.terminal_response.frame.payload["request_kind"] == "QUERY_CALL"
    assert client.provider_gates == [start]
    assert client.kinds == [
        "PREPARE_PHYSICAL_CALL",
        "ACCEPT_DEBUG_ZERO_MOTION",
        "START_PREPARED_CALL",
        "QUERY_CALL_PHYSICAL",
    ]
    assert "CALL" not in client.kinds


def test_debug_acceptance_cannot_start_before_reference_bind(tmp_path: Path) -> None:
    from tests.test_targetd_physical_worker import _call

    point = datetime.now(timezone.utc)
    request, manifest = _call(
        tmp_path / "debug-bind-required",
        deadline=point + timedelta(seconds=30),
    )
    request = _with_landerpi_motion_endpoints(request)
    armed = _armed_zero(request, manifest)
    admission, _receipt, frame, _start = _debug_acceptance_bundle(
        tmp_path,
        request,
        armed,
        point=point,
    )
    client = _PreparedLifecycleClient(
        request,
        armed,
        debug_acceptance_frame=frame,
    )
    bridge = PreparedPhysicalTraceBridge(
        request,
        manifest,
        client,
        terminal_query_budget=2,
        poll_interval_s=0,
        clock=lambda: point,
    )
    bridge.prepare_zero_motion(MotionSpec())
    bridge.accept_debug_zero_motion(admission)

    with pytest.raises(N7PhysicalBlocked, match="ARMED_ZERO and a sealed gate"):
        bridge.call_for_trace(request)
    assert "START_PREPARED_CALL" not in client.kinds


def test_formal_trace_tool_call_dispatches_only_authenticated_start_prepared(
    tmp_path: Path,
    mapping_confirmation_factory,
) -> None:
    from tests.test_targetd_physical_worker import _call
    from tests.test_targetd_protocol import _execution_request

    _, manifest = _call(tmp_path / "manifest")
    publisher, catalog, release_digest, identity, evidence_digest = (
        _physical_release_fixture(tmp_path, mapping_confirmation_factory, manifest)
    )
    authority = TargetdExecutionAuthority.build(
        tool_id="app.base.rotate",
        target_id="mentorpi",
        target_fingerprint=identity.target_fingerprint,
        bundle_digest=manifest.bundle_digest,
        binding_digest=manifest.binding_digest,
        surface_digest="b" * 64,
        release_digest=release_digest,
        context_digest=identity.context_digest,
        mapping_confirmation_receipt_digest=(
            publisher.current("app.base.rotate")[1].mapping_confirmation_receipt_digest
        ),
        mapping_admission=identity,
        catalog_head_digest="sha256:" + "1" * 64,
        provider_id="ros-container",
        provider_operation="base.rotate",
        mode="SUPERVISED_FIELD_DEBUG",
        fence_epoch=1,
    )
    point = datetime.now(timezone.utc)
    request = _execution_request(
        authority,
        SimpleNamespace(session_id="physical-worker-session"),
        run_id="physical-worker-session",
        idempotency_key="physical-trace-call",
        arguments=MotionSpec().arguments(),
        deadline=point + timedelta(seconds=30),
        motion_now=point,
    )
    armed = _armed_zero(request, manifest)
    client = _PreparedLifecycleClient(request, armed)
    bridge = PreparedPhysicalTraceBridge(
        request,
        manifest,
        client,
        gate_payload_factory=_SealedGatePayloadFactory(),
        terminal_query_budget=2,
        poll_interval_s=0,
        clock=lambda: point,
    )
    adapter = PreparedPhysicalTargetdTraceAdapter(
        authority,
        bridge,
        authority_resolver=lambda _tool_id: authority,
        request_store=DurableTraceRequestStore(tmp_path / "physical-requests"),
        physical_request_factory=lambda _plan, _call, _authority, _now: request,
        clock=lambda: point,
    )
    trace = ReleaseBoundTrace(
        catalog,
        publisher,
        release_digest=release_digest,
        target_fingerprint=identity.target_fingerprint,
        evidence_digest=evidence_digest,
        compile_context_digest=identity.context_digest,
        invoker=adapter,
        artifact_root=tmp_path / "formal-physical-trace",
    )

    bridge.prepare_zero_motion(MotionSpec())
    bridge.bind_provider_gate(SimpleNamespace(call_id=request.idempotency_key))
    session, paths = trace.run(
        TraceSessionRequest(
            target_id="mentorpi",
            catalog_digest=catalog.digest or "",
            task="rotate the chassis by one bounded degree",
            mode="SUPERVISED_FIELD_DEBUG",
            ttl_s=60,
            max_calls=1,
            operator_id="test-operator:onsite",
            safety_confirmed=True,
            session_id="physical-worker-session",
        ),
        [
            TraceCall(
                tool_id="app.base.rotate",
                arguments=MotionSpec().arguments(),
                idempotency_key="physical-trace-call",
            )
        ],
    )

    assert session.state == SessionState.COMPLETED
    assert _tool_call_count_for_test(session, "physical-trace-call") == 1
    assert client.kinds == [
        "PREPARE_PHYSICAL_CALL",
        "START_PREPARED_CALL",
        "QUERY_CALL_PHYSICAL",
    ]
    assert "CALL" not in client.kinds
    assert any(key.startswith("receipt:") for key in paths)
    assert "targetd-trace-receipt:" in paths["events"].read_text(encoding="utf-8")


def _tool_call_count_for_test(session, call_id: str) -> int:
    return sum(
        event.event == "TOOL_CALL" and event.idempotency_key == call_id
        for event in session.events
    )


def test_process_identity_requires_exact_node_executable_pid_start_and_argv_digest() -> None:
    value = _processes()[0]
    identity = PublisherProcessIdentity.parse(value)
    assert identity.executable == PUBLISHER_PROCESS_ALLOWLIST[identity.node_id]
    assert identity.launch_argv_prefix == ("/usr/bin/python3", identity.executable)
    for field, replacement in (
        ("executable", "/tmp/fake"),
        ("pid", 1),
        ("start_ticks", 0),
        ("argv_sha256", "sha256:bad"),
        ("launch_argv_prefix", ["/usr/bin/python3", "/tmp/fake"]),
    ):
        changed = dict(value)
        changed[field] = replacement
        with pytest.raises(N7PhysicalBlocked, match="allowlist"):
            PublisherProcessIdentity.parse(changed)


def test_remote_publisher_identity_accepts_only_native_or_python_allowlisted_prefix() -> None:
    compile(_REMOTE_CONTROL_SOURCE, "<n7-remote>", "exec")
    assert 'argv[0] == executable' in _REMOTE_CONTROL_SOURCE
    assert 'argv[0] == "/usr/bin/python3" and argv[1] == executable' in _REMOTE_CONTROL_SOURCE
    assert '"launch_argv_prefix": launch_argv_prefix' in _REMOTE_CONTROL_SOURCE
    assert 'expected_argv = item["launch_argv_prefix"]' in _REMOTE_CONTROL_SOURCE
    assert '["/usr/bin/python3", item["executable"]]' in _REMOTE_CONTROL_SOURCE
    assert "time.monotonic_ns()" in _REMOTE_CONTROL_SOURCE
    assert '"arrival_clocks_ns":samples' in _REMOTE_CONTROL_SOURCE
    assert "ended_wall_ns - (ended_mono_ns - mono_stamps[-1])" in _REMOTE_CONTROL_SOURCE
    assert _REMOTE_CONTROL_SOURCE.index("subscriptions.clear()") < _REMOTE_CONTROL_SOURCE.index(
        '"SENSOR_POST"'
    )


def _remote_graph_wait_namespace(monkeypatch):
    definitions = _REMOTE_CONTROL_SOURCE.split(
        "try:\n    raw = sys.stdin.buffer.read",
        1,
    )[0]
    namespace: dict[str, object] = {}
    exec(definitions, namespace)

    class Clock:
        value = 0.0

        @classmethod
        def monotonic(cls):
            return cls.value

    def spin_once(_node, *, timeout_sec):
        Clock.value += max(0.01, timeout_sec)

    monkeypatch.setitem(
        sys.modules,
        "rclpy",
        SimpleNamespace(spin_once=spin_once),
    )
    namespace["time"] = SimpleNamespace(monotonic=Clock.monotonic)
    return namespace


def _remote_baseline_expectation():
    full = _snapshot("BASELINE", isolated=False)
    expected = {
        key: full[key]
        for key in (
            "command_publishers",
            "command_subscribers",
            "competing_publishers",
            "competing_subscribers",
            "direct_motor_publishers",
            "direct_motor_subscribers",
        )
    }
    partial = json.loads(json.dumps(full))
    partial["competing_publishers"] = partial["competing_publishers"][:3]
    partial["competing_publisher_gids"] = partial["competing_publisher_gids"][:3]
    return full, partial, expected


def test_remote_graph_discovery_waits_for_two_stable_exact_observations(
    monkeypatch,
) -> None:
    namespace = _remote_graph_wait_namespace(monkeypatch)
    full, partial, expected = _remote_baseline_expectation()
    observations = iter((partial, full, full))
    namespace["graph_snapshot"] = lambda _node, _phase: next(observations)

    result = namespace["wait_expected_graph_node"](
        object(),
        "BASELINE",
        expected,
        True,
        2.0,
    )

    assert result is full


def test_remote_graph_discovery_rejects_persistently_incomplete_snapshot(
    monkeypatch,
) -> None:
    namespace = _remote_graph_wait_namespace(monkeypatch)
    _full, partial, expected = _remote_baseline_expectation()
    namespace["graph_snapshot"] = lambda _node, _phase: partial

    with pytest.raises(
        namespace["Blocked"],
        match="N7_PHYSICAL_GRAPH_DISCOVERY_TIMEOUT",
    ):
        namespace["wait_expected_graph_node"](
            object(),
            "BASELINE",
            expected,
            True,
            0.5,
        )


def test_remote_bringup_group_allows_only_known_dbus_autolaunch_helper() -> None:
    definitions = _REMOTE_CONTROL_SOURCE.split("\ntry:\n    raw", 1)[0]
    namespace: dict[str, object] = {}
    exec(compile(definitions, "<remote-control-fixture>", "exec"), namespace)

    allowed = namespace["allowed_bringup_member"]
    assert allowed({"executable": "python3"}) is True
    assert allowed({"executable": "dbus-launch"}) is True
    assert (
        allowed(
            {
                "executable": (
                    "/home/ubuntu/third_party_ros2/third_party_ws/install/"
                    "imu_calib/lib/imu_calib/apply_calib"
                )
            }
        )
        is True
    )
    assert allowed({"executable": "/bin/bash"}) is False


def test_remote_bringup_group_accepts_only_exact_captured_zombie(
    tmp_path: Path,
) -> None:
    definitions = _REMOTE_CONTROL_SOURCE.split("\ntry:\n    raw", 1)[0]
    namespace: dict[str, object] = {}
    exec(compile(definitions, "<remote-control-fixture>", "exec"), namespace)
    entry = tmp_path / "3079"
    entry.mkdir()
    fields = ["Z", *(["0"] * 18), "1282531"]
    (entry / "stat").write_text(
        "3079 (dbus-launch) " + " ".join(fields),
        encoding="ascii",
    )

    exact_zombie = namespace["exact_stopped_zombie"]
    assert exact_zombie(entry, {"start_ticks": 1_282_531}) is True
    assert exact_zombie(entry, None) is True
    assert exact_zombie(entry, {"start_ticks": 1_282_532}) is False
    fields[0] = "S"
    (entry / "stat").write_text(
        "3079 (dbus-launch) " + " ".join(fields),
        encoding="ascii",
    )
    assert exact_zombie(entry, {"start_ticks": 1_282_531}) is False


def test_prepared_lifecycle_surfaces_authenticated_targetd_error(
    tmp_path: Path,
) -> None:
    from tests.test_targetd_physical_worker import _call

    request, _manifest = _call(tmp_path / "lifecycle-error")
    bridge = object.__new__(PreparedPhysicalTraceBridge)
    bridge.request = request
    frame = ProtocolFrame.create(
        kind=FrameKind.RESULT,
        sequence=1,
        session_id=request.session_id,
        run_id=request.run_id,
        payload={
            "request_kind": FrameKind.PREPARE_PHYSICAL_CALL.value,
            "ok": False,
            "error": "TARGETD_PHYSICAL_PROCESS_PREPARE_FAILED",
            "provider_invocation_count": 0,
        },
    )

    with pytest.raises(N7PhysicalBlocked) as caught:
        bridge._parse_response(
            frame,
            expected_kind=FrameKind.PREPARE_PHYSICAL_CALL,
            expected_run_id=request.run_id,
        )

    assert caught.value.code == "TARGETD_PHYSICAL_PROCESS_PREPARE_FAILED"


def test_stop_parser_surfaces_authenticated_targetd_error(tmp_path: Path) -> None:
    from tests.test_targetd_physical_worker import _call

    request, _manifest = _call(tmp_path / "stop-error")
    verifier = object.__new__(TargetdPhysicalProofVerifier)
    verifier.request = request
    frame = ProtocolFrame.create(
        kind=FrameKind.RESULT,
        sequence=1,
        session_id=request.session_id,
        payload={
            "request_kind": FrameKind.STOP.value,
            "ok": False,
            "error": "TARGETD_PHYSICAL_PROCESS_NO_WORKER",
        },
    )

    with pytest.raises(N7PhysicalBlocked) as caught:
        verifier._parse_control_response(
            TargetdTraceResponse(frame=frame, sequence_correlated=True),
            expected_kind=FrameKind.STOP,
        )

    assert caught.value.code == "TARGETD_PHYSICAL_PROCESS_NO_WORKER"


@pytest.mark.parametrize("error", ["", "targetd_failed", "TARGETD-FAILED"])
def test_lifecycle_rejects_non_code_error_payload(
    tmp_path: Path,
    error: str,
) -> None:
    from tests.test_targetd_physical_worker import _call

    request, _manifest = _call(tmp_path / "invalid-error")
    bridge = object.__new__(PreparedPhysicalTraceBridge)
    bridge.request = request
    frame = ProtocolFrame.create(
        kind=FrameKind.RESULT,
        sequence=1,
        session_id=request.session_id,
        run_id=request.run_id,
        payload={
            "request_kind": FrameKind.PREPARE_PHYSICAL_CALL.value,
            "ok": False,
            "error": error,
        },
    )

    with pytest.raises(N7PhysicalBlocked) as caught:
        bridge._parse_response(
            frame,
            expected_kind=FrameKind.PREPARE_PHYSICAL_CALL,
            expected_run_id=request.run_id,
        )

    assert caught.value.code == "N7_PHYSICAL_LIFECYCLE_RESPONSE_INVALID"
