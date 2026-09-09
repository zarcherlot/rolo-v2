import ast
import base64
import hashlib
import json
import re
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

import rolo.targetd.worker as worker_module
from rolo.core.hashing import canonical_json_sha256
from rolo.dsl.admission import (
    MappingAdmissionError,
    MappingAdmissionIdentity,
    MappingAdmissionScope,
    MappingConfirmationStore,
    mapping_digest,
)
from rolo.dsl.models import OperationKind
from rolo.releases.publisher import ToolRelease, tool_release_digest
from rolo.targetd import (
    BundleCache,
    ExecutionBundleManifest,
    ExecutionRequest,
    ExecutionRequestV3,
    FrameKind,
    JourneyPhase,
    JourneySession,
    JourneySessionClient,
    ProtocolFrame,
    TargetdAuthorityActivationRequest,
    TargetdCallReceipt,
    TargetdExecutionAuthority,
    TargetdExecutionAuthorityStore,
    TargetdMappingCancelRequest,
    TargetdReleaseCatalog,
    TargetdService,
    TargetdStateStore,
    TargetdVerifiedReleaseProvisionRequest,
    decode_frame,
    encode_frame,
    execution_subject_digest,
    requires_motion_safety,
    validate_execution_request,
)
from rolo.targetd.daemon import Ros2ReadOnlyProvider, TargetdDaemon, _public_error_code
from rolo.targetd.dsl_protocol import DslFrame, DslFrameType
from rolo.targetd.motion_safety import (
    MotionSafetyAdmissionRequest,
    MotionSafetyEvidenceBundle,
    MotionSafetyIntent,
    MotionSafetyPolicy,
    SignedMotionEvidence,
    compute_direct_motor_fence_digest,
    compute_estop_response_digest,
    compute_ros_graph_digest,
    compute_stop_action_digest,
)
from rolo.targetd.process_worker import ProcessWorkerError
from rolo.targetd.protocol import ProtocolError
from rolo.targetd.ros2_runtime import Ros2RuntimeResolver, Ros2RuntimeSnapshot, parse_ros2_topic_types
from rolo.targetd.runtime_backend import ros2_registry
from rolo.targetd.worker import PythonBundleWorker, RosContainerProvider

_MOTION_COMMAND_ROUTE = "/test/cmd_vel"
_MOTION_COMMAND_INTERFACE = "geometry_msgs/msg/Twist"
_MOTION_PUBLISHER = "targetd:test-motion-provider"
_MOTION_DIRECT_ROUTE = "/test/direct_motor"
_MOTION_DIRECT_INTERFACE = "std_msgs/msg/Float64MultiArray"
_MOTION_DIRECT_PUBLISHER = "targetd:test-direct-motor-bridge"
_MOTION_ISSUERS = {
    "operator": "test-authority:operator",
    "presence": "test-authority:presence",
    "safety": "test-authority:safety",
    "graph": "test-authority:graph",
    "target": "test-authority:target",
}


def test_targetd_public_error_allows_only_code_shaped_process_failures() -> None:
    assert (
        _public_error_code(
            ProcessWorkerError("PHYSICAL_WORKER_ARMED_ZERO_TOPOLOGY_UNAVAILABLE")
        )
        == "PHYSICAL_WORKER_ARMED_ZERO_TOPOLOGY_UNAVAILABLE"
    )
    assert (
        _public_error_code(ProcessWorkerError("sensitive free-form detail"))
        == "TARGETD_REQUEST_VALIDATION_FAILED"
    )


_MOTION_KEYS = {
    _MOTION_ISSUERS["operator"]: b"o" * 32,
    _MOTION_ISSUERS["presence"]: b"p" * 32,
    _MOTION_ISSUERS["safety"]: b"s" * 32,
    _MOTION_ISSUERS["graph"]: b"g" * 32,
    _MOTION_ISSUERS["target"]: b"t" * 32,
}


def _motion_policy(authority: TargetdExecutionAuthority) -> MotionSafetyPolicy:
    return MotionSafetyPolicy(
        target_id=authority.target_id,
        target_identity=authority.mapping_admission.target_identity_digest,
        site_id="test-site:lab",
        safe_zone_id="test-zone:pad",
        command_route=_MOTION_COMMAND_ROUTE,
        command_interface=_MOTION_COMMAND_INTERFACE,
        allowed_publisher_identity=_MOTION_PUBLISHER,
        direct_motor_route=_MOTION_DIRECT_ROUTE,
        direct_motor_interface=_MOTION_DIRECT_INTERFACE,
        allowed_direct_motor_publisher_identity=_MOTION_DIRECT_PUBLISHER,
        operator_authority_id=_MOTION_ISSUERS["operator"],
        presence_authority_id=_MOTION_ISSUERS["presence"],
        safety_authority_id=_MOTION_ISSUERS["safety"],
        graph_authority_id=_MOTION_ISSUERS["graph"],
        target_authority_id=_MOTION_ISSUERS["target"],
        max_graph_age_s=5,
        max_attestation_age_s=30,
    )


def _synthetic_motion_admission(
    authority: TargetdExecutionAuthority,
    *,
    execution_digest: str,
    call_id: str,
    session_id: str,
    now: datetime,
    publishers: list[str] | None = None,
    direct_motor_publishers: list[str] | None = None,
    fence_epoch: int | None = None,
) -> MotionSafetyAdmissionRequest:
    """Build signed synthetic evidence; this never observes or drives hardware."""

    policy = _motion_policy(authority)
    command_publishers = [_MOTION_PUBLISHER] if publishers is None else publishers
    motor_publishers = (
        [_MOTION_DIRECT_PUBLISHER]
        if direct_motor_publishers is None
        else direct_motor_publishers
    )
    graph_at = now - timedelta(seconds=1)
    attestation_at = now - timedelta(seconds=1)
    target_identity = authority.mapping_admission.target_identity_digest
    motion_fence_epoch = authority.fence_epoch if fence_epoch is None else fence_epoch
    graph_digest = compute_ros_graph_digest(
        target_id=authority.target_id,
        target_identity=target_identity,
        observed_at=graph_at,
        command_route=policy.command_route,
        command_interface=policy.command_interface,
        publisher_identities=command_publishers,
        direct_motor_route=policy.direct_motor_route,
        direct_motor_interface=policy.direct_motor_interface,
        direct_motor_publisher_identities=motor_publishers,
    )
    fence_digest = compute_direct_motor_fence_digest(
        execution_subject_digest=execution_digest,
        call_id=call_id,
        session_id=session_id,
        target_id=authority.target_id,
        target_identity=target_identity,
        ros_graph_digest=graph_digest,
        command_route=policy.command_route,
        publisher_identity=policy.allowed_publisher_identity,
        direct_motor_route=policy.direct_motor_route,
        direct_motor_interface=policy.direct_motor_interface,
        direct_motor_publisher_identity=(
            policy.allowed_direct_motor_publisher_identity
        ),
        fence_epoch=motion_fence_epoch,
    )
    stop_digest = compute_stop_action_digest(
        execution_subject_digest=execution_digest,
        call_id=call_id,
        session_id=session_id,
        target_id=authority.target_id,
        target_identity=target_identity,
        ros_graph_digest=graph_digest,
        command_route=policy.command_route,
        publisher_identity=policy.allowed_publisher_identity,
        direct_motor_route=policy.direct_motor_route,
        direct_motor_interface=policy.direct_motor_interface,
        direct_motor_publisher_identity=(
            policy.allowed_direct_motor_publisher_identity
        ),
        direct_motor_fence_digest=fence_digest,
    )
    operator_id = "test-operator:onsite"
    intent = MotionSafetyIntent(
        call_id=call_id,
        session_id=session_id,
        target_id=authority.target_id,
        target_identity=target_identity,
        operator_id=operator_id,
        execution_subject_digest=execution_digest,
        requested_at=attestation_at,
        ros_graph_digest=graph_digest,
        command_route=policy.command_route,
        command_interface=policy.command_interface,
        publisher_identity=policy.allowed_publisher_identity,
        direct_motor_route=policy.direct_motor_route,
        direct_motor_interface=policy.direct_motor_interface,
        direct_motor_publisher_identity=(
            policy.allowed_direct_motor_publisher_identity
        ),
        direct_motor_fence_digest=fence_digest,
        stop_action_digest=stop_digest,
    )
    common = {
        "call_id": call_id,
        "session_id": session_id,
        "target_id": authority.target_id,
        "target_identity": target_identity,
        "operator_id": operator_id,
        "execution_subject_digest": execution_digest,
        "ros_graph_digest": graph_digest,
        "issued_at": attestation_at,
        "expires_at": attestation_at + timedelta(seconds=30),
    }

    def signed(
        evidence_id: str,
        kind,
        issuer_id: str,
        claims: dict,
        *,
        graph: bool = False,
    ) -> SignedMotionEvidence:
        identity = dict(common)
        if graph:
            identity.update(
                issued_at=graph_at,
                expires_at=graph_at + timedelta(seconds=5),
            )
        return SignedMotionEvidence.build(
            evidence_id=evidence_id,
            kind=kind,
            issuer_id=issuer_id,
            claims=claims,
            signing_key=_MOTION_KEYS[issuer_id],
            **identity,
        )

    challenge_digest = mapping_digest({"kind": "test-estop-challenge"})
    evidence = MotionSafetyEvidenceBundle(
        operator_authorization=signed(
            "test-evidence-operator",
            "OPERATOR_AUTHORIZATION",
            _MOTION_ISSUERS["operator"],
            {
                "authorization_id": "test-motion-authorization",
                "authorized": True,
                "motion_scope": "PHYSICAL_MOTION",
                "operator_id": operator_id,
            },
        ),
        onsite_presence=signed(
            "test-evidence-presence",
            "ONSITE_PRESENCE",
            _MOTION_ISSUERS["presence"],
            {
                "operator_id": operator_id,
                "presence_method": "ON_SITE_CHALLENGE",
                "present": True,
                "site_id": policy.site_id,
            },
        ),
        safe_zone_confirmation=signed(
            "test-evidence-zone",
            "SAFE_ZONE_CONFIRMATION",
            _MOTION_ISSUERS["safety"],
            {
                "confirmed_clear": True,
                "safe_zone_id": policy.safe_zone_id,
                "site_id": policy.site_id,
            },
        ),
        estop_verification=signed(
            "test-evidence-estop",
            "ESTOP_VERIFICATION",
            _MOTION_ISSUERS["safety"],
            {
                "available": True,
                "challenge_digest": challenge_digest,
                "engage_verified": True,
                "release_verified": True,
                "response_digest": compute_estop_response_digest(
                    execution_subject_digest=execution_digest,
                    challenge_digest=challenge_digest,
                    call_id=call_id,
                    session_id=session_id,
                    target_id=authority.target_id,
                    target_identity=target_identity,
                    ros_graph_digest=graph_digest,
                ),
                "verification_method": "TARGET_CHALLENGE_RESPONSE",
            },
        ),
        ros_graph_snapshot=signed(
            "test-evidence-graph",
            "ROS_GRAPH_SNAPSHOT",
            _MOTION_ISSUERS["graph"],
            {
                "command_interface": policy.command_interface,
                "command_route": policy.command_route,
                "direct_motor_interface": policy.direct_motor_interface,
                "direct_motor_publisher_identities": motor_publishers,
                "direct_motor_route": policy.direct_motor_route,
                "publisher_identities": command_publishers,
            },
            graph=True,
        ),
        direct_motor_fence=signed(
            "test-evidence-fence",
            "DIRECT_MOTOR_FENCE",
            _MOTION_ISSUERS["target"],
            {
                "active": True,
                "direct_access_blocked": True,
                "direct_motor_interface": policy.direct_motor_interface,
                "direct_motor_route": policy.direct_motor_route,
                "fence_digest": fence_digest,
                "fence_epoch": motion_fence_epoch,
                "owner_identity": _MOTION_ISSUERS["target"],
                "publisher_identity": (
                    policy.allowed_direct_motor_publisher_identity
                ),
            },
        ),
        target_stop_acknowledgement=signed(
            "test-evidence-stop",
            "TARGET_STOP_ACKNOWLEDGEMENT",
            _MOTION_ISSUERS["target"],
            {
                "acknowledged": True,
                "owner_identity": _MOTION_ISSUERS["target"],
                "stop_action_digest": stop_digest,
                "target_owned": True,
            },
        ),
    )
    return MotionSafetyAdmissionRequest(intent=intent, evidence=evidence)


def test_targetd_daemon_import_does_not_require_control_plane_dependencies(tmp_path: Path) -> None:
    source_root = Path(__file__).resolve().parents[1] / "src"
    program = f"""
import importlib.abc
import sys

sys.path.insert(0, {str(source_root)!r})

class BlockControlPlaneDependencies(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        blocked = {{"tomli", "tomllib", "pydantic_settings", "typer", "fastapi"}}
        if fullname.split(".", 1)[0] in blocked:
            raise ModuleNotFoundError(f"{{fullname}} is intentionally unavailable", name=fullname)
        return None

sys.meta_path.insert(0, BlockControlPlaneDependencies())

from rolo.targetd.daemon import TargetdDaemon
import rolo.core as core

assert TargetdDaemon.__module__ == "rolo.targetd.daemon"
assert {{"Settings", "get_settings"}} <= set(dir(core))
assert "rolo.core.config" not in sys.modules
assert not ({{"tomli", "tomllib", "pydantic_settings", "typer", "fastapi"}} & set(sys.modules))
assert "rolo.releases.journey" not in sys.modules
assert "rolo.releases.consumers" not in sys.modules
assert not any(name == "rolo.mvp" or name.startswith("rolo.mvp.") for name in sys.modules)
assert not any(name == "rolo.stages.probe" or name.startswith("rolo.stages.probe.") for name in sys.modules)
"""
    completed = subprocess.run(
        [sys.executable, "-c", program],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr


def test_releases_lazy_exports_preserve_from_import_and_dir_compatibility(tmp_path: Path) -> None:
    source_root = Path(__file__).resolve().parents[1] / "src"
    program = f"""
import sys

sys.path.insert(0, {str(source_root)!r})

import rolo.releases as releases

assert "PostCompilerJourney" in releases.__all__
assert "PostCompilerJourney" in dir(releases)
assert "rolo.releases.journey" not in sys.modules
assert "rolo.releases.consumers" not in sys.modules

from rolo.releases import PostCompilerJourney
from rolo.releases.journey import PostCompilerJourney as DirectPostCompilerJourney

assert PostCompilerJourney is DirectPostCompilerJourney
assert releases.PostCompilerJourney is DirectPostCompilerJourney
assert "rolo.releases.journey" in sys.modules
"""
    completed = subprocess.run(
        [sys.executable, "-c", program],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr


def test_core_settings_exports_remain_compatible() -> None:
    from rolo.core import Settings, get_settings
    from rolo.core.config import Settings as DirectSettings
    from rolo.core.config import get_settings as direct_get_settings

    assert Settings is DirectSettings
    assert get_settings is direct_get_settings


def _embedded_provider_request(program: str) -> dict:
    """Decode the JSON argv payload emitted by ``RosContainerProvider``."""

    match = re.search(r"sys\.argv = \['rolo_bounded_twist', (.+)\]\n", program)
    assert match is not None
    return json.loads(ast.literal_eval(match.group(1)))


def _verified_rotation_result(**overrides):
    result = {
        "status": "SUCCEEDED",
        "stop_published": True,
        "physical_stop_verified": True,
        "stopped_observed": True,
        "angle_accuracy_verified": True,
        "independent_motion_evidence": {
            "status": "VERIFIED",
            "independent_of_odom": True,
            "settled": True,
            "angle_accuracy_status": "VERIFIED",
            "target_angle_error_rad": 0.001,
            "target_angle_tolerance_rad": 0.005,
        },
    }
    result.update(overrides)
    return result


def _execution_setup(
    tmp_path,
    manifest,
    source,
    *,
    provider_id="targetd-python",
    provider_operation=None,
    operation_kind=OperationKind.EXECUTE,
    journey_session_id="execution-session",
):
    now = datetime.now(timezone.utc)
    operation = provider_operation or manifest.tool_id
    context_value = mapping_digest({"kind": "context", "tool_id": manifest.tool_id})
    scope = MappingAdmissionScope(
        tool_id=manifest.tool_id,
        operation_kind=operation_kind,
        operations=(operation,),
        access="read" if operation_kind == OperationKind.OBSERVE else "experimental_write",
        risk="R0" if operation_kind == OperationKind.OBSERVE else "R3",
    )
    identity = MappingAdmissionIdentity.build(
        journey_session_id=journey_session_id,
        target_id="mentorpi",
        target_fingerprint="mentorpi:test-fingerprint",
        candidate_index_digest=mapping_digest({"kind": "candidate-index"}),
        candidate_digest=mapping_digest({"kind": "candidate"}),
        proposal_digest=mapping_digest({"kind": "proposal"}),
        dsl_digest=mapping_digest({"kind": "dsl", "tool_id": manifest.tool_id}),
        context_digest=context_value,
        evidence_digest=mapping_digest({"kind": "evidence"}),
        available_tool_catalog_digest=mapping_digest({"kind": "available-catalog"}),
        scope=scope,
    )
    confirmations = MappingConfirmationStore(tmp_path / "admission", clock=lambda: now)
    receipt = confirmations.confirm(
        identity,
        decision_id="decision-1",
        actor_id="test-operator",
        ttl_s=900,
        decided_at=now,
    )
    authority = TargetdExecutionAuthority.build(
        tool_id=manifest.tool_id,
        target_id="mentorpi",
        target_fingerprint=identity.target_fingerprint,
        bundle_digest=manifest.bundle_digest,
        binding_digest=manifest.binding_digest,
        surface_digest="b" * 64,
        release_digest=mapping_digest({"kind": "release"}),
        context_digest=context_value,
        mapping_confirmation_receipt_digest=receipt.receipt_digest,
        mapping_admission=identity,
        catalog_head_digest=mapping_digest({"kind": "release-catalog-head"}),
        provider_id=provider_id,
        provider_operation=operation,
        mode="SUPERVISED_FIELD_DEBUG",
        fence_epoch=1,
    )
    authority_store = TargetdExecutionAuthorityStore(tmp_path / "authority")
    authority_store.publish(authority)
    service = TargetdService(
        target_id="mentorpi",
        state_root=tmp_path / "state",
        confirmation_store=confirmations,
        execution_authority_store=authority_store,
    )
    service.put_bundle(manifest, source)
    return service, authority, confirmations, authority_store


def _readonly_manifest(tool_id: str, source: bytes) -> ExecutionBundleManifest:
    return ExecutionBundleManifest.build(
        tool_id=tool_id,
        source=source,
        binding_digest="a" * 64,
        signer_key_id="rolo-dev",
        signing_key=b"secret",
        observation_contract={
            "provider": "ros2-readonly",
            "operation": "odom.sample",
        },
    )


def _readonly_execution_setup(
    tmp_path,
    manifest: ExecutionBundleManifest,
    source: bytes,
    *,
    journey_session_id: str,
):
    return _execution_setup(
        tmp_path,
        manifest,
        source,
        provider_id="ros2-readonly",
        provider_operation="odom.sample",
        operation_kind=OperationKind.OBSERVE,
        journey_session_id=journey_session_id,
    )


def _execution_session(service, authority, session_id):
    session = JourneySession.create(
        session_id=session_id,
        target_id="mentorpi",
        profile_id="landerpi",
    ).model_copy(update={"phase": JourneyPhase.TRACE, "surface_digest": authority.surface_digest})
    return service.open_session(session)


def _execution_request(
    authority,
    session,
    *,
    run_id="run-1",
    idempotency_key="call-1",
    arguments=None,
    deadline=None,
    force_v2=False,
    motion_now=None,
    publishers=None,
    direct_motor_publishers=None,
    motion_fence_epoch=None,
):
    request_version = (
        "rolo-execution-request/v3"
        if requires_motion_safety(authority) and not force_v2
        else "rolo-execution-request/v2"
    )
    payload = {
        "schema_version": request_version,
        "run_id": run_id,
        "session_id": session.session_id,
        "target_id": authority.target_id,
        "idempotency_key": idempotency_key,
        "bundle_digest": authority.bundle_digest,
        "binding_digest": authority.binding_digest,
        "surface_digest": authority.surface_digest,
        "release_digest": authority.release_digest,
        "context_digest": authority.context_digest,
        "mapping_confirmation_receipt_digest": (
            authority.mapping_confirmation_receipt_digest
        ),
        "authority_head_digest": authority.authority_head_digest,
        "fence_epoch": authority.fence_epoch,
        "provider_id": authority.provider_id,
        "provider_operation": authority.provider_operation,
        "authority": authority,
        "arguments": arguments or {},
        "mode": authority.mode,
        "deadline": deadline or datetime.now(timezone.utc) + timedelta(seconds=30),
    }
    if request_version == "rolo-execution-request/v2":
        return ExecutionRequest.model_validate(payload)
    subject_digest = execution_subject_digest(payload)
    admission = _synthetic_motion_admission(
        authority,
        execution_digest=subject_digest,
        call_id=idempotency_key,
        session_id=session.session_id,
        now=motion_now or datetime.now(timezone.utc),
        publishers=publishers,
        direct_motor_publishers=direct_motor_publishers,
        fence_epoch=motion_fence_epoch,
    )
    return ExecutionRequestV3.model_validate(
        {
            **payload,
            "execution_subject_digest": subject_digest,
            "motion_safety_admission": admission,
        }
    )


def _activation_setup(tmp_path, *, session_id="activation-session"):
    now = datetime.now(timezone.utc)
    tool_id = "app.observe.odom"
    operation = "odom.sample"
    generated_bundle_digest = mapping_digest({"kind": "bundle-plan"})
    scope = MappingAdmissionScope(
        tool_id=tool_id,
        operation_kind=OperationKind.OBSERVE,
        operations=(operation,),
        access="read",
        risk="R0",
    )
    identity = MappingAdmissionIdentity.build(
        journey_session_id=session_id,
        target_id="mentorpi",
        target_fingerprint="mentorpi:activation-fingerprint",
        candidate_index_digest=mapping_digest({"kind": "candidate-index"}),
        candidate_digest=mapping_digest({"kind": "candidate"}),
        proposal_digest=mapping_digest({"kind": "proposal"}),
        dsl_digest=mapping_digest({"kind": "dsl", "tool_id": tool_id}),
        context_digest=mapping_digest({"kind": "context", "tool_id": tool_id}),
        evidence_digest=mapping_digest({"kind": "evidence"}),
        available_tool_catalog_digest=mapping_digest({"kind": "available-catalog"}),
        scope=scope,
    )
    confirmations = MappingConfirmationStore(
        tmp_path / "admission",
        clock=lambda: now,
    )
    confirmation = confirmations.confirm(
        identity,
        decision_id="activation-confirmation",
        actor_id="test-operator",
        ttl_s=900,
        decided_at=now,
    )
    release = ToolRelease(
        tool_id=tool_id,
        target_id="mentorpi",
        operation_kind="OBSERVE",
        dsl_digest=identity.dsl_digest,
        ir_digest=mapping_digest({"kind": "ir"}),
        probe_evidence_digest=identity.evidence_digest,
        compiler_version="test-compiler",
        generated_bundle_digest=generated_bundle_digest,
        conformance_digest=mapping_digest({"kind": "compiler-conformance"}),
        target_fingerprint=identity.target_fingerprint,
        compile_context_digest=identity.context_digest,
        target_conformance_digest=mapping_digest({"kind": "target-conformance"}),
        mapping_confirmation_receipt_digest=confirmation.receipt_digest,
        mapping_admission=identity,
    )
    release_digest = tool_release_digest(release)
    catalog_root = tmp_path / "catalog"
    release_path = catalog_root / "releases" / f"{release_digest.removeprefix('sha256:')}.json"
    release_path.parent.mkdir(parents=True)
    release_path.write_text(
        json.dumps(release.model_dump(mode="json"), sort_keys=True),
        encoding="utf-8",
    )
    (catalog_root / "tool-catalog.json").write_text(
        json.dumps(
            {
                "schema_version": "rolo-tool-catalog/v1",
                "tools": {
                    tool_id: {
                        "current": release_digest,
                        "release": release.model_dump(mode="json"),
                    }
                },
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    source = b"raise RuntimeError('signed source must not run for readonly')\n"
    manifest = ExecutionBundleManifest.build(
        tool_id=tool_id,
        source=source,
        binding_digest="a" * 64,
        signer_key_id="rolo-dev",
        signing_key=b"secret",
        observation_contract={
            "provider": "ros2-readonly",
            "operation": operation,
            "mode": "SUPERVISED_FIELD_DEBUG",
            "generated_bundle_digest": generated_bundle_digest,
        },
        release_version=release_digest,
    )
    authority_store = TargetdExecutionAuthorityStore(tmp_path / "authority")
    service = TargetdService(
        target_id="mentorpi",
        state_root=tmp_path / "state",
        signing_key=b"secret",
        confirmation_store=confirmations,
        execution_authority_store=authority_store,
        release_catalog=TargetdReleaseCatalog(catalog_root),
    )
    service.put_bundle(manifest, source)
    session = JourneySession.create(
        session_id=session_id,
        target_id="mentorpi",
        profile_id="landerpi",
    ).model_copy(
        update={
            "phase": JourneyPhase.TRACE,
            "surface_digest": "b" * 64,
        }
    )
    service.open_session(session)
    activation = TargetdAuthorityActivationRequest(
        schema_version="rolo-targetd-authority-activation/v1",
        tool_id=tool_id,
        release_digest=release_digest,
        bundle_digest=manifest.bundle_digest,
        expected_current_authority_head_digest=None,
    )
    return (
        service,
        session,
        activation,
        manifest,
        source,
        confirmations,
        authority_store,
    )


def _verified_release_inputs(release: ToolRelease) -> dict:
    assert release.mapping_admission is not None
    assert release.mapping_confirmation_receipt_digest is not None
    assert release.compile_context_digest is not None
    assert release.target_conformance_digest is not None
    return {
        "tool_id": release.tool_id,
        "target_id": release.target_id,
        "operation_kind": release.operation_kind,
        "dsl_digest": release.dsl_digest,
        "ir_digest": release.ir_digest,
        "bundle_digest": release.generated_bundle_digest,
        "evidence_digest": release.probe_evidence_digest,
        "compiler_version": release.compiler_version,
        "context_digest": release.compile_context_digest,
        "target_fingerprint": release.target_fingerprint,
        "target_conformance_digest": release.target_conformance_digest,
        "conformance_digest": release.conformance_digest,
        "mapping_confirmation_receipt_digest": release.mapping_confirmation_receipt_digest,
        "mapping_admission": release.mapping_admission,
    }


def _remove_preprovisioned_release(
    service: TargetdService,
    tool_id: str,
) -> ToolRelease:
    assert service.release_catalog is not None
    head = service.release_catalog.resolve_current(tool_id)
    release_path = service.release_catalog.root / "releases" / f"{head.release_digest.removeprefix('sha256:')}.json"
    service.release_catalog.catalog_path.unlink()
    release_path.unlink()
    return head.release


def test_targetd_rotation_scripts_use_isolated_cmd_vel_and_real_feedback_defaults():
    from scripts.targetd_certify_landerpi import (
        DEFAULT_COMMAND_ENDPOINT as certify_command_endpoint,
    )
    from scripts.targetd_certify_landerpi import (
        DEFAULT_FEEDBACK_ENDPOINTS as certify_feedback_endpoints,
    )
    from scripts.targetd_rotate_ssh_smoke import (
        DEFAULT_COMMAND_ENDPOINT as smoke_command_endpoint,
    )
    from scripts.targetd_rotate_ssh_smoke import (
        DEFAULT_FEEDBACK_ENDPOINTS as smoke_feedback_endpoints,
    )

    assert certify_command_endpoint == smoke_command_endpoint == "/cmd_vel"
    assert certify_feedback_endpoints == smoke_feedback_endpoints == ["/odom_raw", "/odom"]


def test_bundle_builds_verifies_and_round_trips(tmp_path):
    source = b"def execute(arguments):\n    return {'ok': True}\n"
    manifest = ExecutionBundleManifest.build(
        tool_id="app.base.rotate",
        source=source,
        binding_digest="a" * 64,
        signer_key_id="rolo-dev",
        signing_key=b"secret",
        limits={"max_duration_s": 60, "max_output_bytes": 65536},
    )
    manifest.verify_signature(b"secret")
    cache = BundleCache(tmp_path / "targetd")
    cache.put(manifest, source)
    loaded, loaded_source = cache.load(manifest.bundle_digest)
    assert loaded == manifest
    assert loaded_source == source
    with pytest.raises(ValueError, match="signature"):
        manifest.verify_signature(b"wrong")
    assert cache.put(manifest, source) == (tmp_path / "targetd" / "bundles" / manifest.bundle_digest)
    with pytest.raises(ValueError, match="immutable"):
        cache.put(manifest.model_copy(update={"signature": "tampered-signature"}), source)


@pytest.mark.parametrize(
    "invalid_digest",
    [
        "../../sentinel",
        "../" + "a" * 64,
        "sha256:" + "a" * 64,
        "A" * 64,
    ],
)
def test_bundle_cache_rejects_noncanonical_digest_before_path_lookup(
    tmp_path,
    invalid_digest,
):
    cache = BundleCache(tmp_path / "targetd")
    (cache.root / "bundles").mkdir(parents=True)
    sentinel = tmp_path / "sentinel"
    sentinel.mkdir()
    (sentinel / "manifest.json").write_text('{"secret":"must-not-be-read"}\n', encoding="utf-8")
    (sentinel / "source.py").write_text("secret = 'must-not-be-read'\n", encoding="utf-8")

    for lookup in (cache.has, cache.load):
        with pytest.raises(ProtocolError) as caught:
            lookup(invalid_digest)
        assert str(caught.value) == "TARGETD_BUNDLE_DIGEST_INVALID"
        assert "sentinel" not in str(caught.value)


def test_bundle_cache_rejects_absolute_digest_before_path_lookup(tmp_path):
    sentinel = (tmp_path / "absolute-sentinel").resolve()
    sentinel.mkdir()
    (sentinel / "manifest.json").write_text("{}\n", encoding="utf-8")
    (sentinel / "source.py").write_text("pass\n", encoding="utf-8")
    cache = BundleCache(tmp_path / "targetd")

    for lookup in (cache.has, cache.load):
        with pytest.raises(ProtocolError) as caught:
            lookup(str(sentinel))
        assert str(caught.value) == "TARGETD_BUNDLE_DIGEST_INVALID"
        assert str(sentinel) not in str(caught.value)


@pytest.mark.parametrize("link_target", ["entry", "manifest"])
def test_bundle_cache_rejects_linked_entries_when_supported(tmp_path, link_target):
    cache_root = tmp_path / "targetd"
    bundles = cache_root / "bundles"
    bundles.mkdir(parents=True)
    digest = "a" * 64
    external = tmp_path / f"external-{link_target}"
    external.mkdir()
    (external / "manifest.json").write_text("{}\n", encoding="utf-8")
    (external / "source.py").write_text("pass\n", encoding="utf-8")
    entry = bundles / digest
    try:
        if link_target == "entry":
            try:
                entry.symlink_to(external, target_is_directory=True)
            except (NotImplementedError, OSError):
                if sys.platform != "win32":
                    raise
                junction = subprocess.run(
                    ["cmd.exe", "/d", "/c", "mklink", "/J", str(entry), str(external)],
                    capture_output=True,
                    check=False,
                    text=True,
                )
                if junction.returncode != 0:
                    raise OSError("directory links are unavailable") from None
        else:
            entry.mkdir()
            (entry / "manifest.json").symlink_to(external / "manifest.json")
            (entry / "source.py").write_text("pass\n", encoding="utf-8")
    except (NotImplementedError, OSError) as exc:
        pytest.skip(f"filesystem links are unavailable: {type(exc).__name__}")

    cache = BundleCache(cache_root)
    for lookup in (cache.has, cache.load):
        with pytest.raises(ProtocolError) as caught:
            lookup(digest)
        assert str(caught.value) == "TARGETD_BUNDLE_CACHE_PATH_UNSAFE"


@pytest.mark.parametrize("invalid_digest", ["../../secret-sentinel", "C:/secret/sentinel", "/secret/sentinel"])
def test_targetd_daemon_has_rejects_invalid_digest_without_echo(
    tmp_path,
    invalid_digest,
):
    service = TargetdService(target_id="mentorpi", state_root=tmp_path / "state")
    session = service.open_session(
        JourneySession.create(
            session_id="has-validation-session",
            target_id="mentorpi",
            profile_id="landerpi",
        )
    )
    daemon = TargetdDaemon(service)
    daemon._session = session
    response = daemon._handle(
        ProtocolFrame.create(
            kind=FrameKind.HAS,
            sequence=0,
            session_id=session.session_id,
            payload={"bundle_digest": invalid_digest},
        )
    )

    assert response.payload == {
        "request_kind": "HAS",
        "ok": False,
        "error": "TARGETD_BUNDLE_DIGEST_INVALID",
    }
    assert invalid_digest not in json.dumps(response.payload, sort_keys=True)


def test_fenced_execution_schemas_require_explicit_versions_and_identity():
    request_schema = json.loads((Path("schemas") / "ExecutionRequest.schema.json").read_text(encoding="utf-8"))
    request_v3_schema = json.loads((Path("schemas") / "ExecutionRequestV3.schema.json").read_text(encoding="utf-8"))
    receipt_schema = json.loads((Path("schemas") / "TargetdCallReceipt.schema.json").read_text(encoding="utf-8"))
    authority_schema = json.loads((Path("schemas") / "TargetdExecutionAuthority.schema.json").read_text(encoding="utf-8"))
    activation_schema = json.loads((Path("schemas") / "TargetdAuthorityActivationRequest.schema.json").read_text(encoding="utf-8"))
    cancel_schema = json.loads((Path("schemas") / "TargetdMappingCancelRequest.schema.json").read_text(encoding="utf-8"))
    provision_schema = json.loads((Path("schemas") / "TargetdVerifiedReleaseProvisionRequest.schema.json").read_text(encoding="utf-8"))
    assert request_schema["properties"]["schema_version"]["const"] == "rolo-execution-request/v2"
    assert request_v3_schema["properties"]["schema_version"]["const"] == "rolo-execution-request/v3"
    assert receipt_schema["properties"]["schema_version"]["const"] == "rolo-targetd-call-receipt/v2"
    assert authority_schema["properties"]["schema_version"]["const"] == "rolo-targetd-execution-authority/v1"
    assert activation_schema["properties"]["schema_version"]["const"] == "rolo-targetd-authority-activation/v1"
    assert cancel_schema["properties"]["schema_version"]["const"] == "rolo-targetd-mapping-cancel/v1"
    assert provision_schema["properties"]["schema_version"]["const"] == "rolo-targetd-verified-release-provision/v1"
    assert {"authority", "release_digest", "context_digest", "fence_epoch", "provider_id"} <= set(request_schema["required"])
    assert {"request_digest", "provider_fence_digest", "authority_head_digest"} <= set(receipt_schema["required"])
    assert request_schema["additionalProperties"] is False
    assert request_v3_schema["additionalProperties"] is False
    assert {
        "execution_subject_digest",
        "motion_safety_admission",
    } <= set(request_v3_schema["required"])
    assert request_v3_schema["properties"]["motion_safety_admission"]["$ref"] == "TargetdMotionSafetyAdmission.schema.json"
    assert "execution_subject_digest" not in request_schema["properties"]
    assert "motion_safety_admission" not in request_schema["properties"]
    assert receipt_schema["additionalProperties"] is False
    assert authority_schema["additionalProperties"] is False
    assert "expected_current_authority_head_digest" in activation_schema["required"]
    assert activation_schema["additionalProperties"] is False
    assert cancel_schema["additionalProperties"] is False
    assert provision_schema["additionalProperties"] is False
    assert {
        "candidate_release",
        "conformance_cache_key",
        "execution_bundle_digest",
        "expected_catalog_head_digest",
    } <= set(provision_schema["required"])
    assert provision_schema["$defs"]["ToolRelease"]["additionalProperties"] is False
    assert provision_schema["$defs"]["ToolRelease"]["properties"]["route_digest"] == {"type": "null"}
    assert provision_schema["$defs"]["ToolRelease"]["properties"]["mhs_manifest_digests"]["maxItems"] == 0
    assert provision_schema["$defs"]["ToolRelease"]["properties"]["mapping_admission"]["$ref"].endswith("#/$defs/mapping_admission")


def test_frame_digest_is_deterministic_and_tamper_evident():
    frame = ProtocolFrame.create(
        kind=FrameKind.CALL,
        sequence=1,
        session_id="session-1",
        run_id="run-1",
        payload={"bundle_digest": "b" * 64, "arguments": {"angle_degrees": 15}},
    )
    assert frame.frame_digest == canonical_json_sha256(frame.model_dump(mode="json", exclude={"frame_digest"}))
    with pytest.raises(ValueError, match="digest"):
        ProtocolFrame.model_validate({**frame.model_dump(), "payload": {"changed": True}})
    assert decode_frame(encode_frame(frame)) == frame
    with pytest.raises(ValueError, match="length"):
        decode_frame(encode_frame(frame) + b"trailing")
    assert decode_frame(encode_frame(ProtocolFrame.create(kind=FrameKind.HAS, sequence=2, session_id="session-1"))).run_id is None


def test_decode_frame_rejects_duplicate_json_members():
    payload = b'{"frame_digest":"' + b"0" * 64 + b'","frame_digest":"' + b"1" * 64 + b'"}'
    encoded = len(payload).to_bytes(4, "big") + payload
    with pytest.raises(ProtocolError, match="payload is invalid"):
        decode_frame(encoded)


def test_session_and_receipt_state_support_resume_and_idempotency(tmp_path):
    store = TargetdStateStore(tmp_path / "run")
    session = JourneySession.create(session_id="session-1", target_id="mentorpi", profile_id="landerpi")
    store.save_session(session)
    assert store.load_session("session-1").resume_token == session.resume_token
    receipt = TargetdCallReceipt(
        schema_version="rolo-targetd-call-receipt/v2",
        idempotency_key="call-1",
        session_id=session.session_id,
        target_id="mentorpi",
        bundle_digest="b" * 64,
        request_digest="c" * 64,
        release_digest="sha256:" + "d" * 64,
        context_digest="sha256:" + "e" * 64,
        mapping_confirmation_receipt_digest="sha256:" + "f" * 64,
        authority_head_digest="1" * 64,
        fence_epoch=1,
        provider_id="targetd-python",
        provider_operation="app.generic",
        provider_fence_digest="2" * 64,
        status="SUCCEEDED",
        result={"angle_degrees": 15},
        updated_at=datetime.now(timezone.utc),
    )
    store.save_receipt(receipt)
    assert store.load_receipt(session.session_id, "call-1") == receipt


def test_state_store_rejects_duplicate_json_members_as_protocol_error(tmp_path):
    store = TargetdStateStore(tmp_path / "run")
    store.path.parent.mkdir(parents=True)
    store.path.write_text('{"sessions": {}, "sessions": {}}\n', encoding="utf-8")
    with pytest.raises(ProtocolError, match="state is unreadable"):
        store.load_receipt("session", "missing")


@pytest.mark.parametrize("field", ["sessions", "calls"])
def test_state_store_rejects_non_mapping_collections(field, tmp_path):
    store = TargetdStateStore(tmp_path / "run")
    store.path.parent.mkdir(parents=True)
    store.path.write_text(json.dumps({field: []}), encoding="utf-8")
    with pytest.raises(ProtocolError, match="state is unreadable"):
        store.load_receipt("session", "missing")


def test_targetd_health_is_unavailable_when_persisted_state_is_corrupt(tmp_path):
    service = TargetdService(target_id="mentorpi", state_root=tmp_path / "state")
    service.state.path.parent.mkdir(parents=True)
    service.state.path.write_text('{"sessions": "not-a-map"}\n', encoding="utf-8")
    assert service.health().status == "UNAVAILABLE"


def test_targetd_service_duplicate_inflight_call_requires_reconciliation(tmp_path):
    source = b"def execute(arguments): return arguments"
    manifest = _readonly_manifest("app.observe.test", source)
    service, authority, _, _ = _readonly_execution_setup(
        tmp_path,
        manifest,
        source,
        journey_session_id="session-2",
    )
    session = _execution_session(service, authority, "session-2")
    request = _execution_request(
        authority,
        session,
        run_id="run-2",
        idempotency_key="call-2",
        arguments={"angle_degrees": 15},
    )
    first = service.accept_call(request, manifest, provider_id=authority.provider_id)
    assert first.status == "ACCEPTED"
    assert first.request_digest == request.request_digest()
    unresolved = service.accept_call(
        request,
        manifest,
        provider_id=authority.provider_id,
    )
    assert unresolved.status == "UNKNOWN"
    assert unresolved.result == {"error": "CALL_RECONCILIATION_REQUIRED"}
    with pytest.raises(ProtocolError, match="different call identity"):
        service.accept_call(
            _execution_request(
                authority,
                session,
                run_id="run-2",
                idempotency_key="call-2",
                arguments={"angle_degrees": 16},
            ),
            manifest,
            provider_id=authority.provider_id,
        )
    with pytest.raises(ValueError, match="binding_digest does not match authority"):
        service.accept_call(
            request.model_copy(update={"idempotency_key": "call-binding-mismatch", "binding_digest": "c" * 64}),
            manifest,
            provider_id=authority.provider_id,
        )
    assert service.query_call(session.session_id, "call-2").status == "UNKNOWN"

    second_session = service.open_session(
        JourneySession.create(session_id="session-2b", target_id="mentorpi", profile_id="landerpi").model_copy(update={"phase": JourneyPhase.TRACE, "surface_digest": authority.surface_digest})
    )
    second_request = request.model_copy(
        update={
            "run_id": "run-2b",
            "session_id": second_session.session_id,
        }
    )
    with pytest.raises(ValueError, match="session does not match Mapping journey"):
        service.accept_call(
            second_request,
            manifest,
            provider_id=authority.provider_id,
        )
    assert service.query_call(second_session.session_id, second_request.idempotency_key) is None
    provider_calls = 0

    def cross_session_provider():
        nonlocal provider_calls
        provider_calls += 1
        return "SUCCEEDED", {"status": "SUCCEEDED"}

    with pytest.raises(ValueError, match="session does not match Mapping journey"):
        service.execute_provider(
            second_request,
            manifest,
            provider_id=authority.provider_id,
            execute=cross_session_provider,
        )
    assert provider_calls == 0


def test_targetd_v3_complete_synthetic_evidence_is_not_execution_capability(
    tmp_path,
):
    now = datetime.now(timezone.utc)
    source = b"def execute(arguments): return arguments"
    manifest = ExecutionBundleManifest.build(
        tool_id="app.base.rotate",
        source=source,
        binding_digest="a" * 64,
        signer_key_id="rolo-dev",
        signing_key=b"secret",
    )
    service, authority, _, _ = _execution_setup(
        tmp_path,
        manifest,
        source,
        journey_session_id="motion-v3-pass",
    )
    session = _execution_session(service, authority, "motion-v3-pass")
    request = _execution_request(
        authority,
        session,
        run_id="motion-v3-pass-run",
        idempotency_key="motion-v3-pass-call",
        motion_now=now,
    )
    assert isinstance(request, ExecutionRequestV3)
    assert request.execution_subject_digest == execution_subject_digest(request)
    changed_admission = request.model_copy(
        update={
            "motion_safety_admission": (
                request.motion_safety_admission.model_copy(
                    update={"evidence": MotionSafetyEvidenceBundle()}
                )
            )
        }
    )
    assert execution_subject_digest(changed_admission) == (
        request.execution_subject_digest
    )
    assert changed_admission.request_digest() != request.request_digest()
    with pytest.raises(
        ProtocolError,
        match="TARGETD_PHYSICAL_MOTION_EXECUTION_UNAVAILABLE",
    ):
        service.accept_call(request, manifest, provider_id="targetd-python")
    assert service.query_call(session.session_id, request.idempotency_key) is None


@pytest.mark.parametrize(
    "invalid_case",
    [
        "missing-evidence",
        "authority-fence-drift",
        "stale-graph",
        "extra-publisher",
    ],
)
def test_targetd_v3_evidence_variants_never_create_execution_capability(
    tmp_path,
    invalid_case,
):
    now = datetime.now(timezone.utc)
    source = b"def execute(arguments): return arguments"
    manifest = ExecutionBundleManifest.build(
        tool_id="app.base.rotate",
        source=source,
        binding_digest="a" * 64,
        signer_key_id="rolo-dev",
        signing_key=b"secret",
    )
    service, authority, _, _ = _execution_setup(
        tmp_path,
        manifest,
        source,
        journey_session_id=f"motion-v3-{invalid_case}",
    )
    session = _execution_session(
        service,
        authority,
        f"motion-v3-{invalid_case}",
    )
    request = _execution_request(
        authority,
        session,
        run_id=f"motion-v3-{invalid_case}-run",
        idempotency_key=f"motion-v3-{invalid_case}-call",
        motion_now=(
            now - timedelta(seconds=6)
            if invalid_case == "stale-graph"
            else now
        ),
        publishers=(
            [_MOTION_PUBLISHER, "/hand_gesture"]
            if invalid_case == "extra-publisher"
            else None
        ),
        motion_fence_epoch=(
            authority.fence_epoch + 1
            if invalid_case == "authority-fence-drift"
            else None
        ),
    )
    if invalid_case == "missing-evidence":
        request = request.model_copy(
            update={
                "motion_safety_admission": (
                    request.motion_safety_admission.model_copy(
                        update={"evidence": MotionSafetyEvidenceBundle()}
                    )
                )
            }
        )
    with pytest.raises(
        ProtocolError,
        match="TARGETD_PHYSICAL_MOTION_EXECUTION_UNAVAILABLE",
    ):
        service.accept_call(request, manifest, provider_id="targetd-python")
    assert service.query_call(session.session_id, request.idempotency_key) is None


def test_targetd_v3_static_evidence_cannot_claim_live_fence_cas(tmp_path):
    now = datetime.now(timezone.utc)
    source = b"def execute(arguments): return arguments"
    manifest = ExecutionBundleManifest.build(
        tool_id="app.base.rotate",
        source=source,
        binding_digest="a" * 64,
        signer_key_id="rolo-dev",
        signing_key=b"secret",
    )
    service, authority, _, _ = _execution_setup(
        tmp_path,
        manifest,
        source,
        journey_session_id="motion-v3-no-live-fence",
    )
    session = _execution_session(
        service,
        authority,
        "motion-v3-no-live-fence",
    )
    request = _execution_request(
        authority,
        session,
        run_id="motion-v3-no-live-fence-run",
        idempotency_key="motion-v3-no-live-fence-call",
        motion_now=now,
    )
    calls = 0

    class RecordingWorker:
        def execute(self, *_args, **_kwargs):
            nonlocal calls
            calls += 1
            return {"status": "SUCCEEDED"}

    daemon = TargetdDaemon(service, execute_calls=True)
    daemon.worker = RecordingWorker()
    daemon._session = session
    response = daemon._handle(
        ProtocolFrame.create(
            kind=FrameKind.CALL,
            sequence=0,
            session_id=session.session_id,
            run_id=request.run_id,
            payload=request.model_dump(mode="json"),
        )
    )
    assert response.payload["ok"] is False
    assert response.payload["error"] == "TARGETD_PHYSICAL_PROCESS_WORKER_REQUIRED"
    assert calls == 0
    assert service.query_call(session.session_id, request.idempotency_key) is None


def test_targetd_physical_v2_is_blocked_before_daemon_provider(tmp_path):
    source = b"def execute(arguments): return arguments"
    manifest = ExecutionBundleManifest.build(
        tool_id="app.base.rotate",
        source=source,
        binding_digest="a" * 64,
        signer_key_id="rolo-dev",
        signing_key=b"secret",
    )
    service, authority, _, _ = _execution_setup(
        tmp_path,
        manifest,
        source,
        journey_session_id="motion-v2-blocked",
    )
    session = _execution_session(service, authority, "motion-v2-blocked")
    request = _execution_request(
        authority,
        session,
        run_id="motion-v2-blocked-run",
        idempotency_key="motion-v2-blocked-call",
        force_v2=True,
    )
    calls = 0

    class RecordingWorker:
        def execute(self, *_args, **_kwargs):
            nonlocal calls
            calls += 1
            return {"status": "SUCCEEDED"}

    daemon = TargetdDaemon(service, execute_calls=True)
    daemon.worker = RecordingWorker()
    daemon._session = session
    response = daemon._handle(
        ProtocolFrame.create(
            kind=FrameKind.CALL,
            sequence=0,
            session_id=session.session_id,
            run_id=request.run_id,
            payload=request.model_dump(mode="json"),
        )
    )
    assert response.payload["ok"] is False
    assert response.payload["error"] == (
        "PHYSICAL_MOTION_EXECUTION_REQUEST_V3_REQUIRED"
    )
    assert calls == 0
    assert service.query_call(session.session_id, request.idempotency_key) is None


def test_targetd_service_treats_not_accepted_as_terminal(tmp_path):
    source = b"def execute(arguments): return arguments"
    manifest = _readonly_manifest("app.observe.test", source)
    service, authority, _, _ = _readonly_execution_setup(
        tmp_path,
        manifest,
        source,
        journey_session_id="session-not-accepted",
    )
    session = _execution_session(service, authority, "session-not-accepted")
    request = _execution_request(
        authority,
        session,
        run_id="run-not-accepted",
        idempotency_key="call-not-accepted",
    )
    assert service.accept_call(
        request,
        manifest,
        provider_id=authority.provider_id,
    ).status == "ACCEPTED"
    rejected = service.complete_call(request.session_id, request.idempotency_key, status="NOT_ACCEPTED")
    assert rejected.status == "NOT_ACCEPTED"
    assert service.complete_call(request.session_id, request.idempotency_key, status="FAILED") == rejected


def test_targetd_cancel_before_provider_fence_makes_zero_provider_calls(tmp_path):
    source = b"def execute(arguments): return arguments"
    manifest = _readonly_manifest("app.observe.test", source)
    service, authority, _, _ = _readonly_execution_setup(
        tmp_path,
        manifest,
        source,
        journey_session_id="cancel-before-provider",
    )
    session = _execution_session(service, authority, "cancel-before-provider")
    request = _execution_request(authority, session)
    service.accept_call(request, manifest, provider_id=authority.provider_id)
    assert service.start_call(
        request,
        manifest,
        provider_id=authority.provider_id,
    ).status == "STARTED"
    assert service.cancel_call(session.session_id, request.idempotency_key).status == "CANCELLED"
    calls = 0

    def provider():
        nonlocal calls
        calls += 1
        return "SUCCEEDED", {"status": "SUCCEEDED"}

    receipt = service.execute_provider(
        request,
        manifest,
        provider_id=authority.provider_id,
        execute=provider,
    )
    assert receipt.status == "CANCELLED"
    assert calls == 0


def test_targetd_provider_exception_after_start_is_unknown(tmp_path):
    source = b"def execute(arguments): return arguments"
    manifest = _readonly_manifest("app.observe.test", source)
    service, authority, _, _ = _readonly_execution_setup(
        tmp_path,
        manifest,
        source,
        journey_session_id="ambiguous-provider-exception",
    )
    session = _execution_session(service, authority, "ambiguous-provider-exception")
    request = _execution_request(authority, session)
    service.accept_call(request, manifest, provider_id=authority.provider_id)
    service.start_call(request, manifest, provider_id=authority.provider_id)

    def provider():
        raise RuntimeError("sensitive provider detail")

    receipt = service.execute_provider(
        request,
        manifest,
        provider_id=authority.provider_id,
        execute=provider,
    )
    assert receipt.status == "UNKNOWN"
    assert receipt.result == {"error": "WORKER_EXCEPTION_AMBIGUOUS"}
    assert "sensitive" not in str(receipt.model_dump(mode="json"))


def test_targetd_mapping_cancel_at_provider_boundary_is_not_accepted(tmp_path):
    source = b"def execute(arguments): return arguments"
    manifest = _readonly_manifest("app.observe.test", source)
    service, authority, confirmations, _ = _readonly_execution_setup(
        tmp_path,
        manifest,
        source,
        journey_session_id="mapping-cancel",
    )
    session = _execution_session(service, authority, "mapping-cancel")
    request = _execution_request(authority, session)
    service.accept_call(request, manifest, provider_id=authority.provider_id)
    service.start_call(request, manifest, provider_id=authority.provider_id)
    confirmations.cancel(
        authority.mapping_confirmation_receipt_digest,
        decision_id="cancel-1",
        actor_id="test-operator",
    )
    calls = 0

    def provider():
        nonlocal calls
        calls += 1
        return "SUCCEEDED", {"status": "SUCCEEDED"}

    receipt = service.execute_provider(
        request,
        manifest,
        provider_id=authority.provider_id,
        execute=provider,
    )
    assert receipt.status == "NOT_ACCEPTED"
    assert "MAPPING_CONFIRMATION_CANCELLED" in receipt.result["error"]
    assert calls == 0


def test_targetd_start_revalidates_mapping_after_accept(tmp_path):
    source = b"def execute(arguments): return arguments"
    manifest = _readonly_manifest("app.observe.test", source)
    service, authority, confirmations, _ = _readonly_execution_setup(
        tmp_path,
        manifest,
        source,
        journey_session_id="mapping-cancel-before-start",
    )
    session = _execution_session(service, authority, "mapping-cancel-before-start")
    request = _execution_request(authority, session)
    service.accept_call(request, manifest, provider_id=authority.provider_id)
    confirmations.cancel(
        authority.mapping_confirmation_receipt_digest,
        decision_id="cancel-before-start",
        actor_id="test-operator",
    )
    with pytest.raises(ValueError, match="MAPPING_CONFIRMATION_CANCELLED"):
        service.start_call(
            request,
            manifest,
            provider_id=authority.provider_id,
        )
    assert service.state.load_receipt(session.session_id, request.idempotency_key).status == "ACCEPTED"


def test_targetd_current_head_promotion_fences_started_call(tmp_path):
    source = b"def execute(arguments): return arguments"
    manifest = _readonly_manifest("app.observe.test", source)
    service, authority, _, authority_store = _readonly_execution_setup(
        tmp_path,
        manifest,
        source,
        journey_session_id="stale-current-head",
    )
    session = _execution_session(service, authority, "stale-current-head")
    request = _execution_request(authority, session)
    service.accept_call(request, manifest, provider_id=authority.provider_id)
    service.start_call(request, manifest, provider_id=authority.provider_id)
    promoted = TargetdExecutionAuthority.build(
        **{
            **authority.model_dump(
                mode="python",
                exclude={
                    "schema_version",
                    "authority_head_digest",
                    "release_digest",
                    "catalog_head_digest",
                    "fence_epoch",
                },
            ),
            "release_digest": mapping_digest({"kind": "release-2"}),
            "catalog_head_digest": mapping_digest({"kind": "catalog-head-2"}),
            "fence_epoch": 2,
        }
    )
    authority_store.publish(promoted)
    calls = 0

    def provider():
        nonlocal calls
        calls += 1
        return "SUCCEEDED", {"status": "SUCCEEDED"}

    receipt = service.execute_provider(
        request,
        manifest,
        provider_id=authority.provider_id,
        execute=provider,
    )
    assert receipt.status == "NOT_ACCEPTED"
    assert "EXECUTION_AUTHORITY_HEAD_STALE" in receipt.result["error"]
    assert calls == 0


def test_targetd_terminal_replay_does_not_repeat_provider(tmp_path):
    source = b"def execute(arguments): return arguments"
    manifest = _readonly_manifest("app.observe.test", source)
    service, authority, _, _ = _readonly_execution_setup(
        tmp_path,
        manifest,
        source,
        journey_session_id="terminal-replay",
    )
    session = _execution_session(service, authority, "terminal-replay")
    request = _execution_request(authority, session)
    service.accept_call(request, manifest, provider_id=authority.provider_id)
    service.start_call(request, manifest, provider_id=authority.provider_id)
    calls = 0

    def provider():
        nonlocal calls
        calls += 1
        return "SUCCEEDED", {"status": "SUCCEEDED"}

    first = service.execute_provider(
        request,
        manifest,
        provider_id=authority.provider_id,
        execute=provider,
    )
    second = service.accept_call(
        request,
        manifest,
        provider_id=authority.provider_id,
    )
    assert first.status == second.status == "SUCCEEDED"
    assert calls == 1


def test_targetd_rejects_unprovisioned_or_wrong_provider_before_accept(tmp_path):
    source = b"def execute(arguments): return arguments"
    manifest = ExecutionBundleManifest.build(
        tool_id="app.generic",
        source=source,
        binding_digest="a" * 64,
        signer_key_id="rolo-dev",
        signing_key=b"secret",
    )
    service, authority, _, _ = _execution_setup(tmp_path, manifest, source, journey_session_id="wrong-provider")
    session = _execution_session(service, authority, "wrong-provider")
    request = _execution_request(authority, session)
    with pytest.raises(ProtocolError, match="provider does not match"):
        service.accept_call(request, manifest, provider_id="ros-container")

    unprovisioned = TargetdService(target_id="mentorpi", state_root=tmp_path / "unprovisioned")
    unprovisioned.put_bundle(manifest, source)
    unprovisioned.open_session(session)
    with pytest.raises(ProtocolError, match="AUTHORITY_STORE_REQUIRED"):
        unprovisioned.accept_call(
            request,
            manifest,
            provider_id="targetd-python",
        )


def test_targetd_mapping_status_runtime_is_not_accepted_as_read_only(tmp_path):
    source = b"def execute(arguments, provider): return provider.invoke('mapping.status', arguments)"
    manifest = ExecutionBundleManifest.build(
        tool_id="app.mapping.status",
        source=source,
        binding_digest="a" * 64,
        signer_key_id="rolo-dev",
        signing_key=b"secret",
        observation_contract={"provider": "ros-container", "operation": "mapping.status"},
    )
    service, authority, _, _ = _execution_setup(
        tmp_path,
        manifest,
        source,
        provider_id="ros-container",
        provider_operation="mapping.status",
        operation_kind=OperationKind.OBSERVE,
        journey_session_id="mapping-status-not-readonly",
    )
    session = _execution_session(service, authority, "mapping-status-not-readonly")
    request = _execution_request(authority, session)
    with pytest.raises(ProtocolError, match="TARGETD_READ_ONLY_PROVIDER_REQUIRED"):
        service.accept_call(request, manifest, provider_id="ros-container")


def test_targetd_read_scope_cannot_underdeclare_python_bundle_runtime(tmp_path):
    source = b"def execute(arguments): return {'status': 'SUCCEEDED'}"
    manifest = ExecutionBundleManifest.build(
        tool_id="app.observe.unsafe",
        source=source,
        binding_digest="a" * 64,
        signer_key_id="rolo-dev",
        signing_key=b"secret",
    )
    service, authority, _, _ = _execution_setup(
        tmp_path,
        manifest,
        source,
        provider_id="targetd-python",
        operation_kind=OperationKind.OBSERVE,
        journey_session_id="underdeclared-observe",
    )
    session = _execution_session(service, authority, "underdeclared-observe")
    request = _execution_request(authority, session)
    with pytest.raises(ProtocolError, match="TARGETD_READ_ONLY_PROVIDER_REQUIRED"):
        service.accept_call(request, manifest, provider_id="targetd-python")
    assert service.query_call(session.session_id, request.idempotency_key) is None


def test_targetd_readonly_provider_bypasses_arbitrary_python_bundle_source(tmp_path):
    source = b"raise RuntimeError('bundle source must not execute')"
    manifest = ExecutionBundleManifest.build(
        tool_id="app.observe.odom",
        source=source,
        binding_digest="a" * 64,
        signer_key_id="rolo-dev",
        signing_key=b"secret",
        observation_contract={
            "provider": "ros2-readonly",
            "operation": "odom.sample",
        },
    )
    service, authority, _, _ = _execution_setup(
        tmp_path,
        manifest,
        source,
        provider_id="ros2-readonly",
        provider_operation="odom.sample",
        operation_kind=OperationKind.OBSERVE,
        journey_session_id="readonly-provider",
    )
    session = _execution_session(service, authority, "readonly-provider")
    request = _execution_request(authority, session)

    raw = "header:\n  stamp:\n    sec: 1\n"
    calls = []

    def execute(binding, arguments):
        calls.append((dict(binding), dict(arguments)))
        return {"status": "SUCCEEDED", "topic": "/odom", "raw": raw}

    resolver = Ros2RuntimeResolver(
        Ros2RuntimeSnapshot(
            "humble",
            "/opt/ros/humble/bin/ros2",
            parse_ros2_topic_types(["/odom nav_msgs/msg/Odometry"]),
        )
    )
    provider = Ros2ReadOnlyProvider(ros2_registry(resolver, execute))
    daemon = TargetdDaemon(
        service,
        execute_calls=True,
        provider=provider,
    )
    daemon._session = session
    response = daemon._handle(
        ProtocolFrame.create(
            kind=FrameKind.CALL,
            sequence=0,
            session_id=session.session_id,
            run_id=request.run_id,
            payload=request.model_dump(mode="json"),
        )
    )
    assert response.payload["ok"] is True
    assert response.payload["receipt"]["status"] == "SUCCEEDED"
    assert response.payload["receipt"]["result"] == {
        "status": "SUCCEEDED",
        "sha256": f"sha256:{hashlib.sha256(raw.encode('utf-8')).hexdigest()}",
        "byte_count": len(raw.encode("utf-8")),
    }
    assert calls == [
        (
            {
                "resource_id": "/odom",
                "interface_type": "nav_msgs/msg/Odometry",
            },
            {},
        )
    ]
    assert "raw" not in json.dumps(response.payload["receipt"])


@pytest.mark.parametrize(
    ("operation", "arguments", "error"),
    [
        ("topic.sample", {}, "ROS2_READ_ONLY_OPERATION_NOT_ALLOWED"),
        ("odom.sample", {"topic": "/scan"}, "ROS2_READ_ONLY_ARGUMENTS_NOT_ALLOWED"),
    ],
)
def test_targetd_readonly_provider_rejects_unregistered_shape_before_receipt(
    tmp_path,
    operation,
    arguments,
    error,
):
    source = b"raise RuntimeError('bundle source must not execute')"
    manifest = ExecutionBundleManifest.build(
        tool_id="app.observe.odom",
        source=source,
        binding_digest="a" * 64,
        signer_key_id="rolo-dev",
        signing_key=b"secret",
        observation_contract={"provider": "ros2-readonly", "operation": operation},
    )
    service, authority, _, _ = _execution_setup(
        tmp_path,
        manifest,
        source,
        provider_id="ros2-readonly",
        provider_operation=operation,
        operation_kind=OperationKind.OBSERVE,
        journey_session_id="readonly-shape",
    )
    session = _execution_session(service, authority, "readonly-shape")
    request = _execution_request(authority, session, arguments=arguments)
    calls = []
    resolver = Ros2RuntimeResolver(
        Ros2RuntimeSnapshot(
            "humble",
            "/opt/ros/humble/bin/ros2",
            parse_ros2_topic_types(["/odom nav_msgs/msg/Odometry"]),
        )
    )
    provider = Ros2ReadOnlyProvider(
        ros2_registry(
            resolver,
            lambda binding, runtime_arguments: calls.append((dict(binding), dict(runtime_arguments))),
        )
    )
    daemon = TargetdDaemon(service, execute_calls=True, provider=provider)
    daemon._session = session

    response = daemon._handle(
        ProtocolFrame.create(
            kind=FrameKind.CALL,
            sequence=0,
            session_id=session.session_id,
            run_id=request.run_id,
            payload=request.model_dump(mode="json"),
        )
    )

    assert response.payload == {
        "request_kind": "CALL",
        "ok": False,
        "error": error,
        "provider_invocation_count": 0,
    }
    assert service.query_call(session.session_id, request.idempotency_key) is None
    assert calls == []


def test_targetd_readonly_provider_failure_receipt_drops_raw_and_detail(tmp_path):
    source = b"raise RuntimeError('bundle source must not execute')"
    manifest = ExecutionBundleManifest.build(
        tool_id="app.observe.odom",
        source=source,
        binding_digest="a" * 64,
        signer_key_id="rolo-dev",
        signing_key=b"secret",
        observation_contract={
            "provider": "ros2-readonly",
            "operation": "odom.sample",
        },
    )
    service, authority, _, _ = _execution_setup(
        tmp_path,
        manifest,
        source,
        provider_id="ros2-readonly",
        provider_operation="odom.sample",
        operation_kind=OperationKind.OBSERVE,
        journey_session_id="readonly-failure",
    )
    session = _execution_session(service, authority, "readonly-failure")
    request = _execution_request(authority, session)
    resolver = Ros2RuntimeResolver(
        Ros2RuntimeSnapshot(
            "humble",
            "/opt/ros/humble/bin/ros2",
            parse_ros2_topic_types(["/odom nav_msgs/msg/Odometry"]),
        )
    )

    def fail(_binding, _arguments):
        return {
            "status": "UNKNOWN",
            "error": "ROS2_TOPIC_ECHO_FAILED",
            "raw": "secret stdout",
            "detail": "secret stderr",
            "topic": "/odom",
        }

    daemon = TargetdDaemon(
        service,
        execute_calls=True,
        provider=Ros2ReadOnlyProvider(ros2_registry(resolver, fail)),
    )
    daemon._session = session
    response = daemon._handle(
        ProtocolFrame.create(
            kind=FrameKind.CALL,
            sequence=0,
            session_id=session.session_id,
            run_id=request.run_id,
            payload=request.model_dump(mode="json"),
        )
    )

    assert response.payload["ok"] is True
    assert response.payload["receipt"]["status"] == "UNKNOWN"
    assert response.payload["receipt"]["result"] == {
        "status": "UNKNOWN",
        "error": "ROS2_TOPIC_ECHO_FAILED",
    }
    serialized = json.dumps(response.payload["receipt"])
    assert "secret stdout" not in serialized
    assert "secret stderr" not in serialized
    assert "raw" not in serialized
    assert "detail" not in serialized


def test_ros2_readonly_provider_requires_exact_observed_odom_binding():
    resolver = Ros2RuntimeResolver(
        Ros2RuntimeSnapshot(
            "humble",
            "/opt/ros/humble/bin/ros2",
            parse_ros2_topic_types(["/odom example_msgs/msg/Odometry"]),
        )
    )

    with pytest.raises(ProtocolError, match="ROS2_READ_ONLY_BINDING_UNAVAILABLE"):
        Ros2ReadOnlyProvider(ros2_registry(resolver, lambda _binding, _arguments: {}))


def test_targetd_activation_derives_current_authority_and_fence_on_target(
    tmp_path,
):
    service, session, activation, manifest, _, _, authority_store = _activation_setup(tmp_path)
    authority = service.activate_authority(
        activation,
        session_id=session.session_id,
        provider_id="ros2-readonly",
    )
    assert authority.fence_epoch == 1
    assert authority == authority_store.resolve(authority.tool_id)
    assert authority.mapping_admission.journey_session_id == session.session_id
    assert authority.surface_digest == session.surface_digest
    assert authority.bundle_digest == manifest.bundle_digest
    assert authority.provider_id == "ros2-readonly"
    assert authority.provider_operation == "odom.sample"
    assert authority.mode == "SUPERVISED_FIELD_DEBUG"

    replay = service.activate_authority(
        activation,
        session_id=session.session_id,
        provider_id="ros2-readonly",
    )
    assert replay == authority
    assert replay.fence_epoch == 1


def test_targetd_same_channel_provisions_cache_verified_release(tmp_path):
    service, session, activation, manifest, _, _, _ = _activation_setup(tmp_path)
    candidate = _remove_preprovisioned_release(service, activation.tool_id)
    provision = TargetdVerifiedReleaseProvisionRequest(
        schema_version="rolo-targetd-verified-release-provision/v1",
        release_digest=activation.release_digest,
        candidate_release=candidate,
        conformance_cache_key="c" * 64,
        execution_bundle_digest=manifest.bundle_digest,
        expected_catalog_head_digest=None,
    )

    class VerifiedDslCache:
        def verified_release_inputs(self, cache_key, *, journey_session_id):
            assert cache_key == provision.conformance_cache_key
            assert journey_session_id == session.session_id
            return _verified_release_inputs(candidate)

    resolver = Ros2RuntimeResolver(
        Ros2RuntimeSnapshot(
            "humble",
            "/opt/ros/humble/bin/ros2",
            parse_ros2_topic_types(["/odom nav_msgs/msg/Odometry"]),
        )
    )
    daemon = TargetdDaemon(
        service,
        execute_calls=True,
        provider=Ros2ReadOnlyProvider(ros2_registry(resolver, lambda _binding, _arguments: {})),
        dsl_service=VerifiedDslCache(),
    )
    daemon._session = session
    response = daemon._handle(
        ProtocolFrame.create(
            kind=FrameKind.PROVISION_VERIFIED_RELEASE,
            sequence=0,
            session_id=session.session_id,
            payload=provision.model_dump(mode="json"),
        )
    )
    assert response.payload["ok"] is True
    assert response.payload["release_digest"] == provision.release_digest
    assert response.payload["provider_invocation_count"] == 0
    assert service.release_catalog is not None
    current = service.release_catalog.resolve_current(candidate.tool_id)
    assert current.release == candidate
    assert current.catalog_head_digest == response.payload["catalog_head_digest"]


def test_targetd_release_provision_is_idempotent_but_rejects_stale_cas(tmp_path):
    service, _, activation, _, _, _, _ = _activation_setup(tmp_path)
    assert service.release_catalog is not None
    current = service.release_catalog.resolve_current(activation.tool_id)
    duplicate = service.release_catalog.provision_verified(
        release_digest=current.release_digest,
        release=current.release,
        expected_catalog_head_digest=None,
    )
    assert duplicate == current

    replacement = current.release.model_copy(update={"compiler_version": "stale-controller-replacement"})
    with pytest.raises(ProtocolError, match="CATALOG_CAS_FAILED"):
        service.release_catalog.provision_verified(
            release_digest=tool_release_digest(replacement),
            release=replacement,
            expected_catalog_head_digest=None,
        )
    assert service.release_catalog.resolve_current(activation.tool_id) == current


def test_targetd_release_provision_rejects_wrong_session_bundle_and_cancel(
    tmp_path,
):
    service, session, activation, manifest, _, confirmations, _ = _activation_setup(tmp_path)
    candidate = _remove_preprovisioned_release(service, activation.tool_id)
    inputs = _verified_release_inputs(candidate)
    provision = TargetdVerifiedReleaseProvisionRequest(
        schema_version="rolo-targetd-verified-release-provision/v1",
        release_digest=activation.release_digest,
        candidate_release=candidate,
        conformance_cache_key="d" * 64,
        execution_bundle_digest="f" * 64,
        expected_catalog_head_digest=None,
    )
    with pytest.raises(ProtocolError, match="cache entry is unreadable"):
        service.provision_verified_release(
            provision,
            session_id=session.session_id,
            provider_id="ros2-readonly",
            verified_inputs=inputs,
        )

    wrong_source = b"raise RuntimeError('unrelated signed bundle')\n"
    wrong_manifest = ExecutionBundleManifest.build(
        tool_id=candidate.tool_id,
        source=wrong_source,
        binding_digest="a" * 64,
        signer_key_id="rolo-dev",
        signing_key=b"secret",
        observation_contract={
            "provider": "ros2-readonly",
            "operation": "odom.sample",
            "mode": "SUPERVISED_FIELD_DEBUG",
            "generated_bundle_digest": mapping_digest({"kind": "wrong-bundle-plan"}),
        },
        release_version=activation.release_digest,
    )
    service.put_bundle(wrong_manifest, wrong_source)
    unrelated_bundle = provision.model_copy(update={"execution_bundle_digest": wrong_manifest.bundle_digest})
    with pytest.raises(ProtocolError, match="EXECUTION_BUNDLE_RELEASE_MISMATCH"):
        service.provision_verified_release(
            unrelated_bundle,
            session_id=session.session_id,
            provider_id="ros2-readonly",
            verified_inputs=inputs,
        )

    other = JourneySession.create(
        session_id="other-provision-session",
        target_id="mentorpi",
        profile_id="landerpi",
    ).model_copy(update={"phase": JourneyPhase.TRACE, "surface_digest": "b" * 64})
    service.open_session(other)
    correct_bundle = provision.model_copy(update={"execution_bundle_digest": manifest.bundle_digest})

    tampered_candidate = candidate.model_copy(update={"compiler_version": "caller-claimed-compiler"})
    tampered_request = TargetdVerifiedReleaseProvisionRequest(
        schema_version="rolo-targetd-verified-release-provision/v1",
        release_digest=tool_release_digest(tampered_candidate),
        candidate_release=tampered_candidate,
        conformance_cache_key=provision.conformance_cache_key,
        execution_bundle_digest=manifest.bundle_digest,
        expected_catalog_head_digest=None,
    )
    with pytest.raises(ProtocolError, match="VERIFIED_RELEASE_IDENTITY_MISMATCH"):
        service.provision_verified_release(
            tampered_request,
            session_id=session.session_id,
            provider_id="ros2-readonly",
            verified_inputs=inputs,
        )

    with pytest.raises(ProtocolError, match="SESSION_MISMATCH"):
        service.provision_verified_release(
            correct_bundle,
            session_id=other.session_id,
            provider_id="ros2-readonly",
            verified_inputs=inputs,
        )

    assert candidate.mapping_confirmation_receipt_digest is not None
    confirmations.cancel(
        candidate.mapping_confirmation_receipt_digest,
        decision_id="cancel-before-release-provision",
        actor_id="test-operator",
    )
    with pytest.raises(MappingAdmissionError, match="MAPPING_CONFIRMATION_CANCELLED"):
        service.provision_verified_release(
            correct_bundle,
            session_id=session.session_id,
            provider_id="ros2-readonly",
            verified_inputs=inputs,
        )
    assert service.release_catalog is not None
    assert not service.release_catalog.catalog_path.exists()


def test_targetd_release_provision_rejects_caller_supplied_verification(
    tmp_path,
):
    service, session, activation, manifest, _, _, _ = _activation_setup(tmp_path)
    candidate = _remove_preprovisioned_release(service, activation.tool_id)

    class MustNotReadDslCache:
        calls = 0

        def verified_release_inputs(self, cache_key, *, journey_session_id):
            self.calls += 1
            raise AssertionError("untyped caller proof reached target verifier")

    dsl_cache = MustNotReadDslCache()
    resolver = Ros2RuntimeResolver(
        Ros2RuntimeSnapshot(
            "humble",
            "/opt/ros/humble/bin/ros2",
            parse_ros2_topic_types(["/odom nav_msgs/msg/Odometry"]),
        )
    )
    daemon = TargetdDaemon(
        service,
        execute_calls=True,
        provider=Ros2ReadOnlyProvider(ros2_registry(resolver, lambda _binding, _arguments: {})),
        dsl_service=dsl_cache,
    )
    daemon._session = session
    response = daemon._handle(
        ProtocolFrame.create(
            kind=FrameKind.PROVISION_VERIFIED_RELEASE,
            sequence=0,
            session_id=session.session_id,
            payload={
                "schema_version": "rolo-targetd-verified-release-provision/v1",
                "release_digest": activation.release_digest,
                "candidate_release": candidate.model_dump(mode="json"),
                "conformance_cache_key": "e" * 64,
                "execution_bundle_digest": manifest.bundle_digest,
                "expected_catalog_head_digest": None,
                "verified_inputs": {"caller_claimed": True},
            },
        )
    )
    assert response.payload["ok"] is False
    assert response.payload["error"] == "TARGETD_REQUEST_VALIDATION_FAILED"
    assert response.payload["provider_invocation_count"] == 0
    assert dsl_cache.calls == 0
    assert service.release_catalog is not None
    assert not service.release_catalog.catalog_path.exists()


def test_targetd_daemon_validation_error_does_not_echo_secret_payload(
    tmp_path,
):
    secret = "secret-resume-token-must-not-appear"
    service = TargetdService(target_id="mentorpi", state_root=tmp_path / "state")
    session = service.open_session(
        JourneySession.create(
            session_id="secret-validation-session",
            target_id="mentorpi",
            profile_id="landerpi",
        )
    )
    daemon = TargetdDaemon(service, execute_calls=True)
    daemon._session = session
    response = daemon._handle(
        ProtocolFrame.create(
            kind=FrameKind.CALL,
            sequence=0,
            session_id="secret-validation-session",
            payload={
                "schema_version": "rolo-execution-request/v2",
                "deadline": secret,
                "resume_token": secret,
            },
        )
    )
    assert response.payload == {
        "request_kind": "CALL",
        "ok": False,
        "error": "TARGETD_REQUEST_VALIDATION_FAILED",
        "provider_invocation_count": 0,
    }
    assert secret not in json.dumps(response.payload, sort_keys=True)


def test_targetd_daemon_phase_value_error_does_not_echo_wire_canary(tmp_path):
    canary = "SERVER_SECRET_CANARY_PHASE_91"
    service = TargetdService(target_id="mentorpi", state_root=tmp_path / "state")
    session = service.open_session(
        JourneySession.create(
            session_id="phase-validation-session",
            target_id="mentorpi",
            profile_id="landerpi",
        )
    )
    daemon = TargetdDaemon(service)
    daemon._session = session

    response = daemon._handle(
        ProtocolFrame.create(
            kind=FrameKind.PHASE_CHANGE,
            sequence=0,
            session_id=session.session_id,
            payload={"phase": canary},
        )
    )

    assert response.payload == {
        "request_kind": "PHASE_CHANGE",
        "ok": False,
        "error": "TARGETD_REQUEST_VALIDATION_FAILED",
    }
    assert canary not in json.dumps(response.payload, sort_keys=True)


def test_targetd_daemon_put_untrusted_signer_does_not_echo_wire_canary(tmp_path):
    canary = "SERVER_SECRET_CANARY_SIGNER_91"
    source = b"def execute(arguments): return arguments\n"
    manifest = ExecutionBundleManifest.build(
        tool_id="app.untrusted",
        source=source,
        binding_digest="a" * 64,
        signer_key_id=canary,
        signing_key=b"untrusted-signing-key",
    )
    service = TargetdService(
        target_id="mentorpi",
        state_root=tmp_path / "state",
        verification_keys={"trusted-signer": b"trusted-signing-key"},
    )
    session = service.open_session(
        JourneySession.create(
            session_id="put-signer-validation-session",
            target_id="mentorpi",
            profile_id="landerpi",
        )
    )
    daemon = TargetdDaemon(service)
    daemon._session = session

    response = daemon._handle(
        ProtocolFrame.create(
            kind=FrameKind.PUT,
            sequence=0,
            session_id=session.session_id,
            payload={
                "manifest": manifest.model_dump(mode="json"),
                "source_b64": base64.b64encode(source).decode("ascii"),
            },
        )
    )

    assert response.payload == {
        "request_kind": "PUT",
        "ok": False,
        "error": "TARGETD_BUNDLE_SIGNER_UNTRUSTED",
    }
    assert canary not in json.dumps(response.payload, sort_keys=True)
    assert not service.has_bundle(manifest.bundle_digest)


def test_targetd_activation_rejects_caller_authority_and_forged_release(
    tmp_path,
):
    service, session, activation, _, _, _, authority_store = _activation_setup(tmp_path)
    with pytest.raises(ValueError, match="Extra inputs"):
        TargetdAuthorityActivationRequest.model_validate(
            {
                **activation.model_dump(mode="json"),
                "fence_epoch": 999,
                "provider_id": "targetd-python",
            }
        )
    forged = activation.model_copy(update={"release_digest": mapping_digest({"kind": "forged-release"})})
    with pytest.raises(ProtocolError, match="NOT_CURRENT"):
        service.activate_authority(
            forged,
            session_id=session.session_id,
            provider_id="ros2-readonly",
        )
    with pytest.raises(KeyError):
        authority_store.resolve(activation.tool_id)


def test_targetd_authority_store_requires_current_head_to_advance_fence(
    tmp_path,
):
    service, session, activation, _, _, _, authority_store = _activation_setup(tmp_path)
    current = service.activate_authority(
        activation,
        session_id=session.session_id,
        provider_id="ros2-readonly",
    )

    def promoted(epoch):
        return TargetdExecutionAuthority.build(
            tool_id=current.tool_id,
            target_id=current.target_id,
            target_fingerprint=current.target_fingerprint,
            bundle_digest=current.bundle_digest,
            binding_digest=current.binding_digest,
            surface_digest=current.surface_digest,
            release_digest=current.release_digest,
            context_digest=current.context_digest,
            mapping_confirmation_receipt_digest=current.mapping_confirmation_receipt_digest,
            mapping_admission=current.mapping_admission,
            catalog_head_digest=current.catalog_head_digest,
            provider_id=current.provider_id,
            provider_operation=current.provider_operation,
            mode="SUPERVISED_FIELD_DEBUG_V2",
            fence_epoch=epoch,
        )

    with pytest.raises(ProtocolError, match="ACTIVATION_CAS_FAILED"):
        authority_store.activate(
            current.tool_id,
            expected_current_head_digest=None,
            build=promoted,
        )
    next_head = authority_store.activate(
        current.tool_id,
        expected_current_head_digest=current.authority_head_digest,
        build=promoted,
    )
    assert next_head.fence_epoch == current.fence_epoch + 1
    assert next_head.authority_head_digest != current.authority_head_digest


def test_targetd_catalog_head_change_blocks_call_before_accept(tmp_path):
    service, session, activation, manifest, _, _, _ = _activation_setup(tmp_path)
    authority = service.activate_authority(
        activation,
        session_id=session.session_id,
        provider_id="ros2-readonly",
    )
    assert service.release_catalog is not None
    catalog_path = service.release_catalog.catalog_path
    catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
    catalog["target_revision"] = 2
    catalog_path.write_text(json.dumps(catalog, sort_keys=True), encoding="utf-8")
    request = _execution_request(
        authority,
        session,
        idempotency_key="stale-catalog-head",
    )
    with pytest.raises(ProtocolError, match="CATALOG_HEAD_STALE"):
        service.accept_call(
            request,
            manifest,
            provider_id="ros2-readonly",
        )
    assert service.query_call(session.session_id, request.idempotency_key) is None


def test_targetd_same_channel_mapping_cancel_blocks_new_call_before_provider(
    tmp_path,
):
    service, session, activation, _, _, _, _ = _activation_setup(tmp_path)
    calls = []

    def observe(binding, arguments):
        calls.append((dict(binding), dict(arguments)))
        return {"status": "SUCCEEDED", "raw": "safe odom sample"}

    resolver = Ros2RuntimeResolver(
        Ros2RuntimeSnapshot(
            "humble",
            "/opt/ros/humble/bin/ros2",
            parse_ros2_topic_types(["/odom nav_msgs/msg/Odometry"]),
        )
    )
    provider = Ros2ReadOnlyProvider(ros2_registry(resolver, observe))
    daemon = TargetdDaemon(
        service,
        execute_calls=True,
        provider=provider,
    )
    daemon._session = session
    activated = daemon._handle(
        ProtocolFrame.create(
            kind=FrameKind.ACTIVATE_AUTHORITY,
            sequence=0,
            session_id=session.session_id,
            payload=activation.model_dump(mode="json"),
        )
    )
    assert activated.payload["ok"] is True
    assert activated.payload["provider_invocation_count"] == 0
    authority = TargetdExecutionAuthority.model_validate(activated.payload["authority"])

    first_request = _execution_request(
        authority,
        session,
        run_id="activation-run",
        idempotency_key="before-mapping-cancel",
    )
    first = daemon._handle(
        ProtocolFrame.create(
            kind=FrameKind.CALL,
            sequence=1,
            session_id=session.session_id,
            run_id=first_request.run_id,
            payload=first_request.model_dump(mode="json"),
        )
    )
    assert first.payload["ok"] is True
    assert first.payload["receipt"]["status"] == "SUCCEEDED"
    assert first.payload["provider_invocation_count"] == 1
    assert len(calls) == 1

    cancel = TargetdMappingCancelRequest(
        schema_version="rolo-targetd-mapping-cancel/v1",
        tool_id=authority.tool_id,
        authority_head_digest=authority.authority_head_digest,
        mapping_confirmation_receipt_digest=authority.mapping_confirmation_receipt_digest,
        idempotency_key="cancel-current-mapping",
    )
    cancelled = daemon._handle(
        ProtocolFrame.create(
            kind=FrameKind.CANCEL_MAPPING,
            sequence=2,
            session_id=session.session_id,
            payload=cancel.model_dump(mode="json"),
        )
    )
    assert cancelled.payload["ok"] is True
    assert cancelled.payload["receipt"]["decision"] == "CANCELLED"
    assert cancelled.payload["receipt"]["actor_id"] == "targetd:mentorpi"
    assert cancelled.payload["provider_invocation_count"] == 1

    after_cancel = _execution_request(
        authority,
        session,
        run_id="activation-run",
        idempotency_key="after-mapping-cancel",
    )
    blocked = daemon._handle(
        ProtocolFrame.create(
            kind=FrameKind.CALL,
            sequence=3,
            session_id=session.session_id,
            run_id=after_cancel.run_id,
            payload=after_cancel.model_dump(mode="json"),
        )
    )
    assert blocked.payload["ok"] is False
    assert blocked.payload["status"] == "BLOCKED"
    assert "MAPPING_CONFIRMATION_CANCELLED" in blocked.payload["error"]
    assert blocked.payload["provider_invocation_count"] == 1
    assert (
        service.query_call(
            session.session_id,
            after_cancel.idempotency_key,
        )
        is None
    )
    assert len(calls) == 1


def test_targetd_mapping_cancel_rejects_noncurrent_head_without_tombstone(
    tmp_path,
):
    service, session, activation, _, _, confirmations, _ = _activation_setup(tmp_path)
    authority = service.activate_authority(
        activation,
        session_id=session.session_id,
        provider_id="ros2-readonly",
    )
    forged = TargetdMappingCancelRequest(
        schema_version="rolo-targetd-mapping-cancel/v1",
        tool_id=authority.tool_id,
        authority_head_digest="f" * 64,
        mapping_confirmation_receipt_digest=authority.mapping_confirmation_receipt_digest,
        idempotency_key="forged-cancel",
    )
    with pytest.raises(ProtocolError, match="HEAD_MISMATCH"):
        service.cancel_mapping(forged, session_id=session.session_id)
    assert len(confirmations.receipts()) == 1


def test_execution_request_v1_cannot_migrate_physical_authority(tmp_path):
    source = b"def execute(arguments): return arguments"
    manifest = ExecutionBundleManifest.build(
        tool_id="app.generic",
        source=source,
        binding_digest="a" * 64,
        signer_key_id="rolo-dev",
        signing_key=b"secret",
    )
    service, authority, _, _ = _execution_setup(tmp_path, manifest, source, journey_session_id="legacy-migration")
    session = _execution_session(service, authority, "legacy-migration")
    legacy = {
        "schema_version": "rolo-execution-request/v1",
        "run_id": "legacy-run",
        "session_id": session.session_id,
        "target_id": authority.target_id,
        "idempotency_key": "legacy-call",
        "bundle_digest": authority.bundle_digest,
        "binding_digest": authority.binding_digest,
        "surface_digest": authority.surface_digest,
        "arguments": {},
        "mode": authority.mode,
        "deadline": datetime.now(timezone.utc) + timedelta(seconds=30),
    }
    with pytest.raises(ValueError, match="rolo-execution-request/v2"):
        ExecutionRequest.model_validate(legacy)
    with pytest.raises(
        ProtocolError,
        match="PHYSICAL_MOTION_EXECUTION_REQUEST_V3_REQUIRED",
    ):
        ExecutionRequest.migrate_v1(
            legacy,
            authority=authority,
            provider_id=authority.provider_id,
            provider_operation=authority.provider_operation,
        )


def test_execution_request_v1_migration_preserves_nonmotion_v2_compatibility(
    tmp_path,
):
    source = b"raise RuntimeError('read-only provider owns execution')\n"
    manifest = ExecutionBundleManifest.build(
        tool_id="app.observe.odom",
        source=source,
        binding_digest="a" * 64,
        signer_key_id="rolo-dev",
        signing_key=b"secret",
        observation_contract={
            "provider": "ros2-readonly",
            "operation": "odom.sample",
        },
    )
    service, authority, _, _ = _execution_setup(
        tmp_path,
        manifest,
        source,
        provider_id="ros2-readonly",
        provider_operation="odom.sample",
        operation_kind=OperationKind.OBSERVE,
        journey_session_id="legacy-observe-migration",
    )
    session = _execution_session(
        service,
        authority,
        "legacy-observe-migration",
    )
    legacy = {
        "schema_version": "rolo-execution-request/v1",
        "run_id": "legacy-observe-run",
        "session_id": session.session_id,
        "target_id": authority.target_id,
        "idempotency_key": "legacy-observe-call",
        "bundle_digest": authority.bundle_digest,
        "binding_digest": authority.binding_digest,
        "surface_digest": authority.surface_digest,
        "arguments": {},
        "mode": authority.mode,
        "deadline": datetime.now(timezone.utc) + timedelta(seconds=30),
    }
    migrated = ExecutionRequest.migrate_v1(
        legacy,
        authority=authority,
        provider_id=authority.provider_id,
        provider_operation=authority.provider_operation,
    )
    parsed = validate_execution_request(migrated)
    assert type(parsed) is ExecutionRequest
    assert parsed.schema_version == "rolo-execution-request/v2"
    assert parsed.authority_head_digest == authority.authority_head_digest


def test_targetd_plain_complete_cannot_mint_success(tmp_path):
    source = b"def execute(arguments): return arguments"
    manifest = _readonly_manifest("app.observe.test", source)
    service, authority, _, _ = _readonly_execution_setup(
        tmp_path,
        manifest,
        source,
        journey_session_id="plain-complete",
    )
    session = _execution_session(service, authority, "plain-complete")
    request = _execution_request(authority, session)
    service.accept_call(request, manifest, provider_id=authority.provider_id)
    with pytest.raises(ProtocolError, match="fenced provider"):
        service.complete_call(session.session_id, request.idempotency_key, status="SUCCEEDED")


def test_targetd_service_uses_signer_key_id_for_verification(tmp_path):
    source = b"def execute(arguments): return arguments"
    manifest = ExecutionBundleManifest.build(
        tool_id="app.base.rotate",
        source=source,
        binding_digest="a" * 64,
        signer_key_id="release-1",
        signing_key=b"release-key",
    )
    service = TargetdService(
        target_id="mentorpi",
        state_root=tmp_path / "state",
        verification_keys={"release-1": b"release-key"},
    )
    service.put_bundle(manifest, source)
    with pytest.raises(ValueError, match="TARGETD_BUNDLE_SIGNER_UNTRUSTED"):
        service.put_bundle(manifest.model_copy(update={"signer_key_id": "other"}), source)


def test_request_requires_timezone_aware_deadline(tmp_path):
    source = b"def execute(arguments): return arguments"
    manifest = ExecutionBundleManifest.build(
        tool_id="app.generic",
        source=source,
        binding_digest="a" * 64,
        signer_key_id="rolo-dev",
        signing_key=b"secret",
    )
    service, authority, _, _ = _execution_setup(tmp_path, manifest, source, journey_session_id="session-timezone")
    session = _execution_session(service, authority, "session-timezone")
    payload = _execution_request(authority, session).model_dump(mode="python")
    payload["deadline"] = datetime.now() + timedelta(seconds=30)
    with pytest.raises(ValueError, match="timezone"):
        ExecutionRequestV3.model_validate(payload)


def test_targetd_daemon_handoff_updates_persisted_phase(tmp_path):
    service = TargetdService(target_id="mentorpi", state_root=tmp_path / "state")
    daemon = TargetdDaemon(service)
    session = JourneySession.create(session_id="daemon-session", target_id="mentorpi", profile_id="landerpi")
    opened = daemon._handle(
        ProtocolFrame.create(
            kind=FrameKind.OPEN_JOURNEY,
            sequence=0,
            session_id=session.session_id,
            payload={"target_id": "mentorpi", "profile_id": "landerpi"},
        )
    )
    assert opened.payload["ok"] is True
    handed_off = daemon._handle(
        ProtocolFrame.create(
            kind=FrameKind.HANDOFF,
            sequence=1,
            session_id=session.session_id,
            payload={"phase": "PROBE"},
        )
    )
    assert handed_off.payload["phase"] == "PROBE"
    assert service.state.load_session(session.session_id).phase.value == "PROBE"


def test_targetd_daemon_open_rejects_surface_digest_conflict(tmp_path):
    service = TargetdService(target_id="mentorpi", state_root=tmp_path / "state")
    session = service.open_session(
        JourneySession.create(
            session_id="surface-conflict",
            target_id="mentorpi",
            profile_id="landerpi",
        ).model_copy(update={"surface_digest": "a" * 64})
    )
    daemon = TargetdDaemon(service)
    response = daemon._handle(
        ProtocolFrame.create(
            kind=FrameKind.OPEN_JOURNEY,
            sequence=0,
            session_id=session.session_id,
            payload={
                "target_id": "mentorpi",
                "profile_id": "landerpi",
                "resume_token": session.resume_token,
                "surface_digest": "b" * 64,
            },
        )
    )
    assert response.payload["ok"] is False
    assert response.payload["error"] == "TARGETD_REQUEST_VALIDATION_FAILED"


def test_targetd_daemon_existing_open_requires_resume_token(tmp_path):
    service = TargetdService(target_id="mentorpi", state_root=tmp_path / "state")
    session = service.open_session(
        JourneySession.create(
            session_id="resume-token-required",
            target_id="mentorpi",
            profile_id="landerpi",
        )
    )
    daemon = TargetdDaemon(service)

    missing = daemon._handle(
        ProtocolFrame.create(
            kind=FrameKind.OPEN_JOURNEY,
            sequence=0,
            session_id=session.session_id,
            payload={"target_id": "mentorpi", "profile_id": "landerpi"},
        )
    )
    assert missing.payload["ok"] is False
    assert missing.payload["error"] == "TARGETD_REQUEST_VALIDATION_FAILED"

    wrong = daemon._handle(
        ProtocolFrame.create(
            kind=FrameKind.OPEN_JOURNEY,
            sequence=1,
            session_id=session.session_id,
            payload={
                "target_id": "mentorpi",
                "profile_id": "landerpi",
                "resume_token": "wrong-token",
            },
        )
    )
    assert wrong.payload["ok"] is False
    assert wrong.payload["error"] == "TARGETD_REQUEST_VALIDATION_FAILED"

    resumed = daemon._handle(
        ProtocolFrame.create(
            kind=FrameKind.OPEN_JOURNEY,
            sequence=2,
            session_id=session.session_id,
            payload={
                "target_id": "mentorpi",
                "profile_id": "landerpi",
                "resume_token": session.resume_token,
            },
        )
    )
    assert resumed.payload["ok"] is True


@pytest.mark.parametrize(
    "inactive_state",
    ("closed", "expired"),
)
def test_targetd_daemon_existing_open_rejects_closed_or_expired(tmp_path, inactive_state):
    service = TargetdService(target_id="mentorpi", state_root=tmp_path / "state")
    session = JourneySession.create(
        session_id="resume-inactive",
        target_id="mentorpi",
        profile_id="landerpi",
    )
    if inactive_state == "closed":
        session = session.model_copy(update={"closed": True})
    else:
        now = datetime.now(timezone.utc)
        session = session.model_copy(
            update={
                "created_at": now - timedelta(hours=2),
                "expires_at": now - timedelta(hours=1),
            }
        )
    service.open_session(session)

    response = TargetdDaemon(service)._handle(
        ProtocolFrame.create(
            kind=FrameKind.OPEN_JOURNEY,
            sequence=0,
            session_id=session.session_id,
            payload={
                "target_id": "mentorpi",
                "profile_id": "landerpi",
                "resume_token": session.resume_token,
            },
        )
    )

    assert response.payload["ok"] is False
    assert response.payload["error"] == "TARGETD_REQUEST_VALIDATION_FAILED"


def test_targetd_daemon_resumes_session_and_queries_receipt(tmp_path):
    service = TargetdService(target_id="mentorpi", state_root=tmp_path / "state")
    session = service.open_session(JourneySession.create(session_id="resume-session", target_id="mentorpi", profile_id="landerpi"))
    daemon = TargetdDaemon(service)
    daemon._session = session
    resumed = daemon._handle(
        ProtocolFrame.create(
            kind=FrameKind.RESUME_SESSION,
            sequence=0,
            session_id=session.session_id,
            payload={"session_id": session.session_id, "resume_token": session.resume_token},
        )
    )
    assert resumed.payload["ok"] is True
    queried = daemon._handle(
        ProtocolFrame.create(
            kind=FrameKind.QUERY_CALL,
            sequence=1,
            session_id=session.session_id,
            payload={"call_id": "missing-call"},
        )
    )
    assert queried.payload["receipt"] is None


def test_targetd_daemon_routes_dsl_on_same_bound_journey_session(tmp_path):
    service = TargetdService(target_id="mentorpi", state_root=tmp_path / "state")
    session = service.open_session(JourneySession.create(session_id="combined-channel", target_id="mentorpi", profile_id="landerpi"))

    class RecordingDslService:
        calls = 0

        def handle(self, frame):
            self.calls += 1
            return DslFrame(
                frame_type=DslFrameType.DSL_RESULT,
                request_id=frame.request_id,
                payload={"status": "PASS"},
            )

    dsl = RecordingDslService()
    daemon = TargetdDaemon(service, dsl_service=dsl)
    daemon._session = session
    nested = DslFrame(
        frame_type=DslFrameType.DSL_PUT,
        request_id="dsl-1",
        payload={
            "journey_session_id": session.session_id,
            "context": {"robot_id": "mentorpi"},
        },
    )
    response = daemon._handle(
        ProtocolFrame.create(
            kind=FrameKind.DSL_REQUEST,
            sequence=0,
            session_id=session.session_id,
            payload={"frame": nested.model_dump(mode="json")},
        )
    )
    assert response.payload["ok"] is True
    assert response.payload["frame"]["payload"]["status"] == "PASS"
    assert dsl.calls == 1

    mismatched = nested.model_copy(update={"payload": {"journey_session_id": "another-session"}})
    blocked = daemon._handle(
        ProtocolFrame.create(
            kind=FrameKind.DSL_REQUEST,
            sequence=1,
            session_id=session.session_id,
            payload={"frame": mismatched.model_dump(mode="json")},
        )
    )
    assert blocked.payload["ok"] is False
    assert blocked.payload["error"] == "TARGETD_REQUEST_VALIDATION_FAILED"
    assert dsl.calls == 1


def test_targetd_daemon_terminalizes_unexpected_worker_exception(tmp_path):
    source = b"def execute(arguments): return arguments\n"
    manifest = _readonly_manifest("app.observe.test", source)
    service, authority, _, _ = _readonly_execution_setup(
        tmp_path,
        manifest,
        source,
        journey_session_id="worker-failure",
    )
    session = _execution_session(service, authority, "worker-failure")
    request = _execution_request(
        authority,
        session,
        run_id="worker-failure-run",
        idempotency_key="worker-failure-call",
    )
    resolver = Ros2RuntimeResolver(
        Ros2RuntimeSnapshot(
            "humble",
            "/opt/ros/humble/bin/ros2",
            parse_ros2_topic_types(["/odom nav_msgs/msg/Odometry"]),
        )
    )
    daemon = TargetdDaemon(
        service,
        execute_calls=True,
        provider=Ros2ReadOnlyProvider(
            ros2_registry(
                resolver,
                lambda _binding, _arguments: {"status": "SUCCEEDED", "raw": ""},
            )
        ),
    )
    daemon._session = session

    class FailingWorker:
        def execute(self, *_args, **_kwargs):
            raise ValueError("unexpected worker failure")

    daemon.worker = FailingWorker()
    response = daemon._handle(
        ProtocolFrame.create(
            kind=FrameKind.CALL,
            sequence=0,
            session_id=session.session_id,
            payload=request.model_dump(mode="json"),
        )
    )
    assert response.payload["ok"] is True
    assert response.payload["receipt"]["status"] == "UNKNOWN"
    assert response.payload["receipt"]["result"] == {
        "error": "WORKER_EXCEPTION_AMBIGUOUS"
    }
    assert service.query_call(request.session_id, request.idempotency_key).status == "UNKNOWN"


def test_targetd_daemon_blocks_rotation_before_missing_provider_can_run(tmp_path):
    source = b"def execute(arguments): return {'status': 'SUCCEEDED'}\n"
    manifest = ExecutionBundleManifest.build(
        tool_id="app.base.rotate",
        source=source,
        binding_digest="a" * 64,
        signer_key_id="rolo-dev",
        signing_key=b"secret",
    )
    service, authority, _, _ = _execution_setup(tmp_path, manifest, source, journey_session_id="rotation-provider")
    session = _execution_session(service, authority, "rotation-provider")
    request = _execution_request(
        authority,
        session,
        run_id="rotation-provider-run",
        idempotency_key="rotation-provider-call",
    )
    daemon = TargetdDaemon(service, execute_calls=True)
    daemon._session = session
    response = daemon._handle(
        ProtocolFrame.create(
            kind=FrameKind.CALL,
            sequence=0,
            session_id=session.session_id,
            payload=request.model_dump(mode="json"),
        )
    )
    assert response.payload["ok"] is False
    assert response.payload["error"] == "TARGETD_PHYSICAL_PROCESS_WORKER_REQUIRED"
    assert service.query_call(request.session_id, request.idempotency_key) is None


def test_targetd_rotation_receipt_fails_closed_without_physical_evidence(tmp_path):
    source = b"def execute(arguments): return arguments\n"
    manifest = ExecutionBundleManifest.build(
        tool_id="app.base.rotate",
        source=source,
        binding_digest="a" * 64,
        signer_key_id="rolo-dev",
        signing_key=b"secret",
    )
    verified = _verified_rotation_result()
    weak = {"status": "SUCCEEDED", "stop_published": True, "stopped_observed": True}
    assert TargetdDaemon._terminal_status(manifest, verified) == "SUCCEEDED"
    assert TargetdDaemon._terminal_status(manifest, weak) == "UNKNOWN"
    assert TargetdDaemon._terminal_status(manifest, {"status": "BLOCKED", "error": "NO_LIVE_INDEPENDENT_IMU"}) == "FAILED"


def test_targetd_rotation_receipt_rejects_motion_witness_without_exact_angle(tmp_path):
    source = b"def execute(arguments): return arguments\n"
    manifest = ExecutionBundleManifest.build(
        tool_id="app.base.rotate",
        source=source,
        binding_digest="a" * 64,
        signer_key_id="rolo-dev",
        signing_key=b"secret",
    )
    result = _verified_rotation_result(
        angle_accuracy_verified=False,
        independent_motion_evidence={
            "status": "VERIFIED",
            "independent_of_odom": True,
            "settled": True,
            "angle_accuracy_status": "NOT_VERIFIED",
            "target_angle_error_rad": 0.02,
            "target_angle_tolerance_rad": 0.005,
        },
    )
    assert TargetdDaemon._terminal_status(manifest, result) == "UNKNOWN"


@pytest.mark.parametrize(
    "evidence_update",
    [
        {"independent_of_odom": False},
        {"angle_accuracy_status": "NOT_VERIFIED"},
        {"target_angle_error_rad": 0.02},
        {"target_angle_tolerance_rad": 0.0},
    ],
)
def test_targetd_rotation_receipt_rejects_unproven_independent_or_exact_angle(evidence_update):
    manifest = ExecutionBundleManifest.build(
        tool_id="app.base.rotate",
        source=b"def execute(arguments): return arguments\n",
        binding_digest="a" * 64,
        signer_key_id="rolo-dev",
        signing_key=b"secret",
    )
    result = _verified_rotation_result()
    result["independent_motion_evidence"].update(evidence_update)
    assert TargetdDaemon._terminal_status(manifest, result) == "UNKNOWN"


@pytest.mark.parametrize("reported", ["FAILED", "STOPPED", "CANCELLED", "UNKNOWN", "NOT_ACCEPTED"])
def test_targetd_rotation_receipt_preserves_explicit_terminal_status(reported):
    manifest = ExecutionBundleManifest.build(
        tool_id="app.base.rotate",
        source=b"def execute(arguments): return arguments\n",
        binding_digest="a" * 64,
        signer_key_id="rolo-dev",
        signing_key=b"secret",
    )
    assert TargetdDaemon._terminal_status(manifest, {"status": reported}) == reported


@pytest.mark.parametrize(
    ("reported", "expected"),
    [
        ({"value": "ok"}, "SUCCEEDED"),
        ({"status": "SUCCEEDED"}, "SUCCEEDED"),
        ({"status": "FAILED", "error": "provider"}, "FAILED"),
        ({"status": "BLOCKED", "error": "policy"}, "FAILED"),
        ({"status": "UNKNOWN"}, "UNKNOWN"),
        ({"status": "NOT_ACCEPTED", "error": "lease"}, "NOT_ACCEPTED"),
    ],
)
def test_targetd_generic_receipt_preserves_explicit_result_status(reported, expected):
    manifest = ExecutionBundleManifest.build(
        tool_id="app.generic",
        source=b"def execute(arguments): return arguments\n",
        binding_digest="a" * 64,
        signer_key_id="rolo-dev",
        signing_key=b"secret",
    )
    assert TargetdDaemon._terminal_status(manifest, reported) == expected


@pytest.mark.parametrize(
    ("reported", "expected"),
    [
        ({"status": "SUCCEEDED"}, "SUCCEEDED"),
        ({"status": "STOPPED"}, "STOPPED"),
        ({"status": "CANCELLED"}, "CANCELLED"),
        ({"status": "FAILED"}, "FAILED"),
        ({"status": "BLOCKED"}, "FAILED"),
        ({"status": "RUNNING"}, "UNKNOWN"),
        ({"value": "missing-status"}, "UNKNOWN"),
    ],
)
def test_targetd_mapping_receipt_is_terminal_and_fail_closed(reported, expected):
    manifest = ExecutionBundleManifest.build(
        tool_id="app.mapping.status",
        source=b"def execute(arguments): return arguments\n",
        binding_digest="a" * 64,
        signer_key_id="rolo-dev",
        signing_key=b"secret",
    )
    assert TargetdDaemon._terminal_status(manifest, reported) == expected


def test_python_bundle_worker_uses_generic_entrypoint_and_limits_output():
    source = b"def execute(arguments):\n    return {'received': arguments}\n"
    manifest = ExecutionBundleManifest.build(
        tool_id="app.base.rotate",
        source=source,
        binding_digest="a" * 64,
        signer_key_id="rolo-dev",
        signing_key=b"secret",
        limits={"max_output_bytes": 4096},
    )
    result = PythonBundleWorker().execute(manifest, source, {"angle_degrees": 15})
    assert result == {"received": {"angle_degrees": 15}}


def test_python_bundle_worker_passes_registered_provider_context():
    class Provider:
        def invoke(self, operation, arguments):
            return {"operation": operation, **arguments}

    source = b"def execute(arguments, provider):\n    return provider.invoke('base.rotate', arguments)\n"
    manifest = ExecutionBundleManifest.build(
        tool_id="app.base.rotate",
        source=source,
        binding_digest="a" * 64,
        signer_key_id="rolo-dev",
        signing_key=b"secret",
    )
    result = PythonBundleWorker(Provider()).execute(manifest, source, {"angle_degrees": 15, "max_speed_rad_s": 0.15})
    assert result["operation"] == "base.rotate"


def test_python_bundle_worker_does_not_pollute_generic_provider_arguments():
    seen = {}

    class Provider:
        def invoke(self, operation, arguments):
            seen["operation"] = operation
            seen["arguments"] = dict(arguments)
            return {"status": "BLOCKED", "motion_started": False}

    source = b"def execute(arguments, provider):\n    return provider.invoke('base.rotate', arguments)\n"
    manifest = ExecutionBundleManifest.build(
        tool_id="app.base.rotate",
        source=source,
        binding_digest="a" * 64,
        signer_key_id="rolo-dev",
        signing_key=b"secret",
    )
    PythonBundleWorker(Provider()).execute(manifest, source, {"angle_degrees": 1, "max_speed_rad_s": 0.1})
    assert seen["operation"] == "base.rotate"
    assert "__rolo_observation_contract" not in seen["arguments"]
    assert seen["arguments"]["angle_degrees"] == 1


def test_python_bundle_worker_does_not_alias_ros_rotation_through_generic_tool():
    source = b"def execute(arguments, provider):\n    return provider.invoke('base.rotate', arguments)\n"
    manifest = ExecutionBundleManifest.build(
        tool_id="app.generic",
        source=source,
        binding_digest="a" * 64,
        signer_key_id="rolo-dev",
        signing_key=b"secret",
        observation_contract={
            "provider": "ros-container",
            "operation": "base.rotate",
            "command_endpoint": "/cmd_vel",
        },
    )
    with pytest.raises(ProtocolError, match="requires app.base.rotate"):
        PythonBundleWorker(RosContainerProvider("MentorPi")).execute(manifest, source, {"angle_degrees": 1, "max_speed_rad_s": 0.1})


def test_python_bundle_worker_allows_registered_mapping_tool(monkeypatch):
    seen = {}

    def fake_run(command, **kwargs):
        seen["input"] = kwargs["input"]
        return type(
            "Completed",
            (),
            {
                "returncode": 0,
                "stdout": '{"schema_version":"rolo-landerpi-mapping-runtime/v1","status":"SUCCEEDED","mode":"status"}\n',
                "stderr": "",
            },
        )()

    monkeypatch.setattr("rolo.targetd.worker.subprocess.run", fake_run)
    source = b"def execute(arguments, provider):\n    return provider.invoke('mapping.status', arguments)\n"
    manifest = ExecutionBundleManifest.build(
        tool_id="app.mapping.status",
        source=source,
        binding_digest="a" * 64,
        signer_key_id="rolo-dev",
        signing_key=b"secret",
        observation_contract=_mapping_contract(),
    )
    result = PythonBundleWorker(RosContainerProvider("MentorPi")).execute(manifest, source, {"status_window_s": 2})
    assert result["status"] == "SUCCEEDED"
    assert '--mode","status' in seen["input"]


def test_python_bundle_worker_rejects_mapping_tool_operation_alias(monkeypatch):
    source = b"def execute(arguments, provider):\n    return provider.invoke('mapping.stop', arguments)\n"
    manifest = ExecutionBundleManifest.build(
        tool_id="app.mapping.status",
        source=source,
        binding_digest="a" * 64,
        signer_key_id="rolo-dev",
        signing_key=b"secret",
        observation_contract=_mapping_contract(),
    )
    with pytest.raises(ProtocolError, match="operation mismatches|tool id"):
        PythonBundleWorker(RosContainerProvider("MentorPi")).execute(manifest, source, {})


def test_ros_container_provider_uses_fixed_docker_argv(monkeypatch):
    seen = {}

    def fake_run(command, **kwargs):
        seen["command"] = command
        seen["input"] = kwargs["input"]
        return type("Completed", (), {"returncode": 0, "stdout": '{"stop_published":true}\n', "stderr": ""})()

    monkeypatch.setattr("rolo.targetd.worker.subprocess.run", fake_run)
    result = RosContainerProvider("MentorPi").invoke("base.rotate", {"angle_degrees": 15, "max_speed_rad_s": 0.15})
    assert result["stop_published"] is True
    assert seen["command"][:7] == ["docker", "exec", "-i", "-u", "ubuntu", "MentorPi", "bash"]
    assert "ros2 topic pub" not in seen["input"]
    assert "angle_degrees" in seen["input"]
    assert "independent_motion_evidence" in seen["input"]
    assert "independent_feedback_endpoints" in seen["input"]
    # A direct provider call has no signed manifest contract, so it uses the
    # isolated low-level fallback.  Production bundle execution injects the
    # signed contract (covered below) and selects the same route explicitly.
    assert _embedded_provider_request(seen["input"])["command_endpoint"] == "/cmd_vel"


def test_ros_container_provider_rejects_duplicate_json_output(monkeypatch):
    def fake_run(command, **kwargs):
        return type(
            "Completed",
            (),
            {
                "returncode": 0,
                "stdout": '{"status":"SUCCEEDED","status":"UNKNOWN"}\n',
                "stderr": "",
            },
        )()

    monkeypatch.setattr("rolo.targetd.worker.subprocess.run", fake_run)
    with pytest.raises(ProtocolError, match="invalid JSON"):
        RosContainerProvider("MentorPi").invoke("base.rotate", {"angle_degrees": 15, "max_speed_rad_s": 0.15})


def test_ros_container_provider_honors_signed_command_endpoint_contract(monkeypatch):
    seen = {}

    def fake_run(command, **kwargs):
        seen["input"] = kwargs["input"]
        return type("Completed", (), {"returncode": 0, "stdout": '{"status":"UNKNOWN"}\n', "stderr": ""})()

    monkeypatch.setattr("rolo.targetd.worker.subprocess.run", fake_run)
    contract = {
        "provider": "ros-container",
        "operation": "base.rotate",
        "command_endpoint": "/cmd_vel",
        "feedback_endpoints": ["/odom_raw", "/odom"],
        "independent_feedback_endpoints": ["/imu", "/imu_corrected"],
        "interface_type": "geometry_msgs/msg/Twist",
        "stop_strategy": "zero_velocity",
    }
    RosContainerProvider("MentorPi").invoke(
        "base.rotate",
        {
            "angle_degrees": 1,
            "max_speed_rad_s": 0.1,
            "__rolo_observation_contract": contract,
        },
    )
    assert _embedded_provider_request(seen["input"])["command_endpoint"] == "/cmd_vel"


def test_ros_container_provider_preserves_v1_topic_contract_alias(monkeypatch):
    seen = {}

    def fake_run(command, **kwargs):
        seen["input"] = kwargs["input"]
        return type("Completed", (), {"returncode": 0, "stdout": '{"status":"UNKNOWN"}\n', "stderr": ""})()

    monkeypatch.setattr("rolo.targetd.worker.subprocess.run", fake_run)
    RosContainerProvider("MentorPi").invoke(
        "base.rotate",
        {
            "angle_degrees": 1,
            "max_speed_rad_s": 0.1,
            "__rolo_observation_contract": {
                "provider": "ros-container",
                "operation": "base.rotate",
                "topic": "/controller/cmd_vel",
            },
        },
    )
    assert _embedded_provider_request(seen["input"])["command_endpoint"] == "/controller/cmd_vel"


def _mapping_contract(operation: str = "mapping.status") -> dict[str, str]:
    return {
        "provider": "ros-container",
        "operation": operation,
        "runtime": "rolo-mapping-v1",
        "cmd_topic": "/controller/cmd_vel",
        "scan_topic": "/scan",
        "odom_topic": "/odom",
        "map_topic": "/map",
        "stop_marker": "/tmp/rolo-mapping-stop",
        "status_file": "/tmp/rolo-mapping-status.json",
        "map_dir": "/home/ubuntu/rolo_debug/maps",
    }


def _embedded_mapping_argv(program: str) -> list[str]:
    match = re.search(r"sys\.argv = (\[.*\])\n", program)
    assert match is not None
    return json.loads(match.group(1))


def test_ros_container_provider_mapping_uses_fixed_runtime_and_contract(monkeypatch):
    seen = {}

    def fake_run(command, **kwargs):
        seen["command"] = command
        seen["input"] = kwargs["input"]
        seen["timeout"] = kwargs["timeout"]
        return type(
            "Completed",
            (),
            {
                "returncode": 0,
                "stdout": '{"schema_version":"rolo-landerpi-mapping-runtime/v1","status":"SUCCEEDED","mode":"status"}\n',
                "stderr": "",
            },
        )()

    monkeypatch.setattr("rolo.targetd.worker.subprocess.run", fake_run)
    result = RosContainerProvider("MentorPi").invoke(
        "mapping.status",
        {"status_window_s": 3, "__rolo_observation_contract": _mapping_contract()},
    )
    assert result["status"] == "SUCCEEDED"
    assert seen["command"][:7] == ["docker", "exec", "-i", "-u", "ubuntu", "MentorPi", "bash"]
    argv = _embedded_mapping_argv(seen["input"])
    assert argv[:3] == ["rolo_mapping_runtime", "--mode", "status"]
    assert "--cmd-topic" in argv and "/controller/cmd_vel" in argv
    assert "--map-topic" in argv and "/map" in argv
    # The reviewed runtime reserves the fixed topic-publisher fallback for the
    # explicit stop operation; status itself remains a sensor observation.
    assert "_stop_immediate" in seen["input"]
    assert "rolo-landerpi-mapping-runtime/v1" in seen["input"]
    # Status is bounded by its observation window; a stalled DDS graph must
    # not hold the targetd channel for the provider's 120-second default.
    assert seen["timeout"] == 11.0


def test_mapping_runtime_source_prefers_installed_worker_adjacent_copy(tmp_path, monkeypatch):
    worker_path = tmp_path / "remote" / "rolo" / "targetd" / "worker.py"
    worker_path.parent.mkdir(parents=True)
    worker_path.write_text("# worker\n", encoding="utf-8")
    bundled = worker_path.with_name("landerpi_autonomous_mapping_runtime.py")
    bundled.write_text("# bundled runtime\n", encoding="utf-8")
    monkeypatch.setattr(worker_module, "__file__", str(worker_path))
    assert RosContainerProvider._mapping_runtime_source() == bundled.read_text(encoding="utf-8")


@pytest.mark.parametrize(
    ("operation", "arguments", "mode"),
    [
        ("mapping.run", {"duration_s": 5, "max_distance_m": 0.2, "obstacle_stop_m": 0.3}, "run"),
        ("mapping.stop", {}, "stop"),
        ("mapping.save", {"map_name": "field-1", "save_timeout_s": 5}, "save"),
    ],
)
def test_ros_container_provider_mapping_operations_have_fixed_modes(monkeypatch, operation, arguments, mode):
    seen = {}

    def fake_run(command, **kwargs):
        seen["input"] = kwargs["input"]
        return type(
            "Completed",
            (),
            {
                "returncode": 0,
                "stdout": json.dumps(
                    {
                        "schema_version": "rolo-landerpi-mapping-runtime/v1",
                        "status": "STOPPED",
                        "mode": mode,
                    }
                )
                + "\n",
                "stderr": "",
            },
        )()

    monkeypatch.setattr("rolo.targetd.worker.subprocess.run", fake_run)
    provider = RosContainerProvider("MentorPi", autonomous_source_confirmed=True)
    result = provider.invoke(
        operation,
        {**arguments, "__rolo_observation_contract": _mapping_contract(operation)},
    )
    assert result["mode"] == mode
    argv = _embedded_mapping_argv(seen["input"])
    assert argv[argv.index("--mode") + 1] == mode


@pytest.mark.parametrize(
    "contract_update",
    [
        {"runtime": "other"},
        {"operation": "mapping.run"},
        {"provider": "other"},
        {"map_dir": "/tmp/escape"},
        {"unexpected": "field"},
    ],
)
def test_ros_container_provider_mapping_contract_fails_closed(contract_update):
    contract = _mapping_contract()
    contract.update(contract_update)
    with pytest.raises(ProtocolError, match="mapping"):
        RosContainerProvider("MentorPi").invoke(
            "mapping.status",
            {"__rolo_observation_contract": contract},
        )


@pytest.mark.parametrize(
    "arguments",
    [
        {"status_window_s": 0.9},
        {"status_window_s": True},
        {"unknown": 1},
    ],
)
def test_ros_container_provider_mapping_arguments_fail_closed(arguments):
    with pytest.raises(ProtocolError, match="mapping"):
        RosContainerProvider("MentorPi").invoke(
            "mapping.status",
            {**arguments, "__rolo_observation_contract": _mapping_contract()},
        )


def test_ros_container_provider_mapping_run_requires_supervised_source_confirmation():
    with pytest.raises(ProtocolError, match="confirmation"):
        RosContainerProvider("MentorPi").invoke(
            "mapping.run",
            {"__rolo_observation_contract": _mapping_contract("mapping.run")},
        )


@pytest.mark.parametrize(
    "stdout",
    [
        '{"status":"SUCCEEDED","mode":"status"}\n',
        '{"schema_version":"other","status":"SUCCEEDED","mode":"status"}\n',
        '{"schema_version":"rolo-landerpi-mapping-runtime/v1","status":"SUCCEEDED","mode":"run"}\n',
    ],
)
def test_ros_container_provider_mapping_result_contract_is_strict(monkeypatch, stdout):
    def fake_run(command, **kwargs):
        return type("Completed", (), {"returncode": 0, "stdout": stdout, "stderr": ""})()

    monkeypatch.setattr("rolo.targetd.worker.subprocess.run", fake_run)
    with pytest.raises(ProtocolError, match="mapping provider result"):
        RosContainerProvider("MentorPi").invoke(
            "mapping.status",
            {"__rolo_observation_contract": _mapping_contract()},
        )


@pytest.mark.parametrize(
    "contract",
    [
        {"operation": "base.rotate"},
        {"provider": "ros-container"},
        {"provider": "other", "operation": "base.rotate"},
        {"provider": "ros-container", "operation": "base.rotate"},
    ],
)
def test_ros_container_provider_requires_bound_contract_identity(contract):
    with pytest.raises(ProtocolError, match="provider|operation|endpoint"):
        RosContainerProvider("MentorPi").invoke(
            "base.rotate",
            {
                "angle_degrees": 1,
                "max_speed_rad_s": 0.1,
                "__rolo_observation_contract": contract,
            },
        )


@pytest.mark.parametrize(
    "arguments",
    [
        {"angle_degrees": 0, "max_speed_rad_s": 0.1},
        {"angle_degrees": 30.1, "max_speed_rad_s": 0.1},
        {"angle_degrees": 1, "max_speed_rad_s": 0.1501},
        {"angle_degrees": -31, "max_speed_rad_s": 0.15},
        {"angle_degrees": True, "max_speed_rad_s": 0.1},
    ],
)
def test_ros_container_provider_rejects_rotation_values_outside_canary_bounds(arguments):
    with pytest.raises(ProtocolError, match="outside provider limits|arguments are invalid"):
        RosContainerProvider("MentorPi").invoke("base.rotate", arguments)


class _RecordingChannel:
    def __init__(self):
        self.frames = []

    def send(self, frame):
        self.frames.append(frame)

    def receive(self):
        return self.frames[-1]

    def close(self):
        pass


def test_journey_session_client_reuses_sequence_and_rejects_other_target(tmp_path):
    channel = _RecordingChannel()
    source = b"def execute(arguments): return arguments"
    manifest = ExecutionBundleManifest.build(
        tool_id="app.generic",
        source=source,
        binding_digest="a" * 64,
        signer_key_id="rolo-dev",
        signing_key=b"secret",
    )
    service, authority, _, _ = _execution_setup(tmp_path, manifest, source, journey_session_id="session-3")
    session = _execution_session(service, authority, "session-3")
    client = JourneySessionClient(channel, session)
    assert client.open().kind.value == "OPEN_JOURNEY"
    assert client.bootstrap().sequence == 1
    assert client.phase_change("PROBE").sequence == 2
    assert [frame.sequence for frame in channel.frames] == [0, 1, 2]
    with pytest.raises(ValueError, match="session"):
        client.call(
            _execution_request(
                authority,
                session,
                run_id="run-3",
                idempotency_key="call-3",
            ).model_copy(update={"session_id": "other"})
        )


def test_journey_session_client_consumes_event_frames_before_result():
    session = JourneySession.create(session_id="event-session", target_id="mentorpi", profile_id="landerpi")
    sent = []
    queue = [
        ProtocolFrame.create(
            kind=FrameKind.EVENT,
            sequence=0,
            session_id=session.session_id,
            run_id="run-1",
            payload={"call_id": "call-1", "status": "STARTED"},
        ),
        ProtocolFrame.create(
            kind=FrameKind.RESULT,
            sequence=1,
            session_id=session.session_id,
            run_id="run-1",
            payload={"request_kind": "CALL", "ok": True},
        ),
        ProtocolFrame.create(
            kind=FrameKind.RESULT,
            sequence=2,
            session_id=session.session_id,
            payload={"request_kind": "BOOTSTRAP", "ok": True},
        ),
    ]

    class EventChannel:
        def send(self, frame):
            sent.append(frame)

        def receive(self):
            return queue.pop(0)

        def close(self):
            pass

    channel = EventChannel()
    client = JourneySessionClient(channel, session)
    response = client.exchange(
        FrameKind.CALL,
        {"idempotency_key": "call-1"},
        run_id="run-1",
    )
    assert response.kind == FrameKind.RESULT
    assert len(client.last_events) == 1
    assert client.exchange(
        FrameKind.BOOTSTRAP,
        {"session_id": session.session_id},
    ).sequence == 2


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("session_id", "other-session", "journey session"),
        ("run_id", "other-run", "another run"),
        ("sequence", 1, "sequence"),
        ("kind", FrameKind.HAS, "RESULT frame"),
        ("request_kind", "HAS", "request kind"),
        ("request_kind", None, "request kind"),
    ],
)
def test_journey_session_client_rejects_uncorrelated_result_without_resend(
    field,
    value,
    message,
):
    session = JourneySession.create(
        session_id="result-fence-session",
        target_id="mentorpi",
        profile_id="landerpi",
    )
    frame_values = {
        "kind": FrameKind.RESULT,
        "sequence": 0,
        "session_id": session.session_id,
        "run_id": "run-1",
        "payload": {"request_kind": "CALL", "ok": True},
    }
    if field == "request_kind":
        if value is None:
            frame_values["payload"] = {"ok": True}
        else:
            frame_values["payload"] = {"request_kind": value, "ok": True}
    else:
        frame_values[field] = value

    class Channel:
        def __init__(self):
            self.sent = []

        def send(self, frame):
            self.sent.append(frame)

        def receive(self):
            return ProtocolFrame.create(**frame_values)

        def close(self):
            pass

    channel = Channel()
    client = JourneySessionClient(channel, session)
    with pytest.raises(ProtocolError, match=message):
        client.exchange(
            FrameKind.CALL,
            {"idempotency_key": "call-1"},
            run_id="run-1",
        )
    assert len(channel.sent) == 1


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("session_id", "other-session", "journey session"),
        ("run_id", "other-run", "another run"),
        ("sequence", 1, "sequence"),
    ],
)
def test_journey_session_client_rejects_uncorrelated_call_event(
    field,
    value,
    message,
):
    session = JourneySession.create(
        session_id="event-fence-session",
        target_id="mentorpi",
        profile_id="landerpi",
    )
    frame_values = {
        "kind": FrameKind.EVENT,
        "sequence": 0,
        "session_id": session.session_id,
        "run_id": "run-1",
        "payload": {"call_id": "call-1", "status": "STARTED"},
    }
    frame_values[field] = value

    class Channel:
        def __init__(self):
            self.sent = []

        def send(self, frame):
            self.sent.append(frame)

        def receive(self):
            return ProtocolFrame.create(**frame_values)

        def close(self):
            pass

    channel = Channel()
    client = JourneySessionClient(channel, session)
    with pytest.raises(ProtocolError, match=message):
        client.exchange(
            FrameKind.CALL,
            {"idempotency_key": "call-1"},
            run_id="run-1",
        )
    assert len(channel.sent) == 1


def test_journey_session_client_rejects_event_for_wrong_request_or_call_id():
    session = JourneySession.create(
        session_id="event-kind-session",
        target_id="mentorpi",
        profile_id="landerpi",
    )

    class Channel:
        def __init__(self, event):
            self.event = event
            self.sent = []

        def send(self, frame):
            self.sent.append(frame)

        def receive(self):
            return self.event

        def close(self):
            pass

    non_call = Channel(
        ProtocolFrame.create(
            kind=FrameKind.EVENT,
            sequence=0,
            session_id=session.session_id,
            payload={"call_id": "call-1", "status": "STARTED"},
        )
    )
    with pytest.raises(ProtocolError, match="non-CALL"):
        JourneySessionClient(non_call, session).exchange(
            FrameKind.BOOTSTRAP,
            {"session_id": session.session_id},
        )
    assert len(non_call.sent) == 1

    wrong_call = Channel(
        ProtocolFrame.create(
            kind=FrameKind.EVENT,
            sequence=0,
            session_id=session.session_id,
            run_id="run-1",
            payload={"call_id": "other-call", "status": "STARTED"},
        )
    )
    with pytest.raises(ProtocolError, match="idempotency key"):
        JourneySessionClient(wrong_call, session).exchange(
            FrameKind.CALL,
            {"idempotency_key": "call-1"},
            run_id="run-1",
        )
    assert len(wrong_call.sent) == 1


def test_journey_session_client_bounds_call_events():
    session = JourneySession.create(
        session_id="event-limit-session",
        target_id="mentorpi",
        profile_id="landerpi",
    )
    queue = [
        ProtocolFrame.create(
            kind=FrameKind.EVENT,
            sequence=sequence,
            session_id=session.session_id,
            run_id="run-1",
            payload={"call_id": "call-1", "status": "STARTED"},
        )
        for sequence in range(5)
    ]

    class Channel:
        def __init__(self):
            self.sent = []

        def send(self, frame):
            self.sent.append(frame)

        def receive(self):
            return queue.pop(0)

        def close(self):
            pass

    channel = Channel()
    client = JourneySessionClient(channel, session)
    with pytest.raises(ProtocolError, match="too many"):
        client.exchange(
            FrameKind.CALL,
            {"idempotency_key": "call-1"},
            run_id="run-1",
        )
    assert len(client.last_events) == 4
    assert len(channel.sent) == 1


def test_journey_session_client_stays_poisoned_after_consuming_bad_frame():
    session = JourneySession.create(
        session_id="poisoned-frame-session",
        target_id="mentorpi",
        profile_id="landerpi",
    )
    queue = [
        ProtocolFrame.create(
            kind=FrameKind.RESULT,
            sequence=0,
            session_id=session.session_id,
            payload={"request_kind": "HAS", "ok": True},
        ),
        ProtocolFrame.create(
            kind=FrameKind.RESULT,
            sequence=1,
            session_id=session.session_id,
            payload={"request_kind": "BOOTSTRAP", "ok": True},
        ),
    ]

    class Channel:
        def __init__(self):
            self.sent = []

        def send(self, frame):
            self.sent.append(frame)

        def receive(self):
            return queue.pop(0)

        def close(self):
            pass

    channel = Channel()
    client = JourneySessionClient(channel, session)
    with pytest.raises(ProtocolError, match="request kind"):
        client.exchange(
            FrameKind.BOOTSTRAP,
            {"session_id": session.session_id},
        )

    with pytest.raises(ProtocolError, match="unusable after a channel failure"):
        client.exchange(
            FrameKind.BOOTSTRAP,
            {"session_id": session.session_id},
        )

    assert len(channel.sent) == 1
    assert len(queue) == 1


@pytest.mark.parametrize("failure_point", ["send", "receive"])
def test_journey_session_client_stays_poisoned_after_channel_error(failure_point):
    session = JourneySession.create(
        session_id=f"poisoned-{failure_point}-session",
        target_id="mentorpi",
        profile_id="landerpi",
    )

    class Channel:
        def __init__(self):
            self.send_attempts = 0

        def send(self, frame):
            self.send_attempts += 1
            if failure_point == "send":
                raise ConnectionError("send failed")

        def receive(self):
            raise ConnectionError("receive failed")

        def close(self):
            pass

    channel = Channel()
    client = JourneySessionClient(channel, session)
    with pytest.raises(ConnectionError, match=failure_point):
        client.exchange(
            FrameKind.BOOTSTRAP,
            {"session_id": session.session_id},
        )

    with pytest.raises(ProtocolError, match="unusable after a channel failure"):
        client.exchange(
            FrameKind.BOOTSTRAP,
            {"session_id": session.session_id},
        )

    assert channel.send_attempts == 1
