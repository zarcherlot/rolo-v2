import copy
import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker, ValidationError

from rolo.targetd.landerpi_motion_target import (
    AtomicLanderPiMotionStateStore,
    FreshZeroMotionEvidence,
    LanderPiTargetMotionState,
    LanderPiZeroMotionStatus,
    LanderPiZeroMotionTarget,
    PinnedLanderPiRpcSecurity,
    TargetSigningKey,
    compute_armed_zero_provider_identity_digest,
)
from rolo.targetd.motion_acceptance import (
    SignedZeroMotionArtifact,
    ZeroMotionAcceptanceRequest,
    capture_landerpi_isolation_observation,
    compute_provider_fence_digest,
    compute_provider_gate_consume_token_digest,
    compute_zero_motion_fence_lease_digest,
    compute_zero_motion_isolation_digest,
    consume_provider_gate_challenge,
    parse_ros2_topic_info_verbose,
    run_zero_motion_acceptance,
)
from rolo.targetd.motion_safety import (
    MotionSafetyAdmissionRequest,
    MotionSafetyEvidenceBundle,
    MotionSafetyIntent,
    MotionSafetyPolicy,
    MotionSafetyTrustStore,
    SignedMotionEvidence,
    compute_direct_motor_fence_digest,
    compute_estop_response_digest,
    compute_motion_payload_digest,
    compute_ros_graph_digest,
    compute_stop_action_digest,
    evaluate_motion_safety,
)

NOW = datetime(2026, 9, 8, 8, 0, tzinfo=timezone.utc)
TARGET_ID = "mentorpi"
TARGET_IDENTITY = "sha256:mentorpi-device-key"
OPERATOR_ID = "operator:field-1"
COMMAND_ROUTE = "/cmd_vel"
COMMAND_INTERFACE = "geometry_msgs/msg/Twist"
PUBLISHER_IDENTITY = "/rolo_bounded_twist"
COMPETING_COMMAND_ROUTE = "/controller/cmd_vel"
COMMAND_SUBSCRIBER_IDENTITY = "/odom_publisher"
DIRECT_MOTOR_ROUTE = "/ros_robot_controller/set_motor"
DIRECT_MOTOR_INTERFACE = "ros_robot_controller_msgs/msg/MotorsState"
DIRECT_MOTOR_PUBLISHER_IDENTITY = "/odom_publisher"
COMMAND_PUBLISHER_GID = "01.00000001"
COMMAND_SUBSCRIBER_GID = "01.00000002"
COMPETING_SUBSCRIBER_GID = "01.00000003"
DIRECT_MOTOR_PUBLISHER_GID = "01.00000004"
SITE_ID = "site:lab-1"
SAFE_ZONE_ID = "zone:motion-pad-a"
EXECUTION_SUBJECT_DIGEST = "sha256:" + "e" * 64

ISSUERS = {
    "operator": "authority:operator",
    "presence": "authority:presence",
    "safety": "authority:safety",
    "graph": "authority:ros-graph",
    "target": "authority:targetd",
}
KEYS = {
    ISSUERS["operator"]: b"o" * 32,
    ISSUERS["presence"]: b"p" * 32,
    ISSUERS["safety"]: b"s" * 32,
    ISSUERS["graph"]: b"g" * 32,
    ISSUERS["target"]: b"t" * 32,
}
EVIDENCE_FIELDS = (
    "operator_authorization",
    "onsite_presence",
    "safe_zone_confirmation",
    "estop_verification",
    "ros_graph_snapshot",
    "direct_motor_fence",
    "target_stop_acknowledgement",
)


def _digest(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _fresh_zero_claims() -> dict:
    evidence = {
        "schema_version": "rolo-landerpi-fresh-zero-motion-evidence/v1",
        "window_started_at": (NOW - timedelta(seconds=0.4)).isoformat().replace("+00:00", "Z"),
        "window_ended_at": NOW.isoformat().replace("+00:00", "Z"),
        "command_sample_count": 8,
        "command_latest_sample_at": (NOW - timedelta(seconds=0.01)).isoformat().replace("+00:00", "Z"),
        "command_max_abs_component": 0.0,
        "command_samples_digest": _digest("zero-command-samples"),
        "motor_sample_count": 8,
        "motor_latest_sample_at": (NOW - timedelta(seconds=0.01)).isoformat().replace("+00:00", "Z"),
        "motor_value_count": 32,
        "motor_max_abs_rps": 0.0,
        "motor_samples_digest": _digest("zero-motor-samples"),
        "imu_stream": "/imu",
        "imu_sample_count": 8,
        "imu_latest_sample_at": (NOW - timedelta(seconds=0.01)).isoformat().replace("+00:00", "Z"),
        "imu_sample_rate_hz": 20.0,
        "imu_max_abs_angular_z_rad_s": 0.002,
        "imu_max_abs_z_bias_residual_rad_s": 0.001,
        "imu_samples_digest": _digest("stationary-imu-samples"),
    }
    evidence["evidence_sha256"] = compute_motion_payload_digest(evidence)
    return {
        "last_command_is_zero": True,
        "motor_output_zero": True,
        "motors_stopped": True,
        "zero_velocity_verified": True,
        "fresh_zero_evidence_digest": evidence["evidence_sha256"],
        "fresh_zero_evidence": evidence,
    }


def _policy() -> MotionSafetyPolicy:
    return MotionSafetyPolicy(
        target_id=TARGET_ID,
        target_identity=TARGET_IDENTITY,
        site_id=SITE_ID,
        safe_zone_id=SAFE_ZONE_ID,
        command_route=COMMAND_ROUTE,
        command_interface=COMMAND_INTERFACE,
        allowed_publisher_identity=PUBLISHER_IDENTITY,
        direct_motor_route=DIRECT_MOTOR_ROUTE,
        direct_motor_interface=DIRECT_MOTOR_INTERFACE,
        allowed_direct_motor_publisher_identity=DIRECT_MOTOR_PUBLISHER_IDENTITY,
        operator_authority_id=ISSUERS["operator"],
        presence_authority_id=ISSUERS["presence"],
        safety_authority_id=ISSUERS["safety"],
        graph_authority_id=ISSUERS["graph"],
        target_authority_id=ISSUERS["target"],
        max_graph_age_s=5,
        max_attestation_age_s=30,
    )


def _fixture(
    *,
    publishers: list[str] | None = None,
    direct_motor_publishers: list[str] | None = None,
) -> tuple[MotionSafetyAdmissionRequest, MotionSafetyPolicy, MotionSafetyTrustStore]:
    policy = _policy()
    command_publishers = [PUBLISHER_IDENTITY] if publishers is None else publishers
    motor_publishers = [DIRECT_MOTOR_PUBLISHER_IDENTITY] if direct_motor_publishers is None else direct_motor_publishers
    graph_issued_at = NOW - timedelta(seconds=1)
    attestation_issued_at = NOW - timedelta(seconds=1)
    graph_digest = compute_ros_graph_digest(
        target_id=TARGET_ID,
        target_identity=TARGET_IDENTITY,
        observed_at=graph_issued_at,
        command_route=COMMAND_ROUTE,
        command_interface=COMMAND_INTERFACE,
        publisher_identities=command_publishers,
        direct_motor_route=DIRECT_MOTOR_ROUTE,
        direct_motor_interface=DIRECT_MOTOR_INTERFACE,
        direct_motor_publisher_identities=motor_publishers,
    )
    fence_digest = compute_direct_motor_fence_digest(
        execution_subject_digest=EXECUTION_SUBJECT_DIGEST,
        call_id="call-motion-1",
        session_id="session-motion-1",
        target_id=TARGET_ID,
        target_identity=TARGET_IDENTITY,
        ros_graph_digest=graph_digest,
        command_route=COMMAND_ROUTE,
        publisher_identity=PUBLISHER_IDENTITY,
        direct_motor_route=DIRECT_MOTOR_ROUTE,
        direct_motor_interface=DIRECT_MOTOR_INTERFACE,
        direct_motor_publisher_identity=DIRECT_MOTOR_PUBLISHER_IDENTITY,
        fence_epoch=7,
    )
    stop_digest = compute_stop_action_digest(
        execution_subject_digest=EXECUTION_SUBJECT_DIGEST,
        call_id="call-motion-1",
        session_id="session-motion-1",
        target_id=TARGET_ID,
        target_identity=TARGET_IDENTITY,
        ros_graph_digest=graph_digest,
        command_route=COMMAND_ROUTE,
        publisher_identity=PUBLISHER_IDENTITY,
        direct_motor_route=DIRECT_MOTOR_ROUTE,
        direct_motor_interface=DIRECT_MOTOR_INTERFACE,
        direct_motor_publisher_identity=DIRECT_MOTOR_PUBLISHER_IDENTITY,
        direct_motor_fence_digest=fence_digest,
    )
    intent = MotionSafetyIntent(
        call_id="call-motion-1",
        session_id="session-motion-1",
        target_id=TARGET_ID,
        target_identity=TARGET_IDENTITY,
        operator_id=OPERATOR_ID,
        execution_subject_digest=EXECUTION_SUBJECT_DIGEST,
        requested_at=NOW - timedelta(seconds=1),
        ros_graph_digest=graph_digest,
        command_route=COMMAND_ROUTE,
        command_interface=COMMAND_INTERFACE,
        publisher_identity=PUBLISHER_IDENTITY,
        direct_motor_route=DIRECT_MOTOR_ROUTE,
        direct_motor_interface=DIRECT_MOTOR_INTERFACE,
        direct_motor_publisher_identity=DIRECT_MOTOR_PUBLISHER_IDENTITY,
        direct_motor_fence_digest=fence_digest,
        stop_action_digest=stop_digest,
    )
    common = {
        "call_id": intent.call_id,
        "session_id": intent.session_id,
        "target_id": intent.target_id,
        "target_identity": intent.target_identity,
        "operator_id": intent.operator_id,
        "execution_subject_digest": intent.execution_subject_digest,
        "ros_graph_digest": intent.ros_graph_digest,
        "issued_at": attestation_issued_at,
        "expires_at": attestation_issued_at + timedelta(seconds=30),
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
                issued_at=graph_issued_at,
                expires_at=graph_issued_at + timedelta(seconds=5),
            )
        return SignedMotionEvidence.build(
            evidence_id=evidence_id,
            kind=kind,
            issuer_id=issuer_id,
            claims=claims,
            signing_key=KEYS[issuer_id],
            **identity,
        )

    challenge_digest = _digest("fixture-estop-challenge")
    evidence = MotionSafetyEvidenceBundle(
        operator_authorization=signed(
            "evidence-operator",
            "OPERATOR_AUTHORIZATION",
            ISSUERS["operator"],
            {
                "authorization_id": "authorization-motion-1",
                "authorized": True,
                "motion_scope": "PHYSICAL_MOTION",
                "operator_id": OPERATOR_ID,
            },
        ),
        onsite_presence=signed(
            "evidence-presence",
            "ONSITE_PRESENCE",
            ISSUERS["presence"],
            {
                "operator_id": OPERATOR_ID,
                "presence_method": "ON_SITE_CHALLENGE",
                "present": True,
                "site_id": SITE_ID,
            },
        ),
        safe_zone_confirmation=signed(
            "evidence-safe-zone",
            "SAFE_ZONE_CONFIRMATION",
            ISSUERS["safety"],
            {
                "confirmed_clear": True,
                "safe_zone_id": SAFE_ZONE_ID,
                "site_id": SITE_ID,
            },
        ),
        estop_verification=signed(
            "evidence-estop",
            "ESTOP_VERIFICATION",
            ISSUERS["safety"],
            {
                "available": True,
                "challenge_digest": challenge_digest,
                "engage_verified": True,
                "release_verified": True,
                "response_digest": compute_estop_response_digest(
                    execution_subject_digest=intent.execution_subject_digest,
                    challenge_digest=challenge_digest,
                    call_id=intent.call_id,
                    session_id=intent.session_id,
                    target_id=intent.target_id,
                    target_identity=intent.target_identity,
                    ros_graph_digest=intent.ros_graph_digest,
                ),
                "verification_method": "TARGET_CHALLENGE_RESPONSE",
            },
        ),
        ros_graph_snapshot=signed(
            "evidence-graph",
            "ROS_GRAPH_SNAPSHOT",
            ISSUERS["graph"],
            {
                "command_interface": COMMAND_INTERFACE,
                "command_route": COMMAND_ROUTE,
                "direct_motor_interface": DIRECT_MOTOR_INTERFACE,
                "direct_motor_publisher_identities": motor_publishers,
                "direct_motor_route": DIRECT_MOTOR_ROUTE,
                "publisher_identities": command_publishers,
            },
            graph=True,
        ),
        direct_motor_fence=signed(
            "evidence-motor-fence",
            "DIRECT_MOTOR_FENCE",
            ISSUERS["target"],
            {
                "active": True,
                "direct_access_blocked": True,
                "direct_motor_interface": DIRECT_MOTOR_INTERFACE,
                "direct_motor_route": DIRECT_MOTOR_ROUTE,
                "fence_digest": fence_digest,
                "fence_epoch": 7,
                "owner_identity": ISSUERS["target"],
                "publisher_identity": DIRECT_MOTOR_PUBLISHER_IDENTITY,
            },
        ),
        target_stop_acknowledgement=signed(
            "evidence-stop-ack",
            "TARGET_STOP_ACKNOWLEDGEMENT",
            ISSUERS["target"],
            {
                "acknowledged": True,
                "owner_identity": ISSUERS["target"],
                "stop_action_digest": stop_digest,
                "target_owned": True,
            },
        ),
    )
    return (
        MotionSafetyAdmissionRequest(intent=intent, evidence=evidence),
        policy,
        MotionSafetyTrustStore(KEYS),
    )


def _resign(
    request: MotionSafetyAdmissionRequest,
    field: str,
    *,
    claims: dict | None = None,
    signing_key: bytes | None = None,
    **updates,
) -> MotionSafetyAdmissionRequest:
    current = getattr(request.evidence, field)
    assert current is not None
    payload = current.model_dump(
        mode="python",
        exclude={"schema_version", "payload_sha256", "signature_hmac_sha256"},
    )
    payload.update(updates)
    if claims is not None:
        payload["claims"] = claims
    replacement = SignedMotionEvidence.build(
        signing_key=signing_key or KEYS[payload["issuer_id"]],
        **payload,
    )
    evidence = request.evidence.model_copy(update={field: replacement})
    return request.model_copy(update={"evidence": evidence})


def test_motion_safety_gate_defaults_to_blocked_without_claiming_field_state():
    decision = evaluate_motion_safety()

    assert decision.status == "BLOCKED"
    assert decision.admitted is False
    assert decision.reasons == ("MOTION_SAFETY_REQUEST_REQUIRED",)
    assert decision.evidence_digests == ()


def test_complete_synthetic_evidence_is_admitted_only_by_offline_evaluator():
    request, policy, trust_store = _fixture()

    decision = evaluate_motion_safety(
        request,
        policy=policy,
        trust_store=trust_store,
        now=NOW,
    )

    assert decision.status == "ADMITTED"
    assert decision.reasons == ()
    assert decision.call_id == request.intent.call_id
    assert decision.session_id == request.intent.session_id
    assert decision.target_id == request.intent.target_id
    assert decision.execution_subject_digest == request.intent.execution_subject_digest
    assert decision.ros_graph_digest == request.intent.ros_graph_digest
    assert len(decision.evidence_digests) == len(EVIDENCE_FIELDS)


@pytest.mark.parametrize("field", EVIDENCE_FIELDS)
def test_each_missing_safety_evidence_blocks(field):
    request, policy, trust_store = _fixture()
    evidence = request.evidence.model_copy(update={field: None})
    request = request.model_copy(update={"evidence": evidence})

    decision = evaluate_motion_safety(
        request,
        policy=policy,
        trust_store=trust_store,
        now=NOW,
    )

    assert decision.status == "BLOCKED"
    assert f"{field.upper()}_REQUIRED" in decision.reasons


@pytest.mark.parametrize("field", EVIDENCE_FIELDS)
def test_each_stale_attestation_blocks(field):
    request, policy, trust_store = _fixture()
    max_age = policy.max_graph_age_s if field == "ros_graph_snapshot" else policy.max_attestation_age_s
    issued_at = NOW - timedelta(seconds=max_age + 1)
    request = _resign(
        request,
        field,
        issued_at=issued_at,
        expires_at=issued_at + timedelta(seconds=max_age),
    )

    decision = evaluate_motion_safety(
        request,
        policy=policy,
        trust_store=trust_store,
        now=NOW,
    )

    assert decision.status == "BLOCKED"
    assert f"{field.upper()}_STALE" in decision.reasons


@pytest.mark.parametrize(
    ("identity_field", "drifted"),
    [
        ("call_id", "call-motion-other"),
        ("session_id", "session-motion-other"),
        ("target_id", "other-target"),
        ("target_identity", "sha256:other-device-key"),
        ("operator_id", "operator:other"),
        ("execution_subject_digest", _digest("other-execution-subject")),
        ("ros_graph_digest", _digest("other-graph")),
    ],
)
def test_signed_evidence_identity_drift_blocks(identity_field, drifted):
    request, policy, trust_store = _fixture()
    request = _resign(request, "operator_authorization", **{identity_field: drifted})

    decision = evaluate_motion_safety(
        request,
        policy=policy,
        trust_store=trust_store,
        now=NOW,
    )

    assert decision.status == "BLOCKED"
    assert any(identity_field.upper() in reason for reason in decision.reasons)


def test_extra_command_publisher_blocks_even_when_graph_digest_and_signatures_match():
    request, policy, trust_store = _fixture(publishers=[PUBLISHER_IDENTITY, "rogue:teleop-publisher"])

    decision = evaluate_motion_safety(
        request,
        policy=policy,
        trust_store=trust_store,
        now=NOW,
    )

    assert decision.status == "BLOCKED"
    assert "COMMAND_ROUTE_NOT_EXCLUSIVE" in decision.reasons
    assert "COMMAND_ROUTE_PUBLISHER_NOT_ALLOWED" in decision.reasons


def test_single_unapproved_publisher_identity_blocks():
    request, policy, trust_store = _fixture(publishers=["rogue:teleop-publisher"])

    decision = evaluate_motion_safety(
        request,
        policy=policy,
        trust_store=trust_store,
        now=NOW,
    )

    assert decision.status == "BLOCKED"
    assert "COMMAND_ROUTE_PUBLISHER_NOT_ALLOWED" in decision.reasons


def test_hand_gesture_extra_direct_motor_publisher_blocks():
    request, policy, trust_store = _fixture(
        direct_motor_publishers=[
            DIRECT_MOTOR_PUBLISHER_IDENTITY,
            "/hand_gesture",
        ]
    )

    decision = evaluate_motion_safety(
        request,
        policy=policy,
        trust_store=trust_store,
        now=NOW,
    )

    assert decision.status == "BLOCKED"
    assert "DIRECT_MOTOR_ROUTE_NOT_EXCLUSIVE" in decision.reasons
    assert "DIRECT_MOTOR_ROUTE_PUBLISHER_NOT_ALLOWED" in decision.reasons


@pytest.mark.parametrize(
    ("fixture_kwargs", "reason"),
    [
        ({"publishers": []}, "COMMAND_ROUTE_NOT_EXCLUSIVE"),
        ({"direct_motor_publishers": []}, "DIRECT_MOTOR_ROUTE_NOT_EXCLUSIVE"),
    ],
)
def test_missing_route_publisher_blocks(fixture_kwargs, reason):
    request, policy, trust_store = _fixture(**fixture_kwargs)

    decision = evaluate_motion_safety(
        request,
        policy=policy,
        trust_store=trust_store,
        now=NOW,
    )

    assert decision.status == "BLOCKED"
    assert reason in decision.reasons


@pytest.mark.parametrize(
    ("intent_field", "drifted", "reason"),
    [
        ("target_id", "other-target", "TARGET_ID_MISMATCH"),
        ("target_identity", "sha256:other-device-key", "TARGET_IDENTITY_MISMATCH"),
        ("command_route", "/other/cmd_vel", "COMMAND_ROUTE_MISMATCH"),
        ("publisher_identity", "rogue:publisher", "PUBLISHER_IDENTITY_MISMATCH"),
        (
            "direct_motor_route",
            "/other/direct_motor",
            "DIRECT_MOTOR_ROUTE_MISMATCH",
        ),
        (
            "direct_motor_publisher_identity",
            "rogue:hand-gesture",
            "DIRECT_MOTOR_PUBLISHER_IDENTITY_MISMATCH",
        ),
    ],
)
def test_intent_cannot_drift_from_trusted_policy(intent_field, drifted, reason):
    request, policy, trust_store = _fixture()
    intent = request.intent.model_copy(update={intent_field: drifted})
    request = request.model_copy(update={"intent": intent})

    decision = evaluate_motion_safety(
        request,
        policy=policy,
        trust_store=trust_store,
        now=NOW,
    )

    assert decision.status == "BLOCKED"
    assert reason in decision.reasons


@pytest.mark.parametrize("missing_issuer", tuple(KEYS))
def test_each_missing_verifier_identity_blocks(missing_issuer):
    request, policy, _ = _fixture()
    trust_store = MotionSafetyTrustStore({issuer: key for issuer, key in KEYS.items() if issuer != missing_issuer})

    decision = evaluate_motion_safety(
        request,
        policy=policy,
        trust_store=trust_store,
        now=NOW,
    )

    assert decision.status == "BLOCKED"
    assert any("KEY_REQUIRED" in reason or "SIGNATURE_INVALID" in reason for reason in decision.reasons)


@pytest.mark.parametrize(
    ("left_role", "right_role"),
    [
        ("operator", "presence"),
        ("operator", "safety"),
        ("operator", "target"),
        ("presence", "safety"),
        ("presence", "target"),
        ("safety", "target"),
    ],
)
def test_field_authority_keys_are_pairwise_independent(left_role, right_role):
    request, policy, _ = _fixture()
    keys = dict(KEYS)
    keys[ISSUERS[right_role]] = keys[ISSUERS[left_role]]
    trust_store = MotionSafetyTrustStore(keys)

    decision = evaluate_motion_safety(
        request,
        policy=policy,
        trust_store=trust_store,
        now=NOW,
    )

    assert decision.status == "BLOCKED"
    assert any("AUTHORITY_KEYS_NOT_INDEPENDENT" in reason for reason in decision.reasons)


def test_field_authority_issuer_ids_are_pairwise_independent():
    request, policy, trust_store = _fixture()
    policy_payload = policy.model_dump(mode="python")
    policy_payload["presence_authority_id"] = policy.operator_authority_id

    decision = evaluate_motion_safety(
        request,
        policy=policy_payload,
        trust_store=trust_store,
        now=NOW,
    )

    assert decision.status == "BLOCKED"
    assert decision.reasons == ("MOTION_SAFETY_POLICY_INVALID",)


def test_graph_authority_may_share_target_role_only_when_policy_names_it():
    request, policy, trust_store = _fixture()
    graph = request.evidence.ros_graph_snapshot
    assert graph is not None
    request = _resign(
        request,
        "ros_graph_snapshot",
        issuer_id=ISSUERS["target"],
        signing_key=KEYS[ISSUERS["target"]],
    )
    policy = policy.model_copy(update={"graph_authority_id": ISSUERS["target"]})

    decision = evaluate_motion_safety(
        request,
        policy=policy,
        trust_store=trust_store,
        now=NOW,
    )

    assert decision.status == "ADMITTED"


def test_graph_authority_cannot_reuse_an_independent_field_role():
    request, policy, trust_store = _fixture()
    policy_payload = policy.model_dump(mode="python")
    policy_payload["graph_authority_id"] = ISSUERS["operator"]

    decision = evaluate_motion_safety(
        request,
        policy=policy_payload,
        trust_store=trust_store,
        now=NOW,
    )

    assert decision.status == "BLOCKED"
    assert decision.reasons == ("MOTION_SAFETY_POLICY_INVALID",)


def test_distinct_graph_authority_key_cannot_reuse_a_field_role_key():
    request, policy, _ = _fixture()
    keys = dict(KEYS)
    keys[ISSUERS["graph"]] = keys[ISSUERS["operator"]]

    decision = evaluate_motion_safety(
        request,
        policy=policy,
        trust_store=MotionSafetyTrustStore(keys),
        now=NOW,
    )

    assert decision.status == "BLOCKED"
    assert "GRAPH_OPERATOR_AUTHORITY_KEYS_NOT_INDEPENDENT" in decision.reasons


def test_invalid_signature_blocks_without_trusting_boolean_claims():
    request, policy, trust_store = _fixture()
    evidence = request.evidence.operator_authorization
    assert evidence is not None
    invalid = evidence.model_copy(update={"signature_hmac_sha256": "hmac-sha256:" + "0" * 64})
    request = request.model_copy(update={"evidence": request.evidence.model_copy(update={"operator_authorization": invalid})})

    decision = evaluate_motion_safety(
        request,
        policy=policy,
        trust_store=trust_store,
        now=NOW,
    )

    assert decision.status == "BLOCKED"
    assert "OPERATOR_AUTHORIZATION_SIGNATURE_INVALID" in decision.reasons


@pytest.mark.parametrize(
    ("field", "claim", "value", "reason"),
    [
        ("operator_authorization", "authorized", False, "OPERATOR_AUTHORIZATION_DENIED"),
        ("onsite_presence", "present", False, "ONSITE_PRESENCE_NOT_CONFIRMED"),
        ("safe_zone_confirmation", "confirmed_clear", False, "SAFE_ZONE_NOT_CONFIRMED"),
        ("direct_motor_fence", "direct_access_blocked", False, "DIRECT_MOTOR_FENCE_NOT_VERIFIED"),
        ("target_stop_acknowledgement", "target_owned", False, "TARGET_STOP_NOT_ACKNOWLEDGED"),
    ],
)
def test_false_safety_claims_block_even_when_correctly_signed(field, claim, value, reason):
    request, policy, trust_store = _fixture()
    evidence = getattr(request.evidence, field)
    assert evidence is not None
    claims = dict(evidence.claims)
    claims[claim] = value
    request = _resign(request, field, claims=claims)

    decision = evaluate_motion_safety(
        request,
        policy=policy,
        trust_store=trust_store,
        now=NOW,
    )

    assert decision.status == "BLOCKED"
    assert reason in decision.reasons


def test_estop_requires_recomputable_challenge_response():
    request, policy, trust_store = _fixture()
    evidence = request.evidence.estop_verification
    assert evidence is not None
    claims = dict(evidence.claims)
    claims["response_digest"] = _digest("forged-estop-response")
    request = _resign(request, "estop_verification", claims=claims)

    decision = evaluate_motion_safety(
        request,
        policy=policy,
        trust_store=trust_store,
        now=NOW,
    )

    assert decision.status == "BLOCKED"
    assert "ESTOP_RESPONSE_MISMATCH" in decision.reasons


def test_direct_motor_fence_must_bind_exact_call_graph_and_epoch():
    request, policy, trust_store = _fixture()
    evidence = request.evidence.direct_motor_fence
    assert evidence is not None
    claims = dict(evidence.claims)
    claims["fence_epoch"] = 8
    request = _resign(request, "direct_motor_fence", claims=claims)

    decision = evaluate_motion_safety(
        request,
        policy=policy,
        trust_store=trust_store,
        now=NOW,
    )

    assert decision.status == "BLOCKED"
    assert "DIRECT_MOTOR_FENCE_NOT_VERIFIED" in decision.reasons


def test_target_stop_acknowledgement_must_bind_expected_stop_action():
    request, policy, trust_store = _fixture()
    evidence = request.evidence.target_stop_acknowledgement
    assert evidence is not None
    claims = dict(evidence.claims)
    claims["stop_action_digest"] = _digest("different-stop-action")
    request = _resign(request, "target_stop_acknowledgement", claims=claims)

    decision = evaluate_motion_safety(
        request,
        policy=policy,
        trust_store=trust_store,
        now=NOW,
    )

    assert decision.status == "BLOCKED"
    assert "TARGET_STOP_NOT_ACKNOWLEDGED" in decision.reasons


def test_noncanonical_or_extra_claims_fail_closed():
    request, policy, trust_store = _fixture()
    evidence = request.evidence.safe_zone_confirmation
    assert evidence is not None
    claims = {**evidence.claims, "unreviewed_override": True}
    request = _resign(request, "safe_zone_confirmation", claims=claims)

    decision = evaluate_motion_safety(
        request,
        policy=policy,
        trust_store=trust_store,
        now=NOW,
    )

    assert decision.status == "BLOCKED"
    assert "SAFE_ZONE_CONFIRMATION_CLAIMS_INVALID" in decision.reasons


@pytest.mark.parametrize(
    "claims",
    [
        {"oversized": ["x" * 4000 for _ in range(9)]},
        {"too_many": list(range(65))},
        {"too_deep": {"a": {"b": {"c": {"d": {"e": {"f": {"g": {"h": {"i": True}}}}}}}}}},
    ],
)
def test_canonical_evidence_limits_reject_bytes_entries_and_depth(claims):
    request, _, _ = _fixture()

    with pytest.raises(ValueError, match="maximum"):
        _resign(request, "operator_authorization", claims=claims)


def test_oversized_untrusted_claims_are_a_blocked_decision_not_an_exception():
    request, policy, trust_store = _fixture()
    evidence = request.evidence.operator_authorization
    assert evidence is not None
    oversized = evidence.model_copy(update={"claims": {"oversized": ["x" * 4000 for _ in range(9)]}})
    request = request.model_copy(update={"evidence": request.evidence.model_copy(update={"operator_authorization": oversized})})

    decision = evaluate_motion_safety(
        request,
        policy=policy,
        trust_store=trust_store,
        now=NOW,
    )

    assert decision.status == "BLOCKED"
    assert decision.reasons == ("MOTION_SAFETY_REQUEST_INVALID",)


@pytest.mark.parametrize("invalid_now", [False, "2026-09-08T08:00:00Z", datetime(2026, 9, 8, 8, 0)])
def test_invalid_evaluation_time_fails_closed(invalid_now):
    request, policy, trust_store = _fixture()

    decision = evaluate_motion_safety(
        request,
        policy=policy,
        trust_store=trust_store,
        now=invalid_now,
    )

    assert decision.status == "BLOCKED"
    assert decision.reasons == ("EVALUATION_TIME_INVALID",)


def test_canonical_integer_magnitude_is_bounded():
    request, _, _ = _fixture()

    with pytest.raises(ValueError, match="maximum magnitude"):
        _resign(
            request,
            "direct_motor_fence",
            claims={"fence_epoch": 1 << 64},
        )


def test_trust_store_entry_and_key_sizes_are_bounded():
    too_many_keys = {f"authority:extra-{index}": bytes([index]) * 32 for index in range(33)}

    with pytest.raises(ValueError, match="maximum verifier entries"):
        MotionSafetyTrustStore(too_many_keys)
    with pytest.raises(ValueError, match="outside safe bounds"):
        MotionSafetyTrustStore({ISSUERS["operator"]: b"x" * 4097})


def test_admission_schema_accepts_complete_request_and_rejects_unsafe_shapes():
    request, _, _ = _fixture()
    schema_path = Path(__file__).parents[1] / "schemas" / "TargetdMotionSafetyAdmission.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    payload = request.model_dump(mode="json")

    validator.validate(payload)

    extra = copy.deepcopy(payload)
    extra["execute"] = True
    with pytest.raises(ValidationError):
        validator.validate(extra)

    malformed_digest = copy.deepcopy(payload)
    malformed_digest["intent"]["ros_graph_digest"] = "not-a-digest"
    with pytest.raises(ValidationError):
        validator.validate(malformed_digest)

    extra_claim = copy.deepcopy(payload)
    extra_claim["evidence"]["operator_authorization"]["claims"]["bypass"] = True
    with pytest.raises(ValidationError):
        validator.validate(extra_claim)


class _ZeroMotionTargetFixture:
    """Signed target fixture with no publish, velocity, or provider-call method."""

    def __init__(
        self,
        request: ZeroMotionAcceptanceRequest,
        policy: MotionSafetyPolicy,
        *,
        fault: str | None = None,
    ) -> None:
        self.request = request
        self.policy = policy
        self.fault = fault
        self.calls: list[str] = []
        self.provider_invocations = 0
        self.motion_commands = 0
        self.graph_revision = _digest("live-graph-revision-1")
        self.baseline_epoch = 7
        self.lease_epoch = 8
        self.release_epoch = 9
        self.provider_epoch = 10
        self.pre: SignedZeroMotionArtifact | None = None
        self.cas: SignedZeroMotionArtifact | None = None
        self.start: SignedZeroMotionArtifact | None = None
        self.stop: SignedZeroMotionArtifact | None = None
        self.post: SignedZeroMotionArtifact | None = None
        self.release: SignedZeroMotionArtifact | None = None
        self.challenge: SignedZeroMotionArtifact | None = None
        self.lease_digest: str | None = None
        self.release_fence_digest: str | None = None
        self.challenge_consumed = False

    def production_peer_verified(self):
        return True

    def _raise_if_requested(self, phase: str) -> None:
        if self.fault == f"{phase}_exception":
            raise RuntimeError("UNTRUSTED_TARGET_EXCEPTION_MARKER")

    def _signed(
        self,
        *,
        phase: str,
        artifact_id: str,
        kind: str,
        issuer_id: str,
        claims: dict,
    ) -> SignedZeroMotionArtifact:
        claims = dict(claims)
        if phase in {"pre", "start", "stop", "post", "challenge", "consume"}:
            claims.update(_fresh_zero_claims())
        if self.fault == "command_publisher" and phase == "pre":
            claims["publisher_identities"] = [PUBLISHER_IDENTITY, "/rogue_cmd_vel"]
        elif self.fault == "competing_publisher" and phase == "pre":
            claims["competing_publisher_identities"] = ["/hand_gesture"]
        elif self.fault == "motor_publisher" and phase == "pre":
            claims["direct_motor_publisher_identities"] = [DIRECT_MOTOR_PUBLISHER_IDENTITY, "/hand_gesture"]
        elif self.fault == "cas_not_acquired" and phase == "cas":
            claims["acquired"] = False
        elif self.fault == "start_emitted_motion" and phase == "start":
            claims["motion_command_emitted"] = True
        elif self.fault == "stop_wrong_start" and phase == "stop":
            claims["start_ack_artifact_digest"] = _digest("wrong-start")
        elif self.fault == "post_graph_drift" and phase == "post":
            claims["graph_revision"] = _digest("live-graph-revision-2")
        elif self.fault == "release_not_released" and phase == "release":
            claims["released"] = False
        elif self.fault == "challenge_not_one_shot" and phase == "challenge":
            claims["one_shot"] = False
        elif self.fault == "fresh_zero_missing" and phase == "pre":
            claims.pop("fresh_zero_evidence")
        elif self.fault == "fresh_zero_moving" and phase == "pre":
            evidence = copy.deepcopy(claims["fresh_zero_evidence"])
            evidence["imu_max_abs_angular_z_rad_s"] = 0.031
            evidence["evidence_sha256"] = compute_motion_payload_digest({key: value for key, value in evidence.items() if key != "evidence_sha256"})
            claims["fresh_zero_evidence"] = evidence
            claims["fresh_zero_evidence_digest"] = evidence["evidence_sha256"]
        elif self.fault == "fresh_zero_stale" and phase == "pre":
            evidence = copy.deepcopy(claims["fresh_zero_evidence"])
            for field in (
                "window_started_at",
                "window_ended_at",
                "command_latest_sample_at",
                "motor_latest_sample_at",
                "imu_latest_sample_at",
            ):
                evidence[field] = (datetime.fromisoformat(evidence[field].replace("Z", "+00:00")) - timedelta(seconds=2)).isoformat().replace("+00:00", "Z")
            evidence["evidence_sha256"] = compute_motion_payload_digest({key: value for key, value in evidence.items() if key != "evidence_sha256"})
            claims["fresh_zero_evidence"] = evidence
            claims["fresh_zero_evidence_digest"] = evidence["evidence_sha256"]

        artifact_intent = self.request.admission.intent
        if self.fault == "cas_call_drift" and phase == "cas":
            artifact_intent = artifact_intent.model_copy(update={"call_id": "call-motion-drift"})
        artifact = SignedZeroMotionArtifact.build(
            artifact_id=("artifact-pre" if self.fault == "reused_artifact_id" and phase == "cas" else artifact_id),
            kind=kind,
            issuer_id=issuer_id,
            acceptance_id=self.request.acceptance_id,
            intent=artifact_intent,
            issued_at=NOW,
            expires_at=NOW + timedelta(seconds=self.policy.max_graph_age_s),
            claims=claims,
            signing_key=KEYS[issuer_id],
        )
        if self.fault == "cas_bad_signature" and phase == "cas":
            artifact = artifact.model_copy(update={"signature_hmac_sha256": "hmac-sha256:" + "0" * 64})
        return artifact

    def _snapshot_claims(self, phase: str) -> dict:
        if phase == "PRE_CAS":
            fence_digest = self.request.admission.intent.direct_motor_fence_digest
            fence_epoch = self.baseline_epoch
        else:
            assert self.lease_digest is not None
            fence_digest = self.lease_digest
            fence_epoch = self.lease_epoch
        claims = {
            "phase": phase,
            "command_route": COMMAND_ROUTE,
            "command_interface": COMMAND_INTERFACE,
            "publisher_identities": [PUBLISHER_IDENTITY],
            "publisher_gids": [COMMAND_PUBLISHER_GID],
            "subscriber_identities": [COMMAND_SUBSCRIBER_IDENTITY],
            "subscriber_gids": [COMMAND_SUBSCRIBER_GID],
            "competing_command_route": COMPETING_COMMAND_ROUTE,
            "competing_command_interface": COMMAND_INTERFACE,
            "competing_publisher_identities": [],
            "competing_publisher_gids": [],
            "competing_subscriber_identities": [COMMAND_SUBSCRIBER_IDENTITY],
            "competing_subscriber_gids": [COMPETING_SUBSCRIBER_GID],
            "direct_motor_route": DIRECT_MOTOR_ROUTE,
            "direct_motor_interface": DIRECT_MOTOR_INTERFACE,
            "direct_motor_publisher_identities": [DIRECT_MOTOR_PUBLISHER_IDENTITY],
            "direct_motor_publisher_gids": [DIRECT_MOTOR_PUBLISHER_GID],
            "graph_revision": self.graph_revision,
            "live_ros_graph_digest": "",
            "fence_epoch": fence_epoch,
            "active_fence_digest": fence_digest,
            "fence_owner_call_id": self.request.admission.intent.call_id,
            "motion_enabled": False,
            "provider_invocation_count": 0,
        }
        if self.fault == "command_publisher" and phase == "PRE_CAS":
            claims["publisher_identities"] = [PUBLISHER_IDENTITY, "/rogue_cmd_vel"]
        elif self.fault == "competing_publisher" and phase == "PRE_CAS":
            claims["competing_publisher_identities"] = ["/hand_gesture"]
        elif self.fault == "motor_publisher" and phase == "PRE_CAS":
            claims["direct_motor_publisher_identities"] = [DIRECT_MOTOR_PUBLISHER_IDENTITY, "/hand_gesture"]
        claims["live_ros_graph_digest"] = compute_zero_motion_isolation_digest(
            target_id=self.request.admission.intent.target_id,
            target_identity=self.request.admission.intent.target_identity,
            observed_at=NOW,
            command_route=claims["command_route"],
            command_interface=claims["command_interface"],
            publisher_identities=claims["publisher_identities"],
            subscriber_identities=claims["subscriber_identities"],
            competing_command_route=claims["competing_command_route"],
            competing_command_interface=claims["competing_command_interface"],
            competing_publisher_identities=claims["competing_publisher_identities"],
            competing_subscriber_identities=claims["competing_subscriber_identities"],
            direct_motor_route=claims["direct_motor_route"],
            direct_motor_interface=claims["direct_motor_interface"],
            direct_motor_publisher_identities=claims["direct_motor_publisher_identities"],
            command_publisher_gids=claims["publisher_gids"],
            command_subscriber_gids=claims["subscriber_gids"],
            competing_publisher_gids=claims["competing_publisher_gids"],
            competing_subscriber_gids=claims["competing_subscriber_gids"],
            direct_motor_publisher_gids=claims["direct_motor_publisher_gids"],
        )
        return claims

    def observe_isolation(self, *, acceptance_id, intent, policy, phase, fence_binding_digest):
        assert acceptance_id == self.request.acceptance_id
        assert intent == self.request.admission.intent
        assert policy == self.policy
        if phase == "PRE_CAS":
            assert fence_binding_digest is None
            self.calls.append("snapshot:pre")
            self._raise_if_requested("pre")
            self.pre = self._signed(
                phase="pre",
                artifact_id="artifact-pre",
                kind="LIVE_ISOLATION_SNAPSHOT",
                issuer_id=ISSUERS["graph"],
                claims=self._snapshot_claims("PRE_CAS"),
            )
            return self.pre
        assert phase == "POST_STOP"
        assert fence_binding_digest == self.lease_digest
        self.calls.append("snapshot:post")
        self._raise_if_requested("post")
        self.post = self._signed(
            phase="post",
            artifact_id="artifact-post",
            kind="LIVE_ISOLATION_SNAPSHOT",
            issuer_id=ISSUERS["graph"],
            claims=self._snapshot_claims("POST_STOP"),
        )
        return self.post

    def compare_and_set_fence(self, *, acceptance_id, intent, policy, snapshot_artifact_digest):
        assert acceptance_id == self.request.acceptance_id
        assert intent == self.request.admission.intent
        assert policy == self.policy
        assert self.pre is not None and snapshot_artifact_digest == self.pre.payload_sha256
        self.calls.append("fence:cas")
        self._raise_if_requested("cas")
        self.lease_digest = compute_zero_motion_fence_lease_digest(
            acceptance_id=acceptance_id,
            intent=intent,
            snapshot_artifact_digest=snapshot_artifact_digest,
            live_ros_graph_digest=self.pre.claims["live_ros_graph_digest"],
            graph_revision=self.pre.claims["graph_revision"],
            expected_fence_digest=intent.direct_motor_fence_digest,
            fence_epoch=self.lease_epoch,
        )
        self.cas = self._signed(
            phase="cas",
            artifact_id="artifact-cas",
            kind="LIVE_FENCE_CAS",
            issuer_id=ISSUERS["target"],
            claims={
                "acquired": True,
                "snapshot_artifact_digest": snapshot_artifact_digest,
                "live_ros_graph_digest": self.pre.claims["live_ros_graph_digest"],
                "graph_revision": self.graph_revision,
                "expected_fence_digest": intent.direct_motor_fence_digest,
                "expected_fence_epoch": self.baseline_epoch,
                "fence_epoch": self.lease_epoch,
                "fence_lease_digest": self.lease_digest,
                "lease_owner_call_id": intent.call_id,
                "motion_enabled": False,
                "provider_invocation_count": 0,
            },
        )
        return self.cas

    def acknowledge_zero_motion_start(self, *, acceptance_id, intent, fence_cas_artifact_digest):
        assert acceptance_id == self.request.acceptance_id
        assert intent == self.request.admission.intent
        assert self.pre is not None and self.cas is not None and self.lease_digest is not None
        assert fence_cas_artifact_digest == self.cas.payload_sha256
        self.calls.append("ack:start")
        self._raise_if_requested("start")
        self.start = self._signed(
            phase="start",
            artifact_id="artifact-start",
            kind="ZERO_MOTION_START_ACK",
            issuer_id=ISSUERS["target"],
            claims={
                "acknowledged": True,
                "phase": "START",
                "snapshot_artifact_digest": self.pre.payload_sha256,
                "cas_artifact_digest": self.cas.payload_sha256,
                "fence_lease_digest": self.lease_digest,
                "graph_revision": self.graph_revision,
                "zero_velocity_verified": True,
                "motors_stopped": True,
                "motion_command_emitted": False,
                "provider_invocation_count": 0,
            },
        )
        return self.start

    def acknowledge_zero_motion_stop(
        self,
        *,
        acceptance_id,
        intent,
        fence_cas_artifact_digest,
        start_ack_artifact_digest,
    ):
        assert acceptance_id == self.request.acceptance_id
        assert intent == self.request.admission.intent
        assert self.pre is not None and self.cas is not None and self.start is not None and self.lease_digest is not None
        assert fence_cas_artifact_digest == self.cas.payload_sha256
        assert start_ack_artifact_digest == self.start.payload_sha256
        self.calls.append("ack:stop")
        self._raise_if_requested("stop")
        self.stop = self._signed(
            phase="stop",
            artifact_id="artifact-stop",
            kind="ZERO_MOTION_STOP_ACK",
            issuer_id=ISSUERS["target"],
            claims={
                "acknowledged": True,
                "phase": "STOP",
                "snapshot_artifact_digest": self.pre.payload_sha256,
                "cas_artifact_digest": self.cas.payload_sha256,
                "fence_lease_digest": self.lease_digest,
                "graph_revision": self.graph_revision,
                "zero_velocity_verified": True,
                "motors_stopped": True,
                "motion_command_emitted": False,
                "provider_invocation_count": 0,
                "start_ack_artifact_digest": self.start.payload_sha256,
            },
        )
        return self.stop

    def release_fence(
        self,
        *,
        acceptance_id,
        intent,
        fence_cas_artifact_digest,
        stop_ack_artifact_digest,
        post_snapshot_artifact_digest,
    ):
        assert acceptance_id == self.request.acceptance_id
        assert intent == self.request.admission.intent
        assert self.cas is not None and self.stop is not None and self.post is not None and self.lease_digest is not None
        assert fence_cas_artifact_digest == self.cas.payload_sha256
        assert stop_ack_artifact_digest == self.stop.payload_sha256
        assert post_snapshot_artifact_digest == self.post.payload_sha256
        self.calls.append("fence:release")
        self._raise_if_requested("release")
        self.release_fence_digest = compute_direct_motor_fence_digest(
            execution_subject_digest=intent.execution_subject_digest,
            call_id=intent.call_id,
            session_id=intent.session_id,
            target_id=intent.target_id,
            target_identity=intent.target_identity,
            ros_graph_digest=intent.ros_graph_digest,
            command_route=intent.command_route,
            publisher_identity=intent.publisher_identity,
            direct_motor_route=intent.direct_motor_route,
            direct_motor_interface=intent.direct_motor_interface,
            direct_motor_publisher_identity=intent.direct_motor_publisher_identity,
            fence_epoch=self.release_epoch,
        )
        self.release = self._signed(
            phase="release",
            artifact_id="artifact-release",
            kind="LIVE_FENCE_RELEASE",
            issuer_id=ISSUERS["target"],
            claims={
                "released": True,
                "cas_artifact_digest": self.cas.payload_sha256,
                "stop_ack_artifact_digest": self.stop.payload_sha256,
                "post_snapshot_artifact_digest": self.post.payload_sha256,
                "released_fence_lease_digest": self.lease_digest,
                "restored_fence_digest": self.release_fence_digest,
                "restored_fence_epoch": self.release_epoch,
                "direct_access_blocked": True,
                "motion_enabled": False,
                "provider_invocation_count": 0,
            },
        )
        return self.release

    def issue_provider_gate_challenge(
        self,
        *,
        acceptance_id,
        intent,
        release_artifact_digest,
        post_snapshot_artifact_digest,
        released_fence_digest,
        released_fence_epoch,
        expected_graph_revision,
    ):
        assert acceptance_id == self.request.acceptance_id
        assert intent == self.request.admission.intent
        assert self.release is not None and self.post is not None and self.release_fence_digest is not None
        assert release_artifact_digest == self.release.payload_sha256
        assert post_snapshot_artifact_digest == self.post.payload_sha256
        assert released_fence_digest == self.release_fence_digest
        assert released_fence_epoch == self.release_epoch
        assert expected_graph_revision == self.graph_revision
        self.calls.append("gate:challenge")
        self._raise_if_requested("challenge")
        expires_at = NOW + timedelta(seconds=self.policy.max_graph_age_s)
        consume_token = compute_provider_gate_consume_token_digest(
            acceptance_id=acceptance_id,
            intent=intent,
            release_artifact_digest=release_artifact_digest,
            post_snapshot_artifact_digest=post_snapshot_artifact_digest,
            expected_fence_digest=self.release_fence_digest,
            expected_fence_epoch=self.release_epoch,
            expected_graph_revision=self.graph_revision,
            expires_at=expires_at,
        )
        self.challenge = self._signed(
            phase="challenge",
            artifact_id="artifact-provider-gate",
            kind="PROVIDER_GATE_CHALLENGE",
            issuer_id=ISSUERS["target"],
            claims={
                "one_shot": True,
                "consumed": False,
                "release_artifact_digest": release_artifact_digest,
                "post_snapshot_artifact_digest": post_snapshot_artifact_digest,
                "expected_fence_digest": self.release_fence_digest,
                "expected_fence_epoch": self.release_epoch,
                "expected_graph_revision": self.graph_revision,
                "consume_token_digest": consume_token,
                "motion_enabled": False,
                "provider_invocation_count": 0,
            },
        )
        return self.challenge

    def compare_and_set_provider_gate(
        self,
        *,
        acceptance_id,
        intent,
        policy,
        challenge_artifact_digest,
        consume_token_digest,
    ):
        assert acceptance_id == self.request.acceptance_id
        assert intent == self.request.admission.intent
        assert policy == self.policy
        assert self.challenge is not None and self.post is not None and self.release_fence_digest is not None
        assert challenge_artifact_digest == self.challenge.payload_sha256
        assert consume_token_digest == self.challenge.claims["consume_token_digest"]
        self.calls.append("gate:consume")
        self._raise_if_requested("consume")
        already_consumed = self.challenge_consumed
        self.challenge_consumed = True
        live_digest = self.post.claims["live_ros_graph_digest"]
        provider_fence = compute_provider_fence_digest(
            acceptance_id=acceptance_id,
            intent=intent,
            challenge_artifact_digest=challenge_artifact_digest,
            consume_token_digest=consume_token_digest,
            live_isolation_digest=live_digest,
            graph_revision=self.graph_revision,
            expected_fence_digest=self.release_fence_digest,
            fence_epoch=self.provider_epoch,
        )
        return self._signed(
            phase="consume",
            artifact_id=("artifact-consumed-replay" if already_consumed else "artifact-consumed"),
            kind="PROVIDER_GATE_CONSUMED",
            issuer_id=ISSUERS["target"],
            claims={
                "consumed": not already_consumed,
                "one_shot": True,
                "challenge_artifact_digest": challenge_artifact_digest,
                "consume_token_digest": consume_token_digest,
                "expected_fence_digest": self.release_fence_digest,
                "expected_fence_epoch": self.release_epoch,
                "expected_graph_revision": self.graph_revision,
                "observed_fence_digest": self.release_fence_digest,
                "observed_fence_epoch": self.release_epoch,
                "observed_graph_revision": self.graph_revision,
                "live_isolation_digest": live_digest,
                "graph_compare_and_set": not already_consumed,
                "fence_compare_and_set": not already_consumed,
                "provider_fence_digest": provider_fence,
                "provider_fence_epoch": self.provider_epoch,
                "motion_enabled": False,
                "provider_invocation_count": 0,
            },
        )

    def abort_zero_motion(self, *, acceptance_id, intent):
        assert acceptance_id == self.request.acceptance_id
        assert intent == self.request.admission.intent
        self.calls.append("abort")


def _zero_motion_fixture(*, fault: str | None = None):
    admission, policy, trust_store = _fixture()
    request = ZeroMotionAcceptanceRequest(
        acceptance_id="acceptance-motion-1",
        admission=admission,
    )
    target = _ZeroMotionTargetFixture(request, policy, fault=fault)
    return request, policy, trust_store, target


def _topic_info(interface: str, *, publishers: list[str], subscribers: list[str], gid_prefix: str) -> str:
    lines = [
        f"Type: {interface}",
        f"Publisher count: {len(publishers)}",
    ]
    endpoint_index = 0
    for identity in publishers:
        endpoint_index += 1
        namespace, _, name = identity.rpartition("/")
        lines.extend(
            [
                f"Node name: {name}",
                f"Node namespace: {namespace or '/'}",
                "Topic type: ignored/by/parser",
                "Endpoint type: PUBLISHER",
                f"GID: {gid_prefix}.{endpoint_index:08x}",
            ]
        )
    lines.append(f"Subscription count: {len(subscribers)}")
    for identity in subscribers:
        endpoint_index += 1
        namespace, _, name = identity.rpartition("/")
        lines.extend(
            [
                f"Node name: {name}",
                f"Node namespace: {namespace or '/'}",
                "Topic type: ignored/by/parser",
                "Endpoint type: SUBSCRIPTION",
                f"GID: {gid_prefix}.{endpoint_index:08x}",
            ]
        )
    return "\n".join(lines) + "\n"


def test_read_only_landerpi_snapshot_callable_covers_all_three_drive_paths():
    outputs = {
        COMMAND_ROUTE: _topic_info(
            COMMAND_INTERFACE,
            publishers=[],
            subscribers=[COMMAND_SUBSCRIBER_IDENTITY],
            gid_prefix="10",
        ),
        COMPETING_COMMAND_ROUTE: _topic_info(
            COMMAND_INTERFACE,
            publishers=[],
            subscribers=[COMMAND_SUBSCRIBER_IDENTITY],
            gid_prefix="20",
        ),
        DIRECT_MOTOR_ROUTE: _topic_info(
            DIRECT_MOTOR_INTERFACE,
            publishers=[DIRECT_MOTOR_PUBLISHER_IDENTITY],
            subscribers=[],
            gid_prefix="30",
        ),
    }
    calls: list[tuple[str, ...]] = []

    def run_read_only(argv: tuple[str, ...]) -> str:
        calls.append(argv)
        assert argv[:3] == ("ros2", "topic", "info")
        assert argv[4:] == ("--verbose",)
        return outputs[argv[3]]

    observation = capture_landerpi_isolation_observation(
        run_read_only,
        policy=_policy(),
        observed_at=NOW,
    )

    assert calls == [
        ("ros2", "topic", "info", COMMAND_ROUTE, "--verbose"),
        ("ros2", "topic", "info", COMPETING_COMMAND_ROUTE, "--verbose"),
        ("ros2", "topic", "info", DIRECT_MOTOR_ROUTE, "--verbose"),
    ]
    claims = observation.artifact_claims(
        phase="PRE_CAS",
        fence_epoch=7,
        active_fence_digest=_digest("baseline-fence"),
        fence_owner_call_id="call-motion-1",
    )
    assert claims["publisher_identities"] == []
    assert claims["competing_publisher_identities"] == []
    assert claims["direct_motor_publisher_identities"] == ["/odom_publisher"]
    assert claims["provider_invocation_count"] == 0
    assert claims["motion_enabled"] is False


def test_ros2_topic_parser_rejects_count_mismatch_without_guessing():
    malformed = _topic_info(
        COMMAND_INTERFACE,
        publishers=[],
        subscribers=["/odom_publisher"],
        gid_prefix="40",
    )
    malformed = malformed.replace("Publisher count: 0", "Publisher count: 1")

    with pytest.raises(ValueError, match="do not match declared counts"):
        parse_ros2_topic_info_verbose(
            malformed,
            route=COMMAND_ROUTE,
            expected_interface=COMMAND_INTERFACE,
        )


def test_zero_motion_acceptance_rehearses_exact_order_without_motion_or_provider_call():
    request, policy, trust_store, target = _zero_motion_fixture()

    receipt = run_zero_motion_acceptance(
        request,
        policy=policy,
        trust_store=trust_store,
        target=target,
        now=NOW,
    )

    assert receipt.status == "READY_FOR_PROVIDER_GATE"
    assert receipt.ready_for_provider_gate is True
    assert receipt.motion_authorized is False
    assert receipt.motion_command_emitted is False
    assert receipt.provider_invocation_count == 0
    assert receipt.requires_live_provider_cas is True
    assert receipt.artifacts.complete() is True
    assert target.calls == [
        "snapshot:pre",
        "fence:cas",
        "ack:start",
        "ack:stop",
        "snapshot:post",
        "fence:release",
        "gate:challenge",
    ]
    assert target.provider_invocations == 0
    assert target.motion_commands == 0


def test_zero_motion_acceptance_defaults_to_blocked_without_target_adapter():
    request, policy, trust_store, _ = _zero_motion_fixture()

    receipt = run_zero_motion_acceptance(
        request,
        policy=policy,
        trust_store=trust_store,
        now=NOW,
    )

    assert receipt.status == "BLOCKED"
    assert receipt.reasons == ("ZERO_MOTION_TARGET_ADAPTER_REQUIRED",)
    assert receipt.motion_authorized is False


def test_zero_motion_acceptance_rejects_explicit_debug_only_peer_before_target_actions():
    request, policy, trust_store, target = _zero_motion_fixture()
    target.production_peer_verified = lambda: False

    receipt = run_zero_motion_acceptance(
        request,
        policy=policy,
        trust_store=trust_store,
        target=target,
        now=NOW,
    )

    assert receipt.status == "BLOCKED"
    assert receipt.reasons == ("PRODUCTION_PINNED_TARGET_PEER_REQUIRED",)
    assert target.calls == []


def test_zero_motion_acceptance_rejects_adapter_with_missing_peer_provenance():
    request, policy, trust_store, target = _zero_motion_fixture()
    target.production_peer_verified = None

    receipt = run_zero_motion_acceptance(
        request,
        policy=policy,
        trust_store=trust_store,
        target=target,
        now=NOW,
    )

    assert receipt.status == "BLOCKED"
    assert receipt.reasons == ("PRODUCTION_PINNED_TARGET_PEER_REQUIRED",)
    assert target.calls == []


@pytest.mark.parametrize(
    ("fault", "reason"),
    [
        ("fresh_zero_missing", "PRE_ISOLATION_SNAPSHOT_CLAIMS_INVALID"),
        ("fresh_zero_moving", "PRE_ISOLATION_SNAPSHOT_FRESH_ZERO_EVIDENCE_INVALID"),
        ("fresh_zero_stale", "PRE_ISOLATION_SNAPSHOT_FRESH_ZERO_EVIDENCE_STALE"),
    ],
)
def test_zero_motion_acceptance_requires_fresh_command_motor_and_imu_zero_proof(fault, reason):
    request, policy, trust_store, target = _zero_motion_fixture(fault=fault)

    receipt = run_zero_motion_acceptance(
        request,
        policy=policy,
        trust_store=trust_store,
        target=target,
        now=NOW,
    )

    assert receipt.status == "BLOCKED"
    assert reason in receipt.reasons
    assert "fence:cas" not in target.calls


def test_static_operator_or_field_safety_failure_rejects_before_target():
    request, policy, trust_store, target = _zero_motion_fixture()
    admission = request.admission.model_copy(
        update={
            "evidence": request.admission.evidence.model_copy(update={"operator_authorization": None}),
        }
    )
    request = request.model_copy(update={"admission": admission})

    receipt = run_zero_motion_acceptance(
        request,
        policy=policy,
        trust_store=trust_store,
        target=target,
        now=NOW,
    )

    assert receipt.status == "BLOCKED"
    assert "STATIC_MOTION_SAFETY_BLOCKED" in receipt.reasons
    assert "OPERATOR_AUTHORIZATION_REQUIRED" in receipt.reasons
    assert target.calls == []


@pytest.mark.parametrize(
    ("fault", "reason"),
    [
        ("command_publisher", "COMMAND_ROUTE_NOT_ISOLATED"),
        ("competing_publisher", "COMPETING_COMMAND_ROUTE_NOT_ISOLATED"),
        ("motor_publisher", "DIRECT_MOTOR_ROUTE_NOT_ISOLATED"),
    ],
)
def test_each_live_drive_path_conflict_blocks_before_fence_cas(fault, reason):
    request, policy, trust_store, target = _zero_motion_fixture(fault=fault)

    receipt = run_zero_motion_acceptance(
        request,
        policy=policy,
        trust_store=trust_store,
        target=target,
        now=NOW,
    )

    assert receipt.status == "BLOCKED"
    assert reason in receipt.reasons
    assert target.calls == ["snapshot:pre"]
    assert target.provider_invocations == target.motion_commands == 0


@pytest.mark.parametrize(
    ("fault", "reason"),
    [
        ("cas_bad_signature", "LIVE_FENCE_CAS_SIGNATURE_INVALID"),
        ("cas_call_drift", "LIVE_FENCE_CAS_CALL_ID_MISMATCH"),
        ("cas_not_acquired", "LIVE_FENCE_CAS_NOT_ACQUIRED"),
        ("reused_artifact_id", "ZERO_MOTION_ARTIFACT_ID_REUSED"),
    ],
)
def test_invalid_live_cas_never_reaches_start_and_triggers_fail_closed_abort(fault, reason):
    request, policy, trust_store, target = _zero_motion_fixture(fault=fault)

    receipt = run_zero_motion_acceptance(
        request,
        policy=policy,
        trust_store=trust_store,
        target=target,
        now=NOW,
    )

    assert receipt.status == "BLOCKED"
    assert reason in receipt.reasons
    assert target.calls == ["snapshot:pre", "fence:cas", "abort"]
    assert "ack:start" not in target.calls
    assert target.provider_invocations == target.motion_commands == 0


@pytest.mark.parametrize(
    ("fault", "reason", "prefix"),
    [
        ("start_emitted_motion", "ZERO_MOTION_START_ACK_MOTION_COMMAND_EMITTED", ["snapshot:pre", "fence:cas", "ack:start"]),
        ("stop_wrong_start", "ZERO_MOTION_STOP_ACK_START_MISMATCH", ["snapshot:pre", "fence:cas", "ack:start", "ack:stop"]),
        (
            "post_graph_drift",
            "POST_STOP_ISOLATION_SNAPSHOT_GRAPH_REVISION_CHANGED",
            ["snapshot:pre", "fence:cas", "ack:start", "ack:stop", "snapshot:post"],
        ),
        (
            "release_not_released",
            "LIVE_FENCE_NOT_RELEASED",
            ["snapshot:pre", "fence:cas", "ack:start", "ack:stop", "snapshot:post", "fence:release"],
        ),
        (
            "challenge_not_one_shot",
            "PROVIDER_GATE_CHALLENGE_NOT_ONE_SHOT",
            [
                "snapshot:pre",
                "fence:cas",
                "ack:start",
                "ack:stop",
                "snapshot:post",
                "fence:release",
                "gate:challenge",
            ],
        ),
    ],
)
def test_ack_graph_or_release_failure_is_blocked_and_aborted(fault, reason, prefix):
    request, policy, trust_store, target = _zero_motion_fixture(fault=fault)

    receipt = run_zero_motion_acceptance(
        request,
        policy=policy,
        trust_store=trust_store,
        target=target,
        now=NOW,
    )

    assert receipt.status == "BLOCKED"
    assert reason in receipt.reasons
    assert target.calls == [*prefix, "abort"]
    assert target.provider_invocations == target.motion_commands == 0


def test_target_exception_is_sanitized_not_retried_and_aborted_after_cas_attempt():
    request, policy, trust_store, target = _zero_motion_fixture(fault="cas_exception")

    receipt = run_zero_motion_acceptance(
        request,
        policy=policy,
        trust_store=trust_store,
        target=target,
        now=NOW,
    )

    assert receipt.reasons == ("LIVE_FENCE_CAS_UNAVAILABLE",)
    assert target.calls == ["snapshot:pre", "fence:cas", "abort"]
    assert "UNTRUSTED_TARGET_EXCEPTION_MARKER" not in json.dumps(receipt.model_dump(mode="json"))


def test_missing_target_lifecycle_method_blocks_before_any_target_call():
    request, policy, trust_store, target = _zero_motion_fixture()
    target.release_fence = None

    receipt = run_zero_motion_acceptance(
        request,
        policy=policy,
        trust_store=trust_store,
        target=target,
        now=NOW,
    )

    assert receipt.status == "BLOCKED"
    assert receipt.reasons == ("ZERO_MOTION_TARGET_RELEASE_FENCE_REQUIRED",)
    assert target.calls == []


def test_provider_boundary_consumes_challenge_with_a_fresh_one_shot_cas():
    request, policy, trust_store, target = _zero_motion_fixture()
    acceptance = run_zero_motion_acceptance(
        request,
        policy=policy,
        trust_store=trust_store,
        target=target,
        now=NOW,
    )

    consumption = consume_provider_gate_challenge(
        request,
        acceptance,
        policy=policy,
        trust_store=trust_store,
        target=target,
        now=NOW,
    )

    assert consumption.status == "CONSUMED"
    assert consumption.consumed is True
    assert consumption.provider_boundary_open is True
    assert consumption.provider_invocation_limit == 1
    assert consumption.motion_authorized is False
    assert consumption.consume_artifact is not None
    assert consumption.consume_artifact.kind == "PROVIDER_GATE_CONSUMED"
    assert target.calls[-1] == "gate:consume"
    assert target.provider_invocations == target.motion_commands == 0


def test_provider_gate_challenge_replay_is_rejected_by_target_owned_cas():
    request, policy, trust_store, target = _zero_motion_fixture()
    acceptance = run_zero_motion_acceptance(
        request,
        policy=policy,
        trust_store=trust_store,
        target=target,
        now=NOW,
    )
    first = consume_provider_gate_challenge(
        request,
        acceptance,
        policy=policy,
        trust_store=trust_store,
        target=target,
        now=NOW,
    )

    replay = consume_provider_gate_challenge(
        request,
        acceptance,
        policy=policy,
        trust_store=trust_store,
        target=target,
        now=NOW,
    )

    assert first.status == "CONSUMED"
    assert replay.status == "BLOCKED"
    assert "PROVIDER_GATE_NOT_CONSUMED_ONCE" in replay.reasons
    assert replay.provider_boundary_open is False
    assert target.calls[-2:] == ["gate:consume", "abort"]


def test_invalid_provider_challenge_signature_blocks_before_fresh_cas():
    request, policy, trust_store, target = _zero_motion_fixture()
    acceptance = run_zero_motion_acceptance(
        request,
        policy=policy,
        trust_store=trust_store,
        target=target,
        now=NOW,
    )
    assert acceptance.provider_gate is not None
    invalid_challenge = acceptance.provider_gate.model_copy(update={"signature_hmac_sha256": "hmac-sha256:" + "0" * 64})
    invalid_acceptance = acceptance.model_copy(update={"provider_gate": invalid_challenge})
    call_count = len(target.calls)

    consumption = consume_provider_gate_challenge(
        request,
        invalid_acceptance,
        policy=policy,
        trust_store=trust_store,
        target=target,
        now=NOW,
    )

    assert consumption.status == "BLOCKED"
    assert "PROVIDER_GATE_CHALLENGE_SIGNATURE_INVALID" in consumption.reasons
    assert len(target.calls) == call_count


def test_provider_fresh_cas_exception_is_sanitized_and_never_opens_boundary():
    request, policy, trust_store, target = _zero_motion_fixture(fault="consume_exception")
    acceptance = run_zero_motion_acceptance(
        request,
        policy=policy,
        trust_store=trust_store,
        target=target,
        now=NOW,
    )

    consumption = consume_provider_gate_challenge(
        request,
        acceptance,
        policy=policy,
        trust_store=trust_store,
        target=target,
        now=NOW,
    )

    assert consumption.status == "BLOCKED"
    assert consumption.reasons == ("PROVIDER_GATE_FRESH_CAS_UNAVAILABLE",)
    assert consumption.provider_boundary_open is False
    assert target.calls[-2:] == ["gate:consume", "abort"]
    assert "UNTRUSTED_TARGET_EXCEPTION_MARKER" not in json.dumps(consumption.model_dump(mode="json"))


def test_zero_motion_acceptance_schema_preserves_the_no_motion_boundary():
    request, policy, trust_store, target = _zero_motion_fixture()
    receipt = run_zero_motion_acceptance(
        request,
        policy=policy,
        trust_store=trust_store,
        target=target,
        now=NOW,
    )
    schema_path = Path(__file__).parents[1] / "schemas" / "TargetdZeroMotionAcceptance.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema, format_checker=FormatChecker())

    validator.validate(request.model_dump(mode="json"))
    validator.validate(receipt.model_dump(mode="json"))
    consumption = consume_provider_gate_challenge(
        request,
        receipt,
        policy=policy,
        trust_store=trust_store,
        target=target,
        now=NOW,
    )
    validator.validate(consumption.model_dump(mode="json"))

    unsafe_receipt = receipt.model_dump(mode="json")
    unsafe_receipt["motion_authorized"] = True
    with pytest.raises(ValidationError):
        validator.validate(unsafe_receipt)

    unsafe_request = request.model_dump(mode="json")
    unsafe_request["motion_command"] = {"linear_x": 0.1}
    with pytest.raises(ValidationError):
        validator.validate(unsafe_request)


def test_production_landerpi_target_composes_with_acceptance_and_fresh_consume(tmp_path):
    admission, policy, trust_store = _fixture()
    request = ZeroMotionAcceptanceRequest(acceptance_id="acceptance-live-target-1", admission=admission)

    class Rpc:
        armed = False

        def security_context(self):
            host_key = "sha256:" + "1" * 64
            return PinnedLanderPiRpcSecurity(
                target_id=TARGET_ID,
                target_identity=TARGET_IDENTITY,
                pinned_host_key_sha256=host_key,
                observed_host_key_sha256=host_key,
            )

        def topic_info_verbose(self, *, route, expected_interface):
            if route == COMMAND_ROUTE:
                return _topic_info(
                    expected_interface,
                    publishers=[PUBLISHER_IDENTITY] if self.armed else [],
                    subscribers=[COMMAND_SUBSCRIBER_IDENTITY],
                    gid_prefix="10",
                )
            if route == COMPETING_COMMAND_ROUTE:
                return _topic_info(
                    expected_interface,
                    publishers=[],
                    subscribers=[COMMAND_SUBSCRIBER_IDENTITY],
                    gid_prefix="20",
                )
            assert route == DIRECT_MOTOR_ROUTE
            return _topic_info(
                expected_interface,
                publishers=[DIRECT_MOTOR_PUBLISHER_IDENTITY],
                subscribers=[],
                gid_prefix="30",
            )

        def zero_motion_status(self):
            if not self.armed:
                return LanderPiZeroMotionStatus(observed_at=NOW, provider_process_state="ABSENT")
            runtime_digest = compute_armed_zero_provider_identity_digest(
                call_id=admission.intent.call_id,
                session_id=admission.intent.session_id,
                execution_subject_digest=admission.intent.execution_subject_digest,
                publisher_identity=PUBLISHER_IDENTITY,
                publisher_gid="10.00000001",
                provider_pid=4242,
                provider_start_time_ticks=123456,
                provider_runtime_sha256="sha256:" + "b" * 64,
                provider_cmdline_sha256="sha256:" + "c" * 64,
            )
            return LanderPiZeroMotionStatus(
                observed_at=NOW,
                provider_process_state="ARMED_ZERO",
                publisher_identity=PUBLISHER_IDENTITY,
                publisher_gid="10.00000001",
                call_id=admission.intent.call_id,
                session_id=admission.intent.session_id,
                execution_subject_digest=admission.intent.execution_subject_digest,
                provider_pid=4242,
                provider_start_time_ticks=123456,
                provider_runtime_sha256="sha256:" + "b" * 64,
                provider_cmdline_sha256="sha256:" + "c" * 64,
                provider_runtime_identity_digest=runtime_digest,
                last_command_is_zero=True,
                motor_output_zero=True,
                motors_stopped=True,
                zero_velocity_verified=True,
                fresh_zero_evidence=FreshZeroMotionEvidence.model_validate(_fresh_zero_claims()["fresh_zero_evidence"]),
                fresh_zero_evidence_digest=_fresh_zero_claims()["fresh_zero_evidence_digest"],
            )

    rpc = Rpc()
    store = AtomicLanderPiMotionStateStore(tmp_path.resolve())
    store.provision(LanderPiTargetMotionState.initial(admission.intent, fence_epoch=7, now=NOW))
    target = LanderPiZeroMotionTarget(
        policy=policy,
        rpc=rpc,
        store=store,
        graph_signing_key=TargetSigningKey.from_bytes(KEYS[ISSUERS["graph"]]),
        target_signing_key=TargetSigningKey.from_bytes(KEYS[ISSUERS["target"]]),
        clock=lambda: NOW,
    )
    assert target.verify_initial_isolation().command.publisher_count == 0
    rpc.armed = True

    acceptance = run_zero_motion_acceptance(
        request,
        policy=policy,
        trust_store=trust_store,
        target=target,
        now=NOW,
    )
    consumption = consume_provider_gate_challenge(
        request,
        acceptance,
        policy=policy,
        trust_store=trust_store,
        target=target,
        now=NOW,
    )

    assert acceptance.status == "READY_FOR_PROVIDER_GATE"
    assert acceptance.motion_authorized is False
    assert consumption.status == "CONSUMED"
    assert consumption.provider_boundary_open is True
    assert consumption.provider_invocation_limit == 1
    assert consumption.motion_authorized is False
    assert consumption.consume_artifact is not None
    assert consumption.consume_artifact.claims["armed_zero_provider_binding"]["publisher_gid"] == "10.00000001"
    assert consumption.consume_artifact.claims["armed_zero_provider_binding"]["provider_pid"] == 4242
    assert (store.load().phase, store.load().fence_epoch) == ("PROVIDER_FENCE", 10)
