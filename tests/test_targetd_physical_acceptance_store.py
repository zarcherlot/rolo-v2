import hashlib
import json
import os
from datetime import datetime, timedelta, timezone

import pytest

import rolo.targetd.physical_acceptance as physical_acceptance
from rolo.targetd.landerpi_motion_target import (
    DebugOnlyUserAttestedAdmission,
    DebugUserAttestedAcceptanceReceipt,
    compute_armed_zero_provider_identity_digest,
)
from rolo.targetd.lifecycle import WorkerCallKey
from rolo.targetd.motion_acceptance import (
    SignedZeroMotionArtifact,
    ZeroMotionArtifactDigests,
)
from rolo.targetd.motion_safety import (
    MotionSafetyIntent,
    MotionSafetyPolicy,
    compute_motion_payload_digest,
)
from rolo.targetd.physical_acceptance import DebugPhysicalAcceptanceReceiptStore
from rolo.targetd.physical_worker import parse_physical_worker_armed_zero
from rolo.targetd.protocol import ProtocolError

NOW = datetime(2026, 9, 9, 8, 0, tzinfo=timezone.utc)
EXECUTION_SUBJECT = "sha256:" + "a" * 64
RUNTIME_SHA256 = "b" * 64
REQUEST_DIGEST = "c" * 64
TARGET_ID = "mentorpi"
CALL_ID = "call-debug-1"
SESSION_ID = "session-debug-1"
TARGET_IDENTITY = "sha256:mentorpi-device-key"
PUBLISHER_GID = "10" * 16


def _call_key(*, request_digest: str = REQUEST_DIGEST) -> WorkerCallKey:
    return WorkerCallKey(
        target_id=TARGET_ID,
        session_id=SESSION_ID,
        idempotency_key=CALL_ID,
        request_digest=request_digest,
    )


def _intent() -> MotionSafetyIntent:
    return MotionSafetyIntent(
        call_id=CALL_ID,
        session_id=SESSION_ID,
        target_id=TARGET_ID,
        target_identity=TARGET_IDENTITY,
        operator_id="operator:field-1",
        execution_subject_digest=EXECUTION_SUBJECT,
        requested_at=NOW,
        ros_graph_digest="sha256:" + "d" * 64,
        command_route="/cmd_vel",
        command_interface="geometry_msgs/msg/Twist",
        publisher_identity="/rolo_bounded_twist",
        direct_motor_route="/ros_robot_controller/set_motor",
        direct_motor_interface="ros_robot_controller_msgs/msg/MotorsState",
        direct_motor_publisher_identity="/odom_publisher",
        direct_motor_fence_digest="sha256:" + "e" * 64,
        stop_action_digest="sha256:" + "f" * 64,
    )


def _policy() -> MotionSafetyPolicy:
    return MotionSafetyPolicy(
        target_id=TARGET_ID,
        target_identity=TARGET_IDENTITY,
        site_id="site:lab-1",
        safe_zone_id="zone:bench-1",
        command_route="/cmd_vel",
        command_interface="geometry_msgs/msg/Twist",
        allowed_publisher_identity="/rolo_bounded_twist",
        direct_motor_route="/ros_robot_controller/set_motor",
        direct_motor_interface="ros_robot_controller_msgs/msg/MotorsState",
        allowed_direct_motor_publisher_identity="/odom_publisher",
        operator_authority_id="authority:operator",
        presence_authority_id="authority:presence",
        safety_authority_id="authority:safety",
        graph_authority_id="authority:graph",
        target_authority_id="authority:target",
    )


def _admission() -> DebugOnlyUserAttestedAdmission:
    return DebugOnlyUserAttestedAdmission.build(
        attestation_id="debug-attestation-1",
        acceptance_id="debug-acceptance-1",
        intent=_intent(),
        policy=_policy(),
        basis_text="现场人员、安全区和独立急停均已由用户明确确认。",
        requested_rotation_degrees=1.0,
        requested_linear_meters=0.0,
        issued_at=NOW,
        expires_at=NOW + timedelta(seconds=20),
    )


def _armed_zero(*, call_key: WorkerCallKey | None = None, pid: int = 4242):
    key = _call_key() if call_key is None else call_key
    start_ticks = 123456
    cmdline_sha256 = "1" * 64
    issued_at = NOW.timestamp()
    expires_at = issued_at + 20.0
    runtime_identity = compute_armed_zero_provider_identity_digest(
        call_id=key.idempotency_key,
        session_id=key.session_id,
        execution_subject_digest=EXECUTION_SUBJECT,
        publisher_identity="/rolo_bounded_twist",
        publisher_gid=PUBLISHER_GID,
        provider_pid=pid,
        provider_start_time_ticks=start_ticks,
        provider_runtime_sha256="sha256:" + RUNTIME_SHA256,
        provider_cmdline_sha256="sha256:" + cmdline_sha256,
    )
    registry_unsigned = {
        "schema_version": "rolo-targetd-physical-worker-registry-binding/v1",
        "target_id": key.target_id,
        "call_key_digest": key.digest(),
        "call_id": key.idempotency_key,
        "session_id": key.session_id,
        "execution_subject_digest": EXECUTION_SUBJECT,
        "publisher_identity": "/rolo_bounded_twist",
        "publisher_gid": PUBLISHER_GID,
        "provider_pid": pid,
        "provider_start_time_ticks": start_ticks,
        "provider_runtime_sha256": "sha256:" + RUNTIME_SHA256,
        "provider_cmdline_sha256": "sha256:" + cmdline_sha256,
        "issued_at_epoch_s": issued_at,
        "expires_at_epoch_s": expires_at,
    }
    registry_digest = "sha256:" + hashlib.sha256(
        json.dumps(
            registry_unsigned,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    ).hexdigest()
    unsigned = {
        "schema_version": "rolo-targetd-physical-worker-arm-receipt/v1",
        "call_key_digest": key.digest(),
        "target_id": key.target_id,
        "call_id": key.idempotency_key,
        "session_id": key.session_id,
        "request_digest": key.request_digest,
        "execution_subject_digest": EXECUTION_SUBJECT,
        "runtime_sha256": RUNTIME_SHA256,
        "command_endpoint": "/cmd_vel",
        "publisher_identity": "/rolo_bounded_twist",
        "publisher_endpoint_gids": [PUBLISHER_GID],
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
        "target_monotonic_s": 100.0,
        "provider_runtime_sha256": "sha256:" + RUNTIME_SHA256,
        "provider_cmdline_sha256": "sha256:" + cmdline_sha256,
        "provider_runtime_identity_digest": runtime_identity,
        "registry_issued_at_epoch_s": issued_at,
        "registry_expires_at_epoch_s": expires_at,
        "registry_binding_digest": registry_digest,
    }
    arm_digest = hashlib.sha256(
        json.dumps(
            unsigned,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    ).hexdigest()
    return parse_physical_worker_armed_zero(
        {**unsigned, "arm_receipt_digest": arm_digest},
        expected_call_key_digest=key.digest(),
        expected_target_id=key.target_id,
        expected_call_id=key.idempotency_key,
        expected_session_id=key.session_id,
        expected_request_digest=key.request_digest,
        expected_execution_subject_digest=EXECUTION_SUBJECT,
        expected_runtime_sha256=RUNTIME_SHA256,
    )


def _receipt(admission: DebugOnlyUserAttestedAdmission, armed_zero):
    intent = _intent()
    signing_key = b"t" * 32
    issued_at = NOW + timedelta(milliseconds=50)
    expires_at = NOW + timedelta(seconds=15)
    debug_claims = {
        "debug_only": True,
        "report_status": "PASS_WITH_USER_ATTESTED_SITE_SAFETY",
        "debug_admission_digest": admission.payload_sha256,
        "basis": admission.basis,
        "basis_digest": admission.basis_digest,
        "site_id": admission.site_id,
        "safe_zone_id": admission.safe_zone_id,
        "requested_rotation_degrees": admission.requested_rotation_degrees,
        "requested_linear_meters": admission.requested_linear_meters,
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
        artifact_id="debug-attestation-artifact-1",
        kind="DEBUG_USER_ATTESTED_ADMISSION",
        issuer_id="authority:target",
        acceptance_id=admission.acceptance_id,
        intent=intent,
        issued_at=issued_at,
        expires_at=expires_at,
        claims=debug_claims,
        signing_key=signing_key,
    )
    debug_binding = {
        "debug_admission_digest": admission.payload_sha256,
        "debug_attestation_artifact_digest": debug_artifact.payload_sha256,
        "basis_digest": admission.basis_digest,
        "requested_rotation_degrees": admission.requested_rotation_degrees,
        "requested_linear_meters": admission.requested_linear_meters,
        "max_abs_rotation_degrees": 1.0,
        "max_abs_linear_meters": 0.03,
        "production_authority_verified": False,
        "fresh_estop_challenge_verified": False,
        "production_ready": False,
        "report_status": "PASS_WITH_USER_ATTESTED_SITE_SAFETY",
    }
    challenge = SignedZeroMotionArtifact.build(
        artifact_id="debug-provider-challenge-1",
        kind="PROVIDER_GATE_CHALLENGE",
        issuer_id="authority:target",
        acceptance_id=admission.acceptance_id,
        intent=intent,
        issued_at=issued_at + timedelta(milliseconds=50),
        expires_at=expires_at,
        claims={
            "one_shot": True,
            "consumed": False,
            "armed_zero_provider_binding": armed_zero.provider_binding().model_dump(
                mode="json"
            ),
            "debug_gate_binding": debug_binding,
            "motion_enabled": False,
            "provider_invocation_count": 0,
        },
        signing_key=signing_key,
    )
    artifact_digests = {
        "pre_isolation_snapshot": "sha256:" + "1" * 64,
        "fence_cas": "sha256:" + "2" * 64,
        "start_ack": "sha256:" + "3" * 64,
        "stop_ack": "sha256:" + "4" * 64,
        "post_stop_isolation_snapshot": "sha256:" + "5" * 64,
        "fence_release": "sha256:" + "6" * 64,
        "provider_gate_challenge": challenge.payload_sha256,
    }
    return DebugUserAttestedAcceptanceReceipt(
        status="DEBUG_ACCEPTED",
        report_status="PASS_WITH_USER_ATTESTED_SITE_SAFETY",
        reasons=(),
        evaluated_at=NOW + timedelta(milliseconds=150),
        acceptance_id=admission.acceptance_id,
        call_id=admission.call_id,
        session_id=admission.session_id,
        target_id=admission.target_id,
        target_identity=admission.target_identity,
        operator_id=admission.operator_id,
        execution_subject_digest=admission.execution_subject_digest,
        debug_admission_digest=admission.payload_sha256,
        debug_attestation_artifact=debug_artifact,
        artifacts=ZeroMotionArtifactDigests(**artifact_digests),
        provider_gate=challenge,
        debug_gate_ready=True,
    )


def _fixture():
    key = _call_key()
    admission = _admission()
    armed = _armed_zero(call_key=key)
    receipt = _receipt(admission, armed)
    persisted_at = NOW + timedelta(milliseconds=200)
    return key, admission, armed, receipt, persisted_at


def test_persist_load_resolve_revalidate_and_exact_replay_are_idempotent(tmp_path):
    key, admission, armed, receipt, persisted_at = _fixture()
    store = DebugPhysicalAcceptanceReceiptStore(tmp_path / "acceptances")

    first = store.persist(
        key,
        receipt,
        armed_zero=armed,
        debug_admission=admission,
        now=persisted_at,
    )
    replay = store.persist(
        key,
        receipt,
        armed_zero=armed.as_dict(),
        debug_admission=admission,
        now=persisted_at,
    )

    assert replay == first
    assert first.sidecar.content_digest == first.sidecar.sidecar_digest
    assert first.uri.startswith(
        f"artifact://targetd/debug-physical-acceptances/{key.digest()}/"
    )
    assert first.digest_uri == "digest://sha256/" + first.sidecar.sidecar_digest[7:]
    assert first.sidecar.armed_zero == armed.as_dict()
    assert store.load(key) == first
    assert (
        store.resolve(first.uri, call_key=key, digest_uri=first.digest_uri) == first
    )
    assert store.revalidate(first) == first

    with pytest.raises(ProtocolError, match="ACCEPTANCE_CONFLICT"):
        store.persist(
            key,
            receipt,
            armed_zero=armed,
            debug_admission=admission,
            now=persisted_at + timedelta(milliseconds=1),
        )


def test_rejects_expired_history_and_arm_challenge_drift(tmp_path):
    key, admission, armed, receipt, _ = _fixture()
    store = DebugPhysicalAcceptanceReceiptStore(tmp_path / "acceptances")

    with pytest.raises(ProtocolError, match="ACCEPTANCE_INVALID"):
        store.persist(
            key,
            receipt,
            armed_zero=armed,
            debug_admission=admission,
            now=receipt.provider_gate.expires_at,
        )

    drifted_arm = _armed_zero(call_key=key, pid=5252)
    with pytest.raises(ProtocolError, match="ACCEPTANCE_INVALID"):
        store.persist(
            key,
            receipt,
            armed_zero=drifted_arm,
            debug_admission=admission,
            now=NOW + timedelta(milliseconds=200),
        )

    incomplete = receipt.model_copy(
        update={
            "artifacts": ZeroMotionArtifactDigests(
                provider_gate_challenge=receipt.provider_gate.payload_sha256
            )
        }
    )
    with pytest.raises(ProtocolError, match="ACCEPTANCE_INVALID"):
        store.persist(
            key,
            incomplete,
            armed_zero=armed,
            debug_admission=admission,
            now=NOW + timedelta(milliseconds=200),
        )


def test_tampered_sidecar_and_index_path_fail_closed(tmp_path):
    key, admission, armed, receipt, persisted_at = _fixture()
    root = tmp_path / "acceptances"
    store = DebugPhysicalAcceptanceReceiptStore(root)
    reference = store.persist(
        key,
        receipt,
        armed_zero=armed,
        debug_admission=admission,
        now=persisted_at,
    )
    sidecar_path = root / "receipts" / f"{reference.sidecar.sidecar_digest[7:]}.json"
    payload = json.loads(sidecar_path.read_text(encoding="utf-8"))
    payload["acceptance_receipt"]["debug_gate_ready"] = False
    sidecar_path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ProtocolError, match="SIDECAR_INVALID"):
        store.load(key)

    other_root = tmp_path / "bad-index"
    other_store = DebugPhysicalAcceptanceReceiptStore(other_root)
    other_store.persist(
        key,
        receipt,
        armed_zero=armed,
        debug_admission=admission,
        now=persisted_at,
    )
    index_path = other_root / "index.json"
    index = json.loads(index_path.read_text(encoding="utf-8"))
    index["entries"][key.digest()]["relative_path"] = "../outside.json"
    index_path.write_text(json.dumps(index), encoding="utf-8")
    with pytest.raises(ProtocolError, match="INDEX_INVALID"):
        other_store.load(key)


def test_reference_grammar_and_symlink_root_are_rejected(tmp_path):
    key, admission, armed, receipt, persisted_at = _fixture()
    store = DebugPhysicalAcceptanceReceiptStore(tmp_path / "acceptances")
    reference = store.persist(
        key,
        receipt,
        armed_zero=armed,
        debug_admission=admission,
        now=persisted_at,
    )
    with pytest.raises(ProtocolError, match="REFERENCE_INVALID"):
        store.resolve(
            reference.uri + "/../escape",
            call_key=key,
            digest_uri=reference.digest_uri,
        )
    with pytest.raises(ProtocolError, match="REFERENCE_INVALID"):
        store.resolve(
            reference.uri,
            call_key=key,
            digest_uri="digest://sha256/" + "0" * 64,
        )

    real_root = tmp_path / "real-root"
    real_root.mkdir()
    linked_root = tmp_path / "linked-root"
    try:
        os.symlink(real_root, linked_root, target_is_directory=True)
    except (NotImplementedError, OSError):
        pytest.skip("symlink creation is not available")
    with pytest.raises(ProtocolError, match="STORE_UNTRUSTED"):
        DebugPhysicalAcceptanceReceiptStore(linked_root)


def test_same_debug_admission_cannot_be_indexed_under_another_call_key(tmp_path):
    key, admission, armed, receipt, persisted_at = _fixture()
    store = DebugPhysicalAcceptanceReceiptStore(tmp_path / "acceptances")
    store.persist(
        key,
        receipt,
        armed_zero=armed,
        debug_admission=admission,
        now=persisted_at,
    )
    changed_key = _call_key(request_digest="9" * 64)
    changed_arm = _armed_zero(call_key=changed_key)
    with pytest.raises(ProtocolError, match="ACCEPTANCE_CONFLICT"):
        store.persist(
            changed_key,
            receipt,
            armed_zero=changed_arm,
            debug_admission=admission,
            now=persisted_at,
        )


def test_admission_payload_digest_is_not_a_free_form_index_value(tmp_path):
    key, admission, armed, receipt, persisted_at = _fixture()
    store = DebugPhysicalAcceptanceReceiptStore(tmp_path / "acceptances")
    store.persist(
        key,
        receipt,
        armed_zero=armed,
        debug_admission=admission,
        now=persisted_at,
    )
    index_path = tmp_path / "acceptances" / "index.json"
    index = json.loads(index_path.read_text(encoding="utf-8"))
    index["entries"][key.digest()]["debug_admission_digest"] = (
        "sha256:" + "0" * 64
    )
    index_path.write_text(json.dumps(index), encoding="utf-8")
    with pytest.raises(ProtocolError, match="SIDECAR_INVALID"):
        store.load(key)


def test_store_byte_bound_is_checked_before_creating_a_sidecar(tmp_path, monkeypatch):
    key, admission, armed, receipt, persisted_at = _fixture()
    root = tmp_path / "bounded"
    store = DebugPhysicalAcceptanceReceiptStore(root)
    monkeypatch.setattr(
        physical_acceptance,
        "MAX_DEBUG_PHYSICAL_ACCEPTANCE_STORE_BYTES",
        1,
    )

    with pytest.raises(ProtocolError, match="CAPACITY_EXCEEDED"):
        store.persist(
            key,
            receipt,
            armed_zero=armed,
            debug_admission=admission,
            now=persisted_at,
        )
    assert not (root / "receipts").exists()


def test_debug_admission_builder_digest_remains_canonical():
    admission = _admission()
    assert admission.payload_sha256 == compute_motion_payload_digest(
        admission.unsigned_payload()
    )
