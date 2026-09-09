from __future__ import annotations

import time
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from rolo.targetd.landerpi_motion_target import (
    DebugOnlyUserAttestedAdmission,
    DebugUserAttestedProviderGateReceipt,
)
from rolo.targetd.lifecycle import WorkerCallKey, WorkerLeaseStore
from rolo.targetd.motion_acceptance import SignedZeroMotionArtifact
from rolo.targetd.motion_safety import MotionSafetyPolicy
from rolo.targetd.physical_acceptance import (
    DebugPhysicalAcceptanceReceiptStore,
)
from rolo.targetd.physical_gate import (
    DebugUserAttestedPhysicalProviderGate,
    PhysicalProviderGateReceiptStore,
)
from rolo.targetd.protocol import ProtocolError
from tests import test_targetd_physical_acceptance_store as acceptance_helpers
from tests.test_targetd_process_service import _armed_zero, _physical_service


def _debug_admission(request, *, now: datetime) -> DebugOnlyUserAttestedAdmission:
    intent = request.motion_safety_admission.intent
    policy = MotionSafetyPolicy(
        target_id=intent.target_id,
        target_identity=intent.target_identity,
        site_id="test-site:debug-lab",
        safe_zone_id="test-zone:debug-pad",
        command_route=intent.command_route,
        command_interface=intent.command_interface,
        allowed_publisher_identity=intent.publisher_identity,
        direct_motor_route=intent.direct_motor_route,
        direct_motor_interface=intent.direct_motor_interface,
        allowed_direct_motor_publisher_identity=(
            intent.direct_motor_publisher_identity
        ),
        operator_authority_id="test-authority:debug-operator",
        presence_authority_id="test-authority:debug-presence",
        safety_authority_id="test-authority:debug-safety",
        graph_authority_id="test-authority:debug-graph",
        target_authority_id="test-authority:debug-target",
    )
    return DebugOnlyUserAttestedAdmission.build(
        attestation_id="debug-attestation-service-1",
        acceptance_id="debug-acceptance-service-1",
        intent=intent,
        policy=policy,
        basis_text="The operator, clear zone, and independent E-stop are asserted.",
        requested_rotation_degrees=1.0,
        requested_linear_meters=0.0,
        issued_at=now,
        expires_at=now + timedelta(seconds=20),
    )


def _tree_snapshot(root: Path) -> dict[str, bytes]:
    if not root.exists():
        return {}
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def _prepared_acceptance(tmp_path, monkeypatch, *, sidecar_arm=None):
    service, _authority, request, manifest = _physical_service(tmp_path)
    worker_store = WorkerLeaseStore(tmp_path / "physical-leases")
    gate_store = PhysicalProviderGateReceiptStore(tmp_path / "physical-gates")
    acceptance_store = DebugPhysicalAcceptanceReceiptStore(
        tmp_path / "debug-acceptances"
    )
    service.physical_worker_store = worker_store
    service.physical_gate_receipt_store = gate_store
    service.physical_acceptance_receipt_store = acceptance_store

    accepted = service.prepare_physical_process_call(
        request,
        manifest,
        provider_id="ros-container",
    )
    assert accepted.status == "ACCEPTED"
    call_key = WorkerCallKey.from_request(request)
    armed_zero = _armed_zero(request, manifest)
    claim = worker_store.claim(
        call_key,
        supervisor_id="targetd-debug-service-test",
        worker_id="physical-debug-worker",
        deadline_at=request.deadline,
        physical_execution_subject_digest=request.execution_subject_digest,
        physical_runtime_sha256=manifest.observation_contract[
            "provider_runtime_sha256"
        ],
    )
    worker_store.start(claim)
    worker_store.record_armed_zero(claim, armed_zero=armed_zero.as_dict())

    clock = max(datetime.now(timezone.utc), accepted.updated_at) + timedelta(
        milliseconds=10
    )
    admission = _debug_admission(request, now=clock)
    monkeypatch.setattr(acceptance_helpers, "NOW", clock)
    monkeypatch.setattr(
        acceptance_helpers,
        "_intent",
        lambda: request.motion_safety_admission.intent,
    )
    persisted_arm = armed_zero if sidecar_arm is None else sidecar_arm
    debug_receipt = acceptance_helpers._receipt(admission, persisted_arm)
    reference = acceptance_store.persist(
        call_key,
        debug_receipt,
        armed_zero=persisted_arm,
        debug_admission=admission,
        now=clock + timedelta(milliseconds=200),
    )
    return (
        service,
        request,
        manifest,
        worker_store,
        acceptance_store,
        call_key,
        armed_zero,
        claim,
        reference,
    )


def _consumed_debug_receipt(request, admission, acceptance, armed_zero):
    intent = request.motion_safety_admission.intent
    challenge = acceptance.provider_gate
    assert challenge is not None
    point = acceptance.evaluated_at + timedelta(milliseconds=10)
    consume = SignedZeroMotionArtifact.build(
        artifact_id="debug-provider-consumed-service-1",
        kind="PROVIDER_GATE_CONSUMED",
        issuer_id="authority:target",
        acceptance_id=admission.acceptance_id,
        intent=intent,
        issued_at=point,
        expires_at=challenge.expires_at,
        claims={
            "consumed": True,
            "one_shot": True,
            "challenge_artifact_digest": challenge.payload_sha256,
            "graph_compare_and_set": True,
            "fence_compare_and_set": True,
            "motion_enabled": False,
            "provider_invocation_count": 0,
            "armed_zero_provider_binding": armed_zero.provider_binding().model_dump(
                mode="json"
            ),
            "debug_gate_binding": challenge.claims["debug_gate_binding"],
        },
        signing_key=b"t" * 32,
    )
    return DebugUserAttestedProviderGateReceipt(
        status="DEBUG_CONSUMED",
        report_status="PASS_WITH_USER_ATTESTED_SITE_SAFETY",
        reasons=(),
        evaluated_at=point,
        acceptance_id=admission.acceptance_id,
        call_id=request.idempotency_key,
        session_id=request.session_id,
        target_id=request.target_id,
        target_identity=intent.target_identity,
        operator_id=intent.operator_id,
        execution_subject_digest=request.execution_subject_digest,
        debug_admission_digest=admission.payload_sha256,
        challenge_artifact_digest=challenge.payload_sha256,
        debug_attestation_artifact=acceptance.debug_attestation_artifact,
        challenge_artifact=challenge,
        consume_artifact=consume,
        debug_provider_boundary_open=True,
        debug_motion_authorized=True,
        provider_invocation_limit=1,
    )


def test_record_keeps_call_accepted_and_is_exactly_idempotent(
    tmp_path,
    monkeypatch,
):
    (
        service,
        request,
        _manifest,
        _worker_store,
        _acceptance_store,
        call_key,
        _armed_zero_receipt,
        _claim,
        reference,
    ) = _prepared_acceptance(tmp_path, monkeypatch)
    before = service.state.load_receipt(
        request.session_id,
        request.idempotency_key,
    )
    assert before is not None

    recorded = service.record_debug_physical_acceptance(call_key, reference)

    assert recorded.status == "ACCEPTED"
    assert recorded.provider_started_at is None
    assert recorded.evidence_refs == before.evidence_refs == []
    assert recorded.artifact_refs == [reference.uri, reference.digest_uri]
    state_bytes = service.state.path.read_bytes()

    replay = service.record_debug_physical_acceptance(call_key, reference)

    assert replay == recorded
    assert service.state.path.read_bytes() == state_bytes
    assert replay.status == "ACCEPTED"
    assert replay.provider_started_at is None
    assert replay.evidence_refs == []


def test_resolve_is_a_pure_read_of_the_exact_target_owned_reference(
    tmp_path,
    monkeypatch,
):
    (
        service,
        request,
        _manifest,
        worker_store,
        acceptance_store,
        call_key,
        _armed_zero_receipt,
        _claim,
        reference,
    ) = _prepared_acceptance(tmp_path, monkeypatch)
    recorded = service.record_debug_physical_acceptance(call_key, reference)
    state_before = service.state.path.read_bytes()
    worker_before = _tree_snapshot(worker_store.root)
    acceptance_before = _tree_snapshot(acceptance_store.root)

    resolved = service.resolve_debug_physical_acceptance(
        call_key,
        expected_uri=reference.uri,
        expected_digest_uri=reference.digest_uri,
    )

    assert resolved == reference
    assert service.state.load_receipt(
        request.session_id,
        request.idempotency_key,
    ) == recorded
    assert service.state.path.read_bytes() == state_before
    assert _tree_snapshot(worker_store.root) == worker_before
    assert _tree_snapshot(acceptance_store.root) == acceptance_before


def test_record_rejects_a_forged_acceptance_reference(tmp_path, monkeypatch):
    (
        service,
        request,
        _manifest,
        _worker_store,
        _acceptance_store,
        call_key,
        _armed_zero_receipt,
        _claim,
        reference,
    ) = _prepared_acceptance(tmp_path, monkeypatch)
    forged = replace(
        reference,
        uri=reference.uri[:-1] + ("0" if reference.uri[-1] != "0" else "1"),
    )

    with pytest.raises(ProtocolError, match="ACCEPTANCE_REFERENCE_"):
        service.record_debug_physical_acceptance(call_key, forged)

    receipt = service.state.load_receipt(
        request.session_id,
        request.idempotency_key,
    )
    assert receipt is not None and receipt.status == "ACCEPTED"
    assert receipt.provider_started_at is None
    assert receipt.artifact_refs == []
    assert receipt.evidence_refs == []


def test_record_rejects_sidecar_bound_to_a_different_live_arm(
    tmp_path,
    monkeypatch,
):
    # Build the service fixture around the correct live worker ARM, then
    # persist the otherwise valid debug challenge under a separate store with
    # the different ARM identity.
    (
        service,
        request,
        manifest,
        worker_store,
        _acceptance_store,
        call_key,
        live_arm,
        _claim,
        _reference,
    ) = _prepared_acceptance(tmp_path, monkeypatch)
    # The helper signs a fresh registry window on every construction, so this
    # is a different, parser-validated ARM for the same exact call key.
    different_arm = _armed_zero(request, manifest)
    assert live_arm.as_dict() != different_arm.as_dict()
    wrong_store = DebugPhysicalAcceptanceReceiptStore(tmp_path / "wrong-arm")
    accepted = service.state.load_receipt(request.session_id, request.idempotency_key)
    assert accepted is not None
    clock = max(datetime.now(timezone.utc), accepted.updated_at) + timedelta(
        milliseconds=10
    )
    admission = _debug_admission(request, now=clock)
    monkeypatch.setattr(acceptance_helpers, "NOW", clock)
    monkeypatch.setattr(
        acceptance_helpers,
        "_intent",
        lambda: request.motion_safety_admission.intent,
    )
    wrong_receipt = acceptance_helpers._receipt(admission, different_arm)
    wrong_reference = wrong_store.persist(
        call_key,
        wrong_receipt,
        armed_zero=different_arm,
        debug_admission=admission,
        now=clock + timedelta(milliseconds=200),
    )
    service.physical_acceptance_receipt_store = wrong_store

    with pytest.raises(ProtocolError, match="PHYSICAL_WORKER_ARM_NOT_LIVE"):
        service.record_debug_physical_acceptance(call_key, wrong_reference)

    assert worker_store.load(call_key).armed_zero == live_arm.as_dict()
    unchanged = service.state.load_receipt(
        request.session_id,
        request.idempotency_key,
    )
    assert unchanged is not None and unchanged.status == "ACCEPTED"
    assert unchanged.provider_started_at is None
    assert unchanged.artifact_refs == []
    assert unchanged.evidence_refs == []


def test_debug_start_consumes_only_the_recorded_acceptance_once(
    tmp_path,
    monkeypatch,
):
    (
        service,
        request,
        manifest,
        _worker_store,
        _acceptance_store,
        call_key,
        armed_zero,
        claim,
        reference,
    ) = _prepared_acceptance(tmp_path, monkeypatch)
    recorded = service.record_debug_physical_acceptance(call_key, reference)
    admission = reference.sidecar.debug_admission
    accepted = reference.sidecar.acceptance_receipt
    consumed = _consumed_debug_receipt(
        request,
        admission,
        accepted,
        armed_zero,
    )
    gate = object.__new__(DebugUserAttestedPhysicalProviderGate)
    object.__setattr__(gate, "admission", admission)
    object.__setattr__(gate, "acceptance_receipt", accepted)
    consumes = []

    def validate(_self, observed_request, observed_authority):
        assert observed_request == request
        assert observed_authority == request.authority

    def consume(_self, observed_request, observed_authority):
        validate(_self, observed_request, observed_authority)
        consumes.append(call_key)
        return consumed

    def revalidate(_self, observed, observed_key, *, at):
        assert observed == consumed
        assert observed_key == call_key
        assert at.tzinfo is not None

    monkeypatch.setattr(
        DebugUserAttestedPhysicalProviderGate,
        "validate_request",
        validate,
    )
    monkeypatch.setattr(
        DebugUserAttestedPhysicalProviderGate,
        "consume",
        consume,
    )
    monkeypatch.setattr(
        DebugUserAttestedPhysicalProviderGate,
        "revalidate_consumption",
        revalidate,
    )
    service.physical_motion_gate = gate
    # The acceptance fixture intentionally signs artifacts a few hundred
    # milliseconds ahead of its creation point. Wait until its durable
    # historical timestamp is current before testing the START boundary.
    time.sleep(0.25)

    started = service.start_physical_process_call(
        request,
        manifest,
        provider_id="ros-container",
        lease_claim=claim,
        armed_zero=armed_zero,
    ).receipt

    assert started.status == "STARTED"
    assert started.provider_started_at is not None
    assert started.artifact_refs == recorded.artifact_refs
    assert len(started.evidence_refs) == 2
    assert started.evidence_refs[0].startswith(
        "artifact://targetd/physical-provider-gates/"
    )
    assert started.evidence_refs[1].startswith("digest://sha256/")
    assert consumes == [call_key]

    with pytest.raises(
        ProtocolError,
        match="TARGETD_PHYSICAL_PROCESS_RECEIPT_NOT_ACCEPTED",
    ):
        service.start_physical_process_call(
            request,
            manifest,
            provider_id="ros-container",
            lease_claim=claim,
            armed_zero=armed_zero,
        )
    assert consumes == [call_key]
