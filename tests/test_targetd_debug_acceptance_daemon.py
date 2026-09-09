from __future__ import annotations

import io
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from rolo.core.hashing import canonical_json_sha256
from rolo.targetd.daemon import TargetdDaemon
from rolo.targetd.landerpi_motion_target import DebugOnlyUserAttestedAdmission
from rolo.targetd.lifecycle import WorkerCallKey, WorkerLeaseStore
from rolo.targetd.motion_safety import MotionSafetyPolicy
from rolo.targetd.physical_acceptance import (
    DebugPhysicalAcceptanceReceiptStore,
)
from rolo.targetd.physical_gate import (
    DebugUserAttestedPhysicalProviderGate,
    PhysicalProviderGateReceiptStore,
)
from rolo.targetd.protocol import (
    FrameKind,
    ProtocolFrame,
    debug_zero_motion_acceptance_auth_tag,
    encode_frame,
    physical_gate_query_auth_tag,
    physical_prepared_start_auth_tag,
)
from rolo.targetd.service import TargetdPhysicalProcessStart
from rolo.targetd.worker import RosContainerProvider
from tests import test_targetd_physical_acceptance_store as acceptance_fixtures
from tests.test_targetd_process_service import (
    _armed_zero,
    _physical_service,
    _TwoPhaseRuntimeStub,
)


def _debug_policy(request) -> MotionSafetyPolicy:
    intent = request.motion_safety_admission.intent
    return MotionSafetyPolicy(
        target_id=request.target_id,
        target_identity=intent.target_identity,
        site_id="site:supervised-field-debug",
        safe_zone_id="zone:supervised-field-debug",
        command_route=intent.command_route,
        command_interface=intent.command_interface,
        allowed_publisher_identity=intent.publisher_identity,
        direct_motor_route=intent.direct_motor_route,
        direct_motor_interface=intent.direct_motor_interface,
        allowed_direct_motor_publisher_identity=(
            intent.direct_motor_publisher_identity
        ),
        operator_authority_id="authority:operator",
        presence_authority_id="authority:presence",
        safety_authority_id="authority:safety",
        graph_authority_id="authority:target",
        target_authority_id="authority:target",
    )


def _debug_material(request, armed_zero, monkeypatch):
    now = datetime.now(timezone.utc)
    policy = _debug_policy(request)
    admission = DebugOnlyUserAttestedAdmission.build(
        attestation_id="debug-attestation-daemon",
        acceptance_id="debug-acceptance-daemon",
        intent=request.motion_safety_admission.intent,
        policy=policy,
        basis_text="explicit session-only onsite debug safety attestation",
        requested_rotation_degrees=request.arguments["angle_degrees"],
        requested_linear_meters=0.0,
        issued_at=now,
        expires_at=now + timedelta(seconds=20),
    )
    monkeypatch.setattr(acceptance_fixtures, "NOW", now)
    monkeypatch.setattr(
        acceptance_fixtures,
        "_intent",
        lambda: request.motion_safety_admission.intent,
    )
    receipt = acceptance_fixtures._receipt(admission, armed_zero)
    gate = object.__new__(DebugUserAttestedPhysicalProviderGate)
    object.__setattr__(gate, "admission", admission)
    object.__setattr__(gate, "acceptance_receipt", receipt)
    object.__setattr__(gate, "intent", request.motion_safety_admission.intent)
    object.__setattr__(gate, "policy", policy)
    object.__setattr__(gate, "trust_store", object())
    object.__setattr__(
        gate,
        "target",
        SimpleNamespace(abort_zero_motion=lambda **_kwargs: None),
    )
    object.__setattr__(gate, "clock", lambda: now + timedelta(milliseconds=200))
    return admission, receipt, gate


def _accept_frame(request, session, admission, armed_zero, *, sequence, auth=None):
    return ProtocolFrame.create(
        kind=FrameKind.ACCEPT_DEBUG_ZERO_MOTION,
        sequence=sequence,
        session_id=request.session_id,
        run_id=request.run_id,
        payload={
            "call_id": request.idempotency_key,
            "target_id": request.target_id,
            "request_digest": request.request_digest(),
            "armed_zero_receipt_digest": armed_zero.arm_receipt_digest,
            "debug_admission": admission.model_dump(mode="json"),
            "debug_admission_digest": admission.payload_sha256,
            "acceptance_auth": (
                auth
                if auth is not None
                else debug_zero_motion_acceptance_auth_tag(
                    session.resume_token,
                    target_id=request.target_id,
                    session_id=request.session_id,
                    call_id=request.idempotency_key,
                    request_digest=request.request_digest(),
                    armed_zero_receipt_digest=armed_zero.arm_receipt_digest,
                    debug_admission_digest=admission.payload_sha256,
                    sequence=sequence,
                )
            ),
        },
    )


def _start_frame(request, session, armed_zero, provider_gate, *, sequence):
    digest = canonical_json_sha256(provider_gate)
    return ProtocolFrame.create(
        kind=FrameKind.START_PREPARED_CALL,
        sequence=sequence,
        session_id=request.session_id,
        run_id=request.run_id,
        payload={
            "call_id": request.idempotency_key,
            "target_id": request.target_id,
            "request_digest": request.request_digest(),
            "armed_zero_receipt_digest": armed_zero.arm_receipt_digest,
            "provider_gate": provider_gate,
            "provider_gate_payload_digest": digest,
            "start_auth": physical_prepared_start_auth_tag(
                session.resume_token,
                target_id=request.target_id,
                session_id=request.session_id,
                call_id=request.idempotency_key,
                request_digest=request.request_digest(),
                armed_zero_receipt_digest=armed_zero.arm_receipt_digest,
                provider_gate_payload_digest=digest,
                sequence=sequence,
            ),
        },
    )


def test_debug_acceptance_is_one_shot_recoverable_and_start_bound(
    tmp_path,
    monkeypatch,
):
    service, authority, request, manifest = _physical_service(tmp_path)
    worker_store = WorkerLeaseStore(tmp_path / "physical-leases")
    gate_store = PhysicalProviderGateReceiptStore(tmp_path / "physical-gates")
    acceptance_store = DebugPhysicalAcceptanceReceiptStore(
        tmp_path / "physical-acceptances"
    )
    armed_zero = _armed_zero(request, manifest)
    admission, acceptance_receipt, gate = _debug_material(
        request,
        armed_zero,
        monkeypatch,
    )
    runtime = _TwoPhaseRuntimeStub(worker_store, armed_zero)
    service.physical_worker_store = worker_store
    service.physical_gate_receipt_store = gate_store
    service.physical_acceptance_receipt_store = acceptance_store
    factory_calls = []

    monkeypatch.setattr(
        DebugUserAttestedPhysicalProviderGate,
        "validate_request",
        lambda _self, observed_request, observed_authority: (
            factory_calls.append("validate")
            if observed_request == request and observed_authority == authority
            else pytest.fail("debug gate identity drift")
        ),
    )

    def acceptance_factory(observed_request, observed_manifest, observed_arm, observed):
        assert (observed_request, observed_manifest) == (request, manifest)
        assert observed_arm == armed_zero
        assert observed == admission
        factory_calls.append("accept")
        return gate

    daemon = TargetdDaemon(
        service,
        execute_calls=True,
        provider=RosContainerProvider(),
        physical_process_runtime=runtime,
        physical_process_work_factory=lambda *_args: object(),
        physical_acceptance_factory=acceptance_factory,
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

    bypass_gate = {
        "schema_version": "rolo-targetd-debug-zero-motion-acceptance-reference/v1"
    }
    bypass = daemon._handle(
        _start_frame(request, session, armed_zero, bypass_gate, sequence=1)
    )
    assert bypass.payload["ok"] is False
    assert bypass.payload["error"] == "TARGETD_DEBUG_ZERO_MOTION_ACCEPTANCE_REQUIRED"
    assert runtime.start_calls == 0

    forged = daemon._handle(
        _accept_frame(
            request,
            session,
            admission,
            armed_zero,
            sequence=2,
            auth="0" * 64,
        )
    )
    assert forged.payload["ok"] is False
    assert forged.payload["error"] == (
        "TARGETD_DEBUG_ZERO_MOTION_ACCEPTANCE_AUTHENTICATION_FAILED"
    )
    assert factory_calls == []

    accepted = daemon._handle(
        _accept_frame(
            request,
            session,
            admission,
            armed_zero,
            sequence=3,
        )
    )
    assert accepted.payload["ok"] is True
    assert accepted.payload["accepted"] is True
    assert accepted.payload["start_eligible"] is True
    assert accepted.payload["acceptance_receipt"] == acceptance_receipt.model_dump(
        mode="json"
    )
    assert accepted.payload["receipt"]["status"] == "ACCEPTED"
    assert accepted.payload["receipt"]["provider_started_at"] is None
    assert accepted.payload["provider_invocation_count"] == 0
    assert factory_calls.count("accept") == 1
    assert runtime.start_calls == 0

    replayed = daemon._handle(
        _accept_frame(
            request,
            session,
            admission,
            armed_zero,
            sequence=4,
        )
    )
    assert replayed.payload["ok"] is True
    assert replayed.payload["debug_acceptance"] == accepted.payload["debug_acceptance"]
    assert replayed.payload["provider_gate_start"] == accepted.payload[
        "provider_gate_start"
    ]
    assert factory_calls.count("accept") == 1
    assert runtime.start_calls == 0

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
                "gate_uri": None,
                "gate_digest_uri": None,
                "query_gate_auth": physical_gate_query_auth_tag(
                    session.resume_token,
                    target_id=request.target_id,
                    session_id=request.session_id,
                    call_id=request.idempotency_key,
                    request_digest=request.request_digest(),
                    gate_uri=None,
                    gate_digest_uri=None,
                    sequence=query_sequence,
                ),
            },
        )
    )
    assert queried.payload["ok"] is True
    assert queried.payload["accepted"] is True
    assert queried.payload["start_eligible"] is True
    assert queried.payload["provider_gate_start"] == accepted.payload[
        "provider_gate_start"
    ]
    assert queried.payload["physical_worker_lease"]["call_key"] == (
        WorkerCallKey.from_request(request).model_dump(mode="json")
    )
    assert "lease_token" not in queried.payload["physical_worker_lease"]
    assert factory_calls.count("accept") == 1
    assert service.state.load_receipt(
        request.session_id,
        request.idempotency_key,
    ).status == "ACCEPTED"

    # A daemon restart may recover the immutable acceptance proof, but the
    # deployment gate/target capability is intentionally not serialized.
    # Therefore the recovered reference can never become a new START seam.
    restarted = TargetdDaemon(service)
    restarted.physical_process_runtime = runtime
    restarted._session = session
    restarted_query_sequence = 0
    recovered = restarted._handle(
        ProtocolFrame.create(
            kind=FrameKind.QUERY_CALL,
            sequence=restarted_query_sequence,
            session_id=request.session_id,
            payload={
                "call_id": request.idempotency_key,
                "target_id": request.target_id,
                "request_digest": request.request_digest(),
                "gate_uri": None,
                "gate_digest_uri": None,
                "query_gate_auth": physical_gate_query_auth_tag(
                    session.resume_token,
                    target_id=request.target_id,
                    session_id=request.session_id,
                    call_id=request.idempotency_key,
                    request_digest=request.request_digest(),
                    gate_uri=None,
                    gate_digest_uri=None,
                    sequence=restarted_query_sequence,
                ),
            },
        )
    )
    assert recovered.payload["ok"] is True
    assert recovered.payload["accepted"] is True
    assert recovered.payload["start_eligible"] is False
    restart_start = restarted._handle(
        _start_frame(
            request,
            session,
            armed_zero,
            recovered.payload["provider_gate_start"],
            sequence=1,
        )
    )
    assert restart_start.payload["ok"] is False
    assert restart_start.payload["error"] == "TARGETD_PHYSICAL_PREPARED_CALL_NOT_FOUND"
    assert runtime.start_calls == 0

    original_load = runtime.store.load
    monkeypatch.setattr(runtime.store, "load", lambda _call_key: None)
    missing_sequence = 6
    missing_lease = daemon._handle(
        ProtocolFrame.create(
            kind=FrameKind.QUERY_CALL,
            sequence=missing_sequence,
            session_id=request.session_id,
            run_id=request.run_id,
            payload={
                "call_id": request.idempotency_key,
                "target_id": request.target_id,
                "request_digest": request.request_digest(),
                "gate_uri": None,
                "gate_digest_uri": None,
                "query_gate_auth": physical_gate_query_auth_tag(
                    session.resume_token,
                    target_id=request.target_id,
                    session_id=request.session_id,
                    call_id=request.idempotency_key,
                    request_digest=request.request_digest(),
                    gate_uri=None,
                    gate_digest_uri=None,
                    sequence=missing_sequence,
                ),
            },
        )
    )
    assert missing_lease.payload["ok"] is False
    assert missing_lease.payload["error"] == "TARGETD_PHYSICAL_WORKER_LEASE_MISSING"
    assert service.state.load_receipt(
        request.session_id,
        request.idempotency_key,
    ).status == "ACCEPTED"
    monkeypatch.setattr(runtime.store, "load", original_load)

    monkeypatch.setattr(
        "rolo.targetd.physical_worker.read_target_physical_worker_registry",
        lambda **_kwargs: SimpleNamespace(armed_zero=armed_zero),
    )
    expected_arm = armed_zero

    def fake_start(
        observed_request,
        observed_manifest,
        *,
        provider_id,
        lease_claim,
        armed_zero,
    ):
        assert (observed_request, observed_manifest) == (request, manifest)
        assert provider_id == "ros-container"
        assert lease_claim.lease.call_key == WorkerCallKey.from_request(request)
        assert armed_zero == expected_arm
        assert service.physical_motion_gate is gate
        service.resolve_debug_physical_acceptance(
            WorkerCallKey.from_request(request),
            expected_uri=accepted.payload["debug_acceptance"]["uri"],
            expected_digest_uri=accepted.payload["debug_acceptance"]["digest_uri"],
        )
        point = datetime.now(timezone.utc)
        receipt = service.state.update_receipt(
            request.session_id,
            request.idempotency_key,
            lambda current: current.model_copy(
                update={
                    "status": "STARTED",
                    "provider_started_at": point,
                    "updated_at": point,
                }
            ),
        )
        return TargetdPhysicalProcessStart(receipt=receipt, provider_gate=object())

    monkeypatch.setattr(service, "start_physical_process_call", fake_start)
    started = daemon._handle(
        _start_frame(
            request,
            session,
            armed_zero,
            accepted.payload["provider_gate_start"],
            sequence=7,
        )
    )
    assert started.payload["ok"] is True
    assert started.payload["receipt"]["status"] == "STARTED"
    assert started.payload["provider_invocation_count"] == 1
    assert runtime.start_calls == 1

    replay_start = daemon._handle(
        _start_frame(
            request,
            session,
            armed_zero,
            accepted.payload["provider_gate_start"],
            sequence=8,
        )
    )
    assert replay_start.payload["ok"] is False
    assert replay_start.payload["error"] == (
        "TARGETD_PHYSICAL_PREPARED_START_ALREADY_CONSUMED"
    )
    assert runtime.start_calls == 1


def test_debug_acceptance_unexpected_factory_failure_is_stable_and_stops(
    tmp_path,
    monkeypatch,
):
    service, _authority, request, manifest = _physical_service(tmp_path)
    worker_store = WorkerLeaseStore(tmp_path / "physical-leases")
    service.physical_worker_store = worker_store
    service.physical_gate_receipt_store = PhysicalProviderGateReceiptStore(
        tmp_path / "physical-gates"
    )
    service.physical_acceptance_receipt_store = (
        DebugPhysicalAcceptanceReceiptStore(tmp_path / "physical-acceptances")
    )
    armed_zero = _armed_zero(request, manifest)
    admission, _, _ = _debug_material(request, armed_zero, monkeypatch)
    runtime = _TwoPhaseRuntimeStub(worker_store, armed_zero)
    factory_calls = 0

    def request_interrupt(call_key, *, intent):
        assert call_key == WorkerCallKey.from_request(request)
        assert intent == "STOP"
        runtime.interrupt_calls += 1
        return SimpleNamespace()

    runtime.request_interrupt = request_interrupt

    def fail_factory(*_args):
        nonlocal factory_calls
        factory_calls += 1
        raise OSError("target transport unavailable")

    daemon = TargetdDaemon(
        service,
        execute_calls=True,
        provider=RosContainerProvider(),
        physical_process_runtime=runtime,
        physical_process_work_factory=lambda *_args: object(),
        physical_acceptance_factory=fail_factory,
    )
    session = service.state.load_session(request.session_id)
    daemon._session = session
    assert daemon._handle(
        ProtocolFrame.create(
            kind=FrameKind.PREPARE_PHYSICAL_CALL,
            sequence=0,
            session_id=request.session_id,
            payload=request.model_dump(mode="json"),
        )
    ).payload["ok"] is True

    response = daemon._handle(
        _accept_frame(
            request,
            session,
            admission,
            armed_zero,
            sequence=1,
        )
    )
    assert response.payload == {
        "request_kind": "ACCEPT_DEBUG_ZERO_MOTION",
        "ok": False,
        "error": "TARGETD_DEBUG_ZERO_MOTION_ACCEPTANCE_BLOCKED",
        "provider_invocation_count": 0,
    }
    assert runtime.interrupt_calls == 1
    assert runtime.start_calls == 0
    assert factory_calls == 1

    replay = daemon._handle(
        _accept_frame(
            request,
            session,
            admission,
            armed_zero,
            sequence=2,
        )
    )
    assert replay.payload["ok"] is False
    assert replay.payload["error"] == (
        "TARGETD_DEBUG_ZERO_MOTION_ACCEPTANCE_OUTCOME_UNKNOWN"
    )
    assert factory_calls == 1


def test_debug_acceptance_ack_failure_stops_exact_prepared_worker(
    tmp_path,
    monkeypatch,
):
    service, authority, request, manifest = _physical_service(tmp_path)
    worker_store = WorkerLeaseStore(tmp_path / "physical-leases")
    service.physical_worker_store = worker_store
    service.physical_gate_receipt_store = PhysicalProviderGateReceiptStore(
        tmp_path / "physical-gates"
    )
    service.physical_acceptance_receipt_store = (
        DebugPhysicalAcceptanceReceiptStore(tmp_path / "physical-acceptances")
    )
    armed_zero = _armed_zero(request, manifest)
    admission, _, gate = _debug_material(request, armed_zero, monkeypatch)
    runtime = _TwoPhaseRuntimeStub(worker_store, armed_zero)
    stopped = []

    def request_interrupt(call_key, *, intent):
        stopped.append((call_key, intent))
        runtime.interrupt_calls += 1
        return SimpleNamespace()

    runtime.request_interrupt = request_interrupt
    monkeypatch.setattr(
        DebugUserAttestedPhysicalProviderGate,
        "validate_request",
        lambda _self, observed_request, observed_authority: (
            None
            if observed_request == request and observed_authority == authority
            else pytest.fail("debug gate identity drift")
        ),
    )
    daemon = TargetdDaemon(
        service,
        execute_calls=True,
        provider=RosContainerProvider(),
        physical_process_runtime=runtime,
        physical_process_work_factory=lambda *_args: object(),
        physical_acceptance_factory=lambda *_args: gate,
    )
    session = service.state.load_session(request.session_id)
    daemon._session = session
    assert daemon._handle(
        ProtocolFrame.create(
            kind=FrameKind.PREPARE_PHYSICAL_CALL,
            sequence=11,
            session_id=request.session_id,
            payload=request.model_dump(mode="json"),
        )
    ).payload["ok"] is True

    class BrokenOutput:
        def write(self, _payload):
            raise OSError("simulated lost acceptance response")

        def flush(self):
            raise AssertionError("flush must not follow a failed write")

    # serve(), unlike direct _handle() tests, enforces the stream sequence.
    # The PREPARE above did not pass through serve and therefore sequence 0
    # is the next wire frame for this isolated transport exercise.
    frame = _accept_frame(
        request,
        session,
        admission,
        armed_zero,
        sequence=0,
    )
    with pytest.raises(OSError, match="lost acceptance response"):
        daemon.serve(io.BytesIO(encode_frame(frame)), BrokenOutput())

    assert stopped == [(WorkerCallKey.from_request(request), "STOP")]
    assert runtime.start_calls == 0
    assert daemon._provider_invocation_count == 0
    assert WorkerCallKey.from_request(request).digest() not in daemon._pending_physical
    receipt = service.state.load_receipt(
        request.session_id,
        request.idempotency_key,
    )
    assert receipt is not None and receipt.status == "ACCEPTED"
    assert receipt.provider_started_at is None


def test_debug_acceptance_persistence_failure_stops_without_start(
    tmp_path,
    monkeypatch,
):
    service, authority, request, manifest = _physical_service(tmp_path)
    worker_store = WorkerLeaseStore(tmp_path / "physical-leases")
    acceptance_store = DebugPhysicalAcceptanceReceiptStore(
        tmp_path / "physical-acceptances"
    )
    service.physical_worker_store = worker_store
    service.physical_gate_receipt_store = PhysicalProviderGateReceiptStore(
        tmp_path / "physical-gates"
    )
    service.physical_acceptance_receipt_store = acceptance_store
    armed_zero = _armed_zero(request, manifest)
    admission, _, gate = _debug_material(request, armed_zero, monkeypatch)
    runtime = _TwoPhaseRuntimeStub(worker_store, armed_zero)
    stopped = []

    def request_interrupt(call_key, *, intent):
        stopped.append((call_key, intent))
        runtime.interrupt_calls += 1
        return SimpleNamespace()

    runtime.request_interrupt = request_interrupt
    monkeypatch.setattr(
        DebugUserAttestedPhysicalProviderGate,
        "validate_request",
        lambda _self, observed_request, observed_authority: (
            None
            if observed_request == request and observed_authority == authority
            else pytest.fail("debug gate identity drift")
        ),
    )
    monkeypatch.setattr(
        acceptance_store,
        "persist",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            OSError("simulated acceptance store outage")
        ),
    )
    daemon = TargetdDaemon(
        service,
        execute_calls=True,
        provider=RosContainerProvider(),
        physical_process_runtime=runtime,
        physical_process_work_factory=lambda *_args: object(),
        physical_acceptance_factory=lambda *_args: gate,
    )
    session = service.state.load_session(request.session_id)
    daemon._session = session
    assert daemon._handle(
        ProtocolFrame.create(
            kind=FrameKind.PREPARE_PHYSICAL_CALL,
            sequence=0,
            session_id=request.session_id,
            payload=request.model_dump(mode="json"),
        )
    ).payload["ok"] is True

    response = daemon._handle(
        _accept_frame(
            request,
            session,
            admission,
            armed_zero,
            sequence=1,
        )
    )
    assert response.payload["ok"] is False
    assert response.payload["error"] == (
        "TARGETD_DEBUG_ZERO_MOTION_ACCEPTANCE_BLOCKED"
    )
    assert stopped == [(WorkerCallKey.from_request(request), "STOP")]
    assert runtime.start_calls == 0
    receipt = service.state.load_receipt(
        request.session_id,
        request.idempotency_key,
    )
    assert receipt is not None and receipt.status == "ACCEPTED"
    assert receipt.provider_started_at is None
    assert receipt.artifact_refs == []
