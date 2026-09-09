from __future__ import annotations

import hmac
import math
from datetime import datetime, timedelta, timezone

import pytest

from rolo.targetd.controller import TargetdJourneyController
from rolo.targetd.landerpi_motion_target import DebugOnlyUserAttestedAdmission
from rolo.targetd.motion_safety import MotionSafetyIntent, MotionSafetyPolicy
from rolo.targetd.protocol import (
    FrameKind,
    JourneySession,
    ProtocolError,
    ProtocolFrame,
    debug_zero_motion_acceptance_auth_tag,
)
from rolo.targetd.transport import JourneySessionClient

TOKEN = "t" * 32
TARGET_ID = "mentorpi"
SESSION_ID = "session-wire-1"
CALL_ID = "call-wire-1"
REQUEST_DIGEST = "a" * 64
ARMED_ZERO_RECEIPT_DIGEST = "b" * 64
POINT = datetime(2026, 9, 9, 8, 0, tzinfo=timezone.utc)


def _session() -> JourneySession:
    return JourneySession(
        session_id=SESSION_ID,
        target_id=TARGET_ID,
        profile_id="landerpi",
        resume_token=TOKEN,
        created_at=POINT,
        expires_at=POINT + timedelta(hours=1),
    )


def _admission() -> DebugOnlyUserAttestedAdmission:
    intent = MotionSafetyIntent(
        call_id=CALL_ID,
        session_id=SESSION_ID,
        target_id=TARGET_ID,
        target_identity="sha256:mentorpi-device-key",
        operator_id="operator:field-1",
        execution_subject_digest="sha256:" + "1" * 64,
        requested_at=POINT,
        ros_graph_digest="sha256:" + "2" * 64,
        command_route="/cmd_vel",
        command_interface="geometry_msgs/msg/Twist",
        publisher_identity="/rolo_bounded_twist",
        direct_motor_route="/ros_robot_controller/set_motor",
        direct_motor_interface="ros_robot_controller_msgs/msg/MotorsState",
        direct_motor_publisher_identity="/odom_publisher",
        direct_motor_fence_digest="sha256:" + "3" * 64,
        stop_action_digest="sha256:" + "4" * 64,
    )
    policy = MotionSafetyPolicy(
        target_id=TARGET_ID,
        target_identity=intent.target_identity,
        site_id="site:wire-test",
        safe_zone_id="zone:wire-test",
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
        graph_authority_id="authority:graph",
        target_authority_id="authority:target",
    )
    return DebugOnlyUserAttestedAdmission.build(
        attestation_id="debug-wire-attestation-1",
        acceptance_id="debug-wire-acceptance-1",
        intent=intent,
        policy=policy,
        basis_text="Wire-only deterministic safety attestation fixture.",
        requested_rotation_degrees=1.0,
        requested_linear_meters=0.0,
        issued_at=POINT,
        expires_at=POINT + timedelta(seconds=20),
    )


def _auth_kwargs() -> dict[str, object]:
    return {
        "target_id": TARGET_ID,
        "session_id": SESSION_ID,
        "call_id": CALL_ID,
        "request_digest": REQUEST_DIGEST,
        "armed_zero_receipt_digest": ARMED_ZERO_RECEIPT_DIGEST,
        "debug_admission_digest": "sha256:" + "c" * 64,
        "sequence": 7,
    }


def test_debug_zero_motion_acceptance_auth_has_stable_vector() -> None:
    assert debug_zero_motion_acceptance_auth_tag(TOKEN, **_auth_kwargs()) == (
        "e28dd1a02bcb2170f1366e51efb9343c54f8ebdcd2e8920e7cf9c6b0f51e608e"
    )


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("session_token", "u" * 32),
        ("target_id", "mentorpi-other"),
        ("session_id", "session-wire-2"),
        ("call_id", "call-wire-2"),
        ("request_digest", "d" * 64),
        ("armed_zero_receipt_digest", "e" * 64),
        ("debug_admission_digest", "sha256:" + "f" * 64),
        ("sequence", 8),
    ],
)
def test_debug_zero_motion_acceptance_auth_binds_every_field(
    field: str,
    replacement: object,
) -> None:
    baseline = debug_zero_motion_acceptance_auth_tag(TOKEN, **_auth_kwargs())
    token = TOKEN
    kwargs = _auth_kwargs()
    if field == "session_token":
        token = str(replacement)
    else:
        kwargs[field] = replacement

    tampered = debug_zero_motion_acceptance_auth_tag(token, **kwargs)

    assert not hmac.compare_digest(baseline, tampered)


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("session_token", "too-short"),
        ("target_id", "bad/target"),
        ("session_id", ""),
        ("call_id", "call with spaces"),
        ("request_digest", "sha256:" + "a" * 64),
        ("request_digest", "g" * 64),
        ("armed_zero_receipt_digest", "b" * 63),
        ("debug_admission_digest", "c" * 64),
        ("debug_admission_digest", "sha256:" + "C" * 64),
        ("sequence", True),
        ("sequence", -1),
        ("sequence", 1.0),
        ("sequence", math.nan),
    ],
)
def test_debug_zero_motion_acceptance_auth_rejects_noncanonical_identity(
    field: str,
    replacement: object,
) -> None:
    token = TOKEN
    kwargs = _auth_kwargs()
    if field == "session_token":
        token = str(replacement)
    else:
        kwargs[field] = replacement

    with pytest.raises(
        ProtocolError,
        match="^TARGETD_DEBUG_ZERO_MOTION_ACCEPTANCE_IDENTITY_INVALID$",
    ):
        debug_zero_motion_acceptance_auth_tag(token, **kwargs)


class _EchoResultChannel:
    def __init__(self) -> None:
        self.sent: list[ProtocolFrame] = []
        self.responses: list[ProtocolFrame] = []
        self.response_sequence = 0

    def send(self, frame: ProtocolFrame) -> None:
        self.sent.append(frame)
        self.responses.append(
            ProtocolFrame.create(
                kind=FrameKind.RESULT,
                sequence=self.response_sequence,
                session_id=frame.session_id,
                run_id=frame.run_id,
                payload={"request_kind": frame.kind.value, "ok": True},
            )
        )
        self.response_sequence += 1

    def receive(self) -> ProtocolFrame:
        return self.responses.pop(0)

    def close(self) -> None:
        return None


def test_debug_acceptance_client_uses_exact_payload_and_same_session_sequence() -> None:
    admission = _admission()
    channel = _EchoResultChannel()
    client = JourneySessionClient(channel, _session())

    for _ in range(2):
        response = client.accept_debug_zero_motion_remote(
            call_id=CALL_ID,
            request_digest=REQUEST_DIGEST,
            armed_zero_receipt_digest=ARMED_ZERO_RECEIPT_DIGEST,
            debug_admission=admission,
        )
        assert response.payload["ok"] is True

    assert [frame.kind for frame in channel.sent] == [
        FrameKind.ACCEPT_DEBUG_ZERO_MOTION,
        FrameKind.ACCEPT_DEBUG_ZERO_MOTION,
    ]
    assert [frame.sequence for frame in channel.sent] == [0, 1]
    assert {frame.session_id for frame in channel.sent} == {SESSION_ID}
    assert {frame.run_id for frame in channel.sent} == {None}

    expected_keys = {
        "call_id",
        "target_id",
        "request_digest",
        "armed_zero_receipt_digest",
        "debug_admission",
        "debug_admission_digest",
        "acceptance_auth",
    }
    for sequence, frame in enumerate(channel.sent):
        assert set(frame.payload) == expected_keys
        assert frame.payload == {
            "call_id": CALL_ID,
            "target_id": TARGET_ID,
            "request_digest": REQUEST_DIGEST,
            "armed_zero_receipt_digest": ARMED_ZERO_RECEIPT_DIGEST,
            "debug_admission": admission.model_dump(mode="json"),
            "debug_admission_digest": admission.payload_sha256,
            "acceptance_auth": debug_zero_motion_acceptance_auth_tag(
                TOKEN,
                target_id=TARGET_ID,
                session_id=SESSION_ID,
                call_id=CALL_ID,
                request_digest=REQUEST_DIGEST,
                armed_zero_receipt_digest=ARMED_ZERO_RECEIPT_DIGEST,
                debug_admission_digest=admission.payload_sha256,
                sequence=sequence,
            ),
        }
    assert channel.sent[0].payload["acceptance_auth"] != channel.sent[1].payload[
        "acceptance_auth"
    ]


def test_debug_acceptance_controller_forwards_only_the_typed_client_api() -> None:
    admission = _admission()
    expected = object()

    class _Client:
        def __init__(self) -> None:
            self.calls = []

        def accept_debug_zero_motion_remote(self, **kwargs):
            self.calls.append(kwargs)
            return expected

    client = _Client()
    controller = object.__new__(TargetdJourneyController)
    controller.client = client

    assert (
        controller.accept_debug_zero_motion(
            call_id=CALL_ID,
            request_digest=REQUEST_DIGEST,
            armed_zero_receipt_digest=ARMED_ZERO_RECEIPT_DIGEST,
            debug_admission=admission,
        )
        is expected
    )
    assert client.calls == [
        {
            "call_id": CALL_ID,
            "request_digest": REQUEST_DIGEST,
            "armed_zero_receipt_digest": ARMED_ZERO_RECEIPT_DIGEST,
            "debug_admission": admission,
        }
    ]


@pytest.mark.parametrize("debug_admission", [object(), {}, {"extra": True}])
def test_debug_acceptance_client_rejects_invalid_admission_before_send(
    debug_admission: object,
) -> None:
    channel = _EchoResultChannel()
    client = JourneySessionClient(channel, _session())

    with pytest.raises(
        ProtocolError,
        match="^TARGETD_DEBUG_ZERO_MOTION_ACCEPTANCE_IDENTITY_INVALID$",
    ):
        client.accept_debug_zero_motion_remote(
            call_id=CALL_ID,
            request_digest=REQUEST_DIGEST,
            armed_zero_receipt_digest=ARMED_ZERO_RECEIPT_DIGEST,
            debug_admission=debug_admission,
        )

    assert channel.sent == []


@pytest.mark.parametrize(
    ("response_kind", "request_kind", "message"),
    [
        (FrameKind.EVENT, FrameKind.ACCEPT_DEBUG_ZERO_MOTION.value, "non-CALL"),
        (FrameKind.HAS, FrameKind.ACCEPT_DEBUG_ZERO_MOTION.value, "RESULT frame"),
        (FrameKind.RESULT, FrameKind.START_PREPARED_CALL.value, "request kind"),
    ],
)
def test_debug_acceptance_client_rejects_spoofed_response_frame_type(
    response_kind: FrameKind,
    request_kind: str,
    message: str,
) -> None:
    session = _session()

    class _SpoofedResponseChannel:
        def __init__(self) -> None:
            self.sent: list[ProtocolFrame] = []

        def send(self, frame: ProtocolFrame) -> None:
            self.sent.append(frame)

        def receive(self) -> ProtocolFrame:
            return ProtocolFrame.create(
                kind=response_kind,
                sequence=0,
                session_id=session.session_id,
                payload={"request_kind": request_kind},
            )

        def close(self) -> None:
            return None

    channel = _SpoofedResponseChannel()
    client = JourneySessionClient(channel, session)

    with pytest.raises(ProtocolError, match=message):
        client.accept_debug_zero_motion_remote(
            call_id=CALL_ID,
            request_digest=REQUEST_DIGEST,
            armed_zero_receipt_digest=ARMED_ZERO_RECEIPT_DIGEST,
            debug_admission=_admission(),
        )

    assert len(channel.sent) == 1
    with pytest.raises(ProtocolError, match="unusable after a channel failure"):
        client.accept_debug_zero_motion_remote(
            call_id=CALL_ID,
            request_digest=REQUEST_DIGEST,
            armed_zero_receipt_digest=ARMED_ZERO_RECEIPT_DIGEST,
            debug_admission=_admission(),
        )
    assert len(channel.sent) == 1
