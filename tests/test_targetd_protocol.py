from datetime import datetime, timedelta, timezone

import pytest

from rolo.core.hashing import canonical_json_sha256
from rolo.targetd import (
    BundleCache,
    ExecutionBundleManifest,
    ExecutionRequest,
    FrameKind,
    JourneySession,
    JourneySessionClient,
    ProtocolFrame,
    TargetdCallReceipt,
    TargetdService,
    TargetdStateStore,
    decode_frame,
    encode_frame,
)
from rolo.targetd.daemon import TargetdDaemon
from rolo.targetd.worker import PythonBundleWorker, RosContainerProvider


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


def test_frame_digest_is_deterministic_and_tamper_evident():
    frame = ProtocolFrame.create(
        kind=FrameKind.CALL,
        sequence=1,
        session_id="session-1",
        run_id="run-1",
        payload={"bundle_digest": "b" * 64, "arguments": {"angle_degrees": 15}},
    )
    assert frame.frame_digest == canonical_json_sha256(
        frame.model_dump(mode="json", exclude={"frame_digest"})
    )
    with pytest.raises(ValueError, match="digest"):
        ProtocolFrame.model_validate({**frame.model_dump(), "payload": {"changed": True}})
    assert decode_frame(encode_frame(frame)) == frame
    with pytest.raises(ValueError, match="length"):
        decode_frame(encode_frame(frame) + b"trailing")
    assert decode_frame(encode_frame(ProtocolFrame.create(
        kind=FrameKind.HAS, sequence=2, session_id="session-1"
    ))).run_id is None


def test_session_and_receipt_state_support_resume_and_idempotency(tmp_path):
    store = TargetdStateStore(tmp_path / "run")
    session = JourneySession.create(session_id="session-1", target_id="mentorpi", profile_id="landerpi")
    store.save_session(session)
    assert store.load_session("session-1").resume_token == session.resume_token
    receipt = TargetdCallReceipt(
        idempotency_key="call-1",
        session_id=session.session_id,
        bundle_digest="b" * 64,
        status="SUCCEEDED",
        result={"angle_degrees": 15},
        updated_at=datetime.now(timezone.utc),
    )
    store.save_receipt(receipt)
    assert store.load_receipt("call-1") == receipt


def test_targetd_service_accepts_call_once_and_cancels_it(tmp_path):
    service = TargetdService(target_id="mentorpi", state_root=tmp_path / "state")
    session = service.open_session(
        JourneySession.create(session_id="session-2", target_id="mentorpi", profile_id="landerpi")
    )
    manifest = ExecutionBundleManifest.build(
        tool_id="app.base.rotate",
        source=b"def execute(arguments): return arguments",
        binding_digest="a" * 64,
        signer_key_id="rolo-dev",
        signing_key=b"secret",
    )
    service.put_bundle(manifest, b"def execute(arguments): return arguments")
    request = ExecutionRequest(
        run_id="run-2",
        session_id=session.session_id,
        target_id="mentorpi",
        idempotency_key="call-2",
        bundle_digest=manifest.bundle_digest,
        binding_digest="a" * 64,
        surface_digest="b" * 64,
        arguments={"angle_degrees": 15},
        mode="SUPERVISED_FIELD_DEBUG",
        deadline=datetime.now(timezone.utc) + timedelta(seconds=30),
    )
    first = service.accept_call(request, manifest)
    assert first.status == "ACCEPTED"
    assert service.accept_call(request, manifest) == first
    assert service.cancel_call("call-2").status == "CANCELLED"
    assert service.query_call("call-2").status == "CANCELLED"


def test_targetd_service_uses_signer_key_id_for_verification(tmp_path):
    source = b"def execute(arguments): return arguments"
    manifest = ExecutionBundleManifest.build(
        tool_id="app.base.rotate", source=source, binding_digest="a" * 64,
        signer_key_id="release-1", signing_key=b"release-key",
    )
    service = TargetdService(
        target_id="mentorpi", state_root=tmp_path / "state",
        verification_keys={"release-1": b"release-key"},
    )
    service.put_bundle(manifest, source)
    with pytest.raises(ValueError, match="not trusted"):
        service.put_bundle(manifest.model_copy(update={"signer_key_id": "other"}), source)


def test_request_requires_timezone_aware_deadline():
    with pytest.raises(ValueError, match="timezone"):
        ExecutionRequest(
            run_id="run-1",
            session_id="session-1",
            target_id="mentorpi",
            idempotency_key="call-1",
            bundle_digest="b" * 64,
            binding_digest="c" * 64,
            surface_digest="d" * 64,
            mode="SUPERVISED_FIELD_DEBUG",
            deadline=datetime.now() + timedelta(seconds=30),
        )


def test_targetd_daemon_handoff_updates_persisted_phase(tmp_path):
    service = TargetdService(target_id="mentorpi", state_root=tmp_path / "state")
    daemon = TargetdDaemon(service)
    session = JourneySession.create(
        session_id="daemon-session", target_id="mentorpi", profile_id="landerpi"
    )
    opened = daemon._handle(ProtocolFrame.create(
        kind=FrameKind.OPEN_JOURNEY,
        sequence=0,
        session_id=session.session_id,
        payload={"target_id": "mentorpi", "profile_id": "landerpi"},
    ))
    assert opened.payload["ok"] is True
    handed_off = daemon._handle(ProtocolFrame.create(
        kind=FrameKind.HANDOFF,
        sequence=1,
        session_id=session.session_id,
        payload={"phase": "PROBE"},
    ))
    assert handed_off.payload["phase"] == "PROBE"
    assert service.state.load_session(session.session_id).phase.value == "PROBE"


def test_targetd_daemon_resumes_session_and_queries_receipt(tmp_path):
    service = TargetdService(target_id="mentorpi", state_root=tmp_path / "state")
    session = service.open_session(
        JourneySession.create(session_id="resume-session", target_id="mentorpi", profile_id="landerpi")
    )
    daemon = TargetdDaemon(service)
    daemon._session = session
    resumed = daemon._handle(ProtocolFrame.create(
        kind=FrameKind.RESUME_SESSION, sequence=0, session_id=session.session_id,
        payload={"session_id": session.session_id, "resume_token": session.resume_token},
    ))
    assert resumed.payload["ok"] is True
    queried = daemon._handle(ProtocolFrame.create(
        kind=FrameKind.QUERY_CALL, sequence=1, session_id=session.session_id,
        payload={"call_id": "missing-call"},
    ))
    assert queried.payload["receipt"] is None


def test_python_bundle_worker_uses_generic_entrypoint_and_limits_output():
    source = b"def execute(arguments):\n    return {'received': arguments}\n"
    manifest = ExecutionBundleManifest.build(
        tool_id="app.base.rotate", source=source, binding_digest="a" * 64,
        signer_key_id="rolo-dev", signing_key=b"secret", limits={"max_output_bytes": 4096},
    )
    result = PythonBundleWorker().execute(manifest, source, {"angle_degrees": 15})
    assert result == {"received": {"angle_degrees": 15}}


def test_python_bundle_worker_passes_registered_provider_context():
    class Provider:
        def invoke(self, operation, arguments):
            return {"operation": operation, **arguments}

    source = b"def execute(arguments, provider):\n    return provider.invoke('base.rotate', arguments)\n"
    manifest = ExecutionBundleManifest.build(
        tool_id="app.base.rotate", source=source, binding_digest="a" * 64,
        signer_key_id="rolo-dev", signing_key=b"secret",
    )
    result = PythonBundleWorker(Provider()).execute(
        manifest, source, {"angle_degrees": 15, "max_speed_rad_s": 0.2}
    )
    assert result["operation"] == "base.rotate"


def test_ros_container_provider_uses_fixed_docker_argv(monkeypatch):
    seen = {}

    def fake_run(command, **kwargs):
        seen["command"] = command
        seen["input"] = kwargs["input"]
        return type("Completed", (), {"returncode": 0, "stdout": '{"stop_published":true}\n', "stderr": ""})()

    monkeypatch.setattr("rolo.targetd.worker.subprocess.run", fake_run)
    result = RosContainerProvider("MentorPi").invoke(
        "base.rotate", {"angle_degrees": 15, "max_speed_rad_s": 0.2}
    )
    assert result["stop_published"] is True
    assert seen["command"][:5] == ["docker", "exec", "-i", "MentorPi", "bash"]
    assert "ros2 topic pub" not in seen["input"]
    assert "angle_degrees" in seen["input"]


class _RecordingChannel:
    def __init__(self):
        self.frames = []

    def send(self, frame):
        self.frames.append(frame)

    def receive(self):
        return self.frames[-1]

    def close(self):
        pass


def test_journey_session_client_reuses_sequence_and_rejects_other_target():
    channel = _RecordingChannel()
    session = JourneySession.create(session_id="session-3", target_id="mentorpi", profile_id="landerpi")
    client = JourneySessionClient(channel, session)
    assert client.open().kind.value == "OPEN_JOURNEY"
    assert client.bootstrap().sequence == 1
    assert client.phase_change("PROBE").sequence == 2
    assert [frame.sequence for frame in channel.frames] == [0, 1, 2]
    with pytest.raises(ValueError, match="session"):
        client.call(ExecutionRequest(
            run_id="run-3", session_id="other", target_id="mentorpi", idempotency_key="call-3",
            bundle_digest="b" * 64, binding_digest="c" * 64, surface_digest="d" * 64,
            mode="PROBE", deadline=datetime.now(timezone.utc) + timedelta(seconds=30),
        ))


def test_journey_session_client_consumes_event_frames_before_result():
    session = JourneySession.create(session_id="event-session", target_id="mentorpi", profile_id="landerpi")
    sent = []
    queue = [
        ProtocolFrame.create(
            kind=FrameKind.EVENT, sequence=0, session_id=session.session_id, payload={"status": "STARTED"}
        ),
        ProtocolFrame.create(
            kind=FrameKind.RESULT, sequence=1, session_id=session.session_id, payload={"ok": True}
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
    response = client.exchange(FrameKind.BOOTSTRAP, {"session_id": session.session_id})
    assert response.kind == FrameKind.RESULT
    assert len(client.last_events) == 1
