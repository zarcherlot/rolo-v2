import ast
import json
import re
from datetime import datetime, timedelta, timezone

import pytest

import rolo.targetd.worker as worker_module
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
from rolo.targetd.protocol import ProtocolError
from rolo.targetd.worker import PythonBundleWorker, RosContainerProvider


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


def test_decode_frame_rejects_duplicate_json_members():
    payload = (
        b'{"frame_digest":"' + b"0" * 64
        + b'","frame_digest":"' + b"1" * 64 + b'"}'
    )
    encoded = len(payload).to_bytes(4, "big") + payload
    with pytest.raises(ProtocolError, match="payload is invalid"):
        decode_frame(encoded)


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


def test_state_store_rejects_duplicate_json_members_as_protocol_error(tmp_path):
    store = TargetdStateStore(tmp_path / "run")
    store.path.parent.mkdir(parents=True)
    store.path.write_text('{"sessions": {}, "sessions": {}}\n', encoding="utf-8")
    with pytest.raises(ProtocolError, match="state is unreadable"):
        store.load_receipt("missing")


@pytest.mark.parametrize("field", ["sessions", "calls"])
def test_state_store_rejects_non_mapping_collections(field, tmp_path):
    store = TargetdStateStore(tmp_path / "run")
    store.path.parent.mkdir(parents=True)
    store.path.write_text(json.dumps({field: []}), encoding="utf-8")
    with pytest.raises(ProtocolError, match="state is unreadable"):
        store.load_receipt("missing")


def test_targetd_health_is_unavailable_when_persisted_state_is_corrupt(tmp_path):
    service = TargetdService(target_id="mentorpi", state_root=tmp_path / "state")
    service.state.path.parent.mkdir(parents=True)
    service.state.path.write_text('{"sessions": "not-a-map"}\n', encoding="utf-8")
    assert service.health().status == "UNAVAILABLE"


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
    with pytest.raises(ProtocolError, match="binding does not match"):
        service.accept_call(
            request.model_copy(
                update={"idempotency_key": "call-binding-mismatch", "binding_digest": "c" * 64}
            ),
            manifest,
        )
    assert service.cancel_call("call-2").status == "CANCELLED"
    assert service.query_call("call-2").status == "CANCELLED"


def test_targetd_service_treats_not_accepted_as_terminal(tmp_path):
    service = TargetdService(target_id="mentorpi", state_root=tmp_path / "state")
    session = service.open_session(
        JourneySession.create(session_id="session-not-accepted", target_id="mentorpi", profile_id="landerpi")
    )
    manifest = ExecutionBundleManifest.build(
        tool_id="app.generic",
        source=b"def execute(arguments): return arguments",
        binding_digest="a" * 64,
        signer_key_id="rolo-dev",
        signing_key=b"secret",
    )
    service.put_bundle(manifest, b"def execute(arguments): return arguments")
    request = ExecutionRequest(
        run_id="run-not-accepted",
        session_id=session.session_id,
        target_id="mentorpi",
        idempotency_key="call-not-accepted",
        bundle_digest=manifest.bundle_digest,
        binding_digest=manifest.binding_digest,
        surface_digest="b" * 64,
        arguments={},
        mode="SUPERVISED_FIELD_DEBUG",
        deadline=datetime.now(timezone.utc) + timedelta(seconds=30),
    )
    assert service.accept_call(request, manifest).status == "ACCEPTED"
    rejected = service.complete_call(request.idempotency_key, status="NOT_ACCEPTED")
    assert rejected.status == "NOT_ACCEPTED"
    assert service.complete_call(request.idempotency_key, status="SUCCEEDED") == rejected


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
                "surface_digest": "b" * 64,
            },
        )
    )
    assert response.payload["ok"] is False
    assert "surface digest conflicts" in response.payload["error"]


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


def test_targetd_daemon_terminalizes_unexpected_worker_exception(tmp_path):
    source = b"def execute(arguments): return arguments\n"
    service = TargetdService(target_id="mentorpi", state_root=tmp_path / "state")
    session = service.open_session(
        JourneySession.create(session_id="worker-failure", target_id="mentorpi", profile_id="landerpi")
    )
    manifest = ExecutionBundleManifest.build(
        tool_id="app.generic", source=source, binding_digest="a" * 64,
        signer_key_id="rolo-dev", signing_key=b"secret",
    )
    service.put_bundle(manifest, source)
    request = ExecutionRequest(
        run_id="worker-failure-run",
        session_id=session.session_id,
        target_id="mentorpi",
        idempotency_key="worker-failure-call",
        bundle_digest=manifest.bundle_digest,
        binding_digest="a" * 64,
        surface_digest="b" * 64,
        mode="SUPERVISED_FIELD_DEBUG",
        deadline=datetime.now(timezone.utc) + timedelta(seconds=30),
    )
    daemon = TargetdDaemon(service, execute_calls=True)
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
    assert response.payload["receipt"]["status"] == "FAILED"
    assert service.query_call(request.idempotency_key).status == "FAILED"


def test_targetd_daemon_blocks_rotation_without_physical_provider(tmp_path):
    source = b"def execute(arguments): return {'status': 'SUCCEEDED'}\n"
    service = TargetdService(target_id="mentorpi", state_root=tmp_path / "state")
    session = service.open_session(
        JourneySession.create(session_id="rotation-provider", target_id="mentorpi", profile_id="landerpi")
    )
    manifest = ExecutionBundleManifest.build(
        tool_id="app.base.rotate", source=source, binding_digest="a" * 64,
        signer_key_id="rolo-dev", signing_key=b"secret",
    )
    service.put_bundle(manifest, source)
    request = ExecutionRequest(
        run_id="rotation-provider-run",
        session_id=session.session_id,
        target_id="mentorpi",
        idempotency_key="rotation-provider-call",
        bundle_digest=manifest.bundle_digest,
        binding_digest=manifest.binding_digest,
        surface_digest="b" * 64,
        mode="SUPERVISED_FIELD_DEBUG",
        deadline=datetime.now(timezone.utc) + timedelta(seconds=30),
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
    assert response.payload["ok"] is True
    assert response.payload["receipt"]["status"] == "FAILED"
    assert response.payload["receipt"]["result"]["error"] == "rotation provider is required"


def test_targetd_rotation_receipt_fails_closed_without_physical_evidence(tmp_path):
    source = b"def execute(arguments): return arguments\n"
    manifest = ExecutionBundleManifest.build(
        tool_id="app.base.rotate", source=source, binding_digest="a" * 64,
        signer_key_id="rolo-dev", signing_key=b"secret",
    )
    verified = _verified_rotation_result()
    weak = {"status": "SUCCEEDED", "stop_published": True, "stopped_observed": True}
    assert TargetdDaemon._terminal_status(manifest, verified) == "SUCCEEDED"
    assert TargetdDaemon._terminal_status(manifest, weak) == "UNKNOWN"
    assert TargetdDaemon._terminal_status(
        manifest, {"status": "BLOCKED", "error": "NO_LIVE_INDEPENDENT_IMU"}
    ) == "FAILED"


def test_targetd_rotation_receipt_rejects_motion_witness_without_exact_angle(tmp_path):
    source = b"def execute(arguments): return arguments\n"
    manifest = ExecutionBundleManifest.build(
        tool_id="app.base.rotate", source=source, binding_digest="a" * 64,
        signer_key_id="rolo-dev", signing_key=b"secret",
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
        tool_id="app.generic", source=b"def execute(arguments): return arguments\n",
        binding_digest="a" * 64, signer_key_id="rolo-dev", signing_key=b"secret",
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
        manifest, source, {"angle_degrees": 15, "max_speed_rad_s": 0.15}
    )
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
        tool_id="app.base.rotate", source=source, binding_digest="a" * 64,
        signer_key_id="rolo-dev", signing_key=b"secret",
    )
    PythonBundleWorker(Provider()).execute(
        manifest, source, {"angle_degrees": 1, "max_speed_rad_s": 0.1}
    )
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
        PythonBundleWorker(RosContainerProvider("MentorPi")).execute(
            manifest, source, {"angle_degrees": 1, "max_speed_rad_s": 0.1}
        )


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
    result = PythonBundleWorker(RosContainerProvider("MentorPi")).execute(
        manifest, source, {"status_window_s": 2}
    )
    assert result["status"] == "SUCCEEDED"
    assert "--mode\",\"status" in seen["input"]


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
        PythonBundleWorker(RosContainerProvider("MentorPi")).execute(
            manifest, source, {}
        )


def test_ros_container_provider_uses_fixed_docker_argv(monkeypatch):
    seen = {}

    def fake_run(command, **kwargs):
        seen["command"] = command
        seen["input"] = kwargs["input"]
        return type("Completed", (), {"returncode": 0, "stdout": '{"stop_published":true}\n', "stderr": ""})()

    monkeypatch.setattr("rolo.targetd.worker.subprocess.run", fake_run)
    result = RosContainerProvider("MentorPi").invoke(
        "base.rotate", {"angle_degrees": 15, "max_speed_rad_s": 0.15}
    )
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
        RosContainerProvider("MentorPi").invoke(
            "base.rotate", {"angle_degrees": 15, "max_speed_rad_s": 0.15}
        )


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
def test_ros_container_provider_mapping_operations_have_fixed_modes(
    monkeypatch, operation, arguments, mode
):
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
                ) + "\n",
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
