import io
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from rolo.dsl.admission import MappingConfirmationStore
from rolo.dsl.canonical import context_digest, dsl_digest
from rolo.dsl.parser import parse_document
from rolo.releases import TargetConformanceReport
from rolo.targetd import (
    DslFrame,
    FrameCodec,
    FrameKind,
    InMemoryTargetdTransport,
    JourneyDslTransport,
    JourneySession,
    JourneySessionClient,
    ProtocolFrame,
    TargetdDslService,
    TargetdSession,
)
from rolo.targetd.dsl_daemon import run as run_dsl_daemon


def values():
    evidence_digest = "sha256:" + "e" * 64
    dsl = {"tool_id": "app.x", "kind": "OBSERVE", "target": {"robot_id": "r", "evidence_digest": evidence_digest}, "binding": {"resource_id": "route:/state"}}
    context = {"robot_id": "r", "target_fingerprint": "fp", "evidence_digest": evidence_digest, "evidence_refs": ["route:/state"]}
    doc, _ = parse_document(dsl)
    return dsl, context, dsl_digest(doc), context_digest(context)


def test_jsonl_codec_roundtrip():
    frame = DslFrame(frame_type="DSL_CHECK", request_id="1", payload={"dsl_digest": "sha256:x"})
    assert FrameCodec.decode(FrameCodec.encode(frame)) == frame


def test_jsonl_codec_rejects_duplicate_keys():
    with pytest.raises(ValueError, match="duplicate mapping key"):
        FrameCodec.decode('{"frame_type":"DSL_CHECK","frame_type":"DSL_PUT","request_id":"1","payload":{}}')


def test_journey_dsl_transport_uses_generic_session_envelope():
    journey = JourneySession.create(
        session_id="journey-1",
        target_id="r",
        profile_id="landerpi",
    )
    request = DslFrame(
        frame_type="DSL_CHECK",
        request_id="journey-1:check",
        payload={"dsl_digest": "sha256:x"},
    )

    class Client:
        session = journey

        def exchange(self, kind, payload):
            assert kind == FrameKind.DSL_REQUEST
            assert payload == {"frame": request.model_dump(mode="json")}
            response = DslFrame(
                frame_type="DSL_RESULT",
                request_id=request.request_id,
                payload={"status": "PASS", "dsl_digest": "sha256:x"},
            )
            return ProtocolFrame.create(
                kind=FrameKind.RESULT,
                sequence=1,
                session_id="journey-1",
                payload={"ok": True, "frame": response.model_dump(mode="json")},
            )

    response = JourneyDslTransport(Client()).request(request)
    assert response.payload["status"] == "PASS"


def test_journey_dsl_transport_binds_put_to_own_session():
    journey = JourneySession.create(
        session_id="journey-1",
        target_id="r",
        profile_id="landerpi",
    )
    seen = []

    class Client:
        session = journey

        def exchange(self, kind, payload):
            assert kind == FrameKind.DSL_REQUEST
            nested = DslFrame.model_validate(payload["frame"])
            seen.append(nested)
            result = DslFrame(
                frame_type="DSL_EVENT",
                request_id=nested.request_id,
                payload={"phase": "PUT"},
            )
            return ProtocolFrame.create(
                kind=FrameKind.RESULT,
                sequence=0,
                session_id=journey.session_id,
                payload={"ok": True, "frame": result.model_dump(mode="json")},
            )

    transport = JourneyDslTransport(Client())
    put = DslFrame(
        frame_type="DSL_PUT",
        request_id="put",
        payload={"dsl": {}, "context": {}},
    )
    assert transport.request(put).payload["phase"] == "PUT"
    assert "journey_session_id" not in put.payload
    assert seen[0].payload["journey_session_id"] == journey.session_id

    mismatched = put.model_copy(
        update={"payload": {**put.payload, "journey_session_id": "another-journey"}}
    )
    with pytest.raises(ValueError, match="journey does not match"):
        transport.request(mismatched)
    assert len(seen) == 1


def test_one_journey_channel_carries_dsl_and_generic_call():
    session = JourneySession.create(session_id="journey-1", target_id="r", profile_id="landerpi")

    class Channel:
        def __init__(self):
            self.sent = []
            self.responses = []
            self.response_sequence = 0

        def send(self, frame):
            self.sent.append(frame)
            payload = {"request_kind": frame.kind.value, "ok": True}
            if frame.kind == FrameKind.DSL_REQUEST:
                nested = DslFrame.model_validate(frame.payload["frame"])
                payload["frame"] = DslFrame(
                    frame_type="DSL_RESULT",
                    request_id=nested.request_id,
                    payload={"status": "PASS", "dsl_digest": "sha256:x"},
                ).model_dump(mode="json")
            self.responses.append(
                ProtocolFrame.create(
                    kind=FrameKind.RESULT,
                    sequence=self.response_sequence,
                    session_id=frame.session_id,
                    run_id=frame.run_id,
                    payload=payload,
                )
            )
            self.response_sequence += 1

        def receive(self):
            return self.responses.pop(0)

        def close(self):
            return None

    channel = Channel()
    client = JourneySessionClient(channel, session)
    assert client.exchange(
        FrameKind.OPEN_JOURNEY,
        {"target_id": "r", "profile_id": "landerpi"},
    ).payload["ok"]
    dsl_result = JourneyDslTransport(client).request(
        DslFrame(
            frame_type="DSL_CHECK",
            request_id="journey-1:check",
            payload={"dsl_digest": "sha256:x"},
        )
    )
    assert dsl_result.payload["status"] == "PASS"
    assert client.exchange(FrameKind.CALL, {"marker": "generic-call"}).payload["ok"]
    assert [frame.kind for frame in channel.sent] == [
        FrameKind.OPEN_JOURNEY,
        FrameKind.DSL_REQUEST,
        FrameKind.CALL,
    ]


def test_dsl_daemon_rejects_duplicate_frame_keys(tmp_path: Path):
    line = '{"frame_type":"DSL_CHECK","frame_type":"DSL_PUT","request_id":"1","payload":{}}\n'
    output = io.StringIO()
    assert run_dsl_daemon(io.StringIO(line), output, str(tmp_path)) == 0
    response = json.loads(output.getvalue())
    assert response["payload"] == {
        "code": "FRAME_INVALID",
        "message": "invalid DSL frame",
    }
    assert "duplicate mapping key" not in output.getvalue()


def test_dsl_daemon_validation_error_does_not_echo_input_value(tmp_path: Path):
    canary = "secret-token-must-not-appear"
    line = json.dumps(
        {
            "frame_type": "DSL_CHECK",
            "request_id": {"token": canary},
            "payload": {},
        }
    )
    output = io.StringIO()

    assert run_dsl_daemon(io.StringIO(line + "\n"), output, str(tmp_path)) == 0
    response = json.loads(output.getvalue())
    assert response == {
        "frame_type": "DSL_EVENT",
        "request_id": "unknown",
        "payload": {
            "code": "FRAME_INVALID",
            "message": "invalid DSL frame",
        },
    }
    assert canary not in output.getvalue()


def test_dsl_daemon_uses_explicit_admission_store(tmp_path: Path, mapping_confirmation_factory):
    dsl, context, dd, cd = values()
    confirmed = mapping_confirmation_factory(dsl, context)
    daemon_store = MappingConfirmationStore(tmp_path / "daemon-admission")
    daemon_receipt = daemon_store.confirm(
        confirmed.receipt.admission_identity(),
        decision_id="daemon-decision",
        actor_id="test-operator",
        ttl_s=900,
    )
    frames = (
        DslFrame(
            frame_type="DSL_PUT",
            request_id="put",
            payload={
                "journey_session_id": "journey-1",
                "dsl": dsl,
                "context": context,
                "compiler_version": "rolo-compiler/0.1",
                "dsl_digest": dd,
                "context_digest": cd,
                "target_fingerprint": "fp",
            },
        ),
        DslFrame(
            frame_type="DSL_COMPILE",
            request_id="compile",
            payload={
                "schema_version": "rolo-targetd-dsl-compile/v2",
                "journey_session_id": "journey-1",
                "confirmation_receipt_digest": daemon_receipt.receipt_digest,
                "dsl_digest": dd,
                "context_digest": cd,
                "target_fingerprint": "fp",
            },
        ),
    )
    stdin = io.StringIO(b"".join(FrameCodec.encode(frame) for frame in frames).decode("utf-8"))

    class ProtocolOutput:
        def __init__(self):
            self.buffer = io.BytesIO()

        def write(self, value: str) -> int:
            return self.buffer.write(value.encode("utf-8"))

        def flush(self) -> None:
            return None

    output = ProtocolOutput()
    assert (
        run_dsl_daemon(
            stdin,
            output,
            str(tmp_path / "cache"),
            admission_store=daemon_store.root,
        )
        == 0
    )
    responses = [FrameCodec.decode(line) for line in output.buffer.getvalue().splitlines(keepends=True)]
    assert responses[-1].payload["status"] == "PASS"
    assert responses[-1].payload["confirmation_receipt_digest"] == daemon_receipt.receipt_digest


def test_target_conformance_requires_v3_complete_identity_and_proofs():
    gates = {
        "t1_target_resolve": "PASS",
        "t2_bundle_build": "PASS",
        "t3_runtime_behavior": "PASS",
        "t4_release_integrity": "PASS",
        "target_fingerprint": "fp",
    }
    with pytest.raises(ValidationError):
        TargetConformanceReport.model_validate(gates)
    with pytest.raises(ValidationError):
        TargetConformanceReport.model_validate(
            {
                **gates,
                "schema_version": "rolo-target-conformance/v1",
                "journey_session_id": "journey-1",
                "confirmation_receipt_digest": "sha256:" + "1" * 64,
            }
        )
    complete = {
        **gates,
        "schema_version": "rolo-target-conformance/v3",
        "tool_id": "app.state",
        "operation_kind": "OBSERVE",
        "target_id": "r",
        "target_identity_digest": "sha256:" + "0" * 64,
        "evidence_digest": "sha256:" + "2" * 64,
        "dsl_digest": "sha256:" + "3" * 64,
        "context_digest": "sha256:" + "4" * 64,
        "ir_digest": "sha256:" + "5" * 64,
        "bundle_digest": "sha256:" + "6" * 64,
        "compile_artifact_digest": "sha256:" + "7" * 64,
        "compiler_version": "rolo-compiler/0.1",
        "compiler_backend_id": "ros2_observe",
        "compiler_backend_version": "rolo-backend-spi/v2",
        "runtime_backend_id": "ros2_runtime",
        "runtime_binding_digest": "sha256:" + "8" * 64,
        "runtime_result_digest": "sha256:" + "9" * 64,
        "required_capabilities": ["read_only_topic"],
        "required_runtime_capabilities": ["read_only_topic", "ros2"],
        "negotiated_capabilities": ["operation:OBSERVE"],
        "journey_session_id": "journey-1",
        "confirmation_receipt_digest": "sha256:" + "1" * 64,
        "conformance_idempotency_key": "sha256:" + "a" * 64,
        "proofs": [
            {
                "gate": f"T{index}",
                "status": "PASS",
                "evidence_ref": f"target-conformance/t{index}-proof.json",
                "evidence_digest": "sha256:" + str(index) * 64,
            }
            for index in range(1, 5)
        ],
        "diagnostics": [],
    }
    report = TargetConformanceReport.model_validate(complete)
    assert report.schema_version == "rolo-target-conformance/v3"
    with pytest.raises(ValidationError):
        TargetConformanceReport.model_validate({**complete, "dsl_digest": "sha256:" + "f" * 63})


def test_session_runs_targetd_pipeline(tmp_path: Path, mapping_confirmation_factory):
    dsl, context, dd, cd = values()
    confirmed = mapping_confirmation_factory(dsl, context, journey_session_id="journey-1")
    session = TargetdSession(InMemoryTargetdTransport(TargetdDslService(tmp_path, confirmation_store=confirmed.store)))
    put = DslFrame(
        frame_type="DSL_PUT",
        request_id="1",
        payload={
            "journey_session_id": "journey-1",
            "dsl": dsl,
            "context": context,
            "compiler_version": "rolo-compiler/0.1",
            "dsl_digest": dd,
            "context_digest": cd,
            "target_fingerprint": "fp",
        },
    )
    session.request(put)
    check = session.request(
        DslFrame(
            frame_type="DSL_CHECK",
            request_id="check",
            payload={"dsl_digest": dd},
        )
    )
    assert check.payload["status"] == "PASS"
    result = session.request(
        DslFrame(
            frame_type="DSL_COMPILE",
            request_id="2",
            payload={
                "schema_version": "rolo-targetd-dsl-compile/v2",
                "journey_session_id": "journey-1",
                "confirmation_receipt_digest": confirmed.receipt.receipt_digest,
                "dsl_digest": dd,
                "context_digest": cd,
                "target_fingerprint": "fp",
            },
        )
    )
    assert result.payload["status"] == "PASS"


def test_session_allows_preconfirmation_put_and_check_but_blocks_compile(tmp_path: Path):
    dsl, context, dd, cd = values()
    session = TargetdSession(InMemoryTargetdTransport(TargetdDslService(tmp_path)))
    put = DslFrame(
        frame_type="DSL_PUT",
        request_id="put",
        payload={
            "journey_session_id": "journey-1",
            "dsl": dsl,
            "context": context,
            "compiler_version": "rolo-compiler/0.1",
            "dsl_digest": dd,
            "context_digest": cd,
            "target_fingerprint": "fp",
        },
    )
    assert session.request(put).payload["phase"] == "PUT"
    checked = session.request(
        DslFrame(
            frame_type="DSL_CHECK",
            request_id="check",
            payload={"dsl_digest": dd},
        )
    )
    assert checked.payload["status"] == "PASS"
    blocked = session.request(
        DslFrame(
            frame_type="DSL_COMPILE",
            request_id="compile",
            payload={
                "schema_version": "rolo-targetd-dsl-compile/v2",
                "journey_session_id": "journey-1",
                "confirmation_receipt_digest": "sha256:" + "1" * 64,
                "dsl_digest": dd,
                "context_digest": cd,
                "target_fingerprint": "fp",
            },
        )
    )
    assert blocked.payload["status"] == "BLOCKED"
    assert blocked.payload["diagnostics"] == ["MAPPING_CONFIRMATION_STORE_REQUIRED"]


def test_session_reports_disconnect(tmp_path: Path):
    transport = InMemoryTargetdTransport(TargetdDslService(tmp_path))
    session = TargetdSession(transport)
    transport.connected = False
    try:
        session.request(DslFrame(frame_type="DSL_CHECK", request_id="1", payload={}))
    except ConnectionError as exc:
        assert str(exc) == "TARGETD_SESSION_DISCONNECTED"
    else:
        raise AssertionError("disconnect must be surfaced")
