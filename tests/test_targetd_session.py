from pathlib import Path

from rolo.dsl.canonical import context_digest, dsl_digest
from rolo.dsl.parser import parse_document
from rolo.targetd import DslFrame, FrameCodec, InMemoryTargetdTransport, TargetdDslService, TargetdSession


def values():
    dsl = {"tool_id": "x", "kind": "OBSERVE", "target": {"robot_id": "r", "evidence_digest": "sha256:e"}, "binding": {"resource_id": "route:/state"}}
    context = {"robot_id": "r", "target_fingerprint": "fp", "evidence_digest": "sha256:e", "evidence_refs": ["route:/state"]}
    doc, _ = parse_document(dsl)
    return dsl, context, dsl_digest(doc), context_digest(context)


def test_jsonl_codec_roundtrip():
    frame = DslFrame(frame_type="DSL_CHECK", request_id="1", payload={"dsl_digest": "sha256:x"})
    assert FrameCodec.decode(FrameCodec.encode(frame)) == frame


def test_session_runs_targetd_pipeline(tmp_path: Path):
    dsl, context, dd, cd = values()
    session = TargetdSession(InMemoryTargetdTransport(TargetdDslService(tmp_path)))
    put = DslFrame(
        frame_type="DSL_PUT", request_id="1", payload={"dsl": dsl, "context": context, "compiler_version": "rolo-compiler/0.1", "dsl_digest": dd, "context_digest": cd, "target_fingerprint": "fp"}
    )
    session.request(put)
    result = session.request(DslFrame(frame_type="DSL_COMPILE", request_id="2", payload={"dsl_digest": dd, "context_digest": cd, "target_fingerprint": "fp"}))
    assert result.payload["status"] == "PASS"


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
