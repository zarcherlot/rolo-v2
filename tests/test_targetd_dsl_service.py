from rolo.dsl.canonical import context_digest, dsl_digest
from rolo.dsl.parser import parse_document
from rolo.targetd import DslFrame, TargetdDslService


def values():
    dsl = {"tool_id": "x", "kind": "OBSERVE", "target": {"robot_id": "r", "evidence_digest": "sha256:e"}, "binding": {"resource_id": "route:/state"}}
    context = {"robot_id": "r", "target_fingerprint": "fp", "evidence_digest": "sha256:e", "evidence_refs": ["route:/state"]}
    doc, _ = parse_document(dsl)
    return dsl, context, dsl_digest(doc), context_digest(context)


def test_targetd_put_check_compile_and_cache(tmp_path):
    dsl, context, dd, cd = values()
    service = TargetdDslService(tmp_path)
    put = DslFrame(
        frame_type="DSL_PUT", request_id="1", payload={"dsl": dsl, "context": context, "compiler_version": "rolo-compiler/0.1", "dsl_digest": dd, "context_digest": cd, "target_fingerprint": "fp"}
    )
    assert service.handle(put).payload["phase"] == "PUT"
    assert service.handle(DslFrame(frame_type="DSL_CHECK", request_id="2", payload={"dsl_digest": dd})).payload["status"] == "PASS"
    compile_frame = DslFrame(frame_type="DSL_COMPILE", request_id="3", payload={"dsl_digest": dd, "context_digest": cd, "target_fingerprint": "fp"})
    first = service.handle(compile_frame)
    second = service.handle(DslFrame(frame_type="DSL_COMPILE", request_id="4", payload=compile_frame.payload))
    assert first.payload["status"] == "PASS" and first.payload["cache_hit"] is False
    assert second.payload["cache_hit"] is True
