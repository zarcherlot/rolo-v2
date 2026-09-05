from rolo.dsl.api import DslCompileRequest
from rolo.dsl.canonical import context_digest, dsl_digest
from rolo.dsl.service import RoloDslCompiler


def test_service_rejects_dsl_digest_mismatch(tmp_path):
    dsl = {"tool_id": "x", "kind": "OBSERVE", "target": {"robot_id": "r", "evidence_digest": "sha256:e"}, "binding": {"resource_id": "route:/state"}}
    context = {"robot_id": "r", "evidence_digest": "sha256:e", "target_fingerprint": "fp", "evidence_refs": ["route:/state"]}
    result = RoloDslCompiler().compile(DslCompileRequest(dsl=dsl, dsl_digest="sha256:wrong", context=context, context_digest=context_digest(context), target_fingerprint="fp"), tmp_path)
    assert result.diagnostics == ("DSL_DIGEST_MISMATCH",)


def test_service_rejects_context_digest_mismatch(tmp_path):
    dsl = {"tool_id": "x", "kind": "OBSERVE", "target": {"robot_id": "r", "evidence_digest": "sha256:e"}, "binding": {"resource_id": "route:/state"}}
    context = {"robot_id": "r", "evidence_digest": "sha256:e", "target_fingerprint": "fp", "evidence_refs": ["route:/state"]}
    result = RoloDslCompiler().compile(
        DslCompileRequest(
            dsl=dsl, dsl_digest=dsl_digest(__import__("rolo.dsl.parser", fromlist=["parse_document"]).parse_document(dsl)[0]), context=context, context_digest="sha256:wrong", target_fingerprint="fp"
        ),
        tmp_path,
    )
    assert result.diagnostics == ("CONTEXT_DIGEST_MISMATCH",)
