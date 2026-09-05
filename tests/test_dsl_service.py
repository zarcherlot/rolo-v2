from rolo.dsl.api import DslCheckRequest, DslCompileRequest
from rolo.dsl.canonical import context_digest
from rolo.dsl.service import RoloDslCompiler


def value():
    return {"tool_id": "x", "kind": "OBSERVE", "target": {"robot_id": "r", "evidence_digest": "sha256:e"}, "binding": {"resource_id": "route:/state"}}


def context():
    return {"robot_id": "r", "evidence_digest": "sha256:e", "evidence_refs": ["route:/state"]}


def test_service_check_and_compile(tmp_path):
    service = RoloDslCompiler()
    checked = service.check(DslCheckRequest(dsl=value()))
    assert checked.status == "PASS"
    compiled = service.compile(DslCompileRequest(dsl=value(), dsl_digest=checked.dsl_digest, context=context(), context_digest=context_digest(context()), target_fingerprint="fp"), tmp_path)
    assert compiled.status == "PASS"
    assert compiled.conformance and compiled.conformance.passed
