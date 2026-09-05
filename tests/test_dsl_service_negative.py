from rolo.dsl.api import DslCheckRequest
from rolo.dsl.service import RoloDslCompiler


def test_service_check_rejects_invalid_semantics():
    request = DslCheckRequest(dsl={"tool_id": "x", "kind": "OBSERVE", "target": {"robot_id": "r", "evidence_digest": "sha256:e"}})
    assert RoloDslCompiler().check(request).status == "DSL_CHECK_FAILED"
