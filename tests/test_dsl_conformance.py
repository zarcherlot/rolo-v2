from rolo.dsl.compiler import compile_text
from rolo.dsl.conformance import conformance


def test_compile_and_conformance_pass(tmp_path):
    result = compile_text({"tool_id": "x", "kind": "INVOKE", "target": {"robot_id": "r", "evidence_digest": "sha256:e"}, "binding": {"operation": "ping"}}, tmp_path)
    assert result.ok
    assert conformance(result).ok


def test_compile_invalid_dsl_is_blocked(tmp_path):
    result = compile_text({"tool_id": "x", "kind": "OBSERVE", "target": {"robot_id": "r", "evidence_digest": "sha256:e"}}, tmp_path)
    report = conformance(result)
    assert not report.ok
    assert report.diagnostics[0].code == "BINDING_REQUIRED"
