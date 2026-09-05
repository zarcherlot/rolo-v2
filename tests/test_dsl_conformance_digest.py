from rolo.dsl.compiler import compile_text
from rolo.dsl.conformance import conformance

def test_bundle_ir_digest_is_verified(tmp_path):
    result = compile_text({"tool_id": "x", "kind": "INVOKE", "target": {"robot_id": "r", "evidence_digest": "sha256:e"}, "binding": {"operation": "ping"}}, tmp_path)
    assert conformance(result).ok
    result.bundle.manifest["ir_digest"] = "sha256:tampered"
    assert not conformance(result).ok
