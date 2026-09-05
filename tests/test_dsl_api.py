from rolo.dsl.api import DslCompileRequest, DslCompileResult, DslCheckRequest

def test_compile_request_carries_replay_identity():
    request = DslCompileRequest(dsl={"tool_id": "x"}, dsl_digest="sha256:d", context_digest="sha256:c", target_fingerprint="fp")
    assert request.compiler_version == "rolo-compiler/0.1"
    assert request.target_fingerprint == "fp"
def test_compile_result_can_be_serialized():
    result = DslCompileResult(status="PASS", dsl_digest="sha256:d")
    assert result.model_dump()["status"] == "PASS"
