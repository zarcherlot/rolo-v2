from rolo.dsl.compiler import compile_text


def test_compile_with_context_blocks_unobserved_resource(tmp_path):
    result = compile_text(
        {"tool_id": "x", "kind": "OBSERVE", "target": {"robot_id": "r", "evidence_digest": "sha256:e"}, "binding": {"resource_id": "route:fake"}},
        tmp_path,
        {"robot_id": "r", "evidence_digest": "sha256:e", "evidence_refs": []},
    )
    assert not result.ok
    assert result.report.diagnostics[0].code == "RESOURCE_NOT_OBSERVED"
