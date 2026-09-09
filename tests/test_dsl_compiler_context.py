from rolo.dsl.compiler import compile_text


def test_compile_with_context_blocks_unobserved_resource(tmp_path, mapping_confirmation_factory):
    dsl = {"tool_id": "app.x", "kind": "OBSERVE", "target": {"robot_id": "r", "evidence_digest": "sha256:" + "e" * 64}, "binding": {"resource_id": "route:fake"}}
    context = {"robot_id": "r", "evidence_digest": "sha256:" + "e" * 64, "target_fingerprint": "fp", "evidence_refs": []}
    confirmed = mapping_confirmation_factory(dsl, context)
    result = compile_text(
        dsl,
        tmp_path / "compile",
        context,
        **confirmed.compiler_kwargs,
    )
    assert not result.ok
    assert result.report.diagnostics[0].code == "RESOURCE_NOT_OBSERVED"
