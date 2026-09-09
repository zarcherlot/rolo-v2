from dataclasses import replace

from rolo.dsl.compiler import compile_text
from rolo.dsl.conformance import conformance


def test_bundle_ir_digest_is_verified(tmp_path, mapping_confirmation_factory):
    dsl = {"tool_id": "app.x", "kind": "INVOKE", "target": {"robot_id": "r", "evidence_digest": "sha256:" + "e" * 64}, "binding": {"operation": "ping"}}
    context = {"robot_id": "r", "target_fingerprint": "fp", "evidence_digest": "sha256:" + "e" * 64}
    confirmed = mapping_confirmation_factory(dsl, context)
    result = compile_text(
        dsl,
        tmp_path / "compile",
        context,
        **confirmed.compiler_kwargs,
    )
    assert conformance(result).ok
    result.bundle = replace(result.bundle, manifest=result.bundle.manifest.model_copy(update={"ir_digest": "sha256:" + "0" * 64}))
    assert not conformance(result).ok
