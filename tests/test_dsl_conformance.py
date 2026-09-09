from rolo.dsl.admission import MappingConfirmationStore
from rolo.dsl.compiler import compile_text
from rolo.dsl.conformance import conformance


def test_compile_and_conformance_pass(tmp_path, mapping_confirmation_factory):
    dsl = {"tool_id": "app.x", "kind": "INVOKE", "target": {"robot_id": "r", "evidence_digest": "sha256:" + "e" * 64}, "binding": {"operation": "ping"}}
    context = {"robot_id": "r", "target_fingerprint": "fp", "evidence_digest": "sha256:" + "e" * 64}
    confirmed = mapping_confirmation_factory(dsl, context)
    result = compile_text(
        dsl,
        tmp_path / "compile",
        context,
        **confirmed.compiler_kwargs,
    )
    assert result.ok
    assert conformance(result).ok


def test_compile_invalid_dsl_is_blocked(tmp_path, mapping_confirmation_factory):
    dsl = {"tool_id": "app.x", "kind": "OBSERVE", "target": {"robot_id": "r", "evidence_digest": "sha256:" + "e" * 64}}
    context = {"robot_id": "r", "target_fingerprint": "fp", "evidence_digest": "sha256:" + "e" * 64}
    confirmed = mapping_confirmation_factory(dsl, context)
    result = compile_text(
        dsl,
        tmp_path / "compile",
        context,
        **confirmed.compiler_kwargs,
    )
    report = conformance(result)
    assert not report.ok
    assert report.diagnostics[0].code == "BINDING_REQUIRED"


def test_compile_without_target_context_is_blocked(tmp_path):
    result = compile_text(
        {"tool_id": "app.x", "kind": "INVOKE", "target": {"robot_id": "r", "evidence_digest": "sha256:" + "e" * 64}, "binding": {"operation": "ping"}},
        tmp_path / "compile",
        confirmation_store=MappingConfirmationStore(tmp_path / "admission"),
        confirmation_receipt_digest="sha256:" + "0" * 64,
        journey_session_id="journey-missing-context",
    )
    assert not result.ok
    assert result.report.diagnostics[0].code == "TARGET_FINGERPRINT_REQUIRED"
