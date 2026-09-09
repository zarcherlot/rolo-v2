from rolo.dsl.compiler import compile_text
from rolo.dsl.conformance_report import report_for


def test_report_for_compile_result(tmp_path, mapping_confirmation_factory):
    value = {"tool_id": "app.x", "kind": "OBSERVE", "target": {"robot_id": "r", "evidence_digest": "sha256:" + "e" * 64}, "binding": {"resource_id": "route:/state"}}
    context = {"robot_id": "r", "evidence_digest": "sha256:" + "e" * 64, "target_fingerprint": "fp", "evidence_refs": ["route:/state"]}
    confirmed = mapping_confirmation_factory(value, context)
    report = report_for(compile_text(value, tmp_path / "compile", context, **confirmed.compiler_kwargs), context)
    assert report.passed


def test_report_for_bad_evidence_fails_c2(tmp_path, mapping_confirmation_factory):
    value = {"tool_id": "app.x", "kind": "OBSERVE", "target": {"robot_id": "r", "evidence_digest": "sha256:" + "e" * 64}, "binding": {"resource_id": "route:fake"}}
    context = {"robot_id": "r", "evidence_digest": "sha256:" + "e" * 64, "target_fingerprint": "fp", "evidence_refs": []}
    confirmed = mapping_confirmation_factory(value, context)
    report = report_for(compile_text(value, tmp_path / "compile", context, **confirmed.compiler_kwargs), context)
    assert report.c2_evidence == "FAIL"
    assert not report.passed
