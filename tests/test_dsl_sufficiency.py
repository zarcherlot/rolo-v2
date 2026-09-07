import pytest

from rolo.dsl.candidates import build_candidate_index
from rolo.dsl.context import ProbeContext
from rolo.dsl.sufficiency import assess_mapping_sufficiency


def _context(**updates):
    value = ProbeContext(
        robot_id="r",
        target_fingerprint="fp",
        evidence_digest="e",
        evidence_refs=("artifact://target-evidence/r-bundle.json",),
        routes=({"operation": "app.base.rotate"},),
    )
    return value.model_copy(update=updates)


def test_sufficiency_is_ready_for_observed_candidate():
    context = _context()
    report = assess_mapping_sufficiency(context, build_candidate_index(context), "rotate base")
    assert report.status == "READY"
    assert report.candidate_ids == ("app.base.rotate",)
    assert report.bounded_probe_allowed is False


def test_sufficiency_requests_bounded_probe_for_missing_intent():
    context = _context()
    report = assess_mapping_sufficiency(context, build_candidate_index(context), "build map")
    assert report.status == "NEEDS_PROBE"
    assert report.bounded_probe_allowed is True
    assert "INTENT_NOT_OBSERVED" in report.reasons


def test_sufficiency_preserves_explicit_unsupported_limitations():
    context = _context(limitations=("capability unsupported by target",))
    report = assess_mapping_sufficiency(context, build_candidate_index(context), "rotate base")
    assert report.status == "UNSUPPORTED"
    assert report.bounded_probe_allowed is False


def test_sufficiency_rejects_cross_context_index():
    context = _context()
    index = build_candidate_index(context)
    with pytest.raises(ValueError, match="CONTEXT_DIGEST_MISMATCH"):
        assess_mapping_sufficiency(context.model_copy(update={"evidence_digest": "other"}), index, "rotate")
