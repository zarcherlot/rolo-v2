from rolo.dsl.models import DslDocument
from rolo.dsl.resolver import resolve_evidence


def doc():
    return DslDocument(tool_id="x", kind="OBSERVE", target={"robot_id": "r", "evidence_digest": "sha256:e"}, binding={"resource_id": "route:/state"}, evidence_refs=("route:/state",))


def test_resolver_accepts_observed_reference():
    assert resolve_evidence(doc(), {"robot_id": "r", "evidence_digest": "sha256:e", "evidence_refs": ["route:/state"]}).ok


def test_resolver_blocks_forged_reference():
    report = resolve_evidence(doc(), {"robot_id": "r", "evidence_digest": "sha256:e", "evidence_refs": []})
    assert not report.ok
    assert {item.code for item in report.diagnostics} == {"EVIDENCE_REF_NOT_FOUND", "RESOURCE_NOT_OBSERVED"}


def test_resolver_blocks_cross_target_context():
    report = resolve_evidence(doc(), {"robot_id": "other", "evidence_digest": "sha256:e", "evidence_refs": ["route:/state"]})
    assert report.diagnostics[0].code == "TARGET_MISMATCH"
