import pytest

from rolo.agent_tools.mhs_association import AssociationReport, validate_association_payload


def test_association_report_is_proposed_only_with_evidence() -> None:
    report = AssociationReport(
        target_fingerprint="a" * 64,
        status="PROPOSED",
        evidence_refs=["probe:e1"],
        route="ros2:///scan",
    )
    assert report.access == "READ_ONLY"
    assert report.write_requests == 0


def test_association_report_rejects_write_request_and_unknown_fields() -> None:
    with pytest.raises(ValueError, match="write requests"):
        AssociationReport(target_fingerprint="a" * 64, status="UNKNOWN", write_requests=1)
    with pytest.raises(ValueError):
        validate_association_payload(
            {"target_fingerprint": "a" * 64, "status": "UNKNOWN", "commands": ["reset"]}
        )
