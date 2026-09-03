from rolo.rkb.mhs_read_models import project_mhs_read_result, project_probe_evidence_view


def test_rkb_projection_preserves_unavailable_and_read_only() -> None:
    result = project_mhs_read_result(
        {"status": "UNAVAILABLE", "reason": "manifest missing", "access": "READ_ONLY"}
    )
    assert result.status == "UNAVAILABLE"
    assert result.status_reason == "manifest missing"


def test_probe_evidence_view_has_no_write_surface() -> None:
    view = project_probe_evidence_view(target_fingerprint="a" * 64)
    assert view["access"] == "READ_ONLY"
    assert view["write_operations"] == 0
