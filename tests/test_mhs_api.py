import pytest

from rolo.rkb.mhs_api import MhsEvidenceReadApi


def test_mhs_api_publishes_and_reads_target_bound_view() -> None:
    api = MhsEvidenceReadApi()
    view = api.publish_parts(target_fingerprint="a" * 64)
    assert api.get("a" * 64) == view
    assert api.list_targets() == ["a" * 64]
    assert view.access == "READ_ONLY"
    assert view.write_operations == 0


def test_mhs_api_rejects_non_read_only_payload() -> None:
    api = MhsEvidenceReadApi()
    with pytest.raises(ValueError):
        api.publish(
            {
                "schema_version": "rolo-probe-evidence-view/v1",
                "target_fingerprint": "a" * 64,
                "mhs_references": [],
                "manifests": [],
                "read_results": [],
                "access": "WRITE",
                "write_operations": 1,
            }
        )
