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


def test_mhs_api_validates_manifest_registry_records_before_publish() -> None:
    api = MhsEvidenceReadApi()
    with pytest.raises(ValueError, match="canonical_route"):
        api.publish_parts(
            target_fingerprint="a" * 64,
            manifests=[
                {
                    "manifest_id": "manifest-1",
                    "target_fingerprint": "a" * 64,
                    "status": "MHS_MANIFEST_AVAILABLE",
                    "available": True,
                    "verified": True,
                    "canonical_route": "not-mhs-route",
                }
            ],
        )


def test_mhs_api_validates_provider_read_results_before_publish() -> None:
    api = MhsEvidenceReadApi()
    with pytest.raises(ValueError, match="unsupported MHS operation"):
        api.publish_parts(
            target_fingerprint="a" * 64,
            read_results=[
                {
                    "device_id": "sensor-1",
                    "operation": "write",
                    "route": "mhs://sensor-1/read",
                    "status": "AVAILABLE",
                    "access": "READ_ONLY",
                }
            ],
        )
