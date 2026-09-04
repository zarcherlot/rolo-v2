from datetime import datetime, timezone

from rolo.rkb.mhs_read_models import (
    MhsManifestReference,
    MhsReadOnlyResult,
    MhsReferenceCandidate,
    build_probe_evidence_view,
    project_mhs_read_result,
    project_probe_evidence_view,
)

NOW = datetime(2026, 9, 3, tzinfo=timezone.utc)


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


def test_probe_evidence_view_keeps_provisional_and_unavailable_states_visible() -> None:
    view = build_probe_evidence_view(
        target_fingerprint="a" * 64,
        references=[
            MhsReferenceCandidate(
                candidate_id="ref-1",
                target_fingerprint="a" * 64,
                authority="PROVISIONAL",
                status="MHS_PROVISIONAL_FIXTURE",
                observed_at=NOW,
            )
        ],
        manifests=[
            MhsManifestReference(
                manifest_id="manifest-1",
                target_fingerprint="a" * 64,
                authority="PROVISIONAL",
                status="MHS_MANIFEST_UNAVAILABLE",
            )
        ],
        read_results=[
            MhsReadOnlyResult(
                device_id="device-1",
                status="UNAVAILABLE",
                access="READ_ONLY",
                observed_at=NOW,
            )
        ],
    )

    assert view.freshness == "UNKNOWN"
    assert view.mhs_references[0].authority == "PROVISIONAL"
    assert view.manifests[0].status == "MHS_MANIFEST_UNAVAILABLE"
    assert view.read_results[0].status == "UNAVAILABLE"
    assert view.write_operations == 0


def test_probe_evidence_view_only_becomes_fresh_when_everything_is_confirmed() -> None:
    view = build_probe_evidence_view(
        target_fingerprint="a" * 64,
        references=[
            MhsReferenceCandidate(
                candidate_id="ref-2",
                target_fingerprint="a" * 64,
                authority="OBSERVED",
                status="MHS_PROVIDER_READ_ONLY_CONFIRMED",
                observed_at=NOW,
            )
        ],
        manifests=[
            MhsManifestReference(
                manifest_id="manifest-2",
                target_fingerprint="a" * 64,
                authority="OBSERVED",
                available=True,
                verified=True,
                status="MHS_MANIFEST_AVAILABLE",
            )
        ],
        read_results=[
            MhsReadOnlyResult(
                device_id="device-2",
                status="AVAILABLE",
                access="READ_ONLY",
                observed_at=NOW,
            )
        ],
    )

    assert view.freshness == "FRESH"
