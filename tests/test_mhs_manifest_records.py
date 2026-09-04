from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from rolo.mhs_hardware import MhsChannel, MhsDeviceClass, MhsDeviceManifest, MhsDeviceProvider
from rolo.mhs_manifest_records import (
    MhsAuthority,
    MhsManifestReference,
    MhsReadOnly,
    MhsReferenceCandidate,
    MhsSourceKind,
    project_read_only_result,
    resolve_manifest_reference,
)

NOW = datetime(2026, 9, 3, 12, 0, tzinfo=timezone.utc)
FINGERPRINT = "a" * 64


def _manifest() -> dict[str, object]:
    return {
        "device_id": "sensor-1",
        "device_class": "sensor",
        "name": "temperature",
        "vendor": "example",
        "model": "t-1",
        "channels": [{"id": "temperature", "name": "Temperature", "unit": "degC"}],
        "transport": {"kind": "fake"},
        "driver_sha256": "1" * 64,
    }


def _provider() -> MhsDeviceProvider:
    manifest = MhsDeviceManifest(
        device_id="sensor-1",
        device_class=MhsDeviceClass.SENSOR,
        name="temperature",
        vendor="example",
        model="t-1",
        channels=[MhsChannel(id="temperature", name="Temperature", unit="degC")],
        transport={"kind": "fake"},
    )

    class Backend:
        def read(self):
            return {"temperature": 21.5}

        def status(self):
            return {"health": "OK"}

    return MhsDeviceProvider(manifest, Backend())


def test_manifest_reference_fails_closed_without_vendor_manifest() -> None:
    record = resolve_manifest_reference(
        None,
        target_fingerprint=FINGERPRINT,
        manifest_id="manifest-1",
    )

    assert record.status == "MHS_MANIFEST_UNAVAILABLE"
    assert not record.available
    assert not record.verified
    assert "vendor manifest unavailable" in record.limitations


def test_manifest_reference_projects_verified_vendor_manifest() -> None:
    record = resolve_manifest_reference(
        _manifest(),
        target_fingerprint=FINGERPRINT,
        manifest_id="manifest-1",
        canonical_route="mhs://sensor-1/read",
        source_ref="file://vendor/sensor-1.json",
        expected_driver_sha256="1" * 64,
    )

    assert record.status == "MHS_MANIFEST_AVAILABLE"
    assert record.available
    assert record.verified
    assert record.canonical_route == "mhs://sensor-1/read"
    assert len(record.computed_digest()) == 64


def test_manifest_reference_rejects_unknown_fields() -> None:
    with pytest.raises(ValidationError):
        MhsManifestReference.model_validate(
            {
                "schema_version": "rolo-mhs-manifest-reference/v1",
                "manifest_id": "manifest-1",
                "target_fingerprint": FINGERPRINT,
                "status": "MHS_MANIFEST_AVAILABLE",
                "access": "READ_ONLY",
                "unexpected": True,
            }
        )


def test_reference_candidate_remains_provisional_for_fixtures() -> None:
    with pytest.raises(ValueError, match="provisional"):
        MhsReferenceCandidate(
            candidate_id="candidate-1",
            target_fingerprint=FINGERPRINT,
            source_kind=MhsSourceKind.TEST_FIXTURE,
            authority=MhsAuthority.VENDOR,
        )


def test_project_read_only_result_preserves_canonical_route_and_access() -> None:
    provider = _provider()
    result = provider.read()
    view = project_read_only_result(result, target_fingerprint=FINGERPRINT)

    assert isinstance(view, MhsReadOnly)
    assert view.access == "READ_ONLY"
    assert view.route == result.route
    assert view.status == "AVAILABLE"
