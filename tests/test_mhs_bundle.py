from __future__ import annotations

import json
from pathlib import Path

import pytest

from rolo.mhs_bundle import (
    MhsBindingStatus,
    MhsBundle,
    MhsBundleDevice,
    MhsConfidence,
    landerpi_mhs_bundle,
)
from rolo.mhs_hardware import (
    MhsCommandDescriptor,
    MhsDeviceManifest,
    MhsInterfaceSample,
    migrate_mhs_manifest_payload,
)


def test_landerpi_bundle_covers_sensor_controller_and_actuator() -> None:
    bundle = landerpi_mhs_bundle()
    classes = {item.manifest.device_class.value for item in bundle.devices}
    assert classes == {"sensor", "controller", "actuator"}
    assert all(item.status == MhsBindingStatus.DISCOVERED_UNVERIFIED for item in bundle.devices)
    assert all(not item.manifest.commands for item in bundle.devices)
    assert bundle.devices[0].manifest.serial == "HY400516001016421G00082"
    assert bundle.devices[0].manifest.driver_sha256 != "0" * 64
    assert bundle.devices[0].owner == "rolo-maintainers"
    assert bundle.devices[0].stage == "D3"
    assert bundle.devices[0].next_action
    aurora = bundle.devices[0].manifest
    assert aurora.identity.stable_id == "HY400516001016421G00082"
    assert {interface.kind for interface in aurora.interfaces} == {"image", "point_cloud"}
    assert aurora.provenance.field_status["vendor"] == "inferred"
    lidar = bundle.devices[1].manifest
    assert lidar.interfaces[0].kind == "laser_scan"
    controller = bundle.devices[2].manifest
    assert controller.relations[0].target == "landerpi-servo-actuator"


def test_bundle_round_trip_artifact() -> None:
    path = Path(__file__).parents[1] / "examples/mhs-landerpi/mhs-bundle-20260902.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    bundle = MhsBundle.model_validate(payload)
    assert bundle.schema_version == "rolo-mhs-bundle/v1"
    assert len(bundle.devices) == 4


def test_verified_requires_evidence_and_writes_are_rejected() -> None:
    base = landerpi_mhs_bundle().devices[0]
    with pytest.raises(ValueError, match="verified device requires evidence"):
        MhsBundleDevice(
            manifest=base.manifest,
            status=MhsBindingStatus.VERIFIED,
            confidence=MhsConfidence.HIGH,
        )
    with pytest.raises(ValueError, match="must not enable write commands"):
        manifest = base.manifest.model_copy(
            update={
                "commands": [
                    MhsCommandDescriptor(
                        id="capture",
                        hardware_resource_id="camera",
                        risk="R1",
                        input_schema={
                            "type": "object",
                            "properties": {},
                            "additionalProperties": False,
                        },
                        timeout_s=1,
                    )
                ]
            }
        )
        MhsBundleDevice(manifest=manifest)


def test_v1_manifest_migration_and_structured_sample() -> None:
    payload = {
        "schema_version": "rolo-mhs-device/v1",
        "device_id": "legacy-sensor",
        "device_class": "sensor",
        "name": "legacy",
        "vendor": "example",
        "model": "x",
    }
    migrated = migrate_mhs_manifest_payload(payload)
    manifest = MhsDeviceManifest.model_validate(migrated)
    assert manifest.schema_version == "rolo-mhs-device/v1.1"
    assert manifest.interfaces == []
    sample = MhsInterfaceSample(
        interface_id="depth",
        value={"width": 640, "height": 480, "data": [1, 2]},
        observed_at=landerpi_mhs_bundle().generated_at,
    )
    assert sample.value["width"] == 640
