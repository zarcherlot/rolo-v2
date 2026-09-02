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
from rolo.mhs_hardware import MhsCommandDescriptor


def test_landerpi_bundle_covers_sensor_controller_and_actuator() -> None:
    bundle = landerpi_mhs_bundle()
    classes = {item.manifest.device_class.value for item in bundle.devices}
    assert classes == {"sensor", "controller", "actuator"}
    assert all(item.status == MhsBindingStatus.DISCOVERED_UNVERIFIED for item in bundle.devices)
    assert all(not item.manifest.commands for item in bundle.devices)
    assert bundle.devices[0].manifest.serial == "HY400516001016421G00082"
    assert bundle.devices[0].manifest.driver_sha256 != "0" * 64


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
