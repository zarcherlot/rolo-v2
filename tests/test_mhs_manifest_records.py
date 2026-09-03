from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

from rolo.mhs_manifest_records import MhsManifestRecord


ROOT = Path(__file__).parents[1]
MODULE_PATH = ROOT / "examples" / "mhs-landerpi" / "mhs_manifests.py"
SPEC = importlib.util.spec_from_file_location("landerpi_mhs_manifests", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def test_landerpi_has_one_identity_confirmed_read_only_manifest() -> None:
    records = MODULE.build_recorded_manifest_records()
    confirmed = [item for item in records if item.confirmation_status == "CONFIRMED_READ_ONLY"]
    assert len(confirmed) == 1
    record = confirmed[0]
    assert record.manifest.device_id == "landerpi-rrc"
    assert record.manifest.serial == "5B22016029"
    assert record.identity_stability == "stable"
    assert record.manifest.commands == []
    assert record.manifest.manifest_sha256


def test_landerpi_actuator_endpoints_remain_unverified_and_non_writable() -> None:
    records = MODULE.build_recorded_manifest_records()
    candidates = {
        item.manifest.device_id: item
        for item in records
        if item.manifest.device_class.value in {"actuator", "end-effector"}
    }
    assert set(candidates) == {"landerpi-base-drive", "landerpi-arm", "landerpi-gripper"}
    assert candidates["landerpi-arm"].confirmation_status == "CONFIRMED_BOUND_WRITE_BLOCKED"
    assert candidates["landerpi-arm"].manifest.commands[0].id == "stop_arm"
    assert candidates["landerpi-arm"].manifest.commands[0].risk == "R1"
    assert (
        candidates["landerpi-arm"].manifest.commands[0].hardware_resource_id
        == "landerpi-rrc:5b22016029:bus-servo:arm"
    )
    assert candidates["landerpi-arm"].hardware_bindings[0].feedback_routes == [
        "ros2:/joint_states",
        "ros2:/controller_manager/servo_states",
    ]
    assert candidates["landerpi-arm"].safety_evidence is not None
    assert candidates["landerpi-arm"].safety_evidence.is_write_ready() is False
    assert candidates["landerpi-gripper"].confirmation_status == "CONFIRMED_BOUND_WRITE_BLOCKED"
    assert candidates["landerpi-gripper"].manifest.commands[0].id == "stop_gripper"
    assert (
        candidates["landerpi-gripper"].manifest.commands[0].hardware_resource_id
        == "landerpi-rrc:5b22016029:bus-servo:gripper"
    )
    assert candidates["landerpi-gripper"].hardware_bindings[0].feedback_routes == [
        "ros2:/joint_states",
        "ros2:/controller_manager/servo_states",
    ]
    assert candidates["landerpi-gripper"].safety_evidence is not None
    assert candidates["landerpi-gripper"].safety_evidence.is_write_ready() is False
    assert all(
        item.confirmation_status == "DISCOVERED_UNVERIFIED"
        for key, item in candidates.items()
        if key not in {"landerpi-arm", "landerpi-gripper"}
    )
    assert all(
        not item.manifest.commands
        for key, item in candidates.items()
        if key not in {"landerpi-arm", "landerpi-gripper"}
    )


def test_landerpi_camera_is_observed_but_not_identity_confirmed() -> None:
    camera = next(
        item
        for item in MODULE.build_recorded_manifest_records()
        if item.manifest.device_id == "landerpi-aurora930"
    )
    assert camera.confirmation_status == "DISCOVERED_UNVERIFIED"
    assert camera.identity_stability == "path"
    assert "ros2:/ascamera/camera_publisher/rgb0/image" in camera.manifest.resources
    assert camera.manifest.commands == []


def test_confirmed_record_rejects_path_identity_or_write_commands() -> None:
    record = MODULE.build_rrc_controller_record()
    with pytest.raises(ValueError, match="stable identity"):
        MhsManifestRecord.model_validate(
            record.model_dump(mode="json") | {"identity_stability": "path"}
        )
