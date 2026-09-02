"""Recorded LanderPi MHS manifests built from read-only observations.

The builders consume no ROS SDK and perform no target I/O.  The controller
board is confirmed as a read-only MHS because its USB serial, udev links,
ROS node, and driver source digest agree.  ROS logical actuator endpoints are
kept as unverified records until their physical resource and safety chain are
independently established.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from rolo.mhs_hardware import MhsChannel, MhsDeviceClass, MhsDeviceManifest
from rolo.mhs_manifest_records import MhsManifestRecord


OBSERVED_AT = datetime(2026, 9, 2, 18, 54, 17, tzinfo=timezone.utc)
TARGET_SERIAL = "5B22016029"
RRC_DRIVER_SHA256 = "f4afe5e307d8b08750dbd0c185a50c77395ea1184789a11026516b3b557b6e2d"


def build_rrc_controller_record() -> MhsManifestRecord:
    manifest = MhsDeviceManifest(
        device_id="landerpi-rrc",
        device_class=MhsDeviceClass.CONTROLLER,
        name="ROS Robot Controller board",
        vendor="1a86",
        model="USB Single Serial",
        serial=TARGET_SERIAL,
        channels=[
            MhsChannel(
                id="battery_raw",
                name="Controller battery reading",
                unit="raw",
                min_value=0,
            )
        ],
        resources=["/dev/rrc", "/dev/ttyACM0", "usb:1a86_USB_Single_Serial_5B22016029"],
        state={"read": ["battery", "button", "imu_raw", "joy", "sbus"]},
        transport={
            "kind": "ros2+serial",
            "properties": {
                "node": "/ros_robot_controller",
                "device_path": "/dev/rrc",
                "resolved_path": "/dev/ttyACM0",
                "udev_id": "usb-1a86_USB_Single_Serial_5B22016029-if00",
            },
        },
        limits=[
            "confirmed read-only manifest",
            "write topics observed but intentionally not declared as MHS commands",
            "no GPIO/I2C/SPI/serial writes",
        ],
        driver_id="landerpi.ros_robot_controller_sdk",
        driver_version="observed-source",
        driver_sha256=RRC_DRIVER_SHA256,
    )
    return MhsManifestRecord(
        manifest=manifest,
        confirmation_status="CONFIRMED_READ_ONLY",
        identity_stability="stable",
        source_refs=[
            "udev:/dev/ttyACM0",
            "udev:/dev/rrc",
            "ros2:/ros_robot_controller",
            "/home/pi/robot_pi/arm_pc/ros_robot_controller_sdk.py",
        ],
        evidence_ids=[
            "landerpi:udev:1a86_USB_Single_Serial_5B22016029",
            "landerpi:ros2:ros_robot_controller",
            f"landerpi:driver-sha256:{RRC_DRIVER_SHA256}",
        ],
        observed_at=OBSERVED_AT,
        limitations=[
            "confirms the controller board and read channels, not actuator safety",
            "ROS write endpoints require a separate command manifest and W4 approval",
        ],
    )


def build_unverified_logical_records() -> list[MhsManifestRecord]:
    candidates = [
        (
            "landerpi-ld19",
            MhsDeviceClass.SENSOR,
            "LD19 ROS laser scanner candidate",
            "LD19 ROS node label",
            ["/dev/ldlidar", "/dev/ttyUSB0", "ros2:/LD19", "ros2:/scan"],
            {"kind": "ros2+serial", "properties": {"node": "/LD19", "topic": "/scan"}},
        ),
        (
            "landerpi-base-drive",
            MhsDeviceClass.ACTUATOR,
            "ROS base drive logical candidate",
            "ros2_control base controller",
            ["ros2:/cmd_vel", "joint:wheel_left_front_joint", "joint:wheel_right_front_joint"],
            {"kind": "ros2", "properties": {"topic": "/cmd_vel", "topic_type": "geometry_msgs/msg/Twist"}},
        ),
        (
            "landerpi-arm",
            MhsDeviceClass.ACTUATOR,
            "ROS arm controller logical candidate",
            "arm_controller",
            ["ros2:/arm_controller/follow_joint_trajectory", "joint:joint1", "joint:joint5"],
            {"kind": "ros2", "properties": {"action": "/arm_controller/follow_joint_trajectory"}},
        ),
        (
            "landerpi-gripper",
            MhsDeviceClass.END_EFFECTOR,
            "ROS gripper controller logical candidate",
            "gripper_controller",
            ["ros2:/gripper_controller/follow_joint_trajectory", "joint:left_jaw_joint", "joint:right_jaw_joint"],
            {"kind": "ros2", "properties": {"action": "/gripper_controller/follow_joint_trajectory"}},
        ),
    ]
    records: list[MhsManifestRecord] = []
    for device_id, device_class, name, model, resources, transport in candidates:
        manifest = MhsDeviceManifest(
            device_id=device_id,
            device_class=device_class,
            name=name,
            vendor="unknown",
            model=model,
            resources=resources,
            state={"read": ["status", "feedback"]},
            transport=transport,
            limits=[
                "logical ROS endpoint only",
                "physical resource and safety chain not confirmed",
                "write capability not declared",
            ],
            driver_id="landerpi.ros.graph-observer",
            driver_version="2026-09-02",
            driver_sha256="0" * 64,
        )
        records.append(
            MhsManifestRecord(
                manifest=manifest,
                confirmation_status="DISCOVERED_UNVERIFIED",
                identity_stability="unknown" if device_class != MhsDeviceClass.SENSOR else "path",
                source_refs=[f"ros2:{device_id}"],
                evidence_ids=[f"landerpi:ros-graph:{device_id}"],
                observed_at=OBSERVED_AT,
                limitations=list(manifest.limits),
            )
        )
    return records


def build_recorded_manifest_records() -> list[MhsManifestRecord]:
    return [build_rrc_controller_record(), *build_unverified_logical_records()]


if __name__ == "__main__":
    import json

    print(
        json.dumps(
            [record.model_dump(mode="json") for record in build_recorded_manifest_records()],
            indent=2,
        )
    )
