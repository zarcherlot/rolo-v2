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

from rolo.mhs_hardware import (
    MhsChannel,
    MhsCommandDescriptor,
    MhsDeviceClass,
    MhsDeviceManifest,
)
from rolo.mhs_manifest_records import (
    MhsHardwareBinding,
    MhsManifestRecord,
    MhsSafetyEvidence,
    MhsSafetyEvidenceBundle,
)


OBSERVED_AT = datetime(2026, 9, 2, 18, 54, 17, tzinfo=timezone.utc)
TARGET_SERIAL = "5B22016029"
TARGET_RESOURCE_TOKEN = TARGET_SERIAL.lower()
RRC_DRIVER_SHA256 = "f4afe5e307d8b08750dbd0c185a50c77395ea1184789a11026516b3b557b6e2d"
SERVO_CONFIG_SHA256 = "fa68e017c13fda3735f0daa5a96f2f9221f6e43235cf3eb662b3342331b6a594"
ARM_URDF_SHA256 = "a3baed619f444995bc8f65569248f04d0ebabcdf23f4b55b00b597dceeab1981"


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


def build_arm_bound_record() -> MhsManifestRecord:
    resources = [
        f"landerpi-rrc:{TARGET_RESOURCE_TOKEN}:bus-servo:{servo_id}"
        for servo_id in range(1, 6)
    ]
    manifest = MhsDeviceManifest(
        device_id="landerpi-arm",
        device_class=MhsDeviceClass.ACTUATOR,
        name="LanderPi arm controller",
        vendor="ros2_control",
        model="arm_controller",
        serial=TARGET_SERIAL,
        channels=[
            MhsChannel(
                id=f"joint{joint}_position",
                name=f"Joint {joint} position",
                unit="rad",
                min_value=-2.09,
                max_value=2.09,
            )
            for joint in range(1, 6)
        ],
        resources=resources,
        state={"read": ["joint_states", "servo_states", "controller_state"]},
        commands=[
            MhsCommandDescriptor(
                id="stop_arm",
                hardware_resource_id=f"landerpi-rrc:{TARGET_RESOURCE_TOKEN}:bus-servo:arm",
                risk="R1",
                input_schema={
                    "type": "object",
                    "properties": {},
                    "required": [],
                    "additionalProperties": False,
                },
                timeout_s=0.5,
                idempotent=True,
                requires=["arm_feedback_fresh", "controller_ready"],
                cancel_capability="stop_arm",
            )
        ],
        transport={
            "kind": "ros2+serial",
            "properties": {
                "controller_node": "/arm_controller",
                "action": "/arm_controller/follow_joint_trajectory",
                "stop_endpoint": "/ros_robot_controller/bus_servo/set_state",
                "device_path": "/dev/rrc",
                "resolved_path": "/dev/ttyACM0",
                "udev_id": "usb-1a86_USB_Single_Serial_5B22016029-if00",
                "servo_config_sha256": SERVO_CONFIG_SHA256,
                "urdf_sha256": ARM_URDF_SHA256,
            },
        },
        limits=[
            "write blocked pending independent safety evidence",
            "servo IDs 1..5 are sourced from servo_controller.yaml",
            "joint limits are sourced from arm.urdf.xacro",
            "stop endpoint is identified but not invoked by this discovery run",
        ],
        driver_id="landerpi.ros_robot_controller_sdk",
        driver_version="observed-source",
        driver_sha256=RRC_DRIVER_SHA256,
    )
    safety = MhsSafetyEvidenceBundle(
        external_estop=MhsSafetyEvidence(
            status="UNVERIFIED",
            source_refs=["operator:landerpi-external-estop"],
            notes="External e-stop is declared on the device side; Rolo-readable state and trip evidence were not observed.",
        ),
        stop=MhsSafetyEvidence(
            status="UNVERIFIED",
            source_refs=["ros2:/ros_robot_controller/bus_servo/set_state"],
            notes="SDK and message field expose stop, but no stop test was executed.",
        ),
        rollback=MhsSafetyEvidence(
            status="NOT_OBSERVED",
            notes="No rollback/compensation procedure was tested.",
        ),
        watchdog=MhsSafetyEvidence(
            status="UNVERIFIED",
            source_refs=["ros2:/diagnostics", "ros2:/controller_manager"],
            notes="Controller liveness is observed; an independent actuator watchdog is not proven.",
        ),
        no_load=MhsSafetyEvidence(
            status="NOT_OBSERVED",
            notes="Physical no-load condition cannot be established from SSH/ROS evidence.",
        ),
    )
    return MhsManifestRecord(
        manifest=manifest,
        confirmation_status="CONFIRMED_BOUND_WRITE_BLOCKED",
        identity_stability="stable",
        source_refs=[
            "udev:/dev/ttyACM0",
            "udev:/dev/rrc",
            "ros2:/arm_controller",
            "ros2:/arm_controller/follow_joint_trajectory",
            "/home/ubuntu/ros2_ws/src/driver/servo_controller/config/servo_controller.yaml",
            "/home/ubuntu/ros2_ws/src/simulations/landerpi_description/urdf/arm.urdf.xacro",
            "/home/pi/robot_pi/arm_pc/ros_robot_controller_sdk.py",
        ],
        evidence_ids=[
            "landerpi:udev:1a86_USB_Single_Serial_5B22016029",
            "landerpi:ros2:arm_controller",
            f"landerpi:servo-config-sha256:{SERVO_CONFIG_SHA256}",
            f"landerpi:arm-urdf-sha256:{ARM_URDF_SHA256}",
        ],
        observed_at=OBSERVED_AT,
        limitations=list(manifest.limits),
        hardware_bindings=[
            MhsHardwareBinding(
                hardware_resource_id=f"landerpi-rrc:{TARGET_RESOURCE_TOKEN}:bus-servo:arm",
                controller_manifest_device_id="landerpi-rrc",
                control_endpoint="ros2:/ros_robot_controller/bus_servo/set_state",
                feedback_routes=[
                    "ros2:/joint_states",
                    "ros2:/controller_manager/servo_states",
                ],
                limit_sources=[
                    f"sha256:{SERVO_CONFIG_SHA256}",
                    f"sha256:{ARM_URDF_SHA256}",
                ],
            )
        ],
        safety_evidence=safety,
    )


def build_gripper_bound_record() -> MhsManifestRecord:
    """Bind the observed gripper action to bus-servo ID 10, but keep writes blocked."""
    resource = f"landerpi-rrc:{TARGET_RESOURCE_TOKEN}:bus-servo:gripper"
    manifest = MhsDeviceManifest(
        device_id="landerpi-gripper",
        device_class=MhsDeviceClass.END_EFFECTOR,
        name="LanderPi gripper controller",
        vendor="ros2_control",
        model="gripper_controller",
        serial=TARGET_SERIAL,
        channels=[
            MhsChannel(
                id="r_joint_position",
                name="Gripper rotary joint position",
                unit="rad",
                min_value=-2.09,
                max_value=2.09,
            )
        ],
        resources=[
            f"{resource}:10",
            "ros2:/gripper_controller/follow_joint_trajectory",
        ],
        state={"read": ["joint_states", "servo_states", "controller_state"]},
        commands=[
            MhsCommandDescriptor(
                id="stop_gripper",
                hardware_resource_id=resource,
                risk="R1",
                input_schema={
                    "type": "object",
                    "properties": {},
                    "required": [],
                    "additionalProperties": False,
                },
                timeout_s=0.5,
                idempotent=True,
                requires=["gripper_feedback_fresh", "controller_ready"],
                cancel_capability="stop_gripper",
            )
        ],
        transport={
            "kind": "ros2+serial",
            "properties": {
                "controller_node": "/gripper_controller",
                "action": "/gripper_controller/follow_joint_trajectory",
                "stop_endpoint": "/ros_robot_controller/bus_servo/set_state",
                "device_path": "/dev/rrc",
                "resolved_path": "/dev/ttyACM0",
                "udev_id": "usb-1a86_USB_Single_Serial_5B22016029-if00",
                "servo_id": 10,
                "servo_config_sha256": SERVO_CONFIG_SHA256,
                "urdf_sha256": ARM_URDF_SHA256,
            },
        },
        limits=[
            "write blocked pending independent safety evidence",
            "r_joint -> bus-servo ID 10 is sourced from servo_controller.yaml",
            "joint limits are sourced from arm.urdf.xacro; gripper-specific limit needs confirmation",
            "stop endpoint is identified but not invoked by this discovery run",
        ],
        driver_id="landerpi.ros_robot_controller_sdk",
        driver_version="observed-source",
        driver_sha256=RRC_DRIVER_SHA256,
    )
    safety = MhsSafetyEvidenceBundle(
        external_estop=MhsSafetyEvidence(
            status="UNVERIFIED",
            source_refs=["operator:landerpi-external-estop"],
            notes="External e-stop is declared on the device side; Rolo-readable state was not observed.",
        ),
        stop=MhsSafetyEvidence(
            status="UNVERIFIED",
            source_refs=["ros2:/ros_robot_controller/bus_servo/set_state"],
            notes="Stop endpoint and servo ID are identified, but no stop test was executed.",
        ),
        rollback=MhsSafetyEvidence(status="NOT_OBSERVED", notes="No rollback/compensation procedure was tested."),
        watchdog=MhsSafetyEvidence(status="UNVERIFIED", notes="Independent actuator watchdog is not proven."),
        no_load=MhsSafetyEvidence(status="NOT_OBSERVED", notes="Physical no-load condition was not established."),
    )
    return MhsManifestRecord(
        manifest=manifest,
        confirmation_status="CONFIRMED_BOUND_WRITE_BLOCKED",
        identity_stability="stable",
        source_refs=[
            "udev:/dev/ttyACM0",
            "ros2:/gripper_controller",
            "ros2:/gripper_controller/follow_joint_trajectory",
            "/home/ubuntu/ros2_ws/src/driver/servo_controller/config/servo_controller.yaml",
            "/home/ubuntu/ros2_ws/src/simulations/landerpi_description/urdf/arm.urdf.xacro",
        ],
        evidence_ids=[
            "landerpi:udev:1a86_USB_Single_Serial_5B22016029",
            "landerpi:ros2:gripper_controller",
            f"landerpi:servo-config-sha256:{SERVO_CONFIG_SHA256}",
        ],
        observed_at=OBSERVED_AT,
        limitations=list(manifest.limits),
        hardware_bindings=[
            MhsHardwareBinding(
                hardware_resource_id=resource,
                controller_manifest_device_id="landerpi-rrc",
                control_endpoint="ros2:/ros_robot_controller/bus_servo/set_state",
                feedback_routes=[
                    "ros2:/joint_states",
                    "ros2:/controller_manager/servo_states",
                ],
                limit_sources=[
                    f"sha256:{SERVO_CONFIG_SHA256}",
                    f"sha256:{ARM_URDF_SHA256}",
                ],
            )
        ],
        safety_evidence=safety,
    )


def build_camera_unverified_record() -> MhsManifestRecord:
    """Record the observed Aurora 930 camera without inventing a serial number."""
    manifest = MhsDeviceManifest(
        device_id="landerpi-aurora930",
        device_class=MhsDeviceClass.SENSOR,
        name="LanderPi Aurora 930 depth camera",
        vendor="3251",
        model="1930 / Aurora 930",
        resources=[
            "usb:1-3:3251:1930",
            "/dev/video19..37",
            "ros2:/ascamera/camera_publisher/rgb0/image",
            "ros2:/ascamera/camera_publisher/depth0/image_raw",
            "ros2:/ascamera/camera_publisher/ir0/image",
        ],
        channels=[
            MhsChannel(id="rgb_frame", name="RGB image frame", unit="frame", value_type="string"),
            MhsChannel(id="depth_frame", name="Depth image frame", unit="frame", value_type="string"),
            MhsChannel(id="ir_frame", name="IR image frame", unit="frame", value_type="string"),
        ],
        state={"read": ["status", "rgb", "depth", "ir", "points"]},
        transport={
            "kind": "ros2+usb",
            "properties": {
                "usb_path": "1-3",
                "vid": "3251",
                "pid": "1930",
                "rgb_topic": "/ascamera/camera_publisher/rgb0/image",
                "depth_topic": "/ascamera/camera_publisher/depth0/image_raw",
                "ir_topic": "/ascamera/camera_publisher/ir0/image",
                "points_topic": "/ascamera/camera_publisher/depth0/points",
            },
        },
        limits=[
            "read-only candidate; no write commands",
            "USB serial was not observed; identity is topology/path based",
            "multiple /dev/video nodes require modality-specific format probing",
            "vendor log states OpenNI2 camera does not support watchdog function",
        ],
        driver_id="deptrum-ros-driver-aurora930",
        driver_version="observed-process",
        driver_sha256="0" * 64,
    )
    return MhsManifestRecord(
        manifest=manifest,
        confirmation_status="DISCOVERED_UNVERIFIED",
        identity_stability="path",
        source_refs=[
            "lsusb:3251:1930",
            "udev:/dev/video19",
            "udev:/dev/video20",
            "ros2:/ascamera/camera_publisher/rgb0/image",
            "ros2:/ascamera/camera_publisher/depth0/image_raw",
            "/home/pi/robot_pi/tool/Log/OrbbecSDK.log.txt",
        ],
        evidence_ids=[
            "landerpi:usb:3251:1930:1-3",
            "landerpi:ros2:camera-topics",
        ],
        observed_at=OBSERVED_AT,
        limitations=list(manifest.limits),
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
            [
                "ros2:/cmd_vel",
                "ros2:/controller/cmd_vel",
                "joint:wheel_left_front_joint",
                "joint:wheel_right_front_joint",
            ],
            {
                "kind": "ros2",
                "properties": {
                    "input_topic": "/cmd_vel",
                    "controller_topic": "/controller/cmd_vel",
                    "topic_type": "geometry_msgs/msg/Twist",
                    "observed_subscriber": "odom_publisher (feedback path); actuator subscriber identity unresolved",
                },
            },
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
    return [
        build_rrc_controller_record(),
        build_arm_bound_record(),
        build_gripper_bound_record(),
        build_camera_unverified_record(),
        *build_unverified_logical_records(),
    ]


if __name__ == "__main__":
    import json

    print(
        json.dumps(
            [record.model_dump(mode="json") for record in build_recorded_manifest_records()],
            indent=2,
        )
    )
