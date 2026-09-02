"""Portable MHS bundles for hardware sampling and review.

The bundle format deliberately separates a typed :class:`MhsDeviceManifest`
from discovery metadata.  A manifest describes the proposed MHS surface;
``status`` and ``evidence`` describe what was (and was not) observed on a
particular robot.  This lets another project ingest the same JSON and promote
devices only after its own sampling evidence is available.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .mhs_hardware import (
    MhsChannel,
    MhsDeviceClass,
    MhsDeviceManifest,
    MhsIdentity,
    MhsIdentitySource,
    MhsInterfaceDescriptor,
    MhsProvenance,
    MhsRelation,
    MhsSafetyContract,
)

LANDERPI_DRIVER_ID = "rolo.mhs.landerpi-observation"
LANDERPI_DRIVER_VERSION = "0.1.0"
LANDERPI_DRIVER_SHA256 = hashlib.sha256(
    f"{LANDERPI_DRIVER_ID}:{LANDERPI_DRIVER_VERSION}".encode()
).hexdigest()


class MhsBindingStatus(str, Enum):
    DISCOVERED_UNVERIFIED = "DISCOVERED_UNVERIFIED"
    READY_FOR_SAMPLING = "READY_FOR_SAMPLING"
    VERIFIED = "VERIFIED"


class MhsConfidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class MhsEvidenceRef(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: Literal["physical", "software", "documentation", "inference"]
    ref: str = Field(min_length=1)
    statement: str = Field(min_length=1)


class MhsSamplingAction(BaseModel):
    """Machine-readable, bounded action for a future sampler."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1, pattern=r"^[a-z][a-z0-9_.-]*$")
    operation: Literal["inspect", "status", "read", "read_structured", "approved_identity_probe"]
    source_ref: str = Field(min_length=1)
    query: str = Field(min_length=1)
    side_effect: Literal["none"] = "none"
    timeout_s: float = Field(default=5.0, gt=0, le=60)
    requires_approval: bool = False


class MhsBundleDevice(BaseModel):
    """One proposed device surface plus its sampling contract."""

    model_config = ConfigDict(extra="forbid")

    manifest: MhsDeviceManifest
    owner: str = Field(default="rolo-maintainers", min_length=1)
    target_host: str = Field(default="raspberrypi", min_length=1)
    dependencies: list[str] = Field(default_factory=list)
    stage: str = Field(default="D3", pattern=r"^D[0-5]$")
    next_action: str = Field(default="collect read-only runtime evidence", min_length=1)
    status: MhsBindingStatus = MhsBindingStatus.DISCOVERED_UNVERIFIED
    confidence: MhsConfidence = MhsConfidence.LOW
    evidence: list[MhsEvidenceRef] = Field(default_factory=list)
    sampling_contract: list[str] = Field(default_factory=list)
    sampling_plan: list[MhsSamplingAction] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def status_is_conservative(self) -> MhsBundleDevice:
        if self.status == MhsBindingStatus.VERIFIED and not self.evidence:
            raise ValueError("verified device requires evidence")
        if self.manifest.commands:
            raise ValueError("LanderPi sampling bundle must not enable write commands")
        ids = [action.id for action in self.sampling_plan]
        if len(ids) != len(set(ids)):
            raise ValueError("bundle contains duplicate sampling action ids")
        return self


class MhsBundle(BaseModel):
    """Versioned, controller-portable collection of LanderPi MHS candidates."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = "rolo-mhs-bundle/v1"
    robot_id: str = Field(min_length=1, pattern=r"^[a-z][a-z0-9_.-]*$")
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source_discovery: str = Field(min_length=1)
    devices: list[MhsBundleDevice] = Field(min_length=1)

    @model_validator(mode="after")
    def unique_device_ids(self) -> MhsBundle:
        ids = [item.manifest.device_id for item in self.devices]
        if len(ids) != len(set(ids)):
            raise ValueError("bundle contains duplicate device ids")
        return self


def _manifest(
    *,
    device_id: str,
    device_class: MhsDeviceClass,
    name: str,
    vendor: str,
    model: str,
    channels: list[MhsChannel],
    resources: list[str],
    state: dict[str, list[str]],
    transport: dict[str, Any],
    limits: list[str],
    serial: str | None = None,
    identity: MhsIdentity | None = None,
    provenance: MhsProvenance | None = None,
    relations: list[MhsRelation] | None = None,
    interfaces: list[MhsInterfaceDescriptor] | None = None,
    safety: MhsSafetyContract | None = None,
) -> MhsDeviceManifest:
    return MhsDeviceManifest(
        device_id=device_id,
        device_class=device_class,
        name=name,
        vendor=vendor,
        model=model,
        serial=serial,
        channels=channels,
        resources=resources,
        state=state,
        transport=transport,
        limits=[*limits, "read-only sampling profile; no write commands"],
        driver_id=LANDERPI_DRIVER_ID,
        driver_version=LANDERPI_DRIVER_VERSION,
        driver_sha256=LANDERPI_DRIVER_SHA256,
        identity=identity or MhsIdentity(),
        provenance=provenance or MhsProvenance(status="DISCOVERED_UNVERIFIED"),
        relations=relations or [],
        interfaces=interfaces or [],
        safety=safety or MhsSafetyContract(),
    )


def _provenance(*evidence_ids: str, **field_status: str) -> MhsProvenance:
    return MhsProvenance(
        status="DISCOVERED_UNVERIFIED",
        evidence_ids=list(evidence_ids),
        field_status=field_status,
    )


def _sampling_plan(
    common: str, device_id: str, *, structured: bool = False
) -> list[MhsSamplingAction]:
    operations: list[tuple[str, str]] = [
        ("inspect", "read manifest and interface declarations"),
        ("status", "read health and connection state"),
        ("read", "read declared scalar channels"),
    ]
    if structured:
        operations.append(("read_structured", "read one bounded structured sample"))
    return [
        MhsSamplingAction(
            id=f"{device_id}-{operation}",
            operation=operation,
            source_ref=f"mhs://{device_id}/{operation}",
            query=query,
        )
        for operation, query in operations
    ]


def landerpi_mhs_bundle() -> MhsBundle:
    """Build the initial LanderPi sensor/controller/actuator MHS surfaces.

    These are intentionally candidates: channels are the expected sampling
    contract, not claims that a value was observed during discovery.
    """

    common = "artifact://mhs-landerpi/discovery-20260902.json"
    ros_graph = "artifact://mhs-landerpi/ros-graph-20260902.json"
    ros_payload = "artifact://mhs-landerpi/ros-payload-20260902.json"
    devices = [
        MhsBundleDevice(
            manifest=_manifest(
                device_id="landerpi-vision-aurora930",
                device_class=MhsDeviceClass.SENSOR,
                name="Aurora 930 depth camera",
                vendor="deptrum (inferred)",
                model="Aurora 930",
                channels=[
                    MhsChannel(
                        id="depth_frame_available",
                        name="Depth frame available",
                        unit="bool",
                        value_type="boolean",
                    ),
                    MhsChannel(
                        id="rgb_frame_available",
                        name="RGB frame available",
                        unit="bool",
                        value_type="boolean",
                    ),
                    MhsChannel(
                        id="ir_frame_available",
                        name="IR frame available",
                        unit="bool",
                        value_type="boolean",
                    ),
                    MhsChannel(
                        id="frame_timestamp_ns", name="Frame timestamp", unit="ns", min_value=0
                    ),
                ],
                resources=["usb:1-2", "process:/aurora/aurora"],
                state={"read": ["health", "serial", "ros_topics", "frame_encoding", "resolution"]},
                transport={
                    "kind": "usb-ros2",
                    "properties": {
                        "sysfs": "1-2",
                        "vid": "3251",
                        "pid": "1930",
                        "serial": "HY400516001016421G00082",
                    },
                },
                limits=[
                    "product identity supported by USB descriptor and ROS process; "
                    "exact VID/PID vendor mapping pending"
                ],
                serial="HY400516001016421G00082",
                identity=MhsIdentity(
                    stable_id="HY400516001016421G00082",
                    confidence="high",
                    sources=[
                        MhsIdentitySource(
                            kind="serial",
                            value="HY400516001016421G00082",
                            evidence_ids=[f"{common}#usb_devices/1-2"],
                        ),
                        MhsIdentitySource(
                            kind="path", value="usb:1-2", evidence_ids=[f"{common}#usb_devices/1-2"]
                        ),
                    ],
                ),
                provenance=_provenance(
                    f"{common}#usb_devices/1-2",
                    f"{common}#software_stack/processes_of_interest",
                    device_id="observed",
                    vendor="inferred",
                    model="observed",
                    serial="observed",
                    interfaces="declared",
                ),
                relations=[
                    MhsRelation(
                        kind="driven_by",
                        target="process:/aurora/aurora",
                        evidence_ids=[f"{common}#software_stack/processes_of_interest"],
                    )
                ],
                interfaces=[
                    MhsInterfaceDescriptor(
                        id="rgb",
                        kind="image",
                        access="stream",
                        transport_ref="ros2:///ascamera/camera_publisher/rgb0/image",
                        encoding="sensor_msgs/Image",
                        frame_id="pending",
                        timestamp="source",
                    ),
                    MhsInterfaceDescriptor(
                        id="ir",
                        kind="image",
                        access="stream",
                        transport_ref="ros2:///ascamera/camera_publisher/ir0/image",
                        encoding="sensor_msgs/Image",
                        frame_id="pending",
                        timestamp="source",
                    ),
                    MhsInterfaceDescriptor(
                        id="depth",
                        kind="image",
                        access="stream",
                        transport_ref="ros2:///ascamera/camera_publisher/depth0/image_raw",
                        encoding="16UC1|32FC1",
                        frame_id="pending",
                        timestamp="source",
                    ),
                    MhsInterfaceDescriptor(
                        id="points",
                        kind="point_cloud",
                        access="stream",
                        transport_ref="ros2:///ascamera/camera_publisher/depth0/points",
                        encoding="sensor_msgs/PointCloud2",
                        frame_id="pending",
                        timestamp="source",
                    ),
                ],
                safety=MhsSafetyContract(read_only=True),
            ),
            dependencies=["USB sysfs", "/aurora/aurora", "ROS 2 adapter"],
            next_action="sample RGB/IR/depth topics and bind them to the USB serial",
            sampling_plan=_sampling_plan(common, "landerpi-vision-aurora930", structured=True),
            confidence=MhsConfidence.HIGH,
            evidence=[
                MhsEvidenceRef(
                    kind="physical",
                    ref=f"{common}#usb_devices/1-2",
                    statement=(
                        "USB sysfs device 1-2 exposes Aurora 930 product string and stable serial."
                    ),
                ),
                MhsEvidenceRef(
                    kind="software",
                    ref=f"{common}#software_stack/processes_of_interest",
                    statement="The target exposes an /aurora/aurora node for the camera.",
                ),
                MhsEvidenceRef(
                    kind="software",
                    ref=f"{ros_graph}#/bindings/0",
                    statement=(
                        "The /aurora/aurora node publishes RGB, IR, depth and point-cloud topics."
                    ),
                ),
                MhsEvidenceRef(
                    kind="documentation",
                    ref="https://www.deptrum.com/en/site/product_details/318",
                    statement="Aurora 930 is documented as a Linux/ROS 3D depth camera.",
                ),
                MhsEvidenceRef(
                    kind="software",
                    ref=ros_payload,
                    statement="Camera payload was not sampled in this bounded observation window.",
                ),
            ],
            sampling_contract=[
                "read ROS node/topic graph",
                "observe one RGB/IR/depth frame without commanding hardware",
                "bind topic stream to USB serial",
            ],
            limitations=["No frame payload or calibration was observed during discovery."],
        ),
        MhsBundleDevice(
            manifest=_manifest(
                device_id="landerpi-lidar",
                device_class=MhsDeviceClass.SENSOR,
                name="LanderPi LiDAR",
                vendor="unknown",
                model="unknown (filtered /scan)",
                channels=[
                    MhsChannel(
                        id="scan_available",
                        name="Laser scan available",
                        unit="bool",
                        value_type="boolean",
                    ),
                    MhsChannel(
                        id="ranges_count", name="Range sample count", unit="count", min_value=0
                    ),
                    MhsChannel(id="range_min_m", name="Minimum range", unit="m", min_value=0),
                    MhsChannel(id="range_max_m", name="Maximum range", unit="m", min_value=0),
                ],
                resources=["process:/scan_to_scan_filter_chain", "ros_topic:/scan"],
                state={"read": ["health", "ros_topics", "frame_id", "scan_rate_hz"]},
                transport={
                    "kind": "ros2-laserscan",
                    "properties": {"node": "/scan_to_scan_filter_chain", "topic_hint": "/scan"},
                },
                limits=[
                    "driver presence only; model, serial, protocol and physical "
                    "attachment are unknown"
                ],
                provenance=_provenance(
                    f"{common}#software_stack/processes_of_interest",
                    model="unknown",
                    serial="unknown",
                    interfaces="declared",
                ),
                relations=[
                    MhsRelation(
                        kind="publishes_to",
                        target="ros_topic:/scan",
                        evidence_ids=[f"{common}#software_stack/processes_of_interest"],
                    )
                ],
                interfaces=[
                    MhsInterfaceDescriptor(
                        id="scan",
                        kind="laser_scan",
                        access="stream",
                        transport_ref="ros2:///scan",
                        encoding="sensor_msgs/LaserScan",
                        frame_id="pending",
                        timestamp="source",
                        payload_schema={
                            "ranges": "float32[]",
                            "intensities": "float32[]",
                            "angle_min": "rad",
                            "angle_max": "rad",
                            "angle_increment": "rad",
                        },
                    )
                ],
                safety=MhsSafetyContract(read_only=True),
            ),
            dependencies=["/scan_to_scan_filter_chain", "ROS 2 adapter", "serial identity"],
            next_action="sample one LaserScan and resolve transport serial/model",
            sampling_plan=_sampling_plan(common, "landerpi-lidar", structured=True),
            confidence=MhsConfidence.MEDIUM,
            evidence=[
                MhsEvidenceRef(
                    kind="software",
                    ref=f"{common}#software_stack/processes_of_interest",
                    statement="The target publishes /scan from scan_to_scan_filter_chain.",
                ),
                MhsEvidenceRef(
                    kind="software",
                    ref=f"{ros_graph}#/topic_info/~1scan",
                    statement=(
                        "/scan is a sensor_msgs/msg/LaserScan topic with a RELIABLE publisher."
                    ),
                ),
                MhsEvidenceRef(
                    kind="software",
                    ref=ros_payload,
                    statement="Bounded /scan payload read timed out without a LaserScan message.",
                ),
            ],
            sampling_contract=[
                "read ROS topic types and QoS",
                "observe one bounded LaserScan message",
                "identify transport device and serial",
            ],
            limitations=["No ROS payload was read; this remains a sensor candidate."],
        ),
        MhsBundleDevice(
            manifest=_manifest(
                device_id="landerpi-ros-robot-controller",
                device_class=MhsDeviceClass.CONTROLLER,
                name="ROS robot controller",
                vendor="unknown",
                model="ros_robot_controller",
                channels=[
                    MhsChannel(
                        id="controller_ready",
                        name="Controller ready",
                        unit="bool",
                        value_type="boolean",
                    ),
                    MhsChannel(
                        id="fault_active", name="Fault active", unit="bool", value_type="boolean"
                    ),
                    MhsChannel(
                        id="joint_state_available",
                        name="Joint state available",
                        unit="bool",
                        value_type="boolean",
                    ),
                    MhsChannel(id="joint_count", name="Joint count", unit="count", min_value=0),
                ],
                resources=[
                    "process:/ros_robot_controller",
                    "process:/joint_state_publisher",
                    "ros_topic:/controller_manager/joint_states",
                ],
                state={"read": ["health", "controller_state", "resources", "faults", "limits"]},
                transport={
                    "kind": "ros2-controller",
                    "properties": {"node": "ros_robot_controller"},
                },
                limits=[
                    "controller model, resource claims, limits and interlocks are not yet observed"
                ],
                provenance=_provenance(
                    f"{common}#software_stack/processes_of_interest",
                    model="observed",
                    resources="inferred",
                    safety="unknown",
                    interfaces="declared",
                ),
                relations=[
                    MhsRelation(
                        kind="controls",
                        target="landerpi-servo-actuator",
                        evidence_ids=[f"{common}#software_stack/processes_of_interest"],
                    )
                ],
                interfaces=[
                    MhsInterfaceDescriptor(
                        id="joint_state",
                        kind="joint_state",
                        access="stream",
                        transport_ref="ros2:///controller_manager/joint_states",
                        encoding="sensor_msgs/JointState",
                        timestamp="source",
                        payload_schema={
                            "name": "string[]",
                            "position": "float64[]",
                            "velocity": "float64[]",
                            "effort": "float64[]",
                        },
                    )
                ],
                safety=MhsSafetyContract(read_only=True, estop_required=None),
            ),
            dependencies=["ros_robot_controller", "joint_state_pub", "controller manager"],
            next_action="read controller resources, limits, faults and estop state",
            sampling_plan=_sampling_plan(common, "landerpi-ros-robot-controller", structured=True),
            confidence=MhsConfidence.MEDIUM,
            evidence=[
                MhsEvidenceRef(
                    kind="software",
                    ref=f"{common}#software_stack/processes_of_interest",
                    statement="ros_robot_controller and joint_state_pub are running.",
                ),
                MhsEvidenceRef(
                    kind="software",
                    ref=f"{ros_graph}#/bindings/2",
                    statement=(
                        "/ros_robot_controller exposes battery state and "
                        "servo/motor command subscriptions."
                    ),
                ),
                MhsEvidenceRef(
                    kind="software",
                    ref=ros_payload,
                    statement="No joint-state payload was observed in the bounded read window.",
                ),
            ],
            sampling_contract=[
                "read controller manager state",
                "read joint_states topic metadata",
                "enumerate resource IDs, limits, faults and estop state",
            ],
            limitations=["No command or service call is enabled by this bundle."],
        ),
        MhsBundleDevice(
            manifest=_manifest(
                device_id="landerpi-servo-actuator",
                device_class=MhsDeviceClass.ACTUATOR,
                name="Servo actuator group",
                vendor="unknown",
                model="unknown (servo_controller)",
                channels=[
                    MhsChannel(
                        id="enabled", name="Actuator enabled", unit="bool", value_type="boolean"
                    ),
                    MhsChannel(
                        id="fault_active", name="Actuator fault", unit="bool", value_type="boolean"
                    ),
                    MhsChannel(
                        id="position_feedback_available",
                        name="Position feedback available",
                        unit="bool",
                        value_type="boolean",
                    ),
                    MhsChannel(
                        id="channel_count", name="Actuator channel count", unit="count", min_value=0
                    ),
                ],
                resources=[
                    "process:/servo_manager",
                    "serial:/dev/serial/by-id/usb-1a86_USB_Single_Serial_5B22016029-if00",
                    "serial:/dev/serial/by-id/usb-1a86_USB_Serial-if00-port0",
                ],
                state={"read": ["health", "faults", "limits", "feedback", "interlocks"]},
                transport={
                    "kind": "ros2-serial-controller",
                    "properties": {"node": "servo_controller", "device_identity": "pending"},
                },
                limits=[
                    "serial bridges are present but motor/servo protocol and "
                    "physical mapping are unknown"
                ],
                provenance=_provenance(
                    f"{common}#software_stack/processes_of_interest",
                    model="unknown",
                    serial="unknown",
                    resource_mapping="unknown",
                    safety="unknown",
                    interfaces="declared",
                ),
                relations=[
                    MhsRelation(
                        kind="driven_by",
                        target="landerpi-ros-robot-controller",
                        evidence_ids=[f"{common}#software_stack/processes_of_interest"],
                    )
                ],
                interfaces=[
                    MhsInterfaceDescriptor(
                        id="feedback",
                        kind="joint_state",
                        access="stream",
                        transport_ref="ros2:///controller_manager/servo_states",
                        encoding="sensor_msgs/JointState",
                        timestamp="source",
                    )
                ],
                safety=MhsSafetyContract(read_only=True, estop_required=None),
            ),
            dependencies=["/servo_manager", "serial bridge", "robot controller"],
            next_action="map serial bridge to actuator resources and read feedback/interlocks",
            sampling_plan=_sampling_plan(common, "landerpi-servo-actuator", structured=True),
            confidence=MhsConfidence.LOW,
            evidence=[
                MhsEvidenceRef(
                    kind="software",
                    ref=f"{common}#software_stack/processes_of_interest",
                    statement="The target exposes servo state through the ROS controller stack.",
                ),
                MhsEvidenceRef(
                    kind="software",
                    ref=f"{ros_graph}#/topics/~1controller_manager~1servo_states",
                    statement=(
                        "The controller graph exposes a servo state topic for feedback sampling."
                    ),
                ),
            ],
            sampling_contract=[
                "read controller/resource metadata only",
                "map serial by-id to controller resource",
                "observe feedback/fault/interlock state",
                "require human approval before any future write adapter",
            ],
            limitations=["This is an actuator candidate, not an authorization to move hardware."],
        ),
    ]
    return MhsBundle(robot_id="landerpi", source_discovery=common, devices=devices)


__all__ = [
    "LANDERPI_DRIVER_ID",
    "LANDERPI_DRIVER_VERSION",
    "LANDERPI_DRIVER_SHA256",
    "MhsBindingStatus",
    "MhsConfidence",
    "MhsEvidenceRef",
    "MhsSamplingAction",
    "MhsBundleDevice",
    "MhsBundle",
    "landerpi_mhs_bundle",
]
