"""Reusable, read-only ROS2 diagnosis chain for Trace Agent.

The plan deliberately separates graph discovery from data receipt.  A ROS2
graph can report an endpoint while a diagnostic process still receives no
messages (for example when Fast DDS shared-memory endpoints run as different
users).  Physical writes are never part of this plan.
"""

from __future__ import annotations

import math
from collections.abc import Mapping
from typing import Any, Literal

from pydantic import Field

from .contracts import MvpModel


class TraceDiagnosticStep(MvpModel):
    schema_version: Literal["rolo-trace-diagnostic-step/v1"] = "rolo-trace-diagnostic-step/v1"
    step_id: str = Field(pattern=r"^[A-Z][A-Z0-9_]{2,63}$")
    title: str = Field(min_length=1, max_length=160)
    argv: tuple[str, ...] = Field(min_length=1, max_length=32)
    timeout_s: float = Field(gt=0, le=60)
    read_only: Literal[True] = True
    pass_condition: str = Field(min_length=1, max_length=240)
    block_code: str = Field(pattern=r"^[A-Z][A-Z0-9_]{2,63}$")


class TraceDiagnosticPlan(MvpModel):
    schema_version: Literal["rolo-trace-diagnostic-plan/v1"] = "rolo-trace-diagnostic-plan/v1"
    plan_id: Literal["landerpi-odom-ekf/v1"] = "landerpi-odom-ekf/v1"
    steps: tuple[TraceDiagnosticStep, ...] = Field(min_length=1, max_length=16)
    physical_write_allowed: Literal[False] = False


class OdomEkfObservation(MvpModel):
    """Evidence collected by the plan, without shell output or credentials."""

    schema_version: Literal["rolo-odom-ekf-observation/v1"] = "rolo-odom-ekf-observation/v1"
    executor_user: str = Field(min_length=1, max_length=64)
    publisher_user: str | None = Field(default=None, max_length=64)
    rmw_implementation: str | None = Field(default=None, max_length=128)
    graph_publisher_count: int = Field(ge=0)
    graph_subscription_count: int = Field(ge=0)
    command_publisher_count: int = Field(default=0, ge=0)
    autonomous_source_confirmed: bool = False
    odom_raw_samples: int = Field(ge=0)
    odom_samples: int = Field(ge=0)
    imu_samples: int = Field(ge=0)
    tf_odom_base_available: bool = False
    raw_yaw_delta_rad: float | None = None
    ekf_yaw_delta_rad: float | None = None
    odom_pose_source: Literal["COMMAND_INTEGRATION", "MEASURED_FEEDBACK", "UNKNOWN"] = "UNKNOWN"
    raw_imu_orientation_valid: bool | None = None
    imu_orientation_covariance_valid: bool | None = None
    imu_orientation_covariance_status: Literal["VALID", "UNKNOWN_ALL_ZERO", "UNAVAILABLE_SENTINEL", "MALFORMED", "MIXED"] | None = None
    imu_use_mag: bool | None = None
    imu_absolute_yaw_available: bool | None = None
    imu_yaw_initialization: Literal["UNSET", "RELATIVE", "ABSOLUTE", "UNKNOWN"] = "UNKNOWN"
    reset_callback_error: str | None = Field(default=None, max_length=160)
    bringup_environment_complete: bool | None = None
    # The fields below preserve the evidence needed to distinguish a graph
    # endpoint from a live sample and a constant frame offset from a changing
    # yaw-rate disagreement.  They are optional so v1 observations captured
    # by older probes remain valid.
    observed_at: str | None = Field(default=None, max_length=64)
    duration_s: float | None = Field(default=None, gt=0, le=300)
    ros_domain_id: str | None = Field(default=None, max_length=32)
    executor_uid: int | None = Field(default=None, ge=0)
    node_names: list[str] = Field(default_factory=list, max_length=256)
    process_presence: dict[str, bool] = Field(default_factory=dict, max_length=16)
    service_names: list[str] = Field(default_factory=list, max_length=256)
    graph_topics: list[str] = Field(default_factory=list, max_length=256)
    graph: dict[str, Any] = Field(default_factory=dict, max_length=64)
    raw_publisher_nodes: list[str] = Field(default_factory=list, max_length=64)
    ekf_publisher_nodes: list[str] = Field(default_factory=list, max_length=64)
    command_publisher_nodes: list[str] = Field(default_factory=list, max_length=64)
    topic_rates_hz: dict[str, float | None] = Field(default_factory=dict, max_length=32)
    topic_max_gap_s: dict[str, float | None] = Field(default_factory=dict, max_length=32)
    topic_header_timestamp_quality: dict[str, str] = Field(default_factory=dict, max_length=32)
    topic_timestamp_regressions: dict[str, int] = Field(default_factory=dict, max_length=32)
    command_integrated_yaw_delta_rad: float | None = None
    command_to_raw_yaw_error_rad: float | None = None
    command_nonzero_samples: int | None = Field(default=None, ge=0)
    command_active_span_s: float | None = Field(default=None, ge=0)
    raw_yaw_initial_rad: float | None = None
    ekf_yaw_initial_rad: float | None = None
    imu_yaw_initial_rad: float | None = None
    imu_yaw_delta_rad: float | None = None
    # ``imu_yaw_delta_rad`` is reserved for covariance-valid orientation.
    # These fields retain relative-only quaternion/gyro evidence when the
    # IMU publishes an all-zero or unavailable orientation covariance.
    imu_quaternion_yaw_initial_rad: float | None = None
    imu_relative_yaw_delta_rad: float | None = None
    imu_gyro_integrated_yaw_delta_rad: float | None = None
    imu_gyro_mean_rad_s: float | None = None
    imu_gyro_streams: dict[str, float | None] = Field(default_factory=dict, max_length=8)
    imu_yaw_comparison_source: Literal["QUATERNION_RELATIVE", "NONE"] | None = None
    independent_motion_evidence: dict[str, Any] = Field(default_factory=dict, max_length=16)
    physical_motion_verified: bool | None = None
    motion_evidence_status: Literal["VERIFIED", "NOT_VERIFIED", "UNKNOWN"] | None = None
    motion_evidence_kind: str | None = Field(default=None, max_length=64)
    imu_yaw_rate_residual_rad_s: float | None = None
    imu_yaw_rate_residual_abs_rad_s: float | None = None
    raw_frame_ids: list[str] = Field(default_factory=list, max_length=16)
    raw_child_frame_ids: list[str] = Field(default_factory=list, max_length=16)
    ekf_frame_ids: list[str] = Field(default_factory=list, max_length=16)
    ekf_child_frame_ids: list[str] = Field(default_factory=list, max_length=16)
    imu_frame_ids: list[str] = Field(default_factory=list, max_length=16)
    frame_consistency: dict[str, Any] = Field(default_factory=dict, max_length=16)
    imu_valid_samples: int | None = Field(default=None, ge=0)
    imu_invalid_orientation_samples: int | None = Field(default=None, ge=0)
    imu_orientation_valid_ratio: float | None = Field(default=None, ge=0, le=1)
    imu_yaw_fused: bool | None = None
    yaw_relationship: dict[str, Any] | None = None
    imu_raw_yaw_relationship: dict[str, Any] | None = None
    tf_pairs: list[str] = Field(default_factory=list, max_length=256)
    reset_service_available: bool | None = None
    reset_topic_available: bool | None = None
    reset_probe_performed: bool = False
    reset_survival_verified: bool | None = None
    launch_environment: dict[str, Any] = Field(default_factory=dict, max_length=32)
    ekf_parameters: dict[str, Any] = Field(default_factory=dict, max_length=32)
    measurement_semantics: dict[str, Any] = Field(default_factory=dict, max_length=32)
    calibration: dict[str, Any] = Field(default_factory=dict, max_length=32)
    source_inference: str | None = Field(default=None, max_length=64)
    source_inference_confidence: Literal["HIGH", "MEDIUM", "LOW", "UNKNOWN"] = "UNKNOWN"
    limitations: list[str] = Field(default_factory=list, max_length=64)


class OdomEkfDiagnosis(MvpModel):
    schema_version: Literal["rolo-odom-ekf-diagnosis/v1"] = "rolo-odom-ekf-diagnosis/v1"
    status: Literal["READY", "BLOCKED", "INCONSISTENT", "UNKNOWN"]
    findings: tuple[str, ...] = Field(default_factory=tuple, max_length=32)
    missing_development: tuple[str, ...] = Field(default_factory=tuple, max_length=32)
    recommended_action: str = Field(min_length=1, max_length=320)


def build_odom_ekf_diagnostic_plan() -> TraceDiagnosticPlan:
    """Return the fixed command sequence Trace may execute on a customer host."""

    steps = (
        TraceDiagnosticStep(
            step_id="PROCESS_PRESENCE",
            title="bringup/odom/EKF presence",
            argv=("ros2", "node", "list", "--no-daemon"),
            timeout_s=10,
            pass_condition="bringup, odom_publisher and EKF are present",
            block_code="PROCESS_MISSING",
        ),
        TraceDiagnosticStep(
            step_id="TOPIC_GRAPH",
            title="EKF publisher/subscriber graph",
            argv=("ros2", "topic", "info", "/odom", "-v"),
            timeout_s=10,
            pass_condition="/odom has the expected EKF publisher and subscribers",
            block_code="GRAPH_INCOMPLETE",
        ),
        TraceDiagnosticStep(
            step_id="ODOM_RAW_GRAPH",
            title="raw odometry graph",
            argv=("ros2", "topic", "info", "/odom_raw", "-v"),
            timeout_s=10,
            pass_condition="/odom_raw has the expected raw odometry publisher",
            block_code="RAW_GRAPH_INCOMPLETE",
        ),
        TraceDiagnosticStep(
            step_id="ODOM_RAW_SAMPLE",
            title="raw odometry receipt",
            argv=("ros2", "topic", "echo", "/odom_raw", "--once"),
            timeout_s=8,
            pass_condition="at least one live /odom_raw sample is received",
            block_code="ODOM_RAW_SILENT",
        ),
        TraceDiagnosticStep(
            step_id="EKF_SAMPLE",
            title="EKF odometry receipt",
            argv=("ros2", "topic", "echo", "/odom", "--once"),
            timeout_s=8,
            pass_condition="at least one live /odom sample is received",
            block_code="EKF_SILENT",
        ),
        TraceDiagnosticStep(
            step_id="IMU_SAMPLE",
            title="IMU receipt",
            argv=("ros2", "topic", "echo", "/imu", "--once"),
            timeout_s=8,
            pass_condition="at least one live /imu sample is received",
            block_code="IMU_SILENT",
        ),
        TraceDiagnosticStep(
            step_id="TF_CHAIN",
            title="odom to base transform",
            argv=("ros2", "run", "tf2_ros", "tf2_echo", "odom", "base_footprint"),
            timeout_s=8,
            pass_condition="odom→base_footprint transform is available",
            block_code="TF_MISSING",
        ),
        TraceDiagnosticStep(
            step_id="COMMAND_EXCLUSIVITY",
            title="autonomous cmd_vel source",
            argv=("ros2", "topic", "info", "/controller/cmd_vel", "-v"),
            timeout_s=8,
            pass_condition="the designated autonomous command source is confirmed and graph counts are recorded",
            block_code="COMMAND_SOURCE_UNVERIFIED",
        ),
        TraceDiagnosticStep(
            step_id="IDENTITY_CONSISTENCY",
            title="executor identity consistency",
            argv=("id", "-un"),
            timeout_s=5,
            pass_condition="diagnostic executor uses the same OS user as ROS publishers",
            block_code="DDS_USER_MISMATCH",
        ),
        TraceDiagnosticStep(
            step_id="SENSOR_SEMANTICS",
            title="EKF and IMU measurement semantics",
            argv=("ros2", "param", "dump", "/ekf_filter_node"),
            timeout_s=10,
            pass_condition="the EKF input configuration and IMU yaw observability can be identified",
            block_code="SENSOR_SEMANTICS_UNKNOWN",
        ),
        TraceDiagnosticStep(
            step_id="INITIAL_HEADING",
            title="initial heading evidence",
            argv=("ros2", "topic", "echo", "/imu", "--once"),
            timeout_s=8,
            pass_condition="an IMU sample is captured so its orientation validity and startup heading contract can be assessed",
            block_code="IMU_YAW_UNOBSERVABLE",
        ),
        TraceDiagnosticStep(
            step_id="RESET_SURVIVAL",
            title="odom reset topic contract",
            argv=("ros2", "topic", "info", "/set_odom", "-v"),
            timeout_s=8,
            pass_condition="the vendor reset Pose2D topic and odom subscriber are discoverable; callback survival requires a separately controlled staging probe",
            block_code="ODOM_RESET_CALLBACK_CRASH",
        ),
        TraceDiagnosticStep(
            step_id="BRINGUP_ENVIRONMENT",
            title="bringup environment contract",
            argv=("env",),
            timeout_s=5,
            pass_condition="all launch-required machine environment variables are present",
            block_code="BRINGUP_ENV_MISSING",
        ),
    )
    return TraceDiagnosticPlan(steps=steps)


def assess_odom_ekf_observation(observation: OdomEkfObservation, *, yaw_tolerance_rad: float = 0.15) -> OdomEkfDiagnosis:
    """Classify evidence and expose missing implementation work to Trace."""

    findings: list[str] = []
    missing: list[str] = []
    if observation.publisher_user and observation.publisher_user != observation.executor_user:
        findings.append("DDS_USER_MISMATCH")
        missing.append("run ROS diagnostics as the publisher OS user or disable cross-user shared-memory isolation")
    if observation.graph_publisher_count == 0:
        findings.append("ODOM_PUBLISHER_ABSENT")
    if observation.graph_subscription_count == 0:
        findings.append("ODOM_SUBSCRIBER_ABSENT")
    # A publisher in the graph with no received sample (or a sample with no
    # publisher in the same snapshot) is a distinct failure mode.  It often
    # means the diagnostic process ran under a different OS user or DDS
    # discovery had not converged yet; treating it as healthy is unsafe.
    if (observation.graph_publisher_count > 0 and observation.odom_samples == 0) or (observation.graph_publisher_count == 0 and observation.odom_samples > 0):
        findings.append("GRAPH_RECEIPT_MISMATCH")
        missing.append("repeat graph and receipt capture under the publisher OS user after DDS discovery settles")
    if observation.command_publisher_count > 1:
        findings.append("COMMAND_PUBLISHER_COUNT_RECORDED")
        if not observation.autonomous_source_confirmed:
            findings.append("COMMAND_MULTIPLE_PUBLISHERS")
            missing.append("identify and confirm the designated autonomous command source before any physical canary")
    if observation.odom_raw_samples == 0:
        findings.append("ODOM_RAW_SILENT")
        missing.append("capture live /odom_raw samples in the same ROS domain and OS user as the publisher")
    if observation.odom_samples == 0:
        findings.append("EKF_SILENT")
        missing.append("capture live /odom samples and verify the EKF process remains alive")
    if observation.imu_samples == 0:
        findings.append("IMU_SILENT")
        missing.append("capture live /imu samples before making any heading or calibration claim")
    if observation.physical_motion_verified is False:
        findings.append("PHYSICAL_MOTION_UNVERIFIED")
        missing.append("require an independent IMU/encoder motion response; command-path and EKF deltas alone are not proof of chassis rotation")
    if observation.motion_evidence_kind == "IMU_STREAMS_DISAGREE":
        findings.append("IMU_STREAMS_DISAGREE")
        missing.append("reconcile raw, corrected and filtered IMU yaw-rate sign/scale before accepting a rotation result")
    if observation.odom_pose_source == "COMMAND_INTEGRATION":
        findings.append("ODOM_OPEN_LOOP_COMMAND_INTEGRATION")
        missing.append("replace command integration with measured wheel/odometry feedback, or explicitly mark rotation as open-loop")
    elif observation.odom_raw_samples > 0 and observation.odom_pose_source == "UNKNOWN":
        findings.append("ODOM_SOURCE_UNVERIFIED")
        missing.append("capture source code/parameters or a command-integral fit before treating /odom_raw as measured feedback")
    if observation.source_inference == "COMMAND_INTEGRAL_FIT" and observation.odom_pose_source != "COMMAND_INTEGRATION":
        findings.append("ODOM_COMMAND_INTEGRATION_EVIDENCE")
        missing.append("review the command-integral fit and label /odom_raw semantics explicitly")
    # Invalid orientation metadata matters to this gate only when the EKF is
    # configured to consume IMU orientation.  A vyaw-only filter can carry a
    # REP-145 unavailable orientation without making its yaw-rate path
    # invalid; keep that distinction explicit in Trace.
    imu_orientation_relevant = observation.imu_yaw_fused is not False
    if observation.raw_imu_orientation_valid is False and imu_orientation_relevant:
        findings.append("IMU_ORIENTATION_INVALID")
        missing.append("provide a non-zero, frame-correct orientation or explicitly disable IMU orientation yaw fusion")
    if observation.imu_orientation_covariance_valid is False and imu_orientation_relevant:
        findings.append("IMU_ORIENTATION_COVARIANCE_INVALID")
        missing.append("remove the REP-145 orientation-unavailable sentinel or disable orientation yaw fusion")
    if observation.imu_use_mag is False and observation.imu_absolute_yaw_available is not True:
        # If EKF explicitly disables the IMU yaw bit, lack of an absolute
        # heading is expected and should not by itself block a vyaw-only
        # configuration.  Older observations lack ``imu_yaw_fused`` and keep
        # the conservative behaviour.
        if observation.imu_yaw_fused is not False:
            findings.append("IMU_YAW_UNOBSERVABLE")
            missing.append("provide a calibrated absolute heading or disable absolute IMU yaw fusion and initialize a relative yaw")
    if observation.imu_samples > 0 and (observation.imu_absolute_yaw_available is None or observation.imu_yaw_initialization == "UNKNOWN"):
        findings.append("IMU_YAW_SEMANTICS_UNKNOWN")
        missing.append("record whether /imu orientation is absolute, relative, or unavailable; finite quaternion data alone is insufficient")
    if observation.imu_yaw_initialization == "UNSET":
        findings.append("IMU_INITIAL_HEADING_UNSET")
        missing.append("define the startup heading contract and record the initial yaw used by the filter")
    if observation.reset_callback_error:
        findings.append("ODOM_RESET_CALLBACK_CRASH")
        missing.append("exercise set_odom in a read-only-safe staging path and verify the publisher process survives the callback")
    if observation.reset_service_available and not observation.reset_probe_performed:
        findings.append("RESET_SURVIVAL_UNVERIFIED")
        missing.append("run the separately authorized bounded set_odom survival probe and record publisher liveness")
    if observation.reset_topic_available and not observation.reset_probe_performed:
        findings.append("RESET_SURVIVAL_UNVERIFIED")
        missing.append("run the separately authorized bounded /set_odom topic probe and record odom publisher liveness")
    if observation.reset_probe_performed and observation.reset_survival_verified is False:
        findings.append("ODOM_RESET_CALLBACK_CRASH")
        missing.append("repair the reset callback before any physical canary")
    if observation.bringup_environment_complete is False:
        findings.append("BRINGUP_ENV_MISSING")
        missing.append("capture and validate need_compile, MACHINE_TYPE, LIDAR_TYPE and DEPTH_CAMERA_TYPE before launch")
    if not observation.tf_odom_base_available:
        findings.append("TF_MISSING")
    if observation.raw_yaw_delta_rad is not None and observation.ekf_yaw_delta_rad is not None:
        delta_error = abs(
            math.atan2(
                math.sin(observation.raw_yaw_delta_rad - observation.ekf_yaw_delta_rad),
                math.cos(observation.raw_yaw_delta_rad - observation.ekf_yaw_delta_rad),
            )
        )
        if delta_error > yaw_tolerance_rad:
            findings.append("EKF_RAW_YAW_INCONSISTENT")
            missing.append("validate IMU yaw frame/covariance and fuse wheel yaw without an unverified absolute heading")
    frame_status = observation.frame_consistency.get("status") if isinstance(observation.frame_consistency, Mapping) else None
    if frame_status == "ODOM_FRAME_MISMATCH":
        findings.append("ODOM_FRAME_MISMATCH")
        missing.append("align odom/EKF parent and child frame IDs or publish and verify the required static transform")
    relationship = observation.yaw_relationship or {}
    classification = relationship.get("classification") if isinstance(relationship, Mapping) else None
    if classification == "CONSTANT_OFFSET":
        findings.append("EKF_RAW_YAW_CONSTANT_OFFSET")
        missing.append("define and record the initial frame/heading alignment; a constant offset is not evidence of yaw-rate agreement failure")
    elif classification == "DIVERGING" and "EKF_RAW_YAW_INCONSISTENT" not in findings:
        findings.append("EKF_RAW_YAW_INCONSISTENT")
        missing.append("compare synchronized yaw increments and inspect EKF measurement masks/covariances")
    imu_relationship = observation.imu_raw_yaw_relationship or {}
    imu_classification = imu_relationship.get("classification") if isinstance(imu_relationship, Mapping) else None
    if imu_classification == "DIVERGING":
        findings.append("IMU_RAW_YAW_INCONSISTENT")
        missing.append("calibrate IMU axes/bias and verify the IMU frame and yaw source before fusing orientation")
    elif imu_classification == "CONSTANT_OFFSET":
        findings.append("IMU_RAW_YAW_CONSTANT_OFFSET")
        missing.append("record the startup heading/frame alignment between IMU orientation and odom")
    if observation.command_to_raw_yaw_error_rad is not None and abs(observation.command_to_raw_yaw_error_rad) > yaw_tolerance_rad:
        findings.append("COMMAND_RAW_YAW_MISMATCH")
        missing.append("synchronize command and odom timestamps and determine whether /odom_raw is measured or command-integrated")
    if observation.imu_yaw_rate_residual_abs_rad_s is not None and observation.imu_yaw_rate_residual_abs_rad_s > 0.1 and observation.imu_yaw_fused is not False:
        findings.append("IMU_YAW_RATE_CALIBRATION_MISMATCH")
        missing.append("calibrate gyro scale/sign/bias and verify orientation update timing before fusing IMU yaw")
    if observation.topic_rates_hz:
        for topic, rate in observation.topic_rates_hz.items():
            if rate is not None and rate <= 0:
                findings.append("TOPIC_RATE_INVALID")
                missing.append(f"restore a positive receipt rate for {topic}")
    if any(value in {"NON_MONOTONIC", "ZERO"} for value in observation.topic_header_timestamp_quality.values()):
        findings.append("ROS_TIMESTAMP_INVALID")
        missing.append("repair publisher header timestamps or use a documented clock source before comparing yaw streams")
    if any(value > 0 for value in observation.topic_timestamp_regressions.values()):
        findings.append("ROS_TIMESTAMP_REGRESSION")
        missing.append("investigate ROS clock jumps and synchronize timestamp bases")
    if observation.calibration:
        sensor_status = observation.calibration.get("sensor_calibration_status")
        if sensor_status == "ABSENT":
            findings.append("IMU_SENSOR_CALIBRATION_MISSING")
            missing.append("supply the calibrated IMU scale/misalignment and bias artifact, then record its digest")
        heading_status = observation.calibration.get("heading_calibrated")
        if heading_status is False and observation.imu_yaw_fused is not False:
            findings.append("IMU_HEADING_CALIBRATION_MISSING")
            missing.append("calibrate/declare an absolute heading source or disable IMU orientation yaw fusion")
    if findings:
        status = (
            "INCONSISTENT"
            if any(
                code in findings
                for code in (
                    "EKF_RAW_YAW_INCONSISTENT",
                    "EKF_RAW_YAW_CONSTANT_OFFSET",
                    "IMU_RAW_YAW_INCONSISTENT",
                    "IMU_RAW_YAW_CONSTANT_OFFSET",
                    "IMU_ORIENTATION_COVARIANCE_INVALID",
                    "IMU_YAW_UNOBSERVABLE",
                    "IMU_SENSOR_CALIBRATION_MISSING",
                    "IMU_HEADING_CALIBRATION_MISSING",
                    "ODOM_OPEN_LOOP_COMMAND_INTEGRATION",
                    "ODOM_COMMAND_INTEGRATION_EVIDENCE",
                    "COMMAND_RAW_YAW_MISMATCH",
                    "IMU_YAW_RATE_CALIBRATION_MISMATCH",
                    "IMU_STREAMS_DISAGREE",
                    "ODOM_FRAME_MISMATCH",
                    "ROS_TIMESTAMP_INVALID",
                    "ROS_TIMESTAMP_REGRESSION",
                )
            )
            else "BLOCKED"
        )
        action = "resolve the listed runtime gates, repeat the read-only chain, then admit rotation canary"
    else:
        status = "READY"
        action = "all odom/EKF read-only gates passed; a separate supervised rotation canary may be considered"
    return OdomEkfDiagnosis(status=status, findings=tuple(findings), missing_development=tuple(missing), recommended_action=action)


def observation_from_trace_payload(payload: Mapping[str, Any]) -> OdomEkfObservation:
    """Project a ``landerpi_odom_trace.py`` artifact into the Trace model.

    The projection deliberately accepts only the nested observation plus a
    small legacy fallback.  It never turns a missing graph/sample into a
    success value, which keeps old probe artifacts useful without weakening
    the evidence boundary.
    """

    if not isinstance(payload, Mapping):
        raise ValueError("trace payload must be an object")
    nested = payload.get("observation")
    if isinstance(nested, Mapping):
        data = dict(nested)
    elif payload.get("schema_version") == "rolo-landerpi-rotation-canary/v1":
        # A supervised canary is a motion artifact, not a replacement for the
        # read-only odom probe.  Project only the facts it actually contains;
        # leave IMU absolute-heading, TF, and measured-source semantics
        # unknown so the diagnosis cannot turn a successful Twist publish into
        # a false sensor PASS.
        graph = payload.get("graph") if isinstance(payload.get("graph"), Mapping) else {}
        records = payload.get("sample_records") if isinstance(payload.get("sample_records"), Mapping) else {}
        raw_records = records.get("odom_raw") if isinstance(records.get("odom_raw"), list) else []
        ekf_records = records.get("odom") if isinstance(records.get("odom"), list) else []
        imu_records = records.get("imu") if isinstance(records.get("imu"), list) else []
        command_graph = graph.get(payload.get("command_topic", "/controller/cmd_vel"))
        if not isinstance(command_graph, Mapping):
            command_graph = graph.get("/controller/cmd_vel") if isinstance(graph.get("/controller/cmd_vel"), Mapping) else {}
        odom_graph = graph.get(payload.get("feedback_topic", "/odom"))
        if not isinstance(odom_graph, Mapping):
            odom_graph = graph.get("/odom") if isinstance(graph.get("/odom"), Mapping) else {}
        raw_graph = graph.get("/odom_raw") if isinstance(graph.get("/odom_raw"), Mapping) else {}

        def finite_value(value: Any) -> float | None:
            try:
                result = float(value)
            except (TypeError, ValueError):
                return None
            return result if math.isfinite(result) else None

        def first_value(items: list[Any], field: str = "yaw") -> float | None:
            for item in items:
                if isinstance(item, Mapping):
                    value = finite_value(item.get(field))
                    if value is not None:
                        return value
            return None

        def count_valid(items: list[Any], field: str = "yaw") -> int:
            return sum(1 for item in items if isinstance(item, Mapping) and finite_value(item.get(field)) is not None)

        # ``quaternion_valid`` only says that the numeric quaternion is
        # non-zero.  It is deliberately *not* an absolute-orientation claim;
        # use the covariance-backed ``orientation_valid`` bit for that field.
        imu_valid = [item for item in imu_records if isinstance(item, Mapping) and item.get("orientation_valid") is True]
        imu_covariance_valid = [item for item in imu_records if isinstance(item, Mapping) and item.get("orientation_covariance_valid") is True]
        reset_graph = graph.get("/set_odom") if isinstance(graph.get("/set_odom"), Mapping) else {}
        motion_evidence = payload.get("independent_motion_evidence")
        if not isinstance(motion_evidence, Mapping):
            motion_evidence = {}
        relationship = payload.get("yaw_relationship") if isinstance(payload.get("yaw_relationship"), Mapping) else None
        imu_relationship = payload.get("imu_raw_yaw_relationship") if isinstance(payload.get("imu_raw_yaw_relationship"), Mapping) else None
        data = {
            "schema_version": "rolo-odom-ekf-observation/v1",
            "executor_user": str(payload.get("executor_user") or "unknown"),
            "publisher_user": payload.get("publisher_user"),
            "rmw_implementation": payload.get("rmw_implementation"),
            "graph_publisher_count": int(odom_graph.get("publisher_count", 0) or 0),
            "graph_subscription_count": int(odom_graph.get("subscription_count", 0) or 0),
            "command_publisher_count": int(command_graph.get("publisher_count", 0) or 0),
            "autonomous_source_confirmed": bool(payload.get("autonomous_source_confirmed", False)),
            "odom_raw_samples": len(raw_records),
            "odom_samples": len(ekf_records),
            "imu_samples": len(imu_records),
            "tf_odom_base_available": False,
            "raw_yaw_delta_rad": finite_value(payload.get("raw_yaw_delta_rad")),
            "ekf_yaw_delta_rad": finite_value(payload.get("ekf_yaw_delta_rad")),
            "odom_pose_source": "UNKNOWN",
            "raw_imu_orientation_valid": bool(imu_records) and len(imu_valid) == len(imu_records),
            "imu_orientation_covariance_valid": bool(imu_records) and len(imu_covariance_valid) == len(imu_records),
            "imu_orientation_covariance_status": payload.get("imu_orientation_covariance_status"),
            "imu_absolute_yaw_available": None,
            "imu_yaw_initialization": "UNKNOWN",
            "observed_at": payload.get("observed_at"),
            "duration_s": finite_value(payload.get("motion_window_duration_s")) or finite_value(payload.get("duration_limit_s")),
            "node_names": list(payload.get("nodes", [])) if isinstance(payload.get("nodes"), list) else [],
            "graph_topics": list(graph.keys()),
            "graph": dict(graph),
            "raw_publisher_nodes": list(raw_graph.get("publisher_nodes", [])),
            "ekf_publisher_nodes": list(odom_graph.get("publisher_nodes", [])),
            "command_publisher_nodes": list(command_graph.get("publisher_nodes", [])),
            "command_integrated_yaw_delta_rad": finite_value(payload.get("command_integrated_yaw_delta_rad")),
            "command_to_raw_yaw_error_rad": finite_value(payload.get("command_to_raw_yaw_error_rad")),
            "command_nonzero_samples": int(payload.get("published_command_nonzero_samples", payload.get("command_nonzero_samples", 0)) or 0),
            "raw_yaw_initial_rad": first_value(raw_records),
            "ekf_yaw_initial_rad": first_value(ekf_records),
            "imu_yaw_initial_rad": first_value(imu_records),
            "imu_yaw_delta_rad": finite_value(payload.get("imu_yaw_delta_rad")),
            "imu_quaternion_yaw_initial_rad": first_value(imu_records, "quaternion_yaw"),
            "imu_relative_yaw_delta_rad": finite_value(payload.get("imu_relative_yaw_delta_rad")),
            "imu_gyro_integrated_yaw_delta_rad": finite_value(payload.get("imu_gyro_integrated_yaw_delta_rad")),
            "imu_gyro_mean_rad_s": finite_value(payload.get("imu_gyro_mean_rad_s")),
            "imu_gyro_streams": {
                str(name): finite_value(value) for name, value in (motion_evidence.get("gyro_deltas_rad", {}) if isinstance(motion_evidence.get("gyro_deltas_rad", {}), Mapping) else {}).items()
            },
            "imu_yaw_comparison_source": payload.get("imu_yaw_comparison_source")
            or ("QUATERNION_RELATIVE" if any(isinstance(item, Mapping) and finite_value(item.get("quaternion_yaw")) is not None for item in imu_records) else "NONE"),
            "physical_motion_verified": (bool(motion_evidence.get("status") == "VERIFIED") if motion_evidence else None),
            "motion_evidence_status": (str(motion_evidence.get("status")) if motion_evidence.get("status") in {"VERIFIED", "NOT_VERIFIED"} else None),
            "motion_evidence_kind": (str(motion_evidence.get("kind")) if motion_evidence.get("kind") is not None else None),
            "independent_motion_evidence": dict(motion_evidence),
            "imu_valid_samples": len(imu_valid),
            "imu_invalid_orientation_samples": len(imu_records) - len(imu_valid),
            "imu_orientation_valid_ratio": len(imu_valid) / len(imu_records) if imu_records else None,
            "yaw_relationship": dict(relationship) if relationship is not None else None,
            "imu_raw_yaw_relationship": dict(imu_relationship) if imu_relationship is not None else None,
            "reset_topic_available": bool(reset_graph.get("publisher_count", 0) or reset_graph.get("subscription_count", 0)),
            "reset_service_available": None,
            "reset_probe_performed": False,
            "reset_survival_verified": None,
            "source_inference": None,
            "limitations": [
                "rotation canary artifact; no absolute IMU heading contract was supplied",
                "motor command-path evidence is not encoder feedback or proof of wheel motion",
                "TF and reset survival were not exercised by the canary",
            ],
        }
    else:
        graph = payload.get("graph") if isinstance(payload.get("graph"), Mapping) else {}
        odom_graph = graph.get("/odom") if isinstance(graph.get("/odom"), Mapping) else {}
        raw_graph = graph.get("/odom_raw") if isinstance(graph.get("/odom_raw"), Mapping) else {}
        command_graph = graph.get("/controller/cmd_vel") if isinstance(graph.get("/controller/cmd_vel"), Mapping) else {}
        series = payload.get("series") if isinstance(payload.get("series"), Mapping) else {}

        def count(name: str) -> int:
            value = series.get(name)
            return int(value.get("count", 0)) if isinstance(value, Mapping) else 0

        def value(name: str, field: str) -> float | None:
            item = series.get(name)
            if not isinstance(item, Mapping):
                return None
            candidate = item.get(field)
            return float(candidate) if isinstance(candidate, (int, float)) and math.isfinite(float(candidate)) else None

        raw_first = value("odom_raw_yaw", "first")
        raw_last = value("odom_raw_yaw", "last")
        ekf_first = value("odom_yaw", "first")
        ekf_last = value("odom_yaw", "last")
        relationship = None
        if raw_first is not None and raw_last is not None and ekf_first is not None and ekf_last is not None:
            raw_delta = raw_last - raw_first
            ekf_delta = ekf_last - ekf_first
            offset = math.atan2(math.sin(ekf_first - raw_first), math.cos(ekf_first - raw_first))
            delta_error = math.atan2(math.sin(ekf_delta - raw_delta), math.cos(ekf_delta - raw_delta))
            relationship = {
                "first_samples": count("odom_raw_yaw"),
                "second_samples": count("odom_yaw"),
                "initial_offset_rad": offset,
                "first_delta_rad": raw_delta,
                "second_delta_rad": ekf_delta,
                "delta_error_rad": delta_error,
                "classification": "ALIGNED" if abs(offset) <= 0.15 and abs(delta_error) <= 0.15 else "CONSTANT_OFFSET" if abs(delta_error) <= 0.15 else "DIVERGING",
            }

        data = {
            "schema_version": "rolo-odom-ekf-observation/v1",
            "executor_user": str(payload.get("executor_user") or "unknown"),
            "publisher_user": payload.get("publisher_user"),
            "rmw_implementation": payload.get("rmw_implementation"),
            "graph_publisher_count": int(odom_graph.get("publisher_count", 0) or 0),
            "graph_subscription_count": int(odom_graph.get("subscription_count", 0) or 0),
            "command_publisher_count": int(command_graph.get("publisher_count", 0) or 0),
            "odom_raw_samples": count("odom_raw_yaw"),
            "odom_samples": count("odom_yaw"),
            "imu_samples": count("imu_vyaw"),
            "tf_odom_base_available": False,
            "raw_yaw_delta_rad": value("odom_raw_yaw", "delta"),
            "ekf_yaw_delta_rad": value("odom_yaw", "delta"),
            "raw_yaw_initial_rad": raw_first,
            "ekf_yaw_initial_rad": ekf_first,
            "yaw_relationship": relationship,
            "raw_publisher_nodes": list(raw_graph.get("publisher_nodes", [])),
            "ekf_publisher_nodes": list(odom_graph.get("publisher_nodes", [])),
            "command_publisher_nodes": list(command_graph.get("publisher_nodes", [])),
            "graph": dict(graph),
            "reset_topic_available": bool(
                (graph.get("/set_odom", {}).get("publisher_count", 0) if isinstance(graph.get("/set_odom"), Mapping) else 0)
                or (graph.get("/set_odom", {}).get("subscription_count", 0) if isinstance(graph.get("/set_odom"), Mapping) else 0)
            ),
        }
    # Do not let a top-level probe marker override the nested schema version.
    data.setdefault("schema_version", "rolo-odom-ekf-observation/v1")
    try:
        return OdomEkfObservation.model_validate(data)
    except Exception as exc:
        raise ValueError(f"invalid odom/EKF trace observation: {exc}") from exc


def diagnose_trace_payload(payload: Mapping[str, Any], *, yaw_tolerance_rad: float = 0.15) -> OdomEkfDiagnosis:
    """Build and assess one read-only trace artifact in a single call."""

    return assess_odom_ekf_observation(observation_from_trace_payload(payload), yaw_tolerance_rad=yaw_tolerance_rad)


__all__ = [
    "TraceDiagnosticStep",
    "TraceDiagnosticPlan",
    "OdomEkfObservation",
    "OdomEkfDiagnosis",
    "build_odom_ekf_diagnostic_plan",
    "assess_odom_ekf_observation",
    "observation_from_trace_payload",
    "diagnose_trace_payload",
]
