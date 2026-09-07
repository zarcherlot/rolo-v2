import math
from types import SimpleNamespace

from rolo.mvp import (
    OdomEkfObservation,
    assess_odom_ekf_observation,
    build_odom_ekf_diagnostic_plan,
    diagnose_trace_payload,
    observation_from_trace_payload,
)
from scripts.landerpi_odom_trace import (
    _parameter_value,
    compare_yaw_series,
    continuous_delta,
    estimate_imu_yaw_rate_residual,
    header_timestamp_quality,
    integrate_command_yaw,
    orientation_covariance_is_valid,
    quaternion_to_yaw,
)


def test_plan_is_read_only_and_has_receipt_gates() -> None:
    plan = build_odom_ekf_diagnostic_plan()
    ids = [step.step_id for step in plan.steps]
    assert plan.physical_write_allowed is False
    assert ids == [
        "PROCESS_PRESENCE",
        "TOPIC_GRAPH",
        "ODOM_RAW_GRAPH",
        "ODOM_RAW_SAMPLE",
        "EKF_SAMPLE",
        "IMU_SAMPLE",
        "TF_CHAIN",
        "COMMAND_EXCLUSIVITY",
        "IDENTITY_CONSISTENCY",
        "SENSOR_SEMANTICS",
        "INITIAL_HEADING",
        "RESET_SURVIVAL",
        "BRINGUP_ENVIRONMENT",
    ]
    assert all(step.read_only for step in plan.steps)


def test_cross_user_and_sensor_disagreement_is_inconsistent() -> None:
    result = assess_odom_ekf_observation(
        OdomEkfObservation(
            executor_user="root",
            publisher_user="ubuntu",
            rmw_implementation="rmw_fastrtps_cpp",
            graph_publisher_count=1,
            graph_subscription_count=1,
            command_publisher_count=1,
            autonomous_source_confirmed=True,
            odom_raw_samples=4,
            odom_samples=4,
            imu_samples=4,
            tf_odom_base_available=True,
            raw_yaw_delta_rad=0.02,
            ekf_yaw_delta_rad=1.2,
            odom_pose_source="COMMAND_INTEGRATION",
            raw_imu_orientation_valid=False,
            imu_use_mag=False,
            imu_absolute_yaw_available=False,
            imu_yaw_initialization="UNSET",
            reset_callback_error="ROSClock object is not callable",
            bringup_environment_complete=False,
        )
    )
    assert result.status == "INCONSISTENT"
    assert "DDS_USER_MISMATCH" in result.findings
    assert "EKF_RAW_YAW_INCONSISTENT" in result.findings
    assert "ODOM_OPEN_LOOP_COMMAND_INTEGRATION" in result.findings
    assert "IMU_YAW_UNOBSERVABLE" in result.findings
    assert "IMU_INITIAL_HEADING_UNSET" in result.findings
    assert "ODOM_RESET_CALLBACK_CRASH" in result.findings
    assert "BRINGUP_ENV_MISSING" in result.findings
    assert result.missing_development


def test_complete_receipt_chain_is_ready() -> None:
    result = assess_odom_ekf_observation(
        OdomEkfObservation(
            executor_user="ubuntu",
            publisher_user="ubuntu",
            rmw_implementation="rmw_fastrtps_cpp",
            graph_publisher_count=1,
            graph_subscription_count=1,
            command_publisher_count=1,
            autonomous_source_confirmed=True,
            odom_raw_samples=10,
            odom_samples=10,
            imu_samples=10,
            tf_odom_base_available=True,
            raw_yaw_delta_rad=0.1,
            ekf_yaw_delta_rad=0.12,
            odom_pose_source="MEASURED_FEEDBACK",
            raw_imu_orientation_valid=True,
            imu_use_mag=True,
            imu_absolute_yaw_available=True,
            imu_yaw_initialization="ABSOLUTE",
        )
    )
    assert result.status == "READY"


def test_yaw_comparison_separates_constant_offset_from_rate_disagreement() -> None:
    raw = [{"yaw": 0.0}, {"yaw": 0.2}, {"yaw": 0.4}]
    offset = [{"yaw": 1.0}, {"yaw": 1.2}, {"yaw": 1.4}]
    divergent = [{"yaw": 1.0}, {"yaw": 1.3}, {"yaw": 1.8}]
    assert compare_yaw_series(raw, offset)["classification"] == "CONSTANT_OFFSET"
    assert compare_yaw_series(raw, divergent)["classification"] == "DIVERGING"
    assert continuous_delta([3.0, -3.0]) > 0


def test_command_integral_is_explicit_open_loop_evidence() -> None:
    records = [
        {"t": 0.0, "angular_z": 0.5},
        {"t": 0.5, "angular_z": 0.5},
        {"t": 1.0, "angular_z": 0.0},
    ]
    assert integrate_command_yaw(records) == 0.375
    assert header_timestamp_quality([{"header_stamp_s": 1}, {"header_stamp_s": 2}]) == ("MONOTONIC", 0)
    assert header_timestamp_quality([{"header_stamp_s": 2}, {"header_stamp_s": 1}]) == ("NON_MONOTONIC", 1)


def test_zero_quaternion_is_not_absolute_heading() -> None:
    zero = SimpleNamespace(x=0.0, y=0.0, z=0.0, w=0.0)
    quarter_turn = SimpleNamespace(x=0.0, y=0.0, z=0.3826834324, w=0.9238795325)
    assert quaternion_to_yaw(zero) is None
    assert abs(quaternion_to_yaw(quarter_turn) - 0.7853981634) < 1e-6
    assert orientation_covariance_is_valid([-1.0] + [0.0] * 8) is False
    assert orientation_covariance_is_valid([0.1] + [0.0] * 8) is True
    assert orientation_covariance_is_valid([]) is None


def test_imu_yaw_rate_residual_exposes_gyro_bias_or_axis_mismatch() -> None:
    records = [
        {"t": 0.0, "yaw": 0.0, "angular_z": 0.0},
        {"t": 1.0, "yaw": 0.3, "angular_z": 0.0},
    ]
    result = estimate_imu_yaw_rate_residual(records)
    assert result["count"] == 1
    assert result["mean_rad_s"] == 0.3
    assert result["mean_abs_rad_s"] == 0.3


def test_ros_parameter_type_is_used_instead_of_default_scalar_members() -> None:
    # ParameterValue exposes all scalar members; only ``type`` identifies the
    # selected one.  This catches the old bug that decoded every bool as "".
    value = SimpleNamespace(type=1, bool_value=False, string_value="", integer_value=0, double_value=0.0)
    array = SimpleNamespace(type=7, integer_array_value=[5, 6], string_value="")
    assert _parameter_value(value) is False
    assert _parameter_value(array) == [5, 6]


def test_trace_projection_and_semantic_findings_are_replayable() -> None:
    payload = {
        "schema_version": "rolo-landerpi-odom-trace/v1",
        "executor_user": "ubuntu",
        "publisher_user": "ubuntu",
        "rmw_implementation": "rmw_fastrtps_cpp",
        "graph": {
            "/odom": {"publisher_count": 1, "subscription_count": 1, "publisher_nodes": ["/ekf_filter_node"]},
            "/odom_raw": {"publisher_count": 1, "subscription_count": 1, "publisher_nodes": ["/odom_publisher"]},
            "/controller/cmd_vel": {"publisher_count": 3, "subscription_count": 1, "publisher_nodes": ["/autonomy"]},
        },
        "series": {
            "odom_raw_yaw": {"count": 3, "first": 0.0, "last": 0.4, "delta": 0.4},
            "odom_yaw": {"count": 3, "first": 1.0, "last": 1.4, "delta": 0.4},
            "imu_vyaw": {"count": 3},
        },
    }
    observation = observation_from_trace_payload(payload)
    assert observation.odom_raw_samples == 3
    assert observation.command_publisher_count == 3
    result = diagnose_trace_payload(payload)
    assert "ODOM_SOURCE_UNVERIFIED" in result.findings
    assert "EKF_RAW_YAW_CONSTANT_OFFSET" in result.findings


def test_relative_imu_yaw_is_allowed_when_ekf_does_not_fuse_yaw() -> None:
    result = assess_odom_ekf_observation(
        OdomEkfObservation(
            executor_user="ubuntu",
            graph_publisher_count=1,
            graph_subscription_count=1,
            odom_raw_samples=3,
            odom_samples=3,
            imu_samples=3,
            tf_odom_base_available=True,
            odom_pose_source="COMMAND_INTEGRATION",
            imu_use_mag=False,
            imu_absolute_yaw_available=False,
            imu_yaw_initialization="RELATIVE",
            imu_yaw_fused=False,
        )
    )
    assert "IMU_YAW_UNOBSERVABLE" not in result.findings


def test_frame_and_timestamp_evidence_is_actionable() -> None:
    result = assess_odom_ekf_observation(
        OdomEkfObservation(
            executor_user="ubuntu",
            graph_publisher_count=1,
            graph_subscription_count=1,
            odom_raw_samples=3,
            odom_samples=3,
            imu_samples=3,
            tf_odom_base_available=True,
            odom_pose_source="MEASURED_FEEDBACK",
            imu_use_mag=True,
            imu_absolute_yaw_available=True,
            imu_yaw_initialization="ABSOLUTE",
            frame_consistency={"status": "ODOM_FRAME_MISMATCH"},
            topic_header_timestamp_quality={"/odom": "NON_MONOTONIC"},
        )
    )
    assert result.status == "INCONSISTENT"
    assert "ODOM_FRAME_MISMATCH" in result.findings
    assert "ROS_TIMESTAMP_INVALID" in result.findings


def test_large_wrapped_yaw_deltas_are_compared_as_angles() -> None:
    result = assess_odom_ekf_observation(
        OdomEkfObservation(
            executor_user="ubuntu",
            graph_publisher_count=1,
            graph_subscription_count=1,
            odom_raw_samples=3,
            odom_samples=3,
            imu_samples=3,
            tf_odom_base_available=True,
            odom_pose_source="MEASURED_FEEDBACK",
            imu_yaw_fused=False,
            raw_yaw_delta_rad=math.tau - 0.02,
            ekf_yaw_delta_rad=-0.02,
        )
    )
    assert "EKF_RAW_YAW_INCONSISTENT" not in result.findings


def test_rotation_canary_projects_into_the_same_trace_diagnosis() -> None:
    payload = {
        "schema_version": "rolo-landerpi-rotation-canary/v1",
        "observed_at": "2026-09-06T12:00:00Z",
        "status": "UNKNOWN",
        "autonomous_source_confirmed": True,
        "command_topic": "/controller/cmd_vel",
        "feedback_topic": "/odom",
        "duration_limit_s": 10.0,
        "motion_window_duration_s": 2.0,
            "raw_yaw_delta_rad": 0.4,
            "ekf_yaw_delta_rad": 0.4,
            "imu_yaw_delta_rad": 0.1,
            "imu_relative_yaw_delta_rad": 0.11,
            "imu_gyro_integrated_yaw_delta_rad": 0.10,
            "imu_yaw_comparison_source": "QUATERNION_RELATIVE",
        "command_integrated_yaw_delta_rad": 0.4,
        "command_to_raw_yaw_error_rad": 0.0,
        "published_command_nonzero_samples": 10,
        "graph": {
            "/controller/cmd_vel": {"publisher_count": 2, "subscription_count": 1, "publisher_nodes": ["/planner", "/rolo_rotation_canary"]},
            "/odom_raw": {"publisher_count": 1, "subscription_count": 1, "publisher_nodes": ["/odom_publisher"]},
            "/odom": {"publisher_count": 1, "subscription_count": 1, "publisher_nodes": ["/ekf_filter_node"]},
        },
        "sample_records": {
            "odom_raw": [{"t": 0.0, "yaw": 0.0}, {"t": 1.0, "yaw": 0.2}],
            "odom": [{"t": 0.0, "yaw": 0.0}, {"t": 1.0, "yaw": 0.2}],
            "imu": [{"t": 0.0, "yaw": None, "quaternion_yaw": 0.1, "quaternion_valid": True, "orientation_covariance_valid": False}],
        },
    }
    observation = observation_from_trace_payload(payload)
    assert observation.odom_raw_samples == 2
    assert observation.odom_samples == 2
    assert observation.command_publisher_count == 2
    assert observation.autonomous_source_confirmed is True
    assert observation.odom_pose_source == "UNKNOWN"
    assert observation.imu_relative_yaw_delta_rad == 0.11
    assert observation.imu_gyro_integrated_yaw_delta_rad == 0.10
    assert observation.imu_yaw_comparison_source == "QUATERNION_RELATIVE"
    assert observation.imu_quaternion_yaw_initial_rad == 0.1
    assert "ODOM_SOURCE_UNVERIFIED" in diagnose_trace_payload(payload).findings
