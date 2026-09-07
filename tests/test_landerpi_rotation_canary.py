from __future__ import annotations

import math

import pytest

from rolo.mvp.bounded_twist import goal_tolerance_rad as bounded_twist_goal_tolerance_rad
from scripts.landerpi_rotation_canary import (
    _motor_message_summary,
    _relationship,
    classify_independent_motion,
    goal_tolerance_rad,
    imu_yaw_evidence,
    integrate_angular_velocity,
    motion_observation_duration_s,
    orientation_covariance_status,
    orientation_covariance_valid,
    run_canary,
)


def test_blocked_canary_is_side_effect_free_and_keeps_request_evidence() -> None:
    result = run_canary(5, 0.03, duration_s=10, autonomous_source_confirmed=False)
    assert result["status"] == "BLOCKED"
    assert result["error"] == "AUTONOMOUS_SOURCE_NOT_CONFIRMED"
    assert result["motion_started"] is False
    assert result["motor_topic"] == "/ros_robot_controller/set_motor"
    assert result["motor_is_encoder_feedback"] is False
    assert result["motor_evidence_kind"] == "GRAPH_ONLY_OR_UNAVAILABLE"
    assert result["imu_orientation_covariance_status"] is None
    assert result["sample_records"]["published_cmd_vel"] == []


def test_covariance_sentinel_and_malformed_values_are_not_absolute_heading() -> None:
    assert orientation_covariance_valid([0.0] * 9) is False
    assert orientation_covariance_status([0.0] * 9) == "UNKNOWN_ALL_ZERO"
    assert orientation_covariance_status([0.1] + [0.0] * 8) == "VALID"
    assert orientation_covariance_valid([-1.0] + [0.0] * 8) is False
    assert orientation_covariance_status([-1.0] + [0.0] * 8) == "UNAVAILABLE_SENTINEL"
    assert orientation_covariance_valid([float("nan")] + [0.0] * 8) is False
    assert orientation_covariance_valid([0.0, float("nan")] + [0.0] * 7) is False
    assert orientation_covariance_valid([0.0] * 8) is False


def test_unknown_covariance_keeps_relative_quaternion_evidence() -> None:
    quaternion = type("Quaternion", (), {"x": 0.0, "y": 0.0, "z": 0.3826834324, "w": 0.9238795325})()
    evidence = imu_yaw_evidence(quaternion, [0.0] * 9)
    assert evidence["yaw"] is None
    assert evidence["quaternion_yaw"] == pytest.approx(0.7853981634)
    assert evidence["quaternion_valid"] is True
    assert evidence["orientation_valid"] is False
    assert evidence["yaw_semantics"] == "RELATIVE_ONLY"


def test_relationship_interpolates_common_receipt_window() -> None:
    raw = [{"t": 0.0, "yaw": 0.0}, {"t": 1.0, "yaw": 0.2}, {"t": 2.0, "yaw": 0.4}]
    ekf = [{"t": 0.5, "yaw": 1.0}, {"t": 1.5, "yaw": 1.2}, {"t": 2.5, "yaw": 1.4}]
    result = _relationship(raw, ekf)
    assert result["synchronized"] is True
    assert result["overlap_start_t"] == 0.5
    assert result["overlap_end_t"] == 2.0
    assert result["classification"] == "CONSTANT_OFFSET"
    assert result["first_delta_rad"] == pytest.approx(0.3)
    assert result["second_delta_rad"] == pytest.approx(0.3)


def test_relationship_detects_rate_divergence_without_index_pairing() -> None:
    raw = [{"t": 0.0, "yaw": 0.0}, {"t": 1.0, "yaw": 0.2}, {"t": 2.0, "yaw": 0.4}]
    ekf = [{"t": 0.5, "yaw": 1.0}, {"t": 1.5, "yaw": 1.5}, {"t": 2.5, "yaw": 2.0}]
    result = _relationship(raw, ekf)
    assert result["classification"] == "DIVERGING"
    assert result["delta_error_rad"] == pytest.approx(0.45)


def test_command_integral_excludes_failed_publish_attempt() -> None:
    records = [
        {"t": 0.0, "angular_z": 0.2, "published": False},
        {"t": 0.0, "angular_z": 0.0, "published": True},
        {"t": 1.0, "angular_z": 0.2, "published": True},
    ]
    assert integrate_angular_velocity(records) == pytest.approx(0.1)


def test_motor_summary_is_scalar_and_bounded() -> None:
    item = type("Motor", (), {"id": 2, "rps": 3.5, "value": float("nan")})()
    message = type("MotorsState", (), {"data": [item]})()
    summary = _motor_message_summary(message)
    assert summary["collection_field"] == "data"
    assert summary["motor_count"] == 1
    assert summary["motors"] == [{"id": 2.0, "rps": 3.5}]


def test_motor_summary_prefers_populated_data_over_empty_compatibility_field() -> None:
    item = type("Motor", (), {"motor_id": 4, "velocity": -1.25})()
    message = type("MotorsState", (), {"motors": [], "data": [item]})()
    summary = _motor_message_summary(message)
    assert summary["collection_field"] == "data"
    assert summary["motors"] == [{"motor_id": 4.0, "velocity": -1.25}]


def test_independent_motion_can_use_raw_imu_when_filter_is_stale() -> None:
    result = classify_independent_motion(
        0.0873,
        gyro_delta_rad=0.001,
        quaternion_delta_rad=None,
        gyro_deltas_rad={"imu": 0.001, "imu_corrected": 0.079, "imu_raw": 0.081},
    )
    assert result["status"] == "VERIFIED"
    assert result["selected_gyro_stream"] == "imu_raw"
    assert result["kind"] == "IMU_GYRO_MULTI_STREAM"


def test_independent_motion_rejects_opposite_sensor_sign() -> None:
    result = classify_independent_motion(
        -0.0873,
        gyro_delta_rad=-0.08,
        quaternion_delta_rad=None,
        gyro_deltas_rad={"imu": -0.08, "imu_raw": 0.08},
    )
    assert result["status"] == "NOT_VERIFIED"
    assert result["kind"] == "IMU_STREAMS_DISAGREE"
    assert "imu_raw" in result["opposing_gyro_streams"]


def test_one_degree_goal_uses_scaled_tolerance_instead_of_stopping_at_point_two() -> None:
    one_degree = math.radians(1)
    tolerance = pytest.approx(math.radians(0.2), abs=1e-12)
    assert goal_tolerance_rad(one_degree) == tolerance
    assert bounded_twist_goal_tolerance_rad(one_degree) == tolerance


def test_one_degree_fast_turn_uses_dynamic_observation_window() -> None:
    assert motion_observation_duration_s(math.radians(1), 0.1) == pytest.approx(0.2)
    assert motion_observation_duration_s(math.radians(1), 0.03) == pytest.approx(
        math.radians(1) / 0.03 * 0.5
    )


def test_small_angle_independent_motion_threshold_is_reachable_but_fail_closed() -> None:
    passing = classify_independent_motion(
        math.radians(1),
        gyro_delta_rad=0.012,
        quaternion_delta_rad=None,
        gyro_deltas_rad={"imu": 0.012},
    )
    assert passing["status"] == "VERIFIED"
    assert passing["threshold_rad"] < math.radians(1)

    below_threshold = classify_independent_motion(
        math.radians(1),
        gyro_delta_rad=0.004,
        quaternion_delta_rad=None,
        gyro_deltas_rad={"imu": 0.004},
    )
    assert below_threshold["status"] == "NOT_VERIFIED"
    assert below_threshold["kind"] == "IMU_BELOW_THRESHOLD"


def test_one_degree_opposite_stream_remains_not_verified() -> None:
    result = classify_independent_motion(
        math.radians(1),
        gyro_delta_rad=0.012,
        quaternion_delta_rad=None,
        gyro_deltas_rad={"imu": 0.012, "imu_raw": -0.012},
    )
    assert result["status"] == "NOT_VERIFIED"
    assert result["kind"] == "IMU_STREAMS_DISAGREE"
    assert result["opposing_gyro_streams"] == {"imu_raw": -0.012}


def test_one_degree_reverse_rotation_requires_negative_independent_delta() -> None:
    result = classify_independent_motion(
        -math.radians(1),
        gyro_delta_rad=-0.012,
        quaternion_delta_rad=None,
        gyro_deltas_rad={"imu": -0.012},
    )
    assert result["status"] == "VERIFIED"
    assert result["selected_gyro_stream"] == "imu"
