#!/usr/bin/env python3
"""Run one bounded LanderPi rotation and retain synchronized yaw evidence.

This is the only target-side motion entry point used by the field Trace
workflow.  It requires an explicit operator assertion that the autonomous
command source is the source under test, keeps speed/angle/time bounded, and
publishes zero Twist messages in every exit path.  The command topic may have
idle joystick/application publishers; their endpoint identities are retained
in the artifact, while the assertion controls whether the canary is admitted.

The runner intentionally records three independent yaw streams:

* ``/odom_raw``: the vendor odometry contract;
* ``/odom``: the EKF output;
* ``/imu``: the complementary-filter orientation and gyro rate.

A finite IMU quaternion is not treated as an absolute heading.  The report
contains initial offsets and synchronized deltas so Trace can distinguish a
constant startup/frame offset from a rate disagreement.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import sys
import time
from bisect import bisect_right
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "rolo-landerpi-rotation-canary/v1"
# The isolated vendor subscriber is the safe default.  The shared
# ``/controller/cmd_vel`` route remains available only through an explicit
# command-line override plus the supervised-source assertion.
DEFAULT_COMMAND_TOPIC = "/cmd_vel"
DEFAULT_FEEDBACK_TOPIC = "/odom"
DEFAULT_MOTOR_TOPIC = "/ros_robot_controller/set_motor"
DEFAULT_IMU_TOPIC = "/imu"
DEFAULT_IMU_CORRECTED_TOPIC = "/imu_corrected"
DEFAULT_IMU_RAW_TOPIC = "/ros_robot_controller/imu_raw"
MAX_ANGLE_DEGREES = 30.0
MAX_SPEED_RAD_S = 0.15
MAX_DURATION_S = 60.0
# The old fixed 0.8° tolerance made a 1° canary stop at 0.2° (the lower
# edge of the tolerance band) before the chassis had completed the requested
# turn.  Keep the historical 0.8° cap for larger turns, but scale the band
# for small, supervised calibration turns.
MIN_GOAL_TOLERANCE_RAD = math.radians(0.1)
MAX_GOAL_TOLERANCE_RAD = math.radians(0.8)
GOAL_TOLERANCE_FRACTION = 0.20
# 0.025 rad was larger than a 1° request (0.01745 rad), which made the
# independent-motion gate mathematically impossible to satisfy for the
# smallest documented canary.  0.005 rad remains above normal stationary
# integration noise while allowing a 1° physical turn to be verified.
MIN_INDEPENDENT_ROTATION_RAD = 0.005
YAW_COMPARISON_TOLERANCE_RAD = 0.15
# A 1° open-loop odometry goal is reached in roughly 0.1 s at the
# supervised speed cap, before the chassis/IMU has had time to respond.  Keep
# a bounded 0.2 s command-observation floor so the independent gyro stream can
# witness the acceleration; this still limits the open-loop odometry exposure
# to about 1.7° at the 0.15 rad/s cap.
MIN_MOTION_OBSERVATION_FLOOR_S = 0.20
MAX_MOTION_OBSERVATION_S = 0.50


def goal_tolerance_rad(goal_rad: float) -> float:
    """Return a bounded feedback tolerance appropriate for ``goal_rad``.

    A fixed angular tolerance is useful for larger turns but is unsafe for a
    1° canary: it permits the feedback loop to stop after only 0.2°.  Scaling
    by the requested magnitude preserves that bounded behavior while keeping
    a small floor for sensor quantization.
    """

    goal = abs(float(goal_rad))
    if not math.isfinite(goal) or goal <= 0:
        raise ValueError("goal_rad must be finite and positive")
    return min(
        MAX_GOAL_TOLERANCE_RAD,
        max(MIN_GOAL_TOLERANCE_RAD, goal * GOAL_TOLERANCE_FRACTION),
    )


def motion_observation_duration_s(goal_rad: float, speed_rad_s: float) -> float:
    """Bound the minimum observation window before accepting feedback.

    The previous fixed 0.5 s window was longer than the ideal 1° turn at the
    maximum canary speed and could force an unnecessary overshoot.  Retain a
    short safety floor and observe at least half of the ideal travel time,
    while capping the delay for larger turns.
    """

    goal = abs(float(goal_rad))
    speed = abs(float(speed_rad_s))
    if not math.isfinite(goal) or goal <= 0 or not math.isfinite(speed) or speed <= 0:
        raise ValueError("goal_rad and speed_rad_s must be finite and positive")
    return min(MAX_MOTION_OBSERVATION_S, max(MIN_MOTION_OBSERVATION_FLOOR_S, goal / speed * 0.5))


def _finite(value: Any) -> float | None:
    try:
        result = float(value)
    except (OverflowError, TypeError, ValueError):
        return None
    return result if math.isfinite(result) else None


def wrap_angle(value: float) -> float:
    value = float(value)
    if not math.isfinite(value):
        raise ValueError("angle must be finite")
    return math.atan2(math.sin(value), math.cos(value))


def quaternion_yaw(q: Any) -> float | None:
    values = [_finite(getattr(q, name, None)) for name in ("x", "y", "z", "w")]
    if any(value is None for value in values):
        return None
    x, y, z, w = values
    norm = math.sqrt(x * x + y * y + z * z + w * w)
    if not math.isfinite(norm) or norm < 1e-9:
        return None
    x, y, z, w = (value / norm for value in (x, y, z, w))
    return math.atan2(2.0 * (w * z + x * y), 1.0 - 2.0 * (y * y + z * z))


def stamp_seconds(message: Any) -> float | None:
    try:
        sec = _finite(message.header.stamp.sec)
        nanosec = _finite(message.header.stamp.nanosec)
    except AttributeError:
        return None
    if sec is None or nanosec is None:
        return None
    value = sec + nanosec * 1e-9
    return value if math.isfinite(value) else None


def orientation_covariance_status(covariance: Any) -> str:
    """Classify an IMU orientation covariance according to ROS semantics.

    ``orientation_covariance[0] == -1`` is the explicit unavailable sentinel.
    A matrix of all zeros means covariance is unknown (the quaternion may still
    be finite, but it is not a calibrated absolute-heading claim).  A short,
    empty, NaN, or otherwise malformed covariance is unusable as well.
    """

    try:
        values = list(covariance or ())
    except TypeError:
        return "MALFORMED"
    if len(values) < 9:
        return "MALFORMED"
    finite_values = [_finite(value) for value in values[:9]]
    if any(value is None for value in finite_values):
        return "MALFORMED"
    if finite_values[0] == -1.0:
        return "UNAVAILABLE_SENTINEL"
    if all(value == 0.0 for value in finite_values):
        return "UNKNOWN_ALL_ZERO"
    return "VALID"


def orientation_covariance_valid(covariance: Any) -> bool:
    """Return whether an IMU orientation covariance is explicitly usable."""

    return orientation_covariance_status(covariance) == "VALID"


def imu_yaw_evidence(quaternion: Any, covariance: Any) -> dict[str, Any]:
    """Separate absolute-heading candidates from relative quaternion evidence.

    A finite quaternion is still useful for estimating *relative* rotation
    even when REP-145 marks its covariance unknown/unavailable.  It must not,
    however, be promoted to an absolute heading in that case.  The caller
    therefore gets both ``yaw`` (usable only with an explicitly populated
    covariance) and ``quaternion_yaw`` (relative-only evidence).
    """

    quaternion_value = quaternion_yaw(quaternion)
    status = orientation_covariance_status(covariance)
    covariance_valid = status == "VALID"
    if covariance_valid and quaternion_value is not None:
        semantics = "ABSOLUTE_CANDIDATE"
    elif quaternion_value is not None:
        semantics = "RELATIVE_ONLY"
    else:
        semantics = "UNAVAILABLE"
    return {
        "yaw": quaternion_value if covariance_valid else None,
        "quaternion_yaw": quaternion_value,
        "quaternion_valid": quaternion_value is not None,
        "orientation_valid": covariance_valid and quaternion_value is not None,
        "orientation_covariance_valid": covariance_valid,
        "orientation_covariance_status": status,
        "yaw_semantics": semantics,
    }


def _timed_yaw_points(records: list[dict[str, Any]], key: str = "yaw") -> list[tuple[float, float]]:
    """Return sorted, unwrapped ``(receipt_time, yaw)`` points.

    The canary receives each topic in a different callback schedule.  Pairing
    samples by list index therefore creates false offsets whenever one topic
    starts later or runs at a different rate.  Receipt monotonic time is the
    common clock available to all callbacks, so comparisons interpolate on it.
    """

    points: list[tuple[float, float]] = []
    for record in records:
        t = _finite(record.get("t"))
        yaw = _finite(record.get(key))
        if t is None or yaw is None:
            continue
        points.append((t, yaw))
    points.sort(key=lambda item: item[0])
    # A callback can carry the same timestamp more than once.  Keep the most
    # recent value rather than creating a zero-duration interpolation segment.
    deduplicated: list[tuple[float, float]] = []
    for t, yaw in points:
        if deduplicated and t == deduplicated[-1][0]:
            deduplicated[-1] = (t, yaw)
        else:
            deduplicated.append((t, yaw))
    if not deduplicated:
        return []
    unwrapped: list[tuple[float, float]] = [deduplicated[0]]
    previous_wrapped = deduplicated[0][1]
    previous_unwrapped = deduplicated[0][1]
    for t, yaw in deduplicated[1:]:
        previous_unwrapped += wrap_angle(yaw - previous_wrapped)
        unwrapped.append((t, previous_unwrapped))
        previous_wrapped = yaw
    return unwrapped


def _interpolate_timed(points: list[tuple[float, float]], t: float) -> float | None:
    if not points or not math.isfinite(t) or t < points[0][0] or t > points[-1][0]:
        return None
    index = bisect_right([item[0] for item in points], t)
    if index == 0:
        return points[0][1]
    if index >= len(points):
        return points[-1][1]
    left_t, left_yaw = points[index - 1]
    right_t, right_yaw = points[index]
    if right_t <= left_t:
        return right_yaw
    fraction = (t - left_t) / (right_t - left_t)
    return left_yaw + fraction * (right_yaw - left_yaw)


def unwrapped_delta(
    records: list[dict[str, Any]],
    key: str = "yaw",
    *,
    start_t: float | None = None,
    end_t: float | None = None,
) -> float | None:
    """Compute yaw change, interpolating a requested receipt-time window.

    If records do not carry usable receipt timestamps, the legacy record-order
    calculation is retained.  This makes old artifacts replayable while new
    field captures get a synchronized result.
    """

    points = _timed_yaw_points(records, key)
    if len(points) >= 2:
        start = points[0][0] if start_t is None else max(points[0][0], float(start_t))
        end = points[-1][0] if end_t is None else min(points[-1][0], float(end_t))
        if end <= start:
            return None
        first = _interpolate_timed(points, start)
        last = _interpolate_timed(points, end)
        return None if first is None or last is None else last - first

    values = [_finite(record.get(key)) for record in records]
    values = [value for value in values if value is not None]
    if len(values) < 2:
        return None
    return sum(wrap_angle(current - previous) for previous, current in zip(values, values[1:], strict=False))


def integrate_angular_velocity(
    records: list[dict[str, Any]],
    *,
    start_t: float | None = None,
    end_t: float | None = None,
    key: str = "angular_z",
    bias_rad_s: float = 0.0,
) -> float | None:
    """Integrate a command stream over a receipt-time window.

    Only the canary publisher's records are passed here.  Incoming ``Twist``
    callbacks are intentionally kept separate because they can contain idle
    joystick/application publishers and must not be used as evidence for the
    autonomous command under test.
    """

    try:
        bias = float(bias_rad_s)
    except (TypeError, ValueError):
        bias = 0.0
    if not math.isfinite(bias):
        bias = 0.0
    points: list[tuple[float, float]] = []
    for record in records:
        if record.get("published") is False:
            continue
        t = _finite(record.get("t"))
        value = _finite(record.get(key))
        if t is not None and value is not None:
            points.append((t, value - bias))
    points.sort(key=lambda item: item[0])
    if len(points) < 2:
        return None
    deduplicated: list[tuple[float, float]] = []
    for point in points:
        if deduplicated and point[0] == deduplicated[-1][0]:
            deduplicated[-1] = point
        else:
            deduplicated.append(point)
    start = deduplicated[0][0] if start_t is None else max(deduplicated[0][0], float(start_t))
    end = deduplicated[-1][0] if end_t is None else min(deduplicated[-1][0], float(end_t))
    if end <= start:
        return None

    def interpolate(t: float) -> float | None:
        index = bisect_right([item[0] for item in deduplicated], t)
        if index == 0 or index >= len(deduplicated):
            return deduplicated[0][1] if index == 0 else deduplicated[-1][1]
        left_t, left_value = deduplicated[index - 1]
        right_t, right_value = deduplicated[index]
        if right_t <= left_t:
            return right_value
        return left_value + (t - left_t) / (right_t - left_t) * (right_value - left_value)

    clipped = [(start, interpolate(start)), (end, interpolate(end))]
    clipped.extend((t, value) for t, value in deduplicated if start < t < end)
    clipped = [(t, value) for t, value in clipped if value is not None]
    clipped.sort(key=lambda item: item[0])
    if len(clipped) < 2:
        return None
    return sum(
        0.5 * (right_value + left_value) * (right_t - left_t)
        for (left_t, left_value), (right_t, right_value) in zip(clipped, clipped[1:], strict=False)
    )


def classify_independent_motion(
    goal_rad: float,
    *,
    gyro_delta_rad: float | None,
    quaternion_delta_rad: float | None,
    gyro_deltas_rad: dict[str, float | None] | None = None,
) -> dict[str, Any]:
    """Classify motion evidence that is independent of the EKF/open-loop odom.

    ``/odom`` and ``/odom_raw`` can both move when only a command is being
    integrated.  A canary is therefore allowed to report ``SUCCEEDED`` only
    when a body IMU stream also reports a signed, non-trivial rotation.  The
    quaternion path is accepted as relative corroboration; its covariance and
    absolute-heading status remain separate fields.
    """

    goal = float(goal_rad)
    expected = abs(goal)
    threshold = max(MIN_INDEPENDENT_ROTATION_RAD, expected * 0.25)
    sign = 1.0 if goal >= 0 else -1.0

    def candidate(value: float | None) -> tuple[bool, float | None]:
        numeric = _finite(value)
        if numeric is None:
            return False, None
        return sign * numeric >= threshold, numeric

    streams: dict[str, float | None] = dict(gyro_deltas_rad or {})
    streams.setdefault("imu", gyro_delta_rad)
    # Keep only finite values in the evidence map while retaining explicit
    # nulls for streams that were subscribed but did not produce a usable
    # integral.  A raw driver stream is independent of the EKF and is often
    # the decisive signal when the complementary filter is stale.
    stream_values = {
        name: _finite(value) for name, value in streams.items()
        if isinstance(name, str) and name
    }
    passing = {
        name: value for name, value in stream_values.items()
        if value is not None and sign * value >= threshold
    }
    opposing = {
        name: value for name, value in stream_values.items()
        if value is not None and sign * value <= -threshold
    }
    gyro_ok = bool(passing) and not opposing
    # The legacy scalar is the filtered /imu stream.  Prefer the strongest
    # passing stream for the compatibility field and make the source explicit.
    selected_gyro_stream = None
    gyro_value = _finite(gyro_delta_rad)
    if passing:
        selected_gyro_stream = max(passing, key=lambda name: abs(float(passing[name])))
        gyro_value = passing[selected_gyro_stream]
    quaternion_ok, quaternion_value = candidate(quaternion_delta_rad)
    kind = "NONE"
    verified = False
    agreement_error = None
    stream_values_finite = [float(value) for value in passing.values()]
    stream_spread = (
        max(stream_values_finite) - min(stream_values_finite)
        if len(stream_values_finite) >= 2 else None
    )
    streams_agree = stream_spread is None or stream_spread <= max(0.10, expected * 0.75)
    if opposing:
        # A strong opposite-sign stream is a frame/sign or timestamp fault;
        # never let a single passing stream turn that contradiction into a
        # physical-motion success.
        kind = "IMU_STREAMS_DISAGREE"
    elif gyro_ok and not streams_agree:
        kind = "IMU_STREAMS_DISAGREE"
    elif gyro_ok and quaternion_ok:
        agreement_error = abs(gyro_value - quaternion_value) if gyro_value is not None and quaternion_value is not None else None
        # Large disagreement usually means a frame/sign or stale-filter issue;
        # retain the evidence but do not call it physical confirmation.
        if agreement_error is not None and agreement_error <= max(0.10, expected * 0.75):
            kind = "IMU_GYRO_AND_QUATERNION"
            verified = True
        else:
            kind = "IMU_STREAMS_DISAGREE"
    elif gyro_ok:
        kind = "IMU_GYRO" if len(passing) == 1 else "IMU_GYRO_MULTI_STREAM"
        verified = True
    elif quaternion_ok:
        kind = "IMU_QUATERNION_RELATIVE"
        # This is useful evidence but lower confidence because covariance is
        # often unknown and the quaternion may itself be filter-derived.
        verified = True
    elif gyro_value is not None or quaternion_value is not None or any(value is not None for value in stream_values.values()):
        kind = "IMU_BELOW_THRESHOLD"
    return {
        "status": "VERIFIED" if verified else "NOT_VERIFIED",
        "kind": kind,
        "threshold_rad": threshold,
        "gyro_delta_rad": gyro_value,
        "gyro_deltas_rad": stream_values,
        "selected_gyro_stream": selected_gyro_stream,
        "gyro_stream_spread_rad": stream_spread,
        "opposing_gyro_streams": opposing,
        "quaternion_delta_rad": quaternion_value,
        "agreement_error_rad": agreement_error,
        "independent_of_odom": True,
    }


def _relationship(
    first: list[dict[str, Any]],
    second: list[dict[str, Any]],
    *,
    start_t: float | None = None,
    end_t: float | None = None,
    first_key: str = "yaw",
    second_key: str = "yaw",
    second_stream_semantics: str | None = None,
) -> dict[str, Any]:
    """Compare yaw increments over the actual common receipt-time window."""

    first_values = [item for item in first if _finite(item.get(first_key)) is not None]
    second_values = [item for item in second if _finite(item.get(second_key)) is not None]
    result: dict[str, Any] = {
        "first_samples": len(first_values),
        "second_samples": len(second_values),
        "initial_offset_rad": None,
        "first_delta_rad": None,
        "second_delta_rad": None,
        "delta_error_rad": None,
        "classification": "INSUFFICIENT_DATA",
        "comparison_time_basis": "receipt_monotonic_s",
        "synchronized": False,
        "overlap_start_t": None,
        "overlap_end_t": None,
        "overlap_duration_s": None,
    }
    if second_stream_semantics is not None:
        result["second_stream_semantics"] = second_stream_semantics
        # This explicit marker prevents a relative quaternion comparison from
        # being rendered as proof of an absolute IMU heading.
        result["absolute_heading_claim"] = False
    first_points = _timed_yaw_points(first, first_key)
    second_points = _timed_yaw_points(second, second_key)
    if len(first_points) >= 2 and len(second_points) >= 2:
        overlap_start = max(first_points[0][0], second_points[0][0])
        overlap_end = min(first_points[-1][0], second_points[-1][0])
        if start_t is not None:
            overlap_start = max(overlap_start, float(start_t))
        if end_t is not None:
            overlap_end = min(overlap_end, float(end_t))
        if overlap_end > overlap_start:
            first_start = _interpolate_timed(first_points, overlap_start)
            first_end = _interpolate_timed(first_points, overlap_end)
            second_start = _interpolate_timed(second_points, overlap_start)
            second_end = _interpolate_timed(second_points, overlap_end)
            if None not in (first_start, first_end, second_start, second_end):
                result.update({
                    "initial_offset_rad": wrap_angle(float(second_start) - float(first_start)),
                    "first_delta_rad": float(first_end) - float(first_start),
                    "second_delta_rad": float(second_end) - float(second_start),
                    "overlap_start_t": overlap_start,
                    "overlap_end_t": overlap_end,
                    "overlap_duration_s": overlap_end - overlap_start,
                    "synchronized": True,
                })
    else:
        # Legacy artifacts may not have ``t``.  Preserve a conservative
        # record-order comparison and make the weaker evidence explicit.
        result["comparison_time_basis"] = "record_order_fallback"
        if first_values and second_values:
            result["initial_offset_rad"] = wrap_angle(
                float(second_values[0][second_key]) - float(first_values[0][first_key])
            )
        result["first_delta_rad"] = unwrapped_delta(first_values, first_key)
        result["second_delta_rad"] = unwrapped_delta(second_values, second_key)

    if result["first_delta_rad"] is None or result["second_delta_rad"] is None:
        return result
    error = wrap_angle(float(result["second_delta_rad"]) - float(result["first_delta_rad"]))
    result["delta_error_rad"] = error
    offset = abs(float(result["initial_offset_rad"] or 0.0))
    result["classification"] = (
        "ALIGNED" if offset <= YAW_COMPARISON_TOLERANCE_RAD and abs(error) <= YAW_COMPARISON_TOLERANCE_RAD
        else "CONSTANT_OFFSET" if abs(error) <= YAW_COMPARISON_TOLERANCE_RAD
        else "DIVERGING"
    )
    return result


def _topic_graph(node: Any, topic: str) -> dict[str, Any]:
    def scalar(value: Any) -> Any:
        if value is None or isinstance(value, (bool, int, float, str)):
            return value
        name = getattr(value, "name", None)
        if isinstance(name, str) and name:
            return name
        sec = getattr(value, "sec", None)
        nanosec = getattr(value, "nanosec", None)
        if sec is not None and nanosec is not None:
            return {"sec": _finite(sec), "nanosec": _finite(nanosec)}
        return str(value)

    def endpoint_payload(endpoint: Any) -> dict[str, Any]:
        result = {
            "node_name": str(getattr(endpoint, "node_name", "") or ""),
            "node_namespace": str(getattr(endpoint, "node_namespace", "") or ""),
            "topic_type": str(getattr(endpoint, "topic_type", "") or ""),
            "endpoint_type": str(getattr(endpoint, "endpoint_type", "") or ""),
        }
        qos = getattr(endpoint, "qos_profile", None)
        if qos is not None:
            result["qos"] = {
                field: scalar(getattr(qos, field, None))
                for field in ("history", "depth", "reliability", "durability", "lifespan", "deadline", "liveliness")
            }
        return result

    try:
        publishers = list(node.get_publishers_info_by_topic(topic))
    except Exception:
        publishers = []
    try:
        subscriptions = list(node.get_subscriptions_info_by_topic(topic))
    except Exception:
        subscriptions = []
    return {
        "publisher_count": len(publishers),
        "subscription_count": len(subscriptions),
        "publisher_nodes": sorted({
            f"{getattr(item, 'node_namespace', '') or ''}{getattr(item, 'node_name', '') or ''}"
            for item in publishers
        }),
        "subscription_nodes": sorted({
            f"{getattr(item, 'node_namespace', '') or ''}{getattr(item, 'node_name', '') or ''}"
            for item in subscriptions
        }),
        "publishers": [endpoint_payload(item) for item in publishers],
        "subscriptions": [endpoint_payload(item) for item in subscriptions],
    }


def _motor_message_summary(message: Any) -> dict[str, Any]:
    """Keep bounded, scalar motor-command evidence without echoing payloads."""

    def has_items(value: Any) -> bool:
        if value is None or isinstance(value, (str, bytes)):
            return False
        try:
            return len(value) > 0
        except (TypeError, AttributeError):
            # Do not consume a generator merely to inspect it; the bounded
            # ``list`` conversion below is the single place that materializes
            # an iterable.
            try:
                iter(value)
            except TypeError:
                return False
            return True

    result: dict[str, Any] = {
        "message_type": f"{type(message).__module__}.{type(message).__name__}",
    }
    collection_field = "motors"
    try:
        motors = getattr(message, collection_field, None)
    except Exception:
        motors = None
    # Some vendor wrappers expose an empty compatibility ``motors`` member
    # while the actual repeated field is ``data``.  Prefer the populated field
    # when both are present; this is the shape of Hiwonder's MotorsState.
    try:
        data_field = getattr(message, "data", None)
    except Exception:
        data_field = None
    if motors is None or (not has_items(motors) and data_field is not None):
        # Hiwonder's published ``MotorsState`` message uses ``data`` for the
        # repeated MotorState entries; keep support for both vendor spellings.
        collection_field = "data"
        try:
            motors = data_field
        except Exception:
            motors = None
    if motors is not None:
        try:
            values = list(motors)
        except TypeError:
            values = []
        result["collection_field"] = collection_field
        result["motor_count"] = len(values)
        summaries: list[dict[str, Any]] = []
        for item in values[:64]:
            item_summary: dict[str, Any] = {}
            scalar_item = _finite(item)
            if scalar_item is not None:
                item_summary["value"] = scalar_item
            else:
                for field in ("id", "motor_id", "rps", "velocity", "speed", "duty", "value", "position"):
                    candidate = _finite(getattr(item, field, None))
                    if candidate is not None:
                        item_summary[field] = candidate
            if item_summary:
                summaries.append(item_summary)
        if summaries:
            result["motors"] = summaries
        return result
    for field in ("value", "speed", "velocity"):
        candidate = getattr(message, field, None)
        if isinstance(candidate, (list, tuple)):
            finite_values = [_finite(item) for item in list(candidate)[:64]]
            result[field] = [item for item in finite_values if item is not None]
        else:
            finite_value = _finite(candidate)
            if finite_value is not None:
                result[field] = finite_value
    return result


def run_canary(
    angle_degrees: float,
    speed_rad_s: float,
    *,
    duration_s: float = 30.0,
    command_topic: str = DEFAULT_COMMAND_TOPIC,
    feedback_topic: str = DEFAULT_FEEDBACK_TOPIC,
    motor_topic: str | None = DEFAULT_MOTOR_TOPIC,
    autonomous_source_confirmed: bool = False,
    max_records: int = 20_000,
) -> dict[str, Any]:
    """Execute one bounded canary.  All motion exits publish a zero command."""

    angle = _finite(angle_degrees)
    speed = _finite(speed_rad_s)
    duration = _finite(duration_s)
    if angle is None or speed is None or duration is None:
        raise ValueError("motion parameters must be finite")
    if angle == 0 or abs(angle) > MAX_ANGLE_DEGREES:
        raise ValueError(f"angle must be non-zero and <= {MAX_ANGLE_DEGREES} degrees")
    if speed <= 0 or speed > MAX_SPEED_RAD_S:
        raise ValueError(f"speed must be in (0, {MAX_SPEED_RAD_S}] rad/s")
    if duration <= 0 or duration > MAX_DURATION_S:
        raise ValueError(f"duration must be in (0, {MAX_DURATION_S}] seconds")
    if isinstance(max_records, bool) or int(max_records) != max_records or max_records <= 0:
        raise ValueError("max_records must be a positive integer")
    for topic, label in (
        (command_topic, "command_topic"),
        (feedback_topic, "feedback_topic"),
        (motor_topic, "motor_topic"),
    ):
        if topic is None:
            continue
        if not isinstance(topic, str) or not topic.startswith("/") or not topic.strip() or any(char.isspace() for char in topic):
            raise ValueError(f"{label} must be an absolute ROS topic name")
    if not autonomous_source_confirmed:
        return {
            "schema_version": SCHEMA_VERSION,
            "observed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "status": "BLOCKED",
            "error": "AUTONOMOUS_SOURCE_NOT_CONFIRMED",
            "motion_started": False,
            "autonomous_source_confirmed": False,
            "requested_angle_degrees": angle,
            "requested_speed_rad_s": math.copysign(speed, angle),
            "duration_limit_s": duration,
            "feedback_tolerance_degrees": math.degrees(goal_tolerance_rad(math.radians(angle))),
            "command_topic": command_topic,
            "feedback_topic": feedback_topic,
            "motor_topic": motor_topic,
            "motor_evidence_status": "NOT_REQUESTED" if motor_topic is None else "NOT_STARTED",
            "motor_evidence_kind": "NONE" if motor_topic is None else "GRAPH_ONLY_OR_UNAVAILABLE",
            "motor_is_encoder_feedback": False,
            "imu_orientation_covariance_status": None,
            "imu_yaw_comparison_source": "NONE",
            "imu_quaternion_yaw_initial_rad": None,
            "imu_relative_yaw_delta_rad": None,
            "imu_gyro_integrated_yaw_delta_rad": None,
            "stop_published": False,
            "physical_stop_verified": False,
            "settled": False,
            "angle_accuracy_verified": False,
            "stopped_observed": False,
            "sample_records": {
                "cmd_vel": [], "published_cmd_vel": [], "odom_raw": [], "odom": [],
                "imu": [], "imu_corrected": [], "imu_raw": [], "motor": [],
            },
        }

    import rclpy
    from geometry_msgs.msg import Twist
    from nav_msgs.msg import Odometry
    from rclpy.qos import DurabilityPolicy, QoSProfile, ReliabilityPolicy
    from sensor_msgs.msg import Imu

    # The LanderPi driver publishes the raw IMU and motor command topics with
    # RELIABLE/volatile QoS.  A best-effort sensor profile can be discovered
    # in the graph yet receive no samples under Fast DDS, which would turn a
    # real independent signal into a false ``IMU_BELOW_THRESHOLD`` result.
    # Use a bounded reliable profile for every evidence subscription.
    evidence_qos = QoSProfile(
        depth=10,
        reliability=ReliabilityPolicy.RELIABLE,
        durability=DurabilityPolicy.VOLATILE,
    )

    motor_message_type: Any | None = None
    motor_evidence_status = "NOT_REQUESTED" if motor_topic is None else "TYPE_UNAVAILABLE"
    motor_subscription_error: str | None = None
    if motor_topic is not None:
        try:
            from ros_robot_controller_msgs.msg import MotorsState
        except Exception as exc:
            motor_subscription_error = type(exc).__name__
        else:
            motor_message_type = MotorsState
            motor_evidence_status = "READY"

    initialized = False
    node: Any | None = None
    publisher: Any | None = None
    started = time.monotonic()
    records: dict[str, list[dict[str, Any]]] = {
        "cmd_vel": [], "published_cmd_vel": [], "odom_raw": [], "odom": [],
        "imu": [], "imu_corrected": [], "imu_raw": [], "motor": [],
    }
    state: dict[str, dict[str, Any] | None] = {key: None for key in records}
    subscriptions: list[Any] = []
    motion_started = False
    command_attempted = False
    stop_sent = False
    stop_attempts = 0
    stop_successes = 0
    stop_errors: list[str] = []
    failure: str | None = None
    feedback_topic_seen: str | None = None
    motion_start_t: float | None = None
    motion_end_t: float | None = None
    settle_end_t: float | None = None
    motion_baseline_yaw: float | None = None
    motion_end_yaw: float | None = None
    goal = math.radians(angle)
    feedback_tolerance = goal_tolerance_rad(goal)
    minimum_motion_observation_s = motion_observation_duration_s(goal, speed)
    signed_speed = math.copysign(speed, goal)

    def local_time() -> float:
        return time.monotonic() - started

    def append(name: str, item: dict[str, Any]) -> None:
        bucket = records[name]
        if len(bucket) < max_records:
            bucket.append(item)
        state[name] = item

    def on_cmd(message: Any) -> None:
        append("cmd_vel", {
            "t": local_time(),
            "header_stamp_s": stamp_seconds(message),
            "angular_z": _finite(message.angular.z),
            "linear_x": _finite(message.linear.x),
            "linear_y": _finite(message.linear.y),
        })

    def on_odom(name: str, message: Any) -> None:
        nonlocal feedback_topic_seen
        if name == "odom":
            feedback_topic_seen = feedback_topic
        append(name, {
            "t": local_time(),
            "header_stamp_s": stamp_seconds(message),
            "yaw": quaternion_yaw(message.pose.pose.orientation),
            "angular_z": _finite(message.twist.twist.angular.z),
            "frame_id": str(getattr(message.header, "frame_id", "") or ""),
            "child_frame_id": str(getattr(message, "child_frame_id", "") or ""),
        })

    def on_imu(name: str, message: Any) -> None:
        raw_covariance = getattr(message, "orientation_covariance", ())
        covariance = [] if raw_covariance is None else list(raw_covariance)
        evidence = imu_yaw_evidence(message.orientation, covariance)
        # Keep each subscribed stream in its own bucket.  Collapsing all
        # callbacks into ``imu`` made the artifact claim that corrected/raw
        # streams had no samples while silently mixing them into the filtered
        # stream, defeating the independent-evidence and disagreement gates.
        append(name, {
            "t": local_time(),
            "header_stamp_s": stamp_seconds(message),
            **evidence,
            "orientation_covariance_size": len(covariance),
            "angular_x": _finite(message.angular_velocity.x),
            "angular_y": _finite(message.angular_velocity.y),
            "angular_z": _finite(message.angular_velocity.z),
            "frame_id": str(getattr(message.header, "frame_id", "") or ""),
            "source_topic": name,
        })

    def on_motor(message: Any) -> None:
        append("motor", {"t": local_time(), **_motor_message_summary(message)})

    def spin(seconds: float) -> None:
        if node is not None:
            rclpy.spin_once(node, timeout_sec=max(0.0, seconds))

    def publish(value: float, *, phase: str) -> None:
        """Publish and record one command; exceptions remain visible to caller."""

        nonlocal command_attempted
        numeric_value = float(value)
        if abs(numeric_value) > 1e-9:
            command_attempted = True
        item: dict[str, Any] = {
            "t": local_time(),
            "angular_z": numeric_value,
            "phase": phase,
            "published": False,
        }
        message = Twist()
        message.angular.z = numeric_value
        try:
            if publisher is None:
                raise RuntimeError("publisher_not_initialized")
            publisher.publish(message)
        except Exception:
            append("published_cmd_vel", item)
            raise
        item["published"] = True
        append("published_cmd_vel", item)

    def live_independent_progress(end_t: float) -> float:
        """Return median fresh same-sign gyro progress for the stop gate."""

        if motion_start_t is None:
            return 0.0
        values: list[float] = []
        for stream_name in ("imu", "imu_corrected", "imu_raw"):
            stream = records[stream_name]
            timed = [
                (_finite(item.get("t")), _finite(item.get("angular_z")))
                for item in stream
            ]
            timed = [
                (timestamp, value)
                for timestamp, value in timed
                if timestamp is not None and value is not None
            ]
            if not timed or end_t - timed[-1][0] > 0.15:
                continue
            baseline_rates = [
                value for timestamp, value in timed
                if motion_start_t - 0.5 <= timestamp < motion_start_t
            ]
            bias = sum(baseline_rates) / len(baseline_rates) if baseline_rates else 0.0
            delta = integrate_angular_velocity(
                stream,
                key="angular_z",
                start_t=motion_start_t,
                end_t=end_t,
                bias_rad_s=bias,
            )
            if delta is not None and math.isfinite(delta) and math.copysign(1.0, goal) * delta > 0:
                values.append(float(delta))
        if not values:
            return 0.0
        values.sort()
        middle = len(values) // 2
        return values[middle] if len(values) % 2 else 0.5 * (values[middle - 1] + values[middle])

    try:
        rclpy.init(args=[])
        initialized = True
        node = rclpy.create_node("rolo_rotation_canary")
        publisher = node.create_publisher(Twist, command_topic, 10)
        subscriptions.append(node.create_subscription(Twist, command_topic, on_cmd, evidence_qos))
        subscriptions.append(node.create_subscription(
            Odometry, "/odom_raw", lambda message: on_odom("odom_raw", message), evidence_qos
        ))
        subscriptions.append(node.create_subscription(
            Odometry, feedback_topic, lambda message: on_odom("odom", message), evidence_qos
        ))
        for topic, record_name in (
            (DEFAULT_IMU_TOPIC, "imu"),
            (DEFAULT_IMU_CORRECTED_TOPIC, "imu_corrected"),
            (DEFAULT_IMU_RAW_TOPIC, "imu_raw"),
        ):
            subscriptions.append(
                node.create_subscription(
                    Imu,
                    topic,
                    lambda message, name=record_name: on_imu(name, message),
                    evidence_qos,
                )
            )
        if motor_topic is not None and motor_message_type is not None:
            try:
                subscriptions.append(node.create_subscription(
                    motor_message_type, motor_topic, on_motor, evidence_qos
                ))
                motor_evidence_status = "SUBSCRIBED"
            except Exception as exc:
                motor_subscription_error = type(exc).__name__
                motor_evidence_status = "SUBSCRIBE_FAILED"

        ready_deadline = time.monotonic() + 5.0
        while time.monotonic() < ready_deadline:
            spin(0.02)
            feedback = state.get("odom")
            independent_stream_ready = any(
                records[name] for name in ("imu", "imu_corrected", "imu_raw")
            )
            if (
                publisher.get_subscription_count() > 0
                and feedback is not None
                and independent_stream_ready
            ):
                break
        else:
            failure = (
                "NO_LIVE_INDEPENDENT_IMU"
                if state.get("odom") is not None and not any(
                    records[name] for name in ("imu", "imu_corrected", "imu_raw")
                )
                else "NO_LIVE_SUBSCRIBER_OR_ODOMETRY"
            )

        baseline = state.get("odom")
        baseline_yaw = None if baseline is None else _finite(baseline.get("yaw"))
        if failure is None and baseline_yaw is None:
            failure = "INVALID_INITIAL_ODOM_YAW"

        if failure is None:
            last_motion_yaw = baseline_yaw
            deadline = time.monotonic() + duration
            next_publish = time.monotonic()
            while time.monotonic() < deadline:
                spin(0.01)
                feedback = state.get("odom")
                current_yaw = None if feedback is None else _finite(feedback.get("yaw"))
                feedback_t = None if feedback is None else _finite(feedback.get("t"))
                if feedback is None or current_yaw is None or feedback_t is None or local_time() - feedback_t > 0.5:
                    failure = "ODOMETRY_STALE"
                    break
                last_motion_yaw = current_yaw
                travelled = wrap_angle(current_yaw - baseline_yaw)
                # For a single bounded turn (<30 degrees), no wrap crossing is
                # expected.  The sign check prevents an opposite turn from
                # satisfying the goal due to absolute-value comparisons.
                motion_elapsed = (
                    local_time() - motion_start_t if motion_start_t is not None else 0.0
                )
                independent_samples = sum(
                    1
                    for stream_name in ("imu", "imu_corrected", "imu_raw")
                    for item in records[stream_name]
                    if motion_start_t is not None
                    and (_finite(item.get("t")) or 0.0) >= motion_start_t
                )
                independent_progress = (
                    live_independent_progress(local_time()) if motion_started else 0.0
                )
                progress = independent_progress if motion_started else travelled
                if (
                    progress * math.copysign(1.0, goal) >= abs(goal) - feedback_tolerance
                    and motion_elapsed >= minimum_motion_observation_s
                    and independent_samples >= 5
                ):
                    break
                if time.monotonic() >= next_publish:
                    if not motion_started:
                        # Capture the actual pre-command baseline.  Samples
                        # collected while waiting for readiness are excluded;
                        # a goal reached before any command has no motion
                        # window and cannot be reported as a passing canary.
                        motion_start_t = local_time()
                        motion_baseline_yaw = current_yaw
                        last_motion_yaw = current_yaw
                    publish(signed_speed, phase="motion")
                    motion_started = True
                    next_publish = time.monotonic() + 0.05
            else:
                failure = "MOTION_TIMEOUT"
            if motion_start_t is not None:
                motion_end_t = local_time()
                motion_end_yaw = last_motion_yaw
    except (KeyboardInterrupt, Exception) as exc:
        failure = type(exc).__name__
        if motion_start_t is not None and motion_end_t is None:
            motion_end_t = local_time()
            latest = state.get("odom")
            motion_end_yaw = None if latest is None else _finite(latest.get("yaw"))
    finally:
        # A zero command is attempted whenever the publisher exists, even if
        # readiness failed or the first non-zero publish raised.  This closes
        # the stale-command window without claiming that a subscriber received
        # the stop; ``stop_published`` records only successful publish calls.
        if publisher is not None:
            for _ in range(6):
                stop_attempts += 1
                try:
                    publish(0.0, phase="stop")
                    stop_successes += 1
                except (KeyboardInterrupt, Exception) as exc:
                    stop_errors.append(type(exc).__name__)
                try:
                    spin(0.05)
                except (KeyboardInterrupt, Exception) as exc:
                    stop_errors.append(type(exc).__name__)
            stop_sent = stop_successes > 0
            if stop_successes == 0:
                failure = "STOP_UNCONFIRMED"
            settle_deadline = time.monotonic() + 0.6
            while time.monotonic() < settle_deadline:
                try:
                    spin(0.02)
                except (KeyboardInterrupt, Exception) as exc:
                    stop_errors.append(type(exc).__name__)
                    break
            settle_end_t = local_time()

    # Capture graph evidence before destroying the probe node.  It includes
    # all command publishers, while published_cmd_vel below identifies only
    # this canary's own commands.
    try:
        if node is not None:
            graph_topics = [
                command_topic, "/odom_raw", feedback_topic,
                DEFAULT_IMU_TOPIC, DEFAULT_IMU_CORRECTED_TOPIC, DEFAULT_IMU_RAW_TOPIC,
            ]
            if motor_topic is not None:
                graph_topics.append(motor_topic)
            graph = {topic: _topic_graph(node, topic) for topic in dict.fromkeys(graph_topics)}
            node_names = sorted({
                f"{namespace.rstrip('/')}/{name.lstrip('/')}" if namespace not in {"", "/"} else f"/{name.lstrip('/')}"
                for name, namespace in node.get_node_names_and_namespaces()
            })
        else:
            graph = {}
            node_names = []
    except Exception:
        graph = {}
        node_names = []

    for subscription in subscriptions:
        try:
            if node is not None:
                node.destroy_subscription(subscription)
        except Exception:
            pass
    try:
        if node is not None and publisher is not None:
            node.destroy_publisher(publisher)
        if node is not None:
            node.destroy_node()
    except Exception:
        pass
    if initialized:
        try:
            rclpy.shutdown()
        except Exception:
            pass

    baseline_yaw = motion_baseline_yaw
    final_yaw = motion_end_yaw
    # If the motion loop ended without a final feedback callback, use the
    # latest pre-stop sample.  Samples received during settle are deliberately
    # excluded from measured yaw.
    if final_yaw is None and motion_end_t is not None:
        candidates = [
            item for item in records["odom"]
            if _finite(item.get("t")) is not None and _finite(item.get("t")) <= motion_end_t
        ]
        if candidates:
            final_yaw = _finite(candidates[-1].get("yaw"))
    measured = None if baseline_yaw is None or final_yaw is None else wrap_angle(final_yaw - baseline_yaw)
    error_degrees = None if measured is None else math.degrees(measured - goal)
    final_record = state.get("odom")
    final_speed = _finite(final_record.get("angular_z")) if final_record else None
    stopped = final_speed is not None and abs(final_speed) <= 0.03
    have_motion_window = motion_start_t is not None and motion_end_t is not None and motion_end_t > motion_start_t
    raw_relationship = _relationship(
        records["odom_raw"], records["odom"],
        start_t=motion_start_t if have_motion_window else None,
        end_t=motion_end_t if have_motion_window else None,
    ) if have_motion_window else _relationship([], [])
    imu_relationship = _relationship(
        records["odom_raw"], records["imu"],
        start_t=motion_start_t if have_motion_window else None,
        end_t=motion_end_t if have_motion_window else None,
        second_key="quaternion_yaw",
        second_stream_semantics="IMU_QUATERNION_RELATIVE_ONLY",
    ) if have_motion_window else _relationship(
        [], [], second_key="quaternion_yaw",
        second_stream_semantics="IMU_QUATERNION_RELATIVE_ONLY",
    )
    raw_delta = unwrapped_delta(
        records["odom_raw"], start_t=motion_start_t, end_t=motion_end_t
    ) if have_motion_window else None
    ekf_delta = unwrapped_delta(
        records["odom"], start_t=motion_start_t, end_t=motion_end_t
    ) if have_motion_window else None
    imu_delta = unwrapped_delta(
        records["imu"], start_t=motion_start_t, end_t=motion_end_t
    ) if have_motion_window else None
    # Keep a second, explicitly relative stream even when covariance is zero
    # or the REP-145 unavailable sentinel.  This can expose axis/sign/rate
    # disagreement without claiming that the quaternion is an absolute heading.
    imu_relative_delta = unwrapped_delta(
        records["imu"], key="quaternion_yaw", start_t=motion_start_t, end_t=motion_end_t
    ) if have_motion_window else None
    # Estimate a stationary gyro bias independently for each IMU stage, then
    # retain both raw and bias-corrected integrals.  These are body-motion
    # signals; they are never converted into an absolute heading.
    imu_biases: dict[str, float] = {}
    imu_gyro_raw_deltas: dict[str, float | None] = {}
    imu_gyro_deltas: dict[str, float | None] = {}
    for stream_name in ("imu", "imu_corrected", "imu_raw"):
        pre_motion_rates = [
            _finite(item.get("angular_z"))
            for item in records[stream_name]
            if motion_start_t is not None
            and (_finite(item.get("t")) is not None and float(item["t"]) < motion_start_t)
            and _finite(item.get("angular_z")) is not None
        ]
        bias = sum(pre_motion_rates) / len(pre_motion_rates) if pre_motion_rates else 0.0
        imu_biases[stream_name] = bias
        imu_gyro_raw_deltas[stream_name] = (
            integrate_angular_velocity(
                records[stream_name],
                key="angular_z",
                start_t=motion_start_t,
                end_t=motion_end_t,
            )
            if have_motion_window else None
        )
        imu_gyro_deltas[stream_name] = (
            integrate_angular_velocity(
                records[stream_name],
                key="angular_z",
                start_t=motion_start_t,
                end_t=motion_end_t,
                bias_rad_s=bias,
            )
            if have_motion_window else None
        )
    imu_bias = imu_biases["imu"]
    imu_gyro_raw_delta = imu_gyro_raw_deltas["imu"]
    imu_gyro_delta = imu_gyro_deltas["imu"]
    independent_motion = classify_independent_motion(
        goal,
        gyro_delta_rad=imu_gyro_delta,
        quaternion_delta_rad=imu_relative_delta,
        gyro_deltas_rad=imu_gyro_deltas,
    ) if have_motion_window else {
        "status": "NOT_VERIFIED",
        "kind": "NONE",
        "threshold_rad": max(MIN_INDEPENDENT_ROTATION_RAD, abs(goal) * 0.25),
        "gyro_delta_rad": None,
        "quaternion_delta_rad": None,
        "agreement_error_rad": None,
        "independent_of_odom": True,
    }
    # A transient braking spike is not a stop failure.  Require the final
    # 200 ms IMU tail to be quiet, while retaining the full settle peak for
    # diagnosis.  This is the same fail-closed stop proof used by the target
    # bounded runtime.
    settle_rates: list[float] = []
    settle_tail_rates: list[float] = []
    if motion_end_t is not None and settle_end_t is not None:
        settle_tail_start = settle_end_t - 0.20
        for stream_name in ("imu", "imu_corrected", "imu_raw"):
            bias = imu_biases.get(stream_name, 0.0)
            for item in records[stream_name]:
                timestamp = _finite(item.get("t"))
                value = _finite(item.get("angular_z"))
                if (
                    timestamp is not None
                    and value is not None
                    and motion_end_t <= timestamp <= settle_end_t
                ):
                    residual = abs(value - bias)
                    settle_rates.append(residual)
                    if timestamp >= settle_tail_start:
                        settle_tail_rates.append(residual)
    settled = bool(settle_tail_rates) and max(settle_tail_rates) <= 0.03
    independent_motion["settled"] = settled
    independent_motion["settle_sample_count"] = len(settle_rates)
    independent_motion["settle_tail_sample_count"] = len(settle_tail_rates)
    independent_motion["settle_peak_rate_rad_s"] = max(settle_rates) if settle_rates else None
    independent_motion["settle_tail_max_rate_rad_s"] = max(settle_tail_rates) if settle_tail_rates else None
    gyro_delta = _finite(independent_motion.get("gyro_delta_rad"))
    angle_accuracy_tolerance = max(abs(goal) * 0.25, MIN_INDEPENDENT_ROTATION_RAD)
    independent_angle_error = (
        abs(abs(gyro_delta) - abs(goal)) if gyro_delta is not None else None
    )
    angle_accuracy_verified = (
        independent_angle_error is not None
        and independent_angle_error <= angle_accuracy_tolerance
        and math.copysign(1.0, gyro_delta) == math.copysign(1.0, goal)
    )
    independent_motion["target_angle_error_rad"] = independent_angle_error
    independent_motion["target_angle_tolerance_rad"] = angle_accuracy_tolerance
    independent_motion["angle_accuracy_status"] = (
        "VERIFIED" if angle_accuracy_verified else "NOT_VERIFIED"
    )
    command_delta = integrate_angular_velocity(
        records["published_cmd_vel"], start_t=motion_start_t, end_t=motion_end_t
    ) if have_motion_window else None
    command_error = None if command_delta is None or raw_delta is None else wrap_angle(raw_delta - command_delta)
    observed_nonzero = sum(
        1 for item in records["cmd_vel"] if abs(_finite(item.get("angular_z")) or 0.0) > 1e-9
    )
    published_nonzero = sum(
        1 for item in records["published_cmd_vel"]
        if item.get("published") and abs(_finite(item.get("angular_z")) or 0.0) > 1e-9
    )
    covariance_statuses = [
        item.get("orientation_covariance_status")
        for item in records["imu"]
        if item.get("orientation_covariance_status")
    ]
    covariance_status = None
    if covariance_statuses:
        covariance_status = covariance_statuses[0] if len(set(covariance_statuses)) == 1 else "MIXED"
    feedback_within_tolerance = error_degrees is not None and abs(error_degrees) <= 3.0
    status = (
        "SUCCEEDED"
        if failure is None
        and motion_started
        and stop_sent
        and stopped
        and settled
        and feedback_within_tolerance
        and independent_motion["status"] == "VERIFIED"
        # Independent motion is a witness only; an exact-angle canary must
        # also match the requested angle on the selected gyro stream.
        and angle_accuracy_verified
        else "UNKNOWN"
    )
    result_error = failure
    if result_error is None and status != "SUCCEEDED":
        result_error = (
            "ANGLE_ACCURACY_NOT_VERIFIED"
            if feedback_within_tolerance
            and independent_motion["status"] == "VERIFIED"
            and settled
            and not angle_accuracy_verified
            else "PHYSICAL_MOTION_NOT_VERIFIED"
            if feedback_within_tolerance
            and (independent_motion["status"] != "VERIFIED" or not settled)
            else "MOTION_NOT_VERIFIED"
        )
    return {
        "schema_version": SCHEMA_VERSION,
        "observed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "status": status,
        "error": result_error,
        "motion_started": motion_started,
        # Preserve the operator assertion in the evidence.  This path is
        # reached only after the confirmation gate, but hard-coding ``True``
        # would make an artifact lie if the API is ever called through a
        # different admission path.
        "autonomous_source_confirmed": bool(autonomous_source_confirmed),
        "requested_angle_degrees": angle,
        "requested_speed_rad_s": signed_speed,
        "duration_limit_s": duration,
        "feedback_tolerance_degrees": math.degrees(feedback_tolerance),
        "measured_angle_degrees": None if measured is None else math.degrees(measured),
        "angle_error_degrees": error_degrees,
        "stop_published": stop_sent,
        "physical_stop_verified": bool(stop_sent and stopped and settled),
        "settled": settled,
        "angle_accuracy_verified": angle_accuracy_verified,
        "stop_attempts": stop_attempts,
        "stop_successes": stop_successes,
        "stop_errors": stop_errors,
        "command_attempted": command_attempted,
        "stopped_observed": stopped,
        "final_angular_speed_rad_s": final_speed,
        "feedback_topic": feedback_topic_seen or feedback_topic,
        "command_topic": command_topic,
        "motor_topic": motor_topic,
        "motor_evidence_status": motor_evidence_status,
        "motor_subscription_error": motor_subscription_error,
        "motor_sample_count": len(records["motor"]),
        "motor_evidence_kind": (
            "NONE" if motor_topic is None
            else "COMMAND_PATH_SAMPLE" if motor_evidence_status == "SUBSCRIBED" and records["motor"]
            else "GRAPH_ONLY_OR_UNAVAILABLE"
        ),
        "motor_is_encoder_feedback": False,
        "imu_orientation_covariance_status": covariance_status,
        "imu_yaw_comparison_source": "QUATERNION_RELATIVE" if any(
            _finite(item.get("quaternion_yaw")) is not None for item in records["imu"]
        ) else "NONE",
        "graph": graph,
        "nodes": node_names,
        "sample_records": records,
        "yaw_relationship": raw_relationship,
        "imu_raw_yaw_relationship": imu_relationship,
        "motion_start_t": motion_start_t,
        "motion_end_t": motion_end_t,
        "motion_window_duration_s": None if not have_motion_window else motion_end_t - motion_start_t,
        "raw_yaw_delta_rad": raw_delta,
        "ekf_yaw_delta_rad": ekf_delta,
        "imu_yaw_delta_rad": imu_delta,
        "imu_relative_yaw_delta_rad": imu_relative_delta,
        "imu_gyro_integrated_yaw_delta_rad": imu_gyro_delta,
        "imu_gyro_raw_integrated_yaw_delta_rad": imu_gyro_raw_delta,
        "imu_gyro_bias_rad_s": imu_bias,
        "imu_raw_gyro_integrated_yaw_delta_rad": imu_gyro_deltas["imu_raw"],
        "imu_raw_gyro_raw_integrated_yaw_delta_rad": imu_gyro_raw_deltas["imu_raw"],
        "imu_raw_gyro_bias_rad_s": imu_biases["imu_raw"],
        "imu_corrected_gyro_integrated_yaw_delta_rad": imu_gyro_deltas["imu_corrected"],
        "imu_corrected_gyro_raw_integrated_yaw_delta_rad": imu_gyro_raw_deltas["imu_corrected"],
        "imu_corrected_gyro_bias_rad_s": imu_biases["imu_corrected"],
        "imu_quaternion_yaw_initial_rad": next(
            (
                _finite(item.get("quaternion_yaw"))
                for item in records["imu"]
                if _finite(item.get("quaternion_yaw")) is not None
            ),
            None,
        ),
        "command_integrated_yaw_delta_rad": command_delta,
        "command_to_raw_yaw_error_rad": command_error,
        "command_nonzero_samples": observed_nonzero,
        "published_command_nonzero_samples": published_nonzero,
        "independent_motion_evidence": independent_motion,
    }


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run one bounded LanderPi rotation canary")
    parser.add_argument("--angle-degrees", type=float, required=True)
    parser.add_argument("--speed-rad-s", type=float, default=0.03)
    parser.add_argument("--duration", type=float, default=30.0)
    parser.add_argument("--command-topic", default=DEFAULT_COMMAND_TOPIC)
    parser.add_argument("--feedback-topic", default=DEFAULT_FEEDBACK_TOPIC)
    parser.add_argument("--motor-topic", default=DEFAULT_MOTOR_TOPIC)
    parser.add_argument("--no-motor-topic", action="store_true", help="disable optional read-only motor command evidence")
    parser.add_argument("--autonomous-source-confirmed", action="store_true")
    parser.add_argument("--output", type=Path)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        result = run_canary(
            args.angle_degrees,
            args.speed_rad_s,
            duration_s=args.duration,
            command_topic=args.command_topic,
            feedback_topic=args.feedback_topic,
            motor_topic=None if args.no_motor_topic else args.motor_topic,
            autonomous_source_confirmed=args.autonomous_source_confirmed,
        )
    except (ImportError, OSError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    encoded = json.dumps(result, ensure_ascii=False, separators=(",", ":"))
    if args.output:
        temporary = str(args.output) + ".tmp"
        Path(temporary).write_text(encoded + "\n", encoding="utf-8")
        os.replace(temporary, args.output)
    print(encoded)
    return 0 if result.get("status") == "SUCCEEDED" else 2


if __name__ == "__main__":
    raise SystemExit(main())
