#!/usr/bin/env python3
"""Collect bounded, read-only evidence for the LanderPi odom/EKF chain.

The first version of this probe only counted a few scalar values.  That was
not enough to distinguish a DDS discovery false negative from a real sensor
semantic error, or a constant frame offset from a yaw-rate disagreement.  The
probe now keeps bounded sample summaries and the graph/parameter evidence
needed by Trace to make that distinction.  It never publishes a command and
never calls a service; the only ROS operations are subscriptions, graph
queries, and bounded parameter reads.

The executable is intentionally dependency-light outside a ROS target.  ROS
imports happen inside :func:`collect_trace`, so the pure helpers can be used
by CI and by the Trace replay parser on a development machine.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import statistics
import sys
import time
from collections.abc import Iterable, Mapping
from datetime import datetime, timezone
from getpass import getuser
import re
from pathlib import Path
from typing import Any


TRACE_SCHEMA_VERSION = "rolo-landerpi-odom-trace/v1"
DEFAULT_TOPICS = (
    "/controller/cmd_vel",
    "/odom_raw",
    "/odom",
    "/odom_rf2o",
    "/imu",
    "/imu_corrected",
    "/ros_robot_controller/imu_raw",
    "/set_odom",
    "/tf",
    "/tf_static",
)
LAUNCH_ENVIRONMENT_KEYS = (
    "need_compile",
    "MACHINE_TYPE",
    "LIDAR_TYPE",
    "DEPTH_CAMERA_TYPE",
)
PARAMETER_NAMES = (
    "odom0",
    "odom0_config",
    "odom1",
    "odom1_config",
    "imu0",
    "imu0_config",
    "imu0_relative",
    "imu0_remove_gravitational_acceleration",
    "publish_tf",
    "world_frame",
    "base_link_frame",
    "map_frame",
    "odom_frame",
)


def wrap_angle(angle: float) -> float:
    """Wrap an angle to ``[-pi, pi]`` while rejecting non-finite values."""

    value = float(angle)
    if not math.isfinite(value):
        raise ValueError("angle must be finite")
    return math.atan2(math.sin(value), math.cos(value))


def quaternion_norm(q: Any) -> float:
    """Return a quaternion norm, or ``nan`` if a component is not numeric."""

    try:
        values = (float(q.x), float(q.y), float(q.z), float(q.w))
    except (AttributeError, TypeError, ValueError):
        return math.nan
    if not all(math.isfinite(value) for value in values):
        return math.nan
    return math.sqrt(sum(value * value for value in values))


def quaternion_is_valid(q: Any, *, min_norm: float = 1e-9) -> bool:
    """Whether a quaternion contains a usable orientation.

    Drivers in the field use an all-zero quaternion as an
    ``orientation unavailable`` sentinel.  A non-unit but finite quaternion
    is accepted because the yaw conversion below normalizes it implicitly;
    the norm is retained in evidence for calibration review.
    """

    norm = quaternion_norm(q)
    return math.isfinite(norm) and norm >= min_norm


def quaternion_to_yaw(q: Any) -> float | None:
    """Convert a ROS quaternion to yaw, returning ``None`` for invalid data."""

    if not quaternion_is_valid(q):
        return None
    try:
        x, y, z, w = (float(q.x), float(q.y), float(q.z), float(q.w))
    except (AttributeError, TypeError, ValueError):
        return None
    norm = quaternion_norm(q)
    if not math.isfinite(norm) or norm <= 0:
        return None
    x, y, z, w = (item / norm for item in (x, y, z, w))
    return math.atan2(2.0 * (w * z + x * y), 1.0 - 2.0 * (y * y + z * z))


def orientation_covariance_status(covariance: Iterable[Any] | None) -> str | None:
    """Classify IMU orientation covariance using the sensor_msgs contract.

    REP-145 uses ``-1`` in the first element when orientation is unavailable;
    an all-zero matrix means the covariance is unknown.  Both cases must stay
    distinct from a finite, explicitly supplied covariance so a quaternion is
    never promoted to an absolute heading by accident.
    """

    if covariance is None:
        return None
    values = list(covariance)
    # Keep the historical ``None`` result for an absent/empty field.  A ROS
    # message implementation can expose an empty sequence when the field is
    # omitted; this is missing evidence rather than a malformed, populated
    # covariance matrix.  Non-empty short sequences remain explicitly
    # malformed so they cannot be mistaken for a calibrated heading.
    if not values:
        return None
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


def orientation_covariance_is_valid(covariance: Iterable[Any] | None) -> bool | None:
    """Return true only for an explicitly populated covariance matrix."""

    status = orientation_covariance_status(covariance)
    return None if status is None else status == "VALID"


def ros_stamp_to_seconds(stamp: Any) -> float | None:
    """Convert a ROS ``builtin_interfaces/Time`` value to seconds."""

    try:
        sec = float(stamp.sec)
        nanosec = float(stamp.nanosec)
    except (AttributeError, TypeError, ValueError):
        return None
    value = sec + nanosec * 1e-9
    return value if math.isfinite(value) else None


def _header_stamp(message: Any) -> float | None:
    try:
        return ros_stamp_to_seconds(message.header.stamp)
    except AttributeError:
        return None


def _finite(value: Any) -> float | None:
    try:
        result = float(value)
    except (TypeError, ValueError):
        return None
    return result if math.isfinite(result) else None


def _text(value: Any) -> str | None:
    if value is None:
        return None
    result = str(value).strip()
    return result or None


def _bool_arg(value: str | None) -> bool | None:
    if value is None:
        return None
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    return None


def continuous_delta(values: Iterable[float]) -> float | None:
    """Compute a continuous first-to-last yaw delta for a sample sequence."""

    finite = [float(value) for value in values if _finite(value) is not None]
    if len(finite) < 2:
        return None
    total = 0.0
    for previous, current in zip(finite, finite[1:]):
        total += wrap_angle(current - previous)
    return total


def _timed_delta(records: list[Mapping[str, Any]], key: str = "yaw") -> float | None:
    values = [record.get(key) for record in records]
    return continuous_delta(value for value in values if _finite(value) is not None)


def integrate_command_yaw(
    records: list[Mapping[str, Any]],
    *,
    start_t: float | None = None,
    end_t: float | None = None,
) -> float | None:
    """Integrate command angular velocity over local receipt time.

    This is an evidence signal, not a claim that a vendor implementation is
    open-loop.  A close fit with ``/odom_raw`` is what lets Trace flag the
    likely command-integration source while retaining the original records.
    """

    points: list[tuple[float, float]] = []
    for record in records:
        t = _finite(record.get("t"))
        angular = _finite(record.get("angular_z"))
        if t is not None and angular is not None:
            points.append((t, angular))
    if len(points) < 2:
        return None
    points.sort(key=lambda item: item[0])
    if start_t is not None or end_t is not None:
        lower = -math.inf if start_t is None else float(start_t)
        upper = math.inf if end_t is None else float(end_t)
        if upper < lower:
            return None
        def interpolate(timestamp: float) -> tuple[float, float] | None:
            if timestamp < points[0][0] or timestamp > points[-1][0]:
                return None
            for left, right in zip(points, points[1:]):
                if left[0] <= timestamp <= right[0]:
                    if right[0] == left[0]:
                        return (timestamp, right[1])
                    ratio = (timestamp - left[0]) / (right[0] - left[0])
                    return (timestamp, left[1] + ratio * (right[1] - left[1]))
            return (timestamp, points[-1][1])

        bounded = [point for point in points if lower <= point[0] <= upper]
        start_point = interpolate(lower)
        end_point = interpolate(upper)
        if start_point is not None:
            bounded.insert(0, start_point)
        if end_point is not None:
            bounded.append(end_point)
        points = sorted(set(bounded), key=lambda item: item[0])
        if len(points) < 2:
            return None
    total = 0.0
    previous_t, previous_v = points[0]
    for current_t, current_v in points[1:]:
        dt = current_t - previous_t
        if 0 <= dt <= 5.0:
            total += (previous_v + current_v) * 0.5 * dt
        previous_t, previous_v = current_t, current_v
    return total


def integrate_angular_rate(
    records: list[Mapping[str, Any]],
    *,
    key: str = "angular_z",
    start_t: float | None = None,
    end_t: float | None = None,
    bias_rad_s: float = 0.0,
) -> float | None:
    """Integrate a reported angular-rate stream over a bounded window.

    ``/imu`` carries a body-rate measurement even when its orientation
    quaternion has unknown covariance. Keeping this calculation separate
    from command integration gives Trace an independent motion signal. The
    optional bias is normally estimated from a short pre-motion stationary
    window; it is never used to manufacture an absolute heading.
    """

    try:
        bias = float(bias_rad_s)
    except (TypeError, ValueError):
        bias = 0.0
    if not math.isfinite(bias):
        bias = 0.0
    points = [
        (_finite(item.get("t")), _finite(item.get(key)))
        for item in records
    ]
    points = sorted(
        (float(t), float(value) - bias)
        for t, value in points
        if t is not None and value is not None
    )
    if len(points) < 2:
        return None
    lower = points[0][0] if start_t is None else max(points[0][0], float(start_t))
    upper = points[-1][0] if end_t is None else min(points[-1][0], float(end_t))
    if upper <= lower:
        return None

    def interpolate(timestamp: float) -> tuple[float, float] | None:
        if timestamp < points[0][0] or timestamp > points[-1][0]:
            return None
        for left, right in zip(points, points[1:]):
            if left[0] <= timestamp <= right[0]:
                if right[0] <= left[0]:
                    return (timestamp, right[1])
                fraction = (timestamp - left[0]) / (right[0] - left[0])
                return (timestamp, left[1] + fraction * (right[1] - left[1]))
        return (timestamp, points[-1][1])

    clipped: list[tuple[float, float]] = []
    for boundary in (lower, upper):
        point = interpolate(boundary)
        if point is not None:
            clipped.append(point)
    clipped.extend(point for point in points if lower < point[0] < upper)
    clipped = sorted(set(clipped), key=lambda item: item[0])
    if len(clipped) < 2:
        return None
    return sum(
        0.5 * (right_value + left_value) * (right_t - left_t)
        for (left_t, left_value), (right_t, right_value)
        in zip(clipped, clipped[1:])
    )


def mean_angular_rate(
    records: list[Mapping[str, Any]], *, key: str = "angular_z", end_t: float | None = None
) -> float | None:
    """Return a finite mean for an optional pre-motion bias window."""

    values = []
    for item in records:
        timestamp = _finite(item.get("t"))
        value = _finite(item.get(key))
        if value is None or (end_t is not None and (timestamp is None or timestamp >= end_t)):
            continue
        values.append(value)
    return statistics.fmean(values) if values else None


def _unwrapped_timed_yaw(records: list[Mapping[str, Any]], key: str) -> list[tuple[float, float]]:
    """Return yaw samples sorted by local time with boundary crossings unwrapped."""

    points = [
        (_finite(item.get("t")), _finite(item.get(key)))
        for item in records
    ]
    valid = sorted(
        (float(t), float(value)) for t, value in points if t is not None and value is not None
    )
    if not valid:
        return []
    result = [(valid[0][0], valid[0][1])]
    for timestamp, value in valid[1:]:
        previous = result[-1][1]
        result.append((timestamp, previous + wrap_angle(value - previous)))
    return result


def _interpolate_timed_yaw(points: list[tuple[float, float]], timestamp: float) -> float | None:
    if not points or timestamp < points[0][0] or timestamp > points[-1][0]:
        return None
    for (left_t, left_yaw), (right_t, right_yaw) in zip(points, points[1:]):
        if left_t <= timestamp <= right_t:
            if right_t == left_t:
                return right_yaw
            ratio = (timestamp - left_t) / (right_t - left_t)
            return left_yaw + ratio * (right_yaw - left_yaw)
    return points[-1][1]


def compare_yaw_series(
    first: list[Mapping[str, Any]],
    second: list[Mapping[str, Any]],
    *,
    key: str = "yaw",
    first_key: str | None = None,
    second_key: str | None = None,
    second_stream_semantics: str | None = None,
) -> dict[str, Any]:
    """Describe offset versus motion disagreement between two yaw streams."""

    first_key = first_key or key
    second_key = second_key or key
    first_values = [float(item[first_key]) for item in first if _finite(item.get(first_key)) is not None]
    second_values = [float(item[second_key]) for item in second if _finite(item.get(second_key)) is not None]
    first_timed = _unwrapped_timed_yaw(first, first_key)
    second_timed = _unwrapped_timed_yaw(second, second_key)
    result: dict[str, Any] = {
        "first_samples": len(first_values),
        "second_samples": len(second_values),
        "initial_offset_rad": None,
        "first_delta_rad": None,
        "second_delta_rad": None,
        "delta_error_rad": None,
        "classification": "INSUFFICIENT_DATA",
    }
    if second_stream_semantics is not None:
        result["second_stream_semantics"] = second_stream_semantics
        # A relative quaternion can expose rate/sign disagreement, but it
        # cannot establish a world-referenced heading by itself.
        result["absolute_heading_claim"] = False
    if first_values and second_values:
        if first_timed and second_timed:
            overlap_start = max(first_timed[0][0], second_timed[0][0])
            overlap_end = min(first_timed[-1][0], second_timed[-1][0])
            first_start = _interpolate_timed_yaw(first_timed, overlap_start)
            second_start = _interpolate_timed_yaw(second_timed, overlap_start)
            first_end = _interpolate_timed_yaw(first_timed, overlap_end)
            second_end = _interpolate_timed_yaw(second_timed, overlap_end)
            if None not in (first_start, second_start, first_end, second_end):
                result["initial_offset_rad"] = wrap_angle(float(second_start) - float(first_start))
                result["first_delta_rad"] = float(first_end) - float(first_start)
                result["second_delta_rad"] = float(second_end) - float(second_start)
        if result["initial_offset_rad"] is None:
            result["initial_offset_rad"] = wrap_angle(second_values[0] - first_values[0])
    first_delta = result["first_delta_rad"]
    second_delta = result["second_delta_rad"]
    if first_delta is None:
        first_delta = continuous_delta(first_values)
        result["first_delta_rad"] = first_delta
    if second_delta is None:
        second_delta = continuous_delta(second_values)
        result["second_delta_rad"] = second_delta
    if first_delta is None or second_delta is None:
        return result
    delta_error = wrap_angle(second_delta - first_delta)
    result["delta_error_rad"] = delta_error
    offset = abs(float(result["initial_offset_rad"] or 0.0))
    if abs(delta_error) <= 0.15:
        result["classification"] = "ALIGNED" if offset <= 0.15 else "CONSTANT_OFFSET"
    else:
        result["classification"] = "DIVERGING"
    return result


def _series_summary(values: list[float], times: list[float] | None = None) -> dict[str, Any]:
    finite = [float(value) for value in values if _finite(value) is not None]
    result: dict[str, Any] = {"count": len(finite)}
    if not finite:
        return result
    result.update({"first": finite[0], "last": finite[-1], "min": min(finite), "max": max(finite)})
    if len(finite) >= 2:
        result["delta"] = finite[-1] - finite[0]
    if times:
        finite_times = [float(value) for value in times if _finite(value) is not None]
        if len(finite_times) >= 2 and finite_times[-1] > finite_times[0]:
            span = finite_times[-1] - finite_times[0]
            result["span_s"] = span
            result["rate_hz"] = (len(finite_times) - 1) / span
            result["max_gap_s"] = max(
                (current - previous for previous, current in zip(finite_times, finite_times[1:])),
                default=0.0,
            )
    return result


def _topic_summary(records: list[Mapping[str, Any]], *, value_key: str | None = None) -> dict[str, Any]:
    times = [record.get("t") for record in records]
    result: dict[str, Any] = {
        "count": len(records),
        "first_local_t": times[0] if times else None,
        "last_local_t": times[-1] if times else None,
    }
    if len(times) >= 2:
        valid_times = [float(value) for value in times if _finite(value) is not None]
        if len(valid_times) >= 2 and valid_times[-1] > valid_times[0]:
            span = valid_times[-1] - valid_times[0]
            result["span_s"] = span
            result["rate_hz"] = (len(valid_times) - 1) / span
            result["max_gap_s"] = max(
                (current - previous for previous, current in zip(valid_times, valid_times[1:])),
                default=0.0,
            )
    if value_key:
        result["values"] = _series_summary(
            [record[value_key] for record in records if _finite(record.get(value_key)) is not None],
            [float(value) for value in times if _finite(value) is not None],
        )
    return result


def header_timestamp_quality(records: list[Mapping[str, Any]]) -> tuple[str, int]:
    """Classify header timestamps and count regressions in receipt order."""

    values = [
        float(item["header_stamp_s"])
        for item in records
        if _finite(item.get("header_stamp_s")) is not None
    ]
    if not values:
        return "MISSING", 0
    regressions = sum(1 for previous, current in zip(values, values[1:]) if current < previous)
    if regressions:
        return "NON_MONOTONIC", regressions
    if all(value == 0 for value in values):
        return "ZERO", 0
    return "MONOTONIC", 0


def estimate_imu_yaw_rate_residual(
    records: list[Mapping[str, Any]], *, yaw_key: str = "yaw"
) -> dict[str, float | int | None]:
    """Compare orientation-derived yaw rate with reported gyro ``angular_z``.

    The estimate is diagnostic evidence only.  It catches a stale/invalid
    orientation, an axis/sign mismatch, or an unaccounted gyro bias; it does
    not attempt to rewrite calibration on the target.
    """

    points = _unwrapped_timed_yaw(records, yaw_key)
    by_time = {
        float(item["t"]): _finite(item.get("angular_z"))
        for item in records
        if _finite(item.get("t")) is not None and _finite(item.get("angular_z")) is not None
    }
    residuals: list[float] = []
    for (left_t, left_yaw), (right_t, right_yaw) in zip(points, points[1:]):
        dt = right_t - left_t
        if dt <= 0 or dt > 1.0:
            continue
        left_rate = by_time.get(left_t)
        right_rate = by_time.get(right_t)
        if left_rate is None and right_rate is None:
            continue
        gyro_rate = float(right_rate if left_rate is None else left_rate if right_rate is None else (left_rate + right_rate) * 0.5)
        residuals.append((right_yaw - left_yaw) / dt - gyro_rate)
    if not residuals:
        return {"count": 0, "mean_rad_s": None, "median_rad_s": None, "mean_abs_rad_s": None}
    return {
        "count": len(residuals),
        "mean_rad_s": statistics.fmean(residuals),
        "median_rad_s": statistics.median(residuals),
        "mean_abs_rad_s": statistics.fmean(abs(value) for value in residuals),
    }


def _unique_record_values(records: Iterable[Mapping[str, Any]], key: str, limit: int = 16) -> list[str]:
    values = {
        str(value).strip()
        for record in records
        for value in (record.get(key),)
        if value is not None and str(value).strip()
    }
    return sorted(values)[:limit]


def _endpoint_value(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if hasattr(value, "sec") and hasattr(value, "nanosec"):
        return {
            "sec": _finite(getattr(value, "sec")),
            "nanosec": _finite(getattr(value, "nanosec")),
        }
    name = getattr(value, "name", None)
    if name:
        return str(name)
    return str(value)


def endpoint_to_dict(endpoint: Any) -> dict[str, Any]:
    """Serialize a ROS ``TopicEndpointInfo`` without unstable object reprs."""

    qos = getattr(endpoint, "qos_profile", None)
    qos_payload: dict[str, Any] | None = None
    if qos is not None:
        qos_payload = {
            "history": _endpoint_value(getattr(qos, "history", None)),
            "depth": _endpoint_value(getattr(qos, "depth", None)),
            "reliability": _endpoint_value(getattr(qos, "reliability", None)),
            "durability": _endpoint_value(getattr(qos, "durability", None)),
            "lifespan": _endpoint_value(getattr(qos, "lifespan", None)),
            "deadline": _endpoint_value(getattr(qos, "deadline", None)),
            "liveliness": _endpoint_value(getattr(qos, "liveliness", None)),
        }
    return {
        "node_name": _text(getattr(endpoint, "node_name", None)),
        "node_namespace": _text(getattr(endpoint, "node_namespace", None)),
        "topic_type": _text(getattr(endpoint, "topic_type", None)),
        "endpoint_type": _endpoint_value(getattr(endpoint, "endpoint_type", None)),
        "qos": qos_payload,
    }


def _parameter_value(value: Any) -> Any:
    """Convert a ROS ``ParameterValue`` to JSON without leaking object data."""

    if value is None:
        return None
    # rcl_interfaces ParameterValue exposes every scalar member with a
    # default value.  Always consult ``type`` first; otherwise a bool or an
    # array would be misread as the default empty string.
    type_to_field = {
        1: ("bool_value", bool),
        2: ("integer_value", int),
        3: ("double_value", float),
        4: ("string_value", str),
        5: ("byte_array_value", list),
        6: ("bool_array_value", list),
        7: ("integer_array_value", list),
        8: ("double_array_value", list),
        9: ("string_array_value", list),
    }
    try:
        parameter_type = int(getattr(value, "type", 0))
    except (TypeError, ValueError):
        parameter_type = 0
    field_spec = type_to_field.get(parameter_type)
    if field_spec is not None:
        field, converter = field_spec
        candidate = getattr(value, field, None)
        if converter is list:
            # Generated ROS array fields may be numpy-like sequences whose
            # truth-value is intentionally undefined.  Test for ``None``
            # explicitly instead of using ``candidate or ()``.
            return list(()) if candidate is None else list(candidate)
        try:
            return converter(candidate)
        except (TypeError, ValueError):
            return None
    # A small fallback for test doubles or older rclpy versions that omit
    # ``type``.  Prefer non-empty arrays, then non-default scalar values.
    for name in ("string_array_value", "byte_array_value", "bool_array_value", "integer_array_value", "double_array_value"):
        candidate = getattr(value, name, None)
        if candidate is not None and len(candidate) > 0:
            return list(candidate)
    for name in ("string_value", "bool_value", "integer_value", "double_value", "byte_value"):
        if not hasattr(value, name):
            continue
        candidate = getattr(value, name)
        if name == "string_value" and candidate:
            return str(candidate)
        if name == "bool_value" and bool(candidate):
            return True
        if name in {"integer_value", "byte_value"} and candidate != 0:
            return int(candidate)
        if name == "double_value" and candidate != 0.0:
            return float(candidate)
    return None


def _env_evidence(environ: Mapping[str, str] | None = None) -> dict[str, Any]:
    values = dict(environ or os.environ)
    present = {key: values[key] for key in LAUNCH_ENVIRONMENT_KEYS if values.get(key, "").strip()}
    missing = [key for key in LAUNCH_ENVIRONMENT_KEYS if key not in present]
    # Only launch selectors are included.  The complete environment may hold
    # credentials and must never be copied into an artifact.
    return {
        "required_keys": list(LAUNCH_ENVIRONMENT_KEYS),
        "present": present,
        "missing": missing,
        "complete": not missing,
    }


def _infer_source(
    command_integral: float | None,
    raw_delta: float | None,
    explicit: str | None = None,
    *,
    active_command_samples: int = 2,
) -> tuple[str, str]:
    if explicit in {"COMMAND_INTEGRATION", "MEASURED_FEEDBACK"}:
        return explicit, "EXPLICIT"
    if command_integral is None or raw_delta is None or active_command_samples < 2:
        return "UNKNOWN", "NONE"
    error = abs(wrap_angle(raw_delta - command_integral))
    # This is intentionally labelled an inference.  A matching command
    # integral is strong evidence for the current vendor implementation but
    # does not replace source-code or encoder evidence.
    if error <= max(0.15, abs(raw_delta) * 0.15):
        return "COMMAND_INTEGRATION", "COMMAND_INTEGRAL_FIT"
    return "UNKNOWN", "NO_FIT"


def _parameter_section_values(parameters: Mapping[str, Any], section: str) -> Mapping[str, Any]:
    item = parameters.get(section)
    if not isinstance(item, Mapping):
        return {}
    values = item.get("values")
    return values if isinstance(values, Mapping) else {}


def _measurement_semantics(parameters: Mapping[str, Any]) -> dict[str, Any]:
    """Project robot_localization boolean masks into named measurements."""

    names = (
        "x",
        "y",
        "z",
        "roll",
        "pitch",
        "yaw",
        "vx",
        "vy",
        "vz",
        "vroll",
        "vpitch",
        "vyaw",
        "ax",
        "ay",
        "az",
    )
    result: dict[str, Any] = {}
    section = _parameter_section_values(parameters, "ekf")
    for source in ("odom0", "odom1", "imu0"):
        config = section.get(f"{source}_config")
        if not isinstance(config, (list, tuple)):
            continue
        flags = [bool(value) for value in config]
        result[source] = {
            "config_length": len(flags),
            "enabled": {name: flags[index] for index, name in enumerate(names) if index < len(flags)},
            "yaw_fused": bool(flags[5]) if len(flags) > 5 else None,
            "yaw_rate_fused": bool(flags[11]) if len(flags) > 11 else None,
        }
    return result


def _imu_yaw_fused(measurement_semantics: Mapping[str, Any]) -> bool | None:
    item = measurement_semantics.get("imu0")
    if not isinstance(item, Mapping):
        return None
    value = item.get("yaw_fused")
    return value if isinstance(value, bool) else None


def _calibration_evidence(
    *,
    imu_use_mag: bool | None,
    environ: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Record calibration presence as metadata and a digest, never contents."""

    values = dict(environ or os.environ)
    explicit = values.get("ROLO_IMU_CALIBRATION_FILE", "").strip()
    candidates = [Path(explicit)] if explicit else [
        Path("/home/ubuntu/ros2_ws/src/calibration/config/imu_calib.yaml"),
        Path("/home/ubuntu/ros2_ws/install/calibration/share/calibration/config/imu_calib.yaml"),
    ]
    files: list[dict[str, Any]] = []
    for path in candidates:
        try:
            if not path.is_file():
                continue
            data = path.read_bytes()
            text = data.decode("utf-8", errors="ignore")
            keys = {key for key in ("SM", "bias", "scale", "misalignment") if re.search(rf"\b{re.escape(key)}\b", text, re.IGNORECASE)}
            files.append({
                "path": str(path),
                "size_bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
                "declared_fields": sorted(keys),
            })
        except (OSError, ValueError):
            continue
    sensor_status = "PRESENT" if files else "UNKNOWN" if not explicit else "ABSENT"
    scale_bias = None
    if files:
        scale_bias = any({"SM", "bias"}.issubset(set(item["declared_fields"])) for item in files)
    heading = False if imu_use_mag is False else None
    return {
        "sensor_calibration_status": sensor_status,
        "files": files,
        "scale_bias_calibrated": scale_bias,
        "heading_calibrated": heading,
        "heading_basis": "magnetometer_or_external_absolute_source" if imu_use_mag else "none_or_unknown",
    }


def _build_observation(
    *,
    duration_s: float,
    graph: Mapping[str, Mapping[str, Any]],
    records: Mapping[str, list[Mapping[str, Any]]],
    parameters: Mapping[str, Any],
    environment: Mapping[str, Any],
    node_names: list[str],
    service_names: list[str],
    executor_user: str,
    publisher_user: str | None,
    rmw_implementation: str | None,
    imu_use_mag: bool | None,
    imu_yaw_mode: str | None,
    odom_source: str | None,
    autonomous_source_confirmed: bool,
    tf_pairs: Iterable[str],
) -> dict[str, Any]:
    command_records = list(records.get("cmd_vel", ()))
    raw_records = list(records.get("odom_raw", ()))
    ekf_records = list(records.get("odom", ()))
    imu_records = list(records.get("imu", ()))
    raw_delta = _timed_delta(raw_records)
    ekf_delta = _timed_delta(ekf_records)
    imu_yaw_records = [item for item in imu_records if item.get("orientation_valid") and item.get("yaw") is not None]
    # A complementary-filter quaternion may be finite while its covariance is
    # all-zero/unknown. Keep that stream for relative-rate analysis, but never
    # use it as the absolute-heading candidate represented by ``imu_yaw_records``.
    imu_quaternion_records = [
        item for item in imu_records
        if _finite(item.get("quaternion_yaw")) is not None
    ]
    imu_delta = _timed_delta(imu_yaw_records)
    imu_relative_delta = _timed_delta(imu_quaternion_records, key="quaternion_yaw")
    imu_gyro_delta = integrate_angular_rate(imu_records)
    imu_gyro_values = [
        _finite(item.get("angular_z"))
        for item in imu_records
        if _finite(item.get("angular_z")) is not None
    ]
    imu_gyro_mean = statistics.fmean(imu_gyro_values) if imu_gyro_values else None
    raw_times = [
        _finite(record.get("t"))
        for record in raw_records
        if _finite(record.get("t")) is not None and _finite(record.get("yaw")) is not None
    ]
    command_integral = integrate_command_yaw(
        command_records,
        start_t=min(raw_times) if raw_times else None,
        end_t=max(raw_times) if raw_times else None,
    )
    active_commands = [
        record
        for record in command_records
        if (_finite(record.get("angular_z")) or 0.0) != 0.0
    ]
    source, source_evidence = _infer_source(
        command_integral,
        raw_delta,
        odom_source,
        active_command_samples=len(active_commands),
    )
    source_confidence = {
        "EXPLICIT": "HIGH",
        "COMMAND_INTEGRAL_FIT": "MEDIUM",
        "NO_FIT": "LOW",
        "NONE": "UNKNOWN",
    }.get(source_evidence, "UNKNOWN")
    measurement_semantics = _measurement_semantics(parameters)
    imu_yaw_fused = _imu_yaw_fused(measurement_semantics)
    calibration = _calibration_evidence(imu_use_mag=imu_use_mag)
    yaw_relationship = compare_yaw_series(raw_records, ekf_records)
    imu_raw_relationship = compare_yaw_series(
        raw_records,
        imu_quaternion_records,
        second_key="quaternion_yaw",
        second_stream_semantics="IMU_QUATERNION_RELATIVE_ONLY",
    )
    imu_rate_residual = estimate_imu_yaw_rate_residual(
        imu_quaternion_records, yaw_key="quaternion_yaw"
    )
    valid_imu_count = sum(1 for item in imu_records if item.get("orientation_valid"))
    invalid_imu_count = len(imu_records) - valid_imu_count
    orientation_valid = None if not imu_records else valid_imu_count > 0
    covariance_values = [item.get("orientation_covariance_valid") for item in imu_records]
    if not covariance_values or all(value is None for value in covariance_values):
        covariance_valid = None
    elif any(value is False for value in covariance_values):
        covariance_valid = False
    else:
        covariance_valid = True
    covariance_status_values = [
        item.get("orientation_covariance_status")
        for item in imu_records
        if item.get("orientation_covariance_status")
    ]
    if not covariance_status_values:
        covariance_status = None
    elif len(set(covariance_status_values)) == 1:
        covariance_status = covariance_status_values[0]
    else:
        covariance_status = "MIXED"
    orientation_ratio = (valid_imu_count / len(imu_records)) if imu_records else None
    explicit_mode = (imu_yaw_mode or "").upper()
    if explicit_mode not in {"UNSET", "RELATIVE", "ABSOLUTE", "UNKNOWN"}:
        explicit_mode = "UNKNOWN"
    if explicit_mode == "UNKNOWN":
        if not imu_records or not imu_quaternion_records:
            # A declared sensor mode cannot substitute for a received startup
            # sample.  Keep this as UNSET so Trace asks for initial-heading
            # evidence instead of silently treating a dead IMU as relative.
            explicit_mode = "UNSET"
        elif imu_use_mag is False:
            explicit_mode = "RELATIVE"
        elif imu_use_mag is True and orientation_valid:
            explicit_mode = "ABSOLUTE"
        elif imu_use_mag is True:
            explicit_mode = "UNKNOWN"
    absolute_available: bool | None
    if explicit_mode == "ABSOLUTE":
        absolute_available = bool(orientation_valid)
    elif explicit_mode in {"RELATIVE", "UNSET"} or imu_use_mag is False:
        absolute_available = False
    else:
        absolute_available = None
    odom_graph = graph.get("/odom", {})
    raw_graph = graph.get("/odom_raw", {})
    command_graph = graph.get("/controller/cmd_vel", {})
    tf_pair_set = sorted(set(str(item) for item in tf_pairs))
    tf_available = any(
        pair in {"odom->base_footprint", "odom->base_link", "odom/base_footprint", "odom/base_link"}
        for pair in tf_pair_set
    )
    reset_service_available = any(
        name.rstrip("/") in {"/set_odom", "/controller/set_odom"} for name in service_names
    )
    # LanderPi's vendor node exposes ``/set_odom`` as a Pose2D *topic*, not a
    # ROS service.  Keep the two endpoint kinds separate so a service query
    # cannot falsely claim that reset support exists.
    reset_topic_available = bool(
        graph.get("/set_odom", {}).get("publisher_count", 0)
        or graph.get("/set_odom", {}).get("subscription_count", 0)
    )
    all_nodes = sorted(set(node_names))[:256]
    lowered_nodes = " ".join(node.lower() for node in all_nodes)
    process_presence = {
        "odom_publisher": "odom_publisher" in lowered_nodes,
        "ekf_filter_node": "ekf_filter_node" in lowered_nodes or "/ekf" in lowered_nodes,
        "imu_filter": "imu_filter" in lowered_nodes,
        "ros_robot_controller": "ros_robot_controller" in lowered_nodes,
        "bringup": "bringup" in lowered_nodes,
    }
    raw_topic_summary = _topic_summary(raw_records, value_key="yaw")
    ekf_topic_summary = _topic_summary(ekf_records, value_key="yaw")
    imu_topic_summary = _topic_summary(imu_records)
    cmd_topic_summary = _topic_summary(command_records, value_key="angular_z")
    timestamp_quality: dict[str, str] = {}
    timestamp_regressions: dict[str, int] = {}
    for topic, topic_records in (
        ("/controller/cmd_vel", command_records),
        ("/odom_raw", raw_records),
        ("/odom", ekf_records),
        ("/imu", imu_records),
    ):
        quality, regressions = header_timestamp_quality(topic_records)
        timestamp_quality[topic] = quality
        timestamp_regressions[topic] = regressions
    command_fit_error = None
    if command_integral is not None and raw_delta is not None:
        command_fit_error = wrap_angle(raw_delta - command_integral)
    raw_frames = _unique_record_values(raw_records, "frame_id")
    raw_children = _unique_record_values(raw_records, "child_frame_id")
    ekf_frames = _unique_record_values(ekf_records, "frame_id")
    ekf_children = _unique_record_values(ekf_records, "child_frame_id")
    imu_frames = _unique_record_values(imu_records, "frame_id")
    if not raw_frames or not ekf_frames:
        frame_status = "UNKNOWN"
    elif set(raw_frames) != set(ekf_frames) or set(raw_children) != set(ekf_children):
        frame_status = "ODOM_FRAME_MISMATCH"
    else:
        frame_status = "ALIGNED"
    frame_consistency = {
        "status": frame_status,
        "raw_parent_frames": raw_frames,
        "raw_child_frames": raw_children,
        "ekf_parent_frames": ekf_frames,
        "ekf_child_frames": ekf_children,
        "imu_frames": imu_frames,
    }
    observation = {
        "schema_version": "rolo-odom-ekf-observation/v1",
        "executor_user": executor_user,
        "publisher_user": publisher_user,
        "rmw_implementation": rmw_implementation,
        "graph_publisher_count": int(odom_graph.get("publisher_count", 0) or 0),
        "graph_subscription_count": int(odom_graph.get("subscription_count", 0) or 0),
        "command_publisher_count": int(command_graph.get("publisher_count", 0) or 0),
        "autonomous_source_confirmed": autonomous_source_confirmed,
        "odom_raw_samples": len(raw_records),
        "odom_samples": len(ekf_records),
        "imu_samples": len(imu_records),
        "tf_odom_base_available": tf_available,
        "raw_yaw_delta_rad": raw_delta,
        "ekf_yaw_delta_rad": ekf_delta,
        "odom_pose_source": source,
        "raw_imu_orientation_valid": orientation_valid,
        "imu_orientation_covariance_valid": covariance_valid,
        "imu_orientation_covariance_status": covariance_status,
        "imu_use_mag": imu_use_mag,
        "imu_absolute_yaw_available": absolute_available,
        "imu_yaw_initialization": explicit_mode,
        "imu_yaw_fused": imu_yaw_fused,
        "reset_callback_error": None,
        "bringup_environment_complete": environment.get("complete"),
        # Extended Trace evidence.  All fields are optional in the v1 model so
        # older hand-authored observations remain valid.
        "observed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "duration_s": duration_s,
        "ros_domain_id": os.environ.get("ROS_DOMAIN_ID"),
        "executor_uid": os.geteuid() if hasattr(os, "geteuid") else None,
        "node_names": all_nodes,
        "process_presence": process_presence,
        "service_names": sorted(set(service_names)),
        "graph_topics": sorted(graph),
        "graph": dict(graph),
        "raw_publisher_nodes": raw_graph.get("publisher_nodes", []),
        "ekf_publisher_nodes": odom_graph.get("publisher_nodes", []),
        "command_publisher_nodes": command_graph.get("publisher_nodes", []),
        "topic_rates_hz": {
            "/controller/cmd_vel": cmd_topic_summary.get("rate_hz"),
            "/odom_raw": raw_topic_summary.get("rate_hz"),
            "/odom": ekf_topic_summary.get("rate_hz"),
            "/imu": imu_topic_summary.get("rate_hz"),
        },
        "topic_max_gap_s": {
            "/controller/cmd_vel": cmd_topic_summary.get("max_gap_s"),
            "/odom_raw": raw_topic_summary.get("max_gap_s"),
            "/odom": ekf_topic_summary.get("max_gap_s"),
            "/imu": imu_topic_summary.get("max_gap_s"),
        },
        "topic_header_timestamp_quality": timestamp_quality,
        "topic_timestamp_regressions": timestamp_regressions,
        "command_integrated_yaw_delta_rad": command_integral,
        "command_to_raw_yaw_error_rad": command_fit_error,
        "command_nonzero_samples": len(active_commands),
        "command_active_span_s": (
            max((_finite(record.get("t")) or 0.0 for record in active_commands), default=0.0)
            - min((_finite(record.get("t")) or 0.0 for record in active_commands), default=0.0)
            if active_commands
            else None
        ),
        "raw_yaw_initial_rad": raw_records[0].get("yaw") if raw_records else None,
        "ekf_yaw_initial_rad": ekf_records[0].get("yaw") if ekf_records else None,
        "imu_yaw_initial_rad": imu_yaw_records[0].get("yaw") if imu_yaw_records else None,
        "imu_yaw_delta_rad": imu_delta,
        "imu_quaternion_yaw_initial_rad": (
            imu_quaternion_records[0].get("quaternion_yaw")
            if imu_quaternion_records else None
        ),
        "imu_relative_yaw_delta_rad": imu_relative_delta,
        "imu_gyro_integrated_yaw_delta_rad": imu_gyro_delta,
        "imu_yaw_comparison_source": (
            "QUATERNION_RELATIVE" if imu_quaternion_records else "NONE"
        ),
        "imu_gyro_mean_rad_s": imu_gyro_mean,
        "imu_yaw_rate_residual_rad_s": imu_rate_residual.get("mean_rad_s"),
        "imu_yaw_rate_residual_abs_rad_s": imu_rate_residual.get("mean_abs_rad_s"),
        "raw_frame_ids": raw_frames,
        "raw_child_frame_ids": raw_children,
        "ekf_frame_ids": ekf_frames,
        "ekf_child_frame_ids": ekf_children,
        "imu_frame_ids": imu_frames,
        "frame_consistency": frame_consistency,
        "imu_valid_samples": valid_imu_count,
        "imu_invalid_orientation_samples": invalid_imu_count,
        "imu_orientation_valid_ratio": orientation_ratio,
        "yaw_relationship": yaw_relationship,
        "imu_raw_yaw_relationship": imu_raw_relationship,
        "tf_pairs": tf_pair_set,
        "reset_service_available": reset_service_available,
        "reset_topic_available": reset_topic_available,
        "reset_probe_performed": False,
        "reset_survival_verified": None,
        "launch_environment": dict(environment),
        "ekf_parameters": dict(parameters),
        "measurement_semantics": measurement_semantics,
        "calibration": calibration,
        "source_inference": source_evidence,
        "source_inference_confidence": source_confidence,
        "limitations": [
            "read-only probe; reset callback survival was not exercised",
            "graph endpoint discovery does not prove message receipt",
            "absolute IMU yaw requires an explicit calibration/source contract; a finite quaternion alone is insufficient",
        ],
    }
    return observation


def _safe_endpoint_query(node: Any, topic: str) -> dict[str, Any]:
    try:
        publishers = node.get_publishers_info_by_topic(topic)
    except Exception:
        publishers = []
    try:
        subscriptions = node.get_subscriptions_info_by_topic(topic)
    except Exception:
        subscriptions = []
    publisher_payload = [endpoint_to_dict(item) for item in publishers]
    subscription_payload = [endpoint_to_dict(item) for item in subscriptions]
    return {
        "publisher_count": len(publisher_payload),
        "subscription_count": len(subscription_payload),
        "publisher_nodes": sorted(
            {
                f"{item.get('node_namespace') or ''}{item.get('node_name') or ''}"
                for item in publisher_payload
                if item.get("node_name")
            }
        ),
        "subscription_nodes": sorted(
            {
                f"{item.get('node_namespace') or ''}{item.get('node_name') or ''}"
                for item in subscription_payload
                if item.get("node_name")
            }
        ),
        "publishers": publisher_payload,
        "subscriptions": subscription_payload,
    }


def _query_node_parameters(node: Any, node_name: str, parameter_names: Iterable[str], timeout_s: float = 1.0) -> dict[str, Any]:
    """Read known parameters through the standard ROS service, bounded."""

    try:
        from rcl_interfaces.srv import GetParameters
    except ImportError:
        return {"status": "UNAVAILABLE", "node": node_name, "values": {}}
    service_name = node_name.rstrip("/") + "/get_parameters"
    try:
        client = node.create_client(GetParameters, service_name)
        if not client.wait_for_service(timeout_sec=min(0.5, timeout_s)):
            node.destroy_client(client)
            return {"status": "UNAVAILABLE", "node": node_name, "values": {}}
        request = GetParameters.Request()
        request.names = list(parameter_names)
        future = client.call_async(request)
        import rclpy

        rclpy.spin_until_future_complete(node, future, timeout_sec=max(0.1, timeout_s))
        if not future.done() or future.result() is None:
            node.destroy_client(client)
            return {"status": "TIMEOUT", "node": node_name, "values": {}}
        values = future.result().values
        payload = {name: _parameter_value(value) for name, value in zip(request.names, values)}
        node.destroy_client(client)
        return {"status": "READ", "node": node_name, "values": payload}
    except Exception as exc:  # target-side API differences stay as evidence
        return {"status": "ERROR", "node": node_name, "error": type(exc).__name__, "values": {}}


def _find_node(node_names: Iterable[str], tokens: Iterable[str]) -> str | None:
    """Find a node with exact/suffix preference before broad token matching.

    A broad ``"imu"`` token otherwise selects ``imu_calib`` or
    ``ros_robot_controller`` before the actual complementary filter, which
    makes a parameter receipt look healthy while silently querying the wrong
    node.  Trace must preserve the selected node name in the artifact.
    """

    names = list(node_names)
    lowered = [(name, name.lower(), name.strip("/").lower()) for name in names]
    normalized_tokens = [str(token).strip("/").lower() for token in tokens]
    for token in normalized_tokens:
        for name, lower, bare in lowered:
            if bare == token or bare.endswith("/" + token):
                return name
    for token in normalized_tokens:
        for name, lower, _bare in lowered:
            if token and token in lower:
                return name
    return None


def collect_trace(
    duration_s: float = 10.0,
    *,
    topics: Iterable[str] = DEFAULT_TOPICS,
    imu_use_mag: bool | None = None,
    imu_yaw_mode: str | None = None,
    odom_source: str | None = None,
    autonomous_source_confirmed: bool = False,
    publisher_user: str | None = None,
    query_parameters: bool = True,
    enable_tf: bool = True,
    max_records_per_topic: int = 20_000,
) -> dict[str, Any]:
    """Collect one bounded ROS trace and return a JSON-serializable payload."""

    duration_s = float(duration_s)
    if not math.isfinite(duration_s) or not 0 < duration_s <= 300:
        raise ValueError("duration must be a finite number in (0, 300]")
    if max_records_per_topic < 1:
        raise ValueError("max_records_per_topic must be positive")
    # ROS imports are lazy so pure helpers and replay code work off-target.
    import rclpy
    from geometry_msgs.msg import Twist
    from nav_msgs.msg import Odometry
    from sensor_msgs.msg import Imu

    try:
        from rclpy.qos import qos_profile_sensor_data
    except ImportError:
        qos_profile_sensor_data = 10
    try:
        from rclpy.qos import DurabilityPolicy, QoSProfile, ReliabilityPolicy

        tf_static_qos = QoSProfile(
            depth=10,
            reliability=ReliabilityPolicy.RELIABLE,
            durability=DurabilityPolicy.TRANSIENT_LOCAL,
        )
    except ImportError:
        tf_static_qos = 10
    try:
        from tf2_msgs.msg import TFMessage
    except ImportError:
        TFMessage = None

    rclpy.init(args=None)
    node = rclpy.create_node("rolo_odom_trace_probe")
    started = time.monotonic()
    records: dict[str, list[dict[str, Any]]] = {
        key: []
        for key in ("cmd_vel", "odom_raw", "odom", "odom_rf2o", "imu", "imu_corrected", "imu_raw")
    }
    legacy_values: dict[str, list[float]] = {
        "cmd_vel": [],
        "odom_raw_yaw": [],
        "odom_yaw": [],
        "odom_rf2o_yaw": [],
        "imu_vyaw": [],
        "imu_orientation_valid": [],
    }
    tf_pairs: set[str] = set()
    subscriptions: list[Any] = []

    def append(topic: str, item: dict[str, Any]) -> None:
        bucket = records.setdefault(topic, [])
        if len(bucket) < max_records_per_topic:
            bucket.append(item)

    def local_time() -> float:
        return time.monotonic() - started

    def on_cmd(message: Any) -> None:
        item = {
            "t": local_time(),
            "header_stamp_s": _header_stamp(message),
            "linear_x": _finite(message.linear.x),
            "linear_y": _finite(message.linear.y),
            "angular_z": _finite(message.angular.z),
        }
        append("cmd_vel", item)
        if item["angular_z"] is not None:
            legacy_values["cmd_vel"].append(item["angular_z"])

    def on_odom(topic: str, message: Any) -> None:
        q = message.pose.pose.orientation
        value = quaternion_to_yaw(q)
        item = {
            "t": local_time(),
            "header_stamp_s": _header_stamp(message),
            "yaw": value,
            "orientation_valid": value is not None,
            "orientation_norm": quaternion_norm(q),
            "angular_z": _finite(message.twist.twist.angular.z),
            "frame_id": _text(getattr(message.header, "frame_id", None)),
            "child_frame_id": _text(getattr(message, "child_frame_id", None)),
        }
        # Keep internal record keys stable (without a leading slash).  The
        # graph uses canonical ROS names, but mixing the two namespaces here
        # makes the nested observation report zero raw/EKF samples even when
        # the detailed topic summaries contain live messages.
        record_name = topic.lstrip("/")
        append(record_name, item)
        if value is not None:
            legacy_key = {
                "/odom_raw": "odom_raw_yaw",
                "/odom": "odom_yaw",
                "/odom_rf2o": "odom_rf2o_yaw",
            }.get(topic)
            if legacy_key is not None:
                legacy_values[legacy_key].append(value)

    def on_imu(topic: str, message: Any) -> None:
        q = message.orientation
        quaternion_yaw = quaternion_to_yaw(q)
        raw_covariance = getattr(message, "orientation_covariance", ())
        covariance = list(()) if raw_covariance is None else list(raw_covariance)
        covariance_status = orientation_covariance_status(covariance)
        covariance_valid = None if covariance_status is None else covariance_status == "VALID"
        # A finite quaternion is not enough to claim an absolute heading. Keep
        # it as explicitly relative-only evidence when covariance is unknown;
        # reserve ``yaw`` for a covariance-backed orientation candidate.
        value = quaternion_yaw if covariance_valid is True else None
        if covariance_valid is True and quaternion_yaw is not None:
            yaw_semantics = "ABSOLUTE_CANDIDATE"
        elif quaternion_yaw is not None:
            yaw_semantics = "RELATIVE_ONLY"
        else:
            yaw_semantics = "UNAVAILABLE"
        item = {
            "t": local_time(),
            "header_stamp_s": _header_stamp(message),
            "yaw": value,
            "orientation_valid": value is not None,
            "quaternion_valid": quaternion_yaw is not None,
            "quaternion_yaw": quaternion_yaw,
            "yaw_semantics": yaw_semantics,
            "orientation_covariance_valid": covariance_valid,
            "orientation_covariance_status": covariance_status,
            "orientation_norm": quaternion_norm(q),
            "angular_x": _finite(message.angular_velocity.x),
            "angular_y": _finite(message.angular_velocity.y),
            "angular_z": _finite(message.angular_velocity.z),
            "linear_acceleration": {
                "x": _finite(message.linear_acceleration.x),
                "y": _finite(message.linear_acceleration.y),
                "z": _finite(message.linear_acceleration.z),
            },
            "orientation_covariance": [_finite(value) for value in covariance],
            "frame_id": _text(getattr(message.header, "frame_id", None)),
        }
        append(topic, item)
        if item["angular_z"] is not None:
            legacy_values["imu_vyaw"].append(item["angular_z"])
        legacy_values["imu_orientation_valid"].append(1.0 if value is not None else 0.0)

    def on_tf(message: Any) -> None:
        for transform in getattr(message, "transforms", ()):
            parent = _text(getattr(transform.header, "frame_id", None))
            child = _text(getattr(transform, "child_frame_id", None))
            if parent and child:
                tf_pairs.add(f"{parent.strip('/')}->{child.strip('/')}")

    try:
        subscriptions.append(node.create_subscription(Twist, "/controller/cmd_vel", on_cmd, qos_profile_sensor_data))
        for topic in ("/odom_raw", "/odom", "/odom_rf2o"):
            subscriptions.append(
                node.create_subscription(
                    Odometry,
                    topic,
                    lambda message, topic=topic: on_odom(topic, message),
                    qos_profile_sensor_data,
                )
            )
        for topic, record_name in (("/imu", "imu"), ("/imu_corrected", "imu_corrected"), ("/ros_robot_controller/imu_raw", "imu_raw")):
            subscriptions.append(
                node.create_subscription(
                    Imu,
                    topic,
                    lambda message, topic=record_name: on_imu(topic, message),
                    qos_profile_sensor_data,
                )
            )
        if enable_tf and TFMessage is not None:
            for topic in ("/tf", "/tf_static"):
                try:
                    subscriptions.append(
                        node.create_subscription(
                            TFMessage,
                            topic,
                            on_tf,
                            tf_static_qos if topic == "/tf_static" else 10,
                        )
                    )
                except Exception:
                    pass
        while time.monotonic() - started < duration_s and rclpy.ok():
            rclpy.spin_once(node, timeout_sec=0.05)

        topic_names = tuple(dict.fromkeys(str(topic) for topic in topics))
        graph = {topic: _safe_endpoint_query(node, topic) for topic in topic_names}
        try:
            node_names = sorted(
                {
                    f"{namespace.rstrip('/')}/{name.lstrip('/')}"
                    if namespace not in {"", "/"}
                    else f"/{name.lstrip('/') }"
                    for name, namespace in node.get_node_names_and_namespaces()
                }
            )
        except Exception:
            node_names = []
        try:
            service_names = sorted({str(name) for name, _types in node.get_service_names_and_types()})
        except Exception:
            service_names = []
        parameters: dict[str, Any] = {}
        if query_parameters:
            ekf_name = _find_node(node_names, ("ekf_filter_node", "ekf"))
            imu_name = _find_node(node_names, ("imu_filter", "imu"))
            if ekf_name:
                parameters["ekf"] = _query_node_parameters(node, ekf_name, PARAMETER_NAMES)
            if imu_name and imu_name != ekf_name:
                parameters["imu_filter"] = _query_node_parameters(
                    node,
                    imu_name,
                    ("use_mag", "do_bias_estimation", "do_adaptive_gain"),
                )
        # Parameter evidence can fill in an explicit use_mag value when the
        # caller did not provide one.  Unknown remains unknown; no inference
        # from a finite quaternion is allowed.
        if imu_use_mag is None:
            for item in parameters.values():
                candidate = item.get("values", {}).get("use_mag") if isinstance(item, Mapping) else None
                if isinstance(candidate, bool):
                    imu_use_mag = candidate
                    break
        environment = _env_evidence()
        observation = _build_observation(
            duration_s=duration_s,
            graph=graph,
            records=records,
            parameters=parameters,
            environment=environment,
            node_names=node_names,
            service_names=service_names,
            executor_user=getuser(),
            publisher_user=publisher_user or os.environ.get("ROLO_PUBLISHER_USER"),
            rmw_implementation=os.environ.get("RMW_IMPLEMENTATION"),
            imu_use_mag=imu_use_mag,
            imu_yaw_mode=imu_yaw_mode or os.environ.get("ROLO_IMU_YAW_MODE"),
            odom_source=odom_source or os.environ.get("ROLO_ODOM_SOURCE"),
            autonomous_source_confirmed=bool(autonomous_source_confirmed),
            tf_pairs=tf_pairs,
        )
    finally:
        for subscription in subscriptions:
            try:
                node.destroy_subscription(subscription)
            except Exception:
                pass
        node.destroy_node()
        rclpy.shutdown()

    # Keep the original compact scalar series for compatibility with the
    # first probe artifact, and add detailed records/derived evidence beside
    # it.  Values are capped by max_records_per_topic above.
    legacy_series: dict[str, Any] = {}
    for topic, values in legacy_values.items():
        legacy_series[topic] = _series_summary(values)
    detailed_summaries = {
        topic: _topic_summary(
            items,
            value_key="yaw" if topic.startswith("odom") else "angular_z" if topic == "cmd_vel" else None,
        )
        for topic, items in records.items()
    }
    return {
        "schema_version": TRACE_SCHEMA_VERSION,
        "observed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "duration_s": duration_s,
        "samples": sum(len(items) for items in records.values()),
        "executor_user": getuser(),
        "executor_uid": os.geteuid() if hasattr(os, "geteuid") else None,
        "publisher_user": publisher_user or os.environ.get("ROLO_PUBLISHER_USER"),
        "rmw_implementation": os.environ.get("RMW_IMPLEMENTATION"),
        "ros_domain_id": os.environ.get("ROS_DOMAIN_ID"),
        "graph": graph,
        "nodes": node_names,
        "services": service_names,
        "series": legacy_series,
        "topic_summaries": detailed_summaries,
        "sample_records": records,
        "tf_pairs": sorted(tf_pairs),
        "parameters": parameters,
        "launch_environment": environment,
        "observation": observation,
        "limitations": observation["limitations"],
    }


def run(duration_s: float = 10.0, **kwargs: Any) -> dict[str, Any]:
    """Compatibility wrapper used by operators and tests."""

    return collect_trace(duration_s, **kwargs)


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Collect a read-only LanderPi ROS2 odom/EKF trace")
    parser.add_argument("duration", nargs="?", type=float, help="capture duration in seconds (legacy positional form)")
    parser.add_argument("--duration", dest="duration_flag", type=float, help="capture duration in seconds")
    parser.add_argument("--output", type=str, help="write JSON artifact to this path")
    parser.add_argument("--imu-use-mag", choices=("true", "false", "unknown"), default="unknown")
    parser.add_argument("--imu-yaw-mode", choices=("unset", "relative", "absolute", "unknown"), default="unknown")
    parser.add_argument("--odom-source", choices=("command_integration", "measured_feedback", "unknown"), default="unknown")
    parser.add_argument(
        "--autonomous-source-confirmed",
        action="store_true",
        help="record the operator's confirmation of the designated autonomous command source",
    )
    parser.add_argument("--publisher-user", default=None, help="declared ROS publisher OS user (metadata only)")
    parser.add_argument("--no-parameter-query", action="store_true", help="skip read-only parameter services")
    parser.add_argument("--no-tf", action="store_true", help="skip /tf subscriptions")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    duration = args.duration_flag if args.duration_flag is not None else args.duration
    duration = 10.0 if duration is None else duration
    source_map = {
        "command_integration": "COMMAND_INTEGRATION",
        "measured_feedback": "MEASURED_FEEDBACK",
        "unknown": "UNKNOWN",
    }
    mode_map = {"unset": "UNSET", "relative": "RELATIVE", "absolute": "ABSOLUTE", "unknown": "UNKNOWN"}
    try:
        result = collect_trace(
            duration,
            imu_use_mag=_bool_arg(args.imu_use_mag),
            imu_yaw_mode=mode_map[args.imu_yaw_mode],
            odom_source=source_map[args.odom_source],
            autonomous_source_confirmed=args.autonomous_source_confirmed,
            publisher_user=args.publisher_user,
            query_parameters=not args.no_parameter_query,
            enable_tf=not args.no_tf,
        )
    except (ImportError, OSError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    encoded = json.dumps(result, ensure_ascii=False, separators=(",", ":"))
    if args.output:
        output_path = os.path.abspath(args.output)
        temporary = output_path + ".tmp"
        with open(temporary, "w", encoding="utf-8") as stream:
            stream.write(encoded + "\n")
        os.replace(temporary, output_path)
    print(encoded)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
