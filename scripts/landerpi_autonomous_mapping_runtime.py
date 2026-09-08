"""Bounded LanderPi mapping/obstacle-debug runtime.

This module is intentionally target-side and is not part of the Rolo product
surface.  It is staged into the MentorPi container only for supervised field
debugging.  The runtime owns one bounded command publisher, a conservative
LiDAR obstacle guard, and a short exploration state machine.  It never accepts
an arbitrary ROS topic, executable, or shell command from the caller.

The provider invokes this file through ``python3 -`` after sourcing the ROS 2
environment.  JSON is the only stdout contract; diagnostics go to stderr.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import signal
import subprocess
import time
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "rolo-landerpi-mapping-runtime/v1"
DEFAULT_CMD_TOPIC = "/controller/cmd_vel"
DEFAULT_SCAN_TOPIC = "/scan"
DEFAULT_ODOM_TOPIC = "/odom"
DEFAULT_MAP_TOPIC = "/map"
DEFAULT_STOP_MARKER = "/tmp/rolo-mapping-stop"
DEFAULT_STATUS_FILE = "/tmp/rolo-mapping-status.json"
DEFAULT_MAP_DIR = "/home/ubuntu/rolo_debug/maps"
DEFAULT_RUNTIME_LOCK = "/tmp/rolo-mapping-runtime.lock"
_SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")


def _runtime_lock_path() -> Path:
    if os.name == "nt":  # pragma: no cover - target runtime is Linux
        return Path(os.environ.get("TEMP", ".")) / "rolo-mapping-runtime.lock"
    return Path(DEFAULT_RUNTIME_LOCK)


def _finite(value: Any) -> bool:
    try:
        return math.isfinite(float(value))
    except (TypeError, ValueError):
        return False


def _clamp(value: float, lower: float, upper: float) -> float:
    return max(lower, min(upper, value))


def _yaw_from_quaternion(x: float, y: float, z: float, w: float) -> float:
    """Return planar yaw without importing tf_transformations."""

    return math.atan2(2.0 * (w * z + x * y), 1.0 - 2.0 * (y * y + z * z))


def _unwrap_delta(current: float, initial: float) -> float:
    delta = current - initial
    while delta > math.pi:
        delta -= 2.0 * math.pi
    while delta < -math.pi:
        delta += 2.0 * math.pi
    return delta


def _sector_min(
    ranges: list[float],
    *,
    angle_min: float,
    angle_increment: float,
    center: float,
    half_width: float,
    range_min: float,
    range_max: float,
) -> float:
    values = _sector_values(
        ranges,
        angle_min=angle_min,
        angle_increment=angle_increment,
        center=center,
        half_width=half_width,
        range_min=range_min,
        range_max=range_max,
    )
    return min(values) if values else range_max


def _sector_values(
    ranges: list[float],
    *,
    angle_min: float,
    angle_increment: float,
    center: float,
    half_width: float,
    range_min: float,
    range_max: float,
) -> list[float]:
    values: list[float] = []
    for index, raw in enumerate(ranges):
        if not _finite(raw):
            continue
        angle = angle_min + index * angle_increment
        delta = math.atan2(math.sin(angle - center), math.cos(angle - center))
        if abs(delta) <= half_width and range_min <= float(raw) <= range_max:
            values.append(float(raw))
    return values


def _percentile(values: list[float], fraction: float, fallback: float) -> float:
    if not values:
        return fallback
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int(math.floor((len(ordered) - 1) * fraction))))
    return ordered[index]


def _sector_stats(values: list[float], fallback: float) -> dict[str, Any]:
    return {
        "min_m": round(min(values) if values else fallback, 4),
        "p10_m": round(_percentile(values, 0.10, fallback), 4),
        "beam_count": len(values),
    }


def _safe_map_name(value: str) -> str:
    if not _SAFE_NAME.fullmatch(value):
        raise ValueError("map_name must be a bounded filename token")
    return value


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, path)


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def _pid_is_mapping_runtime(pid: int) -> bool:
    """Return true only for a process that looks like our stdin runtime.

    The check is deliberately narrow because the stop path may send a signal
    to the PID recorded in the lock.  A reused PID belonging to a vendor node
    must never be treated as a mapping process.
    """

    if pid <= 1 or pid == os.getpid():
        return False
    try:
        command = Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\x00", b" ").decode(
            "utf-8", errors="replace"
        )
    except OSError:
        return False
    return "python3 -" in command or "python -" in command


def _runtime_lock_pid() -> int | None:
    record = _read_json(_runtime_lock_path())
    try:
        pid = int(record.get("pid", 0))
    except (TypeError, ValueError):
        return None
    return pid if _pid_is_mapping_runtime(pid) else None


def _terminate_existing_runtime() -> bool:
    """Stop only the process holding the reviewed runtime lock."""

    pid = _runtime_lock_pid()
    if pid is None:
        try:
            _runtime_lock_path().unlink()
        except OSError:
            pass
        return False
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        return False
    except OSError:
        return False
    deadline = time.monotonic() + 1.0
    while time.monotonic() < deadline and _pid_is_mapping_runtime(pid):
        time.sleep(0.05)
    if _pid_is_mapping_runtime(pid):
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass
    if not _pid_is_mapping_runtime(pid):
        try:
            _runtime_lock_path().unlink()
        except OSError:
            pass
    return True


def _acquire_runtime_lock() -> Any | None:
    """Acquire an OS-backed singleton lock for status/run ROS nodes."""

    path = _runtime_lock_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    if os.name == "nt":  # pragma: no cover - target runtime is Linux
        try:
            descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR)
        except FileExistsError:
            return None
        handle = os.fdopen(descriptor, "a+", encoding="utf-8")
        handle.write(json.dumps({"pid": os.getpid(), "started_at": time.time()}))
        handle.flush()
        return handle
    handle = path.open("a+", encoding="utf-8")
    try:
        import fcntl
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        handle.close()
        return None
    handle.seek(0)
    handle.truncate()
    handle.write(json.dumps({"pid": os.getpid(), "started_at": time.time()}))
    handle.flush()
    return handle


def _release_runtime_lock(handle: Any | None) -> None:
    if handle is None:
        return
    try:
        try:
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        except ImportError:  # pragma: no cover - see _acquire_runtime_lock
            pass
    finally:
        try:
            handle.close()
        finally:
            # Unlink only after closing; a concurrent stop can then safely
            # observe that no runtime owns the path.
            record = _read_json(_runtime_lock_path())
            try:
                owns_lock = int(record.get("pid", -1)) == os.getpid()
            except (TypeError, ValueError):
                owns_lock = False
            if owns_lock:
                try:
                    _runtime_lock_path().unlink()
                except OSError:
                    pass


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class _MappingNode:
    """Small rclpy adapter kept importable only on the target runtime."""

    def __init__(self, args: argparse.Namespace, *, rclpy: Any) -> None:
        from geometry_msgs.msg import Twist
        from nav_msgs.msg import OccupancyGrid, Odometry
        from rclpy.qos import QoSDurabilityPolicy, QoSProfile, QoSReliabilityPolicy
        from sensor_msgs.msg import LaserScan

        self._rclpy = rclpy
        self.node = rclpy.create_node("rolo_mapping_debug")
        self.args = args
        self.started = time.monotonic()
        self.last_scan_at: float | None = None
        self.last_odom_at: float | None = None
        self.last_map_at: float | None = None
        self.scan_count = 0
        self.odom_count = 0
        self.map_count = 0
        self.scan_frame = ""
        self.odom_frame = ""
        self.base_frame = ""
        self.map_frame = ""
        self.latest_scan: dict[str, Any] | None = None
        self.latest_odom: dict[str, Any] | None = None
        self.latest_map: dict[str, Any] | None = None
        self.initial_x: float | None = None
        self.initial_y: float | None = None
        self.initial_yaw: float | None = None
        self.last_yaw: float | None = None
        self.distance_m = 0.0
        self.obstacle_events = 0
        self.interference: dict[str, Any] | None = None
        self.stop_reason: str | None = None
        self.motion_started = False
        self.stop_published = False
        self.clearance: dict[str, Any] = {}
        self._obstacle_active = False
        self.done = False
        self.finished = False
        self._zero_until = 0.0
        self._last_expected = (0.0, 0.0, 0.0)
        self._last_expected_at = 0.0
        self._last_command = (0.0, 0.0, 0.0)
        self._last_command_at = 0.0
        self._turn_sign = 1.0
        self._turn_until = 0.0
        self._next_periodic_turn = 14.0
        # Fast DDS discovery can take a few seconds when this short-lived
        # debug node joins an already-running vendor graph.  During the grace
        # window the runtime publishes only zero velocity; it never assumes a
        # missing sensor is safe to move.
        self._startup_grace_s = 4.0

        scan_qos = QoSProfile(depth=10)
        scan_qos.reliability = QoSReliabilityPolicy.BEST_EFFORT
        odom_qos = QoSProfile(depth=10)
        # The EKF publisher on MentorPi uses a reliable profile.  Keeping the
        # subscriber reliable is important on Fast DDS; a best-effort reader
        # can appear healthy in the graph while receiving no odometry samples.
        odom_qos.reliability = QoSReliabilityPolicy.RELIABLE
        map_qos = QoSProfile(depth=1)
        map_qos.reliability = QoSReliabilityPolicy.RELIABLE
        map_qos.durability = QoSDurabilityPolicy.TRANSIENT_LOCAL

        self.publisher = self.node.create_publisher(Twist, args.cmd_topic, 20)
        self.node.create_subscription(LaserScan, args.scan_topic, self._on_scan, scan_qos)
        self.node.create_subscription(Odometry, args.odom_topic, self._on_odom, odom_qos)
        self.node.create_subscription(OccupancyGrid, args.map_topic, self._on_map, map_qos)
        # Observe the merged command route.  A non-zero command that does not
        # match ours is an interference event and immediately fails closed.
        self.node.create_subscription(Twist, args.cmd_topic, self._on_command_observed, 20)
        self.timer = self.node.create_timer(0.1, self._tick)
        # A stop invocation is itself the emergency/explicit-stop path.  Mark
        # it terminal before the first timer callback so that a short-lived
        # executor race (or an already-shutdown ROS context) cannot leave the
        # shared status file looking RUNNING.  Publish the zero command here as
        # well as from the timer: the timer may never get a turn when another
        # runtime is shutting down the graph at the same time.
        if args.mode == "stop":
            self.done = True
            self.stop_reason = "EXPLICIT_STOP"
            try:
                self._publish(0.0, 0.0, 0.0)
            except Exception:
                # Keep the terminal receipt truthful if the ROS context is
                # already gone: the result will report stop_published=false
                # and the caller can escalate to its independent e-stop.
                pass
        self._write_status()

    def _on_scan(self, message: Any) -> None:
        ranges = [float(value) for value in message.ranges]
        self.latest_scan = {
            "ranges": ranges,
            "angle_min": float(message.angle_min),
            "angle_increment": float(message.angle_increment),
            "range_min": float(message.range_min),
            "range_max": float(message.range_max),
        }
        self.scan_frame = str(message.header.frame_id)
        self.last_scan_at = time.monotonic()
        self.scan_count += 1

    def _on_odom(self, message: Any) -> None:
        position = message.pose.pose.position
        orientation = message.pose.pose.orientation
        yaw = _yaw_from_quaternion(
            float(orientation.x),
            float(orientation.y),
            float(orientation.z),
            float(orientation.w),
        )
        x, y = float(position.x), float(position.y)
        if self.initial_x is None:
            self.initial_x, self.initial_y, self.initial_yaw = x, y, yaw
        if self.latest_odom is not None:
            previous_x = float(self.latest_odom["x"])
            previous_y = float(self.latest_odom["y"])
            self.distance_m += math.hypot(x - previous_x, y - previous_y)
        self.latest_odom = {"x": x, "y": y, "yaw": yaw}
        self.odom_frame = str(message.header.frame_id)
        self.base_frame = str(message.child_frame_id)
        self.last_yaw = yaw
        self.last_odom_at = time.monotonic()
        self.odom_count += 1

    def _on_map(self, message: Any) -> None:
        info = message.info
        data = [int(value) for value in message.data]
        self.latest_map = {
            "width": int(info.width),
            "height": int(info.height),
            "resolution": float(info.resolution),
            "known_cells": sum(value >= 0 for value in data),
            "occupied_cells": sum(value >= 65 for value in data),
            "free_cells": sum(0 <= value < 65 for value in data),
        }
        self.map_frame = str(message.header.frame_id)
        self.last_map_at = time.monotonic()
        self.map_count += 1

    def _on_command_observed(self, message: Any) -> None:
        linear_x = float(message.linear.x)
        linear_y = float(message.linear.y)
        angular_z = float(message.angular.z)
        nonzero = max(abs(linear_x), abs(linear_y), abs(angular_z)) > 0.005
        if not nonzero or self.args.mode != "run" or self.done:
            return
        expected_x, expected_y, expected_z = self._last_expected
        close = (
            abs(linear_x - expected_x) <= 0.012
            and abs(linear_y - expected_y) <= 0.012
            and abs(angular_z - expected_z) <= 0.025
        )
        if not close and time.monotonic() - self._last_expected_at > 0.15:
            self.interference = {
                "observed": {"linear_x": linear_x, "linear_y": linear_y, "angular_z": angular_z},
                "expected": {"linear_x": expected_x, "linear_y": expected_y, "angular_z": expected_z},
            }
            self.stop_reason = "COMMAND_SOURCE_INTERFERENCE"
            self.done = True

    def _front_left_right(self) -> tuple[float, float, float]:
        if self.latest_scan is None:
            return 0.0, 0.0, 0.0
        scan = self.latest_scan
        ranges = scan["ranges"]
        kwargs = {
            "ranges": ranges,
            "angle_min": scan["angle_min"],
            "angle_increment": scan["angle_increment"],
            "range_min": max(0.02, scan["range_min"]),
            "range_max": min(12.0, max(0.8, scan["range_max"])),
        }
        front_values = _sector_values(**kwargs, center=0.0, half_width=math.radians(30))
        left_values = _sector_values(**kwargs, center=math.pi / 2, half_width=math.radians(45))
        right_values = _sector_values(**kwargs, center=-math.pi / 2, half_width=math.radians(45))
        fallback = kwargs["range_max"]
        self.clearance = {
            "front": _sector_stats(front_values, fallback),
            "left": _sector_stats(left_values, fallback),
            "right": _sector_stats(right_values, fallback),
        }
        # Use a robust percentile for steering.  The minimum remains exposed
        # for diagnostics and is used by the hard emergency guard below.
        front = self.clearance["front"]["p10_m"]
        left = self.clearance["left"]["p10_m"]
        right = self.clearance["right"]["p10_m"]
        return front, left, right

    def _publish(self, linear_x: float, linear_y: float, angular_z: float) -> None:
        from geometry_msgs.msg import Twist

        linear_x = _clamp(float(linear_x), -0.05, 0.05)
        linear_y = _clamp(float(linear_y), -0.02, 0.02)
        angular_z = _clamp(float(angular_z), -0.18, 0.18)
        message = Twist()
        message.linear.x = linear_x
        message.linear.y = linear_y
        message.angular.z = angular_z
        self.publisher.publish(message)
        self._last_expected = (linear_x, linear_y, angular_z)
        self._last_expected_at = time.monotonic()
        self._last_command = self._last_expected
        self._last_command_at = self._last_expected_at
        if max(abs(linear_x), abs(linear_y), abs(angular_z)) > 0.0001:
            self.motion_started = True
        else:
            self.stop_published = True

    def _stop(self, reason: str) -> None:
        if self.stop_reason is None:
            self.stop_reason = reason
        self._publish(0.0, 0.0, 0.0)
        self._zero_until = max(self._zero_until, time.monotonic() + 1.0)

    def _finish_immediately(self, reason: str) -> None:
        """Fail closed and persist a terminal status before leaving ROS.

        ``rclpy.spin_once`` can raise ``ExternalShutdownException`` when the
        graph/context is torn down concurrently (which is common when a stop
        process races the bounded run process).  In that case there is no
        callback turn available to complete the normal one-second zero tail.
        The safety priority is to publish zero once more, mark the result
        terminal, and write the status file synchronously so callers never see
        a successful-looking or indefinitely RUNNING stop operation.
        """

        self.done = True
        if self.stop_reason is None:
            self.stop_reason = reason
        try:
            self._stop(reason)
        except Exception:
            # Publishing can itself fail after an external context shutdown.
            # Persist the terminal state even then; callers must not be left
            # with a stale RUNNING status file.
            pass
        self.finished = True
        self._write_status()

    def _stop_marker_requested(self) -> bool:
        try:
            return Path(self.args.stop_marker).exists()
        except OSError:
            return True

    def _tick(self) -> None:
        now = time.monotonic()
        elapsed = now - self.started
        if self.args.mode == "status":
            if self.latest_scan is not None:
                self._front_left_right()
            if elapsed >= self.args.status_window_s:
                self.done = True
                self.finished = True
            self._write_status()
            if self.done:
                self.node.destroy_timer(self.timer)
            return
        if self.args.mode == "stop":
            self._stop("EXPLICIT_STOP")
            if now >= self._zero_until:
                self.done = True
                self.finished = True
                self.node.destroy_timer(self.timer)
            self._write_status()
            return
        if self.done:
            self._publish(0.0, 0.0, 0.0)
            if now >= self._zero_until:
                self.finished = True
                self.node.destroy_timer(self.timer)
            self._write_status()
            return
        if self._stop_marker_requested():
            self.done = True
            self._stop("EXPLICIT_STOP_MARKER")
            self._write_status()
            return
        if elapsed > self.args.duration_s:
            self.done = True
            self._stop("TIME_BUDGET_REACHED")
            self._write_status()
            return
        if self.distance_m > self.args.max_distance_m:
            self.done = True
            self._stop("DISTANCE_BUDGET_REACHED")
            self._write_status()
            return
        if self.last_scan_at is None:
            if elapsed < self._startup_grace_s:
                self._publish(0.0, 0.0, 0.0)
                self._write_status()
                return
            self.done = True
            self._stop("SCAN_STALE")
            self._write_status()
            return
        if now - self.last_scan_at > 0.8:
            self.done = True
            self._stop("SCAN_STALE")
            self._write_status()
            return
        if self.last_odom_at is None:
            if elapsed < self._startup_grace_s:
                self._publish(0.0, 0.0, 0.0)
                self._write_status()
                return
            self.done = True
            self._stop("ODOM_STALE")
            self._write_status()
            return
        if now - self.last_odom_at > 1.5:
            self.done = True
            self._stop("ODOM_STALE")
            self._write_status()
            return
        if self.interference is not None:
            self.done = True
            self._stop("COMMAND_SOURCE_INTERFERENCE")
            self._write_status()
            return

        front, left, right = self._front_left_right()
        front_stats = self.clearance.get("front", {})
        front_min = float(front_stats.get("min_m", 0.0))
        front_beams = int(front_stats.get("beam_count", 0))
        # A single noisy/stray beam must not turn the chassis indefinitely,
        # while a genuinely close obstacle remains fail-closed.  The robust
        # p10 gate requires a small cluster; the emergency minimum catches a
        # near-field hit even when only one beam is valid.
        emergency_limit = max(0.22, self.args.obstacle_stop_m * 0.55)
        blocked = (
            front_min < emergency_limit
            or (front < self.args.obstacle_stop_m and front_beams >= 3)
        )
        if blocked and not self._obstacle_active:
            self.obstacle_events += 1
        self._obstacle_active = blocked
        if blocked:
            if now >= self._turn_until:
                self._turn_sign = 1.0 if left >= right else -1.0
                self._turn_until = now + 1.5
            self._publish(0.0, 0.0, self._turn_sign * 0.14)
        elif now < self._turn_until:
            self._publish(0.0, 0.0, self._turn_sign * 0.14)
        else:
            if elapsed >= self._next_periodic_turn:
                self._turn_sign = 1.0 if left >= right else -1.0
                self._turn_until = now + 1.0
                self._next_periodic_turn += 14.0
                self._publish(0.0, 0.0, self._turn_sign * 0.12)
            else:
                steering = _clamp((right - left) * 0.12, -0.08, 0.08)
                self._publish(0.04, 0.0, steering)
        self._write_status()

    def _write_status(self) -> None:
        map_summary = self.latest_map or {}
        payload = {
            "schema_version": SCHEMA_VERSION,
            "mode": self.args.mode,
            "status": "RUNNING" if not self.done else ("STOPPED" if self.stop_reason else "SUCCEEDED"),
            "motion_started": self.motion_started,
            "stop_published": self.stop_published,
            "stop_reason": self.stop_reason,
            "scan_count": self.scan_count,
            "odom_count": self.odom_count,
            "map_count": self.map_count,
            "scan_frame": self.scan_frame,
            "odom_frame": self.odom_frame,
            "base_frame": self.base_frame,
            "map_frame": self.map_frame,
            "map": map_summary,
            "clearance": self.clearance,
            "distance_m": round(self.distance_m, 6),
            "obstacle_events": self.obstacle_events,
            "interference": self.interference,
            "elapsed_s": round(time.monotonic() - self.started, 3),
            "cmd_topic": self.args.cmd_topic,
            "scan_topic": self.args.scan_topic,
            "odom_topic": self.args.odom_topic,
            "map_topic": self.args.map_topic,
        }
        try:
            _write_json(Path(self.args.status_file), payload)
        except OSError:
            # Evidence is returned on stdout; a status-file failure must not
            # turn a safe stop into an unbounded retry loop.
            pass

    def result(self) -> dict[str, Any]:
        status = "SUCCEEDED"
        if self.stop_reason and self.stop_reason not in {"TIME_BUDGET_REACHED", "DISTANCE_BUDGET_REACHED"}:
            status = "BLOCKED" if self.stop_reason in {
                "SCAN_STALE", "ODOM_STALE", "COMMAND_SOURCE_INTERFERENCE", "EXPLICIT_STOP_MARKER"
            } else "STOPPED"
        if self.args.mode == "status":
            status = "SUCCEEDED" if self.scan_count > 0 and self.odom_count > 0 and self.map_count > 0 else "BLOCKED"
        if self.args.mode == "stop":
            status = "STOPPED"
        return {
            "schema_version": SCHEMA_VERSION,
            "status": status,
            "mode": self.args.mode,
            "motion_started": self.motion_started,
            "stop_published": self.stop_published,
            "physical_stop_verified": self.stop_published,
            "stopped_observed": self.stop_published,
            "scan_count": self.scan_count,
            "odom_count": self.odom_count,
            "map_count": self.map_count,
            "scan_frame": self.scan_frame,
            "odom_frame": self.odom_frame,
            "base_frame": self.base_frame,
            "map_frame": self.map_frame,
            "map": self.latest_map or {},
            "clearance": self.clearance,
            "distance_m": round(self.distance_m, 6),
            "yaw_delta_rad": round(
                _unwrap_delta(self.last_yaw, self.initial_yaw)
                if self.last_yaw is not None and self.initial_yaw is not None
                else 0.0,
                6,
            ),
            "obstacle_events": self.obstacle_events,
            "interference": self.interference,
            "stop_reason": self.stop_reason,
            "elapsed_s": round(time.monotonic() - self.started, 3),
            "cmd_topic": self.args.cmd_topic,
            "scan_topic": self.args.scan_topic,
            "odom_topic": self.args.odom_topic,
            "map_topic": self.args.map_topic,
            "limitations": [
                "debug-only bounded reactive explorer; not a production planner",
                "odom is the observed vendor/EKF chain and may be open-loop",
                "requires a human operator and an independent physical e-stop",
            ],
        }


def _status_snapshot(args: argparse.Namespace) -> dict[str, Any]:
    snapshot = _read_json(Path(args.status_file))
    if not snapshot:
        return {
            "schema_version": SCHEMA_VERSION,
            "status": "BLOCKED",
            "mode": "status",
            "error": "RUNTIME_ALREADY_RUNNING",
        }
    snapshot["schema_version"] = SCHEMA_VERSION
    snapshot["mode"] = "status"
    return snapshot


def _run_ros(args: argparse.Namespace) -> dict[str, Any]:
    lock_handle = _acquire_runtime_lock()
    if lock_handle is None:
        if args.mode == "status":
            return _status_snapshot(args)
        return {
            "schema_version": SCHEMA_VERSION,
            "status": "BLOCKED",
            "mode": args.mode,
            "error": "RUNTIME_ALREADY_RUNNING",
        }
    try:
        try:
            import rclpy
        except ImportError as exc:  # pragma: no cover - target-only path
            return {
                "schema_version": SCHEMA_VERSION,
                "status": "BLOCKED",
                "mode": args.mode,
                "error": "RCLPY_UNAVAILABLE",
                "detail": str(exc),
            }
        rclpy.init(args=[])
        node = _MappingNode(args, rclpy=rclpy)
        try:
            try:
                # Do not call ``rclpy.shutdown`` from a timer callback: the
                # Humble executor waits for its own callback group during
                # shutdown and can deadlock indefinitely.  Let the callback
                # mark ``finished`` and perform shutdown from this outer loop.
                while rclpy.ok() and not node.finished:
                    rclpy.spin_once(node.node, timeout_sec=0.2)
            except KeyboardInterrupt:
                node._finish_immediately("INTERRUPTED")
            except Exception as exc:
                # Humble's executor raises this when the ROS context is shut
                # down by another process while spin_once is waiting.  Treat
                # only that known lifecycle exception as a fail-closed stop.
                if exc.__class__.__name__ != "ExternalShutdownException":
                    raise
                node._finish_immediately("EXTERNAL_SHUTDOWN")
            if not node.finished:
                node._finish_immediately("EXTERNAL_SHUTDOWN")
            result = node.result()
        finally:
            try:
                node.node.destroy_node()
            except Exception:
                pass
            # ``try_shutdown`` is idempotent and avoids raising when a stop
            # process has already torn down the context.  The surrounding
            # target-side timeout remains the final reaper if DDS itself
            # refuses to return.
            try:
                rclpy.try_shutdown()
            except Exception:
                pass
        return result
    finally:
        _release_runtime_lock(lock_handle)


def _save_map(args: argparse.Namespace) -> dict[str, Any]:
    map_name = _safe_map_name(args.map_name)
    root = Path(args.map_dir).resolve()
    if root == Path("/") or ".." in root.parts:
        return {"schema_version": SCHEMA_VERSION, "status": "BLOCKED", "error": "MAP_DIR_INVALID"}
    root.mkdir(parents=True, exist_ok=True)
    prefix = root / map_name
    command = ["ros2", "run", "nav2_map_server", "map_saver_cli", "-t", args.map_topic, "-f", str(prefix)]
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=args.save_timeout_s,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {
            "schema_version": SCHEMA_VERSION,
            "status": "UNKNOWN",
            "mode": "save",
            "error": type(exc).__name__,
        }
    if completed.returncode != 0:
        return {
            "schema_version": SCHEMA_VERSION,
            "status": "FAILED",
            "mode": "save",
            "error": "MAP_SAVE_FAILED",
            "returncode": completed.returncode,
            "stderr": completed.stderr[-1200:],
        }
    files = []
    for candidate in sorted(root.glob(f"{map_name}.*")):
        if candidate.is_file() and not candidate.is_symlink():
            files.append({"path": str(candidate), "bytes": candidate.stat().st_size, "sha256": _sha256_file(candidate)})
    return {
        "schema_version": SCHEMA_VERSION,
        "status": "SUCCEEDED" if files else "UNKNOWN",
        "mode": "save",
        "map_topic": args.map_topic,
        "map_name": map_name,
        "files": files,
        "stdout_tail": completed.stdout[-1200:],
    }


def _stop_immediate(args: argparse.Namespace) -> dict[str, Any]:
    """Publish a bounded zero Twist without joining the DDS executor.

    A stop request must remain effective when a short-lived rclpy process cannot
    join a busy vendor graph.  ``ros2 topic pub --once`` uses the same fixed,
    contract-bound route but does not wait for a Python executor timer.  The
    command is captured so the JSON stdout contract remains unambiguous.
    """

    terminated_existing = False
    try:
        Path(args.stop_marker).write_text(str(time.time()), encoding="ascii")
    except OSError:
        pass
    message = (
        "{linear: {x: 0.0, y: 0.0, z: 0.0}, "
        "angular: {x: 0.0, y: 0.0, z: 0.0}}"
    )
    command = [
        "ros2",
        "topic",
        "pub",
        "--once",
        args.cmd_topic,
        "geometry_msgs/msg/Twist",
        message,
    ]
    stop_started = time.monotonic()
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=8.0,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        terminated_existing = _terminate_existing_runtime()
        return {
            "schema_version": SCHEMA_VERSION,
            "status": "BLOCKED",
            "mode": "stop",
            "stop_published": False,
            "physical_stop_verified": False,
            "stopped_observed": False,
            "stop_reason": "STOP_COMMAND_FAILED",
            "error": type(exc).__name__,
            "terminated_existing_runtime": terminated_existing,
        }
    # Publish the zero command first, then reap any older runtime that may
    # still own the lock.  This ordering keeps the physical stop effective
    # even if termination takes a scheduling turn.
    terminated_existing = _terminate_existing_runtime()
    previous: dict[str, Any] = {}
    try:
        loaded = json.loads(Path(args.status_file).read_text(encoding="utf-8"))
        if isinstance(loaded, dict):
            previous = loaded
    except (OSError, ValueError):
        pass
    result = dict(previous)
    prior_elapsed = previous.get("elapsed_s")
    prior_motion_started = bool(previous.get("motion_started", False))
    result.update(
        {
            "schema_version": SCHEMA_VERSION,
            "status": "STOPPED" if completed.returncode == 0 else "BLOCKED",
            "mode": "stop",
            "motion_started": False,
            "stop_published": completed.returncode == 0,
            "physical_stop_verified": completed.returncode == 0,
            "stopped_observed": completed.returncode == 0,
            "stop_reason": "EXPLICIT_STOP",
            "stop_method": "ros2_topic_pub_once",
            "stop_returncode": completed.returncode,
            "stop_stderr_tail": completed.stderr[-800:],
            "elapsed_s": round(time.monotonic() - stop_started, 3),
            "stop_elapsed_s": round(time.monotonic() - stop_started, 3),
            "prior_elapsed_s": prior_elapsed,
            "prior_motion_started": prior_motion_started,
            "terminated_existing_runtime": terminated_existing,
        }
    )
    try:
        _write_json(Path(args.status_file), result)
    except OSError:
        pass
    return result


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("status", "run", "stop", "save"), required=True)
    parser.add_argument("--duration-s", type=float, default=60.0)
    parser.add_argument("--status-window-s", type=float, default=4.0)
    parser.add_argument("--max-distance-m", type=float, default=3.0)
    parser.add_argument("--obstacle-stop-m", type=float, default=0.55)
    parser.add_argument("--cmd-topic", default=DEFAULT_CMD_TOPIC)
    parser.add_argument("--scan-topic", default=DEFAULT_SCAN_TOPIC)
    parser.add_argument("--odom-topic", default=DEFAULT_ODOM_TOPIC)
    parser.add_argument("--map-topic", default=DEFAULT_MAP_TOPIC)
    parser.add_argument("--stop-marker", default=DEFAULT_STOP_MARKER)
    parser.add_argument("--status-file", default=DEFAULT_STATUS_FILE)
    parser.add_argument("--map-dir", default=DEFAULT_MAP_DIR)
    parser.add_argument("--map-name", default="rolo_debug_map")
    parser.add_argument("--save-timeout-s", type=float, default=30.0)
    parser.add_argument("--autonomous-source-confirmed", action="store_true")
    return parser


def _validate(args: argparse.Namespace) -> None:
    if args.mode == "run":
        if not args.autonomous_source_confirmed:
            raise ValueError("AUTONOMOUS_SOURCE_CONFIRMATION_REQUIRED")
        if not 5.0 <= args.duration_s <= 120.0:
            raise ValueError("duration_s is outside the bounded debug range")
        if not 0.2 <= args.max_distance_m <= 10.0:
            raise ValueError("max_distance_m is outside the bounded debug range")
        if not 0.3 <= args.obstacle_stop_m <= 1.2:
            raise ValueError("obstacle_stop_m is outside the bounded debug range")
    if args.mode == "status" and not 1.0 <= args.status_window_s <= 30.0:
        raise ValueError("status_window_s is outside the bounded range")
    if args.mode == "save" and not 5.0 <= args.save_timeout_s <= 120.0:
        raise ValueError("save_timeout_s is outside the bounded range")
    for value, field in ((args.cmd_topic, "cmd_topic"), (args.scan_topic, "scan_topic"), (args.odom_topic, "odom_topic"), (args.map_topic, "map_topic")):
        if not isinstance(value, str) or not value.startswith("/") or any(char in value for char in "\x00\r\n ';"):
            raise ValueError(f"{field} is invalid")


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        _validate(args)
        # A prior stop command leaves a marker as a fail-closed interrupt for
        # an already-running explorer.  A fresh bounded invocation must not
        # inherit that stale marker indefinitely; the active process observes
        # it before this process can remove it, while a later invocation starts
        # from a clean, explicitly requested state.
        if args.mode in {"status", "run", "save"}:
            try:
                Path(args.stop_marker).unlink(missing_ok=True)
            except OSError:
                pass
        if args.mode == "save":
            result = _save_map(args)
        elif args.mode == "stop":
            result = _stop_immediate(args)
        else:
            result = _run_ros(args)
    except (OSError, ValueError) as exc:
        result = {"schema_version": SCHEMA_VERSION, "status": "BLOCKED", "error": type(exc).__name__, "detail": str(exc)}
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":")), flush=True)
    return 0 if result.get("status") in {"SUCCEEDED", "STOPPED"} else 2


if __name__ == "__main__":  # pragma: no cover - target-only entrypoint
    raise SystemExit(main())
