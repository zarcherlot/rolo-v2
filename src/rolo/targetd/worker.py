"""Generic signed bundle worker used by targetd.

Provider bindings stay outside this module.  A generated bundle exposes one
entrypoint with the stable ``execute(arguments)`` shape, so future tools can
reuse the same runtime without adding tool-specific branches to targetd.
"""

from __future__ import annotations

import json
import math
import subprocess
from typing import Any, Protocol

from .protocol import ExecutionBundleManifest, ProtocolError


class Provider(Protocol):
    def invoke(self, operation: str, arguments: dict[str, Any]) -> dict[str, Any]: ...


class RosContainerProvider:
    """Run a bounded ROS provider program inside an existing Docker runtime."""

    def __init__(
        self, container: str = "MentorPi", *, timeout_s: float = 120.0,
        container_user: str = "ubuntu",
    ) -> None:
        if not container or any(c in container for c in "\x00\r\n '"):
            raise ValueError("ROS container name is invalid")
        if not container_user or any(c in container_user for c in "\x00\r\n '"):
            raise ValueError("ROS container user is invalid")
        if not math.isfinite(float(timeout_s)) or float(timeout_s) <= 0:
            raise ValueError("ROS provider timeout is invalid")
        self.container = container
        self.container_user = container_user
        self.timeout_s = float(timeout_s)

    def invoke(self, operation: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if operation != "base.rotate":
            raise ProtocolError(f"ROS provider operation is not registered: {operation}")
        try:
            angle = float(arguments["angle_degrees"])
            speed = float(arguments["max_speed_rad_s"])
        except (KeyError, TypeError, ValueError) as exc:
            raise ProtocolError("rotate arguments are invalid") from exc
        if not math.isfinite(angle) or not math.isfinite(speed) or speed <= 0 or abs(angle) > 360:
            raise ProtocolError("rotate arguments are outside provider limits")
        command = [
            "docker", "exec", "-i", "-u", self.container_user, self.container,
            "bash", "--noprofile", "--norc", "-c",
            "if [ -f /opt/ros/humble/setup.bash ]; then . /opt/ros/humble/setup.bash; fi; "
            "if [ -f /home/ubuntu/ros2_ws/install/setup.bash ]; then . /home/ubuntu/ros2_ws/install/setup.bash; fi; "
            "exec python3 -",
        ]
        program = _ROS_ROTATE_PROGRAM.replace(
            "__ROLO_ARGS__", json.dumps({"angle_degrees": angle, "max_speed_rad_s": speed})
        )
        try:
            completed = subprocess.run(
                command, input=f"{program}\n", text=True,
                capture_output=True, check=False, timeout=max(1.0, self.timeout_s + 1.5),
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ProtocolError(f"ROS provider execution failed: {exc}") from exc
        if completed.returncode != 0:
            raise ProtocolError(f"ROS provider exited {completed.returncode}: {completed.stderr[-512:]}")
        try:
            result = json.loads(completed.stdout.strip().splitlines()[-1])
        except (IndexError, json.JSONDecodeError) as exc:
            raise ProtocolError("ROS provider returned invalid JSON") from exc
        if not isinstance(result, dict):
            raise ProtocolError("ROS provider result is not an object")
        return result


_ROS_ROTATE_PROGRAM = r'''
import json, math, time
import rclpy
from geometry_msgs.msg import Twist
from nav_msgs.msg import Odometry

args = __ROLO_ARGS__
angle = float(args["angle_degrees"])
speed = float(args["max_speed_rad_s"])
endpoint = "/controller/cmd_vel"
odom_endpoint = "/odom"
tolerance = math.radians(3.0)
target = abs(math.radians(angle))
direction = 1.0 if angle >= 0 else -1.0
max_duration = max(5.0, min(60.0, target / speed * 2.5 + 3.0))

def yaw_from_quaternion(q):
    return math.atan2(2.0 * (q.w * q.z + q.x * q.y),
                      1.0 - 2.0 * (q.y * q.y + q.z * q.z))

def angle_delta(current, initial):
    return math.atan2(math.sin(current - initial), math.cos(current - initial))

rclpy.init(args=None)
node = rclpy.create_node("rolo_signed_bundle_rotate")
publisher = None
latest_yaw = None
initial_yaw = None
last_sample = None

def odom_callback(message):
    global latest_yaw, last_sample
    latest_yaw = yaw_from_quaternion(message.pose.pose.orientation)
    last_sample = time.monotonic()

subscription = node.create_subscription(Odometry, odom_endpoint, odom_callback, 10)
status = "BLOCKED"
error = None
measured = 0.0
discovered_command_publishers = 0
started = time.monotonic()
try:
    # The field profile designates this provider as the autonomous command
    # source.  Other discovered publishers (for example joystick/app nodes)
    # are recorded by the ROS graph but are outside this canary's command
    # contract and must not be treated as an automatic failure.
    while time.monotonic() - started < 3.0 and rclpy.ok():
        rclpy.spin_once(node, timeout_sec=0.05)
        discovered_command_publishers = node.count_publishers(endpoint)
        if node.count_subscribers(endpoint) > 0 and latest_yaw is not None:
            initial_yaw = latest_yaw
            publisher = node.create_publisher(Twist, endpoint, 10)
            break
    if error is None and publisher is None:
        error = "ROS_COMMAND_OR_ODOM_UNREADY"
    if error is None:
        command = Twist()
        command.angular.z = direction * speed
        deadline = time.monotonic() + max_duration
        while time.monotonic() < deadline and rclpy.ok():
            publisher.publish(command)
            rclpy.spin_once(node, timeout_sec=0.05)
            if latest_yaw is not None and initial_yaw is not None:
                measured = abs(angle_delta(latest_yaw, initial_yaw))
                if measured + tolerance >= target:
                    status = "SUCCEEDED"
                    break
            time.sleep(0.02)
        if status != "SUCCEEDED" and error is None:
            error = "ODOM_TARGET_NOT_REACHED"
finally:
    if publisher is not None:
        stop = Twist()
        for _ in range(8):
            publisher.publish(stop)
            rclpy.spin_once(node, timeout_sec=0.02)
            time.sleep(0.02)
    node.destroy_node()
    rclpy.shutdown()
result = {"operation": "base.rotate", "status": status,
          "angle_degrees": angle, "max_speed_rad_s": speed,
          "measured_angle_degrees": math.degrees(measured),
          "discovered_command_publishers": discovered_command_publishers,
          "duration_s": time.monotonic() - started, "stop_published": publisher is not None}
if error is not None:
    result["error"] = error
print(json.dumps(result, separators=(",", ":")))
'''.strip()


class PythonBundleWorker:
    """Execute a verified Python bundle and return a bounded JSON result."""

    def __init__(self, provider: Provider | None = None) -> None:
        self.provider = provider

    def execute(
        self, manifest: ExecutionBundleManifest, source: bytes, arguments: dict[str, Any]
    ) -> dict[str, Any]:
        namespace: dict[str, Any] = {"__name__": f"rolo_bundle_{manifest.bundle_digest}"}
        try:
            exec(compile(source, f"<bundle:{manifest.bundle_digest}>", "exec"), namespace, namespace)
        except Exception as exc:  # pragma: no cover - exact provider exception is target-specific
            raise ProtocolError(f"bundle compilation failed: {exc}") from exc
        entrypoint = namespace.get(manifest.entrypoint)
        if not callable(entrypoint):
            raise ProtocolError(f"bundle entrypoint is not callable: {manifest.entrypoint}")
        try:
            if self.provider is not None:
                result = entrypoint(arguments, self.provider)
            else:
                result = entrypoint(arguments)
        except Exception as exc:  # pragma: no cover - exact provider exception is target-specific
            raise ProtocolError(f"bundle execution failed: {exc}") from exc
        if result is None:
            result = {}
        if not isinstance(result, dict):
            result = {"value": result}
        try:
            encoded = json.dumps(result, ensure_ascii=False, default=str)
        except (TypeError, ValueError) as exc:
            raise ProtocolError("bundle result is not JSON serializable") from exc
        max_output = int(manifest.limits.get("max_output_bytes", 65_536))
        if len(encoded.encode("utf-8")) > max_output:
            raise ProtocolError("bundle result exceeds max_output_bytes")
        return result
