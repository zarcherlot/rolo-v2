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

    def __init__(self, container: str = "MentorPi", *, timeout_s: float = 120.0) -> None:
        if not container or any(c in container for c in "\x00\r\n '"):
            raise ValueError("ROS container name is invalid")
        self.container = container
        self.timeout_s = timeout_s

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
            "docker", "exec", "-i", self.container, "bash", "--noprofile", "--norc", "-c",
            ". /opt/ros/humble/setup.bash; exec python3 -",
        ]
        program = _ROS_ROTATE_PROGRAM.replace(
            "__ROLO_ARGS__", json.dumps({"angle_degrees": angle, "max_speed_rad_s": speed})
        )
        try:
            completed = subprocess.run(
                command, input=f"{program}\n", text=True,
                capture_output=True, check=False, timeout=self.timeout_s,
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
import json, math, sys, time
import rclpy
from geometry_msgs.msg import Twist
args = __ROLO_ARGS__
angle = float(args["angle_degrees"])
speed = float(args["max_speed_rad_s"])
rclpy.init(args=None)
node = rclpy.create_node("rolo_signed_bundle_rotate")
publisher = node.create_publisher(Twist, "/cmd_vel", 10)
duration = abs(math.radians(angle)) / speed
direction = 1.0 if angle >= 0 else -1.0
deadline = time.monotonic() + duration
message = Twist()
message.angular.z = direction * speed
try:
    while time.monotonic() < deadline and rclpy.ok():
        publisher.publish(message)
        rclpy.spin_once(node, timeout_sec=0.02)
        time.sleep(0.02)
finally:
    message.angular.z = 0.0
    for _ in range(5):
        publisher.publish(message)
        rclpy.spin_once(node, timeout_sec=0.02)
        time.sleep(0.02)
    node.destroy_node()
    rclpy.shutdown()
print(json.dumps({"operation": "base.rotate", "angle_degrees": angle,
                  "max_speed_rad_s": speed, "duration_s": duration,
                  "stop_published": True}, separators=(",", ":")))
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
