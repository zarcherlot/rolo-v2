"""Typed ROS 2 execution provider for evidence-bound application bindings."""

from __future__ import annotations

import math
from collections.abc import Mapping
from typing import Any

from .probe_registration import ExecutionBinding


class RosBindingExecutor:
    """Execute a bounded Twist binding through a target provider.

    The target executor is intentionally injected.  It must be a pinned Rolo
    target connector; no shell text or caller-supplied argv is accepted.
    """

    def __init__(self, target_executor: Any, *, ros_setup_files: tuple[str, ...] = ()) -> None:
        self.target_executor = target_executor
        self.ros_setup_files = ros_setup_files

    def rotate(
        self,
        binding: ExecutionBinding,
        arguments: Mapping[str, Any],
    ) -> dict[str, Any]:
        if binding.kind != "ros2_topic" or binding.interface_type != "geometry_msgs/msg/Twist":
            return {"status": "BLOCKED", "error": "UNSUPPORTED_BINDING"}
        try:
            angle = float(arguments["angle_degrees"])
            speed = float(arguments["max_speed_rad_s"])
        except (KeyError, TypeError, ValueError):
            return {"status": "BLOCKED", "error": "INVALID_ROTATION_ARGUMENTS"}
        if not math.isfinite(angle) or not -180.0 < angle < 180.0:
            return {"status": "BLOCKED", "error": "ANGLE_OUT_OF_BOUNDS"}
        if not math.isfinite(speed) or not 0.0 < speed <= 1.0:
            return {"status": "BLOCKED", "error": "SPEED_OUT_OF_BOUNDS"}
        duration = abs(math.radians(angle)) / speed
        # Ten fixed publishes per second, capped to keep the provider bounded.
        publishes = max(1, min(300, math.ceil(duration * 10)))
        signed_speed = speed if angle >= 0 else -speed
        velocity = self._twist(binding.command_endpoint, signed_speed)
        stop = self._twist(binding.command_endpoint, 0.0)
        results: list[dict[str, Any]] = []
        try:
            for _ in range(publishes):
                result = self.target_executor.run_bound(
                    ["ros2", "topic", "pub", "--once", binding.command_endpoint, binding.interface_type, velocity],
                    ros_setup_files=self.ros_setup_files,
                )
                results.append({"returncode": result.returncode, "stderr": result.stderr, "stdout": result.stdout})
                if result.returncode != 0:
                    return {"status": "FAILED", "error": "ROS_PUBLISH_FAILED", "results": results}
            return {"status": "SUCCEEDED", "angle_degrees": angle, "duration_s": duration, "publishes": publishes, "results": results}
        finally:
            # Stop is mandatory even when a publish fails or the caller aborts.
            self.target_executor.run_bound(
                ["ros2", "topic", "pub", "--once", binding.command_endpoint, binding.interface_type, stop],
                ros_setup_files=self.ros_setup_files,
            )

    @staticmethod
    def _twist(endpoint: str, angular_z: float) -> str:
        # Endpoint is validated by ExecutionBinding; keep the message fixed and typed.
        del endpoint
        return f"{{linear: {{x: 0.0, y: 0.0, z: 0.0}}, angular: {{x: 0.0, y: 0.0, z: {angular_z:.6f}}}}}"


__all__ = ["RosBindingExecutor"]
