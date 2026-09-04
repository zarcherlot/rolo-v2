"""Controller adapter for the target-local, feedback-checked Twist primitive."""

from __future__ import annotations

import hashlib
import json
import math
import subprocess
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .probe_registration import ExecutionBinding


class RosBindingExecutor:
    def __init__(self, target_executor: Any, *, ros_setup_files: tuple[str, ...] = ()) -> None:
        self.target_executor = target_executor
        self.ros_setup_files = ros_setup_files

    def rotate(self, binding: ExecutionBinding, arguments: Mapping[str, Any]) -> dict[str, Any]:
        if (binding.kind != 'ros2_topic' or binding.interface_type != 'geometry_msgs/msg/Twist'
                or binding.stop_strategy != 'zero_velocity' or not binding.feedback_endpoints):
            return {'status': 'BLOCKED', 'error': 'UNSUPPORTED_BINDING', 'motion_started': False}
        if set(arguments) != {'angle_degrees', 'max_speed_rad_s'} or any(isinstance(value, bool) for value in arguments.values()):
            return {'status': 'BLOCKED', 'error': 'INVALID_ROTATION_ARGUMENTS', 'motion_started': False}
        try:
            angle = float(arguments['angle_degrees'])
            speed = float(arguments['max_speed_rad_s'])
        except (TypeError, ValueError):
            return {'status': 'BLOCKED', 'error': 'INVALID_ROTATION_ARGUMENTS', 'motion_started': False}
        if not math.isfinite(angle) or not -180 < angle < 180:
            return {'status': 'BLOCKED', 'error': 'ANGLE_OUT_OF_BOUNDS', 'motion_started': False}
        if not math.isfinite(speed) or not 0 < speed <= 1:
            return {'status': 'BLOCKED', 'error': 'SPEED_OUT_OF_BOUNDS', 'motion_started': False}
        if angle == 0:
            return {'status': 'SUCCEEDED', 'motion_started': False, 'measured_angle_degrees': 0}
        duration = abs(math.radians(angle)) / speed
        if duration > 10:
            return {'status': 'BLOCKED', 'error': 'MOTION_DURATION_EXCEEDS_10_SECONDS', 'motion_started': False}
        request = {
            'command_endpoint': binding.command_endpoint,
            'feedback_endpoints': binding.feedback_endpoints,
            'angular_speed_rad_s': math.copysign(speed, angle),
            'duration_s': duration,
            'goal_yaw_rad': math.radians(angle),
        }
        runtime = Path(__file__).with_name('bounded_twist.py').read_text(encoding='utf-8')
        runtime_digest = hashlib.sha256(runtime.encode()).hexdigest()
        try:
            completed = self.target_executor.run_bound(
                ['python3', '-c', runtime, json.dumps(request, separators=(',', ':'))],
                timeout_s=duration + 12,
                ros_setup_files=self.ros_setup_files,
            )
            if completed.returncode != 0:
                result = {'status': 'UNKNOWN', 'error': 'TARGET_RUNTIME_FAILED', 'returncode': completed.returncode, 'stderr': completed.stderr}
            else:
                result = json.loads(completed.stdout)
                if not isinstance(result, dict) or result.get('status') not in {'SUCCEEDED', 'BLOCKED', 'UNKNOWN', 'CANCELLED'}:
                    raise ValueError('invalid target result')
        except (OSError, subprocess.TimeoutExpired, ValueError) as exc:
            result = {'status': 'UNKNOWN', 'error': type(exc).__name__, 'stop_published': None}
        return {**result, 'runtime_sha256': runtime_digest, 'requested_angle_degrees': angle, 'max_speed_rad_s': speed}


__all__ = ['RosBindingExecutor']
