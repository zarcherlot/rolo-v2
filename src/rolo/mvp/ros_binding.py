"""Controller adapter for the target-local, feedback-checked Twist primitive."""

from __future__ import annotations

import hashlib
import json
import math
import subprocess
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from rolo.core.rotation_evidence import (
    has_verified_independent_motion_evidence,
    has_verified_rotation_evidence,
)
from rolo.dsl.parser import loads_unique_json

from .bounded_twist import motion_observation_duration_s
from .harness_execution import HarnessCodeExecutor, make_code_bundle
from .probe_registration import ExecutionBinding

MAX_ROTATION_ANGLE_DEGREES = 30.0
MAX_ROTATION_SPEED_RAD_S = 0.15


class RosBindingExecutor:
    def __init__(
        self,
        target_executor: Any,
        *,
        ros_setup_files: tuple[str, ...] = (),
        autonomous_source_confirmed: bool = False,
    ) -> None:
        self.target_executor = target_executor
        self.ros_setup_files = ros_setup_files
        # This is a separate operator assertion from the physical safety
        # confirmation.  The target runtime uses it only to admit a canary
        # when other idle cmd_vel publishers are present; it is deliberately
        # false by default so a generic binding cannot silently commandeer a
        # shared command topic.
        self.autonomous_source_confirmed = bool(autonomous_source_confirmed)

    def rotate(self, binding: ExecutionBinding, arguments: Mapping[str, Any]) -> dict[str, Any]:
        if (binding.kind != 'ros2_topic' or binding.interface_type != 'geometry_msgs/msg/Twist'
                or binding.stop_strategy != 'zero_velocity' or not binding.feedback_endpoints):
            return {'status': 'BLOCKED', 'error': 'UNSUPPORTED_BINDING', 'motion_started': False}
        if set(arguments) != {'angle_degrees', 'max_speed_rad_s'} or any(isinstance(value, bool) for value in arguments.values()):
            return {'status': 'BLOCKED', 'error': 'INVALID_ROTATION_ARGUMENTS', 'motion_started': False}
        try:
            raw_angle = arguments['angle_degrees']
            raw_speed = arguments['max_speed_rad_s']
            if isinstance(raw_angle, bool) or isinstance(raw_speed, bool):
                raise TypeError('rotation arguments must be numeric')
            angle = float(raw_angle)
            speed = float(raw_speed)
        except (TypeError, ValueError):
            return {'status': 'BLOCKED', 'error': 'INVALID_ROTATION_ARGUMENTS', 'motion_started': False}
        if not math.isfinite(angle) or not -MAX_ROTATION_ANGLE_DEGREES <= angle <= MAX_ROTATION_ANGLE_DEGREES:
            return {'status': 'BLOCKED', 'error': 'ANGLE_OUT_OF_BOUNDS', 'motion_started': False}
        if not math.isfinite(speed) or not 0 < speed <= MAX_ROTATION_SPEED_RAD_S:
            return {'status': 'BLOCKED', 'error': 'SPEED_OUT_OF_BOUNDS', 'motion_started': False}
        if angle == 0:
            # The target bounded runtime intentionally accepts only a
            # positive-magnitude turn.  Do not manufacture a physical
            # success for a zero-op request (and then fail the downstream
            # exact-angle gate because no evidence exists).
            return {
                'status': 'BLOCKED',
                'error': 'ZERO_ANGLE_NOT_SUPPORTED',
                'motion_started': False,
            }
        goal_rad = math.radians(angle)
        # The target runtime has a bounded minimum observation floor (needed
        # for a small turn's IMU evidence).  The transport deadline must leave
        # enough room to reach that floor before its stop/settle sequence.
        # The requested speed is an upper bound.  The field robot's
        # independent gyro rate is substantially below the commanded rate at
        # low duty cycles, so reserve bounded observation margin for the
        # independent-angle stop gate instead of timing out at ideal
        # kinematics.  The runtime still enforces its 60 s hard ceiling.
        duration = max(
            abs(goal_rad) / speed * 3.0,
            0.4,
            motion_observation_duration_s(goal_rad, speed),
        )
        if duration > 60:
            return {'status': 'BLOCKED', 'error': 'MOTION_DURATION_EXCEEDS_60_SECONDS', 'motion_started': False}
        request = {
            'protocol': 'rolo-harness/v1',
            'tool_id': 'app.base.rotate',
            'operation': 'bounded_twist',
            'binding_sha256': hashlib.sha256(
                json.dumps(binding.model_dump(mode='json'), sort_keys=True, separators=(',', ':')).encode()
            ).hexdigest(),
            'binding': binding.model_dump(mode='json'),
            'command_endpoint': binding.command_endpoint,
            'feedback_endpoints': binding.feedback_endpoints,
            # Independent body-motion evidence is deliberately explicit in
            # the generated request.  The target runtime may subscribe to
            # only observed endpoints; unknown/missing streams fail closed.
            'independent_feedback_endpoints': [
                '/imu', '/imu_corrected', '/ros_robot_controller/imu_raw'
            ],
            'autonomous_source_confirmed': self.autonomous_source_confirmed,
            'angular_speed_rad_s': math.copysign(speed, angle),
            'duration_s': duration,
            'goal_yaw_rad': goal_rad,
        }
        runtime = Path(__file__).with_name('bounded_twist.py').read_text(encoding='utf-8')
        runtime_digest = hashlib.sha256(runtime.encode()).hexdigest()

        def normalize_result(value: Any) -> dict[str, Any]:
            """Validate the target result and fail closed on weak evidence.

            Both the transient harness and the legacy ``run_bound`` transport
            are production paths.  Keeping this check after transport
            selection prevents a harness provider from bypassing the same
            physical-motion proof required by the ordinary SSH path.
            """

            if not isinstance(value, Mapping):
                raise ValueError('invalid target result')
            result = dict(value)
            status = result.get('status')
            if not isinstance(status, str):
                raise ValueError('invalid target result')
            status = status.upper()
            if status not in {
                'SUCCEEDED', 'BLOCKED', 'UNKNOWN', 'CANCELLED', 'STOPPED', 'FAILED',
                'NOT_ACCEPTED',
            }:
                raise ValueError('invalid target result')
            result['status'] = status
            if result.get('status') == 'SUCCEEDED':
                physical_motion_verified = (
                    result.get('stop_published') is True
                    and result.get('stopped_observed') is True
                    and result.get('physical_stop_verified') is True
                    and has_verified_independent_motion_evidence(result)
                )
                if (
                    result.get('stop_published') is not True
                    or result.get('stopped_observed') is not True
                    or result.get('physical_stop_verified') is not True
                    or not has_verified_rotation_evidence(result)
                ):
                    result.update({
                        'status': 'UNKNOWN',
                        'error': (
                            'ANGLE_ACCURACY_NOT_VERIFIED'
                            if physical_motion_verified
                            else 'PHYSICAL_MOTION_NOT_VERIFIED'
                        ),
                    })
            return result

        try:
            if hasattr(self.target_executor, 'run_transient_code'):
                bundle = make_code_bundle(
                    tool_id='app.base.rotate', source=runtime, request=request
                )
                result = HarnessCodeExecutor(self.target_executor).execute(
                    bundle, timeout_s=duration + 12
                )
                result = normalize_result(result)
            else:
                # Kept for deterministic local/unit fakes; production may use
                # the ordinary profile SSH transport or a local executor.
                request['runtime_sha256'] = runtime_digest
                completed = self.target_executor.run_bound(
                    ['python3', '-c', runtime, json.dumps(request, separators=(',', ':'))],
                    timeout_s=duration + 12,
                    ros_setup_files=self.ros_setup_files,
                )
                if completed.returncode != 0:
                    result = {
                        'status': 'UNKNOWN',
                        'error': 'TARGET_RUNTIME_FAILED',
                        'returncode': completed.returncode,
                        'stderr': completed.stderr,
                    }
                else:
                    result = normalize_result(loads_unique_json(completed.stdout))
        except (OSError, subprocess.TimeoutExpired, TypeError, ValueError) as exc:
            result = {'status': 'UNKNOWN', 'error': type(exc).__name__, 'stop_published': None}
        return {**result, 'runtime_sha256': runtime_digest, 'requested_angle_degrees': angle, 'max_speed_rad_s': speed}


__all__ = ['RosBindingExecutor']
