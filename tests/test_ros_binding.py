from __future__ import annotations

import json
import math
from types import SimpleNamespace

import pytest

from rolo.mvp import ExecutionBinding, RosBindingExecutor
from rolo.mvp.bounded_twist import execute_bounded_twist


class VirtualIO:
    cancelled = False

    def __init__(self, *, responsive=True, subscribers=True, fail_motion=False, fail_stop=False):
        self.t = 0.0
        self.yaw = 0.0
        self.velocity = 0.0
        self.calls = []
        self.responsive = responsive
        self.subscribers = subscribers
        self.fail_motion = fail_motion
        self.fail_stop = fail_stop

    def now(self):
        return self.t

    def ready(self):
        return self.subscribers

    def latest(self):
        return {'yaw': self.yaw, 'angular_speed': self.velocity if self.responsive else 0, 'at': self.t}

    def spin(self, seconds):
        self.t += seconds
        if self.responsive:
            self.yaw += self.velocity * seconds

    def publish(self, speed):
        self.calls.append((self.t, speed))
        if (speed and self.fail_motion) or (not speed and self.fail_stop):
            raise RuntimeError('publish failed')
        self.velocity = speed


def request():
    return {'angular_speed_rad_s': 0.2, 'duration_s': math.radians(15) / 0.2, 'goal_yaw_rad': math.radians(15)}


def test_target_local_deadline_and_feedback_confirm_angle_and_stop():
    io = VirtualIO()
    result = execute_bounded_twist(io, request())
    assert result['status'] == 'SUCCEEDED'
    assert 14 <= result['measured_angle_degrees'] <= 16
    assert result['stopped_observed']
    assert max(t for t, speed in io.calls if speed) < request()['duration_s'] + 0.02
    assert io.calls[-1][1] == 0


def test_missing_command_subscriber_blocks_without_motion():
    io = VirtualIO(subscribers=False)
    result = execute_bounded_twist(io, request())
    assert result['status'] == 'BLOCKED'
    assert io.calls == []


@pytest.mark.parametrize('failure', ['fail_motion', 'fail_stop'])
def test_publish_or_stop_failure_never_claims_success(failure):
    io = VirtualIO(**{failure: True})
    result = execute_bounded_twist(io, request())
    assert result['status'] == 'UNKNOWN'
    assert any(speed == 0 for _, speed in io.calls)


def test_no_observed_rotation_cannot_pass_based_on_publish_count():
    result = execute_bounded_twist(VirtualIO(responsive=False), request())
    assert result['status'] == 'UNKNOWN'
    assert result['measured_angle_degrees'] == 0


def binding():
    return ExecutionBinding(kind='ros2_topic', command_endpoint='/cmd_vel', interface_type='geometry_msgs/msg/Twist',
                            feedback_endpoints=['/odom_raw'], stop_strategy='zero_velocity', evidence_refs=['evidence:1'])


def test_controller_uses_one_target_call_and_serialized_parameters():
    calls = []

    class Target:
        def run_bound(self, argv, **kwargs):
            calls.append((argv, kwargs))
            return SimpleNamespace(returncode=0, stdout=json.dumps({'status': 'SUCCEEDED', 'stop_published': True}), stderr='')

    result = RosBindingExecutor(Target()).rotate(binding(), {'angle_degrees': 15, 'max_speed_rad_s': 0.2})
    assert result['status'] == 'SUCCEEDED'
    assert len(calls) == 1
    assert calls[0][0][:2] == ['python3', '-c']
    assert json.loads(calls[0][0][-1])['duration_s'] == pytest.approx(1.308996938995747)
    assert calls[0][1]['timeout_s'] < 20


def test_overlong_motion_rejected_instead_of_clamping():
    result = RosBindingExecutor(None).rotate(binding(), {'angle_degrees': 15, 'max_speed_rad_s': 0.001})
    assert result['error'] == 'MOTION_DURATION_EXCEEDS_60_SECONDS'
