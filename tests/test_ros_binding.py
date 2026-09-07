from __future__ import annotations

import json
import math
from types import SimpleNamespace

import pytest

from rolo.mvp import ExecutionBinding, RosBindingExecutor
from rolo.mvp.bounded_twist import execute_bounded_twist, motion_observation_duration_s


class VirtualIO:
    cancelled = False

    def __init__(self, *, responsive=True, subscribers=True, exclusive=True, fail_motion=False, fail_stop=False):
        self.t = 0.0
        self.yaw = 0.0
        self.velocity = 0.0
        self.calls = []
        self.responsive = responsive
        self.subscribers = subscribers
        self.exclusive = exclusive
        self.fail_motion = fail_motion
        self.fail_stop = fail_stop

    def now(self):
        return self.t

    def ready(self):
        return self.subscribers

    def latest(self):
        return {'yaw': self.yaw, 'angular_speed': self.velocity if self.responsive else 0, 'at': self.t}

    def command_exclusive(self):
        return self.exclusive

    def independent_ready(self):
        return True

    def independent_motion_evidence(self, goal, start, end):
        delta = self.yaw if self.responsive else 0.0
        threshold = max(0.005, abs(goal) * 0.25)
        verified = math.copysign(delta, goal) >= threshold
        return {
            'status': 'VERIFIED' if verified else 'NOT_VERIFIED',
            'kind': 'IMU_GYRO' if verified else 'IMU_BELOW_THRESHOLD',
            'threshold_rad': threshold,
            'gyro_delta_rad': delta,
            'settled': True,
            'independent_of_odom': True,
        }

    def spin(self, seconds):
        self.t += seconds
        if self.responsive:
            self.yaw += self.velocity * seconds

    def publish(self, speed):
        self.calls.append((self.t, speed))
        if (speed and self.fail_motion) or (not speed and self.fail_stop):
            raise RuntimeError('publish failed')
        self.velocity = speed


class InaccurateGyroIO(VirtualIO):
    """The odometry reaches the goal while the independent gyro under-reads."""

    def independent_motion_evidence(self, goal, start, end):
        evidence = super().independent_motion_evidence(goal, start, end)
        evidence['gyro_delta_rad'] *= 0.5
        return evidence


def request():
    return {'angular_speed_rad_s': 0.15, 'duration_s': math.radians(15) / 0.15, 'goal_yaw_rad': math.radians(15)}


def verified_target_result(**overrides):
    result = {
        'status': 'SUCCEEDED',
        'stop_published': True,
        'physical_stop_verified': True,
        'stopped_observed': True,
        'angle_accuracy_verified': True,
        'independent_motion_evidence': {
            'status': 'VERIFIED',
            'independent_of_odom': True,
            'settled': True,
            'angle_accuracy_status': 'VERIFIED',
            'target_angle_error_rad': 0.001,
            'target_angle_tolerance_rad': 0.005,
        },
    }
    result.update(overrides)
    return result


def test_target_local_deadline_and_feedback_confirm_angle_and_stop():
    io = VirtualIO()
    result = execute_bounded_twist(io, request())
    assert result['status'] == 'SUCCEEDED'
    assert 14 <= result['measured_angle_degrees'] <= 16
    assert result['stopped_observed']
    assert result['physical_stop_verified']
    assert max(t for t, speed in io.calls if speed) < request()['duration_s'] + 0.02
    assert io.calls[-1][1] == 0


def test_one_degree_turn_does_not_stop_at_fixed_point_two_degree_floor():
    io = VirtualIO()
    one_degree_request = {
        "angular_speed_rad_s": 0.03,
        "duration_s": math.radians(1) / 0.03 * 1.5,
        "goal_yaw_rad": math.radians(1),
    }
    result = execute_bounded_twist(io, one_degree_request)
    assert result["status"] == "SUCCEEDED"
    assert result["measured_angle_degrees"] >= 0.8
    assert result["angle_error_degrees"] > -0.3
    assert io.calls[-1][1] == 0
    first_stop = next(t for t, speed in io.calls if speed == 0)
    assert first_stop >= motion_observation_duration_s(math.radians(1), 0.03)


def test_missing_command_subscriber_blocks_without_motion():
    io = VirtualIO(subscribers=False)
    result = execute_bounded_twist(io, request())
    assert result['status'] == 'BLOCKED'
    assert io.calls == []


def test_multiple_command_publishers_block_before_motion():
    io = VirtualIO(exclusive=False)
    result = execute_bounded_twist(io, request())
    assert result == {'status': 'BLOCKED', 'error': 'COMMAND_MULTIPLE_PUBLISHERS', 'motion_started': False}
    assert io.calls == []


def test_confirmed_autonomous_source_allows_known_background_publishers():
    io = VirtualIO(exclusive=False)
    result = execute_bounded_twist(io, {**request(), 'autonomous_source_confirmed': True})
    assert result['status'] == 'SUCCEEDED'
    assert result['stopped_observed']


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


def test_exact_angle_gate_rejects_motion_witness_with_wrong_gyro_delta():
    result = execute_bounded_twist(InaccurateGyroIO(), request())
    assert result['status'] == 'UNKNOWN'
    assert result['error'] == 'ANGLE_ACCURACY_NOT_VERIFIED'
    assert result['physical_stop_verified'] is True
    assert result['angle_accuracy_verified'] is False


def binding():
    return ExecutionBinding(kind='ros2_topic', command_endpoint='/cmd_vel', interface_type='geometry_msgs/msg/Twist',
                            feedback_endpoints=['/odom_raw'], stop_strategy='zero_velocity', evidence_refs=['evidence:1'])


def test_controller_uses_one_target_call_and_serialized_parameters():
    calls = []

    class Target:
        def run_bound(self, argv, **kwargs):
            calls.append((argv, kwargs))
            return SimpleNamespace(
                returncode=0,
                stdout=json.dumps({
                    'status': 'SUCCEEDED',
                    'stop_published': True,
                    'physical_stop_verified': True,
                    'stopped_observed': True,
                    'angle_accuracy_verified': True,
                    'independent_motion_evidence': {
                        'status': 'VERIFIED', 'kind': 'IMU_GYRO', 'settled': True,
                        'independent_of_odom': True,
                        'angle_accuracy_status': 'VERIFIED',
                        'target_angle_error_rad': 0.001,
                        'target_angle_tolerance_rad': 0.005,
                    },
                }),
                stderr='',
            )

    result = RosBindingExecutor(Target()).rotate(binding(), {'angle_degrees': 15, 'max_speed_rad_s': 0.15})
    assert result['status'] == 'SUCCEEDED'
    assert len(calls) == 1
    assert calls[0][0][:2] == ['python3', '-c']
    assert json.loads(calls[0][0][-1])['duration_s'] == pytest.approx(math.radians(15) / 0.15 * 3.0)
    assert json.loads(calls[0][0][-1])['autonomous_source_confirmed'] is False
    assert calls[0][1]['timeout_s'] < 20


def test_controller_propagates_explicit_autonomous_source_confirmation():
    calls = []

    class Target:
        def run_bound(self, argv, **kwargs):
            calls.append((argv, kwargs))
            return SimpleNamespace(
                returncode=0,
                stdout=json.dumps({
                    'status': 'SUCCEEDED',
                    'stop_published': True,
                    'physical_stop_verified': True,
                    'stopped_observed': True,
                    'angle_accuracy_verified': True,
                    'independent_motion_evidence': {
                        'status': 'VERIFIED', 'settled': True,
                        'independent_of_odom': True,
                        'angle_accuracy_status': 'VERIFIED',
                        'target_angle_error_rad': 0.001,
                        'target_angle_tolerance_rad': 0.005,
                    },
                }),
                stderr='',
            )

    result = RosBindingExecutor(Target(), autonomous_source_confirmed=True).rotate(
        binding(), {'angle_degrees': 5, 'max_speed_rad_s': 0.1}
    )
    assert result['status'] == 'SUCCEEDED'
    assert json.loads(calls[0][0][-1])['autonomous_source_confirmed'] is True


def test_controller_handles_transient_harness_without_run_bound_response():
    calls = []

    class Target:
        def run_transient_code(self, launcher, **kwargs):
            calls.append((launcher, kwargs))
            return SimpleNamespace(
                returncode=0,
                stdout=json.dumps({
                    'status': 'SUCCEEDED',
                    'stop_published': True,
                    'physical_stop_verified': True,
                    'stopped_observed': True,
                    'angle_accuracy_verified': True,
                    'independent_motion_evidence': {
                        'status': 'VERIFIED', 'settled': True,
                        'independent_of_odom': True,
                        'angle_accuracy_status': 'VERIFIED',
                        'target_angle_error_rad': 0.001,
                        'target_angle_tolerance_rad': 0.005,
                    },
                }),
                stderr='',
            )

    result = RosBindingExecutor(Target()).rotate(
        binding(), {'angle_degrees': 1, 'max_speed_rad_s': 0.1}
    )
    assert result['status'] == 'SUCCEEDED'
    assert len(calls) == 1
    assert calls[0][1]['timeout_s'] >= 1


def test_overlong_motion_rejected_instead_of_clamping():
    result = RosBindingExecutor(None).rotate(binding(), {'angle_degrees': 15, 'max_speed_rad_s': 0.001})
    assert result['error'] == 'MOTION_DURATION_EXCEEDS_60_SECONDS'


@pytest.mark.parametrize(
    ('angle_degrees', 'max_speed_rad_s', 'error'),
    [(30.1, 0.1, 'ANGLE_OUT_OF_BOUNDS'), (1, 0.1501, 'SPEED_OUT_OF_BOUNDS')],
)
def test_controller_applies_canary_rotation_bounds(angle_degrees, max_speed_rad_s, error):
    result = RosBindingExecutor(None).rotate(
        binding(), {'angle_degrees': angle_degrees, 'max_speed_rad_s': max_speed_rad_s}
    )
    assert result['status'] == 'BLOCKED'
    assert result['error'] == error


def test_controller_rejects_boolean_rotation_arguments():
    result = RosBindingExecutor(None).rotate(
        binding(), {'angle_degrees': True, 'max_speed_rad_s': 0.1}
    )
    assert result['status'] == 'BLOCKED'
    assert result['error'] == 'INVALID_ROTATION_ARGUMENTS'


def test_target_runtime_rejects_boolean_motion_parameters():
    with pytest.raises(ValueError, match='must be numeric'):
        execute_bounded_twist(
            VirtualIO(),
            {'angular_speed_rad_s': True, 'duration_s': 1.0, 'goal_yaw_rad': 0.1},
        )


def test_controller_rejects_zero_angle_instead_of_claiming_physical_success():
    result = RosBindingExecutor(None).rotate(
        binding(), {'angle_degrees': 0, 'max_speed_rad_s': 0.1}
    )
    assert result == {
        'status': 'BLOCKED',
        'error': 'ZERO_ANGLE_NOT_SUPPORTED',
        'motion_started': False,
    }


def test_controller_downgrades_odom_only_success_without_independent_evidence():
    class Target:
        def run_bound(self, argv, **kwargs):
            return SimpleNamespace(
                returncode=0,
                stdout=json.dumps({'status': 'SUCCEEDED', 'stop_published': True, 'stopped_observed': True}),
                stderr='',
            )

    result = RosBindingExecutor(Target()).rotate(
        binding(), {'angle_degrees': 1, 'max_speed_rad_s': 0.1}
    )
    assert result['status'] == 'UNKNOWN'
    assert result['error'] == 'PHYSICAL_MOTION_NOT_VERIFIED'


@pytest.mark.parametrize('status', ['FAILED', 'STOPPED', 'NOT_ACCEPTED', 'failed', 'stopped'])
def test_controller_preserves_explicit_terminal_failure_status(status):
    class Target:
        def run_bound(self, argv, **kwargs):
            return SimpleNamespace(
                returncode=0,
                stdout=json.dumps({'status': status}),
                stderr='',
            )

    result = RosBindingExecutor(Target()).rotate(
        binding(), {'angle_degrees': 1, 'max_speed_rad_s': 0.1}
    )
    assert result['status'] == status.upper()


def test_controller_rejects_motion_evidence_that_is_not_independent_of_odom():
    class Target:
        def run_bound(self, argv, **kwargs):
            evidence = dict(verified_target_result()['independent_motion_evidence'])
            evidence['independent_of_odom'] = False
            return SimpleNamespace(
                returncode=0,
                stdout=json.dumps(verified_target_result(independent_motion_evidence=evidence)),
                stderr='',
            )

    result = RosBindingExecutor(Target()).rotate(
        binding(), {'angle_degrees': 1, 'max_speed_rad_s': 0.1}
    )
    assert result['status'] == 'UNKNOWN'
    assert result['error'] == 'PHYSICAL_MOTION_NOT_VERIFIED'


def test_controller_rejects_angle_flag_without_nested_accuracy_proof():
    class Target:
        def run_bound(self, argv, **kwargs):
            evidence = dict(verified_target_result()['independent_motion_evidence'])
            evidence['angle_accuracy_status'] = 'NOT_VERIFIED'
            return SimpleNamespace(
                returncode=0,
                stdout=json.dumps(verified_target_result(independent_motion_evidence=evidence)),
                stderr='',
            )

    result = RosBindingExecutor(Target()).rotate(
        binding(), {'angle_degrees': 1, 'max_speed_rad_s': 0.1}
    )
    assert result['status'] == 'UNKNOWN'
    assert result['error'] == 'ANGLE_ACCURACY_NOT_VERIFIED'
