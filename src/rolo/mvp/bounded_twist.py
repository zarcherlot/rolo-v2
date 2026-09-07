"""Target-local bounded Twist primitive; no SSH or ROS CLI in the control loop.

The controller accepts an injected clock/transport for deterministic tests.
ROS imports are confined to the executable entry point on the robot.
"""

from __future__ import annotations

import json
import math
import signal
import sys
import time

MIN_GOAL_TOLERANCE_RAD = math.radians(0.1)
MAX_GOAL_TOLERANCE_RAD = math.radians(0.8)
GOAL_TOLERANCE_FRACTION = 0.20
# Give a small physical turn enough bounded dwell for the independent IMU to
# observe acceleration before accepting open-loop odometry feedback.
MIN_MOTION_OBSERVATION_FLOOR_S = 0.20
MAX_MOTION_OBSERVATION_S = 0.50
MAX_ROTATION_ANGLE_RAD = math.radians(30.0)
MAX_ROTATION_SPEED_RAD_S = 0.15
MIN_INDEPENDENT_ROTATION_RAD = 0.005
DEFAULT_INDEPENDENT_IMU_ENDPOINTS = (
    '/imu',
    '/imu_corrected',
    '/ros_robot_controller/imu_raw',
)


def goal_tolerance_rad(goal_rad):
    """Scale feedback tolerance for small turns without widening the bound."""

    goal = abs(float(goal_rad))
    if not math.isfinite(goal) or goal <= 0:
        raise ValueError('goal_rad must be finite and positive')
    return min(MAX_GOAL_TOLERANCE_RAD, max(MIN_GOAL_TOLERANCE_RAD, goal * GOAL_TOLERANCE_FRACTION))


def motion_observation_duration_s(goal_rad, speed_rad_s):
    """Bound the minimum feedback window before accepting a small turn."""

    goal = abs(float(goal_rad))
    speed = abs(float(speed_rad_s))
    if not math.isfinite(goal) or goal <= 0 or not math.isfinite(speed) or speed <= 0:
        raise ValueError('goal_rad and speed_rad_s must be finite and positive')
    return min(MAX_MOTION_OBSERVATION_S, max(MIN_MOTION_OBSERVATION_FLOOR_S, goal / speed * 0.5))


def _integrate_angular_samples(
    samples, start: float, end: float, *, bias: float = 0.0
) -> float | None:
    """Integrate timestamped gyro samples over a bounded motion window."""

    points = sorted(
        (float(timestamp), float(value) - bias)
        for timestamp, value in samples
        if math.isfinite(float(timestamp)) and math.isfinite(float(value))
    )
    if len(points) < 2 or end <= start:
        return None
    # Keep the latest sample at a duplicate timestamp.
    deduped = []
    for point in points:
        if deduped and point[0] == deduped[-1][0]:
            deduped[-1] = point
        else:
            deduped.append(point)
    if len(deduped) < 2 or end < deduped[0][0] or start > deduped[-1][0]:
        return None
    left = max(start, deduped[0][0])
    right = min(end, deduped[-1][0])
    if right <= left:
        return None

    def interpolate(timestamp: float) -> float | None:
        if timestamp <= deduped[0][0]:
            return deduped[0][1]
        if timestamp >= deduped[-1][0]:
            return deduped[-1][1]
        for (left_t, left_v), (right_t, right_v) in zip(deduped, deduped[1:], strict=False):
            if left_t <= timestamp <= right_t:
                if right_t <= left_t:
                    return right_v
                fraction = (timestamp - left_t) / (right_t - left_t)
                return left_v + fraction * (right_v - left_v)
        return None

    clipped = [(left, interpolate(left)), (right, interpolate(right))]
    clipped.extend(
        (timestamp, value)
        for timestamp, value in deduped
        if left < timestamp < right
    )
    usable = sorted((t, v) for t, v in clipped if v is not None)
    if len(usable) < 2:
        return None
    return sum(
        0.5 * (right_v + left_v) * (right_t - left_t)
        for (left_t, left_v), (right_t, right_v) in zip(usable, usable[1:], strict=False)
    )


def _classify_independent_gyro(goal, deltas):
    """Classify multi-stream gyro evidence without trusting odometry."""

    expected = abs(float(goal))
    threshold = max(MIN_INDEPENDENT_ROTATION_RAD, expected * 0.25)
    sign = 1.0 if goal >= 0 else -1.0
    finite = {
        name: value for name, value in deltas.items()
        if isinstance(name, str) and value is not None and math.isfinite(float(value))
    }
    passing = {name: value for name, value in finite.items() if sign * value >= threshold}
    opposing = {name: value for name, value in finite.items() if sign * value <= -threshold}
    spread = None
    if len(passing) >= 2:
        values = [float(value) for value in passing.values()]
        spread = max(values) - min(values)
    disagree = bool(opposing) or (
        spread is not None and spread > max(0.10, expected * 0.75)
    )
    selected = max(passing, key=lambda name: abs(float(passing[name]))) if passing else None
    if disagree:
        kind = 'IMU_STREAMS_DISAGREE'
    elif passing:
        kind = 'IMU_GYRO_MULTI_STREAM' if len(passing) > 1 else 'IMU_GYRO'
    else:
        kind = 'IMU_BELOW_THRESHOLD'
    return {
        'status': 'VERIFIED' if passing and not disagree else 'NOT_VERIFIED',
        'kind': kind,
        'threshold_rad': threshold,
        'gyro_delta_rad': passing.get(selected) if selected else None,
        'gyro_deltas_rad': deltas,
        'selected_gyro_stream': selected,
        'gyro_stream_spread_rad': spread,
        'opposing_gyro_streams': opposing,
        'independent_of_odom': True,
    }


def execute_bounded_twist(io, request):
    raw_speed = request['angular_speed_rad_s']
    raw_duration = request['duration_s']
    raw_goal = request['goal_yaw_rad']
    if any(isinstance(value, bool) for value in (raw_speed, raw_duration, raw_goal)):
        raise ValueError('motion parameters must be numeric')
    speed = float(raw_speed)
    duration = float(raw_duration)
    goal = float(raw_goal)
    if not all(math.isfinite(v) for v in (speed, duration, goal)):
        raise ValueError('motion parameters must be finite')
    if (
        not 0 < abs(speed) <= MAX_ROTATION_SPEED_RAD_S
        or not 0 < duration <= 60
        or not 0 < abs(goal) <= MAX_ROTATION_ANGLE_RAD
    ):
        raise ValueError('motion parameters exceed bounds')
    if speed * goal <= 0:
        raise ValueError('speed and goal directions differ')
    feedback_tolerance = goal_tolerance_rad(goal)
    minimum_motion_observation_s = motion_observation_duration_s(goal, speed)

    ready_deadline = io.now() + 5
    while io.now() < ready_deadline:
        io.spin(0.02)
        state = io.latest()
        if io.cancelled:
            return {'status': 'CANCELLED', 'motion_started': False}
        exclusive = getattr(io, 'command_exclusive', lambda: True)()
        source_confirmed = bool(request.get('autonomous_source_confirmed', False))
        independent_ready = getattr(io, 'independent_ready', lambda: True)()
        if (
            io.ready()
            and independent_ready
            and (exclusive or source_confirmed)
            and state
            and io.now() - state['at'] <= 0.5
        ):
            break
        if io.ready() and not exclusive and not source_confirmed:
            return {'status': 'BLOCKED', 'error': 'COMMAND_MULTIPLE_PUBLISHERS', 'motion_started': False}
    else:
        error = (
            'NO_LIVE_INDEPENDENT_IMU'
            if io.ready() and state and not getattr(io, 'independent_ready', lambda: True)()
            else 'NO_LIVE_SUBSCRIBER_OR_ODOMETRY'
        )
        return {'status': 'BLOCKED', 'error': error, 'motion_started': False}

    previous_yaw = state['yaw']
    travelled = 0.0
    started = io.now()
    deadline = started + duration
    next_publish = started
    stop_sent = False
    failure = None
    motion_started = False

    def observe():
        nonlocal previous_yaw, travelled
        observation = io.latest()
        if observation:
            change = observation['yaw'] - previous_yaw
            travelled += math.atan2(math.sin(change), math.cos(change))
            previous_yaw = observation['yaw']
        return observation

    def independent_progress():
        """Return signed live gyro progress when the transport exposes it.

        LanderPi ``/odom_raw`` is a command integral and can lead the actual
        chassis motion.  The production ROS transport therefore supplies a
        bounded independent IMU integrator for the stop decision.  Small
        deterministic transports that predate this optional hook continue to
        use odometry as their progress signal for compatibility with the
        local conformance tests.
        """

        reader = getattr(io, 'independent_motion_progress', None)
        if not callable(reader):
            return None
        try:
            value = reader(goal, started, io.now())
        except TypeError:
            try:
                value = reader(goal, started)
            except (Exception, KeyboardInterrupt):
                return 0.0
        except (Exception, KeyboardInterrupt):
            return 0.0
        try:
            numeric = float(value) if value is not None else None
        except (TypeError, ValueError, OverflowError):
            return None
        # A production reader exists only for independent feedback.  Treat a
        # malformed/temporarily unavailable value as zero progress rather than
        # falling back to odometry and accidentally satisfying the stop gate.
        return numeric if numeric is not None and math.isfinite(numeric) else 0.0

    try:
        while io.now() < deadline:
            state = observe()
            if io.cancelled:
                failure = 'CANCELLED'
                break
            if not state or io.now() - state['at'] > 0.5:
                failure = 'ODOMETRY_STALE'
                break
            independent_delta = independent_progress()
            progress = independent_delta if independent_delta is not None else travelled
            if (
                progress * math.copysign(1, goal) >= abs(goal) - feedback_tolerance
                and io.now() - started >= minimum_motion_observation_s
            ):
                break
            if io.now() >= next_publish:
                motion_started = True
                io.publish(speed)
                next_publish = io.now() + 0.05
            io.spin(min(0.01, max(0, deadline - io.now())))
    except (Exception, KeyboardInterrupt) as exc:
        failure = type(exc).__name__
    finally:
        motion_elapsed = io.now() - started
        if motion_started:
            try:
                for _ in range(5):
                    io.publish(0.0)
                    io.spin(0.05)
                    observe()
                stop_sent = True
                settle_deadline = io.now() + 0.5
                while io.now() < settle_deadline:
                    io.spin(0.02)
                    observe()
            except (Exception, KeyboardInterrupt):
                failure = 'STOP_UNCONFIRMED'

    state = observe()
    fresh = state is not None and io.now() - state['at'] <= 0.5
    stopped = bool(fresh and abs(state['angular_speed']) <= 0.03)
    error_degrees = math.degrees(travelled - goal)
    evidence_reader = getattr(io, 'independent_motion_evidence', None)
    settle_end = io.now()
    if callable(evidence_reader):
        try:
            independent_motion_evidence = evidence_reader(
                goal, started, started + motion_elapsed, settle_end
            )
        except TypeError:
            # Keep injected test transports/backends compatible while the
            # target ROS transport exposes the optional settle window.
            independent_motion_evidence = evidence_reader(
                goal, started, started + motion_elapsed
            )
    else:
        independent_motion_evidence = {
            'status': 'NOT_VERIFIED',
            'kind': 'UNAVAILABLE',
            'threshold_rad': max(MIN_INDEPENDENT_ROTATION_RAD, abs(goal) * 0.25),
            'independent_of_odom': True,
        }
    evidence_verified = (
        isinstance(independent_motion_evidence, dict)
        and str(independent_motion_evidence.get('status', '')).upper() == 'VERIFIED'
    )
    gyro_delta = None
    if isinstance(independent_motion_evidence, dict):
        try:
            candidate_gyro_delta = independent_motion_evidence.get('gyro_delta_rad')
            if candidate_gyro_delta is not None and math.isfinite(float(candidate_gyro_delta)):
                gyro_delta = float(candidate_gyro_delta)
        except (TypeError, ValueError, OverflowError):
            gyro_delta = None
    angle_accuracy_tolerance = max(abs(goal) * 0.25, MIN_INDEPENDENT_ROTATION_RAD)
    independent_angle_error = (
        abs(abs(gyro_delta) - abs(goal)) if gyro_delta is not None else None
    )
    angle_accuracy_verified = (
        independent_angle_error is not None
        and independent_angle_error <= angle_accuracy_tolerance
        and math.copysign(1.0, gyro_delta) == math.copysign(1.0, goal)
    )
    if isinstance(independent_motion_evidence, dict):
        independent_motion_evidence['target_angle_error_rad'] = independent_angle_error
        independent_motion_evidence['target_angle_tolerance_rad'] = angle_accuracy_tolerance
        independent_motion_evidence['angle_accuracy_status'] = (
            'VERIFIED' if angle_accuracy_verified else 'NOT_VERIFIED'
        )
    physical_stop_verified = bool(
        isinstance(independent_motion_evidence, dict)
        and independent_motion_evidence.get('settled') is True
    )
    succeeded = (
        failure is None
        and stop_sent
        and stopped
        and abs(error_degrees) <= 3
        and evidence_verified
        and physical_stop_verified
        # Independent motion proves that the chassis moved, but not that it
        # moved by the requested angle.  Keep exact-angle verification as a
        # separate success gate.
        and angle_accuracy_verified
    )
    result_error = failure
    if result_error is None and not succeeded:
        result_error = (
            'ANGLE_ACCURACY_NOT_VERIFIED'
            if evidence_verified and physical_stop_verified and not angle_accuracy_verified
            else 'PHYSICAL_MOTION_NOT_VERIFIED'
            if not evidence_verified or not physical_stop_verified
            else 'MOTION_NOT_VERIFIED'
        )
    return {
        'status': 'SUCCEEDED' if succeeded else 'UNKNOWN',
        'error': result_error,
        'motion_started': motion_started,
        'motion_elapsed_s': round(motion_elapsed, 4),
        'measured_angle_degrees': round(math.degrees(travelled), 4),
        'angle_error_degrees': round(error_degrees, 4),
        'stop_published': stop_sent,
        'command_stopped': stopped,
        'stopped_observed': stopped,
        'physical_stop_verified': physical_stop_verified,
        'angle_accuracy_verified': angle_accuracy_verified,
        'final_speed_rad_s': round(state['angular_speed'], 5) if fresh else None,
        'independent_motion_evidence': independent_motion_evidence,
    }


def main():
    import rclpy
    from geometry_msgs.msg import Twist
    from nav_msgs.msg import Odometry
    from rclpy.qos import DurabilityPolicy, QoSProfile, ReliabilityPolicy
    from sensor_msgs.msg import Imu

    request = json.loads(sys.argv[1])
    rclpy.init(args=[])
    node = rclpy.create_node('rolo_bounded_twist')
    publisher = node.create_publisher(Twist, request['command_endpoint'], 10)

    class RosIO:
        cancelled = False
        state = None
        feedback_topic = None

        def __init__(self):
            self.imu_samples = {topic: [] for topic in imu_endpoints}

        def now(self):
            return time.monotonic()

        def ready(self):
            return publisher.get_subscription_count() > 0

        def command_exclusive(self):
            # The supervised publisher must be the only command source.  This
            # prevents joystick/app traffic from invalidating feedback bounds.
            return len(node.get_publishers_info_by_topic(request['command_endpoint'])) <= 1

        def spin(self, seconds):
            rclpy.spin_once(node, timeout_sec=seconds)

        def latest(self):
            return self.state

        def independent_ready(self):
            now = self.now()
            return any(
                len(samples) >= 2 and now - samples[-1][0] <= 0.5
                for samples in self.imu_samples.values()
            )

        def publish(self, speed):
            message = Twist()
            message.angular.z = speed
            publisher.publish(message)

        def receive(self, message, topic):
            if self.feedback_topic is not None and topic != self.feedback_topic:
                return
            q = message.pose.pose.orientation
            if not all(math.isfinite(value) for value in (q.x, q.y, q.z, q.w, message.twist.twist.angular.z)):
                return
            self.feedback_topic = topic
            yaw = math.atan2(2 * (q.w * q.z + q.x * q.y), 1 - 2 * (q.y * q.y + q.z * q.z))
            self.state = {'yaw': yaw, 'angular_speed': message.twist.twist.angular.z, 'at': self.now()}

        def receive_imu(self, message, topic):
            try:
                value = float(message.angular_velocity.z)
            except (AttributeError, TypeError, ValueError):
                return
            if math.isfinite(value):
                self.imu_samples[topic].append((self.now(), value))

        def independent_motion_progress(self, goal, start, end):
            """Integrate fresh body-gyro samples for the bounded stop gate.

            The command loop must not stop on the vendor odometry integral
            alone: that signal reflects the commanded wheel model and was
            observed to lead the physical chassis on LanderPi.  Use the
            median of same-sign fresh IMU streams, with a zero progress value
            (rather than an odometry fallback) while the independent window
            is not yet observable.  This keeps a missing/stale IMU fail-closed
            at the bounded deadline.
            """

            sign = 1.0 if float(goal) >= 0 else -1.0
            values = []
            for _topic, samples in self.imu_samples.items():
                if not samples or end - samples[-1][0] > 0.15:
                    continue
                pre_motion = [
                    value for timestamp, value in samples
                    if start - 0.5 <= timestamp < start
                ]
                bias = sum(pre_motion) / len(pre_motion) if pre_motion else 0.0
                delta = _integrate_angular_samples(samples, start, end, bias=bias)
                if delta is not None and math.isfinite(delta) and sign * delta > 0:
                    values.append(float(delta))
            if not values:
                return 0.0
            values.sort()
            middle = len(values) // 2
            if len(values) % 2:
                return values[middle]
            return 0.5 * (values[middle - 1] + values[middle])

        def independent_motion_evidence(self, goal, start, end, settle_end=None):
            deltas = {}
            settle_end = self.now() if settle_end is None else float(settle_end)
            for topic, samples in self.imu_samples.items():
                pre_motion = [
                    value for timestamp, value in samples
                    if start - 0.5 <= timestamp < start
                ]
                bias = sum(pre_motion) / len(pre_motion) if pre_motion else 0.0
                deltas[topic] = _integrate_angular_samples(
                    samples, start, end, bias=bias
                )
            evidence = _classify_independent_gyro(goal, deltas)
            # A command echo/odom stop is not a physical settle proof.  Use a
            # short post-stop IMU window and require at least one fresh stream
            # whose residual rate is below the bounded stationary threshold.
            settle_rates = []
            settle_tail_rates = []
            settle_tail_start = settle_end - 0.20
            for _topic, samples in self.imu_samples.items():
                pre_motion = [
                    value for timestamp, value in samples
                    if start - 0.5 <= timestamp < start
                ]
                bias = sum(pre_motion) / len(pre_motion) if pre_motion else 0.0
                for timestamp, value in samples:
                    if end <= timestamp <= settle_end and math.isfinite(value):
                        residual = abs(value - bias)
                        settle_rates.append(residual)
                        if timestamp >= settle_tail_start:
                            settle_tail_rates.append(residual)
            # A transient braking spike immediately after the zero command is
            # expected on a small chassis.  Physical stop proof concerns the
            # final bounded tail, not the historical peak during braking.
            evidence['settled'] = (
                bool(settle_tail_rates)
                and max(settle_tail_rates) <= 0.03
            )
            evidence['settle_sample_count'] = len(settle_rates)
            evidence['settle_tail_sample_count'] = len(settle_tail_rates)
            evidence['settle_peak_rate_rad_s'] = max(settle_rates) if settle_rates else None
            evidence['settle_tail_max_rate_rad_s'] = (
                max(settle_tail_rates) if settle_tail_rates else None
            )
            evidence['motion_window_start'] = start
            evidence['motion_window_end'] = end
            evidence['settle_window_end'] = settle_end
            return evidence

    imu_endpoints = tuple(dict.fromkeys(
        request.get('independent_feedback_endpoints', DEFAULT_INDEPENDENT_IMU_ENDPOINTS)
    ))
    io = RosIO()
    evidence_qos = QoSProfile(
        depth=10,
        reliability=ReliabilityPolicy.RELIABLE,
        durability=DurabilityPolicy.VOLATILE,
    )
    subscriptions = [
        node.create_subscription(Odometry, topic, lambda message, topic=topic: io.receive(message, topic), evidence_qos)
        for topic in request['feedback_endpoints']
    ]
    subscriptions.extend(
        node.create_subscription(
            Imu, topic, lambda message, topic=topic: io.receive_imu(message, topic), evidence_qos
        )
        for topic in imu_endpoints
    )
    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(sig, lambda *_: setattr(io, 'cancelled', True))
    try:
        result = execute_bounded_twist(io, request)
        result['feedback_topic'] = io.feedback_topic
        print(json.dumps(result), flush=True)
    finally:
        for subscription in subscriptions:
            node.destroy_subscription(subscription)
        node.destroy_node()
        rclpy.shutdown()


if __name__ == '__main__':
    main()
