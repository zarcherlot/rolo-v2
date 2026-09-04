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


def execute_bounded_twist(io, request):
    speed = float(request['angular_speed_rad_s'])
    duration = float(request['duration_s'])
    goal = float(request['goal_yaw_rad'])
    if not all(math.isfinite(v) for v in (speed, duration, goal)):
        raise ValueError('motion parameters must be finite')
    if not 0 < abs(speed) <= 1 or not 0 < duration <= 60 or not 0 < abs(goal) <= 2 * math.pi + 1e-9:
        raise ValueError('motion parameters exceed bounds')
    if speed * goal <= 0:
        raise ValueError('speed and goal directions differ')

    ready_deadline = io.now() + 5
    while io.now() < ready_deadline:
        io.spin(0.02)
        state = io.latest()
        if io.cancelled:
            return {'status': 'CANCELLED', 'motion_started': False}
        if io.ready() and state and io.now() - state['at'] <= 0.5:
            break
    else:
        return {'status': 'BLOCKED', 'error': 'NO_LIVE_SUBSCRIBER_OR_ODOMETRY', 'motion_started': False}

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

    try:
        while io.now() < deadline:
            state = observe()
            if io.cancelled:
                failure = 'CANCELLED'
                break
            if not state or io.now() - state['at'] > 0.5:
                failure = 'ODOMETRY_STALE'
                break
            if travelled * math.copysign(1, goal) >= abs(goal) - math.radians(0.8):
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
    succeeded = failure is None and stop_sent and stopped and abs(error_degrees) <= 3
    return {
        'status': 'SUCCEEDED' if succeeded else 'UNKNOWN',
        'error': failure or (None if succeeded else 'MOTION_NOT_VERIFIED'),
        'motion_started': motion_started,
        'motion_elapsed_s': round(motion_elapsed, 4),
        'measured_angle_degrees': round(math.degrees(travelled), 4),
        'angle_error_degrees': round(error_degrees, 4),
        'stop_published': stop_sent,
        'stopped_observed': stopped,
        'final_speed_rad_s': round(state['angular_speed'], 5) if fresh else None,
    }


def main():
    import rclpy
    from geometry_msgs.msg import Twist
    from nav_msgs.msg import Odometry
    from rclpy.qos import qos_profile_sensor_data

    request = json.loads(sys.argv[1])
    rclpy.init(args=[])
    node = rclpy.create_node('rolo_bounded_twist')
    publisher = node.create_publisher(Twist, request['command_endpoint'], 10)

    class RosIO:
        cancelled = False
        state = None
        feedback_topic = None

        def now(self):
            return time.monotonic()

        def ready(self):
            return publisher.get_subscription_count() > 0

        def spin(self, seconds):
            rclpy.spin_once(node, timeout_sec=seconds)

        def latest(self):
            return self.state

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

    io = RosIO()
    subscriptions = [
        node.create_subscription(Odometry, topic, lambda message, topic=topic: io.receive(message, topic), qos_profile_sensor_data)
        for topic in request['feedback_endpoints']
    ]
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
