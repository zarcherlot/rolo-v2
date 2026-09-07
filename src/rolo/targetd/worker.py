"""Generic signed bundle worker used by targetd.

Provider bindings stay outside this module.  A generated bundle exposes one
entrypoint with the stable ``execute(arguments)`` shape, so future tools can
reuse the same runtime without adding tool-specific branches to targetd.
"""

from __future__ import annotations

import json
import math
import subprocess
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Protocol

from rolo.dsl.parser import loads_unique_json

from .protocol import ExecutionBundleManifest, ProtocolError

MAX_ROTATION_ANGLE_DEGREES = 30.0
MAX_ROTATION_SPEED_RAD_S = 0.15


class Provider(Protocol):
    def invoke(self, operation: str, arguments: dict[str, Any]) -> dict[str, Any]: ...


class RosContainerProvider:
    """Run a bounded ROS provider program inside an existing Docker runtime."""

    def __init__(
        self, container: str = "MentorPi", *, timeout_s: float = 120.0,
        container_user: str = "ubuntu", autonomous_source_confirmed: bool = False,
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
        self.autonomous_source_confirmed = bool(autonomous_source_confirmed)

    def invoke(self, operation: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if operation != "base.rotate":
            raise ProtocolError(f"ROS provider operation is not registered: {operation}")
        arguments = dict(arguments)
        # The signed bundle manifest is the source of truth for target routes.
        # ``PythonBundleWorker`` passes it under a reserved, internal key so a
        # generated bundle cannot silently redirect a write to a hard-coded
        # topic.  Direct provider calls retain the target-specific defaults for
        # deterministic low-level tests; production worker calls always carry
        # the marker and therefore fail closed when the contract is absent.
        raw_contract = arguments.pop("__rolo_observation_contract", None)
        if raw_contract is None:
            contract: Mapping[str, Any] = {}
        elif isinstance(raw_contract, Mapping):
            contract = raw_contract
        else:
            raise ProtocolError("rotation observation contract is invalid")
        if raw_contract is not None:
            if not contract:
                raise ProtocolError("rotation observation contract is required")
            if contract.get("provider") != "ros-container":
                raise ProtocolError("rotation observation provider is required")
            if contract.get("operation") != operation:
                raise ProtocolError("rotation observation operation mismatches provider")
        # Keep the direct low-level fallback on the isolated vendor route;
        # production bundle calls consume a signed contract.  ``topic`` is a
        # v1 compatibility alias used by the first targetd manifests; when it
        # is present without the newer route fields, preserve that route while
        # retaining the same bounded feedback defaults.
        legacy_topic = contract.get("topic")
        command_endpoint = contract.get("command_endpoint")
        if (
            raw_contract is not None
            and command_endpoint is None
            and legacy_topic is None
        ):
            raise ProtocolError("rotation command endpoint is required")
        if command_endpoint is None and legacy_topic is not None:
            command_endpoint = legacy_topic
        if command_endpoint is None:
            command_endpoint = "/cmd_vel"
        if (
            legacy_topic is not None
            and contract.get("command_endpoint") is not None
            and legacy_topic != command_endpoint
        ):
            raise ProtocolError("rotation command endpoint conflicts with legacy topic")
        feedback_endpoints = contract.get("feedback_endpoints", ["/odom_raw", "/odom"])
        independent_endpoints = contract.get(
            "independent_feedback_endpoints",
            ["/imu", "/imu_corrected", "/ros_robot_controller/imu_raw"],
        )

        def endpoint_list(value: Any, field: str, *, minimum: int = 1) -> list[str]:
            if not isinstance(value, (list, tuple)) or len(value) < minimum or len(value) > 8:
                raise ProtocolError(f"rotation {field} is invalid")
            result = []
            for item in value:
                if not isinstance(item, str) or not item.startswith("/") or any(
                    character in item for character in "\x00\r\n '"
                ):
                    raise ProtocolError(f"rotation {field} is invalid")
                result.append(item)
            return list(dict.fromkeys(result))

        if (
            not isinstance(command_endpoint, str)
            or not command_endpoint.startswith("/")
            or any(character in command_endpoint for character in "\x00\r\n '")
        ):
            raise ProtocolError("rotation command endpoint is invalid")
        feedback_endpoints = endpoint_list(feedback_endpoints, "feedback_endpoints")
        independent_endpoints = endpoint_list(
            independent_endpoints, "independent_feedback_endpoints"
        )
        if contract.get("interface_type") not in {None, "geometry_msgs/msg/Twist"}:
            raise ProtocolError("rotation command interface is unsupported")
        if contract.get("stop_strategy") not in {None, "zero_velocity"}:
            raise ProtocolError("rotation stop strategy is unsupported")

        try:
            raw_angle = arguments["angle_degrees"]
            raw_speed = arguments["max_speed_rad_s"]
            if isinstance(raw_angle, bool) or isinstance(raw_speed, bool):
                raise TypeError("rotation arguments must be numeric")
            angle = float(raw_angle)
            speed = float(raw_speed)
        except (KeyError, TypeError, ValueError) as exc:
            raise ProtocolError("rotate arguments are invalid") from exc
        if (
            not math.isfinite(angle)
            or not math.isfinite(speed)
            or speed <= 0
            or speed > MAX_ROTATION_SPEED_RAD_S
            or not 0 < abs(angle) <= MAX_ROTATION_ANGLE_DEGREES
        ):
            raise ProtocolError("rotate arguments are outside provider limits")
        goal_rad = math.radians(angle)
        minimum_observation = min(0.5, max(0.2, abs(goal_rad) / speed * 0.5))
        # Reserve bounded margin for the independent gyro stop gate.  On the
        # field chassis the physical rate can be well below the command cap,
        # so ideal kinematic duration is not enough for a small-angle canary.
        duration = max(abs(goal_rad) / speed * 3.0, 0.4, minimum_observation)
        request = {
            "command_endpoint": command_endpoint,
            "feedback_endpoints": feedback_endpoints,
            "independent_feedback_endpoints": independent_endpoints,
            "autonomous_source_confirmed": self.autonomous_source_confirmed,
            "angular_speed_rad_s": math.copysign(speed, angle),
            "duration_s": duration,
            "goal_yaw_rad": goal_rad,
        }
        runtime_path = Path(__file__).resolve().parents[1] / "mvp" / "bounded_twist.py"
        try:
            runtime = runtime_path.read_text(encoding="utf-8")
        except OSError as exc:
            raise ProtocolError("bounded_twist runtime source is unavailable") from exc
        # Compile the runtime separately so its ``from __future__`` statement
        # remains valid, then invoke its normal JSON entrypoint in ``__main__``
        # mode inside the target container.  This keeps the provider and
        # transient Harness paths on one fail-closed IMU/stop implementation.
        program = (
            "import json, sys\n"
            f"sys.argv = ['rolo_bounded_twist', {json.dumps(json.dumps(request, separators=(',', ':')))}]\n"
            f"exec(compile({json.dumps(runtime)}, '<rolo-bounded-twist>', 'exec'), {{'__name__': '__main__'}})\n"
        )
        command = [
            "docker", "exec", "-i", "-u", self.container_user, self.container,
            "bash", "--noprofile", "--norc", "-c",
            "if [ -f /opt/ros/humble/setup.bash ]; then . /opt/ros/humble/setup.bash; fi; "
            "if [ -f /home/ubuntu/ros2_ws/install/setup.bash ]; then . /home/ubuntu/ros2_ws/install/setup.bash; fi; "
            "exec python3 -",
        ]
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
            result = loads_unique_json(completed.stdout.strip().splitlines()[-1])
        # Duplicate JSON members are rejected by ``loads_unique_json`` with a
        # plain ``ValueError``.  Treat that the same as malformed provider
        # output so callers never observe a parser implementation exception.
        except (IndexError, ValueError) as exc:
            raise ProtocolError("ROS provider returned invalid JSON") from exc
        if not isinstance(result, dict):
            raise ProtocolError("ROS provider result is not an object")
        return result


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
                provider_arguments = dict(arguments)
                # Bind only the ROS provider to the signed observation
                # contract.  Generic providers receive exactly the user
                # argument object; injecting an internal key into every
                # provider would silently change otherwise strict DSL input
                # contracts.  The ROS provider itself fail-closes when this
                # marker is present but the contract is empty/invalid.
                if isinstance(self.provider, RosContainerProvider):
                    # This provider currently exposes one physical write
                    # operation.  Do not let a differently named generic
                    # bundle invoke ``base.rotate`` and then inherit the
                    # generic receipt path (which would bypass the exact
                    # angle/evidence gate in targetd.
                    if manifest.tool_id != "app.base.rotate":
                        raise ProtocolError(
                            "ROS rotation provider requires app.base.rotate"
                        )
                    provider_arguments["__rolo_observation_contract"] = manifest.observation_contract
                result = entrypoint(provider_arguments, self.provider)
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
