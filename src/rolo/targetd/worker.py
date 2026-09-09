"""Generic signed bundle worker used by targetd.

Provider bindings stay outside this module.  A generated bundle exposes one
entrypoint with the stable ``execute(arguments)`` shape, so future tools can
reuse the same runtime without adding tool-specific branches to targetd.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import subprocess
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from rolo.dsl.parser import loads_unique_json

from .lifecycle import WorkerCompletion
from .lifecycle_integration import LeasedProviderOutcome
from .process_worker import ProcessWorkerControl
from .protocol import ExecutionBundleManifest, ProtocolError
from .ros2_runtime import Ros2RuntimeSnapshot

MAX_ROTATION_ANGLE_DEGREES = 30.0
MAX_ROTATION_SPEED_RAD_S = 0.15

# Mapping is deliberately a small, target-only provider surface.  The
# operation names below are the provider names; the corresponding published
# Tool ids retain the ``app.`` prefix.  Keeping this table explicit prevents a
# generated bundle from turning an arbitrary string into a target-side
# executable operation.
MAPPING_RUNTIME_ID = "rolo-mapping-v1"
MAPPING_RUNTIME_SOURCE = "landerpi_autonomous_mapping_runtime.py"
MAPPING_TOOL_OPERATIONS = {
    "app.mapping.status": "mapping.status",
    "app.mapping.save": "mapping.save",
    "app.mapping.run": "mapping.run",
    "app.mapping.stop": "mapping.stop",
}
MAPPING_OPERATIONS = frozenset(MAPPING_TOOL_OPERATIONS.values())
MAPPING_STATUSES = frozenset({"SUCCEEDED", "RUNNING", "STOPPED", "CANCELLED", "FAILED", "UNKNOWN", "NOT_ACCEPTED", "BLOCKED"})
_MAPPING_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")

# These defaults are also the only filesystem locations accepted by the
# temporary LanderPi runtime.  They are intentionally not caller-controlled:
# a signed observation contract may repeat them, but may not redirect a save
# operation into an arbitrary target path.
MAPPING_DEFAULTS: dict[str, str] = {
    "cmd_topic": "/controller/cmd_vel",
    "scan_topic": "/scan",
    "odom_topic": "/odom",
    "map_topic": "/map",
    "stop_marker": "/tmp/rolo-mapping-stop",
    "status_file": "/tmp/rolo-mapping-status.json",
    "map_dir": "/home/ubuntu/rolo_debug/maps",
}

_MAPPING_CONTRACT_KEYS = frozenset(
    {
        "provider",
        "operation",
        "runtime",
        "cmd_topic",
        "scan_topic",
        "odom_topic",
        "map_topic",
        "stop_marker",
        "status_file",
        "map_dir",
        # The endpoint spellings are accepted as a v1 compatibility alias for
        # the route vocabulary used by rotation bindings.  They normalize to
        # the fixed runtime names above and cannot be supplied together with
        # the canonical spelling.
        "command_endpoint",
        "scan_endpoint",
        "odom_endpoint",
        "map_endpoint",
    }
)
_MAPPING_ENDPOINT_KEYS = ("cmd_topic", "scan_topic", "odom_topic", "map_topic")


class Provider(Protocol):
    def invoke(self, operation: str, arguments: dict[str, Any]) -> dict[str, Any]: ...


@dataclass(frozen=True)
class Ros2OdomProcessWorker:
    """Spawn-safe, fixed-argv `/odom` observer with cooperative STOP."""

    snapshot: Ros2RuntimeSnapshot
    timeout_s: float = 10.0

    provider_id = "ros2-readonly"
    provider_operation = "odom.sample"
    mode = "READ_ONLY"
    physical_capable = False

    def __post_init__(self) -> None:
        if not 1 <= self.timeout_s <= 60:
            raise ValueError("ROS2 read-only process timeout is invalid")
        topic = next(
            (item for item in self.snapshot.topics if item.name == "/odom" and item.interface_type == "nav_msgs/msg/Odometry"),
            None,
        )
        if topic is None or not self.snapshot.ros2_path or "\x00" in self.snapshot.ros2_path:
            raise ValueError("ROS2 /odom process route is unavailable")

    def __call__(self, control: ProcessWorkerControl) -> LeasedProviderOutcome:
        process = subprocess.Popen(
            [
                self.snapshot.ros2_path,
                "topic",
                "echo",
                "--no-daemon",
                "--spin-time",
                "5",
                "--once",
                "/odom",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
        )
        stdout = bytearray()
        stderr = bytearray()
        overflow = threading.Event()

        def drain(stream, target: bytearray, limit: int) -> None:
            if stream is None:
                return
            try:
                while True:
                    chunk = stream.read(4096)
                    if not chunk:
                        return
                    remaining = limit - len(target)
                    if remaining > 0:
                        target.extend(chunk[:remaining])
                    if len(chunk) > remaining:
                        overflow.set()
            except OSError:
                overflow.set()

        readers = (
            threading.Thread(target=drain, args=(process.stdout, stdout, 65_536), daemon=True),
            threading.Thread(target=drain, args=(process.stderr, stderr, 4_096), daemon=True),
        )
        for reader in readers:
            reader.start()
        deadline = time.monotonic() + self.timeout_s
        while process.poll() is None:
            if control.aborted():
                self._terminate(process)
                raise ProtocolError("ROS2_READ_ONLY_WORKER_ABORTED")
            intent = control.interrupt_intent()
            if intent is not None:
                self._terminate(process)
                for reader in readers:
                    reader.join(1.0)
                status = "CANCELLED" if intent == "CANCEL" else "STOPPED"
                return LeasedProviderOutcome(
                    WorkerCompletion(status, f"ODOM_{intent}_CONFIRMED"),
                    {"status": status, "code": f"ODOM_{intent}_CONFIRMED"},
                )
            if overflow.is_set():
                self._terminate(process)
                raise ProtocolError("ROS2_READ_ONLY_OUTPUT_TOO_LARGE")
            if time.monotonic() >= deadline:
                self._terminate(process)
                raise ProtocolError("ROS2_TOPIC_ECHO_TIMEOUT")
            time.sleep(0.02)
        for reader in readers:
            reader.join(1.0)
        if any(reader.is_alive() for reader in readers) or overflow.is_set():
            self._terminate(process)
            raise ProtocolError("ROS2_READ_ONLY_OUTPUT_TOO_LARGE")
        if process.returncode != 0:
            return LeasedProviderOutcome(
                WorkerCompletion("FAILED", "ROS2_TOPIC_ECHO_FAILED"),
                {"status": "FAILED", "error": "ROS2_TOPIC_ECHO_FAILED"},
            )
        if not bytes(stdout).strip():
            return LeasedProviderOutcome(
                WorkerCompletion("FAILED", "ROS2_TOPIC_ECHO_EMPTY"),
                {"status": "FAILED", "error": "ROS2_TOPIC_ECHO_EMPTY"},
            )
        return LeasedProviderOutcome(
            WorkerCompletion("SUCCEEDED", "ODOM_SAMPLE_SUCCEEDED"),
            {
                "status": "SUCCEEDED",
                "sha256": f"sha256:{hashlib.sha256(stdout).hexdigest()}",
                "byte_count": len(stdout),
            },
        )

    @staticmethod
    def _terminate(process: subprocess.Popen[bytes]) -> None:
        if process.poll() is not None:
            return
        process.terminate()
        try:
            process.wait(timeout=1.0)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=1.0)


@dataclass(frozen=True)
class Ros2OdomLiveFence:
    """Re-observe the exact read-only `/odom` route at the START boundary."""

    snapshot: Ros2RuntimeSnapshot
    timeout_s: float = 3.0

    def __call__(self, _request, _authority) -> None:
        try:
            completed = subprocess.run(
                [
                    self.snapshot.ros2_path,
                    "topic",
                    "type",
                    "--no-daemon",
                    "/odom",
                ],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                check=False,
                timeout=self.timeout_s,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ProtocolError("ROS2_ODOM_LIVE_FENCE_UNAVAILABLE") from exc
        stdout = bytes(completed.stdout or b"")
        stderr = bytes(completed.stderr or b"")
        if len(stdout) > 4_096 or len(stderr) > 4_096:
            raise ProtocolError("ROS2_ODOM_LIVE_FENCE_OUTPUT_TOO_LARGE")
        if completed.returncode != 0:
            raise ProtocolError("ROS2_ODOM_LIVE_FENCE_UNAVAILABLE")
        try:
            observed = stdout.decode("utf-8").strip().splitlines()
        except UnicodeDecodeError as exc:
            raise ProtocolError("ROS2_ODOM_LIVE_FENCE_INVALID") from exc
        if observed != ["nav_msgs/msg/Odometry"]:
            raise ProtocolError("ROS2_ODOM_LIVE_FENCE_MISMATCH")


class RosContainerProvider:
    """Run a bounded ROS provider program inside an existing Docker runtime."""

    def __init__(
        self,
        container: str = "MentorPi",
        *,
        timeout_s: float = 120.0,
        container_user: str = "ubuntu",
        autonomous_source_confirmed: bool = False,
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
        """Invoke one explicitly registered ROS operation.

        ``base.rotate`` keeps its existing compatibility behavior.  Mapping
        operations are intentionally separate: they always require a signed
        observation contract and are dispatched through the fixed, bounded
        runtime source in ``scripts/``.  No operation name is ever converted
        into a shell command or module path.
        """

        normalized_operation = self._normalize_mapping_operation(operation)
        if normalized_operation in MAPPING_OPERATIONS:
            return self._invoke_mapping(normalized_operation, arguments)
        if operation != "base.rotate":
            raise ProtocolError(f"ROS provider operation is not registered: {operation}")
        return self._invoke_rotation(operation, arguments)

    @staticmethod
    def _normalize_mapping_operation(operation: str) -> str:
        if operation in MAPPING_OPERATIONS:
            return operation
        if isinstance(operation, str) and operation.startswith("app.mapping."):
            candidate = operation[4:]
            if candidate in MAPPING_OPERATIONS:
                return candidate
        return ""

    @staticmethod
    def _safe_endpoint(value: Any, field: str) -> str:
        if not isinstance(value, str) or not value.startswith("/") or len(value) > 127 or ".." in value or any(character in value for character in "\x00\r\n '\";"):
            raise ProtocolError(f"mapping {field} is invalid")
        return value

    @classmethod
    def _mapping_contract(
        cls,
        operation: str,
        raw_contract: Any,
        *,
        tool_id: str | None = None,
    ) -> dict[str, str]:
        """Validate and normalize the fixed mapping observation contract."""

        if not isinstance(raw_contract, Mapping) or not raw_contract:
            raise ProtocolError("mapping observation contract is required")
        contract = dict(raw_contract)
        unknown = sorted(set(contract) - _MAPPING_CONTRACT_KEYS)
        if unknown:
            raise ProtocolError(f"mapping observation contract has unknown fields: {unknown}")
        if contract.get("provider") != "ros-container":
            raise ProtocolError("mapping observation provider is required")
        declared_operation = cls._normalize_mapping_operation(str(contract.get("operation", "")))
        if declared_operation != operation:
            raise ProtocolError("mapping observation operation mismatches provider")
        if contract.get("runtime") != MAPPING_RUNTIME_ID:
            raise ProtocolError("mapping runtime contract is unsupported")
        if tool_id is not None:
            expected_tool = next(
                (candidate for candidate, candidate_operation in MAPPING_TOOL_OPERATIONS.items() if candidate_operation == operation),
                None,
            )
            if tool_id != expected_tool:
                raise ProtocolError("mapping tool id does not match provider operation")

        normalized: dict[str, str] = {
            "provider": "ros-container",
            "operation": operation,
            "runtime": MAPPING_RUNTIME_ID,
        }
        aliases = {
            "cmd_topic": "command_endpoint",
            "scan_topic": "scan_endpoint",
            "odom_topic": "odom_endpoint",
            "map_topic": "map_endpoint",
        }
        for canonical in _MAPPING_ENDPOINT_KEYS:
            alias = aliases[canonical]
            canonical_value = contract.get(canonical)
            alias_value = contract.get(alias)
            if canonical_value is None and alias_value is None:
                raise ProtocolError(f"mapping {canonical} is required")
            if canonical_value is not None and alias_value is not None and canonical_value != alias_value:
                raise ProtocolError(f"mapping {canonical} conflicts with {alias}")
            value = canonical_value if canonical_value is not None else alias_value
            normalized[canonical] = cls._safe_endpoint(value, canonical)

        # Filesystem paths are fixed to the debug runtime's bounded locations.
        # Accepting a different path here would turn a signed mapping Tool into
        # a general file writer, so fail closed even when the path is syntactically
        # safe.
        for field in ("stop_marker", "status_file", "map_dir"):
            if field not in contract:
                raise ProtocolError(f"mapping {field} is required")
            value = contract[field]
            if value != MAPPING_DEFAULTS[field]:
                raise ProtocolError(f"mapping {field} is not the fixed debug path")
            normalized[field] = value
        return normalized

    @staticmethod
    def _number(
        value: Any,
        field: str,
        *,
        lower: float,
        upper: float,
    ) -> float:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ProtocolError(f"mapping {field} is invalid")
        try:
            result = float(value)
        except (TypeError, ValueError) as exc:
            raise ProtocolError(f"mapping {field} is invalid") from exc
        if not math.isfinite(result) or not lower <= result <= upper:
            raise ProtocolError(f"mapping {field} is outside provider limits")
        return result

    @classmethod
    def _mapping_arguments(cls, operation: str, raw_arguments: Any) -> dict[str, Any]:
        if not isinstance(raw_arguments, Mapping):
            raise ProtocolError("mapping arguments must be an object")
        arguments = dict(raw_arguments)
        # Reserved keys are inserted by PythonBundleWorker, never accepted as
        # user arguments.  They are removed by ``_invoke_mapping`` first.
        schemas: dict[str, tuple[set[str], dict[str, Any]]] = {
            "mapping.status": (
                {"status_window_s"},
                {"status_window_s": 4.0},
            ),
            "mapping.run": (
                {"duration_s", "max_distance_m", "obstacle_stop_m"},
                {"duration_s": 60.0, "max_distance_m": 3.0, "obstacle_stop_m": 0.55},
            ),
            "mapping.stop": (set(), {}),
            "mapping.save": (
                {"map_name", "save_timeout_s"},
                {"map_name": "rolo_debug_map", "save_timeout_s": 30.0},
            ),
        }
        allowed, defaults = schemas[operation]
        unknown = sorted(set(arguments) - allowed)
        if unknown:
            raise ProtocolError(f"mapping arguments have unknown fields: {unknown}")
        values = {**defaults, **arguments}
        if operation == "mapping.status":
            values["status_window_s"] = cls._number(values["status_window_s"], "status_window_s", lower=1.0, upper=30.0)
        elif operation == "mapping.run":
            values["duration_s"] = cls._number(values["duration_s"], "duration_s", lower=5.0, upper=120.0)
            values["max_distance_m"] = cls._number(values["max_distance_m"], "max_distance_m", lower=0.2, upper=10.0)
            values["obstacle_stop_m"] = cls._number(values["obstacle_stop_m"], "obstacle_stop_m", lower=0.3, upper=1.2)
        elif operation == "mapping.save":
            map_name = values["map_name"]
            if not isinstance(map_name, str) or not _MAPPING_NAME.fullmatch(map_name):
                raise ProtocolError("mapping map_name is invalid")
            values["save_timeout_s"] = cls._number(values["save_timeout_s"], "save_timeout_s", lower=5.0, upper=120.0)
        return values

    @staticmethod
    def _mapping_runtime_source() -> str:
        # Installed targetd runs from a self-contained source tree.  The
        # installer places the reviewed runtime beside this worker so the
        # target does not need a checkout of the controller repository.  Keep
        # the repository ``scripts/`` fallback for local development and for
        # source-tree tests, but never accept a caller-provided path or source
        # blob.
        worker_path = Path(__file__).resolve()
        candidates = [worker_path.with_name(MAPPING_RUNTIME_SOURCE)]
        # ``worker.py`` normally lives at ``<repo>/src/rolo/targetd``.  Keep
        # the fallback guarded for embedded/minimal package layouts where the
        # expected ancestor does not exist.
        if len(worker_path.parents) > 3:
            candidates.append(worker_path.parents[3] / "scripts" / MAPPING_RUNTIME_SOURCE)
        for path in candidates:
            try:
                return path.read_text(encoding="utf-8")
            except OSError:
                continue
        raise ProtocolError("mapping runtime source is unavailable")

    def _invoke_mapping(self, operation: str, arguments: dict[str, Any]) -> dict[str, Any]:
        raw_arguments = dict(arguments)
        raw_contract = raw_arguments.pop("__rolo_observation_contract", None)
        raw_tool_id = raw_arguments.pop("__rolo_tool_id", None)
        contract = self._mapping_contract(operation, raw_contract, tool_id=raw_tool_id)
        values = self._mapping_arguments(operation, raw_arguments)
        if operation == "mapping.run" and not self.autonomous_source_confirmed:
            raise ProtocolError("mapping autonomous source confirmation is required")

        mode = operation.rsplit(".", 1)[1]
        argv = [
            "rolo_mapping_runtime",
            "--mode",
            mode,
            "--cmd-topic",
            contract["cmd_topic"],
            "--scan-topic",
            contract["scan_topic"],
            "--odom-topic",
            contract["odom_topic"],
            "--map-topic",
            contract["map_topic"],
            "--stop-marker",
            contract["stop_marker"],
            "--status-file",
            contract["status_file"],
            "--map-dir",
            contract["map_dir"],
        ]
        for key, flag in (
            ("status_window_s", "--status-window-s"),
            ("duration_s", "--duration-s"),
            ("max_distance_m", "--max-distance-m"),
            ("obstacle_stop_m", "--obstacle-stop-m"),
            ("map_name", "--map-name"),
            ("save_timeout_s", "--save-timeout-s"),
        ):
            if key in values:
                argv.extend([flag, str(values[key])])
        if operation == "mapping.run":
            argv.append("--autonomous-source-confirmed")
        runtime = self._mapping_runtime_source()
        program = (
            "import json, sys\n"
            f"sys.argv = {json.dumps(argv, ensure_ascii=False, separators=(',', ':'))}\n"
            f"exec(compile({json.dumps(runtime, ensure_ascii=False)}, '<rolo-mapping-runtime>', 'exec'), {{'__name__': '__main__'}})\n"
        )
        provider_timeout = self.timeout_s
        if operation == "mapping.stop":
            # A stop is a safety action, not a long-running exploration.
            # Bound discovery/context teardown separately so a stuck DDS
            # graph cannot hold the targetd channel for the full provider
            # default (128 seconds in the field).
            provider_timeout = min(provider_timeout, 15.0)
        elif operation == "mapping.status":
            provider_timeout = min(provider_timeout, float(values.get("status_window_s", 4.0)) + 8.0)
        elif operation == "mapping.save":
            provider_timeout = min(provider_timeout, float(values.get("save_timeout_s", 30.0)) + 8.0)
        execution_timeout = max(provider_timeout, float(values.get("duration_s", 0.0)) + 8.0)
        reaper_timeout = max(1.0, execution_timeout - 1.0)
        command = [
            "docker",
            "exec",
            "-i",
            "-u",
            self.container_user,
            self.container,
            "bash",
            "--noprofile",
            "--norc",
            "-c",
            "if [ -f /opt/ros/humble/setup.bash ]; then . /opt/ros/humble/setup.bash; fi; "
            "if [ -f /home/ubuntu/ros2_ws/install/setup.bash ]; then . /home/ubuntu/ros2_ws/install/setup.bash; fi; "
            # The provider is fed over stdin.  GNU timeout inside the
            # container is an independent reaper: if the DDS interpreter
            # ignores rclpy shutdown, closing the outer docker exec must not
            # leave an anonymous ``python3 -`` publisher behind.
            f"exec timeout --foreground --kill-after=2s "
            f"{reaper_timeout:.3f}s python3 -",
        ]
        try:
            completed = subprocess.run(
                command,
                input=f"{program}\n",
                text=True,
                capture_output=True,
                check=False,
                timeout=execution_timeout,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ProtocolError(f"mapping provider execution failed: {exc}") from exc
        if completed.returncode not in {0, 2}:
            raise ProtocolError(f"mapping provider exited {completed.returncode}: {completed.stderr[-512:]}")
        try:
            output = completed.stdout.strip().splitlines()[-1]
            result = loads_unique_json(output)
        except (IndexError, ValueError) as exc:
            raise ProtocolError("mapping provider returned invalid JSON") from exc
        if not isinstance(result, dict):
            raise ProtocolError("mapping provider result is not an object")
        if result.get("schema_version") != "rolo-landerpi-mapping-runtime/v1":
            raise ProtocolError("mapping provider result schema is unsupported")
        status = result.get("status")
        if not isinstance(status, str) or status.upper() not in MAPPING_STATUSES:
            raise ProtocolError("mapping provider result status is invalid")
        result["status"] = status.upper()
        if result.get("mode") != mode:
            raise ProtocolError("mapping provider result mode mismatches operation")
        if completed.returncode == 2:
            result.setdefault("runtime_returncode", completed.returncode)
        return result

    def _invoke_rotation(self, operation: str, arguments: dict[str, Any]) -> dict[str, Any]:
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
        if raw_contract is not None and command_endpoint is None and legacy_topic is None:
            raise ProtocolError("rotation command endpoint is required")
        if command_endpoint is None and legacy_topic is not None:
            command_endpoint = legacy_topic
        if command_endpoint is None:
            command_endpoint = "/cmd_vel"
        if legacy_topic is not None and contract.get("command_endpoint") is not None and legacy_topic != command_endpoint:
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
                if not isinstance(item, str) or not item.startswith("/") or any(character in item for character in "\x00\r\n '"):
                    raise ProtocolError(f"rotation {field} is invalid")
                result.append(item)
            return list(dict.fromkeys(result))

        if not isinstance(command_endpoint, str) or not command_endpoint.startswith("/") or any(character in command_endpoint for character in "\x00\r\n '"):
            raise ProtocolError("rotation command endpoint is invalid")
        feedback_endpoints = endpoint_list(feedback_endpoints, "feedback_endpoints")
        independent_endpoints = endpoint_list(independent_endpoints, "independent_feedback_endpoints")
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
        if not math.isfinite(angle) or not math.isfinite(speed) or speed <= 0 or speed > MAX_ROTATION_SPEED_RAD_S or not 0 < abs(angle) <= MAX_ROTATION_ANGLE_DEGREES:
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
            "docker",
            "exec",
            "-i",
            "-u",
            self.container_user,
            self.container,
            "bash",
            "--noprofile",
            "--norc",
            "-c",
            "if [ -f /opt/ros/humble/setup.bash ]; then . /opt/ros/humble/setup.bash; fi; "
            "if [ -f /home/ubuntu/ros2_ws/install/setup.bash ]; then . /home/ubuntu/ros2_ws/install/setup.bash; fi; "
            "exec python3 -",
        ]
        try:
            completed = subprocess.run(
                command,
                input=f"{program}\n",
                text=True,
                capture_output=True,
                check=False,
                timeout=max(1.0, self.timeout_s + 1.5),
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

    def execute(self, manifest: ExecutionBundleManifest, source: bytes, arguments: dict[str, Any]) -> dict[str, Any]:
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
                    # Keep the provider allowlist tied to the signed Tool id.
                    # A bundle cannot invoke rotation or mapping under a
                    # differently named generic Tool and thereby bypass the
                    # operation-specific receipt/evidence gates.
                    expected_operation = {
                        "app.base.rotate": "base.rotate",
                        **MAPPING_TOOL_OPERATIONS,
                    }.get(manifest.tool_id)
                    if expected_operation is None:
                        if manifest.observation_contract.get("operation") == "base.rotate":
                            # Preserve the stable diagnostic used by the
                            # rotation aliasing gate and its callers.
                            raise ProtocolError("ROS rotation provider requires app.base.rotate")
                        raise ProtocolError("ROS provider tool is not registered")
                    provider_arguments["__rolo_observation_contract"] = manifest.observation_contract
                    if manifest.tool_id in MAPPING_TOOL_OPERATIONS:
                        provider_arguments["__rolo_tool_id"] = manifest.tool_id
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
