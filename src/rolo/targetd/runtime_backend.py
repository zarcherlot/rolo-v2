"""Target-side backend selection and bounded execution hooks.

The registry keeps provider selection explicit.  It never invents a route: a
backend can resolve only bindings already present in the runtime snapshot.
Actual target execution is injected by the authorized targetd worker.
"""

from __future__ import annotations

import subprocess
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from getpass import getuser
from typing import Any, Protocol

from rolo.dsl.models import OperationKind

from .ros2_runtime import Ros2RuntimeResolver


class RuntimeBackend(Protocol):
    backend_id: str

    def resolve(self, binding: Mapping[str, Any]) -> dict[str, Any]: ...

    def execute(self, binding: Mapping[str, Any], arguments: Mapping[str, Any]) -> dict[str, Any]: ...

    def capabilities(self) -> tuple[str, ...]: ...


@dataclass(frozen=True)
class ResolvedBackend:
    backend_id: str
    operation_kind: str
    binding: dict[str, Any]


class Ros2RuntimeBackend:
    """ROS2 provider whose routes are constrained by ``Ros2RuntimeResolver``."""

    backend_id = "ros2_runtime"

    def capabilities(self) -> tuple[str, ...]:
        return ("read_only_topic", "ros2")

    def __init__(self, resolver: Ros2RuntimeResolver, executor: Callable[[Mapping[str, Any], Mapping[str, Any]], Mapping[str, Any]] | None = None) -> None:
        self.resolver = resolver
        self.executor = executor

    def resolve(self, binding: Mapping[str, Any]) -> dict[str, Any]:
        resolved = self.resolver.resolve_binding(binding)
        return {"backend_id": self.backend_id, **resolved}

    def execute(self, binding: Mapping[str, Any], arguments: Mapping[str, Any]) -> dict[str, Any]:
        self.resolve(binding)
        if self.executor is None:
            return {"status": "BLOCKED", "error": "RUNTIME_EXECUTOR_REQUIRED"}
        result = dict(self.executor(binding, arguments))
        result.setdefault("backend_id", self.backend_id)
        return result


class Ros2ReadOnlyExecutor:
    """Bounded ``ros2 topic echo`` executor for observed topics.

    The command is assembled from the resolver's observed topic name and is
    executed without a shell.  It is intentionally read-only and returns the
    bounded CLI payload as evidence; service/action writes require a separate
    explicitly registered provider.
    """

    def __init__(
        self,
        resolver: Ros2RuntimeResolver,
        *,
        ros2_path: str | None = None,
        timeout_s: float = 10.0,
        runner: Callable[..., Any] | None = None,
        executor_user: str | None = None,
    ) -> None:
        if not 1 <= timeout_s <= 60:
            raise ValueError("ROS2 read-only timeout must be between 1 and 60 seconds")
        self.resolver = resolver
        self.ros2_path = ros2_path or resolver.snapshot.ros2_path
        if not self.ros2_path or "\x00" in self.ros2_path:
            raise ValueError("ROS2 CLI path is invalid")
        self.timeout_s = timeout_s
        self.runner = runner or subprocess.run
        self.executor_user = str(executor_user or getuser()).strip() or None

    def __call__(self, binding: Mapping[str, Any], arguments: Mapping[str, Any]) -> dict[str, Any]:
        del arguments
        resolved = self.resolver.resolve_binding(dict(binding))
        topic = str(resolved["endpoint"])
        publisher_user = self.resolver.snapshot.publisher_user
        if publisher_user and self.executor_user and publisher_user != self.executor_user:
            return {
                "status": "BLOCKED",
                "error": "DDS_USER_MISMATCH",
                "topic": topic,
                "publisher_user": publisher_user,
                "executor_user": self.executor_user,
            }
        try:
            completed = self.runner(
                [
                    self.ros2_path,
                    "topic",
                    "echo",
                    "--no-daemon",
                    "--spin-time",
                    "5",
                    "--once",
                    topic,
                ],
                capture_output=True,
                check=False,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=self.timeout_s,
            )
        except subprocess.TimeoutExpired:
            return {"status": "UNKNOWN", "error": "ROS2_TOPIC_ECHO_TIMEOUT", "topic": topic}
        except OSError as exc:
            return {"status": "UNKNOWN", "error": type(exc).__name__, "topic": topic}
        stdout = str(getattr(completed, "stdout", "") or "")[:64 * 1024]
        if int(getattr(completed, "returncode", 1)) != 0:
            stderr = str(getattr(completed, "stderr", "") or "")[:4096]
            return {"status": "UNKNOWN", "error": "ROS2_TOPIC_ECHO_FAILED", "detail": stderr, "topic": topic}
        if not stdout.strip():
            return {"status": "UNKNOWN", "error": "ROS2_TOPIC_ECHO_EMPTY", "topic": topic}
        return {"status": "SUCCEEDED", "topic": topic, "raw": stdout}


class DeclarativeRuntimeBackend:
    """Backend hook for composed plans and validated source runtimes."""

    def __init__(self, backend_id: str) -> None:
        self.backend_id = backend_id

    def resolve(self, binding: Mapping[str, Any]) -> dict[str, Any]:
        return {"backend_id": self.backend_id, "binding": dict(binding)}

    def capabilities(self) -> tuple[str, ...]:
        return ("declarative",)

    def execute(self, binding: Mapping[str, Any], arguments: Mapping[str, Any]) -> dict[str, Any]:
        del binding, arguments
        return {"status": "BLOCKED", "error": "RUNTIME_EXECUTOR_REQUIRED", "backend_id": self.backend_id}


class RuntimeBackendRegistry:
    """Select a registered backend by DSL operation kind."""

    def __init__(self, backends: Mapping[str, RuntimeBackend] | None = None) -> None:
        self._by_kind: dict[str, RuntimeBackend] = {}
        for kind, backend in (backends or {}).items():
            self.register(kind, backend)

    def register(self, kind: str, backend: RuntimeBackend) -> None:
        normalized = str(kind).upper()
        if normalized not in {item.value for item in OperationKind}:
            raise ValueError("unsupported runtime operation kind")
        if normalized in self._by_kind:
            raise ValueError("runtime backend already registered")
        self._by_kind[normalized] = backend

    def resolve(
        self,
        kind: str,
        binding: Mapping[str, Any],
        *,
        required_capabilities: tuple[str, ...] = (),
    ) -> ResolvedBackend:
        backend = self._by_kind.get(str(kind).upper())
        if backend is None:
            raise ValueError("BACKEND_UNAVAILABLE")
        capabilities = tuple(getattr(backend, "capabilities", lambda: ())())
        if any(required not in capabilities for required in required_capabilities):
            raise ValueError("BACKEND_CAPABILITY_UNAVAILABLE")
        resolved = backend.resolve(binding)
        return ResolvedBackend(
            backend_id=str(resolved.get("backend_id", backend.backend_id)),
            operation_kind=str(kind).upper(),
            binding=dict(resolved),
        )

    def execute(self, kind: str, binding: Mapping[str, Any], arguments: Mapping[str, Any]) -> dict[str, Any]:
        backend = self._by_kind.get(str(kind).upper())
        if backend is None:
            raise ValueError("BACKEND_UNAVAILABLE")
        return backend.execute(binding, arguments)


def ros2_registry(resolver: Ros2RuntimeResolver, executor: Callable[[Mapping[str, Any], Mapping[str, Any]], Mapping[str, Any]] | None = None) -> RuntimeBackendRegistry:
    """Create the default registry for an observed ROS2 target.

    The ROS2 provider is deliberately read-only.  Do not advertise it for
    ``INVOKE`` (which would turn a topic observer into a write-capable
    provider), and do not synthesize an ``EXECUTE`` provider without an
    explicit source-bundle runtime.  Composition remains a declarative plan
    backend and is not a ROS2 topic execution path.
    """

    ros_backend = Ros2RuntimeBackend(resolver, executor)
    return RuntimeBackendRegistry(
        {
            OperationKind.OBSERVE.value: ros_backend,
            OperationKind.COMPOSE.value: DeclarativeRuntimeBackend("workflow"),
        }
    )


__all__ = [
    "DeclarativeRuntimeBackend",
    "ResolvedBackend",
    "Ros2RuntimeBackend",
    "Ros2ReadOnlyExecutor",
    "RuntimeBackend",
    "RuntimeBackendRegistry",
    "ros2_registry",
]
