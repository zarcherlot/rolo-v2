"""Generic dispatch for registered application Tool bindings."""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Mapping
from typing import Any

from .harness_execution import HarnessCodeExecutor, make_code_bundle
from .probe_registration import ExecutionBinding, load_registered_codegen_artifact

BindingHandler = Callable[[ExecutionBinding, Mapping[str, Any]], dict[str, Any]]


class ApplicationBindingDispatcher:
    """Route a binding to a provider handler without assuming a middleware."""

    def __init__(self, handlers: Mapping[str, BindingHandler] | None = None) -> None:
        self._handlers = dict(handlers or {})

    def register(self, kind: str, handler: BindingHandler) -> None:
        if not kind or kind in self._handlers:
            raise ValueError("binding handler kind must be unique and non-empty")
        self._handlers[kind] = handler

    @classmethod
    def for_target_executor(cls, target_executor: Any) -> ApplicationBindingDispatcher:
        """Create the default provider registry for a target.

        ROS 2 is one provider registration, not the dispatcher contract.  New
        providers can be added by Probe/Harness integration without changing
        Trace or the registration schema.
        """

        from .ros_binding import RosBindingExecutor

        ros = RosBindingExecutor(target_executor)
        dispatcher = cls()
        dispatcher.register("ros2_topic", lambda binding, arguments: ros.rotate(binding, arguments))
        return dispatcher

    def execute(self, binding: ExecutionBinding, arguments: Mapping[str, Any]) -> dict[str, Any]:
        handler = self._handlers.get(binding.kind)
        if handler is None:
            return {
                "status": "BLOCKED",
                "error": "UNSUPPORTED_BINDING_KIND",
                "binding_kind": binding.kind,
                "motion_started": False,
            }
        return handler(binding, arguments)


class RegisteredCodegenInvoker:
    """Reconstruct and execute a registered Harness function for Trace."""

    def __init__(self, registry_root: Any, target_id: str, target_executor: Any) -> None:
        self.registry_root = registry_root
        self.target_id = target_id
        self.target_executor = target_executor

    def invoke(self, tool_id: str, arguments: Mapping[str, Any], session_id: str) -> dict[str, Any]:
        del session_id
        artifact = load_registered_codegen_artifact(self.registry_root, self.target_id, tool_id)
        if artifact is None:
            return {"status": "BLOCKED", "error": "CODEGEN_ARTIFACT_UNAVAILABLE"}
        bundle_payload = artifact.get("bundle")
        if not isinstance(bundle_payload, Mapping):
            return {"status": "BLOCKED", "error": "CODEGEN_ARTIFACT_INVALID"}
        try:
            source = str(bundle_payload["source"])
            declared_digest = bundle_payload.get("source_sha256")
            if declared_digest and hashlib.sha256(source.encode("utf-8")).hexdigest() != declared_digest:
                return {"status": "BLOCKED", "error": "CODEGEN_ARTIFACT_DIGEST_MISMATCH"}
            bundle = make_code_bundle(
                tool_id=tool_id,
                source=source,
                request=dict(arguments),
                entrypoint=str(bundle_payload.get("entrypoint", "execute")),
            )
            return HarnessCodeExecutor(self.target_executor).execute(bundle, timeout_s=120)
        except (KeyError, TypeError, ValueError) as exc:
            return {"status": "BLOCKED", "error": "CODEGEN_ARTIFACT_INVALID", "detail": str(exc)[:240]}


__all__ = ["ApplicationBindingDispatcher", "BindingHandler", "RegisteredCodegenInvoker"]
