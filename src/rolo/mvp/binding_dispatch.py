"""Generic dispatch for registered application Tool bindings."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from .probe_registration import ExecutionBinding

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


__all__ = ["ApplicationBindingDispatcher", "BindingHandler"]
