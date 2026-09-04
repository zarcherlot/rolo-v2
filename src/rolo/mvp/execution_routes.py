"""Target-bound execution routes used by application Tool adapters.

Application Tools describe intent; this module is the only runtime bridge to a
provider/driver.  A route may be backed by MHS, a middleware provider, or a
future transport, but the Tool never embeds a shell command or subprocess.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class ExecutionRoute(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["rolo-execution-route/v1"] = "rolo-execution-route/v1"
    route_id: str = Field(pattern=r"^[a-z][a-z0-9_.-]{1,127}$")
    target_id: str = Field(min_length=1, max_length=128)
    provider_id: str = Field(min_length=1, max_length=128)
    interface_type: str = Field(min_length=1, max_length=128)
    access: Literal["read", "write"]
    parameter_schema: dict[str, Any] = Field(default_factory=dict)
    stop_route_id: str | None = Field(default=None, max_length=128)
    evidence_refs: list[str] = Field(min_length=1, max_length=128)
    status: Literal["OBSERVED", "REGISTERED", "BLOCKED"] = "OBSERVED"
    registered_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @model_validator(mode="after")
    def validate_write_route(self) -> ExecutionRoute:
        if self.access == "write" and not self.stop_route_id:
            raise ValueError("write routes require a stop_route_id")
        if self.parameter_schema.get("type", "object") != "object":
            raise ValueError("route parameter_schema must describe an object")
        return self

    def digest(self) -> str:
        payload = self.model_dump(mode="json", exclude={"status"})
        return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class ExecutionRouteRegistry:
    """Small durable route registry; handlers remain process-local."""

    def __init__(self, root: Path) -> None:
        self.root = root

    def register(self, route: ExecutionRoute) -> ExecutionRoute:
        destination = self.root / route.target_id
        destination.mkdir(parents=True, exist_ok=True)
        path = destination / f"{route.route_id}.json"
        path.write_text(json.dumps(route.model_copy(update={"status": "REGISTERED"}).model_dump(mode="json"), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        return route.model_copy(update={"status": "REGISTERED"})

    def list(self, target_id: str) -> list[ExecutionRoute]:
        directory = self.root / target_id
        if not directory.is_dir():
            return []
        return [ExecutionRoute.model_validate_json(path.read_text(encoding="utf-8")) for path in sorted(directory.glob("*.json")) if path.is_file() and not path.is_symlink()]

    def get(self, target_id: str, route_id: str) -> ExecutionRoute:
        for route in self.list(target_id):
            if route.route_id == route_id and route.status == "REGISTERED":
                return route
        raise KeyError(f"registered execution route not found: {target_id}/{route_id}")


RouteHandler = Callable[[ExecutionRoute, Mapping[str, Any]], Mapping[str, Any]]


class RoloRouteBroker:
    """Invoke only a registered route through a provider-owned handler."""

    def __init__(self, registry: ExecutionRouteRegistry, handlers: Mapping[str, RouteHandler] | None = None) -> None:
        self.registry = registry
        self.handlers = dict(handlers or {})

    def invoke(self, *, target_id: str, route_id: str, arguments: Mapping[str, Any]) -> dict[str, Any]:
        route = self.registry.get(target_id, route_id)
        schema = route.parameter_schema
        required = schema.get("required", [])
        missing = sorted(name for name in required if name not in arguments)
        if missing:
            return {"status": "BLOCKED", "error": "ROUTE_ARGUMENTS_INVALID", "missing": missing, "route_id": route_id}
        if schema.get("additionalProperties") is False:
            properties = set(schema.get("properties", {}))
            unknown = sorted(set(arguments) - properties)
            if unknown:
                return {"status": "BLOCKED", "error": "ROUTE_ARGUMENTS_INVALID", "unknown": unknown, "route_id": route_id}
        handler = self.handlers.get(route.provider_id)
        if handler is None:
            return {"status": "BLOCKED", "error": "ROUTE_PROVIDER_UNAVAILABLE", "route_id": route_id}
        return dict(handler(route, arguments))


__all__ = ["ExecutionRoute", "ExecutionRouteRegistry", "RoloRouteBroker", "RouteHandler"]
