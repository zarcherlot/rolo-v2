from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any, Protocol

from .contracts import TargetCatalog


class AgentAdapter(Protocol):
    def discover_target(self, target_id: str) -> TargetCatalog: ...
    def read_rkb(self, query: str) -> dict[str, Any]: ...
    def invoke_tool(self, tool_id: str, arguments: Mapping[str, Any], session_id: str) -> Any: ...
    def get_run(self, run_id: str) -> dict[str, Any]: ...


class InMemoryAgentAdapter:
    """Deterministic adapter used by offline replay and contract tests."""

    def __init__(
        self,
        catalog: TargetCatalog,
        *,
        tool_runner: Callable[[str, Mapping[str, Any], str], Any] | None = None,
        rkb_values: Mapping[str, Any] | None = None,
    ) -> None:
        self.catalog = catalog
        self.tool_runner = tool_runner or (lambda tool_id, arguments, session_id: {"status": "SUCCEEDED", "tool_id": tool_id, "arguments": dict(arguments)})
        self.rkb_values = dict(rkb_values or {})
        self.runs: dict[str, dict[str, Any]] = {}

    def discover_target(self, target_id: str) -> TargetCatalog:
        if target_id != self.catalog.target_id:
            raise ValueError("target not found")
        return self.catalog

    def read_rkb(self, query: str) -> dict[str, Any]:
        if query not in self.rkb_values:
            return {"status": "UNKNOWN", "value": None, "evidence_ids": [], "limitations": ["query not present in verified snapshot"]}
        value = self.rkb_values[query]
        return {"status": "KNOWN", "value": value, "evidence_ids": [], "limitations": []}

    def invoke_tool(self, tool_id: str, arguments: Mapping[str, Any], session_id: str) -> Any:
        return self.tool_runner(tool_id, arguments, session_id)

    def get_run(self, run_id: str) -> dict[str, Any]:
        return self.runs.get(run_id, {"status": "UNKNOWN", "run_id": run_id})


class RoloHttpAgentAdapter:
    """Small HTTP connector for external Agent products.

    The adapter only speaks the four MVP actions and never exposes a generic
    proxy.  ``httpx`` is imported lazily so offline contract tooling can run
    without installing the HTTP extra.
    """

    def __init__(self, base_url: str, *, timeout_s: float = 15.0, client: Any | None = None) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout_s = timeout_s
        self._client = client

    def _request(self, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        client = self._client
        if client is None:
            import httpx

            with httpx.Client(base_url=self.base_url, timeout=self.timeout_s) as client:
                response = client.request(method, path, **kwargs)
        else:
            response = client.request(method, path, **kwargs)
        response.raise_for_status()
        data = response.json()
        if not isinstance(data, dict):
            raise ValueError("Rolo adapter response must be an object")
        return data

    def discover_target(self, target_id: str) -> TargetCatalog:
        data = self._request("GET", f"/v1/mvp/targets/{target_id}/catalog")
        return TargetCatalog.model_validate(data)

    def read_rkb(self, query: str) -> dict[str, Any]:
        return self._request("GET", "/v1/mvp/rkb", params={"query": query})

    def invoke_tool(self, tool_id: str, arguments: Mapping[str, Any], session_id: str) -> Any:
        return self._request("POST", "/v1/mvp/invoke", json={"tool_id": tool_id, "arguments": dict(arguments), "session_id": session_id})

    def get_run(self, run_id: str) -> dict[str, Any]:
        return self._request("GET", f"/v1/mvp/runs/{run_id}")


__all__ = ["AgentAdapter", "InMemoryAgentAdapter", "RoloHttpAgentAdapter"]
