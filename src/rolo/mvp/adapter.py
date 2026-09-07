from __future__ import annotations

import inspect
from collections.abc import Callable, Mapping
from typing import Any, Protocol

from .contracts import TargetCatalog


class AgentAdapter(Protocol):
    def discover_target(self, target_id: str) -> TargetCatalog: ...
    def read_rkb(self, query: str) -> dict[str, Any]: ...
    def start_trace(self, task: str, target_id: str, **kwargs: Any) -> dict[str, Any]: ...
    def invoke_tool(
        self,
        tool_id: str,
        arguments: Mapping[str, Any],
        session_id: str,
        *,
        idempotency_key: str | None = None,
        target_id: str | None = None,
    ) -> Any: ...
    def start_certify(self, suite_ref: str, target_id: str, **kwargs: Any) -> dict[str, Any]: ...
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

    def start_trace(self, task: str, target_id: str, **kwargs: Any) -> dict[str, Any]:
        if target_id != self.catalog.target_id:
            raise ValueError("target not found")
        # Keep the in-memory adapter equivalent to the public connector while
        # avoiding a second state machine in this deterministic test helper.
        run_id = kwargs.get("run_id") or f"memory-trace-{len(self.runs) + 1}"
        payload = {
            "schema_version": "rolo-trace-run/v1",
            "run_id": run_id,
            "session_id": run_id,
            "target_id": target_id,
            "task": task,
            "status": "DISCOVERED",
            "catalog_digest": self.catalog.digest,
        }
        self.runs[run_id] = payload
        return payload

    def invoke_tool(
        self,
        tool_id: str,
        arguments: Mapping[str, Any],
        session_id: str,
        *,
        idempotency_key: str | None = None,
        target_id: str | None = None,
    ) -> Any:
        if target_id is not None and target_id != self.catalog.target_id:
            raise ValueError("target not found")
        try:
            signature = inspect.signature(self.tool_runner)
            parameters = tuple(signature.parameters.values())
            positional = [
                parameter
                for parameter in parameters
                if parameter.kind in (parameter.POSITIONAL_ONLY, parameter.POSITIONAL_OR_KEYWORD)
            ]
            accepts_varargs = any(parameter.kind == parameter.VAR_POSITIONAL for parameter in parameters)
        except (TypeError, ValueError):
            parameters = ()
            positional = []
            accepts_varargs = True
        if idempotency_key is not None and (accepts_varargs or len(positional) >= 4):
            return self.tool_runner(tool_id, arguments, session_id, idempotency_key)
        if idempotency_key is not None:
            keyword_key = next(
                (
                    parameter.name
                    for parameter in parameters
                    if parameter.kind == parameter.KEYWORD_ONLY
                    and parameter.name in {"idempotency_key", "operation_id"}
                ),
                None,
            )
            if keyword_key is not None:
                return self.tool_runner(tool_id, arguments, session_id, **{keyword_key: idempotency_key})
            if any(parameter.kind == parameter.VAR_KEYWORD for parameter in parameters):
                return self.tool_runner(tool_id, arguments, session_id, idempotency_key=idempotency_key)
        return self.tool_runner(tool_id, arguments, session_id)

    def start_certify(self, suite_ref: str, target_id: str, **kwargs: Any) -> dict[str, Any]:
        if target_id != self.catalog.target_id:
            raise ValueError("target not found")
        # There is no filesystem or provider execution in this adapter.  Keep
        # the action explicit and machine-readable so an Agent can surface a
        # bounded BLOCKED result instead of mistaking an adapter exception for
        # a failed physical test.
        return {
            "schema_version": "rolo-certify-run/v1",
            "status": "BLOCKED",
            "target_id": target_id,
            "suite_ref": suite_ref,
            "reason": "certification execution is unavailable in the in-memory adapter",
        }

    def get_run(self, run_id: str) -> dict[str, Any]:
        return self.runs.get(run_id, {"status": "UNKNOWN", "run_id": run_id})


class RoloHttpAgentAdapter:
    """Small HTTP connector for external Agent products.

    The adapter only speaks the semantic connector actions and never exposes a
    generic proxy.  Legacy ``/v1/mvp`` methods remain the default for source
    compatibility; the explicit journey methods use the normative ``/v1``
    routes.  ``httpx`` is imported lazily so offline contract tooling can run
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

    def discover_target(self, target_id: str, *, public: bool = False) -> TargetCatalog:
        """Read a catalog using the historical MVP route by default.

        ``public=True`` selects the normative Agent connector route.  Keeping
        the default on ``/v1/mvp`` preserves callers written against the first
        adapter contract while the new journey methods below use the public
        route explicitly.
        """

        prefix = "/v1" if public else "/v1/mvp"
        data = self._request("GET", f"{prefix}/targets/{target_id}/catalog")
        return TargetCatalog.model_validate(data)

    def read_rkb(self, query: str, *, target_id: str | None = None, public: bool = False) -> dict[str, Any]:
        prefix = "/v1" if public else "/v1/mvp"
        params: dict[str, Any] = {"query": query}
        if target_id is not None:
            params["target_id"] = target_id
        return self._request("GET", f"{prefix}/rkb", params=params)

    def start_trace(self, task: str, target_id: str, **kwargs: Any) -> dict[str, Any]:
        catalog = self.discover_target(target_id, public=True)
        payload: dict[str, Any] = {
            "target_id": target_id,
            "catalog_digest": catalog.digest,
            "task": task,
        }
        for key in ("mode", "ttl_s", "max_calls", "operator_id", "safety_confirmed", "release_digest", "compile_context_digest", "target_fingerprint", "scope"):
            if key in kwargs and kwargs[key] is not None:
                payload[key] = kwargs[key]
        return self._request("POST", "/v1/runs", json=payload)

    def invoke_tool(
        self,
        tool_id: str,
        arguments: Mapping[str, Any],
        session_id: str,
        *,
        idempotency_key: str | None = None,
        target_id: str | None = None,
        public: bool = False,
        return_result: bool = False,
    ) -> Any:
        payload: dict[str, Any] = {"tool_id": tool_id, "arguments": dict(arguments)}
        if idempotency_key is not None:
            payload["idempotency_key"] = idempotency_key
        if target_id is not None:
            payload["target_id"] = target_id
        if not public:
            payload["session_id"] = session_id
            return self._request("POST", "/v1/mvp/invoke", json=payload)
        response = self._request("POST", f"/v1/runs/{session_id}/tool-calls", json=payload)
        # The connector returns the updated run envelope.  Preserve the
        # historical adapter behavior of returning the latest operation result
        # when one is available, while exposing the full envelope for callers
        # that need audit fields.
        if not return_result:
            return response
        events = response.get("events")
        if isinstance(events, list):
            for event in reversed(events):
                if isinstance(event, Mapping) and event.get("event") in {"TOOL_RESULT", "TOOL_RESULT_REUSED"}:
                    return event.get("result", response)
        return response

    def start_certify(self, suite_ref: str, target_id: str, **kwargs: Any) -> dict[str, Any]:
        payload: dict[str, Any] = {"target_id": target_id, "suite_ref": suite_ref}
        for key in ("snapshot_digest", "compile_context_digest", "target_fingerprint", "failure_policy", "session_id"):
            if key in kwargs and kwargs[key] is not None:
                payload[key] = kwargs[key]
        return self._request("POST", "/v1/certify/runs", json=payload)

    def get_run(self, run_id: str) -> dict[str, Any]:
        return self._request("GET", f"/v1/mvp/runs/{run_id}")

    def invoke_trace_tool(
        self,
        tool_id: str,
        arguments: Mapping[str, Any],
        run_id: str,
        *,
        idempotency_key: str | None = None,
        target_id: str | None = None,
        return_result: bool = False,
    ) -> Any:
        """Invoke through the public ``/v1/runs`` connector explicitly."""

        return self.invoke_tool(
            tool_id,
            arguments,
            run_id,
            idempotency_key=idempotency_key,
            target_id=target_id,
            public=True,
            return_result=return_result,
        )

    def get_public_run(self, run_id: str, *, target_id: str | None = None) -> dict[str, Any]:
        params = {"target_id": target_id} if target_id is not None else None
        return self._request("GET", f"/v1/runs/{run_id}", params=params)


__all__ = ["AgentAdapter", "InMemoryAgentAdapter", "RoloHttpAgentAdapter"]
