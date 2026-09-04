from __future__ import annotations

import hashlib
import json
import re
import secrets
from collections.abc import Callable, Mapping, Sequence
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .contracts import (
    CatalogTool,
    RunMode,
    SessionState,
    TargetCatalog,
    TraceCall,
    TraceEvent,
    TraceSession,
    TraceSessionRequest,
)


def _now() -> datetime:
    return datetime.now(timezone.utc)


class TraceService:
    """Bounded Trace state machine over a Probe-published catalog."""

    def __init__(
        self,
        catalog: TargetCatalog,
        invoker: Callable[[str, Mapping[str, Any], str], Any],
        *,
        artifact_root: Path | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.catalog = catalog
        self.invoker = invoker
        self.artifact_root = artifact_root
        self.clock = clock or _now
        self.sessions: dict[str, TraceSession] = {}

    @classmethod
    def from_registered_tools(
        cls,
        catalog: TargetCatalog,
        *,
        registry_root: Path,
        target_executor: Any,
        artifact_root: Path | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> TraceService:
        """Build a Trace service that reconstructs registered Harness artifacts."""

        from .binding_dispatch import RegisteredCodegenInvoker

        codegen = RegisteredCodegenInvoker(registry_root, catalog.target_id, target_executor)
        from .binding_dispatch import ApplicationBindingDispatcher
        from .ros_binding import RosBindingExecutor

        bindings = {item.tool_id: item.binding for item in catalog.tools if getattr(item, "binding", None)}
        dispatcher = ApplicationBindingDispatcher()
        dispatcher.register("ros2_topic", RosBindingExecutor(target_executor).rotate)

        def invoke(tool_id: str, arguments: Mapping[str, Any], session_id: str) -> Any:
            result = codegen.invoke(tool_id, arguments, session_id)
            if result.get("error") != "CODEGEN_ARTIFACT_UNAVAILABLE":
                return result
            binding = bindings.get(tool_id)
            if binding is not None:
                return dispatcher.execute(binding, arguments)
            return {"status": "BLOCKED", "error": "REGISTERED_EXECUTOR_UNAVAILABLE", "tool_id": tool_id}

        return cls(catalog, invoke, artifact_root=artifact_root, clock=clock)

    def create_session(self, request: TraceSessionRequest) -> TraceSession:
        if request.target_id != self.catalog.target_id or request.catalog_digest != self.catalog.digest:
            raise ValueError("TRACE_BLOCKED: target or catalog digest does not match Probe catalog")
        if self.catalog.freshness != "fresh":
            raise ValueError("TRACE_BLOCKED: Probe catalog is stale or unknown")
        now = self.clock()
        session = TraceSession(
            session_id=f"trace-{secrets.token_urlsafe(12)}",
            target_id=request.target_id,
            catalog_digest=request.catalog_digest,
            task=request.task,
            mode=request.mode,
            state=SessionState.DISCOVERED,
            created_at=now,
            expires_at=now + timedelta(seconds=request.ttl_s),
            max_calls=request.max_calls,
            operator_id=request.operator_id,
            safety_confirmed=request.safety_confirmed,
        )
        self.sessions[session.session_id] = session
        self._event(session, SessionState.DISCOVERED, "SESSION_CREATED")
        task_lower = request.task.lower()
        if ("map" in task_lower or "mapping" in task_lower or "建图" in request.task) and not self._mapping_tool():
            session.state = SessionState.BLOCKED
            session.limitations.append("BLOCKED: capability not observed")
            self._event(session, SessionState.BLOCKED, "MAPPING_TOOL_NOT_OBSERVED", error_code="CAPABILITY_NOT_OBSERVED")
        if any(token in task_lower for token in ("rotate", "rotation", "chassis", "旋转", "底盘", "地盘")) and not self._rotation_tool():
            session.state = SessionState.BLOCKED
            session.limitations.append("BLOCKED: physical rotation capability not observed")
            self._event(session, SessionState.BLOCKED, "ROTATION_TOOL_NOT_OBSERVED", error_code="CAPABILITY_NOT_OBSERVED")
        return session

    def execute(
        self,
        session_id: str,
        calls: Sequence[TraceCall | Mapping[str, Any]],
        *,
        diagnose: Callable[[Any, TraceSession], TraceCall | Mapping[str, Any] | None] | None = None,
        recover: Callable[[Any, TraceSession], TraceCall | Mapping[str, Any] | None] | None = None,
    ) -> TraceSession:
        session = self._get(session_id)
        self._check_live(session)
        if session.state in {SessionState.BLOCKED, SessionState.CANCELLED, SessionState.STOPPED}:
            return session
        self._transition(session, SessionState.PLANNED, "PLAN_ACCEPTED")
        for raw in calls:
            self._check_live(session)
            call = raw if isinstance(raw, TraceCall) else TraceCall.model_validate(raw)
            result = self._invoke(session, call)
            if not self._succeeded(result):
                self._transition(session, SessionState.DIAGNOSING, "TOOL_FAILURE", result=result, error_code="TOOL_FAILED")
                diagnosis = diagnose(result, session) if diagnose else None
                if diagnosis is not None:
                    self._invoke(session, diagnosis if isinstance(diagnosis, TraceCall) else TraceCall.model_validate(diagnosis))
                recovery = recover(result, session) if recover else None
                if recovery is not None:
                    self._transition(session, SessionState.RECOVERING, "RECOVERY_ATTEMPT")
                    retry_result = self._invoke(session, recovery if isinstance(recovery, TraceCall) else TraceCall.model_validate(recovery))
                    if not self._succeeded(retry_result):
                        session.state = SessionState.BLOCKED
                        session.limitations.append("recovery attempt failed")
                        self._event(session, SessionState.BLOCKED, "RECOVERY_FAILED", result=retry_result, error_code="RECOVERY_FAILED")
                        break
                else:
                    session.state = SessionState.UNKNOWN
                    session.limitations.append("tool failure could not be resolved")
                    self._event(session, SessionState.UNKNOWN, "UNRESOLVED_FAILURE", error_code="UNKNOWN")
                    break
        if session.state not in {SessionState.BLOCKED, SessionState.UNKNOWN, SessionState.CANCELLED, SessionState.STOPPED}:
            session.state = SessionState.COMPLETED
            self._event(session, SessionState.COMPLETED, "SESSION_COMPLETED")
        return session

    def cancel(self, session_id: str) -> TraceSession:
        return self._finish(session_id, SessionState.CANCELLED, "SESSION_CANCELLED")

    def stop(self, session_id: str) -> TraceSession:
        return self._finish(session_id, SessionState.STOPPED, "SESSION_STOPPED")

    def get(self, session_id: str) -> TraceSession:
        return self._get(session_id)

    def persist_session(self, session_id: str, root: Path | None = None) -> dict[str, Any]:
        """Write the replayable session, evidence bundle, and artifact index."""
        session = self._get(session_id)
        destination = root or self.artifact_root
        if destination is None:
            raise ValueError("an artifact root is required to persist a Trace session")
        directory = destination / session.target_id / session.session_id
        directory.mkdir(parents=True, exist_ok=True)
        session_path = directory / "trace-session.json"
        evidence_path = directory / "trace-evidence-bundle.json"
        session_path.write_text(json.dumps(session.model_dump(mode="json"), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        evidence = {
            "schema_version": "rolo-mvp-trace-evidence-bundle/v1",
            "session_id": session.session_id,
            "target_id": session.target_id,
            "catalog_digest": session.catalog_digest,
            "evidence_ids": session.evidence_ids,
            "events": [item.model_dump(mode="json") for item in session.events],
            "limitations": session.limitations,
        }
        evidence_path.write_text(json.dumps(evidence, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        files = [session_path, evidence_path]
        index = {
            "schema_version": "rolo-mvp-artifact-index/v1",
            "run_id": session.session_id,
            "target_id": session.target_id,
            "artifacts": [{"path": file.name, "sha256": hashlib.sha256(file.read_bytes()).hexdigest()} for file in files],
        }
        index_path = directory / "artifact-index.json"
        index_path.write_text(json.dumps(index, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        return {"session": session_path, "evidence": evidence_path, "index": index_path}

    def _invoke(self, session: TraceSession, call: TraceCall) -> Any:
        self._check_live(session)
        descriptor = next((item for item in self.catalog.tools if item.tool_id == call.tool_id), None)
        if descriptor is None or descriptor.target_id != session.target_id or not descriptor.agent_callable:
            session.state = SessionState.BLOCKED
            self._event(session, SessionState.BLOCKED, "TOOL_NOT_CALLABLE", tool_id=call.tool_id, error_code="TOOL_NOT_CALLABLE")
            raise ValueError("TRACE_BLOCKED: tool is not callable in the Probe catalog")
        if descriptor.experimental_write and session.mode != RunMode.SUPERVISED_FIELD_DEBUG:
            session.state = SessionState.BLOCKED
            self._event(session, SessionState.BLOCKED, "WRITE_MODE_REQUIRED", tool_id=call.tool_id, error_code="WRITE_MODE_REQUIRED")
            raise ValueError("WRITE_BLOCKED: experimental write requires supervised field debug")
        if session.calls >= session.max_calls:
            session.state = SessionState.BLOCKED
            self._event(session, SessionState.BLOCKED, "TRACE_BUDGET_EXHAUSTED", error_code="TRACE_BUDGET_EXHAUSTED")
            raise ValueError("TRACE_BUDGET_EXHAUSTED: call budget reached")
        try:
            encoded_arguments = json.dumps(call.arguments, ensure_ascii=False, separators=(",", ":"))
        except (TypeError, ValueError) as exc:
            session.state = SessionState.BLOCKED
            self._event(session, SessionState.BLOCKED, "PARAMETER_REJECTED", tool_id=call.tool_id, error_code="PARAMETER_REJECTED")
            raise ValueError("PARAMETER_REJECTED: arguments must be JSON serializable") from exc
        if len(encoded_arguments.encode("utf-8")) > 16 * 1024:
            session.state = SessionState.BLOCKED
            self._event(session, SessionState.BLOCKED, "PARAMETER_REJECTED", tool_id=call.tool_id, error_code="PARAMETER_REJECTED")
            raise ValueError("PARAMETER_REJECTED: arguments exceed 16 KiB")
        try:
            self._validate_arguments(descriptor, call.arguments)
        except ValueError as exc:
            session.state = SessionState.BLOCKED
            self._event(session, SessionState.BLOCKED, "PARAMETER_REJECTED", tool_id=call.tool_id, error_code="PARAMETER_REJECTED")
            raise exc
        session.state = SessionState.CALLING
        self._event(session, SessionState.CALLING, "TOOL_CALL", tool_id=call.tool_id, arguments=dict(call.arguments))
        session.calls += 1
        try:
            result = self.invoker(call.tool_id, call.arguments, session.session_id)
        except Exception as exc:
            result = {"status": "FAILED", "error": type(exc).__name__}
        try:
            result_size = len(json.dumps(result, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
        except (TypeError, ValueError):
            result_size = 0
        if result_size > 512 * 1024:
            result = {"status": "FAILED", "error": "RESULT_TOO_LARGE"}
        session.state = SessionState.OBSERVED
        evidence = [f"trace:{session.session_id}:call:{session.calls}"]
        session.evidence_ids.extend(evidence)
        self._event(session, SessionState.OBSERVED, "TOOL_RESULT", tool_id=call.tool_id, result=result, evidence_ids=evidence)
        return result

    @staticmethod
    def _succeeded(result: Any) -> bool:
        return isinstance(result, Mapping) and str(result.get("status", "")).upper() in {"SUCCEEDED", "SUCCESS", "PASS"}

    def _mapping_tool(self) -> CatalogTool | None:
        return next((item for item in self.catalog.tools if item.agent_callable and ("map" in item.tool_id.lower() or "mapping" in item.tool_id.lower())), None)

    def _rotation_tool(self) -> CatalogTool | None:
        return next(
            (
                item
                for item in self.catalog.tools
                if item.agent_callable
                and item.experimental_write
                and any(token in item.tool_id.lower() for token in ("rotate", "rotation", "chassis"))
            ),
            None,
        )

    def _get(self, session_id: str) -> TraceSession:
        if session_id not in self.sessions:
            raise KeyError(session_id)
        return self.sessions[session_id]

    def _check_live(self, session: TraceSession) -> None:
        if self.clock() >= session.expires_at:
            if session.state == SessionState.BLOCKED and "session TTL expired" in session.limitations:
                raise ValueError("TRACE_BLOCKED: session TTL expired")
            session.state = SessionState.BLOCKED
            session.limitations.append("session TTL expired")
            self._event(session, SessionState.BLOCKED, "SESSION_EXPIRED", error_code="SESSION_EXPIRED")
            raise ValueError("TRACE_BLOCKED: session TTL expired")

    @staticmethod
    def _validate_arguments(descriptor: CatalogTool, arguments: Mapping[str, Any]) -> None:
        definitions = descriptor.parameters
        unknown = sorted(set(arguments) - set(definitions))
        if unknown:
            raise ValueError(f"PARAMETER_REJECTED: unknown arguments {unknown}")
        for name, definition in definitions.items():
            if not isinstance(definition, Mapping):
                continue
            required = bool(definition.get("required", False))
            if required and name not in arguments:
                raise ValueError(f"PARAMETER_REJECTED: missing argument {name}")
            if name not in arguments:
                continue
            value = arguments[name]
            max_length = int(definition.get("max_length", 1024))
            if isinstance(value, str) and len(value) > max_length:
                raise ValueError(f"PARAMETER_REJECTED: argument {name} exceeds max_length")
            choices = definition.get("choices", [])
            if choices and value not in choices:
                raise ValueError(f"PARAMETER_REJECTED: argument {name} is outside choices")
            pattern = definition.get("pattern")
            if pattern and isinstance(value, str) and re.fullmatch(str(pattern), value) is None:
                raise ValueError(f"PARAMETER_REJECTED: argument {name} does not match pattern")
            if definition.get("kind") == "integer" and (isinstance(value, bool) or not isinstance(value, int)):
                raise ValueError(f"PARAMETER_REJECTED: argument {name} must be an integer")

    def _finish(self, session_id: str, state: SessionState, event: str) -> TraceSession:
        session = self._get(session_id)
        if session.state not in {SessionState.COMPLETED, SessionState.BLOCKED, SessionState.UNKNOWN}:
            session.state = state
            self._event(session, state, event)
        return session

    def _transition(self, session: TraceSession, state: SessionState, event: str, **kwargs: Any) -> None:
        session.state = state
        self._event(session, state, event, **kwargs)

    def _event(self, session: TraceSession, state: SessionState, event: str, **kwargs: Any) -> None:
        safe_kwargs = {key: self._safe_value(value, key=key) for key, value in kwargs.items()}
        item = TraceEvent(sequence=len(session.events) + 1, session_id=session.session_id, state=state, event=event, created_at=self.clock(), **safe_kwargs)
        session.events.append(item)
        if self.artifact_root is not None:
            path = self.artifact_root / session.target_id / session.session_id / "trace-events.jsonl"
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(item.model_dump(mode="json"), ensure_ascii=False, separators=(",", ":")) + "\n")

    @classmethod
    def _safe_value(cls, value: Any, *, key: str = "") -> Any:
        if any(token in key.lower() for token in ("token", "secret", "password", "authorization", "credential")):
            return "<redacted>"
        if value is None or isinstance(value, (bool, int, float)):
            return value
        if isinstance(value, str):
            return value[:4096]
        if isinstance(value, Mapping):
            return {str(k): cls._safe_value(v, key=str(k)) for k, v in list(value.items())[:64]}
        if isinstance(value, (list, tuple)):
            return [cls._safe_value(item) for item in list(value)[:128]]
        try:
            json.dumps(value)
        except (TypeError, ValueError):
            return f"<{type(value).__name__}>"
        return value


__all__ = ["TraceService"]
