from __future__ import annotations

import hashlib
import inspect
import json
import re
import secrets
from collections.abc import Callable, Mapping, Sequence
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .artifacts import build_artifact_index, write_artifact_index
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
from .trace_diagnostics import TraceDiagnosticPlan, build_odom_ekf_diagnostic_plan


def _now() -> datetime:
    return datetime.now(timezone.utc)


_TARGET_FINGERPRINT_RE = re.compile(r"^[0-9a-f]{64}$")


def _valid_target_fingerprint(value: str | None) -> bool:
    return value in (None, "UNKNOWN") or bool(_TARGET_FINGERPRINT_RE.fullmatch(value))


class TraceService:
    """Bounded Trace state machine over a Probe-published catalog."""

    def __init__(
        self,
        catalog: TargetCatalog,
        invoker: Callable[..., Any],
        *,
        artifact_root: Path | None = None,
        clock: Callable[[], datetime] | None = None,
        stopper: Callable[[str, str], Any] | None = None,
        release_digest: str | None = None,
        compile_context_digest: str | None = None,
        target_fingerprint: str | None = None,
        autonomous_source_confirmed: bool = False,
        max_diagnosis_attempts: int = 2,
        max_recovery_attempts: int = 2,
    ) -> None:
        self.catalog = catalog
        self.invoker = invoker
        self.artifact_root = artifact_root
        self.clock = clock or _now
        self.stopper = stopper
        self.release_digest = release_digest
        self.compile_context_digest = compile_context_digest
        self.target_fingerprint = target_fingerprint or catalog.target_fingerprint
        self.autonomous_source_confirmed = bool(autonomous_source_confirmed)
        self.max_diagnosis_attempts = max(0, min(int(max_diagnosis_attempts), 8))
        self.max_recovery_attempts = max(0, min(int(max_recovery_attempts), 8))
        self.sessions: dict[str, TraceSession] = {}
        # Results are keyed by caller-visible idempotency key.  This map is
        # deliberately scoped to the service instance; a durable targetd
        # transport remains responsible for cross-process reconciliation.
        self._idempotent_results: dict[tuple[str, str], tuple[str, str, Any, str]] = {}
        self._next_call_sequence: dict[str, int] = {}

    @staticmethod
    def odom_ekf_diagnostic_plan() -> TraceDiagnosticPlan:
        """Expose the fixed, read-only customer-host diagnosis chain to Agent."""

        return build_odom_ekf_diagnostic_plan()

    @classmethod
    def from_registered_tools(
        cls,
        catalog: TargetCatalog,
        *,
        registry_root: Path,
        target_executor: Any,
        artifact_root: Path | None = None,
        clock: Callable[[], datetime] | None = None,
        stopper: Callable[[str, str], Any] | None = None,
        release_digest: str | None = None,
        compile_context_digest: str | None = None,
        target_fingerprint: str | None = None,
        autonomous_source_confirmed: bool = False,
        max_diagnosis_attempts: int = 2,
        max_recovery_attempts: int = 2,
    ) -> TraceService:
        """Build a Trace service that reconstructs registered Harness artifacts."""

        from .binding_dispatch import RegisteredCodegenInvoker

        codegen = RegisteredCodegenInvoker(registry_root, catalog.target_id, target_executor)
        from .binding_dispatch import ApplicationBindingDispatcher
        from .ros_binding import RosBindingExecutor

        bindings = {item.tool_id: item.binding for item in catalog.tools if getattr(item, "binding", None)}
        dispatcher = ApplicationBindingDispatcher()
        dispatcher.register(
            "ros2_topic",
            RosBindingExecutor(
                target_executor,
                autonomous_source_confirmed=autonomous_source_confirmed,
            ).rotate,
        )

        def invoke(
            tool_id: str,
            arguments: Mapping[str, Any],
            session_id: str,
            idempotency_key: str | None = None,
        ) -> Any:
            # Registered codegen providers still expose the legacy three
            # argument shape today.  Pass the key when a provider supports it,
            # retaining compatibility with existing generated artifacts.
            try:
                signature = inspect.signature(codegen.invoke)
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
                result = codegen.invoke(tool_id, arguments, session_id, idempotency_key)
            elif idempotency_key is not None:
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
                    result = codegen.invoke(tool_id, arguments, session_id, **{keyword_key: idempotency_key})
                elif any(parameter.kind == parameter.VAR_KEYWORD for parameter in parameters):
                    result = codegen.invoke(tool_id, arguments, session_id, idempotency_key=idempotency_key)
                else:
                    result = codegen.invoke(tool_id, arguments, session_id)
            else:
                result = codegen.invoke(tool_id, arguments, session_id)
            if result.get("error") != "CODEGEN_ARTIFACT_UNAVAILABLE":
                return result
            binding = bindings.get(tool_id)
            if binding is not None:
                return dispatcher.execute(binding, arguments)
            return {"status": "BLOCKED", "error": "REGISTERED_EXECUTOR_UNAVAILABLE", "tool_id": tool_id}

        return cls(
            catalog,
            invoke,
            artifact_root=artifact_root,
            clock=clock,
            stopper=stopper,
            release_digest=release_digest,
            compile_context_digest=compile_context_digest,
            target_fingerprint=target_fingerprint,
            autonomous_source_confirmed=autonomous_source_confirmed,
            max_diagnosis_attempts=max_diagnosis_attempts,
            max_recovery_attempts=max_recovery_attempts,
        )

    def create_session(self, request: TraceSessionRequest) -> TraceSession:
        if request.target_id != self.catalog.target_id or request.catalog_digest != self.catalog.digest:
            raise ValueError("TRACE_BLOCKED: target or catalog digest does not match Probe catalog")
        if self.catalog.freshness != "fresh":
            raise ValueError("TRACE_BLOCKED: Probe catalog is stale or unknown")
        # A release-bound service owns these identities.  An Agent may omit
        # them for backwards compatibility, but it may not substitute a
        # different release/context/target fingerprint or downgrade a known
        # fingerprint to UNKNOWN.
        for label, supplied, bound in (
            ("release digest", request.release_digest, self.release_digest),
            ("compile context digest", request.compile_context_digest, self.compile_context_digest),
            ("target fingerprint", request.target_fingerprint, self.target_fingerprint),
        ):
            if bound is not None and supplied is not None and supplied != bound:
                raise ValueError(f"TRACE_BLOCKED: {label} does not match the bound identity")
        # The Probe catalog is the second independent source of target
        # identity.  A caller cannot replace a service binding with a custom
        # fingerprint (or downgrade a known catalog fingerprint to UNKNOWN),
        # even when the service itself was created without an explicit bound
        # value.
        effective_fingerprint = request.target_fingerprint or self.target_fingerprint
        if not _valid_target_fingerprint(effective_fingerprint):
            raise ValueError("TRACE_BLOCKED: target fingerprint is invalid")
        if self.catalog.target_fingerprint == "UNKNOWN" and effective_fingerprint not in (None, "UNKNOWN"):
            raise ValueError("TRACE_BLOCKED: catalog target fingerprint is unknown")
        if self.catalog.target_fingerprint != "UNKNOWN" and effective_fingerprint != self.catalog.target_fingerprint:
            raise ValueError("TRACE_BLOCKED: target fingerprint does not match Probe catalog")
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
            release_digest=request.release_digest or self.release_digest,
            compile_context_digest=request.compile_context_digest or self.compile_context_digest,
            target_fingerprint=effective_fingerprint,
            scope=tuple(request.scope),
        )
        self.sessions[session.session_id] = session
        self._next_call_sequence[session.session_id] = 0
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
        if session.state == SessionState.UNKNOWN:
            # An UNKNOWN result means the transport may have accepted the
            # operation.  Replaying without an explicit resume/reconcile step
            # could duplicate a physical action.
            raise ValueError("TRACE_RESUME_REQUIRED: reconcile UNKNOWN before submitting more calls")
        if session.state in {SessionState.BLOCKED, SessionState.CANCELLED, SessionState.STOPPED}:
            return session
        self._transition(session, SessionState.PLANNED, "PLAN_ACCEPTED")
        diagnosis_attempts = session.diagnosis_attempts
        recovery_attempts = session.recovery_attempts
        for raw in calls:
            self._check_live(session)
            call = raw if isinstance(raw, TraceCall) else TraceCall.model_validate(raw)
            result = self._invoke(session, call)
            if not self._succeeded(result):
                provider_status = str(result.get("status", "")).upper() if isinstance(result, Mapping) else ""
                if provider_status in {"BLOCKED", "DENIED", "UNAUTHORIZED", "AUTHORIZATION"}:
                    self._transition(
                        session,
                        SessionState.BLOCKED,
                        "TOOL_BLOCKED",
                        result=result,
                        error_code="TOOL_BLOCKED",
                    )
                    break
                self._transition(session, SessionState.DIAGNOSING, "TOOL_FAILURE", result=result, error_code="TOOL_FAILED")
                diagnosis_result = None
                if diagnose is not None and diagnosis_attempts < self.max_diagnosis_attempts:
                    diagnosis_attempts += 1
                    session.diagnosis_attempts = diagnosis_attempts
                    self._event(
                        session,
                        SessionState.DIAGNOSING,
                        "DIAGNOSIS_ATTEMPT",
                        attempt=diagnosis_attempts,
                    )
                    try:
                        diagnosis = diagnose(result, session)
                        if diagnosis is not None:
                            diagnosis_result = self._invoke(
                                session,
                                diagnosis if isinstance(diagnosis, TraceCall) else TraceCall.model_validate(diagnosis),
                            )
                            self._event(
                                session,
                                SessionState.DIAGNOSING,
                                "DIAGNOSIS_RESULT",
                                result=diagnosis_result,
                                attempt=diagnosis_attempts,
                            )
                    except Exception as exc:
                        error_code = self._callback_error_code("DIAGNOSIS", exc)
                        session.limitations.append(f"{error_code}: diagnostic callback failed")
                        self._event(
                            session,
                            SessionState.DIAGNOSING,
                            "DIAGNOSIS_FAILED",
                            error_code=error_code,
                            error=type(exc).__name__,
                            attempt=diagnosis_attempts,
                        )
                        # A diagnostic call that was rejected by the catalog
                        # must leave the run blocked; do not let a later
                        # recovery callback overwrite that safety decision.
                        if session.state == SessionState.BLOCKED:
                            break
                elif diagnose is not None:
                    self._event(
                        session,
                        SessionState.DIAGNOSING,
                        "DIAGNOSIS_LIMIT_REACHED",
                        error_code="DIAGNOSIS_LIMIT_REACHED",
                        attempt=diagnosis_attempts,
                    )
                recovery = None
                recovery_attempt = None
                if recover is not None and recovery_attempts < self.max_recovery_attempts:
                    # The plan callback itself is a bounded attempt.  Counting
                    # only a returned Tool call allowed a callback that raised
                    # or returned ``None`` to run again after every resume.
                    recovery_attempts += 1
                    recovery_attempt = recovery_attempts
                    session.recovery_attempts = recovery_attempts
                    self._event(
                        session,
                        SessionState.RECOVERING,
                        "RECOVERY_PLAN_ATTEMPT",
                        attempt=recovery_attempt,
                    )
                    try:
                        recovery = recover(result, session)
                    except Exception as exc:
                        error_code = self._callback_error_code("RECOVERY", exc)
                        session.limitations.append(f"{error_code}: recovery callback failed")
                        self._event(
                            session,
                            SessionState.RECOVERING,
                            "RECOVERY_PLAN_FAILED",
                            error_code=error_code,
                            error=type(exc).__name__,
                            attempt=recovery_attempt,
                        )
                        # Authorization failures are a policy block.  Other
                        # callback failures remain UNKNOWN until an explicit
                        # reconciliation/resume, with the consumed attempt
                        # retained in the session budget.
                        if isinstance(exc, PermissionError):
                            session.state = SessionState.BLOCKED
                            self._event(
                                session,
                                SessionState.BLOCKED,
                                "RECOVERY_AUTHORIZATION_BLOCKED",
                                error_code="RECOVERY_AUTHORIZATION",
                                attempt=recovery_attempt,
                            )
                            break
                elif recover is not None:
                    # Do not invoke the callback after the configured budget;
                    # callback execution itself could have side effects.
                    session.state = SessionState.BLOCKED
                    session.limitations.append("recovery attempt limit reached")
                    self._event(
                        session,
                        SessionState.BLOCKED,
                        "RECOVERY_LIMIT_REACHED",
                        error_code="RECOVERY_LIMIT_REACHED",
                        attempt=recovery_attempts,
                    )
                    break
                if recovery is not None:
                    self._transition(session, SessionState.RECOVERING, "RECOVERY_ATTEMPT")
                    self._event(session, SessionState.RECOVERING, "RECOVERY_ATTEMPT_BOUNDED", attempt=recovery_attempt)
                    try:
                        retry_result = self._invoke(session, recovery if isinstance(recovery, TraceCall) else TraceCall.model_validate(recovery))
                    except Exception as exc:
                        retry_result = {"status": "FAILED", "error": type(exc).__name__}
                    if not self._succeeded(retry_result):
                        session.state = SessionState.BLOCKED
                        session.limitations.append("recovery attempt failed")
                        self._event(session, SessionState.BLOCKED, "RECOVERY_FAILED", result=retry_result, error_code="RECOVERY_FAILED")
                        break
                else:
                    if session.state == SessionState.BLOCKED:
                        break
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

    def resume(self, session_id: str) -> TraceSession:
        """Re-open an unresolved session after the caller reconciles transport state.

        Resume never replays a call by itself.  The caller must submit the
        original idempotency key through ``execute``; an already observed key
        is returned from the local result cache and a missing key is a new,
        explicitly requested operation.
        """

        session = self._get(session_id)
        self._check_live(session)
        if session.state not in {SessionState.UNKNOWN, SessionState.BLOCKED}:
            return session
        if session.state == SessionState.BLOCKED and "session TTL expired" in session.limitations:
            raise ValueError("TRACE_BLOCKED: session TTL expired")
        if session.state == SessionState.BLOCKED:
            raise ValueError("TRACE_BLOCKED: only an UNKNOWN transport result may be resumed")
        session.state = SessionState.DISCOVERED
        session.resume_count += 1
        self._event(session, SessionState.DISCOVERED, "SESSION_RESUMED", attempt=session.resume_count)
        return session

    @staticmethod
    def _callback_error_code(prefix: str, error: Exception) -> str:
        """Classify callback failures without exposing provider internals."""

        if isinstance(error, PermissionError):
            return f"{prefix}_AUTHORIZATION"
        if isinstance(error, TimeoutError):
            return f"{prefix}_TIMEOUT"
        return f"{prefix}_ERROR"

    def get(self, session_id: str) -> TraceSession:
        return self._get(session_id)

    def persist_session(
        self,
        session_id: str,
        root: Path | None = None,
        *,
        signing_secret: bytes | None = None,
        previous_index: str | None = None,
    ) -> dict[str, Any]:
        """Write the replayable session, evidence bundle, and artifact index."""
        session = self._get(session_id)
        destination = root or self.artifact_root
        if destination is None:
            raise ValueError("an artifact root is required to persist a Trace session")
        if destination.exists() and destination.is_symlink():
            raise ValueError("trace artifact root must not be a symlink")
        destination.mkdir(parents=True, exist_ok=True)
        if not destination.is_dir():
            raise ValueError("trace artifact root must be a directory")
        target_directory = destination / session.target_id
        if target_directory.exists() and target_directory.is_symlink():
            raise ValueError("trace target artifact directory must not be a symlink")
        directory = destination / session.target_id / session.session_id
        if directory.exists() and directory.is_symlink():
            raise ValueError("trace session artifact directory must not be a symlink")
        directory.mkdir(parents=True, exist_ok=True)
        session.artifact_index_ref = f"artifact://{(directory / 'artifact-index.json').as_posix()}"
        session_path = directory / "trace-session.json"
        evidence_path = directory / "trace-evidence-bundle.json"
        index_path = directory / "artifact-index.json"
        event_path = directory / "trace-events.jsonl"
        for artifact_path in (session_path, evidence_path, event_path, index_path):
            if artifact_path.is_symlink():
                raise ValueError(f"trace artifact must not be a symlink: {artifact_path}")
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
        # ``_event`` streams to the service's configured root.  Callers may
        # persist a session into an explicit alternate root, so materialize a
        # complete deterministic JSONL copy there before indexing it.
        event_path.write_text(
            "".join(
                json.dumps(item.model_dump(mode="json"), ensure_ascii=False, separators=(",", ":")) + "\n"
                for item in session.events
            ),
            encoding="utf-8",
        )
        files = [session_path, evidence_path]
        files.append(event_path)
        index = build_artifact_index(
            run_id=session.session_id,
            target_id=session.target_id,
            files=files,
            root=directory,
            secret=signing_secret,
            previous_index=previous_index,
        )
        write_artifact_index(index_path, index)
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
        try:
            # Canonical ordering makes the idempotency digest represent the
            # argument object rather than the caller's dictionary insertion
            # order.  A retry that serializes the same parameters in another
            # order must still reuse the original result.
            encoded_arguments = json.dumps(
                call.arguments,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            )
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
        arguments_digest = hashlib.sha256(encoded_arguments.encode("utf-8")).hexdigest()
        # Explicit keys can be retried after a session has reached its call
        # budget (or after an UNKNOWN result).  Resolve the cache before
        # applying the budget so a replay never consumes another call slot.
        # Auto-generated keys are unique by construction and therefore follow
        # the normal budget path below.
        if call.idempotency_key is not None:
            cache_key = (session.session_id, call.idempotency_key)
            cached = self._idempotent_results.get(cache_key)
            if cached is not None:
                previous_tool, previous_arguments_digest, result, evidence_id = cached
                if previous_tool != call.tool_id or previous_arguments_digest != arguments_digest:
                    session.state = SessionState.BLOCKED
                    self._event(
                        session,
                        SessionState.BLOCKED,
                        "IDEMPOTENCY_CONFLICT",
                        tool_id=call.tool_id,
                        error_code="IDEMPOTENCY_CONFLICT",
                        operation_id=call.idempotency_key,
                        idempotency_key=call.idempotency_key,
                    )
                    raise ValueError("TRACE_BLOCKED: idempotency key was reused with different tool or arguments")
                evidence = [evidence_id]
                self._event(
                    session,
                    SessionState.OBSERVED,
                    "TOOL_RESULT_REUSED",
                    tool_id=call.tool_id,
                    result=result,
                    evidence_ids=evidence,
                    operation_id=call.idempotency_key,
                    idempotency_key=call.idempotency_key,
                    release_digest=session.release_digest,
                    compile_context_digest=session.compile_context_digest,
                    target_fingerprint=session.target_fingerprint,
                )
                return result

        if session.calls >= session.max_calls:
            session.state = SessionState.BLOCKED
            self._event(session, SessionState.BLOCKED, "TRACE_BUDGET_EXHAUSTED", error_code="TRACE_BUDGET_EXHAUSTED")
            raise ValueError("TRACE_BUDGET_EXHAUSTED: call budget reached")

        sequence = self._next_call_sequence.get(session.session_id, session.calls)
        sequence += 1
        self._next_call_sequence[session.session_id] = sequence
        idempotency_key = call.idempotency_key or f"{session.session_id}:call:{sequence}"
        cache_key = (session.session_id, idempotency_key)
        operation_id = idempotency_key
        session.state = SessionState.CALLING
        self._event(
            session,
            SessionState.CALLING,
            "TOOL_CALL",
            tool_id=call.tool_id,
            arguments=dict(call.arguments),
            operation_id=operation_id,
            idempotency_key=idempotency_key,
            release_digest=session.release_digest,
            compile_context_digest=session.compile_context_digest,
            target_fingerprint=session.target_fingerprint,
        )
        session.calls += 1
        try:
            result = self._call_invoker(call.tool_id, call.arguments, session.session_id, idempotency_key)
        except PermissionError as exc:
            result = {"status": "BLOCKED", "error": str(exc) or "AUTHORIZATION"}
        except TimeoutError as exc:
            result = {"status": "UNKNOWN", "error": str(exc) or "TIMEOUT"}
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
        session.operation_ids.append(operation_id)
        self._idempotent_results[cache_key] = (call.tool_id, arguments_digest, result, evidence[0])
        self._event(
            session,
            SessionState.OBSERVED,
            "TOOL_RESULT",
            tool_id=call.tool_id,
            result=result,
            evidence_ids=evidence,
            operation_id=operation_id,
            idempotency_key=idempotency_key,
            release_digest=session.release_digest,
            compile_context_digest=session.compile_context_digest,
            target_fingerprint=session.target_fingerprint,
        )
        return result

    def _call_invoker(
        self,
        tool_id: str,
        arguments: Mapping[str, Any],
        session_id: str,
        idempotency_key: str,
    ) -> Any:
        """Call legacy providers and both v2 key calling conventions.

        Generated providers in the wild use either a fourth positional
        argument or a keyword-only ``idempotency_key``.  Inspecting the
        signature before calling avoids the tempting (and unsafe) retry-on-
        ``TypeError`` pattern, which could execute a physical operation twice.
        """

        try:
            signature = inspect.signature(self.invoker)
        except (TypeError, ValueError):
            # Some extension callables do not expose a signature.  Prefer the
            # new form; a TypeError from the callable is converted to a failed
            # operation by the caller.
            return self.invoker(tool_id, arguments, session_id, idempotency_key)
        parameters = tuple(signature.parameters.values())
        positional = [
            parameter
            for parameter in parameters
            if parameter.kind in (parameter.POSITIONAL_ONLY, parameter.POSITIONAL_OR_KEYWORD)
        ]
        accepts_varargs = any(parameter.kind == parameter.VAR_POSITIONAL for parameter in parameters)
        if accepts_varargs or len(positional) >= 4:
            return self.invoker(tool_id, arguments, session_id, idempotency_key)
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
            return self.invoker(tool_id, arguments, session_id, **{keyword_key: idempotency_key})
        if any(parameter.kind == parameter.VAR_KEYWORD for parameter in parameters):
            return self.invoker(tool_id, arguments, session_id, idempotency_key=idempotency_key)
        return self.invoker(tool_id, arguments, session_id)

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
        if session.state not in {SessionState.COMPLETED, SessionState.CANCELLED, SessionState.STOPPED}:
            # UNKNOWN is intentionally included: the provider may have
            # accepted a physical command before the transport went away, so a
            # later cancel/stop must still issue the provider's hard-stop hook.
            # A BLOCKED session that already issued a call is also potentially
            # live.  A pre-call capability/parameter block (``calls == 0``)
            # has nothing to stop and should not invoke a provider hook.
            should_stop = session.state != SessionState.BLOCKED or session.calls > 0
            if self.stopper is not None and should_stop:
                try:
                    signature = inspect.signature(self.stopper)
                    positional = [
                        parameter
                        for parameter in signature.parameters.values()
                        if parameter.kind in (parameter.POSITIONAL_ONLY, parameter.POSITIONAL_OR_KEYWORD)
                    ]
                    accepts_varargs = any(parameter.kind == parameter.VAR_POSITIONAL for parameter in signature.parameters.values())
                    if accepts_varargs or len(positional) >= 2:
                        self.stopper(session.session_id, event)
                    elif len(positional) == 1:
                        self.stopper(session.session_id)
                    else:
                        self.stopper()
                    self._event(session, SessionState.RECOVERING, "STOP_SIGNAL_SENT")
                except Exception as exc:
                    # A failed stop signal must remain visible.  The state is
                    # still terminal so callers cannot accidentally continue.
                    session.limitations.append(f"stop signal failed: {type(exc).__name__}")
                    self._event(session, SessionState.RECOVERING, "STOP_SIGNAL_FAILED", error_code="STOP_SIGNAL_FAILED", error=type(exc).__name__)
            session.state = state
            self._event(session, state, event)
        return session

    def _transition(self, session: TraceSession, state: SessionState, event: str, **kwargs: Any) -> None:
        session.state = state
        self._event(session, state, event, **kwargs)

    def _event(self, session: TraceSession, state: SessionState, event: str, **kwargs: Any) -> None:
        safe_kwargs = {key: self._safe_value(value, key=key) for key, value in kwargs.items()}
        item = TraceEvent(
            sequence=len(session.events) + 1,
            run_id=session.session_id,
            session_id=session.session_id,
            target_id=session.target_id,
            state=state,
            event=event,
            created_at=self.clock(),
            release_digest=safe_kwargs.pop("release_digest", session.release_digest),
            compile_context_digest=safe_kwargs.pop("compile_context_digest", session.compile_context_digest),
            target_fingerprint=safe_kwargs.pop("target_fingerprint", session.target_fingerprint),
            **safe_kwargs,
        )
        session.events.append(item)
        if self.artifact_root is not None:
            if self.artifact_root.exists() and self.artifact_root.is_symlink():
                raise ValueError("trace artifact root must not be a symlink")
            path = self.artifact_root / session.target_id / session.session_id / "trace-events.jsonl"
            if path.is_symlink():
                # Keep the in-memory event available for callers, but fail
                # closed before following an attacker-controlled artifact link.
                raise ValueError("trace event artifact must not be a symlink")
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
