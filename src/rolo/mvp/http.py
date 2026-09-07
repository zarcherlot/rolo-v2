from __future__ import annotations

import json
import os
import re
import secrets
from collections.abc import Mapping
from pathlib import Path
from typing import Annotated, Any

from fastapi import APIRouter, Body, HTTPException

from .artifacts import build_artifact_index, write_artifact_index
from .certify import CertificationRunner, load_suite, write_report
from .contracts import CertifyRequest, TargetCatalog, ToolState, TraceCall, TraceSessionRequest, TraceStartRequest
from .trace import TraceService

router = APIRouter(prefix="/v1/mvp", tags=["mvp"])
_catalogs: dict[str, TargetCatalog] = {}
_services: dict[str, TraceService] = {}
_rkb: dict[str, dict[str, Any]] = {}
_publishers: dict[str, Any] = {}
_certify_runners: dict[str, CertificationRunner] = {}
_certify_runs: dict[str, dict[str, Any]] = {}
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")


def _is_digest(value: str, *, allow_unknown: bool = True) -> bool:
    return (allow_unknown and value == "UNKNOWN") or bool(_DIGEST_RE.fullmatch(value))


def _artifact_root() -> Path:
    return Path(os.getenv("ROLO_ARTIFACT_ROOT", os.getenv("ROLO_ARTIFACT_DIR", ".rolo/artifacts"))).expanduser()


def register_catalog(
    catalog: TargetCatalog,
    *,
    invoker=None,
    certify_invoker=None,
    certify_runner: CertificationRunner | None = None,
    artifact_root: Path | None = None,
    stopper=None,
    release_digest: str | None = None,
    compile_context_digest: str | None = None,
    target_fingerprint: str | None = None,
    rkb: Mapping[str, Any] | None = None,
) -> None:
    if not catalog.digest or catalog.digest != catalog.computed_digest():
        raise ValueError("catalog digest is missing or does not match content")
    if target_fingerprint is not None and target_fingerprint != "UNKNOWN" and not _DIGEST_RE.fullmatch(target_fingerprint):
        raise ValueError("target fingerprint must be a 64-hex digest or UNKNOWN")
    if (
        target_fingerprint is not None
        and catalog.target_fingerprint != "UNKNOWN"
        and target_fingerprint != catalog.target_fingerprint
    ):
        raise ValueError("target fingerprint does not match catalog")
    if target_fingerprint == "UNKNOWN" and catalog.target_fingerprint != "UNKNOWN":
        raise ValueError("target fingerprint cannot downgrade a known catalog")
    if target_fingerprint not in (None, "UNKNOWN") and catalog.target_fingerprint == "UNKNOWN":
        raise ValueError("target fingerprint cannot be verified against an unknown catalog")
    default_invoker = invoker or (lambda tool_id, arguments, session_id: {"status": "SUCCEEDED", "tool_id": tool_id})
    service = TraceService(
        catalog,
        default_invoker,
        artifact_root=artifact_root or _artifact_root(),
        stopper=stopper,
        release_digest=release_digest,
        compile_context_digest=compile_context_digest,
        target_fingerprint=target_fingerprint,
    )
    _catalogs[catalog.target_id] = catalog
    _services[catalog.target_id] = service
    _rkb[catalog.target_id] = dict(rkb or {})
    _certify_runners[catalog.target_id] = certify_runner or CertificationRunner(
        certify_invoker or default_invoker,
        target_id=catalog.target_id,
    )


def register_release_bound_catalog(
    catalog: TargetCatalog,
    *,
    publisher: Any,
    release_digests: Mapping[str, str],
    target_fingerprint: str,
    evidence_digest: str,
    invoker,
    compile_context_digest: str | None = None,
    route_digest: str | None = None,
    mhs_manifest_digests: tuple[str, ...] = (),
    rkb: Mapping[str, Any] | None = None,
) -> None:
    """Register an HTTP catalog whose calls are pinned to current releases."""

    from rolo.releases.journey import PublishedReleaseInvoker

    bound = {
        tool_id: PublishedReleaseInvoker(
            publisher,
            digest,
            target_fingerprint=target_fingerprint,
            evidence_digest=evidence_digest,
            invoker=invoker,
            compile_context_digest=compile_context_digest,
            route_digest=route_digest,
            mhs_manifest_digests=mhs_manifest_digests,
        )
        for tool_id, digest in release_digests.items()
    }

    def release_invoker(
        tool_id: str,
        arguments: Mapping[str, Any],
        session_id: str,
        idempotency_key: str | None = None,
    ) -> Any:
        callback = bound.get(tool_id)
        if callback is None:
            raise ValueError("RELEASE_NOT_CURRENT")
        return callback(tool_id, arguments, session_id, idempotency_key)

    def certify_invoker(tool_id: str, arguments: Mapping[str, Any], session_id: str, idempotency_key: str | None = None) -> Any:
        callback = bound.get(tool_id)
        if callback is None:
            raise ValueError("RELEASE_NOT_CURRENT")
        return callback(tool_id, arguments, session_id, idempotency_key)

    register_catalog(
        catalog,
        invoker=release_invoker,
        certify_invoker=certify_invoker,
        compile_context_digest=compile_context_digest,
        target_fingerprint=target_fingerprint,
        rkb=rkb,
    )
    _publishers[catalog.target_id] = publisher


@router.get("/targets/{target_id}/catalog", response_model=TargetCatalog)
def discover_target(target_id: str) -> TargetCatalog:
    try:
        catalog = _catalogs[target_id]
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="target catalog not found") from exc
    if not catalog.digest or catalog.digest != catalog.computed_digest():
        raise HTTPException(status_code=503, detail="target catalog digest is invalid")
    return catalog


@router.get("/targets/{target_id}/releases/{tool_id}")
def current_release(target_id: str, tool_id: str) -> dict[str, Any]:
    """Expose the immutable current release read model to rolo-vis."""

    publisher = _publishers.get(target_id)
    if publisher is None:
        raise HTTPException(status_code=404, detail="release publisher not registered")
    try:
        current = publisher.current(tool_id)
    except (FileNotFoundError, ValueError) as exc:
        raise HTTPException(status_code=503, detail="release catalog is unavailable") from exc
    if current is None:
        raise HTTPException(status_code=404, detail="current release not found")
    digest, release = current
    return {
        "schema_version": "rolo-release-read-model/v1",
        "target_id": target_id,
        "tool_id": tool_id,
        "release_digest": digest,
        "status": release.status,
        "agent_callable": release.agent_callable,
        "release": release.model_dump(mode="json"),
    }


@router.get("/rkb")
def read_rkb(query: str, target_id: str | None = None) -> dict[str, Any]:
    if target_id is None and len(_rkb) == 1:
        target_id = next(iter(_rkb))
    if target_id and target_id in _rkb and query in _rkb[target_id]:
        return {"status": "KNOWN", "value": _rkb[target_id][query], "evidence_ids": [], "limitations": []}
    return {"status": "UNKNOWN", "value": None, "evidence_ids": [], "limitations": ["query not present in verified snapshot"]}


@router.post("/trace/sessions")
def create_trace_session(request: TraceSessionRequest) -> dict[str, Any]:
    service = _services.get(request.target_id)
    if service is None:
        raise HTTPException(status_code=404, detail="target catalog not found")
    try:
        return service.create_session(request).model_dump(mode="json")
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/trace/sessions/{session_id}/execute")
def execute_trace(session_id: str, target_id: str, calls: list[TraceCall]) -> dict[str, Any]:
    service = _services.get(target_id)
    if service is None:
        raise HTTPException(status_code=404, detail="target catalog not found")
    try:
        return service.execute(session_id, calls).model_dump(mode="json")
    except (KeyError, ValueError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get("/trace/sessions/{session_id}")
def get_trace_session(session_id: str, target_id: str) -> dict[str, Any]:
    service = _services.get(target_id)
    if service is None:
        raise HTTPException(status_code=404, detail="target catalog not found")
    try:
        return service.get(session_id).model_dump(mode="json")
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="trace session not found") from exc


@router.get("/trace/sessions/{session_id}/events")
def get_trace_events(session_id: str, target_id: str) -> dict[str, Any]:
    service = _services.get(target_id)
    if service is None:
        raise HTTPException(status_code=404, detail="target catalog not found")
    try:
        session = service.get(session_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="trace session not found") from exc
    return {"session_id": session_id, "target_id": target_id, "items": [item.model_dump(mode="json") for item in session.events]}


@router.post("/trace/sessions/{session_id}/cancel")
def cancel_trace(session_id: str, target_id: str) -> dict[str, Any]:
    service = _services.get(target_id)
    if service is None:
        raise HTTPException(status_code=404, detail="target catalog not found")
    try:
        return service.cancel(session_id).model_dump(mode="json")
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="trace session not found") from exc


@router.post("/trace/sessions/{session_id}/stop")
def stop_trace(session_id: str, target_id: str) -> dict[str, Any]:
    service = _services.get(target_id)
    if service is None:
        raise HTTPException(status_code=404, detail="target catalog not found")
    try:
        return service.stop(session_id).model_dump(mode="json")
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="trace session not found") from exc


@router.post("/invoke")
def invoke_tool(payload: dict[str, Any]) -> dict[str, Any]:
    session_id = payload.get("session_id")
    tool_id = payload.get("tool_id")
    arguments = payload.get("arguments", {})
    target_id = payload.get("target_id")
    if not isinstance(session_id, str) or not isinstance(tool_id, str) or not isinstance(arguments, dict):
        raise HTTPException(status_code=422, detail="session_id, tool_id, and object arguments are required")
    supplied_catalog = payload.get("catalog_digest")
    supplied_fingerprint = payload.get("target_fingerprint")
    if supplied_catalog is not None and (not isinstance(supplied_catalog, str) or not _DIGEST_RE.fullmatch(supplied_catalog)):
        raise HTTPException(status_code=422, detail="catalog_digest must be a 64-hex digest")
    if supplied_fingerprint is not None and (
        not isinstance(supplied_fingerprint, str)
        or (supplied_fingerprint != "UNKNOWN" and not _DIGEST_RE.fullmatch(supplied_fingerprint))
    ):
        raise HTTPException(status_code=422, detail="target_fingerprint must be a 64-hex digest or UNKNOWN")
    services = [_services[target_id]] if isinstance(target_id, str) and target_id in _services else list(_services.values()) if target_id is None else []
    if target_id is None and len(services) > 1:
        raise HTTPException(status_code=400, detail="target_id is required when multiple targets are registered")
    for service in services:
        if session_id in service.sessions:
            session_record = service.sessions[session_id]
            if supplied_catalog is not None and supplied_catalog != session_record.catalog_digest:
                raise HTTPException(status_code=409, detail="TRACE_BLOCKED: catalog digest does not match session")
            if supplied_fingerprint is not None and supplied_fingerprint != session_record.target_fingerprint:
                raise HTTPException(status_code=409, detail="TRACE_BLOCKED: target fingerprint does not match session")
            try:
                calls = _coerce_calls(
                    payload,
                    run_id=session_id,
                    target_id=session_record.target_id,
                    catalog_digest=session_record.catalog_digest,
                    target_fingerprint=session_record.target_fingerprint,
                )
                if len(calls) != 1:
                    raise ValueError("one tool invocation is required")
                session = service.execute(session_id, calls)
            except (KeyError, ValueError, HTTPException) as exc:
                if isinstance(exc, HTTPException):
                    raise
                raise HTTPException(status_code=409, detail=str(exc)) from exc
            event = next(
                (
                    item
                    for item in reversed(session.events)
                    if item.event in {"TOOL_RESULT", "TOOL_RESULT_REUSED"}
                ),
                None,
            )
            return event.result if event and isinstance(event.result, dict) else {"status": session.state.value}
    raise HTTPException(status_code=404, detail="session not found")


@router.get("/runs/{run_id}")
def get_run(run_id: str, target_id: str | None = None) -> dict[str, Any]:
    if run_id in _certify_runs:
        record = _certify_runs[run_id]
        report = record["report"]
        if target_id is not None and report.target_id != target_id:
            raise HTTPException(status_code=404, detail="run not found")
        return {
            "schema_version": "rolo-certify-run/v1",
            "status": report.conclusion,
            "run_id": report.run_id,
            "target_id": report.target_id,
            "report": report.model_dump(mode="json"),
            "artifact_paths": record.get("artifact_paths", {}),
            "events": record.get("events", []),
        }
    services = [_services[target_id]] if target_id in _services else list(_services.values()) if target_id is None else []
    if target_id is None and len(services) > 1:
        raise HTTPException(status_code=400, detail="target_id is required when multiple targets are registered")
    for service in services:
        if run_id in service.sessions:
            return service.sessions[run_id].model_dump(mode="json")
    raise HTTPException(status_code=404, detail="run not found")


# Public Agent connector aliases.  The original MVP routes under
# ``/v1/mvp`` remain supported; these paths match the normative connector
# contract used by Codex/other harnesses.


def _service_for_session(run_id: str, target_id: str | None = None) -> TraceService:
    if target_id is not None:
        service = _services.get(target_id)
        if service is None or run_id not in service.sessions:
            raise HTTPException(status_code=404, detail="run not found")
        return service
    matches = [service for service in _services.values() if run_id in service.sessions]
    if len(matches) != 1:
        raise HTTPException(status_code=404, detail="run not found")
    return matches[0]


def _coerce_calls(
    payload: Any,
    *,
    run_id: str | None = None,
    target_id: str | None = None,
    catalog_digest: str | None = None,
    target_fingerprint: str | None = None,
) -> list[TraceCall]:
    if isinstance(payload, Mapping):
        if "calls" in payload:
            envelope = dict(payload)
            schema_version = envelope.pop("schema_version", None)
            if schema_version is not None and schema_version != "rolo-agent-tool-call-batch/v1":
                # The single-call AgentToolInvocation schema is also accepted
                # for convenience; a batch envelope may omit its version.
                if schema_version != "rolo-agent-tool-invocation/v1":
                    raise HTTPException(status_code=422, detail="unsupported tool call batch schema")
            supplied_run = envelope.pop("session_id", None)
            if supplied_run is not None and run_id is not None and supplied_run != run_id:
                raise HTTPException(status_code=422, detail="tool call batch session_id does not match run_id")
            supplied_target = envelope.pop("target_id", None)
            if supplied_target is not None and target_id is not None and supplied_target != target_id:
                raise HTTPException(status_code=422, detail="tool call batch target_id does not match run target")
            supplied_catalog = envelope.pop("catalog_digest", None)
            if supplied_catalog is not None and catalog_digest is not None and supplied_catalog != catalog_digest:
                raise HTTPException(status_code=422, detail="tool call batch catalog_digest does not match run catalog")
            supplied_fingerprint = envelope.pop("target_fingerprint", None)
            if (
                supplied_fingerprint is not None
                and target_fingerprint is not None
                and supplied_fingerprint != target_fingerprint
            ):
                raise HTTPException(status_code=422, detail="tool call batch target_fingerprint does not match run target")
            if set(envelope) != {"calls"}:
                raise HTTPException(status_code=422, detail="unknown tool call batch fields")
            raw = payload.get("calls")
        elif "tool_id" in payload:
            # Accept a single canonical call as a convenience form while
            # retaining the batch ``{"calls": [...]}`` contract.
            raw = [payload]
        else:
            raw = None
    else:
        raw = payload
    if not isinstance(raw, list):
        raise HTTPException(status_code=422, detail="request must contain a calls array")
    normalised: list[TraceCall] = []
    try:
        for item in raw:
            if isinstance(item, TraceCall):
                normalised.append(item)
                continue
            if not isinstance(item, Mapping):
                raise ValueError("each call must be an object")
            data = dict(item)
            schema_version = data.pop("schema_version", None)
            if schema_version is not None and schema_version != "rolo-agent-tool-invocation/v1":
                raise ValueError("unsupported tool invocation schema")
            supplied_run = data.pop("session_id", None)
            if supplied_run is not None and run_id is not None and supplied_run != run_id:
                raise ValueError("tool invocation session_id does not match run_id")
            supplied_target = data.pop("target_id", None)
            if supplied_target is not None and target_id is not None and supplied_target != target_id:
                raise ValueError("tool invocation target_id does not match run target")
            supplied_catalog = data.pop("catalog_digest", None)
            if supplied_catalog is not None and catalog_digest is not None and supplied_catalog != catalog_digest:
                raise ValueError("tool invocation catalog_digest does not match run catalog")
            supplied_fingerprint = data.pop("target_fingerprint", None)
            if (
                supplied_fingerprint is not None
                and target_fingerprint is not None
                and supplied_fingerprint != target_fingerprint
            ):
                raise ValueError("tool invocation target_fingerprint does not match run target")
            normalised.append(TraceCall.model_validate(data))
        return normalised
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


def _public_event(event: Any, target_id: str) -> dict[str, Any]:
    """Project an internal Trace event onto the generic Agent event schema.

    Trace keeps its historical ``rolo-mvp-trace-event/v1`` envelope in
    replay artifacts.  The public connector uses the normative
    ``rolo-agent-run-event/v1`` schema, which additionally requires the target
    identity.  Returning a projection here keeps both consumers versioned and
    avoids asking external Agents to understand an internal event name.
    """

    if hasattr(event, "model_dump"):
        payload = event.model_dump(mode="json")
    elif isinstance(event, Mapping):
        payload = dict(event)
    else:
        payload = {}
    payload["schema_version"] = "rolo-agent-run-event/v1"
    payload["run_id"] = str(payload.get("run_id") or payload.get("session_id") or "")
    payload["target_id"] = target_id
    return payload


def _persist_trace(service: TraceService, run_id: str) -> dict[str, str]:
    try:
        paths = service.persist_session(run_id)
    except (OSError, ValueError, KeyError) as exc:
        # A run without its evidence/index cannot be replayed safely.  Surface
        # persistence failure instead of returning a partial success payload.
        raise HTTPException(status_code=500, detail=f"TRACE_ARTIFACT_PERSIST_FAILED: {exc}") from exc
    return {str(key): str(value) for key, value in paths.items()}


def _coerce_start_trace(payload: Any) -> tuple[TraceSessionRequest, list[TraceCall]]:
    """Accept the direct request and the optional ``TraceStartRequest`` envelope."""

    if isinstance(payload, TraceSessionRequest):
        return payload, []
    if isinstance(payload, TraceStartRequest):
        return payload.request, list(payload.calls)
    if not isinstance(payload, Mapping):
        raise ValueError("Trace start request must be an object")
    if "request" in payload:
        envelope = TraceStartRequest.model_validate(payload)
        calls = _coerce_calls(
            {"calls": [item.model_dump(mode="json") for item in envelope.calls]},
            target_id=envelope.request.target_id,
            catalog_digest=envelope.request.catalog_digest,
            target_fingerprint=envelope.request.target_fingerprint,
        )
        return envelope.request, calls
    # A few callers send the calls alongside the request fields.  Validate the
    # request fields with the strict model after removing that one envelope
    # member; unknown fields remain rejected by ``extra=forbid``.
    if "calls" in payload:
        request_payload = {key: value for key, value in payload.items() if key != "calls"}
        request = TraceSessionRequest.model_validate(request_payload)
        calls = _coerce_calls(
            {"calls": payload.get("calls")},
            target_id=request.target_id,
            catalog_digest=request.catalog_digest,
            target_fingerprint=request.target_fingerprint,
        )
        return request, calls
    return TraceSessionRequest.model_validate(payload), []


@router.post("/runs")
def start_trace(request: Annotated[TraceSessionRequest | TraceStartRequest, Body(...)]) -> dict[str, Any]:
    try:
        request_model, initial_calls = _coerce_start_trace(request)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    service = _services.get(request_model.target_id)
    if service is None:
        raise HTTPException(status_code=404, detail="target catalog not found")
    try:
        session = service.create_session(request_model)
        if initial_calls:
            session = service.execute(session.session_id, initial_calls)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    paths = _persist_trace(service, session.session_id)
    payload = session.model_dump(mode="json")
    # The public connector names the session identifier ``run_id``.  Retain
    # ``session_id`` in the payload for compatibility with the historical MVP
    # routes and expose both aliases so callers do not need endpoint-specific
    # parsing.
    payload["run_id"] = session.session_id
    if paths:
        payload["artifact_paths"] = paths
    return payload


@router.post("/runs/{run_id}/tool-calls")
def add_trace_calls(run_id: str, payload: Annotated[Any, Body(...)], target_id: str | None = None) -> dict[str, Any]:
    service = _service_for_session(run_id, target_id)
    session_record = service.get(run_id)
    calls = _coerce_calls(
        payload,
        run_id=run_id,
        target_id=session_record.target_id,
        catalog_digest=session_record.catalog_digest,
        target_fingerprint=session_record.target_fingerprint,
    )
    try:
        session = service.execute(run_id, calls)
    except (KeyError, ValueError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    paths = _persist_trace(service, run_id)
    result = session.model_dump(mode="json")
    result["run_id"] = run_id
    if paths:
        result["artifact_paths"] = paths
    return result


@router.get("/runs/{run_id}")
def read_trace_run(run_id: str, target_id: str | None = None) -> dict[str, Any]:
    service = _service_for_session(run_id, target_id)
    payload = service.get(run_id).model_dump(mode="json")
    payload["run_id"] = run_id
    return payload


@router.get("/runs/{run_id}/events")
def read_trace_run_events(run_id: str, target_id: str | None = None) -> dict[str, Any]:
    service = _service_for_session(run_id, target_id)
    session = service.get(run_id)
    return {
        "schema_version": "rolo-agent-run-event-collection/v1",
        "run_id": run_id,
        "target_id": session.target_id,
        "items": [_public_event(item, session.target_id) for item in session.events],
        "count": len(session.events),
    }


@router.post("/runs/{run_id}/cancel")
def cancel_trace_run(run_id: str, target_id: str | None = None) -> dict[str, Any]:
    service = _service_for_session(run_id, target_id)
    try:
        session = service.cancel(run_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="run not found") from exc
    _persist_trace(service, run_id)
    payload = session.model_dump(mode="json")
    payload["run_id"] = run_id
    return payload


@router.post("/runs/{run_id}/stop")
def stop_trace_run(run_id: str, target_id: str | None = None) -> dict[str, Any]:
    service = _service_for_session(run_id, target_id)
    try:
        session = service.stop(run_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="run not found") from exc
    _persist_trace(service, run_id)
    payload = session.model_dump(mode="json")
    payload["run_id"] = run_id
    return payload


@router.post("/runs/{run_id}/resume")
def resume_trace_run(run_id: str, target_id: str | None = None) -> dict[str, Any]:
    service = _service_for_session(run_id, target_id)
    try:
        session = service.resume(run_id)
    except (KeyError, ValueError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    _persist_trace(service, run_id)
    payload = session.model_dump(mode="json")
    payload["run_id"] = run_id
    return payload


def _suite_path(value: str) -> Path:
    path = Path(value).expanduser()
    if path.is_symlink() or not path.is_file():
        raise ValueError("suite_ref must name a regular file")
    if path.stat().st_size > 1024 * 1024:
        raise ValueError("suite exceeds 1 MiB")
    return path.resolve()


def _validate_certify_binding(
    catalog: TargetCatalog,
    request: CertifyRequest,
    suite: Any,
) -> tuple[str, str | None]:
    """Validate the immutable catalog identity before running any case."""

    if catalog.freshness != "fresh":
        raise ValueError("catalog is stale or unknown")
    if not catalog.digest or catalog.digest != catalog.computed_digest():
        raise ValueError("catalog digest is missing or does not match content")
    if catalog.target_id != request.target_id or suite.target_id != catalog.target_id:
        raise ValueError("target identity does not match catalog and suite")
    if not _is_digest(catalog.snapshot_digest) or not _is_digest(request.snapshot_digest):
        raise ValueError("snapshot digest is invalid")
    if request.target_fingerprint not in (None, "UNKNOWN") and not _is_digest(request.target_fingerprint):
        raise ValueError("target fingerprint is invalid")
    missing = sorted(
        {
            case.tool_id
            for case in suite.cases
            if not any(
                item.tool_id == case.tool_id
                and item.target_id == catalog.target_id
                and item.agent_callable
                and item.state == ToolState.CALLABLE
                for item in catalog.tools
            )
        }
    )
    if missing:
        raise ValueError("catalog tools are not callable: " + ", ".join(missing))
    if (
        request.snapshot_digest != "UNKNOWN"
        and catalog.snapshot_digest != "UNKNOWN"
        and request.snapshot_digest != catalog.snapshot_digest
    ):
        raise ValueError("snapshot digest does not match catalog")
    if catalog.snapshot_digest == "UNKNOWN" and request.snapshot_digest != "UNKNOWN":
        raise ValueError("catalog snapshot digest is unknown; supplied snapshot cannot be verified")
    effective_snapshot = catalog.snapshot_digest if request.snapshot_digest == "UNKNOWN" else request.snapshot_digest
    if (
        request.target_fingerprint not in (None, "UNKNOWN")
        and catalog.target_fingerprint != "UNKNOWN"
        and request.target_fingerprint != catalog.target_fingerprint
    ):
        raise ValueError("target fingerprint does not match catalog")
    if catalog.target_fingerprint == "UNKNOWN" and request.target_fingerprint not in (None, "UNKNOWN"):
        raise ValueError("catalog target fingerprint is unknown; supplied fingerprint cannot be verified")
    effective_fingerprint = request.target_fingerprint
    if effective_fingerprint in (None, "UNKNOWN") and catalog.target_fingerprint != "UNKNOWN":
        effective_fingerprint = catalog.target_fingerprint
    return effective_snapshot, effective_fingerprint


@router.post("/certify/runs")
def start_certify(request: CertifyRequest) -> dict[str, Any]:
    service = _services.get(request.target_id)
    runner = _certify_runners.get(request.target_id)
    if service is None or runner is None:
        raise HTTPException(status_code=404, detail="target catalog not found")
    try:
        suite = load_suite(_suite_path(request.suite_ref), target_id=request.target_id, require_ten_cases=True)
    except (FileNotFoundError, OSError, ValueError) as exc:
        raise HTTPException(status_code=409, detail=f"CERTIFY_BLOCKED: {exc}") from exc
    run_id = request.session_id or f"certify-{secrets.token_urlsafe(10)}"
    if run_id in _certify_runs:
        raise HTTPException(status_code=409, detail="CERTIFY_RUN_ID_REUSED: run_id already exists")
    catalog = _catalogs[request.target_id]
    try:
        effective_snapshot, effective_fingerprint = _validate_certify_binding(catalog, request, suite)
        if (
            service.compile_context_digest is not None
            and request.compile_context_digest not in (None, service.compile_context_digest)
        ):
            raise ValueError("compile context digest does not match bound service")
        if (
            service.target_fingerprint not in (None, "UNKNOWN")
            and effective_fingerprint not in (None, service.target_fingerprint)
        ):
            raise ValueError("target fingerprint does not match bound service")
        if service.target_fingerprint == "UNKNOWN" and effective_fingerprint not in (None, "UNKNOWN"):
            raise ValueError("bound service target fingerprint is unknown")
        effective_context = request.compile_context_digest or service.compile_context_digest
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=f"CERTIFY_BLOCKED: {exc}") from exc
    # Keep certification evidence beside the Trace evidence for this
    # registered target.  Using the process-wide default here would silently
    # mix runs from isolated adapters/tests (and can select a stale report
    # when the requested filename already exists).  ``register_catalog``
    # deliberately binds an artifact root to the service, so use that root
    # whenever it is available.
    artifact_root = service.artifact_root or _artifact_root()
    if artifact_root.exists() and artifact_root.is_symlink():
        raise HTTPException(status_code=500, detail="CERTIFY_FAILED: artifact root must not be a symlink")
    output_root = artifact_root / request.target_id / "certify" / run_id
    try:
        report = runner.run(
            suite,
            snapshot_digest=effective_snapshot,
            run_id=run_id,
            session_id=run_id,
            compile_context_digest=effective_context,
            target_fingerprint=effective_fingerprint,
            fail_fast=request.failure_policy == "fail_fast",
        )
        json_path, md_path = write_report(report, output_root / "certify-test-report.json")
        requested_report = output_root / "certify-test-report.json"
        suffix_name = json_path.name != requested_report.name
        stem_prefix = json_path.stem if suffix_name else "certify"
        suite_name = "certify-test-suite.json" if not suffix_name else f"{stem_prefix}.certify-test-suite.json"
        request_name = "certify-request.json" if not suffix_name else f"{stem_prefix}.certify-request.json"
        event_name = "certify-events.jsonl" if not suffix_name else f"{stem_prefix}.certify-events.jsonl"
        suite_artifact = json_path.parent / suite_name
        request_artifact = json_path.parent / request_name
        event_artifact = json_path.parent / event_name
        html_path = json_path.with_suffix(".html")
        index_name = "artifact-index.json" if json_path.name == "certify-test-report.json" else f"{json_path.stem}.artifact-index.json"
        index_path = json_path.with_name(index_name)
        for artifact_path in (suite_artifact, request_artifact, event_artifact, html_path, index_path):
            if artifact_path.is_symlink():
                raise ValueError(f"certification artifact path must not be a symlink: {artifact_path}")
        suite_artifact.write_text(json.dumps(suite.model_dump(mode="json"), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        request_artifact.write_text(json.dumps(request.model_dump(mode="json"), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        event_artifact.write_text("".join(json.dumps(item, ensure_ascii=False, sort_keys=True) + "\n" for item in runner.events), encoding="utf-8")
        if not html_path.is_file() or html_path.is_symlink():
            raise ValueError("derived HTML certification report is missing")
        files = [json_path, md_path, suite_artifact, request_artifact, event_artifact, html_path]
        write_artifact_index(index_path, build_artifact_index(run_id=report.run_id, target_id=report.target_id, files=files, root=json_path.parent))
    except (OSError, ValueError) as exc:
        raise HTTPException(status_code=500, detail=f"CERTIFY_FAILED: {exc}") from exc
    artifact_paths = {
        "report": str(json_path),
        "markdown": str(md_path),
        "html": str(html_path),
        "suite": str(suite_artifact),
        "request": str(request_artifact),
        "events": str(event_artifact),
        "index": str(index_path),
    }
    _certify_runs[report.run_id] = {"report": report, "artifact_paths": artifact_paths, "events": list(runner.events)}
    return {
        "schema_version": "rolo-certify-run/v1",
        "status": report.conclusion,
        "run_id": report.run_id,
        "target_id": report.target_id,
        "suite_digest": report.suite_digest,
        "artifact_paths": artifact_paths,
        "report": report.model_dump(mode="json"),
    }


@router.get("/certify/runs/{run_id}/report")
def read_certify_report(run_id: str, target_id: str | None = None) -> dict[str, Any]:
    record = _certify_runs.get(run_id)
    if record is None:
        raise HTTPException(status_code=404, detail="certification run not found")
    report = record["report"]
    if target_id is not None and report.target_id != target_id:
        raise HTTPException(status_code=404, detail="certification run not found")
    return {
        "schema_version": "rolo-certify-report-read-model/v1",
        "run_id": report.run_id,
        "target_id": report.target_id,
        "status": report.conclusion,
        "report": report.model_dump(mode="json"),
        "artifact_paths": record.get("artifact_paths", {}),
        "events": record.get("events", []),
    }


@router.get("/certify/runs/{run_id}/events")
def read_certify_events(run_id: str, target_id: str | None = None) -> dict[str, Any]:
    """Return the immutable certification event stream for observability clients."""

    record = _certify_runs.get(run_id)
    if record is None:
        raise HTTPException(status_code=404, detail="certification run not found")
    report = record["report"]
    if target_id is not None and report.target_id != target_id:
        raise HTTPException(status_code=404, detail="certification run not found")
    events = list(record.get("events", []))
    return {
        "schema_version": "rolo-certify-event-collection/v1",
        "run_id": run_id,
        "target_id": report.target_id,
        "items": events,
        "count": len(events),
    }


# Register the same handlers on the public /v1 connector prefix.  Keeping a
# separate router avoids changing the historical /v1/mvp paths used by older
# integrations while making the normative Agent contract available directly.
connector_router = APIRouter(prefix="/v1", tags=["agent-connector"])
connector_router.add_api_route("/targets/{target_id}/catalog", discover_target, methods=["GET"])
connector_router.add_api_route("/rkb", read_rkb, methods=["GET"])
connector_router.add_api_route("/targets/{target_id}/releases/{tool_id}", current_release, methods=["GET"])
connector_router.add_api_route("/runs", start_trace, methods=["POST"])
connector_router.add_api_route("/runs/{run_id}/tool-calls", add_trace_calls, methods=["POST"])
connector_router.add_api_route("/runs/{run_id}", read_trace_run, methods=["GET"])
connector_router.add_api_route("/runs/{run_id}/events", read_trace_run_events, methods=["GET"])
connector_router.add_api_route("/runs/{run_id}/cancel", cancel_trace_run, methods=["POST"])
connector_router.add_api_route("/runs/{run_id}/stop", stop_trace_run, methods=["POST"])
connector_router.add_api_route("/runs/{run_id}/resume", resume_trace_run, methods=["POST"])
connector_router.add_api_route("/certify/runs", start_certify, methods=["POST"])
connector_router.add_api_route("/certify/runs/{run_id}/report", read_certify_report, methods=["GET"])
connector_router.add_api_route("/certify/runs/{run_id}/events", read_certify_events, methods=["GET"])


__all__ = [
    "router",
    "connector_router",
    "register_catalog",
    "register_release_bound_catalog",
    "start_trace",
    "add_trace_calls",
    "read_trace_run",
    "read_trace_run_events",
    "cancel_trace_run",
    "stop_trace_run",
    "resume_trace_run",
    "start_certify",
    "read_certify_report",
    "read_certify_events",
]
