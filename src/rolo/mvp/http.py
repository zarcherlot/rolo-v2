from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from fastapi import APIRouter, HTTPException

from .contracts import TargetCatalog, TraceCall, TraceSessionRequest
from .trace import TraceService

router = APIRouter(prefix="/v1/mvp", tags=["mvp"])
_catalogs: dict[str, TargetCatalog] = {}
_services: dict[str, TraceService] = {}
_rkb: dict[str, dict[str, Any]] = {}


def register_catalog(catalog: TargetCatalog, *, invoker=None, rkb: Mapping[str, Any] | None = None) -> None:
    service = TraceService(catalog, invoker or (lambda tool_id, arguments, session_id: {"status": "SUCCEEDED", "tool_id": tool_id}), artifact_root=None)
    _catalogs[catalog.target_id] = catalog
    _services[catalog.target_id] = service
    _rkb[catalog.target_id] = dict(rkb or {})


@router.get("/targets/{target_id}/catalog", response_model=TargetCatalog)
def discover_target(target_id: str) -> TargetCatalog:
    try:
        return _catalogs[target_id]
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="target catalog not found") from exc


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


@router.post("/invoke")
def invoke_tool(payload: dict[str, Any]) -> dict[str, Any]:
    session_id = payload.get("session_id")
    tool_id = payload.get("tool_id")
    arguments = payload.get("arguments", {})
    if not isinstance(session_id, str) or not isinstance(tool_id, str) or not isinstance(arguments, dict):
        raise HTTPException(status_code=422, detail="session_id, tool_id, and object arguments are required")
    for service in _services.values():
        if session_id in service.sessions:
            try:
                session = service.execute(session_id, [TraceCall(tool_id=tool_id, arguments=arguments)])
            except (KeyError, ValueError) as exc:
                raise HTTPException(status_code=409, detail=str(exc)) from exc
            event = session.events[-1] if session.events else None
            return event.result if event and isinstance(event.result, dict) else {"status": session.state.value}
    raise HTTPException(status_code=404, detail="session not found")


@router.get("/runs/{run_id}")
def get_run(run_id: str, target_id: str | None = None) -> dict[str, Any]:
    services = [_services[target_id]] if target_id in _services else list(_services.values()) if target_id is None else []
    for service in services:
        if run_id in service.sessions:
            return service.sessions[run_id].model_dump(mode="json")
    raise HTTPException(status_code=404, detail="run not found")


__all__ = ["router", "register_catalog"]
