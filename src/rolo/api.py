"""Read-only HTTP facade for the rolo v2 Robot Knowledge Base.

The facade consumes only a validated latest snapshot.  It never probes targets,
registers providers, executes tools, or exposes raw bundle payloads.
"""

from __future__ import annotations

import os
import re
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from .agent_tools.conformance import ToolConformanceReport
from .mhs_registry import MhsProviderRegistry, MhsRegistryError
from .rkb import (
    CapabilityState,
    EvidenceValidationError,
    QueryRejectedError,
    ReadOnlyKnowledgeBase,
    RKBStore,
)
from .mvp.http import router as mvp_router

app = FastAPI(title="rolo v2 read-only API", version="0.38.0")
app.include_router(mvp_router)
API_FEATURES = (
    "rkb.read-model/v1",
    "mhs.inventory-read-model/v1",
    "tool.verification-read-model/v1",
    "rkb.episodes-read-model/v1",
)
_SAFE_SEGMENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


def _safe_segment(value: str) -> bool:
    return bool(_SAFE_SEGMENT.fullmatch(value))


@app.middleware("http")
async def same_origin_api_prefix(request, call_next):
    path = request.scope.get("path", "")
    if path == "/rolo-api" or path.startswith("/rolo-api/"):
        request.scope["path"] = path[len("/rolo-api") :] or "/"
    return await call_next(request)


def configure_workbench_mount(workbench_dir: Path | None = None) -> None:
    raw = str(workbench_dir) if workbench_dir is not None else os.getenv("ROLO_WORKBENCH_DIR", "")
    if not raw or any(
        getattr(route, "name", None) == "rolo-workbench-assets" for route in app.routes
    ):
        return
    directory = Path(raw).expanduser().resolve()
    assets = StaticFiles(directory=str(directory / "assets"), check_dir=False)
    app.mount("/workbench/assets", assets, name="rolo-workbench-assets")
    app.mount("/assets", assets, name="rolo-workbench-root-assets")


@app.get("/workbench/", include_in_schema=False, response_model=None)
def workbench() -> Any:
    raw = os.getenv("ROLO_WORKBENCH_DIR", "")
    index = Path(raw).expanduser() / "index.html" if raw else None
    if index is None or not index.is_file() or index.is_symlink():
        return JSONResponse(
            status_code=503,
            content={
                "status": "UNAVAILABLE",
                "reason": "rolo-vis-v2 Workbench package is not mounted",
            },
        )
    return FileResponse(index, media_type="text/html")


def _latest_conformance(robot_id: str, fingerprint: str) -> ToolConformanceReport | None:
    if not _safe_segment(robot_id):
        return None
    root = Path(os.getenv("ROLO_ARTIFACT_ROOT", ".rolo/artifacts")).expanduser()
    if root.is_symlink() or not root.is_dir():
        return None
    for path in sorted(
        root.glob(f"native/{robot_id}/sessions/*/conformance.json"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    ):
        if path.is_symlink() or not path.is_file():
            continue
        try:
            report = ToolConformanceReport.model_validate_json(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if report.target_id == robot_id and report.target_host_fingerprint == fingerprint:
            return report
    return None


def _store() -> RKBStore:
    return RKBStore(Path(os.getenv("ROLO_RKB_ROOT", ".rolo/rkb")))


def _snapshot(robot_id: str):
    store = _store()
    # An uninitialized runtime has no snapshot yet; this is a normal 404, not
    # a corrupt-artifact outage.  Existing but unreadable pointers remain 503.
    if not store.latest_path.exists():
        raise HTTPException(status_code=404, detail="robot snapshot not found")
    try:
        snapshot = store.load_latest()
    except EvidenceValidationError as exc:
        raise HTTPException(status_code=503, detail="RKB snapshot unavailable") from exc
    if snapshot is None or snapshot.identity.robot_id != robot_id:
        raise HTTPException(status_code=404, detail="robot snapshot not found")
    return snapshot


def _query_or_unknown(query: Callable[[], Any]) -> dict[str, Any]:
    try:
        return query().model_dump(mode="json")
    except (QueryRejectedError, ValueError) as exc:
        return {
            "schema_version": "rkb-typed-query-result/v1",
            "status": "UNKNOWN",
            "value": None,
            "evidence_ids": [],
            "limitations": [str(exc)],
            "status_reason": "query rejected; value withheld",
        }


def _base(snapshot: Any) -> dict[str, Any]:
    return {
        "robot_id": snapshot.identity.robot_id,
        "snapshot_digest": snapshot.digest or snapshot.computed_digest(),
        "observed_at": snapshot.identity.observed_at,
        "fresh_until": snapshot.identity.fresh_until,
        "source_kind": "verified_rkb_snapshot",
        "access": "READ_ONLY",
    }


def _mhs_registry() -> MhsProviderRegistry:
    return MhsProviderRegistry(Path(os.getenv("ROLO_MHS_REGISTRY_ROOT", ".rolo/mhs")))


@app.get("/health")
def health() -> dict[str, Any]:
    try:
        snapshot = _store().load_latest()
    except EvidenceValidationError:
        snapshot = None
    return {
        "status": "HEALTHY" if snapshot else "DEGRADED",
        "service": "rolo",
        "version": app.version,
        "robots": 1 if snapshot else 0,
        "api_features": [
            "rkb.read-model/v1",
            "mhs.inventory-read-model/v1",
            "tool.verification-read-model/v1",
            "rkb.episodes-read-model/v1",
        ],
        "timestamp": datetime.now(timezone.utc),
    }


@app.get("/v1/features")
def features(accept: str | None = None) -> dict[str, Any]:
    """Negotiate optional read-model features without enabling capabilities."""
    requested = [item.strip() for item in (accept or "").split(",") if item.strip()]
    negotiated = [item for item in API_FEATURES if not requested or item in requested]
    return {
        "schema_version": "rolo-api-feature-negotiation/v1",
        "features": list(API_FEATURES),
        "requested": requested,
        "negotiated": negotiated,
        "read_only": True,
    }


@app.get("/v1/robots")
def robots() -> dict[str, Any]:
    try:
        snapshot = _store().load_latest()
    except EvidenceValidationError:
        snapshot = None
    items = (
        []
        if snapshot is None
        else [
            {
                **_base(snapshot),
                "schema_version": "robot-capability/v1",
                "adapter": "rkb",
                "platform": {},
                "geometry": {},
                "sensors": {},
                "features": {},
            }
        ]
    )
    return {
        "schema_version": "rolo-robot-collection/v1",
        "items": items,
        "total": len(items),
        "observed_at": datetime.now(timezone.utc),
        "freshness": "fresh" if items else "unknown",
        "limitations": [] if items else ["no verified RKB snapshot available"],
    }


@app.get("/v1/robots/{robot_id}/rkb")
def rkb(robot_id: str) -> dict[str, Any]:
    snapshot = _snapshot(robot_id)
    kb = ReadOnlyKnowledgeBase([snapshot])
    now = datetime.now(timezone.utc)
    sections = {
        "identity": _query_or_unknown(lambda: kb.robot.identity(now=now)),
        "os_runtime": _query_or_unknown(lambda: kb.os.runtime_status(now=now)),
        "hardware": _query_or_unknown(lambda: kb.hw.inventory_scan(now=now)),
        "middleware": _query_or_unknown(lambda: kb.middleware.graph_snapshot(now=now)),
        "application": _query_or_unknown(lambda: kb.app_executable_list(now=now)),
        "episodes": _query_or_unknown(lambda: kb.app.episodes(now=now)),
        "capabilities": _query_or_unknown(lambda: kb.capability_list(now=now)),
        "state_safety": _query_or_unknown(lambda: kb.state_safety.snapshot(now=now)),
    }
    return {
        "schema_version": "rkb-robot-knowledge-base/v1",
        **_base(snapshot),
        "sections": sections,
        "provenance": {
            "snapshot_digest": snapshot.digest or snapshot.computed_digest(),
            "evidence_ids": sorted({fact.fact_id for fact in snapshot.facts}),
            "limitations": [
                "application executable collection is bounded; "
                "inspect requires an explicit executable id",
                "episode detail is bounded to the verified snapshot",
            ],
        },
    }


@app.get("/v1/robots/{robot_id}/mhs")
def mhs(
    robot_id: str,
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=100, ge=1, le=100),
) -> dict[str, Any]:
    snapshot = _snapshot(robot_id)
    result = ReadOnlyKnowledgeBase([snapshot]).hw.inventory_scan(
        now=datetime.now(timezone.utc), offset=offset, limit=limit
    )
    resources = result.value.resources if result.value else []
    try:
        registrations = {item.provider_id: item for item in _mhs_registry().list()}
    except MhsRegistryError:
        registrations = {}
    items = []
    for resource in resources:
        provider_id = resource.provider_id or resource.resource_id
        registration = registrations.get(provider_id) or registrations.get(f"mhs.{provider_id}")
        device_id = provider_id.removeprefix("mhs.")
        limitations = [
            "provider registration does not grant verification",
            "no write capabilities are exposed",
        ]
        if registration is not None:
            registration_state = registration.status.value
            evidence_ids = sorted(set(result.evidence_ids) | set(registration.evidence_ids))
            limitations.extend(registration.limitations)
        else:
            registration_state = "PENDING"
            evidence_ids = result.evidence_ids
        items.append(
            {
                "schema_version": "rolo-mhs-device-read-model/v1",
                "device_id": device_id,
                "device_class": resource.kind,
                "model": resource.name or "UNKNOWN",
                "discovery": "DISCOVERED",
                "registration": registration_state,
                "tool_state": "DISCOVERED_UNVERIFIED",
                "callable": False,
                "route": f"mhs://{device_id}/inspect",
                "evidence_ids": evidence_ids,
                "limitations": sorted(set(limitations)),
            }
        )
    return {
        "schema_version": "rolo-mhs-inventory/v1",
        **_base(snapshot),
        "items": items,
        "total": result.total or 0,
        "offset": result.offset,
        "limit": result.limit,
        "next_offset": result.next_offset,
        "discovered_count": len(items),
        "registered_count": sum(item["registration"] == "REGISTERED" for item in items),
        "verified_count": 0,
        "callable_count": 0,
        "limitations": result.limitations,
    }


@app.get("/v1/robots/{robot_id}/tools")
def tools(
    robot_id: str,
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=100, ge=1, le=100),
) -> dict[str, Any]:
    snapshot = _snapshot(robot_id)
    result = ReadOnlyKnowledgeBase([snapshot]).capability_list(
        now=datetime.now(timezone.utc), offset=offset, limit=limit
    )
    records = result.value or []
    conformance = _latest_conformance(robot_id, snapshot.identity.target_host_fingerprint)
    conformance_ready = conformance is not None and conformance.status == "PASS"
    items = [
        {
            "schema_version": "rolo-tool-verification-read-model/v1",
            "operation_id": record.operation_id,
            "state": record.state.value
            if (record.state != CapabilityState.VERIFIED or conformance_ready)
            else "DISCOVERED_UNVERIFIED",
            "verified": record.state == CapabilityState.VERIFIED and conformance_ready,
            "agent_callable": record.state == CapabilityState.VERIFIED and conformance_ready,
            "reason": record.reason
            if conformance_ready
            else "formal Tool conformance artifact is required",
            "fingerprint": record.fingerprint,
            "target_host_fingerprint": snapshot.identity.target_host_fingerprint,
            "conformance_status": conformance.status if conformance else "MISSING",
            "session_id": conformance.session_id if conformance else None,
            "surface_digest": conformance.surface_digest if conformance else None,
            "evidence_ids": result.evidence_ids,
            "limitations": record.limitations,
        }
        for record in records
    ]
    return {
        "schema_version": "rolo-tool-surface/v1",
        **_base(snapshot),
        "items": items,
        "total": result.total or 0,
        "offset": result.offset,
        "limit": result.limit,
        "next_offset": result.next_offset,
        "verified_count": sum(item["verified"] for item in items),
        "agent_callable_count": sum(item["agent_callable"] for item in items),
        "limitations": result.limitations
        + (
            []
            if conformance_ready
            else [
                "Tool verification is withheld until a target-bound conformance artifact is available"
            ]
        ),
    }


@app.get("/v1/robots/{robot_id}/episodes")
def episodes(
    robot_id: str,
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=100),
) -> dict[str, Any]:
    snapshot = _snapshot(robot_id)
    result = _query_or_unknown(
        lambda: ReadOnlyKnowledgeBase([snapshot]).app.episodes(
            now=datetime.now(timezone.utc), offset=offset, limit=limit
        )
    )
    raw_items = result.get("value") if isinstance(result.get("value"), list) else []
    observed = snapshot.identity.observed_at.isoformat()
    items = []
    for raw in raw_items:
        item = dict(raw) if isinstance(raw, dict) else {"episode_id": str(raw)}
        state = str(item.get("state", "PARTIAL")).upper()
        if state not in {"RUNNING", "COMPLETED", "FAILED", "CANCELLED", "PARTIAL"}:
            state = "PARTIAL"
        items.append(
            {
                "schema_version": "rolo-episode-summary/v1",
                "robot_id": robot_id,
                "episode_id": str(item.get("episode_id", "episode-unknown")),
                "revision": int(item.get("revision", 1)),
                "task_label": str(item.get("task_label", item.get("episode_id", "RKB episode"))),
                "state": state,
                "outcome": str(item.get("outcome", "UNKNOWN")),
                "verification": str(item.get("verification", "NOT_AVAILABLE")),
                "coverage": str(item.get("coverage", "METADATA_ONLY")),
                "started_at": str(item.get("started_at", observed)),
                "ended_at": item.get("ended_at"),
                "event_count": int(item.get("event_count", 0)),
                "evidence_ids": [str(v) for v in item.get("evidence_ids", []) if v],
                "limitations": list(item.get("limitations", [])),
                "source_kind": "published_episode_projection",
            }
        )
    return {
        "schema_version": "rolo-episode-collection/v1",
        **_base(snapshot),
        "items": items,
        "total": result.get("total") or 0,
        "offset": result.get("offset", offset),
        "limit": result.get("limit", limit),
        "next_offset": result.get("next_offset"),
        "status": result.get("status", "UNKNOWN"),
        "evidence_ids": result.get("evidence_ids", []),
        "limitations": result.get("limitations", []),
    }


@app.get("/v1/robots/{robot_id}/episodes/{episode_id}")
def episode_detail(robot_id: str, episode_id: str) -> dict[str, Any]:
    collection = episodes(robot_id)
    item = next(
        (candidate for candidate in collection["items"] if candidate["episode_id"] == episode_id),
        None,
    )
    if item is None:
        raise HTTPException(status_code=404, detail="episode not found")
    return {
        **item,
        "schema_version": "rolo-episode-detail/v1",
        "immutable": item["state"] != "RUNNING",
        "clock_domain": "RKB_SNAPSHOT",
        "synchronization": "UNKNOWN",
        "available_lanes": [],
        "assets": [],
        "findings": [],
        "timeline": [],
        "limitations": item["limitations"]
        + ["timeline, assets, and findings are not published by this snapshot"],
    }
