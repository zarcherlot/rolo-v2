"""Read-only HTTP facade for the rolo v2 Robot Knowledge Base.

The facade consumes only a validated latest snapshot.  It never probes targets,
registers providers, executes tools, or exposes raw bundle payloads.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Query

from .mhs_registry import MhsProviderRegistry, MhsRegistryError
from .rkb import (
    CapabilityState,
    EvidenceValidationError,
    QueryRejectedError,
    ReadOnlyKnowledgeBase,
    RKBStore,
)

app = FastAPI(title="rolo v2 read-only API", version="0.38.0")


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
        ],
        "timestamp": datetime.now(timezone.utc),
    }


@app.get("/v1/robots")
def robots() -> dict[str, Any]:
    try:
        snapshot = _store().load_latest()
    except EvidenceValidationError:
        snapshot = None
    items = [] if snapshot is None else [{
        **_base(snapshot),
        "schema_version": "robot-capability/v1",
        "adapter": "rkb",
        "platform": {},
        "geometry": {},
        "sensors": {},
        "features": {},
    }]
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
                "episodes are not present in the current RKB query contract",
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
        "schema_version": "rolo-mhs-inventory/v1", **_base(snapshot), "items": items,
        "total": result.total or 0, "offset": result.offset, "limit": result.limit,
        "next_offset": result.next_offset, "discovered_count": len(items),
        "registered_count": sum(item["registration"] == "REGISTERED" for item in items),
        "verified_count": 0, "callable_count": 0, "limitations": result.limitations,
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
    items = [{
        "schema_version": "rolo-tool-verification-read-model/v1",
        "operation_id": record.operation_id, "state": record.state.value,
        "verified": record.state == CapabilityState.VERIFIED,
        "agent_callable": record.state == CapabilityState.VERIFIED,
        "reason": record.reason, "fingerprint": record.fingerprint,
        "evidence_ids": result.evidence_ids, "limitations": record.limitations,
    } for record in records]
    return {
        "schema_version": "rolo-tool-surface/v1", **_base(snapshot), "items": items,
        "total": result.total or 0, "offset": result.offset, "limit": result.limit,
        "next_offset": result.next_offset,
        "verified_count": sum(item["verified"] for item in items),
        "agent_callable_count": sum(item["agent_callable"] for item in items),
        "limitations": result.limitations,
    }
