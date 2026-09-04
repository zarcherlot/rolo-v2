from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from rolo.agent_tools.conformance import ToolConformanceReport
from rolo.agent_tools.native_tools import AgentNativeToolDescriptor
from rolo.agent_tools.session import native_catalog_sha256

from .contracts import CatalogTool, MhsInventoryEntry, RkbModelRef, TargetCatalog, ToolState


def _descriptor_digest(descriptor: AgentNativeToolDescriptor) -> str:
    import hashlib

    payload = json.dumps(descriptor.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode()).hexdigest()


def build_target_catalog(
    *,
    target_id: str,
    target_fingerprint: str = "UNKNOWN",
    snapshot_digest: str = "UNKNOWN",
    descriptors: Iterable[AgentNativeToolDescriptor | Mapping[str, Any]] = (),
    conformance: ToolConformanceReport | Mapping[str, Any] | None = None,
    mhs: Iterable[MhsInventoryEntry | Mapping[str, Any]] = (),
    rkb: Iterable[RkbModelRef | Mapping[str, Any]] = (),
    freshness: str = "unknown",
    generated_at: datetime | None = None,
) -> TargetCatalog:
    """Project verified Probe artifacts into the stable Agent catalog.

    ``conformance`` is intentionally optional for fixture construction, but a
    missing or failing report keeps every tool non-callable.  No capability is
    inferred from a tool name or from an MHS reference.
    """
    report = conformance if isinstance(conformance, ToolConformanceReport) else (ToolConformanceReport.model_validate(conformance) if conformance else None)
    descriptors = [item if isinstance(item, AgentNativeToolDescriptor) else AgentNativeToolDescriptor.model_validate(item) for item in descriptors]
    report_ok = bool(
        report is not None
        and report.status == "PASS"
        and report.target_id == target_id
        and report.surface_digest == native_catalog_sha256(descriptors)
        and (report.target_host_fingerprint is None or report.target_host_fingerprint == target_fingerprint)
    )
    # A conformance report covers the complete frozen surface; the session
    # allowlist is carried by the descriptors/session artifact and is therefore
    # represented here by the supplied descriptor set.
    allowed = {item.tool_id for item in descriptors} if report_ok else set()
    tools: list[CatalogTool] = []
    for raw in descriptors:
        descriptor = raw if isinstance(raw, AgentNativeToolDescriptor) else AgentNativeToolDescriptor.model_validate(raw)
        callable_ = bool(report_ok and descriptor.tool_id in allowed)
        access = "experimental_write" if getattr(descriptor, "access", "read") == "experimental_write" else "read"
        state = ToolState.CALLABLE if callable_ else (ToolState.VERIFIED if report_ok else ToolState.DISCOVERED_UNVERIFIED)
        limitations: list[str] = []
        if not report_ok:
            limitations.append("target-bound conformance artifact is required")
        tools.append(
            CatalogTool(
                tool_id=descriptor.tool_id,
                target_id=target_id,
                state=state,
                agent_callable=callable_,
                access=access,
                experimental_write=access == "experimental_write",
                descriptor_digest=_descriptor_digest(descriptor),
                source="probe",
                parameters={item.name: item.model_dump(mode="json") for item in descriptor.parameters},
                timeout_s=descriptor.max_duration_s,
                limitations=limitations,
            )
        )
    entries = [item if isinstance(item, MhsInventoryEntry) else MhsInventoryEntry.model_validate(item) for item in mhs]
    refs = [item if isinstance(item, RkbModelRef) else RkbModelRef.model_validate(item) for item in rkb]
    limitations: list[str] = []
    if not any(item.agent_callable and ("map" in item.tool_id.lower() or "mapping" in item.tool_id.lower()) for item in tools):
        limitations.append("mapping tool not observed")
    if freshness != "fresh":
        limitations.append(f"catalog freshness is {freshness}")
    return TargetCatalog(
        target_id=target_id,
        target_fingerprint=target_fingerprint,
        snapshot_digest=snapshot_digest,
        generated_at=generated_at or datetime.now(timezone.utc),
        freshness=freshness if freshness in {"fresh", "stale", "unknown"} else "unknown",
        tools=tools,
        mhs=entries,
        rkb=refs,
        limitations=limitations,
    ).with_digest()


def save_target_catalog(catalog: TargetCatalog, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(catalog.with_digest().model_dump(mode="json"), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return path


def load_target_catalog(path: Path) -> TargetCatalog:
    if path.is_symlink() or not path.is_file():
        raise FileNotFoundError(path)
    return TargetCatalog.model_validate_json(path.read_text(encoding="utf-8"))


__all__ = ["build_target_catalog", "save_target_catalog", "load_target_catalog"]
