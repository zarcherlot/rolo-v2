"""Layered digest and dirty evaluation for Probe compile contexts."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any, Literal

from pydantic import Field

from .context import ProbeContext
from .models import StrictModel


def _digest(value: Any) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


class ContextLayerDigests(StrictModel):
    """Independent digests used to classify a context refresh."""

    schema_version: Literal["rolo-context-layer-digests/v1"] = "rolo-context-layer-digests/v1"
    target_identity_digest: str = Field(min_length=1)
    runtime_snapshot_digest: str = Field(min_length=1)
    surface_digest: str = Field(min_length=1)
    evidence_digest: str = Field(min_length=1)


class ContextChangeReport(StrictModel):
    """Read-only result of comparing two context digest layers."""

    schema_version: Literal["rolo-context-change-report/v1"] = "rolo-context-change-report/v1"
    status: Literal["CLEAN", "DIRTY"]
    changed_layers: tuple[str, ...] = Field(default_factory=tuple, max_length=4)
    dirty_namespaces: tuple[str, ...] = Field(default_factory=tuple, max_length=64)


def context_layer_digests(context: ProbeContext | Mapping[str, Any]) -> ContextLayerDigests:
    """Compute stable layers without promoting limitations to observed facts."""

    value = context if isinstance(context, ProbeContext) else ProbeContext.model_validate(context)
    return ContextLayerDigests(
        target_identity_digest=_digest({"robot_id": value.robot_id, "target_fingerprint": value.target_fingerprint}),
        # Collection timestamps and freshness windows are evidence metadata,
        # not runtime identity.  Including them here would mark every fresh
        # Probe as a software change and force needless bounded re-probes.
        runtime_snapshot_digest=_digest(
            {
                "runtime_revision": value.runtime_revision,
                "runtime": _stable_runtime_fields(value.freshness),
            }
        ),
        surface_digest=_digest(
            {
                "routes": value.routes,
                "message_schemas": value.message_schemas,
                "published_tools": value.published_tools,
                "mhs_manifest_refs": value.mhs_manifest_refs,
                "mhs_manifest_digests": value.mhs_manifest_digests,
            }
        ),
        evidence_digest=value.evidence_digest,
    )


def _stable_runtime_fields(value: Mapping[str, Any]) -> dict[str, Any]:
    """Drop volatile observation timestamps from the runtime layer digest."""

    volatile = {"collected_at", "observed_at", "fresh_until", "expires_at", "timestamp", "generated_at"}
    return {str(key): item for key, item in value.items() if str(key) not in volatile}


def evaluate_context_change(previous: ContextLayerDigests, current: ContextLayerDigests) -> ContextChangeReport:
    """Mark only layers whose digest changed; callers decide whether to re-probe."""

    changed: list[str] = []
    if previous.target_identity_digest != current.target_identity_digest:
        changed.append("target_identity")
    if previous.runtime_snapshot_digest != current.runtime_snapshot_digest:
        changed.append("runtime")
    if previous.surface_digest != current.surface_digest:
        changed.append("surface")
    if previous.evidence_digest != current.evidence_digest:
        changed.append("evidence")
    return ContextChangeReport(
        status="DIRTY" if changed else "CLEAN",
        changed_layers=tuple(changed),
        dirty_namespaces=tuple(changed),
    )


__all__ = ["ContextChangeReport", "ContextLayerDigests", "context_layer_digests", "evaluate_context_change"]
