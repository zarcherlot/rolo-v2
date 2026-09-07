"""Deterministic prompt templates for Agent-side DSL mapping."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .mapping import AdapterMappingRequest
from .models import OperationKind

OPERATION_PROMPTS: dict[OperationKind, str] = {
    OperationKind.OBSERVE: "Map one observed target resource to a read-only OBSERVE tool.",
    OperationKind.COMPOSE: "Compose existing published tools into a bounded COMPOSE DAG.",
    OperationKind.INVOKE: "Map one observed provider operation to an INVOKE tool.",
    OperationKind.EXECUTE: "Describe a declared source bundle and implementation contract for EXECUTE.",
}


def render_mapping_prompt(request: AdapterMappingRequest, *, context_summary: Mapping[str, Any] | None = None) -> str:
    """Render a bounded prompt carrying only digest-bound mapping metadata."""

    candidates = ", ".join(request.operation_candidates) or "(none)"
    summary = dict(context_summary or {})
    summary_text = ", ".join(f"{key}={summary[key]}" for key in sorted(summary) if key in {"robot_id", "target_fingerprint", "freshness"})
    return (
        "You generate Rolo DSL only; do not use SSH, shell, network, or catalog mutation.\n"
        f"journey_session_id={request.journey_session_id}\n"
        f"user_goal={request.user_goal}\n"
        f"context_digest={request.context_digest}\n"
        f"available_tool_catalog_digest={request.available_tool_catalog_digest}\n"
        f"operation_candidates={candidates}\n"
        f"context_summary={summary_text or '(digest-bound context supplied separately)'}\n"
        "Return exactly one rolo-dsl/v1 document and preserve observed-evidence boundaries."
    )


__all__ = ["OPERATION_PROMPTS", "render_mapping_prompt"]
