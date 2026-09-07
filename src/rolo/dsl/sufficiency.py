"""Deterministic evidence sufficiency decisions for intent-driven mapping."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import Field

from .candidates import CapabilityCandidateIndex, query_candidates
from .canonical import context_digest
from .context import ProbeContext
from .models import StrictModel


class MappingSufficiencyReport(StrictModel):
    """Explain whether observed evidence is enough to start DSL mapping."""

    schema_version: Literal["rolo-mapping-sufficiency/v1"] = "rolo-mapping-sufficiency/v1"
    intent: str = Field(min_length=1, max_length=2_000)
    context_digest: str = Field(min_length=1)
    status: Literal["READY", "NEEDS_PROBE", "UNSUPPORTED"]
    candidate_ids: tuple[str, ...] = Field(default_factory=tuple, max_length=64)
    missing_items: tuple[str, ...] = Field(default_factory=tuple, max_length=32)
    reasons: tuple[str, ...] = Field(default_factory=tuple, max_length=32)
    bounded_probe_allowed: bool = False


def assess_mapping_sufficiency(
    context: ProbeContext | Mapping[str, object],
    index: CapabilityCandidateIndex,
    intent: str,
    *,
    limit: int = 16,
) -> MappingSufficiencyReport:
    """Return a conservative decision using only the supplied evidence.

    The function never treats an absent candidate as an available capability.
    A missing match becomes ``NEEDS_PROBE`` so a caller can issue a separately
    bounded Probe request; explicit limitation text indicating unsupported
    capability is the only route to ``UNSUPPORTED``.
    """

    context_model = context if isinstance(context, ProbeContext) else ProbeContext.model_validate(context)
    normalized_intent = intent.strip()
    if not normalized_intent:
        raise ValueError("intent must be non-empty")
    index.verify()
    expected_context_digest = context_digest(context_model)
    if index.context_digest != expected_context_digest:
        raise ValueError("CONTEXT_DIGEST_MISMATCH")
    matches = query_candidates(index, normalized_intent, limit=limit)
    candidate_ids = tuple(item.candidate_id for item in matches)
    limitations = tuple(sorted(context_model.limitations))
    unsupported = tuple(item for item in limitations if "unsupported" in item.lower() or "not supported" in item.lower())
    if unsupported:
        return MappingSufficiencyReport(
            intent=normalized_intent,
            context_digest=expected_context_digest,
            status="UNSUPPORTED",
            candidate_ids=candidate_ids,
            reasons=("EXPLICIT_UNSUPPORTED_LIMITATION",),
            missing_items=unsupported,
            bounded_probe_allowed=False,
        )
    if not matches:
        return MappingSufficiencyReport(
            intent=normalized_intent,
            context_digest=expected_context_digest,
            status="NEEDS_PROBE",
            reasons=("INTENT_NOT_OBSERVED",),
            missing_items=("observed_route_or_published_tool",),
            bounded_probe_allowed=True,
        )
    gaps = tuple(sorted({gap for item in matches for gap in (*item.gaps, *item.missing_evidence)}))
    low_confidence = tuple(item.candidate_id for item in matches if item.confidence < 0.5)
    freshness_unknown = tuple(
        item.candidate_id
        for item in matches
        if _freshness_requires_probe(item.freshness)
    )
    if gaps or low_confidence or freshness_unknown:
        missing = list(gaps)
        reasons: list[str] = []
        if gaps:
            reasons.append("CANDIDATE_HAS_GAPS")
        if low_confidence:
            reasons.append("CANDIDATE_CONFIDENCE_LOW")
            missing.extend(f"confidence:{candidate_id}" for candidate_id in low_confidence)
        if freshness_unknown:
            reasons.append("CANDIDATE_FRESHNESS_UNKNOWN")
            missing.extend(f"freshness:{candidate_id}" for candidate_id in freshness_unknown)
        return MappingSufficiencyReport(
            intent=normalized_intent,
            context_digest=expected_context_digest,
            status="NEEDS_PROBE",
            candidate_ids=candidate_ids,
            reasons=tuple(reasons),
            missing_items=tuple(dict.fromkeys(missing)),
            bounded_probe_allowed=True,
        )
    return MappingSufficiencyReport(
        intent=normalized_intent,
        context_digest=expected_context_digest,
        status="READY",
        candidate_ids=candidate_ids,
        bounded_probe_allowed=False,
    )


__all__ = ["MappingSufficiencyReport", "assess_mapping_sufficiency"]


def _freshness_requires_probe(freshness: Mapping[str, Any]) -> bool:
    """Recognize explicit stale/unknown states and elapsed freshness bounds."""

    states = {"UNKNOWN", "STALE", "EXPIRED", "INVALID"}
    for key, value in freshness.items():
        if isinstance(value, str) and value.strip().upper() in states:
            return True
        if str(key).lower() not in {"expires_at", "fresh_until"}:
            continue
        if not isinstance(value, str):
            continue
        try:
            expiry = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            continue
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        if expiry <= datetime.now(timezone.utc):
            return True
    return False
