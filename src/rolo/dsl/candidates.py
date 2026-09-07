"""Evidence-bound capability candidates and deterministic intent lookup."""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Literal

from pydantic import Field

from .canonical import context_digest
from .context import ProbeContext
from .models import StrictModel


class CapabilityCandidate(StrictModel):
    """One candidate copied from an observed route or published Tool."""

    schema_version: Literal["rolo-capability-candidate/v1"] = "rolo-capability-candidate/v1"
    candidate_id: str = Field(min_length=1, max_length=256)
    operation: str = Field(min_length=1, max_length=256)
    evidence_refs: tuple[str, ...] = Field(min_length=1, max_length=32)
    confidence: float = Field(ge=0.0, le=1.0)
    freshness: dict[str, Any] = Field(default_factory=dict, max_length=32)
    gaps: tuple[str, ...] = Field(default_factory=tuple, max_length=32)
    probe_template: tuple[str, ...] = Field(default_factory=tuple, max_length=16)


class CapabilityCandidateIndex(StrictModel):
    """Digest-addressed index that never contains unobserved capabilities."""

    schema_version: Literal["rolo-capability-candidate-index/v1"] = "rolo-capability-candidate-index/v1"
    robot_id: str = Field(min_length=1, max_length=128)
    target_fingerprint: str = Field(min_length=1, max_length=256)
    context_digest: str = Field(min_length=1)
    evidence_digest: str = Field(min_length=1)
    candidates: tuple[CapabilityCandidate, ...] = Field(default_factory=tuple, max_length=256)
    index_digest: str = Field(pattern=r"^[0-9a-f]{64}$")

    def unsigned_payload(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude={"index_digest"})

    def computed_digest(self) -> str:
        encoded = json.dumps(self.unsigned_payload(), ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def verify(self) -> None:
        if self.index_digest != self.computed_digest():
            raise ValueError("candidate index digest mismatch")


def build_candidate_index(context: ProbeContext | Mapping[str, Any]) -> CapabilityCandidateIndex:
    """Build candidates only from context records that Probe actually observed."""

    context_model = context if isinstance(context, ProbeContext) else ProbeContext.model_validate(context)
    candidates: dict[str, CapabilityCandidate] = {}
    evidence_ref = context_model.evidence_refs[0] if context_model.evidence_refs else f"artifact://probe/{context_model.evidence_digest}"
    limitation_gaps = tuple(sorted(context_model.limitations))
    confidence = 0.5 if limitation_gaps else 0.8
    for record in (*context_model.routes, *context_model.published_tools):
        operation = _operation_name(record)
        if operation is None:
            continue
        candidate_id = str(record.get("candidate_id") or record.get("tool_id") or record.get("route_id") or operation)
        candidate = CapabilityCandidate(
            candidate_id=candidate_id,
            operation=operation,
            evidence_refs=(evidence_ref,),
            confidence=confidence,
            freshness=dict(context_model.freshness),
            gaps=limitation_gaps,
            probe_template=(str(record.get("probe_template")),) if record.get("probe_template") else ("route",),
        )
        candidates[candidate_id] = candidate
    index = CapabilityCandidateIndex(
        robot_id=context_model.robot_id,
        target_fingerprint=context_model.target_fingerprint,
        context_digest=context_digest(context_model),
        evidence_digest=context_model.evidence_digest,
        candidates=tuple(candidates[key] for key in sorted(candidates)),
        index_digest="0" * 64,
    )
    return index.model_copy(update={"index_digest": index.computed_digest()})


def query_candidates(index: CapabilityCandidateIndex, intent: str, *, limit: int = 16) -> tuple[CapabilityCandidate, ...]:
    """Return deterministic token matches for an intent, preserving evidence bounds."""

    if not intent or not 1 <= limit <= 64:
        raise ValueError("intent must be non-empty and limit must be between 1 and 64")
    tokens = {token for token in _tokens(intent) if len(token) >= 2}
    scored: list[tuple[int, CapabilityCandidate]] = []
    for candidate in index.candidates:
        haystack = set(_tokens(f"{candidate.candidate_id} {candidate.operation}"))
        score = len(tokens & haystack)
        if score:
            scored.append((score, candidate))
    scored.sort(key=lambda item: (-item[0], item[1].candidate_id))
    return tuple(candidate for _, candidate in scored[:limit])


def persist_candidate_index(index: CapabilityCandidateIndex, root: str | Path) -> Path:
    """Atomically persist a candidate index and verify its digest first."""

    index.verify()
    destination = Path(root)
    destination.mkdir(parents=True, exist_ok=True)
    path = destination / "candidate-index.json"
    temporary = path.with_suffix(".json.tmp")
    temporary.write_text(index.model_dump_json(indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, path)
    return path


def _operation_name(record: Mapping[str, Any]) -> str | None:
    for key in ("operation", "operation_id", "route_id", "name", "tool_id"):
        value = record.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _tokens(value: str) -> tuple[str, ...]:
    return tuple(token for token in "".join(character.lower() if character.isalnum() else " " for character in value).split() if token)


__all__ = ["CapabilityCandidate", "CapabilityCandidateIndex", "build_candidate_index", "persist_candidate_index", "query_candidates"]
