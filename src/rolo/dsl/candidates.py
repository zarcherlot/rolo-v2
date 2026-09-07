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
    # The original ``operation``/``probe_template`` fields remain the compact
    # v1 surface.  These explicit projections make the candidate index useful
    # to an Agent without asking it to reinterpret raw Probe records.
    intent_tags: tuple[str, ...] = Field(default_factory=tuple, max_length=32)
    possible_operations: tuple[str, ...] = Field(default_factory=tuple, max_length=32)
    observed_resources: tuple[str, ...] = Field(default_factory=tuple, max_length=64)
    mhs_refs: tuple[str, ...] = Field(default_factory=tuple, max_length=32)
    evidence_refs: tuple[str, ...] = Field(min_length=1, max_length=32)
    confidence: float = Field(ge=0.0, le=1.0)
    freshness: dict[str, Any] = Field(default_factory=dict, max_length=32)
    gaps: tuple[str, ...] = Field(default_factory=tuple, max_length=32)
    missing_evidence: tuple[str, ...] = Field(default_factory=tuple, max_length=32)
    probe_template: tuple[str, ...] = Field(default_factory=tuple, max_length=16)
    bounded_probe_templates: tuple[str, ...] = Field(default_factory=tuple, max_length=16)


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
        resources = _string_values(record, "resource_id", "endpoint", "route_id")
        mhs_refs = _string_values(record, "mhs_manifest_ref", "mhs_ref", "manifest_ref")
        record_evidence = _string_values(record, "evidence_ref", "evidence_refs")
        record_gaps = _string_values(record, "gap", "gaps", "missing_evidence", "limitations")
        tags = _string_values(record, "intent_tags", "tags", "intent")
        possible = _string_values(record, "possible_operations", "operations")
        templates = _string_values(record, "bounded_probe_templates", "probe_templates", "probe_template")
        if not templates:
            templates = ("route",)
        observed_confidence = record.get("confidence")
        candidate_confidence = (
            float(observed_confidence)
            if isinstance(observed_confidence, (int, float)) and 0 <= float(observed_confidence) <= 1
            else confidence
        )
        candidate = CapabilityCandidate(
            candidate_id=candidate_id,
            operation=operation,
            intent_tags=tuple(sorted(set(tags))),
            possible_operations=tuple(sorted(set((operation, *possible)))),
            observed_resources=tuple(sorted(set(resources))),
            mhs_refs=tuple(sorted(set(mhs_refs))),
            evidence_refs=tuple(sorted(set((evidence_ref, *record_evidence)))),
            confidence=candidate_confidence,
            freshness=dict(context_model.freshness),
            gaps=tuple(sorted(set((*limitation_gaps, *record_gaps)))),
            missing_evidence=tuple(sorted(set((*limitation_gaps, *record_gaps)))),
            probe_template=templates,
            bounded_probe_templates=templates,
        )
        previous = candidates.get(candidate_id)
        candidates[candidate_id] = candidate if previous is None else _merge_candidates(previous, candidate)
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
    index.verify()
    tokens = {token for token in _tokens(intent) if len(token) >= 2}
    tokens.update(_intent_aliases(intent))
    scored: list[tuple[int, CapabilityCandidate]] = []
    for candidate in index.candidates:
        haystack = set(
            _tokens(
                " ".join(
                    (
                        candidate.candidate_id,
                        candidate.operation,
                        *candidate.intent_tags,
                        *candidate.possible_operations,
                        *candidate.observed_resources,
                    )
                )
            )
        )
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


def _string_values(record: Mapping[str, Any], *keys: str) -> tuple[str, ...]:
    values: list[str] = []
    for key in keys:
        value = record.get(key)
        if isinstance(value, str) and value.strip():
            values.append(value.strip())
        elif isinstance(value, (list, tuple)):
            values.extend(str(item).strip() for item in value if isinstance(item, str) and item.strip())
    return tuple(values)


def _merge_candidates(left: CapabilityCandidate, right: CapabilityCandidate) -> CapabilityCandidate:
    """Merge duplicate route/tool records without discarding evidence."""

    return left.model_copy(
        update={
            "intent_tags": tuple(sorted(set((*left.intent_tags, *right.intent_tags)))),
            "possible_operations": tuple(sorted(set((*left.possible_operations, *right.possible_operations)))),
            "observed_resources": tuple(sorted(set((*left.observed_resources, *right.observed_resources)))),
            "mhs_refs": tuple(sorted(set((*left.mhs_refs, *right.mhs_refs)))),
            "evidence_refs": tuple(sorted(set((*left.evidence_refs, *right.evidence_refs)))),
            "confidence": max(left.confidence, right.confidence),
            "gaps": tuple(sorted(set((*left.gaps, *right.gaps)))),
            "missing_evidence": tuple(sorted(set((*left.missing_evidence, *right.missing_evidence)))),
            "probe_template": tuple(sorted(set((*left.probe_template, *right.probe_template)))),
            "bounded_probe_templates": tuple(sorted(set((*left.bounded_probe_templates, *right.bounded_probe_templates)))),
        }
    )


def _tokens(value: str) -> tuple[str, ...]:
    normalized = "".join(character.lower() if character.isalnum() else " " for character in value)
    tokens = [token for token in normalized.split() if token]
    # Keep short CJK terms searchable even when the user phrase and the
    # observed operation use different surrounding words (e.g. 完成建图 vs
    # app.mapping.run).  This does not create a candidate; it only changes
    # ranking among already observed records.
    for token in tuple(tokens):
        if any("\u4e00" <= character <= "\u9fff" for character in token):
            tokens.extend(token[index : index + 2] for index in range(len(token) - 1))
    return tuple(dict.fromkeys(tokens))


def _intent_aliases(intent: str) -> set[str]:
    aliases = {
        "建图": {"map", "mapping", "slam"},
        "地图": {"map", "mapping", "slam"},
        "旋转": {"rotate", "rotation"},
        "状态": {"state", "status"},
        "导航": {"navigation", "navigate"},
    }
    return {alias for phrase, values in aliases.items() if phrase in intent for alias in values}


__all__ = ["CapabilityCandidate", "CapabilityCandidateIndex", "build_candidate_index", "persist_candidate_index", "query_candidates"]
