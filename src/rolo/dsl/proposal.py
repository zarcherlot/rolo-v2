"""Read-only mapping proposal contract shown before any publish or execution."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Literal

from pydantic import Field

from .candidates import CapabilityCandidate, CapabilityCandidateIndex
from .mapping import AdapterMappingRequest
from .models import StrictModel


class MappingProposal(StrictModel):
    """Evidence and risk summary requiring explicit user confirmation."""

    schema_version: Literal["rolo-mapping-proposal/v1"] = "rolo-mapping-proposal/v1"
    journey_session_id: str = Field(min_length=1, max_length=256)
    user_goal: str = Field(min_length=1, max_length=2_000)
    candidate_id: str = Field(min_length=1, max_length=256)
    operation: str = Field(min_length=1, max_length=256)
    context_digest: str = Field(min_length=1)
    evidence_digest: str = Field(min_length=1)
    evidence_refs: tuple[str, ...] = Field(min_length=1, max_length=32)
    dsl_digest: str | None = Field(default=None, max_length=128)
    risks: tuple[str, ...] = Field(default_factory=tuple, max_length=32)
    unknowns: tuple[str, ...] = Field(default_factory=tuple, max_length=32)
    requested_actions: tuple[str, ...] = Field(default_factory=lambda: ("user_confirmation",), max_length=16)
    status: Literal["PROPOSED", "CONFIRMED", "REJECTED", "BLOCKED"] = "PROPOSED"

    def confirm(self) -> MappingProposal:
        if self.status != "PROPOSED":
            raise ValueError("only a proposed mapping can be confirmed")
        return self.model_copy(update={"status": "CONFIRMED"})

    def reject(self) -> MappingProposal:
        if self.status != "PROPOSED":
            raise ValueError("only a proposed mapping can be rejected")
        return self.model_copy(update={"status": "REJECTED"})


def build_mapping_proposal(request: AdapterMappingRequest, index: CapabilityCandidateIndex, candidate: CapabilityCandidate) -> MappingProposal:
    """Build a proposal only when request and candidate share the same Context."""

    index.verify()
    if request.context_digest != index.context_digest:
        raise ValueError("mapping proposal context digest mismatch")
    if candidate not in index.candidates:
        raise ValueError("mapping proposal candidate is not in the index")
    unknowns = tuple(dict.fromkeys((*candidate.gaps, *candidate.missing_evidence)))
    if any(str(value).lower() in {"unknown", "stale", "expired", "invalid"} for value in candidate.freshness.values()):
        unknowns = tuple(dict.fromkeys((*unknowns, "candidate_freshness_requires_probe")))
    risks = ("candidate_has_limitations",) if unknowns else ()
    return MappingProposal(
        journey_session_id=request.journey_session_id,
        user_goal=request.user_goal,
        candidate_id=candidate.candidate_id,
        operation=candidate.operation,
        context_digest=index.context_digest,
        evidence_digest=index.evidence_digest,
        evidence_refs=candidate.evidence_refs,
        risks=risks,
        unknowns=unknowns,
    )


def persist_mapping_proposal(proposal: MappingProposal, root: str | Path) -> Path:
    """Atomically persist a proposal for UI or human review."""

    destination = Path(root)
    destination.mkdir(parents=True, exist_ok=True)
    path = destination / "mapping-proposal.json"
    temporary = path.with_suffix(".json.tmp")
    temporary.write_text(proposal.model_dump_json(indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, path)
    return path


__all__ = ["MappingProposal", "build_mapping_proposal", "persist_mapping_proposal"]
