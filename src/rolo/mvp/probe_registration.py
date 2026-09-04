"""Generic Probe-to-Tool registration contracts.

The external Agent harness owns the interactive coding conversation.  Rolo
owns the typed envelope, evidence binding, descriptor validation and the
registration artifact that Trace later consumes.  This keeps the MVP useful
for rotation while avoiding a rotation-specific registry.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from rolo.agent_tools.native_tools import AgentNativeToolDescriptor

_SAFE_ID = re.compile(r"^[a-z][a-z0-9_.-]{1,127}$")


class ProbeAnalysisInput(BaseModel):
    """Bounded input envelope handed from Rolo to an interactive harness."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["rolo-probe-analysis-input/v1"] = "rolo-probe-analysis-input/v1"
    target_id: str = Field(min_length=1, max_length=128)
    target_fingerprint: str = Field(default="UNKNOWN", max_length=128)
    evidence_refs: list[str] = Field(min_length=1, max_length=128)
    candidates: list[dict[str, Any]] = Field(default_factory=list, max_length=128)
    routes: list[dict[str, Any]] = Field(default_factory=list, max_length=256)
    rkb: dict[str, Any] = Field(default_factory=dict)
    mhs: dict[str, Any] = Field(default_factory=dict)
    limitations: list[str] = Field(default_factory=list, max_length=128)
    requested_tool: str | None = Field(default=None, max_length=128)


class ToolRegistrationProposal(BaseModel):
    """Harness output describing one generated, target-bound application tool."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["rolo-tool-registration-proposal/v1"] = "rolo-tool-registration-proposal/v1"
    target_id: str = Field(min_length=1, max_length=128)
    tool_id: str = Field(pattern=_SAFE_ID.pattern)
    evidence_refs: list[str] = Field(min_length=1, max_length=128)
    descriptor: AgentNativeToolDescriptor
    implementation: Literal["descriptor"] = "descriptor"
    code_digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    status: Literal["PROPOSED", "REGISTERED", "BLOCKED"] = "PROPOSED"
    harness_notes: str = Field(default="", max_length=4_000)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @model_validator(mode="after")
    def validate_consistency(self) -> ToolRegistrationProposal:
        if self.descriptor.tool_id != self.tool_id:
            raise ValueError("proposal tool_id must match descriptor.tool_id")
        if self.descriptor.access != "experimental_write":
            raise ValueError("Probe registration currently requires experimental_write access")
        if self.descriptor.risk != "R3":
            raise ValueError("experimental application tools must declare R3 risk")
        if not self.evidence_refs:
            raise ValueError("registration requires at least one evidence reference")
        return self

    def payload(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude={"status"})

    def digest(self) -> str:
        encoded = json.dumps(self.payload(), sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


class ToolRegistrationResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["rolo-tool-registration-result/v1"] = "rolo-tool-registration-result/v1"
    target_id: str
    tool_id: str
    status: Literal["REGISTERED", "BLOCKED"]
    proposal_digest: str
    descriptor_digest: str
    registration_ref: str | None = None
    limitations: list[str] = Field(default_factory=list)


def _descriptor_digest(descriptor: AgentNativeToolDescriptor) -> str:
    encoded = json.dumps(descriptor.model_dump(mode="json"), sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def build_probe_analysis_input(
    *,
    target_id: str,
    evidence_refs: list[str],
    routes: list[Mapping[str, Any]] = (),
    candidates: list[Mapping[str, Any]] = (),
    rkb: Mapping[str, Any] | None = None,
    mhs: Mapping[str, Any] | None = None,
    limitations: list[str] = (),
    requested_tool: str | None = None,
    target_fingerprint: str = "UNKNOWN",
) -> ProbeAnalysisInput:
    return ProbeAnalysisInput(
        target_id=target_id,
        target_fingerprint=target_fingerprint,
        evidence_refs=list(evidence_refs),
        routes=[dict(item) for item in routes],
        candidates=[dict(item) for item in candidates],
        rkb=dict(rkb or {}),
        mhs=dict(mhs or {}),
        limitations=list(limitations),
        requested_tool=requested_tool,
    )


def register_tool_proposal(
    proposal: ToolRegistrationProposal,
    *,
    target_id: str,
    evidence_refs: set[str],
    registry_root: Path,
) -> ToolRegistrationResult:
    """Validate and persist a proposal for later Trace execution.

    MVP deliberately has no separate user approval gate: the interactive
    harness is the review loop.  Rolo still refuses target/evidence mismatches
    and malformed descriptors before publishing the callable artifact.
    """

    if proposal.target_id != target_id:
        return ToolRegistrationResult(
            target_id=target_id,
            tool_id=proposal.tool_id,
            status="BLOCKED",
            proposal_digest=proposal.digest(),
            descriptor_digest=_descriptor_digest(proposal.descriptor),
            limitations=["proposal target does not match Probe target"],
        )
    missing = sorted(set(proposal.evidence_refs) - evidence_refs)
    if missing:
        return ToolRegistrationResult(
            target_id=target_id,
            tool_id=proposal.tool_id,
            status="BLOCKED",
            proposal_digest=proposal.digest(),
            descriptor_digest=_descriptor_digest(proposal.descriptor),
            limitations=[f"proposal references unknown evidence: {missing}"],
        )
    target_dir = registry_root / target_id
    target_dir.mkdir(parents=True, exist_ok=True)
    path = target_dir / f"{proposal.tool_id}.json"
    payload = proposal.model_copy(update={"status": "REGISTERED"}).model_dump(mode="json")
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return ToolRegistrationResult(
        target_id=target_id,
        tool_id=proposal.tool_id,
        status="REGISTERED",
        proposal_digest=proposal.digest(),
        descriptor_digest=_descriptor_digest(proposal.descriptor),
        registration_ref=f"artifact://registered-tools/{target_id}/{proposal.tool_id}.json",
    )


def load_registered_descriptors(registry_root: Path, target_id: str) -> list[AgentNativeToolDescriptor]:
    """Load only descriptors previously registered for one target."""

    directory = registry_root / target_id
    if not directory.is_dir():
        return []
    descriptors: list[AgentNativeToolDescriptor] = []
    for path in sorted(directory.glob("*.json")):
        if path.is_symlink() or not path.is_file():
            continue
        payload = json.loads(path.read_text(encoding="utf-8"))
        if payload.get("status") != "REGISTERED":
            continue
        proposal = ToolRegistrationProposal.model_validate(payload)
        descriptors.append(proposal.descriptor)
    return descriptors


__all__ = [
    "ProbeAnalysisInput",
    "ToolRegistrationProposal",
    "ToolRegistrationResult",
    "build_probe_analysis_input",
    "register_tool_proposal",
    "load_registered_descriptors",
]
