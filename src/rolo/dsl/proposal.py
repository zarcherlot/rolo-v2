"""Immutable, digest-bound Mapping proposal shown before confirmation."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any, Literal

from pydantic import Field, field_validator, model_validator

from rolo.core.persistence import atomic_write_text, interprocess_lock

from .admission import (
    MappingAdmissionError,
    MappingAdmissionIdentity,
    MappingAdmissionScope,
    mapping_digest,
)
from .candidates import CapabilityCandidate, CapabilityCandidateIndex
from .canonical import context_digest, dsl_digest
from .context import ProbeContext
from .contracts import MAPPING_PROPOSAL_SCHEMA_VERSION
from .mapping import AdapterMappingRequest
from .models import DslDocument, StrictModel
from .parser import parse_document

_DIGEST_PATTERN = r"^sha256:[0-9a-f]{64}$"


class MappingProposal(StrictModel):
    """Complete read-only payload submitted to the confirmation authority.

    A Proposal is never an authorization object. Its digest covers every
    field displayed for review, while a separate, committed confirmation
    receipt is the only object accepted by post-confirmation consumers.
    """

    # No default: a missing version must not be upgraded silently at this
    # security boundary.
    schema_version: Literal["rolo-mapping-proposal/v2"]
    journey_session_id: str = Field(min_length=1, max_length=256)
    user_goal: str = Field(min_length=1, max_length=2_000)
    target_id: str = Field(min_length=1, max_length=128)
    target_fingerprint: str = Field(min_length=1, max_length=256)
    candidate_index_digest: str = Field(pattern=_DIGEST_PATTERN)
    candidate_digest: str = Field(pattern=_DIGEST_PATTERN)
    candidate_id: str = Field(min_length=1, max_length=256)
    operation: str = Field(min_length=1, max_length=256)
    dsl_digest: str = Field(pattern=_DIGEST_PATTERN)
    context_digest: str = Field(pattern=_DIGEST_PATTERN)
    evidence_digest: str = Field(pattern=_DIGEST_PATTERN)
    available_tool_catalog_digest: str = Field(pattern=_DIGEST_PATTERN)
    scope: MappingAdmissionScope
    evidence_refs: tuple[str, ...] = Field(min_length=1, max_length=32)
    risks: tuple[str, ...] = Field(default_factory=tuple, max_length=32)
    unknowns: tuple[str, ...] = Field(default_factory=tuple, max_length=32)
    requested_actions: tuple[str, ...] = Field(
        default_factory=lambda: ("user_confirmation",), min_length=1, max_length=16
    )
    status: Literal["PROPOSED"] = "PROPOSED"
    proposal_digest: str = Field(pattern=_DIGEST_PATTERN)

    @field_validator("target_fingerprint")
    @classmethod
    def known_target_fingerprint(cls, value: str) -> str:
        if value != value.strip() or value.upper() == "UNKNOWN":
            raise ValueError("Mapping Proposal requires a known target fingerprint")
        return value

    @field_validator("evidence_refs", "risks", "unknowns", "requested_actions")
    @classmethod
    def stable_strings(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if any(
            not isinstance(item, str)
            or not item
            or item != item.strip()
            for item in value
        ):
            raise ValueError("Mapping Proposal lists must contain normalized strings")
        return tuple(sorted(set(value)))

    @model_validator(mode="after")
    def verify_identity_and_digest(self) -> MappingProposal:
        if self.requested_actions != ("user_confirmation",):
            raise ValueError("Mapping Proposal must request only user confirmation")
        if self.scope.tool_id != self.operation:
            raise ValueError("Mapping Proposal scope does not match operation")
        if self.operation not in self.scope.operations:
            raise ValueError("Mapping Proposal operation is outside scope")
        if self.proposal_digest != self.computed_digest():
            raise ValueError("Mapping Proposal digest mismatch")
        # Re-validate the complete identity through the shared admission API.
        self.admission_identity()
        return self

    def display_payload(self) -> dict[str, Any]:
        """Return the complete human-review payload covered by the digest."""

        return self.model_dump(mode="json", exclude={"proposal_digest"})

    def computed_digest(self) -> str:
        return mapping_digest(self.display_payload())

    def verify(self) -> None:
        if self.proposal_digest != self.computed_digest():
            raise MappingAdmissionError("MAPPING_PROPOSAL_DIGEST_MISMATCH")
        self.admission_identity()

    def admission_identity(self) -> MappingAdmissionIdentity:
        """Project the reviewed payload into the shared receipt identity."""

        return MappingAdmissionIdentity.build(
            journey_session_id=self.journey_session_id,
            target_id=self.target_id,
            target_fingerprint=self.target_fingerprint,
            candidate_index_digest=self.candidate_index_digest,
            candidate_digest=self.candidate_digest,
            proposal_digest=self.proposal_digest,
            dsl_digest=self.dsl_digest,
            context_digest=self.context_digest,
            evidence_digest=self.evidence_digest,
            available_tool_catalog_digest=self.available_tool_catalog_digest,
            scope=self.scope,
        )

    def confirm(self) -> MappingProposal:
        """Reject the legacy status mutation; confirmation requires a receipt."""

        raise MappingAdmissionError("MAPPING_CONFIRMATION_RECEIPT_REQUIRED")

    def reject(self) -> MappingProposal:
        """Reject legacy status mutation; rejection is also a ledger decision."""

        raise MappingAdmissionError("MAPPING_CONFIRMATION_RECEIPT_REQUIRED")


def build_mapping_proposal(
    request: AdapterMappingRequest,
    index: CapabilityCandidateIndex,
    candidate: CapabilityCandidate,
    *,
    dsl: DslDocument | Mapping[str, Any],
    context: ProbeContext | Mapping[str, Any],
    scope: MappingAdmissionScope | Mapping[str, Any],
) -> MappingProposal:
    """Build one proposal only when every observed and requested identity agrees."""

    index.verify()
    context_model = (
        context if isinstance(context, ProbeContext) else ProbeContext.model_validate(context)
    )
    actual_context_digest = context_digest(context_model)
    if request.context_digest != actual_context_digest or index.context_digest != actual_context_digest:
        raise MappingAdmissionError("MAPPING_PROPOSAL_CONTEXT_DIGEST_MISMATCH")
    if candidate not in index.candidates:
        raise MappingAdmissionError("MAPPING_PROPOSAL_CANDIDATE_NOT_IN_INDEX")
    if candidate.operation not in request.operation_candidates:
        raise MappingAdmissionError("MAPPING_PROPOSAL_CANDIDATE_NOT_REQUESTED")
    if (
        index.robot_id != context_model.robot_id
        or index.target_fingerprint != context_model.target_fingerprint
        or index.evidence_digest != context_model.evidence_digest
    ):
        raise MappingAdmissionError("MAPPING_PROPOSAL_CONTEXT_IDENTITY_MISMATCH")

    dsl_payload = (
        dsl.model_dump(mode="json") if isinstance(dsl, DslDocument) else dict(dsl)
    )
    document, report = parse_document(dsl_payload)
    if document is None or not report.ok:
        raise MappingAdmissionError("MAPPING_PROPOSAL_DSL_INVALID")
    if document.tool_id != candidate.operation:
        raise MappingAdmissionError("MAPPING_PROPOSAL_DSL_CANDIDATE_MISMATCH")
    if (
        document.target.robot_id != context_model.robot_id
        or document.target.evidence_digest != context_model.evidence_digest
    ):
        raise MappingAdmissionError("MAPPING_PROPOSAL_DSL_CONTEXT_MISMATCH")

    scope_model = (
        scope
        if isinstance(scope, MappingAdmissionScope)
        else MappingAdmissionScope.model_validate(scope)
    )
    if (
        scope_model.tool_id != document.tool_id
        or scope_model.operation_kind != document.kind
        or candidate.operation not in scope_model.operations
    ):
        raise MappingAdmissionError("MAPPING_PROPOSAL_SCOPE_MISMATCH")

    unknowns = tuple(dict.fromkeys((*candidate.gaps, *candidate.missing_evidence)))
    if any(
        str(value).lower() in {"unknown", "stale", "expired", "invalid"}
        for value in candidate.freshness.values()
    ):
        unknowns = tuple(dict.fromkeys((*unknowns, "candidate_freshness_requires_probe")))
    risks = ("candidate_has_limitations",) if unknowns else ()
    evidence_refs = tuple(sorted(set((*candidate.evidence_refs, *document.evidence_refs))))
    candidate_index_digest = "sha256:" + index.index_digest
    candidate_digest = mapping_digest(candidate)
    payload: dict[str, Any] = {
        "schema_version": MAPPING_PROPOSAL_SCHEMA_VERSION,
        "journey_session_id": request.journey_session_id,
        "user_goal": request.user_goal,
        "target_id": context_model.robot_id,
        "target_fingerprint": context_model.target_fingerprint,
        "candidate_index_digest": candidate_index_digest,
        "candidate_digest": candidate_digest,
        "candidate_id": candidate.candidate_id,
        "operation": candidate.operation,
        "dsl_digest": dsl_digest(document),
        "context_digest": actual_context_digest,
        "evidence_digest": context_model.evidence_digest,
        "available_tool_catalog_digest": request.available_tool_catalog_digest,
        "scope": scope_model.model_dump(mode="json"),
        "evidence_refs": evidence_refs,
        "risks": risks,
        "unknowns": unknowns,
        "requested_actions": ("user_confirmation",),
        "status": "PROPOSED",
    }
    return MappingProposal.model_validate(
        {**payload, "proposal_digest": mapping_digest(payload)}
    )


def persist_mapping_proposal(proposal: MappingProposal, root: str | Path) -> Path:
    """Persist one verified Proposal by digest without ever replacing content."""

    proposal.verify()
    directory = Path(root) / "mapping-proposals"
    if directory.is_symlink():
        raise MappingAdmissionError("MAPPING_PROPOSAL_STORE_UNTRUSTED")
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{proposal.proposal_digest.removeprefix('sha256:')}.json"
    serialized = proposal.model_dump_json(indent=2) + "\n"
    with interprocess_lock(path):
        if path.exists():
            if path.is_symlink() or not path.is_file():
                raise MappingAdmissionError("MAPPING_PROPOSAL_STORE_UNTRUSTED")
            try:
                existing = MappingProposal.model_validate_json(
                    path.read_text(encoding="utf-8")
                )
            except (OSError, ValueError) as exc:
                raise MappingAdmissionError(
                    "MAPPING_PROPOSAL_IMMUTABLE_CONFLICT"
                ) from exc
            if existing != proposal:
                raise MappingAdmissionError("MAPPING_PROPOSAL_IMMUTABLE_CONFLICT")
            return path
        atomic_write_text(
            path,
            serialized,
            acquire_lock=False,
            require_absent=True,
        )
    return path


__all__ = ["MappingProposal", "build_mapping_proposal", "persist_mapping_proposal"]
