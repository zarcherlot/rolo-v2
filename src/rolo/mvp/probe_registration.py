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
from rolo.core.persistence import atomic_write_text, interprocess_lock
from rolo.dsl.admission import (
    MappingAdmissionError,
    MappingAdmissionGate,
    MappingAdmissionIdentity,
    MappingAdmissionScope,
    MappingConfirmationReceipt,
    MappingConfirmationStore,
    mapping_digest,
)
from rolo.dsl.canonical import dsl_digest
from rolo.dsl.models import DslDocument, OperationKind
from rolo.dsl.parser import loads_unique_json, parse_document
from rolo.dsl.proposal import MappingProposal

_SAFE_ID = re.compile(r"^[a-z][a-z0-9_.-]{1,127}$")
_SAFE_TARGET_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHA256 = r"^sha256:[0-9a-f]{64}$"


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


class ExecutionBinding(BaseModel):
    """Evidence-bound transport binding produced by Probe + interactive Harness."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["rolo-execution-binding/v1"] = "rolo-execution-binding/v1"
    kind: str = Field(pattern=r"^[a-z][a-z0-9_.-]{1,63}$")
    command_endpoint: str = Field(pattern=r"^/[A-Za-z0-9_./-]{1,127}$")
    interface_type: str = Field(min_length=1, max_length=128)
    feedback_endpoints: list[str] = Field(default_factory=list, max_length=8)
    stop_strategy: Literal["zero_velocity", "explicit_endpoint"]
    stop_endpoint: str | None = Field(default=None, pattern=r"^/[A-Za-z0-9_./-]{1,127}$")
    parameter_mapping: dict[str, str] = Field(default_factory=dict, max_length=32)
    evidence_refs: list[str] = Field(min_length=1, max_length=128)

    @model_validator(mode="after")
    def validate_stop(self) -> ExecutionBinding:
        if self.stop_strategy == "explicit_endpoint" and not self.stop_endpoint:
            raise ValueError("explicit_endpoint stop strategy requires stop_endpoint")
        if self.stop_strategy == "zero_velocity" and self.stop_endpoint is not None:
            raise ValueError("zero_velocity stop strategy must not define stop_endpoint")
        if any(not key or not value for key, value in self.parameter_mapping.items()):
            raise ValueError("parameter_mapping keys and values must be non-empty")
        return self

    @property
    def command_resource_id(self) -> str:
        prefix = "ros_topic" if self.kind == "ros2_topic" else self.kind
        return f"{prefix}:{self.command_endpoint}"

    def digest(self) -> str:
        """Return the stable digest submitted by Harness for this binding."""

        encoded = json.dumps(
            self.model_dump(mode="json"), sort_keys=True, separators=(",", ":"), ensure_ascii=True
        )
        return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


class ToolRegistrationProposal(BaseModel):
    """Harness output describing one generated, target-bound application tool."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["rolo-tool-registration-proposal/v1"] = "rolo-tool-registration-proposal/v1"
    target_id: str = Field(min_length=1, max_length=128)
    tool_id: str = Field(pattern=_SAFE_ID.pattern)
    evidence_refs: list[str] = Field(min_length=1, max_length=128)
    descriptor: AgentNativeToolDescriptor
    implementation: Literal["descriptor", "binding"] = "descriptor"
    binding: ExecutionBinding | None = None
    code_digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    binding_digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    codegen_artifact_ref: str | None = Field(default=None, max_length=512)
    codegen_artifact: dict[str, Any] | None = None
    input_contract: dict[str, Any] | None = None
    observation_contract: dict[str, Any] | None = None
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
        if self.implementation == "binding" and self.binding is None:
            raise ValueError("binding implementation requires an execution binding")
        if self.binding is not None:
            missing_binding_evidence = sorted(set(self.binding.evidence_refs) - set(self.evidence_refs))
            if missing_binding_evidence:
                raise ValueError(f"binding references evidence outside proposal: {missing_binding_evidence}")
            if self.binding_digest is not None and self.binding_digest != self.binding.digest():
                raise ValueError("binding_digest does not match binding")
        codegen_fields = (self.codegen_artifact_ref, self.input_contract, self.observation_contract)
        if any(item is not None for item in codegen_fields) and not all(item is not None for item in codegen_fields):
            raise ValueError("codegen_artifact_ref, input_contract and observation_contract must be supplied together")
        if self.input_contract is not None:
            parameters = self.input_contract.get("parameters")
            if not isinstance(parameters, list):
                raise ValueError("input_contract.parameters must be a list")
            expected_names = [item.name for item in self.descriptor.parameters]
            actual_names = [item.get("name") for item in parameters if isinstance(item, dict)]
            if actual_names != expected_names:
                raise ValueError("input_contract.parameters must preserve descriptor parameter order")
        if self.observation_contract is not None:
            fields = self.observation_contract.get("fields")
            if not isinstance(fields, list) or not fields or "status" not in fields or len(fields) != len(set(fields)):
                raise ValueError("observation_contract.fields must be unique and include status")
        if self.codegen_artifact is not None:
            if self.codegen_artifact.get("tool_id") != self.tool_id or self.codegen_artifact.get("target_id") != self.target_id:
                raise ValueError("codegen_artifact target/tool does not match proposal")
            bundle = self.codegen_artifact.get("bundle")
            if not isinstance(bundle, dict) or bundle.get("tool_id") != self.tool_id:
                raise ValueError("codegen_artifact.bundle is missing or mismatched")
            if self.codegen_artifact_ref is None:
                raise ValueError("codegen_artifact requires codegen_artifact_ref")
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
    mapping_proposal_digest: str | None = Field(default=None, pattern=_SHA256)
    confirmation_receipt_digest: str | None = Field(default=None, pattern=_SHA256)
    registration_record_digest: str | None = Field(default=None, pattern=_SHA256)
    limitations: list[str] = Field(default_factory=list)


class RegisteredToolRecord(BaseModel):
    """Immutable registry record carrying the complete Mapping lineage."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    # No default is intentional: legacy hand-written ``REGISTERED`` proposal
    # files are historical data, not callable registration authority.
    schema_version: Literal["rolo-registered-tool/v2"]
    target_id: str = Field(pattern=_SAFE_TARGET_ID.pattern)
    target_fingerprint: str = Field(min_length=1, max_length=256)
    tool_id: str = Field(pattern=_SAFE_ID.pattern)
    proposal: ToolRegistrationProposal
    registration_proposal_digest: str = Field(pattern=_SHA256)
    registration_binding_digest: str | None = Field(default=None, pattern=_SHA256)
    mapping_proposal_digest: str = Field(pattern=_SHA256)
    confirmation_receipt_digest: str = Field(pattern=_SHA256)
    mapping_admission: MappingAdmissionIdentity
    mapping_dsl: DslDocument
    codegen_artifact_digest: str | None = Field(default=None, pattern=_SHA256)
    record_digest: str = Field(pattern=_SHA256)

    @model_validator(mode="after")
    def validate_lineage(self) -> RegisteredToolRecord:
        proposal = ToolRegistrationProposal.model_validate(
            self.proposal.model_dump(mode="python")
        )
        if proposal.status != "PROPOSED":
            raise ValueError("registered proposal must preserve PROPOSED source state")
        if (
            proposal.target_id != self.target_id
            or proposal.tool_id != self.tool_id
            or proposal.descriptor.tool_id != self.tool_id
        ):
            raise ValueError("registered proposal target/tool identity mismatch")
        if self.registration_proposal_digest != _registration_proposal_digest(
            proposal
        ):
            raise ValueError("registered proposal digest mismatch")
        expected_binding_digest = _registration_binding_digest(proposal)
        if self.registration_binding_digest != expected_binding_digest:
            raise ValueError("registered binding digest mismatch")
        lineage = self.mapping_admission
        if (
            lineage.target_id != self.target_id
            or lineage.target_fingerprint != self.target_fingerprint
            or lineage.scope.tool_id != self.tool_id
            or self.tool_id not in lineage.scope.operations
            or lineage.scope.access != proposal.descriptor.access
            or lineage.scope.risk != proposal.descriptor.risk
            or lineage.proposal_digest != self.mapping_proposal_digest
        ):
            raise ValueError("registered Mapping lineage mismatch")
        dsl_error = _registration_dsl_error(
            proposal,
            lineage,
            self.mapping_dsl,
        )
        if dsl_error is not None:
            raise ValueError(f"registered Mapping DSL lineage mismatch: {dsl_error}")
        expected_codegen_digest = (
            mapping_digest(proposal.codegen_artifact)
            if proposal.codegen_artifact is not None
            else None
        )
        if self.codegen_artifact_digest != expected_codegen_digest:
            raise ValueError("registered codegen artifact digest mismatch")
        if self.record_digest != self.computed_digest():
            raise ValueError("registered Tool record digest mismatch")
        return self

    def computed_digest(self) -> str:
        return mapping_digest(
            self.model_dump(mode="json", exclude={"record_digest"})
        )

    @classmethod
    def build(
        cls,
        proposal: ToolRegistrationProposal,
        receipt: MappingConfirmationReceipt,
        mapping_dsl: DslDocument,
    ) -> RegisteredToolRecord:
        lineage = receipt.admission_identity()
        payload: dict[str, Any] = {
            "schema_version": "rolo-registered-tool/v2",
            "target_id": proposal.target_id,
            "target_fingerprint": lineage.target_fingerprint,
            "tool_id": proposal.tool_id,
            "proposal": proposal.model_dump(mode="json"),
            "registration_proposal_digest": _registration_proposal_digest(
                proposal
            ),
            "registration_binding_digest": _registration_binding_digest(proposal),
            "mapping_proposal_digest": lineage.proposal_digest,
            "confirmation_receipt_digest": receipt.receipt_digest,
            "mapping_admission": lineage.model_dump(mode="json"),
            "mapping_dsl": mapping_dsl.model_dump(mode="json"),
            "codegen_artifact_digest": (
                mapping_digest(proposal.codegen_artifact)
                if proposal.codegen_artifact is not None
                else None
            ),
        }
        return cls.model_validate(
            {**payload, "record_digest": mapping_digest(payload)}
        )


def _descriptor_digest(descriptor: AgentNativeToolDescriptor) -> str:
    encoded = json.dumps(descriptor.model_dump(mode="json"), sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _registration_proposal_digest(proposal: ToolRegistrationProposal) -> str:
    return "sha256:" + proposal.digest()


def _registration_binding_digest(
    proposal: ToolRegistrationProposal,
) -> str | None:
    return "sha256:" + proposal.binding.digest() if proposal.binding is not None else None


def _blocked_registration(
    proposal: ToolRegistrationProposal,
    *,
    target_id: str,
    code: str,
    receipt_digest: str | None = None,
    mapping_proposal_digest: str | None = None,
) -> ToolRegistrationResult:
    try:
        proposal_digest = proposal.digest()
    except (AttributeError, TypeError, ValueError):
        proposal_digest = "INVALID"
    try:
        descriptor_digest = _descriptor_digest(proposal.descriptor)
    except (AttributeError, TypeError, ValueError):
        descriptor_digest = "INVALID"
    tool_id = getattr(proposal, "tool_id", "INVALID")
    safe_receipt_digest = (
        receipt_digest
        if isinstance(receipt_digest, str) and re.fullmatch(_SHA256, receipt_digest)
        else None
    )
    safe_mapping_proposal_digest = (
        mapping_proposal_digest
        if isinstance(mapping_proposal_digest, str)
        and re.fullmatch(_SHA256, mapping_proposal_digest)
        else None
    )
    return ToolRegistrationResult(
        target_id=target_id,
        tool_id=tool_id,
        status="BLOCKED",
        proposal_digest=proposal_digest,
        descriptor_digest=descriptor_digest,
        mapping_proposal_digest=safe_mapping_proposal_digest,
        confirmation_receipt_digest=safe_receipt_digest,
        limitations=[code],
    )


def _current_registration_identity(
    proposal: ToolRegistrationProposal,
    mapping_proposal: MappingProposal,
    *,
    journey_session_id: str,
    target_id: str,
    target_fingerprint: str,
) -> MappingAdmissionIdentity:
    """Overlay registry-owned identity on the currently reviewed Proposal."""

    reviewed = mapping_proposal.admission_identity()
    scope = MappingAdmissionScope(
        tool_id=proposal.tool_id,
        operation_kind=reviewed.scope.operation_kind,
        operations=reviewed.scope.operations,
        access=proposal.descriptor.access,
        risk=proposal.descriptor.risk,
    )
    return MappingAdmissionIdentity.build(
        journey_session_id=journey_session_id,
        target_id=target_id,
        target_fingerprint=target_fingerprint,
        candidate_index_digest=reviewed.candidate_index_digest,
        candidate_digest=reviewed.candidate_digest,
        proposal_digest=reviewed.proposal_digest,
        dsl_digest=reviewed.dsl_digest,
        context_digest=reviewed.context_digest,
        evidence_digest=reviewed.evidence_digest,
        available_tool_catalog_digest=reviewed.available_tool_catalog_digest,
        scope=scope,
    )


def _registration_dsl_error(
    proposal: ToolRegistrationProposal,
    reviewed: MappingAdmissionIdentity,
    mapping_dsl: DslDocument | Mapping[str, Any],
) -> str | None:
    """Return why the reviewed DSL does not cover the callable proposal."""

    payload = (
        mapping_dsl.model_dump(mode="json")
        if isinstance(mapping_dsl, DslDocument)
        else dict(mapping_dsl)
    )
    document, report = parse_document(payload)
    if document is None or not report.ok:
        return "MAPPING_REGISTRATION_DSL_INVALID"
    if dsl_digest(document) != reviewed.dsl_digest:
        return "MAPPING_DSL_DIGEST_MISMATCH"
    if (
        document.tool_id != proposal.tool_id
        or reviewed.scope.tool_id != proposal.tool_id
        or proposal.tool_id not in reviewed.scope.operations
    ):
        return "MAPPING_REGISTRATION_TOOL_MISMATCH"
    if document.target.robot_id != reviewed.target_id:
        return "MAPPING_PROPOSAL_TARGET_MISMATCH"
    if document.target.evidence_digest != reviewed.evidence_digest:
        return "MAPPING_EVIDENCE_DIGEST_MISMATCH"
    if reviewed.scope.operation_kind != document.kind:
        return "MAPPING_SCOPE_MISMATCH"
    if not set(proposal.evidence_refs).issubset(document.evidence_refs):
        return "MAPPING_REGISTRATION_EVIDENCE_NOT_IN_DSL"

    if document.kind == OperationKind.EXECUTE:
        executable_identity = document.implementation
    elif document.kind == OperationKind.INVOKE:
        executable_identity = document.binding
        if document.binding.get("operation") != proposal.tool_id:
            return "MAPPING_REGISTRATION_BINDING_OPERATION_MISMATCH"
    else:
        return "MAPPING_REGISTRATION_DSL_KIND_UNSUPPORTED"

    if (
        executable_identity.get("registration_proposal_digest")
        != _registration_proposal_digest(proposal)
    ):
        return "MAPPING_REGISTRATION_PROPOSAL_DIGEST_MISMATCH"
    if (
        executable_identity.get("descriptor_digest")
        != "sha256:" + _descriptor_digest(proposal.descriptor)
    ):
        return "MAPPING_REGISTRATION_DESCRIPTOR_DIGEST_MISMATCH"
    if executable_identity.get("implementation_kind") != proposal.implementation:
        return "MAPPING_REGISTRATION_IMPLEMENTATION_MISMATCH"
    if executable_identity.get("binding_digest") != _registration_binding_digest(
        proposal
    ):
        return "MAPPING_REGISTRATION_BINDING_DIGEST_MISMATCH"
    return None


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
    observed_route_ids: set[str] | None = None,
    registry_root: Path,
    mapping_proposal: MappingProposal | None = None,
    mapping_dsl: DslDocument | Mapping[str, Any] | None = None,
    confirmation_store: MappingConfirmationStore | None = None,
    confirmation_receipt_digest: str | None = None,
    journey_session_id: str | None = None,
    target_fingerprint: str | None = None,
    now: datetime | None = None,
) -> ToolRegistrationResult:
    """Register only a proposal covered by a committed active confirmation.

    A caller-provided receipt is never trusted.  The function verifies the
    currently reviewed Mapping Proposal, overlays the current registration
    target/tool/scope, proves that its complete callable identity is covered
    by the Proposal's DSL, and resolves the receipt from
    ``confirmation_store`` before writing any file.
    """

    try:
        proposal = ToolRegistrationProposal.model_validate(
            proposal.model_dump(mode="python")
        )
    except (AttributeError, TypeError, ValueError):
        return _blocked_registration(
            proposal,
            target_id=target_id,
            code="MAPPING_REGISTRATION_PROPOSAL_INVALID",
        )
    if proposal.status != "PROPOSED":
        return _blocked_registration(
            proposal,
            target_id=target_id,
            code="MAPPING_REGISTRATION_PROPOSAL_NOT_PROPOSED",
        )
    if mapping_proposal is None:
        return _blocked_registration(
            proposal,
            target_id=target_id,
            code="MAPPING_PROPOSAL_REQUIRED",
        )
    try:
        mapping_proposal = MappingProposal.model_validate(
            mapping_proposal.model_dump(mode="python")
        )
        mapping_proposal.verify()
    except (AttributeError, MappingAdmissionError, TypeError, ValueError):
        return _blocked_registration(
            proposal,
            target_id=target_id,
            code="MAPPING_PROPOSAL_INVALID",
        )
    if mapping_dsl is None:
        return _blocked_registration(
            proposal,
            target_id=target_id,
            code="MAPPING_REGISTRATION_DSL_REQUIRED",
            mapping_proposal_digest=mapping_proposal.proposal_digest,
        )
    try:
        normalized_mapping_dsl = DslDocument.model_validate(
            mapping_dsl.model_dump(mode="python")
            if isinstance(mapping_dsl, DslDocument)
            else dict(mapping_dsl)
        )
        dsl_error = _registration_dsl_error(
            proposal,
            mapping_proposal.admission_identity(),
            normalized_mapping_dsl,
        )
    except (TypeError, ValueError):
        dsl_error = "MAPPING_REGISTRATION_DSL_INVALID"
    if dsl_error is not None:
        return _blocked_registration(
            proposal,
            target_id=target_id,
            code=dsl_error,
            mapping_proposal_digest=mapping_proposal.proposal_digest,
        )
    if confirmation_store is None:
        return _blocked_registration(
            proposal,
            target_id=target_id,
            code="MAPPING_CONFIRMATION_STORE_REQUIRED",
        )
    if not confirmation_receipt_digest:
        return _blocked_registration(
            proposal,
            target_id=target_id,
            code="MAPPING_CONFIRMATION_REQUIRED",
        )
    if not journey_session_id:
        return _blocked_registration(
            proposal,
            target_id=target_id,
            code="MAPPING_JOURNEY_SESSION_REQUIRED",
            receipt_digest=confirmation_receipt_digest,
        )
    if not target_fingerprint:
        return _blocked_registration(
            proposal,
            target_id=target_id,
            code="MAPPING_TARGET_FINGERPRINT_REQUIRED",
            receipt_digest=confirmation_receipt_digest,
        )
    if proposal.target_id != target_id:
        return _blocked_registration(
            proposal,
            target_id=target_id,
            code="MAPPING_TARGET_ID_MISMATCH",
            receipt_digest=confirmation_receipt_digest,
            mapping_proposal_digest=mapping_proposal.proposal_digest,
        )
    if mapping_proposal.target_id != target_id:
        return _blocked_registration(
            proposal,
            target_id=target_id,
            code="MAPPING_PROPOSAL_TARGET_MISMATCH",
            receipt_digest=confirmation_receipt_digest,
            mapping_proposal_digest=mapping_proposal.proposal_digest,
        )
    if mapping_proposal.target_fingerprint != target_fingerprint:
        return _blocked_registration(
            proposal,
            target_id=target_id,
            code="MAPPING_TARGET_FINGERPRINT_MISMATCH",
            receipt_digest=confirmation_receipt_digest,
            mapping_proposal_digest=mapping_proposal.proposal_digest,
        )
    if mapping_proposal.journey_session_id != journey_session_id:
        return _blocked_registration(
            proposal,
            target_id=target_id,
            code="MAPPING_JOURNEY_SESSION_MISMATCH",
            receipt_digest=confirmation_receipt_digest,
            mapping_proposal_digest=mapping_proposal.proposal_digest,
        )
    if mapping_proposal.operation != proposal.tool_id:
        return _blocked_registration(
            proposal,
            target_id=target_id,
            code="MAPPING_REGISTRATION_TOOL_MISMATCH",
            receipt_digest=confirmation_receipt_digest,
            mapping_proposal_digest=mapping_proposal.proposal_digest,
        )
    missing = sorted(set(proposal.evidence_refs) - evidence_refs)
    if missing:
        return _blocked_registration(
            proposal,
            target_id=target_id,
            code=f"MAPPING_REGISTRATION_EVIDENCE_UNKNOWN:{missing}",
            receipt_digest=confirmation_receipt_digest,
            mapping_proposal_digest=mapping_proposal.proposal_digest,
        )
    outside_review = sorted(
        set(proposal.evidence_refs) - set(mapping_proposal.evidence_refs)
    )
    if outside_review:
        return _blocked_registration(
            proposal,
            target_id=target_id,
            code=f"MAPPING_REGISTRATION_EVIDENCE_NOT_REVIEWED:{outside_review}",
            receipt_digest=confirmation_receipt_digest,
            mapping_proposal_digest=mapping_proposal.proposal_digest,
        )
    if proposal.binding is not None:
        if proposal.binding_digest is None:
            return _blocked_registration(
                proposal,
                target_id=target_id,
                code="MAPPING_REGISTRATION_BINDING_DIGEST_REQUIRED",
                receipt_digest=confirmation_receipt_digest,
                mapping_proposal_digest=mapping_proposal.proposal_digest,
            )
        if observed_route_ids is None:
            return _blocked_registration(
                proposal,
                target_id=target_id,
                code="MAPPING_REGISTRATION_OBSERVED_ROUTES_REQUIRED",
                receipt_digest=confirmation_receipt_digest,
                mapping_proposal_digest=mapping_proposal.proposal_digest,
            )
        if proposal.binding.command_resource_id not in observed_route_ids:
            return _blocked_registration(
                proposal,
                target_id=target_id,
                code=f"MAPPING_REGISTRATION_BINDING_NOT_OBSERVED:{proposal.binding.command_resource_id}",
                receipt_digest=confirmation_receipt_digest,
                mapping_proposal_digest=mapping_proposal.proposal_digest,
            )
        prefix = "ros_topic" if proposal.binding.kind == "ros2_topic" else proposal.binding.kind
        missing_feedback = sorted(
            f"{prefix}:{endpoint}"
            for endpoint in proposal.binding.feedback_endpoints
            if f"{prefix}:{endpoint}" not in observed_route_ids
        )
        if missing_feedback:
            return _blocked_registration(
                proposal,
                target_id=target_id,
                code=f"MAPPING_REGISTRATION_FEEDBACK_NOT_OBSERVED:{missing_feedback}",
                receipt_digest=confirmation_receipt_digest,
                mapping_proposal_digest=mapping_proposal.proposal_digest,
            )
    try:
        expected = _current_registration_identity(
            proposal,
            mapping_proposal,
            journey_session_id=journey_session_id,
            target_id=target_id,
            target_fingerprint=target_fingerprint,
        )
        receipt = MappingAdmissionGate(confirmation_store).require_active(
            confirmation_receipt_digest,
            expected,
            now=now,
        )
    except (MappingAdmissionError, ValueError) as exc:
        code = exc.code if isinstance(exc, MappingAdmissionError) else "MAPPING_REGISTRATION_IDENTITY_INVALID"
        return _blocked_registration(
            proposal,
            target_id=target_id,
            code=code,
            receipt_digest=confirmation_receipt_digest,
            mapping_proposal_digest=mapping_proposal.proposal_digest,
        )

    record = RegisteredToolRecord.build(proposal, receipt, normalized_mapping_dsl)
    try:
        _persist_registered_record(record, registry_root)
    except (OSError, ValueError, MappingAdmissionError):
        return _blocked_registration(
            proposal,
            target_id=target_id,
            code="MAPPING_REGISTRATION_IMMUTABLE_CONFLICT",
            receipt_digest=receipt.receipt_digest,
            mapping_proposal_digest=receipt.proposal_digest,
        )
    return ToolRegistrationResult(
        target_id=target_id,
        tool_id=proposal.tool_id,
        status="REGISTERED",
        proposal_digest=proposal.digest(),
        descriptor_digest=_descriptor_digest(proposal.descriptor),
        registration_ref=f"artifact://registered-tools/{target_id}/{proposal.tool_id}.json",
        mapping_proposal_digest=receipt.proposal_digest,
        confirmation_receipt_digest=receipt.receipt_digest,
        registration_record_digest=record.record_digest,
    )


def _persist_registered_record(
    record: RegisteredToolRecord, registry_root: Path
) -> Path:
    root = Path(registry_root)
    if root.is_symlink() or not _SAFE_TARGET_ID.fullmatch(record.target_id):
        raise MappingAdmissionError("MAPPING_REGISTRY_UNTRUSTED")
    target_dir = root / record.target_id
    path = target_dir / f"{record.tool_id}.json"
    artifact_path = target_dir / "generated" / f"{record.tool_id}.json"
    lock_path = root / ".registration.lock"
    with interprocess_lock(lock_path):
        if target_dir.is_symlink() or path.is_symlink():
            raise MappingAdmissionError("MAPPING_REGISTRY_UNTRUSTED")
        existing = _read_registered_record(path) if path.exists() else None
        if existing is not None and existing != record:
            raise MappingAdmissionError("MAPPING_REGISTRATION_IMMUTABLE_CONFLICT")
        if record.codegen_artifact_digest is not None:
            _verify_or_write_codegen(record, artifact_path, write=True)
        elif artifact_path.exists():
            raise MappingAdmissionError("MAPPING_REGISTRATION_ORPHAN_CODEGEN")
        if existing is None:
            atomic_write_text(
                path,
                json.dumps(
                    record.model_dump(mode="json"),
                    ensure_ascii=False,
                    sort_keys=True,
                    indent=2,
                )
                + "\n",
                acquire_lock=False,
                require_absent=True,
            )
    return path


def _read_registered_record(path: Path) -> RegisteredToolRecord:
    if path.is_symlink() or not path.is_file():
        raise MappingAdmissionError("MAPPING_REGISTRATION_RECORD_UNTRUSTED")
    try:
        payload = loads_unique_json(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("registration record must be an object")
        return RegisteredToolRecord.model_validate(payload)
    except (OSError, ValueError) as exc:
        raise MappingAdmissionError("MAPPING_REGISTRATION_RECORD_INVALID") from exc


def _verify_or_write_codegen(
    record: RegisteredToolRecord,
    path: Path,
    *,
    write: bool,
) -> dict[str, Any] | None:
    expected = record.proposal.codegen_artifact
    if record.codegen_artifact_digest is None:
        if path.exists():
            raise MappingAdmissionError("MAPPING_REGISTRATION_ORPHAN_CODEGEN")
        return None
    if expected is None:
        raise MappingAdmissionError("MAPPING_REGISTRATION_CODEGEN_LINEAGE_INVALID")
    if path.exists():
        if path.is_symlink() or not path.is_file():
            raise MappingAdmissionError("MAPPING_REGISTRATION_CODEGEN_UNTRUSTED")
        try:
            payload = loads_unique_json(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise MappingAdmissionError("MAPPING_REGISTRATION_CODEGEN_INVALID") from exc
        if not isinstance(payload, dict):
            raise MappingAdmissionError("MAPPING_REGISTRATION_CODEGEN_INVALID")
    elif write:
        if path.parent.is_symlink():
            raise MappingAdmissionError("MAPPING_REGISTRATION_CODEGEN_UNTRUSTED")
        atomic_write_text(
            path,
            json.dumps(expected, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
            acquire_lock=False,
            require_absent=True,
        )
        payload = expected
    else:
        raise MappingAdmissionError("MAPPING_REGISTRATION_CODEGEN_MISSING")
    if (
        mapping_digest(payload) != record.codegen_artifact_digest
        or payload != expected
        or payload.get("target_id") != record.target_id
        or payload.get("tool_id") != record.tool_id
    ):
        raise MappingAdmissionError("MAPPING_REGISTRATION_CODEGEN_DIGEST_MISMATCH")
    return payload


def _verified_registered_records(
    registry_root: Path,
    target_id: str,
    *,
    confirmation_store: MappingConfirmationStore | None,
    target_fingerprint: str | None,
    now: datetime | None,
) -> tuple[RegisteredToolRecord, ...]:
    if confirmation_store is None:
        raise MappingAdmissionError("MAPPING_CONFIRMATION_STORE_REQUIRED")
    if not target_fingerprint:
        raise MappingAdmissionError("MAPPING_TARGET_FINGERPRINT_REQUIRED")
    if not _SAFE_TARGET_ID.fullmatch(target_id):
        raise MappingAdmissionError("MAPPING_TARGET_ID_INVALID")
    root = Path(registry_root)
    directory = root / target_id
    if root.is_symlink() or directory.is_symlink() or not directory.is_dir():
        return ()
    records: list[RegisteredToolRecord] = []
    for path in sorted(directory.glob("*.json")):
        try:
            record = _read_registered_record(path)
            if (
                record.target_id != target_id
                or record.target_fingerprint != target_fingerprint
                or path.stem != record.tool_id
            ):
                raise MappingAdmissionError("MAPPING_REGISTRATION_TARGET_MISMATCH")
            lineage = record.mapping_admission
            scope = MappingAdmissionScope(
                tool_id=record.proposal.tool_id,
                operation_kind=lineage.scope.operation_kind,
                operations=lineage.scope.operations,
                access=record.proposal.descriptor.access,
                risk=record.proposal.descriptor.risk,
            )
            expected = MappingAdmissionIdentity.build(
                journey_session_id=lineage.journey_session_id,
                target_id=target_id,
                target_fingerprint=target_fingerprint,
                candidate_index_digest=lineage.candidate_index_digest,
                candidate_digest=lineage.candidate_digest,
                proposal_digest=record.mapping_proposal_digest,
                dsl_digest=lineage.dsl_digest,
                context_digest=lineage.context_digest,
                evidence_digest=lineage.evidence_digest,
                available_tool_catalog_digest=lineage.available_tool_catalog_digest,
                scope=scope,
            )
            receipt = MappingAdmissionGate(confirmation_store).require_active(
                record.confirmation_receipt_digest,
                expected,
                now=now,
            )
            if receipt.admission_identity() != lineage:
                raise MappingAdmissionError("MAPPING_REGISTRATION_LINEAGE_MISMATCH")
            generated = directory / "generated" / f"{record.tool_id}.json"
            _verify_or_write_codegen(record, generated, write=False)
        except (OSError, ValueError, MappingAdmissionError):
            # A corrupt, legacy, cross-target, expired, or unconfirmed record
            # must never be projected into the callable registry surface.
            continue
        records.append(record)
    return tuple(records)


def load_registered_descriptors(
    registry_root: Path,
    target_id: str,
    *,
    confirmation_store: MappingConfirmationStore | None = None,
    target_fingerprint: str | None = None,
    now: datetime | None = None,
) -> list[AgentNativeToolDescriptor]:
    """Load descriptors only from active, target-bound registration records."""

    return [
        record.proposal.descriptor
        for record in _verified_registered_records(
            registry_root,
            target_id,
            confirmation_store=confirmation_store,
            target_fingerprint=target_fingerprint,
            now=now,
        )
        if record.proposal.implementation == "descriptor"
    ]


def load_registered_bindings(
    registry_root: Path,
    target_id: str,
    *,
    confirmation_store: MappingConfirmationStore | None = None,
    target_fingerprint: str | None = None,
    now: datetime | None = None,
) -> list[ExecutionBinding]:
    """Load bindings only from active, target-bound registration records."""

    return [
        record.proposal.binding
        for record in _verified_registered_records(
            registry_root,
            target_id,
            confirmation_store=confirmation_store,
            target_fingerprint=target_fingerprint,
            now=now,
        )
        if record.proposal.implementation == "binding"
        and record.proposal.binding is not None
    ]


def load_registered_proposals(
    registry_root: Path,
    target_id: str,
    *,
    confirmation_store: MappingConfirmationStore | None = None,
    target_fingerprint: str | None = None,
    now: datetime | None = None,
) -> list[ToolRegistrationProposal]:
    """Load source proposals only after revalidating their Mapping lineage."""

    return [
        record.proposal
        for record in _verified_registered_records(
            registry_root,
            target_id,
            confirmation_store=confirmation_store,
            target_fingerprint=target_fingerprint,
            now=now,
        )
    ]


def load_registered_codegen_artifact(
    registry_root: Path,
    target_id: str,
    tool_id: str,
    *,
    confirmation_store: MappingConfirmationStore | None = None,
    target_fingerprint: str | None = None,
    now: datetime | None = None,
) -> dict[str, Any] | None:
    """Load codegen only through its active registration and receipt lineage."""

    record = next(
        (
            item
            for item in _verified_registered_records(
                registry_root,
                target_id,
                confirmation_store=confirmation_store,
                target_fingerprint=target_fingerprint,
                now=now,
            )
            if item.tool_id == tool_id
        ),
        None,
    )
    if record is None or record.codegen_artifact_digest is None:
        return None
    try:
        return _verify_or_write_codegen(
            record,
            Path(registry_root) / target_id / "generated" / f"{tool_id}.json",
            write=False,
        )
    except (OSError, ValueError, MappingAdmissionError):
        return None


__all__ = [
    "ExecutionBinding",
    "ProbeAnalysisInput",
    "RegisteredToolRecord",
    "ToolRegistrationProposal",
    "ToolRegistrationResult",
    "build_probe_analysis_input",
    "register_tool_proposal",
    "load_registered_descriptors",
    "load_registered_bindings",
    "load_registered_proposals",
    "load_registered_codegen_artifact",
]
