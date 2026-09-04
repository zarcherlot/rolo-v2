"""Untrusted, read-only association reports returned by external Harnesses."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class EvidenceRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: Literal["ROUTE_OBSERVATION", "MANIFEST_INSPECTION", "HARDWARE_INSPECTION"]
    subject_ref: str = Field(min_length=1, max_length=256)
    reason: str = Field(min_length=8, max_length=1000)


class AssociationReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["rolo-mhs-association-report/v1"] = "rolo-mhs-association-report/v1"
    target_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    status: Literal["PROPOSED", "UNKNOWN", "UNSUPPORTED"]
    evidence_refs: list[str] = Field(default_factory=list, max_length=64)
    # Association consumes routes from multiple Probe transports (MHS, ROS,
    # serial, ...); keep this bounded without narrowing the route vocabulary.
    route: str | None = Field(default=None, min_length=1, max_length=256)
    manifest_digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    requests: list[EvidenceRequest] = Field(default_factory=list, max_length=16)
    limitations: list[str] = Field(default_factory=list, max_length=64)
    access: Literal["READ_ONLY"] = "READ_ONLY"
    write_requests: int = Field(default=0, ge=0)

    @model_validator(mode="after")
    def fail_closed(self) -> AssociationReport:
        if self.write_requests != 0:
            raise ValueError("association reports cannot contain write requests")
        if self.status == "PROPOSED" and not self.evidence_refs:
            raise ValueError("PROPOSED association requires evidence_refs")
        if len(set(self.evidence_refs)) != len(self.evidence_refs):
            raise ValueError("association evidence_refs must be unique")
        if any(not ref.strip() or len(ref) > 256 for ref in self.evidence_refs):
            raise ValueError("association evidence_refs must be bounded non-empty strings")
        if self.status == "PROPOSED" and self.route is None:
            raise ValueError("PROPOSED association requires a canonical MHS route")
        return self


def validate_association_payload(payload: dict[str, Any]) -> AssociationReport:
    """Validate a Harness payload without granting authority or execution rights."""

    if not isinstance(payload, dict):
        raise TypeError("association payload must be an object")
    return AssociationReport.model_validate(payload)


__all__ = ["AssociationReport", "EvidenceRequest", "validate_association_payload"]
