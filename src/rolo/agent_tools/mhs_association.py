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
    route: str | None = None
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
        return self


def validate_association_payload(payload: dict[str, Any]) -> AssociationReport:
    """Validate a Harness payload without granting authority or execution rights."""

    return AssociationReport.model_validate(payload)


__all__ = ["AssociationReport", "EvidenceRequest", "validate_association_payload"]
