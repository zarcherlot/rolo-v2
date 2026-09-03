"""RKB projections for MHS references and read-only observations."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .read_models import TypedQueryResult


class MhsReferenceCandidate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = "rolo-mhs-reference-candidate/v1"
    candidate_id: str = Field(min_length=1)
    target_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    vendor_id: str | None = None
    provider_id: str | None = None
    device_id: str | None = None
    manifest_id: str | None = None
    source_kind: str = "TARGET_PROBE"
    authority: str = "OBSERVED"
    transport: str = "UNKNOWN"
    resource_id: str | None = None
    route: str | None = None
    source_ref: str | None = None
    collector_id: str | None = None
    observed_at: datetime | None = None
    freshness: str = "UNKNOWN"
    digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    status: str = "MHS_REFERENCE_DISCOVERED"
    limitations: list[str] = Field(default_factory=list)
    access: str = "READ_ONLY"

    @model_validator(mode="after")
    def validate_reference(self) -> MhsReferenceCandidate:
        if self.access != "READ_ONLY":
            raise ValueError("MHS reference candidates are read-only")
        return self


class MhsManifestReference(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = "rolo-mhs-manifest-reference/v1"
    manifest_id: str = Field(min_length=1)
    target_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_kind: str = "VENDOR_MANIFEST"
    authority: str = "VENDOR"
    uri: str | None = None
    manifest_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    driver_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    canonical_route: str | None = None
    available: bool = False
    verified: bool = False
    status: str = "MHS_MANIFEST_UNAVAILABLE"
    fixture_id: str | None = None
    generated_by: str | None = None
    generated_at: datetime | None = None
    input_evidence_ids: list[str] = Field(default_factory=list)
    digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    not_vendor_manifest: bool = False
    not_release_authority: bool = False
    access: str = "READ_ONLY"
    limitations: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_manifest(self) -> MhsManifestReference:
        if self.access != "READ_ONLY":
            raise ValueError("MHS manifest references are read-only")
        return self


class MhsReadOnlyResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = "rolo-mhs-read-only/v1"
    device_id: str = Field(min_length=1)
    provider_id: str | None = None
    target_fingerprint: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    route: str | None = None
    operation: str = "read"
    status: str = "UNKNOWN"
    value: Any = None
    manifest_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    driver_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    observed_at: datetime | None = None
    fresh_until: datetime | None = None
    evidence_ids: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    access: str = "READ_ONLY"

    @model_validator(mode="after")
    def validate_read_only(self) -> MhsReadOnlyResult:
        if self.access != "READ_ONLY":
            raise ValueError("MHS read-only results are read-only")
        return self


class ProbeEvidenceView(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = "rolo-probe-evidence-view/v1"
    target_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    mhs_references: list[MhsReferenceCandidate] = Field(default_factory=list)
    manifests: list[MhsManifestReference] = Field(default_factory=list)
    read_results: list[MhsReadOnlyResult] = Field(default_factory=list)
    freshness: str = "UNKNOWN"
    limitations: list[str] = Field(default_factory=list)
    access: str = "READ_ONLY"
    write_operations: int = 0

    @model_validator(mode="after")
    def validate_view(self) -> ProbeEvidenceView:
        if self.access != "READ_ONLY":
            raise ValueError("probe evidence view is read-only")
        if self.write_operations != 0:
            raise ValueError("probe evidence view cannot advertise write operations")
        return self


def _model_payload(item: Mapping[str, Any] | BaseModel) -> dict[str, Any]:
    if isinstance(item, BaseModel):
        return item.model_dump(mode="json")
    return dict(item)


def _is_provisional(item: Mapping[str, Any] | BaseModel) -> bool:
    payload = _model_payload(item)
    return str(payload.get("authority", "")).upper() == "PROVISIONAL"


def _freshness_for_view(
    references: Sequence[Mapping[str, Any] | BaseModel],
    manifests: Sequence[Mapping[str, Any] | BaseModel],
    read_results: Sequence[Mapping[str, Any] | BaseModel],
) -> str:
    if any(_is_provisional(item) for item in (*references, *manifests, *read_results)):
        return "UNKNOWN"
    if any(
        str(_model_payload(item).get("status", "")).upper()
        in {"STALE", "UNAVAILABLE", "MHS_MANIFEST_UNAVAILABLE", "DISCOVERED_UNVERIFIED"}
        for item in (*references, *manifests, *read_results)
    ):
        return "STALE"
    if not references and not manifests and not read_results:
        return "UNKNOWN"
    if (
        bool(references)
        and bool(manifests)
        and bool(read_results)
        and all(
            str(_model_payload(item).get("status", "")).upper()
            == "MHS_PROVIDER_READ_ONLY_CONFIRMED"
            for item in references
        )
        and all(
            str(_model_payload(item).get("status", "")).upper() == "MHS_MANIFEST_AVAILABLE"
            and bool(_model_payload(item).get("available", False))
            and bool(_model_payload(item).get("verified", False))
            for item in manifests
        )
        and all(
            str(_model_payload(item).get("status", "")).upper() == "AVAILABLE"
            for item in read_results
        )
    ):
        return "FRESH"
    return "UNKNOWN"


def build_probe_evidence_view(
    *,
    target_fingerprint: str,
    references: Sequence[Mapping[str, Any] | BaseModel] = (),
    manifests: Sequence[Mapping[str, Any] | BaseModel] = (),
    read_results: Sequence[Mapping[str, Any] | BaseModel] = (),
    freshness: str | None = None,
    limitations: Sequence[str] = (),
) -> ProbeEvidenceView:
    combined_limitations = {
        str(item)
        for source in (*references, *manifests, *read_results)
        for item in _model_payload(source).get("limitations", [])
    }
    combined_limitations.update(str(item) for item in limitations)
    freshness_value = freshness or _freshness_for_view(references, manifests, read_results)
    return ProbeEvidenceView(
        target_fingerprint=target_fingerprint,
        mhs_references=[
            MhsReferenceCandidate.model_validate(_model_payload(item)) for item in references
        ],
        manifests=[MhsManifestReference.model_validate(_model_payload(item)) for item in manifests],
        read_results=[
            MhsReadOnlyResult.model_validate(_model_payload(item)) for item in read_results
        ],
        freshness=freshness_value,
        limitations=sorted(combined_limitations),
    )


def project_mhs_read_result(
    result: Mapping[str, Any], *, evidence_ids: Sequence[str] = ()
) -> TypedQueryResult[MhsReadOnlyResult]:
    """Map one MHS read result into the common RKB typed envelope.

    The projection deliberately preserves ``UNKNOWN``, ``STALE`` and
    ``UNAVAILABLE`` states and always advertises read-only access.
    """

    status = str(result.get("status", "UNKNOWN")).upper()
    if status not in {"AVAILABLE", "STALE", "UNAVAILABLE", "UNKNOWN"}:
        status = "UNKNOWN"
    typed_status = "FRESH" if status == "AVAILABLE" else status
    limitations = list(result.get("limitations") or [])
    if result.get("access") != "READ_ONLY":
        typed_status = "UNKNOWN"
        limitations.append("MHS result is not read-only")
    value = MhsReadOnlyResult.model_validate(
        {
            "device_id": str(result.get("device_id") or result.get("route") or "mhs-device"),
            "provider_id": result.get("provider_id"),
            "target_fingerprint": result.get("target_fingerprint"),
            "route": result.get("route"),
            "operation": str(result.get("operation") or "read"),
            "status": status,
            "value": result.get("value"),
            "manifest_sha256": result.get("manifest_sha256"),
            "driver_sha256": result.get("driver_sha256"),
            "observed_at": result.get("observed_at"),
            "fresh_until": result.get("fresh_until"),
            "evidence_ids": list(evidence_ids or result.get("evidence_ids") or []),
            "limitations": limitations,
            "access": "READ_ONLY",
        }
    )
    return TypedQueryResult(
        status=typed_status,
        value=value,
        evidence_ids=list(evidence_ids or result.get("evidence_ids") or []),
        observed_at=result.get("observed_at"),
        fresh_until=result.get("fresh_until"),
        limitations=limitations,
        status_reason=str(result.get("reason") or ""),
    )


def project_probe_evidence_view(
    *,
    target_fingerprint: str,
    references: Sequence[Mapping[str, Any] | BaseModel] = (),
    manifests: Sequence[Mapping[str, Any] | BaseModel] = (),
    read_results: Sequence[Mapping[str, Any] | BaseModel] = (),
    freshness: str | None = None,
    limitations: Sequence[str] = (),
) -> dict[str, Any]:
    """Build the strict ProbeEvidenceView wire shape without write affordances."""

    return build_probe_evidence_view(
        target_fingerprint=target_fingerprint,
        references=references,
        manifests=manifests,
        read_results=read_results,
        freshness=freshness,
        limitations=limitations,
    ).model_dump(mode="json")


__all__ = [
    "MhsManifestReference",
    "MhsReadOnlyResult",
    "MhsReferenceCandidate",
    "ProbeEvidenceView",
    "build_probe_evidence_view",
    "project_mhs_read_result",
    "project_probe_evidence_view",
]
