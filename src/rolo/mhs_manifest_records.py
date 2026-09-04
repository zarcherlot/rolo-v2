"""Strict MHS reference and manifest record helpers.

The module is intentionally fail-closed: it can validate an already serialized
record, or project a vendor manifest into a read-only reference, but it never
infers missing authority, route, or write capability.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .mhs_hardware import MhsDeviceManifest, MhsResult


class MhsSourceKind(str, Enum):
    TARGET_PROBE = "TARGET_PROBE"
    OBSERVED = "OBSERVED"
    VENDOR_MANIFEST = "VENDOR_MANIFEST"
    TEST_FIXTURE = "TEST_FIXTURE"


class MhsAuthority(str, Enum):
    OBSERVED = "OBSERVED"
    VENDOR = "VENDOR"
    PROVISIONAL = "PROVISIONAL"


class MhsFreshness(str, Enum):
    FRESH = "FRESH"
    STALE = "STALE"
    UNKNOWN = "UNKNOWN"


class MhsReferenceCandidate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = "rolo-mhs-reference-candidate/v1"
    candidate_id: str = Field(min_length=1)
    target_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    vendor_id: str | None = None
    provider_id: str | None = None
    device_id: str | None = None
    manifest_id: str | None = None
    source_kind: MhsSourceKind = MhsSourceKind.TARGET_PROBE
    authority: MhsAuthority = MhsAuthority.OBSERVED
    transport: str = "UNKNOWN"
    resource_id: str | None = None
    route: str | None = None
    source_ref: str | None = None
    collector_id: str | None = None
    observed_at: datetime | None = None
    freshness: MhsFreshness = MhsFreshness.UNKNOWN
    digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    status: str = "MHS_REFERENCE_DISCOVERED"
    limitations: list[str] = Field(default_factory=list)
    access: str = "READ_ONLY"

    @model_validator(mode="after")
    def validate_candidate(self) -> MhsReferenceCandidate:
        if self.access != "READ_ONLY":
            raise ValueError("MHS reference candidates must remain read-only")
        if self.status not in {
            "MHS_REFERENCE_DISCOVERED",
            "MHS_MANIFEST_AVAILABLE",
            "MHS_MANIFEST_UNAVAILABLE",
            "DISCOVERED_UNVERIFIED",
            "MHS_PROVISIONAL_FIXTURE",
            "MHS_PROVIDER_READ_ONLY_CONFIRMED",
        }:
            raise ValueError("unsupported MHS reference candidate status")
        if (
            self.source_kind == MhsSourceKind.VENDOR_MANIFEST
            and self.authority != MhsAuthority.VENDOR
        ):
            raise ValueError("vendor manifest candidates must stay vendor-authority")
        if (
            self.source_kind == MhsSourceKind.TEST_FIXTURE
            and self.authority != MhsAuthority.PROVISIONAL
        ):
            raise ValueError("test fixtures must stay provisional")
        return self


class MhsManifestReference(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = "rolo-mhs-manifest-reference/v1"
    manifest_id: str = Field(min_length=1)
    target_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_kind: MhsSourceKind = MhsSourceKind.VENDOR_MANIFEST
    authority: MhsAuthority = MhsAuthority.VENDOR
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
            raise ValueError("manifest references must remain read-only")
        if self.status not in {
            "MHS_MANIFEST_AVAILABLE",
            "MHS_MANIFEST_UNAVAILABLE",
            "DISCOVERED_UNVERIFIED",
            "MHS_PROVISIONAL_FIXTURE",
        }:
            raise ValueError("unsupported MHS manifest reference status")
        if (
            self.source_kind == MhsSourceKind.VENDOR_MANIFEST
            and self.authority != MhsAuthority.VENDOR
        ):
            raise ValueError("vendor manifests must use vendor authority")
        if (
            self.source_kind == MhsSourceKind.TEST_FIXTURE
            and self.authority != MhsAuthority.PROVISIONAL
        ):
            raise ValueError("test fixtures must use provisional authority")
        if self.source_kind == MhsSourceKind.OBSERVED and self.authority not in {
            MhsAuthority.OBSERVED,
            MhsAuthority.PROVISIONAL,
        }:
            raise ValueError("observed manifests must stay observed or provisional")
        if self.canonical_route is not None and not self.canonical_route.startswith("mhs://"):
            raise ValueError("canonical_route must be an mhs:// route")
        if self.available and not self.verified:
            raise ValueError("available manifest references must also be verified")
        if self.not_vendor_manifest and self.authority == MhsAuthority.VENDOR:
            raise ValueError("vendor authority cannot be marked as not_vendor_manifest")
        if self.not_release_authority and self.authority == MhsAuthority.VENDOR:
            raise ValueError("vendor authority cannot be marked as not_release_authority")
        if self.digest is not None and self.digest != self.computed_digest():
            raise ValueError("manifest reference digest does not match content")
        return self

    def _digest_payload(self) -> dict[str, Any]:
        payload = self.model_dump(mode="json", exclude={"digest"})
        return payload

    def computed_digest(self) -> str:
        return hashlib.sha256(
            json.dumps(
                self._digest_payload(),
                sort_keys=True,
                separators=(",", ":"),
                default=str,
            ).encode("utf-8")
        ).hexdigest()


class MhsReadOnly(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = "rolo-mhs-read-only/v1"
    device_id: str = Field(min_length=1)
    provider_id: str | None = None
    target_fingerprint: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    route: str | None = None
    operation: str = Field(default="read")
    status: str = "UNKNOWN"
    value: dict[str, Any] | None = None
    manifest_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    driver_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    observed_at: datetime | None = None
    fresh_until: datetime | None = None
    evidence_ids: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    access: str = "READ_ONLY"

    @model_validator(mode="after")
    def validate_read_only(self) -> MhsReadOnly:
        if self.access != "READ_ONLY":
            raise ValueError("MHS read results must remain read-only")
        if self.operation not in {"inspect", "status", "read"}:
            raise ValueError("unsupported MHS operation")
        if self.status not in {"AVAILABLE", "UNAVAILABLE", "STALE", "UNKNOWN"}:
            raise ValueError("unsupported MHS read status")
        if self.route is not None and not self.route.startswith("mhs://"):
            raise ValueError("MHS read routes must be canonical mhs:// routes")
        if self.observed_at and self.fresh_until and self.fresh_until < self.observed_at:
            raise ValueError("freshness window must be non-decreasing")
        return self


def _canonical_digest(payload: Mapping[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    ).hexdigest()


def _read_json(source: str | Path | Mapping[str, Any]) -> dict[str, Any]:
    if isinstance(source, Mapping):
        return dict(source)
    return json.loads(Path(source).read_text(encoding="utf-8"))


def resolve_manifest_reference(
    source: str | Path | Mapping[str, Any] | None,
    *,
    target_fingerprint: str,
    manifest_id: str,
    canonical_route: str | None = None,
    source_kind: MhsSourceKind = MhsSourceKind.VENDOR_MANIFEST,
    authority: MhsAuthority = MhsAuthority.VENDOR,
    source_ref: str | None = None,
    collector_id: str | None = None,
    generated_by: str | None = None,
    generated_at: datetime | None = None,
    input_evidence_ids: list[str] | None = None,
    fixture_id: str | None = None,
    not_vendor_manifest: bool = False,
    not_release_authority: bool = False,
    limitations: list[str] | None = None,
    expected_manifest_sha256: str | None = None,
    expected_driver_sha256: str | None = None,
) -> MhsManifestReference:
    if source is None:
        return MhsManifestReference(
            manifest_id=manifest_id,
            target_fingerprint=target_fingerprint,
            source_kind=source_kind,
            authority=authority,
            uri=source_ref,
            canonical_route=canonical_route,
            available=False,
            verified=False,
            status="MHS_MANIFEST_UNAVAILABLE",
            fixture_id=fixture_id,
            generated_by=generated_by,
            generated_at=generated_at,
            input_evidence_ids=list(input_evidence_ids or []),
            not_vendor_manifest=not_vendor_manifest,
            not_release_authority=not_release_authority,
            limitations=list(limitations or [])
            + ["vendor manifest unavailable", "no authority inferred"],
        )

    raw = _read_json(source)
    if raw.get("schema_version") == MhsManifestReference.model_fields["schema_version"].default:
        return MhsManifestReference.model_validate(raw)

    manifest = MhsDeviceManifest.model_validate(raw)
    manifest_sha256 = manifest.manifest_sha256
    if expected_manifest_sha256 is not None and expected_manifest_sha256 != manifest_sha256:
        raise ValueError("manifest digest does not match expected digest")
    if expected_driver_sha256 is not None and expected_driver_sha256 != manifest.driver_sha256:
        raise ValueError("driver digest does not match expected digest")
    if canonical_route is None:
        raise ValueError("canonical_route is required for a verified manifest reference")
    return MhsManifestReference(
        manifest_id=manifest_id,
        target_fingerprint=target_fingerprint,
        source_kind=source_kind,
        authority=authority,
        uri=str(source_ref) if source_ref is not None else None,
        manifest_sha256=manifest_sha256,
        driver_sha256=manifest.driver_sha256,
        canonical_route=canonical_route,
        available=True,
        verified=True,
        status="MHS_MANIFEST_AVAILABLE",
        fixture_id=fixture_id,
        generated_by=generated_by,
        generated_at=generated_at,
        input_evidence_ids=list(input_evidence_ids or []),
        not_vendor_manifest=not_vendor_manifest,
        not_release_authority=not_release_authority,
        limitations=list(limitations or []),
    )


def project_read_only_result(
    result: MhsResult | Mapping[str, Any],
    *,
    target_fingerprint: str | None = None,
) -> MhsReadOnly:
    raw = result.model_dump(mode="json") if isinstance(result, MhsResult) else dict(result)
    payload = dict(raw)
    if target_fingerprint is not None:
        payload.setdefault("target_fingerprint", target_fingerprint)
    # ``MhsResult`` is the provider-facing envelope and intentionally contains
    # transport/driver metadata that is not part of the compact RKB read model.
    # Project explicitly instead of relying on permissive parsing: unknown
    # provider fields must never leak into the public contract.
    allowed = set(MhsReadOnly.model_fields)
    payload = {key: value for key, value in payload.items() if key in allowed}
    if "capability_id" in raw:
        capability = raw["capability_id"]
        payload["operation"] = str(capability).removeprefix("mhs.")
    return MhsReadOnly.model_validate(payload)


def load_manifest_reference(path: str | Path, **kwargs: Any) -> MhsManifestReference:
    return resolve_manifest_reference(Path(path), **kwargs)


__all__ = [
    "MhsAuthority",
    "MhsFreshness",
    "MhsManifestReference",
    "MhsReadOnly",
    "MhsReferenceCandidate",
    "MhsSourceKind",
    "load_manifest_reference",
    "project_read_only_result",
    "resolve_manifest_reference",
]
