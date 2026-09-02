"""Auditable, read-only discovery helpers for the Rolo MHS profile.

The module deliberately stops at candidate and evidence production.  It does
not open transports, execute shell commands, or invoke write capabilities.
Callers supply observations collected by an approved target-side collector.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .mhs_hardware import MhsResult
from .rkb import EvidenceEnvelope, Fact, FactSourceKind, SnapshotIdentity


class IdentityStability(str, Enum):
    STABLE = "stable"
    PATH = "path"
    UNKNOWN = "unknown"


class MhsIdentityResolution(BaseModel):
    """Resolution of a device identity from ordered, target-observed sources."""

    model_config = ConfigDict(extra="forbid")

    sources: dict[str, str | None] = Field(default_factory=dict)
    selected_source: str | None = None
    selected_value: str | None = None
    stability: IdentityStability = IdentityStability.UNKNOWN
    conflicts: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_selection(self) -> MhsIdentityResolution:
        if self.selected_source is not None and self.selected_source not in self.sources:
            raise ValueError("selected identity source is not present in sources")
        if self.selected_value is not None and not self.selected_value.strip():
            raise ValueError("selected identity value cannot be blank")
        if self.conflicts and self.stability != IdentityStability.UNKNOWN:
            raise ValueError("identity conflicts must remain UNKNOWN")
        return self

    @property
    def usable(self) -> bool:
        return bool(self.selected_value) and not self.conflicts


class DiscoveryTrace(BaseModel):
    """One redacted, reproducible source observation."""

    model_config = ConfigDict(extra="forbid")

    trace_id: str = Field(default_factory=lambda: f"trace-{uuid4().hex}")
    collector_id: str = Field(min_length=1, max_length=128)
    target_host_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    deployment_mode: Literal["local", "remote"]
    source_kind: FactSourceKind
    source_ref: str = Field(min_length=1, max_length=4096)
    observed_at: datetime
    query: str | None = None
    exit_code: int | None = None
    raw_output: str = ""
    output_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    redacted: bool = False
    limitations: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_output_digest(self) -> DiscoveryTrace:
        expected = hashlib.sha256(self.raw_output.encode("utf-8")).hexdigest()
        if self.output_sha256 != expected:
            raise ValueError("trace output_sha256 does not match raw_output")
        if not self.redacted and _contains_secret(self.raw_output):
            raise ValueError("trace raw_output appears to contain a secret")
        return self

    @classmethod
    def from_output(
        cls,
        *,
        collector_id: str,
        target_host_fingerprint: str,
        deployment_mode: Literal["local", "remote"],
        source_kind: FactSourceKind,
        source_ref: str,
        output: str,
        observed_at: datetime | None = None,
        query: str | None = None,
        exit_code: int | None = None,
        limitations: list[str] | None = None,
    ) -> DiscoveryTrace:
        redacted_output, changed = redact_secrets(output)
        return cls(
            collector_id=collector_id,
            target_host_fingerprint=target_host_fingerprint,
            deployment_mode=deployment_mode,
            source_kind=source_kind,
            source_ref=source_ref,
            observed_at=observed_at or datetime.now(timezone.utc),
            query=query,
            exit_code=exit_code,
            raw_output=redacted_output,
            output_sha256=hashlib.sha256(redacted_output.encode("utf-8")).hexdigest(),
            redacted=changed,
            limitations=list(limitations or []),
        )


class MhsProbePolicy(BaseModel):
    """Allowlist and resource budget for a read-only provider probe."""

    model_config = ConfigDict(extra="forbid")

    allowed_operations: frozenset[str] = frozenset({"inspect", "status", "read"})
    timeout_s: float = Field(default=5.0, gt=0, le=60)
    max_retries: int = Field(default=0, ge=0, le=3)
    max_concurrency: int = Field(default=1, ge=1, le=8)
    require_no_write: bool = True

    @model_validator(mode="after")
    def validate_operations(self) -> MhsProbePolicy:
        for operation in self.allowed_operations:
            if not re.fullmatch(r"[a-z][a-z0-9_.:-]*", operation):
                raise ValueError(f"invalid probe operation: {operation!r}")
            if operation in {"reset", "calibrate", "setpoint", "enable", "stop", "write"}:
                raise ValueError(f"write-like operation is forbidden: {operation!r}")
        return self

    def require_allowed(self, operation: str) -> None:
        if operation not in self.allowed_operations:
            raise PermissionError(f"probe operation is not allowlisted: {operation}")


def redact_secrets(value: str) -> tuple[str, bool]:
    """Redact common credentials before a trace can enter an evidence artifact."""

    redacted = value
    redacted = re.sub(
        r"(?i)(password|passwd|token|secret|api[_-]?key|authorization)(\s*[:=]\s*)\S+",
        r"\1\2<redacted>",
        redacted,
    )
    redacted = re.sub(
        r"(?i)(https?://)([^/@\s]+):([^/@\s]+)@([^/\s]+)",
        r"\1<redacted>@\4",
        redacted,
    )
    return redacted, redacted != value


def resolve_identity(
    sources: Mapping[str, str | None], *, path: str | None = None
) -> MhsIdentityResolution:
    """Resolve identity using stable sources first and fail closed on disagreement."""

    ordered = ("serial", "device_tree", "udev_by_id", "controller_resource_id", "path")
    normalized = {
        key: (value.strip() if isinstance(value, str) and value.strip() else None)
        for key, value in sources.items()
    }
    if path is not None and "path" not in normalized:
        normalized["path"] = path
    present = [(key, normalized.get(key)) for key in ordered if normalized.get(key)]
    stable_values = {value for key, value in present if key != "path"}
    conflicts = sorted(stable_values) if len(stable_values) > 1 else []
    if conflicts:
        return MhsIdentityResolution(sources=normalized, conflicts=conflicts)
    if present:
        selected_source, selected_value = present[0]
        stability = (
            IdentityStability.PATH
            if selected_source == "path"
            else IdentityStability.STABLE
        )
        return MhsIdentityResolution(
            sources=normalized,
            selected_source=selected_source,
            selected_value=selected_value,
            stability=stability,
        )
    return MhsIdentityResolution(sources=normalized)


def write_gate_allowed(identity: MhsIdentityResolution) -> bool:
    """Return whether a resolved device identity may be considered for writes."""

    return identity.stability == IdentityStability.STABLE and identity.usable


def mhs_evidence_envelope(
    results: list[MhsResult],
    *,
    identity: SnapshotIdentity,
    source_ref: str,
    device_id: str,
    provider_id: str,
    freshness: timedelta | None = None,
) -> EvidenceEnvelope:
    """Bind provider results to one verified RKB identity tuple."""

    if not results:
        raise ValueError("at least one MHS result is required")
    deadline = freshness or (identity.fresh_until - identity.observed_at)
    facts: list[Fact] = []
    for result in results:
        observed_at = result.observed_at or identity.observed_at
        fresh_until = result.fresh_until or observed_at + deadline
        if observed_at < identity.observed_at or fresh_until > identity.fresh_until:
            raise ValueError("MHS result freshness window is outside envelope identity")
        facts.append(
            Fact(
                robot_id=identity.robot_id,
                target_host_fingerprint=identity.target_host_fingerprint,
                collector_id=identity.collector_id,
                deployment_mode=identity.deployment_mode,
                access=identity.access,
                request_nonce=identity.request_nonce,
                source_kind=FactSourceKind.OBSERVED_RUNTIME,
                source_ref=f"{source_ref}#{result.route}",
                observed_at=observed_at,
                fresh_until=fresh_until,
                value=result.model_dump(mode="json"),
                limitations=list(result.limitations),
            )
        )
    return EvidenceEnvelope(
        identity=identity,
        facts=facts,
        snapshot={
            "mhs_device_id": device_id,
            "provider_id": provider_id,
            "routes": [result.route for result in results],
            "manifest_digests": sorted(
                {result.manifest_sha256 for result in results if result.manifest_sha256}
            ),
            "driver_digests": sorted(
                {result.driver_sha256 for result in results if result.driver_sha256}
            ),
        },
    ).with_digest()


def _contains_secret(value: str) -> bool:
    return bool(
        re.search(
            r"(?i)(password|passwd|token|secret|api[_-]?key|authorization)\s*[:=]",
            value,
        )
    )


__all__ = [
    "DiscoveryTrace",
    "IdentityStability",
    "MhsIdentityResolution",
    "MhsProbePolicy",
    "mhs_evidence_envelope",
    "redact_secrets",
    "resolve_identity",
    "write_gate_allowed",
]
