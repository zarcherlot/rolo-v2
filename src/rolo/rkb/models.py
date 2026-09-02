"""RKB-1 evidence envelope.

The envelope is deliberately small: it is a verified, read-only projection of a
Probe result and never a second capability registry.  Every fact carries the
same target identity and an explicit freshness deadline.  Consumers should call
``verify`` before using an envelope received from storage or transport.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, model_validator


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def canonical_json(value: Any) -> bytes:
    """Serialize JSON deterministically for evidence digests."""

    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=lambda item: item.isoformat() if isinstance(item, datetime) else str(item),
    ).encode("utf-8")


class IdentityStatus(str, Enum):
    VERIFIED = "VERIFIED"
    UNKNOWN = "UNKNOWN"


class FactSourceKind(str, Enum):
    # Layer vocabulary used by the RKB contract.  The more specific values
    # below remain accepted for compatibility with the initial P0 prototype.
    DECLARED = "DECLARED"
    OBSERVED = "OBSERVED"
    VERIFIED = "VERIFIED"
    INFERRED = "INFERRED"
    DECISION = "DECISION"
    TARGET_PROBE = "TARGET_PROBE"
    DECLARED_STATIC = "DECLARED_STATIC"
    OBSERVED_RUNTIME = "OBSERVED_RUNTIME"
    VERIFIED_BUNDLE = "VERIFIED_BUNDLE"


class FactConfidence(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class FreshnessStatus(str, Enum):
    FRESH = "FRESH"
    STALE = "STALE"
    UNKNOWN = "UNKNOWN"


class SnapshotIdentity(BaseModel):
    """The immutable identity tuple for a target observation."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = "robot-snapshot-identity/v1"
    robot_id: str = Field(min_length=1, max_length=128)
    target_host_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    collector_id: str = Field(min_length=1, max_length=128)
    deployment_mode: str = Field(pattern=r"^(local|remote)$")
    access: str = Field(default="READ_ONLY", pattern=r"^READ_ONLY$")
    request_nonce: str | None = Field(default=None, pattern=r"^[0-9a-f]{32}$")
    observed_at: datetime
    fresh_until: datetime
    identity_status: IdentityStatus = IdentityStatus.VERIFIED

    @model_validator(mode="after")
    def validate_window(self) -> SnapshotIdentity:
        if self.fresh_until <= self.observed_at:
            raise ValueError("fresh_until must be after observed_at")
        return self

    def tuple(self) -> tuple[str, ...]:
        return (
            self.robot_id,
            self.target_host_fingerprint,
            self.collector_id,
            self.deployment_mode,
            self.access,
            self.request_nonce or "",
        )

    def freshness(self, *, now: datetime | None = None) -> FreshnessStatus:
        point = now or _utc_now()
        if point < self.observed_at:
            return FreshnessStatus.UNKNOWN
        return FreshnessStatus.FRESH if point <= self.fresh_until else FreshnessStatus.STALE


class Fact(BaseModel):
    """One independently traceable typed observation."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = "robot-fact/v1"
    fact_id: str = Field(default_factory=lambda: f"fact-{uuid4().hex}", min_length=1)
    robot_id: str = Field(min_length=1, max_length=128)
    target_host_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    collector_id: str = Field(min_length=1, max_length=128)
    deployment_mode: str = Field(pattern=r"^(local|remote)$")
    access: str = Field(default="READ_ONLY", pattern=r"^READ_ONLY$")
    request_nonce: str | None = Field(default=None, pattern=r"^[0-9a-f]{32}$")
    source_kind: FactSourceKind
    source_ref: str = Field(min_length=1, max_length=4096)
    observed_at: datetime
    fresh_until: datetime
    value: Any
    sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    confidence: FactConfidence = FactConfidence.HIGH
    limitations: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_fact(self) -> Fact:
        if self.fresh_until <= self.observed_at:
            raise ValueError("fresh_until must be after observed_at")
        expected = hashlib.sha256(canonical_json(self.value)).hexdigest()
        if self.sha256 is None:
            object.__setattr__(self, "sha256", expected)
        elif self.sha256 != expected:
            raise ValueError("fact sha256 does not match value")
        return self

    def freshness(self, *, now: datetime | None = None) -> FreshnessStatus:
        point = now or _utc_now()
        if point < self.observed_at:
            return FreshnessStatus.UNKNOWN
        return FreshnessStatus.FRESH if point <= self.fresh_until else FreshnessStatus.STALE


class EvidenceEnvelope(BaseModel):
    """Canonical RKB snapshot envelope; only verified read evidence is accepted."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = "robot-evidence-envelope/v1"
    identity: SnapshotIdentity
    facts: list[Fact] = Field(default_factory=list)
    snapshot: dict[str, Any] = Field(default_factory=dict)
    digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    signature_hmac_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    created_at: datetime = Field(default_factory=_utc_now)

    @model_validator(mode="before")
    @classmethod
    def coerce_single_fact_shape(cls, value: Any) -> Any:
        if not isinstance(value, dict) or "facts" in value or "fact_id" not in value:
            return value
        raw = dict(value)
        identity = SnapshotIdentity.model_validate(raw["identity"])
        raw["facts"] = [Fact(
            fact_id=raw.pop("fact_id"),
            robot_id=identity.robot_id,
            target_host_fingerprint=identity.target_host_fingerprint,
            collector_id=identity.collector_id,
            deployment_mode=identity.deployment_mode,
            access=identity.access,
            request_nonce=identity.request_nonce,
            source_kind=raw.pop("source_kind"),
            source_ref=raw.pop("source_ref"),
            observed_at=identity.observed_at,
            fresh_until=identity.fresh_until,
            value=raw.pop("value"),
            sha256=raw.pop("sha256", None),
            confidence=raw.pop("confidence", FactConfidence.HIGH),
            limitations=raw.pop("limitations", []),
        )]
        raw.setdefault("snapshot", {})
        return raw

    @classmethod
    def from_probe(
        cls,
        probe: Any,
        *,
        identity: SnapshotIdentity,
        source_ref: str,
        freshness: timedelta = timedelta(minutes=5),
    ) -> EvidenceEnvelope:
        return envelope_from_probe(
            probe, identity=identity, source_ref=source_ref, freshness=freshness
        )

    @model_validator(mode="after")
    def validate_fact_identity(self) -> EvidenceEnvelope:
        identity = self.identity.tuple()
        for fact in self.facts:
            if (
                fact.robot_id,
                fact.target_host_fingerprint,
                fact.collector_id,
                fact.deployment_mode,
                fact.access,
                fact.request_nonce or "",
            ) != identity:
                raise ValueError("fact identity tuple does not match envelope identity")
        return self

    def payload(self) -> dict[str, Any]:
        # Optional envelope metadata is omitted at the artifact boundary;
        # explicit nulls inside ``value`` remain part of the observed fact.
        return self.model_dump(
            mode="json", exclude={"digest", "signature_hmac_sha256"}, exclude_none=True
        )

    def computed_digest(self) -> str:
        return hashlib.sha256(canonical_json(self.payload())).hexdigest()

    def with_digest(self) -> EvidenceEnvelope:
        return self.model_copy(update={"digest": self.computed_digest()})

    def with_hmac(self, secret: bytes) -> EvidenceEnvelope:
        if not self.digest:
            raise ValueError("envelope digest is required before signing")
        signature = hmac.new(secret, self.digest.encode("ascii"), hashlib.sha256).hexdigest()
        return self.model_copy(update={"signature_hmac_sha256": signature})

    @property
    def fact_id(self) -> str | None:
        return self.facts[0].fact_id if len(self.facts) == 1 else None

    @property
    def source_kind(self) -> FactSourceKind | None:
        return self.facts[0].source_kind if len(self.facts) == 1 else None

    @property
    def source_ref(self) -> str | None:
        return self.facts[0].source_ref if len(self.facts) == 1 else None

    @property
    def value(self) -> Any:
        return self.facts[0].value if len(self.facts) == 1 else None

    @property
    def sha256(self) -> str | None:
        return self.facts[0].sha256 if len(self.facts) == 1 else None

    @property
    def confidence(self) -> FactConfidence | None:
        return self.facts[0].confidence if len(self.facts) == 1 else None

    @property
    def limitations(self) -> list[str]:
        return self.facts[0].limitations if len(self.facts) == 1 else []

    def verify(
        self, *, now: datetime | None = None, require_fresh: bool = True
    ) -> EvidenceEnvelope:
        if self.identity.identity_status != IdentityStatus.VERIFIED:
            raise ValueError("evidence identity is not verified")
        if not self.digest or self.digest != self.computed_digest():
            raise ValueError("evidence envelope digest mismatch")
        freshness = self.identity.freshness(now=now)
        if require_fresh and freshness != FreshnessStatus.FRESH:
            raise ValueError(f"evidence envelope is {freshness.value.lower()}")
        for fact in self.facts:
            if require_fresh and fact.freshness(now=now) != FreshnessStatus.FRESH:
                raise ValueError(f"fact {fact.fact_id} is stale")
        return self


class Snapshot(BaseModel):
    """Standalone RKB snapshot artifact.

    A snapshot is intentionally self-describing: it contains the target
    identity, all facts and the digest of exactly the serialized payload being
    read.  ``EvidenceEnvelope`` remains the compatibility name used by the
    first RKB prototype and can be converted with :meth:`from_envelope`.
    """

    model_config = ConfigDict(extra="forbid")

    schema_version: str = "robot-snapshot/v1"
    identity: SnapshotIdentity
    facts: list[Fact] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    signature_hmac_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    created_at: datetime = Field(default_factory=_utc_now)

    @model_validator(mode="after")
    def validate_fact_identity(self) -> Snapshot:
        identity = self.identity.tuple()
        for fact in self.facts:
            if (
                fact.robot_id,
                fact.target_host_fingerprint,
                fact.collector_id,
                fact.deployment_mode,
                fact.access,
                fact.request_nonce or "",
            ) != identity:
                raise ValueError("fact identity tuple does not match snapshot identity")
        return self

    def payload(self) -> dict[str, Any]:
        return self.model_dump(
            mode="json", exclude={"digest", "signature_hmac_sha256"}, exclude_none=True
        )

    def computed_digest(self) -> str:
        return hashlib.sha256(canonical_json(self.payload())).hexdigest()

    def with_digest(self) -> Snapshot:
        return self.model_copy(update={"digest": self.computed_digest()})

    @classmethod
    def from_envelope(cls, envelope: EvidenceEnvelope) -> Snapshot:
        return cls(
            identity=envelope.identity,
            facts=envelope.facts,
            metadata=envelope.snapshot,
            created_at=envelope.created_at,
        ).with_digest()

    def to_envelope(self) -> EvidenceEnvelope:
        return EvidenceEnvelope(
            identity=self.identity,
            facts=self.facts,
            snapshot=self.metadata,
            digest=self.digest,
            signature_hmac_sha256=self.signature_hmac_sha256,
            created_at=self.created_at,
        )

    def with_hmac(self, secret: bytes) -> Snapshot:
        if not self.digest:
            raise ValueError("snapshot digest is required before signing")
        signature = hmac.new(secret, self.digest.encode("ascii"), hashlib.sha256).hexdigest()
        return self.model_copy(update={"signature_hmac_sha256": signature})


def envelope_from_probe(
    probe: Any,
    *,
    identity: SnapshotIdentity,
    source_ref: str,
    freshness: timedelta = timedelta(minutes=5),
) -> EvidenceEnvelope:
    """Convert a verified or local ProbeResult into the canonical envelope."""

    observed_at = getattr(probe, "observed_at", None) or identity.observed_at
    if observed_at != identity.observed_at:
        raise ValueError("probe observed_at does not match identity")
    probe_access = getattr(probe, "access", identity.access)
    if probe_access != identity.access:
        raise ValueError("probe access does not match identity")
    probe_fresh_until = getattr(probe, "fresh_until", None)
    if probe_fresh_until is not None and probe_fresh_until != identity.fresh_until:
        raise ValueError("probe fresh_until does not match identity")
    value = getattr(probe, "data", {})
    fact = Fact(
        robot_id=identity.robot_id,
        target_host_fingerprint=identity.target_host_fingerprint,
        collector_id=identity.collector_id,
        deployment_mode=identity.deployment_mode,
        access=identity.access,
        request_nonce=identity.request_nonce,
        source_kind=FactSourceKind.TARGET_PROBE,
        source_ref=source_ref,
        observed_at=observed_at,
        fresh_until=identity.fresh_until,
        value=value,
        limitations=list(getattr(probe, "warnings", [])) + list(getattr(probe, "errors", [])),
    )
    return EvidenceEnvelope(
        identity=identity,
        facts=[fact],
        snapshot={"layer": getattr(probe, "layer", "unknown")},
    ).with_digest()


def snapshot_from_target_bundle(
    bundle: Any,
    *,
    deployment_mode: str,
    fresh_for: timedelta = timedelta(minutes=5),
    source_ref: str = "artifact://target-evidence-bundle",
) -> EvidenceEnvelope:
    """Build an envelope only from a bundle that has already passed verification."""

    collected_at = bundle.collected_at
    identity = SnapshotIdentity(
        robot_id=bundle.robot_id,
        target_host_fingerprint=bundle.target_host_fingerprint,
        collector_id=bundle.collector_id,
        deployment_mode=deployment_mode,
        access=bundle.access,
        request_nonce=bundle.request_nonce,
        observed_at=collected_at,
        fresh_until=collected_at + fresh_for,
    )
    facts = [
        Fact(
            robot_id=identity.robot_id,
            target_host_fingerprint=identity.target_host_fingerprint,
            collector_id=identity.collector_id,
            deployment_mode=identity.deployment_mode,
            access=identity.access,
            request_nonce=identity.request_nonce,
            source_kind=FactSourceKind.VERIFIED_BUNDLE,
            source_ref=f"{source_ref}#/probes/{layer}",
            observed_at=collected_at,
            fresh_until=identity.fresh_until,
            value=probe.model_dump(mode="json"),
            limitations=list(probe.warnings) + list(probe.errors),
        )
        for layer, probe in sorted(bundle.probes.items())
    ]
    return EvidenceEnvelope(
        identity=identity,
        facts=facts,
        snapshot={"requested_layers": bundle.requested_layers},
    ).with_digest()
