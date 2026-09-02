"""Fail-closed validation for RKB snapshots and legacy evidence inputs."""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
from typing import Any

from .canonical import canonical_json, payload_digest
from .models import (
    EvidenceEnvelope,
    Fact,
    FactSourceKind,
    FreshnessStatus,
    IdentityStatus,
    Snapshot,
    SnapshotIdentity,
)


class EvidenceValidationError(ValueError):
    """Raised when evidence cannot be safely consumed."""


DEFAULT_CLOCK_SKEW = timedelta(seconds=30)


def _as_utc(value: datetime, *, field: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise EvidenceValidationError(f"{field} must include a timezone")
    return value.astimezone(timezone.utc)


def validate_identity(
    identity: SnapshotIdentity,
    *,
    now: datetime | None = None,
    expected: SnapshotIdentity | Mapping[str, Any] | None = None,
    require_fresh: bool = False,
    clock_skew: timedelta = DEFAULT_CLOCK_SKEW,
) -> SnapshotIdentity:
    """Validate identity binding, access policy, and time window."""

    try:
        identity = SnapshotIdentity.model_validate(identity)
    except ValueError as exc:
        raise EvidenceValidationError(str(exc)) from exc
    observed = _as_utc(identity.observed_at, field="observed_at")
    fresh_until = _as_utc(identity.fresh_until, field="fresh_until")
    if fresh_until <= observed:
        raise EvidenceValidationError("fresh_until must be after observed_at")
    if identity.identity_status != IdentityStatus.VERIFIED:
        raise EvidenceValidationError("evidence identity is not verified")
    if identity.access != "READ_ONLY":
        raise EvidenceValidationError("only READ_ONLY evidence may enter the RKB")
    if expected is not None:
        other = SnapshotIdentity.model_validate(expected)
        if identity.tuple() != other.tuple():
            raise EvidenceValidationError("evidence identity tuple mismatch")
    point = _as_utc(now or datetime.now(timezone.utc), field="now")
    if observed > point + clock_skew:
        raise EvidenceValidationError("evidence observed_at is in the future")
    if require_fresh and point > fresh_until + clock_skew:
        raise EvidenceValidationError("evidence snapshot is stale")
    return identity


def validate_fact(
    fact: Fact,
    *,
    identity: SnapshotIdentity | None = None,
    now: datetime | None = None,
    require_fresh: bool = False,
    clock_skew: timedelta = DEFAULT_CLOCK_SKEW,
) -> Fact:
    """Validate provenance, payload digest and fact freshness."""

    try:
        fact = Fact.model_validate(fact)
    except ValueError as exc:
        raise EvidenceValidationError(str(exc)) from exc
    if fact.source_kind not in set(FactSourceKind):
        raise EvidenceValidationError("unknown fact source_kind")
    if not fact.source_ref.strip():
        raise EvidenceValidationError("fact source_ref is required")
    if identity is not None and fact_identity_tuple(fact) != identity.tuple():
        raise EvidenceValidationError("fact identity tuple mismatch")
    expected_digest = hashlib.sha256(canonical_json(fact.value)).hexdigest()
    if not fact.sha256 or not hmac.compare_digest(expected_digest, fact.sha256):
        raise EvidenceValidationError(f"fact {fact.fact_id} payload digest mismatch")
    observed = _as_utc(fact.observed_at, field="fact.observed_at")
    fresh_until = _as_utc(fact.fresh_until, field="fact.fresh_until")
    if fresh_until <= observed:
        raise EvidenceValidationError("fact fresh_until must be after observed_at")
    point = _as_utc(now or datetime.now(timezone.utc), field="now")
    if observed > point + clock_skew:
        raise EvidenceValidationError(f"fact {fact.fact_id} observed_at is in the future")
    if require_fresh and point > fresh_until + clock_skew:
        raise EvidenceValidationError(f"fact {fact.fact_id} is stale")
    return fact


def fact_identity_tuple(fact: Fact) -> tuple[str, ...]:
    return (
        fact.robot_id,
        fact.target_host_fingerprint,
        fact.collector_id,
        fact.deployment_mode,
        fact.access,
        fact.request_nonce or "",
    )


def validate_envelope(
    envelope: EvidenceEnvelope | Snapshot,
    *,
    now: datetime | None = None,
    expected_identity: SnapshotIdentity | Mapping[str, Any] | None = None,
    require_fresh: bool = True,
    clock_skew: timedelta = DEFAULT_CLOCK_SKEW,
    hmac_secret: bytes | None = None,
) -> EvidenceEnvelope | Snapshot:
    """Validate either compatibility envelope or standalone snapshot."""

    validate_identity(
        envelope.identity,
        now=now,
        expected=expected_identity,
        require_fresh=require_fresh,
        clock_skew=clock_skew,
    )
    expected_digest = payload_digest(envelope, exclude=("digest", "signature_hmac_sha256"))
    if not envelope.digest or not hmac.compare_digest(expected_digest, envelope.digest):
        raise EvidenceValidationError("evidence envelope digest mismatch")
    for fact in envelope.facts:
        validate_fact(
            fact,
            identity=envelope.identity,
            now=now,
            require_fresh=require_fresh,
            clock_skew=clock_skew,
        )
    if hmac_secret is not None:
        signature = getattr(envelope, "signature_hmac_sha256", None)
        expected_signature = hmac.new(
            hmac_secret, envelope.digest.encode("ascii"), hashlib.sha256
        ).hexdigest()
        if not signature or not hmac.compare_digest(expected_signature, signature):
            raise EvidenceValidationError("evidence envelope HMAC mismatch")
    return envelope


def validate_snapshot(*args: Any, **kwargs: Any) -> Snapshot:
    """Snapshot-specialized alias returning the validated snapshot."""

    result = validate_envelope(*args, **kwargs)
    if not isinstance(result, Snapshot):
        raise TypeError("validate_snapshot expects a Snapshot")
    return result


def freshness_status(
    observed_at: datetime, fresh_until: datetime, *, now: datetime | None = None
) -> FreshnessStatus:
    point = now or datetime.now(timezone.utc)
    if point < observed_at:
        return FreshnessStatus.UNKNOWN
    return FreshnessStatus.FRESH if point <= fresh_until else FreshnessStatus.STALE


def validate_bundle_hmac(
    payload: Mapping[str, Any] | Any,
    *,
    payload_sha256: str,
    signature_hmac_sha256: str,
    secret: bytes,
) -> None:
    """Validate legacy bundle digest/signature before read-only migration."""

    actual = payload_digest(payload, exclude=("payload_sha256", "signature_hmac_sha256"))
    if not hmac.compare_digest(actual, payload_sha256):
        raise EvidenceValidationError("evidence bundle payload hash mismatch")
    expected = hmac.new(secret, payload_sha256.encode("ascii"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature_hmac_sha256):
        raise EvidenceValidationError("evidence bundle HMAC mismatch")

