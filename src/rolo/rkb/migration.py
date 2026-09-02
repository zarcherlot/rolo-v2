"""Read-only migration from v2/v3 Probe artifacts into RKB snapshots."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timedelta
from typing import Any

from .models import (
    EvidenceEnvelope,
    Fact,
    FactSourceKind,
    Snapshot,
    SnapshotIdentity,
)

# Keep the migration bounded.  The old bundle remains the source artifact; an
# envelope carries only a safe, JSON-sized projection of its facts.
MAX_INLINE_STRING = 250_000
_SECRET_MARKERS = ("secret", "password", "passwd", "token", "private_key", "api_key")


def _scrub(value: Any, limitations: list[str], *, key: str = "") -> Any:
    lowered = key.lower()
    if any(marker in lowered for marker in _SECRET_MARKERS):
        limitations.append(f"redacted sensitive field: {key}")
        return "<REDACTED>"
    if isinstance(value, Mapping):
        return {str(k): _scrub(v, limitations, key=str(k)) for k, v in value.items()}
    if isinstance(value, list):
        return [_scrub(item, limitations, key=key) for item in value]
    if isinstance(value, str) and len(value) > MAX_INLINE_STRING:
        limitations.append(f"large value omitted for {key or 'fact'}")
        return f"<OMITTED:{len(value)} bytes>"
    return value


def _identity_from_probe(
    probe: Any,
    *,
    identity: SnapshotIdentity | Mapping[str, Any] | None,
    observed_at: datetime | None,
    fresh_for: timedelta,
    deployment_mode: str | None,
) -> SnapshotIdentity:
    if identity is not None:
        return SnapshotIdentity.model_validate(identity)
    raw = getattr(probe, "identity", None)
    if raw is None:
        raise ValueError("probe migration requires an explicit SnapshotIdentity")
    values = dict(raw)
    point = observed_at or getattr(probe, "observed_at", None)
    if point is None:
        raise ValueError("probe migration requires observed_at")
    values.setdefault("observed_at", point)
    values.setdefault("fresh_until", point + fresh_for)
    values.setdefault("deployment_mode", deployment_mode or "remote")
    values.setdefault("access", getattr(probe, "access", "READ_ONLY"))
    return SnapshotIdentity.model_validate(values)


def probe_to_snapshot(
    probe: Any,
    *,
    identity: SnapshotIdentity | Mapping[str, Any] | None = None,
    source_ref: str = "artifact://probe",
    fresh_for: timedelta = timedelta(minutes=5),
    deployment_mode: str | None = None,
    observed_at: datetime | None = None,
) -> Snapshot:
    """Project one legacy ``ProbeResult`` without changing the probe itself."""

    snapshot_identity = _identity_from_probe(
        probe,
        identity=identity,
        observed_at=observed_at or getattr(probe, "observed_at", None),
        fresh_for=fresh_for,
        deployment_mode=deployment_mode,
    )
    observed_at = (
        observed_at or getattr(probe, "observed_at", None) or snapshot_identity.observed_at
    )
    if observed_at != snapshot_identity.observed_at and observed_at is not None:
        # A bundle may contain per-probe timestamps.  The snapshot identity is
        # anchored at bundle collection time; fact timestamps remain per-fact.
        if observed_at > snapshot_identity.fresh_until:
            raise ValueError("probe observed_at is outside snapshot freshness window")
    probe_fresh_until = getattr(probe, "fresh_until", None)
    if probe_fresh_until is not None and probe_fresh_until < observed_at:
        raise ValueError("probe fresh_until is before probe observed_at")
    if getattr(probe, "access", snapshot_identity.access) != snapshot_identity.access:
        raise ValueError("probe access does not match snapshot identity")
    limitations = list(getattr(probe, "warnings", ())) + list(getattr(probe, "errors", ()))
    value = {
        "layer": getattr(probe, "layer", "unknown"),
        "status": getattr(
            getattr(probe, "status", None), "value", getattr(probe, "status", "UNKNOWN")
        ),
        "data": _scrub(getattr(probe, "data", {}), limitations),
        "warnings": list(getattr(probe, "warnings", ())),
        "errors": list(getattr(probe, "errors", ())),
    }
    fact = Fact(
        robot_id=snapshot_identity.robot_id,
        target_host_fingerprint=snapshot_identity.target_host_fingerprint,
        collector_id=snapshot_identity.collector_id,
        deployment_mode=snapshot_identity.deployment_mode,
        access=snapshot_identity.access,
        request_nonce=snapshot_identity.request_nonce,
        source_kind=FactSourceKind.TARGET_PROBE,
        source_ref=source_ref,
        observed_at=observed_at,
        fresh_until=snapshot_identity.fresh_until,
        value=value,
        limitations=limitations,
    )
    return Snapshot(
        identity=snapshot_identity,
        facts=[fact],
        metadata={"layer": getattr(probe, "layer", "unknown")},
    ).with_digest()


def bundle_to_snapshot(
    bundle: Any,
    *,
    identity: SnapshotIdentity | Mapping[str, Any] | None = None,
    deployment_mode: str = "remote",
    fresh_for: timedelta = timedelta(minutes=5),
    source_ref: str = "artifact://target-evidence-bundle",
) -> Snapshot:
    """Project a previously verified v2/v3 bundle into a standalone snapshot.

    This function performs no write and never mutates ``bundle``.  Callers
    should run the existing ``verify_evidence_bundle`` (or
    :func:`rolo.rkb.validation.validate_bundle_hmac`) before invoking it.
    """

    if isinstance(bundle, Mapping):
        from rolo.stages.probe.target_evidence import TargetEvidenceBundle

        bundle = TargetEvidenceBundle.model_validate(bundle)
    collected_at = bundle.collected_at
    if identity is None:
        snapshot_identity = SnapshotIdentity(
            robot_id=bundle.robot_id,
            target_host_fingerprint=bundle.target_host_fingerprint,
            collector_id=bundle.collector_id,
            deployment_mode=deployment_mode,
            access=bundle.access,
            request_nonce=bundle.request_nonce,
            observed_at=collected_at,
            fresh_until=collected_at + fresh_for,
        )
    else:
        snapshot_identity = SnapshotIdentity.model_validate(identity)
        if snapshot_identity.observed_at != collected_at:
            raise ValueError("bundle collected_at does not match snapshot identity")
    facts: list[Fact] = []
    for layer, probe in sorted(bundle.probes.items()):
        migrated = probe_to_snapshot(
            probe,
            identity=snapshot_identity,
            source_ref=f"{source_ref}#/probes/{_escape_pointer(layer)}",
            fresh_for=fresh_for,
            observed_at=collected_at,
        )
        facts.extend(migrated.facts)
    if getattr(bundle, "source_snapshot", None) is not None:
        limitations: list[str] = []
        facts.append(
            Fact(
                robot_id=snapshot_identity.robot_id,
                target_host_fingerprint=snapshot_identity.target_host_fingerprint,
                collector_id=snapshot_identity.collector_id,
                deployment_mode=snapshot_identity.deployment_mode,
                access=snapshot_identity.access,
                request_nonce=snapshot_identity.request_nonce,
                source_kind=FactSourceKind.VERIFIED_BUNDLE,
                source_ref=f"{source_ref}#/source_snapshot",
                observed_at=collected_at,
                fresh_until=snapshot_identity.fresh_until,
                value=_scrub(bundle.source_snapshot, limitations),
                limitations=limitations,
            )
        )
    return Snapshot(
        identity=snapshot_identity,
        facts=facts,
        metadata={
            "source_schema_version": bundle.schema_version,
            "requested_layers": list(bundle.requested_layers),
            "bundle_payload_sha256": bundle.payload_sha256,
        },
    ).with_digest()


def snapshot_from_target_bundle(*args: Any, **kwargs: Any) -> Snapshot:
    """Compatibility alias retaining the P0 function name."""

    return bundle_to_snapshot(*args, **kwargs)


def envelope_from_probe(*args: Any, **kwargs: Any) -> EvidenceEnvelope:
    """Compatibility projection for callers that still consume envelopes."""

    snapshot = probe_to_snapshot(*args, **kwargs)
    return snapshot.to_envelope()


def snapshot_to_legacy_probes(snapshot: Snapshot) -> dict[str, Any]:
    """Return old ``layer -> ProbeResult`` objects for DiscoveryReport readers."""

    from rolo.core.models import DiscoveryStatus, ProbeResult

    probes: dict[str, Any] = {}
    for fact in snapshot.facts:
        value = fact.value if isinstance(fact.value, Mapping) else {}
        layer = str(value.get("layer", "unknown"))
        status_raw = value.get("status", "UNKNOWN")
        try:
            status = DiscoveryStatus(status_raw)
        except ValueError:
            status = DiscoveryStatus.UNAVAILABLE
        probes[layer] = ProbeResult(
            layer=layer,
            status=status,
            data=dict(value.get("data", {})),
            warnings=list(value.get("warnings", [])),
            errors=list(value.get("errors", [])),
            observed_at=fact.observed_at,
            access=snapshot.identity.access,
            fresh_until=fact.fresh_until,
            identity=snapshot.identity.model_dump(mode="json"),
        )
    return probes


def _escape_pointer(value: str) -> str:
    return value.replace("~", "~0").replace("/", "~1")
