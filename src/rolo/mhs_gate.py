"""Fail-closed eligibility and verification checks for MHS manifests."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from .mhs_hardware import MhsDeviceManifest, MhsResult, MhsStatus


class MhsGateContext(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target_host_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    evidence_target_host_fingerprint: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    identity_verified: bool = False
    physical_binding_verified: bool = False
    conformance_passed: bool = False
    safety_reviewed: bool = False
    observed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class MhsGateDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal["ELIGIBLE", "VERIFIED", "REJECTED"]
    checks: dict[str, bool]
    reasons: list[str] = Field(default_factory=list)


def evaluate_mhs_gate(
    manifest: MhsDeviceManifest,
    results: list[MhsResult],
    context: MhsGateContext,
) -> MhsGateDecision:
    """Evaluate runtime evidence without opening transports or issuing writes."""

    checks = {
        "identity_tuple": bool(manifest.identity.stable_id)
        and not manifest.identity.conflicts
        and context.identity_verified,
        "target_fingerprint": context.evidence_target_host_fingerprint
        == context.target_host_fingerprint,
        "manifest_digest": bool(manifest.manifest_sha256),
        "driver_digest": manifest.driver_sha256 != "0" * 64,
        "canonical_routes": all(
            result.route == f"mhs://{manifest.device_id}/{result.capability_id}"
            for result in results
        ),
        "runtime_results": bool(results)
        and all(result.status == MhsStatus.AVAILABLE for result in results),
        "freshness": bool(results)
        and all(
            result.observed_at is not None
            and result.fresh_until is not None
            and result.observed_at <= context.observed_at <= result.fresh_until
            for result in results
        ),
        "physical_binding": context.physical_binding_verified,
        "safety_review": context.safety_reviewed,
    }
    reasons = [name for name, passed in checks.items() if not passed]
    eligible_checks = checks.copy()
    eligible_checks.pop("physical_binding")
    eligible_checks.pop("safety_review")
    eligible = all(eligible_checks.values())
    verified = (
        eligible
        and checks["physical_binding"]
        and checks["safety_review"]
        and context.conformance_passed
    )
    if verified:
        return MhsGateDecision(
            status="VERIFIED", checks={**checks, "conformance": True}, reasons=[]
        )
    if eligible:
        if not context.conformance_passed:
            reasons.append("conformance")
        return MhsGateDecision(
            status="ELIGIBLE",
            checks={**checks, "conformance": context.conformance_passed},
            reasons=reasons,
        )
    return MhsGateDecision(
        status="REJECTED",
        checks={**checks, "conformance": context.conformance_passed},
        reasons=reasons,
    )


__all__ = ["MhsGateContext", "MhsGateDecision", "evaluate_mhs_gate"]
