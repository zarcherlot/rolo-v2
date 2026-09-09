"""Strict target-side T1-T4 conformance evidence contracts."""

from __future__ import annotations

from typing import Literal

from pydantic import Field, model_validator

from .models import OperationKind, StrictModel

_DIGEST = r"^sha256:[0-9a-f]{64}$"
_IDENTIFIER = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"


class TargetGateProof(StrictModel):
    """Digest-addressed evidence for one independently evaluated target gate."""

    gate: Literal["T1", "T2", "T3", "T4"]
    status: Literal["PASS", "FAIL"]
    evidence_ref: str = Field(pattern=r"^target-conformance/t[1-4]-[a-z0-9-]+\.json$")
    evidence_digest: str = Field(pattern=_DIGEST)


class TargetConformanceReport(StrictModel):
    """Complete target identity and proof set consumed by Release Publisher."""

    schema_version: Literal["rolo-target-conformance/v3"]
    t1_target_resolve: Literal["PASS", "FAIL"]
    t2_bundle_build: Literal["PASS", "FAIL"]
    t3_runtime_behavior: Literal["PASS", "FAIL"]
    t4_release_integrity: Literal["PASS", "FAIL"]
    tool_id: str = Field(pattern=_IDENTIFIER)
    operation_kind: OperationKind
    target_id: str = Field(pattern=_IDENTIFIER)
    target_fingerprint: str = Field(min_length=1, max_length=512)
    target_identity_digest: str = Field(pattern=_DIGEST)
    evidence_digest: str = Field(pattern=_DIGEST)
    dsl_digest: str = Field(pattern=_DIGEST)
    context_digest: str = Field(pattern=_DIGEST)
    ir_digest: str = Field(pattern=_DIGEST)
    bundle_digest: str = Field(pattern=_DIGEST)
    compile_artifact_digest: str = Field(pattern=_DIGEST)
    compiler_version: str = Field(min_length=1, max_length=128)
    compiler_backend_id: str = Field(min_length=1, max_length=128)
    compiler_backend_version: str = Field(min_length=1, max_length=128)
    runtime_backend_id: str = Field(min_length=1, max_length=128)
    runtime_binding_digest: str = Field(pattern=_DIGEST)
    runtime_result_digest: str = Field(pattern=_DIGEST)
    required_capabilities: tuple[str, ...] = Field(max_length=32)
    required_runtime_capabilities: tuple[str, ...] = Field(max_length=32)
    negotiated_capabilities: tuple[str, ...] = Field(min_length=1, max_length=32)
    journey_session_id: str = Field(pattern=_IDENTIFIER)
    confirmation_receipt_digest: str = Field(pattern=_DIGEST)
    conformance_idempotency_key: str = Field(pattern=_DIGEST)
    proofs: tuple[TargetGateProof, ...] = Field(min_length=4, max_length=4)
    diagnostics: tuple[str, ...] = ()

    @model_validator(mode="after")
    def proof_set_matches_gates(self) -> TargetConformanceReport:
        expected = {
            "T1": self.t1_target_resolve,
            "T2": self.t2_bundle_build,
            "T3": self.t3_runtime_behavior,
            "T4": self.t4_release_integrity,
        }
        actual = {proof.gate: proof.status for proof in self.proofs}
        if len(actual) != 4 or actual != expected:
            raise ValueError("target conformance proofs must match T1-T4 gates")
        return self

    @property
    def passed(self) -> bool:
        return all(
            value == "PASS"
            for value in (
                self.t1_target_resolve,
                self.t2_bundle_build,
                self.t3_runtime_behavior,
                self.t4_release_integrity,
            )
        )


__all__ = ["TargetConformanceReport", "TargetGateProof"]
