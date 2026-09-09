"""Trace and Certify consumers for immutable Tool Releases."""

from typing import Any

from pydantic import Field

from rolo.dsl.admission import (
    MappingAdmissionError,
    MappingAdmissionGate,
    MappingAdmissionIdentity,
    MappingAdmissionScope,
    MappingConfirmationStore,
    ProductionMappingConfirmationStore,
    bind_mapping_admission_gate,
)
from rolo.dsl.models import StrictModel

from .publisher import ToolRelease, tool_release_digest


class ExecutionEnvelope(StrictModel):
    consumer: str
    tool_id: str
    release_digest: str
    session_id: str = Field(min_length=1)
    idempotency_key: str = Field(min_length=1, max_length=128)
    evidence_digest: str
    target_fingerprint: str
    compile_context_digest: str | None = None
    route_digest: str | None = None
    mhs_manifest_digests: tuple[str, ...] = ()
    mapping_confirmation_receipt_digest: str
    mapping_admission: MappingAdmissionIdentity
    input: dict[str, Any] = Field(default_factory=dict)
    test_case_id: str | None = None


class ReleaseConsumer:
    consumer_id = "base"

    def __init__(
        self,
        *,
        confirmation_store: (
            MappingConfirmationStore | ProductionMappingConfirmationStore | None
        ) = None,
        admission_gate: MappingAdmissionGate | None = None,
    ) -> None:
        self.confirmation_store = confirmation_store
        self.admission_gate = bind_mapping_admission_gate(
            confirmation_store,
            admission_gate,
        )

    def consume(
        self,
        release: ToolRelease,
        *,
        release_digest: str,
        session_id: str,
        idempotency_key: str | None = None,
        evidence_digest: str,
        target_fingerprint: str,
        compile_context_digest: str | None = None,
        route_digest: str | None = None,
        mhs_manifest_digests: tuple[str, ...] = (),
        input: dict[str, Any] | None = None,
        test_case_id: str | None = None,
    ) -> ExecutionEnvelope:
        if release.status != "PUBLISHED":
            raise ValueError("RELEASE_NOT_PUBLISHED")
        if not release.agent_callable:
            raise ValueError("RELEASE_NOT_AGENT_CALLABLE")
        if release.target_fingerprint != target_fingerprint:
            raise ValueError("TARGET_FINGERPRINT_MISMATCH")
        if release.probe_evidence_digest != evidence_digest:
            raise ValueError("EVIDENCE_DIGEST_MISMATCH")
        if release.compile_context_digest is not None and release.compile_context_digest != compile_context_digest:
            raise ValueError("CONTEXT_DIGEST_MISMATCH")
        if release.route_digest is not None and release.route_digest != route_digest:
            raise ValueError("ROUTE_DIGEST_MISMATCH")
        if release.mhs_manifest_digests and tuple(sorted(set(release.mhs_manifest_digests))) != tuple(sorted(set(mhs_manifest_digests))):
            raise ValueError("MHS_MANIFEST_DIGEST_MISMATCH")
        if (
            len(release_digest) != 71
            or not release_digest.startswith("sha256:")
            or any(character not in "0123456789abcdef" for character in release_digest[7:])
        ):
            raise ValueError("RELEASE_DIGEST_INVALID")
        if release_digest != tool_release_digest(release):
            raise ValueError("RELEASE_DIGEST_MISMATCH")
        mapping_identity = self._require_active_mapping(release)
        return ExecutionEnvelope(
            consumer=self.consumer_id,
            tool_id=release.tool_id,
            release_digest=release_digest,
            session_id=session_id,
            idempotency_key=idempotency_key or f"{session_id}:{release.tool_id}",
            evidence_digest=evidence_digest,
            target_fingerprint=target_fingerprint,
            compile_context_digest=compile_context_digest,
            route_digest=route_digest,
            mhs_manifest_digests=tuple(mhs_manifest_digests),
            mapping_confirmation_receipt_digest=release.mapping_confirmation_receipt_digest,
            mapping_admission=mapping_identity,
            input=input or {},
            test_case_id=test_case_id,
        )

    def _require_active_mapping(self, release: ToolRelease) -> MappingAdmissionIdentity:
        """Revalidate the exact confirmation on every release consumption."""

        if self.confirmation_store is None or self.admission_gate is None:
            raise MappingAdmissionError("MAPPING_CONFIRMATION_STORE_REQUIRED")
        if not release.mapping_confirmation_receipt_digest or release.mapping_admission is None:
            raise MappingAdmissionError("MAPPING_CONFIRMATION_REQUIRED")
        if not release.target_id or release.compile_context_digest is None:
            raise MappingAdmissionError("MAPPING_RELEASE_IDENTITY_INCOMPLETE")

        lineage = release.mapping_admission
        scope = MappingAdmissionScope(
            tool_id=release.tool_id,
            operation_kind=release.operation_kind,
            operations=lineage.scope.operations,
            access=lineage.scope.access,
            risk=lineage.scope.risk,
        )
        expected = MappingAdmissionIdentity.build(
            journey_session_id=lineage.journey_session_id,
            target_id=release.target_id,
            target_fingerprint=release.target_fingerprint,
            candidate_index_digest=lineage.candidate_index_digest,
            candidate_digest=lineage.candidate_digest,
            proposal_digest=lineage.proposal_digest,
            dsl_digest=release.dsl_digest,
            context_digest=release.compile_context_digest,
            evidence_digest=release.probe_evidence_digest,
            available_tool_catalog_digest=lineage.available_tool_catalog_digest,
            scope=scope,
        )
        receipt = self.admission_gate.require_active(
            release.mapping_confirmation_receipt_digest,
            expected,
        )
        if receipt.admission_identity() != lineage:
            raise MappingAdmissionError("MAPPING_RELEASE_LINEAGE_MISMATCH")
        return lineage


class TraceConsumer(ReleaseConsumer):
    consumer_id = "trace"


class CertifyConsumer(ReleaseConsumer):
    consumer_id = "certify"

    def consume(self, release: ToolRelease, **kwargs: Any) -> ExecutionEnvelope:
        """Certify only consumes a release backed by target T1-T4 evidence."""

        digest = release.target_conformance_digest
        if (
            digest is None
            or len(digest) != 71
            or not digest.startswith("sha256:")
            or any(character not in "0123456789abcdef" for character in digest[7:])
        ):
            raise ValueError("TARGET_CONFORMANCE_REQUIRED")
        return super().consume(release, **kwargs)
