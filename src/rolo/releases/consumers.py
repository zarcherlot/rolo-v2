"""Trace and Certify consumers for immutable Tool Releases."""

from typing import Any

from pydantic import Field

from rolo.dsl.models import StrictModel

from .publisher import ToolRelease


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
    input: dict[str, Any] = Field(default_factory=dict)
    test_case_id: str | None = None


class ReleaseConsumer:
    consumer_id = "base"

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
        if not release_digest.startswith("sha256:"):
            raise ValueError("RELEASE_DIGEST_INVALID")
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
            input=input or {},
            test_case_id=test_case_id,
        )


class TraceConsumer(ReleaseConsumer):
    consumer_id = "trace"


class CertifyConsumer(ReleaseConsumer):
    consumer_id = "certify"
