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
    evidence_digest: str
    target_fingerprint: str
    input: dict[str, Any] = Field(default_factory=dict)
    test_case_id: str | None = None


class ReleaseConsumer:
    consumer_id = "base"

    def consume(
        self, release: ToolRelease, *, release_digest: str, session_id: str, evidence_digest: str, target_fingerprint: str, input: dict[str, Any] | None = None, test_case_id: str | None = None
    ) -> ExecutionEnvelope:
        if release.status != "PUBLISHED":
            raise ValueError("RELEASE_NOT_PUBLISHED")
        if not release.agent_callable:
            raise ValueError("RELEASE_NOT_AGENT_CALLABLE")
        if release.target_fingerprint != target_fingerprint:
            raise ValueError("TARGET_FINGERPRINT_MISMATCH")
        if release.probe_evidence_digest != evidence_digest:
            raise ValueError("EVIDENCE_DIGEST_MISMATCH")
        if not release_digest.startswith("sha256:"):
            raise ValueError("RELEASE_DIGEST_INVALID")
        return ExecutionEnvelope(
            consumer=self.consumer_id,
            tool_id=release.tool_id,
            release_digest=release_digest,
            session_id=session_id,
            evidence_digest=evidence_digest,
            target_fingerprint=target_fingerprint,
            input=input or {},
            test_case_id=test_case_id,
        )


class TraceConsumer(ReleaseConsumer):
    consumer_id = "trace"


class CertifyConsumer(ReleaseConsumer):
    consumer_id = "certify"
