"""Fail-closed projection from conformance artifacts to callable tool state."""

from __future__ import annotations

import hashlib
import json
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field

from .conformance import ToolConformanceReport
from .session import NativeToolSessionDescriptor


class ToolVerificationState(str, Enum):
    VERIFIED = "VERIFIED"
    BLOCKED = "BLOCKED"


class ToolVerificationProjection(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = "rolo-tool-verification/v1"
    target_id: str
    session_id: str
    target_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    artifact_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    session_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    state: ToolVerificationState
    agent_callable: bool
    limitations: list[str] = Field(default_factory=list)


def project_tool_verification(
    report: ToolConformanceReport,
    session: NativeToolSessionDescriptor,
    *,
    target_fingerprint: str,
    expected_fingerprint: str,
) -> ToolVerificationProjection:
    """Bind conformance, session, target identity and artifact digest."""
    artifact_sha256 = hashlib.sha256(
        json.dumps(
            report.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
    ).hexdigest()
    limitations: list[str] = []
    if report.status != "PASS":
        limitations.append("conformance report is not PASS")
    if report.target_id != session.robot_id:
        limitations.append("conformance target does not match session")
    if report.session_id != session.session_id:
        limitations.append("conformance session does not match session")
    if report.surface_digest != session.native_catalog_sha256:
        limitations.append("conformance surface digest does not match session")
    if target_fingerprint != expected_fingerprint:
        limitations.append("target fingerprint does not match expected identity")
    verified = not limitations
    return ToolVerificationProjection(
        target_id=session.robot_id,
        session_id=session.session_id,
        target_fingerprint=target_fingerprint,
        artifact_sha256=artifact_sha256,
        session_digest=session.native_catalog_sha256,
        state=ToolVerificationState.VERIFIED if verified else ToolVerificationState.BLOCKED,
        agent_callable=verified,
        limitations=limitations,
    )


__all__ = [
    "ToolVerificationProjection",
    "ToolVerificationState",
    "project_tool_verification",
]
