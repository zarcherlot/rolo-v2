from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class RunMode(str, Enum):
    OBSERVATION_ONLY = "OBSERVATION_ONLY"
    SUPERVISED_FIELD_DEBUG = "SUPERVISED_FIELD_DEBUG"
    UNATTENDED_REMOTE = "UNATTENDED_REMOTE"


class ToolState(str, Enum):
    DISCOVERED_UNVERIFIED = "DISCOVERED_UNVERIFIED"
    VERIFIED = "VERIFIED"
    CALLABLE = "CALLABLE"
    UNAVAILABLE = "UNAVAILABLE"


class SessionState(str, Enum):
    DISCOVERED = "DISCOVERED"
    PLANNED = "PLANNED"
    CALLING = "CALLING"
    OBSERVED = "OBSERVED"
    DIAGNOSING = "DIAGNOSING"
    RECOVERING = "RECOVERING"
    COMPLETED = "COMPLETED"
    BLOCKED = "BLOCKED"
    UNKNOWN = "UNKNOWN"
    CANCELLED = "CANCELLED"
    STOPPED = "STOPPED"


class CaseStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    BLOCKED = "BLOCKED"
    UNKNOWN = "UNKNOWN"
    NOT_RUN = "NOT_RUN"


class MvpModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class CatalogTool(MvpModel):
    schema_version: Literal["rolo-mvp-tool-catalog-entry/v1"] = "rolo-mvp-tool-catalog-entry/v1"
    tool_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
    target_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
    state: ToolState = ToolState.DISCOVERED_UNVERIFIED
    agent_callable: bool = False
    access: Literal["read", "experimental_write"] = "read"
    experimental_write: bool = False
    descriptor_digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    source: str = "probe"
    evidence_ids: list[str] = Field(default_factory=list, max_length=128)
    parameters: dict[str, Any] = Field(default_factory=dict)
    timeout_s: float = Field(default=30.0, gt=0, le=300)
    limitations: list[str] = Field(default_factory=list, max_length=64)

    @model_validator(mode="after")
    def callable_rules(self) -> CatalogTool:
        if self.experimental_write and self.access != "experimental_write":
            raise ValueError("experimental_write tools must declare experimental_write access")
        if self.agent_callable and self.state != ToolState.CALLABLE:
            raise ValueError("agent_callable tools must be CALLABLE")
        return self


class MhsInventoryEntry(MvpModel):
    schema_version: Literal["rolo-mvp-mhs-inventory-entry/v1"] = "rolo-mvp-mhs-inventory-entry/v1"
    provider_id: str = Field(min_length=1, max_length=128)
    manifest_id: str | None = None
    source_kind: str = "OBSERVED"
    authority: str = "OBSERVED"
    status: str = "UNKNOWN"
    manifest_digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    callable: bool = False
    evidence_ids: list[str] = Field(default_factory=list, max_length=128)
    limitations: list[str] = Field(default_factory=list, max_length=64)


class RkbModelRef(MvpModel):
    schema_version: Literal["rolo-mvp-rkb-model-ref/v1"] = "rolo-mvp-rkb-model-ref/v1"
    query: str = Field(min_length=1, max_length=256)
    status: Literal["KNOWN", "UNKNOWN", "STALE"] = "UNKNOWN"
    evidence_ids: list[str] = Field(default_factory=list, max_length=128)
    limitations: list[str] = Field(default_factory=list, max_length=64)


class TargetCatalog(MvpModel):
    schema_version: Literal["rolo-mvp-target-catalog/v1"] = "rolo-mvp-target-catalog/v1"
    target_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
    target_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$|^UNKNOWN$")
    snapshot_digest: str = Field(pattern=r"^[0-9a-f]{64}$|^UNKNOWN$")
    surface_digest: str = Field(default="UNKNOWN", pattern=r"^[0-9a-f]{64}$|^UNKNOWN$")
    generated_at: datetime
    freshness: Literal["fresh", "stale", "unknown"] = "unknown"
    tools: list[CatalogTool] = Field(default_factory=list, max_length=512)
    mhs: list[MhsInventoryEntry] = Field(default_factory=list, max_length=256)
    rkb: list[RkbModelRef] = Field(default_factory=list, max_length=256)
    limitations: list[str] = Field(default_factory=list, max_length=128)
    digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")

    def payload(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude={"digest"})

    def computed_digest(self) -> str:
        encoded = json.dumps(self.payload(), sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        return hashlib.sha256(encoded.encode()).hexdigest()

    def with_digest(self) -> TargetCatalog:
        return self.model_copy(update={"digest": self.computed_digest()})

    @model_validator(mode="after")
    def verify_digest(self) -> TargetCatalog:
        if self.digest is not None and self.digest != self.computed_digest():
            raise ValueError("target catalog digest does not match content")
        if not any(item.agent_callable and (item.tool_id.startswith("app.") or item.tool_id.startswith("native.application.")) for item in self.tools):
            if "no callable application tool observed" not in self.limitations:
                self.limitations.append("no callable application tool observed")
        return self


class TraceSessionRequest(MvpModel):
    schema_version: Literal["rolo-mvp-trace-session-request/v1"] = "rolo-mvp-trace-session-request/v1"
    target_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
    catalog_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    task: str = Field(min_length=1, max_length=2_000)
    mode: RunMode = RunMode.OBSERVATION_ONLY
    ttl_s: float = Field(default=900, gt=0, le=86_400)
    max_calls: int = Field(default=32, ge=1, le=10_000)
    operator_id: str | None = Field(default=None, max_length=128)
    safety_confirmed: bool = False
    # Optional release/context identity is populated by release-bound callers
    # and retained in every resulting event for audit and replay.
    release_digest: str | None = Field(default=None, max_length=256)
    compile_context_digest: str | None = Field(default=None, max_length=256)
    target_fingerprint: str | None = Field(default=None, max_length=256, pattern=r"^[0-9a-f]{64}$|^UNKNOWN$")
    scope: tuple[str, ...] = Field(default=(), max_length=32)

    @model_validator(mode="after")
    def mode_requirements(self) -> TraceSessionRequest:
        if self.mode == RunMode.SUPERVISED_FIELD_DEBUG and not self.safety_confirmed:
            raise ValueError("SUPERVISED_FIELD_DEBUG requires safety_confirmed")
        if self.mode == RunMode.UNATTENDED_REMOTE:
            raise ValueError("UNATTENDED_REMOTE is blocked for the MVP")
        return self


class TraceCall(MvpModel):
    tool_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
    arguments: dict[str, Any] = Field(default_factory=dict)
    # Retries after a transport interruption must be idempotent.  A missing
    # key is filled deterministically by TraceService.
    idempotency_key: str | None = Field(default=None, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class TraceEvent(MvpModel):
    schema_version: Literal["rolo-mvp-trace-event/v1"] = "rolo-mvp-trace-event/v1"
    sequence: int = Field(ge=1)
    # ``run_id`` is the connector-facing alias for ``session_id``.  Keeping
    # both fields makes an event self-contained when it is consumed through
    # the generic AgentRunEvent contract while preserving the historical MVP
    # session terminology.
    run_id: str
    session_id: str
    target_id: str
    state: SessionState
    event: str = Field(min_length=1, max_length=128)
    tool_id: str | None = None
    arguments: dict[str, Any] | None = None
    result: Any = None
    evidence_ids: list[str] = Field(default_factory=list, max_length=128)
    error_code: str | None = None
    error: str | None = None
    attempt: int | None = Field(default=None, ge=1)
    operation_id: str | None = None
    idempotency_key: str | None = None
    release_digest: str | None = None
    compile_context_digest: str | None = None
    target_fingerprint: str | None = None
    created_at: datetime

    @model_validator(mode="before")
    @classmethod
    def backfill_identity_for_legacy_events(cls, value: Any) -> Any:
        """Read v1 events written before run/target identity was added.

        New events always provide both fields from ``TraceService``.  The
        compatibility fill keeps persisted pre-contract evidence readable
        without weakening the public AgentRunEvent projection, which replaces
        the unknown target with the session's verified target before serving it.
        """

        if isinstance(value, dict):
            data = dict(value)
            data.setdefault("run_id", data.get("session_id") or "UNKNOWN")
            data.setdefault("target_id", "UNKNOWN")
            return data
        return value


class TraceSession(MvpModel):
    schema_version: Literal["rolo-mvp-trace-session/v1"] = "rolo-mvp-trace-session/v1"
    session_id: str
    target_id: str
    catalog_digest: str
    task: str
    mode: RunMode
    state: SessionState = SessionState.DISCOVERED
    created_at: datetime
    expires_at: datetime
    max_calls: int
    operator_id: str | None = None
    safety_confirmed: bool = False
    calls: int = 0
    events: list[TraceEvent] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    release_digest: str | None = None
    compile_context_digest: str | None = None
    target_fingerprint: str | None = None
    scope: tuple[str, ...] = ()
    operation_ids: list[str] = Field(default_factory=list)
    artifact_index_ref: str | None = None
    diagnosis_attempts: int = Field(default=0, ge=0)
    recovery_attempts: int = Field(default=0, ge=0)
    resume_count: int = Field(default=0, ge=0)


class CertificationCase(MvpModel):
    case_id: str = Field(pattern=r"^[a-z][a-z0-9_.-]{0,63}$")
    description: str = Field(min_length=1, max_length=500)
    tool_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
    arguments: dict[str, Any] = Field(default_factory=dict)
    expected: Any = None
    timeout_s: float = Field(default=30, gt=0, le=300)
    risk: Literal["R0", "R1", "R2"] = "R0"
    stop_condition: str = Field(default="operator stop", max_length=256)


class CertificationSuite(MvpModel):
    schema_version: Literal["rolo-mvp-certification-suite/v1"] = "rolo-mvp-certification-suite/v1"
    suite_id: str = Field(min_length=1, max_length=128)
    target_id: str
    cases: list[CertificationCase] = Field(min_length=1, max_length=100)
    digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")

    def payload(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude={"digest"})

    def computed_digest(self) -> str:
        return hashlib.sha256(json.dumps(self.payload(), sort_keys=True, separators=(",", ":")).encode()).hexdigest()

    def with_digest(self) -> CertificationSuite:
        return self.model_copy(update={"digest": self.computed_digest()})

    @model_validator(mode="after")
    def validate_suite(self) -> CertificationSuite:
        if self.digest is not None and self.digest != self.computed_digest():
            raise ValueError("certification suite digest does not match content")
        return self


class CertificationCaseResult(MvpModel):
    case_id: str
    expected: Any = None
    actual: Any = None
    status: CaseStatus
    operation_ids: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)
    artifact_digests: list[str] = Field(default_factory=list)
    started_at: datetime
    finished_at: datetime
    elapsed_ms: int = Field(ge=0)
    failure_class: str | None = None
    operator_notes: str | None = None
    # Release/context identity is repeated per case so a report remains
    # auditable even when a suite contains multiple tools.
    release_digest: str | None = None
    compile_context_digest: str | None = None
    target_fingerprint: str | None = None
    idempotency_key: str | None = None


class CertificationReport(MvpModel):
    schema_version: Literal["rolo-mvp-certification-report/v1"] = "rolo-mvp-certification-report/v1"
    run_id: str
    target_id: str
    snapshot_digest: str
    suite_digest: str
    results: list[CertificationCaseResult]
    conclusion: Literal["PASS", "CONDITIONAL", "BLOCKED"]
    artifact_digests: list[str] = Field(default_factory=list)
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    limitations: list[str] = Field(default_factory=list)
    compile_context_digest: str | None = None
    target_fingerprint: str | None = None
    failure_policy: Literal["continue", "fail_fast"] = "continue"
    event_count: int = Field(default=0, ge=0)


class CertifyRequest(MvpModel):
    """Explicit Agent request for a certification run.

    Certify is intentionally a separate request type: no Trace endpoint may
    implicitly create a test run.  ``suite_ref`` is resolved by the Rolo
    process and must point at a regular, non-symlink file.
    """

    schema_version: Literal["rolo-certify-request/v1"] = "rolo-certify-request/v1"
    target_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
    suite_ref: str = Field(min_length=1, max_length=1024)
    snapshot_digest: str = Field(default="UNKNOWN", max_length=256)
    compile_context_digest: str | None = Field(default=None, max_length=256)
    target_fingerprint: str | None = Field(default=None, max_length=256, pattern=r"^[0-9a-f]{64}$|^UNKNOWN$")
    failure_policy: Literal["continue", "fail_fast"] = "continue"
    session_id: str | None = Field(default=None, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class TraceStartRequest(MvpModel):
    """Convenience envelope for the single-call Trace connector endpoint."""

    request: TraceSessionRequest
    calls: list[TraceCall] = Field(default_factory=list, max_length=128)
