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
        if not any(item.agent_callable and item.tool_id.startswith("mapping") for item in self.tools):
            # The exact vendor route is unknown until Probe observes it.  Keep this
            # limitation explicit so callers can return BLOCKED instead of guessing.
            if "mapping tool not observed" not in self.limitations:
                self.limitations.append("mapping tool not observed")
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


class TraceEvent(MvpModel):
    schema_version: Literal["rolo-mvp-trace-event/v1"] = "rolo-mvp-trace-event/v1"
    sequence: int = Field(ge=1)
    session_id: str
    state: SessionState
    event: str = Field(min_length=1, max_length=128)
    tool_id: str | None = None
    arguments: dict[str, Any] | None = None
    result: Any = None
    evidence_ids: list[str] = Field(default_factory=list, max_length=128)
    error_code: str | None = None
    created_at: datetime


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
