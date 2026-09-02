from __future__ import annotations

import json
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class HealthState(str, Enum):
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    UNHEALTHY = "UNHEALTHY"


class RobotUseVerdict(str, Enum):
    NORMAL = "NORMAL"
    SUSPECTED_FAILURE = "SUSPECTED_FAILURE"
    FAILURE = "FAILURE"
    UNKNOWN = "UNKNOWN"


class ImageFrame(BaseModel):
    timestamp: datetime
    image_url: str | None = Field(default=None, max_length=8 * 1024 * 1024)
    artifact_ref: str | None = Field(default=None, max_length=512)
    camera_id: str = Field(default="semantic://sensor/front_camera", max_length=256)

    @model_validator(mode="after")
    def require_source(self) -> ImageFrame:
        if not self.image_url and not self.artifact_ref:
            raise ValueError("image_url or artifact_ref is required")
        return self


class RobotUseRequest(BaseModel):
    schema_version: str = "robot-use-request/v1"
    request_id: str = Field(max_length=128)
    robot_id: str = Field(max_length=128)
    execution_id: str = Field(max_length=128)
    test_case_id: str | None = Field(default=None, max_length=128)
    window_start: datetime
    window_end: datetime
    frames: list[ImageFrame] = Field(min_length=1, max_length=16)
    task_contract: dict[str, Any]
    telemetry_summary: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_window(self) -> RobotUseRequest:
        if self.window_end <= self.window_start:
            raise ValueError("window_end must be after window_start")
        context_bytes = len(
            json.dumps(
                {
                    "task_contract": self.task_contract,
                    "telemetry_summary": self.telemetry_summary,
                },
                ensure_ascii=False,
                separators=(",", ":"),
            ).encode("utf-8")
        )
        if context_bytes > 1_000_000:
            raise ValueError("task contract and telemetry exceed the 1000000-byte budget")
        return self


class ObservedFact(BaseModel):
    frame_time: datetime | None = None
    fact: str


class CandidateCause(BaseModel):
    cause: str
    confidence: float = Field(ge=0.0, le=1.0)


class TimeInterval(BaseModel):
    start: datetime
    end: datetime


class RobotUseSupervision(BaseModel):
    schema_version: str = "robot-use-supervision/v1"
    request_id: str
    verdict: RobotUseVerdict
    failure_type: str | None = None
    first_abnormal_interval: TimeInterval | None = None
    expected_behavior: str
    observed_facts: list[ObservedFact] = Field(default_factory=list)
    candidate_causes: list[CandidateCause] = Field(default_factory=list)
    requested_checks: list[str] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0)
    limitations: list[str] = Field(default_factory=list)
    model: str
    model_response_id: str | None = None
    created_at: datetime = Field(default_factory=utc_now)


class RobotCapability(BaseModel):
    schema_version: str
    robot_id: str
    adapter: str
    platform: dict[str, Any]
    geometry: dict[str, Any]
    sensors: dict[str, Any]
    features: dict[str, Any]


class HealthResponse(BaseModel):
    status: HealthState
    service: str = "rolo-control-plane"
    version: str
    robots: int
    robot_use_backend: str
    openai_key_configured: bool
    api_features: list[str] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=utc_now)


class DiscoveryStatus(str, Enum):
    SUCCEEDED = "SUCCEEDED"
    PARTIAL = "PARTIAL"
    UNAVAILABLE = "UNAVAILABLE"
    FAILED = "FAILED"


class ProbeResult(BaseModel):
    layer: str
    status: DiscoveryStatus
    data: dict[str, Any] = Field(default_factory=dict)
    warnings: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    observed_at: datetime = Field(default_factory=utc_now)
    # v2 evidence metadata.  Legacy probe producers may omit these while the
    # RKB envelope builder requires and validates them before publication.
    identity: dict[str, Any] | None = None
    access: Literal["READ_ONLY"] = "READ_ONLY"
    fresh_until: datetime | None = None

    @model_validator(mode="after")
    def validate_freshness_window(self) -> ProbeResult:
        if self.fresh_until is not None and self.fresh_until <= self.observed_at:
            raise ValueError("fresh_until must be after observed_at")
        return self


class ToolDescriptor(BaseModel):
    schema_version: str = "robot-tool/v1"
    operation: str
    canonical_cli: list[str]
    layer: str
    description: str
    risk: str = "R0"
    access: str = "read"
    idempotent: bool = True
    cancelable: bool = False
    availability: str
    adapter: str
    contract_lifecycle: Literal["DRAFT", "GATEABLE", "RELEASED", "DEPRECATED"] = "DRAFT"
    contract_version: str | None = None
    contract_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    data_classification: Literal["PUBLIC", "INTERNAL", "SENSITIVE", "SECRET"] | None = None
    result_semantics: Literal["OBSERVATION", "ACKNOWLEDGEMENT_ONLY", "SESSION_HANDLE"] | None = None
    execution_mode: Literal[
        "REQUEST_RESPONSE", "BOUNDED_STREAM", "SESSION_START", "SESSION_STOP"
    ] = "REQUEST_RESPONSE"
    paired_operation: str | None = None
    replacement_operation: str | None = None
    input_schema: dict[str, Any] = Field(default_factory=lambda: {"type": "object"})
    output_schema: dict[str, Any] = Field(default_factory=lambda: {"type": "object"})
    capability_requirements: list[str] = Field(default_factory=list)
    preconditions: list[str] = Field(default_factory=list)
    postconditions: list[str] = Field(default_factory=list)
    semantic_bindings: list[str] = Field(default_factory=list)
    semantic_units: dict[str, str] = Field(default_factory=dict)
    coordinate_frames: list[str] = Field(default_factory=list)
    time_semantics: str = ""
    side_effects: list[str] = Field(default_factory=list)
    resource_locks: list[str] = Field(default_factory=list)
    max_duration_s: float = 30.0
    rate_limit: str = "on_demand"
    error_codes: list[str] = Field(
        default_factory=lambda: ["UNAVAILABLE", "TIMEOUT", "PROBE_FAILED"]
    )
    retry_policy: str = "bounded_exponential_backoff_for_read_only_probe"
    compensation_operation: str | None = None
    requires_quiescence: bool = False
    observation_overhead: Literal["NEGLIGIBLE", "BOUNDED", "ELEVATED"] = "BOUNDED"
    evidence: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class RouteEvidence(BaseModel):
    """One stable, typed operation route observed or declared during discovery."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["robot-route-evidence/v2"] = "robot-route-evidence/v2"
    resource_id: str = Field(min_length=1)
    kind: Literal["ros_topic", "ros_service", "ros_action", "device", "cli"]
    endpoint: str = Field(min_length=1)
    interface_type: str | None = None
    interface_schema_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    provider_id: str | None = None
    runtime_revision: str | None = None
    observed_at: datetime | None = None
    evidence_origin: Literal["OBSERVED_RUNTIME", "DECLARED_STATIC"]
    source: str = Field(min_length=1)
    limitations: list[str] = Field(default_factory=list)

    @model_validator(mode="before")
    @classmethod
    def migrate_v1(cls, value: Any) -> Any:
        """Accept stored v1 evidence while exposing only the v2 representation."""
        if not isinstance(value, dict):
            return value
        migrated = dict(value)
        endpoint = str(migrated.pop("name", migrated.get("endpoint", ""))).strip()
        kind = str(migrated.get("kind", "")).strip()
        original_endpoint = endpoint
        if kind.startswith("ros_") and endpoint:
            endpoint = f"/{endpoint.lstrip('/')}"
        migrated["endpoint"] = endpoint
        if not migrated.get("resource_id") or migrated["resource_id"] == (
            f"{kind}:{original_endpoint}"
        ):
            migrated["resource_id"] = f"{kind}:{endpoint}"
        observed = bool(migrated.pop("observed", False))
        migrated.setdefault(
            "evidence_origin",
            "OBSERVED_RUNTIME" if observed else "DECLARED_STATIC",
        )
        migrated["schema_version"] = "robot-route-evidence/v2"
        return migrated

    @property
    def observed(self) -> bool:
        return self.evidence_origin == "OBSERVED_RUNTIME"


class OperationCandidate(BaseModel):
    """Untrusted applicability and binding evidence from discovery."""

    model_config = ConfigDict(extra="forbid")

    operation: str
    semantic_bindings: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    route_evidence: list[RouteEvidence] = Field(default_factory=list)
    route_binding_mode: Literal["ALL_OF", "ANY_OF"] = "ALL_OF"
    executable_ids: list[str] = Field(default_factory=list)
    hardware_resource_ids: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    status: Literal["DISCOVERED_UNVERIFIED"] = "DISCOVERED_UNVERIFIED"
    origin: Literal["DETERMINISTIC", "HEURISTIC_AGENT"] = "DETERMINISTIC"
    semantic_review_required: bool = False
    semantic_review_disposition: Literal["NOT_REVIEWED", "ACCEPT", "DEFER", "REJECT"] = (
        "NOT_REVIEWED"
    )
    route_review_dispositions: dict[str, Literal["ACCEPT", "DEFER", "REJECT"]] = Field(
        default_factory=dict
    )
    semantic_review_artifact_sha256: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )

    @property
    def requires_semantic_review(self) -> bool:
        """Fail closed for legacy CLI candidates that lack the explicit flag."""

        return self.semantic_review_required or (
            any(route.kind == "cli" for route in self.route_evidence)
            and any(uri.startswith("semantic://cli/") for uri in self.semantic_bindings)
        )


class DiscoveryReport(BaseModel):
    schema_version: str = "robot-discovery/v1"
    discovery_id: str
    robot_id: str
    status: DiscoveryStatus
    platform: dict[str, Any]
    capability_manifest: dict[str, Any]
    probes: dict[str, ProbeResult]
    semantic_bindings: dict[str, dict[str, Any]] = Field(default_factory=dict)
    operation_candidates: list[OperationCandidate] = Field(default_factory=list)
    software_summary: dict[str, Any] = Field(default_factory=dict)
    software_summary_ref: str = ""
    dependency_report_ref: str = ""
    active_discovery_report_ref: str = ""
    review_ref: str = ""
    discovery_mode: str = ""
    heuristic_analysis_ref: str = ""
    heuristic_status: str = "DISABLED"
    heuristic_mode: str = "disabled"
    heuristic_inferred_operation_count: int = Field(default=0, ge=0)
    heuristic_missing_evidence_count: int = Field(default=0, ge=0)
    source_roots: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=utc_now)


class DiscoveryLatestIndex(BaseModel):
    schema_version: Literal["robot-discovery-latest/v1"] = "robot-discovery-latest/v1"
    robot_id: str
    discovery_id: str
    report_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    manifest_ref: str
    manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    published_at: datetime = Field(default_factory=utc_now)
