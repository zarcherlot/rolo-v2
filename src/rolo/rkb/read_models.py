"""Typed, read-only projections used by the RKB-2 query facade.

The models in this module deliberately contain no mutating operations.  They
are projections of verified facts and carry enough provenance for an agent to
decide whether a value is usable without opening the source bundle.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Generic, TypeVar

from pydantic import BaseModel, ConfigDict, Field

from .models import FreshnessStatus


class Stability(str, Enum):
    STABLE = "STABLE"
    UNSTABLE = "UNSTABLE"
    UNKNOWN = "UNKNOWN"


class CapabilityState(str, Enum):
    DISCOVERED_UNVERIFIED = "DISCOVERED_UNVERIFIED"
    ELIGIBLE = "ELIGIBLE"
    VERIFIED = "VERIFIED"
    UNAVAILABLE = "UNAVAILABLE"
    STALE = "STALE"


class ReadModelMetadata(BaseModel):
    """Evidence and freshness envelope shared by every typed query result."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = "rkb-read-model-metadata/v1"
    evidence_ids: list[str] = Field(default_factory=list)
    observed_at: datetime | None = None
    fresh_until: datetime | None = None
    limitations: list[str] = Field(default_factory=list)
    status_reason: str = ""


T = TypeVar("T")


class TypedQueryResult(BaseModel, Generic[T]):
    """A typed value plus fail-closed query metadata."""

    model_config = ConfigDict(arbitrary_types_allowed=True, extra="forbid")

    schema_version: str = "rkb-typed-query-result/v1"
    status: FreshnessStatus | CapabilityState
    value: T | None = None
    evidence_ids: list[str] = Field(default_factory=list)
    observed_at: datetime | None = None
    fresh_until: datetime | None = None
    limitations: list[str] = Field(default_factory=list)
    status_reason: str = ""
    total: int | None = None
    offset: int = 0
    limit: int | None = None
    next_offset: int | None = None


class RobotIdentityModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = "robot-snapshot-identity/v1"
    robot_id: str
    target_host_fingerprint: str
    collector_id: str
    deployment_mode: str
    access: str = "READ_ONLY"
    request_nonce: str | None = None
    identity_status: str = "VERIFIED"
    observed_at: datetime | None = None
    fresh_until: datetime | None = None


class UnknownValue(BaseModel):
    """Structured absence of an observation; never an implicit default."""

    model_config = ConfigDict(extra="forbid")

    status: str = "UNKNOWN"
    reason: str = "not observed"


class RuntimeStatusModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = "rkb-runtime-status/v1"
    state: str = "UNKNOWN"
    os_name: str | None = None
    os_version: str | None = None
    kernel: str | None = None
    architecture: str | None = None
    hostname: str | None = None
    ros_distro: str | None = None
    ros_version: str | None = None
    ros_domain_id: int | UnknownValue = Field(default_factory=UnknownValue)
    rmw_implementation: str | UnknownValue = Field(default_factory=UnknownValue)


class HardwareResourceModel(BaseModel):
    model_config = ConfigDict(extra="allow")

    schema_version: str = "rkb-hardware-resource/v1"
    resource_id: str
    kind: str = "UNKNOWN"
    name: str | None = None
    serial: str | None = None
    transport: str | None = None
    address: str | None = None
    path: str | None = None
    provider_id: str | None = None
    stability: Stability = Stability.UNKNOWN
    limitations: list[str] = Field(default_factory=list)


class HardwareInventoryModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = "rkb-hardware-inventory/v1"
    resources: list[HardwareResourceModel] = Field(default_factory=list)


class MiddlewareEndpointModel(BaseModel):
    model_config = ConfigDict(
        extra="allow",
        populate_by_name=True,
        serialize_by_alias=True,
    )

    schema_version: str = "rkb-middleware-endpoint/v1"
    route_id: str
    role: str = "UNKNOWN"
    node: str | None = None
    interface: str | None = None
    schema_: str | None = Field(default=None, alias="schema")
    provider: str | None = None
    runtime_revision: str | None = None
    observed_at: datetime | None = None
    fresh_until: datetime | None = None
    stability: Stability = Stability.UNKNOWN
    endpoint: str | None = None
    limitations: list[str] = Field(default_factory=list)

    @property
    def schema(self) -> str | None:
        """Compatibility accessor for the wire-level ``schema`` field."""

        return self.schema_


class MiddlewareRelationshipModel(BaseModel):
    model_config = ConfigDict(extra="allow")

    schema_version: str = "rkb-middleware-relationship/v1"
    relationship_id: str
    source: str | None = None
    target: str | None = None
    role: str = "UNKNOWN"
    interface: str | None = None
    limitations: list[str] = Field(default_factory=list)


class MiddlewareGraphModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = "rkb-middleware-graph/v1"
    endpoints: list[MiddlewareEndpointModel] = Field(default_factory=list)
    relationships: list[MiddlewareRelationshipModel] = Field(default_factory=list)


class ExecutableModel(BaseModel):
    model_config = ConfigDict(extra="allow")

    schema_version: str = "rkb-executable/v1"
    executable_id: str
    name: str
    executable_hash: str | None = None
    shebang: str | None = None
    interpreter: str | None = None
    source_kind: str = "OBSERVED"
    observed: bool = False
    limitations: list[str] = Field(default_factory=list)


class CapabilityRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = "rkb-capability-record/v1"
    operation_id: str
    state: CapabilityState
    reason: str
    source_kind: str | None = None
    fingerprint: str | None = None
    limitations: list[str] = Field(default_factory=list)


class StateSafetyModel(BaseModel):
    model_config = ConfigDict(extra="allow")

    schema_version: str = "rkb-state-safety/v1"
    state: str = "UNKNOWN"
    observed_fields: dict[str, Any] = Field(default_factory=dict)
    safety_status: str = "UNKNOWN"
