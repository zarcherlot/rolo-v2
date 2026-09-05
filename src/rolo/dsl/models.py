"""Schema-level models for the versioned Rolo DSL contract."""

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from rolo._compat import StrEnum


class OperationKind(StrEnum):
    OBSERVE = "OBSERVE"
    COMPOSE = "COMPOSE"
    INVOKE = "INVOKE"
    EXECUTE = "EXECUTE"


class OperationStatus(StrEnum):
    PROPOSED = "PROPOSED"
    CONFORMANT = "CONFORMANT"
    PUBLISHED = "PUBLISHED"
    STALE = "STALE"
    BLOCKED = "BLOCKED"


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class TargetBinding(StrictModel):
    robot_id: str = Field(min_length=1)
    evidence_digest: str = Field(min_length=1)
    mhs_manifest_refs: tuple[str, ...] = ()


class DslDocument(StrictModel):
    """Minimal top-level DSL document; semantic checks belong to the frontend."""

    schema_version: str = "rolo-dsl/v1"
    tool_id: str = Field(min_length=1)
    kind: OperationKind
    status: OperationStatus = OperationStatus.PROPOSED
    target: TargetBinding
    binding: dict[str, Any] = Field(default_factory=dict)
    input_schema: dict[str, Any] = Field(default_factory=dict)
    output_schema: dict[str, Any] = Field(default_factory=dict)
    mapping: dict[str, Any] = Field(default_factory=dict)
    preconditions: tuple[dict[str, Any], ...] = Field(default_factory=tuple)
    error_mapping: dict[str, Any] = Field(default_factory=dict)
    composition: dict[str, Any] = Field(default_factory=dict)
    implementation: dict[str, Any] = Field(default_factory=dict)
    evidence_refs: tuple[str, ...] = Field(default_factory=tuple)

    @field_validator("schema_version")
    @classmethod
    def supported_schema(cls, value: str) -> str:
        if value != "rolo-dsl/v1":
            raise ValueError("unsupported DSL schema version")
        return value
