"""Typed, deterministic handoff plans produced by DSL backends."""

from __future__ import annotations

from pathlib import PurePosixPath
from typing import Any, Literal

from pydantic import Field, field_validator, model_validator

from .contracts import BUNDLE_PLAN_SCHEMA_VERSION, LEGACY_BUNDLE_PLAN_SCHEMA_VERSION
from .models import OperationKind, StrictModel

_FORBIDDEN_BINDING_KEYS = frozenset(
    {
        "eval",
        "exec",
        "network_access",
        "python",
        "python_code",
        "raw_address",
        "script",
        "shell",
        "shell_command",
        "source_code",
    }
)


class BundlePlanVersionError(ValueError):
    """Raised when a legacy plan must be recompiled instead of consumed."""


class LegacyBundlePlanV1(StrictModel):
    """Recognition-only model for the incomplete five-field v1 artifact."""

    schema_version: Literal["rolo-bundle-plan/v1"]
    tool_id: str = Field(min_length=1)
    kind: OperationKind
    backend_id: str = Field(min_length=1)
    ir_digest: str

    @field_validator("ir_digest")
    @classmethod
    def canonical_digest(cls, value: str) -> str:
        return _validate_digest(value)


class BundleArtifact(StrictModel):
    """One deterministic, non-self-referential file emitted with a plan."""

    path: str = Field(min_length=1)
    sha256: str
    size: int = Field(ge=0)
    role: str = Field(min_length=1)

    @field_validator("path")
    @classmethod
    def relative_path(cls, value: str) -> str:
        path = PurePosixPath(value)
        if (
            "\\" in value
            or path.is_absolute()
            or ".." in path.parts
            or value in {"", "."}
            or str(path) != value
        ):
            raise ValueError("artifact path must be a normalized relative POSIX path")
        return value

    @field_validator("sha256")
    @classmethod
    def canonical_digest(cls, value: str) -> str:
        return _validate_digest(value)


class BundlePlan(StrictModel):
    """Frozen ``rolo-bundle-plan/v2`` contract consumed after compilation.

    Bindings intentionally remain JSON objects because each backend owns its
    binding vocabulary.  The envelope itself is strict and versioned, so a
    backend cannot silently add handoff fields outside the frozen contract.
    """

    schema_version: Literal["rolo-bundle-plan/v2"]
    tool_id: str = Field(min_length=1)
    kind: OperationKind
    target_fingerprint: str = Field(min_length=1)
    dsl_digest: str
    context_digest: str
    ir_digest: str
    compiler_version: str = Field(min_length=1)
    backend_id: str = Field(min_length=1)
    backend_version: str = Field(min_length=1)
    negotiated_capabilities: tuple[str, ...] = Field(min_length=1)
    entrypoint_contract: Literal["rolo.tool.invoke/v1"]
    bindings: tuple[dict[str, Any], ...]
    runtime_requirements: tuple[str, ...]
    runtime_context: dict[str, Any]
    source_bundle_ref: str | None = Field(min_length=1)
    artifacts: tuple[BundleArtifact, ...] = Field(min_length=1)

    @field_validator("dsl_digest", "context_digest", "ir_digest")
    @classmethod
    def canonical_digest(cls, value: str) -> str:
        return _validate_digest(value)

    @field_validator("negotiated_capabilities", "runtime_requirements")
    @classmethod
    def stable_string_set(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if any(not isinstance(item, str) or not item for item in value):
            raise ValueError("capabilities and runtime requirements must be non-empty strings")
        return tuple(sorted(set(value)))

    @field_validator("bindings")
    @classmethod
    def safe_bindings(cls, value: tuple[dict[str, Any], ...]) -> tuple[dict[str, Any], ...]:
        for binding in value:
            forbidden = _find_forbidden_key(binding)
            if forbidden is not None:
                raise ValueError(f"binding field {forbidden!r} is forbidden in Bundle Plan")
        return value

    @field_validator("artifacts")
    @classmethod
    def stable_artifacts(cls, value: tuple[BundleArtifact, ...]) -> tuple[BundleArtifact, ...]:
        ordered = tuple(sorted(value, key=lambda item: (item.path, item.role, item.sha256, item.size)))
        if len({item.path for item in ordered}) != len(ordered):
            raise ValueError("artifact paths must be unique")
        return ordered

    @model_validator(mode="after")
    def source_matches_kind(self) -> BundlePlan:
        if self.kind == OperationKind.EXECUTE and self.source_bundle_ref is None:
            raise ValueError("EXECUTE Bundle Plan requires source_bundle_ref")
        if self.kind != OperationKind.EXECUTE and self.source_bundle_ref is not None:
            raise ValueError("source_bundle_ref is only valid for EXECUTE Bundle Plan")
        return self

    def __getitem__(self, key: str) -> Any:
        """Retain read-only access used by early bundle-manifest consumers."""

        if key not in type(self).model_fields:
            raise KeyError(key)
        return getattr(self, key)

    def get(self, key: str, default: Any = None) -> Any:
        """Return one plan field without weakening the strict model."""

        if key not in type(self).model_fields:
            return default
        return getattr(self, key)


def parse_bundle_plan(value: BundlePlan | LegacyBundlePlanV1 | dict[str, Any]) -> BundlePlan:
    """Parse a current plan and fail explicitly for incomplete legacy v1."""

    if isinstance(value, BundlePlan):
        return BundlePlan.model_validate(value.model_dump(mode="json"))
    if isinstance(value, LegacyBundlePlanV1):
        raise BundlePlanVersionError("BUNDLE_PLAN_V1_RECOMPILE_REQUIRED")
    version = value.get("schema_version")
    if version is None:
        raise BundlePlanVersionError("BUNDLE_PLAN_VERSION_REQUIRED")
    if version == LEGACY_BUNDLE_PLAN_SCHEMA_VERSION:
        LegacyBundlePlanV1.model_validate(value)
        raise BundlePlanVersionError("BUNDLE_PLAN_V1_RECOMPILE_REQUIRED")
    if version != BUNDLE_PLAN_SCHEMA_VERSION:
        raise BundlePlanVersionError("BUNDLE_PLAN_VERSION_UNSUPPORTED")
    return BundlePlan.model_validate(value)


def _validate_digest(value: str) -> str:
    prefix, separator, digest = value.partition(":")
    if prefix != "sha256" or separator != ":" or len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
        raise ValueError("digest must use sha256:<64 lowercase hex> format")
    return value


def _find_forbidden_key(value: Any) -> str | None:
    if isinstance(value, dict):
        for key, nested in value.items():
            normalized = str(key).lower()
            if normalized in _FORBIDDEN_BINDING_KEYS:
                return str(key)
            found = _find_forbidden_key(nested)
            if found is not None:
                return found
    elif isinstance(value, (list, tuple)):
        for nested in value:
            found = _find_forbidden_key(nested)
            if found is not None:
                return found
    return None


__all__ = [
    "BundleArtifact",
    "BundlePlan",
    "BundlePlanVersionError",
    "LegacyBundlePlanV1",
    "parse_bundle_plan",
]
