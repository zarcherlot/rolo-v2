"""Versioned Probe Context contract used by DSL resolution."""

from typing import Any, Literal

from pydantic import Field

from .contracts import COMPILE_CONTEXT_SCHEMA_VERSION
from .models import StrictModel


class CompileContext(StrictModel):
    """Frozen Probe-derived context consumed by the standalone Compiler."""

    schema_version: Literal["rolo-compile-context/v1"] = COMPILE_CONTEXT_SCHEMA_VERSION
    robot_id: str = Field(min_length=1)
    target_fingerprint: str = Field(min_length=1)
    runtime_revision: str | None = None
    evidence_digest: str = Field(min_length=1)
    evidence_refs: tuple[str, ...] = Field(default_factory=tuple)
    routes: tuple[dict[str, Any], ...] = Field(default_factory=tuple)
    message_schemas: tuple[dict[str, Any], ...] = Field(default_factory=tuple)
    published_tools: tuple[dict[str, Any], ...] = Field(default_factory=tuple)
    mhs_manifest_refs: tuple[str, ...] = Field(default_factory=tuple)
    mhs_manifest_digests: tuple[str, ...] = Field(default_factory=tuple)
    freshness: dict[str, Any] = Field(default_factory=dict)
    limitations: tuple[str, ...] = Field(default_factory=tuple)


# Keep the historical Python import name while exposing the versioned
# contract as ``rolo-compile-context/v1`` on the wire.
ProbeContext = CompileContext


__all__ = ["CompileContext", "ProbeContext"]
