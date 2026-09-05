"""Versioned Probe Context contract used by DSL resolution."""

from typing import Any

from pydantic import Field

from .models import StrictModel


class ProbeContext(StrictModel):
    schema_version: str = "rolo-probe-context/v1"
    robot_id: str = Field(min_length=1)
    target_fingerprint: str = Field(min_length=1)
    evidence_digest: str = Field(min_length=1)
    evidence_refs: tuple[str, ...] = Field(default_factory=tuple)
    routes: tuple[dict[str, Any], ...] = Field(default_factory=tuple)
    message_schemas: tuple[dict[str, Any], ...] = Field(default_factory=tuple)
    mhs_manifest_refs: tuple[str, ...] = Field(default_factory=tuple)
    mhs_manifest_digests: tuple[str, ...] = Field(default_factory=tuple)
    freshness: dict[str, Any] = Field(default_factory=dict)
    limitations: tuple[str, ...] = Field(default_factory=tuple)
