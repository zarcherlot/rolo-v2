"""Evidence wrapper for deciding whether an MHS manifest is confirmed.

``MhsDeviceManifest`` describes a device, but its presence alone is not proof
that the device was observed on a target.  This wrapper keeps confirmation
status, identity stability, and source evidence beside the manifest so a
discovery record cannot accidentally become write-eligible.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .mhs_hardware import MhsDeviceManifest


class MhsSafetyEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal["VERIFIED", "UNVERIFIED", "FAILED", "NOT_OBSERVED"]
    source_refs: list[str] = Field(default_factory=list)
    notes: str = ""


class MhsSafetyEvidenceBundle(BaseModel):
    """Independent evidence required before a physical write can be enabled."""

    model_config = ConfigDict(extra="forbid")

    external_estop: MhsSafetyEvidence
    stop: MhsSafetyEvidence
    rollback: MhsSafetyEvidence
    watchdog: MhsSafetyEvidence
    no_load: MhsSafetyEvidence

    def is_write_ready(self) -> bool:
        return all(
            item.status == "VERIFIED"
            for item in (
                self.external_estop,
                self.stop,
                self.rollback,
                self.watchdog,
                self.no_load,
            )
        )


class MhsHardwareBinding(BaseModel):
    """Evidence-backed mapping from an MHS resource to control/feedback paths."""

    model_config = ConfigDict(extra="forbid")

    hardware_resource_id: str = Field(
        min_length=1, pattern=r"^[a-z][a-z0-9_.:/-]*$"
    )
    controller_manifest_device_id: str = Field(min_length=1)
    control_endpoint: str = Field(min_length=1)
    feedback_routes: list[str] = Field(min_length=1)
    limit_sources: list[str] = Field(min_length=1)


class MhsManifestRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["rolo-mhs-manifest-record/v1"] = (
        "rolo-mhs-manifest-record/v1"
    )
    manifest: MhsDeviceManifest
    confirmation_status: Literal[
        "CONFIRMED_READ_ONLY",
        "CONFIRMED_BOUND_WRITE_BLOCKED",
        "DISCOVERED_UNVERIFIED",
    ]
    identity_stability: Literal["stable", "path", "unknown"]
    source_refs: list[str] = Field(min_length=1)
    evidence_ids: list[str] = Field(min_length=1)
    observed_at: datetime
    limitations: list[str] = Field(default_factory=list)
    hardware_bindings: list[MhsHardwareBinding] = Field(default_factory=list)
    safety_evidence: MhsSafetyEvidenceBundle | None = None

    @model_validator(mode="after")
    def validate_confirmation(self) -> MhsManifestRecord:
        if self.confirmation_status == "CONFIRMED_READ_ONLY":
            if self.identity_stability != "stable" or not self.manifest.serial:
                raise ValueError(
                    "confirmed MHS manifest requires stable identity and serial"
                )
            if self.manifest.commands:
                raise ValueError(
                    "confirmed read-only MHS manifest cannot contain write commands"
                )
        if self.confirmation_status == "CONFIRMED_BOUND_WRITE_BLOCKED":
            if self.identity_stability != "stable" or not self.manifest.serial:
                raise ValueError(
                    "bound MHS manifest requires stable identity and serial"
                )
            if not self.manifest.commands or not self.hardware_bindings:
                raise ValueError(
                    "bound MHS manifest requires declared commands and hardware bindings"
                )
            if self.safety_evidence is None or self.safety_evidence.is_write_ready():
                raise ValueError(
                    "bound write-blocked manifest must retain incomplete safety evidence"
                )
        if self.confirmation_status == "DISCOVERED_UNVERIFIED" and not self.limitations:
            raise ValueError("unverified MHS manifest must state its limitations")
        return self


__all__ = [
    "MhsSafetyEvidence",
    "MhsSafetyEvidenceBundle",
    "MhsHardwareBinding",
    "MhsManifestRecord",
]
