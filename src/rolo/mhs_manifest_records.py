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


class MhsManifestRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["rolo-mhs-manifest-record/v1"] = (
        "rolo-mhs-manifest-record/v1"
    )
    manifest: MhsDeviceManifest
    confirmation_status: Literal["CONFIRMED_READ_ONLY", "DISCOVERED_UNVERIFIED"]
    identity_stability: Literal["stable", "path", "unknown"]
    source_refs: list[str] = Field(min_length=1)
    evidence_ids: list[str] = Field(min_length=1)
    observed_at: datetime
    limitations: list[str] = Field(default_factory=list)

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
        if self.confirmation_status == "DISCOVERED_UNVERIFIED" and not self.limitations:
            raise ValueError("unverified MHS manifest must state its limitations")
        return self


__all__ = ["MhsManifestRecord"]
