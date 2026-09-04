"""Sanitized LanderPi MHS provisional fixtures and deterministic replay helpers.

Fixtures are test evidence only.  They are never treated as vendor authority
and expose no transport or write operation.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator


class MhsProvisionalFixture(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = "rolo-mhs-provisional-fixture/v1"
    fixture_id: str = Field(min_length=1)
    target_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_kind: str = "TEST_FIXTURE"
    authority: str = "PROVISIONAL"
    access: str = "READ_ONLY"
    generated_by: str = Field(min_length=1)
    generated_at: datetime
    input_evidence_ids: list[str] = Field(default_factory=list)
    samples: dict[str, Any] = Field(default_factory=dict)
    freshness: str = "UNKNOWN"
    digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    not_vendor_manifest: bool = True
    not_release_authority: bool = True

    @model_validator(mode="after")
    def validate_provisional(self) -> MhsProvisionalFixture:
        if self.source_kind != "TEST_FIXTURE" or self.authority != "PROVISIONAL":
            raise ValueError("fixture must remain TEST_FIXTURE/PROVISIONAL")
        if self.access != "READ_ONLY":
            raise ValueError("fixture access must be READ_ONLY")
        if not self.not_vendor_manifest or not self.not_release_authority:
            raise ValueError("fixture must not claim vendor or release authority")
        if self.samples.get("write_operations", 0) != 0:
            raise ValueError("fixture cannot contain write operations")
        if self.computed_digest() != self.digest:
            raise ValueError("fixture digest does not match content")
        return self

    def _digest_payload(self) -> dict[str, Any]:
        payload = self.model_dump(mode="python", exclude={"digest"})
        return payload

    def computed_digest(self) -> str:
        encoded = json.dumps(
            self._digest_payload(),
            sort_keys=True,
            separators=(",", ":"),
            default=lambda value: value.isoformat() if isinstance(value, datetime) else str(value),
        ).encode()
        return hashlib.sha256(encoded).hexdigest()


def load_fixture(path: str | Path) -> MhsProvisionalFixture:
    return MhsProvisionalFixture.model_validate_json(Path(path).read_text(encoding="utf-8"))


def replay_fixture(fixture: MhsProvisionalFixture, *, target_fingerprint: str) -> dict[str, Any]:
    """Return a read-only replay snapshot bound to the requested target."""

    if target_fingerprint != fixture.target_fingerprint:
        raise ValueError("fixture target fingerprint mismatch")
    return {
        "schema_version": "rolo-mhs-read-only/v1",
        "device_id": "landerpi-provisional",
        "provider_id": "fixture.landerpi",
        "target_fingerprint": fixture.target_fingerprint,
        "route": "fixture://landerpi/read",
        "operation": "read",
        "status": "AVAILABLE" if fixture.freshness == "FRESH" else fixture.freshness,
        "value": fixture.samples,
        "observed_at": fixture.generated_at.isoformat(),
        "evidence_ids": fixture.input_evidence_ids,
        "limitations": ["provisional fixture", "not vendor manifest", "replay only"],
        "access": "READ_ONLY",
    }


__all__ = ["MhsProvisionalFixture", "load_fixture", "replay_fixture"]
