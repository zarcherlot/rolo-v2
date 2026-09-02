"""Rolo-owned, read-only MHS-compatible provider seam.

This is intentionally independent of any unpublished vendor MHS wire schema.
It exposes only inspect/status/read for v2; write-like capability ids are
rejected at the provider boundary and cannot be enabled by a backend method.
"""

from __future__ import annotations

import hashlib
import math
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Protocol

from pydantic import BaseModel, ConfigDict, Field, model_validator


class MhsStatus(str, Enum):
    AVAILABLE = "AVAILABLE"
    UNAVAILABLE = "UNAVAILABLE"
    STALE = "STALE"


class MhsDeviceClass(str, Enum):
    SENSOR = "sensor"
    CONTROLLER = "controller"
    ACTUATOR = "actuator"
    POWER = "power"
    COMPUTE = "compute"
    BUS = "bus"
    TOOL = "tool"


class MhsChannel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1, pattern=r"^[a-z][a-z0-9_.-]*$")
    name: str = Field(min_length=1)
    unit: str = Field(min_length=1)
    value_type: str = Field(default="number", pattern=r"^(number|boolean|string)$")
    min_value: float | None = None
    max_value: float | None = None

    @model_validator(mode="after")
    def valid_bounds(self) -> MhsChannel:
        if (
            self.min_value is not None
            and self.max_value is not None
            and self.min_value > self.max_value
        ):
            raise ValueError("channel min_value cannot exceed max_value")
        return self


class MhsDeviceManifest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = "rolo-mhs-device/v1"
    device_id: str = Field(min_length=1, pattern=r"^[a-z][a-z0-9_.-]*$")
    device_class: MhsDeviceClass
    name: str = Field(min_length=1)
    vendor: str = Field(min_length=1)
    model: str = Field(min_length=1)
    serial: str | None = None
    channels: list[MhsChannel] = Field(default_factory=list)
    resources: list[str] = Field(default_factory=list)
    transport: dict[str, Any] = Field(default_factory=dict)
    limits: list[str] = Field(default_factory=list)
    driver_id: str = Field(default="unknown-driver", min_length=1)
    driver_sha256: str = Field(default="0" * 64, pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def unique_channels(self) -> MhsDeviceManifest:
        ids = [item.id for item in self.channels]
        if len(ids) != len(set(ids)):
            raise ValueError("manifest contains duplicate channel ids")
        return self

    @property
    def manifest_sha256(self) -> str:
        payload = self.model_dump(mode="json")
        import json

        return hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()


class MhsBackend(Protocol):
    def read(self) -> Mapping[str, int | float | bool | str]: ...

    def status(self) -> Mapping[str, Any]: ...


class MhsResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: MhsStatus
    device_id: str
    capability_id: str
    route: str
    value: dict[str, Any] | None = None
    observed_at: datetime | None = None
    fresh_until: datetime | None = None
    manifest_sha256: str | None = None
    driver_version: str | None = None
    transport: dict[str, Any] = Field(default_factory=dict)
    reason: str | None = None
    evidence_ids: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class MhsDeviceProvider:
    """Read-only Provider SPI for one MHS device manifest and backend."""

    provider_version = "1.0.0"
    freshness_seconds = 300
    READ_CAPABILITIES = frozenset({"inspect", "status", "read"})

    def __init__(self, manifest: MhsDeviceManifest, backend: MhsBackend) -> None:
        self.manifest = manifest
        self.backend = backend
        self.provider_id = f"mhs.{manifest.device_id}"

    def route(self, capability_id: str) -> str:
        capability = capability_id.removeprefix("mhs.")
        return f"mhs://{self.manifest.device_id}/{capability}"

    def capabilities(self) -> list[dict[str, Any]]:
        return [
            {
                "capability_id": capability,
                "access": "read",
                "route": self.route(capability),
                "status": "DISCOVERED_UNVERIFIED",
                "evidence_ids": [f"mhs-manifest:{self.manifest.manifest_sha256}"],
            }
            for capability in sorted(self.READ_CAPABILITIES)
        ]

    def inspect(self) -> MhsResult:
        return self._ok("inspect", self.manifest.model_dump(mode="json"))

    def status(self) -> MhsResult:
        try:
            return self._ok("status", dict(self.backend.status()))
        except Exception as exc:
            return self._error("status", f"backend status failed: {type(exc).__name__}")

    def read(self) -> MhsResult:
        capability = "read"
        observed_at = datetime.now(timezone.utc)
        try:
            values = dict(self.backend.read())
            channels = {channel.id: channel for channel in self.manifest.channels}
            unknown = sorted(set(values) - set(channels))
            if unknown:
                raise ValueError(f"undeclared channels: {', '.join(unknown)}")
            samples: list[dict[str, Any]] = []
            for channel_id, value in sorted(values.items()):
                channel = channels[channel_id]
                if channel.value_type == "number":
                    if (
                        isinstance(value, bool)
                        or not isinstance(value, (int, float))
                        or not math.isfinite(float(value))
                    ):
                        raise ValueError(f"channel {channel_id} is not a finite number")
                    if channel.min_value is not None and float(value) < channel.min_value:
                        raise ValueError(f"channel {channel_id} is below its minimum")
                    if channel.max_value is not None and float(value) > channel.max_value:
                        raise ValueError(f"channel {channel_id} is above its maximum")
                elif channel.value_type == "boolean" and not isinstance(value, bool):
                    raise ValueError(f"channel {channel_id} is not boolean")
                elif channel.value_type == "string" and not isinstance(value, str):
                    raise ValueError(f"channel {channel_id} is not string")
                samples.append({"channel": channel_id, "value": value, "unit": channel.unit})
            return self._ok(
                capability,
                {"device_id": self.manifest.device_id, "samples": samples},
                observed_at,
            )
        except ValueError as exc:
            return self._error(capability, f"read rejected: {exc}")
        except Exception as exc:
            return self._error(capability, f"backend read failed: {type(exc).__name__}")

    def invoke(self, capability_id: str, arguments: Mapping[str, Any] | None = None) -> MhsResult:
        """Invoke only read capabilities; all write-like requests fail closed."""

        del arguments
        capability = capability_id.removeprefix("mhs.")
        if capability == "inspect":
            return self.inspect()
        if capability == "status":
            return self.status()
        if capability == "read":
            return self.read()
        return self._error(capability, "write or unknown capability is not available in v2")

    def _ok(
        self, capability: str, value: dict[str, Any], observed_at: datetime | None = None
    ) -> MhsResult:
        point = observed_at or datetime.now(timezone.utc)
        return MhsResult(
            status=MhsStatus.AVAILABLE,
            device_id=self.manifest.device_id,
            capability_id=capability,
            route=self.route(capability),
            value=value,
            observed_at=point,
            fresh_until=point + timedelta(seconds=self.freshness_seconds),
            manifest_sha256=self.manifest.manifest_sha256,
            driver_version=self.provider_version,
            transport=self.manifest.transport,
            evidence_ids=[
                f"mhs-manifest:{self.manifest.manifest_sha256}",
                f"mhs-driver:{self.manifest.driver_sha256}",
            ],
        )

    def _error(self, capability: str, reason: str) -> MhsResult:
        point = datetime.now(timezone.utc)
        return MhsResult(
            status=MhsStatus.UNAVAILABLE,
            device_id=self.manifest.device_id,
            capability_id=capability,
            route=self.route(capability),
            reason=reason,
            observed_at=point,
            fresh_until=point + timedelta(seconds=self.freshness_seconds),
            manifest_sha256=self.manifest.manifest_sha256,
            driver_version=self.provider_version,
            transport=self.manifest.transport,
            limitations=["read-only provider; no write operations"],
        )
