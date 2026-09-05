"""A small, provider-neutral MHS-style adapter for physical sensors.

Anthropic's public MHS announcement describes the concepts (a device driver,
machine-readable device reference, and ``read``/``write`` primitives), but the
research-preview wire schema is not public yet.  This module therefore does not
claim official MHS conformance.  It provides a stable compatibility seam that
can be registered in Rolo's existing :class:`~rolo.capabilities.ProviderHost`
and replaced/translated when the final MHS schema is published.
"""

from __future__ import annotations

import math
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any, Protocol

from pydantic import BaseModel, ConfigDict, Field, model_validator
from rolo.capabilities.models import (
    CapabilityAccess,
    CapabilityDescriptor,
    InspectRequest,
    InspectResult,
    InvokeRequest,
    InvokeResult,
    ProviderCapabilitiesResult,
    ProviderCapability,
    ProviderManifest,
    ProviderProbeResult,
    ProviderStatus,
    SemanticLayer,
    TransportDescriptor,
)


class SensorChannel(BaseModel):
    """One measured quantity and its physical safety bounds."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1, pattern=r"^[a-z][a-z0-9_.-]*$")
    name: str = Field(min_length=1)
    unit: str = Field(min_length=1)
    value_type: str = Field(default="number", pattern=r"^(number|boolean)$")
    min_value: float | None = None
    max_value: float | None = None
    nominal_rate_hz: float | None = Field(default=None, gt=0)

    @model_validator(mode="after")
    def validate_bounds(self) -> SensorChannel:
        if (
            self.min_value is not None
            and self.max_value is not None
            and self.min_value > self.max_value
        ):
            raise ValueError("sensor channel min_value cannot exceed max_value")
        return self


class SensorManifest(BaseModel):
    """MHS-style machine-readable reference for one sensor device."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = "mhs-sensor-reference/v0-preview"
    device_id: str = Field(min_length=1, pattern=r"^[a-z][a-z0-9_.-]*$")
    name: str = Field(min_length=1)
    vendor: str = Field(min_length=1)
    model: str = Field(min_length=1)
    serial: str | None = None
    modality: str = Field(min_length=1)
    channels: list[SensorChannel] = Field(min_length=1)
    transport: TransportDescriptor
    safety_limits: list[str] = Field(default_factory=list)
    tags: dict[str, str] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_unique_channels(self) -> SensorManifest:
        ids = [channel.id for channel in self.channels]
        if len(ids) != len(set(ids)):
            raise ValueError("sensor manifest contains duplicate channel IDs")
        return self

    def reference_file(self) -> dict[str, Any]:
        """Return the reference information an agent needs before operating it."""

        return self.model_dump(mode="json")


class SensorBackend(Protocol):
    """Hardware-specific part of a sensor driver.

    ``read`` must return a bounded snapshot keyed by channel ID.  It should not
    return arbitrary device objects or execute shell commands.
    """

    def read(self) -> Mapping[str, int | float | bool]: ...

    def status(self) -> Mapping[str, Any]: ...


class ResettableSensorBackend(SensorBackend, Protocol):
    def reset(self, profile_id: str) -> Mapping[str, Any]: ...


class MhsSensorProvider:
    """Expose a sensor through Rolo's capability-provider SPI.

    The provider offers read-only ``sensor.inspect``, ``sensor.read`` and
    ``sensor.status`` capabilities.  ``sensor.reset`` is added only when the
    backend explicitly implements ``reset`` and remains a write capability;
    :class:`rolo.capabilities.ProviderHost` will require runtime authorization
    before it can be invoked.
    """

    provider_version = "0.1.0"

    def __init__(self, manifest: SensorManifest, backend: SensorBackend) -> None:
        self.sensor = manifest
        self.backend = backend
        self.provider_id = f"mhs.sensor.{manifest.device_id}"
        self._routes = {
            "sensor.inspect": f"mhs://sensor/{manifest.device_id}/inspect",
            "sensor.read": f"mhs://sensor/{manifest.device_id}/read",
            "sensor.status": f"mhs://sensor/{manifest.device_id}/status",
        }
        if callable(getattr(backend, "reset", None)):
            self._routes["sensor.reset"] = f"mhs://sensor/{manifest.device_id}/reset"

    def _manifest(self) -> ProviderManifest:
        return ProviderManifest(
            provider_id=self.provider_id,
            provider_kind="mhs-sensor",
            provider_version=self.provider_version,
            semantic_layers=[SemanticLayer.HARDWARE],
            transport=self.sensor.transport,
            capabilities=[
                ProviderCapability(
                    capability_id=capability_id,
                    capability_version="1.0.0",
                    route_ref=route,
                    evidence=["mhs-sensor-reference:v0-preview"],
                )
                for capability_id, route in sorted(self._routes.items())
            ],
            evidence=[f"mhs-device:{self.sensor.device_id}"],
        )

    def probe(self) -> ProviderProbeResult:
        return ProviderProbeResult(
            status=ProviderStatus.AVAILABLE,
            provider_version=self.provider_version,
            manifest=self._manifest(),
            evidence=["mhs:manifest", "mhs:driver"],
        )

    def capabilities(self) -> ProviderCapabilitiesResult:
        descriptors: list[CapabilityDescriptor] = []
        for capability_id in sorted(self._routes):
            writable = capability_id == "sensor.reset"
            descriptors.append(
                CapabilityDescriptor(
                    capability_id=capability_id,
                    semantic_layer=SemanticLayer.HARDWARE,
                    version="1.0.0",
                    access=CapabilityAccess.WRITE if writable else CapabilityAccess.READ,
                    risk="R2" if writable else "R0",
                    input_schema=self._input_schema(capability_id),
                    output_schema={"type": "object"},
                    constraints=[*self.sensor.safety_limits, "bounded_request_response"],
                    extensions={"mhs_device_id": self.sensor.device_id},
                )
            )
        return ProviderCapabilitiesResult(
            status=ProviderStatus.AVAILABLE,
            provider_version=self.provider_version,
            capabilities=descriptors,
            evidence=["mhs:capability-discovery"],
        )

    def inspect(self, request: InspectRequest) -> InspectResult:
        if request.capability_id == "sensor.inspect":
            return self._ok_inspect(self.sensor.reference_file(), "mhs:reference-file")
        if request.capability_id == "sensor.status":
            try:
                return self._ok_inspect(dict(self.backend.status()), "mhs:status")
            except Exception as exc:  # provider boundary: never leak backend errors
                return self._inspect_error(f"sensor status failed: {type(exc).__name__}")
        return self._inspect_error("capability is not an inspectable sensor capability")

    def invoke(self, request: InvokeRequest) -> InvokeResult:
        if request.capability_id == "sensor.read":
            return self._read()
        if request.capability_id == "sensor.status":
            try:
                return self._ok_invoke(dict(self.backend.status()), "mhs:status")
            except Exception as exc:
                return self._invoke_error(f"sensor status failed: {type(exc).__name__}")
        if request.capability_id == "sensor.inspect":
            return self._ok_invoke(self.sensor.reference_file(), "mhs:reference-file")
        if request.capability_id == "sensor.reset":
            profile_id = request.arguments.get("profile_id")
            if not isinstance(profile_id, str) or not profile_id.strip():
                return self._invoke_error("profile_id is required")
            try:
                value = self.backend.reset(profile_id)  # type: ignore[attr-defined]
                return self._ok_invoke(dict(value), "mhs:reset")
            except Exception as exc:
                return self._invoke_error(f"sensor reset failed: {type(exc).__name__}")
        return self._invoke_error("unknown sensor capability")

    def _read(self) -> InvokeResult:
        observed_at = datetime.now(timezone.utc).isoformat()
        try:
            values = dict(self.backend.read())
            channels = {channel.id: channel for channel in self.sensor.channels}
            unknown = sorted(set(values) - set(channels))
            if unknown:
                raise ValueError(f"backend returned undeclared channels: {', '.join(unknown)}")
            samples = []
            for channel_id, value in sorted(values.items()):
                channel = channels[channel_id]
                if channel.value_type == "number":
                    if isinstance(value, bool) or not isinstance(value, (int, float)):
                        raise ValueError(f"channel {channel_id} is not numeric")
                    if not math.isfinite(float(value)):
                        raise ValueError(f"channel {channel_id} is not finite")
                    if channel.min_value is not None and float(value) < channel.min_value:
                        raise ValueError(f"channel {channel_id} is below its safety limit")
                    if channel.max_value is not None and float(value) > channel.max_value:
                        raise ValueError(f"channel {channel_id} is above its safety limit")
                elif not isinstance(value, bool):
                    raise ValueError(f"channel {channel_id} is not boolean")
                samples.append(
                    {
                        "channel": channel_id,
                        "value": value,
                        "unit": channel.unit,
                        "timestamp": observed_at,
                    }
                )
            return self._ok_invoke(
                {
                    "device_id": self.sensor.device_id,
                    "samples": samples,
                    "observed_at": observed_at,
                },
                "mhs:read",
            )
        except ValueError as exc:
            # Validation failures are safe, actionable driver-boundary errors;
            # do not hide the channel/limit that rejected the sample.
            return self._invoke_error(f"sensor read failed: {exc}")
        except Exception as exc:
            return self._invoke_error(f"sensor read failed: {type(exc).__name__}")

    def _ok_inspect(self, value: dict[str, Any], evidence: str) -> InspectResult:
        return InspectResult(
            status=ProviderStatus.AVAILABLE,
            provider_version=self.provider_version,
            value=value,
            evidence=[evidence],
        )

    def _inspect_error(self, reason: str) -> InspectResult:
        return InspectResult(
            status=ProviderStatus.UNAVAILABLE,
            provider_version=self.provider_version,
            reason=reason,
            evidence=["mhs:inspect-failed"],
        )

    def _ok_invoke(self, value: dict[str, Any], evidence: str) -> InvokeResult:
        return InvokeResult(
            status=ProviderStatus.AVAILABLE,
            provider_version=self.provider_version,
            value=value,
            evidence=[evidence],
        )

    def _invoke_error(self, reason: str) -> InvokeResult:
        return InvokeResult(
            status=ProviderStatus.UNAVAILABLE,
            provider_version=self.provider_version,
            reason=reason,
            evidence=["mhs:invoke-failed"],
        )

    @staticmethod
    def _input_schema(capability_id: str) -> dict[str, Any]:
        if capability_id == "sensor.reset":
            return {
                "type": "object",
                "properties": {"profile_id": {"type": "string", "minLength": 1}},
                "required": ["profile_id"],
                "additionalProperties": False,
            }
        return {"type": "object", "additionalProperties": False}
