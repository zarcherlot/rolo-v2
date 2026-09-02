"""Software-environment adapter SPI for the MHS provider.

MHS models a physical device; this module models how a driver reaches it.  A
single ``MhsDeviceManifest`` can therefore be served by native code, ROS 2,
serial/USB, HTTP, or a simulator without changing the Rolo route or safety
validation.  Adapters only supply the existing read/status backend.
"""

from __future__ import annotations

from enum import Enum
from typing import Protocol

from pydantic import BaseModel, ConfigDict, Field

from .mhs_hardware import MhsBackend, MhsDeviceManifest, MhsDeviceProvider


class MhsSoftwareEnvironment(str, Enum):
    NATIVE = "native"
    ROS2 = "ros2"
    SERIAL = "serial"
    HTTP = "http"
    SIMULATION = "simulation"


class MhsEnvironmentDescriptor(BaseModel):
    """Non-secret description of the software/transport boundary."""

    model_config = ConfigDict(extra="forbid")

    kind: MhsSoftwareEnvironment
    runtime: str = Field(min_length=1)
    version: str | None = None
    endpoint: str | None = None
    properties: dict[str, str] = Field(default_factory=dict)


class MhsEnvironmentAdapter(Protocol):
    """Bridge one software environment to the provider-neutral backend SPI."""

    adapter_id: str
    environment: MhsEnvironmentDescriptor

    def backend_for(self, manifest: MhsDeviceManifest) -> MhsBackend: ...


class MhsAdapterRegistry:
    """Resolve environment adapters without changing device manifests/routes."""

    def __init__(self) -> None:
        self._adapters: dict[str, MhsEnvironmentAdapter] = {}

    def register(self, adapter: MhsEnvironmentAdapter) -> None:
        if not adapter.adapter_id or adapter.adapter_id in self._adapters:
            raise ValueError(f"duplicate or empty MHS adapter id: {adapter.adapter_id!r}")
        self._adapters[adapter.adapter_id] = adapter

    def provider(self, adapter_id: str, manifest: MhsDeviceManifest) -> MhsDeviceProvider:
        try:
            adapter = self._adapters[adapter_id]
        except KeyError as exc:
            raise KeyError(f"unknown MHS environment adapter: {adapter_id}") from exc
        return MhsDeviceProvider(manifest, adapter.backend_for(manifest))

    def descriptors(self) -> list[MhsEnvironmentDescriptor]:
        return [self._adapters[key].environment for key in sorted(self._adapters)]


__all__ = [
    "MhsSoftwareEnvironment",
    "MhsEnvironmentDescriptor",
    "MhsEnvironmentAdapter",
    "MhsAdapterRegistry",
]
