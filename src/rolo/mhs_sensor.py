"""Canonical MHS sensor entry point (v2 read-only profile)."""

from .mhs_hardware import MhsBackend as SensorBackend
from .mhs_hardware import MhsChannel as SensorChannel
from .mhs_hardware import MhsDeviceManifest as SensorManifest
from .mhs_hardware import MhsDeviceProvider as MhsSensorProvider

__all__ = ["MhsSensorProvider", "SensorBackend", "SensorChannel", "SensorManifest"]
