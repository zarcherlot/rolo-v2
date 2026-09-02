"""Target-neutral read-only Linux hardware backend for the MHS profile.

The backend observes procfs/sysfs through a configurable root.  It contains no
board, vendor, address, or credential assumptions; callers supply identity
metadata when building a manifest.
"""

from __future__ import annotations

import hashlib
import math
import platform
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .mhs_hardware import MhsChannel, MhsDeviceClass, MhsDeviceManifest

DRIVER_ID = "rolo.mhs.linux-observer"
DRIVER_VERSION = "0.1.0"
DRIVER_SHA256 = hashlib.sha256(f"{DRIVER_ID}:{DRIVER_VERSION}".encode()).hexdigest()


class LinuxHardwareBackend:
    """Bounded Linux hardware observations, parameterized by filesystem root."""

    def __init__(self, root: str | Path = "/") -> None:
        self.root = Path(root)

    def _read_text(self, path: str, default: str = "") -> str:
        try:
            return (self.root / path.lstrip("/")).read_text(encoding="utf-8").strip("\x00\n ")
        except (OSError, UnicodeError):
            return default

    def _temperature(self) -> float:
        raw = self._read_text("/sys/class/thermal/thermal_zone0/temp")
        if not raw:
            raise RuntimeError("cpu thermal zone is unavailable")
        value = float(raw) / 1000.0
        if not -40.0 <= value <= 125.0:
            raise ValueError("cpu temperature is outside physical bounds")
        return round(value, 3)

    def _memory_percent(self) -> float:
        values: dict[str, int] = {}
        for line in self._read_text("/proc/meminfo").splitlines():
            key, _, value = line.partition(":")
            if key in {"MemTotal", "MemAvailable"}:
                values[key] = int(value.strip().split()[0])
        total, available = values.get("MemTotal", 0), values.get("MemAvailable", 0)
        if total <= 0 or not 0 <= available <= total:
            raise RuntimeError("memory information is unavailable")
        return round((total - available) * 100.0 / total, 3)

    def _load_1m(self) -> float:
        fields = self._read_text("/proc/loadavg").split()
        if not fields:
            raise RuntimeError("load average is unavailable")
        value = float(fields[0])
        if value < 0 or not math.isfinite(value):
            raise ValueError("load average is invalid")
        return round(value, 3)

    def read(self) -> Mapping[str, int | float | bool | str]:
        return {
            "cpu_temperature": self._temperature(),
            "memory_used_percent": self._memory_percent(),
            "load_1m": self._load_1m(),
        }

    def status(self) -> Mapping[str, Any]:
        dev = self.root / "dev"
        uptime = self._read_text("/proc/uptime").split()
        uptime_s = float(uptime[0]) if uptime else None
        return {
            "health": "OK",
            "model": self._read_text("/proc/device-tree/model", platform.machine()),
            "serial": self._read_text("/proc/device-tree/serial-number") or None,
            "kernel": self._read_text("/proc/version").split(" ", 1)[0] or platform.release(),
            "uptime_seconds": round(uptime_s, 3) if uptime_s is not None else None,
            "transports": {
                "i2c": any(dev.glob("i2c-*")),
                "spi": any(dev.glob("spidev*")),
                "gpio": any(dev.glob("gpiochip*")),
                "usb": (self.root / "sys/bus/usb").exists(),
            },
            "read_only": True,
        }


def build_linux_manifest(
    *,
    device_id: str,
    name: str,
    vendor: str,
    model: str,
    serial: str | None = None,
    device_class: MhsDeviceClass = MhsDeviceClass.COMPUTE,
    transport_target: str = "local-linux",
) -> MhsDeviceManifest:
    """Create a generic manifest; target identity is an explicit caller input."""

    return MhsDeviceManifest(
        device_id=device_id,
        device_class=device_class,
        name=name,
        vendor=vendor,
        model=model,
        serial=serial,
        channels=[
            MhsChannel(
                id="cpu_temperature",
                name="CPU temperature",
                unit="degC",
                min_value=-40,
                max_value=125,
            ),
            MhsChannel(
                id="memory_used_percent",
                name="Memory used",
                unit="percent",
                min_value=0,
                max_value=100,
            ),
            MhsChannel(id="load_1m", name="One minute load average", unit="load", min_value=0),
        ],
        resources=["cpu", "memory", "thermal-zone0"],
        state={"read": ["health", "model", "serial", "transports"]},
        commands=[],
        transport={"kind": "local-linux", "properties": {"target": transport_target}},
        limits=["read-only", "procfs/sysfs bounded reads", "no device writes"],
        driver_id=DRIVER_ID,
        driver_version=DRIVER_VERSION,
        driver_sha256=DRIVER_SHA256,
    )


__all__ = [
    "DRIVER_ID",
    "DRIVER_VERSION",
    "DRIVER_SHA256",
    "LinuxHardwareBackend",
    "build_linux_manifest",
]
