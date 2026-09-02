"""Read-only MHS-compatible adapter for the landerpi Raspberry Pi 5.

The adapter deliberately uses Linux procfs/sysfs only.  It does not execute
commands, touch GPIO/I2C/SPI, or expose credentials.  The same backend can be
run locally on the Pi or imported by Rolo's ``MhsDeviceProvider`` on a
controller that has a mounted target filesystem.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any

DRIVER_ID = "rolo.mhs.landerpi"
DRIVER_VERSION = "0.1.0"
DRIVER_SHA256 = hashlib.sha256(f"{DRIVER_ID}:{DRIVER_VERSION}".encode()).hexdigest()


class LanderPiBackend:
    """Bounded read/status backend for Raspberry Pi Linux hardware facts."""

    def __init__(self, root: str | os.PathLike[str] = "/") -> None:
        self.root = Path(root)

    def _read_text(self, path: str, default: str = "") -> str:
        try:
            return (self.root / path.lstrip("/")).read_text(encoding="utf-8").strip("\x00\n ")
        except (OSError, UnicodeError):
            return default

    def _exists(self, path: str) -> bool:
        return (self.root / path.lstrip("/")).exists()

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
        total = values.get("MemTotal", 0)
        available = values.get("MemAvailable", 0)
        if total <= 0 or available < 0 or available > total:
            raise RuntimeError("memory information is unavailable")
        return round((total - available) * 100.0 / total, 3)

    def _load_1m(self) -> float:
        raw = self._read_text("/proc/loadavg").split()
        if not raw:
            raise RuntimeError("load average is unavailable")
        value = float(raw[0])
        if value < 0:
            raise ValueError("load average cannot be negative")
        return round(value, 3)

    def read(self) -> Mapping[str, int | float | bool | str]:
        return {
            "cpu_temperature": self._temperature(),
            "memory_used_percent": self._memory_percent(),
            "load_1m": self._load_1m(),
        }

    def status(self) -> Mapping[str, Any]:
        model = self._read_text("/proc/device-tree/model", platform.machine())
        serial = self._read_text("/proc/device-tree/serial-number") or None
        uptime = self._read_text("/proc/uptime").split()
        uptime_s = float(uptime[0]) if uptime else None
        transports = {
            "i2c": sorted(Path(self.root / "dev").glob("i2c-*")) != [],
            "spi": sorted(Path(self.root / "dev").glob("spidev*")) != [],
            "gpio": sorted(Path(self.root / "dev").glob("gpiochip*")) != [],
            "usb": self._exists("/sys/bus/usb"),
        }
        return {
            "health": "OK",
            "model": model,
            "serial": serial,
            "kernel": self._read_text("/proc/version").split(" ", 1)[0] or platform.release(),
            "uptime_seconds": round(uptime_s, 3) if uptime_s is not None else None,
            "transports": transports,
            "read_only": True,
        }


def build_manifest(backend: LanderPiBackend | None = None):
    """Build the stable device reference without embedding network secrets."""

    from rolo.mhs_hardware import MhsChannel, MhsDeviceClass, MhsDeviceManifest

    serial = (backend or LanderPiBackend()).status().get("serial")
    return MhsDeviceManifest(
        device_id="landerpi",
        device_class=MhsDeviceClass.COMPUTE,
        name="landerpi Raspberry Pi 5",
        vendor="Raspberry Pi",
        model="Raspberry Pi 5 Model B",
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
        resources=["cpu", "memory", "thermal-zone0", "i2c-1", "spidev10.0", "gpiochip0"],
        state={"read": ["health", "model", "serial", "transports"]},
        commands=[],
        transport={"kind": "local-linux", "properties": {"target": "landerpi"}},
        limits=["read-only", "procfs/sysfs bounded reads", "no GPIO/I2C/SPI writes"],
        driver_id=DRIVER_ID,
        driver_sha256=DRIVER_SHA256,
    )


def collect_raw() -> dict[str, Any]:
    """Collect a dependency-free raw canary payload on the target machine."""

    backend = LanderPiBackend()
    status = dict(backend.status())
    return {
        "schema_version": "rolo-mhs-landerpi-canary/v1",
        "device_id": "landerpi",
        "driver": {"id": DRIVER_ID, "version": DRIVER_VERSION, "sha256": DRIVER_SHA256},
        "manifest": {
            "device_class": "compute",
            "model": status.get("model"),
            "serial": status.get("serial"),
            "transport": "local-linux",
            "read_only": True,
        },
        "status": status,
        "read": dict(backend.read()),
        "observed_at_epoch": time.time(),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="emit one JSON canary payload")
    args = parser.parse_args()
    payload = collect_raw()
    if args.json:
        print(json.dumps(payload, sort_keys=True, separators=(",", ":")))
    else:
        print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
