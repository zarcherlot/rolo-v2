"""Dependency-free, target-neutral Linux MHS observation recorder."""

from __future__ import annotations

import json
import platform
import time
from pathlib import Path
from typing import Any


class LinuxObservationCollector:
    def __init__(self, root: str | Path = "/") -> None:
        self.root = Path(root)

    def _text(self, path: str, default: str = "") -> str:
        try:
            return (self.root / path.lstrip("/")).read_text(encoding="utf-8").strip("\x00\n ")
        except (OSError, UnicodeError):
            return default

    def collect(self) -> dict[str, Any]:
        temp = float(self._text("/sys/class/thermal/thermal_zone0/temp")) / 1000
        memory: dict[str, int] = {}
        for line in self._text("/proc/meminfo").splitlines():
            key, _, value = line.partition(":")
            if key in {"MemTotal", "MemAvailable"}:
                memory[key] = int(value.split()[0])
        total = memory["MemTotal"]
        available = memory["MemAvailable"]
        return {
            "schema_version": "rolo-mhs-linux-observation/v1",
            "device_identity": {
                "model": self._text("/proc/device-tree/model", platform.machine()),
                "serial": self._text("/proc/device-tree/serial-number") or None,
            },
            "read": {
                "cpu_temperature": round(temp, 3),
                "memory_used_percent": round((total - available) * 100 / total, 3),
                "load_1m": round(float(self._text("/proc/loadavg").split()[0]), 3),
            },
            "observed_at_epoch": time.time(),
            "read_only": True,
        }


if __name__ == "__main__":
    print(json.dumps(LinuxObservationCollector().collect(), sort_keys=True, separators=(",", ":")))
