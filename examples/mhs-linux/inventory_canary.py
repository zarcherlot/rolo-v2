"""Dependency-free inventory of Linux nodes that can become MHS candidates.

This records discovery only.  It does not probe or write any device and does
not claim that a candidate is a verified MHS device.
"""

from __future__ import annotations

import json
import platform
import time
from pathlib import Path


def collect(root: str | Path = "/") -> dict:
    root = Path(root)
    def text(path: str, default: str = "") -> str:
        try:
            return (root / path.lstrip("/")).read_text(encoding="utf-8").strip("\x00\n ")
        except (OSError, UnicodeError):
            return default

    nodes = []
    for pattern, kind in (("dev/i2c-*", "i2c"), ("dev/spidev*", "spi"), ("dev/gpiochip*", "gpio")):
        for path in sorted(root.glob(pattern)):
            nodes.append({"kind": kind, "path": "/" + path.relative_to(root).as_posix(), "status": "DISCOVERED_UNVERIFIED"})
    for path in sorted((root / "sys/class/thermal").glob("thermal_zone*/temp")):
        zone = path.parent.name
        nodes.append({"kind": "thermal", "path": f"/sys/class/thermal/{zone}", "status": "DISCOVERED_UNVERIFIED"})
    return {
        "schema_version": "rolo-mhs-linux-inventory/v1",
        "device_identity": {
            "model": text("/proc/device-tree/model", platform.machine()),
            "serial": text("/proc/device-tree/serial-number") or None,
        },
        "nodes": nodes,
        "observed_at_epoch": time.time(),
        "read_only": True,
    }


if __name__ == "__main__":
    print(json.dumps(collect(), sort_keys=True, separators=(",", ":")))
