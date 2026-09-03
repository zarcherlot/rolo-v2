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
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from .mhs_hardware import MhsBackend, MhsChannel, MhsDeviceClass, MhsDeviceManifest, MhsDeviceProvider

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
    "LinuxPresenceBackend",
    "LinuxThermalBackend",
    "LinuxMhsCandidate",
    "LinuxMhsInventory",
]


class LinuxPresenceBackend:
    """Read-only backend for a discovered node with presence-only semantics."""

    def __init__(self, root: str | Path, node: str, kind: str) -> None:
        self.root, self.node, self.kind = Path(root), node, kind

    def read(self) -> Mapping[str, bool]:
        return {"present": (self.root / self.node.lstrip("/")).exists()}

    def status(self) -> Mapping[str, Any]:
        path = self.root / self.node.lstrip("/")
        return {"health": "OK" if path.exists() else "UNAVAILABLE", "kind": self.kind, "node": self.node}


class LinuxThermalBackend(LinuxHardwareBackend):
    """Linux thermal-zone reader parameterized by zone path."""

    def __init__(self, root: str | Path, zone: str) -> None:
        super().__init__(root)
        self.zone = zone.strip("/")

    def _temperature(self) -> float:
        raw = self._read_text(f"/{self.zone}/temp")
        if not raw:
            raise RuntimeError("thermal zone is unavailable")
        value = float(raw) / 1000.0
        if not -40.0 <= value <= 150.0:
            raise ValueError("thermal reading is outside physical bounds")
        return round(value, 3)

    def read(self) -> Mapping[str, float]:
        return {"temperature": self._temperature()}

    def status(self) -> Mapping[str, Any]:
        return {"health": "OK", "zone": self.zone, "type": self._read_text(f"/{self.zone}/type")}


class LinuxMhsCandidate(BaseModel):
    """A discovered candidate; it is not verified until RKB evidence is added."""

    model_config = ConfigDict(extra="forbid")

    manifest: MhsDeviceManifest
    discovery_status: Literal["DISCOVERED_UNVERIFIED"] = "DISCOVERED_UNVERIFIED"
    source: str = Field(min_length=1)
    identity_stability: Literal["stable", "path", "unknown"] = "unknown"


class LinuxMhsInventory:
    """Discover generic Linux hardware candidates without board assumptions."""

    def __init__(self, root: str | Path = "/", device_prefix: str = "linux") -> None:
        self.root = Path(root)
        self.device_prefix = device_prefix

    def candidates(self) -> list[LinuxMhsCandidate]:
        found: list[LinuxMhsCandidate] = []
        status = LinuxHardwareBackend(self.root).status()
        found.append(
            LinuxMhsCandidate(
                manifest=build_linux_manifest(
                    device_id=f"{self.device_prefix}-compute",
                    name="Linux compute host",
                    vendor="unknown",
                    model=str(status["model"]),
                    serial=status.get("serial"),
                    transport_target="local-linux",
                ),
                source="/proc/device-tree + /proc + /sys",
                identity_stability="stable" if status.get("serial") else "unknown",
            )
        )
        thermal_root = self.root / "sys/class/thermal"
        for zone in sorted(thermal_root.glob("thermal_zone*/temp")):
            zone_name = zone.parent.name
            manifest = MhsDeviceManifest(
                device_id=f"{self.device_prefix}-{zone_name}",
                device_class=MhsDeviceClass.SENSOR,
                name=f"Linux thermal {zone_name}",
                vendor="linux-kernel",
                model=LinuxHardwareBackend(self.root)._read_text(
                    f"/sys/class/thermal/{zone_name}/type", "thermal-zone"
                ),
                channels=[
                    MhsChannel(
                        id="temperature", name="Temperature", unit="degC", min_value=-40, max_value=150
                    )
                ],
                resources=[zone_name],
                state={"read": ["health", "zone", "type"]},
                transport={"kind": "sysfs", "properties": {"path": f"/sys/class/thermal/{zone_name}"}},
                limits=["read-only", "path identity; serial not observed"],
                driver_id=DRIVER_ID,
                driver_version=DRIVER_VERSION,
                driver_sha256=DRIVER_SHA256,
            )
            found.append(
                LinuxMhsCandidate(
                    manifest=manifest,
                    source=f"/sys/class/thermal/{zone_name}",
                    identity_stability="path",
                )
            )
        found.extend(self._presence_candidates("dev/i2c-*", "bus", "i2c"))
        found.extend(self._presence_candidates("dev/spidev*", "bus", "spi"))
        found.extend(self._presence_candidates("dev/gpiochip*", "bus", "gpio"))
        found.extend(
            self._presence_candidates(
                "dev/video*", "camera", "camera", device_class=MhsDeviceClass.SENSOR
            )
        )
        found.extend(self._usb_candidates())
        return found

    def providers(self) -> list[tuple[LinuxMhsCandidate, MhsDeviceProvider]]:
        providers: list[tuple[LinuxMhsCandidate, MhsDeviceProvider]] = []
        for candidate in self.candidates():
            device_id = candidate.manifest.device_id
            if device_id.endswith("-compute"):
                backend: MhsBackend = LinuxHardwareBackend(self.root)
            elif "thermal_zone" in device_id:
                zone = device_id.rsplit("-", 1)[-1]
                backend = LinuxThermalBackend(self.root, f"sys/class/thermal/{zone}")
            else:
                node = candidate.manifest.transport.get("properties", {}).get("path", "")
                backend = LinuxPresenceBackend(self.root, str(node), candidate.manifest.device_class.value)
            providers.append((candidate, MhsDeviceProvider(candidate.manifest, backend)))
        return providers

    def _presence_candidates(
        self,
        pattern: str,
        kind: str,
        label: str,
        *,
        device_class: MhsDeviceClass = MhsDeviceClass.BUS,
    ) -> list[LinuxMhsCandidate]:
        records: list[LinuxMhsCandidate] = []
        for path in sorted(self.root.glob(pattern)):
            node = "/" + path.relative_to(self.root).as_posix()
            safe = node.strip("/").replace("/", "-").replace(".", "-")
            manifest = MhsDeviceManifest(
                device_id=f"{self.device_prefix}-{safe}",
                device_class=device_class,
                name=f"Linux {label} node {safe}",
                vendor="linux-kernel",
                model=label,
                channels=[MhsChannel(id="present", name="Node present", unit="bool", value_type="boolean")],
                resources=[safe],
                state={"read": ["health", "kind", "node"]},
                transport={"kind": "linux-device-node", "properties": {"path": node}},
                limits=["read-only", "presence only", "path identity; serial not observed"]
                + (["camera frames require modality-specific provider and format probe"] if device_class == MhsDeviceClass.SENSOR else []),
                driver_id=DRIVER_ID,
                driver_version=DRIVER_VERSION,
                driver_sha256=DRIVER_SHA256,
            )
            records.append(
                LinuxMhsCandidate(manifest=manifest, source=node, identity_stability="path")
            )
        return records

    def _usb_candidates(self) -> list[LinuxMhsCandidate]:
        records: list[LinuxMhsCandidate] = []
        usb_root = self.root / "sys/bus/usb/devices"
        for path in sorted(usb_root.glob("*")):
            if not path.is_dir() or not (path / "idVendor").exists():
                continue
            safe = path.name.replace(".", "-")
            vendor = (path / "idVendor").read_text(encoding="utf-8", errors="ignore").strip()
            product = (path / "idProduct").read_text(encoding="utf-8", errors="ignore").strip()
            serial_path = path / "serial"
            serial = (
                serial_path.read_text(encoding="utf-8", errors="ignore").strip()
                if serial_path.exists()
                else None
            )
            manifest = MhsDeviceManifest(
                device_id=f"{self.device_prefix}-usb-{safe}",
                device_class=MhsDeviceClass.BUS,
                name=f"USB device {safe}",
                vendor=vendor or "unknown-usb-vendor",
                model=product or "unknown-usb-product",
                serial=serial,
                channels=[MhsChannel(id="present", name="Node present", unit="bool", value_type="boolean")],
                resources=[safe],
                state={"read": ["health", "kind", "node"]},
                transport={"kind": "sysfs-usb", "properties": {"path": f"/sys/bus/usb/devices/{path.name}"}},
                limits=["read-only", "presence only", "USB identity requires serial when available"],
                driver_id=DRIVER_ID,
                driver_version=DRIVER_VERSION,
                driver_sha256=DRIVER_SHA256,
            )
            records.append(
                LinuxMhsCandidate(
                    manifest=manifest,
                    source=f"/sys/bus/usb/devices/{path.name}",
                    identity_stability="stable" if serial else "path",
                )
            )
        return records
