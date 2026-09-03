"""Target-neutral, read-only Linux backend for the RKB-3 MHS profile."""

from __future__ import annotations

import hashlib
import math
import platform
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from .mhs_hardware import (
    MhsChannel,
    MhsDeviceClass,
    MhsDeviceManifest,
    MhsDeviceProvider,
)

DRIVER_ID = "rolo.mhs.linux-observer"
DRIVER_VERSION = "1.0.0"
DRIVER_SHA256 = hashlib.sha256(f"{DRIVER_ID}:{DRIVER_VERSION}".encode()).hexdigest()


class LinuxHardwareBackend:
    """Read procfs/sysfs without executing commands or writing device nodes."""

    def __init__(self, root: str | Path = "/") -> None:
        self.root = Path(root)

    def _read_text(self, path: str, default: str = "") -> str:
        try:
            return (self.root / path.lstrip("/")).read_text(encoding="utf-8").strip("\x00\n ")
        except (OSError, UnicodeError):
            return default

    def read(self) -> Mapping[str, int | float | bool | str]:
        raw_temp = self._read_text("/sys/class/thermal/thermal_zone0/temp")
        if not raw_temp:
            raise RuntimeError("cpu thermal zone is unavailable")
        temperature = float(raw_temp) / 1000.0
        if not -40 <= temperature <= 125 or not math.isfinite(temperature):
            raise ValueError("cpu temperature is outside physical bounds")
        memory: dict[str, int] = {}
        for line in self._read_text("/proc/meminfo").splitlines():
            key, _, value = line.partition(":")
            if key in {"MemTotal", "MemAvailable"}:
                memory[key] = int(value.strip().split()[0])
        total, available = memory.get("MemTotal", 0), memory.get("MemAvailable", 0)
        if total <= 0 or not 0 <= available <= total:
            raise RuntimeError("memory information is unavailable")
        fields = self._read_text("/proc/loadavg").split()
        if not fields:
            raise RuntimeError("load average is unavailable")
        load = float(fields[0])
        if load < 0 or not math.isfinite(load):
            raise ValueError("load average is invalid")
        return {
            "cpu_temperature": round(temperature, 3),
            "memory_used_percent": round((total - available) * 100.0 / total, 3),
            "load_1m": round(load, 3),
        }

    def status(self) -> Mapping[str, Any]:
        uptime = self._read_text("/proc/uptime").split()
        dev = self.root / "dev"
        return {
            "health": "OK",
            "model": self._read_text("/proc/device-tree/model", platform.machine()),
            "serial": self._read_text("/proc/device-tree/serial-number") or None,
            "kernel": self._read_text("/proc/version").split(" ", 1)[0] or platform.release(),
            "uptime_seconds": round(float(uptime[0]), 3) if uptime else None,
            "transports": {
                "i2c": any(dev.glob("i2c-*")),
                "spi": any(dev.glob("spidev*")),
                "gpio": any(dev.glob("gpiochip*")),
                "usb": (self.root / "sys/bus/usb").exists(),
            },
            "read_only": True,
        }


def build_linux_manifest(
    *, device_id: str, name: str, vendor: str, model: str, serial: str | None = None
) -> MhsDeviceManifest:
    return MhsDeviceManifest(
        device_id=device_id,
        device_class=MhsDeviceClass.COMPUTE,
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
        transport={"kind": "local-linux", "properties": {"target": "local-linux"}},
        limits=["read-only", "procfs/sysfs bounded reads", "no device writes"],
        driver_id=DRIVER_ID,
        driver_version=DRIVER_VERSION,
        driver_sha256=DRIVER_SHA256,
    )


class LinuxPresenceBackend:
    """Presence-only adapter for a discovered device node."""

    def __init__(self, root: str | Path, node: str, kind: str) -> None:
        self.root, self.node, self.kind = Path(root), node, kind

    def read(self) -> Mapping[str, bool]:
        return {"present": (self.root / self.node.lstrip("/")).exists()}

    def status(self) -> Mapping[str, Any]:
        path = self.root / self.node.lstrip("/")
        return {
            "health": "OK" if path.exists() else "UNAVAILABLE",
            "kind": self.kind,
            "node": self.node,
        }


class LinuxThermalBackend(LinuxHardwareBackend):
    def __init__(self, root: str | Path, zone: str) -> None:
        super().__init__(root)
        self.zone = zone.strip("/")

    def read(self) -> Mapping[str, float]:
        raw = self._read_text(f"/{self.zone}/temp")
        if not raw:
            raise RuntimeError("thermal zone is unavailable")
        value = float(raw) / 1000.0
        if not -40 <= value <= 150 or not math.isfinite(value):
            raise ValueError("thermal reading is outside physical bounds")
        return {"temperature": round(value, 3)}

    def status(self) -> Mapping[str, Any]:
        return {"health": "OK", "zone": self.zone, "type": self._read_text(f"/{self.zone}/type")}


class LinuxMhsCandidate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    manifest: MhsDeviceManifest
    discovery_status: Literal["DISCOVERED_UNVERIFIED"] = "DISCOVERED_UNVERIFIED"
    source: str = Field(min_length=1)
    identity_stability: Literal["stable", "path", "unknown"] = "unknown"


class LinuxMhsInventory:
    """Discover compute, thermal, bus and USB candidates as unverified facts."""

    def __init__(self, root: str | Path = "/", device_prefix: str = "linux") -> None:
        self.root, self.device_prefix = Path(root), device_prefix

    def candidates(self) -> list[LinuxMhsCandidate]:
        backend = LinuxHardwareBackend(self.root)
        status = backend.status()
        common = {
            "resources": ["cpu", "memory", "thermal-zone0"],
            "state": {"read": ["health", "model", "serial", "transports"]},
            "transport": {"kind": "local-linux", "properties": {"target": str(self.root)}},
            "limits": ["read-only", "procfs/sysfs bounded reads", "no device writes"],
            "driver_id": DRIVER_ID,
            "driver_version": DRIVER_VERSION,
            "driver_sha256": DRIVER_SHA256,
        }
        manifest = MhsDeviceManifest(
            device_id=f"{self.device_prefix}-compute",
            device_class=MhsDeviceClass.COMPUTE,
            name="Linux compute host",
            vendor="unknown",
            model=str(status["model"]),
            serial=status.get("serial"),
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
            **common,
        )
        found = [
            LinuxMhsCandidate(
                manifest=manifest,
                source="/proc + /sys",
                identity_stability="stable" if manifest.serial else "unknown",
            )
        ]
        thermal_root = self.root / "sys/class/thermal"
        for temp_path in sorted(thermal_root.glob("thermal_zone*/temp")):
            zone = temp_path.parent.name
            zone_type = LinuxHardwareBackend(self.root)._read_text(
                f"/sys/class/thermal/{zone}/type", "thermal-zone"
            )
            zone_manifest = MhsDeviceManifest(
                device_id=f"{self.device_prefix}-{zone}",
                device_class=MhsDeviceClass.SENSOR,
                name=f"Linux thermal {zone}",
                vendor="linux-kernel",
                model=zone_type,
                channels=[
                    MhsChannel(
                        id="temperature",
                        name="Temperature",
                        unit="degC",
                        min_value=-40,
                        max_value=150,
                    )
                ],
                resources=[zone],
                state={"read": ["health", "zone", "type"]},
                transport={"kind": "sysfs", "properties": {"path": f"/sys/class/thermal/{zone}"}},
                limits=["read-only", "path identity; serial not observed"],
                driver_id=DRIVER_ID,
                driver_version=DRIVER_VERSION,
                driver_sha256=DRIVER_SHA256,
            )
            found.append(
                LinuxMhsCandidate(
                    manifest=zone_manifest, source=str(temp_path), identity_stability="path"
                )
            )
        for pattern, label in (("i2c-*", "i2c"), ("spidev*", "spi"), ("gpiochip*", "gpio")):
            for node_path in sorted((self.root / "dev").glob(pattern)):
                node = "/" + node_path.relative_to(self.root).as_posix()
                safe = node.strip("/").replace("/", "-").replace(".", "-")
                node_manifest = MhsDeviceManifest(
                    device_id=f"{self.device_prefix}-{safe}",
                    device_class=MhsDeviceClass.BUS,
                    name=f"Linux {label} node {safe}",
                    vendor="linux-kernel",
                    model=label,
                    channels=[
                        MhsChannel(
                            id="present", name="Node present", unit="bool", value_type="boolean"
                        )
                    ],
                    resources=[safe],
                    state={"read": ["health", "kind", "node"]},
                    transport={"kind": "linux-device-node", "properties": {"path": node}},
                    limits=["read-only", "presence only", "path identity; serial not observed"],
                    driver_id=DRIVER_ID,
                    driver_version=DRIVER_VERSION,
                    driver_sha256=DRIVER_SHA256,
                )
                found.append(
                    LinuxMhsCandidate(
                        manifest=node_manifest, source=node, identity_stability="path"
                    )
                )
        # Device nodes are presence-only until a modality-specific provider
        # proves protocol, identity and safe read semantics.
        found.extend(self._presence_candidates("dev/video*", "camera", "camera", device_class=MhsDeviceClass.SENSOR))
        found.extend(self._usb_candidates())
        return found

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
            records.append(LinuxMhsCandidate(manifest=manifest, source=node, identity_stability="path"))
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
            serial = serial_path.read_text(encoding="utf-8", errors="ignore").strip() if serial_path.exists() else None
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
            records.append(LinuxMhsCandidate(manifest=manifest, source=f"/sys/bus/usb/devices/{path.name}", identity_stability="stable" if serial else "path"))
        return records

    def providers(self) -> list[tuple[LinuxMhsCandidate, MhsDeviceProvider]]:
        return [
            (
                candidate,
                MhsDeviceProvider(
                    candidate.manifest,
                    LinuxThermalBackend(
                        self.root,
                        f"sys/class/thermal/{candidate.manifest.device_id.rsplit('-', 1)[-1]}",
                    )
                    if "thermal_zone" in candidate.manifest.device_id
                    else LinuxPresenceBackend(
                        self.root,
                        str(
                            candidate.manifest.transport.get("properties", {}).get(
                                "path", "/missing"
                            )
                        ),
                        candidate.manifest.device_class.value,
                    )
                    if candidate.manifest.device_class == MhsDeviceClass.BUS
                    else LinuxHardwareBackend(self.root),
                ),
            )
            for candidate in self.candidates()
        ]


__all__ = [
    "DRIVER_ID",
    "DRIVER_VERSION",
    "DRIVER_SHA256",
    "LinuxHardwareBackend",
    "LinuxPresenceBackend",
    "LinuxThermalBackend",
    "LinuxMhsCandidate",
    "LinuxMhsInventory",
    "build_linux_manifest",
]
