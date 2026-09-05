"""Auditable, read-only discovery helpers for the Rolo MHS profile.

The module deliberately stops at candidate and evidence production.  It does
not open transports, execute shell commands, or invoke write capabilities.
Callers supply observations collected by an approved target-side probe_runner.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .mhs_hardware import MhsChannel, MhsDeviceClass, MhsDeviceManifest, MhsResult
from .mhs_linux import LinuxHardwareBackend, LinuxMhsCandidate, build_linux_manifest
from .rkb import EvidenceEnvelope, Fact, FactSourceKind, SnapshotIdentity


class IdentityStability(str, Enum):
    STABLE = "stable"
    PATH = "path"
    UNKNOWN = "unknown"


class MhsIdentityResolution(BaseModel):
    """Resolution of a device identity from ordered, target-observed sources."""

    model_config = ConfigDict(extra="forbid")

    sources: dict[str, str | None] = Field(default_factory=dict)
    selected_source: str | None = None
    selected_value: str | None = None
    stability: IdentityStability = IdentityStability.UNKNOWN
    conflicts: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_selection(self) -> MhsIdentityResolution:
        if self.selected_source is not None and self.selected_source not in self.sources:
            raise ValueError("selected identity source is not present in sources")
        if self.selected_value is not None and not self.selected_value.strip():
            raise ValueError("selected identity value cannot be blank")
        if self.conflicts and self.stability != IdentityStability.UNKNOWN:
            raise ValueError("identity conflicts must remain UNKNOWN")
        return self

    @property
    def usable(self) -> bool:
        return bool(self.selected_value) and not self.conflicts


class DiscoveryTrace(BaseModel):
    """One redacted, reproducible source observation."""

    model_config = ConfigDict(extra="forbid")

    trace_id: str = Field(default_factory=lambda: f"trace-{uuid4().hex}")
    source_id: str = Field(min_length=1, max_length=128)
    target_host_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    deployment_mode: Literal["local", "remote"]
    source_kind: FactSourceKind
    source_ref: str = Field(min_length=1, max_length=4096)
    observed_at: datetime
    query: str | None = None
    exit_code: int | None = None
    raw_output: str = ""
    output_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    redacted: bool = False
    limitations: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_output_digest(self) -> DiscoveryTrace:
        expected = hashlib.sha256(self.raw_output.encode("utf-8")).hexdigest()
        if self.output_sha256 != expected:
            raise ValueError("trace output_sha256 does not match raw_output")
        if not self.redacted and _contains_secret(self.raw_output):
            raise ValueError("trace raw_output appears to contain a secret")
        return self

    @classmethod
    def from_output(
        cls,
        *,
        source_id: str,
        target_host_fingerprint: str,
        deployment_mode: Literal["local", "remote"],
        source_kind: FactSourceKind,
        source_ref: str,
        output: str,
        observed_at: datetime | None = None,
        query: str | None = None,
        exit_code: int | None = None,
        limitations: list[str] | None = None,
    ) -> DiscoveryTrace:
        redacted_output, changed = redact_secrets(output)
        return cls(
            source_id=source_id,
            target_host_fingerprint=target_host_fingerprint,
            deployment_mode=deployment_mode,
            source_kind=source_kind,
            source_ref=source_ref,
            observed_at=observed_at or datetime.now(timezone.utc),
            query=query,
            exit_code=exit_code,
            raw_output=redacted_output,
            output_sha256=hashlib.sha256(redacted_output.encode("utf-8")).hexdigest(),
            redacted=changed,
            limitations=list(limitations or []),
        )


class MhsProbePolicy(BaseModel):
    """Allowlist and resource budget for a read-only provider probe."""

    model_config = ConfigDict(extra="forbid")

    allowed_operations: frozenset[str] = frozenset({"inspect", "status", "read"})
    timeout_s: float = Field(default=5.0, gt=0, le=60)
    max_retries: int = Field(default=0, ge=0, le=3)
    max_concurrency: int = Field(default=1, ge=1, le=8)
    require_no_write: bool = True

    @model_validator(mode="after")
    def validate_operations(self) -> MhsProbePolicy:
        for operation in self.allowed_operations:
            if not re.fullmatch(r"[a-z][a-z0-9_.:-]*", operation):
                raise ValueError(f"invalid probe operation: {operation!r}")
            if operation in {"reset", "calibrate", "setpoint", "enable", "stop", "write"}:
                raise ValueError(f"write-like operation is forbidden: {operation!r}")
        return self

    def require_allowed(self, operation: str) -> None:
        if operation not in self.allowed_operations:
            raise PermissionError(f"probe operation is not allowlisted: {operation}")


class LinuxUsbDevice(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sysfs_name: str
    vendor_id: str | None = None
    product_id: str | None = None
    manufacturer: str | None = None
    product: str | None = None
    serial: str | None = None
    driver: str | None = None
    identity_stability: IdentityStability = IdentityStability.PATH


class LinuxBusDevice(BaseModel):
    model_config = ConfigDict(extra="forbid")

    bus: Literal["i2c", "spi"]
    sysfs_name: str
    sysfs_target: str | None = None
    name: str | None = None
    modalias: str | None = None
    driver: str | None = None
    address: str | None = None
    identity_stability: IdentityStability = IdentityStability.PATH


class LinuxGpioChip(BaseModel):
    model_config = ConfigDict(extra="forbid")

    node: str
    label: str | None = None
    base: int | None = None
    line_count: int | None = None
    identity_stability: IdentityStability = IdentityStability.PATH


class LinuxDiscoverySnapshot(BaseModel):
    """Machine-readable D1/D2 snapshot collected without transport writes."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = "rolo-mhs-discovery-snapshot/v1"
    robot_id: str = Field(min_length=1)
    target_host_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_id: str = Field(min_length=1)
    deployment_mode: Literal["local", "remote"]
    observed_at: datetime
    fresh_until: datetime
    model: str | None = None
    serial: str | None = None
    kernel: str | None = None
    device_nodes: list[str] = Field(default_factory=list)
    usb_devices: list[LinuxUsbDevice] = Field(default_factory=list)
    bus_devices: list[LinuxBusDevice] = Field(default_factory=list)
    gpio_chips: list[LinuxGpioChip] = Field(default_factory=list)
    thermal: list[dict[str, str | None]] = Field(default_factory=list)
    software_stack: dict[str, list[str]] = Field(default_factory=dict)
    read_values: dict[str, Any] = Field(default_factory=dict)
    status_values: dict[str, Any] = Field(default_factory=dict)
    traces: list[DiscoveryTrace] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_window(self) -> LinuxDiscoverySnapshot:
        if self.fresh_until <= self.observed_at:
            raise ValueError("snapshot fresh_until must be after observed_at")
        return self


def collect_linux_snapshot(
    *,
    root: str | Path,
    robot_id: str,
    target_host_fingerprint: str,
    source_id: str,
    deployment_mode: Literal["local", "remote"] = "local",
    observed_at: datetime | None = None,
    freshness: timedelta = timedelta(minutes=5),
) -> LinuxDiscoverySnapshot:
    """Collect bounded procfs/sysfs metadata; never executes a target command."""

    base = Path(root)
    point = observed_at or datetime.now(timezone.utc)
    backend = LinuxHardwareBackend(base)
    limitations: list[str] = []
    try:
        status = dict(backend.status())
    except Exception as exc:
        status = {}
        limitations.append(f"status unavailable: {type(exc).__name__}")
    try:
        read_values = dict(backend.read())
    except Exception as exc:
        read_values = {}
        limitations.append(f"read unavailable: {type(exc).__name__}")

    def text(path: Path) -> str | None:
        try:
            value = path.read_text(encoding="utf-8", errors="replace").strip("\x00\n ")
            return value or None
        except OSError:
            return None

    def link(path: Path) -> str | None:
        try:
            return str(path.readlink())
        except OSError:
            return None

    device_nodes = sorted(
        path.relative_to(base).as_posix()
        for pattern in ("dev/i2c-*", "dev/spidev*", "dev/gpiochip*", "dev/serial/by-id/*")
        for path in base.glob(pattern)
        if path.exists() or path.is_symlink()
    )

    usb_devices: list[LinuxUsbDevice] = []
    for path in sorted((base / "sys/bus/usb/devices").glob("*")):
        vendor_id = text(path / "idVendor")
        if not vendor_id:
            continue
        serial = text(path / "serial")
        usb_devices.append(
            LinuxUsbDevice(
                sysfs_name=path.name,
                vendor_id=vendor_id,
                product_id=text(path / "idProduct"),
                manufacturer=text(path / "manufacturer"),
                product=text(path / "product"),
                serial=serial,
                driver=Path(link(path / "driver")).name if link(path / "driver") else None,
                identity_stability=IdentityStability.STABLE if serial else IdentityStability.PATH,
            )
        )

    bus_devices: list[LinuxBusDevice] = []
    for bus, pattern in (("i2c", "sys/bus/i2c/devices/*"), ("spi", "sys/bus/spi/devices/*")):
        for path in sorted(base.glob(pattern)):
            if not path.is_symlink() and not path.exists():
                continue
            name = path.name
            address = name.rsplit("-", 1)[-1] if bus == "i2c" and "-" in name else None
            bus_devices.append(
                LinuxBusDevice(
                    bus=bus,
                    sysfs_name=name,
                    sysfs_target=link(path),
                    name=text(path / "name"),
                    modalias=text(path / "modalias"),
                    driver=Path(link(path / "driver")).name if link(path / "driver") else None,
                    address=address,
                )
            )

    gpio_chips: list[LinuxGpioChip] = []
    for path in sorted((base / "sys/class/gpio").glob("gpiochip*")):
        if not path.is_dir() and not path.is_symlink():
            continue
        base_raw, count_raw = text(path / "base"), text(path / "ngpio")
        try:
            base_value = int(base_raw) if base_raw is not None else None
        except ValueError:
            base_value = None
        try:
            count_value = int(count_raw) if count_raw is not None else None
        except ValueError:
            count_value = None
        gpio_chips.append(
            LinuxGpioChip(
                node=f"/sys/class/gpio/{path.name}",
                label=text(path / "label"),
                base=base_value,
                line_count=count_value,
            )
        )

    thermal: list[dict[str, str | None]] = []
    for path in sorted((base / "sys/class/thermal").glob("thermal_zone*")):
        if path.is_dir():
            thermal.append(
                {"zone": path.name, "type": text(path / "type"), "temp": text(path / "temp")}
            )

    processes: list[str] = []
    for path in sorted((base / "proc").glob("[0-9]*/comm")):
        value = text(path)
        if value and value not in processes:
            processes.append(value)
    services = sorted(path.name for path in (base / "etc/systemd/system").glob("*.service"))
    software_stack = {"processes": processes[:256], "services": services[:256]}

    sections = {
        "status": status,
        "read": read_values,
        "device_nodes": device_nodes,
        "usb_devices": [item.model_dump(mode="json") for item in usb_devices],
        "bus_devices": [item.model_dump(mode="json") for item in bus_devices],
        "gpio_chips": [item.model_dump(mode="json") for item in gpio_chips],
        "thermal": thermal,
        "software_stack": software_stack,
    }
    traces = [
        DiscoveryTrace.from_output(
            source_id=source_id,
            target_host_fingerprint=target_host_fingerprint,
            deployment_mode=deployment_mode,
            source_kind=FactSourceKind.OBSERVED_RUNTIME,
            source_ref=f"sysfs://{section}",
            query=section,
            output=json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
            observed_at=point,
            limitations=limitations,
        )
        for section, value in sections.items()
    ]
    return LinuxDiscoverySnapshot(
        robot_id=robot_id,
        target_host_fingerprint=target_host_fingerprint,
        source_id=source_id,
        deployment_mode=deployment_mode,
        observed_at=point,
        fresh_until=point + freshness,
        model=status.get("model"),
        serial=status.get("serial"),
        kernel=status.get("kernel"),
        device_nodes=device_nodes,
        usb_devices=usb_devices,
        bus_devices=bus_devices,
        gpio_chips=gpio_chips,
        thermal=thermal,
        software_stack=software_stack,
        read_values=read_values,
        status_values=status,
        traces=traces,
        limitations=limitations,
    )


def snapshot_evidence_envelope(snapshot: LinuxDiscoverySnapshot) -> EvidenceEnvelope:
    """Convert a D1/D2 snapshot into one verified, read-only RKB envelope."""

    identity = SnapshotIdentity(
        robot_id=snapshot.robot_id,
        target_host_fingerprint=snapshot.target_host_fingerprint,
        source_id=snapshot.source_id,
        deployment_mode=snapshot.deployment_mode,
        access="READ_ONLY",
        observed_at=snapshot.observed_at,
        fresh_until=snapshot.fresh_until,
    )
    fact = Fact(
        robot_id=identity.robot_id,
        target_host_fingerprint=identity.target_host_fingerprint,
        source_id=identity.source_id,
        deployment_mode=identity.deployment_mode,
        access=identity.access,
        source_kind=FactSourceKind.OBSERVED_RUNTIME,
        source_ref="artifact://mhs/discovery-snapshot",
        observed_at=snapshot.observed_at,
        fresh_until=snapshot.fresh_until,
        value=snapshot.model_dump(mode="json", exclude={"traces"}),
        limitations=list(snapshot.limitations),
    )
    return EvidenceEnvelope(
        identity=identity,
        facts=[fact],
        snapshot={"trace_ids": [trace.trace_id for trace in snapshot.traces]},
    ).with_digest()


def build_snapshot_candidates(snapshot: LinuxDiscoverySnapshot) -> list[LinuxMhsCandidate]:
    """Project a snapshot into conservative MHS candidates.

    Unknown USB, I²C and SPI devices remain bus/presence candidates.  The
    function never infers a sensor or actuator type from VID/PID or a path.
    """

    candidates: list[LinuxMhsCandidate] = []
    compute = build_linux_manifest(
        device_id=f"{_slug(snapshot.robot_id)}-compute",
        name="Linux compute host",
        vendor="observed",
        model=snapshot.model or "unknown-linux-host",
        serial=snapshot.serial,
        transport_target=snapshot.robot_id,
    )
    candidates.append(
        LinuxMhsCandidate(
            manifest=compute,
            source="artifact://mhs/discovery-snapshot#status",
            identity_stability=IdentityStability.STABLE.value
            if snapshot.serial
            else IdentityStability.UNKNOWN.value,
        )
    )
    for item in snapshot.thermal:
        zone = _slug(str(item.get("zone") or "thermal"))
        manifest = MhsDeviceManifest(
            device_id=f"{_slug(snapshot.robot_id)}-{zone}",
            device_class=MhsDeviceClass.SENSOR,
            name=f"Linux thermal {zone}",
            vendor="linux-kernel",
            model=item.get("type") or "thermal-zone",
            channels=[MhsChannel(id="temperature", name="Temperature", unit="degC")],
            resources=[zone],
            state={"read": ["zone", "type", "temp"]},
            transport={"kind": "sysfs", "properties": {"path": f"/sys/class/thermal/{zone}"}},
            limits=["read-only", "path identity; serial not observed"],
        )
        candidates.append(
            LinuxMhsCandidate(
                manifest=manifest,
                source=f"sysfs://thermal/{zone}",
                identity_stability=IdentityStability.PATH.value,
            )
        )
    for item in snapshot.usb_devices:
        safe = _slug(item.sysfs_name)
        manifest = MhsDeviceManifest(
            device_id=f"{_slug(snapshot.robot_id)}-usb-{safe}",
            device_class=MhsDeviceClass.BUS,
            name=f"USB device {item.sysfs_name}",
            vendor=item.vendor_id or "unknown-usb-vendor",
            model=item.product_id or "unknown-usb-product",
            serial=item.serial,
            channels=[
                MhsChannel(id="present", name="Node present", unit="bool", value_type="boolean")
            ],
            resources=[item.sysfs_name],
            state={"read": ["present", "vendor_id", "product_id", "driver"]},
            transport={"kind": "sysfs-usb", "properties": {"path": item.sysfs_name}},
            limits=["read-only", "presence only", "VID/PID do not determine device class"],
        )
        candidates.append(
            LinuxMhsCandidate(
                manifest=manifest,
                source=f"sysfs://usb/{item.sysfs_name}",
                identity_stability=item.identity_stability.value,
            )
        )
    for item in snapshot.bus_devices:
        safe = _slug(item.sysfs_name)
        manifest = MhsDeviceManifest(
            device_id=f"{_slug(snapshot.robot_id)}-{item.bus}-{safe}",
            device_class=MhsDeviceClass.BUS,
            name=f"Linux {item.bus} device {item.sysfs_name}",
            vendor="linux-kernel",
            model=item.name or item.modalias or item.bus,
            channels=[
                MhsChannel(id="present", name="Device present", unit="bool", value_type="boolean")
            ],
            resources=[item.sysfs_name],
            state={"read": ["present", "address", "driver", "modalias"]},
            transport={"kind": f"sysfs-{item.bus}", "properties": {"path": item.sysfs_name}},
            limits=["read-only", "presence only", "identity probe requires explicit approval"],
        )
        candidates.append(
            LinuxMhsCandidate(
                manifest=manifest,
                source=f"sysfs://{item.bus}/{item.sysfs_name}",
                identity_stability=IdentityStability.PATH.value,
            )
        )
    return candidates


def _slug(value: str) -> str:
    cleaned = re.sub(r"[^a-z0-9_.-]+", "-", value.lower()).strip("-.")
    return cleaned or "unknown"


def redact_secrets(value: str) -> tuple[str, bool]:
    """Redact common credentials before a trace can enter an evidence artifact."""

    redacted = value
    redacted = re.sub(
        r"(?i)(password|passwd|token|secret|api[_-]?key|authorization)(\s*[:=]\s*)\S+",
        r"\1\2<redacted>",
        redacted,
    )
    redacted = re.sub(
        r"(?i)(https?://)([^/@\s]+):([^/@\s]+)@([^/\s]+)",
        r"\1<redacted>@\4",
        redacted,
    )
    return redacted, redacted != value


def resolve_identity(
    sources: Mapping[str, str | None], *, path: str | None = None
) -> MhsIdentityResolution:
    """Resolve identity using stable sources first and fail closed on disagreement."""

    ordered = ("serial", "device_tree", "udev_by_id", "controller_resource_id", "path")
    normalized = {
        key: (value.strip() if isinstance(value, str) and value.strip() else None)
        for key, value in sources.items()
    }
    if path is not None and "path" not in normalized:
        normalized["path"] = path
    present = [(key, normalized.get(key)) for key in ordered if normalized.get(key)]
    stable_values = {value for key, value in present if key != "path"}
    conflicts = sorted(stable_values) if len(stable_values) > 1 else []
    if conflicts:
        return MhsIdentityResolution(sources=normalized, conflicts=conflicts)
    if present:
        selected_source, selected_value = present[0]
        stability = (
            IdentityStability.PATH
            if selected_source == "path"
            else IdentityStability.STABLE
        )
        return MhsIdentityResolution(
            sources=normalized,
            selected_source=selected_source,
            selected_value=selected_value,
            stability=stability,
        )
    return MhsIdentityResolution(sources=normalized)


def write_gate_allowed(identity: MhsIdentityResolution) -> bool:
    """Probe never grants write authority from identity discovery.

    The helper is retained for compatibility with older callers, but write
    eligibility belongs to the separately approved Trace/Write gate.
    """

    del identity
    return False


def mhs_evidence_envelope(
    results: list[MhsResult],
    *,
    identity: SnapshotIdentity,
    source_ref: str,
    device_id: str,
    provider_id: str,
    freshness: timedelta | None = None,
) -> EvidenceEnvelope:
    """Bind provider results to one verified RKB identity tuple."""

    if not results:
        raise ValueError("at least one MHS result is required")
    deadline = freshness or (identity.fresh_until - identity.observed_at)
    facts: list[Fact] = []
    for result in results:
        observed_at = result.observed_at or identity.observed_at
        fresh_until = result.fresh_until or observed_at + deadline
        if observed_at < identity.observed_at or fresh_until > identity.fresh_until:
            raise ValueError("MHS result freshness window is outside envelope identity")
        facts.append(
            Fact(
                robot_id=identity.robot_id,
                target_host_fingerprint=identity.target_host_fingerprint,
                source_id=identity.source_id,
                deployment_mode=identity.deployment_mode,
                access=identity.access,
                request_nonce=identity.request_nonce,
                source_kind=FactSourceKind.OBSERVED_RUNTIME,
                source_ref=f"{source_ref}#{result.route}",
                observed_at=observed_at,
                fresh_until=fresh_until,
                value=result.model_dump(mode="json"),
                limitations=list(result.limitations),
            )
        )
    return EvidenceEnvelope(
        identity=identity,
        facts=facts,
        snapshot={
            "mhs_device_id": device_id,
            "provider_id": provider_id,
            "routes": [result.route for result in results],
            "manifest_digests": sorted(
                {result.manifest_sha256 for result in results if result.manifest_sha256}
            ),
            "driver_digests": sorted(
                {result.driver_sha256 for result in results if result.driver_sha256}
            ),
        },
    ).with_digest()


def _contains_secret(value: str) -> bool:
    return bool(
        re.search(
            r"(?i)(password|passwd|token|secret|api[_-]?key|authorization)\s*[:=]",
            value,
        )
    )


__all__ = [
    "DiscoveryTrace",
    "IdentityStability",
    "LinuxBusDevice",
    "LinuxDiscoverySnapshot",
    "LinuxGpioChip",
    "LinuxUsbDevice",
    "MhsIdentityResolution",
    "MhsProbePolicy",
    "build_snapshot_candidates",
    "collect_linux_snapshot",
    "mhs_evidence_envelope",
    "redact_secrets",
    "resolve_identity",
    "snapshot_evidence_envelope",
    "write_gate_allowed",
]
