"""Rolo-owned, read-only MHS-compatible provider seam.

This is intentionally independent of any unpublished vendor MHS wire schema.
It exposes only inspect/status/read for v2; write-like capability ids are
rejected at the provider boundary and cannot be enabled by a backend method.
"""

from __future__ import annotations

import hashlib
import math
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field, model_validator


class MhsStatus(str, Enum):
    AVAILABLE = "AVAILABLE"
    UNAVAILABLE = "UNAVAILABLE"
    STALE = "STALE"


class MhsSourceKind(str, Enum):
    OBSERVED = "OBSERVED"
    DECLARED = "DECLARED"
    INFERRED = "INFERRED"


class MhsDriver(BaseModel):
    model_config = ConfigDict(extra="forbid")
    provider_id: str = Field(min_length=1)
    version: str = Field(min_length=1)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class MhsDeviceClass(str, Enum):
    SENSOR = "sensor"
    CONTROLLER = "controller"
    ACTUATOR = "actuator"
    POWER = "power"
    COMPUTE = "compute"
    BUS = "bus"
    TOOL = "tool"
    END_EFFECTOR = "end-effector"


class MhsChannel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1, pattern=r"^[a-z][a-z0-9_.-]*$")
    name: str = Field(min_length=1)
    unit: str = Field(min_length=1)
    value_type: str = Field(default="number", pattern=r"^(number|boolean|string)$")
    min_value: float | None = None
    max_value: float | None = None

    @model_validator(mode="after")
    def valid_bounds(self) -> MhsChannel:
        if (
            self.min_value is not None
            and self.max_value is not None
            and self.min_value > self.max_value
        ):
            raise ValueError("channel min_value cannot exceed max_value")
        return self


class MhsIdentitySource(BaseModel):
    """One independently observable identity source for a physical device."""

    model_config = ConfigDict(extra="forbid")

    kind: Literal["serial", "device_tree", "udev_by_id", "controller_resource", "path", "other"]
    value: str = Field(min_length=1)
    observed: bool = True
    evidence_ids: list[str] = Field(default_factory=list)


class MhsIdentity(BaseModel):
    """Stable identity and disagreement state, separate from display metadata."""

    model_config = ConfigDict(extra="forbid")

    stable_id: str | None = None
    sources: list[MhsIdentitySource] = Field(default_factory=list)
    confidence: Literal["high", "medium", "low"] = "low"
    conflicts: list[str] = Field(default_factory=list)


class MhsProvenance(BaseModel):
    """Lifecycle and evidence metadata for a declared manifest."""

    model_config = ConfigDict(extra="forbid")

    status: Literal[
        "DECLARED",
        "DISCOVERED_UNVERIFIED",
        "READY_FOR_SAMPLING",
        "VERIFIED",
        "REJECTED",
    ] = "DECLARED"
    evidence_ids: list[str] = Field(default_factory=list)
    observed_at: datetime | None = None
    fresh_until: datetime | None = None
    field_status: dict[str, Literal["declared", "observed", "inferred", "unknown"]] = Field(
        default_factory=dict
    )

    @model_validator(mode="after")
    def valid_window(self) -> MhsProvenance:
        if (
            self.observed_at is not None
            and self.fresh_until is not None
            and self.fresh_until < self.observed_at
        ):
            raise ValueError("provenance fresh_until cannot precede observed_at")
        if self.status == "VERIFIED" and not self.evidence_ids:
            raise ValueError("verified manifest requires provenance evidence")
        return self


class MhsRelation(BaseModel):
    """Typed edge between MHS devices, interfaces, or transport resources."""

    model_config = ConfigDict(extra="forbid")

    kind: Literal["attached_to", "driven_by", "publishes_to", "controls", "member_of"]
    target: str = Field(min_length=1)
    interface_id: str | None = None
    evidence_ids: list[str] = Field(default_factory=list)


class MhsInterfaceDescriptor(BaseModel):
    """Middleware-neutral structured data interface.

    ``transport_ref`` may point to a ROS topic, USB endpoint, CAN frame, native
    SDK handle, or another adapter-specific resource.  The interface kind and
    payload schema remain stable when the transport changes.
    """

    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1, pattern=r"^[a-z][a-z0-9_.-]*$")
    kind: Literal[
        "scalar",
        "image",
        "point_cloud",
        "laser_scan",
        "joint_state",
        "pose",
        "event",
        "command",
    ]
    access: Literal["read", "stream", "write"] = "read"
    transport_ref: str | None = None
    payload_schema: dict[str, Any] = Field(default_factory=dict)
    encoding: str | None = None
    shape: list[int | str] = Field(default_factory=list)
    unit: str | None = None
    frame_id: str | None = None
    timestamp: Literal["none", "source", "receipt", "source_and_receipt"] = "none"
    qos: dict[str, Any] = Field(default_factory=dict)


class MhsSafetyContract(BaseModel):
    """Read-side safety facts and write-adapter prerequisites."""

    model_config = ConfigDict(extra="forbid")

    read_only: bool = True
    resource_claims: list[str] = Field(default_factory=list)
    modes: list[str] = Field(default_factory=list)
    limits: list[str] = Field(default_factory=list)
    faults: list[str] = Field(default_factory=list)
    interlocks: list[str] = Field(default_factory=list)
    estop_required: bool | None = None


class MhsInterfaceSample(BaseModel):
    """One structured sample emitted by a transport adapter."""

    model_config = ConfigDict(extra="forbid")

    interface_id: str = Field(min_length=1, pattern=r"^[a-z][a-z0-9_.-]*$")
    value: Any
    observed_at: datetime
    source_timestamp: datetime | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class MhsCommandDescriptor(BaseModel):
    """One bounded write command declared by a device manifest."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1, pattern=r"^[a-z][a-z0-9_.-]*$")
    access: Literal["write"] = "write"
    hardware_resource_id: str = Field(min_length=1, pattern=r"^[a-z][a-z0-9_.:/-]*$")
    risk: str = Field(pattern=r"^R[1-3]$")
    input_schema: dict[str, Any]
    timeout_s: float = Field(gt=0, le=300)
    idempotent: bool = False
    requires: list[str] = Field(default_factory=list)
    cancel_capability: str | None = None
    compensation_capability: str | None = None

    @model_validator(mode="after")
    def validate_input_schema(self) -> MhsCommandDescriptor:
        if self.input_schema.get("type", "object") != "object":
            raise ValueError("MHS command input_schema must describe an object")
        if self.input_schema.get("additionalProperties") is not False:
            raise ValueError("MHS command input_schema must reject additional properties")
        if not isinstance(self.input_schema.get("properties"), dict):
            raise ValueError("MHS command input_schema must declare properties")
        return self


class MhsDeviceManifest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = "rolo-mhs-device/v1.1"
    device_id: str = Field(min_length=1, pattern=r"^[a-z][a-z0-9_.-]*$")
    device_class: MhsDeviceClass
    name: str = Field(min_length=1)
    vendor: str = Field(min_length=1)
    model: str = Field(min_length=1)
    serial: str | None = None
    channels: list[MhsChannel] = Field(default_factory=list)
    resources: list[str] = Field(default_factory=list)
    state: dict[str, list[str]] = Field(default_factory=lambda: {"read": []})
    commands: list[MhsCommandDescriptor] = Field(default_factory=list)
    transport: dict[str, Any] = Field(default_factory=dict)
    limits: list[str] = Field(default_factory=list)
    driver_id: str = Field(default="unknown-driver", min_length=1)
    driver_version: str = Field(default="unknown", min_length=1)
    driver_sha256: str = Field(default="0" * 64, pattern=r"^[0-9a-f]{64}$")
    driver: MhsDriver | None = None
    identity: MhsIdentity = Field(default_factory=MhsIdentity)
    provenance: MhsProvenance = Field(default_factory=MhsProvenance)
    relations: list[MhsRelation] = Field(default_factory=list)
    interfaces: list[MhsInterfaceDescriptor] = Field(default_factory=list)
    safety: MhsSafetyContract = Field(default_factory=MhsSafetyContract)

    @model_validator(mode="after")
    def unique_channels(self) -> MhsDeviceManifest:
        if self.driver is not None:
            object.__setattr__(self, "driver_id", self.driver.provider_id)
            object.__setattr__(self, "driver_version", self.driver.version)
            object.__setattr__(self, "driver_sha256", self.driver.sha256)
        ids = [item.id for item in self.channels]
        if len(ids) != len(set(ids)):
            raise ValueError("manifest contains duplicate channel ids")
        command_ids = [item.id for item in self.commands]
        if len(command_ids) != len(set(command_ids)):
            raise ValueError("manifest contains duplicate command ids")
        interface_ids = [item.id for item in self.interfaces]
        if len(interface_ids) != len(set(interface_ids)):
            raise ValueError("manifest contains duplicate interface ids")
        return self

    @property
    def manifest_sha256(self) -> str:
        payload = self.model_dump(mode="json")
        import json

        return hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()


def migrate_mhs_manifest_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Upgrade a v1 payload with v1.1 defaults without mutating the input."""

    migrated = dict(payload)
    version = str(migrated.get("schema_version", "rolo-mhs-device/v1"))
    if version == "rolo-mhs-device/v1":
        migrated["schema_version"] = "rolo-mhs-device/v1.1"
    for field, default in (
        ("identity", {}),
        ("provenance", {}),
        ("relations", []),
        ("interfaces", []),
        ("safety", {}),
    ):
        migrated.setdefault(field, default)
    return migrated


class MhsBackend(Protocol):
    def read(self) -> Mapping[str, int | float | bool | str]: ...

    def status(self) -> Mapping[str, Any]: ...


class MhsStructuredBackend(Protocol):
    """Optional adapter surface for non-scalar interfaces."""

    def read_structured(self) -> list[MhsInterfaceSample]: ...


class MhsResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: MhsStatus
    device_id: str
    capability_id: str
    route: str
    value: dict[str, Any] | None = None
    observed_at: datetime | None = None
    fresh_until: datetime | None = None
    manifest_sha256: str | None = None
    driver_id: str | None = None
    driver_version: str | None = None
    driver_sha256: str | None = None
    provider_version: str | None = None
    transport: dict[str, Any] = Field(default_factory=dict)
    reason: str | None = None
    evidence_ids: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    samples: list[MhsInterfaceSample] = Field(default_factory=list)
    target_host_fingerprint: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    source_kind: MhsSourceKind = MhsSourceKind.OBSERVED


class MhsDeviceProvider:
    """Read-only Provider SPI for one MHS device manifest and backend."""

    provider_version = "1.0.0"
    freshness_seconds = 300
    READ_CAPABILITIES = frozenset({"inspect", "status", "read"})

    def __init__(
        self,
        manifest: MhsDeviceManifest,
        backend: MhsBackend,
        *,
        target_host_fingerprint: str | None = None,
        freshness: dict[str, timedelta] | None = None,
        timeout_s: float | None = None,
    ) -> None:
        self.manifest = manifest
        self.backend = backend
        self.provider_id = f"mhs.{manifest.device_id}"
        self.target_host_fingerprint = target_host_fingerprint
        self.freshness_seconds = int((freshness or {}).get("read", timedelta(seconds=self.freshness_seconds)).total_seconds())
        self.timeout_s = timeout_s
        self._manifest_digest = manifest.manifest_sha256
        self._driver_digest = manifest.driver_sha256

    def route(self, capability_id: str) -> str:
        capability = capability_id.removeprefix("mhs.")
        if capability not in self.READ_CAPABILITIES and not (
            capability == "read_structured" and self.manifest.interfaces
        ):
            raise ValueError(f"capability is not available in v2: {capability}")
        return f"mhs://{self.manifest.device_id}/{capability}"

    def capabilities(self) -> list[dict[str, Any]]:
        readable = [
            {
                "capability_id": capability,
                "access": "read",
                "route": self.route(capability),
                "status": "DISCOVERED_UNVERIFIED",
                "evidence_ids": [f"mhs-manifest:{self.manifest.manifest_sha256}"],
            }
            for capability in sorted(self.READ_CAPABILITIES)
        ]
        writable = [
            {
                "capability_id": command.id,
                "access": "write",
                "route": self.route(command.id),
                "status": "DISCOVERED_UNVERIFIED",
                "risk": command.risk,
                "hardware_resource_id": command.hardware_resource_id,
                "requires_rolo_write_gate": True,
                "evidence_ids": [f"mhs-manifest:{self.manifest.manifest_sha256}"],
            }
            for command in sorted(self.manifest.commands, key=lambda item: item.id)
        ]
        if callable(getattr(self.backend, "read_structured", None)):
            readable.append(
                {
                    "capability_id": "read_structured",
                    "access": "read",
                    "route": self.route("read_structured"),
                    "status": "DISCOVERED_UNVERIFIED",
                    "evidence_ids": [f"mhs-manifest:{self.manifest.manifest_sha256}"],
                }
            )
        return [*readable, *writable]

    def inspect(self) -> MhsResult:
        return self._ok("inspect", self.manifest.model_dump(mode="json"))

    def status(self) -> MhsResult:
        if self.manifest.driver_sha256 != self._driver_digest or (
            self.manifest.driver is not None and self.manifest.driver.sha256 != self._driver_digest
        ):
            return self._error("status", "driver digest changed since registration")
        try:
            return self._ok("status", dict(self.backend.status()))
        except Exception as exc:
            return self._error("status", f"backend status failed: {type(exc).__name__}")

    def read(self) -> MhsResult:
        if self.manifest.manifest_sha256 != self._manifest_digest:
            return self._error("read", "manifest digest changed since registration")
        if self.manifest.driver_sha256 != self._driver_digest:
            return self._error("read", "driver digest changed since registration")
        capability = "read"
        observed_at = datetime.now(timezone.utc)
        try:
            if self.timeout_s is not None:
                from concurrent.futures import ThreadPoolExecutor

                with ThreadPoolExecutor(max_workers=1) as executor:
                    values = dict(executor.submit(self.backend.read).result(timeout=self.timeout_s))
            else:
                values = dict(self.backend.read())
            channels = {channel.id: channel for channel in self.manifest.channels}
            unknown = sorted(set(values) - set(channels))
            if unknown:
                raise ValueError(f"undeclared channels: {', '.join(unknown)}")
            samples: list[dict[str, Any]] = []
            for channel_id, value in sorted(values.items()):
                channel = channels[channel_id]
                if channel.value_type == "number":
                    if (
                        isinstance(value, bool)
                        or not isinstance(value, (int, float))
                        or not math.isfinite(float(value))
                    ):
                        raise ValueError(f"channel {channel_id} is not a finite number")
                    if channel.min_value is not None and float(value) < channel.min_value:
                        raise ValueError(f"channel {channel_id} is below its minimum")
                    if channel.max_value is not None and float(value) > channel.max_value:
                        raise ValueError(f"channel {channel_id} is above its maximum")
                elif channel.value_type == "boolean" and not isinstance(value, bool):
                    raise ValueError(f"channel {channel_id} is not boolean")
                elif channel.value_type == "string" and not isinstance(value, str):
                    raise ValueError(f"channel {channel_id} is not string")
                samples.append({"channel": channel_id, "value": value, "unit": channel.unit})
            return self._ok(
                capability,
                {"device_id": self.manifest.device_id, "samples": samples},
                observed_at,
            )
        except ValueError as exc:
            return self._error(capability, f"read rejected: {exc}")
        except Exception as exc:
            reason = "backend read timed out" if type(exc).__name__ == "TimeoutError" else f"backend read failed: {type(exc).__name__}"
            return self._error(capability, reason)

    def read_structured(self) -> MhsResult:
        """Read structured samples through an optional environment adapter."""

        capability = "read_structured"
        observed_at = datetime.now(timezone.utc)
        reader = getattr(self.backend, "read_structured", None)
        if not callable(reader):
            return self._error(capability, "structured interface backend is unavailable")
        try:
            samples = list(reader())
            declared = {interface.id: interface for interface in self.manifest.interfaces}
            for sample in samples:
                interface = declared.get(sample.interface_id)
                if interface is None:
                    raise ValueError(f"undeclared interface: {sample.interface_id}")
                if interface.access == "write":
                    raise ValueError(f"write interface cannot be sampled: {sample.interface_id}")
            return self._ok(
                capability,
                {
                    "device_id": self.manifest.device_id,
                    "samples": [sample.model_dump(mode="json") for sample in samples],
                },
                observed_at,
                samples=samples,
            )
        except ValueError as exc:
            return self._error(capability, f"structured read rejected: {exc}")
        except Exception as exc:
            return self._error(capability, f"structured read failed: {type(exc).__name__}")

    def invoke(self, capability_id: str, arguments: Mapping[str, Any] | None = None, *, route_ref: str | None = None) -> MhsResult:
        """Invoke only read capabilities; all write-like requests fail closed."""

        del arguments, route_ref
        capability = capability_id.removeprefix("mhs.")
        if capability == "inspect":
            return self.inspect()
        if capability == "status":
            return self.status()
        if capability == "read":
            return self.read()
        if capability == "read_structured":
            return self.read_structured()
        return self._error(capability, "write or unknown capability is not available in v2")

    def _ok(
        self,
        capability: str,
        value: dict[str, Any],
        observed_at: datetime | None = None,
        *,
        samples: list[MhsInterfaceSample] | None = None,
    ) -> MhsResult:
        point = observed_at or datetime.now(timezone.utc)
        return MhsResult(
            status=MhsStatus.AVAILABLE,
            device_id=self.manifest.device_id,
            capability_id=capability,
            route=f"mhs://{self.manifest.device_id}/{capability}",
            value=value,
            observed_at=point,
            fresh_until=point + timedelta(seconds=self.freshness_seconds),
            manifest_sha256=self.manifest.manifest_sha256,
            driver_id=self.manifest.driver_id,
            driver_version=self.manifest.driver_version,
            driver_sha256=self.manifest.driver_sha256,
            provider_version=self.provider_version,
            transport=self.manifest.transport,
            samples=list(samples or []),
            evidence_ids=[
                f"mhs-manifest:{self.manifest.manifest_sha256}",
                f"mhs-driver:{self.manifest.driver_sha256}",
            ],
            target_host_fingerprint=self.target_host_fingerprint,
        )

    def _error(self, capability: str, reason: str) -> MhsResult:
        point = datetime.now(timezone.utc)
        return MhsResult(
            status=MhsStatus.UNAVAILABLE,
            device_id=self.manifest.device_id,
            capability_id=capability,
            route=f"mhs://{self.manifest.device_id}/{capability}",
            reason=reason,
            observed_at=point,
            fresh_until=point + timedelta(seconds=self.freshness_seconds),
            manifest_sha256=self.manifest.manifest_sha256,
            driver_id=self.manifest.driver_id,
            driver_version=self.manifest.driver_version,
            driver_sha256=self.manifest.driver_sha256,
            provider_version=self.provider_version,
            transport=self.manifest.transport,
            evidence_ids=[
                f"mhs-manifest:{self.manifest.manifest_sha256}",
                f"mhs-driver:{self.manifest.driver_sha256}",
            ],
            limitations=["read-only provider; no write operations"],
            target_host_fingerprint=self.target_host_fingerprint,
        )


class MhsProviderRegistry:
    """Process-local compatibility registry for provider discovery tests."""

    def __init__(self) -> None:
        self._providers: dict[str, MhsDeviceProvider] = {}

    def register(self, provider: MhsDeviceProvider) -> MhsDeviceProvider:
        if provider.manifest.device_id in self._providers:
            raise ValueError("duplicate MHS device id")
        self._providers[provider.manifest.device_id] = provider
        return provider

    def list(self) -> list[MhsDeviceProvider]:
        return list(self._providers.values())


def mhs_results_to_snapshot(identity, results: list[MhsResult]):
    from rolo.rkb.models import Fact, FactSourceKind, Snapshot

    facts = []
    for result in results:
        kind = FactSourceKind.DECLARED if result.capability_id == "inspect" else FactSourceKind.OBSERVED
        facts.append(Fact(robot_id=identity.robot_id,
            target_host_fingerprint=identity.target_host_fingerprint,
            collector_id=identity.collector_id, deployment_mode=identity.deployment_mode,
            access=identity.access, request_nonce=identity.request_nonce,
            source_kind=kind, source_ref=result.route,
            observed_at=result.observed_at or identity.observed_at,
            fresh_until=result.fresh_until or identity.fresh_until,
            value={
                "layer": "hardware",
                "data": {
                    "resources": [{
                        "resource_id": f"mhs:{result.device_id}",
                        "kind": "mhs_device",
                        "name": result.device_id,
                        "provider_id": f"mhs.{result.device_id}",
                        "transport": result.route,
                        "path": result.route,
                        "limitations": result.limitations,
                    }]
                    ,
                    "mhs": [{
                        "device_id": result.device_id,
                        "capability_id": result.capability_id,
                        "operation_id": f"mhs.{result.device_id}.{result.capability_id}",
                        "status": result.status.value,
                        "route": result.route,
                        "source_kind": result.source_kind.value,
                    }]
                },
                "mhs_result": result.value or {"status": result.status.value},
            },
            limitations=result.limitations + ([result.reason] if result.reason else [])))
    return Snapshot(identity=identity, facts=facts, snapshot={"layer": "mhs"}).with_digest()
