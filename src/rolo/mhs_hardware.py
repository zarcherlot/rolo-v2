"""Rolo-owned, read-only MHS-compatible hardware adapter.

The public MHS wire protocol is not assumed here. This module defines the
small compatibility seam Rolo can verify today: a device manifest, a bounded
``inspect``/``status``/``read`` surface, and provenance that can be projected
into an RKB evidence snapshot. There is deliberately no write SPI.
"""

from __future__ import annotations

import hashlib
import json
import math
import time
from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Protocol

from pydantic import BaseModel, ConfigDict, Field, model_validator


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _stamp(point: datetime) -> int:
    return int(point.timestamp() * 1_000_000_000)


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )


class MhsStatus(str, Enum):
    AVAILABLE = "AVAILABLE"
    UNAVAILABLE = "UNAVAILABLE"
    STALE = "STALE"


class MhsSourceKind(str, Enum):
    DECLARED = "DECLARED"
    OBSERVED = "OBSERVED"


class MhsDeviceClass(str, Enum):
    SENSOR = "sensor"
    CONTROLLER = "controller"
    ACTUATOR = "actuator"
    POWER = "power"
    COMPUTE = "compute"
    BUS = "bus"
    TOOL = "tool"


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


class MhsDriver(BaseModel):
    model_config = ConfigDict(extra="forbid")

    provider_id: str = Field(min_length=1)
    version: str = Field(default="unknown", min_length=1)
    sha256: str = Field(default="0" * 64, pattern=r"^[0-9a-f]{64}$")


class MhsDeviceManifest(BaseModel):
    """Unified MHS device reference for sensors and other device classes."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = "rolo-mhs-device/v1"
    device_id: str = Field(min_length=1, pattern=r"^[a-z][a-z0-9_.-]*$")
    device_class: MhsDeviceClass
    name: str = Field(min_length=1)
    vendor: str = Field(min_length=1)
    model: str = Field(min_length=1)
    serial: str | None = None
    channels: list[MhsChannel] = Field(default_factory=list)
    resources: list[Any] = Field(default_factory=list)
    state: dict[str, Any] = Field(default_factory=dict)
    transport: dict[str, Any] = Field(default_factory=dict)
    limits: dict[str, Any] | list[str] = Field(default_factory=dict)
    commands: list[dict[str, Any]] = Field(default_factory=list)
    driver: MhsDriver | None = None
    # v0 compatibility aliases retained for old manifests.
    driver_id: str = Field(default="unknown-driver", min_length=1)
    driver_version: str = Field(default="unknown", min_length=1)
    driver_sha256: str = Field(default="0" * 64, pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_manifest(self) -> MhsDeviceManifest:
        ids = [item.id for item in self.channels]
        if len(ids) != len(set(ids)):
            raise ValueError("manifest contains duplicate channel ids")
        if self.driver is not None:
            if self.driver_id != "unknown-driver" and self.driver_id != self.driver.provider_id:
                raise ValueError("driver_id conflicts with driver.provider_id")
            if self.driver_sha256 != "0" * 64 and self.driver_sha256 != self.driver.sha256:
                raise ValueError("driver_sha256 conflicts with driver.sha256")
            if self.driver_version != "unknown" and self.driver_version != self.driver.version:
                raise ValueError("driver_version conflicts with driver.version")
        return self

    @property
    def resolved_driver(self) -> MhsDriver:
        return self.driver or MhsDriver(
            provider_id=self.driver_id, version=self.driver_version, sha256=self.driver_sha256
        )

    @property
    def manifest_sha256(self) -> str:
        return hashlib.sha256(_canonical(self.model_dump(mode="json"))).hexdigest()

    def reference_file(self) -> dict[str, Any]:
        """Compatibility alias used by the original sensor example."""

        return self.model_dump(mode="json")


class MhsBackend(Protocol):
    def read(self) -> Mapping[str, int | float | bool | str]: ...

    def status(self) -> Mapping[str, Any]: ...


class MhsResult(BaseModel):
    """Bounded result with enough provenance to become an RKB fact."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = "rolo-mhs-result/v1"
    status: MhsStatus
    device_id: str
    capability_id: str
    route: str
    source_kind: MhsSourceKind
    target_host_fingerprint: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    manifest_sha256: str
    driver_provider_id: str
    driver_version: str
    driver_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    value: dict[str, Any] | None = None
    observed_at: datetime
    fresh_until: datetime
    fact_ids: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)
    reason: str | None = None
    limitations: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_window_and_ids(self) -> MhsResult:
        if self.fresh_until <= self.observed_at:
            raise ValueError("fresh_until must be after observed_at")
        if not self.fact_ids and self.evidence_ids:
            object.__setattr__(self, "fact_ids", list(self.evidence_ids))
        if not self.evidence_ids and self.fact_ids:
            object.__setattr__(self, "evidence_ids", list(self.fact_ids))
        return self

    @property
    def canonical_route(self) -> str:
        return self.route

    def as_fact(self, identity: Any) -> Any:
        from .rkb.models import Fact, FactConfidence, FactSourceKind

        if (
            self.target_host_fingerprint
            and identity.target_host_fingerprint != self.target_host_fingerprint
        ):
            raise ValueError("MHS result target fingerprint mismatch")
        source = (
            FactSourceKind.DECLARED
            if self.source_kind == MhsSourceKind.DECLARED
            else FactSourceKind.OBSERVED
        )
        return Fact(
            fact_id=self.fact_ids[0]
            if self.fact_ids
            else f"mhs:{self.device_id}:{self.capability_id}:{self.manifest_sha256[:16]}",
            robot_id=identity.robot_id,
            target_host_fingerprint=identity.target_host_fingerprint,
            collector_id=identity.collector_id,
            deployment_mode=identity.deployment_mode,
            access=identity.access,
            request_nonce=identity.request_nonce,
            source_kind=source,
            source_ref=self.route,
            observed_at=self.observed_at,
            fresh_until=min(self.fresh_until, identity.fresh_until),
            value={"layer": "hardware", "mhs": self.model_dump(mode="json")},
            confidence=FactConfidence.HIGH
            if self.status == MhsStatus.AVAILABLE
            else FactConfidence.LOW,
            limitations=self.limitations,
        )


class MhsDeviceProvider:
    """Read-only Provider SPI for one manifest and a bounded backend."""

    provider_version = "1.0.0"
    READ_CAPABILITIES = frozenset({"inspect", "status", "read"})
    DEFAULT_FRESHNESS = {
        "inspect": timedelta(hours=24),
        "status": timedelta(seconds=30),
        "read": timedelta(seconds=10),
    }

    def __init__(
        self,
        manifest: MhsDeviceManifest,
        backend: MhsBackend,
        *,
        target_host_fingerprint: str | None = None,
        freshness: Mapping[str, timedelta] | None = None,
        timeout_s: float = 5.0,
        retries: int = 0,
    ) -> None:
        self.manifest = manifest
        self.backend = backend
        self.provider_id = f"mhs.{manifest.device_id}"
        self.target_host_fingerprint = target_host_fingerprint
        self.freshness = {**self.DEFAULT_FRESHNESS, **dict(freshness or {})}
        if timeout_s <= 0:
            raise ValueError("timeout_s must be positive")
        if retries < 0 or retries > 2:
            raise ValueError("retries must be between 0 and 2")
        self.timeout_s = timeout_s
        self.retries = retries
        self._manifest_digest = manifest.manifest_sha256
        self._driver = manifest.resolved_driver

    def route(self, capability_id: str) -> str:
        capability = capability_id.removeprefix("mhs.")
        return f"mhs://{self.manifest.device_id}/{capability}"

    @staticmethod
    def legacy_route(device_id: str, capability_id: str) -> str:
        return f"mhs://sensor/{device_id}/{capability_id.removeprefix('mhs.')}"

    def capabilities(self) -> list[dict[str, Any]]:
        return [
            {
                "capability_id": capability,
                "access": "read",
                "route": self.route(capability),
                "status": "DISCOVERED_UNVERIFIED",
                "source_kind": MhsSourceKind.DECLARED.value,
                "manifest_sha256": self._manifest_digest,
                "driver_sha256": self._driver.sha256,
                "evidence_ids": [f"mhs-manifest:{self._manifest_digest}"],
            }
            for capability in sorted(self.READ_CAPABILITIES)
        ]

    def inspect(self) -> MhsResult:
        return self._ok("inspect", self.manifest.model_dump(mode="json"), MhsSourceKind.DECLARED)

    def status(self) -> MhsResult:
        try:
            return self._ok("status", dict(self._backend_call("status")), MhsSourceKind.OBSERVED)
        except TimeoutError:
            return self._error("status", "backend status timed out")
        except Exception as exc:
            return self._error("status", f"backend status failed: {type(exc).__name__}")

    def read(self) -> MhsResult:
        try:
            values = dict(self._backend_call("read"))
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
                "read",
                {"device_id": self.manifest.device_id, "samples": samples},
                MhsSourceKind.OBSERVED,
            )
        except ValueError as exc:
            return self._error("read", f"read rejected: {exc}")
        except TimeoutError:
            return self._error("read", "backend read timed out")
        except Exception as exc:
            return self._error("read", f"backend read failed: {type(exc).__name__}")

    def invoke(
        self,
        capability_id: str,
        arguments: Mapping[str, Any] | None = None,
        *,
        route_ref: str | None = None,
    ) -> MhsResult:
        del arguments
        capability = capability_id.removeprefix("mhs.")
        expected = self.route(capability)
        if route_ref is not None and route_ref not in {
            expected,
            self.legacy_route(self.manifest.device_id, capability),
        }:
            return self._error(capability, "route does not match this MHS device")
        if capability == "inspect":
            return self.inspect()
        if capability == "status":
            return self.status()
        if capability == "read":
            return self.read()
        return self._error(capability, "write or unknown capability is not available in v2")

    def _integrity_error(self) -> str | None:
        if self.manifest.resolved_driver != self._driver:
            return "driver digest or version changed during provider lifetime"
        if self.manifest.manifest_sha256 != self._manifest_digest:
            return "manifest digest changed during provider lifetime"
        return None

    def _backend_call(self, method: str) -> Mapping[str, Any]:
        """Run one backend call with a bounded wait and no shared executor."""

        last_error: Exception | None = None
        for attempt in range(self.retries + 1):
            executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="rolo-mhs")
            future = executor.submit(getattr(self.backend, method))
            try:
                return future.result(timeout=self.timeout_s)
            except FutureTimeout:
                future.cancel()
                last_error = TimeoutError(f"backend {method} timed out")
            except Exception as exc:  # backend errors are retried only for read-only calls
                last_error = exc
            finally:
                executor.shutdown(wait=False, cancel_futures=True)
            if attempt < self.retries:
                time.sleep(min(0.25, 0.05 * (2**attempt)))
        assert last_error is not None
        raise last_error

    def _ok(self, capability: str, value: dict[str, Any], source: MhsSourceKind) -> MhsResult:
        observed_at = _now()
        if (error := self._integrity_error()) is not None:
            return self._error(capability, error)
        fact_id = f"mhs:{self.manifest.device_id}:{capability}:{_stamp(observed_at)}"
        driver = self._driver
        return MhsResult(
            status=MhsStatus.AVAILABLE,
            device_id=self.manifest.device_id,
            capability_id=capability,
            route=self.route(capability),
            source_kind=source,
            target_host_fingerprint=self.target_host_fingerprint,
            manifest_sha256=self._manifest_digest,
            driver_provider_id=driver.provider_id,
            driver_version=driver.version,
            driver_sha256=driver.sha256,
            value=value,
            observed_at=observed_at,
            fresh_until=observed_at + self.freshness.get(capability, timedelta(seconds=10)),
            fact_ids=[fact_id],
            evidence_ids=[f"mhs-manifest:{self._manifest_digest}", f"mhs-driver:{driver.sha256}"],
            limitations=[
                "measurement bounds are data validity constraints, not actuator or safety limits"
            ],
        )

    def _error(self, capability: str, reason: str) -> MhsResult:
        observed_at = _now()
        driver = self._driver
        fact_id = f"mhs:{self.manifest.device_id}:{capability}:{_stamp(observed_at)}"
        return MhsResult(
            status=MhsStatus.UNAVAILABLE,
            device_id=self.manifest.device_id,
            capability_id=capability,
            route=self.route(capability),
            source_kind=MhsSourceKind.OBSERVED,
            target_host_fingerprint=self.target_host_fingerprint,
            manifest_sha256=self._manifest_digest,
            driver_provider_id=driver.provider_id,
            driver_version=driver.version,
            driver_sha256=driver.sha256,
            observed_at=observed_at,
            fresh_until=observed_at + self.freshness.get(capability, timedelta(seconds=10)),
            fact_ids=[fact_id],
            evidence_ids=[f"mhs-manifest:{self._manifest_digest}", f"mhs-driver:{driver.sha256}"],
            reason=reason,
            limitations=[
                "read-only provider; no write operations",
                "measurement validity is not a physical safety conclusion",
            ],
        )


class MhsProviderRegistry:
    """Deterministic registry that rejects duplicate device identities."""

    def __init__(self) -> None:
        self._providers: dict[str, MhsDeviceProvider] = {}

    def register(self, provider: MhsDeviceProvider) -> None:
        if provider.manifest.device_id in self._providers:
            raise ValueError(f"duplicate MHS device id: {provider.manifest.device_id}")
        self._providers[provider.manifest.device_id] = provider

    def get(self, device_id: str) -> MhsDeviceProvider:
        return self._providers[device_id]

    def providers(self) -> list[MhsDeviceProvider]:
        return [self._providers[key] for key in sorted(self._providers)]


def mhs_results_to_snapshot(identity: Any, results: list[MhsResult]) -> Any:
    """Build a target-bound RKB snapshot from MHS results."""

    from .rkb.models import Snapshot

    facts = [result.as_fact(identity) for result in results]
    return Snapshot(
        identity=identity,
        facts=facts,
        snapshot={
            "layer": "hardware",
            "mhs_devices": sorted({result.device_id for result in results}),
            "routes": sorted({result.route for result in results}),
        },
        freshness_policy={"mhs.inspect": 86400, "mhs.status": 30, "mhs.read": 10},
    ).with_digest()


__all__ = [
    "MhsBackend",
    "MhsChannel",
    "MhsDeviceClass",
    "MhsDeviceManifest",
    "MhsDeviceProvider",
    "MhsDriver",
    "MhsProviderRegistry",
    "MhsResult",
    "MhsSourceKind",
    "MhsStatus",
    "mhs_results_to_snapshot",
]
