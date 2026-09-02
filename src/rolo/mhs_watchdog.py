"""Discovery and safe readout for vendor watchdog capabilities.

Watchdog discovery is deliberately read-only.  A vendor adapter may report a
capability, but Rolo only treats it as an independent safety signal after the
adapter exposes a bounded status record and an induced-loss test has produced
safe-state evidence.  The included fixture is a deterministic development
stand-in; it never touches a robot or an actuator.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Protocol

from pydantic import BaseModel, ConfigDict, Field


def _now() -> datetime:
    return datetime.now(timezone.utc)


class MhsWatchdogDescriptor(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    capability_id: str = Field(min_length=1, pattern=r"^[a-z][a-z0-9_.:/-]*$")
    source_id: str = Field(min_length=1)
    vendor: str = Field(min_length=1)
    protocol: str = Field(min_length=1)
    status_route: str = Field(min_length=1)
    heartbeat_route: str | None = None
    timeout_action: str = Field(min_length=1)
    independent_of_rolo: bool = False


class MhsWatchdogStatus(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    source_id: str = Field(min_length=1)
    armed: bool
    healthy: bool
    independent_source: bool
    heartbeat_seq: int = Field(ge=0)
    last_heartbeat_at: datetime | None = None
    max_age_ms: int = Field(gt=0, le=60000)
    trip_count: int = Field(ge=0)
    safe_state_confirmed: bool
    actuator_enable: bool | None = None
    observed_at: datetime = Field(default_factory=_now)
    evidence_ids: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)

    def is_fresh(self, now: datetime | None = None) -> bool:
        if self.last_heartbeat_at is None:
            return False
        point = now or _now()
        return point - self.last_heartbeat_at <= timedelta(milliseconds=self.max_age_ms)

    def is_eligible(self, now: datetime | None = None) -> bool:
        return (
            self.armed
            and self.healthy
            and self.independent_source
            and self.is_fresh(now)
            and self.safe_state_confirmed
        )


class MhsWatchdogAdapter(Protocol):
    adapter_id: str

    def inspect(self) -> MhsWatchdogDescriptor | None: ...

    def status(self) -> MhsWatchdogStatus: ...


class MhsWatchdogRegistry:
    """Probe vendor adapters and register only explicit watchdog capabilities."""

    def __init__(self) -> None:
        self._adapters: dict[str, MhsWatchdogAdapter] = {}
        self._descriptors: dict[str, MhsWatchdogDescriptor] = {}

    def discover(self, adapter: MhsWatchdogAdapter) -> MhsWatchdogDescriptor | None:
        descriptor = adapter.inspect()
        if descriptor is None:
            return None
        if not descriptor.independent_of_rolo:
            # Application heartbeats are useful diagnostics but must not enter
            # the independent safety registry.
            return None
        if descriptor.capability_id in self._descriptors:
            raise ValueError(f"duplicate watchdog capability: {descriptor.capability_id}")
        self._adapters[descriptor.capability_id] = adapter
        self._descriptors[descriptor.capability_id] = descriptor
        return descriptor

    def descriptors(self) -> list[MhsWatchdogDescriptor]:
        return [self._descriptors[key] for key in sorted(self._descriptors)]

    def status(self, capability_id: str) -> MhsWatchdogStatus:
        try:
            return self._adapters[capability_id].status()
        except KeyError as exc:
            raise KeyError(f"unknown watchdog capability: {capability_id}") from exc


class WatchdogTestFixture:
    """Deterministic independent-watchdog model for a no-load test bench."""

    def __init__(self, *, source_id: str = "fixture-safety-mcu", timeout_ms: int = 100) -> None:
        self.source_id = source_id
        self.timeout_ms = timeout_ms
        self._last_heartbeat: datetime | None = None
        self._sequence = 0
        self._trip_count = 0
        self._safe_state = True
        self._armed = False

    def arm(self, *, at: datetime | None = None) -> None:
        self._armed = True
        self._safe_state = False
        self.heartbeat(at=at)

    def heartbeat(self, *, at: datetime | None = None) -> None:
        self._last_heartbeat = at or _now()
        self._sequence += 1
        self._safe_state = False

    def observe(self, *, at: datetime | None = None) -> MhsWatchdogStatus:
        point = at or _now()
        if (
            self._armed
            and self._last_heartbeat is not None
            and point - self._last_heartbeat > timedelta(milliseconds=self.timeout_ms)
            and not self._safe_state
        ):
            self._trip_count += 1
            self._safe_state = True
        healthy = bool(
            self._armed
            and self._last_heartbeat is not None
            and point - self._last_heartbeat <= timedelta(milliseconds=self.timeout_ms)
        )
        return MhsWatchdogStatus(
            source_id=self.source_id,
            armed=self._armed,
            healthy=healthy,
            independent_source=True,
            heartbeat_seq=self._sequence,
            last_heartbeat_at=self._last_heartbeat,
            max_age_ms=self.timeout_ms,
            trip_count=self._trip_count,
            safe_state_confirmed=self._safe_state,
            actuator_enable=not self._safe_state,
            observed_at=point,
            evidence_ids=[f"fixture:watchdog:{self.source_id}:{self._trip_count}"],
            limitations=["development fixture; no physical actuator attached"],
        )


class WatchdogFixtureAdapter:
    adapter_id = "fixture.watchdog"

    def __init__(self, fixture: WatchdogTestFixture) -> None:
        self.fixture = fixture

    def inspect(self) -> MhsWatchdogDescriptor:
        return MhsWatchdogDescriptor(
            capability_id="safety.watchdog.fixture",
            source_id=self.fixture.source_id,
            vendor="rolo-test-fixture",
            protocol="fixture-heartbeat-v1",
            status_route="fixture://watchdog/status",
            heartbeat_route="fixture://watchdog/heartbeat",
            timeout_action="fixture:disable-actuator-enable",
            independent_of_rolo=True,
        )

    def status(self) -> MhsWatchdogStatus:
        return self.fixture.observe()


__all__ = [
    "MhsWatchdogDescriptor",
    "MhsWatchdogStatus",
    "MhsWatchdogAdapter",
    "MhsWatchdogRegistry",
    "WatchdogTestFixture",
    "WatchdogFixtureAdapter",
]
