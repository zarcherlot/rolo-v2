from __future__ import annotations

from datetime import datetime, timedelta, timezone

from rolo.mhs_watchdog import (
    MhsWatchdogDescriptor,
    MhsWatchdogRegistry,
    WatchdogFixtureAdapter,
    WatchdogTestFixture,
)


def test_fixture_watchdog_is_healthy_then_trips_to_safe_state() -> None:
    fixture = WatchdogTestFixture(timeout_ms=100)
    start = datetime(2026, 9, 2, tzinfo=timezone.utc)
    fixture.arm(at=start)
    healthy = fixture.observe(at=start + timedelta(milliseconds=20))
    assert healthy.is_eligible(start + timedelta(milliseconds=20)) is False
    assert healthy.healthy is True
    assert healthy.safe_state_confirmed is False

    tripped = fixture.observe(at=start + timedelta(milliseconds=150))
    assert tripped.healthy is False
    assert tripped.safe_state_confirmed is True
    assert tripped.safe_state_capable is True
    assert tripped.trip_count == 1

    fixture.arm(at=start + timedelta(milliseconds=160))
    recovered = fixture.observe(at=start + timedelta(milliseconds=180))
    assert recovered.is_eligible(start + timedelta(milliseconds=180)) is True


def test_registry_rejects_application_heartbeat_and_registers_independent_fixture() -> None:
    fixture = WatchdogTestFixture()
    fixture.arm(at=datetime(2026, 9, 2, tzinfo=timezone.utc))
    registry = MhsWatchdogRegistry()

    class AppHeartbeatAdapter:
        adapter_id = "app.heartbeat"

        def inspect(self):
            return MhsWatchdogDescriptor(
                capability_id="safety.watchdog.app",
                source_id="rolo-process",
                vendor="rolo",
                protocol="ros-heartbeat",
                status_route="ros2:/diagnostics",
                timeout_action="exit-process",
                independent_of_rolo=False,
            )

        def status(self):
            raise AssertionError("application heartbeat must not be registered")

    assert registry.discover(AppHeartbeatAdapter()) is None
    descriptor = registry.discover(WatchdogFixtureAdapter(fixture))
    assert descriptor is not None
    assert [item.capability_id for item in registry.descriptors()] == [
        "safety.watchdog.fixture"
    ]
