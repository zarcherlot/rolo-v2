"""Example-provider tests; collected by the v2 CI test configuration."""

from dataclasses import dataclass

from rolo.mhs_hardware import (
    MhsChannel,
    MhsDeviceClass,
    MhsDeviceManifest,
    MhsDeviceProvider,
    MhsStatus,
)


@dataclass
class FakeSensor:
    values: dict[str, float | bool]

    def read(self):
        return dict(self.values)

    def status(self):
        return {"health": "OK", "connection": "ready"}


def make_provider(values=None):
    manifest = MhsDeviceManifest(
        device_id="cabinet-1",
        device_class=MhsDeviceClass.SENSOR,
        name="Cabinet environmental sensor",
        vendor="Example",
        model="ENV-1",
        channels=[
            MhsChannel(
                id="temperature", name="Temperature", unit="degC", min_value=-20, max_value=80
            )
        ],
        transport={"kind": "python", "backend": "fake"},
    )
    return MhsDeviceProvider(manifest, FakeSensor(values or {"temperature": 23.5}))


def test_example_sensor_read():
    result = make_provider().read()
    assert result.status == MhsStatus.AVAILABLE
    assert result.route == "mhs://cabinet-1/read"


def test_example_sensor_rejects_write_and_bad_value():
    assert make_provider().invoke("reset").status == MhsStatus.UNAVAILABLE
    assert make_provider({"temperature": 100}).read().status == MhsStatus.UNAVAILABLE
