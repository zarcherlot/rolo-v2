from dataclasses import dataclass

from rolo.mhs_hardware import (
    MhsChannel,
    MhsDeviceClass,
    MhsDeviceManifest,
    MhsDeviceProvider,
    MhsStatus,
)


@dataclass
class FakeBackend:
    values: dict
    writes: int = 0

    def read(self):
        return dict(self.values)

    def status(self):
        return {"health": "OK"}


def make_provider(values=None):
    manifest = MhsDeviceManifest(
        device_id="cabinet-1",
        device_class=MhsDeviceClass.SENSOR,
        name="environment",
        vendor="example",
        model="env-1",
        channels=[
            MhsChannel(
                id="temperature", name="Temperature", unit="degC", min_value=-20, max_value=80
            )
        ],
        transport={"kind": "fake"},
    )
    backend = FakeBackend(values or {"temperature": 23.5})
    return MhsDeviceProvider(manifest, backend), backend


def test_mhs_provider_exposes_only_read_routes():
    instance, _ = make_provider()
    assert {item["capability_id"] for item in instance.capabilities()} == {
        "inspect",
        "read",
        "status",
    }
    assert instance.route("read") == "mhs://cabinet-1/read"
    assert instance.invoke("reset").status == MhsStatus.UNAVAILABLE


def test_mhs_provider_rejects_unknown_and_unsafe_measurements():
    instance, _ = make_provider({"pressure": 1})
    assert instance.read().status == MhsStatus.UNAVAILABLE
    instance, _ = make_provider({"temperature": 100})
    assert instance.read().status == MhsStatus.UNAVAILABLE
