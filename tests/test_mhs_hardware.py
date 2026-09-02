from dataclasses import dataclass
from datetime import datetime, timezone

from rolo.mhs_hardware import (
    MhsChannel,
    MhsDeviceClass,
    MhsDeviceManifest,
    MhsDeviceProvider,
    MhsInterfaceSample,
    MhsStatus,
)
from rolo.mhs_replay import MhsReplayBackend


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
    denied = instance.invoke("reset")
    assert denied.status == MhsStatus.UNAVAILABLE
    assert denied.observed_at is not None
    assert denied.fresh_until is not None
    assert denied.driver_sha256 == instance.manifest.driver_sha256
    assert denied.evidence_ids


def test_mhs_provider_rejects_unknown_and_unsafe_measurements():
    instance, _ = make_provider({"pressure": 1})
    assert instance.read().status == MhsStatus.UNAVAILABLE
    instance, _ = make_provider({"temperature": 100})
    rejected = instance.read()
    assert rejected.status == MhsStatus.UNAVAILABLE
    assert rejected.manifest_sha256 == instance.manifest.manifest_sha256


def test_structured_replay_is_optional_and_read_only():
    manifest = MhsDeviceManifest(
        device_id="camera-1",
        device_class=MhsDeviceClass.SENSOR,
        name="camera",
        vendor="example",
        model="depth",
        interfaces=[{"id": "depth", "kind": "image", "access": "stream"}],
    )
    sample = MhsInterfaceSample(
        interface_id="depth",
        value={"width": 2, "height": 1, "data": [1, 2]},
        observed_at=datetime.now(timezone.utc),
    )
    provider = MhsDeviceProvider(manifest, MhsReplayBackend(manifest, structured_samples=[sample]))
    assert "read_structured" in {item["capability_id"] for item in provider.capabilities()}
    result = provider.read_structured()
    assert result.status == MhsStatus.AVAILABLE
    assert result.samples[0].interface_id == "depth"
