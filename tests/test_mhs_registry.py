from __future__ import annotations

import pytest

from rolo.mhs_hardware import MhsChannel, MhsDeviceClass, MhsDeviceManifest, MhsDeviceProvider
from rolo.mhs_registry import MhsProviderRegistry, MhsRegistryError


class Backend:
    def read(self):
        return {"temperature": 20.0}

    def status(self):
        return {"ok": True}


def provider(device_id: str = "imu") -> MhsDeviceProvider:
    manifest = MhsDeviceManifest(
        device_id=device_id,
        device_class=MhsDeviceClass.SENSOR,
        name="IMU",
        vendor="fixture",
        model="v1",
        channels=[MhsChannel(id="temperature", name="Temperature", unit="C")],
    )
    return MhsDeviceProvider(manifest, Backend())


def test_registry_persists_registration_without_granting_verification(tmp_path) -> None:
    registry = MhsProviderRegistry(tmp_path)
    record = registry.register(provider())
    assert record.status.value == "REGISTERED"
    assert "inspect" in record.capabilities
    assert all(route.startswith("mhs://imu/") for route in record.routes)
    loaded = MhsProviderRegistry(tmp_path).get("mhs.imu")
    assert loaded is not None
    assert "verification" in loaded.limitations[0]


def test_registry_rejects_duplicate_and_digest_drift(tmp_path) -> None:
    registry = MhsProviderRegistry(tmp_path)
    registry.register(provider())
    with pytest.raises(MhsRegistryError, match="duplicate provider id"):
        registry.register(provider())
    changed = provider()
    changed.manifest = changed.manifest.model_copy(update={"model": "v2"})
    with pytest.raises(MhsRegistryError, match="drift"):
        registry.register(changed)


def test_provider_route_rejects_write_capability() -> None:
    with pytest.raises(ValueError, match="not available"):
        provider().route("stop")
