from __future__ import annotations

from rolo.mhs_adapters import (
    MhsAdapterRegistry,
    MhsEnvironmentDescriptor,
    MhsSoftwareEnvironment,
)
from rolo.mhs_hardware import MhsDeviceManifest


class StaticAdapter:
    def __init__(self, adapter_id: str, environment: MhsEnvironmentDescriptor, backend: object) -> None:
        self.adapter_id = adapter_id
        self.environment = environment
        self.backend = backend

    def backend_for(self, manifest: MhsDeviceManifest) -> object:
        del manifest
        return self.backend


class Backend:
    def read(self):
        return {"value": 1.0}

    def status(self):
        return {"health": "OK"}


def _manifest() -> MhsDeviceManifest:
    return MhsDeviceManifest(
        device_id="sensor-1",
        device_class="sensor",
        name="generic sensor",
        vendor="example",
        model="x",
        channels=[{"id": "value", "name": "Value", "unit": "unit"}],
    )


def test_same_manifest_can_use_multiple_software_adapters() -> None:
    registry = MhsAdapterRegistry()
    backend = Backend()
    for adapter_id, kind in (("sim", MhsSoftwareEnvironment.SIMULATION), ("ros", MhsSoftwareEnvironment.ROS2)):
        registry.register(
            StaticAdapter(
                adapter_id,
                MhsEnvironmentDescriptor(kind=kind, runtime=adapter_id, version="1"),
                backend,
            )
        )
    assert registry.provider("sim", _manifest()).route("read") == "mhs://sensor-1/read"
    assert [item.kind for item in registry.descriptors()] == [
        MhsSoftwareEnvironment.ROS2,
        MhsSoftwareEnvironment.SIMULATION,
    ]


def test_unknown_or_duplicate_adapter_fails_closed() -> None:
    registry = MhsAdapterRegistry()
    adapter = StaticAdapter(
        "sim", MhsEnvironmentDescriptor(kind="simulation", runtime="sim"), Backend()
    )
    registry.register(adapter)
    try:
        registry.register(adapter)
    except ValueError:
        pass
    else:
        raise AssertionError("duplicate adapter was accepted")
    try:
        registry.provider("missing", _manifest())
    except KeyError:
        pass
    else:
        raise AssertionError("unknown adapter was accepted")
