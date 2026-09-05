from __future__ import annotations

from dataclasses import dataclass

from rolo.capabilities import (
    InvokeRequest,
    ProviderHost,
    SemanticLayer,
    TransportDescriptor,
)
from rolo.mhs_sensor import MhsSensorProvider, SensorChannel, SensorManifest


@dataclass
class FakeSensor:
    values: dict[str, float | bool]
    reset_calls: list[str]

    def read(self) -> dict[str, float | bool]:
        return dict(self.values)

    def status(self) -> dict[str, str]:
        return {"health": "OK", "connection": "ready"}

    def reset(self, profile_id: str) -> dict[str, str]:
        self.reset_calls.append(profile_id)
        return {"change_id": "change-1", "profile_id": profile_id}


def _provider(
    values: dict[str, float | bool] | None = None,
) -> tuple[MhsSensorProvider, FakeSensor]:
    backend = FakeSensor(values or {"temperature": 23.5, "door_open": False}, [])
    manifest = SensorManifest(
        device_id="cabinet-1",
        name="Cabinet environmental sensor",
        vendor="Example",
        model="ENV-1",
        modality="environmental",
        channels=[
            SensorChannel(
                id="temperature",
                name="Temperature",
                unit="degC",
                min_value=-20,
                max_value=80,
            ),
            SensorChannel(
                id="door_open",
                name="Door open",
                unit="bool",
                value_type="boolean",
            ),
        ],
        transport=TransportDescriptor(kind="python", properties={"backend": "fake"}),
        safety_limits=["read-only measurements", "reject values outside channel bounds"],
    )
    return MhsSensorProvider(manifest, backend), backend


def test_mhs_sensor_registers_and_reads_through_provider_host() -> None:
    provider, _ = _provider()
    with ProviderHost() as host:
        registration = host.register(provider)
        assert registration.status == "REGISTERED"
        assert registration.capability_count == 4
        result = host.invoke(
            provider.provider_id,
            InvokeRequest(
                capability_id="sensor.read",
                route_ref="mhs://sensor/cabinet-1/read",
            ),
        )
    assert result.status == "AVAILABLE"
    assert result.value["device_id"] == "cabinet-1"
    assert result.value["samples"][0]["channel"] == "door_open"


def test_mhs_sensor_rejects_undeclared_or_unsafe_values() -> None:
    provider, _ = _provider({"temperature": 120.0})
    result = provider.invoke(
        InvokeRequest(
            capability_id="sensor.read",
            route_ref="mhs://sensor/cabinet-1/read",
        )
    )
    assert result.status == "UNAVAILABLE"
    assert "safety limit" in (result.reason or "")

    provider, _ = _provider({"pressure": 1.0})
    result = provider.invoke(
        InvokeRequest(
            capability_id="sensor.read",
            route_ref="mhs://sensor/cabinet-1/read",
        )
    )
    assert result.status == "UNAVAILABLE"
    assert "undeclared" in (result.reason or "")


def test_mhs_sensor_reset_is_write_gated_by_provider_host() -> None:
    provider, backend = _provider()
    with ProviderHost() as host:
        host.register(provider)
        denied = host.invoke(
            provider.provider_id,
            InvokeRequest(
                capability_id="sensor.reset",
                route_ref="mhs://sensor/cabinet-1/reset",
                arguments={"profile_id": "soft"},
            ),
        )
        assert denied.status == "UNAVAILABLE"
        assert backend.reset_calls == []

        class Allow:
            def authorize(self, manifest, descriptor, request) -> None:
                assert descriptor.semantic_layer == SemanticLayer.HARDWARE

        allowed = host.invoke(
            provider.provider_id,
            InvokeRequest(
                capability_id="sensor.reset",
                route_ref="mhs://sensor/cabinet-1/reset",
                arguments={"profile_id": "soft"},
            ),
            authorizer=Allow(),
        )
    assert allowed.status == "AVAILABLE"
    assert backend.reset_calls == ["soft"]
