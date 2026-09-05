from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from rolo.mhs_hardware import (
    MhsChannel,
    MhsDeviceClass,
    MhsDeviceManifest,
    MhsDeviceProvider,
    MhsDriver,
    MhsProviderRegistry,
    MhsSourceKind,
    MhsStatus,
    mhs_results_to_snapshot,
)
from rolo.rkb import ReadOnlyKnowledgeBase
from rolo.rkb.models import SnapshotIdentity
from rolo.rkb.storage import RKBStore
from scripts.mhs_rkb_canary import run_canary


@dataclass
class Backend:
    values: dict
    status_value: dict | None = None

    def read(self):
        return dict(self.values)

    def status(self):
        if self.status_value is None:
            return {"health": "OK"}
        return dict(self.status_value)


def provider(values=None) -> MhsDeviceProvider:
    manifest = MhsDeviceManifest(
        device_id="sensor-1",
        device_class=MhsDeviceClass.SENSOR,
        name="temperature",
        vendor="example",
        model="t-1",
        driver=MhsDriver(provider_id="driver.example", version="1.2.3", sha256="a" * 64),
        channels=[
            MhsChannel(
                id="temperature", name="Temperature", unit="degC", min_value=-20, max_value=80
            )
        ],
        transport={"kind": "fake"},
    )
    return MhsDeviceProvider(
        manifest,
        Backend(values or {"temperature": 22.0}),
        target_host_fingerprint="b" * 64,
        freshness={"read": timedelta(seconds=2)},
    )


def test_results_are_provenance_bound_and_legacy_route_is_input_only():
    instance = provider()
    result = instance.invoke("read", route_ref="mhs://sensor/sensor-1/read")
    assert result.status == MhsStatus.AVAILABLE
    assert result.route == "mhs://sensor-1/read"
    assert result.source_kind == MhsSourceKind.OBSERVED
    assert result.target_host_fingerprint == "b" * 64
    assert result.manifest_sha256 == instance.manifest.manifest_sha256
    assert result.driver_sha256 == "a" * 64
    assert result.fresh_until > result.observed_at


@pytest.mark.parametrize("value", [float("nan"), float("inf"), -float("inf"), 100.0, "hot"])
def test_read_rejects_invalid_measurements(value):
    assert provider({"temperature": value}).read().status == MhsStatus.UNAVAILABLE


def test_manifest_and_driver_drift_fail_closed():
    instance = provider()
    instance.manifest.channels[0].max_value = 90
    assert "manifest digest changed" in (instance.read().reason or "")

    instance = provider()
    instance.manifest.driver = MhsDriver(
        provider_id="driver.example", version="9.9.9", sha256="c" * 64
    )
    assert "driver digest" in (instance.status().reason or "")


def test_registry_rejects_duplicate_device_ids():
    registry = MhsProviderRegistry()
    registry.register(provider())
    with pytest.raises(ValueError, match="duplicate MHS device id"):
        registry.register(provider())


def test_write_like_capabilities_are_not_exposed_or_invokable():
    instance = provider()
    assert {item["capability_id"] for item in instance.capabilities()} == {
        "inspect",
        "status",
        "read",
    }
    result = instance.invoke("reset", route_ref="mhs://sensor/sensor-1/reset")
    assert result.status == MhsStatus.UNAVAILABLE
    assert "write" in (result.reason or "")


def test_backend_timeout_is_bounded():
    class HangingBackend(Backend):
        def read(self):
            import time

            time.sleep(0.2)
            return super().read()

    instance = MhsDeviceProvider(
        provider().manifest,
        HangingBackend({"temperature": 1}),
        timeout_s=0.01,
    )
    result = instance.read()
    assert result.status == MhsStatus.UNAVAILABLE
    assert "timed out" in (result.reason or "")


def test_mhs_results_project_to_target_bound_rkb_snapshot():
    instance = provider()
    identity = SnapshotIdentity(
        robot_id="robot-1",
        target_host_fingerprint="b" * 64,
        source_id="source-1",
        deployment_mode="remote",
        observed_at=datetime.now(timezone.utc),
        fresh_until=datetime.now(timezone.utc) + timedelta(minutes=1),
    )
    snapshot = mhs_results_to_snapshot(identity, [instance.inspect(), instance.read()])
    assert snapshot.digest == snapshot.computed_digest()
    assert {fact.source_kind.value for fact in snapshot.facts} == {"DECLARED", "OBSERVED"}
    assert all(fact.target_host_fingerprint == "b" * 64 for fact in snapshot.facts)


def test_canary_publishes_latest_only_after_all_reads_pass(tmp_path: Path):
    instance = provider()
    first = run_canary(instance, tmp_path)
    assert first["passed"] is True
    latest_before = (tmp_path / "latest.json").read_text(encoding="utf-8")

    failing = provider({"temperature": 999})
    second = run_canary(failing, tmp_path)
    assert second["passed"] is False
    assert (tmp_path / "latest.json").read_text(encoding="utf-8") == latest_before


def test_canary_publishes_verified_rkb_snapshot(tmp_path: Path):
    instance = provider()
    now = datetime.now(timezone.utc)
    identity = SnapshotIdentity(
        robot_id="robot-1",
        target_host_fingerprint="b" * 64,
        source_id="source-1",
        deployment_mode="remote",
        observed_at=now,
        fresh_until=now + timedelta(minutes=5),
    )
    artifact = run_canary(
        instance, tmp_path / "mhs", identity=identity, store=RKBStore(tmp_path / "rkb")
    )
    assert artifact["passed"] is True
    assert artifact["snapshot_digest"]
    assert (tmp_path / "rkb" / "latest.json").exists()


def test_mhs_snapshot_is_visible_to_hardware_and_capability_queries():
    instance = provider()
    now = datetime.now(timezone.utc)
    identity = SnapshotIdentity(
        robot_id="robot-1",
        target_host_fingerprint="b" * 64,
        source_id="source-1",
        deployment_mode="remote",
        observed_at=now,
        fresh_until=now + timedelta(minutes=5),
    )
    snapshot = mhs_results_to_snapshot(identity, [instance.inspect(), instance.read()])
    kb = ReadOnlyKnowledgeBase([snapshot])
    query_now = datetime.now(timezone.utc)
    hardware = kb.hw.inventory_scan(now=query_now)
    assert hardware.value and hardware.value.resources
    capability = kb.capability.get("mhs.sensor-1.read", now=query_now)
    assert capability.status.value == "ELIGIBLE"
