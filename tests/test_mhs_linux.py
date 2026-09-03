from __future__ import annotations

from pathlib import Path

from rolo.mhs_hardware import MhsDeviceProvider, MhsStatus
from rolo.mhs_linux import LinuxHardwareBackend, build_linux_manifest


def _fake_root(tmp_path: Path) -> Path:
    (tmp_path / "sys/class/thermal/thermal_zone0").mkdir(parents=True)
    (tmp_path / "sys/class/thermal/thermal_zone0/temp").write_text("65000\n")
    (tmp_path / "proc/device-tree").mkdir(parents=True)
    (tmp_path / "proc/device-tree/model").write_text("Generic Linux host\x00")
    (tmp_path / "proc/device-tree/serial-number").write_text("generic-001\x00")
    (tmp_path / "proc").mkdir(exist_ok=True)
    (tmp_path / "proc/meminfo").write_text("MemTotal: 1000 kB\nMemAvailable: 250 kB\n")
    (tmp_path / "proc/loadavg").write_text("1.25 0.8 0.5 1/100 42\n")
    (tmp_path / "proc/uptime").write_text("123.4 1.0\n")
    (tmp_path / "proc/version").write_text("Linux version 6.6-test")
    (tmp_path / "dev").mkdir()
    for node in ("i2c-1", "spidev0.0", "gpiochip0"):
        (tmp_path / "dev" / node).touch()
    (tmp_path / "sys/bus/usb").mkdir(parents=True)
    return tmp_path


def test_linux_backend_is_target_neutral(tmp_path: Path) -> None:
    backend = LinuxHardwareBackend(_fake_root(tmp_path))
    assert backend.read() == {
        "cpu_temperature": 65.0,
        "memory_used_percent": 75.0,
        "load_1m": 1.25,
    }
    assert backend.status()["model"] == "Generic Linux host"


def test_linux_manifest_identity_is_supplied_by_caller(tmp_path: Path) -> None:
    manifest = build_linux_manifest(
        device_id="target-001",
        name="Generic Linux target",
        vendor="unknown",
        model="Generic Linux host",
        serial="generic-001",
        transport_target="target-001",
    )
    assert manifest.device_id == "target-001"
    assert manifest.serial == "generic-001"
    assert manifest.driver_id == "rolo.mhs.linux-observer"
    assert manifest.commands == []


def test_linux_backend_flows_through_read_only_mhs_provider(tmp_path: Path) -> None:
    backend = LinuxHardwareBackend(_fake_root(tmp_path))
    manifest = build_linux_manifest(
        device_id="target-001", name="Generic Linux target", vendor="unknown", model="Generic Linux host"
    )
    provider = MhsDeviceProvider(manifest, backend)
    result = provider.invoke("read")
    assert result.status == MhsStatus.AVAILABLE
    assert result.route == "mhs://target-001/read"
    assert provider.invoke("reset").status == MhsStatus.UNAVAILABLE
