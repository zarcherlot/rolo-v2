from pathlib import Path

from rolo.mhs_hardware import MhsDeviceProvider, MhsStatus
from rolo.mhs_linux import LinuxHardwareBackend, LinuxMhsInventory, build_linux_manifest


def _root(tmp_path: Path) -> Path:
    (tmp_path / "sys/class/thermal/thermal_zone0").mkdir(parents=True)
    (tmp_path / "sys/class/thermal/thermal_zone0/temp").write_text("65000\n")
    (tmp_path / "proc/device-tree").mkdir(parents=True)
    (tmp_path / "proc/device-tree/model").write_text("Generic Linux host\x00")
    (tmp_path / "proc/meminfo").write_text("MemTotal: 1000 kB\nMemAvailable: 250 kB\n")
    (tmp_path / "proc/loadavg").write_text("1.25 0.8 0.5 1/100 42\n")
    (tmp_path / "proc/uptime").write_text("123.4 1.0\n")
    (tmp_path / "proc/version").write_text("Linux version 6.6-test")
    (tmp_path / "dev").mkdir()
    (tmp_path / "sys/bus/usb").mkdir(parents=True)
    return tmp_path


def test_linux_backend_is_read_only_and_target_neutral(tmp_path: Path):
    backend = LinuxHardwareBackend(_root(tmp_path))
    assert backend.read() == {"cpu_temperature": 65.0, "memory_used_percent": 75.0, "load_1m": 1.25}
    assert backend.status()["read_only"] is True


def test_linux_inventory_candidates_remain_unverified(tmp_path: Path):
    candidates = LinuxMhsInventory(_root(tmp_path), device_prefix="target").candidates()
    assert candidates[0].discovery_status == "DISCOVERED_UNVERIFIED"
    assert candidates[0].manifest.commands == []


def test_linux_backend_flows_through_mhs_provider(tmp_path: Path):
    root = _root(tmp_path)
    manifest = build_linux_manifest(
        device_id="target-1", name="host", vendor="unknown", model="linux"
    )
    result = MhsDeviceProvider(manifest, LinuxHardwareBackend(root)).read()
    assert result.status == MhsStatus.AVAILABLE
    assert result.route == "mhs://target-1/read"
