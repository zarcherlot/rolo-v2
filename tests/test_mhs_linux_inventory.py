from __future__ import annotations

from pathlib import Path

from rolo.mhs_hardware import MhsStatus
from rolo.mhs_linux import LinuxMhsInventory


def _root(tmp_path: Path) -> Path:
    (tmp_path / "sys/class/thermal/thermal_zone0").mkdir(parents=True)
    (tmp_path / "sys/class/thermal/thermal_zone0/temp").write_text("65000\n")
    (tmp_path / "sys/class/thermal/thermal_zone0/type").write_text("cpu-thermal\n")
    (tmp_path / "proc/device-tree").mkdir(parents=True)
    (tmp_path / "proc/device-tree/model").write_text("Generic host\x00")
    (tmp_path / "proc/device-tree/serial-number").write_text("serial-1\x00")
    (tmp_path / "proc").mkdir(exist_ok=True)
    (tmp_path / "proc/meminfo").write_text("MemTotal: 1000 kB\nMemAvailable: 250 kB\n")
    (tmp_path / "proc/loadavg").write_text("1.0 0.8 0.5 1/10 1\n")
    (tmp_path / "proc/uptime").write_text("10.0 1.0\n")
    (tmp_path / "proc/version").write_text("Linux version test")
    (tmp_path / "dev").mkdir()
    for node in ("i2c-1", "spidev0.0", "gpiochip0"):
        (tmp_path / "dev" / node).touch()
    return tmp_path


def test_inventory_creates_unverified_candidates_and_read_only_providers(tmp_path: Path) -> None:
    inventory = LinuxMhsInventory(_root(tmp_path), device_prefix="target")
    candidates = inventory.candidates()
    assert len(candidates) == 5  # compute + thermal + three device nodes
    assert {candidate.discovery_status for candidate in candidates} == {"DISCOVERED_UNVERIFIED"}
    providers = inventory.providers()
    thermal = next(provider for candidate, provider in providers if "thermal_zone0" in candidate.source)
    assert thermal.read().status == MhsStatus.AVAILABLE
    assert thermal.invoke("reset").status == MhsStatus.UNAVAILABLE
