from __future__ import annotations

import json
import importlib.util
from pathlib import Path

from rolo.mhs_hardware import MhsStatus

_MODULE_PATH = Path(__file__).parents[1] / "examples" / "mhs-landerpi" / "mhs_landerpi.py"
_SPEC = importlib.util.spec_from_file_location("mhs_landerpi", _MODULE_PATH)
assert _SPEC and _SPEC.loader
_MODULE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MODULE)
DRIVER_SHA256 = _MODULE.DRIVER_SHA256
LanderPiBackend = _MODULE.LanderPiBackend
build_manifest = _MODULE.build_manifest


def _fake_root(tmp_path: Path) -> Path:
    (tmp_path / "sys/class/thermal/thermal_zone0").mkdir(parents=True)
    (tmp_path / "sys/class/thermal/thermal_zone0/temp").write_text("65000\n")
    (tmp_path / "proc").mkdir()
    (tmp_path / "proc/meminfo").write_text("MemTotal:       1000 kB\nMemAvailable:    250 kB\n")
    (tmp_path / "proc/loadavg").write_text("1.25 0.80 0.50 1/100 42\n")
    (tmp_path / "proc/device-tree").mkdir()
    (tmp_path / "proc/device-tree/model").write_text("Raspberry Pi 5 Model B Rev 1.0\x00")
    (tmp_path / "proc/device-tree/serial-number").write_text("pi-test-001\x00")
    (tmp_path / "proc/uptime").write_text("123.4 456.7\n")
    (tmp_path / "proc/version").write_text("Linux version 6.6-test")
    (tmp_path / "dev").mkdir()
    for node in ("i2c-1", "spidev10.0", "gpiochip0"):
        (tmp_path / "dev" / node).touch()
    (tmp_path / "sys/bus/usb").mkdir(parents=True)
    return tmp_path


def test_landerpi_backend_reads_bounded_fake_procfs(tmp_path: Path) -> None:
    backend = LanderPiBackend(_fake_root(tmp_path))
    assert backend.read() == {
        "cpu_temperature": 65.0,
        "memory_used_percent": 75.0,
        "load_1m": 1.25,
    }
    status = backend.status()
    assert status["model"] == "Raspberry Pi 5 Model B Rev 1.0"
    assert status["transports"] == {"i2c": True, "spi": True, "gpio": True, "usb": True}


def test_landerpi_manifest_is_stable_and_read_only(tmp_path: Path) -> None:
    manifest = build_manifest(LanderPiBackend(_fake_root(tmp_path)))
    assert manifest.device_id == "landerpi"
    assert manifest.driver_sha256 == DRIVER_SHA256
    assert "read-only" in manifest.limits


def test_real_shape_canary_is_accepted_by_provider(tmp_path: Path) -> None:
    from rolo.mhs_hardware import MhsDeviceProvider

    backend = LanderPiBackend(_fake_root(tmp_path))
    provider = MhsDeviceProvider(build_manifest(backend), backend)
    read = provider.invoke("read")
    assert read.status == MhsStatus.AVAILABLE
    assert json.loads(read.model_dump_json())["route"] == "mhs://landerpi/read"
    assert provider.invoke("setpoint", {"value": 1}).status == MhsStatus.UNAVAILABLE


def test_recorded_real_canary_is_non_secret_and_bounded() -> None:
    fixture = json.loads(
        (_MODULE_PATH.parent / "canary-20260902.json").read_text(encoding="utf-8")
    )
    assert fixture["device_id"] == "landerpi"
    assert fixture["driver"]["sha256"] == DRIVER_SHA256
    assert -40 <= fixture["read"]["cpu_temperature"] <= 125
    assert 0 <= fixture["read"]["memory_used_percent"] <= 100
    assert fixture["status"]["read_only"] is True
    assert "password" not in json.dumps(fixture).lower()
