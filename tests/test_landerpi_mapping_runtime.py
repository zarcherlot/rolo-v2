from __future__ import annotations

import importlib.util
import json
import sys
from argparse import Namespace
from pathlib import Path

import pytest


def _runtime_module():
    path = Path(__file__).parents[1] / "scripts" / "landerpi_autonomous_mapping_runtime.py"
    spec = importlib.util.spec_from_file_location("rolo_mapping_runtime_test", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _legacy_trace_module():
    path = Path(__file__).parents[1] / "scripts" / "targetd_mapping_trace.py"
    spec = importlib.util.spec_from_file_location("rolo_legacy_mapping_trace_test", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_sector_stats_reports_robust_percentile_and_beam_count():
    runtime = _runtime_module()
    stats = runtime._sector_stats([0.31, 0.45, 0.46, 0.47, 0.48, 0.49], 12.0)
    assert stats == {"min_m": 0.31, "p10_m": 0.31, "beam_count": 6}
    broad = runtime._sector_stats([0.42] * 20, 12.0)
    assert broad["p10_m"] == 0.42
    assert broad["beam_count"] == 20


def test_runtime_lock_is_single_instance(tmp_path):
    runtime = _runtime_module()
    lock = tmp_path / "mapping.lock"
    original = runtime._runtime_lock_path
    runtime._runtime_lock_path = lambda: lock
    try:
        first = runtime._acquire_runtime_lock()
        assert first is not None
        assert runtime._acquire_runtime_lock() is None
        runtime._release_runtime_lock(first)
        assert not lock.exists()
    finally:
        runtime._runtime_lock_path = original


def test_stop_immediate_returns_fresh_stop_elapsed_and_prior_state(tmp_path, monkeypatch):
    runtime = _runtime_module()
    status_file = tmp_path / "status.json"
    stop_marker = tmp_path / "stop"
    status_file.write_text(
        json.dumps({"status": "SUCCEEDED", "mode": "run", "elapsed_s": 18.5, "motion_started": True}),
        encoding="utf-8",
    )
    args = Namespace(
        stop_marker=str(stop_marker),
        status_file=str(status_file),
        cmd_topic="/controller/cmd_vel",
    )

    class Completed:
        returncode = 0
        stderr = ""

    monkeypatch.setattr(runtime, "_terminate_existing_runtime", lambda: True)
    monkeypatch.setattr(runtime.subprocess, "run", lambda *a, **k: Completed())
    result = runtime._stop_immediate(args)
    assert result["status"] == "STOPPED"
    assert result["mode"] == "stop"
    assert result["motion_started"] is False
    assert result["prior_motion_started"] is True
    assert result["prior_elapsed_s"] == 18.5
    assert result["terminated_existing_runtime"] is True
    assert result["stop_elapsed_s"] >= 0
    persisted = json.loads(status_file.read_text(encoding="utf-8"))
    assert persisted["stop_reason"] == "EXPLICIT_STOP"


@pytest.mark.parametrize(
    "legacy_flags",
    [
        ("--status-only", "--safety-confirmed"),
        ("--safety-confirmed", "--autonomous-source-confirmed"),
    ],
)
def test_legacy_mapping_trace_blocks_before_installer_executor_or_artifacts(
    tmp_path,
    monkeypatch,
    legacy_flags,
):
    artifact_root = tmp_path / "artifacts"
    touched: list[str] = []

    def forbidden(*_args, **_kwargs):
        touched.append("side-effect")
        raise AssertionError("legacy mapping trace crossed a side-effect boundary")

    # The disabled entry point no longer imports either execution dependency.
    # Patching their constructors protects the assertion if one is reintroduced.
    import rolo.targetd.installer as installer_module
    import rolo.targets.executor as executor_module

    monkeypatch.setattr(installer_module, "TargetdInstaller", forbidden)
    monkeypatch.setattr(executor_module, "SshTargetExecutor", forbidden)
    trace = _legacy_trace_module()
    monkeypatch.setattr(Path, "mkdir", forbidden)
    monkeypatch.setattr(Path, "write_text", forbidden)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "targetd_mapping_trace.py",
            "--target",
            "ssh://pi@192.0.2.8/home/pi",
            "--known-hosts",
            str(tmp_path / "known_hosts"),
            "--artifact-root",
            str(artifact_root),
            *legacy_flags,
        ],
    )

    with pytest.raises(SystemExit) as raised:
        trace.main()

    diagnostic = json.loads(str(raised.value))
    assert diagnostic == trace.legacy_mapping_trace_diagnostic()
    assert diagnostic["code"] == "LEGACY_MAPPING_TRACE_DISABLED"
    assert diagnostic["boundary"] == "before-target-or-artifact-side-effects"
    assert touched == []
    assert not artifact_root.exists()
