from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from rolo.observability import ArtifactRetentionPolicy, ObservabilityRecorder, redact


def test_recorder_redacts_and_rotates(tmp_path: Path) -> None:
    path = tmp_path / "metrics.jsonl"
    recorder = ObservabilityRecorder(path, max_bytes=1024)
    metric = recorder.record(
        event="journey.completed",
        stage="post-compiler-journey",
        status="PASS",
        payload={"password": "hidden", "nested": {"token": "also-hidden"}, "ok": 1},
    )
    assert metric.payload == {"password": "[REDACTED]", "nested": {"token": "[REDACTED]"}, "ok": 1}
    assert json.loads(path.read_text(encoding="utf-8"))["payload"]["password"] == "[REDACTED]"
    for _ in range(8):
        recorder.record(event="x", stage="s", status="PASS", payload={"value": "x" * 300})
    assert path.exists()
    assert path.with_name("metrics.jsonl.1").exists()


def test_retention_plans_and_prunes_only_files(tmp_path: Path) -> None:
    old = tmp_path / "old.json"
    recent = tmp_path / "recent.json"
    old.write_text("old", encoding="utf-8")
    recent.write_text("recent", encoding="utf-8")
    old_time = (datetime.now(timezone.utc) - timedelta(days=5)).timestamp()
    os.utime(old, (old_time, old_time))
    policy = ArtifactRetentionPolicy(max_files=10, max_age_days=1)
    assert policy.plan_prune(tmp_path) == (old,)
    assert policy.prune(tmp_path) == (old,)
    assert recent.exists()


def test_retention_rejects_too_small_metric_file() -> None:
    with pytest.raises(ValueError, match="max_bytes"):
        ObservabilityRecorder(Path("metrics.jsonl"), max_bytes=10)


def test_redact_truncates_deep_values() -> None:
    value: object = {"a": {"b": {"c": {"d": {"e": {"f": {"g": {"h": 1}}}}}}}}
    assert redact(value)["a"]["b"]["c"]["d"]["e"]["f"]["g"]["h"] == "[TRUNCATED]"
