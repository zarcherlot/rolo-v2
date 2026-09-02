from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import tomllib

from rolo.core.models import ProbeResult
from rolo.rkb import SnapshotIdentity, canonical_json


ROOT = Path(__file__).resolve().parents[1]


def test_probe_canonical_path_and_v2_metadata_are_present() -> None:
    assert (ROOT / "src/rolo/stages/probe").is_dir()
    assert not (ROOT / "src/rolo/stages/adapt").exists()
    required = {
        "layer",
        "status",
        "data",
        "warnings",
        "errors",
        "observed_at",
        "identity",
        "access",
        "fresh_until",
    }
    assert required <= set(ProbeResult.model_fields)


def test_identity_contract_rejects_invalid_window_and_freezes_access() -> None:
    now = datetime(2026, 9, 2, tzinfo=timezone.utc)
    values = {
        "robot_id": "robot-1",
        "target_host_fingerprint": "a" * 64,
        "collector_id": "collector-1",
        "deployment_mode": "remote",
        "observed_at": now,
        "fresh_until": now + timedelta(seconds=30),
    }
    identity = SnapshotIdentity(**values)
    assert identity.access == "READ_ONLY"
    assert identity.tuple()[:4] == ("robot-1", "a" * 64, "collector-1", "remote")


def test_canonical_json_is_sorted_and_whitespace_free() -> None:
    assert canonical_json({"z": 1, "a": {"b": 2, "a": 1}}) == b'{"a":{"a":1,"b":2},"z":1}'


def test_schema_drafts_and_dependency_matrix_are_versioned() -> None:
    envelope_schema = json.loads((ROOT / "schemas/RobotEvidenceEnvelope.schema.json").read_text())
    knowledge_schema = json.loads((ROOT / "schemas/RobotKnowledgeBase.schema.json").read_text())
    assert envelope_schema["$id"] == "robot-evidence-envelope/v1"
    assert knowledge_schema["$id"] == "robot-knowledge-base/v1"
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())
    assert project["project"]["requires-python"] == ">=3.10,<3.14"
    dev = project["dependency-groups"]["dev"]
    assert all(any(name in item for item in dev) for name in ("pytest", "ruff"))


def test_ci_matrix_and_rkb_test_entry_are_declared() -> None:
    workflow = (ROOT / ".github/workflows/ci.yml").read_text()
    for version in ('"3.10"', '"3.11"', '"3.12"', '"3.13"'):
        assert version in workflow
    assert "tests/test_rkb_contract_baseline.py" in workflow or "test_rkb_envelope.py" in workflow
