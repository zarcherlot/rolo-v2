from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from scripts.mvp_release_gate import ReleaseGateError, run_release_gate, validate_artifact_index


def test_offline_release_gate_replays_ten_cases(tmp_path: Path) -> None:
    result = run_release_gate(Path("examples/mapping-10.json"), tmp_path)
    assert result["status"] == "PASS"
    assert result["artifact_index"] == "rolo-mvp-artifact-index/v1"
    assert result["trace"] == {"success": "COMPLETED", "recovery": "COMPLETED"}
    assert len(json.loads((tmp_path / "certify-test-report.json").read_text(encoding="utf-8")).get("results", [])) == 10


def test_artifact_index_rejects_digest_drift(tmp_path: Path) -> None:
    artifact = tmp_path / "report.json"
    artifact.write_text("{}\n", encoding="utf-8")
    index = tmp_path / "artifact-index.json"
    index.write_text(
        json.dumps(
            {
                "schema_version": "rolo-mvp-artifact-index/v1",
                "run_id": "r1",
                "target_id": "mentorpi",
                "artifacts": [{"path": artifact.name, "sha256": "0" * 64}],
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ReleaseGateError, match="digest mismatch"):
        validate_artifact_index(index)


def test_artifact_index_rejects_path_escape(tmp_path: Path) -> None:
    index = tmp_path / "artifact-index.json"
    index.write_text(
        json.dumps(
            {
                "schema_version": "rolo-mvp-artifact-index/v1",
                "run_id": "r1",
                "target_id": "mentorpi",
                "artifacts": [{"path": "../outside", "sha256": hashlib.sha256(b"x").hexdigest()}],
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ReleaseGateError, match="escapes"):
        validate_artifact_index(index)
