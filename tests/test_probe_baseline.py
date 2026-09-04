from __future__ import annotations

from pathlib import Path

import pytest

from rolo.probe_baseline import (
    BaselineArtifactIndex,
    BaselineStatus,
    CompletionDecision,
    ProbeBaselineManifest,
    ReadOnlyCompletion,
    audit_read_only,
    build_artifact_index,
    build_manifest,
    validate_baseline,
)

ROOT = Path(__file__).resolve().parents[1]


def test_manifest_is_digest_bound_and_read_only() -> None:
    manifest = build_manifest(ROOT)
    assert manifest.access == "READ_ONLY"
    assert manifest.digest == manifest.computed_digest()
    assert manifest.feature_flags["write"] is False
    ProbeBaselineManifest.model_validate(manifest.model_dump(mode="json"))


def test_artifact_index_detects_file_drift(tmp_path: Path) -> None:
    source = tmp_path / "fixture.json"
    source.write_text('{"value": 1}\n', encoding="utf-8")
    manifest = build_manifest(ROOT)
    index = build_artifact_index(tmp_path, manifest, [source])
    assert index.digest == index.computed_digest()
    source.write_text('{"value": 2}\n', encoding="utf-8")
    errors = validate_baseline(tmp_path, manifest, index)
    assert any("artifact digest drift" in item for item in errors)


def test_w0_audit_requires_all_six_gates() -> None:
    manifest = build_manifest(ROOT)
    index = BaselineArtifactIndex(
        baseline_id=manifest.baseline_id,
        generated_at=manifest.generated_at,
        artifacts=[],
    ).with_digest()
    completion = audit_read_only(manifest, index)
    assert completion.decision == CompletionDecision.READ_ONLY_BLOCKED
    complete = audit_read_only(
        manifest,
        index,
        gate_status={key: BaselineStatus.PASS for key in "ABCDEF"},
    )
    assert complete.decision == CompletionDecision.READ_ONLY_COMPLETE
    blocked = audit_read_only(manifest, index, gate_status={"A": BaselineStatus.BLOCKED})
    assert blocked.decision == CompletionDecision.READ_ONLY_BLOCKED
    with pytest.raises(ValueError):
        ReadOnlyCompletion.model_validate(
            {
                **complete.model_dump(mode="json"),
                "decision": "READ_ONLY_COMPLETE",
                "gates": {
                    **complete.model_dump(mode="json")["gates"],
                    "A": {"gate_id": "A", "status": "BLOCKED", "owner": "x"},
                },
            }
        )
