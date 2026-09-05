from pathlib import Path

from rolo.mvp.artifacts import ArtifactIndex, build_artifact_index, rollback_artifact_index, write_artifact_index


def test_signed_artifact_index_verifies_and_detects_tampering(tmp_path: Path) -> None:
    report = tmp_path / "report.json"
    report.write_text('{"status":"PASS"}\n', encoding="utf-8")
    index = build_artifact_index(
        run_id="run-1", target_id="mentorpi", files=[report], root=tmp_path, secret=b"s" * 32
    )
    index.verify(b"s" * 32)
    tampered = index.model_copy(update={"artifacts": [{"path": "report.json", "sha256": "0" * 64}]})
    try:
        tampered.verify(b"s" * 32)
    except ValueError:
        pass
    else:
        raise AssertionError("tampered artifact index was accepted")


def test_artifact_pointer_rolls_back_atomically(tmp_path: Path) -> None:
    previous = tmp_path / "previous.json"
    previous.write_text("{}\n", encoding="utf-8")
    active = tmp_path / "artifact-index.json"
    write_artifact_index(
        active,
        ArtifactIndex(
            run_id="run-2",
            target_id="mentorpi",
            artifacts=[{"path": "report.json", "sha256": "0" * 64}],
            manifest_sha256="0" * 64,
        ),
    )
    rollback_artifact_index(active, str(previous))
    assert '"active_index"' in active.read_text(encoding="utf-8")
