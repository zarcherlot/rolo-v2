from __future__ import annotations

import json
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi.testclient import TestClient

from rolo.api import app
from rolo.core.config import get_settings
from rolo.stages.artifact_paths import ArtifactLayout
from rolo.stages.diagnose.episode import (
    DiagnosisEpisode,
    EpisodeObservation,
    EpisodePhase,
    TargetProvenance,
    publish_episode,
)

FIXTURE = Path("tests/fixtures/episodes/demo_diff/published/ep-nav-001.json")


def _publish_fixture(artifact_root: Path) -> None:
    target = ArtifactLayout(artifact_root).episode_publication("demo_diff", "ep-nav-001")
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(FIXTURE, target)


def _publish_cohort_member(artifact_root: Path, episode_id: str) -> None:
    payload = json.loads(FIXTURE.read_text(encoding="utf-8"))
    started_at = datetime(2026, 8, 22, 3, tzinfo=timezone.utc)
    payload["detail"]["episode_id"] = episode_id
    payload["detail"]["started_at"] = started_at.isoformat().replace("+00:00", "Z")
    payload["detail"]["ended_at"] = (
        (started_at + timedelta(seconds=4)).isoformat().replace("+00:00", "Z")
    )
    for event in payload["timeline"]:
        event["episode_id"] = episode_id
        event["occurred_at"] = (
            (started_at + timedelta(milliseconds=event["offset_ms"]))
            .isoformat()
            .replace("+00:00", "Z")
        )
    target = ArtifactLayout(artifact_root).episode_publication("demo_diff", episode_id)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload), encoding="utf-8")


def test_episode_api_exposes_empty_collection_without_demo_fallback(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("ROLO_ARTIFACT_DIR", str(tmp_path / "artifacts"))
    monkeypatch.setenv("ROLO_OUTPUT_DIR", str(tmp_path / "output"))
    get_settings.cache_clear()

    with TestClient(app) as client:
        response = client.get("/v1/robots/demo_diff/episodes")

    assert response.status_code == 200
    assert response.json()["schema_version"] == "rolo-episode-collection/v1"
    assert response.json()["items"] == []
    assert response.json()["total"] == 0


def test_episode_api_reads_completed_projection_and_pins_timeline_revision(
    tmp_path: Path,
    monkeypatch,
) -> None:
    artifact_root = tmp_path / "artifacts"
    _publish_fixture(artifact_root)
    monkeypatch.setenv("ROLO_ARTIFACT_DIR", str(artifact_root))
    monkeypatch.setenv("ROLO_OUTPUT_DIR", str(tmp_path / "output"))
    get_settings.cache_clear()

    with TestClient(app) as client:
        collection = client.get(
            "/v1/robots/demo_diff/episodes",
            params={"state": "COMPLETED", "limit": 10},
        )
        detail = client.get("/v1/robots/demo_diff/episodes/ep-nav-001")
        pinned_detail = client.get(
            "/v1/robots/demo_diff/episodes/ep-nav-001",
            params={"revision": 1},
        )
        revisions = client.get(
            "/v1/robots/demo_diff/episodes/ep-nav-001/revisions",
        )
        first = client.get(
            "/v1/robots/demo_diff/episodes/ep-nav-001/timeline",
            params={"revision": 1, "limit": 1},
        )
        stale = client.get(
            "/v1/robots/demo_diff/episodes/ep-nav-001/timeline",
            params={"revision": 2},
        )
        stale_detail = client.get(
            "/v1/robots/demo_diff/episodes/ep-nav-001",
            params={"revision": 2},
        )
        invalid_cursor = client.get(
            "/v1/robots/demo_diff/episodes/ep-nav-001/timeline",
            params={"revision": 1, "cursor": "epcur_invalid"},
        )

    assert collection.status_code == 200
    assert collection.json()["total"] == 1
    assert detail.status_code == 200
    assert detail.json()["immutable"] is True
    assert pinned_detail.status_code == 200
    assert pinned_detail.json()["revision"] == 1
    assert revisions.status_code == 200
    assert revisions.json()["current_revision"] == 1
    assert revisions.json()["items"][0]["source_kind"] == "published_episode_projection"
    assert first.status_code == 200
    assert first.json()["items"][0]["event_id"] == "evt-command"
    assert first.json()["next_cursor"].startswith("epcur_")
    assert stale.status_code == 409
    assert stale_detail.status_code == 409
    assert invalid_cursor.status_code == 422


def test_episode_api_rejects_unknown_robot_invalid_window_and_unknown_episode(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("ROLO_ARTIFACT_DIR", str(tmp_path / "artifacts"))
    get_settings.cache_clear()

    with TestClient(app) as client:
        robot = client.get("/v1/robots/not-a-robot/episodes")
        window = client.get(
            "/v1/robots/demo_diff/episodes",
            params={
                "since": "2026-08-24T00:00:00Z",
                "until": "2026-08-23T00:00:00Z",
            },
        )
        timezone_missing = client.get(
            "/v1/robots/demo_diff/episodes",
            params={"since": "2026-08-23T00:00:00"},
        )
        episode = client.get("/v1/robots/demo_diff/episodes/not-an-episode")

    assert robot.status_code == 404
    assert window.status_code == 422
    assert timezone_missing.status_code == 422
    assert episode.status_code == 404


def test_episode_api_adapts_legacy_diagnose_publication_for_vis(
    tmp_path: Path,
    monkeypatch,
) -> None:
    started_at = datetime(2026, 8, 22, 3, tzinfo=timezone.utc)
    observations = [
        EpisodeObservation(
            sequence=index,
            phase=phase,
            observed_at=started_at + timedelta(seconds=index),
            payload={"internal": "omitted from public projection"},
            provenance=TargetProvenance(
                target_id="demo_diff",
                source="fixture",
                probe_runner_version="1",
                collected_at=started_at + timedelta(seconds=index),
                clock_offset_ms=0,
            ),
        )
        for index, phase in enumerate(EpisodePhase, start=1)
    ]
    episode = DiagnosisEpisode(
        episode_id="legacy-episode",
        robot_id="demo_diff",
        started_at=started_at,
        ended_at=started_at + timedelta(seconds=10),
        observations=observations,
    )
    artifact_root = tmp_path / "artifacts"
    publish_episode(artifact_root, episode)
    monkeypatch.setenv("ROLO_ARTIFACT_DIR", str(artifact_root))
    monkeypatch.setenv("ROLO_OUTPUT_DIR", str(tmp_path / "output"))
    get_settings.cache_clear()

    with TestClient(app) as client:
        response = client.get("/v1/robots/demo_diff/episodes")
        detail = client.get("/v1/robots/demo_diff/episodes/legacy-episode")
        revisions = client.get("/v1/robots/demo_diff/episodes/legacy-episode/revisions")

    assert response.status_code == 200, response.text
    assert response.json()["total"] == 1
    assert detail.status_code == 200, detail.text
    body = detail.json()
    assert body["verification"] == "NOT_AVAILABLE"
    assert body["evidence_ids"] == []
    assert "internal" not in detail.text
    assert body["event_count"] == len(EpisodePhase)
    assert revisions.status_code == 200, revisions.text
    assert revisions.json()["current_revision"] == 1


def test_verify_readiness_endpoint_returns_explicit_blocked_when_missing(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("ROLO_ARTIFACT_DIR", str(tmp_path / "artifacts"))
    monkeypatch.setenv("ROLO_OUTPUT_DIR", str(tmp_path / "output"))
    get_settings.cache_clear()

    with TestClient(app) as client:
        response = client.get("/v1/robots/demo_diff/verify/readiness")

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["schema_version"] == "rolo-real-verify-readiness/v2"
    assert body["status"] == "BLOCKED"
    assert body["release_authority"] == "none"
    assert body["blockers"]


def test_episode_cohort_api_is_feature_negotiated_and_revision_pinned(
    tmp_path: Path,
    monkeypatch,
) -> None:
    artifact_root = tmp_path / "artifacts"
    _publish_fixture(artifact_root)
    _publish_cohort_member(artifact_root, "ep-nav-prior")
    monkeypatch.setenv("ROLO_ARTIFACT_DIR", str(artifact_root))
    monkeypatch.setenv("ROLO_OUTPUT_DIR", str(tmp_path / "output"))
    get_settings.cache_clear()

    params = {
        "reference_episode_id": "ep-nav-001",
        "reference_revision": 1,
        "window_days": 7,
    }
    with TestClient(app) as client:
        health = client.get("/health")
        cohort = client.get("/v1/robots/demo_diff/episode-cohorts", params=params)
        invalid_window = client.get(
            "/v1/robots/demo_diff/episode-cohorts",
            params={**params, "window_days": 14},
        )
        stale = client.get(
            "/v1/robots/demo_diff/episode-cohorts",
            params={**params, "reference_revision": 2},
        )
        missing = client.get(
            "/v1/robots/demo_diff/episode-cohorts",
            params={**params, "reference_episode_id": "ep-missing"},
        )

    assert "workbench.episode-cohort-read-model/v1" in health.json()["api_features"]
    assert cohort.status_code == 200, cohort.text
    assert cohort.json()["reference_revision"] == 1
    assert [item["episode_id"] for item in cohort.json()["items"]] == ["ep-nav-prior"]
    assert invalid_window.status_code == 422
    assert stale.status_code == 409
    assert missing.status_code == 404
