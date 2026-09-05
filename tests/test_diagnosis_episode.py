from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from rolo.stages.diagnose.episode import (
    DiagnosisEpisode,
    EpisodeObservation,
    EpisodePhase,
    TargetProvenance,
    publish_episode,
    validate_published_episode,
)


def _episode() -> DiagnosisEpisode:
    now = datetime.now(timezone.utc)
    provenance = TargetProvenance(
        target_id="robot-1",
        source="target-probe_runner",
        probe_runner_version="1.0.0",
        collected_at=now,
        clock_offset_ms=1.5,
    )
    return DiagnosisEpisode(
        robot_id="robot-1",
        started_at=now,
        ended_at=now + timedelta(seconds=1),
        observations=[
            EpisodeObservation(
                sequence=index,
                phase=phase,
                observed_at=now,
                payload={"status": phase.value},
                provenance=provenance,
            )
            for index, phase in enumerate(EpisodePhase, start=1)
        ],
    )


def test_episode_publication_binds_record_hash_and_target(tmp_path) -> None:
    reference = publish_episode(tmp_path, _episode())
    episode = validate_published_episode(tmp_path, reference, robot_id="robot-1")
    assert episode.robot_id == "robot-1"


def test_complete_episode_requires_all_closed_loop_phases() -> None:
    episode = _episode().model_copy(
        update={"observations": _episode().observations[:-1]}
    )
    with pytest.raises(ValueError, match="missing phases"):
        DiagnosisEpisode.model_validate(episode.model_dump(mode="json"))


def test_episode_rejects_cross_target_provenance() -> None:
    episode = _episode().model_copy(deep=True)
    episode.observations[0].provenance.target_id = "other-robot"
    with pytest.raises(ValueError, match="provenance target"):
        DiagnosisEpisode.model_validate(episode.model_dump(mode="json"))
