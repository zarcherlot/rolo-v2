from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from rolo.core.models import DiscoveryStatus, ProbeResult
from rolo.rkb import (
    EpisodeEvent,
    EpisodeEventKind,
    EpisodeStore,
    Fact,
    FactSourceKind,
    Snapshot,
    SnapshotIdentity,
    build_episode_from_snapshot,
    build_terminal_episode,
    publish_probe_episode,
)
from rolo.rkb.validation import EvidenceValidationError
from rolo.stages.probe.target_evidence import TargetEvidenceBundle

NOW = datetime(2026, 9, 2, 8, 0, tzinfo=timezone.utc)


def make_snapshot() -> Snapshot:
    identity = SnapshotIdentity(
        robot_id="mentorpi",
        target_host_fingerprint="a" * 64,
        collector_id="rkb4-test",
        deployment_mode="local",
        request_nonce="1" * 32,
        observed_at=NOW,
        fresh_until=NOW + timedelta(minutes=5),
    )
    fact = Fact(
        robot_id="mentorpi",
        target_host_fingerprint="a" * 64,
        collector_id="rkb4-test",
        deployment_mode="local",
        request_nonce="1" * 32,
        source_kind=FactSourceKind.OBSERVED_RUNTIME,
        source_ref="artifact://fixture#/runtime",
        observed_at=NOW,
        fresh_until=NOW + timedelta(minutes=5),
        value={"layer": "linux", "data": {"hostname": "mentorpi"}},
    )
    return Snapshot(identity=identity, facts=[fact]).with_digest()


def test_episode_from_snapshot_is_metadata_only_and_typed_query_bound() -> None:
    episode = build_episode_from_snapshot(make_snapshot(), probe_run_id="run-1")
    assert episode.snapshot is not None
    assert [event.kind for event in episode.events] == list(EpisodeEventKind)
    assert all("payload" not in event.model_dump() for event in episode.events)
    assert episode.identity.access == "READ_ONLY"
    assert episode.content_sha256 == episode.computed_digest()


def test_episode_store_publishes_immutable_latest_and_rolls_back(tmp_path) -> None:
    store = EpisodeStore(tmp_path)
    first = build_episode_from_snapshot(make_snapshot(), probe_run_id="run-1", episode_id="ep-1")
    store.publish(first)
    second = first.model_copy(
        update={
            "probe_run_id": "run-2",
            "events": first.events[:1],
            "ended_at": NOW + timedelta(seconds=1),
            "content_sha256": None,
        }
    ).with_digest()
    store.publish(second)
    latest = store.load_latest("mentorpi", "ep-1")
    assert latest.probe_run_id == "run-2"
    rolled_back = store.rollback("mentorpi", "ep-1")
    assert rolled_back.probe_run_id == "run-1"
    assert store.load_latest("mentorpi", "ep-1").probe_run_id == "run-1"


def test_episode_store_is_idempotent_for_probe_run_and_rejects_conflicts(tmp_path) -> None:
    store = EpisodeStore(tmp_path)
    first = build_episode_from_snapshot(make_snapshot(), probe_run_id="same-run", episode_id="ep-1")
    first_path = store.publish(first)
    repeated_path = store.publish(first)
    assert repeated_path == first_path
    conflicting = first.model_copy(
        update={"limitations": ["different"], "content_sha256": None}
    ).with_digest()
    with pytest.raises(EvidenceValidationError, match="conflicting Episode"):
        store.publish(conflicting)
    assert store.metrics.idempotency_hits == 1
    assert store.metrics.idempotency_conflicts == 1


def test_episode_store_recovers_corrupt_latest_and_persists_metrics(tmp_path) -> None:
    store = EpisodeStore(tmp_path)
    first = build_episode_from_snapshot(make_snapshot(), probe_run_id="run-1", episode_id="ep-1")
    store.publish(first)
    second = first.model_copy(
        update={"probe_run_id": "run-2", "content_sha256": None}
    ).with_digest()
    store.publish(second)
    latest_path = tmp_path / "episodes" / "mentorpi" / "ep-1" / "latest.json"
    latest_path.write_text("{broken", encoding="utf-8")
    recovered = store.load_latest("mentorpi", "ep-1")
    assert recovered.probe_run_id == "run-2"
    assert store.metrics.latest_recoveries == 1
    assert EpisodeStore(tmp_path).metrics.latest_recoveries == 1
    metrics = json.loads((tmp_path / "episode-metrics.json").read_text(encoding="utf-8"))
    assert metrics["latest_recoveries"] == 1


def test_episode_query_filters_and_prune_are_bounded(tmp_path) -> None:
    store = EpisodeStore(tmp_path, retention_limit=1)
    first = build_episode_from_snapshot(make_snapshot(), probe_run_id="run-1", episode_id="ep-1")
    store.publish(first)
    second = first.model_copy(
        update={"probe_run_id": "run-2", "content_sha256": None}
    ).with_digest()
    store.publish(second)
    page = store.query(robot_id="mentorpi", source="rkb4-test", limit=1)
    assert page.total == 2
    assert len(page.items) == 1
    assert page.next_offset == 1
    assert store.query(state="PARTIAL", freshness="FRESH", now=NOW, limit=10).total == 2
    assert store.prune("mentorpi", "ep-1") == 1
    assert store.load_latest("mentorpi", "ep-1").probe_run_id == "run-2"


def test_terminal_episode_records_state_without_raw_error_payload() -> None:
    identity = make_snapshot().identity
    episode = build_terminal_episode(
        identity,
        probe_run_id="run-failed",
        state="FAILED",
        reason_code="SSH_SIGNATURE_BLOCKED",
    )
    assert episode.state.value == "FAILED"
    assert episode.events[-1].metadata == {
        "state": "FAILED",
        "reason_code": "SSH_SIGNATURE_BLOCKED",
    }


def test_episode_store_rejects_wrong_parent_without_moving_latest(tmp_path) -> None:
    store = EpisodeStore(tmp_path)
    first = build_episode_from_snapshot(make_snapshot(), probe_run_id="run-1", episode_id="ep-1")
    store.publish(first)
    second = first.model_copy(
        update={"probe_run_id": "run-2", "content_sha256": None}
    ).with_digest()
    with pytest.raises(EvidenceValidationError, match="parent digest"):
        store.publish(second, expected_parent_digest="b" * 64)
    assert store.load_latest("mentorpi", "ep-1").content_sha256 == first.content_sha256


def test_episode_rejects_secret_or_large_event_metadata() -> None:
    with pytest.raises(ValueError, match="forbidden field"):
        EpisodeEvent(
            sequence=1,
            kind=EpisodeEventKind.OBSERVATION,
            occurred_at=NOW,
            summary="bad",
            metadata={"password": "raspberrypi"},
        )


def test_dual_read_legacy_artifact_does_not_write_or_escape_store(tmp_path) -> None:
    legacy = tmp_path / "legacy-report.json"
    legacy.write_text(
        json.dumps({"schema_version": "legacy", "status": "PARTIAL"}), encoding="utf-8"
    )
    store = EpisodeStore(tmp_path)
    assert store.read_legacy_json(legacy)["status"] == "PARTIAL"
    with pytest.raises(EvidenceValidationError, match="escapes"):
        store.read_legacy_json("artifact://../outside.json")

    legacy_root = tmp_path / "legacy-root"
    legacy_root.mkdir()
    legacy_file = legacy_root / "bundle.json"
    legacy_file.write_text(json.dumps({"status": "READY"}), encoding="utf-8")
    configured_store = EpisodeStore(tmp_path / "rkb", legacy_root=legacy_root)
    assert configured_store.read_legacy_json("artifact://legacy/bundle.json")["status"] == "READY"


def test_probe_publication_is_one_way_and_keeps_legacy_bundle_untouched(tmp_path) -> None:
    bundle = TargetEvidenceBundle(
        robot_id="mentorpi",
        collector_id="rkb4-test",
        target_host_fingerprint="a" * 64,
        request_nonce="1" * 32,
        requested_layers=["linux"],
        collected_at=NOW,
        probes={
            "linux": ProbeResult(layer="linux", status=DiscoveryStatus.PARTIAL, observed_at=NOW)
        },
        payload_sha256="b" * 64,
        signature_hmac_sha256="c" * 64,
    )
    legacy = tmp_path / "legacy-bundle.json"
    legacy.write_text(bundle.model_dump_json(), encoding="utf-8")
    before = legacy.read_bytes()
    _, episode, snapshot_path, episode_path = publish_probe_episode(
        bundle,
        artifact_root=tmp_path,
        deployment_mode="local",
        bundle_ref="artifact://legacy-bundle.json",
        probe_run_id="run-legacy",
    )
    assert snapshot_path.is_file() and episode_path.is_file()
    assert episode.bundle is not None and episode.bundle.sha256 == "b" * 64
    assert legacy.read_bytes() == before
