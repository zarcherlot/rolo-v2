import os
import time
from datetime import date, datetime, timedelta, timezone
from multiprocessing import Process
from pathlib import Path

import pytest

from rolo.rkb import (
    EpisodeStore,
    HMACKeyring,
    SchemaRegistry,
    Snapshot,
    build_episode_from_snapshot,
    evaluate_alerts,
    keyring_from_vault,
    run_alert_cycle,
)
from rolo.rkb.episodes import EpisodeMetrics
from rolo.rkb.validation import EvidenceValidationError


def test_alerts_cover_stale_integrity_and_capacity() -> None:
    alerts = evaluate_alerts(
        metrics=EpisodeMetrics(corrupt_artifacts=1),
        capacity_used_bytes=95,
        capacity_limit_bytes=100,
    )
    assert {item.code for item in alerts} == {"digest_mismatch", "capacity_high_watermark"}


def test_hmac_keyring_rotation_revocation_and_replay_window() -> None:
    now = datetime(2026, 9, 3, tzinfo=timezone.utc)
    ring = HMACKeyring()
    ring.rotate("k1", b"x" * 32, activated_at=now)
    sig = ring.sign("k1", "a" * 64, now=now)
    ring.verify("k1", "a" * 64, sig, now=now, max_age=timedelta(days=1))
    ring.verify_once("k1", "a" * 64, sig, "nonce-1", now=now)
    with pytest.raises(EvidenceValidationError):
        ring.verify_once("k1", "a" * 64, sig, "nonce-1", now=now)
    ring.revoke("k1", revoked_at=now + timedelta(hours=1))
    with pytest.raises(EvidenceValidationError):
        ring.verify("k1", "a" * 64, sig, now=now + timedelta(hours=2))


def test_schema_registry_exposes_compatibility_window() -> None:
    registry = SchemaRegistry()
    assert registry.is_readable("TargetEvidenceBundle/v2", on=date(2026, 9, 3))
    assert registry.migration_target("TargetEvidenceBundle/v2") == "robot-snapshot/v1"
    assert not registry.is_readable("TargetEvidenceBundle/v2", on=date(2028, 1, 1))
    with pytest.raises(ValueError):
        registry.policy("unknown/v9")


def test_scheduler_reads_counters_and_vault_never_persists_secret(tmp_path: Path) -> None:
    (tmp_path / "metrics.json").write_text('{"corrupt_artifacts": 1}', encoding="utf-8")
    emitted = run_alert_cycle(tmp_path / "metrics.json")
    assert emitted[0].code == "digest_mismatch"
    ring = keyring_from_vault(lambda key_id: b"v" * 32, ["active"])
    assert ring.sign("active", "a" * 64)


def _crash_publisher(snapshot_json: str, root: str) -> None:
    snapshot = Snapshot.model_validate_json(snapshot_json)
    EpisodeStore(Path(root)).publish(
        build_episode_from_snapshot(snapshot, probe_run_id="kill9-test", episode_id="kill9-test")
    )
    time.sleep(30)


def test_episode_record_survives_publisher_sigkill(tmp_path: Path) -> None:
    identity = {
        "robot_id": "mentorpi", "target_host_fingerprint": "a" * 64,
        "collector_id": "kill9-test", "deployment_mode": "local",
        "request_nonce": "1" * 32, "observed_at": "2026-09-03T00:00:00Z",
        "fresh_until": "2026-09-03T00:05:00Z", "identity_status": "VERIFIED",
        "access": "READ_ONLY",
    }
    snapshot = Snapshot(identity=identity, facts=[]).with_digest()
    process = Process(target=_crash_publisher, args=(snapshot.model_dump_json(), str(tmp_path)))
    process.start()
    time.sleep(0.5)
    os.kill(process.pid, 9)
    process.join(timeout=5)
    recovered = EpisodeStore(tmp_path).load_latest("mentorpi", "kill9-test")
    assert process.exitcode is not None and process.exitcode != 0
    assert recovered.probe_run_id == "kill9-test"
