import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from rolo.rkb import Fact, FactSourceKind, RKBStore, Snapshot, SnapshotIdentity
from rolo.rkb.validation import EvidenceValidationError

NOW = datetime(2026, 9, 2, 8, 0, tzinfo=timezone.utc)


def snapshot(index: int = 1) -> Snapshot:
    identity = SnapshotIdentity(
        robot_id=f"robot-{index}",
        target_host_fingerprint="a" * 64,
        collector_id="collector-1",
        deployment_mode="local",
        request_nonce=f"{index:032x}",
        observed_at=NOW,
        fresh_until=NOW + timedelta(minutes=5),
    )
    fact = Fact(
        robot_id=identity.robot_id,
        target_host_fingerprint=identity.target_host_fingerprint,
        collector_id=identity.collector_id,
        deployment_mode=identity.deployment_mode,
        request_nonce=identity.request_nonce,
        source_kind=FactSourceKind.OBSERVED_RUNTIME,
        source_ref="artifact://fixture#/linux",
        observed_at=NOW,
        fresh_until=identity.fresh_until,
        value={"layer": "linux", "data": {"host": {"system": "Linux"}}},
    )
    return Snapshot(
        identity=identity,
        facts=[fact],
        freshness_policy={"process_state": 30},
    ).with_digest()


def test_store_appends_snapshot_and_publishes_atomic_latest(tmp_path: Path):
    store = RKBStore(tmp_path)
    item = snapshot()
    path = store.write(item, now=NOW)
    assert path.name == f"{item.digest}.json"
    assert store.load_latest().digest == item.digest
    assert store.metrics.as_dict()["writes"] == 1
    assert json.loads((tmp_path / "metrics.json").read_text()) ["writes"] == 1


def test_store_isolates_corrupt_snapshot_and_recovers_previous_latest(tmp_path: Path):
    store = RKBStore(tmp_path)
    previous = snapshot(1)
    item = snapshot(2)
    store.write(previous, now=NOW)
    store.write(item, now=NOW)
    path = tmp_path / "snapshots" / f"{item.digest}.json"
    path.write_text("{broken", encoding="utf-8")
    recovered = store.load_latest()
    assert recovered.digest == previous.digest
    assert json.loads((tmp_path / "latest.json").read_text())["digest"] == previous.digest
    assert list((tmp_path / "corrupt").glob("*.corrupt"))
    assert store.metrics.corrupt_artifacts >= 1


def test_store_rejects_conflicting_content_for_immutable_digest(tmp_path: Path):
    store = RKBStore(tmp_path)
    item = snapshot()
    store.write(item, now=NOW)
    path = tmp_path / "snapshots" / f"{item.digest}.json"
    path.write_text(path.read_text(encoding="utf-8") + " ", encoding="utf-8")
    with pytest.raises(EvidenceValidationError, match="conflicting content"):
        store.write(item, now=NOW)
