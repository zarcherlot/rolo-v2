from datetime import datetime, timedelta, timezone

import pytest

from rolo.core.models import DiscoveryStatus, ProbeResult
from rolo.rkb import (
    EvidenceValidationError,
    SnapshotIdentity,
    bundle_to_snapshot,
    json_pointer,
    payload_digest,
    probe_to_snapshot,
    snapshot_to_legacy_probes,
    validate_snapshot,
)
from rolo.stages.probe.target_evidence import TargetEvidenceBundle

NOW = datetime(2026, 9, 2, 8, 0, tzinfo=timezone.utc)
FP = "a" * 64
NONCE = "b" * 32


def make_identity(**changes):
    values = {
        "robot_id": "robot-1",
        "target_host_fingerprint": FP,
        "collector_id": "collector-1",
        "deployment_mode": "remote",
        "request_nonce": NONCE,
        "observed_at": NOW,
        "fresh_until": NOW + timedelta(minutes=5),
    }
    values.update(changes)
    return SnapshotIdentity(**values)


def test_probe_migration_preserves_unknown_status_and_pointer_source():
    probe = ProbeResult(
        layer="ros", status=DiscoveryStatus.UNAVAILABLE, data={"domain_id": None}, observed_at=NOW
    )
    snapshot = probe_to_snapshot(probe, identity=make_identity(), source_ref="artifact://r#/ros")
    validate_snapshot(snapshot, now=NOW)
    assert snapshot.facts[0].value["status"] == "UNAVAILABLE"
    assert json_pointer(snapshot.model_dump(mode="json"), "/facts/0/value/data/domain_id") is None


def test_legacy_v2_bundle_is_read_only_migrated_and_projects_back():
    bundle = TargetEvidenceBundle(
        robot_id="robot-1",
        collector_id="collector-1",
        target_host_fingerprint=FP,
        request_nonce=NONCE,
        requested_layers=["linux"],
        collected_at=NOW,
        probes={"linux": ProbeResult(layer="linux", status=DiscoveryStatus.PARTIAL)},
        payload_sha256="c" * 64,
        signature_hmac_sha256="d" * 64,
    )
    snapshot = bundle_to_snapshot(bundle, deployment_mode="remote")
    assert snapshot.metadata["source_schema_version"] == "robot-target-evidence-bundle/v2"
    assert snapshot_to_legacy_probes(snapshot)["linux"].status == DiscoveryStatus.PARTIAL


def test_digest_is_stable_and_tamper_is_rejected():
    snapshot = probe_to_snapshot(
        ProbeResult(
            layer="hw",
            status=DiscoveryStatus.SUCCEEDED,
            data={"z": 1, "a": 2},
            observed_at=NOW,
        ),
        identity=make_identity(),
    )
    assert payload_digest(snapshot) == snapshot.digest
    tampered = snapshot.model_copy(update={"metadata": {"secret": "must not pass"}})
    with pytest.raises(EvidenceValidationError, match="digest"):
        validate_snapshot(tampered, now=NOW)


def test_future_identity_and_access_fail_closed():
    with pytest.raises(EvidenceValidationError, match="future"):
        snapshot = probe_to_snapshot(
            ProbeResult(
                layer="linux",
                status=DiscoveryStatus.SUCCEEDED,
                observed_at=NOW + timedelta(minutes=1),
            ),
            identity=make_identity(
                observed_at=NOW + timedelta(minutes=1),
                fresh_until=NOW + timedelta(minutes=2),
            ),
        )
        validate_snapshot(snapshot, now=NOW)
