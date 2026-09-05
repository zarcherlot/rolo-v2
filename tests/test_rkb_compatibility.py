import hashlib
import hmac
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
    snapshot_to_discovery_report,
    snapshot_to_legacy_probes,
    validate_snapshot,
    verified_bundle_to_snapshot,
)
from rolo.stages.probe.target_evidence import (
    EvidenceDeploymentConfig,
    EvidenceDeploymentMode,
    ProbeRunnerDescriptor,
    TargetEvidenceBundle,
)

NOW = datetime(2026, 9, 2, 8, 0, tzinfo=timezone.utc)
FP = "a" * 64
NONCE = "b" * 32


def make_identity(**changes):
    values = {
        "robot_id": "robot-1",
        "target_host_fingerprint": FP,
        "source_id": "source-1",
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
    assert "snapshot" in snapshot.model_dump(mode="json")
    assert "metadata" not in snapshot.model_dump(mode="json")
    assert snapshot.facts[0].value["status"] == "UNAVAILABLE"
    assert json_pointer(snapshot.model_dump(mode="json"), "/facts/0/value/data/domain_id") is None


def test_v4_bundle_projects_into_snapshot():
    bundle = TargetEvidenceBundle(
        robot_id="robot-1",
        source_id="source-1",
        target_host_fingerprint=FP,
        request_nonce=NONCE,
        requested_layers=["linux"],
        collected_at=NOW,
        probes={"linux": ProbeResult(layer="linux", status=DiscoveryStatus.PARTIAL)},
        payload_sha256="c" * 64,
        signature_hmac_sha256="d" * 64,
    )
    snapshot = bundle_to_snapshot(bundle, deployment_mode="remote")
    assert snapshot.snapshot["source_schema_version"] == "robot-target-evidence-bundle/v4"
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
    tampered = snapshot.model_copy(update={"snapshot": {"secret": "must not pass"}})
    with pytest.raises(EvidenceValidationError, match="digest"):
        validate_snapshot(tampered, now=NOW)


def test_nested_null_is_part_of_payload_digest():
    assert payload_digest({"value": {"explicit": None}}) != payload_digest(
        {"value": {"explicit": "<omitted>"}}
    )


def test_bundle_hmac_is_required_when_requested_and_report_projection_is_compatible():
    bundle = TargetEvidenceBundle(
        robot_id="robot-1",
        source_id="source-1",
        target_host_fingerprint=FP,
        request_nonce=NONCE,
        requested_layers=["linux"],
        collected_at=NOW,
        probes={
            "linux": ProbeResult(
                layer="linux", status=DiscoveryStatus.PARTIAL, observed_at=NOW
            )
        },
        payload_sha256="0" * 64,
        signature_hmac_sha256="0" * 64,
    )
    secret = b"s" * 32
    payload = payload_digest(
        bundle, exclude=("payload_sha256", "signature_hmac_sha256")
    )
    signature = hmac.new(secret, payload.encode("ascii"), hashlib.sha256).hexdigest()
    signed = bundle.model_copy(
        update={"payload_sha256": payload, "signature_hmac_sha256": signature}
    )
    snapshot = bundle_to_snapshot(signed, verification_secret=secret)
    report = snapshot_to_discovery_report(snapshot)
    assert report.robot_id == "robot-1"
    with pytest.raises(EvidenceValidationError, match="HMAC"):
        bundle_to_snapshot(signed, verification_secret=b"x" * 31)


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


def test_verified_bundle_projection_requires_pinned_deployment(tmp_path):
    secret = b"s" * 32
    secret_path = tmp_path / "probe_runner.key"
    secret_path.write_bytes(secret)
    # Linux CI enforces the probe_runner's private-key mode at load time;
    # Windows does not expose POSIX mode bits, so make the fixture explicit.
    secret_path.chmod(0o600)
    descriptor = ProbeRunnerDescriptor(
        robot_id="robot-1",
        source_id="source-1",
        target_host_fingerprint=FP,
    )
    deployment = EvidenceDeploymentConfig(
        robot_id="robot-1",
        mode=EvidenceDeploymentMode.LOCAL,
        probe_runner=descriptor,
        verification_secret_path=str(secret_path),
        verification_secret_sha256=hashlib.sha256(secret).hexdigest(),
        local_probe_runner_state_path=str(tmp_path / "source-state.json"),
    )
    bundle = TargetEvidenceBundle(
        robot_id="robot-1",
        source_id="source-1",
        target_host_fingerprint=FP,
        request_nonce=NONCE,
        requested_layers=["linux"],
        collected_at=NOW,
        probes={"linux": ProbeResult(layer="linux", status=DiscoveryStatus.PARTIAL)},
        payload_sha256="0" * 64,
        signature_hmac_sha256="0" * 64,
    )
    payload = payload_digest(bundle, exclude=("payload_sha256", "signature_hmac_sha256"))
    signed = bundle.model_copy(
        update={
            "payload_sha256": payload,
            "signature_hmac_sha256": hmac.new(
                secret, payload.encode("ascii"), hashlib.sha256
            ).hexdigest(),
        }
    )
    snapshot = verified_bundle_to_snapshot(signed, deployment=deployment, now=NOW)
    assert snapshot.identity.robot_id == "robot-1"
    tampered = signed.model_copy(update={"robot_id": "other"})
    with pytest.raises(ValueError, match="robot identity"):
        verified_bundle_to_snapshot(tampered, deployment=deployment, now=NOW)
