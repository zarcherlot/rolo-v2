from datetime import datetime, timedelta, timezone

import pytest

from rolo.core.models import DiscoveryStatus, ProbeResult
from rolo.rkb import EvidenceEnvelope, SnapshotIdentity, envelope_from_probe


NOW = datetime(2026, 9, 2, 8, 0, tzinfo=timezone.utc)
FP = "a" * 64


def identity(**changes):
    values = dict(
        robot_id="r1",
        target_host_fingerprint=FP,
        collector_id="collector-1",
        deployment_mode="remote",
        request_nonce="b" * 32,
        observed_at=NOW,
        fresh_until=NOW + timedelta(minutes=5),
    )
    values.update(changes)
    return SnapshotIdentity(**values)


def test_probe_becomes_canonical_digestable_envelope():
    probe = ProbeResult(layer="linux", status=DiscoveryStatus.SUCCEEDED, data={"os": "Linux"}, observed_at=NOW)
    envelope = envelope_from_probe(probe, identity=identity(), source_ref="artifact://run-1#/linux")
    assert envelope.digest == envelope.computed_digest()
    envelope.verify(now=NOW)
    assert envelope.facts[0].source_ref.endswith("/linux")


def test_digest_tamper_and_identity_mismatch_fail_closed():
    probe = ProbeResult(layer="hw", status=DiscoveryStatus.PARTIAL, observed_at=NOW)
    envelope = envelope_from_probe(probe, identity=identity(), source_ref="artifact://run-1")
    tampered = envelope.model_copy(update={"snapshot": {"tampered": True}})
    with pytest.raises(ValueError, match="digest"):
        tampered.verify(now=NOW)
    with pytest.raises(ValueError, match="identity tuple"):
        EvidenceEnvelope(identity=identity(robot_id="other"), facts=envelope.facts)


def test_stale_envelope_is_rejected():
    probe = ProbeResult(layer="ros", status=DiscoveryStatus.UNAVAILABLE, observed_at=NOW)
    envelope = envelope_from_probe(probe, identity=identity(fresh_until=NOW + timedelta(seconds=1)), source_ref="artifact://run-1")
    with pytest.raises(ValueError, match="stale"):
        envelope.verify(now=NOW + timedelta(seconds=2))
