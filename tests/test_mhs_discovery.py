from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from rolo.mhs_discovery import (
    DiscoveryTrace,
    IdentityStability,
    MhsProbePolicy,
    mhs_evidence_envelope,
    redact_secrets,
    resolve_identity,
    write_gate_allowed,
)
from rolo.mhs_hardware import (
    MhsChannel,
    MhsDeviceClass,
    MhsDeviceManifest,
    MhsDeviceProvider,
)
from rolo.rkb import SnapshotIdentity

NOW = datetime(2026, 9, 2, 12, 0, tzinfo=timezone.utc)
FINGERPRINT = "a" * 64


def _provider() -> MhsDeviceProvider:
    manifest = MhsDeviceManifest(
        device_id="sensor-1",
        device_class=MhsDeviceClass.SENSOR,
        name="temperature",
        vendor="example",
        model="t-1",
        channels=[MhsChannel(id="temperature", name="Temperature", unit="degC")],
        transport={"kind": "fake"},
    )

    class Backend:
        def read(self):
            return {"temperature": 21.5}

        def status(self):
            return {"health": "OK"}

    return MhsDeviceProvider(manifest, Backend())


def test_identity_resolution_prefers_serial_and_marks_path() -> None:
    stable = resolve_identity({"path": "/dev/i2c-1", "serial": "sensor-serial"})
    assert stable.selected_value == "sensor-serial"
    assert stable.stability == IdentityStability.STABLE
    path = resolve_identity({"path": "/dev/i2c-1"})
    assert path.selected_source == "path"
    assert path.stability == IdentityStability.PATH
    assert path.usable
    assert not write_gate_allowed(path)
    assert write_gate_allowed(stable)


def test_identity_conflict_fails_closed() -> None:
    result = resolve_identity({"serial": "a", "device_tree": "b"})
    assert result.stability == IdentityStability.UNKNOWN
    assert result.selected_value is None
    assert result.conflicts == ["a", "b"]


def test_trace_redacts_credentials_and_validates_digest() -> None:
    output, changed = redact_secrets("token=abc https://user:pass@example.test/status")
    assert changed
    assert "abc" not in output
    assert "pass" not in output
    trace = DiscoveryTrace.from_output(
        collector_id="collector-1",
        target_host_fingerprint=FINGERPRINT,
        deployment_mode="remote",
        source_kind="TARGET_PROBE",
        source_ref="ssh://192.0.2.1/hostname",
        output="token=abc",
        observed_at=NOW,
    )
    assert trace.redacted
    assert trace.output_sha256


def test_probe_policy_rejects_write_like_operations() -> None:
    policy = MhsProbePolicy()
    policy.require_allowed("read")
    with pytest.raises(PermissionError):
        policy.require_allowed("reset")
    with pytest.raises(ValueError):
        MhsProbePolicy(allowed_operations=frozenset({"setpoint"}))


def test_mhs_results_bind_to_rkb_evidence() -> None:
    provider = _provider()
    results = [provider.inspect(), provider.status(), provider.read()]
    identity = SnapshotIdentity(
        robot_id="robot-1",
        target_host_fingerprint=FINGERPRINT,
        collector_id="mhs-collector",
        deployment_mode="remote",
        request_nonce="b" * 32,
        observed_at=results[0].observed_at,
        fresh_until=max(result.fresh_until for result in results),
    )
    envelope = mhs_evidence_envelope(
        results,
        identity=identity,
        source_ref="artifact://mhs/sensor-1",
        device_id="sensor-1",
        provider_id=provider.provider_id,
    )
    envelope.verify(now=identity.observed_at + timedelta(seconds=1))
    assert len(envelope.facts) == 3
    assert envelope.snapshot["mhs_device_id"] == "sensor-1"
