from __future__ import annotations

from datetime import datetime, timedelta, timezone

from rolo.mhs_bundle import landerpi_mhs_bundle
from rolo.mhs_gate import MhsGateContext, evaluate_mhs_gate
from rolo.mhs_hardware import MhsDeviceProvider, MhsIdentity, MhsStatus
from rolo.mhs_replay import MhsReplayBackend

FINGERPRINT = "a" * 64


def _results(manifest):
    provider = MhsDeviceProvider(manifest, MhsReplayBackend(manifest))
    return [provider.inspect(), provider.status(), provider.read()]


def test_unverified_landerpi_manifest_is_rejected_closed():
    manifest = landerpi_mhs_bundle().devices[0].manifest
    decision = evaluate_mhs_gate(
        manifest,
        _results(manifest),
        MhsGateContext(
            target_host_fingerprint=FINGERPRINT,
            evidence_target_host_fingerprint=FINGERPRINT,
        ),
    )
    assert decision.status == "REJECTED"
    assert "identity_tuple" in decision.reasons
    assert "physical_binding" in decision.reasons


def test_eligible_requires_verified_identity_and_fresh_results():
    manifest = (
        landerpi_mhs_bundle()
        .devices[0]
        .manifest.model_copy(
            update={"identity": MhsIdentity(stable_id="camera-serial", confidence="high")}
        )
    )
    results = _results(manifest)
    now = max(result.observed_at for result in results)
    decision = evaluate_mhs_gate(
        manifest,
        results,
        MhsGateContext(
            target_host_fingerprint=FINGERPRINT,
            evidence_target_host_fingerprint=FINGERPRINT,
            identity_verified=True,
            observed_at=now,
        ),
    )
    assert decision.status == "ELIGIBLE"
    assert set(decision.reasons) == {"physical_binding", "safety_review", "conformance"}


def test_stale_and_unavailable_results_fail_closed():
    manifest = (
        landerpi_mhs_bundle()
        .devices[0]
        .manifest.model_copy(
            update={"identity": MhsIdentity(stable_id="camera-serial", confidence="high")}
        )
    )
    results = _results(manifest)
    stale = results[0].model_copy(
        update={
            "observed_at": datetime.now(timezone.utc) - timedelta(hours=1),
            "fresh_until": datetime.now(timezone.utc) - timedelta(minutes=30),
        }
    )
    unavailable = results[1].model_copy(update={"status": MhsStatus.UNAVAILABLE})
    decision = evaluate_mhs_gate(
        manifest,
        [stale, unavailable, results[2]],
        MhsGateContext(
            target_host_fingerprint=FINGERPRINT,
            evidence_target_host_fingerprint=FINGERPRINT,
            identity_verified=True,
        ),
    )
    assert decision.status == "REJECTED"
    assert "runtime_results" in decision.reasons
    assert "freshness" in decision.reasons
