"""Evaluate captured LanderPi structured samples through the MHS gate."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from rolo.mhs_bundle import MhsBundle
from rolo.mhs_fixture import load_fixture_for_manifest
from rolo.mhs_gate import MhsGateContext, evaluate_mhs_gate
from rolo.mhs_hardware import MhsDeviceProvider
from rolo.mhs_replay import MhsReplayBackend


HERE = Path(__file__).parent
BUNDLE = HERE / "mhs-bundle-20260902.json"
FIXTURE = HERE / "ros-structured-fixture-20260903.json"
DISCOVERY = HERE / "discovery-20260902.json"
OUTPUT = HERE / "mhs-gate-20260903.json"


def main() -> None:
    bundle = MhsBundle.model_validate(json.loads(BUNDLE.read_text(encoding="utf-8")))
    discovery = json.loads(DISCOVERY.read_text(encoding="utf-8"))
    fingerprint = discovery["identity"]["target_host_fingerprint"]
    decisions = []
    for item in bundle.devices:
        manifest = item.manifest
        samples = load_fixture_for_manifest(FIXTURE, manifest)
        provider = MhsDeviceProvider(
            manifest, MhsReplayBackend(manifest, structured_samples=samples)
        )
        results = [provider.inspect(), provider.status(), provider.read_structured()]
        decision = evaluate_mhs_gate(
            manifest,
            results,
            MhsGateContext(
                target_host_fingerprint=fingerprint,
                evidence_target_host_fingerprint=fingerprint,
                identity_verified=bool(manifest.identity.stable_id),
                physical_binding_verified=False,
                conformance_passed=False,
                safety_reviewed=False,
                observed_at=datetime.now(timezone.utc),
            ),
        )
        decisions.append(
            {
                "device_id": manifest.device_id,
                "sample_count": len(samples),
                "status": decision.status,
                "checks": decision.checks,
                "reasons": decision.reasons,
            }
        )
    payload = {
        "schema_version": "rolo-mhs-gate-evaluation/v1",
        "robot_id": bundle.robot_id,
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
        "access": "READ_ONLY_REPLAY",
        "fixture": "artifact://mhs-landerpi/ros-structured-fixture-20260903.json",
        "decisions": decisions,
        "limitations": [
            "Replay validates manifest routes and payload shape only; it does not touch hardware.",
            "ELIGIBLE does not mean VERIFIED: physical binding, safety review and conformance remain separate gates.",
        ],
    }
    OUTPUT.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(OUTPUT)


if __name__ == "__main__":
    main()
