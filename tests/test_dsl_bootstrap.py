from datetime import datetime, timezone

import pytest

from rolo.dsl.bootstrap import BootstrapProbeProfile, run_bootstrap_projection


def _bundle() -> dict:
    return {
        "schema_version": "robot-target-evidence-bundle/v4",
        "robot_id": "robot-1",
        "source_id": "probe-1",
        "target_host_fingerprint": "b" * 64,
        "request_nonce": "c" * 32,
        "requested_layers": ["ros"],
        "access": "READ_ONLY",
        "collected_at": datetime(2026, 9, 6, tzinfo=timezone.utc).isoformat(),
        "probes": {
            "ros": {
                "layer": "ros",
                "status": "SUCCEEDED",
                "data": {
                    "routes": [{"resource_id": "/scan", "operation": "sensor.scan"}],
                    "message_schemas": [{"schema_id": "sensor_msgs/msg/LaserScan"}],
                },
                "warnings": [],
                "errors": [],
            }
        },
        "payload_sha256": "a" * 64,
        "signature_hmac_sha256": "d" * 64,
    }


def test_bootstrap_projection_writes_context_candidates_and_manifest(tmp_path):
    profile = BootstrapProbeProfile(profile_id="robot-1-bootstrap", robot_id="robot-1")
    first, paths = run_bootstrap_projection(_bundle(), tmp_path, profile=profile, evidence_verified=True)

    assert first.status == "READY"
    assert first.discovery_session_id.startswith("bootstrap-")
    assert first.compile_context_digest
    assert first.candidate_index_digest
    assert first.compile_context_ref == "artifact://context/compile-context.json"
    assert first.candidate_index_ref == "artifact://candidates/candidate-index.json"
    assert paths["manifest"].is_file()
    assert "rolo-compile-context/v1" in paths["context"].read_text(encoding="utf-8")

    second, _ = run_bootstrap_projection(_bundle(), tmp_path, profile=profile, evidence_verified=True)
    assert second.discovery_session_id == first.discovery_session_id
    assert second.compile_context_digest == first.compile_context_digest
    assert second.candidate_index_digest == first.candidate_index_digest


def test_bootstrap_projection_requires_verified_evidence(tmp_path):
    profile = BootstrapProbeProfile(profile_id="robot-1-bootstrap", robot_id="robot-1")
    with pytest.raises(ValueError, match="BOOTSTRAP_REQUIRES_VERIFIED_EVIDENCE"):
        run_bootstrap_projection(_bundle(), tmp_path, profile=profile, evidence_verified=False)


def test_bootstrap_projection_rejects_profile_target_mismatch(tmp_path):
    profile = BootstrapProbeProfile(profile_id="robot-2-bootstrap", robot_id="robot-2")
    with pytest.raises(ValueError, match="BOOTSTRAP_PROFILE_TARGET_MISMATCH"):
        run_bootstrap_projection(_bundle(), tmp_path, profile=profile, evidence_verified=True)
