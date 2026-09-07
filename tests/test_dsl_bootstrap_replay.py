import json
from datetime import datetime, timezone

from rolo.dsl.bootstrap import BootstrapProbeProfile, run_bootstrap_projection
from rolo.dsl.bootstrap_replay import replay_bootstrap_artifacts, verify_bootstrap_artifacts


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


def _project(tmp_path):
    profile = BootstrapProbeProfile(profile_id="robot-1-bootstrap", robot_id="robot-1")
    result, paths = run_bootstrap_projection(_bundle(), tmp_path, profile=profile, evidence_verified=True)
    return result, paths["manifest"].parent


def test_bootstrap_replay_verifies_digest_bound_artifacts(tmp_path):
    result, root = _project(tmp_path)
    report = verify_bootstrap_artifacts(root, expected_robot_id="robot-1", expected_target_fingerprint="b" * 64)
    assert report.status == "PASS"
    assert report.discovery_session_id == result.discovery_session_id
    assert set(report.verified_artifacts) == {"bootstrap-result.json", "compile-context.json", "artifact-index.json", "candidate-index.json"}
    assert replay_bootstrap_artifacts(root).status == "PASS"


def test_bootstrap_replay_blocks_tampered_context(tmp_path):
    _, root = _project(tmp_path)
    context_path = root / "context" / "compile-context.json"
    payload = json.loads(context_path.read_text(encoding="utf-8"))
    payload["robot_id"] = "attacker"
    context_path.write_text(json.dumps(payload), encoding="utf-8")
    report = verify_bootstrap_artifacts(root)
    assert report.status == "BLOCKED"
    assert "COMPILE_CONTEXT_DIGEST_MISMATCH" in report.diagnostics
    assert "COMPILE_CONTEXT_INDEX_MISMATCH" in report.diagnostics


def test_bootstrap_replay_rejects_artifact_traversal(tmp_path):
    _, root = _project(tmp_path)
    manifest_path = root / "bootstrap-result.json"
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    payload["candidate_index_ref"] = "artifact://../outside.json"
    manifest_path.write_text(json.dumps(payload), encoding="utf-8")
    report = verify_bootstrap_artifacts(root)
    assert report.status == "BLOCKED"
    assert "CANDIDATE_INDEX_REF_OUTSIDE_ROOT" in report.diagnostics


def test_bootstrap_replay_rejects_manifest_candidate_digest_drift(tmp_path):
    _, root = _project(tmp_path)
    manifest_path = root / "bootstrap-result.json"
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    payload["candidate_index_digest"] = "0" * 64
    manifest_path.write_text(json.dumps(payload), encoding="utf-8")
    report = verify_bootstrap_artifacts(root)
    assert report.status == "BLOCKED"
    assert "CANDIDATE_INDEX_MANIFEST_DIGEST_MISMATCH" in report.diagnostics
