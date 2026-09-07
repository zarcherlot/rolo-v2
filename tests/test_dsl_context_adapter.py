from datetime import datetime, timezone

from rolo.dsl.canonical import context_digest
from rolo.dsl.context_adapter import build_probe_context, persist_compile_context


def test_probe_context_adapter_projects_observed_records_and_mhs_refs() -> None:
    digest = "a" * 64
    bundle = {
        "robot_id": "robot-1",
        "source_id": "probe-1",
        "target_host_fingerprint": "b" * 64,
        "request_nonce": "c" * 32,
        "requested_layers": ["ros"],
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "probes": {
            "ros": {
                "layer": "ros",
                "status": "SUCCEEDED",
                "data": {
                    "routes": [{"resource_id": "/scan", "kind": "ros_topic"}],
                    "message_schemas": [{"schema_id": "sensor_msgs/LaserScan"}],
                    "runtime_revision": "ros-humble-1",
                    "published_tools": [{"operation": "app.scan", "release_digest": "sha256:release"}],
                    "mhs_manifest": {"ref": "artifact://mhs/manifest.json", "digest": digest},
                },
                "warnings": ["limited metadata"],
                "errors": [],
            }
        },
        "payload_sha256": digest,
        "signature_hmac_sha256": "d" * 64,
    }

    context = build_probe_context(bundle)

    assert context.robot_id == "robot-1"
    assert context.target_fingerprint == "b" * 64
    assert context.evidence_refs == ("artifact://target-evidence/robot-1-bundle.json",)
    assert context.runtime_revision == "ros-humble-1"
    assert context.routes == ({"resource_id": "/scan", "kind": "ros_topic"},)
    assert context.message_schemas == ({"schema_id": "sensor_msgs/LaserScan"},)
    assert context.mhs_manifest_refs == ("artifact://mhs/manifest.json",)
    assert context.mhs_manifest_digests == (digest,)
    assert context.published_tools == ({"operation": "app.scan", "release_digest": "sha256:release"},)
    assert context.limitations == ("limited metadata",)


def test_probe_context_adapter_digest_is_independent_of_probe_order() -> None:
    base = {
        "robot_id": "robot-1", "source_id": "probe-1", "target_host_fingerprint": "b" * 64,
        "request_nonce": "c" * 32, "requested_layers": ["ros"],
        "collected_at": datetime.now(timezone.utc).isoformat(), "payload_sha256": "a" * 64,
        "signature_hmac_sha256": "d" * 64,
    }
    def probe(route: str) -> dict:
        return {"layer": "ros", "status": "SUCCEEDED", "data": {"routes": [{"resource_id": route}]}}
    first = {**base, "probes": {"a": probe("/a"), "b": probe("/b")}}
    second = {**base, "probes": {"b": probe("/b"), "a": probe("/a")}}

    assert context_digest(build_probe_context(first)) == context_digest(build_probe_context(second))


def test_compile_context_persistence_writes_digest_index(tmp_path) -> None:
    context = build_probe_context(
        {
            "robot_id": "robot-1",
            "source_id": "probe-1",
            "target_host_fingerprint": "b" * 64,
            "request_nonce": "c" * 32,
            "requested_layers": ["ros"],
            "collected_at": datetime.now(timezone.utc).isoformat(),
            "probes": {},
            "payload_sha256": "a" * 64,
            "signature_hmac_sha256": "d" * 64,
        }
    )
    files = persist_compile_context(context, tmp_path / "context", signing_secret=b"s" * 16)
    assert files["context"].name == "compile-context.json"
    index = files["index"].read_text(encoding="utf-8")
    assert context_digest(context) in index
    assert "signature_hmac_sha256" in index


def test_failed_probe_payload_is_kept_as_limitation_not_observed_route() -> None:
    context = build_probe_context(
        {
            "robot_id": "robot-1",
            "source_id": "probe-1",
            "target_host_fingerprint": "b" * 64,
            "request_nonce": "c" * 32,
            "requested_layers": ["ros"],
            "collected_at": datetime.now(timezone.utc).isoformat(),
            "probes": {
                "ros": {
                    "layer": "ros",
                    "status": "FAILED",
                    "data": {"routes": [{"resource_id": "/must-not-promote"}]},
                    "warnings": [],
                    "errors": ["permission denied"],
                }
            },
            "payload_sha256": "a" * 64,
            "signature_hmac_sha256": "d" * 64,
        }
    )
    assert context.routes == ()
    assert "probe_ros_failed" in context.limitations
    assert "permission denied" in context.limitations


def test_probe_context_preserves_explicit_freshness_and_unknown_status() -> None:
    context = build_probe_context(
        {
            "robot_id": "robot-1",
            "source_id": "probe-1",
            "target_host_fingerprint": "b" * 64,
            "request_nonce": "c" * 32,
            "requested_layers": ["ros"],
            "collected_at": datetime(2026, 9, 6, tzinfo=timezone.utc).isoformat(),
            "probes": {
                "ros": {
                    "layer": "ros",
                    "status": "PARTIAL",
                    "data": {
                        "routes": [{"resource_id": "/scan", "operation": "sensor.scan", "evidence_refs": ["artifact://route/scan"]}],
                        "freshness": {"state": "STALE", "expires_at": "2026-09-05T00:00:00Z"},
                    },
                    "warnings": [],
                    "errors": [],
                },
                "linux": {
                    "layer": "linux",
                    "status": "UNAVAILABLE",
                    "data": {"routes": [{"resource_id": "/must-not-promote"}]},
                    "warnings": [],
                    "errors": [],
                },
            },
            "payload_sha256": "a" * 64,
            "signature_hmac_sha256": "d" * 64,
        }
    )
    assert context.freshness["state"] == "STALE"
    assert context.freshness["expires_at"] == "2026-09-05T00:00:00Z"
    assert context.routes == ({"resource_id": "/scan", "operation": "sensor.scan", "evidence_refs": ["artifact://route/scan"]},)
    assert "/must-not-promote" not in {record.get("resource_id") for record in context.routes}
    assert "probe_linux_unavailable" in context.limitations
