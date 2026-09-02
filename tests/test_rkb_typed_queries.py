from datetime import datetime, timedelta, timezone

import pytest

from rolo.rkb import (
    CapabilityState,
    Fact,
    FactSourceKind,
    QueryRejectedError,
    ReadOnlyKnowledgeBase,
    Snapshot,
    SnapshotIdentity,
    Stability,
)

NOW = datetime(2026, 9, 2, 8, 0, tzinfo=timezone.utc)
FP = "a" * 64


def identity(**changes):
    value = dict(
        robot_id="robot-1",
        target_host_fingerprint=FP,
        collector_id="collector-1",
        deployment_mode="remote",
        request_nonce="b" * 32,
        observed_at=NOW,
        fresh_until=NOW + timedelta(minutes=5),
    )
    value.update(changes)
    return SnapshotIdentity(**value)


def snapshot_for(*facts):
    return Snapshot(
        identity=identity(), facts=list(facts), freshness_policy={"middleware": 30}
    ).with_digest()


def fact(layer, data, *, source_kind=FactSourceKind.OBSERVED_RUNTIME, fresh_until=None):
    return Fact(
        robot_id="robot-1",
        target_host_fingerprint=FP,
        collector_id="collector-1",
        deployment_mode="remote",
        request_nonce="b" * 32,
        source_kind=source_kind,
        source_ref=f"artifact://fixture#/{layer}",
        observed_at=NOW,
        fresh_until=fresh_until or NOW + timedelta(minutes=5),
        value={"layer": layer, "status": "SUCCEEDED", "data": data},
    )


def test_typed_queries_project_layers_and_retain_evidence():
    snapshot = snapshot_for(
        fact("linux", {"os": "Debian", "version": "12", "domain_id": None}),
        fact(
            "hw",
            {
                "resources": [
                    {"path": "/dev/ttyUSB0", "kind": "sensor"},
                    {"serial": "S1", "kind": "camera"},
                ]
            },
        ),
        fact(
            "ros",
            {
                "endpoints": [
                    {
                        "id": "route-1",
                        "endpoint": "/scan",
                        "role": "publisher",
                        "node": "/lidar",
                        "interface": "sensor_msgs/msg/LaserScan",
                    }
                ]
            },
        ),
    )
    kb = ReadOnlyKnowledgeBase([snapshot])
    assert kb.robot.identity(now=NOW).value.robot_id == "robot-1"
    runtime = kb.os.runtime_status(now=NOW)
    assert runtime.value.ros_domain_id.status == "UNKNOWN"
    hardware = kb.hw.inventory_scan(now=NOW)
    assert hardware.value.resources[0].stability == Stability.UNSTABLE
    graph = kb.middleware.graph_snapshot(now=NOW)
    assert graph.value.endpoints[0].route_id == "route-1"
    assert graph.evidence_ids == [snapshot.facts[2].fact_id]


def test_static_capability_cannot_become_eligible():
    snapshot = snapshot_for(
        fact(
            "capability",
            {"capabilities": [{"operation_id": "drive", "state": "VERIFIED"}]},
            source_kind=FactSourceKind.DECLARED_STATIC,
        )
    )
    result = ReadOnlyKnowledgeBase([snapshot]).capability.get("drive", now=NOW)
    assert result.status == CapabilityState.DISCOVERED_UNVERIFIED
    assert "not sufficient" in result.status_reason


def test_query_rejects_stale_and_fingerprint_mismatch():
    stale_identity = identity(fresh_until=NOW + timedelta(seconds=1))
    stale = Snapshot(
        identity=stale_identity,
        facts=[fact("linux", {}, fresh_until=stale_identity.fresh_until)],
        freshness_policy={},
    ).with_digest()
    kb = ReadOnlyKnowledgeBase([stale])
    with pytest.raises(QueryRejectedError, match="stale"):
        kb.robot.identity(now=NOW + timedelta(seconds=2))
    with pytest.raises(QueryRejectedError, match="fingerprint"):
        kb.robot.identity(fingerprint="c" * 64, now=NOW)


def test_reference_selects_the_requested_snapshot_and_missing_route_is_unknown():
    first = snapshot_for(fact("ros", {"endpoints": [{"route_id": "old", "endpoint": "/old"}]}))
    second = snapshot_for(fact("ros", {"endpoints": [{"route_id": "new", "endpoint": "/new"}]}))
    kb = ReadOnlyKnowledgeBase([first, second])
    ref = kb.reference(first)
    assert (
        kb.middleware.graph_snapshot(snapshot_ref=ref, now=NOW).value.endpoints[0].route_id == "old"
    )
    missing = kb.middleware.route_inspect("missing", now=NOW)
    assert missing.status.value == "UNKNOWN"


def test_state_safety_never_infers_safe():
    result = ReadOnlyKnowledgeBase([snapshot_for(fact("linux", {}))]).state_safety.snapshot(now=NOW)
    assert result.value.safety_status == "UNKNOWN"
    assert any("UNKNOWN" in item for item in result.limitations)


def test_query_freshness_is_layer_scoped_and_stale_values_are_not_exposed():
    snapshot = snapshot_for(
        fact(
            "hw",
            {"resources": [{"serial": "S1", "kind": "camera"}]},
            fresh_until=NOW + timedelta(minutes=4),
        ),
        fact(
            "ros",
            {"endpoints": [{"route_id": "scan", "endpoint": "/scan"}]},
            fresh_until=NOW + timedelta(seconds=1),
        ),
    )
    kb = ReadOnlyKnowledgeBase([snapshot])
    hardware = kb.hw.inventory_scan(now=NOW + timedelta(seconds=30))
    assert hardware.status.value == "FRESH"
    assert hardware.value.resources[0].serial == "S1"
    graph = kb.middleware.graph_snapshot(now=NOW + timedelta(seconds=30))
    assert graph.status.value == "STALE"
    assert graph.value is None


def test_multiple_layer_facts_are_merged_without_dropping_resources():
    snapshot = snapshot_for(
        fact("hw", {"resources": [{"path": "/dev/ttyUSB0", "kind": "sensor"}]}),
        fact("hw", {"resources": [{"serial": "S1", "kind": "camera"}]}),
    )
    result = ReadOnlyKnowledgeBase([snapshot]).hw.inventory_scan(now=NOW)
    assert [item.resource_id for item in result.value.resources] == ["/dev/ttyUSB0", "S1"]


def test_middleware_selector_matches_exact_route_tokens():
    snapshot = snapshot_for(
        fact(
            "ros",
            {
                "endpoints": [
                    {"route_id": "scan", "endpoint": "/scan"},
                    {"route_id": "scan-raw", "endpoint": "/scan/raw"},
                ]
            },
        )
    )
    result = ReadOnlyKnowledgeBase([snapshot]).middleware.graph_snapshot(
        selector="/scan", now=NOW
    )
    assert [item.route_id for item in result.value.endpoints] == ["scan"]


def test_runtime_projection_is_explicit_and_does_not_leak_probe_payload():
    snapshot = snapshot_for(
        fact(
            "linux",
            {
                "host": {
                    "system": "Linux",
                    "release": "6.1",
                    "version": "#1",
                    "architecture": "aarch64",
                    "hostname": "mentorpi",
                },
                "environment": {"ROS_DISTRO": "humble", "ROS_DOMAIN_ID": "7"},
                "processes": ["secret-process-detail"],
            },
        )
    )
    value = ReadOnlyKnowledgeBase([snapshot]).os.runtime_status(now=NOW).value
    assert value.os_name == "Linux"
    assert value.ros_domain_id == 7
    assert value.ros_distro == "humble"
    assert "processes" not in value.model_dump()
