from datetime import datetime, timezone

from rolo.core.models import DiscoveryStatus, ProbeResult, RouteEvidence
from rolo.stages.probe.application import (
    APPLICATION_IDS,
    ApplicationAdapterBundle,
    application_operation_candidate_sha256,
    build_application_adapter_bundle,
    build_application_operation_adapter_bundle,
    conform_application_bundle,
    conform_application_operation_bundle,
    discover_application_candidate,
    discover_application_operation,
)
from rolo.stages.probe.target_evidence import TargetEvidenceBundle


def _route(
    resource_id: str,
    kind: str,
    endpoint: str,
    interface_type: str | None = None,
) -> RouteEvidence:
    return RouteEvidence(
        resource_id=resource_id,
        kind=kind,  # type: ignore[arg-type]
        endpoint=endpoint,
        interface_type=interface_type,
        evidence_origin="OBSERVED_RUNTIME",
        source="test:runtime",
        observed_at=datetime.now(timezone.utc),
    )


def _bundle(*routes: RouteEvidence) -> TargetEvidenceBundle:
    probe = ProbeResult(
        layer="ros",
        status=DiscoveryStatus.PARTIAL,
        data={"route_evidence": [route.model_dump(mode="json") for route in routes]},
    )
    return TargetEvidenceBundle(
        robot_id="testbot",
        source_id="source-test",
        target_host_fingerprint="1" * 64,
        request_nonce="2" * 32,
        requested_layers=["ros"],
        collected_at=datetime.now(timezone.utc),
        probes={"ros": probe},
        payload_sha256="3" * 64,
        signature_hmac_sha256="4" * 64,
    )


def test_four_application_families_are_deterministic_and_bounded() -> None:
    evidence = _bundle(
        _route("ros_service:/startup/init_finish", "ros_service", "/startup/init_finish"),
        _route(
            "ros_topic:/controller/cmd_vel",
            "ros_topic",
            "/controller/cmd_vel",
            "geometry_msgs/msg/Twist",
        ),
        _route("ros_topic:/odom", "ros_topic", "/odom", "nav_msgs/msg/Odometry"),
        _route("ros_topic:/scan", "ros_topic", "/scan", "sensor_msgs/msg/LaserScan"),
        _route(
            "ros_action:/arm_controller/follow_joint_trajectory",
            "ros_action",
            "/arm_controller/follow_joint_trajectory",
            "control_msgs/action/FollowJointTrajectory",
        ),
    )

    statuses = {
        application: discover_application_candidate(evidence, application).status
        for application in APPLICATION_IDS
    }

    assert statuses == {
        "startup": "CANDIDATE",
        "navigation": "CANDIDATE",
        "mapping": "NOT_FOUND",
        "manipulation": "CANDIDATE",
    }


def test_adapter_bundle_conformance_is_independent_and_read_only() -> None:
    evidence = _bundle(
        _route("ros_service:/startup/init_finish", "ros_service", "/startup/init_finish"),
    )
    candidate = discover_application_candidate(evidence, "startup")
    adapter = build_application_adapter_bundle(
        candidate,
        target_evidence_sha256=evidence.payload_sha256,
    )
    report = conform_application_bundle(adapter, candidate, evidence)
    assert report.status == "PASS"
    assert all(check.status == "PASS" for check in report.checks)

    tampered = adapter.model_copy(
        update={
            "routes": [
                adapter.routes[0].model_copy(update={"evidence_origin": "DECLARED_STATIC"})
            ]
        }
    )
    rejected = conform_application_bundle(tampered, candidate, evidence)
    assert rejected.status == "FAIL"
    assert (
        next(check for check in rejected.checks if check.name == "runtime_route_bindings").status
        == "FAIL"
    )


def test_missing_mapping_signal_still_produces_a_rejected_bundle() -> None:
    evidence = _bundle()
    candidate = discover_application_candidate(evidence, "mapping")
    adapter = build_application_adapter_bundle(
        candidate,
        target_evidence_sha256=evidence.payload_sha256,
    )
    assert isinstance(adapter, ApplicationAdapterBundle)
    assert adapter.routes == []
    assert conform_application_bundle(adapter, candidate, evidence).status == "FAIL"


def test_operation_slice_binds_minimal_routes_and_defers_writes() -> None:
    evidence = _bundle(
        _route("ros_topic:/cmd_vel", "ros_topic", "/cmd_vel", "geometry_msgs/msg/Twist"),
        _route("ros_topic:/odom", "ros_topic", "/odom", "nav_msgs/msg/Odometry"),
    )
    candidate = discover_application_operation(evidence, "app.navigation.status")
    assert candidate.status == "CANDIDATE"
    adapter = build_application_operation_adapter_bundle(
        candidate,
        target_evidence_sha256=evidence.payload_sha256,
    )
    assert len(adapter.routes) == 2
    assert adapter.candidate_sha256 == application_operation_candidate_sha256(candidate)
    assert conform_application_operation_bundle(adapter, candidate, evidence).status == "PASS"

    deferred = discover_application_operation(evidence, "app.navigation.start")
    assert deferred.status == "DEFERRED"
    deferred_bundle = build_application_operation_adapter_bundle(
        deferred,
        target_evidence_sha256=evidence.payload_sha256,
    )
    assert deferred_bundle.access == "DEFERRED_WRITE"
    assert (
        conform_application_operation_bundle(deferred_bundle, deferred, evidence).status
        == "FAIL"
    )


def test_operation_slice_reports_unmapped_read_as_not_callable() -> None:
    evidence = _bundle()
    candidate = discover_application_operation(evidence, "app.safety.status")
    assert candidate.status == "UNSUPPORTED"
    assert candidate.access == "unknown"
    adapter = build_application_operation_adapter_bundle(
        candidate,
        target_evidence_sha256=evidence.payload_sha256,
    )
    assert adapter.access == "UNSUPPORTED"
