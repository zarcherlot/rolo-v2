import pytest

from rolo.dsl.canonical import context_digest, dsl_digest
from rolo.dsl.parser import parse_document
from rolo.targetd import DslFrame, TargetdDslService, ros2_registry
from rolo.targetd.ros2_runtime import (
    Ros2RuntimeResolver,
    Ros2RuntimeSnapshot,
    parse_ros2_nodes,
    parse_ros2_topic_list,
    parse_ros2_topic_types,
    snapshot_from_cli_output,
)
from rolo.targetd.runtime_backend import Ros2ReadOnlyExecutor


def test_ros2_topic_parser_is_stable_and_ignores_diagnostics() -> None:
    topics = parse_ros2_topic_types(
        [
            "/scan sensor_msgs/msg/LaserScan",
            "warning from ros2",
            "/cmd_vel geometry_msgs/msg/Twist",
            "/scan sensor_msgs/msg/LaserScan",
        ]
    )
    assert [(topic.name, topic.interface_type) for topic in topics] == [
        ("/cmd_vel", "geometry_msgs/msg/Twist"),
        ("/scan", "sensor_msgs/msg/LaserScan"),
    ]


def test_ros2_node_parser_is_stable() -> None:
    assert parse_ros2_nodes(["/robot_api", "", "diagnostic", "/robot_api"]) == ("/robot_api",)


def test_ros2_topic_list_parser_accepts_cli_type_rows_only() -> None:
    topics = parse_ros2_topic_list(
        [
            "/odom [nav_msgs/msg/Odometry]",
            "/scan [sensor_msgs/msg/LaserScan]",
            "diagnostic",
            "/scan [sensor_msgs/msg/LaserScan]",
            "/broken [not-a-type]",
        ]
    )
    assert [(topic.name, topic.interface_type) for topic in topics] == [
        ("/odom", "nav_msgs/msg/Odometry"),
        ("/scan", "sensor_msgs/msg/LaserScan"),
    ]


def test_ros2_runtime_snapshot_and_resolver_are_digest_stable() -> None:
    topics = parse_ros2_topic_types(["/scan sensor_msgs/msg/LaserScan", "/cmd_vel geometry_msgs/msg/Twist"])
    first = Ros2RuntimeSnapshot("humble", "/opt/ros/humble/bin/ros2", topics, ("/robot_api",), ("rclpy",))
    second = Ros2RuntimeSnapshot("humble", "/opt/ros/humble/bin/ros2", tuple(reversed(topics)), ("/robot_api",), ("rclpy",))
    assert first.runtime_digest == second.runtime_digest
    resolved = Ros2RuntimeResolver(first).resolve_binding({"resource_id": "/scan", "interface_type": "sensor_msgs/msg/LaserScan"})
    assert resolved["evidence_origin"] == "OBSERVED_RUNTIME"


def test_snapshot_from_cli_output_preserves_only_observed_records() -> None:
    snapshot = snapshot_from_cli_output(
        distro=" humble ",
        ros2_path=" /opt/ros/humble/bin/ros2 ",
        topic_lines=["/odom [nav_msgs/msg/Odometry]", "diagnostic"],
        node_lines=["/odom_publisher", "not-a-node"],
        package_lines=["nav_msgs", "", "rclpy", "nav_msgs"],
    )
    assert snapshot.distro == "humble"
    assert snapshot.nodes == ("/odom_publisher",)
    assert snapshot.packages == ("nav_msgs", "rclpy")
    payload = snapshot.as_dict()
    assert payload["runtime_digest"] == snapshot.runtime_digest
    assert payload["topics"] == [{"name": "/odom", "interface_type": "nav_msgs/msg/Odometry"}]


def test_snapshot_keeps_execution_identity_for_dds_diagnostics() -> None:
    snapshot = snapshot_from_cli_output(
        distro="humble",
        ros2_path="/opt/ros/humble/bin/ros2",
        topic_lines=["/odom [nav_msgs/msg/Odometry]"],
        executor_user="root",
        publisher_user="ubuntu",
        rmw_implementation="rmw_fastrtps_cpp",
    )
    assert snapshot.executor_user == "root"
    assert snapshot.publisher_user == "ubuntu"
    assert snapshot.rmw_implementation == "rmw_fastrtps_cpp"
    assert snapshot.as_dict()["publisher_user"] == "ubuntu"
    assert snapshot.runtime_digest.startswith("sha256:")


def test_ros2_runtime_resolver_rejects_unobserved_or_mismatched_topic() -> None:
    snapshot = Ros2RuntimeSnapshot(
        "humble",
        "/opt/ros/humble/bin/ros2",
        parse_ros2_topic_types(["/scan sensor_msgs/msg/LaserScan"]),
    )
    resolver = Ros2RuntimeResolver(snapshot)
    with pytest.raises(ValueError, match="RESOURCE_NOT_OBSERVED"):
        resolver.resolve_topic("/missing")
    with pytest.raises(ValueError, match="MESSAGE_SCHEMA_MISMATCH"):
        resolver.resolve_topic("/scan", interface_type="nav_msgs/msg/Odometry")


def test_targetd_records_registered_runtime_backend(tmp_path) -> None:
    dsl = {
        "tool_id": "app.state",
        "kind": "OBSERVE",
        "target": {"robot_id": "r", "evidence_digest": "sha256:e"},
        "binding": {"resource_id": "route:/scan", "interface_type": "sensor_msgs/msg/LaserScan"},
    }
    context = {
        "robot_id": "r",
        "target_fingerprint": "a" * 64,
        "evidence_digest": "sha256:e",
        "evidence_refs": ["route:/scan"],
    }
    document, _ = parse_document(dsl)
    resolver = Ros2RuntimeResolver(
        Ros2RuntimeSnapshot("humble", "/opt/ros/humble/bin/ros2", parse_ros2_topic_types(["/scan sensor_msgs/msg/LaserScan"]))
    )
    service = TargetdDslService(
        tmp_path,
        runtime_resolver=resolver,
        backend_registry=ros2_registry(resolver, lambda _binding, _arguments: {"status": "PASS"}),
    )
    dd, cd = dsl_digest(document), context_digest(context)
    service.handle(
        DslFrame(
            frame_type="DSL_PUT",
            request_id="put",
            payload={
                "dsl": dsl,
                "context": context,
                "compiler_version": "rolo-compiler/0.1",
                "dsl_digest": dd,
                "context_digest": cd,
                "target_fingerprint": "a" * 64,
            },
        )
    )
    result = service.handle(
        DslFrame(
            frame_type="TARGET_COMPILE",
            request_id="compile",
            payload={"dsl_digest": dd, "context_digest": cd, "target_fingerprint": "a" * 64},
        )
    )
    assert result.payload["status"] == "PASS"
    assert result.payload["backend_id"] == "ros2_runtime"
    assert result.payload["resolved_binding"]["resource_id"] == "/scan"
    conformance = service.handle(
        DslFrame(
            frame_type="TARGET_CONFORMANCE",
            request_id="conformance",
            payload={"dsl_digest": dd, "context_digest": cd, "target_fingerprint": "a" * 64},
        )
    )
    assert conformance.payload["target_conformance"] == "PASS"
    assert conformance.payload["target_conformance_report"]["t3_runtime_behavior"] == "PASS"
    assert service.backend_registry.resolve("COMPOSE", {"steps": []}).backend_id == "workflow"
    with pytest.raises(ValueError, match="BACKEND_UNAVAILABLE"):
        service.backend_registry.resolve("INVOKE", {"resource_id": "/scan"})
    with pytest.raises(ValueError, match="BACKEND_UNAVAILABLE"):
        service.backend_registry.resolve("EXECUTE", {})


def test_targetd_conformance_rejects_runtime_result_without_status(tmp_path) -> None:
    dsl = {
        "tool_id": "app.state",
        "kind": "OBSERVE",
        "target": {"robot_id": "r", "evidence_digest": "sha256:e"},
        "binding": {"resource_id": "route:/scan", "interface_type": "sensor_msgs/msg/LaserScan"},
    }
    context = {
        "robot_id": "r",
        "target_fingerprint": "a" * 64,
        "evidence_digest": "sha256:e",
        "evidence_refs": ["route:/scan"],
    }
    document, _ = parse_document(dsl)
    resolver = Ros2RuntimeResolver(
        Ros2RuntimeSnapshot("humble", "/opt/ros/humble/bin/ros2", parse_ros2_topic_types(["/scan sensor_msgs/msg/LaserScan"]))
    )
    service = TargetdDslService(
        tmp_path,
        runtime_resolver=resolver,
        backend_registry=ros2_registry(resolver, lambda _binding, _arguments: {}),
    )
    dd, cd = dsl_digest(document), context_digest(context)
    put_payload = {
        "dsl": dsl,
        "context": context,
        "compiler_version": "rolo-compiler/0.1",
        "dsl_digest": dd,
        "context_digest": cd,
        "target_fingerprint": "a" * 64,
    }
    service.handle(DslFrame(frame_type="DSL_PUT", request_id="put", payload=put_payload))
    service.handle(DslFrame(
        frame_type="TARGET_COMPILE",
        request_id="compile",
        payload={"dsl_digest": dd, "context_digest": cd, "target_fingerprint": "a" * 64},
    ))
    result = service.handle(DslFrame(
        frame_type="TARGET_CONFORMANCE",
        request_id="conformance",
        payload={"dsl_digest": dd, "context_digest": cd, "target_fingerprint": "a" * 64},
    ))
    assert result.payload["target_conformance"] == "FAIL"
    assert result.payload["target_conformance_report"]["t3_runtime_behavior"] == "FAIL"
    assert "RUNTIME_BEHAVIOR_FAILED" in result.payload["target_conformance_report"]["diagnostics"]


def test_targetd_conformance_normalizes_backend_exception_to_failed_t3(tmp_path) -> None:
    dsl = {
        "tool_id": "app.state",
        "kind": "OBSERVE",
        "target": {"robot_id": "r", "evidence_digest": "sha256:e"},
        "binding": {"resource_id": "route:/scan", "interface_type": "sensor_msgs/msg/LaserScan"},
    }
    context = {
        "robot_id": "r",
        "target_fingerprint": "a" * 64,
        "evidence_digest": "sha256:e",
        "evidence_refs": ["route:/scan"],
    }
    document, _ = parse_document(dsl)
    resolver = Ros2RuntimeResolver(
        Ros2RuntimeSnapshot("humble", "/opt/ros/humble/bin/ros2", parse_ros2_topic_types(["/scan sensor_msgs/msg/LaserScan"]))
    )

    def failing_executor(_binding, _arguments):
        raise RuntimeError("target provider unavailable")

    service = TargetdDslService(
        tmp_path,
        runtime_resolver=resolver,
        backend_registry=ros2_registry(resolver, failing_executor),
    )
    dd, cd = dsl_digest(document), context_digest(context)
    put_payload = {
        "dsl": dsl,
        "context": context,
        "compiler_version": "rolo-compiler/0.1",
        "dsl_digest": dd,
        "context_digest": cd,
        "target_fingerprint": "a" * 64,
    }
    service.handle(DslFrame(frame_type="DSL_PUT", request_id="put", payload=put_payload))
    service.handle(
        DslFrame(
            frame_type="TARGET_COMPILE",
            request_id="compile",
            payload={"dsl_digest": dd, "context_digest": cd, "target_fingerprint": "a" * 64},
        )
    )
    result = service.handle(
        DslFrame(
            frame_type="TARGET_CONFORMANCE",
            request_id="conformance",
            payload={"dsl_digest": dd, "context_digest": cd, "target_fingerprint": "a" * 64},
        )
    )
    assert result.payload["target_conformance"] == "FAIL"
    assert result.payload["target_conformance_report"]["t3_runtime_behavior"] == "FAIL"
    assert any(
        item.startswith("RUNTIME_BEHAVIOR_FAILED:RuntimeError:")
        for item in result.payload["target_conformance_report"]["diagnostics"]
    )


def test_ros2_readonly_executor_uses_fixed_observed_topic_argv() -> None:
    resolver = Ros2RuntimeResolver(
        Ros2RuntimeSnapshot("humble", "/opt/ros/humble/bin/ros2", parse_ros2_topic_types(["/odom nav_msgs/msg/Odometry"]))
    )
    calls = []

    class Completed:
        returncode = 0
        stdout = "header:\n  stamp:\n    sec: 1\n"
        stderr = ""

    def runner(argv, **kwargs):
        calls.append((argv, kwargs))
        return Completed()

    result = Ros2ReadOnlyExecutor(resolver, runner=runner)({"resource_id": "/odom"}, {})
    assert result["status"] == "SUCCEEDED"
    assert calls[0][0] == ["/opt/ros/humble/bin/ros2", "topic", "echo", "--no-daemon", "--once", "/odom"]
    assert calls[0][1]["timeout"] == 10.0


def test_ros2_readonly_executor_blocks_cross_user_shared_memory_false_negative() -> None:
    resolver = Ros2RuntimeResolver(
        Ros2RuntimeSnapshot(
            "humble",
            "/opt/ros/humble/bin/ros2",
            parse_ros2_topic_types(["/odom nav_msgs/msg/Odometry"]),
            publisher_user="ubuntu",
        )
    )
    result = Ros2ReadOnlyExecutor(resolver, executor_user="root", runner=lambda *_args, **_kwargs: None)({"resource_id": "/odom"}, {})
    assert result == {
        "status": "BLOCKED",
        "error": "DDS_USER_MISMATCH",
        "topic": "/odom",
        "publisher_user": "ubuntu",
        "executor_user": "root",
    }
