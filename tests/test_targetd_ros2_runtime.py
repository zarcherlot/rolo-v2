import json
from threading import Event, Thread

import pytest

from rolo.dsl.canonical import context_digest, dsl_digest
from rolo.dsl.parser import parse_document
from rolo.targetd import DslFrame, TargetdDslService, ros2_registry
from rolo.targetd.daemon import load_ros2_dsl_runtime
from rolo.targetd.ros2_runtime import (
    Ros2RuntimeResolver,
    Ros2RuntimeSnapshot,
    parse_ros2_nodes,
    parse_ros2_topic_list,
    parse_ros2_topic_types,
    snapshot_from_cli_output,
)
from rolo.targetd.runtime_backend import Ros2ReadOnlyExecutor

EVIDENCE_DIGEST = "sha256:" + "e" * 64


def confirmed_targetd_service(
    tmp_path,
    mapping_confirmation_factory,
    dsl,
    context,
    **service_kwargs,
):
    document, report = parse_document(dsl)
    assert document is not None and report.ok
    dd, cd = dsl_digest(document), context_digest(context)
    confirmed = mapping_confirmation_factory(dsl, context)
    service = TargetdDslService(
        tmp_path / "cache",
        confirmation_store=confirmed.store,
        **service_kwargs,
    )
    compile_payload = {
        "schema_version": "rolo-targetd-dsl-compile/v2",
        "dsl_digest": dd,
        "context_digest": cd,
        "target_fingerprint": context["target_fingerprint"],
        "journey_session_id": "journey-1",
        "confirmation_receipt_digest": confirmed.receipt.receipt_digest,
    }
    return service, confirmed, dd, cd, compile_payload


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


def test_targetd_daemon_loads_explicit_readonly_ros2_runtime(tmp_path) -> None:
    snapshot = Ros2RuntimeSnapshot(
        "humble",
        "/opt/ros/humble/bin/ros2",
        parse_ros2_topic_types(["/scan sensor_msgs/msg/LaserScan"]),
    )
    snapshot_path = tmp_path / "snapshot.json"
    snapshot_path.write_text(
        json.dumps({"snapshot": snapshot.as_dict()}),
        encoding="utf-8",
    )

    resolver, registry = load_ros2_dsl_runtime(
        snapshot_path,
        execute_readonly=True,
    )

    assert resolver is not None
    assert registry is not None
    resolved = registry.resolve(
        "OBSERVE",
        {"resource_id": "/scan", "interface_type": "sensor_msgs/msg/LaserScan"},
        required_capabilities=("read_only_topic", "ros2"),
    )
    assert resolved.backend_id == "ros2_runtime"


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


def test_targetd_records_registered_runtime_backend(tmp_path, mapping_confirmation_factory) -> None:
    dsl = {
        "tool_id": "app.state",
        "kind": "OBSERVE",
        "target": {"robot_id": "r", "evidence_digest": EVIDENCE_DIGEST},
        "binding": {"resource_id": "route:/scan", "interface_type": "sensor_msgs/msg/LaserScan"},
    }
    context = {
        "robot_id": "r",
        "target_fingerprint": "a" * 64,
        "evidence_digest": EVIDENCE_DIGEST,
        "evidence_refs": ["route:/scan"],
    }
    resolver = Ros2RuntimeResolver(Ros2RuntimeSnapshot("humble", "/opt/ros/humble/bin/ros2", parse_ros2_topic_types(["/scan sensor_msgs/msg/LaserScan"])))
    service, _confirmed, dd, cd, compile_payload = confirmed_targetd_service(
        tmp_path,
        mapping_confirmation_factory,
        dsl,
        context,
        runtime_resolver=resolver,
        backend_registry=ros2_registry(resolver, lambda _binding, _arguments: {"status": "PASS"}),
    )
    compile_payload.update(
        {
            "backend_hint": "ros2_observe",
            "required_capabilities": ["operation:OBSERVE"],
            "runtime_backend_hint": "ros2_runtime",
            "required_runtime_capabilities": ["read_only_topic", "ros2"],
        }
    )
    service.handle(
        DslFrame(
            frame_type="DSL_PUT",
            request_id="put",
            payload={
                "journey_session_id": "journey-1",
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
            payload=compile_payload,
        )
    )
    assert result.payload["status"] == "PASS"
    assert result.payload["backend_id"] == "ros2_runtime"
    assert result.payload["resolved_binding"]["resource_id"] == "/scan"
    conformance = service.handle(
        DslFrame(
            frame_type="TARGET_CONFORMANCE",
            request_id="conformance",
            payload=compile_payload,
        )
    )
    assert conformance.payload["target_conformance"] == "PASS"
    assert conformance.payload["target_conformance_report"]["t3_runtime_behavior"] == "PASS"
    assert conformance.payload["target_conformance_report"]["required_runtime_capabilities"] == ["read_only_topic", "ros2"]
    assert service.backend_registry.resolve("COMPOSE", {"steps": []}).backend_id == "workflow"
    with pytest.raises(ValueError, match="BACKEND_UNAVAILABLE"):
        service.backend_registry.resolve("INVOKE", {"resource_id": "/scan"})
    with pytest.raises(ValueError, match="BACKEND_UNAVAILABLE"):
        service.backend_registry.resolve("EXECUTE", {})


def test_target_conformance_replay_reuses_persisted_t1_t4_proofs(tmp_path, mapping_confirmation_factory) -> None:
    dsl = {
        "tool_id": "app.state",
        "kind": "OBSERVE",
        "target": {"robot_id": "r", "evidence_digest": EVIDENCE_DIGEST},
        "binding": {
            "resource_id": "route:/scan",
            "interface_type": "sensor_msgs/msg/LaserScan",
        },
    }
    context = {
        "robot_id": "r",
        "target_fingerprint": "a" * 64,
        "evidence_digest": EVIDENCE_DIGEST,
        "evidence_refs": ["route:/scan"],
    }
    resolver = Ros2RuntimeResolver(
        Ros2RuntimeSnapshot(
            "humble",
            "/opt/ros/humble/bin/ros2",
            parse_ros2_topic_types(["/scan sensor_msgs/msg/LaserScan"]),
        )
    )
    calls = 0

    def execute(_binding, _arguments):
        nonlocal calls
        calls += 1
        return {"status": "PASS", "raw": "one bounded sample"}

    service, confirmed, dd, cd, compile_payload = confirmed_targetd_service(
        tmp_path,
        mapping_confirmation_factory,
        dsl,
        context,
        runtime_resolver=resolver,
        backend_registry=ros2_registry(resolver, execute),
    )
    assert (
        service.handle(
            DslFrame(
                frame_type="DSL_PUT",
                request_id="put",
                payload={
                    "journey_session_id": "journey-1",
                    "dsl": dsl,
                    "context": context,
                    "compiler_version": "rolo-compiler/0.1",
                    "dsl_digest": dd,
                    "context_digest": cd,
                    "target_fingerprint": "a" * 64,
                },
            )
        ).payload["phase"]
        == "PUT"
    )
    assert (
        service.handle(
            DslFrame(
                frame_type="TARGET_COMPILE",
                request_id="compile",
                payload=compile_payload,
            )
        ).payload["status"]
        == "PASS"
    )
    first = service.handle(
        DslFrame(
            frame_type="TARGET_CONFORMANCE",
            request_id="conformance-1",
            payload=compile_payload,
        )
    )
    second = service.handle(
        DslFrame(
            frame_type="TARGET_CONFORMANCE",
            request_id="conformance-2",
            payload=compile_payload,
        )
    )

    assert calls == 1
    assert first.payload["conformance_cache_hit"] is False
    assert second.payload["conformance_cache_hit"] is True
    assert first.payload["target_conformance_digest"] == second.payload["target_conformance_digest"]
    report = second.payload["target_conformance_report"]
    assert report["schema_version"] == "rolo-target-conformance/v3"
    assert report["target_id"] == "r"
    assert report["target_identity_digest"] == confirmed.receipt.target_identity_digest
    assert report["dsl_digest"] == dd
    assert report["context_digest"] == cd
    assert report["compiler_backend_id"] == "ros2_observe"
    assert report["runtime_backend_id"] == "ros2_runtime"
    assert [proof["gate"] for proof in report["proofs"]] == [
        "T1",
        "T2",
        "T3",
        "T4",
    ]
    proof_dir = next((tmp_path / "cache").glob("*/target-conformance"))
    assert len(tuple(proof_dir.glob("t[1-4]-*.json"))) == 4


def test_targetd_conformance_rejects_runtime_result_without_status(tmp_path, mapping_confirmation_factory) -> None:
    dsl = {
        "tool_id": "app.state",
        "kind": "OBSERVE",
        "target": {"robot_id": "r", "evidence_digest": EVIDENCE_DIGEST},
        "binding": {"resource_id": "route:/scan", "interface_type": "sensor_msgs/msg/LaserScan"},
    }
    context = {
        "robot_id": "r",
        "target_fingerprint": "a" * 64,
        "evidence_digest": EVIDENCE_DIGEST,
        "evidence_refs": ["route:/scan"],
    }
    resolver = Ros2RuntimeResolver(Ros2RuntimeSnapshot("humble", "/opt/ros/humble/bin/ros2", parse_ros2_topic_types(["/scan sensor_msgs/msg/LaserScan"])))
    service, _confirmed, dd, cd, compile_payload = confirmed_targetd_service(
        tmp_path,
        mapping_confirmation_factory,
        dsl,
        context,
        runtime_resolver=resolver,
        backend_registry=ros2_registry(resolver, lambda _binding, _arguments: {}),
    )
    put_payload = {
        "journey_session_id": "journey-1",
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
            payload=compile_payload,
        )
    )
    result = service.handle(
        DslFrame(
            frame_type="TARGET_CONFORMANCE",
            request_id="conformance",
            payload=compile_payload,
        )
    )
    assert result.payload["target_conformance"] == "FAIL"
    assert result.payload["target_conformance_report"]["t3_runtime_behavior"] == "FAIL"
    assert "RUNTIME_BEHAVIOR_FAILED" in result.payload["target_conformance_report"]["diagnostics"]


def test_targetd_conformance_normalizes_backend_exception_to_failed_t3(tmp_path, mapping_confirmation_factory) -> None:
    dsl = {
        "tool_id": "app.state",
        "kind": "OBSERVE",
        "target": {"robot_id": "r", "evidence_digest": EVIDENCE_DIGEST},
        "binding": {"resource_id": "route:/scan", "interface_type": "sensor_msgs/msg/LaserScan"},
    }
    context = {
        "robot_id": "r",
        "target_fingerprint": "a" * 64,
        "evidence_digest": EVIDENCE_DIGEST,
        "evidence_refs": ["route:/scan"],
    }
    resolver = Ros2RuntimeResolver(Ros2RuntimeSnapshot("humble", "/opt/ros/humble/bin/ros2", parse_ros2_topic_types(["/scan sensor_msgs/msg/LaserScan"])))

    def failing_executor(_binding, _arguments):
        raise RuntimeError("target provider unavailable")

    service, _confirmed, dd, cd, compile_payload = confirmed_targetd_service(
        tmp_path,
        mapping_confirmation_factory,
        dsl,
        context,
        runtime_resolver=resolver,
        backend_registry=ros2_registry(resolver, failing_executor),
    )
    put_payload = {
        "journey_session_id": "journey-1",
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
            payload=compile_payload,
        )
    )
    result = service.handle(
        DslFrame(
            frame_type="TARGET_CONFORMANCE",
            request_id="conformance",
            payload=compile_payload,
        )
    )
    assert result.payload["target_conformance"] == "FAIL"
    assert result.payload["target_conformance_report"]["t3_runtime_behavior"] == "FAIL"
    assert any(item.startswith("RUNTIME_BEHAVIOR_FAILED:RuntimeError:") for item in result.payload["target_conformance_report"]["diagnostics"])


def test_cancelled_confirmation_blocks_conformance_before_runtime_execution(tmp_path, mapping_confirmation_factory) -> None:
    dsl = {
        "tool_id": "app.state",
        "kind": "OBSERVE",
        "target": {"robot_id": "r", "evidence_digest": EVIDENCE_DIGEST},
        "binding": {
            "resource_id": "route:/scan",
            "interface_type": "sensor_msgs/msg/LaserScan",
        },
    }
    context = {
        "robot_id": "r",
        "target_fingerprint": "a" * 64,
        "evidence_digest": EVIDENCE_DIGEST,
        "evidence_refs": ["route:/scan"],
    }
    resolver = Ros2RuntimeResolver(
        Ros2RuntimeSnapshot(
            "humble",
            "/opt/ros/humble/bin/ros2",
            parse_ros2_topic_types(["/scan sensor_msgs/msg/LaserScan"]),
        )
    )
    calls = []

    def runtime_executor(_binding, _arguments):
        calls.append(True)
        return {"status": "PASS"}

    service, confirmed, dd, cd, compile_payload = confirmed_targetd_service(
        tmp_path,
        mapping_confirmation_factory,
        dsl,
        context,
        runtime_resolver=resolver,
        backend_registry=ros2_registry(resolver, runtime_executor),
    )
    service.handle(
        DslFrame(
            frame_type="DSL_PUT",
            request_id="put",
            payload={
                "journey_session_id": "journey-1",
                "dsl": dsl,
                "context": context,
                "compiler_version": "rolo-compiler/0.1",
                "dsl_digest": dd,
                "context_digest": cd,
                "target_fingerprint": "a" * 64,
            },
        )
    )
    assert (
        service.handle(
            DslFrame(
                frame_type="TARGET_COMPILE",
                request_id="compile",
                payload=compile_payload,
            )
        ).payload["status"]
        == "PASS"
    )
    confirmed.store.cancel(
        confirmed.receipt.receipt_digest,
        decision_id="cancel-runtime",
        actor_id="operator",
        decided_at=confirmed.receipt.decided_at,
    )

    result = service.handle(
        DslFrame(
            frame_type="TARGET_CONFORMANCE",
            request_id="conformance",
            payload=compile_payload,
        )
    )
    assert result.payload["status"] == "BLOCKED"
    assert result.payload["diagnostics"] == ["MAPPING_CONFIRMATION_CANCELLED"]
    assert calls == []


def test_mapping_cancel_cannot_split_t3_from_conformance_evidence_commit(
    tmp_path,
    mapping_confirmation_factory,
) -> None:
    dsl = {
        "tool_id": "app.state",
        "kind": "OBSERVE",
        "target": {"robot_id": "r", "evidence_digest": EVIDENCE_DIGEST},
        "binding": {
            "resource_id": "route:/scan",
            "interface_type": "sensor_msgs/msg/LaserScan",
        },
    }
    context = {
        "robot_id": "r",
        "target_fingerprint": "a" * 64,
        "evidence_digest": EVIDENCE_DIGEST,
        "evidence_refs": ["route:/scan"],
    }
    resolver = Ros2RuntimeResolver(
        Ros2RuntimeSnapshot(
            "humble",
            "/opt/ros/humble/bin/ros2",
            parse_ros2_topic_types(["/scan sensor_msgs/msg/LaserScan"]),
        )
    )
    backend_started = Event()
    release_backend = Event()
    cancel_started = Event()
    cancel_done = Event()
    calls = 0
    conformance_results = []
    cancellation_results = []
    errors = []

    def runtime_executor(_binding, _arguments):
        nonlocal calls
        calls += 1
        backend_started.set()
        if not release_backend.wait(timeout=5):
            raise TimeoutError("test did not release the T3 backend")
        return {"status": "PASS", "raw": "one bounded sample"}

    service, confirmed, dd, cd, compile_payload = confirmed_targetd_service(
        tmp_path,
        mapping_confirmation_factory,
        dsl,
        context,
        runtime_resolver=resolver,
        backend_registry=ros2_registry(resolver, runtime_executor),
    )
    put = DslFrame(
        frame_type="DSL_PUT",
        request_id="put",
        payload={
            "journey_session_id": "journey-1",
            "dsl": dsl,
            "context": context,
            "compiler_version": "rolo-compiler/0.1",
            "dsl_digest": dd,
            "context_digest": cd,
            "target_fingerprint": "a" * 64,
        },
    )
    assert service.handle(put).payload["phase"] == "PUT"
    assert service.handle(
        DslFrame(
            frame_type="TARGET_COMPILE",
            request_id="compile",
            payload=compile_payload,
        )
    ).payload["status"] == "PASS"

    def run_conformance() -> None:
        try:
            conformance_results.append(
                service.handle(
                    DslFrame(
                        frame_type="TARGET_CONFORMANCE",
                        request_id="conformance",
                        payload=compile_payload,
                    )
                )
            )
        except Exception as exc:  # pragma: no cover - diagnostic for thread failure
            errors.append(exc)

    def cancel_mapping() -> None:
        cancel_started.set()
        try:
            cancellation_results.append(
                confirmed.store.cancel(
                    confirmed.receipt.receipt_digest,
                    decision_id="cancel-during-t3",
                    actor_id="operator",
                )
            )
        except Exception as exc:  # pragma: no cover - diagnostic for thread failure
            errors.append(exc)
        finally:
            cancel_done.set()

    conformance_thread = Thread(target=run_conformance)
    conformance_thread.start()
    assert backend_started.wait(timeout=5)
    cancellation_thread = Thread(target=cancel_mapping)
    cancellation_thread.start()
    assert cancel_started.wait(timeout=5)
    assert not cancel_done.wait(timeout=0.1)

    release_backend.set()
    conformance_thread.join(timeout=5)
    cancellation_thread.join(timeout=5)
    assert not conformance_thread.is_alive()
    assert not cancellation_thread.is_alive()
    assert errors == []
    assert calls == 1
    assert conformance_results[0].payload["target_conformance"] == "PASS"
    assert cancellation_results[0].decision == "CANCELLED"
    proof_dir = next((tmp_path / "cache").glob("*/target-conformance"))
    assert (proof_dir / "result.json").is_file()
    assert len(tuple(proof_dir.glob("t[1-4]-*.json"))) == 4


def test_ros2_readonly_executor_uses_fixed_observed_topic_argv() -> None:
    resolver = Ros2RuntimeResolver(Ros2RuntimeSnapshot("humble", "/opt/ros/humble/bin/ros2", parse_ros2_topic_types(["/odom nav_msgs/msg/Odometry"])))
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
    assert calls[0][0] == [
        "/opt/ros/humble/bin/ros2",
        "topic",
        "echo",
        "--no-daemon",
        "--spin-time",
        "5",
        "--once",
        "/odom",
    ]
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
