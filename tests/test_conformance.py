import base64
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from rolo.core.artifacts import ArtifactStore
from rolo.core.hashing import sha256_bytes, sha256_file
from rolo.core.models import OperationCandidate, ProbeResult, RouteEvidence, utc_now
from rolo.core.registry import RobotRegistry
from rolo.stages.adapt.active_discovery import ActiveDiscoveryInputs, ActiveProbeMode
from rolo.stages.adapt.conformance import (
    AdapterPromotionService,
    _validate_native_tool_bindings,
    validate_adapter_handoff,
)
from rolo.stages.adapt.discovery import DiscoveryService, load_report
from rolo.stages.adapt.models import AdapterAgentResult, AdapterAgentRun, AdaptGateReport
from rolo.stages.adapt.operation_registry import (
    canonical_operation_registry,
    required_adapter_agent_conformance_operations,
)
from rolo.stages.adapt.routes import candidate_route_observed


def _native_handoff(**updates: object) -> SimpleNamespace:
    values: dict[str, object] = {
        "native_tool_rollout_ref": None,
        "native_tool_rollout_sha256": None,
        "native_tool_summary_ref": None,
        "native_tool_summary_sha256": None,
        "native_tool_gate_ref": None,
        "native_tool_gate_sha256": None,
        "native_tool_execution_parity_ref": None,
        "native_tool_execution_parity_sha256": None,
        "native_tool_session_id": None,
        "robot_id": "robot-1",
        "source_agent_run_id": "run-1",
    }
    values.update(updates)
    return SimpleNamespace(**values)


def test_native_execution_parity_reference_and_digest_are_atomic(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="execution parity reference and hash"):
        _validate_native_tool_bindings(
            tmp_path,
            _native_handoff(native_tool_execution_parity_ref="artifact://parity.json"),
        )

    with pytest.raises(ValueError, match="execution parity reference and hash"):
        _validate_native_tool_bindings(
            tmp_path,
            _native_handoff(native_tool_execution_parity_sha256="a" * 64),
        )


def test_native_execution_parity_cannot_float_without_rollout_and_summary(
    tmp_path: Path,
) -> None:
    with pytest.raises(ValueError, match="execution parity requires rollout and summary refs"):
        _validate_native_tool_bindings(
            tmp_path,
            _native_handoff(
                native_tool_execution_parity_ref="artifact://parity.json",
                native_tool_execution_parity_sha256="a" * 64,
            ),
        )


def test_adapt_gate_report_reads_legacy_validation_scope() -> None:
    report = AdaptGateReport.model_validate(
        {
            "schema_version": "robot-adapt-gate/v1",
            "run_id": "run-legacy",
            "robot_id": "robot-1",
            "discovery_id": "disc-1",
            "status": "PASSED",
            "checks": [],
            "error": None,
            "validation_scope": "TARGET_RUNTIME_READONLY",
        }
    )

    assert report.status == "PASSED"
    assert "validation_scope" not in report.model_dump(mode="json")


def _prepare_promotion(
    artifact_root: Path,
    workspace: Path,
    *,
    include_write_operation: bool = False,
    runtime_ready: bool = True,
    route_observed: bool = True,
) -> tuple[str, AdapterAgentRun]:
    (workspace / "pyproject.toml").write_text(
        '[project]\nname = "demo-adapter"\n\n[project.scripts]\ndemo-adapter = "demo:main"\n',
        encoding="utf-8",
    )
    if include_write_operation:
        (workspace / "driver.py").write_text(
            'node.create_publisher(Twist, "/cmd_vel", 10)\n', encoding="utf-8"
        )
    registry = RobotRegistry(Path("tests/fixtures/robots"))
    registry.load()
    ros_probe = ProbeResult(
        layer="ros",
        status="SUCCEEDED" if runtime_ready else "UNAVAILABLE",
        data={
            "ros_distro": "test",
            "installed_distros": ["test"],
            "domain_id": "0",
            "rmw": "test",
            "nodes": [],
            "topics": (
                ["/cmd_vel [geometry_msgs/msg/Twist]"]
                if runtime_ready and route_observed
                else ["/cmd_vel_extra [geometry_msgs/msg/Twist]"]
                if runtime_ready
                else []
            ),
            "services": [],
            "actions": [],
        },
    )
    binding = {
        "robot_id": "demo_diff",
        "source_id": "source-test",
        "target_host_fingerprint": "f" * 64,
        "bundle_payload_sha256": "a" * 64,
        "access": "READ_ONLY",
        "deployment_mode": "local",
    }
    target_probes = {
        "hw": ProbeResult(
            layer="hw",
            status="SUCCEEDED",
            data={"components": [], "target_evidence": binding},
        ),
        "linux": ProbeResult(
            layer="linux", status="SUCCEEDED", data={"target_evidence": binding}
        ),
        "ros": ros_probe.model_copy(
            update={"data": {**ros_probe.data, "target_evidence": binding}}
        ),
    }
    report, _ = DiscoveryService(ArtifactStore(artifact_root)).run(
        robot=registry.get("demo_diff"),
        urdf_path=Path("tests/fixtures/profiles/differential_drive.urdf"),
        active_inputs=ActiveDiscoveryInputs(
            source_roots=[workspace], active_probe=ActiveProbeMode.RUNTIME_READONLY
        ),
        target_probes=target_probes,
    )
    definitions = {
        item.operation: item for item in canonical_operation_registry().operations
    }
    bundle_operations = [
        {
            "operation": candidate.operation,
            "entrypoint": candidate.operation.replace(".", "_"),
            "contract_version": definitions[candidate.operation].contract_version,
            "contract_sha256": definitions[candidate.operation].contract_sha256,
        }
        for candidate in report.operation_candidates
    ]
    operation_map = {item["operation"]: item["entrypoint"] for item in bundle_operations}
    support_path = workspace / "adapter_support.py"
    support_path.write_text(
        f"OPERATIONS = {operation_map!r}\n",
        encoding="utf-8",
    )
    package_path = workspace / "demo_adapter.py"
    package_path.write_text(
        "import json, sys\n"
        "from adapter_support import OPERATIONS\n"
        "if sys.argv[1] == 'describe':\n"
        "    print(json.dumps({'operations': OPERATIONS}))\n"
        "elif sys.argv[1] == 'invoke':\n"
        "    args = dict(zip(sys.argv[2::2], sys.argv[3::2]))\n"
        "    operation = args.get('--operation')\n"
        "    if operation not in OPERATIONS or args.get('--entrypoint') != OPERATIONS[operation]:\n"
        "        print(json.dumps({'error': {'code': 'INVALID_INPUT'}}))\n"
        "        raise SystemExit(1)\n"
        "    print(json.dumps({'status': 'SUCCEEDED'}))\n",
        encoding="utf-8",
    )
    (workspace / "adapter-manifest.json").write_text(
        json.dumps(
            {
                "schema_version": "robot-adapter-bundle/v2",
                "bundle_id": "demo-adapter",
                "bundle_version": "1.0.0",
                "robot_id": "demo_diff",
                "discovery_id": report.discovery_id,
                "runtime_protocol": "robot-adapter-rpc/v1",
                "package_file": package_path.name,
                "package_sha256": sha256_file(package_path),
                "files": [
                    {
                        "path": package_path.name,
                        "sha256": sha256_file(package_path),
                        "role": "ENTRYPOINT",
                    },
                    {
                        "path": support_path.name,
                        "sha256": sha256_file(support_path),
                        "role": "SUPPORT",
                    },
                ],
                "operations": bundle_operations,
            }
        ),
        encoding="utf-8",
    )
    (workspace / "state_graph.json").write_text(
        json.dumps(
            {
                "schema_version": "robot-state-graph/v1",
                "robot_id": "demo_diff",
                "discovery_id": report.discovery_id,
                "nodes": [],
                "edges": [],
            }
        ),
        encoding="utf-8",
    )
    operations = []
    for operation in sorted(required_adapter_agent_conformance_operations(report)):
        operations.append(
            {
                "operation": operation,
                "schema_valid": True,
                "errors_valid": True,
                "idempotency_valid": True,
                "cancellation_valid": True,
                "validation_scopes": ["LOCAL_STATIC"],
                "evidence": ["artifact://evidence/result.json"],
            }
        )
    (workspace / "conformance.json").write_text(
        json.dumps(
            {
                "schema_version": "robot-adapter-conformance/v3",
                "robot_id": "demo_diff",
                "discovery_id": report.discovery_id,
                "operations": operations,
            }
        ),
        encoding="utf-8",
    )
    result = AdapterAgentResult(
        schema_version="robot-adapter-agent-result/v1",
        summary="adapter outputs prepared",
        completed_tasks=[],
        changed_files=[],
        validation=[],
        blockers=[],
        handoff_ready=True,
        outputs={
            "adapter_manifest": "adapter-manifest.json",
            "adapter_package": "demo_adapter.py",
            "state_graph": "state_graph.json",
            "conformance_report": "conformance.json",
        },
        files=[],
    )
    store = ArtifactStore(artifact_root)
    result_path = store.write_json(
        "adapt/demo_diff/runs/run-test/result.json",
        result.model_dump(mode="json"),
    )
    now = utc_now()
    run = AdapterAgentRun(
        run_id="run-test",
        robot_id="demo_diff",
        source_discovery_id=report.discovery_id,
        provider="codex",
        status="SUCCEEDED",
        workspace=str(workspace),
        command=["codex", "exec"],
        prompt_ref="artifact://prompt",
        event_log_ref="artifact://events",
        stderr_ref="artifact://stderr",
        final_message_ref="artifact://final",
        result_ref=f"artifact://{result_path.relative_to(artifact_root).as_posix()}",
        started_at=now,
        completed_at=now,
        duration_s=0,
    )
    return report.discovery_id, run


@pytest.mark.parametrize(
    ("kind", "layer", "endpoint", "interface_type", "probe_data"),
    [
        (
            "ros_topic",
            "ros",
            "/camera/image_raw",
            "sensor_msgs/msg/Image",
            {"topics": ["/camera/image_raw [sensor_msgs/msg/Image]"]},
        ),
        (
            "ros_service",
            "ros",
            "/camera/capture",
            "std_srvs/srv/Trigger",
            {"services": ["/camera/capture [std_srvs/srv/Trigger]"]},
        ),
        (
            "ros_action",
            "ros",
            "/navigate_to_pose",
            "nav2_msgs/action/NavigateToPose",
            {"actions": ["/navigate_to_pose [nav2_msgs/action/NavigateToPose]"]},
        ),
        (
            "device",
            "hw",
            "/dev/video0",
            "camera",
            {
                "devices": [
                    {
                        "path": "/dev/video0",
                        "category": "camera",
                        "driver": "uvcvideo",
                    }
                ]
            },
        ),
        (
            "cli",
            "linux",
            "ros2",
            None,
            {
                "executables": {
                    "ros2": {
                        "path": "/opt/ros/test/bin/ros2",
                        "available": True,
                        "version_output": ["ros2 test"],
                    }
                }
            },
        ),
    ],
)
def test_candidate_route_matching_covers_every_route_kind(
    kind: str,
    layer: str,
    endpoint: str,
    interface_type: str | None,
    probe_data: dict[str, object],
) -> None:
    route = RouteEvidence(
        resource_id=f"{kind}:{endpoint}",
        kind=kind,
        endpoint=endpoint,
        interface_type=interface_type,
        provider_id="uvcvideo" if kind == "device" else None,
        evidence_origin="DECLARED_STATIC",
        source="test-fixture",
    )
    candidate = OperationCandidate(operation="app.camera.snapshot", route_evidence=[route])
    probe = ProbeResult(layer=layer, status="SUCCEEDED", data=probe_data)

    assert candidate_route_observed(candidate, {layer: probe})


def test_candidate_route_matching_rejects_interface_or_schema_mismatch() -> None:
    expected = RouteEvidence(
        resource_id="ros_topic:/camera/image_raw",
        kind="ros_topic",
        endpoint="/camera/image_raw",
        interface_type="sensor_msgs/msg/Image",
        interface_schema_sha256="a" * 64,
        provider_id="camera-node",
        runtime_revision="runtime-1",
        evidence_origin="DECLARED_STATIC",
        source="test-fixture",
    )
    observed = expected.model_copy(
        update={
            "interface_type": "sensor_msgs/msg/CompressedImage",
            "evidence_origin": "OBSERVED_RUNTIME",
        }
    )
    candidate = OperationCandidate(operation="app.camera.snapshot", route_evidence=[expected])
    probe = ProbeResult(
        layer="ros",
        status="SUCCEEDED",
        data={"route_evidence": [observed.model_dump(mode="json")]},
    )

    assert not candidate_route_observed(candidate, {"ros": probe})


def test_route_evidence_v1_is_migrated_at_the_model_boundary() -> None:
    route = RouteEvidence.model_validate(
        {
            "kind": "ros_topic",
            "name": "odom",
            "source": "live_ros_graph",
            "observed": True,
        }
    )

    assert route.schema_version == "robot-route-evidence/v2"
    assert route.resource_id == "ros_topic:/odom"
    assert route.endpoint == "/odom"
    assert route.observed


def test_promotion_publishes_only_independently_validated_handoff(tmp_path: Path) -> None:
    artifact_root = tmp_path / "artifacts"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    discovery_id, run = _prepare_promotion(artifact_root, workspace)

    service = AdapterPromotionService(ArtifactStore(artifact_root), tmp_path / "output")
    snapshot, _ = service.snapshot(run)
    assert not hasattr(snapshot, "tool_catalog_ref")
    frozen_graph = json.loads(
        (
            artifact_root
            / "adapt/demo_diff/runs/run-test/output-snapshot/state-graph.json"
        ).read_text(encoding="utf-8")
    )
    assert frozen_graph["schema_version"] == "robot-state-graph/v2"
    assert frozen_graph["owner"] == "ROLO_GATE"
    assert any(item["kind"] == "operation" for item in frozen_graph["nodes"])
    handoff, path, _, _ = service.promote_run(run, snapshot)
    discovery = load_report(artifact_root, "demo_diff", discovery_id)
    observed_routes = discovery.probes["ros"].data["route_evidence"]

    assert path.is_file()
    assert observed_routes
    assert all(route["schema_version"] == "robot-route-evidence/v2" for route in observed_routes)
    assert all(route["evidence_origin"] == "OBSERVED_RUNTIME" for route in observed_routes)
    assert handoff.source_discovery_id == discovery_id
    assert (
        validate_adapter_handoff(artifact_root, "demo_diff", output_root=tmp_path / "output")
        == handoff
    )
    assert (tmp_path / "output/robots/demo_diff/current.json").is_file()
    release_root = tmp_path / "output/robots/demo_diff/releases/run-test"
    release = json.loads((release_root / "manifest.json").read_text(encoding="utf-8"))
    assert release["schema_version"] == "robot-adapter-release/v2"
    assert {item["path"] for item in release["adapter_files"]} == {
        "adapter/demo_adapter.py",
        "adapter/adapter_support.py",
    }
    assert (release_root / "adapter/adapter_support.py").is_file()


def test_snapshot_reconstructs_structured_handoff_without_workspace_reads(
    tmp_path: Path,
) -> None:
    artifact_root = tmp_path / "artifacts"
    output_root = tmp_path / "output"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    _, run = _prepare_promotion(
        artifact_root, workspace, include_write_operation=True
    )
    names = [
        "adapter-manifest.json",
        "demo_adapter.py",
        "adapter_support.py",
        "state_graph.json",
        "conformance.json",
    ]
    files = []
    for name in names:
        payload = (workspace / name).read_bytes()
        files.append(
            {
                "path": name,
                "encoding": "base64",
                "content": base64.b64encode(payload).decode("ascii"),
                "sha256": sha256_bytes(payload),
            }
        )
    result_path = artifact_root / run.result_ref.removeprefix("artifact://")
    result = json.loads(result_path.read_text(encoding="utf-8"))
    result["schema_version"] = "robot-adapter-agent-result/v2"
    result["files"] = files
    result_path.write_text(json.dumps(result), encoding="utf-8")
    for name in names:
        (workspace / name).unlink()

    snapshot, _ = AdapterPromotionService(ArtifactStore(artifact_root), output_root).snapshot(run)

    assert snapshot.adapter_files
    package_ref = snapshot.adapter_package_ref.removeprefix("artifact://")
    assert (artifact_root / package_ref).is_file()


def test_promotion_rejects_incomplete_conformance_coverage(tmp_path: Path) -> None:
    artifact_root = tmp_path / "artifacts"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    _, run = _prepare_promotion(artifact_root, workspace)
    payload = json.loads((workspace / "conformance.json").read_text(encoding="utf-8"))
    payload["operations"].pop()
    (workspace / "conformance.json").write_text(json.dumps(payload), encoding="utf-8")

    service = AdapterPromotionService(ArtifactStore(artifact_root), tmp_path / "output")
    with pytest.raises(ValueError, match="coverage"):
        snapshot, _ = service.snapshot(run)
        service.promote_run(run, snapshot)


def test_snapshot_rejects_tampered_bundle_support_file(tmp_path: Path) -> None:
    artifact_root = tmp_path / "artifacts"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    _, run = _prepare_promotion(artifact_root, workspace)
    (workspace / "adapter_support.py").write_text("tampered\n", encoding="utf-8")

    service = AdapterPromotionService(ArtifactStore(artifact_root), tmp_path / "output")
    with pytest.raises(ValueError, match="file digest mismatch"):
        service.snapshot(run)


def test_promotion_rejects_agent_attestation_for_rolo_builtin(tmp_path: Path) -> None:
    artifact_root = tmp_path / "artifacts"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    _, run = _prepare_promotion(artifact_root, workspace)
    payload = json.loads((workspace / "conformance.json").read_text(encoding="utf-8"))
    payload["operations"].append(
        {
            "operation": "runtime.health",
            "schema_valid": True,
            "errors_valid": True,
            "idempotency_valid": True,
            "cancellation_valid": True,
            "validation_scopes": ["LOCAL_STATIC"],
            "evidence": [],
        }
    )
    (workspace / "conformance.json").write_text(json.dumps(payload), encoding="utf-8")
    service = AdapterPromotionService(ArtifactStore(artifact_root), tmp_path / "output")
    snapshot, _ = service.snapshot(run)

    with pytest.raises(ValueError, match="bundle candidates"):
        service.promote_run(run, snapshot)


def test_promotion_uses_frozen_snapshot_after_workspace_changes(tmp_path: Path) -> None:
    artifact_root = tmp_path / "artifacts"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    _, run = _prepare_promotion(artifact_root, workspace)
    service = AdapterPromotionService(ArtifactStore(artifact_root), tmp_path / "output")
    snapshot, _ = service.snapshot(run)

    (workspace / "state_graph.json").write_text("{}", encoding="utf-8")
    (workspace / "conformance.json").write_text("{}", encoding="utf-8")

    handoff, path, gate, _ = service.promote_run(run, snapshot)

    assert path.is_file()
    assert gate.status == "PASSED"
    assert handoff.source_agent_run_id == run.run_id


def test_v1_conformance_runtime_and_physical_claims_are_ignored(
    tmp_path: Path,
) -> None:
    artifact_root = tmp_path / "artifacts"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    _, run = _prepare_promotion(artifact_root, workspace, include_write_operation=True)
    service = AdapterPromotionService(ArtifactStore(artifact_root), tmp_path / "output")

    payload = json.loads((workspace / "conformance.json").read_text(encoding="utf-8"))
    payload["schema_version"] = "robot-adapter-conformance/v1"
    for operation in payload["operations"]:
        operation["physical_result_valid"] = False
        operation["safety_valid"] = False
        operation["validation_scopes"] = ["LOCAL_STATIC", "TARGET_RUNTIME", "PHYSICAL"]
    (workspace / "conformance.json").write_text(json.dumps(payload), encoding="utf-8")
    snapshot, _ = service.snapshot(run)

    _, _, gate, _ = service.promote_run(run, snapshot)

    assert gate.status == "PASSED"
    assert "product-owned operation contracts" in gate.checks
    assert "Rolo-owned builtin operation contracts" in gate.checks
    assert "Adapter Agent bundle local-static declarations (advisory)" in gate.checks
    assert "target route existence without outcome execution" in gate.checks


def test_runtime_presence_without_candidate_route_cannot_be_promoted(tmp_path: Path) -> None:
    artifact_root = tmp_path / "artifacts"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    _, run = _prepare_promotion(
        artifact_root,
        workspace,
        include_write_operation=True,
        route_observed=False,
    )
    service = AdapterPromotionService(ArtifactStore(artifact_root), tmp_path / "output")
    with pytest.raises(ValueError, match="no target-observed"):
        service.snapshot(run)


def test_unavailable_runtime_probe_cannot_be_promoted_by_agent_claim(
    tmp_path: Path,
) -> None:
    artifact_root = tmp_path / "artifacts"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    _, run = _prepare_promotion(
        artifact_root, workspace, include_write_operation=True, runtime_ready=False
    )
    service = AdapterPromotionService(ArtifactStore(artifact_root), tmp_path / "output")
    with pytest.raises(ValueError, match="no target-observed"):
        service.snapshot(run)


def test_failed_handoff_validation_removes_unactivated_release(tmp_path: Path) -> None:
    artifact_root = tmp_path / "artifacts"
    output_root = tmp_path / "output"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    _, run = _prepare_promotion(artifact_root, workspace)
    service = AdapterPromotionService(ArtifactStore(artifact_root), output_root)
    snapshot, _ = service.snapshot(run)

    with (
        patch(
            "rolo.stages.adapt.conformance.validate_adapter_handoff",
            side_effect=ValueError("forced handoff failure"),
        ),
        pytest.raises(ValueError, match="forced handoff failure"),
    ):
        service.promote_run(run, snapshot)

    assert not (output_root / "robots/demo_diff/releases/run-test").exists()
    assert not (output_root / "robots/demo_diff/current.json").exists()


def test_failure_after_activation_restores_both_indexes(tmp_path: Path) -> None:
    artifact_root = tmp_path / "artifacts"
    output_root = tmp_path / "output"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    _, run = _prepare_promotion(artifact_root, workspace)
    service = AdapterPromotionService(ArtifactStore(artifact_root), output_root)
    snapshot, _ = service.snapshot(run)

    with (
        patch(
            "rolo.stages.adapt.conformance.validate_adapter_handoff",
            side_effect=[None, ValueError("forced post-activation failure")],
        ),
        pytest.raises(ValueError, match="post-activation failure"),
    ):
        service.promote_run(run, snapshot)

    assert not (output_root / "robots/demo_diff/current.json").exists()
    assert not (artifact_root / "adapt/demo_diff/latest.json").exists()
    assert not (output_root / "robots/demo_diff/releases/run-test").exists()
