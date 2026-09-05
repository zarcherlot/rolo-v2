import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from rolo.cli import app
from rolo.core.artifacts import ArtifactStore
from rolo.core.config import get_settings
from rolo.core.hashing import sha256_file
from rolo.core.models import ProbeResult, utc_now
from rolo.core.registry import RobotRegistry
from rolo.stages.adapt.active_discovery import ActiveDiscoveryInputs, ActiveProbeMode
from rolo.stages.adapt.discovery import DiscoveryService, load_report
from rolo.stages.adapt.models import (
    AdapterAgentConfig,
    AdapterAgentDependencyReport,
    AdapterAgentResult,
    AdapterAgentRun,
)
from rolo.stages.adapt.operation_registry import (
    canonical_operation_registry,
    required_adapter_agent_conformance_operations,
)
from rolo.stages.adapt.service import AdaptStageService
from rolo.stages.pipeline import assess_pipeline


def discover_demo(
    artifact_root: Path, source_root: Path, *, target_runtime: bool = False
) -> str:
    (source_root / "pyproject.toml").write_text(
        '[project]\nname = "stage-demo"\n\n[project.scripts]\nstage-demo = "demo:main"\n',
        encoding="utf-8",
    )
    registry = RobotRegistry(Path("tests/fixtures/robots"))
    registry.load()
    report, _ = DiscoveryService(ArtifactStore(artifact_root)).run(
        robot=registry.get("demo_diff"),
        urdf_path=Path("tests/fixtures/profiles/differential_drive.urdf"),
        active_inputs=ActiveDiscoveryInputs(
            source_roots=[source_root],
            active_probe=(
                ActiveProbeMode.RUNTIME_READONLY if target_runtime else ActiveProbeMode.NONE
            ),
        ),
        target_probes=_bound_target_probes() if target_runtime else None,
    )
    return report.discovery_id


def _runtime_ros_probe() -> ProbeResult:
    return ProbeResult(
        layer="ros",
        status="SUCCEEDED",
        data={
            "ros_distro": "test",
            "installed_distros": ["test"],
            "domain_id": "0",
            "rmw": "test",
            "nodes": [],
            "topics": [
                "/cmd_vel [geometry_msgs/msg/Twist]",
                "/odom [nav_msgs/msg/Odometry]",
            ],
            "services": [],
            "actions": [],
        },
    )


def _bound_target_probes() -> dict[str, ProbeResult]:
    binding = {
        "robot_id": "demo_diff",
        "source_id": "source-test",
        "target_host_fingerprint": "f" * 64,
        "bundle_payload_sha256": "a" * 64,
        "access": "READ_ONLY",
        "deployment_mode": "local",
    }
    ros = _runtime_ros_probe()
    return {
        "hw": ProbeResult(
            layer="hw",
            status="SUCCEEDED",
            data={"components": [], "target_evidence": binding},
        ),
        "linux": ProbeResult(
            layer="linux",
            status="SUCCEEDED",
            data={"target_evidence": binding},
        ),
        "ros": ros.model_copy(update={"data": {**ros.data, "target_evidence": binding}}),
    }


def test_discovery_writes_adapt_inputs_and_derives_runtime_plan(tmp_path: Path) -> None:
    artifact_root = tmp_path / "artifacts"
    discovery_id = discover_demo(artifact_root, tmp_path)

    adapt_inputs = json.loads(
        (artifact_root / "adapt/demo_diff/latest/inputs.json").read_text(encoding="utf-8")
    )
    plan = AdaptStageService(ArtifactStore(artifact_root)).derive_plan("demo_diff")

    assert adapt_inputs["schema_version"] == "robot-adapt-inputs/v2"
    assert adapt_inputs["stage"] == "adapt"
    assert adapt_inputs["semantic_context_ref"].endswith("/semantic_context.json")
    assert not (artifact_root / "adapt/demo_diff/latest/plan.json").exists()
    assert plan.stage == "adapt"
    assert plan.status == "BLOCKED"
    assert plan.eligible_operations == []
    assert plan.deferred_operations == {}
    assert plan.adapter_agent.provider == "codex"
    assert plan.adapter_agent.model is None
    assert plan.adapter_agent.api_key_configured is False
    assert plan.semantic_context_ref == adapt_inputs["semantic_context_ref"]
    assert plan.robot_wiki_ref.endswith("/robot_wiki.md")
    assert plan.schema_version == "robot-adapt-plan/v3"
    assert (artifact_root / "diagnose/demo_diff/latest/inputs.json").is_file()
    assert (artifact_root / "verify/demo_diff/latest/inputs.json").is_file()
    discovery_run = artifact_root / "discovery/demo_diff/runs" / discovery_id
    assert (discovery_run / "wiki_insights.json").is_file()
    assert (discovery_run / "wiki_diff.json").is_file()


def test_pipeline_exposes_three_ordered_stages(tmp_path: Path) -> None:
    artifact_root = tmp_path / "artifacts"
    discover_demo(artifact_root, tmp_path)
    AdaptStageService(ArtifactStore(artifact_root)).derive_plan("demo_diff")

    pipeline = assess_pipeline(artifact_root, "demo_diff")

    assert [stage.stage for stage in pipeline.stages] == ["adapt", "diagnose", "verify"]
    assert pipeline.stages[0].agent_requirement == "adapter_agent"
    assert pipeline.stages[1].agent_requirement == "diagnosis_agent"
    assert pipeline.stages[1].status == "BLOCKED"
    assert "agent_inputs" in pipeline.stages[1].artifacts
    assert pipeline.stages[2].optional is True
    assert "agent_inputs" in pipeline.stages[2].artifacts


def test_adapt_plan_rejects_machine_evidence_after_manifest_changes(tmp_path: Path) -> None:
    artifact_root = tmp_path / "artifacts"
    discovery_id = discover_demo(artifact_root, tmp_path)
    report_path = (
        artifact_root / "discovery/demo_diff/runs" / discovery_id / "active_discovery_report.json"
    )
    report = json.loads(report_path.read_text(encoding="utf-8"))
    report["warnings"].append("machine evidence changed after publication")
    report_path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(ValueError, match="manifest hash mismatch"):
        AdaptStageService(ArtifactStore(artifact_root)).derive_plan("demo_diff")


def test_stage_cli_exposes_only_canonical_lifecycle_entries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    artifact_root = tmp_path / "artifacts"
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "cli-demo"\n', encoding="utf-8")
    monkeypatch.setenv("ROLO_ARTIFACT_DIR", str(artifact_root))
    monkeypatch.setenv("ROLO_OUTPUT_DIR", str(tmp_path / "output"))
    monkeypatch.setenv("WIKI_INSIGHTS_AGENT_ENABLED", "false")
    get_settings.cache_clear()
    runner = CliRunner()

    nested = runner.invoke(
        app,
        [
            "adapt",
            "discover",
            "run",
            "--robot",
            "demo_diff",
            "--urdf",
            str(Path("tests/fixtures/profiles/differential_drive.urdf").resolve()),
            "--source-root",
            str(tmp_path),
        ],
    )
    removed_legacy = runner.invoke(app, ["discover", "show", "--robot", "demo_diff"])
    review = runner.invoke(app, ["adapt", "discover", "review", "--robot", "demo_diff"])
    removed_confirm = runner.invoke(app, ["adapt", "discover", "confirm", "--help"])
    plan = runner.invoke(app, ["adapt", "run", "--robot", "demo_diff", "--dry-run"])
    pipeline = runner.invoke(app, ["pipeline-status", "--robot", "demo_diff"])
    enrollment = runner.invoke(app, ["adapt", "enroll", "show"])
    removed_deploy_stage = runner.invoke(app, ["deploy", "--help"])
    removed_robots = runner.invoke(app, ["robots"])
    removed_profiles = runner.invoke(app, ["adapt", "enroll", "profiles"])
    removed_steps = [
        runner.invoke(app, ["adapt", name, "--help"])
        for name in ("plan", "agent-prepare", "execute", "promote")
    ]

    get_settings.cache_clear()
    assert nested.exit_code == 0, nested.output
    assert removed_legacy.exit_code != 0
    assert review.exit_code == 0, review.output
    assert "# 机器人 Wiki：demo_diff" in review.output
    assert removed_confirm.exit_code != 0
    assert plan.exit_code == 0, plan.output
    assert '"required_skills"' not in plan.output
    assert pipeline.exit_code == 0, pipeline.output
    assert '"stage": "verify"' in pipeline.output
    assert enrollment.exit_code == 0, enrollment.output
    assert '"robot_id": "demo_diff"' in enrollment.output
    assert removed_deploy_stage.exit_code != 0
    assert removed_robots.exit_code != 0
    assert removed_profiles.exit_code != 0
    assert all(result.exit_code != 0 for result in removed_steps)


def test_cli_exposes_only_current_stage_names() -> None:
    runner = CliRunner()
    for name in ("adapt", "diagnose", "verify"):
        result = runner.invoke(app, [name, "--help"])
        assert result.exit_code == 0, result.output
    for name in ("build", "debug", "test"):
        assert runner.invoke(app, [name, "--help"]).exit_code != 0


def test_runtime_plan_accepts_vendor_model_and_never_persists_api_key(tmp_path: Path) -> None:
    artifact_root = tmp_path / "artifacts"
    discover_demo(artifact_root, tmp_path)
    config = AdapterAgentConfig(
        provider="another-vendor",
        base_url="https://relay.example.com/v1",
        model="vendor-code-model",
        api_key_configured=True,
    )

    plan = AdaptStageService(ArtifactStore(artifact_root), coding_agent=config).derive_plan(
        "demo_diff"
    )
    persisted_config = plan.model_dump(mode="json")["adapter_agent"]

    assert plan.adapter_agent == config
    assert plan.adapter_agent.api_key_env == "CODING_AGENT_API_KEY"
    assert set(persisted_config) == {
        "provider",
        "executor",
        "base_url",
        "model",
        "api_key_env",
        "api_key_configured",
        "auto_install",
        "require_auth",
    }
    assert not (artifact_root / "adapt/demo_diff/latest/plan.json").exists()


def test_build_agent_config_reads_environment_without_printing_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = "do-not-print-this-key"
    monkeypatch.setenv("CODING_AGENT_PROVIDER", "another-vendor")
    monkeypatch.setenv("CODING_AGENT_BASE_URL", "https://relay.example.com/v1")
    monkeypatch.setenv("CODING_AGENT_API_KEY", secret)
    monkeypatch.setenv("CODING_AGENT_MODEL", "vendor-code-model")
    get_settings.cache_clear()

    result = CliRunner().invoke(app, ["adapt", "agent-config"])

    get_settings.cache_clear()
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload == {
        "provider": "another-vendor",
        "executor": "codex",
        "base_url": "https://relay.example.com/v1",
        "model": "vendor-code-model",
        "api_key_env": "CODING_AGENT_API_KEY",
        "api_key_configured": True,
        "auto_install": True,
        "require_auth": True,
    }
    assert secret not in result.output


def test_adapt_run_executes_snapshots_gates_and_publishes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    artifact_root = tmp_path / "artifacts"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    monkeypatch.setattr(
        "rolo.stages.adapt.discovery.RosProbe.run",
        lambda self: ProbeResult(
            layer="ros",
            status="SUCCEEDED",
            data={
                "ros_distro": "test",
                "installed_distros": ["test"],
                "domain_id": "0",
                "rmw": "test",
                "nodes": [],
                "topics": [
                    "/cmd_vel [geometry_msgs/msg/Twist]",
                    "/odom [nav_msgs/msg/Odometry]",
                ],
                "services": [],
                "actions": [],
            },
        ),
    )
    discovery_id = discover_demo(artifact_root, workspace, target_runtime=True)
    monkeypatch.setenv("ROLO_ARTIFACT_DIR", str(artifact_root))
    monkeypatch.setenv("ROLO_OUTPUT_DIR", str(tmp_path / "output"))
    get_settings.cache_clear()
    calls: list[str] = []
    agent_workspaces: list[Path] = []

    def fake_prepare(self: object, **kwargs: object) -> tuple[object, Path]:
        del self, kwargs
        calls.append("prepare")
        report = AdapterAgentDependencyReport(
            executor="codex",
            provider="codex",
            status="READY",
            platform="Linux",
            architecture="aarch64",
            executable="/usr/local/bin/codex",
            version="codex-cli test",
            installed=True,
            authentication="AUTHENTICATED",
        )
        return report, artifact_root / "coding-agent/dependency/latest.json"

    def fake_execute(self: object, **kwargs: object) -> tuple[object, Path]:
        del self
        assert kwargs["slice_canary"] is True
        plan = kwargs["plan"]
        agent_workspace = Path(kwargs["workspace"])
        agent_workspaces.append(agent_workspace)
        assert calls == ["prepare"]
        calls.append("execute")
        report = load_report(artifact_root, "demo_diff", discovery_id)
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
        package_path = agent_workspace / "demo_adapter.py"
        package_path.write_text(
            "import json, sys\n"
            f"OPERATIONS = {operation_map!r}\n"
            "if sys.argv[1] == 'describe':\n"
            "    print(json.dumps({'operations': OPERATIONS}))\n"
            "elif sys.argv[1] == 'invoke':\n"
            "    args = dict(zip(sys.argv[2::2], sys.argv[3::2]))\n"
            "    operation = args.get('--operation')\n"
            "    if (operation not in OPERATIONS or "
            "args.get('--entrypoint') != OPERATIONS[operation]):\n"
            "        print(json.dumps({'error': {'code': 'INVALID_INPUT'}}))\n"
            "        raise SystemExit(1)\n"
            "    if operation == 'app.localization.pose':\n"
            "        print(json.dumps({'status': 'SUCCEEDED', 'frame_id': 'odom', "
            "'x_m': 0.0, 'y_m': 0.0, 'orientation_x': 0.0, "
            "'orientation_y': 0.0, 'orientation_z': 0.0, 'orientation_w': 1.0, "
            "'timestamp': '2026-01-01T00:00:00Z', 'observed_at': "
            "'2026-01-01T00:00:00Z'}))\n"
            "    else:\n"
            "        print(json.dumps({'status': 'SUCCEEDED'}))\n",
            encoding="utf-8",
        )
        (agent_workspace / "adapter-manifest.json").write_text(
            json.dumps(
                {
                    "schema_version": "robot-adapter-bundle/v1",
                    "bundle_id": "demo-adapter",
                    "bundle_version": "1.0.0",
                    "robot_id": "demo_diff",
                    "discovery_id": discovery_id,
                    "runtime_protocol": "robot-adapter-rpc/v1",
                    "package_file": package_path.name,
                    "package_sha256": sha256_file(package_path),
                    "operations": bundle_operations,
                }
            ),
            encoding="utf-8",
        )
        (agent_workspace / "state_graph.json").write_text(
            json.dumps(
                {
                    "schema_version": "robot-state-graph/v1",
                    "robot_id": "demo_diff",
                    "discovery_id": discovery_id,
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
        (agent_workspace / "conformance.json").write_text(
            json.dumps(
                {
                    "schema_version": "robot-adapter-conformance/v3",
                    "robot_id": "demo_diff",
                    "discovery_id": discovery_id,
                    "operations": operations,
                }
            ),
            encoding="utf-8",
        )
        agent_result = AdapterAgentResult(
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
            agent_result.model_dump(mode="json"),
        )
        now = utc_now()
        run = AdapterAgentRun(
            run_id="run-test",
            robot_id="demo_diff",
            source_discovery_id=plan.source_discovery_id,
            provider="codex",
            status="SUCCEEDED",
            workspace=str(agent_workspace),
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
        run_path = store.write_json(
            "adapt/demo_diff/runs/run-test/run.json",
            run.model_dump(mode="json"),
        )
        return run, run_path

    monkeypatch.setattr(
        "rolo.stages.adapt.service.AdapterAgentDependencyManager.prepare", fake_prepare
    )
    monkeypatch.setattr("rolo.stages.adapt.service.CodexAdaptExecutor.execute", fake_execute)

    result = CliRunner().invoke(
        app,
        ["adapt", "run", "--robot", "demo_diff", "--slice-canary"],
    )

    get_settings.cache_clear()
    assert result.exit_code == 0, result.output
    assert calls == ["prepare", "execute"]
    assert len(agent_workspaces) == 1
    assert not agent_workspaces[0].exists()
    payload = json.loads(result.output)
    assert payload["run"]["status"] == "COMPLETE"
    run_root = artifact_root / "adapt/demo_diff/runs/run-test"
    assert (run_root / "output-snapshot/snapshot.json").is_file()
    assert (run_root / "gate.json").is_file()
    assert (run_root / "handoff.json").is_file()
    assert (artifact_root / "adapt/demo_diff/latest.json").is_file()
    assert (tmp_path / "output/robots/demo_diff/current.json").is_file()

    newer_discovery_id = discover_demo(artifact_root, workspace, target_runtime=True)
    assert newer_discovery_id != discovery_id
    adapt = assess_pipeline(artifact_root, "demo_diff").stages[0]
    assert adapt.status == "COMPLETE"
    assert not adapt.blockers


def test_adapt_run_prepares_dependency_without_confirmation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    artifact_root = tmp_path / "artifacts"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    monkeypatch.setattr(
        "rolo.stages.adapt.discovery.RosProbe.run", lambda self: _runtime_ros_probe()
    )
    discover_demo(artifact_root, workspace, target_runtime=True)
    monkeypatch.setenv("ROLO_ARTIFACT_DIR", str(artifact_root))
    get_settings.cache_clear()
    calls: list[str] = []

    def unavailable_prepare(self: object, **kwargs: object) -> tuple[object, Path]:
        del self, kwargs
        calls.append("prepare")
        report = AdapterAgentDependencyReport(
            executor="codex",
            provider="codex",
            status="AUTH_REQUIRED",
            platform="Linux",
            architecture="aarch64",
            installed=True,
            authentication="AUTH_REQUIRED",
        )
        return report, artifact_root / "coding-agent/dependency/latest.json"

    monkeypatch.setattr(
        "rolo.stages.adapt.service.AdapterAgentDependencyManager.prepare", unavailable_prepare
    )

    result = CliRunner().invoke(
        app,
        ["adapt", "run", "--robot", "demo_diff"],
    )

    get_settings.cache_clear()
    assert result.exit_code == 2
    assert "dependency is not ready: AUTH_REQUIRED" in result.output
    assert calls == ["prepare"]


def test_adapt_run_rejects_scratch_and_output_inside_rolo_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    artifact_root = tmp_path / "artifacts"
    source = tmp_path / "source"
    source.mkdir()
    monkeypatch.setattr(
        "rolo.stages.adapt.discovery.RosProbe.run", lambda self: _runtime_ros_probe()
    )
    discover_demo(artifact_root, source, target_runtime=True)
    monkeypatch.setenv("ROLO_ARTIFACT_DIR", str(artifact_root))
    monkeypatch.setenv("ROLO_OUTPUT_DIR", str(Path.cwd() / "forbidden-adapter-output"))
    get_settings.cache_clear()

    result = CliRunner().invoke(app, ["adapt", "run", "--robot", "demo_diff"])

    get_settings.cache_clear()
    assert result.exit_code == 2
    assert "ROLO_OUTPUT_DIR must be outside" in result.output

    monkeypatch.setenv("ROLO_OUTPUT_DIR", str(tmp_path / "external-output"))
    get_settings.cache_clear()
    result = CliRunner().invoke(
        app,
        ["adapt", "run", "--robot", "demo_diff", "--scratch-root", str(Path.cwd())],
    )

    get_settings.cache_clear()
    assert result.exit_code == 2
    assert "scratch root must be outside" in result.output
