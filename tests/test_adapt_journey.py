from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from typer.main import get_command
from typer.testing import CliRunner

from rolo.cli import app
from rolo.core.config import get_settings
from rolo.core.models import ProbeResult
from rolo.stages.adapt.journey import detect_project_evidence
from rolo.stages.adapt.models import AdaptPlanStatus, AdaptRunSummary
from rolo.stages.adapt.target_evidence import (
    collect_target_evidence,
    initialize_probe_runner,
    load_probe_runner_state,
)


def _project(root: Path) -> Path:
    project = root / "robot-project"
    (project / "build").mkdir(parents=True)
    (project / "install").mkdir()
    (project / "docs").mkdir()
    (project / "src/navigation/launch").mkdir(parents=True)
    (project / "README.md").write_text("# Robot\n", encoding="utf-8")
    (project / "docs/operator.md").write_text("# Operator\n", encoding="utf-8")
    (project / "src/navigation/launch/navigation.launch.py").write_text(
        "from launch import LaunchDescription\n",
        encoding="utf-8",
    )
    (project / "src/navigation/driver.py").write_text(
        'create_publisher(Twist, "/cmd_vel", 10)\n',
        encoding="utf-8",
    )
    return project


def _stub_target_probes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "rolo.stages.adapt.target_evidence.target_host_fingerprint", lambda: "a" * 64
    )
    monkeypatch.setattr(
        "rolo.stages.adapt.target_evidence.HardwareProbe.run",
        lambda self, *, robot_id: ProbeResult(
            layer="hw",
            status="SUCCEEDED",
            data={"robot": robot_id, "components": []},
        ),
    )
    monkeypatch.setattr(
        "rolo.stages.adapt.target_evidence.LinuxProbe.run",
        lambda self: ProbeResult(
            layer="linux",
            status="SUCCEEDED",
            data={"architecture": "arm64"},
        ),
    )
    monkeypatch.setattr(
        "rolo.stages.adapt.target_evidence.RosProbe.run",
        lambda self: ProbeResult(
            layer="ros",
            status="SUCCEEDED",
            data={
                "nodes": ["/base_driver"],
                "topics": ["/cmd_vel [geometry_msgs/msg/Twist]"],
                "services": [],
                "actions": [],
            },
        ),
    )


def test_project_evidence_detects_primary_roots_without_guessing_urdf(tmp_path: Path) -> None:
    project = _project(tmp_path)
    (project / "src/navigation/urdf").mkdir(parents=True)
    (project / "src/navigation/urdf/robot.urdf").write_text(
        '<robot name="test_robot"><link name="base_link"/></robot>',
        encoding="utf-8",
    )

    evidence = detect_project_evidence(project)

    assert evidence.project_root == project.resolve()
    assert evidence.source_roots == [project.resolve()]
    assert evidence.build_roots == [(project / "build").resolve()]
    assert evidence.install_roots == [(project / "install").resolve()]
    assert (project / "docs").resolve() in evidence.document_roots
    assert evidence.launch_roots == [(project / "src/navigation/launch").resolve()]
    assert not hasattr(evidence, "urdf")
    assert evidence.truncated is False


def test_adapt_start_exposes_semantic_mapping_controls() -> None:
    root = get_command(app)
    start = root.commands["adapt"].commands["start"]
    options = {option for parameter in start.params for option in parameter.opts}

    assert "--heuristic-agent-mode" in options
    assert "--heuristic-agent-timeout" in options
    assert "--heuristic-agent-batch-operations" in options
    assert "--heuristic-agent-parallelism" in options


def test_adapt_start_collapses_enrollment_discovery_and_wiki_into_one_command(
    tmp_path: Path,
) -> None:
    project = _project(tmp_path)
    config_root = tmp_path / "config"
    artifact_root = tmp_path / "artifacts"
    output_root = tmp_path / "output"
    urdf = Path("tests/fixtures/profiles/differential_drive.urdf").resolve()
    get_settings.cache_clear()

    result = CliRunner().invoke(
        app,
        [
            "adapt",
            "start",
            "--robot-id",
            "journey_robot",
            "--project-root",
            str(project),
            "--urdf",
            str(urdf),
            "--active-probe",
            "none",
            "--discover-only",
        ],
        env={
            "ROLO_CONFIG_DIR": str(config_root),
            "ROLO_ARTIFACT_DIR": str(artifact_root),
            "ROLO_OUTPUT_DIR": str(output_root),
            "WIKI_INSIGHTS_AGENT_ENABLED": "false",
            "WIKI_POLISH_ENABLED": "false",
        },
    )
    get_settings.cache_clear()

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["schema_version"] == "robot-adapt-journey/v2"
    assert payload["status"] == "DISCOVERY_COMPLETE"
    assert payload["robot_id"] == "journey_robot"
    assert payload["enrollment"] == "IDENTITY_REGISTERED"
    assert payload["doctor_status"] == "READY"
    assert payload["discovery_id"].startswith("disc-")
    assert payload["wiki"].endswith("robot_wiki.md")
    assert Path(payload["wiki"]).is_file()
    assert (config_root / "robots/journey_robot.yaml").is_file()
    assert payload["next_steps"][0] == "robotctl adapt run --robot journey_robot"


def test_adapt_start_collects_and_binds_fresh_local_target_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _stub_target_probes(monkeypatch)
    project = _project(tmp_path)
    config_root = tmp_path / "config"
    artifact_root = tmp_path / "artifacts"
    env = {
        "ROLO_CONFIG_DIR": str(config_root),
        "ROLO_ARTIFACT_DIR": str(artifact_root),
        "ROLO_OUTPUT_DIR": str(tmp_path / "output"),
        "WIKI_INSIGHTS_AGENT_ENABLED": "false",
        "WIKI_POLISH_ENABLED": "false",
    }
    command = [
        "adapt",
        "start",
        "--robot",
        "signed_robot",
        "--project-root",
        str(project),
        "--allow-executable",
        sys.executable,
        "--discover-only",
    ]
    runner = CliRunner()
    get_settings.cache_clear()
    first = runner.invoke(app, command, env=env)
    get_settings.cache_clear()
    second = runner.invoke(app, command, env=env)
    get_settings.cache_clear()

    assert first.exit_code == 0, first.output
    assert second.exit_code == 0, second.output
    first_payload = json.loads(first.output)
    second_payload = json.loads(second.output)
    target = first_payload["target_evidence"]
    assert target["mode"] == "local"
    assert target["target_host_fingerprint"] == "a" * 64
    assert len(target["bundle_payload_sha256"]) == 64
    assert Path(target["bundle_path"]).is_file()
    bundle = json.loads(Path(target["bundle_path"]).read_text(encoding="utf-8"))
    assert bundle["executable_help"][0]["help_probe"]["status"] == "SUCCEEDED"
    assert second_payload["target_evidence"]["source_id"] == target["source_id"]
    assert (config_root / "target-evidence/signed_robot.json").is_file()
    assert (config_root / "target-evidence/signed_robot-probe_runner.json").is_file()

    acceptance = runner.invoke(
        app,
        ["adapt", "acceptance-pack", "--robot", "signed_robot"],
        env=env,
    )
    get_settings.cache_clear()
    assert acceptance.exit_code == 0, acceptance.output
    acceptance_payload = json.loads(acceptance.output)
    pack = acceptance_payload["pack"]
    assert pack["schema_version"] == "robot-adapt-acceptance-pack/v1"
    assert pack["status"] == "INCOMPLETE"
    assert pack["registry"]["operation_count"] == 294
    assert (
        pack["target_evidence"]["bundle_payload_sha256"]
        == second_payload["target_evidence"]["bundle_payload_sha256"]
    )
    assert Path(acceptance_payload["artifact"]).is_file()
    assert len(acceptance_payload["sha256"]) == 64


def test_adapt_start_remote_mode_requires_a_pinned_deployment(tmp_path: Path) -> None:
    project = _project(tmp_path)
    get_settings.cache_clear()
    result = CliRunner().invoke(
        app,
        [
            "adapt",
            "start",
            "--robot",
            "remote_robot",
            "--project-root",
            str(project),
            "--evidence-mode",
            "remote",
            "--discover-only",
        ],
        env={
            "ROLO_CONFIG_DIR": str(tmp_path / "config"),
            "ROLO_ARTIFACT_DIR": str(tmp_path / "artifacts"),
            "ROLO_OUTPUT_DIR": str(tmp_path / "output"),
        },
    )
    get_settings.cache_clear()

    assert result.exit_code == 2
    assert "requires an existing deployment" in result.output


def test_adapt_start_collects_remote_pinned_evidence_in_the_same_journey(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _stub_target_probes(monkeypatch)
    target_state = tmp_path / "target/probe_runner.json"
    target_secret = tmp_path / "target/probe_runner.key"
    descriptor = initialize_probe_runner(
        robot_id="remote_robot",
        state_path=target_state,
        secret_path=target_secret,
    )
    descriptor_path = tmp_path / "controller/descriptor.json"
    descriptor_path.parent.mkdir(parents=True)
    descriptor_path.write_text(
        descriptor.model_dump_json(indent=2) + "\n",
        encoding="utf-8",
    )
    known_hosts = tmp_path / "controller/known_hosts"
    known_hosts.write_text("target ssh-ed25519 AAAATEST\n", encoding="utf-8")
    monkeypatch.setattr(
        "rolo.stages.adapt.journey.collect_over_ssh",
        lambda deployment, request, *, timeout_s, max_attempts: collect_target_evidence(
            request,
            load_probe_runner_state(target_state),
        ),
    )
    project = _project(tmp_path)
    get_settings.cache_clear()
    result = CliRunner().invoke(
        app,
        [
            "adapt",
            "start",
            "--robot",
            "remote_robot",
            "--project-root",
            str(project),
            "--evidence-mode",
            "remote",
            "--source-descriptor",
            str(descriptor_path),
            "--verification-secret",
            str(target_secret),
            "--ssh-target",
            "rolo@target",
            "--known-hosts",
            str(known_hosts),
            "--discover-only",
        ],
        env={
            "ROLO_CONFIG_DIR": str(tmp_path / "config"),
            "ROLO_ARTIFACT_DIR": str(tmp_path / "artifacts"),
            "ROLO_OUTPUT_DIR": str(tmp_path / "output"),
            "WIKI_INSIGHTS_AGENT_ENABLED": "false",
            "WIKI_POLISH_ENABLED": "false",
        },
    )
    get_settings.cache_clear()

    assert result.exit_code == 0, result.output
    target = json.loads(result.output)["target_evidence"]
    assert target["mode"] == "remote"
    assert target["source_id"] == descriptor.source_id
    assert Path(target["bundle_path"]).is_file()


def test_adapt_start_reuses_the_registered_identity(tmp_path: Path) -> None:
    project = _project(tmp_path)
    env = {
        "ROLO_CONFIG_DIR": str(tmp_path / "config"),
        "ROLO_ARTIFACT_DIR": str(tmp_path / "artifacts"),
        "ROLO_OUTPUT_DIR": str(tmp_path / "output"),
        "WIKI_INSIGHTS_AGENT_ENABLED": "false",
        "WIKI_POLISH_ENABLED": "false",
    }
    command = [
        "adapt",
        "start",
        "--robot",
        "journey_robot",
        "--project-root",
        str(project),
        "--active-probe",
        "none",
        "--discover-only",
    ]
    runner = CliRunner()
    get_settings.cache_clear()
    first = runner.invoke(app, command, env=env)
    get_settings.cache_clear()
    second = runner.invoke(app, command, env=env)
    get_settings.cache_clear()

    assert first.exit_code == 0, first.output
    assert second.exit_code == 0, second.output
    assert json.loads(second.output)["enrollment"] == "ALREADY_REGISTERED"


def test_adapt_start_returns_an_actionable_blocker_without_runtime_routes(
    tmp_path: Path,
) -> None:
    project = _project(tmp_path)
    get_settings.cache_clear()
    result = CliRunner().invoke(
        app,
        [
            "adapt",
            "start",
            "--robot",
            "blocked_robot",
            "--project-root",
            str(project),
            "--active-probe",
            "none",
        ],
        env={
            "ROLO_CONFIG_DIR": str(tmp_path / "config"),
            "ROLO_ARTIFACT_DIR": str(tmp_path / "artifacts"),
            "ROLO_OUTPUT_DIR": str(tmp_path / "output"),
            "WIKI_INSIGHTS_AGENT_ENABLED": "false",
            "WIKI_POLISH_ENABLED": "false",
        },
    )
    get_settings.cache_clear()

    assert result.exit_code == 2
    payload = json.loads(result.output)
    assert payload["status"] == "BLOCKED"
    assert payload["wiki"].endswith("robot_wiki.md")
    assert "target-observed" in payload["blockers"][0]
    assert payload["next_steps"][0] == "robotctl adapt status --robot blocked_robot"


def test_full_adapt_blocks_before_discovery_when_production_sandbox_is_invalid(
    tmp_path: Path,
) -> None:
    project = _project(tmp_path)
    get_settings.cache_clear()
    result = CliRunner().invoke(
        app,
        [
            "adapt",
            "start",
            "--robot",
            "sandbox_blocked_robot",
            "--project-root",
            str(project),
            "--active-probe",
            "none",
        ],
        env={
            "ROLO_CONFIG_DIR": str(tmp_path / "config"),
            "ROLO_ARTIFACT_DIR": str(tmp_path / "artifacts"),
            "ROLO_OUTPUT_DIR": str(tmp_path / "output"),
            "ROLO_ADAPTER_UNSANDBOXED_DEV": "false",
            "ROLO_ADAPTER_SANDBOX_LAUNCHER": str(tmp_path / "missing-launcher"),
        },
    )
    get_settings.cache_clear()

    assert result.exit_code == 2
    payload = json.loads(result.output)
    assert payload["status"] == "BLOCKED"
    assert payload["discovery_id"] is None
    assert "sandbox launcher is invalid" in payload["blockers"][0]


def test_adapt_start_reports_the_gate_handoff_and_release(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = _project(tmp_path)

    class Plan:
        status = AdaptPlanStatus.REQUIRES_CODING

    monkeypatch.setattr(
        "rolo.stages.adapt.journey.AdaptRunService.dry_run",
        lambda self, robot_id: Plan(),
    )

    def completed_run(self: object, **kwargs: object) -> tuple[AdaptRunSummary, Path]:
        del self, kwargs
        artifact = tmp_path / "artifacts/adapt/release_robot/runs/run-short/summary.json"
        artifact.parent.mkdir(parents=True, exist_ok=True)
        artifact.write_text("{}", encoding="utf-8")
        return (
            AdaptRunSummary(
                robot_id="release_robot",
                run_id="run-short",
                agent_run_ref="artifact://agent-run.json",
                snapshot_ref="artifact://snapshot.json",
                gate_ref="artifact://gate.json",
                handoff_ref="artifact://handoff.json",
            ),
            artifact,
        )

    monkeypatch.setattr(
        "rolo.stages.adapt.journey.AdaptRunService.run",
        completed_run,
    )
    get_settings.cache_clear()
    result = CliRunner().invoke(
        app,
        [
            "adapt",
            "start",
            "--robot",
            "release_robot",
            "--project-root",
            str(project),
            "--active-probe",
            "none",
        ],
        env={
            "ROLO_CONFIG_DIR": str(tmp_path / "config"),
            "ROLO_ARTIFACT_DIR": str(tmp_path / "artifacts"),
            "ROLO_OUTPUT_DIR": str(tmp_path / "output"),
            "WIKI_INSIGHTS_AGENT_ENABLED": "false",
            "WIKI_POLISH_ENABLED": "false",
        },
    )
    get_settings.cache_clear()

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["status"] == "COMPLETE"
    assert payload["release_id"] == "run-short"
    assert payload["gate"] == "artifact://gate.json"
    assert payload["handoff"] == "artifact://handoff.json"
