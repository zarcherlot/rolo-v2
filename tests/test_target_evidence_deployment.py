from __future__ import annotations

import base64
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from typer.testing import CliRunner

import rolo.stages.adapt.target_evidence as target_evidence_module
from rolo.cli import app
from rolo.core.artifacts import ArtifactStore
from rolo.core.config import get_settings
from rolo.core.models import ProbeResult
from rolo.core.registry import RobotRegistry
from rolo.stages.adapt.active_discovery import (
    ActiveDiscoveryInputs,
    ActiveDiscoveryReport,
    ActiveProbeMode,
    HelpProbeStatus,
)
from rolo.stages.adapt.discovery import DiscoveryService, _DeterministicR0ProbeDispatcher
from rolo.stages.adapt.ros_environment import select_ros_setup_files
from rolo.stages.adapt.software_relevance import SoftwareDiscoveryPolicy
from rolo.stages.adapt.target_evidence import (
    EvidenceDeploymentMode,
    SSHTransportError,
    collect_over_ssh,
    collect_target_evidence,
    configure_deployment,
    discover_help_executables,
    ensure_local_deployment,
    initialize_probe_runner,
    load_probe_runner_state,
    load_deployment,
    new_request,
    reenroll_deployment,
    refresh_local_deployment,
    stage_probe_runner_rotation,
    verify_evidence_bundle,
)
from rolo.stages.artifact_paths import resolve_artifact_ref


def test_project_entrypoint_discovery_covers_all_application_clis(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        "[project.scripts]\n"
        "lerobot-find-cameras = 'lerobot.cli:find'\n"
        "lerobot-info = 'lerobot.cli:info'\n"
        "lerobot-teleoperate = 'lerobot.cli:teleoperate'\n",
        encoding="utf-8",
    )
    bin_dir = tmp_path / ".venv" / "bin"
    bin_dir.mkdir(parents=True)
    for name in ("lerobot-find-cameras", "lerobot-info", "lerobot-teleoperate"):
        (bin_dir / name).write_text("#!/bin/sh\n", encoding="utf-8")

    discovered = discover_help_executables(tmp_path)

    assert [item.name for item in discovered] == [
        "lerobot-find-cameras",
        "lerobot-info",
        "lerobot-teleoperate",
    ]


def test_project_entrypoint_discovery_uses_semantic_tokens_not_platform_names(
    tmp_path: Path,
) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(parents=True)
    for name in ("vendor_robot_node", "vendor_camera_driver", "vendor_unrelated_tool"):
        (bin_dir / name).write_text("#!/bin/sh\n", encoding="utf-8")

    discovered = discover_help_executables(tmp_path)

    assert [item.name for item in discovered] == ["vendor_camera_driver", "vendor_robot_node"]


def _probe_runner(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(
        "rolo.stages.adapt.target_evidence.target_host_fingerprint", lambda: "a" * 64
    )
    state_path = tmp_path / "probe_runner.json"
    secret_path = tmp_path / "probe_runner.key"
    descriptor = initialize_probe_runner(
        robot_id="wheeltec",
        state_path=state_path,
        secret_path=secret_path,
    )
    return descriptor, state_path, secret_path


def _stub_probes(monkeypatch: pytest.MonkeyPatch) -> None:
    class Hardware:
        def run(self, *, robot_id: str):
            return ProbeResult(layer="hw", status="SUCCEEDED", data={"robot": robot_id})

    class Linux:
        def run(self):
            return ProbeResult(layer="linux", status="SUCCEEDED", data={"arch": "arm64"})

    class Ros:
        def __init__(self, *, enrich_routes: bool = False, stabilize: bool = False):
            self.enrich_routes = enrich_routes
            self.stabilize = stabilize

        def run(self):
            return ProbeResult(
                layer="ros",
                status="SUCCEEDED",
                data={"nodes": [], "topics": [], "services": [], "actions": []},
            )

    monkeypatch.setattr("rolo.stages.adapt.target_evidence.HardwareProbe", Hardware)
    monkeypatch.setattr("rolo.stages.adapt.target_evidence.LinuxProbe", Linux)
    monkeypatch.setattr("rolo.stages.adapt.target_evidence.RosProbe", Ros)


def test_local_bundle_is_target_bound_signed_and_read_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    descriptor, state_path, secret_path = _probe_runner(tmp_path, monkeypatch)
    _stub_probes(monkeypatch)
    deployment = configure_deployment(
        robot_id="wheeltec",
        mode=EvidenceDeploymentMode.LOCAL,
        descriptor=descriptor,
        verification_secret_path=secret_path,
        output_path=tmp_path / "deployment.json",
        local_probe_runner_state_path=state_path,
    )
    request = new_request("wheeltec")
    bundle = collect_target_evidence(request, load_probe_runner_state(state_path))
    probes = verify_evidence_bundle(bundle, deployment=deployment, request=request)

    assert bundle.access == "READ_ONLY"
    assert set(probes) == {"hw", "linux", "ros"}
    assert probes["hw"].data["target_evidence"]["target_host_fingerprint"] == "a" * 64
    assert probes["hw"].data["target_evidence"]["deployment_mode"] == "local"
    assert probes["hw"].data["target_evidence"]["bundle_payload_sha256"] == (bundle.payload_sha256)


def test_probe_runner_uses_bounded_enriched_ros_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    descriptor, state_path, secret_path = _probe_runner(tmp_path, monkeypatch)
    seen: dict[str, bool] = {}

    class Ros:
        def __init__(self, *, enrich_routes: bool = False, stabilize: bool = False):
            seen["enrich_routes"] = enrich_routes
            seen["stabilize"] = stabilize

        def run(self):
            return ProbeResult(
                layer="ros",
                status="SUCCEEDED",
                data={
                    "nodes": ["/lidar"],
                    "topics": ["/scan [sensor_msgs/msg/LaserScan]"],
                    "services": [],
                    "actions": [],
                    "stability": {
                        "attempts": 2,
                        "stable": True,
                        "sampled_fields": ["actions", "nodes", "services", "topics"],
                    },
                    "route_enrichment": {
                        "provider_ids": {"/scan": "ros_node:/lidar"},
                        "interface_schema_sha256": {"sensor_msgs/msg/LaserScan": "a" * 64},
                    },
                },
            )

    monkeypatch.setattr("rolo.stages.adapt.target_evidence.RosProbe", Ros)
    deployment = configure_deployment(
        robot_id="wheeltec",
        mode=EvidenceDeploymentMode.LOCAL,
        descriptor=descriptor,
        verification_secret_path=secret_path,
        output_path=tmp_path / "deployment.json",
        local_probe_runner_state_path=state_path,
    )

    request = new_request("wheeltec")
    bundle = collect_target_evidence(request, load_probe_runner_state(state_path))
    verify_evidence_bundle(
        bundle,
        deployment=deployment,
        request=request,
    )

    assert seen == {"enrich_routes": True, "stabilize": True}
    ros_data = bundle.probes["ros"].data
    assert ros_data["stability"]["stable"] is True
    assert ros_data["route_enrichment"]["provider_ids"]["/scan"] == "ros_node:/lidar"


def test_probe_runner_pins_and_signs_ros_environment_bootstrap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "rolo.stages.adapt.target_evidence.target_host_fingerprint", lambda: "a" * 64
    )
    setup = tmp_path / "install/setup.bash"
    setup.parent.mkdir(parents=True)
    setup.write_text("# pinned overlay\n", encoding="utf-8")
    _, setup_records = select_ros_setup_files(
        auto_source=True,
        configured=[setup],
        project_root=None,
        environment={},
    )
    monkeypatch.setattr(
        "rolo.stages.adapt.ros_environment._source_setup_files",
        lambda records, environment: {**environment, "ROS_DISTRO": "humble"},
    )
    _stub_probes(monkeypatch)
    state_path = tmp_path / "probe_runner.json"
    secret_path = tmp_path / "probe_runner.key"
    descriptor = initialize_probe_runner(
        robot_id="wheeltec",
        state_path=state_path,
        secret_path=secret_path,
        ros_setup_files=setup_records,
    )
    deployment = configure_deployment(
        robot_id="wheeltec",
        mode=EvidenceDeploymentMode.LOCAL,
        descriptor=descriptor,
        verification_secret_path=secret_path,
        output_path=tmp_path / "deployment.json",
        local_probe_runner_state_path=state_path,
    )
    request = new_request("wheeltec")

    bundle = collect_target_evidence(request, load_probe_runner_state(state_path))
    verify_evidence_bundle(bundle, deployment=deployment, request=request)

    bootstrap = bundle.probes["ros"].data["environment_bootstrap"]
    assert bootstrap["setup_files"][0]["path"] == str(setup.resolve())
    assert bootstrap["setup_files"][0]["sha256"] == setup_records[0].sha256


def test_allowlisted_target_help_is_signed_verified_and_merged_into_discovery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "rolo.stages.adapt.target_evidence.target_host_fingerprint", lambda: "a" * 64
    )
    state_path = tmp_path / "probe_runner.json"
    secret_path = tmp_path / "probe_runner.key"
    descriptor = initialize_probe_runner(
        robot_id="demo_diff",
        state_path=state_path,
        secret_path=secret_path,
        help_executables=[Path(sys.executable)],
    )
    _stub_probes(monkeypatch)
    deployment = configure_deployment(
        robot_id="demo_diff",
        mode=EvidenceDeploymentMode.LOCAL,
        descriptor=descriptor,
        verification_secret_path=secret_path,
        output_path=tmp_path / "deployment.json",
        local_probe_runner_state_path=state_path,
    )
    executable_id = descriptor.help_executables[0].executable_id
    request = new_request("demo_diff", executable_help_ids=[executable_id])
    bundle = collect_target_evidence(request, load_probe_runner_state(state_path))
    probes = verify_evidence_bundle(bundle, deployment=deployment, request=request)

    assert bundle.executable_help[0].help_probe.status == HelpProbeStatus.SUCCEEDED
    assert bundle.executable_help[0].usage
    assert (
        probes["linux"].data["target_evidence"]["executable_help"][0]["executable_id"]
        == executable_id
    )
    application_routes = [
        item
        for item in probes["linux"].data["route_evidence"]
        if item.get("interface_type") == "application/cli"
    ]
    assert application_routes
    assert all(item["provider_id"] == executable_id for item in application_routes)
    assert all(item["evidence_origin"] == "OBSERVED_RUNTIME" for item in application_routes)

    source = tmp_path / "source"
    source.mkdir()
    (source / "driver.py").write_text('create_publisher(Twist, "/cmd_vel", 10)\n', encoding="utf-8")
    registry = RobotRegistry(Path("tests/fixtures/robots"))
    registry.load()
    artifact_root = tmp_path / "artifacts"
    report, _ = DiscoveryService(ArtifactStore(artifact_root)).run(
        robot=registry.get("demo_diff"),
        active_inputs=ActiveDiscoveryInputs(
            source_roots=[source], active_probe=ActiveProbeMode.RUNTIME_READONLY
        ),
        target_probes=probes,
    )
    active = ActiveDiscoveryReport.model_validate_json(
        resolve_artifact_ref(artifact_root, report.active_discovery_report_ref).read_text(
            encoding="utf-8"
        )
    )
    executable = next(item for item in active.executables if item.executable_id == executable_id)
    assert executable.sha256 == descriptor.help_executables[0].sha256
    assert executable.invocation.help_probe.status == HelpProbeStatus.SUCCEEDED
    assert executable.invocation.help_probe.output_ref == (
        f"target-evidence:{bundle.payload_sha256}#executable-help/{executable_id}"
    )


def test_target_help_rejects_unknown_id_and_changed_executable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "rolo.stages.adapt.target_evidence.target_host_fingerprint", lambda: "a" * 64
    )
    executable = tmp_path / "driver"
    executable.write_bytes(b"first")
    state_path = tmp_path / "probe_runner.json"
    secret_path = tmp_path / "probe_runner.key"
    descriptor = initialize_probe_runner(
        robot_id="wheeltec",
        state_path=state_path,
        secret_path=secret_path,
        help_executables=[executable],
    )
    _stub_probes(monkeypatch)
    state = load_probe_runner_state(state_path)

    with pytest.raises(ValueError, match="not allowlisted"):
        collect_target_evidence(
            new_request("wheeltec", executable_help_ids=["target-exe-" + "0" * 24]),
            state,
        )

    executable.write_bytes(b"changed")
    with pytest.raises(ValueError, match="digest changed"):
        collect_target_evidence(
            new_request(
                "wheeltec",
                executable_help_ids=[descriptor.help_executables[0].executable_id],
            ),
            state,
        )


def test_target_help_preserves_sibling_evidence_when_one_executable_is_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "rolo.stages.adapt.target_evidence.target_host_fingerprint", lambda: "a" * 64
    )
    first = tmp_path / "camera-driver"
    second = tmp_path / "robot-info"
    first.write_bytes(b"first")
    second.write_bytes(b"second")
    state_path = tmp_path / "probe_runner.json"
    secret_path = tmp_path / "probe_runner.key"
    descriptor = initialize_probe_runner(
        robot_id="wheeltec",
        state_path=state_path,
        secret_path=secret_path,
        help_executables=[first, second],
    )
    _stub_probes(monkeypatch)
    monkeypatch.setattr(
        target_evidence_module,
        "run_bounded_help",
        lambda _path, _output: target_evidence_module.HelpProbeResult(
            status=HelpProbeStatus.SUCCEEDED
        ),
    )
    second.unlink()

    request = new_request(
        "wheeltec",
        executable_help_ids=[item.executable_id for item in descriptor.help_executables],
    )
    bundle = collect_target_evidence(request, load_probe_runner_state(state_path))

    statuses = {item.path: item.help_probe.status for item in bundle.executable_help}
    assert statuses[str(first.resolve())] == HelpProbeStatus.SUCCEEDED
    assert statuses[str(second.resolve())] == HelpProbeStatus.FAILED


def test_target_help_cli_enrollment_and_collection_handoff(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "rolo.stages.adapt.target_evidence.target_host_fingerprint", lambda: "a" * 64
    )
    _stub_probes(monkeypatch)
    state_path = tmp_path / "probe_runner.json"
    secret_path = tmp_path / "probe_runner.key"
    descriptor_path = tmp_path / "descriptor.json"
    runner = CliRunner()
    enrolled = runner.invoke(
        app,
        [
            "target-evidence",
            "probe-runner-init",
            "--robot",
            "wheeltec",
            "--config",
            str(state_path),
            "--secret-file",
            str(secret_path),
            "--descriptor-out",
            str(descriptor_path),
            "--allow-executable",
            sys.executable,
        ],
    )
    assert enrolled.exit_code == 0, enrolled.output
    descriptor = json.loads(descriptor_path.read_text(encoding="utf-8"))
    executable_id = descriptor["help_executables"][0]["executable_id"]
    deployment_path = tmp_path / "deployment.json"
    configure_deployment(
        robot_id="wheeltec",
        mode=EvidenceDeploymentMode.LOCAL,
        descriptor=load_probe_runner_state(state_path),
        verification_secret_path=secret_path,
        output_path=deployment_path,
        local_probe_runner_state_path=state_path,
    )
    bundle_path = tmp_path / "bundle.json"
    collected = runner.invoke(
        app,
        [
            "target-evidence",
            "collect",
            "--robot",
            "wheeltec",
            "--deployment-config",
            str(deployment_path),
            "--source-state",
            str(state_path),
            "--executable-help-id",
            executable_id,
            "--output",
            str(bundle_path),
        ],
    )
    assert collected.exit_code == 0, collected.output
    payload = json.loads(collected.output)
    assert payload["status"] == "VERIFIED"
    assert payload["executable_help"] == [{"executable_id": executable_id, "status": "SUCCEEDED"}]


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("robot_id", "another", "robot identity mismatch"),
        ("source_id", "source-attacker", "probe_runner identity mismatch"),
        ("target_host_fingerprint", "b" * 64, "target host fingerprint mismatch"),
    ],
)
def test_bundle_identity_mismatch_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    value: str,
    message: str,
) -> None:
    descriptor, state_path, secret_path = _probe_runner(tmp_path, monkeypatch)
    _stub_probes(monkeypatch)
    deployment = configure_deployment(
        robot_id="wheeltec",
        mode=EvidenceDeploymentMode.LOCAL,
        descriptor=descriptor,
        verification_secret_path=secret_path,
        output_path=tmp_path / "deployment.json",
        local_probe_runner_state_path=state_path,
    )
    request = new_request("wheeltec")
    bundle = collect_target_evidence(request, load_probe_runner_state(state_path))
    tampered = bundle.model_copy(update={field: value})

    with pytest.raises(ValueError, match=message):
        verify_evidence_bundle(tampered, deployment=deployment, request=request)


def test_tampered_probe_payload_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    descriptor, state_path, secret_path = _probe_runner(tmp_path, monkeypatch)
    _stub_probes(monkeypatch)
    deployment = configure_deployment(
        robot_id="wheeltec",
        mode=EvidenceDeploymentMode.LOCAL,
        descriptor=descriptor,
        verification_secret_path=secret_path,
        output_path=tmp_path / "deployment.json",
        local_probe_runner_state_path=state_path,
    )
    request = new_request("wheeltec")
    bundle = collect_target_evidence(request, load_probe_runner_state(state_path))
    altered_probes = dict(bundle.probes)
    altered_probes["linux"] = altered_probes["linux"].model_copy(
        update={"data": {"arch": "developer-host"}}
    )
    tampered = bundle.model_copy(update={"probes": altered_probes})

    with pytest.raises(ValueError, match="payload hash mismatch"):
        verify_evidence_bundle(tampered, deployment=deployment, request=request)


def test_expired_request_is_rejected_before_any_probe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, state_path, _ = _probe_runner(tmp_path, monkeypatch)
    request = new_request("wheeltec", now=datetime.now(timezone.utc) - timedelta(minutes=10))

    with pytest.raises(ValueError, match="expired"):
        collect_target_evidence(request, load_probe_runner_state(state_path))


def test_requestless_bundle_replay_is_rejected_after_freshness_window(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    descriptor, state_path, secret_path = _probe_runner(tmp_path, monkeypatch)
    _stub_probes(monkeypatch)
    deployment = configure_deployment(
        robot_id="wheeltec",
        mode=EvidenceDeploymentMode.LOCAL,
        descriptor=descriptor,
        verification_secret_path=secret_path,
        output_path=tmp_path / "deployment.json",
        local_probe_runner_state_path=state_path,
    )
    collected_at = datetime.now(timezone.utc)
    request = new_request("wheeltec", now=collected_at)
    bundle = collect_target_evidence(
        request,
        load_probe_runner_state(state_path),
        now=collected_at,
    )

    with pytest.raises(ValueError, match="bundle is stale"):
        verify_evidence_bundle(
            bundle,
            deployment=deployment,
            request=None,
            now=collected_at + timedelta(minutes=8),
        )


def test_remote_transport_pins_known_hosts_and_invokes_only_probe_runner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    descriptor, state_path, secret_path = _probe_runner(tmp_path, monkeypatch)
    _stub_probes(monkeypatch)
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("target ssh-ed25519 AAAA\n", encoding="utf-8")
    identity = tmp_path / "id_ed25519"
    identity.write_text("test-only-private-key\n", encoding="utf-8")
    identity.chmod(0o600)
    deployment = configure_deployment(
        robot_id="wheeltec",
        mode=EvidenceDeploymentMode.REMOTE,
        descriptor=descriptor,
        verification_secret_path=secret_path,
        output_path=tmp_path / "deployment.json",
        ssh_target="rolo@target",
        known_hosts_path=known_hosts,
        ssh_port=2222,
        ssh_identity_file=identity,
        probe_runner_executable="/opt/rolo/.venv/bin/robotctl",
    )
    request = new_request("wheeltec")
    bundle = collect_target_evidence(request, load_probe_runner_state(state_path))
    captured: dict[str, object] = {}

    def fake_transport(command, request_bytes, *, timeout_s):
        del timeout_s
        captured["command"] = command
        captured["input"] = request_bytes
        return bundle.model_dump_json().encode("utf-8")

    monkeypatch.setattr(
        "rolo.stages.adapt.target_evidence._run_ssh_transport", fake_transport
    )
    received = collect_over_ssh(deployment, request)

    command = captured["command"]
    assert "StrictHostKeyChecking=yes" in command
    assert f"UserKnownHostsFile={known_hosts.resolve()}" in command
    assert deployment.known_hosts_sha256 is not None
    assert deployment.ssh_port == 2222
    assert deployment.ssh_identity_sha256 is not None
    assert "IdentitiesOnly=yes" in command
    assert str(identity.resolve()) in command
    assert command[-5:] == [
        "/opt/rolo/.venv/bin/robotctl",
        "target-evidence",
        "probe-runner",
        "--config",
        ".rolo/config/target-evidence-probe-runner.json",
    ]
    assert received.request_nonce == request.nonce


def test_remote_transport_quotes_probe_runner_argv_at_ssh_boundary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    descriptor, state_path, secret_path = _probe_runner(tmp_path, monkeypatch)
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("target ssh-ed25519 AAAA\n", encoding="utf-8")
    deployment = configure_deployment(
        robot_id="wheeltec",
        mode=EvidenceDeploymentMode.REMOTE,
        descriptor=descriptor,
        verification_secret_path=secret_path,
        output_path=tmp_path / "deployment.json",
        ssh_target="rolo@target",
        known_hosts_path=known_hosts,
        ssh_port=2222,
        probe_runner_executable="/opt/rolo/bin/probe_runner",
    )
    deployment = deployment.model_copy(
        update={"probe_runner_config": "/opt/rolo/config/probe_runner config.json"}
    )
    # Constructing the command directly isolates the SSH boundary from probe_runner execution.
    from rolo.stages.adapt.target_evidence import _ssh_transport_command

    command = _ssh_transport_command(deployment, connect_timeout_s=10)
    assert command[-5:] == [
        "/opt/rolo/bin/probe_runner",
        "target-evidence",
        "probe-runner",
        "--config",
        "'/opt/rolo/config/probe_runner config.json'",
    ]


def test_remote_transport_rejects_in_place_known_hosts_change(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    descriptor, _, secret_path = _probe_runner(tmp_path, monkeypatch)
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("target ssh-ed25519 AAAA\n", encoding="utf-8")
    deployment = configure_deployment(
        robot_id="wheeltec",
        mode=EvidenceDeploymentMode.REMOTE,
        descriptor=descriptor,
        verification_secret_path=secret_path,
        output_path=tmp_path / "deployment.json",
        ssh_target="rolo@target",
        known_hosts_path=known_hosts,
    )
    known_hosts.write_text("target ssh-ed25519 BBBB\n", encoding="utf-8")

    with pytest.raises(SSHTransportError, match="SSH_HOST_KEY_PIN_CHANGED"):
        collect_over_ssh(deployment, new_request("wheeltec"))

    preflight = CliRunner().invoke(
        app,
        [
            "target-evidence",
            "preflight",
            "--robot",
            "wheeltec",
            "--deployment-config",
            str(tmp_path / "deployment.json"),
        ],
    )
    payload = json.loads(preflight.output)
    assert preflight.exit_code == 1
    assert payload["status"] == "NOT_READY"
    assert payload["error_code"] == "SSH_HOST_KEY_PIN_CHANGED"


def test_remote_transport_retries_only_retryable_failures(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    descriptor, state_path, secret_path = _probe_runner(tmp_path, monkeypatch)
    _stub_probes(monkeypatch)
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("target ssh-ed25519 AAAA\n", encoding="utf-8")
    deployment = configure_deployment(
        robot_id="wheeltec",
        mode=EvidenceDeploymentMode.REMOTE,
        descriptor=descriptor,
        verification_secret_path=secret_path,
        output_path=tmp_path / "deployment.json",
        ssh_target="rolo@target",
        known_hosts_path=known_hosts,
    )
    request = new_request("wheeltec")
    bundle = collect_target_evidence(request, load_probe_runner_state(state_path))
    calls = 0

    def flaky_transport(command, request_bytes, *, timeout_s):
        nonlocal calls
        del command, request_bytes, timeout_s
        calls += 1
        if calls == 1:
            raise SSHTransportError("SSH_CONNECTION_LOST", "reset", retryable=True)
        return bundle.model_dump_json().encode("utf-8")

    monkeypatch.setattr(target_evidence_module, "_run_ssh_transport", flaky_transport)
    monkeypatch.setattr(target_evidence_module.time, "sleep", lambda delay: None)

    received = collect_over_ssh(deployment, request, max_attempts=2)

    assert calls == 2
    assert received.request_nonce == request.nonce


def test_legacy_remote_deployment_migrates_to_content_pins(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    descriptor, _, secret_path = _probe_runner(tmp_path, monkeypatch)
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("target ssh-ed25519 AAAA\n", encoding="utf-8")
    deployment_path = tmp_path / "deployment.json"
    deployment = configure_deployment(
        robot_id="wheeltec",
        mode=EvidenceDeploymentMode.REMOTE,
        descriptor=descriptor,
        verification_secret_path=secret_path,
        output_path=deployment_path,
        ssh_target="rolo@target",
        known_hosts_path=known_hosts,
    )
    legacy = deployment.model_dump(mode="json")
    legacy["schema_version"] = "robot-target-evidence-deployment/v2"
    legacy.pop("known_hosts_sha256")
    legacy.pop("ssh_port")
    legacy.pop("ssh_identity_file")
    legacy.pop("ssh_identity_sha256")
    deployment_path.write_text(json.dumps(legacy), encoding="utf-8")

    migrated = load_deployment(deployment_path)
    persisted = json.loads(deployment_path.read_text(encoding="utf-8"))

    assert migrated.schema_version == "robot-target-evidence-deployment/v3"
    assert migrated.known_hosts_sha256 == target_evidence_module.sha256_file(known_hosts)
    assert migrated.ssh_port == 22
    assert persisted["known_hosts_sha256"] == migrated.known_hosts_sha256


def test_ssh_transport_enforces_output_limit_while_process_runs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(target_evidence_module, "MAX_BUNDLE_BYTES", 1024)

    with pytest.raises(SSHTransportError, match="SSH_OUTPUT_LIMIT"):
        target_evidence_module._run_ssh_transport(
            [sys.executable, "-c", "import sys; sys.stdout.buffer.write(b'x' * 2048)"],
            b"{}",
            timeout_s=5,
        )


def test_init_exposes_local_mode_as_install_time_choice(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "rolo.stages.adapt.target_evidence.target_host_fingerprint", lambda: "c" * 64
    )
    get_settings.cache_clear()
    result = CliRunner().invoke(
        app,
        ["init", "--robot-id", "field-rover", "--evidence-mode", "local"],
        env={"ROLO_CONFIG_DIR": str(tmp_path / "config")},
    )
    get_settings.cache_clear()

    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["target_evidence"]["mode"] == "local"
    assert payload["target_evidence"]["probe_runner"]["target_host_fingerprint"] == "c" * 64
    assert (tmp_path / "config/target-evidence/field-rover.json").is_file()


def test_remote_configuration_rejects_unpinned_ssh_host(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    descriptor, _, secret_path = _probe_runner(tmp_path, monkeypatch)

    with pytest.raises(ValueError, match="known_hosts_path"):
        configure_deployment(
            robot_id="wheeltec",
            mode=EvidenceDeploymentMode.REMOTE,
            descriptor=descriptor,
            verification_secret_path=secret_path,
            output_path=tmp_path / "deployment.json",
            ssh_target="rolo@target",
        )


def test_remote_configuration_rejects_unsafe_probe_runner_executable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    descriptor, _, secret_path = _probe_runner(tmp_path, monkeypatch)
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("target ssh-ed25519 AAAA\n", encoding="utf-8")

    with pytest.raises(ValueError, match="probe_runner_executable"):
        configure_deployment(
            robot_id="wheeltec",
            mode=EvidenceDeploymentMode.REMOTE,
            descriptor=descriptor,
            verification_secret_path=secret_path,
            output_path=tmp_path / "deployment.json",
            ssh_target="rolo@target",
            known_hosts_path=known_hosts,
            probe_runner_executable="robotctl;touch /tmp/unsafe",
        )


def test_remote_configuration_rejects_probe_runner_repin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    descriptor, _, secret_path = _probe_runner(tmp_path, monkeypatch)
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("target ssh-ed25519 AAAA\n", encoding="utf-8")
    output = tmp_path / "deployment.json"
    first = configure_deployment(
        robot_id="wheeltec",
        mode=EvidenceDeploymentMode.REMOTE,
        descriptor=descriptor,
        verification_secret_path=secret_path,
        output_path=output,
        ssh_target="rolo@target",
        known_hosts_path=known_hosts,
    )

    repeated = configure_deployment(
        robot_id="wheeltec",
        mode=EvidenceDeploymentMode.REMOTE,
        descriptor=descriptor,
        verification_secret_path=secret_path,
        output_path=output,
        ssh_target="rolo@target",
        known_hosts_path=known_hosts,
    )
    assert repeated == first

    with pytest.raises(ValueError, match="already pinned"):
        configure_deployment(
            robot_id="wheeltec",
            mode=EvidenceDeploymentMode.REMOTE,
            descriptor=descriptor,
            verification_secret_path=secret_path,
            output_path=output,
            ssh_target="rolo@target",
            known_hosts_path=known_hosts,
            probe_runner_executable="/opt/rolo/.venv/bin/robotctl",
        )

    replacement = descriptor.model_copy(update={"source_id": "source-replacement"})
    with pytest.raises(ValueError, match="already pinned"):
        configure_deployment(
            robot_id="wheeltec",
            mode=EvidenceDeploymentMode.REMOTE,
            descriptor=replacement,
            verification_secret_path=secret_path,
            output_path=output,
            ssh_target="rolo@target",
            known_hosts_path=known_hosts,
        )


def test_probe_runner_rotation_stages_parallel_identity_without_overwriting_active(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    descriptor, state_path, secret_path = _probe_runner(tmp_path, monkeypatch)
    previous_state = state_path.read_bytes()
    previous_secret = secret_path.read_bytes()

    replacement = stage_probe_runner_rotation(
        previous_state_path=state_path,
        expected_source_id=descriptor.source_id,
        new_state_path=tmp_path / "source-next.json",
        new_secret_path=tmp_path / "source-next.key",
    )

    assert replacement.source_id != descriptor.source_id
    assert replacement.target_host_fingerprint == descriptor.target_host_fingerprint
    assert state_path.read_bytes() == previous_state
    assert secret_path.read_bytes() == previous_secret
    assert load_probe_runner_state(tmp_path / "source-next.json").source_id == (
        replacement.source_id
    )


def test_reenroll_replaces_expected_pin_and_persists_transition_record(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    descriptor, state_path, secret_path = _probe_runner(tmp_path, monkeypatch)
    deployment_path = tmp_path / "deployment.json"
    configure_deployment(
        robot_id="wheeltec",
        mode=EvidenceDeploymentMode.LOCAL,
        descriptor=descriptor,
        verification_secret_path=secret_path,
        output_path=deployment_path,
        local_probe_runner_state_path=state_path,
    )
    replacement_state = tmp_path / "source-next.json"
    replacement_secret = tmp_path / "source-next.key"
    replacement = stage_probe_runner_rotation(
        previous_state_path=state_path,
        expected_source_id=descriptor.source_id,
        new_state_path=replacement_state,
        new_secret_path=replacement_secret,
    )

    deployment, transition, transition_path = reenroll_deployment(
        output_path=deployment_path,
        expected_source_id=descriptor.source_id,
        reason="scheduled credential rotation",
        descriptor=replacement,
        verification_secret_path=replacement_secret,
        local_probe_runner_state_path=replacement_state,
    )

    assert deployment.probe_runner.source_id == replacement.source_id
    assert deployment.transition_id == transition.transition_id
    assert load_deployment(deployment_path) == deployment
    assert transition.previous_source_id == descriptor.source_id
    assert transition.new_source_id == replacement.source_id
    assert transition_path.is_file()
    assert transition_path.parent.name == "transitions"


def test_reenroll_records_a_remote_probe_runner_executable_change(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    descriptor, _, secret_path = _probe_runner(tmp_path, monkeypatch)
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("target ssh-ed25519 AAAA\n", encoding="utf-8")
    deployment_path = tmp_path / "deployment.json"
    configure_deployment(
        robot_id="wheeltec",
        mode=EvidenceDeploymentMode.REMOTE,
        descriptor=descriptor,
        verification_secret_path=secret_path,
        output_path=deployment_path,
        ssh_target="rolo@target",
        known_hosts_path=known_hosts,
    )

    deployment, transition, _ = reenroll_deployment(
        output_path=deployment_path,
        expected_source_id=descriptor.source_id,
        reason="pin virtualenv robotctl",
        descriptor=descriptor,
        verification_secret_path=secret_path,
        probe_runner_executable="/opt/rolo/.venv/bin/robotctl",
    )

    assert deployment.probe_runner_executable == "/opt/rolo/.venv/bin/robotctl"
    assert transition.previous_probe_runner_executable == "robotctl"
    assert transition.new_probe_runner_executable == "/opt/rolo/.venv/bin/robotctl"
    assert transition.previous_ssh_target == "rolo@target"
    assert transition.new_ssh_target == "rolo@target"
    assert transition.previous_ssh_port == 22
    assert transition.new_ssh_port == 22
    assert transition.previous_probe_runner_config == (
        ".rolo/config/target-evidence-probe-runner.json"
    )


def test_reenroll_audits_known_hosts_content_rotation_at_the_same_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    descriptor, _, secret_path = _probe_runner(tmp_path, monkeypatch)
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("target ssh-ed25519 AAAA\n", encoding="utf-8")
    deployment_path = tmp_path / "deployment.json"
    previous = configure_deployment(
        robot_id="wheeltec",
        mode=EvidenceDeploymentMode.REMOTE,
        descriptor=descriptor,
        verification_secret_path=secret_path,
        output_path=deployment_path,
        ssh_target="rolo@target",
        known_hosts_path=known_hosts,
    )
    known_hosts.write_text("target ssh-ed25519 BBBB\n", encoding="utf-8")

    deployment, transition, _ = reenroll_deployment(
        output_path=deployment_path,
        expected_source_id=descriptor.source_id,
        reason="verified SSH host key rotation",
        descriptor=descriptor,
        verification_secret_path=secret_path,
        known_hosts_path=known_hosts,
    )

    assert deployment.known_hosts_sha256 != previous.known_hosts_sha256
    assert transition.previous_known_hosts_sha256 == previous.known_hosts_sha256
    assert transition.new_known_hosts_sha256 == deployment.known_hosts_sha256


def test_local_journey_reuses_reenrolled_probe_runner_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "rolo.stages.adapt.target_evidence.target_host_fingerprint", lambda: "a" * 64
    )
    original, original_state = ensure_local_deployment(
        robot_id="wheeltec",
        config_root=tmp_path,
    )
    replacement_state = tmp_path / "source-next.json"
    replacement_secret = tmp_path / "source-next.key"
    replacement = stage_probe_runner_rotation(
        previous_state_path=original_state,
        expected_source_id=original.probe_runner.source_id,
        new_state_path=replacement_state,
        new_secret_path=replacement_secret,
    )
    deployment_path = tmp_path / "target-evidence/wheeltec.json"
    reenroll_deployment(
        output_path=deployment_path,
        expected_source_id=original.probe_runner.source_id,
        reason="scheduled credential rotation",
        descriptor=replacement,
        verification_secret_path=replacement_secret,
        local_probe_runner_state_path=replacement_state,
    )

    ensured, ensured_state = ensure_local_deployment(
        robot_id="wheeltec",
        config_root=tmp_path,
    )

    assert ensured.probe_runner.source_id == replacement.source_id
    assert ensured_state == replacement_state.resolve()


def test_refresh_local_deployment_expands_pinned_help_allowlist(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "rolo.stages.adapt.target_evidence.target_host_fingerprint", lambda: "a" * 64
    )
    project_root = tmp_path / "project"
    bin_dir = project_root / ".venv" / "bin"
    bin_dir.mkdir(parents=True)
    (project_root / "pyproject.toml").write_text(
        "[project.scripts]\n"
        "demo-camera = 'demo:camera'\n"
        "demo-teleoperate = 'demo:teleoperate'\n",
        encoding="utf-8",
    )
    first = bin_dir / "demo-camera"
    second = bin_dir / "demo-teleoperate"
    first.write_text("#!/bin/sh\n", encoding="utf-8")
    second.write_text("#!/bin/sh\n", encoding="utf-8")

    original, state_path = ensure_local_deployment(
        robot_id="refresh-demo",
        config_root=tmp_path,
        help_executables=[first],
    )
    deployment, transition, transition_path, refreshed_state = refresh_local_deployment(
        robot_id="refresh-demo",
        config_root=tmp_path,
        project_root=project_root,
        expected_source_id=original.probe_runner.source_id,
    )

    assert deployment.probe_runner.source_id != original.probe_runner.source_id
    assert {Path(item.path).name for item in deployment.probe_runner.help_executables} == {
        "demo-camera",
        "demo-teleoperate",
    }
    assert transition.previous_source_id == original.probe_runner.source_id
    assert transition.new_source_id == deployment.probe_runner.source_id
    assert transition_path.is_file()
    assert refreshed_state == Path(deployment.local_probe_runner_state_path or "")
    assert refreshed_state.is_file()
    assert state_path.read_text(encoding="utf-8")


def test_reenroll_rejects_stale_expected_pin_without_changing_deployment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    descriptor, state_path, secret_path = _probe_runner(tmp_path, monkeypatch)
    deployment_path = tmp_path / "deployment.json"
    configure_deployment(
        robot_id="wheeltec",
        mode=EvidenceDeploymentMode.LOCAL,
        descriptor=descriptor,
        verification_secret_path=secret_path,
        output_path=deployment_path,
        local_probe_runner_state_path=state_path,
    )
    original = deployment_path.read_bytes()
    replacement = stage_probe_runner_rotation(
        previous_state_path=state_path,
        expected_source_id=descriptor.source_id,
        new_state_path=tmp_path / "source-next.json",
        new_secret_path=tmp_path / "source-next.key",
    )

    with pytest.raises(ValueError, match="expected re-enrollment pin"):
        reenroll_deployment(
            output_path=deployment_path,
            expected_source_id="source-stale",
            reason="scheduled credential rotation",
            descriptor=replacement,
            verification_secret_path=tmp_path / "source-next.key",
            local_probe_runner_state_path=tmp_path / "source-next.json",
        )

    assert deployment_path.read_bytes() == original
    assert not (tmp_path / "transitions").exists()


def test_rotation_and_reenrollment_cli_preserve_explicit_handoff(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    descriptor, state_path, secret_path = _probe_runner(tmp_path, monkeypatch)
    deployment_path = tmp_path / "deployment.json"
    configure_deployment(
        robot_id="wheeltec",
        mode=EvidenceDeploymentMode.LOCAL,
        descriptor=descriptor,
        verification_secret_path=secret_path,
        output_path=deployment_path,
        local_probe_runner_state_path=state_path,
    )
    replacement_state = tmp_path / "source-next.json"
    replacement_secret = tmp_path / "source-next.key"
    descriptor_path = tmp_path / "source-next-descriptor.json"
    runner = CliRunner()

    staged = runner.invoke(
        app,
        [
            "target-evidence",
            "probe-runner-rotate",
            "--previous-config",
            str(state_path),
            "--expected-source-id",
            descriptor.source_id,
            "--config",
            str(replacement_state),
            "--secret-file",
            str(replacement_secret),
            "--descriptor-out",
            str(descriptor_path),
        ],
    )

    assert staged.exit_code == 0, staged.output
    assert json.loads(staged.output)["previous_probe_runner_preserved"] is True
    replacement = json.loads(descriptor_path.read_text(encoding="utf-8"))
    reenrolled = runner.invoke(
        app,
        [
            "target-evidence",
            "re-enroll",
            "--robot",
            "wheeltec",
            "--deployment-config",
            str(deployment_path),
            "--expected-source-id",
            descriptor.source_id,
            "--reason",
            "scheduled credential rotation",
            "--source-descriptor",
            str(descriptor_path),
            "--verification-secret",
            str(replacement_secret),
            "--source-state",
            str(replacement_state),
        ],
    )

    assert reenrolled.exit_code == 0, reenrolled.output
    payload = json.loads(reenrolled.output)
    assert payload["status"] == "TARGET_EVIDENCE_REENROLLED"
    assert payload["deployment"]["probe_runner"]["source_id"] == replacement["source_id"]
    assert Path(payload["transition_path"]).is_file()


def test_local_init_is_idempotent_and_preserves_probe_runner_pin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "rolo.stages.adapt.target_evidence.target_host_fingerprint", lambda: "d" * 64
    )
    environment = {"ROLO_CONFIG_DIR": str(tmp_path / "config")}
    runner = CliRunner()
    get_settings.cache_clear()
    first = runner.invoke(
        app,
        ["init", "--robot-id", "field-rover", "--evidence-mode", "local"],
        env=environment,
    )
    get_settings.cache_clear()
    repeated = runner.invoke(
        app,
        ["init", "--robot-id", "field-rover", "--evidence-mode", "local"],
        env=environment,
    )
    get_settings.cache_clear()

    assert first.exit_code == 0, first.output
    assert repeated.exit_code == 0, repeated.output
    first_payload = json.loads(first.output)
    repeated_payload = json.loads(repeated.output)
    assert (
        first_payload["target_evidence"]["probe_runner"]
        == (repeated_payload["target_evidence"]["probe_runner"])
    )
    assert repeated_payload["registration"]["status"] == "ALREADY_REGISTERED"


def test_request_protocol_rejects_write_mode() -> None:
    payload = new_request("wheeltec").model_dump(mode="json")
    payload["mode"] = "WRITE"

    with pytest.raises(ValueError):
        from rolo.stages.adapt.target_evidence import TargetEvidenceRequest

        TargetEvidenceRequest.model_validate(payload)


def test_discovery_uses_bound_target_probes_not_controller_host(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "driver.py").write_text('create_publisher(Twist, "/cmd_vel", 10)\n', encoding="utf-8")
    target_binding = {
        "schema_version": "robot-target-evidence-binding/v1",
        "robot_id": "demo_diff",
        "source_id": "source-target",
        "target_host_fingerprint": "a" * 64,
        "bundle_payload_sha256": "b" * 64,
        "access": "READ_ONLY",
        "deployment_mode": "local",
        "collected_at": datetime.now(timezone.utc).isoformat(),
    }
    target_probes = {
        "hw": ProbeResult(
            layer="hw",
            status="SUCCEEDED",
            data={"components": [], "target_evidence": target_binding},
        ),
        "linux": ProbeResult(
            layer="linux", status="SUCCEEDED", data={"target_evidence": target_binding}
        ),
        "ros": ProbeResult(
            layer="ros",
            status="SUCCEEDED",
            data={
                "nodes": [],
                "topics": [],
                "services": [],
                "actions": [],
                "target_evidence": target_binding,
            },
        ),
    }
    monkeypatch.setattr(
        "rolo.stages.adapt.discovery.HardwareProbe.run",
        lambda *args, **kwargs: pytest.fail("controller hardware probe must not run"),
    )
    monkeypatch.setattr(
        "rolo.stages.adapt.discovery.LinuxProbe.run",
        lambda *args, **kwargs: pytest.fail("controller Linux probe must not run"),
    )
    monkeypatch.setattr(
        "rolo.stages.adapt.discovery.RosProbe.run",
        lambda *args, **kwargs: pytest.fail("controller ROS probe must not run"),
    )
    registry = RobotRegistry(Path("tests/fixtures/robots"))
    registry.load()

    report, _ = DiscoveryService(ArtifactStore(tmp_path / "artifacts")).run(
        robot=registry.get("demo_diff"),
        active_inputs=ActiveDiscoveryInputs(
            source_roots=[source], active_probe=ActiveProbeMode.RUNTIME_READONLY
        ),
        target_probes=target_probes,
    )

    assert report.probes["hw"].data["target_evidence"]["source_id"] == "source-target"
    assert report.probes["linux"].data["target_evidence"]["robot_id"] == "demo_diff"


def test_discovery_rejects_unbound_precollected_probes(tmp_path: Path) -> None:
    registry = RobotRegistry(Path("tests/fixtures/robots"))
    registry.load()
    probes = {
        layer: ProbeResult(layer=layer, status="SUCCEEDED", data={})
        for layer in ("hw", "linux", "ros")
    }

    with pytest.raises(ValueError, match="lack verified target binding"):
        DiscoveryService(ArtifactStore(tmp_path / "artifacts")).run(
            robot=registry.get("demo_diff"),
            active_inputs=ActiveDiscoveryInputs(active_probe=ActiveProbeMode.RUNTIME_READONLY),
            target_probes=probes,
        )


def test_runtime_discovery_requires_verified_target_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    registry = RobotRegistry(Path("tests/fixtures/robots"))
    registry.load()
    monkeypatch.setattr(
        "rolo.stages.adapt.discovery.HardwareProbe.run",
        lambda *args, **kwargs: pytest.fail("controller hardware probe must not run"),
    )
    monkeypatch.setattr(
        "rolo.stages.adapt.discovery.LinuxProbe.run",
        lambda *args, **kwargs: pytest.fail("controller Linux probe must not run"),
    )
    monkeypatch.setattr(
        "rolo.stages.adapt.discovery.RosProbe.run",
        lambda *args, **kwargs: pytest.fail("controller ROS probe must not run"),
    )

    with pytest.raises(ValueError, match="verified target evidence bundle"):
        DiscoveryService(ArtifactStore(tmp_path / "artifacts")).run(
            robot=registry.get("demo_diff"),
            active_inputs=ActiveDiscoveryInputs(active_probe=ActiveProbeMode.RUNTIME_READONLY),
        )


def test_granular_runtime_discovery_cli_requires_signed_bundle() -> None:
    result = CliRunner().invoke(
        app,
        [
            "adapt",
            "discover",
            "run",
            "--robot",
            "demo_diff",
            "--active-probe",
            "runtime-readonly",
        ],
    )

    assert result.exit_code == 2


def test_source_only_discovery_never_attributes_controller_probes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "README.md").write_text("# Static application evidence\n", encoding="utf-8")
    registry = RobotRegistry(Path("tests/fixtures/robots"))
    registry.load()
    monkeypatch.setattr(
        "rolo.stages.adapt.discovery.HardwareProbe.run",
        lambda *args, **kwargs: pytest.fail("controller hardware probe must not run"),
    )
    monkeypatch.setattr(
        "rolo.stages.adapt.discovery.LinuxProbe.run",
        lambda *args, **kwargs: pytest.fail("controller Linux probe must not run"),
    )
    monkeypatch.setattr(
        "rolo.stages.adapt.discovery.RosProbe.run",
        lambda *args, **kwargs: pytest.fail("controller ROS probe must not run"),
    )

    report, _ = DiscoveryService(ArtifactStore(tmp_path / "artifacts")).run(
        robot=registry.get("demo_diff"),
        active_inputs=ActiveDiscoveryInputs(
            source_roots=[source],
            document_roots=[source],
            active_probe=ActiveProbeMode.NONE,
        ),
    )

    assert report.probes["hw"].status == "UNAVAILABLE"
    assert report.probes["linux"].status == "UNAVAILABLE"
    assert report.probes["ros"].status == "UNAVAILABLE"


def test_remote_probe_loop_cannot_fall_back_to_controller_runtime(tmp_path: Path) -> None:
    dispatcher = _DeterministicR0ProbeDispatcher(
        robot_id="wheeltec",
        run_root=tmp_path / "run",
        artifact_prefix="artifact://discovery/wheeltec/runs/test",
        artifacts=ArtifactStore(tmp_path / "artifacts"),
        software_policy=SoftwareDiscoveryPolicy(),
        dependency_report_ref="artifact://discovery/wheeltec/runs/test/dependencies.json",
        allow_host_runtime_probes=False,
    )

    with pytest.raises(RuntimeError, match="new signed bundle"):
        dispatcher._hardware(object(), object())
