from __future__ import annotations

import json
import shutil
import sys
import time
from pathlib import Path
from typing import Annotated

import typer

from rolo.commands.common import emit
from rolo.core.config import get_settings
from rolo.stages.probe.ros_environment import select_ros_setup_files
from rolo.stages.probe.target_evidence import (
    CollectorDescriptor,
    EvidenceDeploymentMode,
    SSHTransportError,
    TargetEvidenceBundle,
    TargetEvidenceRequest,
    collect_over_ssh,
    collect_target_evidence,
    configure_deployment,
    discover_help_executables,
    initialize_collector,
    load_collector_state,
    load_deployment,
    new_request,
    reenroll_deployment,
    refresh_local_deployment,
    restricted_collector_authorized_key,
    stage_collector_rotation,
    verify_evidence_bundle,
)

target_evidence_app = typer.Typer(
    help="Configure and collect target-bound, read-only Probe evidence."
)


@target_evidence_app.command("ssh-authorized-key")
def ssh_authorized_key(
    public_key: Annotated[Path, typer.Option("--public-key")],
    collector_executable: Annotated[
        str, typer.Option("--collector-executable")
    ] = "robotctl",
    collector_config: Annotated[
        str, typer.Option("--collector-config")
    ] = ".rolo/config/target-evidence-collector.json",
) -> None:
    """Generate a forced-command authorized_keys entry for a dedicated Collector account."""
    try:
        entry = restricted_collector_authorized_key(
            public_key.read_text(encoding="utf-8"),
            collector_executable=collector_executable,
            collector_config=collector_config,
        )
    except (OSError, ValueError) as exc:
        raise typer.BadParameter(str(exc)) from exc
    emit({"status": "GENERATED", "authorized_keys_entry": entry})


def deployment_path(robot_id: str) -> Path:
    return get_settings().rolo_config_dir / "target-evidence" / f"{robot_id}.json"


@target_evidence_app.command("collector-init")
def collector_init(
    robot_id: Annotated[str, typer.Option("--robot-id", "--robot")],
    config: Annotated[
        Path,
        typer.Option("--config", help="Target-local collector state path"),
    ] = Path(".rolo/config/target-evidence-collector.json"),
    secret_file: Annotated[
        Path,
        typer.Option("--secret-file", help="Target-local 0600 signing secret"),
    ] = Path(".rolo/config/target-evidence-collector.key"),
    descriptor_out: Annotated[
        Path | None,
        typer.Option("--descriptor-out", help="Non-secret descriptor for the controller"),
    ] = None,
    allow_executable: Annotated[
        list[Path] | None,
        typer.Option(
            "--allow-executable",
            help="Exact target executable permitted for bounded --help evidence; repeatable",
        ),
    ] = None,
    project_root: Annotated[
        Path | None,
        typer.Option("--project-root", help="Target workspace used for ROS overlay detection"),
    ] = None,
    ros_setup: Annotated[
        list[Path] | None,
        typer.Option("--ros-setup", help="Approved ROS setup file; repeat in source order"),
    ] = None,
) -> None:
    """Initialize the target-side collector and print its pinned identity."""
    try:
        settings = get_settings()
        install_roots = (
            [project_root.expanduser().resolve() / "install"] if project_root is not None else []
        )
        _, ros_setup_files = select_ros_setup_files(
            auto_source=settings.ros_auto_source,
            configured=ros_setup or settings.ros_setup_files,
            project_root=project_root,
            install_roots=install_roots,
        )
        descriptor = initialize_collector(
            robot_id=robot_id,
            state_path=config,
            secret_path=secret_file,
            help_executables=(
                allow_executable
                if allow_executable
                else discover_help_executables(project_root) if project_root else ()
            ),
            ros_setup_files=ros_setup_files,
        )
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    if descriptor_out is not None:
        descriptor_out.parent.mkdir(parents=True, exist_ok=True)
        descriptor_out.write_text(descriptor.model_dump_json(indent=2) + "\n", encoding="utf-8")
    emit(
        {
            "status": "COLLECTOR_READY",
            "descriptor": descriptor.model_dump(mode="json"),
            "descriptor_path": str(descriptor_out) if descriptor_out else None,
            "secret_path": str(secret_file.resolve()),
            "warning": "Provision the secret to the controller through a separate secure channel.",
            "access": "READ_ONLY",
        }
    )


@target_evidence_app.command("collector-rotate")
def collector_rotate(
    previous_config: Annotated[Path, typer.Option("--previous-config")],
    expected_collector_id: Annotated[str, typer.Option("--expected-collector-id")],
    config: Annotated[Path, typer.Option("--config", help="New parallel collector state")],
    secret_file: Annotated[
        Path, typer.Option("--secret-file", help="New parallel 0600 signing secret")
    ],
    descriptor_out: Annotated[Path, typer.Option("--descriptor-out")],
    allow_executable: Annotated[
        list[Path] | None,
        typer.Option(
            "--allow-executable",
            help="Exact executable permitted by the replacement collector; repeatable",
        ),
    ] = None,
    project_root: Annotated[Path | None, typer.Option("--project-root")] = None,
    ros_setup: Annotated[
        list[Path] | None,
        typer.Option("--ros-setup", help="Approved replacement setup file; repeatable"),
    ] = None,
) -> None:
    """Stage rotated target credentials without overwriting the active collector."""
    try:
        settings = get_settings()
        install_roots = (
            [project_root.expanduser().resolve() / "install"] if project_root is not None else []
        )
        _, ros_setup_files = select_ros_setup_files(
            auto_source=settings.ros_auto_source,
            configured=ros_setup or settings.ros_setup_files,
            project_root=project_root,
            install_roots=install_roots,
        )
        descriptor = stage_collector_rotation(
            previous_state_path=previous_config,
            expected_collector_id=expected_collector_id,
            new_state_path=config,
            new_secret_path=secret_file,
            help_executables=(
                allow_executable
                if allow_executable
                else discover_help_executables(project_root) if project_root else ()
            ),
            ros_setup_files=ros_setup_files,
        )
        descriptor_out.parent.mkdir(parents=True, exist_ok=True)
        descriptor_out.write_text(
            descriptor.model_dump_json(indent=2) + "\n",
            encoding="utf-8",
        )
    except (OSError, ValueError) as exc:
        raise typer.BadParameter(str(exc)) from exc
    emit(
        {
            "status": "COLLECTOR_ROTATION_STAGED",
            "descriptor": descriptor.model_dump(mode="json"),
            "descriptor_path": str(descriptor_out),
            "secret_path": str(secret_file.resolve()),
            "previous_collector_preserved": True,
            "next": "transfer the new descriptor and secret, then run re-enroll",
        }
    )


@target_evidence_app.command("collector-refresh")
def collector_refresh(
    robot_id: Annotated[str, typer.Option("--robot-id", "--robot")],
    project_root: Annotated[
        Path, typer.Option("--project-root", help="Target workspace used to discover entrypoints")
    ],
    expected_collector_id: Annotated[
        str, typer.Option("--expected-collector-id", help="Current pinned collector identity")
    ],
    config_root: Annotated[
        Path | None, typer.Option("--config-root", help="Rolo config root; defaults to settings")
    ] = None,
    allow_executable: Annotated[
        list[Path] | None,
        typer.Option(
            "--allow-executable",
            help="Explicit safe executable override; repeatable (otherwise auto-discover)",
        ),
    ] = None,
    ros_setup: Annotated[
        list[Path] | None,
        typer.Option("--ros-setup", help="Approved ROS setup file; repeat in source order"),
    ] = None,
    reason: Annotated[
        str, typer.Option("--reason", help="Immutable transition reason")
    ] = "refresh target executable help allowlist",
) -> None:
    """Explicitly expand a local collector's bounded executable-help allowlist."""
    try:
        settings = get_settings()
        root = config_root or settings.rolo_config_dir
        install_roots = [project_root.expanduser().resolve() / "install"]
        _, ros_setup_files = select_ros_setup_files(
            auto_source=settings.ros_auto_source,
            configured=ros_setup or settings.ros_setup_files,
            project_root=project_root,
            install_roots=install_roots,
        )
        deployment, transition, transition_path, state_path = refresh_local_deployment(
            robot_id=robot_id,
            config_root=root,
            project_root=project_root,
            expected_collector_id=expected_collector_id,
            help_executables=allow_executable or (),
            ros_setup_files=ros_setup_files,
            reason=reason,
        )
    except (OSError, ValueError) as exc:
        raise typer.BadParameter(str(exc)) from exc
    emit(
        {
            "status": "COLLECTOR_REFRESHED",
            "deployment": deployment.model_dump(mode="json"),
            "transition": transition.model_dump(mode="json"),
            "transition_path": str(transition_path),
            "collector_state": str(state_path),
            "help_executables": [
                item.model_dump(mode="json") for item in deployment.collector.help_executables
            ],
            "next": f"robotctl target-evidence collect --robot {robot_id}",
        }
    )


@target_evidence_app.command("configure")
def configure(
    robot_id: Annotated[str, typer.Option("--robot-id", "--robot")],
    mode: Annotated[EvidenceDeploymentMode, typer.Option("--mode")],
    descriptor_path: Annotated[
        Path, typer.Option("--collector-descriptor", help="Pinned collector descriptor JSON")
    ],
    verification_secret: Annotated[
        Path,
        typer.Option("--verification-secret", help="Securely provisioned collector secret"),
    ],
    ssh_target: Annotated[str | None, typer.Option("--ssh-target")] = None,
    known_hosts: Annotated[
        Path | None,
        typer.Option("--known-hosts", help="Pinned SSH known_hosts file; required remotely"),
    ] = None,
    ssh_port: Annotated[int | None, typer.Option("--ssh-port", min=1, max=65535)] = None,
    ssh_identity_file: Annotated[
        Path | None,
        typer.Option("--ssh-identity-file", help="Pinned controller-side SSH private key"),
    ] = None,
    collector_config: Annotated[
        str,
        typer.Option("--collector-config", help="Collector state path on the target"),
    ] = ".rolo/config/target-evidence-collector.json",
    collector_executable: Annotated[
        str,
        typer.Option(
            "--collector-executable",
            help="Pinned robotctl executable name or absolute path on the remote target",
        ),
    ] = "robotctl",
    output: Annotated[Path | None, typer.Option("--output")] = None,
) -> None:
    """Select local or remote evidence mode for this Rolo installation."""
    try:
        descriptor = CollectorDescriptor.model_validate_json(
            descriptor_path.read_text(encoding="utf-8")
        )
        result = configure_deployment(
            robot_id=robot_id,
            mode=mode,
            descriptor=descriptor,
            verification_secret_path=verification_secret,
            output_path=output or deployment_path(robot_id),
            ssh_target=ssh_target,
            known_hosts_path=known_hosts,
            ssh_port=ssh_port,
            ssh_identity_file=ssh_identity_file,
            collector_config=collector_config,
            collector_executable=collector_executable,
            local_collector_state_path=(
                Path(collector_config) if mode == EvidenceDeploymentMode.LOCAL else None
            ),
        )
    except (OSError, ValueError) as exc:
        raise typer.BadParameter(str(exc)) from exc
    emit(
        {
            "status": "TARGET_EVIDENCE_CONFIGURED",
            "deployment": result.model_dump(mode="json"),
            "next": f"robotctl target-evidence collect --robot {robot_id}",
        }
    )


@target_evidence_app.command("re-enroll")
def re_enroll(
    robot_id: Annotated[str, typer.Option("--robot-id", "--robot")],
    expected_collector_id: Annotated[str, typer.Option("--expected-collector-id")],
    reason: Annotated[str, typer.Option("--reason")],
    descriptor_path: Annotated[Path, typer.Option("--collector-descriptor")],
    verification_secret: Annotated[Path, typer.Option("--verification-secret")],
    mode: Annotated[EvidenceDeploymentMode | None, typer.Option("--mode")] = None,
    ssh_target: Annotated[str | None, typer.Option("--ssh-target")] = None,
    known_hosts: Annotated[Path | None, typer.Option("--known-hosts")] = None,
    ssh_port: Annotated[int | None, typer.Option("--ssh-port", min=1, max=65535)] = None,
    ssh_identity_file: Annotated[
        Path | None, typer.Option("--ssh-identity-file")
    ] = None,
    collector_config: Annotated[str | None, typer.Option("--collector-config")] = None,
    collector_executable: Annotated[
        str | None,
        typer.Option("--collector-executable"),
    ] = None,
    collector_state: Annotated[Path | None, typer.Option("--collector-state")] = None,
    deployment_config: Annotated[Path | None, typer.Option("--deployment-config")] = None,
    transition_dir: Annotated[Path | None, typer.Option("--transition-dir")] = None,
) -> None:
    """Explicitly replace a pinned collector or verification credential."""
    output_path = deployment_config or deployment_path(robot_id)
    try:
        descriptor = CollectorDescriptor.model_validate_json(
            descriptor_path.read_text(encoding="utf-8")
        )
        deployment, transition, transition_path = reenroll_deployment(
            output_path=output_path,
            expected_collector_id=expected_collector_id,
            reason=reason,
            descriptor=descriptor,
            verification_secret_path=verification_secret,
            mode=mode,
            ssh_target=ssh_target,
            known_hosts_path=known_hosts,
            ssh_port=ssh_port,
            ssh_identity_file=ssh_identity_file,
            collector_config=collector_config,
            collector_executable=collector_executable,
            local_collector_state_path=collector_state,
            transition_dir=transition_dir,
        )
    except (OSError, ValueError) as exc:
        raise typer.BadParameter(str(exc)) from exc
    emit(
        {
            "status": "TARGET_EVIDENCE_REENROLLED",
            "deployment": deployment.model_dump(mode="json"),
            "transition": transition.model_dump(mode="json"),
            "transition_path": str(transition_path),
            "next": f"robotctl target-evidence collect --robot {robot_id}",
        }
    )


@target_evidence_app.command("collector-run", hidden=True)
def collector_run(
    config: Annotated[Path, typer.Option("--config")],
) -> None:
    """Run one target-side, stdin/stdout, read-only evidence request."""
    try:
        raw = sys.stdin.buffer.read(64_001)
        if len(raw) > 64_000:
            raise ValueError("target evidence request exceeded its size limit")
        request = TargetEvidenceRequest.model_validate_json(raw)
        bundle = collect_target_evidence(request, load_collector_state(config))
    except (OSError, ValueError) as exc:
        typer.echo(json.dumps({"status": "REJECTED", "error": str(exc)}), err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(bundle.model_dump_json())


@target_evidence_app.command("probe-runner", hidden=True)
def probe_runner(
    config: Annotated[Path, typer.Option("--config")],
) -> None:
    """Compatibility-neutral name for the ordinary SSH Probe runner."""
    collector_run(config)


@target_evidence_app.command("collect")
def collect(
    robot_id: Annotated[str, typer.Option("--robot-id", "--robot")],
    deployment_config: Annotated[Path | None, typer.Option("--deployment-config")] = None,
    collector_state: Annotated[
        Path | None,
        typer.Option("--collector-state", help="Required only for local mode"),
    ] = None,
    output: Annotated[Path | None, typer.Option("--output")] = None,
    timeout: Annotated[float, typer.Option("--timeout", min=1.0, max=300.0)] = 45.0,
    attempts: Annotated[int, typer.Option("--attempts", min=1, max=3)] = 2,
    executable_help_id: Annotated[
        list[str] | None,
        typer.Option(
            "--executable-help-id",
            help="Collector allowlist ID to probe with bounded --help; repeatable",
        ),
    ] = None,
) -> None:
    """Collect and verify one fresh target evidence bundle."""
    try:
        deployment = load_deployment(deployment_config or deployment_path(robot_id))
        requested_help_ids = (
            executable_help_id
            if executable_help_id is not None
            else [item.executable_id for item in deployment.collector.help_executables]
        )
        request = new_request(robot_id, executable_help_ids=requested_help_ids)
        if deployment.mode == EvidenceDeploymentMode.LOCAL:
            state_path = collector_state or Path(deployment.local_collector_state_path or "")
            bundle = collect_target_evidence(request, load_collector_state(state_path))
        else:
            bundle = collect_over_ssh(
                deployment, request, timeout_s=timeout, max_attempts=attempts
            )
        verify_evidence_bundle(bundle, deployment=deployment, request=request)
        destination = output or (
            get_settings().rolo_artifact_dir
            / "target-evidence"
            / robot_id
            / f"{request.nonce}.json"
        )
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(bundle.model_dump_json(indent=2) + "\n", encoding="utf-8")
    except (OSError, ValueError) as exc:
        raise typer.BadParameter(str(exc)) from exc
    emit(
        {
            "status": "VERIFIED",
            "robot_id": robot_id,
            "mode": deployment.mode.value,
            "collector_id": bundle.collector_id,
            "target_host_fingerprint": bundle.target_host_fingerprint,
            "access": bundle.access,
            "bundle": str(destination),
            "executable_help": [
                {
                    "executable_id": item.executable_id,
                    "status": item.help_probe.status.value,
                }
                for item in bundle.executable_help
            ],
            "next": (
                "rolo target application-bundle "
                f"--profile {robot_id} --application <startup|navigation|mapping|manipulation> "
                f"--evidence {destination}"
            ),
        }
    )


@target_evidence_app.command("preflight")
def preflight(
    robot_id: Annotated[str, typer.Option("--robot-id", "--robot")],
    deployment_config: Annotated[Path | None, typer.Option("--deployment-config")] = None,
    timeout: Annotated[float, typer.Option("--timeout", min=1.0, max=300.0)] = 30.0,
    attempts: Annotated[int, typer.Option("--attempts", min=1, max=3)] = 2,
) -> None:
    """Verify pinned SSH transport and collect one disposable signed evidence bundle."""
    started = time.monotonic()
    try:
        if shutil.which("ssh") is None:
            raise SSHTransportError("SSH_CLIENT_UNAVAILABLE", "ssh executable is not installed")
        deployment = load_deployment(deployment_config or deployment_path(robot_id))
        if deployment.mode != EvidenceDeploymentMode.REMOTE:
            raise ValueError("SSH preflight requires a remote target evidence deployment")
        request = new_request(robot_id)
        bundle = collect_over_ssh(
            deployment,
            request,
            timeout_s=timeout,
            max_attempts=attempts,
        )
        verify_evidence_bundle(bundle, deployment=deployment, request=request)
    except (OSError, ValueError) as exc:
        emit(
            {
                "status": "NOT_READY",
                "error_code": getattr(exc, "code", "SSH_PREFLIGHT_FAILED"),
                "error": str(exc),
                "elapsed_ms": round((time.monotonic() - started) * 1000),
            }
        )
        raise typer.Exit(code=1) from exc
    emit(
        {
            "status": "READY",
            "robot_id": robot_id,
            "ssh_target": deployment.ssh_target,
            "ssh_port": deployment.ssh_port,
            "collector_id": bundle.collector_id,
            "target_host_fingerprint": bundle.target_host_fingerprint,
            "known_hosts_sha256": deployment.known_hosts_sha256,
            "elapsed_ms": round((time.monotonic() - started) * 1000),
        }
    )


def load_verified_probes(
    *, robot_id: str, bundle_path: Path, deployment_config: Path | None = None
) -> dict[str, object]:
    deployment = load_deployment(deployment_config or deployment_path(robot_id))
    bundle = TargetEvidenceBundle.model_validate_json(bundle_path.read_text(encoding="utf-8"))
    return verify_evidence_bundle(bundle, deployment=deployment)
