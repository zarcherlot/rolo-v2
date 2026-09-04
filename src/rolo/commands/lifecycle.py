"""Small Probe command surface for Rolo v2.

The Agent owns planning. This module only enrolls/collects target evidence and
exposes a read model; it does not start an Adapter, Trace or Certify workflow.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Literal

import typer
from pydantic import BaseModel, Field

from rolo.commands.common import emit
from rolo.core.config import get_settings, prepare_runtime_directories
from rolo.stages.contracts import StageName
from rolo.stages.pipeline import assess_pipeline, assess_stage
from rolo.stages.probe.active_discovery import ActiveProbeMode
from rolo.stages.probe.ros_environment import select_ros_setup_files
from rolo.stages.probe.target_evidence import (
    CollectorDescriptor,
    EvidenceDeploymentMode,
    TargetEvidenceBundle,
    collect_over_ssh,
    collect_target_evidence,
    configure_deployment,
    ensure_local_deployment,
    load_collector_state,
    load_deployment,
    new_request,
    verify_evidence_bundle,
)

probe_stage_app = typer.Typer(help="Probe a robot target and publish its trusted Tool Surface.")
enroll_app = typer.Typer(help="Inspect the robot identity owned by this installation.")
probe_stage_app.add_typer(enroll_app, name="enroll")


class ProbeStartResult(BaseModel):
    schema_version: Literal["rolo-probe-start/v1"] = "rolo-probe-start/v1"
    status: Literal["READY", "BLOCKED"]
    robot_id: str = Field(min_length=1, max_length=128)
    evidence_ref: str | None = None
    evidence_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    snapshot_ref: str | None = None
    snapshot_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    episode_ref: str | None = None
    episode_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    next_step: str
    limitations: list[str] = Field(default_factory=list)
    observed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


def _bundle_path(robot_id: str) -> Path:
    return get_settings().rolo_config_dir / "target-evidence" / f"{robot_id}-bundle.json"


def _write_bundle(bundle: TargetEvidenceBundle) -> Path:
    path = _bundle_path(bundle.robot_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(bundle.model_dump_json(indent=2) + "\n", encoding="utf-8")
    if path.stat().st_size > 8_000_000:
        path.unlink(missing_ok=True)
        raise ValueError("target evidence bundle exceeds the configured size limit")
    return path


def run_probe_start(
    *,
    robot_id: str,
    project_root: Path | None,
    active_probe: ActiveProbeMode,
    evidence_mode: EvidenceDeploymentMode,
    allow_executable: list[Path] | None,
    collector_descriptor: Path | None,
    verification_secret: Path | None,
    ssh_target: str | None,
    known_hosts: Path | None,
    collector_config: str,
    evidence_timeout: float,
    collector_executable: str | None = None,
    ssh_port: int | None = None,
    ssh_identity_file: Path | None = None,
    evidence_attempts: int = 2,
) -> ProbeStartResult:
    """Collect fresh signed evidence; return the next Agent-owned step."""
    settings = get_settings()
    prepare_runtime_directories(settings)
    if active_probe != ActiveProbeMode.RUNTIME_READONLY:
        return ProbeStartResult(
            status="BLOCKED",
            robot_id=robot_id,
            next_step="use --active-probe runtime-readonly for the v2 Probe chain",
        )
    deployment_path = settings.rolo_config_dir / "target-evidence" / f"{robot_id}.json"
    if evidence_mode == EvidenceDeploymentMode.LOCAL:
        remote_options = (
            collector_descriptor,
            verification_secret,
            ssh_target,
            known_hosts,
            ssh_port,
            ssh_identity_file,
            collector_executable,
        )
        if any(value is not None for value in remote_options):
            raise ValueError("local evidence mode does not accept remote collector options")
        if project_root is None:
            raise ValueError("local evidence mode requires a project root")
        _, ros_setup_files = select_ros_setup_files(
            auto_source=settings.ros_auto_source,
            configured=settings.ros_setup_files,
            project_root=project_root,
            install_roots=(),
        )
        deployment, state_path = ensure_local_deployment(
            robot_id=robot_id,
            config_root=settings.rolo_config_dir,
            project_root=project_root,
            help_executables=allow_executable or (),
            ros_setup_files=ros_setup_files,
        )
        state = load_collector_state(state_path)
        request = new_request(robot_id)
        bundle = collect_target_evidence(request, state)
    else:
        if allow_executable:
            raise ValueError("remote executable allowlists belong to the target collector")
        enrollment_options = (collector_descriptor, verification_secret, ssh_target, known_hosts)
        if deployment_path.is_file() and not any(value is not None for value in enrollment_options):
            deployment = load_deployment(deployment_path)
        else:
            if not all(value is not None for value in enrollment_options):
                raise ValueError(
                    "remote evidence mode requires an enrolled deployment or all collector options"
                )
            descriptor = CollectorDescriptor.model_validate_json(
                collector_descriptor.read_text(encoding="utf-8")
            )
            deployment = configure_deployment(
                robot_id=robot_id,
                mode=EvidenceDeploymentMode.REMOTE,
                descriptor=descriptor,
                verification_secret_path=verification_secret,
                output_path=deployment_path,
                ssh_target=ssh_target,
                known_hosts_path=known_hosts,
                ssh_port=ssh_port,
                ssh_identity_file=ssh_identity_file,
                collector_config=collector_config,
                collector_executable=collector_executable or "robotctl",
            )
        request = new_request(robot_id)
        bundle = collect_over_ssh(
            deployment,
            request,
            timeout_s=evidence_timeout,
            max_attempts=evidence_attempts,
        )
    verify_evidence_bundle(bundle, deployment=deployment, request=request)
    path = _write_bundle(bundle)
    # RKB-4 is a one-way publication boundary: legacy bundle remains readable,
    # while the verified snapshot and metadata-only Episode become the new
    # artifact path.  Publication failure must not affect the legacy bundle.
    from rolo.rkb import publish_probe_episode

    bundle_ref = f"artifact://legacy/target-evidence/{bundle.robot_id}-bundle.json"
    snapshot, episode, snapshot_path, episode_path = publish_probe_episode(
        bundle,
        artifact_root=settings.rolo_artifact_dir,
        deployment_mode=evidence_mode.value,
        bundle_ref=bundle_ref,
        legacy_root=settings.rolo_config_dir,
    )
    artifact_root = settings.rolo_artifact_dir.resolve()

    def artifact_ref(path: Path) -> str:
        return f"artifact://{path.resolve().relative_to(artifact_root).as_posix()}"

    return ProbeStartResult(
        status="READY",
        robot_id=robot_id,
        evidence_ref=str(path),
        evidence_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        snapshot_ref=artifact_ref(snapshot_path),
        snapshot_sha256=snapshot.digest,
        episode_ref=artifact_ref(episode_path),
        episode_sha256=episode.content_sha256,
        next_step=(
            f"agent reads `rolo target tool-surface --profile {robot_id}` and emits a ToolPlan"
        ),
        limitations=["target evidence is a read-only snapshot, not a physical safety certificate"],
    )


@probe_stage_app.command("start")
def probe_stage_start(
    robot_id: Annotated[str, typer.Option("--robot-id", "--robot")],
    project_root: Annotated[Path | None, typer.Option("--project-root")] = None,
    active_probe: Annotated[
        ActiveProbeMode, typer.Option("--active-probe")
    ] = ActiveProbeMode.RUNTIME_READONLY,
    evidence_mode: Annotated[
        EvidenceDeploymentMode, typer.Option("--evidence-mode")
    ] = EvidenceDeploymentMode.LOCAL,
    allow_executable: Annotated[list[Path] | None, typer.Option("--allow-executable")] = None,
    collector_descriptor: Annotated[Path | None, typer.Option("--collector-descriptor")] = None,
    verification_secret: Annotated[Path | None, typer.Option("--verification-secret")] = None,
    ssh_target: Annotated[str | None, typer.Option("--ssh-target")] = None,
    known_hosts: Annotated[Path | None, typer.Option("--known-hosts")] = None,
    ssh_port: Annotated[int | None, typer.Option("--ssh-port", min=1, max=65535)] = None,
    ssh_identity_file: Annotated[Path | None, typer.Option("--ssh-identity-file")] = None,
    collector_config: Annotated[
        str, typer.Option("--collector-config")
    ] = ".rolo/config/target-evidence-collector.json",
    evidence_timeout: Annotated[
        float, typer.Option("--evidence-timeout", min=1.0, max=300.0)
    ] = 45.0,
) -> None:
    """Collect target evidence; Agent planning starts after this command returns."""
    try:
        emit(
            run_probe_start(
                robot_id=robot_id,
                project_root=project_root,
                active_probe=active_probe,
                evidence_mode=evidence_mode,
                allow_executable=allow_executable,
                collector_descriptor=collector_descriptor,
                verification_secret=verification_secret,
                ssh_target=ssh_target,
                known_hosts=known_hosts,
                collector_config=collector_config,
                evidence_timeout=evidence_timeout,
                ssh_port=ssh_port,
                ssh_identity_file=ssh_identity_file,
            )
        )
    except (FileNotFoundError, OSError, ValueError) as exc:
        raise typer.BadParameter(str(exc)) from exc


@probe_stage_app.command("status")
def probe_stage_status(robot: Annotated[str, typer.Option("--robot")]) -> None:
    """Show the evidence readiness of one enrolled robot."""
    settings = get_settings()
    emit(assess_stage(StageName.PROBE, settings.rolo_artifact_dir, robot))


@enroll_app.command("show")
def enrollment_show() -> None:
    """Show the profiles owned by this installation."""
    from rolo.targets.profiles import TargetProfileStore

    profiles = TargetProfileStore(get_settings().rolo_config_dir).list_profiles()
    emit([item.model_dump(mode="json") for item in profiles])


def register_lifecycle_commands(root: typer.Typer) -> None:
    root.add_typer(probe_stage_app, name="probe")

    @root.command("pipeline-status")
    def pipeline_status(robot: Annotated[str, typer.Option("--robot")]) -> None:
        emit(assess_pipeline(get_settings().rolo_artifact_dir, robot))
