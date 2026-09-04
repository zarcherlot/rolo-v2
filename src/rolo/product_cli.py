"""Small Rolo v2 product entrypoint.

The interactive Agent owns intent, coding and planning. Rolo owns the trusted
target boundary: enrollment references, fresh signed Probe evidence, typed Tool
registration, a frozen Tool Surface, and execution of digest-bound plans.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated
from uuid import uuid4

import typer

from rolo.agent_tools import ToolPlan, conform_tool_surface, create_profile_native_tool_session
from rolo.commands.common import emit
from rolo.commands.lifecycle import run_probe_start
from rolo.core.artifacts import ArtifactStore
from rolo.core.config import get_settings
from rolo.mvp.probe_registration import (
    ToolRegistrationProposal,
    build_probe_analysis_input,
    load_registered_descriptors,
    load_registered_proposals,
    register_tool_proposal,
)
from rolo.mvp.ros_binding import RosBindingExecutor
from rolo.release_check import run_release_check
from rolo.stages.probe.active_discovery import ActiveProbeMode
from rolo.stages.probe.application import (
    APPLICATION_IDS,
    build_application_adapter_bundle,
    build_application_operation_adapter_bundle,
    conform_application_bundle,
    conform_application_operation_bundle,
    discover_application_candidate,
    discover_application_operation,
)
from rolo.stages.probe.routes import observed_probe_routes
from rolo.stages.probe.target_evidence import (
    EvidenceDeploymentMode,
    TargetEvidenceBundle,
    load_deployment,
    verify_evidence_bundle,
)
from rolo.target_ref import LocalTargetRef, parse_target_ref
from rolo.targets.executor import (
    create_profile_target_executor,
    create_target_executor,
)
from rolo.targets.models import BootstrapPlanStatus, TargetConnectionState
from rolo.targets.profiles import CredentialReference, TargetProfileStore

app = typer.Typer(help="Probe a local or remote robot target.", no_args_is_help=True)
target_app = typer.Typer(help="Inspect an enrolled target and consume its Tool Surface.")
profile_app = typer.Typer(help="Manage non-secret target connection profiles.")
app.add_typer(target_app, name="target")
target_app.add_typer(profile_app, name="profile")


@app.command("release-check")
def release_check(
    require_artifacts: Annotated[bool, typer.Option("--require-artifacts/--allow-missing-artifacts")] = False,
) -> None:
    """Run release smoke checks for the v2 product surface."""
    result = run_release_check(require_artifacts=require_artifacts)
    emit(result)
    if result.status != "PASS":
        raise typer.Exit(code=2)


def _target_executor(
    target: str,
    known_hosts: Path | None,
    timeout: float,
    identity_file: Path | None = None,
):
    return create_target_executor(
        parse_target_ref(target),
        known_hosts=known_hosts,
        identity_file=identity_file,
        timeout_s=timeout,
    )


def _write_conformance(session) -> tuple[object, str]:
    report = conform_tool_surface(session.descriptor, session.runner.list_tools())
    relative = f"native/{session.descriptor.robot_id}/sessions/{session.descriptor.session_id}/conformance.json"
    session.artifacts.write_json(relative, report.model_dump(mode="json"))
    return report, f"artifact://{relative}"


@target_app.command("inspect")
def target_inspect(
    target: Annotated[str, typer.Argument(help="Local path or ssh:// workspace URI")],
    known_hosts: Annotated[Path | None, typer.Option("--known-hosts")] = None,
    identity_file: Annotated[Path | None, typer.Option("--identity-file")] = None,
    timeout: Annotated[float, typer.Option("--timeout", min=1.0, max=300.0)] = 10.0,
) -> None:
    """Inspect target reachability without installing or changing anything."""
    try:
        assessment = _target_executor(target, known_hosts, timeout, identity_file).inspect()
    except (OSError, ValueError) as exc:
        raise typer.BadParameter(str(exc)) from exc
    emit(assessment)
    if assessment.state != TargetConnectionState.READY:
        raise typer.Exit(code=2)


@target_app.command("inspect-profile")
def target_inspect_profile(
    profile: Annotated[str, typer.Option("--profile", "--robot")],
    timeout: Annotated[float, typer.Option("--timeout", min=1.0, max=300.0)] = 10.0,
) -> None:
    """Inspect an enrolled target using its pinned host key and identity."""
    try:
        assessment = create_profile_target_executor(
            profile,
            config_root=get_settings().rolo_config_dir,
            timeout_s=timeout,
        ).inspect()
    except (FileNotFoundError, OSError, ValueError) as exc:
        raise typer.BadParameter(str(exc)) from exc
    emit(assessment)
    if assessment.state != TargetConnectionState.READY:
        raise typer.Exit(code=2)


@target_app.command("bootstrap-plan")
def target_bootstrap_plan(
    target: Annotated[str, typer.Argument(help="Local path or ssh:// workspace URI")],
    known_hosts: Annotated[Path | None, typer.Option("--known-hosts")] = None,
    identity_file: Annotated[Path | None, typer.Option("--identity-file")] = None,
    timeout: Annotated[float, typer.Option("--timeout", min=1.0, max=300.0)] = 10.0,
) -> None:
    """Return a read-only bootstrap readiness plan; never mutate a host."""
    try:
        plan = _target_executor(target, known_hosts, timeout, identity_file).plan_bootstrap()
    except (OSError, ValueError) as exc:
        raise typer.BadParameter(str(exc)) from exc
    emit(plan)
    if plan.status == BootstrapPlanStatus.BLOCKED:
        raise typer.Exit(code=2)


@target_app.command("bootstrap-plan-profile")
def target_bootstrap_plan_profile(
    profile: Annotated[str, typer.Option("--profile", "--robot")],
    timeout: Annotated[float, typer.Option("--timeout", min=1.0, max=300.0)] = 10.0,
) -> None:
    """Return a read-only bootstrap readiness plan for an enrolled profile."""
    try:
        plan = create_profile_target_executor(
            profile,
            config_root=get_settings().rolo_config_dir,
            timeout_s=timeout,
        ).plan_bootstrap()
    except (FileNotFoundError, OSError, ValueError) as exc:
        raise typer.BadParameter(str(exc)) from exc
    emit(plan)
    if plan.status == BootstrapPlanStatus.BLOCKED:
        raise typer.Exit(code=2)


@target_app.command("tool-surface")
def target_tool_surface(
    profile: Annotated[str, typer.Option("--profile", "--robot")],
    timeout: Annotated[float, typer.Option("--timeout", min=1.0, max=300.0)] = 15.0,
    include_registered: Annotated[bool, typer.Option("--include-registered/--native-only")] = False,
) -> None:
    """Publish the native surface, optionally merged with Probe-registered tools."""
    session = None
    try:
        session = create_profile_native_tool_session(
            profile,
            config_root=get_settings().rolo_config_dir,
            artifact_root=get_settings().rolo_artifact_dir,
            timeout_s=timeout,
            additional_descriptors=(load_registered_descriptors(get_settings().rolo_config_dir / "registered-tools", profile) if include_registered else None),
            allow_experimental_write=include_registered,
        )
        conformance = conform_tool_surface(
            session.descriptor,
            session.runner.list_tools(),
            allow_experimental_write=include_registered,
        )
        relative = f"native/{session.descriptor.robot_id}/sessions/{session.descriptor.session_id}/conformance.json"
        conformance_ref = f"artifact://{relative}"
        session.artifacts.write_json(relative, conformance.model_dump(mode="json"))
        emit(
            {
                "status": "TOOL_SURFACE_READY",
                "session": session.descriptor.model_dump(mode="json"),
                "tools": [item.model_dump(mode="json") for item in session.list_tools()],
                "conformance": conformance.model_dump(mode="json"),
                "conformance_ref": conformance_ref,
            }
        )
        if conformance.status != "PASS":
            raise typer.Exit(code=2)
    except (FileNotFoundError, OSError, ValueError) as exc:
        raise typer.BadParameter(str(exc)) from exc
    finally:
        if session is not None:
            session.close()


@target_app.command("tool-plan")
def target_tool_plan(
    profile: Annotated[str, typer.Option("--profile", "--robot")],
    plan_file: Annotated[Path, typer.Argument(help="JSON file containing an Agent ToolPlan")],
    timeout: Annotated[float, typer.Option("--timeout", min=1.0, max=300.0)] = 15.0,
    include_registered: Annotated[bool, typer.Option("--include-registered/--native-only")] = False,
    allow_mutating: Annotated[bool, typer.Option("--allow-mutating/--readonly")] = False,
) -> None:
    """Execute one Agent-authored, digest-bound ToolPlan."""
    session = None
    try:
        plan = ToolPlan.model_validate_json(plan_file.read_text(encoding="utf-8"))
        session = create_profile_native_tool_session(
            profile,
            config_root=get_settings().rolo_config_dir,
            artifact_root=get_settings().rolo_artifact_dir,
            timeout_s=timeout,
            session_id=plan.session_id,
            session_nonce=plan.session_nonce,
            additional_descriptors=(load_registered_descriptors(get_settings().rolo_config_dir / "registered-tools", profile) if include_registered else None),
            allow_experimental_write=include_registered,
        )
        conformance = conform_tool_surface(
            session.descriptor,
            session.runner.list_tools(),
            allow_experimental_write=include_registered,
        )
        relative = f"native/{session.descriptor.robot_id}/sessions/{session.descriptor.session_id}/conformance.json"
        conformance_ref = f"artifact://{relative}"
        session.artifacts.write_json(relative, conformance.model_dump(mode="json"))
        results = session.execute_plan(plan, allow_mutating=allow_mutating)
        emit(
            {
                "status": "TOOL_PLAN_EXECUTED",
                "plan_sha256": plan.plan_sha256,
                "session_id": plan.session_id,
                "results": [item.model_dump(mode="json") for item in results],
                "conformance": conformance.model_dump(mode="json"),
                "conformance_ref": conformance_ref,
            }
        )
    except (FileNotFoundError, OSError, ValueError) as exc:
        raise typer.BadParameter(str(exc)) from exc
    finally:
        if session is not None:
            session.close()


@target_app.command("application-surface")
def target_application_surface(
    profile: Annotated[str, typer.Option("--profile", "--robot")],
) -> None:
    """Emit registered evidence-bound application Tools for a target."""
    try:
        proposals = load_registered_proposals(get_settings().rolo_config_dir / "registered-tools", profile)
    except (OSError, ValueError) as exc:
        raise typer.BadParameter(str(exc)) from exc
    emit(
        {
            "status": "APPLICATION_SURFACE_READY",
            "target_id": profile,
            "tools": [
                {
                    "tool_id": proposal.tool_id,
                    "implementation": proposal.implementation,
                    "descriptor": proposal.descriptor.model_dump(mode="json"),
                    "binding": proposal.binding.model_dump(mode="json") if proposal.binding else None,
                    "evidence_refs": proposal.evidence_refs,
                    "proposal_digest": proposal.digest(),
                }
                for proposal in proposals
            ],
        }
    )


@target_app.command("application-bundle")
def target_application_bundle(
    profile: Annotated[str, typer.Option("--profile", "--robot")],
    application: Annotated[
        str,
        typer.Option(
            "--application",
            help="Small application family: startup, navigation, mapping, or manipulation",
        ),
    ],
    evidence: Annotated[
        Path | None,
        typer.Option("--evidence", help="Verified target evidence JSON; defaults to profile bundle"),
    ] = None,
) -> None:
    """Discover one application gap and emit its minimal adapter/conformance artifacts."""
    try:
        if application not in APPLICATION_IDS:
            raise ValueError(f"unsupported application: {application}; choose one of {APPLICATION_IDS}")
        settings = get_settings()
        target_profile = TargetProfileStore(settings.rolo_config_dir).load(profile)
        robot_id = target_profile.robot_id
        deployment = load_deployment(settings.rolo_config_dir / "target-evidence" / f"{robot_id}.json")
        evidence_path = evidence or (settings.rolo_config_dir / "target-evidence" / f"{robot_id}-bundle.json")
        target_bundle = TargetEvidenceBundle.model_validate_json(evidence_path.read_text(encoding="utf-8"))
        verified_probes = verify_evidence_bundle(target_bundle, deployment=deployment)
        verified_bundle = target_bundle.model_copy(update={"probes": verified_probes})
        candidate = discover_application_candidate(verified_bundle, application)  # type: ignore[arg-type]
        adapter = build_application_adapter_bundle(
            candidate,
            target_evidence_sha256=verified_bundle.payload_sha256,
        )
        report = conform_application_bundle(adapter, candidate, verified_bundle)
        artifact_store = ArtifactStore(settings.rolo_artifact_dir)
        root = f"application/{robot_id}/{application}/{adapter.bundle_id}"
        candidate_path = artifact_store.write_json(f"{root}/candidate.json", candidate.model_dump(mode="json"))
        bundle_path = artifact_store.write_json(f"{root}/adapter-bundle.json", adapter.model_dump(mode="json"))
        conformance_path = artifact_store.write_json(f"{root}/conformance.json", report.model_dump(mode="json"))
    except (FileNotFoundError, OSError, ValueError) as exc:
        raise typer.BadParameter(str(exc)) from exc
    emit(
        {
            "status": ("APPLICATION_BUNDLE_READY" if report.status == "PASS" else "APPLICATION_BUNDLE_REJECTED"),
            "robot_id": robot_id,
            "application": application,
            "candidate": candidate.model_dump(mode="json"),
            "adapter_bundle": adapter.model_dump(mode="json"),
            "conformance": report.model_dump(mode="json"),
            "artifacts": {
                "candidate": str(candidate_path),
                "adapter_bundle": str(bundle_path),
                "conformance": str(conformance_path),
            },
        }
    )
    if report.status != "PASS":
        raise typer.Exit(code=2)


@target_app.command("application-operation")
def target_application_operation(
    profile: Annotated[str, typer.Option("--profile", "--robot")],
    operation: Annotated[
        str,
        typer.Option(
            "--operation",
            help="v1 application operation ID, for example app.navigation.status",
        ),
    ],
    evidence: Annotated[
        Path | None,
        typer.Option("--evidence", help="Verified target evidence JSON; defaults to profile bundle"),
    ] = None,
) -> None:
    """Discover one application operation and emit its minimal conformance bundle."""
    try:
        settings = get_settings()
        target_profile = TargetProfileStore(settings.rolo_config_dir).load(profile)
        robot_id = target_profile.robot_id
        deployment = load_deployment(settings.rolo_config_dir / "target-evidence" / f"{robot_id}.json")
        evidence_path = evidence or (settings.rolo_config_dir / "target-evidence" / f"{robot_id}-bundle.json")
        target_bundle = TargetEvidenceBundle.model_validate_json(evidence_path.read_text(encoding="utf-8"))
        verified_probes = verify_evidence_bundle(target_bundle, deployment=deployment)
        verified_bundle = target_bundle.model_copy(update={"probes": verified_probes})
        candidate = discover_application_operation(verified_bundle, operation)
        adapter = build_application_operation_adapter_bundle(
            candidate,
            target_evidence_sha256=verified_bundle.payload_sha256,
        )
        report = conform_application_operation_bundle(adapter, candidate, verified_bundle)
        artifact_store = ArtifactStore(settings.rolo_artifact_dir)
        operation_path = operation.replace(".", "_")
        root = f"application/{robot_id}/operations/{operation_path}/{adapter.bundle_id}"
        candidate_path = artifact_store.write_json(f"{root}/candidate.json", candidate.model_dump(mode="json"))
        bundle_path = artifact_store.write_json(f"{root}/adapter-bundle.json", adapter.model_dump(mode="json"))
        conformance_path = artifact_store.write_json(f"{root}/conformance.json", report.model_dump(mode="json"))
    except (FileNotFoundError, OSError, ValueError) as exc:
        raise typer.BadParameter(str(exc)) from exc
    emit(
        {
            "status": ("APPLICATION_OPERATION_READY" if report.status == "PASS" else "APPLICATION_OPERATION_REJECTED"),
            "robot_id": robot_id,
            "operation": operation,
            "candidate": candidate.model_dump(mode="json"),
            "adapter_bundle": adapter.model_dump(mode="json"),
            "conformance": report.model_dump(mode="json"),
            "artifacts": {
                "candidate": str(candidate_path),
                "adapter_bundle": str(bundle_path),
                "conformance": str(conformance_path),
            },
        }
    )
    if report.status != "PASS":
        raise typer.Exit(code=2)


@profile_app.command("init")
def profile_init(
    target: Annotated[str, typer.Argument(help="Local path or ssh:// workspace URI")],
    robot_id: Annotated[str, typer.Option("--robot", "--robot-id")],
    credential_ref: Annotated[
        str,
        typer.Option("--credential-ref", help="Typed reference, never secret material"),
    ] = "ssh-agent:default",
    remote_command_prefix: Annotated[
        list[str] | None,
        typer.Option("--remote-command-prefix", help="Fixed target runtime prefix"),
    ] = None,
    provider_hint: Annotated[
        list[str] | None,
        typer.Option(
            "--provider-hint",
            help="Bounded provider hint as key=value; never put credentials here",
        ),
    ] = None,
) -> None:
    """Create a non-secret target profile without connecting or mutating a host."""
    try:
        target_ref = parse_target_ref(target)
        kind, _, _ = credential_ref.partition(":")
        credential = CredentialReference(kind=kind, reference=credential_ref)
        provider_hints: dict[str, str] = {}
        for item in provider_hint or []:
            key, separator, value = item.partition("=")
            if not separator or not key or not value:
                raise ValueError("--provider-hint must use key=value")
            provider_hints[key] = value
        store = TargetProfileStore(get_settings().rolo_config_dir)
        profile = store.create(
            robot_id=robot_id,
            target=target_ref,
            credential=credential,
            remote_command_prefix=remote_command_prefix,
            provider_hints=provider_hints,
        )
    except (OSError, ValueError) as exc:
        raise typer.BadParameter(str(exc)) from exc
    emit(
        {
            "status": "PROFILE_READY",
            "path": str(store.path_for(profile.profile_id)),
            "profile": profile.model_dump(mode="json"),
        }
    )


@profile_app.command("show")
def profile_show(robot_id: Annotated[str, typer.Option("--robot", "--robot-id")]) -> None:
    """Show a profile while keeping credential references secret-free."""
    try:
        store = TargetProfileStore(get_settings().rolo_config_dir)
        profile = store.load(robot_id)
    except (FileNotFoundError, OSError, ValueError) as exc:
        raise typer.BadParameter(str(exc)) from exc
    emit(
        {
            "status": "PROFILE_FOUND",
            "path": str(store.path_for(profile.profile_id)),
            "profile": profile.model_dump(mode="json"),
        }
    )


@profile_app.command("approve-host-key")
def profile_approve_host_key(
    robot_id: Annotated[str, typer.Option("--robot", "--robot-id")],
    fingerprint: Annotated[str, typer.Option("--fingerprint")],
    approver: Annotated[str, typer.Option("--approver")],
) -> None:
    """Record an explicit host-key decision without changing known_hosts."""
    try:
        store = TargetProfileStore(get_settings().rolo_config_dir)
        profile = store.load(robot_id)
        if profile.host_key is None:
            raise ValueError("local target profiles do not have an SSH host key decision")
        if profile.host_key.status == "APPROVED" and profile.host_key.fingerprint != fingerprint:
            raise ValueError("changing an approved host key requires explicit rotation")
        host_key = profile.host_key.model_copy(
            update={
                "status": "APPROVED",
                "fingerprint": fingerprint,
                "decided_at": datetime.now(timezone.utc),
                "decided_by": approver,
            }
        )
        updated = profile.model_copy(update={"host_key": host_key, "updated_at": datetime.now(timezone.utc)})
        store.save(updated)
    except (FileNotFoundError, OSError, ValueError) as exc:
        raise typer.BadParameter(str(exc)) from exc
    emit(
        {
            "status": "HOST_KEY_APPROVED",
            "path": str(store.path_for(updated.profile_id)),
            "profile": updated.model_dump(mode="json"),
        }
    )


@app.command("probe")
def probe(
    target: Annotated[str | None, typer.Argument(help="Optional local workspace path or ssh:// target")] = None,
    robot_id: Annotated[str | None, typer.Option("--robot", "--robot-id")] = None,
    profile: Annotated[str | None, typer.Option("--profile")] = None,
    active_probe: Annotated[ActiveProbeMode, typer.Option("--active-probe")] = ActiveProbeMode.RUNTIME_READONLY,
    allow_executable: Annotated[list[Path] | None, typer.Option("--allow-executable")] = None,
    evidence_timeout: Annotated[float, typer.Option("--evidence-timeout", min=1.0, max=300.0)] = 45.0,
) -> None:
    """Collect fresh signed target evidence; return the next Agent-owned step."""
    try:
        if profile:
            enrolled = TargetProfileStore(get_settings().rolo_config_dir).load(profile)
            if robot_id is not None and robot_id != enrolled.robot_id:
                raise ValueError("--robot does not match --profile")
            robot_id = enrolled.robot_id
            if isinstance(enrolled.target, LocalTargetRef):
                project_root = enrolled.target.workspace
                evidence_mode = EvidenceDeploymentMode.LOCAL
            else:
                project_root = None
                evidence_mode = EvidenceDeploymentMode.REMOTE
        else:
            if not target or not robot_id:
                raise ValueError("provide --profile or both TARGET and --robot")
            target_ref = parse_target_ref(target)
            if isinstance(target_ref, LocalTargetRef):
                project_root = target_ref.workspace
                evidence_mode = EvidenceDeploymentMode.LOCAL
            else:
                project_root = None
                evidence_mode = EvidenceDeploymentMode.REMOTE
        result = run_probe_start(
            robot_id=robot_id,
            project_root=project_root,
            active_probe=active_probe,
            evidence_mode=evidence_mode,
            allow_executable=allow_executable,
            collector_descriptor=None,
            verification_secret=None,
            ssh_target=None,
            known_hosts=None,
            collector_config=".rolo/config/target-evidence-collector.json",
            evidence_timeout=evidence_timeout,
        )
    except (FileNotFoundError, OSError, ValueError) as exc:
        raise typer.BadParameter(str(exc)) from exc
    emit(result)
    if result.status == "BLOCKED":
        raise typer.Exit(code=2)


@app.command("probe-analysis-input")
def probe_analysis_input(
    evidence: Annotated[Path, typer.Option("--evidence", help="Verified TargetEvidenceBundle JSON")],
    requested_tool: Annotated[str | None, typer.Option("--requested-tool")] = None,
) -> None:
    """Emit the bounded envelope that an interactive Agent harness consumes."""
    try:
        bundle = TargetEvidenceBundle.model_validate_json(evidence.read_text(encoding="utf-8"))
        routes = []
        for probe_result in bundle.probes.values():
            routes.extend(route.model_dump(mode="json") for route in observed_probe_routes(probe_result))
        envelope = build_probe_analysis_input(
            target_id=bundle.robot_id,
            target_fingerprint=bundle.target_host_fingerprint,
            evidence_refs=[f"target-evidence:{bundle.payload_sha256}"],
            routes=routes,
            requested_tool=requested_tool,
            limitations=["harness-generated code is untrusted until registration validation"],
        )
    except (OSError, ValueError) as exc:
        raise typer.BadParameter(str(exc)) from exc
    emit(envelope)


@app.command("execute-rotation")
def execute_rotation(
    profile: Annotated[str, typer.Option("--profile", "--robot")],
    proposal: Annotated[Path, typer.Option("--proposal")],
    evidence: Annotated[Path, typer.Option("--evidence")],
    angle_degrees: Annotated[float, typer.Option("--angle-degrees", min=-360.0, max=360.0)],
    max_speed_rad_s: Annotated[float, typer.Option("--max-speed-rad-s", min=0.0001, max=1.0)],
    safety_confirmed: Annotated[bool, typer.Option("--safety-confirmed/--safety-not-confirmed")],
    operator_id: Annotated[str | None, typer.Option("--operator-id", help="Optional audit label; not required for execution")] = None,
    timeout: Annotated[float, typer.Option("--timeout", min=10.0, max=300.0)] = 120.0,
) -> None:
    """Execute one registered rotation binding and persist execution evidence."""
    if not safety_confirmed:
        emit({"status": "BLOCKED", "reason": "physical safety confirmation is required"})
        raise typer.Exit(code=2)
    try:
        bundle = TargetEvidenceBundle.model_validate_json(evidence.read_text(encoding="utf-8"))
        if bundle.robot_id != profile:
            raise ValueError("evidence target does not match profile")
        proposals = load_registered_proposals(get_settings().rolo_config_dir / "registered-tools", profile)
        registered = next((item for item in proposals if item.tool_id == "app.base.rotate"), None)
        if registered is None or registered.implementation != "binding" or registered.binding is None:
            raise ValueError("registered app.base.rotate binding is unavailable")
        supplied = ToolRegistrationProposal.model_validate_json(proposal.read_text(encoding="utf-8"))
        if supplied.digest() != registered.digest():
            raise ValueError("supplied proposal differs from registered Tool")
        deployment = load_deployment(get_settings().rolo_config_dir / "target-evidence" / f"{profile}.json")
        verify_evidence_bundle(bundle, deployment=deployment)
        expected_ref = f"target-evidence:{bundle.payload_sha256}"
        if expected_ref not in registered.evidence_refs or expected_ref not in registered.binding.evidence_refs:
            raise ValueError("registered rotation binding is stale for this Probe evidence")
        routes = {route.resource_id: route for probe in bundle.probes.values() for route in observed_probe_routes(probe)}
        command = routes.get(registered.binding.command_resource_id)
        if command is None or command.interface_type != registered.binding.interface_type:
            raise ValueError("command binding differs from Probe observations")
        for endpoint in registered.binding.feedback_endpoints:
            feedback = routes.get(f"ros_topic:{endpoint}")
            if feedback is None or feedback.interface_type != "nav_msgs/msg/Odometry":
                raise ValueError("rotation feedback must be observed Odometry")
        run_id = uuid4().hex
        evidence_payload = {
            "schema_version": "rolo-rotation-execution-evidence/v1",
            "target_id": profile,
            "tool_id": "app.base.rotate",
            "run_id": run_id,
            "target_fingerprint": bundle.target_host_fingerprint,
            "proposal_digest": registered.digest(),
            "probe_evidence_ref": expected_ref,
            "operator_id": operator_id,
            "safety_confirmed": safety_confirmed,
            "arguments": {"angle_degrees": angle_degrees, "max_speed_rad_s": max_speed_rad_s},
            "result": {"status": "PENDING"},
            "executed_at": datetime.now(timezone.utc).isoformat(),
        }
        relative = f"application/{profile}/rotations/{run_id}.json"
        store = ArtifactStore(get_settings().rolo_artifact_dir)
        store.write_json(relative, evidence_payload)
        try:
            target_executor = create_profile_target_executor(
                profile,
                config_root=get_settings().rolo_config_dir,
                timeout_s=timeout,
                purpose="execution",
            )
            connection = target_executor.inspect()
            if connection.state != TargetConnectionState.READY:
                result = {"status": "BLOCKED", "error": "TARGET_EXECUTION_CHANNEL_UNAVAILABLE", "motion_started": False}
            else:
                result = RosBindingExecutor(target_executor).rotate(
                    registered.binding,
                    {"angle_degrees": angle_degrees, "max_speed_rad_s": max_speed_rad_s},
                )
        except ValueError as exc:
            # Missing or invalid execution transport is a deterministic
            # capability blocker.  Never retry it through the Collector path.
            result = {
                "status": "BLOCKED",
                "error": "TARGET_EXECUTION_CHANNEL_UNAVAILABLE",
                "detail": str(exc)[:240],
                "motion_started": False,
            }
        except OSError as exc:
            result = {"status": "UNKNOWN", "error": type(exc).__name__}
        evidence_payload["result"] = result
        evidence_payload["completed_at"] = datetime.now(timezone.utc).isoformat()
        store.write_json(relative, evidence_payload)
        emit({"status": result.get("status", "UNKNOWN"), "evidence_ref": f"artifact://{relative}", "result": result})
        if result.get("status") != "SUCCEEDED":
            raise typer.Exit(code=2)
    except (FileNotFoundError, OSError, ValueError) as exc:
        raise typer.BadParameter(str(exc)) from exc


@app.command("register-tool")
def register_tool(
    proposal: Annotated[Path, typer.Option("--proposal", help="Harness-produced ToolRegistrationProposal JSON")],
    evidence: Annotated[Path, typer.Option("--evidence", help="Probe evidence used by the proposal")],
) -> None:
    """Validate and register one harness-generated application Tool."""
    try:
        bundle = TargetEvidenceBundle.model_validate_json(evidence.read_text(encoding="utf-8"))
        parsed = ToolRegistrationProposal.model_validate_json(proposal.read_text(encoding="utf-8"))
        observed_route_ids = {
            route.resource_id
            for probe_result in bundle.probes.values()
            for route in observed_probe_routes(probe_result)
        }
        result = register_tool_proposal(
            parsed,
            target_id=bundle.robot_id,
            evidence_refs={f"target-evidence:{bundle.payload_sha256}"},
            observed_route_ids=observed_route_ids,
            registry_root=get_settings().rolo_config_dir / "registered-tools",
        )
    except (OSError, ValueError) as exc:
        raise typer.BadParameter(str(exc)) from exc
    emit(result)
    if result.status == "BLOCKED":
        raise typer.Exit(code=2)


if __name__ == "__main__":
    app()
