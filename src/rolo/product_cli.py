"""Small Rolo v2 product entrypoint.

The interactive Agent owns intent, coding and planning. Rolo owns the trusted
target boundary: enrollment references, fresh signed Probe evidence, typed Tool
registration, a frozen Tool Surface, and execution of digest-bound plans.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
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
from rolo.dsl.admission import MappingConfirmationStore
from rolo.dsl.parser import loads_unique_json
from rolo.dsl.proposal import MappingProposal
from rolo.mvp.binding_dispatch import ApplicationBindingDispatcher
from rolo.mvp.contracts import RunMode
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
targetd_app = typer.Typer(help="Bootstrap and inspect the targetd session bridge.")
app.add_typer(target_app, name="target")
target_app.add_typer(profile_app, name="profile")
app.add_typer(targetd_app, name="targetd")


@app.command("release-check")
def release_check(
    require_artifacts: Annotated[bool, typer.Option("--require-artifacts/--allow-missing-artifacts")] = False,
) -> None:
    """Run release smoke checks for the v2 product surface."""
    result = run_release_check(require_artifacts=require_artifacts)
    emit(result)
    if result.status != "PASS":
        raise typer.Exit(code=2)


@targetd_app.command("status")
def targetd_status(
    target: Annotated[str, typer.Argument(help="ssh://user@host[:port]/workspace")],
    known_hosts: Annotated[Path, typer.Option("--known-hosts")],
    identity_file: Annotated[Path, typer.Option("--identity-file")],
    timeout: Annotated[float, typer.Option("--timeout", min=1.0, max=300.0)] = 10.0,
) -> None:
    """Check pinned SSH reachability before opening a targetd session."""
    try:
        assessment = _target_executor(target, known_hosts, timeout, identity_file).inspect()
    except (OSError, ValueError) as exc:
        raise typer.BadParameter(str(exc)) from exc
    emit({"targetd": "UNKNOWN", "assessment": assessment.model_dump(mode="json")})
    if assessment.state != TargetConnectionState.READY:
        raise typer.Exit(code=2)


@targetd_app.command("health")
def targetd_health(
    target: Annotated[str, typer.Argument(help="ssh://user@host[:port]/workspace")],
    known_hosts: Annotated[Path, typer.Option("--known-hosts")],
    identity_file: Annotated[Path, typer.Option("--identity-file")],
    remote_root: Annotated[str, typer.Option("--remote-root")],
    state_root: Annotated[str, typer.Option("--state-root")],
    signing_key: Annotated[str, typer.Option("--signing-key")],
    target_id: Annotated[str, typer.Option("--target-id")] = "mentorpi",
) -> None:
    """Open a journey session and return targetd health/capability evidence."""
    from rolo.stages.targetd_session import TargetdStageSession
    from rolo.targetd import JourneySession
    from rolo.targetd.controller import TargetdJourneyController

    parsed = parse_target_ref(target)
    if not hasattr(parsed, "host"):
        raise typer.BadParameter("targetd health requires an SSH target")
    executor = create_target_executor(
        parsed, known_hosts=known_hosts, identity_file=identity_file
    )
    session = JourneySession.create(
        session_id=f"health-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S%f')}",
        target_id=target_id,
        profile_id="cli",
        ttl_s=300,
    )
    controller = TargetdJourneyController(
        executor, session, remote_root=remote_root, state_root=state_root,
        signing_key=signing_key, execute_calls=False,
    )
    try:
        controller.open()
        health, handoff = controller.bootstrap()
        # Health bootstrap is the first business-stage entry: route Probe
        # through the same facade used by Trace and Certify callers.
        TargetdStageSession.from_controller(controller).probe()
        emit({"status": "HEALTHY", "health": health.payload, "handoff": handoff.payload})
    finally:
        controller.close()


@targetd_app.command("install")
def targetd_install(
    target: Annotated[str, typer.Argument(help="ssh://user@host[:port]/workspace")],
    remote_root: Annotated[str, typer.Option("--remote-root")],
    known_hosts: Annotated[Path, typer.Option("--known-hosts")],
    identity_file: Annotated[Path, typer.Option("--identity-file")],
    package_root: Annotated[Path, typer.Option("--package-root") ] = Path("src"),
) -> None:
    """Install the current Rolo package into a dedicated targetd root via SSH stdin."""
    from rolo.targetd.installer import TargetdInstaller

    parsed = parse_target_ref(target)
    if not hasattr(parsed, "host"):
        raise typer.BadParameter("targetd install requires an SSH target")
    executor = create_target_executor(
        parsed, known_hosts=known_hosts, identity_file=identity_file
    )
    if not hasattr(executor, "stream_stdin"):
        raise typer.BadParameter("targetd install requires an SSH executor")
    try:
        installed = TargetdInstaller(executor, package_root=package_root).install(remote_root)
    except (OSError, RuntimeError, ValueError) as exc:
        raise typer.BadParameter(str(exc)) from exc
    emit({"status": "INSTALLED", "remote_root": installed})


@targetd_app.command("upgrade")
def targetd_upgrade(
    target: Annotated[str, typer.Argument(help="ssh://user@host[:port]/workspace")],
    remote_root: Annotated[str, typer.Option("--remote-root")],
    known_hosts: Annotated[Path, typer.Option("--known-hosts")],
    identity_file: Annotated[Path, typer.Option("--identity-file")],
    package_root: Annotated[Path, typer.Option("--package-root")] = Path("src"),
) -> None:
    """Idempotently upgrade a dedicated targetd root from the current package."""
    from rolo.targetd.installer import TargetdInstaller

    parsed = parse_target_ref(target)
    if not hasattr(parsed, "host"):
        raise typer.BadParameter("targetd upgrade requires an SSH target")
    executor = create_target_executor(parsed, known_hosts=known_hosts, identity_file=identity_file)
    if not hasattr(executor, "stream_stdin"):
        raise typer.BadParameter("targetd upgrade requires an SSH executor")
    try:
        installer = TargetdInstaller(executor, package_root=package_root)
        installed = installer.upgrade(remote_root)
        manifest = installer.manifest().model_dump(mode="json")
    except (OSError, RuntimeError, ValueError) as exc:
        raise typer.BadParameter(str(exc)) from exc
    emit({"status": "UPGRADED", "remote_root": installed, "manifest": manifest})


@targetd_app.command("uninstall")
def targetd_uninstall(
    target: Annotated[str, typer.Argument(help="ssh://user@host[:port]/workspace")],
    remote_root: Annotated[str, typer.Option("--remote-root")],
    known_hosts: Annotated[Path, typer.Option("--known-hosts")],
    identity_file: Annotated[Path, typer.Option("--identity-file")],
    package_root: Annotated[Path, typer.Option("--package-root")] = Path("src"),
    confirm: Annotated[bool, typer.Option("--confirm", help="Explicitly confirm removal of the dedicated root.")] = False,
) -> None:
    """Remove a dedicated targetd root after explicit confirmation."""
    from rolo.targetd.installer import TargetdInstaller

    parsed = parse_target_ref(target)
    if not hasattr(parsed, "host"):
        raise typer.BadParameter("targetd uninstall requires an SSH target")
    executor = create_target_executor(parsed, known_hosts=known_hosts, identity_file=identity_file)
    if not hasattr(executor, "stream_stdin"):
        raise typer.BadParameter("targetd uninstall requires an SSH executor")
    try:
        removed = TargetdInstaller(executor, package_root=package_root).uninstall(remote_root, confirm=confirm)
    except (OSError, RuntimeError, ValueError) as exc:
        raise typer.BadParameter(str(exc)) from exc
    emit({"status": "UNINSTALLED", "remote_root": removed})


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


def _load_json_mapping(path: Path, *, label: str) -> dict[str, object]:
    payload = loads_unique_json(path.read_text(encoding="utf-8"))
    if not isinstance(payload, Mapping):
        raise ValueError(f"{label} must contain a JSON object")
    return dict(payload)


def _load_verified_target_evidence(
    evidence_path: Path,
    *,
    expected_target_id: str | None = None,
) -> tuple[TargetEvidenceBundle, Mapping[str, object]]:
    """Load evidence only through the target's pinned deployment verifier."""

    bundle = TargetEvidenceBundle.model_validate_json(
        evidence_path.read_text(encoding="utf-8")
    )
    if expected_target_id is not None and bundle.robot_id != expected_target_id:
        raise ValueError("evidence target does not match profile")
    fingerprint = bundle.target_host_fingerprint
    if (
        not isinstance(fingerprint, str)
        or not fingerprint.strip()
        or fingerprint.upper() == "UNKNOWN"
    ):
        raise ValueError("verified evidence requires a known target fingerprint")
    deployment = load_deployment(
        get_settings().rolo_config_dir
        / "target-evidence"
        / f"{bundle.robot_id}.json"
    )
    verified_probes = verify_evidence_bundle(bundle, deployment=deployment)
    if not isinstance(verified_probes, Mapping):
        raise ValueError("target evidence verifier did not return bound probes")
    return bundle, verified_probes


def _registered_admission_context(
    profile: str,
    *,
    evidence: Path | None,
    admission_store: Path | None,
) -> tuple[TargetEvidenceBundle, Mapping[str, object], MappingConfirmationStore]:
    if evidence is None:
        raise ValueError("--evidence is required for registered Tools")
    if admission_store is None:
        raise ValueError("--admission-store is required for registered Tools")
    bundle, verified_probes = _load_verified_target_evidence(
        evidence,
        expected_target_id=profile,
    )
    return bundle, verified_probes, MappingConfirmationStore(admission_store)


def _load_active_registered_descriptors(
    profile: str,
    *,
    bundle: TargetEvidenceBundle,
    confirmation_store: MappingConfirmationStore,
):
    return load_registered_descriptors(
        get_settings().rolo_config_dir / "registered-tools",
        profile,
        confirmation_store=confirmation_store,
        target_fingerprint=bundle.target_host_fingerprint,
    )


def _load_active_registered_proposals(
    profile: str,
    *,
    bundle: TargetEvidenceBundle,
    confirmation_store: MappingConfirmationStore,
):
    return load_registered_proposals(
        get_settings().rolo_config_dir / "registered-tools",
        profile,
        confirmation_store=confirmation_store,
        target_fingerprint=bundle.target_host_fingerprint,
    )


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
    evidence: Annotated[
        Path | None,
        typer.Option("--evidence", help="Verified target evidence required with --include-registered"),
    ] = None,
    admission_store: Annotated[
        Path | None,
        typer.Option("--admission-store", help="Trusted Mapping confirmation ledger root"),
    ] = None,
    timeout: Annotated[float, typer.Option("--timeout", min=1.0, max=300.0)] = 15.0,
    include_registered: Annotated[bool, typer.Option("--include-registered/--native-only")] = False,
) -> None:
    """Publish the native surface, optionally merged with Probe-registered tools."""
    session = None
    try:
        additional_descriptors = None
        if include_registered:
            bundle, _, confirmation_store = _registered_admission_context(
                profile,
                evidence=evidence,
                admission_store=admission_store,
            )
            additional_descriptors = _load_active_registered_descriptors(
                profile,
                bundle=bundle,
                confirmation_store=confirmation_store,
            )
        session = create_profile_native_tool_session(
            profile,
            config_root=get_settings().rolo_config_dir,
            artifact_root=get_settings().rolo_artifact_dir,
            timeout_s=timeout,
            additional_descriptors=additional_descriptors,
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
    evidence: Annotated[
        Path | None,
        typer.Option("--evidence", help="Verified target evidence required with --include-registered"),
    ] = None,
    admission_store: Annotated[
        Path | None,
        typer.Option("--admission-store", help="Trusted Mapping confirmation ledger root"),
    ] = None,
    timeout: Annotated[float, typer.Option("--timeout", min=1.0, max=300.0)] = 15.0,
    include_registered: Annotated[bool, typer.Option("--include-registered/--native-only")] = False,
    allow_mutating: Annotated[bool, typer.Option("--allow-mutating/--readonly")] = False,
) -> None:
    """Execute one Agent-authored, digest-bound ToolPlan."""
    session = None
    try:
        plan = ToolPlan.model_validate_json(plan_file.read_text(encoding="utf-8"))
        bundle = None
        confirmation_store = None
        additional_descriptors = None
        if include_registered:
            bundle, _, confirmation_store = _registered_admission_context(
                profile,
                evidence=evidence,
                admission_store=admission_store,
            )
            additional_descriptors = _load_active_registered_descriptors(
                profile,
                bundle=bundle,
                confirmation_store=confirmation_store,
            )
        session = create_profile_native_tool_session(
            profile,
            config_root=get_settings().rolo_config_dir,
            artifact_root=get_settings().rolo_artifact_dir,
            timeout_s=timeout,
            session_id=plan.session_id,
            session_nonce=plan.session_nonce,
            additional_descriptors=additional_descriptors,
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
        if include_registered:
            if bundle is None or confirmation_store is None:
                raise ValueError("registered Tool admission context is unavailable")
            current_descriptors = _load_active_registered_descriptors(
                profile,
                bundle=bundle,
                confirmation_store=confirmation_store,
            )
            if current_descriptors != additional_descriptors:
                raise ValueError(
                    "registered Tool admission changed before plan execution"
                )
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
    evidence: Annotated[Path, typer.Option("--evidence", help="Verified target evidence JSON")],
    admission_store: Annotated[
        Path,
        typer.Option("--admission-store", help="Trusted Mapping confirmation ledger root"),
    ],
) -> None:
    """Emit registered evidence-bound application Tools for a target."""
    try:
        bundle, _, confirmation_store = _registered_admission_context(
            profile,
            evidence=evidence,
            admission_store=admission_store,
        )
        proposals = _load_active_registered_proposals(
            profile,
            bundle=bundle,
            confirmation_store=confirmation_store,
        )
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
            probe_runner_descriptor=None,
            verification_secret=None,
            ssh_target=None,
            known_hosts=None,
            probe_runner_config=".rolo/config/target-evidence-probe-runner.json",
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


def _run_trace_command(
    *,
    catalog: Path,
    calls: Path,
    result_fixture: Path,
    task: str,
    output: Path | None,
    mode: RunMode,
    safety_confirmed: bool,
    ttl: float,
    max_calls: int,
    operator_id: str | None,
    target_id: str | None,
    release_binding: Path | None,
) -> None:
    """Shared implementation for the ``trace`` and ``start-trace`` aliases."""

    from rolo.mvp.journey_cli import run_trace

    destination = output or (get_settings().rolo_artifact_dir / "mvp" / "trace")
    try:
        result = run_trace(
            catalog_path=catalog,
            calls_path=calls,
            result_fixture=result_fixture,
            task=task,
            output=destination,
            mode=mode,
            safety_confirmed=safety_confirmed,
            ttl_s=ttl,
            max_calls=max_calls,
            operator_id=operator_id,
            target_id=target_id,
            release_binding_path=release_binding,
        )
    except (FileNotFoundError, OSError, ValueError) as exc:
        raise typer.BadParameter(str(exc)) from exc
    emit(result)
    if result.get("status") != "COMPLETED":
        raise typer.Exit(code=2)


def _trace_command(
    catalog: Annotated[Path, typer.Option("--catalog", help="Verified TargetCatalog JSON")],
    calls: Annotated[Path, typer.Option("--calls", help="JSON array of TraceCall objects")],
    result_fixture: Annotated[
        Path,
        typer.Option("--result-fixture", "--results", help="Explicit offline invocation result fixture"),
    ],
    task: Annotated[str, typer.Option("--task", help="User task recorded in the Trace session")],
    output: Annotated[Path | None, typer.Option("--output", help="Trace artifact directory")] = None,
    mode: Annotated[RunMode, typer.Option("--mode")] = RunMode.OBSERVATION_ONLY,
    safety_confirmed: Annotated[
        bool,
        typer.Option("--safety-confirmed/--safety-not-confirmed", help="Required only for supervised mode"),
    ] = False,
    ttl: Annotated[float, typer.Option("--ttl", min=1.0, max=86_400.0)] = 900.0,
    max_calls: Annotated[int, typer.Option("--max-calls", min=1, max=10_000)] = 32,
    operator_id: Annotated[str | None, typer.Option("--operator-id")] = None,
    target_id: Annotated[str | None, typer.Option("--target-id", help="Optional target identity assertion")] = None,
    release_binding: Annotated[Path | None, typer.Option("--release-binding", help="Optional release/context identity JSON")] = None,
) -> None:
    """Run a bounded, replayable Trace session from verified artifacts.

    The result fixture is intentionally explicit and marked ``fixture_only``
    in the output.  Real target execution remains behind the registered Tool
    provider and the supervised ``invoke-tool`` path.
    """

    _run_trace_command(
        catalog=catalog,
        calls=calls,
        result_fixture=result_fixture,
        task=task,
        output=output,
        mode=mode,
        safety_confirmed=safety_confirmed,
        ttl=ttl,
        max_calls=max_calls,
        operator_id=operator_id,
        target_id=target_id,
        release_binding=release_binding,
    )


app.command("trace")(_trace_command)
app.command("start-trace", hidden=True)(_trace_command)


def _run_certify_command(
    *,
    suite: Path,
    result_fixture: Path,
    output: Path,
    catalog: Path | None,
    snapshot_digest: str,
    target_id: str | None,
    require_ten_cases: bool,
    run_id: str | None,
    release_binding: Path | None,
    fail_fast: bool,
) -> None:
    """Shared implementation for the ``certify`` and ``start-certify`` aliases."""

    from rolo.mvp.journey_cli import run_certify

    try:
        result = run_certify(
            suite_path=suite,
            result_fixture=result_fixture,
            output=output,
            catalog_path=catalog,
            snapshot_digest=snapshot_digest,
            target_id=target_id,
            require_ten_cases=require_ten_cases,
            run_id=run_id,
            release_binding_path=release_binding,
            fail_fast=fail_fast,
        )
    except (FileNotFoundError, OSError, ValueError) as exc:
        raise typer.BadParameter(str(exc)) from exc
    emit(result)
    if result.get("status") not in {"PASS", "SIMULATED_PASS"}:
        raise typer.Exit(code=2)


def _certify_command(
    suite: Annotated[Path, typer.Option("--suite", "--suite-path", help="Certification suite JSON")],
    result_fixture: Annotated[
        Path,
        typer.Option("--result-fixture", "--results", help="Explicit offline per-case result fixture"),
    ],
    output: Annotated[Path, typer.Option("--output", help="JSON report path")] = Path("certify-test-report.json"),
    catalog: Annotated[Path | None, typer.Option("--catalog", help="Optional fresh callable TargetCatalog JSON")] = None,
    snapshot_digest: Annotated[str, typer.Option("--snapshot-digest")] = "UNKNOWN",
    target_id: Annotated[str | None, typer.Option("--target-id")] = None,
    require_ten_cases: Annotated[
        bool,
        typer.Option("--require-ten-cases/--allow-variable-suite", help="Enforce the MVP ten-case contract"),
    ] = True,
    run_id: Annotated[str | None, typer.Option("--run-id")] = None,
    release_binding: Annotated[Path | None, typer.Option("--release-binding", help="Optional release/context identity JSON")] = None,
    fail_fast: Annotated[bool, typer.Option("--fail-fast/--continue-on-failure", help="Stop after the first failed case")] = False,
) -> None:
    """Run an explicitly requested certification suite and write JSON/Markdown.

    This command consumes only the supplied suite and result fixture.  The
    emitted report is labelled ``fixture_only`` so it cannot be mistaken for a
    field certification result.
    """

    _run_certify_command(
        suite=suite,
        result_fixture=result_fixture,
        output=output,
        catalog=catalog,
        snapshot_digest=snapshot_digest,
        target_id=target_id,
        require_ten_cases=require_ten_cases,
        run_id=run_id,
        release_binding=release_binding,
        fail_fast=fail_fast,
    )


app.command("certify")(_certify_command)
app.command("start-certify", hidden=True)(_certify_command)


@app.command("execute-rotation")
def execute_rotation(
    profile: Annotated[str, typer.Option("--profile", "--robot")],
    proposal: Annotated[Path, typer.Option("--proposal")],
    evidence: Annotated[Path, typer.Option("--evidence")],
    admission_store: Annotated[
        Path,
        typer.Option("--admission-store", help="Trusted Mapping confirmation ledger root"),
    ],
    angle_degrees: Annotated[float, typer.Option("--angle-degrees", min=-360.0, max=360.0)],
    max_speed_rad_s: Annotated[float, typer.Option("--max-speed-rad-s", min=0.0001, max=1.0)],
    safety_confirmed: Annotated[bool, typer.Option("--safety-confirmed/--safety-not-confirmed")],
    autonomous_source_confirmed: Annotated[
        bool,
        typer.Option(
            "--autonomous-source-confirmed/--autonomous-source-not-confirmed",
            help="Confirm that the designated autonomous publisher is the source under test",
        ),
    ] = False,
    operator_id: Annotated[str | None, typer.Option("--operator-id", help="Optional audit label; not required for execution")] = None,
    timeout: Annotated[float, typer.Option("--timeout", min=10.0, max=300.0)] = 120.0,
) -> None:
    """Execute one registered rotation binding and persist execution evidence."""
    if not safety_confirmed:
        emit({"status": "BLOCKED", "reason": "physical safety confirmation is required"})
        raise typer.Exit(code=2)
    try:
        bundle, verified_probes = _load_verified_target_evidence(
            evidence,
            expected_target_id=profile,
        )
        confirmation_store = MappingConfirmationStore(admission_store)
        proposals = _load_active_registered_proposals(
            profile,
            bundle=bundle,
            confirmation_store=confirmation_store,
        )
        registered = next((item for item in proposals if item.tool_id == "app.base.rotate"), None)
        if registered is None or registered.implementation != "binding" or registered.binding is None:
            raise ValueError("active registered app.base.rotate binding is unavailable")
        supplied = ToolRegistrationProposal.model_validate_json(proposal.read_text(encoding="utf-8"))
        if supplied.digest() != registered.digest():
            raise ValueError("supplied proposal differs from registered Tool")
        expected_ref = f"target-evidence:{bundle.payload_sha256}"
        if expected_ref not in registered.evidence_refs or expected_ref not in registered.binding.evidence_refs:
            raise ValueError("registered rotation binding is stale for this Probe evidence")
        routes = {
            route.resource_id: route
            for probe in verified_probes.values()
            for route in observed_probe_routes(probe)
        }
        command = routes.get(registered.binding.command_resource_id)
        if command is None or command.interface_type != registered.binding.interface_type:
            raise ValueError("command binding differs from Probe observations")
        for endpoint in registered.binding.feedback_endpoints:
            feedback = routes.get(f"ros_topic:{endpoint}")
            if feedback is None or feedback.interface_type != "nav_msgs/msg/Odometry":
                raise ValueError("rotation feedback must be observed Odometry")
        current_proposals = _load_active_registered_proposals(
            profile,
            bundle=bundle,
            confirmation_store=confirmation_store,
        )
        current = next(
            (item for item in current_proposals if item.tool_id == registered.tool_id),
            None,
        )
        if (
            current is None
            or current.digest() != registered.digest()
            or current.implementation != "binding"
            or current.binding is None
        ):
            raise ValueError(
                "registered app.base.rotate admission is unavailable before execution"
            )
        registered = current
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
            "autonomous_source_confirmed": autonomous_source_confirmed,
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
            )
            connection = target_executor.inspect()
            if connection.state != TargetConnectionState.READY:
                result = {"status": "BLOCKED", "error": "TARGET_EXECUTION_CHANNEL_UNAVAILABLE", "motion_started": False}
            else:
                # Dispatch through the generic application binding registry;
                # ROS 2 is only the provider currently used by the rotation MVP.
                dispatcher = ApplicationBindingDispatcher()
                binding_executor_kwargs = (
                    {"autonomous_source_confirmed": True}
                    if autonomous_source_confirmed
                    else {}
                )
                dispatcher.register(
                    "ros2_topic",
                    RosBindingExecutor(target_executor, **binding_executor_kwargs).rotate,
                )
                result = dispatcher.execute(
                    registered.binding, {"angle_degrees": angle_degrees, "max_speed_rad_s": max_speed_rad_s}
                )
        except ValueError as exc:
            # Missing or invalid execution transport is a deterministic
            # capability blocker.  Do not fall back to an observation-only path.
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


@app.command("invoke-tool")
def invoke_tool(
    profile: Annotated[str, typer.Option("--profile", "--robot")],
    proposal: Annotated[Path, typer.Option("--proposal")],
    evidence: Annotated[Path, typer.Option("--evidence")],
    admission_store: Annotated[
        Path,
        typer.Option("--admission-store", help="Trusted Mapping confirmation ledger root"),
    ],
    arguments: Annotated[Path, typer.Option("--arguments", help="JSON object with descriptor-defined arguments")],
    safety_confirmed: Annotated[bool, typer.Option("--safety-confirmed/--safety-not-confirmed")],
    autonomous_source_confirmed: Annotated[
        bool,
        typer.Option(
            "--autonomous-source-confirmed/--autonomous-source-not-confirmed",
            help="Confirm that the designated autonomous publisher is the source under test",
        ),
    ] = False,
    timeout: Annotated[float, typer.Option("--timeout", min=10.0, max=300.0)] = 120.0,
) -> None:
    """Invoke any registered binding through the provider dispatcher.

    The rotation command remains as a convenience wrapper.  This generic
    entrypoint is the contract used by future non-ROS application providers.
    """
    if not safety_confirmed:
        emit({"status": "BLOCKED", "reason": "physical safety confirmation is required"})
        raise typer.Exit(code=2)
    try:
        bundle, verified_probes = _load_verified_target_evidence(
            evidence,
            expected_target_id=profile,
        )
        confirmation_store = MappingConfirmationStore(admission_store)
        supplied = ToolRegistrationProposal.model_validate_json(proposal.read_text(encoding="utf-8"))
        proposals = _load_active_registered_proposals(
            profile,
            bundle=bundle,
            confirmation_store=confirmation_store,
        )
        registered = next((item for item in proposals if item.tool_id == supplied.tool_id), None)
        if registered is None or registered.digest() != supplied.digest():
            raise ValueError("supplied proposal differs from registered Tool")
        if registered.implementation != "binding" or registered.binding is None:
            raise ValueError("registered Tool does not provide an executable binding")
        try:
            call_arguments = json.loads(arguments.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError("arguments must contain a JSON object") from exc
        if not isinstance(call_arguments, dict):
            raise ValueError("arguments must contain a JSON object")
        expected_ref = f"target-evidence:{bundle.payload_sha256}"
        if expected_ref not in registered.evidence_refs or expected_ref not in registered.binding.evidence_refs:
            raise ValueError("registered Tool binding is stale for this Probe evidence")
        routes = {
            route.resource_id: route
            for probe in verified_probes.values()
            for route in observed_probe_routes(probe)
        }
        command = routes.get(registered.binding.command_resource_id)
        if command is None or command.interface_type != registered.binding.interface_type:
            raise ValueError("Tool command binding differs from Probe observations")
        current_proposals = _load_active_registered_proposals(
            profile,
            bundle=bundle,
            confirmation_store=confirmation_store,
        )
        current = next(
            (item for item in current_proposals if item.tool_id == registered.tool_id),
            None,
        )
        if (
            current is None
            or current.digest() != registered.digest()
            or current.implementation != "binding"
            or current.binding is None
        ):
            raise ValueError(
                "registered Tool admission is unavailable before execution"
            )
        registered = current
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
            dispatcher = ApplicationBindingDispatcher()
            binding_executor_kwargs = (
                {"autonomous_source_confirmed": True}
                if autonomous_source_confirmed
                else {}
            )
            dispatcher.register(
                "ros2_topic",
                RosBindingExecutor(target_executor, **binding_executor_kwargs).rotate,
            )
            result = dispatcher.execute(registered.binding, call_arguments)
        run_id = uuid4().hex
        relative = f"application/{profile}/invocations/{run_id}.json"
        ArtifactStore(get_settings().rolo_artifact_dir).write_json(
            relative,
            {
                "schema_version": "rolo-application-tool-execution-evidence/v1",
                "target_id": profile,
                "tool_id": registered.tool_id,
                "run_id": run_id,
                "proposal_digest": registered.digest(),
                "probe_evidence_ref": expected_ref,
                "safety_confirmed": safety_confirmed,
                "autonomous_source_confirmed": autonomous_source_confirmed,
                "arguments": call_arguments,
                "result": result,
                "executed_at": datetime.now(timezone.utc).isoformat(),
            },
        )
        emit({"status": result.get("status", "UNKNOWN"), "evidence_ref": f"artifact://{relative}", "result": result})
        if result.get("status") != "SUCCEEDED":
            raise typer.Exit(code=2)
    except (FileNotFoundError, OSError, ValueError) as exc:
        raise typer.BadParameter(str(exc)) from exc


@app.command("register-tool")
def register_tool(
    proposal: Annotated[Path, typer.Option("--proposal", help="Harness-produced ToolRegistrationProposal JSON")],
    evidence: Annotated[Path, typer.Option("--evidence", help="Probe evidence used by the proposal")],
    mapping_proposal: Annotated[
        Path,
        typer.Option("--mapping-proposal", help="Confirmed MappingProposal JSON"),
    ],
    mapping_dsl: Annotated[
        Path,
        typer.Option("--mapping-dsl", help="Canonical Mapping DSL JSON reviewed by the operator"),
    ],
    admission_store: Annotated[
        Path,
        typer.Option("--admission-store", help="Trusted Mapping confirmation ledger root"),
    ],
    confirmation_receipt_digest: Annotated[
        str,
        typer.Option("--confirmation-receipt-digest"),
    ],
    journey_session_id: Annotated[str, typer.Option("--journey-session-id")],
) -> None:
    """Validate and register one harness-generated application Tool."""
    try:
        bundle, verified_probes = _load_verified_target_evidence(evidence)
        parsed = ToolRegistrationProposal.model_validate(
            _load_json_mapping(proposal, label="Tool registration proposal")
        )
        parsed_mapping_proposal = MappingProposal.model_validate(
            _load_json_mapping(mapping_proposal, label="Mapping proposal")
        )
        parsed_mapping_dsl = _load_json_mapping(mapping_dsl, label="Mapping DSL")
        observed_route_ids = {
            route.resource_id
            for probe_result in verified_probes.values()
            for route in observed_probe_routes(probe_result)
        }
        result = register_tool_proposal(
            parsed,
            target_id=bundle.robot_id,
            evidence_refs={f"target-evidence:{bundle.payload_sha256}"},
            observed_route_ids=observed_route_ids,
            registry_root=get_settings().rolo_config_dir / "registered-tools",
            mapping_proposal=parsed_mapping_proposal,
            mapping_dsl=parsed_mapping_dsl,
            confirmation_store=MappingConfirmationStore(admission_store),
            confirmation_receipt_digest=confirmation_receipt_digest,
            journey_session_id=journey_session_id,
            target_fingerprint=bundle.target_host_fingerprint,
        )
    except (OSError, TypeError, ValueError) as exc:
        raise typer.BadParameter(str(exc)) from exc
    emit(result)
    if result.status == "BLOCKED":
        raise typer.Exit(code=2)


if __name__ == "__main__":
    app()
