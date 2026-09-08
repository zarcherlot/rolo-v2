"""Run the registered LanderPi mapping tools through one Trace journey.

This is a supervised field-debug harness, not a product CLI.  It publishes a
small, target-bound mapping Tool Surface, installs the targetd source bundle,
and invokes status -> bounded run -> explicit stop -> map save over one SSH
stdio journey.  Password authentication is supported only through the
operator-provided SSH_ASKPASS environment; no credential is accepted as a
command-line argument or written to an artifact.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from rolo.agent_tools import (
    AgentNativeToolDescriptor,
    NativeToolParameter,
    NativeToolSessionBudget,
    NativeToolSessionDescriptor,
    conform_tool_surface,
    native_catalog_sha256,
)
from rolo.mvp import (
    RunMode,
    ToolRegistrationProposal,
    TraceCall,
    TraceService,
    TraceSessionRequest,
    build_target_catalog,
    register_tool_proposal,
)
from rolo.target_ref import SshTargetRef, parse_target_ref
from rolo.targetd import ExecutionBundleManifest, ExecutionRequest, JourneySession
from rolo.targetd.controller import TargetdJourneyController
from rolo.targetd.installer import TargetdInstaller
from rolo.targets.executor import SshTargetExecutor

TARGET_ID = "mentorpi"
RUNTIME_ID = "rolo-mapping-v1"
RUNTIME_SCHEMA = "rolo-landerpi-mapping-runtime/v1"
FOUNDATION_SCHEMA = "rolo-landerpi-mapping-foundation/v1"
MAPPING_DEFAULTS = {
    "cmd_topic": "/controller/cmd_vel",
    "scan_topic": "/scan",
    "odom_topic": "/odom",
    "map_topic": "/map",
    "stop_marker": "/tmp/rolo-mapping-stop",
    "status_file": "/tmp/rolo-mapping-status.json",
    "map_dir": "/home/ubuntu/rolo_debug/maps",
}
OPERATIONS = {
    "app.mapping.status": "mapping.status",
    "app.mapping.run": "mapping.run",
    "app.mapping.stop": "mapping.stop",
    "app.mapping.save": "mapping.save",
}


class AskpassSshTargetExecutor(SshTargetExecutor):
    """Pinned SSH executor with password auth delegated to SSH_ASKPASS."""

    def _ssh_argv(self, remote_argv: list[str]) -> list[str]:
        argv = super()._ssh_argv(remote_argv)
        try:
            batch_index = argv.index("BatchMode=yes")
        except ValueError as exc:  # pragma: no cover - base executor invariant
            raise ValueError("SSH argv did not contain its batch-mode guard") from exc
        argv[batch_index] = "BatchMode=no"
        marker = argv.index("--")
        return [
            *argv[:marker],
            "-o",
            "PreferredAuthentications=password",
            "-o",
            "PubkeyAuthentication=no",
            *argv[marker:],
        ]


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _descriptor(tool_id: str) -> AgentNativeToolDescriptor:
    common = {
        "schema_version": "rolo-agent-native-tool/v1",
        "tool_id": tool_id,
        "family": "application.mapping",
        "execution_path": "MIDDLEWARE_CLI",
        "executable": "rolo-mapping-runtime",
        "argv_template": ["rolo-mapping-runtime", "--mode", OPERATIONS[tool_id].rsplit(".", 1)[1]],
        "access": "experimental_write",
        "risk": "R3",
        "max_duration_s": 120.0,
        "max_output_bytes": 65_536,
        "evidence_kind": "ROS2_MAPPING_DEBUG",
    }
    if tool_id == "app.mapping.status":
        parameters = [NativeToolParameter(name="status_window_s", required=False)]
    elif tool_id == "app.mapping.run":
        parameters = [
            NativeToolParameter(name="duration_s", required=False),
            NativeToolParameter(name="max_distance_m", required=False),
            NativeToolParameter(name="obstacle_stop_m", required=False),
        ]
    elif tool_id == "app.mapping.save":
        parameters = [
            NativeToolParameter(
                name="map_name",
                required=False,
                pattern=r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}",
            ),
            NativeToolParameter(name="save_timeout_s", required=False),
        ]
    else:
        parameters = []
    return AgentNativeToolDescriptor(**common, parameters=parameters)


def _contract(tool_id: str) -> dict[str, str]:
    return {
        "provider": "ros-container",
        "operation": OPERATIONS[tool_id],
        "runtime": RUNTIME_ID,
        **MAPPING_DEFAULTS,
    }


def _source(tool_id: str) -> bytes:
    operation = OPERATIONS[tool_id]
    return (
        "def execute(arguments, provider):\n"
        f"    return provider.invoke({operation!r}, arguments)\n"
    ).encode()


def _binding_digest(contract: dict[str, str]) -> str:
    encoded = json.dumps(contract, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _manifest(tool_id: str, signing_key: str) -> tuple[ExecutionBundleManifest, bytes]:
    source = _source(tool_id)
    contract = _contract(tool_id)
    manifest = ExecutionBundleManifest.build(
        tool_id=tool_id,
        source=source,
        binding_digest=_binding_digest(contract),
        signer_key_id="rolo-mapping-trace",
        signing_key=signing_key.encode("utf-8"),
        observation_contract=contract,
        limits={"max_duration_s": 120, "max_output_bytes": 65_536},
        release_version="rolo-mapping-debug/v1",
    )
    return manifest, source


def _request(
    *,
    manifest: ExecutionBundleManifest,
    session: JourneySession,
    surface_digest: str,
    arguments: dict[str, Any],
    idempotency_key: str,
    run_id: str,
    deadline_s: float = 180.0,
) -> ExecutionRequest:
    return ExecutionRequest(
        run_id=run_id,
        session_id=session.session_id,
        target_id=session.target_id,
        idempotency_key=idempotency_key,
        bundle_digest=manifest.bundle_digest,
        binding_digest=manifest.binding_digest,
        surface_digest=surface_digest,
        arguments=arguments,
        mode="SUPERVISED_FIELD_DEBUG",
        deadline=_utc_now() + timedelta(seconds=deadline_s),
    )


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True, help="pinned SSH target, e.g. ssh://pi@192.168.10.167/home/pi")
    parser.add_argument("--known-hosts", type=Path, required=True)
    parser.add_argument("--identity-file", type=Path)
    parser.add_argument("--remote-root", default="/home/pi/rolo-targetd-mapping-debug-v2")
    parser.add_argument("--state-root", default="/home/pi/rolo-targetd-mapping-debug-state-v2")
    parser.add_argument("--container", default="MentorPi")
    parser.add_argument("--artifact-root", type=Path, default=Path("artifacts"))
    parser.add_argument("--duration-s", type=float, default=15.0)
    parser.add_argument("--max-distance-m", type=float, default=0.8)
    parser.add_argument("--obstacle-stop-m", type=float, default=0.42)
    parser.add_argument("--map-name", default="rolo_mapping_trace_20260908")
    parser.add_argument("--status-only", action="store_true")
    parser.add_argument(
        "--safety-confirmed",
        action="store_true",
        help="explicit operator confirmation for the supervised field Trace",
    )
    parser.add_argument("--autonomous-source-confirmed", action="store_true")
    parser.add_argument("--operator-id", default="field-operator")
    parser.add_argument("--signing-key", default="")
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    if not args.safety_confirmed:
        raise SystemExit("--safety-confirmed is required for a supervised mapping Trace")
    if not args.autonomous_source_confirmed and not args.status_only:
        raise SystemExit("--autonomous-source-confirmed is required for a physical mapping run")
    if not 5.0 <= args.duration_s <= 120.0:
        raise SystemExit("--duration-s must be between 5 and 120")
    if not 0.2 <= args.max_distance_m <= 10.0:
        raise SystemExit("--max-distance-m must be between 0.2 and 10")
    if not 0.3 <= args.obstacle_stop_m <= 1.2:
        raise SystemExit("--obstacle-stop-m must be between 0.3 and 1.2")
    target = parse_target_ref(args.target)
    if not isinstance(target, SshTargetRef):
        raise SystemExit("--target must be an SSH target")
    if args.identity_file is None and not os.environ.get("SSH_ASKPASS"):
        raise SystemExit("password mode requires SSH_ASKPASS; no credential was written by this harness")
    signing_key = args.signing_key or f"mapping-trace-{secrets.token_urlsafe(18)}"
    artifact_root = args.artifact_root.resolve()
    foundation_path = artifact_root / "validation" / "landerpi-mapping-foundation-20260908.json"
    descriptors = [_descriptor(tool_id) for tool_id in OPERATIONS]
    surface_digest = native_catalog_sha256(descriptors)
    native_session = NativeToolSessionDescriptor(
        session_id=f"native-mapping-{secrets.token_urlsafe(8)}",
        nonce=secrets.token_urlsafe(16),
        robot_id=TARGET_ID,
        stage="probe",
        native_catalog_sha256=surface_digest,
        allowed_tools=[item.tool_id for item in descriptors],
        policy_version="rolo-mapping-debug/v1",
        budget=NativeToolSessionBudget(max_calls=8, max_elapsed_s=900, max_result_bytes=500_000),
        created_at=_utc_now(),
        expires_at=_utc_now() + timedelta(minutes=30),
    )
    conformance = conform_tool_surface(native_session, descriptors, allow_experimental_write=True)
    if conformance.status != "PASS":
        raise SystemExit("mapping Tool Surface conformance failed; refusing to create a callable catalog")
    registry_root = artifact_root / "registered-tools"
    registration_results = []
    foundation_ref = f"artifact://{(foundation_path.relative_to(artifact_root)).as_posix()}"
    for descriptor in descriptors:
        proposal = ToolRegistrationProposal(
            target_id=TARGET_ID,
            tool_id=descriptor.tool_id,
            evidence_refs=[foundation_ref],
            descriptor=descriptor,
            implementation="descriptor",
            harness_notes="Supervised LanderPi mapping debug surface; fixed ROS routes and bounded runtime.",
        )
        registration_results.append(
            register_tool_proposal(
                proposal,
                target_id=TARGET_ID,
                evidence_refs={foundation_ref},
                registry_root=registry_root,
            ).model_dump(mode="json")
        )
    catalog = build_target_catalog(
        target_id=TARGET_ID,
        target_fingerprint="UNKNOWN",
        snapshot_digest=hashlib.sha256(json.dumps(MAPPING_DEFAULTS, sort_keys=True).encode()).hexdigest(),
        descriptors=descriptors,
        conformance=conformance,
        freshness="fresh",
    )
    catalog_path = artifact_root / "validation" / "landerpi-mapping-target-catalog.json"
    _write_json(catalog_path, catalog.model_dump(mode="json"))
    _write_json(artifact_root / "validation" / "landerpi-mapping-conformance.json", conformance.model_dump(mode="json"))
    _write_json(
        artifact_root / "validation" / "landerpi-mapping-native-session.json",
        native_session.model_dump(mode="json"),
    )

    executor_cls = SshTargetExecutor if args.identity_file is not None else AskpassSshTargetExecutor
    executor = executor_cls(target, known_hosts=args.known_hosts, identity_file=args.identity_file)
    installer = TargetdInstaller(executor, package_root=Path(__file__).resolve().parents[1] / "src")
    install_manifest = installer.manifest().model_dump(mode="json")
    installer.install(args.remote_root)
    session = JourneySession.create(
        session_id=f"mapping-trace-{secrets.token_urlsafe(8)}",
        target_id=TARGET_ID,
        profile_id="landerpi",
        ttl_s=1800,
    ).model_copy(update={"surface_digest": catalog.surface_digest})
    controller = TargetdJourneyController(
        executor,
        session,
        remote_root=args.remote_root,
        state_root=args.state_root,
        signing_key=signing_key,
        execute_calls=True,
        provider="ros-container",
        container=args.container,
        autonomous_source_confirmed=args.autonomous_source_confirmed,
        artifact_root=artifact_root,
    )
    run_attempted = False
    invocations: list[dict[str, Any]] = []

    def invoke(tool_id: str, arguments: dict[str, Any], session_id: str, idempotency_key: str) -> dict[str, Any]:
        manifest, source = _manifest(tool_id, signing_key)
        request = _request(
            manifest=manifest,
            session=session,
            surface_digest=catalog.surface_digest,
            arguments=dict(arguments),
            idempotency_key=idempotency_key,
            run_id=f"{session_id}-run-{len(invocations) + 1}",
            deadline_s=max(180.0, args.duration_s + 60.0),
        )
        response = controller.call(manifest, source, request)
        receipt = response.payload.get("receipt") or {}
        result = receipt.get("result") if isinstance(receipt, dict) else None
        if not isinstance(result, dict):
            result = {"status": str(receipt.get("status", "UNKNOWN")).upper()}
        result = dict(result)
        if tool_id == "app.mapping.run" and result.get("status") == "SUCCEEDED" and not result.get("motion_started"):
            result.update({"status": "BLOCKED", "error": "MOTION_NOT_STARTED"})
        invocations.append({"tool_id": tool_id, "request": request.model_dump(mode="json"), "receipt": receipt, "result": result})
        return result

    def hard_stop() -> dict[str, Any]:
        return invoke("app.mapping.stop", {}, session.session_id, f"{session.session_id}-hard-stop")

    trace_service = TraceService(
        catalog,
        invoke,
        artifact_root=artifact_root / "trace",
        autonomous_source_confirmed=args.autonomous_source_confirmed,
    )
    trace_request = TraceSessionRequest(
        target_id=TARGET_ID,
        catalog_digest=catalog.digest or catalog.computed_digest(),
        task="在 LanderPi 上执行受监督自主建图、避障并保存地图",
        mode=RunMode.SUPERVISED_FIELD_DEBUG,
        ttl_s=900,
        max_calls=3,
        operator_id=args.operator_id,
        safety_confirmed=args.safety_confirmed,
        scope=tuple(item.tool_id for item in descriptors),
    )
    trace_session = trace_service.create_session(trace_request)
    lifecycle: dict[str, Any] = {}
    try:
        lifecycle["open"] = controller.open().payload
        bootstrap, handoff = controller.bootstrap()
        lifecycle["bootstrap"] = bootstrap.payload
        lifecycle["handoff"] = handoff.payload
        lifecycle["trace_phase"] = controller.change_phase("TRACE").payload

        trace_session = trace_service.execute(
            trace_session.session_id,
            [
                TraceCall(
                    tool_id="app.mapping.status",
                    arguments={"status_window_s": 4.0},
                    idempotency_key=f"{session.session_id}-status",
                )
            ],
        )
        status_result = invocations[-1]["result"] if invocations else {}
        if not args.status_only and trace_session.state.value not in {"BLOCKED", "UNKNOWN"} and status_result.get("status") == "SUCCEEDED":
            run_attempted = True
            trace_session = trace_service.execute(
                trace_session.session_id,
                [
                    TraceCall(
                        tool_id="app.mapping.run",
                        arguments={
                            "duration_s": args.duration_s,
                            "max_distance_m": args.max_distance_m,
                            "obstacle_stop_m": args.obstacle_stop_m,
                        },
                        idempotency_key=f"{session.session_id}-run",
                    )
                ],
            )
            # Make the zero-velocity tail explicit before map persistence.
            hard_stop_result = hard_stop()
            lifecycle["hard_stop"] = hard_stop_result
            if trace_session.state.value not in {"BLOCKED", "UNKNOWN"}:
                trace_session = trace_service.execute(
                    trace_session.session_id,
                    [
                        TraceCall(
                            tool_id="app.mapping.save",
                            arguments={"map_name": args.map_name, "save_timeout_s": 30.0},
                            idempotency_key=f"{session.session_id}-save",
                        )
                    ],
                )
        elif args.status_only:
            lifecycle["status_only"] = True
    finally:
        if run_attempted and not lifecycle.get("hard_stop"):
            try:
                lifecycle["hard_stop"] = hard_stop()
            except Exception as exc:  # pragma: no cover - transport fault path
                lifecycle["hard_stop_error"] = type(exc).__name__
        try:
            controller.close()
        except Exception as exc:  # pragma: no cover - transport fault path
            lifecycle["close_error"] = type(exc).__name__

    trace_paths = trace_service.persist_session(trace_session.session_id, artifact_root / "trace")
    foundation = {
        "schema_version": FOUNDATION_SCHEMA,
        "target_id": TARGET_ID,
        "target": args.target,
        "collected_at": _utc_now().isoformat(),
        "runtime_schema": RUNTIME_SCHEMA,
        "registered_tools": [item.tool_id for item in descriptors],
        "routes": MAPPING_DEFAULTS,
        "preflight_and_run": invocations,
        "map_save": [item for item in invocations if item["tool_id"] == "app.mapping.save"],
        "limitations": [
            "debug-only bounded reactive explorer; not a production planner",
            "vendor command route has multiple publishers; interference gate fails closed",
            "vendor odom/EKF may be open-loop and distance is therefore advisory",
            "independent physical e-stop and operator supervision remain required",
        ],
    }
    _write_json(foundation_path, foundation)
    report = {
        "schema_version": "rolo-landerpi-mapping-trace-report/v1",
        "status": "PASS" if trace_session.state.value == "COMPLETED" else trace_session.state.value,
        "target_id": TARGET_ID,
        "session_id": trace_session.session_id,
        "catalog_digest": catalog.digest,
        "surface_digest": catalog.surface_digest,
        "registration": registration_results,
        "install_manifest": install_manifest,
        "lifecycle": lifecycle,
        "invocations": invocations,
        "trace_session": trace_session.model_dump(mode="json"),
        "trace_artifacts": {key: str(value) for key, value in trace_paths.items()},
        "foundation_ref": foundation_ref,
        "limitations": foundation["limitations"],
    }
    report_path = artifact_root / "validation" / f"landerpi-mapping-trace-{trace_session.session_id}.json"
    _write_json(report_path, report)
    print(json.dumps({**report, "report_ref": f"artifact://{report_path.as_posix()}"}, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    return 0 if report["status"] == "PASS" or args.status_only else 2


if __name__ == "__main__":
    raise SystemExit(main())
