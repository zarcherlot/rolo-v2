"""Legacy LanderPi mapping Trace helpers and a fail-closed CLI tombstone.

The original field-debug entry point created and registered mapping tools,
installed targetd, and invoked them without a committed Mapping confirmation
receipt or an admitted Release. Keeping that executable path would bypass the
v2 Mapping admission boundary. The CLI is therefore deliberately disabled
before any target, installer, CALL, or artifact boundary is reached.

The side-effect-free descriptor, contract, bundle, and request builders remain
available to tests and migration tooling. They are not an execution authority.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, NoReturn

from rolo.agent_tools import AgentNativeToolDescriptor, NativeToolParameter
from rolo.targetd import ExecutionBundleManifest, ExecutionRequest, JourneySession

TARGET_ID = "mentorpi"
RUNTIME_ID = "rolo-mapping-v1"
LEGACY_MAPPING_TRACE_DISABLED_CODE = "LEGACY_MAPPING_TRACE_DISABLED"
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


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


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
    return (f"def execute(arguments, provider):\n    return provider.invoke({operation!r}, arguments)\n").encode()


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


def legacy_mapping_trace_diagnostic() -> dict[str, object]:
    """Return the stable migration diagnostic without touching host state."""

    return {
        "status": "BLOCKED",
        "code": LEGACY_MAPPING_TRACE_DISABLED_CODE,
        "message": "legacy targetd_mapping_trace cannot satisfy confirmed Mapping and Release admission",
        "required_flow": [
            "mapping-proposal/v2",
            "committed-confirmation-receipt",
            "compile",
            "register",
            "release",
            "consume",
        ],
        "boundary": "before-target-or-artifact-side-effects",
        "chat_or_safety_flags_are_confirmation": False,
    }


def _fail_closed() -> NoReturn:
    diagnostic = legacy_mapping_trace_diagnostic()
    raise SystemExit(json.dumps(diagnostic, ensure_ascii=False, sort_keys=True, separators=(",", ":")))


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
    parser.add_argument("--safety-confirmed", action="store_true")
    parser.add_argument("--autonomous-source-confirmed", action="store_true")
    parser.add_argument("--operator-id", default="field-operator")
    parser.add_argument("--signing-key", default="")
    return parser.parse_args()


def main() -> int:
    _parse_args()
    _fail_closed()


if __name__ == "__main__":
    raise SystemExit(main())
