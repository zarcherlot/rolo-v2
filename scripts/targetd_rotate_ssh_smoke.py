"""Execute the generic rotate binding through the ROS container provider."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from rolo.stages.targetd_session import TargetdStageSession
from rolo.target_ref import SshTargetRef, parse_target_ref
from rolo.targetd import ExecutionBundleManifest, ExecutionRequest, JourneySession
from rolo.targetd.controller import TargetdJourneyController
from rolo.targets.executor import SshTargetExecutor

ROTATE_SOURCE = b"def execute(arguments, provider):\n    return provider.invoke('base.rotate', arguments)\n"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    parser.add_argument("--known-hosts", type=Path, required=True)
    parser.add_argument("--identity-file", type=Path, required=True)
    parser.add_argument("--remote-root", required=True)
    parser.add_argument("--state-root", required=True)
    parser.add_argument("--signing-key", required=True)
    parser.add_argument("--angle-degrees", type=float, default=15.0)
    parser.add_argument("--max-speed-rad-s", type=float, default=0.2)
    parser.add_argument("--container", default="MentorPi")
    args = parser.parse_args()
    target = parse_target_ref(args.target)
    if not isinstance(target, SshTargetRef):
        raise SystemExit("--target must be an ssh target")
    session = JourneySession.create(session_id="rotate-smoke-session", target_id="mentorpi", profile_id="landerpi")
    manifest = ExecutionBundleManifest.build(
        tool_id="app.base.rotate", source=ROTATE_SOURCE, binding_digest="a" * 64,
        signer_key_id="rolo-rotate-smoke", signing_key=args.signing_key.encode("utf-8"),
        observation_contract={"provider": "ros-container", "operation": "base.rotate", "topic": "/cmd_vel"},
        limits={"max_duration_s": 120, "max_output_bytes": 65536},
    )
    request = ExecutionRequest(
        run_id="rotate-smoke-run", session_id=session.session_id, target_id=session.target_id,
        idempotency_key="rotate-smoke-call", bundle_digest=manifest.bundle_digest,
        binding_digest=manifest.binding_digest, surface_digest="b" * 64,
        arguments={"angle_degrees": args.angle_degrees, "max_speed_rad_s": args.max_speed_rad_s},
        mode="SUPERVISED_FIELD_DEBUG", deadline=datetime.now(timezone.utc) + timedelta(seconds=180),
    )
    controller = TargetdJourneyController(
        SshTargetExecutor(target, known_hosts=args.known_hosts, identity_file=args.identity_file),
        session, remote_root=args.remote_root, state_root=args.state_root,
        signing_key=args.signing_key, execute_calls=True, provider="ros-container", container=args.container,
        artifact_root=Path("artifacts"),
    )
    try:
        controller.open()
        bootstrap, handoff = controller.bootstrap()
        journey = TargetdStageSession.from_controller(controller)
        journey.trace()
        result = journey.call(manifest, ROTATE_SOURCE, request)
        print(json.dumps({"status": "PASS", "bootstrap": bootstrap.payload, "handoff": handoff.payload,
                          "result": result.payload, "state_root": args.state_root},
                         sort_keys=True, separators=(",", ":")))
    finally:
        controller.close()


if __name__ == "__main__":
    main()
