"""Verify an unexecuted CALL remains queryable after SSH reconnect."""

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


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    parser.add_argument("--known-hosts", type=Path, required=True)
    parser.add_argument("--identity-file", type=Path, required=True)
    parser.add_argument("--remote-root", required=True)
    parser.add_argument("--state-root", required=True)
    parser.add_argument("--signing-key", required=True)
    args = parser.parse_args()
    target = parse_target_ref(args.target)
    if not isinstance(target, SshTargetRef):
        raise SystemExit("--target must be SSH")
    session = JourneySession.create(session_id="pending-recovery-session", target_id="mentorpi", profile_id="landerpi")
    controller = TargetdJourneyController(
        SshTargetExecutor(target, known_hosts=args.known_hosts, identity_file=args.identity_file),
        session, remote_root=args.remote_root, state_root=args.state_root,
        signing_key=args.signing_key, execute_calls=False,
    )
    source = b"def execute(arguments): return arguments"
    manifest = ExecutionBundleManifest.build(
        tool_id="app.base.rotate", source=source, binding_digest="a" * 64,
        signer_key_id="recovery", signing_key=args.signing_key.encode("utf-8"),
    )
    request = ExecutionRequest(
        run_id="pending-recovery-run", session_id=session.session_id, target_id=session.target_id,
        idempotency_key="pending-recovery-call", bundle_digest=manifest.bundle_digest,
        binding_digest=manifest.binding_digest, surface_digest="b" * 64,
        arguments={"angle_degrees": 15, "max_speed_rad_s": 0.2}, mode="TRACE",
        deadline=datetime.now(timezone.utc) + timedelta(seconds=120),
    )
    controller.open()
    controller.bootstrap()
    journey = TargetdStageSession.from_controller(controller)
    journey.trace()
    journey.call(manifest, source, request)
    controller.disconnect()
    controller.resume(session.resume_token)
    queried = controller.query_call(request.idempotency_key)
    controller.close()
    status = queried.payload.get("receipt", {}).get("status")
    print(json.dumps({"status": "PASS" if status == "ACCEPTED" else "FAIL", "receipt_status": status}, separators=(",", ":")))


if __name__ == "__main__":
    main()
