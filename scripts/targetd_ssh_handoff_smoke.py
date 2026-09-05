"""Exercise targetd bootstrap/handoff over a real ordinary SSH stdio channel."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from rolo.target_ref import SshTargetRef, parse_target_ref
from rolo.targetd import ExecutionBundleManifest, ExecutionRequest, FrameKind, JourneySession, JourneySessionClient
from rolo.targets.executor import SshTargetExecutor


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True, help="ssh://user@host[:port]/workspace")
    parser.add_argument("--known-hosts", type=Path, required=True)
    parser.add_argument("--identity-file", type=Path, required=True)
    parser.add_argument("--remote-root", required=True)
    parser.add_argument("--state-root", required=True)
    parser.add_argument("--signing-key", required=True)
    args = parser.parse_args()
    target = parse_target_ref(args.target)
    if not isinstance(target, SshTargetRef):
        raise SystemExit("--target must be an ssh target")
    executor = SshTargetExecutor(target, known_hosts=args.known_hosts, identity_file=args.identity_file)
    session = JourneySession.create(session_id="ssh-smoke-session", target_id="mentorpi", profile_id="landerpi")
    source = b"def execute(arguments):\n    return arguments\n"
    manifest = ExecutionBundleManifest.build(
        tool_id="app.base.rotate", source=source, binding_digest="a" * 64,
        signer_key_id="rolo-ssh-smoke", signing_key=args.signing_key.encode("utf-8"),
    )
    request = ExecutionRequest(
        run_id="ssh-smoke-run", session_id=session.session_id, target_id=session.target_id,
        idempotency_key="ssh-smoke-call", bundle_digest=manifest.bundle_digest,
        binding_digest=manifest.binding_digest, surface_digest="b" * 64,
        arguments={"angle_degrees": 15, "max_speed_rad_s": 0.2}, mode="SUPERVISED_FIELD_DEBUG",
        deadline=datetime.now(timezone.utc) + timedelta(seconds=60),
    )
    remote = [
        "env", f"PYTHONPATH={args.remote_root}", "python3", "-m", "rolo.targetd.daemon",
        "--target-id", session.target_id, "--state-root", args.state_root,
        "--signing-key", args.signing_key,
        "--execute-calls",
    ]
    channel = executor.open_targetd_channel(remote)
    client = JourneySessionClient(channel, session)
    try:
        opened = client.exchange(FrameKind.OPEN_JOURNEY, {"target_id": session.target_id, "profile_id": session.profile_id})
        bootstrapped = client.exchange(FrameKind.BOOTSTRAP, {"session_id": session.session_id})
        handed_off = client.handoff()
        client.put_bundle(manifest, source)
        result = client.call_remote(request)
        cancelled = client.cancel_remote(request.idempotency_key)
        client.exchange(FrameKind.CLOSE_SESSION, {"session_id": session.session_id})
        print(json.dumps({"status": "PASS", "open": opened.payload, "bootstrap": bootstrapped.payload,
                          "handoff": handed_off.payload, "call": result.payload, "cancel": cancelled.payload,
                          "remote_root": args.remote_root, "state_root": args.state_root},
                         sort_keys=True, separators=(",", ":")))
    finally:
        channel.close()


if __name__ == "__main__":
    main()
