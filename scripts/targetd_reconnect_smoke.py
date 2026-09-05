"""Verify logical journey recovery after dropping the physical SSH channel."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from rolo.stages.targetd_session import TargetdStageSession
from rolo.target_ref import SshTargetRef, parse_target_ref
from rolo.targetd import JourneySession
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
    session = JourneySession.create(session_id="reconnect-smoke-session", target_id="mentorpi", profile_id="landerpi")
    controller = TargetdJourneyController(
        SshTargetExecutor(target, known_hosts=args.known_hosts, identity_file=args.identity_file),
        session, remote_root=args.remote_root, state_root=args.state_root,
        signing_key=args.signing_key, execute_calls=False,
    )
    controller.open()
    controller.bootstrap()
    TargetdStageSession.from_controller(controller).probe()
    controller.disconnect()
    resumed = controller.resume(session.resume_token)
    controller.close()
    print(json.dumps({"status": "PASS", "session_id": session.session_id, "resume": resumed.payload},
                     sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
