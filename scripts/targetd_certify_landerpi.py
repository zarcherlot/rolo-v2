"""Run the ten chassis rotation certify cases over one real SSH journey."""

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

SOURCE = b"def execute(arguments, provider):\n    return provider.invoke('base.rotate', arguments)\n"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    parser.add_argument("--known-hosts", type=Path, required=True)
    parser.add_argument("--identity-file", type=Path, required=True)
    parser.add_argument("--remote-root", required=True)
    parser.add_argument("--state-root", required=True)
    parser.add_argument("--signing-key", required=True)
    parser.add_argument("--fixture", type=Path, default=Path("examples/chassis-rotation-10.json"))
    parser.add_argument("--container", default="MentorPi")
    parser.add_argument("--artifact-root", type=Path, default=Path("artifacts"))
    args = parser.parse_args()
    target = parse_target_ref(args.target)
    if not isinstance(target, SshTargetRef):
        raise SystemExit("--target must be SSH")
    session = JourneySession.create(session_id="certify-rotation-10", target_id="mentorpi", profile_id="landerpi", ttl_s=1800)
    controller = TargetdJourneyController(
        SshTargetExecutor(target, known_hosts=args.known_hosts, identity_file=args.identity_file),
        session, remote_root=args.remote_root, state_root=args.state_root,
        signing_key=args.signing_key, execute_calls=True, provider="ros-container", container=args.container,
        artifact_root=args.artifact_root,
    )
    manifest = ExecutionBundleManifest.build(
        tool_id="app.base.rotate", source=SOURCE, binding_digest="a" * 64,
        signer_key_id="certify", signing_key=args.signing_key.encode("utf-8"),
        observation_contract={"provider": "ros-container", "operation": "base.rotate", "topic": "/cmd_vel"},
        limits={"max_duration_s": 120, "max_output_bytes": 65536},
    )
    cases = json.loads(args.fixture.read_text(encoding="utf-8"))["cases"]
    results = []
    controller.open()
    controller.bootstrap()
    journey = TargetdStageSession.from_controller(controller)
    journey.certify()
    try:
        for case in cases:
            request = ExecutionRequest(
                run_id=case["case_id"], session_id=session.session_id, target_id=session.target_id,
                idempotency_key=case["case_id"], bundle_digest=manifest.bundle_digest,
                binding_digest=manifest.binding_digest, surface_digest="b" * 64,
                arguments={"angle_degrees": case["angle_degrees"], "max_speed_rad_s": case["max_speed_rad_s"]},
                mode="SUPERVISED_FIELD_DEBUG", deadline=datetime.now(timezone.utc) + timedelta(seconds=180),
            )
            response = journey.call(manifest, SOURCE, request)
            results.append(response.payload)
    finally:
        controller.close()
    status = "PASS" if all(item.get("receipt", {}).get("status") == "SUCCEEDED" for item in results) else "FAIL"
    report = {
        "schema_version": "rolo-targetd-certify-report/v1",
        "session_id": session.session_id,
        "target_id": session.target_id,
        "fixture": str(args.fixture),
        "status": status,
        "case_count": len(results),
        "cases": results,
    }
    report_path = args.artifact_root / "targetd" / session.target_id / "certify" / f"{session.session_id}.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({**report, "report_ref": f"artifact://{report_path.as_posix()}"}, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
