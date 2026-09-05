"""Run a targetd protocol smoke against a local or remote Python runtime."""

from __future__ import annotations

import argparse
import json
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from rolo.targetd import (
    ExecutionBundleManifest,
    ExecutionRequest,
    JourneySession,
    TargetdService,
)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=None)
    parser.add_argument("--target", default="mentorpi")
    args = parser.parse_args()
    root = args.root or Path(tempfile.mkdtemp(prefix="rolo-targetd-smoke-"))
    source = b"def execute(arguments):\n    return arguments\n"
    service = TargetdService(target_id=args.target, state_root=root / "state", signing_key=b"smoke-key")
    session = service.open_session(
        JourneySession.create(session_id="smoke-session", target_id=args.target, profile_id="landerpi")
    )
    manifest = ExecutionBundleManifest.build(
        tool_id="app.base.rotate",
        source=source,
        binding_digest="a" * 64,
        signer_key_id="rolo-smoke",
        signing_key=b"smoke-key",
        limits={"max_duration_s": 60, "max_output_bytes": 65536},
    )
    service.put_bundle(manifest, source)
    request = ExecutionRequest(
        run_id="smoke-run",
        session_id=session.session_id,
        target_id=args.target,
        idempotency_key="smoke-call",
        bundle_digest=manifest.bundle_digest,
        binding_digest=manifest.binding_digest,
        surface_digest="b" * 64,
        arguments={"angle_degrees": 15, "max_speed_rad_s": 0.2},
        mode="SUPERVISED_FIELD_DEBUG",
        deadline=datetime.now(timezone.utc) + timedelta(seconds=30),
    )
    accepted = service.accept_call(request, manifest)
    cancelled = service.cancel_call(request.idempotency_key)
    print(
        json.dumps(
            {
                "status": "PASS",
                "target_id": args.target,
                "health": service.health().model_dump(mode="json"),
                "bundle_digest": manifest.bundle_digest,
                "accepted": accepted.status,
                "cancelled": cancelled.status,
                "state_root": str(root),
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )


if __name__ == "__main__":
    main()
