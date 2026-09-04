"""Run the generic Linux MHS read-only canary on the current host."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from rolo.mhs_hardware import MhsDeviceProvider
from rolo.mhs_linux import LinuxHardwareBackend, build_linux_manifest
from rolo.rkb.models import SnapshotIdentity
from rolo.rkb.storage import RKBStore

try:
    from scripts.mhs_rkb_canary import run_canary
except ModuleNotFoundError:  # direct execution from a copied target directory
    from mhs_rkb_canary import run_canary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("/"))
    parser.add_argument("--artifact-root", type=Path, required=True)
    parser.add_argument("--device-id", default="linux-compute")
    parser.add_argument("--target-fingerprint")
    parser.add_argument("--deployment-mode", choices=("local", "remote"), default="local")
    parser.add_argument("--robot-id")
    parser.add_argument("--collector-id", default="mhs-linux-canary")
    parser.add_argument("--rkb-root", type=Path)
    args = parser.parse_args()
    backend = LinuxHardwareBackend(args.root)
    status = backend.status()
    manifest = build_linux_manifest(
        device_id=args.device_id,
        name="Linux compute host",
        vendor="unknown",
        model=str(status.get("model", "unknown")),
        serial=status.get("serial"),
    )
    identity = None
    store = None
    if args.rkb_root is not None:
        if not args.target_fingerprint or not args.robot_id:
            parser.error("--rkb-root requires --target-fingerprint and --robot-id")
        observed_at = datetime.now(timezone.utc)
        identity = SnapshotIdentity(
            robot_id=args.robot_id,
            target_host_fingerprint=args.target_fingerprint,
            collector_id=args.collector_id,
            deployment_mode=args.deployment_mode,
            observed_at=observed_at,
            fresh_until=observed_at + timedelta(minutes=5),
        )
        store = RKBStore(args.rkb_root)
    artifact = run_canary(
        MhsDeviceProvider(
            manifest,
            backend,
            target_host_fingerprint=args.target_fingerprint,
        ),
        args.artifact_root,
        identity=identity,
        store=store,
    )
    print(json.dumps(artifact, ensure_ascii=False, sort_keys=True))
    return 0 if artifact["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
