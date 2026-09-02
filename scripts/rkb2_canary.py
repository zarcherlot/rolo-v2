"""Run one bounded read-only RKB canary check for scheduler integration."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

from rolo.rkb import RKBStore


def main(root: Path, *, robot_id: str | None = None) -> int:
    store = RKBStore(root)
    now = datetime.now(timezone.utc)
    try:
        snapshot = store.load_latest()
    except Exception as exc:  # noqa: BLE001 - canary must emit a stable failure record
        print(
            json.dumps(
                {
                    "schema_version": "rkb-canary-result/v1",
                    "status": "FAILED",
                    "reason": str(exc),
                    "metrics": store.metrics.as_dict(),
                },
                sort_keys=True,
            )
        )
        return 1
    if robot_id is not None and snapshot.identity.robot_id != robot_id:
        reason = "latest snapshot robot identity mismatch"
        status = "FAILED"
    elif snapshot.identity.freshness(now=now).value != "FRESH":
        reason = "latest snapshot is stale"
        status = "STALE"
    else:
        reason = "latest snapshot verified and fresh"
        status = "PASSED"
    print(
        json.dumps(
            {
                "schema_version": "rkb-canary-result/v1",
                "status": status,
                "reason": reason,
                "robot_id": snapshot.identity.robot_id,
                "snapshot_digest": snapshot.digest,
                "observed_at": snapshot.identity.observed_at.isoformat(),
                "fresh_until": snapshot.identity.fresh_until.isoformat(),
                "metrics": store.metrics.as_dict(),
            },
            sort_keys=True,
        )
    )
    return 0 if status == "PASSED" else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--robot-id")
    args = parser.parse_args()
    raise SystemExit(main(args.root, robot_id=args.robot_id))
