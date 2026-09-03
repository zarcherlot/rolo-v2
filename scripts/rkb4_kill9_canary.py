"""Prove Episode records remain readable after a publisher process is SIGKILLed."""

from __future__ import annotations

import argparse
import json
import os
import time
from multiprocessing import Process
from pathlib import Path

from rolo.rkb import EpisodeStore, Snapshot, build_episode_from_snapshot


def _publisher(snapshot_path: str, root: str) -> None:
    snapshot = Snapshot.model_validate_json(Path(snapshot_path).read_text(encoding="utf-8"))
    EpisodeStore(Path(root)).publish(
        build_episode_from_snapshot(
            snapshot, probe_run_id="kill9-canary", episode_id="kill9-canary"
        )
    )
    time.sleep(60)


def main(snapshot_path: str, *, artifact_root: str) -> int:
    process = Process(target=_publisher, args=(snapshot_path, artifact_root))
    process.start()
    time.sleep(0.5)
    os.kill(process.pid, 9)
    process.join(timeout=5)
    snapshot = Snapshot.model_validate_json(Path(snapshot_path).read_text(encoding="utf-8"))
    latest = EpisodeStore(Path(artifact_root)).load_latest(
        snapshot.identity.robot_id, "kill9-canary"
    )
    result = {
        "schema_version": "rkb4-kill9-canary/v1",
        "passed": process.exitcode not in (None, 0) and latest.probe_run_id == "kill9-canary",
        "read_only": latest.identity.access == "READ_ONLY",
        "process_exitcode": process.exitcode,
        "episode_digest": latest.content_sha256,
        "limitations": [
            "Process crash recovery is proven for a persisted record; "
            "no device route is invoked."
        ],
    }
    print(json.dumps(result, sort_keys=True))
    return 0 if result["passed"] and result["read_only"] else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("snapshot")
    parser.add_argument("--artifact-root", required=True)
    args = parser.parse_args()
    raise SystemExit(main(args.snapshot, artifact_root=args.artifact_root))
