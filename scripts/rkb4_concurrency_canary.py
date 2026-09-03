"""Run a bounded multi-process Episode publication canary."""

from __future__ import annotations

import argparse
import hashlib
import json
import multiprocessing
from pathlib import Path

from rolo.rkb import EpisodeStore, build_episode_from_snapshot
from rolo.rkb.models import Snapshot


def _publish_child(root: str, snapshot_json: str, probe_run_id: str) -> None:
    snapshot = Snapshot.model_validate_json(snapshot_json)
    episode = build_episode_from_snapshot(
        snapshot,
        probe_run_id=probe_run_id,
        episode_id="concurrency-canary",
    )
    EpisodeStore(Path(root)).publish(episode)


def main(snapshot_path: str, *, artifact_root: str, probe_run_id: str) -> int:
    snapshot_json = Path(snapshot_path).read_text(encoding="utf-8")
    root = Path(artifact_root)
    context = multiprocessing.get_context("spawn")
    processes = [
        context.Process(
            target=_publish_child,
            args=(str(root), snapshot_json, f"{probe_run_id}-{index}"),
        )
        for index in (1, 2)
    ]
    for process in processes:
        process.start()
    for process in processes:
        process.join(timeout=30)
    exit_codes = [process.exitcode for process in processes]
    store = EpisodeStore(root)
    page = store.query(robot_id="mentorpi", limit=10)
    checks = {
        "children_succeeded": all(code == 0 for code in exit_codes),
        "two_immutable_records": page.total == 2,
        "writes_merged": store.metrics.writes == 2,
        "read_only": all(item.identity.access == "READ_ONLY" for item in page.items),
    }
    result: dict[str, object] = {
        "schema_version": "rkb4-concurrency-canary/v1",
        "passed": all(checks.values()),
        "checks": checks,
        "exit_codes": exit_codes,
        "robot_id": "mentorpi",
        "episode_id": "concurrency-canary",
        "record_digests": [item.content_sha256 for item in page.items],
        "metrics": store.metrics.as_dict(),
        "limitations": [
            (
                "The canary exercises Episode storage processes only; it does not "
                "invoke device routes."
            ),
            "The supplied snapshot determines the identity and evidence freshness.",
        ],
    }
    result["artifact_sha256"] = hashlib.sha256(
        json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("snapshot", help="verified robot-snapshot/v1 JSON")
    parser.add_argument("--artifact-root", required=True)
    parser.add_argument("--probe-run-id", required=True)
    args = parser.parse_args()
    raise SystemExit(
        main(args.snapshot, artifact_root=args.artifact_root, probe_run_id=args.probe_run_id)
    )
