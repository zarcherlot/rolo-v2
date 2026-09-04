"""Verify Episode migration-style publish and pointer rollback."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from rolo.rkb import EpisodeStore, build_episode_from_snapshot
from rolo.rkb.models import Snapshot


def main(snapshot_path: str, *, artifact_root: str, probe_run_id: str) -> int:
    snapshot = Snapshot.model_validate_json(Path(snapshot_path).read_text(encoding="utf-8"))
    store = EpisodeStore(Path(artifact_root))
    episode_id = "migration-canary"
    first = build_episode_from_snapshot(
        snapshot, probe_run_id=f"{probe_run_id}-old", episode_id=episode_id
    )
    first_path = store.publish(first)
    published_first = store.load(snapshot.identity.robot_id, episode_id, first_path.stem)
    second = first.model_copy(
        update={
            "probe_run_id": f"{probe_run_id}-new",
            "events": first.events[:1],
            "content_sha256": None,
        }
    ).with_digest()
    second_path = store.publish(second)
    published_second = store.load(snapshot.identity.robot_id, episode_id, second_path.stem)
    latest_before = store.load_latest(snapshot.identity.robot_id, episode_id)
    rolled_back = store.rollback(snapshot.identity.robot_id, episode_id)
    latest_after = store.load_latest(snapshot.identity.robot_id, episode_id)
    checks = {
        "latest_before_is_new": latest_before.content_sha256 == published_second.content_sha256,
        "rollback_returns_old": rolled_back.content_sha256 == published_first.content_sha256,
        "latest_after_is_old": latest_after.content_sha256 == published_first.content_sha256,
        "new_parent_binds_old": published_second.parent_digest == published_first.content_sha256,
        "read_only": all(
            item.identity.access == "READ_ONLY"
            for item in (published_first, published_second, rolled_back)
        ),
    }
    result: dict[str, object] = {
        "schema_version": "rkb4-migration-canary/v1",
        "passed": all(checks.values()),
        "checks": checks,
        "robot_id": snapshot.identity.robot_id,
        "episode_id": episode_id,
        "old_digest": published_first.content_sha256,
        "new_digest": published_second.content_sha256,
        "rollback_digest": rolled_back.content_sha256,
        "metrics": store.metrics.as_dict(),
        "limitations": [
            (
                "This canary validates metadata pointer migration only; it does not "
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
