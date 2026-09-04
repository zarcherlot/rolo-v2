"""Publish and verify one RKB-4 metadata-only Episode from a Snapshot."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from rolo.rkb import EpisodeStore, build_episode_from_snapshot
from rolo.rkb.models import Snapshot


def main(
    snapshot_path: str,
    *,
    artifact_root: str,
    probe_run_id: str,
    episode_id: str | None = None,
    snapshot_ref: str | None = None,
    bundle_ref: str | None = None,
    report_ref: str | None = None,
) -> int:
    snapshot = Snapshot.model_validate_json(Path(snapshot_path).read_text(encoding="utf-8"))
    episode = build_episode_from_snapshot(
        snapshot,
        probe_run_id=probe_run_id,
        episode_id=episode_id,
        snapshot_ref=snapshot_ref,
        bundle_ref=bundle_ref,
        report_ref=report_ref,
    )
    store = EpisodeStore(Path(artifact_root))
    record_path = store.publish(episode)
    published = store.load_latest(snapshot.identity.robot_id, episode.episode_id)
    output = {
        "schema_version": "rkb4-episode-canary/v1",
        "passed": published.content_sha256 == episode.content_sha256,
        "record": str(record_path),
        "episode_id": published.episode_id,
        "robot_id": published.identity.robot_id,
        "snapshot_digest": published.snapshot.sha256 if published.snapshot else None,
        "episode_digest": published.content_sha256,
        "event_kinds": [event.kind.value for event in published.events],
        "read_only": published.identity.access == "READ_ONLY",
        "limitations": published.limitations,
    }
    print(json.dumps(output, ensure_ascii=False, sort_keys=True, default=str))
    return 0 if output["passed"] and output["read_only"] else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("snapshot", help="verified robot-snapshot/v1 JSON")
    parser.add_argument("--artifact-root", required=True)
    parser.add_argument("--probe-run-id", required=True)
    parser.add_argument("--episode-id")
    parser.add_argument("--snapshot-ref")
    parser.add_argument("--bundle-ref")
    parser.add_argument("--report-ref")
    args = parser.parse_args()
    raise SystemExit(
        main(
            args.snapshot,
            artifact_root=args.artifact_root,
            probe_run_id=args.probe_run_id,
            episode_id=args.episode_id,
            snapshot_ref=args.snapshot_ref,
            bundle_ref=args.bundle_ref,
            report_ref=args.report_ref,
        )
    )
