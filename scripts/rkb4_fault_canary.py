"""Exercise RKB-4 storage recovery without touching the target device."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from rolo.rkb import EpisodeStore, build_episode_from_snapshot
from rolo.rkb.models import Snapshot
from rolo.rkb.validation import EvidenceValidationError


def main(snapshot_path: str, *, artifact_root: str, probe_run_id: str) -> int:
    root = Path(artifact_root)
    snapshot = Snapshot.model_validate_json(Path(snapshot_path).read_text(encoding="utf-8"))
    store = EpisodeStore(root)
    episode_id = f"fault-{probe_run_id}"
    first = build_episode_from_snapshot(
        snapshot, probe_run_id=f"{probe_run_id}-1", episode_id=episode_id
    )
    first_path = store.publish(first)
    second = first.model_copy(
        update={
            "probe_run_id": f"{probe_run_id}-2",
            "events": first.events[:1],
            "content_sha256": None,
        }
    ).with_digest()
    second_path = store.publish(second)
    published_second = store.load(snapshot.identity.robot_id, episode_id, second_path.stem)

    latest_path = root / "episodes" / snapshot.identity.robot_id / episode_id / "latest.json"
    latest_path.write_text("{broken", encoding="utf-8")
    recovered = store.load_latest(snapshot.identity.robot_id, episode_id)
    latest_recovered = store.load_latest(snapshot.identity.robot_id, episode_id)

    first_payload = json.loads(first_path.read_text(encoding="utf-8"))
    first_payload["limitations"] = ["fault-canary-tamper"]
    first_path.write_text(json.dumps(first_payload), encoding="utf-8")
    isolated = False
    try:
        store.load(snapshot.identity.robot_id, episode_id, str(first.content_sha256))
    except EvidenceValidationError:
        isolated = not first_path.exists()

    checks = {
        "latest_recovered": recovered.probe_run_id == published_second.probe_run_id,
        "latest_stable_after_recovery": (
            latest_recovered.content_sha256 == published_second.content_sha256
        ),
        "corrupt_record_isolated": isolated,
        "read_only": all(item.identity.access == "READ_ONLY" for item in (first, second)),
    }
    result: dict[str, object] = {
        "schema_version": "rkb4-fault-canary/v1",
        "passed": all(checks.values()),
        "checks": checks,
        "robot_id": snapshot.identity.robot_id,
        "episode_id": episode_id,
        "first_digest": first.content_sha256,
        "second_digest": second.content_sha256,
        "metrics": store.metrics.as_dict(),
        "limitations": [
            (
                "This canary corrupts temporary Episode artifacts only; it never invokes "
                "a device write route."
            ),
            "Process crash/reboot evidence requires the fixed-target execution plan.",
        ],
    }
    digest_payload = dict(result)
    canonical = json.dumps(
        digest_payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    result["artifact_sha256"] = hashlib.sha256(canonical).hexdigest()
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
