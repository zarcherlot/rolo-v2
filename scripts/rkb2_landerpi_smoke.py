"""Run the RKB-2 read-only query loop over a verified target bundle."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

from rolo.rkb import ReadOnlyKnowledgeBase, verified_bundle_to_snapshot
from rolo.stages.probe.target_evidence import TargetEvidenceBundle, load_deployment


def main(path: str, *, deployment_config: str, live: bool = False) -> int:
    bundle = TargetEvidenceBundle.model_validate_json(Path(path).read_text(encoding="utf-8"))
    deployment = load_deployment(Path(deployment_config))
    verification_now = datetime.now(timezone.utc) if live else bundle.collected_at
    snapshot = verified_bundle_to_snapshot(
        bundle,
        deployment=deployment,
        now=verification_now,
        deployment_mode=deployment.mode.value,
    )
    knowledge = ReadOnlyKnowledgeBase([snapshot])
    now = verification_now if live else snapshot.identity.observed_at
    result = {
        "snapshot_digest": snapshot.digest,
        "robot_identity": knowledge.robot.identity(now=now).model_dump(mode="json"),
        "runtime": knowledge.os.runtime_status(now=now).model_dump(mode="json"),
        "hardware": knowledge.hw.inventory_scan(now=now).model_dump(mode="json"),
        "middleware": knowledge.middleware.graph_snapshot(now=now).model_dump(mode="json"),
        "state_safety": knowledge.state_safety.snapshot(now=now).model_dump(mode="json"),
    }
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, default=str))
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", help="TargetEvidenceBundle JSON")
    parser.add_argument(
        "--deployment-config",
        required=True,
        help="pinned EvidenceDeploymentConfig used to verify the bundle",
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="query with current UTC time instead of bundle.collected_at",
    )
    args = parser.parse_args()
    raise SystemExit(main(args.bundle, deployment_config=args.deployment_config, live=args.live))
