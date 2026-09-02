"""Run the RKB-2 read-only query loop over a verified target bundle."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from rolo.rkb import ReadOnlyKnowledgeBase, bundle_to_snapshot
from rolo.stages.probe.target_evidence import TargetEvidenceBundle


def main(path: str) -> int:
    bundle = TargetEvidenceBundle.model_validate_json(Path(path).read_text(encoding="utf-8"))
    snapshot = bundle_to_snapshot(bundle, deployment_mode="local")
    knowledge = ReadOnlyKnowledgeBase([snapshot])
    now = snapshot.identity.observed_at
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
    raise SystemExit(main(sys.argv[1]))
