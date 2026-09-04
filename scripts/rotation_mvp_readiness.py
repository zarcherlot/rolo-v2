from __future__ import annotations

import argparse
import json
from pathlib import Path

from rolo.mvp.rotation import assess_rotation_readiness
from rolo.stages.probe.target_evidence import TargetEvidenceBundle


def main() -> int:
    parser = argparse.ArgumentParser(description="Assess read-only LanderPi chassis rotation prerequisites")
    parser.add_argument("--evidence", type=Path, required=True, help="serialized, digest-verified target evidence bundle")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    bundle = TargetEvidenceBundle.model_validate_json(args.evidence.read_text(encoding="utf-8"))
    assessment = assess_rotation_readiness(bundle)
    payload = json.dumps(assessment.model_dump(mode="json"), ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload, encoding="utf-8")
    print(payload, end="")
    return 0 if assessment.status == "READY_FOR_SUPERVISED_REVIEW" else 2


if __name__ == "__main__":
    raise SystemExit(main())
