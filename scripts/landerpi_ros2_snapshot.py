"""Normalize a captured LanderPi ROS2 graph into a replayable evidence artifact.

The capture itself is intentionally outside this script.  An operator runs the
allowlisted, read-only ``ros2`` inspection commands inside the target runtime,
then supplies their bounded stdout in the input JSON.  This keeps credentials,
SSH policy, and target shell execution out of the parser while making the
observed topic set usable by targetd and the DSL context adapter.
"""

from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from rolo.targetd.ros2_runtime import snapshot_from_cli_output


def _lines(value: Any) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ValueError("CLI output fields must be arrays of strings")
    return value


def normalize(payload: dict[str, Any]) -> dict[str, Any]:
    if payload.get("schema_version") != "rolo-ros2-runtime-capture/v1":
        raise ValueError("unsupported ROS2 runtime capture schema")
    target_id = payload.get("target_id")
    if not isinstance(target_id, str) or not target_id.strip():
        raise ValueError("target_id is required")
    observed_at = payload.get("observed_at")
    if not isinstance(observed_at, str) or not observed_at.strip():
        observed_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    snapshot = snapshot_from_cli_output(
        distro=str(payload.get("distro", "")),
        ros2_path=str(payload.get("ros2_path", "")),
        topic_lines=_lines(payload.get("topic_output", [])),
        node_lines=_lines(payload.get("node_output", [])),
        package_lines=_lines(payload.get("package_output", [])),
        topic_format=str(payload.get("topic_format", "list")),
        executor_user=payload.get("executor_user"),
        publisher_user=payload.get("publisher_user"),
        rmw_implementation=payload.get("rmw_implementation"),
    )
    result = {
        "schema_version": "rolo-ros2-runtime-observation/v1",
        "target_id": target_id.strip(),
        "observed_at": observed_at,
        "access": "READ_ONLY",
        "snapshot": snapshot.as_dict(),
        "runtime_digest": snapshot.runtime_digest,
        "routes": [topic.as_route() for topic in snapshot.topics],
        "limitations": [
            "ROS2 graph is a point-in-time observation",
            "message schema bytes were not captured; interface type is retained",
        ],
    }
    if snapshot.executor_user and snapshot.publisher_user and snapshot.executor_user != snapshot.publisher_user:
        result["limitations"].append("diagnostic executor user differs from ROS publisher user; graph discovery may not imply data receipt")
    return result


def run(input_path: Path, output_path: Path) -> dict[str, Any]:
    payload = json.loads(input_path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("capture input must be a JSON object")
    result = normalize(payload)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = output_path.with_suffix(output_path.suffix + ".tmp")
    temporary.write_text(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, output_path)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Normalize a read-only LanderPi ROS2 capture")
    parser.add_argument("--input", type=Path, required=True, help="capture JSON from bounded ROS2 CLI output")
    parser.add_argument("--output", type=Path, required=True, help="normalized observation artifact")
    args = parser.parse_args()
    print(json.dumps(run(args.input, args.output), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
