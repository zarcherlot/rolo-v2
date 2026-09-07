"""Stdio JSONL daemon for the targetd DSL frame protocol."""

import argparse
import json
import sys
from pathlib import Path

from rolo.dsl.parser import loads_unique_json

from .dsl_service import TargetdDslService
from .ros2_runtime import Ros2RuntimeResolver, Ros2RuntimeSnapshot
from .runtime_backend import Ros2ReadOnlyExecutor, ros2_registry
from .session import FrameCodec


def run(
    stdin,
    stdout,
    cache_dir: str,
    *,
    ros2_snapshot: Path | None = None,
    execute_readonly: bool = False,
) -> int:
    resolver = None
    registry = None
    if ros2_snapshot is not None:
        raw = loads_unique_json(ros2_snapshot.read_text(encoding="utf-8"))
        if isinstance(raw, dict) and isinstance(raw.get("snapshot"), dict):
            raw = raw["snapshot"]
        if not isinstance(raw, dict):
            raise ValueError("ROS2 snapshot artifact must be a JSON object")
        resolver = Ros2RuntimeResolver(Ros2RuntimeSnapshot.from_dict(raw))
        executor = Ros2ReadOnlyExecutor(resolver) if execute_readonly else None
        registry = ros2_registry(resolver, executor)
    service = TargetdDslService(cache_dir, runtime_resolver=resolver, backend_registry=registry)
    for line in stdin:
        if not line.strip():
            continue
        try:
            response = service.handle(FrameCodec.decode(line))
            stdout.buffer.write(FrameCodec.encode(response))
            stdout.flush()
        except Exception as exc:  # protocol boundary must remain alive
            error_payload = {
                "frame_type": "DSL_EVENT",
                "request_id": "unknown",
                "payload": {"code": "FRAME_INVALID", "message": str(exc)},
            }
            stdout.write(json.dumps(error_payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n")
            stdout.flush()
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cache-dir", required=True)
    parser.add_argument("--ros2-snapshot", type=Path, default=None, help="verified read-only ROS2 snapshot artifact")
    parser.add_argument("--execute-readonly", action="store_true", help="allow bounded ros2 topic echo for OBSERVE")
    args = parser.parse_args()
    return run(
        sys.stdin,
        sys.stdout,
        args.cache_dir,
        ros2_snapshot=args.ros2_snapshot,
        execute_readonly=args.execute_readonly,
    )


if __name__ == "__main__":
    raise SystemExit(main())
