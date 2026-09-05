"""Stdio JSONL daemon for the targetd DSL frame protocol."""

import argparse
import sys

from .dsl_service import TargetdDslService
from .session import FrameCodec


def run(stdin, stdout, cache_dir: str) -> int:
    service = TargetdDslService(cache_dir)
    for line in stdin:
        if not line.strip():
            continue
        try:
            response = service.handle(FrameCodec.decode(line))
            stdout.buffer.write(FrameCodec.encode(response))
            stdout.flush()
        except Exception as exc:  # protocol boundary must remain alive
            message = str(exc).replace('"', '\\"')
            stdout.write(f'{{"frame_type":"DSL_EVENT","request_id":"unknown","payload":{{"code":"FRAME_INVALID","message":"{message}"}}}}\n')
            stdout.flush()
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cache-dir", required=True)
    args = parser.parse_args()
    return run(sys.stdin, sys.stdout, args.cache_dir)


if __name__ == "__main__":
    raise SystemExit(main())
