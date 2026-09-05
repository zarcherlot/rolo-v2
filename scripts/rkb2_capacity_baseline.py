"""Run a bounded local RKB snapshot storage capacity baseline."""

from __future__ import annotations

import argparse
import json
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from rolo.rkb import Fact, FactSourceKind, RKBStore, Snapshot, SnapshotIdentity


def build_snapshot(index: int) -> Snapshot:
    observed = datetime.now(timezone.utc)
    identity = SnapshotIdentity(
        robot_id=f"capacity-{index}",
        target_host_fingerprint="a" * 64,
        source_id="capacity-baseline",
        deployment_mode="local",
        request_nonce=f"{index:032x}",
        observed_at=observed,
        fresh_until=observed + timedelta(minutes=5),
    )
    fact = Fact(
        robot_id=identity.robot_id,
        target_host_fingerprint=identity.target_host_fingerprint,
        source_id=identity.source_id,
        deployment_mode=identity.deployment_mode,
        request_nonce=identity.request_nonce,
        source_kind=FactSourceKind.OBSERVED_RUNTIME,
        source_ref=f"artifact://capacity/{index}",
        observed_at=observed,
        fresh_until=identity.fresh_until,
        value={"layer": "linux", "data": {"index": index}},
    )
    return Snapshot(
        identity=identity,
        facts=[fact],
        freshness_policy={"process_state": 30},
    ).with_digest()


def main(count: int, root: Path | None = None) -> int:
    if count < 1 or count > 10_000:
        raise ValueError("count must be between 1 and 10000")
    storage_context = (
        tempfile.TemporaryDirectory(prefix="rkb2-capacity-")
        if root is None
        else _keep(root)
    )
    with storage_context as path:
        path = Path(path)
        store = RKBStore(path)
        started = time.perf_counter()
        snapshots = [build_snapshot(index) for index in range(count)]
        for item in snapshots:
            store.write(item)
        write_seconds = time.perf_counter() - started
        read_started = time.perf_counter()
        for item in snapshots:
            store.load(item.digest or "")
        read_seconds = time.perf_counter() - read_started
        bytes_written = sum(item.stat().st_size for item in path.rglob("*.json"))
        print(
            json.dumps(
                {
                    "schema_version": "rkb-capacity-baseline/v1",
                    "count": count,
                    "bytes_written": bytes_written,
                    "write_seconds": round(write_seconds, 6),
                    "read_seconds": round(read_seconds, 6),
                    "writes_per_second": round(count / max(write_seconds, 1e-9), 3),
                    "reads_per_second": round(count / max(read_seconds, 1e-9), 3),
                    "metrics": store.metrics.as_dict(),
                },
                sort_keys=True,
            )
        )
    return 0


class _keep:
    def __init__(self, path: Path) -> None:
        self.path = path

    def __enter__(self) -> Path:
        self.path.mkdir(parents=True, exist_ok=True)
        return self.path

    def __exit__(self, *_: object) -> None:
        return None


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--count", type=int, default=100)
    parser.add_argument("--root", type=Path)
    args = parser.parse_args()
    raise SystemExit(main(args.count, args.root))
