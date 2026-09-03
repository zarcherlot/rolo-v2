"""Run a bounded, read-only MHS canary and atomically publish its artifact.

The command is intentionally backend-neutral. Deployments construct a provider
from their target adapter; this utility only invokes inspect/status/read and
publishes a JSON record. A failed run never replaces ``latest.json``.
"""

from __future__ import annotations

import argparse
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from rolo.mhs_hardware import MhsDeviceManifest, MhsDeviceProvider, MhsResult, MhsStatus
from rolo.rkb.models import SnapshotIdentity
from rolo.rkb.storage import RKBStore


def _atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(name, path)
    finally:
        try:
            os.unlink(name)
        except FileNotFoundError:
            pass


class MhsCanaryArtifact(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = "mhs-read-canary/v1"
    device_id: str = Field(min_length=1)
    target_host_fingerprint: str | None = None
    collected_at: datetime
    passed: bool
    results: list[MhsResult] = Field(min_length=3)
    limitations: list[str] = Field(min_length=1)
    artifact_sha256: str | None = None
    snapshot_digest: str | None = None


def run_canary(
    provider: MhsDeviceProvider,
    root: Path,
    *,
    identity: SnapshotIdentity | None = None,
    store: RKBStore | None = None,
) -> dict[str, Any]:
    """Collect the four RKB-3 read checks and publish only on full success."""

    results: list[MhsResult] = [provider.inspect(), provider.status(), provider.read()]
    passed = all(item.status == MhsStatus.AVAILABLE for item in results)
    artifact = {
        "schema_version": "mhs-read-canary/v1",
        "device_id": provider.manifest.device_id,
        "target_host_fingerprint": provider.target_host_fingerprint,
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "passed": passed,
        "results": [item.model_dump(mode="json") for item in results],
        "limitations": [
            "read-only canary; no reset, calibrate, setpoint, power or firmware operation",
            "successful read does not establish physical safety or authorization",
        ],
    }
    if passed:
        if store is not None:
            if identity is None:
                raise ValueError("RKB storage requires a verified SnapshotIdentity")
            from rolo.mhs_hardware import mhs_results_to_snapshot

            snapshot = mhs_results_to_snapshot(identity, results)
            store.write(snapshot)
            artifact["snapshot_digest"] = snapshot.digest
        digest = (
            __import__("hashlib")
            .sha256(json.dumps(artifact, sort_keys=True, separators=(",", ":")).encode("utf-8"))
            .hexdigest()
        )
        artifact["artifact_sha256"] = digest
        _atomic_json(root / f"{digest}.json", artifact)
        _atomic_json(
            root / "latest.json",
            {"schema_version": "mhs-read-canary-latest/v1", "artifact_sha256": digest},
        )
    MhsCanaryArtifact.model_validate(artifact)
    return artifact


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--values", type=Path, required=True, help="JSON object returned by read()")
    parser.add_argument("--target-fingerprint", default=None)
    args = parser.parse_args()

    class JsonBackend:
        def __init__(self, values: dict[str, Any]) -> None:
            self.values = values

        def read(self) -> dict[str, Any]:
            return dict(self.values)

        def status(self) -> dict[str, str]:
            return {"health": "OK", "transport": "json-fixture"}

    manifest = MhsDeviceManifest.model_validate_json(args.manifest.read_text(encoding="utf-8"))
    values = json.loads(args.values.read_text(encoding="utf-8"))
    if not isinstance(values, dict):
        parser.error("--values must contain a JSON object")
    artifact = run_canary(
        MhsDeviceProvider(
            manifest, JsonBackend(values), target_host_fingerprint=args.target_fingerprint
        ),
        args.root,
    )
    print(json.dumps(artifact, ensure_ascii=False, sort_keys=True))
    return 0 if artifact["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
