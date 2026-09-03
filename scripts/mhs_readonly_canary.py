"""Offline, bounded MHS read-only canary for a supplied Linux fixture root."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from rolo.mhs_linux import LinuxMhsInventory


def run(root: Path, device_prefix: str) -> dict[str, Any]:
    inventory = LinuxMhsInventory(root, device_prefix=device_prefix)
    observations = []
    for candidate, provider in inventory.providers():
        result = provider.read()
        observations.append(
            {
                "device_id": candidate.manifest.device_id,
                "status": result.status.value,
                "manifest_digest": candidate.manifest.manifest_sha256,
                "result": result.model_dump(mode="json"),
                "limitations": candidate.manifest.limits,
            }
        )
    payload = {
        "schema_version": "rolo-mhs-readonly-canary/v1",
        "root": str(root),
        "device_prefix": device_prefix,
        "observations": observations,
        "write_requests": 0,
        "read_only": True,
        "limitations": ["offline fixture only", "no release authority", "no device writes"],
    }
    payload["digest"] = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return payload


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--device-prefix", default="fixture")
    args = parser.parse_args()
    print(json.dumps(run(args.root, args.device_prefix), sort_keys=True))
