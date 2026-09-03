"""Offline, bounded MHS read-only canary for a supplied Linux fixture root."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any

from rolo.mhs_linux import LinuxMhsInventory


def _rollback_pointer() -> str:
    """Return a reproducible source pointer without touching the target device."""
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"], stderr=subprocess.DEVNULL, text=True
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        return "unavailable"


def run(root: Path, device_prefix: str, rollback_pointer: str | None = None) -> dict[str, Any]:
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
    evidence_ids = sorted(
        {evidence_id for item in observations for evidence_id in item["result"].get("evidence_ids", [])}
    )
    payload = {
        "schema_version": "rolo-mhs-readonly-canary/v1",
        "root": str(root),
        "device_prefix": device_prefix,
        "observations": observations,
        "write_requests": 0,
        "read_only": True,
        "evidence_ids": evidence_ids,
        "artifact": {"kind": "mhs-readonly-canary", "format": "json"},
        "rollback_pointer": rollback_pointer or _rollback_pointer(),
        "limitations": ["offline fixture only", "no release authority", "no device writes", "no control-plane verification"],
    }
    payload["digest"] = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return payload


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--device-prefix", default="fixture")
    parser.add_argument("--artifact", type=Path, help="Write the signed-by-digest JSON artifact")
    parser.add_argument("--rollback-pointer", help="Source/release pointer recorded in the artifact")
    args = parser.parse_args()
    payload = run(args.root, args.device_prefix, args.rollback_pointer)
    rendered = json.dumps(payload, sort_keys=True, indent=2) + "\n"
    if args.artifact:
        args.artifact.parent.mkdir(parents=True, exist_ok=True)
        args.artifact.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
