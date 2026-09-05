"""Validate the Rolo <-> MHS read-only flow from a recorded observation.

The input may come from any MHS-compatible target.  It is replayed through the
same provider and RKB contracts used for a live adapter; no target-specific
driver or network access is required here.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from rolo.mhs_hardware import MhsBackend, MhsDeviceProvider
from rolo.mhs_linux import build_linux_manifest
from rolo.rkb import (
    EvidenceEnvelope,
    Fact,
    FactSourceKind,
    FreshnessStatus,
    ReadOnlyKnowledgeBase,
    SnapshotIdentity,
)


class ReplayBackend:
    """Replay a recorded MHS payload while preserving provider validation."""

    def __init__(self, payload: dict[str, Any]) -> None:
        self.payload = payload

    def read(self) -> dict[str, Any]:
        return dict(self.payload["read"])

    def status(self) -> dict[str, Any]:
        return dict(self.payload["status"])


def validate(payload: dict[str, Any]) -> dict[str, Any]:
    identity_data = payload.get("device_identity") or payload.get("manifest", {})
    model = str(identity_data.get("model") or "unknown")
    serial = identity_data.get("serial")
    device_id = str(payload.get("device_id") or "landerpi")
    manifest = build_linux_manifest(
        device_id=device_id,
        name="Recorded Linux target",
        vendor="observed",
        model=model,
        serial=serial,
        transport_target="recorded-observation",
    )
    backend: MhsBackend = ReplayBackend(payload)
    provider = MhsDeviceProvider(manifest, backend)
    results = [provider.inspect(), provider.status(), provider.read()]
    assert all(item.status.value == "AVAILABLE" for item in results), results
    assert all(item.route.startswith(f"mhs://{device_id}/") for item in results)
    denied = provider.invoke("reset")
    assert denied.status.value == "UNAVAILABLE"

    observed_at = datetime.fromtimestamp(
        float(payload["observed_at_epoch"]), tz=timezone.utc
    )
    fingerprint = hashlib.sha256(f"{model}|{serial or ''}".encode()).hexdigest()
    identity = SnapshotIdentity(
        robot_id=f"recorded-{device_id}",
        target_host_fingerprint=fingerprint,
        source_id="mhs-recording-replay",
        deployment_mode="remote",
        request_nonce=hashlib.md5(device_id.encode()).hexdigest(),  # noqa: S324 - test nonce only
        observed_at=observed_at,
        fresh_until=observed_at + timedelta(minutes=5),
    )
    facts = [
        Fact(
            robot_id=identity.robot_id,
            target_host_fingerprint=identity.target_host_fingerprint,
            source_id=identity.source_id,
            deployment_mode=identity.deployment_mode,
            request_nonce=identity.request_nonce,
            source_kind=FactSourceKind.OBSERVED_RUNTIME,
            source_ref=result.route,
            observed_at=observed_at,
            fresh_until=identity.fresh_until,
            value=result.model_dump(mode="json"),
            limitations=list(result.limitations),
        )
        for result in results
    ]
    envelope = EvidenceEnvelope(
        identity=identity,
        facts=facts,
        snapshot={"mhs_device_id": device_id, "provider_id": provider.provider_id},
    ).with_digest()
    envelope.verify(now=observed_at + timedelta(seconds=1))
    knowledge = ReadOnlyKnowledgeBase([envelope])
    query = knowledge.facts(now=observed_at + timedelta(seconds=1))
    assert len(query) == 3
    assert all(item.status == FreshnessStatus.FRESH for item in query)
    return {
        "status": "PASS",
        "device_id": device_id,
        "provider_id": provider.provider_id,
        "routes": [result.route for result in results],
        "rkb_digest": envelope.digest,
        "fact_ids": [fact.fact_id for fact in facts],
        "write_denied": denied.reason,
        "query_statuses": [item.status.value for item in query],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("observation", type=Path)
    args = parser.parse_args()
    print(json.dumps(validate(json.loads(args.observation.read_text(encoding="utf-8"))), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
