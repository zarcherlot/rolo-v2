"""Small production seam for real, validated RKB snapshot collection."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from typing import Any

from .models import EvidenceEnvelope, Snapshot
from .storage import RKBStore
from .validation import validate_snapshot


class SnapshotProbeRunner:
    """Adapt a target probe_runner callback into immutable RKB persistence."""

    def __init__(self, store: RKBStore, collect: Callable[[], Snapshot | EvidenceEnvelope]) -> None:
        self.store = store
        self.collect = collect

    def collect_and_persist(
        self,
        *,
        now: datetime | None = None,
        expected_robot_id: str | None = None,
        expected_fingerprint: str | None = None,
    ) -> Snapshot:
        value = self.collect()
        snapshot = value if isinstance(value, Snapshot) else Snapshot.from_envelope(value)
        if expected_robot_id is not None and snapshot.identity.robot_id != expected_robot_id:
            raise ValueError("collected snapshot robot identity mismatch")
        if (
            expected_fingerprint is not None
            and snapshot.identity.target_host_fingerprint != expected_fingerprint
        ):
            raise ValueError("collected snapshot target fingerprint mismatch")
        snapshot = snapshot.with_digest()
        validate_snapshot(snapshot, now=now, require_fresh=False)
        self.store.write(snapshot, now=now)
        return snapshot


def collect_snapshot(
    store: RKBStore, probe_runner: Callable[[], Snapshot | EvidenceEnvelope], **kwargs: Any
) -> Snapshot:
    return SnapshotProbeRunner(store, probe_runner).collect_and_persist(**kwargs)
