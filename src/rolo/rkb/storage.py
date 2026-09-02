"""Durable, append-only storage for verified RKB snapshots."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from rolo.core.persistence import atomic_write_text, interprocess_lock

from .models import Snapshot
from .validation import EvidenceValidationError, validate_snapshot


@dataclass
class RKBMetrics:
    writes: int = 0
    reads: int = 0
    validation_rejections: int = 0
    corrupt_artifacts: int = 0

    def as_dict(self) -> dict[str, int]:
        return {
            "writes": self.writes,
            "reads": self.reads,
            "validation_rejections": self.validation_rejections,
            "corrupt_artifacts": self.corrupt_artifacts,
        }


class RKBStore:
    """Persist snapshots without overwriting prior immutable artifacts."""

    schema_version = "rkb-store/v1"

    def __init__(self, root: Path, *, metrics: RKBMetrics | None = None) -> None:
        self.root = root.resolve()
        self.snapshot_root = self.root / "snapshots"
        self.corrupt_root = self.root / "corrupt"
        self.latest_path = self.root / "latest.json"
        self.metrics_path = self.root / "metrics.json"
        self.metrics = metrics or RKBMetrics()

    def write(self, snapshot: Snapshot, *, now: datetime | None = None) -> Path:
        """Validate and durably append one snapshot, then atomically publish latest."""

        try:
            validate_snapshot(snapshot, now=now, require_fresh=False)
        except EvidenceValidationError:
            self.metrics.validation_rejections += 1
            self._flush_metrics()
            raise
        digest = snapshot.digest or snapshot.computed_digest()
        path = self.snapshot_root / f"{digest}.json"
        payload = json.dumps(
            snapshot.model_dump(mode="json"),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ) + "\n"
        with interprocess_lock(self.latest_path):
            if path.exists():
                existing = path.read_text(encoding="utf-8")
                if existing != payload:
                    self.metrics.validation_rejections += 1
                    self._flush_metrics()
                    raise EvidenceValidationError(
                        "immutable snapshot digest has conflicting content"
                    )
            else:
                atomic_write_text(path, payload, acquire_lock=False, require_absent=True)
            index = {
                "schema_version": "rkb-latest-index/v1",
                "digest": digest,
                "robot_id": snapshot.identity.robot_id,
                "updated_at": (now or datetime.now(timezone.utc)).isoformat(),
            }
            atomic_write_text(
                self.latest_path,
                json.dumps(index, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n",
                acquire_lock=False,
            )
        self.metrics.writes += 1
        self._flush_metrics()
        return path

    def load(self, digest: str) -> Snapshot:
        """Load and validate one immutable snapshot, isolating corrupt files."""

        path = self.snapshot_root / f"{digest}.json"
        self.metrics.reads += 1
        try:
            snapshot = Snapshot.model_validate_json(path.read_text(encoding="utf-8"))
            validate_snapshot(snapshot, require_fresh=False)
            if snapshot.digest != digest:
                raise EvidenceValidationError("snapshot filename does not match digest")
            self._flush_metrics()
            return snapshot
        except (OSError, ValueError, EvidenceValidationError) as exc:
            self.metrics.corrupt_artifacts += 1
            self._isolate(path)
            self._flush_metrics()
            if isinstance(exc, EvidenceValidationError):
                raise
            raise EvidenceValidationError(f"snapshot artifact is unreadable: {digest}") from exc

    def load_latest(self) -> Snapshot | None:
        """Return latest only when both pointer and artifact validate."""

        try:
            index = json.loads(self.latest_path.read_text(encoding="utf-8"))
            digest = str(index["digest"])
        except (OSError, ValueError, KeyError, TypeError) as exc:
            self.metrics.corrupt_artifacts += 1
            self._isolate(self.latest_path)
            self._flush_metrics()
            raise EvidenceValidationError("latest index is unreadable") from exc
        try:
            return self.load(digest)
        except EvidenceValidationError:
            # A corrupt latest artifact must not make older immutable
            # snapshots unreachable.  Recover the newest valid artifact and
            # republish the pointer atomically.
            candidates = sorted(
                self.snapshot_root.glob("*.json"),
                key=lambda item: item.stat().st_mtime_ns,
                reverse=True,
            )
            for candidate in candidates:
                candidate_digest = candidate.stem
                if candidate_digest == digest:
                    continue
                try:
                    snapshot = self.load(candidate_digest)
                except EvidenceValidationError:
                    continue
                index = {
                    "schema_version": "rkb-latest-index/v1",
                    "digest": candidate_digest,
                    "robot_id": snapshot.identity.robot_id,
                    "updated_at": datetime.now(timezone.utc).isoformat(),
                }
                atomic_write_text(
                    self.latest_path,
                    json.dumps(index, sort_keys=True, separators=(",", ":")) + "\n",
                )
                return snapshot
            raise

    def _flush_metrics(self) -> None:
        atomic_write_text(
            self.metrics_path,
            json.dumps(self.metrics.as_dict(), sort_keys=True, separators=(",", ":")) + "\n",
        )

    def _isolate(self, path: Path) -> None:
        if not path.exists():
            return
        self.corrupt_root.mkdir(parents=True, exist_ok=True)
        target = self.corrupt_root / f"{path.name}.{uuid4().hex}.corrupt"
        try:
            path.replace(target)
        except OSError:
            # The original remains available for manual recovery if isolation
            # loses a race with another reader or the filesystem is read-only.
            pass
