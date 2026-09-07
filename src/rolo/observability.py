"""Bounded, redacted observability primitives for post-compiler journeys.

The recorder is deliberately file based so field runs can retain a small JSONL
sidecar without requiring a metrics service.  It accepts arbitrary diagnostic
payloads, but removes values under credential-like keys before persistence.
"""

from __future__ import annotations

import os
import re
import threading
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Literal

from pydantic import Field, field_validator

from .dsl.models import StrictModel

_SENSITIVE_KEY = re.compile(r"(?:pass(word)?|token|secret|api[_-]?key|authorization|credential|private[_-]?key)", re.IGNORECASE)
_REDACTED = "[REDACTED]"


def redact(value: Any, *, depth: int = 0, max_depth: int = 8) -> Any:
    """Return a bounded diagnostic value with secret-like fields redacted."""

    if depth >= max_depth:
        return "[TRUNCATED]"
    if isinstance(value, Mapping):
        return {
            str(key)[:128]: (_REDACTED if _SENSITIVE_KEY.search(str(key)) else redact(item, depth=depth + 1, max_depth=max_depth))
            for key, item in list(value.items())[:64]
        }
    if isinstance(value, (list, tuple, set)):
        return [redact(item, depth=depth + 1, max_depth=max_depth) for item in list(value)[:64]]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value if not isinstance(value, str) or len(value) <= 2048 else value[:2048] + "…"
    return str(value)[:2048]


class JourneyMetric(StrictModel):
    """One persisted journey metric or lifecycle event."""

    schema_version: Literal["rolo-journey-metric/v1"] = "rolo-journey-metric/v1"
    event: str = Field(min_length=1, max_length=128)
    stage: str = Field(min_length=1, max_length=64)
    status: str = Field(min_length=1, max_length=32)
    session_id: str | None = Field(default=None, max_length=256)
    target_id: str | None = Field(default=None, max_length=128)
    duration_ms: int | None = Field(default=None, ge=0, le=86_400_000)
    labels: dict[str, str] = Field(default_factory=dict, max_length=32)
    payload: dict[str, Any] = Field(default_factory=dict, max_length=64)
    recorded_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @field_validator("labels")
    @classmethod
    def _bounded_labels(cls, value: dict[str, str]) -> dict[str, str]:
        return {str(key)[:128]: str(item)[:256] for key, item in value.items()}

    @field_validator("payload")
    @classmethod
    def _redact_payload(cls, value: dict[str, Any]) -> dict[str, Any]:
        return redact(value)


class ObservabilityRecorder:
    """Append bounded JSONL metrics and rotate one previous segment."""

    def __init__(self, path: Path, *, max_bytes: int = 2_000_000) -> None:
        if max_bytes < 1024:
            raise ValueError("max_bytes must be at least 1024")
        self.path = Path(path)
        self.max_bytes = max_bytes
        self._lock = threading.Lock()

    def record(
        self,
        *,
        event: str,
        stage: str,
        status: str,
        session_id: str | None = None,
        target_id: str | None = None,
        duration_ms: int | None = None,
        labels: Mapping[str, str] | None = None,
        payload: Mapping[str, Any] | None = None,
    ) -> JourneyMetric:
        metric = JourneyMetric(
            event=event,
            stage=stage,
            status=status,
            session_id=session_id,
            target_id=target_id,
            duration_ms=duration_ms,
            labels=dict(labels or {}),
            payload=dict(payload or {}),
        )
        line = metric.model_dump_json() + "\n"
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            if self.path.exists() and self.path.stat().st_size + len(line.encode("utf-8")) > self.max_bytes:
                rotated = self.path.with_name(self.path.name + ".1")
                os.replace(self.path, rotated)
            with self.path.open("a", encoding="utf-8", newline="\n") as stream:
                stream.write(line)
                stream.flush()
                os.fsync(stream.fileno())
        return metric


class ArtifactRetentionPolicy(StrictModel):
    """Retention limits for a single artifact directory."""

    max_files: int = Field(default=20, ge=1, le=10_000)
    max_age_days: int = Field(default=30, ge=1, le=3650)

    def plan_prune(self, root: Path, *, now: datetime | None = None) -> tuple[Path, ...]:
        root = Path(root).resolve()
        cutoff = (now or datetime.now(timezone.utc)) - timedelta(days=self.max_age_days)
        files = [path for path in root.glob("*") if path.is_file() and not path.is_symlink()]
        files.sort(key=lambda item: item.stat().st_mtime, reverse=True)
        stale = [path for path in files if datetime.fromtimestamp(path.stat().st_mtime, timezone.utc) < cutoff]
        excess = files[self.max_files :]
        return tuple(sorted({path for path in stale + excess}, key=lambda item: item.as_posix()))

    def prune(self, root: Path, *, now: datetime | None = None) -> tuple[Path, ...]:
        planned = self.plan_prune(root, now=now)
        root_resolved = Path(root).resolve()
        removed: list[Path] = []
        for path in planned:
            resolved = path.resolve()
            if resolved.parent != root_resolved or path.is_symlink() or not path.is_file():
                continue
            path.unlink()
            removed.append(path)
        return tuple(removed)


__all__ = ["ArtifactRetentionPolicy", "JourneyMetric", "ObservabilityRecorder", "redact"]
