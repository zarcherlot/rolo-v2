"""Bounded Episode producer records and provenance graph persistence.

The producer writes immutable revision records; HTTP consumers should read only
the sanitized projection returned by :class:`EpisodeStore.publish`.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from rolo.core.persistence import atomic_write_text

from .canonical import canonical_json

_HEX64 = r"^[0-9a-f]{64}$"
_FORBIDDEN = re.compile(
    r"(password|secret|token|credential|prompt|response|artifact_ref|path$|hostname)", re.I
)


def _assert_safe(value: Any, *, key: str = "") -> None:
    if key and _FORBIDDEN.search(key):
        raise ValueError(f"forbidden Episode field: {key}")
    if isinstance(value, dict):
        for name, child in value.items():
            _assert_safe(child, key=str(name))
    elif isinstance(value, list):
        for child in value:
            _assert_safe(child, key=key)


class EpisodeEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal["rolo-episode-producer-event/v1"] = "rolo-episode-producer-event/v1"
    sequence: int = Field(ge=0)
    lane: Literal[
        "COMMAND",
        "STATE",
        "TELEMETRY",
        "OBSERVATION",
        "ALERT",
        "AGENT",
        "CONFIGURATION",
        "CHECKPOINT",
        "GATE",
        "OUTCOME",
    ]
    authority: Literal["DECLARED", "OBSERVED", "INFERRED", "HUMAN_CONFIRMED", "VERIFIED"]
    title: str = Field(min_length=1, max_length=160)
    summary: str = Field(default="", max_length=512)
    occurred_at: datetime
    offset_ms: int = Field(ge=0)
    duration_ms: int | None = Field(default=None, ge=0)
    severity: Literal["INFO", "WARNING", "ERROR"] = "INFO"
    evidence_ids: list[str] = Field(default_factory=list, max_length=32)
    related_event_ids: list[str] = Field(default_factory=list, max_length=32)
    metrics: dict[str, float] = Field(default_factory=dict, max_length=16)


class EpisodeRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal["rolo-episode-producer-record/v1"] = "rolo-episode-producer-record/v1"
    robot_id: str = Field(min_length=1, max_length=128)
    episode_id: str = Field(min_length=1, max_length=128)
    revision: int = Field(ge=1)
    state: Literal["RUNNING", "COMPLETED", "FAILED", "CANCELLED", "PARTIAL"]
    outcome: Literal["SUCCEEDED", "FAILED", "CANCELLED", "UNKNOWN"] = "UNKNOWN"
    verification: Literal["VERIFIED", "UNVERIFIED", "NOT_AVAILABLE"] = "NOT_AVAILABLE"
    started_at: datetime
    ended_at: datetime | None = None
    target_host_fingerprint: str = Field(pattern=_HEX64)
    session_digest: str | None = Field(default=None, pattern=_HEX64)
    surface_digest: str | None = Field(default=None, pattern=_HEX64)
    task_label: str = Field(default="Episode", max_length=160)
    events: list[EpisodeEvent] = Field(default_factory=list, max_length=1000)
    evidence_ids: list[str] = Field(default_factory=list, max_length=128)
    provenance: dict[str, Any] = Field(default_factory=dict)
    content_sha256: str | None = Field(default=None, pattern=_HEX64)

    @model_validator(mode="after")
    def validate_record(self) -> EpisodeRecord:
        if self.ended_at and self.ended_at < self.started_at:
            raise ValueError("episode ended_at precedes started_at")
        sequences = [event.sequence for event in self.events]
        if sequences != sorted(set(sequences)):
            raise ValueError("episode event sequence must be unique and monotonic")
        for event in self.events:
            if event.occurred_at.tzinfo is None:
                raise ValueError("episode event timestamps require timezone")
        _assert_safe(self.provenance)
        return self

    def content_payload(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude={"content_sha256"})

    def computed_content_sha256(self) -> str:
        return hashlib.sha256(canonical_json(self.content_payload())).hexdigest()

    def with_content_sha256(self) -> EpisodeRecord:
        return self.model_copy(update={"content_sha256": self.computed_content_sha256()})


class EpisodeStore:
    def __init__(self, root: Path) -> None:
        self.root = root.resolve()

    def record_path(self, record: EpisodeRecord) -> Path:
        return (
            self.root
            / "episodes"
            / record.robot_id
            / "records"
            / record.episode_id
            / f"revision-{record.revision}.json"
        )

    def publish_path(self, robot_id: str, episode_id: str) -> Path:
        return self.root / "episodes" / robot_id / "published" / f"{episode_id}.json"

    def commit(self, record: EpisodeRecord) -> Path:
        record = record.with_content_sha256()
        path = self.record_path(record)
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = (
            json.dumps(record.model_dump(mode="json"), sort_keys=True, separators=(",", ":")) + "\n"
        )
        if path.exists():
            if path.read_text(encoding="utf-8") != payload:
                raise ValueError("committed Episode revision is immutable")
            return path
        atomic_write_text(path, payload)
        return path

    def publish(self, record: EpisodeRecord) -> Path:
        record = record.with_content_sha256()
        committed = self.commit(record)
        path = self.publish_path(record.robot_id, record.episode_id)
        projection = {
            "schema_version": "rolo-episode-published-projection/v1",
            "detail": {
                "robot_id": record.robot_id,
                "episode_id": record.episode_id,
                "revision": record.revision,
                "state": record.state,
                "outcome": record.outcome,
                "verification": record.verification,
                "task_label": record.task_label,
                "started_at": record.started_at.isoformat(),
                "ended_at": record.ended_at.isoformat() if record.ended_at else None,
                "target_host_fingerprint": record.target_host_fingerprint,
                "session_digest": record.session_digest,
                "surface_digest": record.surface_digest,
                "event_count": len(record.events),
                "evidence_ids": record.evidence_ids,
            },
            "timeline": [event.model_dump(mode="json") for event in record.events],
            "provenance": {
                "record_sha256": record.content_sha256,
                "record_ref": str(committed.name),
            },
        }
        payload = json.dumps(projection, sort_keys=True, separators=(",", ":")) + "\n"
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists() and path.read_text(encoding="utf-8") != payload:
            raise ValueError("published Episode is immutable")
        if not path.exists():
            atomic_write_text(path, payload)
        return path

    def load(self, robot_id: str, episode_id: str, revision: int) -> EpisodeRecord:
        path = (
            self.root / "episodes" / robot_id / "records" / episode_id / f"revision-{revision}.json"
        )
        if path.is_symlink() or not path.is_file():
            raise ValueError("Episode revision is unavailable")
        record = EpisodeRecord.model_validate_json(path.read_text(encoding="utf-8"))
        if (
            record.robot_id != robot_id
            or record.episode_id != episode_id
            or record.content_sha256 != record.computed_content_sha256()
        ):
            raise ValueError("Episode revision integrity mismatch")
        return record
