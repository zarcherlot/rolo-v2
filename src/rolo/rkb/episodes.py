"""RKB-4 metadata-only Episode records and dual-read publication storage.

An Episode in RKB-4 is an audit index around an existing Probe/RKB artifact.  It
does not contain raw telemetry, commands, prompts, model output, or Diagnose /
Certify conclusions.  New writes are always RKB metadata records; legacy
bundle/report files are read through the compatibility helpers only.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, JsonValue, field_validator, model_validator

from rolo.core.persistence import atomic_write_text, interprocess_lock

from .canonical import canonical_json
from .migration import bundle_to_snapshot
from .models import Snapshot, SnapshotIdentity
from .query import ReadOnlyKnowledgeBase
from .validation import EvidenceValidationError, validate_snapshot


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class EpisodeEventKind(str, Enum):
    BASELINE = "baseline"
    OBSERVATION = "observation"
    HYPOTHESIS = "hypothesis"
    CHANGE = "change"
    SMOKE_TEST = "smoke_test"
    DECISION = "decision"
    ROLLBACK = "rollback"


class EpisodeState(str, Enum):
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    PARTIAL = "PARTIAL"


class EpisodeArtifactRef(BaseModel):
    """Bounded reference to an existing artifact, never its payload."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["rkb-episode-artifact-ref/v1"] = "rkb-episode-artifact-ref/v1"
    role: Literal["bundle", "report", "snapshot", "evidence", "rollback"]
    ref: str = Field(min_length=1, max_length=1024)
    sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")

    @field_validator("ref")
    @classmethod
    def validate_ref(cls, value: str) -> str:
        if "\x00" in value or value.startswith(("/", "\\")):
            raise ValueError("artifact reference must be bounded and non-absolute")
        return value


_FORBIDDEN_METADATA_KEYS = {
    "secret",
    "password",
    "passwd",
    "token",
    "private_key",
    "api_key",
    "credential",
    "command_payload",
    "model_prompt",
    "model_response",
    "telemetry_payload",
    "state_payload",
    "raw_payload",
}


def _validate_safe_metadata(value: Any, *, key: str = "") -> None:
    lowered = key.lower()
    if any(marker in lowered for marker in _FORBIDDEN_METADATA_KEYS):
        raise ValueError(f"episode metadata contains forbidden field: {key}")
    if isinstance(value, Mapping):
        for child_key, child_value in value.items():
            _validate_safe_metadata(child_value, key=str(child_key))
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for child in value:
            _validate_safe_metadata(child, key=key)


class EpisodeEvent(BaseModel):
    """One bounded lifecycle event; all payloads are summaries and references."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["rkb-episode-event/v1"] = "rkb-episode-event/v1"
    event_id: str = Field(
        default_factory=lambda: f"event-{uuid4().hex}", pattern=r"^[a-z][a-z0-9_.-]{0,127}$"
    )
    sequence: int = Field(ge=1, le=1024)
    kind: EpisodeEventKind
    occurred_at: datetime
    summary: str = Field(min_length=1, max_length=1000)
    evidence_refs: list[str] = Field(default_factory=list, max_length=64)
    metadata: dict[str, JsonValue] = Field(default_factory=dict)

    @field_validator("evidence_refs")
    @classmethod
    def validate_refs(cls, refs: list[str]) -> list[str]:
        if any(not ref or len(ref) > 1024 for ref in refs):
            raise ValueError("episode evidence references must be bounded")
        return refs

    @model_validator(mode="after")
    def validate_metadata(self) -> EpisodeEvent:
        _validate_safe_metadata(self.metadata)
        encoded = canonical_json(self.metadata)
        if len(encoded) > 16_384:
            raise ValueError("episode event metadata exceeds 16 KiB")
        return self


class EpisodeMetadata(BaseModel):
    """Immutable metadata-only record for one Probe run."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["rkb-episode-metadata/v1"] = "rkb-episode-metadata/v1"
    episode_id: str = Field(
        default_factory=lambda: f"episode-{uuid4().hex}", pattern=r"^[a-z][a-z0-9_.-]{0,127}$"
    )
    probe_run_id: str = Field(min_length=1, max_length=128)
    identity: SnapshotIdentity
    state: EpisodeState = EpisodeState.COMPLETED
    started_at: datetime
    ended_at: datetime | None = None
    revision: int = Field(default=1, ge=1)
    parent_digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    bundle: EpisodeArtifactRef | None = None
    report: EpisodeArtifactRef | None = None
    snapshot: EpisodeArtifactRef | None = None
    events: list[EpisodeEvent] = Field(default_factory=list, max_length=128)
    limitations: list[str] = Field(default_factory=list, max_length=32)
    created_at: datetime = Field(default_factory=_utc_now)
    content_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_record(self) -> EpisodeMetadata:
        if self.ended_at is not None and self.ended_at < self.started_at:
            raise ValueError("episode ended_at must not precede started_at")
        if self.started_at.tzinfo is None or (self.ended_at and self.ended_at.tzinfo is None):
            raise ValueError("episode timestamps must include timezone")
        if any(event.occurred_at < self.started_at for event in self.events):
            raise ValueError("episode event occurs before episode start")
        sequences = [event.sequence for event in self.events]
        if sequences != sorted(sequences) or len(sequences) != len(set(sequences)):
            raise ValueError("episode events must have unique increasing sequences")
        if self.identity.access != "READ_ONLY":
            raise ValueError("RKB-4 Episode records are read-only")
        _validate_safe_metadata(self.model_dump(mode="json", exclude={"content_sha256"}))
        return self

    def payload(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude={"content_sha256"}, exclude_none=True)

    def computed_digest(self) -> str:
        return hashlib.sha256(canonical_json(self.payload())).hexdigest()

    def with_digest(self) -> EpisodeMetadata:
        return self.model_copy(update={"content_sha256": self.computed_digest()})

    @classmethod
    def from_probe_run(
        cls,
        identity: SnapshotIdentity,
        *,
        probe_run_id: str,
        snapshot_ref: str | None = None,
        snapshot_digest: str | None = None,
        bundle_ref: str | None = None,
        bundle_digest: str | None = None,
        report_ref: str | None = None,
        report_digest: str | None = None,
        events: list[EpisodeEvent] | None = None,
        limitations: list[str] | None = None,
        episode_id: str | None = None,
        started_at: datetime | None = None,
        ended_at: datetime | None = None,
    ) -> EpisodeMetadata:
        def ref(
            role: Literal["bundle", "report", "snapshot"], value: str | None, digest: str | None
        ) -> EpisodeArtifactRef | None:
            return EpisodeArtifactRef(role=role, ref=value, sha256=digest) if value else None

        return cls(
            episode_id=episode_id or f"episode-{probe_run_id}",
            probe_run_id=probe_run_id,
            identity=identity,
            started_at=started_at or identity.observed_at,
            ended_at=ended_at or identity.observed_at,
            snapshot=ref("snapshot", snapshot_ref, snapshot_digest),
            bundle=ref("bundle", bundle_ref, bundle_digest),
            report=ref("report", report_ref, report_digest),
            events=events or [],
            limitations=limitations or [],
        ).with_digest()


class EpisodeStore:
    """Append-only Episode records with atomic latest publication and rollback."""

    schema_version = "rkb-episode-store/v1"

    def __init__(self, root: Path, *, legacy_root: Path | None = None) -> None:
        self.root = root.resolve()
        self.legacy_root = (legacy_root or root).resolve()
        self.episode_root = self.root / "episodes"
        self.corrupt_root = self.root / "corrupt-episodes"

    def _dir(self, robot_id: str, episode_id: str) -> Path:
        return self.episode_root / robot_id / episode_id

    def _latest_path(self, robot_id: str, episode_id: str) -> Path:
        return self._dir(robot_id, episode_id) / "latest.json"

    def _record_path(self, episode: EpisodeMetadata) -> Path:
        digest = episode.content_sha256 or episode.computed_digest()
        return (
            self._dir(episode.identity.robot_id, episode.episode_id) / "records" / f"{digest}.json"
        )

    def publish(
        self,
        episode: EpisodeMetadata,
        *,
        expected_parent_digest: str | None = None,
    ) -> Path:
        episode = (
            episode.with_digest()
            if episode.content_sha256 != episode.computed_digest()
            else episode
        )
        path = self._record_path(episode)
        latest = self._latest_path(episode.identity.robot_id, episode.episode_id)
        with interprocess_lock(latest):
            current = self._read_index(latest, allow_missing=True)
            current_digest = current.get("digest") if current else None
            if expected_parent_digest is not None and current_digest != expected_parent_digest:
                raise EvidenceValidationError("episode parent digest does not match latest")
            if episode.parent_digest is not None and current_digest != episode.parent_digest:
                raise EvidenceValidationError("episode parent_digest does not match latest")
            if episode.parent_digest is None and current_digest is not None:
                episode = episode.model_copy(update={"parent_digest": current_digest}).with_digest()
                path = self._record_path(episode)
            payload = (
                json.dumps(
                    episode.model_dump(mode="json"),
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
            )
            if path.exists() and path.read_text(encoding="utf-8") != payload:
                raise EvidenceValidationError("immutable episode digest has conflicting content")
            if not path.exists():
                atomic_write_text(path, payload, acquire_lock=False, require_absent=True)
            index = {
                "schema_version": "rkb-episode-latest-index/v1",
                "robot_id": episode.identity.robot_id,
                "episode_id": episode.episode_id,
                "digest": episode.content_sha256,
                "previous_digest": current_digest,
                "revision": episode.revision,
                "updated_at": _utc_now().isoformat(),
            }
            atomic_write_text(
                latest,
                json.dumps(index, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n",
                acquire_lock=False,
            )
        return path

    def load(self, robot_id: str, episode_id: str, digest: str) -> EpisodeMetadata:
        path = self._dir(robot_id, episode_id) / "records" / f"{digest}.json"
        try:
            episode = EpisodeMetadata.model_validate_json(path.read_text(encoding="utf-8"))
            if episode.content_sha256 != digest or episode.computed_digest() != digest:
                raise EvidenceValidationError("episode content digest mismatch")
            return episode
        except EvidenceValidationError:
            raise
        except (OSError, ValueError) as exc:
            self._isolate(path)
            raise EvidenceValidationError("episode artifact is unreadable") from exc

    def load_latest(self, robot_id: str, episode_id: str) -> EpisodeMetadata:
        latest = self._latest_path(robot_id, episode_id)
        index = self._read_index(latest)
        if index.get("robot_id") != robot_id or index.get("episode_id") != episode_id:
            raise EvidenceValidationError("episode latest identity mismatch")
        return self.load(robot_id, episode_id, str(index["digest"]))

    def rollback(self, robot_id: str, episode_id: str) -> EpisodeMetadata:
        latest = self._latest_path(robot_id, episode_id)
        with interprocess_lock(latest):
            index = self._read_index(latest)
            previous = index.get("previous_digest")
            if not previous:
                raise EvidenceValidationError("episode has no previous latest revision")
            episode = self.load(robot_id, episode_id, str(previous))
            prior_parent = episode.parent_digest
            replacement = {
                **index,
                "digest": previous,
                "previous_digest": prior_parent,
                "revision": episode.revision,
                "updated_at": _utc_now().isoformat(),
            }
            atomic_write_text(
                latest,
                json.dumps(replacement, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
                + "\n",
                acquire_lock=False,
            )
            return episode

    def read_legacy_json(self, ref: str | Path) -> dict[str, Any]:
        """Read an old bundle/report without ever writing or migrating it in place."""
        path = self._resolve_legacy_ref(str(ref))
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise EvidenceValidationError("legacy artifact is unreadable") from exc
        if not isinstance(value, dict):
            raise EvidenceValidationError("legacy artifact must be a JSON object")
        return value

    def read_legacy_bundle(self, ref: str | Path) -> Any:
        from rolo.stages.probe.target_evidence import TargetEvidenceBundle

        return TargetEvidenceBundle.model_validate(self.read_legacy_json(ref))

    def read_legacy_report(self, ref: str | Path) -> Any:
        from rolo.core.models import DiscoveryReport

        return DiscoveryReport.model_validate(self.read_legacy_json(ref))

    def _resolve_legacy_ref(self, ref: str) -> Path:
        if ref.startswith("artifact://"):
            relative = ref.removeprefix("artifact://")
            base = self.legacy_root if relative.startswith("legacy/") else self.root
            if relative.startswith("legacy/"):
                relative = relative.removeprefix("legacy/")
            candidate = (base / relative).resolve()
        else:
            candidate = Path(ref).resolve()
        try:
            candidate.relative_to(self.root)
        except ValueError:
            try:
                candidate.relative_to(self.legacy_root)
            except ValueError as exc:
                raise EvidenceValidationError(
                    "legacy artifact reference escapes allowed root"
                ) from exc
        return candidate

    @staticmethod
    def _read_index(path: Path, *, allow_missing: bool = False) -> dict[str, Any] | None:
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            if allow_missing:
                return None
            raise EvidenceValidationError("episode latest index is missing") from None
        except (OSError, ValueError) as exc:
            raise EvidenceValidationError("episode latest index is unreadable") from exc
        if (
            not isinstance(value, dict)
            or value.get("schema_version") != "rkb-episode-latest-index/v1"
            or not value.get("digest")
        ):
            raise EvidenceValidationError("episode latest index is invalid")
        return value

    def _isolate(self, path: Path) -> None:
        if not path.exists():
            return
        self.corrupt_root.mkdir(parents=True, exist_ok=True)
        target = self.corrupt_root / f"{path.name}.{uuid4().hex}.corrupt"
        try:
            path.replace(target)
        except OSError:
            pass


def publish_probe_episode(
    bundle: Any,
    *,
    artifact_root: Path,
    deployment_mode: str,
    bundle_ref: str,
    legacy_root: Path | None = None,
    probe_run_id: str | None = None,
) -> tuple[Snapshot, EpisodeMetadata, Path, Path]:
    """Persist the new snapshot and its Episode after Probe verification.

    The caller must verify the legacy bundle first.  This helper never rewrites
    that bundle; it only appends the RKB snapshot and metadata-only Episode.
    """

    from .storage import RKBStore

    snapshot = bundle_to_snapshot(
        bundle,
        deployment_mode=deployment_mode,
        source_ref=bundle_ref,
    )
    rkb_root = artifact_root / "rkb"
    snapshot_path = RKBStore(rkb_root).write(snapshot, now=bundle.collected_at)
    episode = build_episode_from_snapshot(
        snapshot,
        probe_run_id=probe_run_id or f"probe-{bundle.payload_sha256[:24]}",
        snapshot_ref=f"artifact://rkb/snapshots/{snapshot.digest}.json",
        bundle_ref=bundle_ref,
        bundle_digest=bundle.payload_sha256,
    )
    episode_path = EpisodeStore(rkb_root, legacy_root=legacy_root).publish(episode)
    return snapshot, episode, snapshot_path, episode_path


def build_episode_from_snapshot(
    snapshot: Snapshot,
    *,
    probe_run_id: str,
    snapshot_ref: str | None = None,
    snapshot_digest: str | None = None,
    bundle_ref: str | None = None,
    bundle_digest: str | None = None,
    report_ref: str | None = None,
    report_digest: str | None = None,
    episode_id: str | None = None,
) -> EpisodeMetadata:
    """Create the RKB-4 metadata envelope from typed read-only queries."""

    validate_snapshot(snapshot, require_fresh=False)
    knowledge = ReadOnlyKnowledgeBase([snapshot])
    # MHS canaries may stamp individual routes a few milliseconds after the
    # snapshot identity.  Query at the newest observed fact while keeping the
    # identity and freshness bindings unchanged.
    now = max([snapshot.identity.observed_at] + [fact.observed_at for fact in snapshot.facts])
    identity_result = knowledge.robot.identity(now=now)
    runtime_result = knowledge.os.runtime_status(now=now)
    graph_result = knowledge.middleware.graph_snapshot(now=now)
    # There may be no application executable in a hardware-only snapshot.  A
    # typed UNKNOWN result is still part of the smoke contract and is safer
    # than inventing an application route.
    app_result = knowledge.app.executable_inspect("__rkb4_probe_app__", now=now)
    smoke_ok = (
        all(result.value is not None for result in (identity_result, runtime_result, graph_result))
        and app_result.status.value != "UNKNOWN"
    )
    evidence_ref = (
        snapshot_ref or f"artifact://snapshots/{snapshot.digest or snapshot.computed_digest()}.json"
    )
    events = [
        EpisodeEvent(
            sequence=1,
            kind=EpisodeEventKind.BASELINE,
            occurred_at=now,
            summary="Probe baseline bound to verified RKB snapshot",
            evidence_refs=[evidence_ref],
        ),
        EpisodeEvent(
            sequence=2,
            kind=EpisodeEventKind.OBSERVATION,
            occurred_at=now,
            summary="Typed identity, runtime, and middleware observations projected",
            evidence_refs=[evidence_ref],
            metadata={
                "identity_status": identity_result.status.value,
                "runtime_status": runtime_result.status.value,
                "graph_status": graph_result.status.value,
                "application_status": app_result.status.value,
            },
        ),
        EpisodeEvent(
            sequence=3,
            kind=EpisodeEventKind.HYPOTHESIS,
            occurred_at=now,
            summary="No diagnosis hypothesis persisted in metadata-only RKB-4",
            metadata={"authority": "UNVERIFIED"},
        ),
        EpisodeEvent(
            sequence=4,
            kind=EpisodeEventKind.CHANGE,
            occurred_at=now,
            summary="No device or configuration change executed; Probe remains read-only",
            metadata={"access": "READ_ONLY", "executed": False},
        ),
        EpisodeEvent(
            sequence=5,
            kind=EpisodeEventKind.SMOKE_TEST,
            occurred_at=now,
            summary="Typed query smoke completed" if smoke_ok else "Typed query smoke is partial",
            evidence_refs=[evidence_ref],
            metadata={
                "identity": identity_result.status.value,
                "runtime": runtime_result.status.value,
                "middleware": graph_result.status.value,
                "application": app_result.status.value,
            },
        ),
        EpisodeEvent(
            sequence=6,
            kind=EpisodeEventKind.DECISION,
            occurred_at=now,
            summary="Metadata-only Episode published for limited rollout"
            if smoke_ok
            else "Metadata-only Episode retained as partial evidence",
            metadata={
                "state": "COMPLETED" if smoke_ok else "PARTIAL",
                "verification": "NOT_AVAILABLE",
            },
        ),
        EpisodeEvent(
            sequence=7,
            kind=EpisodeEventKind.ROLLBACK,
            occurred_at=now,
            summary="Previous latest pointer remains available for atomic rollback",
            metadata={"rollback": "POINTER_ONLY"},
        ),
    ]
    limitations = list(snapshot.facts[0].limitations if snapshot.facts else [])
    limitations.append(
        "RKB-4 records metadata only; no Diagnose, Certify, replay, remediation, "
        "or device write was performed."
    )
    return EpisodeMetadata.from_probe_run(
        snapshot.identity,
        probe_run_id=probe_run_id,
        episode_id=episode_id,
        snapshot_ref=evidence_ref,
        snapshot_digest=snapshot_digest or snapshot.digest or snapshot.computed_digest(),
        bundle_ref=bundle_ref,
        bundle_digest=bundle_digest,
        report_ref=report_ref,
        report_digest=report_digest,
        events=events,
        limitations=limitations,
    )
