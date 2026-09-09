"""Durable Trace/Certify episode history and verified artifact downloads."""

from __future__ import annotations

import hashlib
import json
import mimetypes
import os
import re
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from rolo.core.persistence import atomic_write_text, interprocess_lock
from rolo.dsl.parser import loads_unique_json
from rolo.mvp.artifacts import ArtifactIndex

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_STATUS = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_MAX_ARTIFACT_BYTES = 32 * 1024 * 1024
_MAX_EPISODE_BYTES = 128 * 1024 * 1024
_MAX_LEDGER_BYTES = 64 * 1024 * 1024


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def _reparse(path: Path) -> bool:
    try:
        attributes = getattr(path.lstat(), "st_file_attributes", 0)
    except FileNotFoundError:
        return False
    import stat

    return bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))


class EpisodeArtifact(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=512)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    byte_count: int = Field(ge=0, le=_MAX_ARTIFACT_BYTES)
    media_type: str = Field(min_length=1, max_length=128)

    @model_validator(mode="after")
    def validate_name(self) -> EpisodeArtifact:
        path = PurePosixPath(self.name)
        if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts) or "\\" in self.name:
            raise ValueError("episode artifact name is unsafe")
        return self


class EpisodeRevision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["rolo-episode-revision/v1"] = "rolo-episode-revision/v1"
    episode_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
    run_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
    target_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
    kind: Literal["TRACE", "CERTIFY"]
    status: str = Field(pattern=r"^[A-Z][A-Z0-9_]{0,63}$")
    revision: int = Field(ge=1)
    recorded_at: datetime
    release_digest: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    compile_context_digest: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    target_fingerprint: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$|^UNKNOWN$")
    mapping_confirmation_receipt_digest: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    plan_digest: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    artifact_index_manifest: str = Field(pattern=r"^[0-9a-f]{64}$")
    artifacts: tuple[EpisodeArtifact, ...] = Field(min_length=1, max_length=128)
    artifact_manifest_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    previous_episode_revision_digest: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    previous_ledger_digest: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    revision_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")

    def unsigned_payload(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude={"revision_digest"})

    @model_validator(mode="after")
    def validate_revision(self) -> EpisodeRevision:
        if self.recorded_at.tzinfo is None:
            raise ValueError("episode timestamp must include timezone")
        if len({item.name for item in self.artifacts}) != len(self.artifacts):
            raise ValueError("episode contains duplicate artifact names")
        expected_manifest = _digest([item.model_dump(mode="json") for item in self.artifacts])
        if self.artifact_manifest_digest != expected_manifest:
            raise ValueError("episode artifact manifest digest mismatch")
        if self.revision_digest != _digest(self.unsigned_payload()):
            raise ValueError("episode revision digest mismatch")
        return self

    def public_payload(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


class EpisodeStore:
    """Content-addressed episode ledger for list/history/download APIs."""

    def __init__(self, root: str | Path) -> None:
        self.root = Path(os.path.abspath(os.fspath(root)))
        if self.root.exists() and (self.root.is_symlink() or _reparse(self.root) or not self.root.is_dir()):
            raise ValueError("episode root is unsafe")
        self.root.mkdir(parents=True, exist_ok=True)
        self.objects = self.root / "objects"
        self.objects.mkdir(parents=True, exist_ok=True)
        if any(path.is_symlink() or _reparse(path) for path in (self.root, self.objects)):
            raise ValueError("episode root is unsafe")
        self.ledger = self.root / "episode-history.jsonl"
        self.lock_path = self.root / "episode-ledger"

    def publish(
        self,
        *,
        episode_id: str,
        run_id: str,
        target_id: str,
        kind: Literal["TRACE", "CERTIFY"],
        status: str,
        artifact_index_path: Path,
        release_digest: str | None = None,
        compile_context_digest: str | None = None,
        target_fingerprint: str | None = None,
        mapping_confirmation_receipt_digest: str | None = None,
        plan_digest: str | None = None,
        recorded_at: datetime | None = None,
    ) -> EpisodeRevision:
        if any(_ID.fullmatch(value) is None for value in (episode_id, run_id, target_id)) or _STATUS.fullmatch(status) is None:
            raise ValueError("episode identity is invalid")
        index, source_root, artifacts = self._verify_source_index(artifact_index_path, run_id, target_id)
        now = recorded_at or datetime.now(timezone.utc)
        if now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("episode clock is invalid")
        with interprocess_lock(self.lock_path, stale_after_s=None):
            records = self._load_unlocked()
            history = [item for item in records if item.episode_id == episode_id]
            revision = len(history) + 1
            for artifact in artifacts:
                source = source_root / PurePosixPath(artifact.name)
                self._put_object_unlocked(source, artifact)
            payload = {
                "schema_version": "rolo-episode-revision/v1",
                "episode_id": episode_id,
                "run_id": run_id,
                "target_id": target_id,
                "kind": kind,
                "status": status,
                "revision": revision,
                "recorded_at": now,
                "release_digest": release_digest,
                "compile_context_digest": compile_context_digest,
                "target_fingerprint": target_fingerprint,
                "mapping_confirmation_receipt_digest": mapping_confirmation_receipt_digest,
                "plan_digest": plan_digest,
                "artifact_index_manifest": index.manifest_sha256,
                "artifacts": tuple(artifacts),
                "artifact_manifest_digest": _digest([item.model_dump(mode="json") for item in artifacts]),
                "previous_episode_revision_digest": history[-1].revision_digest if history else None,
                "previous_ledger_digest": records[-1].revision_digest if records else None,
            }
            canonical = {
                key: ([item.model_dump(mode="json") for item in value] if key == "artifacts" else value)
                for key, value in payload.items()
            }
            canonical["recorded_at"] = now.isoformat().replace("+00:00", "Z")
            candidate = EpisodeRevision.model_validate({**payload, "revision_digest": _digest(canonical)})
            if history:
                previous = history[-1]
                same = candidate.model_copy(
                    update={
                        "revision": previous.revision,
                        "recorded_at": previous.recorded_at,
                        "previous_episode_revision_digest": previous.previous_episode_revision_digest,
                        "previous_ledger_digest": previous.previous_ledger_digest,
                        "revision_digest": previous.revision_digest,
                    }
                )
                if same == previous:
                    return previous
            encoded = candidate.model_dump_json() + "\n"
            current_size = self.ledger.stat().st_size if self.ledger.exists() else 0
            if current_size + len(encoded.encode("utf-8")) > _MAX_LEDGER_BYTES:
                raise ValueError("episode ledger exceeds size limit")
            if self.ledger.is_symlink() or _reparse(self.ledger):
                raise ValueError("episode ledger is unsafe")
            with self.ledger.open("a", encoding="utf-8", newline="") as stream:
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            return candidate

    def get(self, episode_id: str) -> EpisodeRevision:
        history = self.history(episode_id)
        if not history:
            raise KeyError(episode_id)
        return history[-1]

    def history(self, episode_id: str) -> tuple[EpisodeRevision, ...]:
        if _ID.fullmatch(episode_id) is None:
            raise KeyError(episode_id)
        with interprocess_lock(self.lock_path, stale_after_s=None):
            records = self._load_unlocked()
        return tuple(record for record in records if record.episode_id == episode_id)

    def list(self, *, after: str | None = None, limit: int = 50) -> tuple[EpisodeRevision, ...]:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 200:
            raise ValueError("episode list limit is invalid")
        if after is not None and _ID.fullmatch(after) is None:
            raise ValueError("episode cursor is invalid")
        with interprocess_lock(self.lock_path, stale_after_s=None):
            records = self._load_unlocked()
        latest: dict[str, EpisodeRevision] = {}
        for record in records:
            latest[record.episode_id] = record
        ordered = sorted(latest.values(), key=lambda item: item.episode_id)
        if after is not None:
            ordered = [item for item in ordered if item.episode_id > after]
        return tuple(ordered[:limit])

    def download(self, episode_id: str, artifact_name: str) -> tuple[bytes, EpisodeArtifact]:
        revision = self.get(episode_id)
        matches = [item for item in revision.artifacts if item.name == artifact_name]
        if len(matches) != 1:
            raise KeyError(artifact_name)
        artifact = matches[0]
        path = self.objects / artifact.sha256
        if path.is_symlink() or _reparse(path) or not path.is_file() or path.stat().st_size != artifact.byte_count:
            raise ValueError("episode object is unavailable")
        payload = path.read_bytes()
        if hashlib.sha256(payload).hexdigest() != artifact.sha256:
            raise ValueError("episode object digest mismatch")
        return payload, artifact

    def _verify_source_index(
        self,
        path: Path,
        run_id: str,
        target_id: str,
    ) -> tuple[ArtifactIndex, Path, tuple[EpisodeArtifact, ...]]:
        path = Path(os.path.abspath(os.fspath(path)))
        if path.is_symlink() or _reparse(path) or not path.is_file() or path.stat().st_size > 4 * 1024 * 1024:
            raise ValueError("episode artifact index is invalid")
        try:
            index = ArtifactIndex.model_validate(loads_unique_json(path.read_text(encoding="utf-8")))
            index.verify()
        except (OSError, TypeError, ValueError) as exc:
            raise ValueError("episode artifact index is invalid") from exc
        if index.run_id != run_id or index.target_id != target_id:
            raise ValueError("episode artifact index identity mismatch")
        root = path.parent.resolve()
        artifacts: list[EpisodeArtifact] = []
        total = 0
        for item in index.artifacts:
            name = item.get("path")
            expected = item.get("sha256")
            if not isinstance(name, str) or not isinstance(expected, str):
                raise ValueError("episode artifact index entry is invalid")
            relative = PurePosixPath(name)
            candidate = root.joinpath(*relative.parts)
            if candidate.resolve().parent != root and root not in candidate.resolve().parents:
                raise ValueError("episode artifact escapes index root")
            if candidate.is_symlink() or _reparse(candidate) or not candidate.is_file():
                raise ValueError("episode source artifact is unsafe")
            size = candidate.stat().st_size
            total += size
            if size > _MAX_ARTIFACT_BYTES or total > _MAX_EPISODE_BYTES:
                raise ValueError("episode artifacts exceed size limit")
            digest = hashlib.sha256(candidate.read_bytes()).hexdigest()
            if digest != expected:
                raise ValueError("episode source artifact digest mismatch")
            media_type = mimetypes.guess_type(name)[0] or "application/octet-stream"
            artifacts.append(EpisodeArtifact(name=name, sha256=digest, byte_count=size, media_type=media_type))
        if not artifacts or len({artifact.name for artifact in artifacts}) != len(artifacts):
            raise ValueError("episode artifact index is empty or duplicated")
        return index, root, tuple(artifacts)

    def _put_object_unlocked(self, source: Path, artifact: EpisodeArtifact) -> None:
        destination = self.objects / artifact.sha256
        if destination.exists():
            if destination.is_symlink() or _reparse(destination) or not destination.is_file():
                raise ValueError("episode object is unsafe")
            payload = destination.read_bytes()
            if len(payload) != artifact.byte_count or hashlib.sha256(payload).hexdigest() != artifact.sha256:
                raise ValueError("episode object collision")
            return
        payload = source.read_bytes()
        if len(payload) != artifact.byte_count or hashlib.sha256(payload).hexdigest() != artifact.sha256:
            raise ValueError("episode source changed during publication")
        # latin-1 is reversible but atomic_write_text is text-only and would
        # alter arbitrary binary data.  Episode artifacts in this slice are
        # JSON/JSONL/Markdown/HTML; fail closed for other bytes until the
        # binary object writer is introduced.
        try:
            text = payload.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("episode binary artifact publication is unsupported") from exc
        atomic_write_text(destination, text, acquire_lock=False, require_absent=True)
        written = destination.read_bytes()
        if hashlib.sha256(written).hexdigest() != artifact.sha256:
            raise ValueError("episode object publication changed bytes")

    def _load_unlocked(self) -> list[EpisodeRevision]:
        if not self.ledger.exists():
            return []
        if self.ledger.is_symlink() or _reparse(self.ledger) or not self.ledger.is_file() or self.ledger.stat().st_size > _MAX_LEDGER_BYTES:
            raise ValueError("episode ledger is invalid")
        records: list[EpisodeRevision] = []
        per_episode: dict[str, EpisodeRevision] = {}
        previous: str | None = None
        try:
            with self.ledger.open("r", encoding="utf-8") as stream:
                for line in stream:
                    if not line.endswith("\n"):
                        raise ValueError("truncated episode record")
                    record = EpisodeRevision.model_validate(loads_unique_json(line))
                    prior = per_episode.get(record.episode_id)
                    if (
                        record.previous_ledger_digest != previous
                        or record.revision != (prior.revision + 1 if prior else 1)
                        or record.previous_episode_revision_digest != (prior.revision_digest if prior else None)
                    ):
                        raise ValueError("episode ledger chain mismatch")
                    records.append(record)
                    per_episode[record.episode_id] = record
                    previous = record.revision_digest
        except (OSError, TypeError, ValueError) as exc:
            raise ValueError("episode ledger is invalid") from exc
        return records


__all__ = ["EpisodeArtifact", "EpisodeRevision", "EpisodeStore"]
