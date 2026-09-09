"""Bounded, resumable, content-addressed Release artifact uploads."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tempfile
from collections.abc import Iterable
from pathlib import Path
from typing import Annotated, Any, Literal

from pydantic import Field, model_validator

from rolo.core.persistence import interprocess_lock
from rolo.dsl.models import StrictModel
from rolo.dsl.parser import loads_unique_json

MAX_UPLOAD_BYTES = 32 * 1024 * 1024
MAX_CHUNK_BYTES = 1024 * 1024
MAX_UPLOAD_CHUNKS = 64
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_MAX_METADATA_BYTES = 64 * 1024
UploadChunkIndex = Annotated[
    int,
    Field(strict=True, ge=0, lt=MAX_UPLOAD_CHUNKS),
]


class ReleaseUploadError(ValueError):
    """A chunk, manifest, or finalized blob failed a closed check."""


def _is_linklike(path: Path) -> bool:
    if path.is_symlink():
        return True
    is_junction = getattr(path, "is_junction", None)
    if callable(is_junction) and is_junction():
        return True
    try:
        attributes = getattr(path.lstat(), "st_file_attributes", 0)
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise ReleaseUploadError("RELEASE_UPLOAD_OBJECT_UNREADABLE") from exc
    return bool(
        attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    )


def _lexical_absolute(path: str | Path) -> Path:
    return Path(os.path.abspath(os.fspath(Path(path).expanduser())))


def _fsync_directory(path: Path) -> None:
    if os.name == "nt":
        return
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _require_collection(path: Path) -> None:
    if _is_linklike(path) or (path.exists() and not path.is_dir()):
        raise ReleaseUploadError("RELEASE_UPLOAD_UNTRUSTED_PATH")


def _require_file_or_absent(path: Path) -> None:
    if _is_linklike(path):
        raise ReleaseUploadError("RELEASE_UPLOAD_UNTRUSTED_PATH")
    try:
        metadata = path.stat()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise ReleaseUploadError("RELEASE_UPLOAD_OBJECT_UNREADABLE") from exc
    if not path.is_file() or metadata.st_nlink != 1:
        raise ReleaseUploadError("RELEASE_UPLOAD_UNTRUSTED_PATH")


def content_digest(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


class ChunkUploadManifest(StrictModel):
    schema_version: Literal["rolo-release-chunk-upload/v1"] = (
        "rolo-release-chunk-upload/v1"
    )
    blob_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    total_bytes: int = Field(strict=True, ge=1, le=MAX_UPLOAD_BYTES)
    chunk_size: int = Field(strict=True, ge=1, le=MAX_CHUNK_BYTES)
    chunk_digests: tuple[str, ...] = Field(
        min_length=1,
        max_length=MAX_UPLOAD_CHUNKS,
    )
    media_type: str = Field(default="application/octet-stream", min_length=1, max_length=128)

    @model_validator(mode="after")
    def validate_layout(self) -> ChunkUploadManifest:
        expected_count = (self.total_bytes + self.chunk_size - 1) // self.chunk_size
        if len(self.chunk_digests) != expected_count:
            raise ValueError("chunk digest count differs from declared upload layout")
        if any(_DIGEST.fullmatch(digest) is None for digest in self.chunk_digests):
            raise ValueError("chunk digest is invalid")
        if self.media_type != self.media_type.strip() or any(
            ord(character) < 32 or ord(character) == 127
            for character in self.media_type
        ):
            raise ValueError("upload media type is invalid")
        return self

    @property
    def manifest_digest(self) -> str:
        encoded = json.dumps(
            self.model_dump(mode="json"),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return content_digest(encoded)

    def expected_chunk_bytes(self, index: int) -> int:
        if (
            isinstance(index, bool)
            or not isinstance(index, int)
            or not 0 <= index < len(self.chunk_digests)
        ):
            raise ReleaseUploadError("RELEASE_UPLOAD_CHUNK_INDEX_INVALID")
        if index < len(self.chunk_digests) - 1:
            return self.chunk_size
        return self.total_bytes - self.chunk_size * index

    @classmethod
    def from_payload(
        cls,
        payload: bytes,
        *,
        chunk_size: int = MAX_CHUNK_BYTES,
        media_type: str = "application/octet-stream",
    ) -> ChunkUploadManifest:
        if not isinstance(payload, bytes):
            raise ReleaseUploadError("RELEASE_UPLOAD_PAYLOAD_INVALID")
        if not payload:
            raise ReleaseUploadError("RELEASE_UPLOAD_EMPTY")
        if len(payload) > MAX_UPLOAD_BYTES:
            raise ReleaseUploadError("RELEASE_UPLOAD_TOO_LARGE")
        if (
            isinstance(chunk_size, bool)
            or not isinstance(chunk_size, int)
            or not 1 <= chunk_size <= MAX_CHUNK_BYTES
        ):
            raise ReleaseUploadError("RELEASE_UPLOAD_CHUNK_SIZE_INVALID")
        if (len(payload) + chunk_size - 1) // chunk_size > MAX_UPLOAD_CHUNKS:
            raise ReleaseUploadError("RELEASE_UPLOAD_CHUNK_COUNT_LIMIT")
        chunks = tuple(
            content_digest(payload[offset : offset + chunk_size])
            for offset in range(0, len(payload), chunk_size)
        )
        return cls(
            blob_digest=content_digest(payload),
            total_bytes=len(payload),
            chunk_size=chunk_size,
            chunk_digests=chunks,
            media_type=media_type,
        )


class UploadStatus(StrictModel):
    schema_version: Literal["rolo-release-upload-status/v1"] = (
        "rolo-release-upload-status/v1"
    )
    manifest_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    blob_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    total_bytes: int = Field(strict=True, ge=1, le=MAX_UPLOAD_BYTES)
    received_chunks: tuple[UploadChunkIndex, ...] = Field(
        max_length=MAX_UPLOAD_CHUNKS,
    )
    missing_chunks: tuple[UploadChunkIndex, ...] = Field(
        max_length=MAX_UPLOAD_CHUNKS,
    )
    finalized: bool

    @model_validator(mode="after")
    def validate_partition(self) -> UploadStatus:
        if (
            tuple(sorted(set(self.received_chunks))) != self.received_chunks
            or tuple(sorted(set(self.missing_chunks))) != self.missing_chunks
            or set(self.received_chunks) & set(self.missing_chunks)
            or (self.finalized and self.missing_chunks)
        ):
            raise ValueError("upload status chunk partition is invalid")
        return self


class UploadCommit(StrictModel):
    schema_version: Literal["rolo-release-upload-commit/v1"] = (
        "rolo-release-upload-commit/v1"
    )
    manifest_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    blob_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    total_bytes: int = Field(strict=True, ge=1, le=MAX_UPLOAD_BYTES)
    chunk_count: int = Field(strict=True, ge=1, le=MAX_UPLOAD_CHUNKS)


class ContentAddressedUploadStore:
    """Persist verified chunks and atomically expose only complete blobs."""

    def __init__(self, root: str | Path) -> None:
        self.root = _lexical_absolute(root)
        self._directory_identities: dict[str, tuple[int, int]] = {}
        self.manifests = self.root / "manifests"
        self.chunks = self.root / "chunks"
        self.blobs = self.root / "blobs"
        self.commits = self.root / "commits"
        self.lock_path = self.root / "upload-transaction.locked"
        self._assert_trusted_layout(create_root=False)

    def begin(
        self,
        manifest: ChunkUploadManifest | dict[str, Any],
    ) -> UploadStatus:
        candidate = self._manifest(manifest)
        self._assert_trusted_layout(create_root=True)
        with interprocess_lock(self.lock_path):
            self._assert_trusted_layout(create_root=True)
            path = self._manifest_path(candidate.manifest_digest)
            _require_file_or_absent(path)
            if path.exists():
                existing = self._load_manifest_unlocked(candidate.manifest_digest)
                if existing != candidate:
                    raise ReleaseUploadError("RELEASE_UPLOAD_MANIFEST_CONFLICT")
            else:
                self._write_new_text(
                    path,
                    json.dumps(
                        candidate.model_dump(mode="json"),
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                    + "\n",
                )
                self._assert_trusted_layout(create_root=True)
            return self._status_unlocked(candidate)

    def put_chunk(
        self,
        manifest_digest: str,
        index: int,
        payload: bytes,
    ) -> UploadStatus:
        self._require_digest(manifest_digest, "RELEASE_UPLOAD_MANIFEST_DIGEST_INVALID")
        if not isinstance(payload, bytes):
            raise ReleaseUploadError("RELEASE_UPLOAD_CHUNK_INVALID")
        self._assert_trusted_layout(create_root=True)
        with interprocess_lock(self.lock_path):
            self._assert_trusted_layout(create_root=True)
            manifest = self._load_manifest_unlocked(manifest_digest)
            expected_bytes = manifest.expected_chunk_bytes(index)
            if len(payload) != expected_bytes:
                raise ReleaseUploadError("RELEASE_UPLOAD_CHUNK_SIZE_MISMATCH")
            expected_digest = manifest.chunk_digests[index]
            if content_digest(payload) != expected_digest:
                raise ReleaseUploadError("RELEASE_UPLOAD_CHUNK_DIGEST_MISMATCH")
            path = self._chunk_path(expected_digest)
            _require_file_or_absent(path)
            if path.exists():
                existing = self._read_bounded(path, expected_bytes)
                if existing != payload:
                    raise ReleaseUploadError("RELEASE_UPLOAD_CHUNK_CONFLICT")
            else:
                self._atomic_write_bytes(path, (payload,), require_absent=True)
                self._assert_trusted_layout(create_root=True)
            return self._status_unlocked(manifest)

    def status(self, manifest_digest: str) -> UploadStatus:
        self._require_digest(manifest_digest, "RELEASE_UPLOAD_MANIFEST_DIGEST_INVALID")
        self._assert_trusted_layout(create_root=True)
        with interprocess_lock(self.lock_path):
            self._assert_trusted_layout(create_root=True)
            return self._status_unlocked(
                self._load_manifest_unlocked(manifest_digest)
            )

    def finalize(self, manifest_digest: str) -> UploadCommit:
        self._require_digest(manifest_digest, "RELEASE_UPLOAD_MANIFEST_DIGEST_INVALID")
        self._assert_trusted_layout(create_root=True)
        with interprocess_lock(self.lock_path):
            self._assert_trusted_layout(create_root=True)
            manifest = self._load_manifest_unlocked(manifest_digest)
            status = self._status_unlocked(manifest)
            if status.missing_chunks:
                raise ReleaseUploadError("RELEASE_UPLOAD_INCOMPLETE")
            blob_path = self._blob_path(manifest.blob_digest)
            commit_path = self._commit_path(manifest_digest)
            _require_file_or_absent(blob_path)
            _require_file_or_absent(commit_path)
            if blob_path.exists():
                self._verify_blob(blob_path, manifest)
            else:
                chunk_paths = [self._chunk_path(item) for item in manifest.chunk_digests]
                self._atomic_write_bytes(
                    blob_path,
                    (self._read_bounded(path, manifest.expected_chunk_bytes(index)) for index, path in enumerate(chunk_paths)),
                    expected_digest=manifest.blob_digest,
                    expected_bytes=manifest.total_bytes,
                    require_absent=True,
                )
            commit = UploadCommit(
                manifest_digest=manifest.manifest_digest,
                blob_digest=manifest.blob_digest,
                total_bytes=manifest.total_bytes,
                chunk_count=len(manifest.chunk_digests),
            )
            encoded = json.dumps(
                commit.model_dump(mode="json"),
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ) + "\n"
            if commit_path.exists():
                try:
                    if commit_path.stat().st_size > _MAX_METADATA_BYTES:
                        raise ReleaseUploadError("RELEASE_UPLOAD_COMMIT_TOO_LARGE")
                    existing = UploadCommit.model_validate(
                        loads_unique_json(commit_path.read_text(encoding="utf-8"))
                    )
                except ReleaseUploadError:
                    raise
                except (OSError, TypeError, ValueError) as exc:
                    raise ReleaseUploadError("RELEASE_UPLOAD_COMMIT_INVALID") from exc
                if existing != commit:
                    raise ReleaseUploadError("RELEASE_UPLOAD_COMMIT_CONFLICT")
            else:
                self._write_new_text(
                    commit_path,
                    encoded,
                )
                self._assert_trusted_layout(create_root=True)
            return commit

    def committed_blob_path(self, manifest_digest: str) -> Path:
        """Resolve bytes only after the matching atomic commit marker exists."""

        self._require_digest(manifest_digest, "RELEASE_UPLOAD_MANIFEST_DIGEST_INVALID")
        self._assert_trusted_layout(create_root=True)
        with interprocess_lock(self.lock_path):
            self._assert_trusted_layout(create_root=True)
            manifest = self._load_manifest_unlocked(manifest_digest)
            status = self._status_unlocked(manifest)
            if not status.finalized:
                raise FileNotFoundError(manifest_digest)
            return self._blob_path(manifest.blob_digest)

    def _status_unlocked(self, manifest: ChunkUploadManifest) -> UploadStatus:
        received: list[int] = []
        missing: list[int] = []
        for index, digest in enumerate(manifest.chunk_digests):
            path = self._chunk_path(digest)
            _require_file_or_absent(path)
            if not path.exists():
                missing.append(index)
                continue
            payload = self._read_bounded(path, manifest.expected_chunk_bytes(index))
            if content_digest(payload) != digest:
                raise ReleaseUploadError("RELEASE_UPLOAD_CHUNK_TAMPERED")
            received.append(index)
        commit_path = self._commit_path(manifest.manifest_digest)
        finalized = commit_path.exists()
        if finalized:
            _require_file_or_absent(commit_path)
            try:
                if commit_path.stat().st_size > _MAX_METADATA_BYTES:
                    raise ReleaseUploadError("RELEASE_UPLOAD_COMMIT_TOO_LARGE")
                commit = UploadCommit.model_validate(
                    loads_unique_json(commit_path.read_text(encoding="utf-8"))
                )
            except ReleaseUploadError:
                raise
            except (OSError, TypeError, ValueError) as exc:
                raise ReleaseUploadError("RELEASE_UPLOAD_COMMIT_INVALID") from exc
            expected = UploadCommit(
                manifest_digest=manifest.manifest_digest,
                blob_digest=manifest.blob_digest,
                total_bytes=manifest.total_bytes,
                chunk_count=len(manifest.chunk_digests),
            )
            if commit != expected:
                raise ReleaseUploadError("RELEASE_UPLOAD_COMMIT_CONFLICT")
            self._verify_blob(self._blob_path(manifest.blob_digest), manifest)
        return UploadStatus(
            manifest_digest=manifest.manifest_digest,
            blob_digest=manifest.blob_digest,
            total_bytes=manifest.total_bytes,
            received_chunks=tuple(received),
            missing_chunks=tuple(missing),
            finalized=finalized,
        )

    def _load_manifest_unlocked(self, manifest_digest: str) -> ChunkUploadManifest:
        path = self._manifest_path(manifest_digest)
        _require_file_or_absent(path)
        try:
            if path.stat().st_size > _MAX_METADATA_BYTES:
                raise ReleaseUploadError("RELEASE_UPLOAD_MANIFEST_TOO_LARGE")
            payload = loads_unique_json(path.read_text(encoding="utf-8"))
            manifest = ChunkUploadManifest.model_validate(payload)
        except FileNotFoundError as exc:
            raise ReleaseUploadError("RELEASE_UPLOAD_UNKNOWN") from exc
        except ReleaseUploadError:
            raise
        except (OSError, TypeError, ValueError) as exc:
            raise ReleaseUploadError("RELEASE_UPLOAD_MANIFEST_INVALID") from exc
        if manifest.manifest_digest != manifest_digest:
            raise ReleaseUploadError("RELEASE_UPLOAD_MANIFEST_TAMPERED")
        return manifest

    def _verify_blob(self, path: Path, manifest: ChunkUploadManifest) -> None:
        _require_file_or_absent(path)
        if not path.is_file():
            raise ReleaseUploadError("RELEASE_UPLOAD_BLOB_MISSING")
        payload = self._read_bounded(path, manifest.total_bytes)
        if content_digest(payload) != manifest.blob_digest:
            raise ReleaseUploadError("RELEASE_UPLOAD_BLOB_TAMPERED")

    @staticmethod
    def _manifest(value: ChunkUploadManifest | dict[str, Any]) -> ChunkUploadManifest:
        try:
            return ChunkUploadManifest.model_validate(
                value.model_dump(mode="python")
                if isinstance(value, ChunkUploadManifest)
                else value
            )
        except ValueError as exc:
            raise ReleaseUploadError("RELEASE_UPLOAD_MANIFEST_INVALID") from exc

    @staticmethod
    def _require_digest(value: str, code: str) -> None:
        if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
            raise ReleaseUploadError(code)

    def _manifest_path(self, digest: str) -> Path:
        _require_collection(self.manifests)
        return self.manifests / f"{digest.removeprefix('sha256:')}.json"

    def _chunk_path(self, digest: str) -> Path:
        _require_collection(self.chunks)
        return self.chunks / f"{digest.removeprefix('sha256:')}.chunk"

    def _blob_path(self, digest: str) -> Path:
        _require_collection(self.blobs)
        return self.blobs / f"{digest.removeprefix('sha256:')}.blob"

    def _commit_path(self, manifest_digest: str) -> Path:
        _require_collection(self.commits)
        return self.commits / f"{manifest_digest.removeprefix('sha256:')}.json"

    @staticmethod
    def _read_bounded(path: Path, expected_bytes: int) -> bytes:
        _require_file_or_absent(path)
        try:
            size = path.stat().st_size
            if size != expected_bytes:
                raise ReleaseUploadError("RELEASE_UPLOAD_OBJECT_SIZE_MISMATCH")
            payload = path.read_bytes()
        except OSError as exc:
            raise ReleaseUploadError("RELEASE_UPLOAD_OBJECT_UNREADABLE") from exc
        if len(payload) != expected_bytes:
            raise ReleaseUploadError("RELEASE_UPLOAD_OBJECT_CHANGED")
        return payload

    def _assert_trusted_layout(self, *, create_root: bool) -> None:
        """Pin every ancestor/root/collection and reject link traversal."""

        paths = (self.root, self.manifests, self.chunks, self.blobs, self.commits)
        if create_root:
            self._validate_directory_chain(self.root)
            try:
                self.root.mkdir(parents=True, exist_ok=True)
            except OSError as exc:
                raise ReleaseUploadError("RELEASE_UPLOAD_ROOT_CREATE_FAILED") from exc
        for path in paths:
            self._validate_directory_chain(path)

    def _validate_directory_chain(self, path: Path) -> None:
        for component in [*reversed(path.parents), path]:
            if _is_linklike(component):
                raise ReleaseUploadError("RELEASE_UPLOAD_UNTRUSTED_PATH")
            try:
                metadata = component.stat()
            except FileNotFoundError:
                break
            except OSError as exc:
                raise ReleaseUploadError("RELEASE_UPLOAD_OBJECT_UNREADABLE") from exc
            if not component.is_dir():
                raise ReleaseUploadError("RELEASE_UPLOAD_UNTRUSTED_PATH")
            identity = (metadata.st_dev, metadata.st_ino)
            key = os.path.normcase(os.fspath(component))
            expected = self._directory_identities.setdefault(key, identity)
            if expected != identity:
                raise ReleaseUploadError("RELEASE_UPLOAD_DIRECTORY_REPLACED")

    @staticmethod
    def _publish_no_replace(temporary: Path, path: Path) -> None:
        """Install a fully fsynced inode without ever replacing a peer."""

        try:
            os.link(temporary, path, follow_symlinks=False)
        except FileExistsError as exc:
            raise ReleaseUploadError("RELEASE_UPLOAD_OBJECT_CONFLICT") from exc
        except OSError as exc:
            raise ReleaseUploadError("RELEASE_UPLOAD_OBJECT_PUBLISH_FAILED") from exc
        _fsync_directory(path.parent)

    @classmethod
    def _write_new_text(cls, path: Path, value: str) -> None:
        encoded = value.encode("utf-8")
        if len(encoded) > _MAX_METADATA_BYTES:
            raise ReleaseUploadError("RELEASE_UPLOAD_METADATA_TOO_LARGE")
        path.parent.mkdir(parents=True, exist_ok=True)
        _require_collection(path.parent)
        _require_file_or_absent(path)
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=".upload-meta-",
            dir=path.parent,
        )
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            cls._publish_no_replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)
            _fsync_directory(path.parent)

    @classmethod
    def _atomic_write_bytes(
        cls,
        path: Path,
        chunks: Iterable[bytes],
        *,
        expected_digest: str | None = None,
        expected_bytes: int | None = None,
        require_absent: bool,
    ) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        _require_collection(path.parent)
        _require_file_or_absent(path)
        if require_absent and path.exists():
            raise ReleaseUploadError("RELEASE_UPLOAD_OBJECT_CONFLICT")
        descriptor, temporary_name = tempfile.mkstemp(prefix=".upload-", dir=path.parent)
        digest = hashlib.sha256()
        written = 0
        try:
            with os.fdopen(descriptor, "wb") as stream:
                for chunk in chunks:
                    written += len(chunk)
                    if written > MAX_UPLOAD_BYTES:
                        raise ReleaseUploadError("RELEASE_UPLOAD_TOO_LARGE")
                    digest.update(chunk)
                    stream.write(chunk)
                stream.flush()
                os.fsync(stream.fileno())
            actual_digest = "sha256:" + digest.hexdigest()
            if expected_bytes is not None and written != expected_bytes:
                raise ReleaseUploadError("RELEASE_UPLOAD_OBJECT_SIZE_MISMATCH")
            if expected_digest is not None and actual_digest != expected_digest:
                raise ReleaseUploadError("RELEASE_UPLOAD_BLOB_DIGEST_MISMATCH")
            if require_absent:
                cls._publish_no_replace(Path(temporary_name), path)
            else:
                os.replace(temporary_name, path)
                _fsync_directory(path.parent)
        finally:
            Path(temporary_name).unlink(missing_ok=True)
            _fsync_directory(path.parent)


__all__ = [
    "ChunkUploadManifest",
    "ContentAddressedUploadStore",
    "MAX_CHUNK_BYTES",
    "MAX_UPLOAD_BYTES",
    "MAX_UPLOAD_CHUNKS",
    "ReleaseUploadError",
    "UploadCommit",
    "UploadStatus",
    "content_digest",
]
