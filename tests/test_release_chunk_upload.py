import json
import os
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError

from rolo.releases import (
    ChunkUploadManifest,
    ContentAddressedUploadStore,
    ReleaseUploadError,
    content_digest,
)
from rolo.releases.upload import MAX_UPLOAD_BYTES, MAX_UPLOAD_CHUNKS


def _chunks(payload: bytes, size: int):
    return [payload[offset : offset + size] for offset in range(0, len(payload), size)]


def test_chunk_upload_resumes_by_digest_and_commits_atomically(tmp_path: Path) -> None:
    payload = b"abcdefghij"
    manifest = ChunkUploadManifest.from_payload(payload, chunk_size=4)
    root = tmp_path / "uploads"
    first = ContentAddressedUploadStore(root)
    status = first.begin(manifest)
    assert status.received_chunks == ()
    assert status.missing_chunks == (0, 1, 2)
    with pytest.raises(FileNotFoundError):
        first.committed_blob_path(manifest.manifest_digest)

    status = first.put_chunk(manifest.manifest_digest, 1, b"efgh")
    assert status.received_chunks == (1,)
    with pytest.raises(ReleaseUploadError, match="RELEASE_UPLOAD_INCOMPLETE"):
        first.finalize(manifest.manifest_digest)
    assert not (root / "blobs" / f"{manifest.blob_digest[7:]}.blob").exists()

    resumed = ContentAddressedUploadStore(root)
    assert resumed.begin(manifest).received_chunks == (1,)
    assert resumed.put_chunk(manifest.manifest_digest, 1, b"efgh").received_chunks == (1,)
    chunks = _chunks(payload, manifest.chunk_size)
    resumed.put_chunk(manifest.manifest_digest, 0, chunks[0])
    resumed.put_chunk(manifest.manifest_digest, 2, chunks[2])
    commit = resumed.finalize(manifest.manifest_digest)
    assert commit.blob_digest == content_digest(payload)
    assert resumed.finalize(manifest.manifest_digest) == commit
    assert resumed.status(manifest.manifest_digest).finalized is True
    assert resumed.committed_blob_path(manifest.manifest_digest).read_bytes() == payload


def test_chunk_upload_rejects_conflicts_and_tamper_before_publish(tmp_path: Path) -> None:
    payload = b"abcdefgh"
    manifest = ChunkUploadManifest.from_payload(payload, chunk_size=4)
    store = ContentAddressedUploadStore(tmp_path / "uploads")
    store.begin(manifest)
    with pytest.raises(
        ReleaseUploadError,
        match="RELEASE_UPLOAD_CHUNK_DIGEST_MISMATCH",
    ):
        store.put_chunk(manifest.manifest_digest, 0, b"xxxx")

    store.put_chunk(manifest.manifest_digest, 0, b"abcd")
    chunk_path = store.chunks / f"{manifest.chunk_digests[0][7:]}.chunk"
    chunk_path.write_bytes(b"wxyz")
    with pytest.raises(
        ReleaseUploadError,
        match="RELEASE_UPLOAD_CHUNK_TAMPERED",
    ):
        store.status(manifest.manifest_digest)
    with pytest.raises(
        ReleaseUploadError,
        match="RELEASE_UPLOAD_CHUNK_CONFLICT",
    ):
        store.put_chunk(manifest.manifest_digest, 0, b"abcd")
    assert not store.blobs.exists()
    assert not store.commits.exists()


def test_finalized_blob_tamper_fails_closed(tmp_path: Path) -> None:
    payload = b"complete-content"
    manifest = ChunkUploadManifest.from_payload(payload, chunk_size=5)
    store = ContentAddressedUploadStore(tmp_path / "uploads")
    store.begin(manifest)
    for index, chunk in enumerate(_chunks(payload, manifest.chunk_size)):
        store.put_chunk(manifest.manifest_digest, index, chunk)
    store.finalize(manifest.manifest_digest)
    path = store.committed_blob_path(manifest.manifest_digest)
    path.write_bytes(b"x" * len(payload))

    with pytest.raises(
        ReleaseUploadError,
        match="RELEASE_UPLOAD_BLOB_TAMPERED",
    ):
        store.status(manifest.manifest_digest)
    with pytest.raises(
        ReleaseUploadError,
        match="RELEASE_UPLOAD_BLOB_TAMPERED",
    ):
        store.finalize(manifest.manifest_digest)


def test_upload_manifest_enforces_layout_limits_and_safe_digest_ids(tmp_path: Path) -> None:
    with pytest.raises(ReleaseUploadError, match="RELEASE_UPLOAD_EMPTY"):
        ChunkUploadManifest.from_payload(b"")
    with pytest.raises(ReleaseUploadError, match="RELEASE_UPLOAD_PAYLOAD_INVALID"):
        ChunkUploadManifest.from_payload(bytearray(b"x"))  # type: ignore[arg-type]
    with pytest.raises(
        ReleaseUploadError,
        match="RELEASE_UPLOAD_CHUNK_SIZE_INVALID",
    ):
        ChunkUploadManifest.from_payload(b"x", chunk_size=True)  # type: ignore[arg-type]
    with pytest.raises(ReleaseUploadError, match="RELEASE_UPLOAD_TOO_LARGE"):
        ChunkUploadManifest.from_payload(b"x" * (MAX_UPLOAD_BYTES + 1))
    with pytest.raises(
        ReleaseUploadError,
        match="RELEASE_UPLOAD_CHUNK_COUNT_LIMIT",
    ):
        ChunkUploadManifest.from_payload(b"x" * (MAX_UPLOAD_CHUNKS + 1), chunk_size=1)
    with pytest.raises(ValidationError):
        ChunkUploadManifest(
            blob_digest="sha256:" + "0" * 64,
            total_bytes=8,
            chunk_size=4,
            chunk_digests=("sha256:" + "1" * 64,),
        )

    store = ContentAddressedUploadStore(tmp_path / "uploads")
    manifest = ChunkUploadManifest.from_payload(b"x")
    store.begin(manifest)
    with pytest.raises(
        ReleaseUploadError,
        match="RELEASE_UPLOAD_CHUNK_INDEX_INVALID",
    ):
        store.put_chunk(manifest.manifest_digest, True, b"x")  # type: ignore[arg-type]
    with pytest.raises(
        ReleaseUploadError,
        match="RELEASE_UPLOAD_MANIFEST_DIGEST_INVALID",
    ):
        store.status("../../outside")


def test_upload_no_replace_race_preserves_peer_object(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import rolo.releases.upload as upload_module

    payload = b"immutable"
    manifest = ChunkUploadManifest.from_payload(payload)
    store = ContentAddressedUploadStore(tmp_path / "uploads")
    expected_path = store.manifests / f"{manifest.manifest_digest[7:]}.json"

    def collide(_source, destination, *, follow_symlinks=False):
        del follow_symlinks
        Path(destination).write_bytes(b"peer-owned")
        raise FileExistsError(destination)

    monkeypatch.setattr(upload_module.os, "link", collide)
    with pytest.raises(
        ReleaseUploadError,
        match="RELEASE_UPLOAD_OBJECT_CONFLICT",
    ):
        store.begin(manifest)
    assert expected_path.read_bytes() == b"peer-owned"


def test_upload_detects_root_collection_replacement_and_hardlinks(
    tmp_path: Path,
) -> None:
    payload = b"abcdefgh"
    manifest = ChunkUploadManifest.from_payload(payload, chunk_size=4)
    root = tmp_path / "uploads"
    store = ContentAddressedUploadStore(root)
    store.begin(manifest)
    store.put_chunk(manifest.manifest_digest, 0, b"abcd")

    old_chunks = root / "chunks-old"
    store.chunks.rename(old_chunks)
    store.chunks.mkdir()
    with pytest.raises(
        ReleaseUploadError,
        match="RELEASE_UPLOAD_DIRECTORY_REPLACED",
    ):
        store.status(manifest.manifest_digest)

    store.chunks.rmdir()
    old_chunks.rename(store.chunks)
    fresh = ContentAddressedUploadStore(root)
    chunk_path = fresh.chunks / f"{manifest.chunk_digests[0][7:]}.chunk"
    try:
        os.link(chunk_path, fresh.chunks / "linked-chunk")
    except OSError:
        pytest.skip("filesystem does not support hard links")
    with pytest.raises(
        ReleaseUploadError,
        match="RELEASE_UPLOAD_UNTRUSTED_PATH",
    ):
        fresh.status(manifest.manifest_digest)

    (fresh.chunks / "linked-chunk").unlink()
    moved = tmp_path / "uploads-old"
    root.rename(moved)
    root.mkdir()
    with pytest.raises(
        ReleaseUploadError,
        match="RELEASE_UPLOAD_DIRECTORY_REPLACED",
    ):
        fresh.status(manifest.manifest_digest)


def test_upload_constructor_rejects_symlinked_ancestor(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "linked"
    try:
        link.symlink_to(real, target_is_directory=True)
    except OSError:
        pytest.skip("filesystem does not permit directory symlinks")
    with pytest.raises(
        ReleaseUploadError,
        match="RELEASE_UPLOAD_UNTRUSTED_PATH",
    ):
        ContentAddressedUploadStore(link / "uploads")


def test_release_upload_schemas_are_valid() -> None:
    schema_root = Path(__file__).parents[1] / "schemas"
    for name in (
        "ReleaseChunkUpload.schema.json",
        "ReleaseUploadCommit.schema.json",
        "ReleaseUploadStatus.schema.json",
    ):
        schema = json.loads((schema_root / name).read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
