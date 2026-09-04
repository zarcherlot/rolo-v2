"""Signed artifact indexes and atomic rollback pointers for MVP runs."""

from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ArtifactIndex(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = "rolo-mvp-artifact-index/v2"
    run_id: str = Field(min_length=1, max_length=256)
    target_id: str = Field(min_length=1, max_length=128)
    artifacts: list[dict[str, str]] = Field(min_length=1, max_length=128)
    manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    signature_hmac_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    previous_index: str | None = Field(default=None, max_length=512)

    def unsigned_payload(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude={"manifest_sha256", "signature_hmac_sha256"})

    def computed_manifest(self) -> str:
        encoded = json.dumps(self.unsigned_payload(), sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(encoded).hexdigest()

    def sign(self, secret: bytes) -> ArtifactIndex:
        if len(secret) < 16:
            raise ValueError("artifact signing secret must contain at least 16 bytes")
        manifest = self.computed_manifest()
        signature = hmac.new(secret, manifest.encode("ascii"), hashlib.sha256).hexdigest()
        return self.model_copy(update={"manifest_sha256": manifest, "signature_hmac_sha256": signature})

    def verify(self, secret: bytes | None = None) -> None:
        if self.manifest_sha256 != self.computed_manifest():
            raise ValueError("artifact manifest digest mismatch")
        if secret is not None:
            if not self.signature_hmac_sha256:
                raise ValueError("artifact signature is missing")
            expected = hmac.new(secret, self.manifest_sha256.encode("ascii"), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(expected, self.signature_hmac_sha256):
                raise ValueError("artifact signature mismatch")


def build_artifact_index(
    *,
    run_id: str,
    target_id: str,
    files: list[Path],
    root: Path,
    secret: bytes | None = None,
    previous_index: str | None = None,
) -> ArtifactIndex:
    artifacts = [
        {"path": file.resolve().relative_to(root.resolve()).as_posix(), "sha256": hashlib.sha256(file.read_bytes()).hexdigest()}
        for file in files
    ]
    index = ArtifactIndex(
        run_id=run_id,
        target_id=target_id,
        artifacts=artifacts,
        manifest_sha256="0" * 64,
        previous_index=previous_index,
    )
    return index.sign(secret) if secret is not None else index.model_copy(update={"manifest_sha256": index.computed_manifest()})


def write_artifact_index(path: Path, index: ArtifactIndex) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(index.model_dump_json(indent=2) + "\n", encoding="utf-8")
    return path


def rollback_artifact_index(path: Path, previous_index: str) -> Path:
    """Atomically move the active pointer back to a previously verified index."""

    if not previous_index or not Path(previous_index).is_file():
        raise FileNotFoundError(previous_index)
    replacement = path.with_suffix(path.suffix + ".rollback")
    replacement.write_text(json.dumps({"active_index": previous_index}, indent=2) + "\n", encoding="utf-8")
    replacement.replace(path)
    return path


__all__ = ["ArtifactIndex", "build_artifact_index", "rollback_artifact_index", "write_artifact_index"]
