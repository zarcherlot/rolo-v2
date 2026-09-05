"""Signed artifact envelopes with explicit version activation and rollback."""

from __future__ import annotations

import base64
import hashlib
import hmac
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from .artifacts import ArtifactStore
from .hashing import canonical_json_sha256


class SignedArtifact(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = "rolo-signed-artifact/v1"
    artifact_id: str = Field(min_length=1, max_length=128)
    version: str = Field(min_length=1, max_length=128)
    signer_key_id: str = Field(min_length=1, max_length=128)
    payload_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    signature: str = Field(min_length=16, max_length=512)
    payload: dict[str, Any]

    @classmethod
    def build(cls, *, artifact_id: str, version: str, payload: dict[str, Any], signer_key_id: str, key: bytes) -> SignedArtifact:
        digest = canonical_json_sha256(payload)
        return cls(artifact_id=artifact_id, version=version, signer_key_id=signer_key_id,
                    payload_digest=digest, signature=_sign(key, digest), payload=payload)

    def verify(self, key: bytes) -> None:
        if canonical_json_sha256(self.payload) != self.payload_digest:
            raise ValueError("signed artifact payload digest mismatch")
        if not hmac.compare_digest(self.signature, _sign(key, self.payload_digest)):
            raise ValueError("signed artifact signature mismatch")


class SignedArtifactStore:
    def __init__(self, root: Path, keys: dict[str, bytes]) -> None:
        self.artifacts = ArtifactStore(root)
        self.keys = dict(keys)

    def publish(self, artifact: SignedArtifact) -> str:
        key = self.keys.get(artifact.signer_key_id)
        if key is None:
            raise ValueError(f"unknown artifact signer: {artifact.signer_key_id}")
        artifact.verify(key)
        relative = f"signed/{artifact.artifact_id}/{artifact.version}.json"
        self.artifacts.write_json(relative, artifact.model_dump(mode="json"))
        return f"artifact://{relative}"

    def activate(self, artifact_id: str, version: str) -> str:
        relative = f"signed/{artifact_id}/current.json"
        self.artifacts.write_json(relative, {"artifact_id": artifact_id, "version": version})
        return f"artifact://{relative}"

    def rollback(self, artifact_id: str, version: str) -> str:
        return self.activate(artifact_id, version)


def _sign(key: bytes, digest: str) -> str:
    if not key:
        raise ValueError("artifact signer key must not be empty")
    return base64.urlsafe_b64encode(hmac.new(key, digest.encode("ascii"), hashlib.sha256).digest()).decode("ascii").rstrip("=")
