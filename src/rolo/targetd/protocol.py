"""Versioned targetd protocol models and digest-addressed local state.

The wire protocol deliberately carries typed JSON objects.  It never accepts
an arbitrary shell command, and every frame/request/bundle has a deterministic
digest that can be checked independently by the controller and targetd.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import struct
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from rolo.core.hashing import canonical_json_sha256
from rolo.core.persistence import atomic_write_text

_SHA256 = r"^[0-9a-f]{64}$"
_TOKEN = r"^[A-Za-z0-9_-]{22,128}$"
_IDENTIFIER = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"
MAX_FRAME_BYTES = 1_048_576


class ProtocolError(ValueError):
    """Raised when a targetd protocol object is malformed or tampered with."""


class FrameKind(str, Enum):
    OPEN_JOURNEY = "OPEN_JOURNEY"
    BOOTSTRAP = "BOOTSTRAP"
    HANDOFF = "HANDOFF"
    HAS = "HAS"
    PUT = "PUT"
    CALL = "CALL"
    EVENT = "EVENT"
    RESULT = "RESULT"
    CANCEL = "CANCEL"
    PHASE_CHANGE = "PHASE_CHANGE"
    CLOSE_SESSION = "CLOSE_SESSION"
    RESUME_SESSION = "RESUME_SESSION"
    QUERY_CALL = "QUERY_CALL"


class JourneyPhase(str, Enum):
    BOOTSTRAP = "BOOTSTRAP"
    PROBE = "PROBE"
    WAITING_CONFIRMATION = "WAITING_CONFIRMATION"
    TRACE = "TRACE"
    CERTIFY = "CERTIFY"
    COMPLETE = "COMPLETE"


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=False)


def _canonical_payload(model: BaseModel, *excluded: str) -> dict[str, Any]:
    return model.model_dump(mode="json", exclude=set(excluded), exclude_none=True)


class ExecutionBundleManifest(_StrictModel):
    """Signed, immutable description of executable Harness source."""

    schema_version: Literal["rolo-execution-bundle/v1"] = "rolo-execution-bundle/v1"
    bundle_digest: str = Field(pattern=_SHA256)
    signer_key_id: str = Field(pattern=_IDENTIFIER)
    signature: str = Field(min_length=16, max_length=512)
    tool_id: str = Field(pattern=_IDENTIFIER)
    runtime: Literal["python3"] = "python3"
    entrypoint: str = Field(pattern=_IDENTIFIER)
    source_digest: str = Field(pattern=_SHA256)
    binding_digest: str = Field(pattern=_SHA256)
    dependencies: list[str] = Field(default_factory=list, max_length=64)
    observation_contract: dict[str, Any] = Field(default_factory=dict)
    limits: dict[str, int | float] = Field(default_factory=dict)
    release_version: str = Field(min_length=1, max_length=128)

    @model_validator(mode="after")
    def validate_digest(self) -> ExecutionBundleManifest:
        expected = canonical_json_sha256(_canonical_payload(self, "bundle_digest", "signature"))
        if self.bundle_digest != expected:
            raise ValueError("execution bundle digest does not match manifest")
        if any(not item or len(item) > 256 for item in self.dependencies):
            raise ValueError("bundle dependencies must be non-empty and bounded")
        if any(value < 0 for value in self.limits.values()):
            raise ValueError("bundle limits must not be negative")
        return self

    @classmethod
    def build(
        cls,
        *,
        tool_id: str,
        source: bytes,
        binding_digest: str,
        signer_key_id: str,
        signing_key: bytes,
        entrypoint: str = "execute",
        dependencies: list[str] | None = None,
        observation_contract: dict[str, Any] | None = None,
        limits: dict[str, int | float] | None = None,
        release_version: str = "dev",
    ) -> ExecutionBundleManifest:
        source_digest = hashlib.sha256(source).hexdigest()
        unsigned = {
            "schema_version": "rolo-execution-bundle/v1",
            "bundle_digest": "0" * 64,
            "signer_key_id": signer_key_id,
            "signature": "unsigned",
            "tool_id": tool_id,
            "runtime": "python3",
            "entrypoint": entrypoint,
            "source_digest": source_digest,
            "binding_digest": binding_digest,
            "dependencies": dependencies or [],
            "observation_contract": observation_contract or {},
            "limits": limits or {},
            "release_version": release_version,
        }
        digest = canonical_json_sha256({k: v for k, v in unsigned.items() if k not in {"bundle_digest", "signature"}})
        signature = _sign_digest(signing_key, digest)
        return cls.model_validate({**unsigned, "bundle_digest": digest, "signature": signature})

    def verify_signature(self, signing_key: bytes) -> None:
        expected = _sign_digest(signing_key, self.bundle_digest)
        if not hmac.compare_digest(expected, self.signature):
            raise ProtocolError("execution bundle signature mismatch")


class ExecutionRequest(_StrictModel):
    """One idempotent invocation of an immutable Bundle."""

    schema_version: Literal["rolo-execution-request/v1"] = "rolo-execution-request/v1"
    run_id: str = Field(pattern=_IDENTIFIER)
    session_id: str = Field(pattern=_IDENTIFIER)
    target_id: str = Field(pattern=_IDENTIFIER)
    idempotency_key: str = Field(pattern=_IDENTIFIER)
    bundle_digest: str = Field(pattern=_SHA256)
    binding_digest: str = Field(pattern=_SHA256)
    surface_digest: str = Field(pattern=_SHA256)
    arguments: dict[str, Any] = Field(default_factory=dict)
    mode: str = Field(min_length=1, max_length=64)
    deadline: datetime

    @model_validator(mode="after")
    def validate_deadline(self) -> ExecutionRequest:
        if self.deadline.tzinfo is None:
            raise ValueError("execution request deadline must include timezone")
        if len(json.dumps(self.arguments, ensure_ascii=False, default=str)) > 64_000:
            raise ValueError("execution request arguments exceed 64 KiB")
        return self


class ProtocolFrame(_StrictModel):
    """Length-delimited logical frame carried over the SSH stdio channel."""

    schema_version: Literal["rolo-targetd-frame/v1"] = "rolo-targetd-frame/v1"
    kind: FrameKind
    sequence: int = Field(ge=0)
    session_id: str = Field(pattern=_IDENTIFIER)
    run_id: str | None = Field(default=None, pattern=_IDENTIFIER)
    payload: dict[str, Any] = Field(default_factory=dict)
    frame_digest: str = Field(pattern=_SHA256)

    @model_validator(mode="after")
    def validate_frame_digest(self) -> ProtocolFrame:
        expected = canonical_json_sha256(_canonical_payload(self, "frame_digest"))
        if expected != self.frame_digest:
            raise ValueError("protocol frame digest does not match payload")
        return self

    @classmethod
    def create(
        cls,
        *,
        kind: FrameKind,
        sequence: int,
        session_id: str,
        payload: dict[str, Any] | None = None,
        run_id: str | None = None,
    ) -> ProtocolFrame:
        data = {
            "schema_version": "rolo-targetd-frame/v1",
            "kind": kind.value,
            "sequence": sequence,
            "session_id": session_id,
            "run_id": run_id,
            "payload": payload or {},
        }
        digest_payload = {key: value for key, value in data.items() if value is not None}
        return cls.model_validate(
            {**data, "frame_digest": canonical_json_sha256(digest_payload)}
        )


def encode_frame(frame: ProtocolFrame) -> bytes:
    """Encode one frame as a bounded 4-byte big-endian length-prefixed record."""

    payload = json.dumps(
        frame.model_dump(mode="json"),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    if len(payload) > MAX_FRAME_BYTES:
        raise ProtocolError("protocol frame exceeds the maximum size")
    return struct.pack(">I", len(payload)) + payload


def decode_frame(encoded: bytes) -> ProtocolFrame:
    """Decode exactly one length-prefixed frame and reject trailing bytes."""

    if len(encoded) < 4:
        raise ProtocolError("protocol frame is truncated")
    (size,) = struct.unpack(">I", encoded[:4])
    if size > MAX_FRAME_BYTES:
        raise ProtocolError("protocol frame exceeds the maximum size")
    if len(encoded) != size + 4:
        raise ProtocolError("protocol frame length does not match payload")
    try:
        return ProtocolFrame.model_validate_json(encoded[4:].decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise ProtocolError("protocol frame payload is invalid") from exc


class JourneySession(_StrictModel):
    schema_version: Literal["rolo-journey-session/v1"] = "rolo-journey-session/v1"
    session_id: str = Field(pattern=_IDENTIFIER)
    target_id: str = Field(pattern=_IDENTIFIER)
    profile_id: str = Field(pattern=_IDENTIFIER)
    phase: JourneyPhase = JourneyPhase.BOOTSTRAP
    resume_token: str = Field(default_factory=lambda: _new_token(), pattern=_TOKEN)
    surface_digest: str | None = Field(default=None, pattern=_SHA256)
    created_at: datetime
    expires_at: datetime
    closed: bool = False

    @model_validator(mode="after")
    def validate_window(self) -> JourneySession:
        if self.created_at.tzinfo is None or self.expires_at.tzinfo is None:
            raise ValueError("journey session timestamps must include timezone")
        if self.expires_at <= self.created_at:
            raise ValueError("journey session expiry must be after creation")
        if self.expires_at - self.created_at > timedelta(hours=24):
            raise ValueError("journey session TTL exceeds 24 hours")
        return self

    @classmethod
    def create(
        cls, *, session_id: str, target_id: str, profile_id: str, ttl_s: int = 3600
    ) -> JourneySession:
        now = datetime.now(timezone.utc)
        return cls(
            session_id=session_id,
            target_id=target_id,
            profile_id=profile_id,
            created_at=now,
            expires_at=now + timedelta(seconds=ttl_s),
        )


class TargetdCallReceipt(_StrictModel):
    schema_version: Literal["rolo-targetd-call-receipt/v1"] = "rolo-targetd-call-receipt/v1"
    idempotency_key: str = Field(pattern=_IDENTIFIER)
    session_id: str = Field(pattern=_IDENTIFIER)
    bundle_digest: str = Field(pattern=_SHA256)
    status: Literal["ACCEPTED", "STARTED", "SUCCEEDED", "FAILED", "STOPPED", "CANCELLED", "UNKNOWN", "NOT_ACCEPTED"]
    result: dict[str, Any] | None = None
    evidence_refs: list[str] = Field(default_factory=list, max_length=64)
    artifact_refs: list[str] = Field(default_factory=list, max_length=64)
    updated_at: datetime


class BundleCache:
    """Digest-addressed cache isolated from the target business workspace."""

    def __init__(self, root: Path) -> None:
        self.root = root

    def put(self, manifest: ExecutionBundleManifest, source: bytes) -> Path:
        if hashlib.sha256(source).hexdigest() != manifest.source_digest:
            raise ProtocolError("bundle source digest mismatch")
        path = self.root / "bundles" / manifest.bundle_digest
        if path.exists():
            existing, existing_source = self.load(manifest.bundle_digest)
            if existing != manifest or existing_source != source:
                raise ProtocolError("bundle digest is immutable and already committed")
            return path
        path.mkdir(parents=True, exist_ok=True)
        atomic_write_text(path / "manifest.json", json.dumps(manifest.model_dump(mode="json"), sort_keys=True, indent=2) + "\n")
        temp = path / "source.tmp"
        temp.write_bytes(source)
        os.replace(temp, path / "source.py")
        return path

    def has(self, bundle_digest: str) -> bool:
        return (self.root / "bundles" / bundle_digest / "manifest.json").is_file() and (self.root / "bundles" / bundle_digest / "source.py").is_file()

    def load(self, bundle_digest: str) -> tuple[ExecutionBundleManifest, bytes]:
        path = self.root / "bundles" / bundle_digest
        try:
            manifest = ExecutionBundleManifest.model_validate_json((path / "manifest.json").read_text(encoding="utf-8"))
            source = (path / "source.py").read_bytes()
        except (OSError, ValueError) as exc:
            raise ProtocolError(f"bundle cache entry is unreadable: {bundle_digest}") from exc
        if manifest.bundle_digest != bundle_digest or hashlib.sha256(source).hexdigest() != manifest.source_digest:
            raise ProtocolError("bundle cache digest mismatch")
        return manifest, source


class TargetdStateStore:
    """Small JSON state store for session leases and idempotent call receipts."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.path = root / "state.json"

    def _read(self) -> dict[str, Any]:
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {"sessions": {}, "calls": {}}
        except (OSError, json.JSONDecodeError) as exc:
            raise ProtocolError("targetd state is unreadable") from exc

    def save_session(self, session: JourneySession) -> None:
        state = self._read()
        state.setdefault("sessions", {})[session.session_id] = session.model_dump(mode="json")
        self._write(state)

    def load_session(self, session_id: str) -> JourneySession:
        payload = self._read().get("sessions", {}).get(session_id)
        if payload is None:
            raise KeyError(session_id)
        return JourneySession.model_validate(payload)

    def save_receipt(self, receipt: TargetdCallReceipt) -> None:
        state = self._read()
        state.setdefault("calls", {})[receipt.idempotency_key] = receipt.model_dump(mode="json")
        self._write(state)

    def load_receipt(self, idempotency_key: str) -> TargetdCallReceipt | None:
        payload = self._read().get("calls", {}).get(idempotency_key)
        return TargetdCallReceipt.model_validate(payload) if payload else None

    def _write(self, state: dict[str, Any]) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        atomic_write_text(self.path, json.dumps(state, ensure_ascii=False, sort_keys=True, indent=2) + "\n")


def _sign_digest(key: bytes, digest: str) -> str:
    if not key:
        raise ValueError("signing key must not be empty")
    return base64.urlsafe_b64encode(hmac.new(key, digest.encode("ascii"), hashlib.sha256).digest()).decode("ascii").rstrip("=")


def _new_token() -> str:
    return base64.urlsafe_b64encode(secrets.token_bytes(16)).decode("ascii").rstrip("=")
