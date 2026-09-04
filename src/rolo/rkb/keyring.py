"""Minimal controlled HMAC key lifecycle for read-only evidence verification."""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from .validation import EvidenceValidationError


@dataclass(frozen=True)
class HMACKey:
    key_id: str
    secret: bytes
    activated_at: datetime
    revoked_at: datetime | None = None


class HMACKeyring:
    """In-memory policy object; callers persist only key metadata in a vault."""

    def __init__(self, keys: Mapping[str, HMACKey] | None = None) -> None:
        self._keys = dict(keys or {})
        self._seen_nonces: set[tuple[str, str]] = set()

    def rotate(
        self, key_id: str, secret: bytes, *, activated_at: datetime | None = None
    ) -> HMACKey:
        if not key_id or len(secret) != 32:
            raise ValueError("key_id and exactly 32-byte secret are required")
        key = HMACKey(key_id, bytes(secret), activated_at or datetime.now(timezone.utc))
        self._keys[key_id] = key
        return key

    def revoke(self, key_id: str, *, revoked_at: datetime | None = None) -> None:
        key = self._keys.get(key_id)
        if key is None:
            raise KeyError(key_id)
        self._keys[key_id] = HMACKey(
            key.key_id, key.secret, key.activated_at,
            revoked_at or datetime.now(timezone.utc)
        )

    def sign(self, key_id: str, digest: str, *, now: datetime | None = None) -> str:
        key = self._active(key_id, now=now)
        return hmac.new(key.secret, digest.encode("ascii"), hashlib.sha256).hexdigest()

    def verify(
        self, key_id: str, digest: str, signature: str, *,
        now: datetime | None = None, max_age: timedelta | None = None
    ) -> None:
        point = now or datetime.now(timezone.utc)
        key = self._active(key_id, now=point)
        if max_age is not None and point - key.activated_at > max_age:
            raise EvidenceValidationError("HMAC key is outside the accepted replay window")
        expected = self.sign(key_id, digest, now=point)
        if not hmac.compare_digest(expected, signature):
            raise EvidenceValidationError("evidence HMAC mismatch")

    def verify_once(
        self, key_id: str, digest: str, signature: str, nonce: str, *,
        now: datetime | None = None
    ) -> None:
        """Verify a signed digest and reject reuse of the same request nonce."""

        if not nonce:
            raise EvidenceValidationError("request nonce is required for replay protection")
        marker = (key_id, nonce)
        if marker in self._seen_nonces:
            raise EvidenceValidationError("evidence request nonce was replayed")
        self.verify(key_id, digest, signature, now=now)
        self._seen_nonces.add(marker)

    def _active(self, key_id: str, *, now: datetime | None = None) -> HMACKey:
        key = self._keys.get(key_id)
        point = now or datetime.now(timezone.utc)
        if (
            key is None or point < key.activated_at
            or (key.revoked_at is not None and point >= key.revoked_at)
        ):
            raise EvidenceValidationError("HMAC key is not active")
        return key
