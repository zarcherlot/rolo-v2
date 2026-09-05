"""Targetd service state machine used by the SSH stdio bridge and tests."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from rolo.core.hashing import canonical_json_sha256

from .protocol import (
    _IDENTIFIER,
    _SHA256,
    BundleCache,
    ExecutionBundleManifest,
    ExecutionRequest,
    FrameKind,
    JourneySession,
    ProtocolError,
    TargetdCallReceipt,
    TargetdStateStore,
)


class TargetdHealth(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["rolo-targetd-health/v1"] = "rolo-targetd-health/v1"
    status: Literal["HEALTHY", "DEGRADED", "UNAVAILABLE"]
    target_id: str = Field(pattern=_IDENTIFIER)
    capability_digest: str = Field(pattern=_SHA256)
    active_sessions: int = Field(ge=0)


class TargetdService:
    """Persisted targetd lifecycle and call receipt authority.

    The service intentionally does not execute source itself.  A worker can
    consume an ``ACCEPTED`` receipt and report a terminal result through
    :meth:`complete_call`; this keeps transport/state semantics reusable for
    Python, ROS, and future providers.
    """

    def __init__(self, *, target_id: str, state_root, bundle_root=None, signing_key: bytes | None = None, verification_keys: dict[str, bytes] | None = None) -> None:
        self.target_id = target_id
        self.state = TargetdStateStore(state_root)
        self.cache = BundleCache(bundle_root or state_root)
        self.signing_key = signing_key
        self.verification_keys = dict(verification_keys or {})

    def health(self) -> TargetdHealth:
        capability_digest = canonical_json_sha256(
            {"protocol": "rolo-targetd/v1", "frames": sorted(item.value for item in FrameKind)}
        )
        active = 0
        for session_id in self._session_ids():
            try:
                session = self.state.load_session(session_id)
            except (KeyError, ProtocolError):
                continue
            if not session.closed and session.expires_at > datetime.now(timezone.utc):
                active += 1
        return TargetdHealth(
            status="HEALTHY",
            target_id=self.target_id,
            capability_digest=capability_digest,
            active_sessions=active,
        )

    def open_session(self, session: JourneySession) -> JourneySession:
        if session.target_id != self.target_id:
            raise ProtocolError("journey session target does not match targetd")
        self.state.save_session(session)
        return session

    def resume_session(self, session_id: str, resume_token: str) -> JourneySession:
        session = self.state.load_session(session_id)
        now = datetime.now(timezone.utc)
        if session.closed or session.expires_at <= now:
            raise ProtocolError("journey session is closed or expired")
        if not self._constant_time_equal(session.resume_token, resume_token):
            raise ProtocolError("journey session resume token mismatch")
        return session

    def has_bundle(self, bundle_digest: str) -> bool:
        return self.cache.has(bundle_digest)

    def put_bundle(self, manifest: ExecutionBundleManifest, source: bytes) -> None:
        verification_key = self.verification_keys.get(manifest.signer_key_id, self.signing_key)
        if verification_key is not None:
            manifest.verify_signature(verification_key)
        elif self.verification_keys:
            raise ProtocolError(f"bundle signer is not trusted: {manifest.signer_key_id}")
        self.cache.put(manifest, source)

    def accept_call(
        self, request: ExecutionRequest, manifest: ExecutionBundleManifest
    ) -> TargetdCallReceipt:
        session = self.resume_session(request.session_id, self.state.load_session(request.session_id).resume_token)
        if request.deadline <= datetime.now(timezone.utc):
            raise ProtocolError("execution request deadline has expired")
        if request.target_id != self.target_id or session.target_id != request.target_id:
            raise ProtocolError("execution request target does not match targetd")
        if request.bundle_digest != manifest.bundle_digest:
            raise ProtocolError("execution request bundle does not match manifest")
        if not self.cache.has(request.bundle_digest):
            raise ProtocolError("execution bundle is not present in targetd cache")
        existing = self.state.load_receipt(request.idempotency_key)
        if existing is not None:
            if existing.session_id != request.session_id or existing.bundle_digest != request.bundle_digest:
                raise ProtocolError("idempotency key was reused with different call identity")
            return existing
        receipt = TargetdCallReceipt(
            idempotency_key=request.idempotency_key,
            session_id=request.session_id,
            bundle_digest=request.bundle_digest,
            status="ACCEPTED",
            updated_at=datetime.now(timezone.utc),
        )
        self.state.save_receipt(receipt)
        return receipt

    def complete_call(
        self,
        idempotency_key: str,
        *,
        status: Literal["SUCCEEDED", "FAILED", "STOPPED", "CANCELLED", "UNKNOWN"],
        result: dict | None = None,
        evidence_refs: list[str] | None = None,
        artifact_refs: list[str] | None = None,
    ) -> TargetdCallReceipt:
        receipt = self.state.load_receipt(idempotency_key)
        if receipt is None:
            raise ProtocolError("cannot complete an unknown call")
        if receipt.status in {"SUCCEEDED", "FAILED", "STOPPED", "CANCELLED", "UNKNOWN"}:
            return receipt
        updated = receipt.model_copy(
            update={
                "status": status,
                "result": result,
                "evidence_refs": evidence_refs or [],
                "artifact_refs": artifact_refs or [],
                "updated_at": datetime.now(timezone.utc),
            }
        )
        self.state.save_receipt(updated)
        return updated

    def cancel_call(self, idempotency_key: str) -> TargetdCallReceipt:
        return self.complete_call(idempotency_key, status="CANCELLED")

    def query_call(self, idempotency_key: str) -> TargetdCallReceipt | None:
        return self.state.load_receipt(idempotency_key)

    def _session_ids(self) -> list[str]:
        try:
            payload = self.state._read()
        except ProtocolError:
            return []
        return list(payload.get("sessions", {}))

    @staticmethod
    def _constant_time_equal(left: str, right: str) -> bool:
        import hmac

        return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))
