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
import re
import secrets
import stat
import struct
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from rolo.core.hashing import canonical_json_sha256
from rolo.core.persistence import atomic_write_text, interprocess_lock
from rolo.dsl.admission import MappingAdmissionIdentity
from rolo.dsl.parser import loads_unique_json

from .motion_safety import MotionSafetyAdmissionRequest

_SHA256 = r"^[0-9a-f]{64}$"
_PREFIXED_SHA256 = r"^sha256:[0-9a-f]{64}$"
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
    PREPARE_PHYSICAL_CALL = "PREPARE_PHYSICAL_CALL"
    ACCEPT_DEBUG_ZERO_MOTION = "ACCEPT_DEBUG_ZERO_MOTION"
    START_PREPARED_CALL = "START_PREPARED_CALL"
    EVENT = "EVENT"
    RESULT = "RESULT"
    CANCEL = "CANCEL"
    STOP = "STOP"
    PHASE_CHANGE = "PHASE_CHANGE"
    CLOSE_SESSION = "CLOSE_SESSION"
    RESUME_SESSION = "RESUME_SESSION"
    QUERY_CALL = "QUERY_CALL"
    DSL_REQUEST = "DSL_REQUEST"
    ACTIVATE_AUTHORITY = "ACTIVATE_AUTHORITY"
    CANCEL_MAPPING = "CANCEL_MAPPING"
    PROVISION_VERIFIED_RELEASE = "PROVISION_VERIFIED_RELEASE"


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


class TargetdExecutionAuthority(_StrictModel):
    """Target-owned current Release/Mapping head used to fence one Tool."""

    # Deliberately has no default.  An authority snapshot is a persisted
    # security boundary, not a convenience model that may infer its version.
    schema_version: Literal["rolo-targetd-execution-authority/v1"]
    tool_id: str = Field(pattern=_IDENTIFIER)
    target_id: str = Field(pattern=_IDENTIFIER)
    target_fingerprint: str = Field(min_length=1, max_length=256)
    bundle_digest: str = Field(pattern=_SHA256)
    binding_digest: str = Field(pattern=_SHA256)
    surface_digest: str = Field(pattern=_SHA256)
    release_digest: str = Field(pattern=_PREFIXED_SHA256)
    context_digest: str = Field(pattern=_PREFIXED_SHA256)
    mapping_confirmation_receipt_digest: str = Field(pattern=_PREFIXED_SHA256)
    mapping_admission: MappingAdmissionIdentity
    catalog_head_digest: str = Field(pattern=_PREFIXED_SHA256)
    provider_id: str = Field(pattern=_IDENTIFIER)
    provider_operation: str = Field(pattern=_IDENTIFIER)
    mode: str = Field(min_length=1, max_length=64)
    fence_epoch: int = Field(ge=1)
    authority_head_digest: str = Field(pattern=_SHA256)

    @model_validator(mode="after")
    def validate_identity(self) -> TargetdExecutionAuthority:
        lineage = self.mapping_admission
        if lineage.scope.tool_id != self.tool_id:
            raise ValueError("execution authority tool does not match Mapping scope")
        if lineage.target_id != self.target_id:
            raise ValueError("execution authority target does not match Mapping")
        if lineage.target_fingerprint != self.target_fingerprint:
            raise ValueError("execution authority fingerprint does not match Mapping")
        if lineage.context_digest != self.context_digest:
            raise ValueError("execution authority Context does not match Mapping")
        if self.provider_operation not in lineage.scope.operations:
            raise ValueError("execution authority provider operation is outside Mapping scope")
        expected = canonical_json_sha256(_canonical_payload(self, "authority_head_digest"))
        if self.authority_head_digest != expected:
            raise ValueError("execution authority head digest does not match snapshot")
        return self

    @classmethod
    def build(
        cls,
        *,
        tool_id: str,
        target_id: str,
        target_fingerprint: str,
        bundle_digest: str,
        binding_digest: str,
        surface_digest: str,
        release_digest: str,
        context_digest: str,
        mapping_confirmation_receipt_digest: str,
        mapping_admission: MappingAdmissionIdentity,
        catalog_head_digest: str,
        provider_id: str,
        provider_operation: str,
        mode: str,
        fence_epoch: int,
    ) -> TargetdExecutionAuthority:
        payload: dict[str, Any] = {
            "schema_version": "rolo-targetd-execution-authority/v1",
            "tool_id": tool_id,
            "target_id": target_id,
            "target_fingerprint": target_fingerprint,
            "bundle_digest": bundle_digest,
            "binding_digest": binding_digest,
            "surface_digest": surface_digest,
            "release_digest": release_digest,
            "context_digest": context_digest,
            "mapping_confirmation_receipt_digest": mapping_confirmation_receipt_digest,
            "mapping_admission": mapping_admission,
            "catalog_head_digest": catalog_head_digest,
            "provider_id": provider_id,
            "provider_operation": provider_operation,
            "mode": mode,
            "fence_epoch": fence_epoch,
        }
        canonical = {key: (value.model_dump(mode="json") if isinstance(value, BaseModel) else value) for key, value in payload.items()}
        return cls.model_validate(
            {
                **payload,
                "authority_head_digest": canonical_json_sha256(canonical),
            }
        )


def requires_motion_safety(authority: TargetdExecutionAuthority) -> bool:
    """Only an exact OBSERVE/read/R0 authority bypasses physical admission."""

    scope = authority.mapping_admission.scope
    return not (scope.operation_kind.value == "OBSERVE" and scope.access == "read" and scope.risk == "R0")


class TargetdAuthorityActivationRequest(_StrictModel):
    """Select a target-resident verified Release for execution.

    The request deliberately does not carry Mapping identity, provider, mode,
    fence epoch, Catalog head, or a pre-built authority snapshot.  targetd
    derives those values from its trusted local stores, signed bundle cache,
    configured provider, and already-open journey session.
    """

    schema_version: Literal["rolo-targetd-authority-activation/v1"]
    tool_id: str = Field(pattern=_IDENTIFIER)
    release_digest: str = Field(pattern=_PREFIXED_SHA256)
    bundle_digest: str = Field(pattern=_SHA256)
    expected_current_authority_head_digest: str | None = Field(
        pattern=_SHA256,
    )


class TargetdMappingCancelRequest(_StrictModel):
    """Cancel the Mapping bound to one target-owned current authority."""

    schema_version: Literal["rolo-targetd-mapping-cancel/v1"]
    tool_id: str = Field(pattern=_IDENTIFIER)
    authority_head_digest: str = Field(pattern=_SHA256)
    mapping_confirmation_receipt_digest: str = Field(pattern=_PREFIXED_SHA256)
    idempotency_key: str = Field(pattern=_IDENTIFIER)


class _TargetdVerifiedToolRelease(_StrictModel):
    """Explicit, route-free ToolRelease shape accepted at the wire boundary.

    This mirrors the publisher's manifest without importing the releases
    package (which would introduce a targetd import cycle).  Every field is
    required so wire callers cannot acquire publisher defaults implicitly.
    """

    tool_id: str = Field(pattern=_IDENTIFIER)
    target_id: str = Field(pattern=_IDENTIFIER)
    operation_kind: Literal["OBSERVE", "COMPOSE", "INVOKE", "EXECUTE"]
    dsl_digest: str = Field(pattern=_PREFIXED_SHA256)
    ir_digest: str = Field(pattern=_PREFIXED_SHA256)
    probe_evidence_digest: str = Field(pattern=_PREFIXED_SHA256)
    mhs_manifest_digests: tuple[str, ...] = Field(max_length=0)
    compiler_version: str = Field(min_length=1, max_length=128)
    generated_bundle_digest: str = Field(pattern=_PREFIXED_SHA256)
    conformance_digest: str = Field(pattern=_PREFIXED_SHA256)
    target_fingerprint: str = Field(min_length=1, max_length=256)
    compile_context_digest: str = Field(pattern=_PREFIXED_SHA256)
    route_digest: None
    target_conformance_digest: str = Field(pattern=_PREFIXED_SHA256)
    mapping_confirmation_receipt_digest: str = Field(pattern=_PREFIXED_SHA256)
    mapping_admission: MappingAdmissionIdentity
    status: Literal["PUBLISHED"]
    agent_callable: Literal[True]


class TargetdVerifiedReleaseProvisionRequest(_StrictModel):
    """CAS request for a Release independently verified by targetd cache."""

    schema_version: Literal["rolo-targetd-verified-release-provision/v1"]
    release_digest: str = Field(pattern=_PREFIXED_SHA256)
    candidate_release: _TargetdVerifiedToolRelease
    conformance_cache_key: str = Field(pattern=_SHA256)
    execution_bundle_digest: str = Field(pattern=_SHA256)
    expected_catalog_head_digest: str | None = Field(
        pattern=_PREFIXED_SHA256,
    )

    @model_validator(mode="before")
    @classmethod
    def require_explicit_candidate_fields(cls, value: Any) -> Any:
        if isinstance(value, dict):
            candidate = value.get("candidate_release")
            if isinstance(candidate, BaseModel):
                candidate = candidate.model_dump(mode="python")
                value = {**value, "candidate_release": candidate}
        return value


class _LegacyExecutionRequestV1(_StrictModel):
    """Read-only parser used only by the explicit v1 migration API."""

    schema_version: Literal["rolo-execution-request/v1"]
    run_id: str = Field(pattern=_IDENTIFIER)
    session_id: str = Field(pattern=_IDENTIFIER)
    target_id: str = Field(pattern=_IDENTIFIER)
    idempotency_key: str = Field(pattern=_IDENTIFIER)
    bundle_digest: str = Field(pattern=_SHA256)
    binding_digest: str = Field(pattern=_SHA256)
    surface_digest: str = Field(pattern=_SHA256)
    arguments: dict[str, Any]
    mode: str = Field(min_length=1, max_length=64)
    deadline: datetime


class ExecutionRequest(_StrictModel):
    """One fenced invocation of an immutable Bundle and current Release."""

    # v1 did not carry Mapping/Release/current-head/provider identity.  The
    # daemon rejects it; callers that intentionally migrate must use
    # ``migrate_v1`` with a trusted target authority snapshot.
    schema_version: Literal["rolo-execution-request/v2"]
    run_id: str = Field(pattern=_IDENTIFIER)
    session_id: str = Field(pattern=_IDENTIFIER)
    target_id: str = Field(pattern=_IDENTIFIER)
    idempotency_key: str = Field(pattern=_IDENTIFIER)
    bundle_digest: str = Field(pattern=_SHA256)
    binding_digest: str = Field(pattern=_SHA256)
    surface_digest: str = Field(pattern=_SHA256)
    release_digest: str = Field(pattern=_PREFIXED_SHA256)
    context_digest: str = Field(pattern=_PREFIXED_SHA256)
    mapping_confirmation_receipt_digest: str = Field(pattern=_PREFIXED_SHA256)
    authority_head_digest: str = Field(pattern=_SHA256)
    fence_epoch: int = Field(ge=1)
    provider_id: str = Field(pattern=_IDENTIFIER)
    provider_operation: str = Field(pattern=_IDENTIFIER)
    authority: TargetdExecutionAuthority
    arguments: dict[str, Any]
    mode: str = Field(min_length=1, max_length=64)
    deadline: datetime

    @model_validator(mode="after")
    def validate_deadline(self) -> ExecutionRequest:
        if self.deadline.tzinfo is None:
            raise ValueError("execution request deadline must include timezone")
        if self.session_id != self.authority.mapping_admission.journey_session_id:
            raise ValueError("execution request session does not match Mapping journey")
        if len(json.dumps(self.arguments, ensure_ascii=False, default=str)) > 64_000:
            raise ValueError("execution request arguments exceed 64 KiB")
        exact = {
            "target_id": self.target_id,
            "bundle_digest": self.bundle_digest,
            "binding_digest": self.binding_digest,
            "surface_digest": self.surface_digest,
            "release_digest": self.release_digest,
            "context_digest": self.context_digest,
            "mapping_confirmation_receipt_digest": self.mapping_confirmation_receipt_digest,
            "authority_head_digest": self.authority_head_digest,
            "fence_epoch": self.fence_epoch,
            "provider_id": self.provider_id,
            "provider_operation": self.provider_operation,
            "mode": self.mode,
        }
        for field, actual in exact.items():
            if getattr(self.authority, field) != actual:
                raise ValueError(f"execution request {field} does not match authority")
        return self

    def request_digest(self) -> str:
        """Bind idempotency to the complete canonical request identity."""

        return canonical_json_sha256(_canonical_payload(self))

    @classmethod
    def migrate_v1(
        cls,
        payload: dict[str, Any],
        *,
        authority: TargetdExecutionAuthority,
        provider_id: str,
        provider_operation: str,
    ) -> ExecutionRequest:
        """Explicitly bind a legacy request to a trusted v2 authority.

        This is intentionally not called by ``model_validate`` or the daemon.
        It exists only for controlled migration tooling that can independently
        resolve the current authority.
        """

        legacy = _LegacyExecutionRequestV1.model_validate(payload)
        if requires_motion_safety(authority):
            raise ProtocolError("PHYSICAL_MOTION_EXECUTION_REQUEST_V3_REQUIRED")
        for field in ("target_id", "bundle_digest", "binding_digest", "surface_digest", "mode"):
            if getattr(legacy, field) != getattr(authority, field):
                raise ProtocolError(f"legacy execution request {field} mismatches authority")
        if provider_id != authority.provider_id or provider_operation != authority.provider_operation:
            raise ProtocolError("legacy execution request provider mismatches authority")
        return cls(
            schema_version="rolo-execution-request/v2",
            **legacy.model_dump(mode="python", exclude={"schema_version"}),
            release_digest=authority.release_digest,
            context_digest=authority.context_digest,
            mapping_confirmation_receipt_digest=authority.mapping_confirmation_receipt_digest,
            authority_head_digest=authority.authority_head_digest,
            fence_epoch=authority.fence_epoch,
            provider_id=provider_id,
            provider_operation=provider_operation,
            authority=authority,
        )


class _ExecutionRequestV3Subject(ExecutionRequest):
    """Canonical v3 fields that may be signed before evidence is attached."""

    schema_version: Literal["rolo-execution-request/v3"]


def execution_subject_digest(value: BaseModel | dict[str, Any]) -> str:
    """Digest the complete v3 call and authority, excluding safety evidence."""

    payload = (
        value.model_dump(
            mode="python",
            exclude={"execution_subject_digest", "motion_safety_admission"},
        )
        if isinstance(value, BaseModel)
        else dict(value)
    )
    payload.pop("execution_subject_digest", None)
    payload.pop("motion_safety_admission", None)
    subject = _ExecutionRequestV3Subject.model_validate(payload)
    return "sha256:" + canonical_json_sha256(_canonical_payload(subject))


class ExecutionRequestV3(_ExecutionRequestV3Subject):
    """Physical-motion request carrying independently verifiable evidence."""

    execution_subject_digest: str = Field(pattern=_PREFIXED_SHA256)
    motion_safety_admission: MotionSafetyAdmissionRequest

    @model_validator(mode="after")
    def validate_motion_subject(self) -> ExecutionRequestV3:
        if not requires_motion_safety(self.authority):
            raise ValueError("execution request v3 is reserved for physical motion")
        expected = execution_subject_digest(self)
        intent = self.motion_safety_admission.intent
        if self.execution_subject_digest != expected:
            raise ValueError("execution request motion subject digest mismatch")
        if intent.execution_subject_digest != expected:
            raise ValueError("motion admission does not match execution request")
        if (
            intent.call_id != self.idempotency_key
            or intent.session_id != self.session_id
            or intent.target_id != self.target_id
            or intent.target_identity != self.authority.mapping_admission.target_identity_digest
        ):
            raise ValueError("motion admission call identity mismatch")
        return self


ExecutionRequestLike = ExecutionRequest | ExecutionRequestV3


def validate_execution_request(value: BaseModel | dict[str, Any]) -> ExecutionRequestLike:
    """Parse an explicitly versioned request without upgrading physical v2."""

    payload = value.model_dump(mode="python") if isinstance(value, BaseModel) else value
    if not isinstance(payload, dict):
        raise ValueError("execution request must be an object")
    version = payload.get("schema_version")
    if version == "rolo-execution-request/v2":
        request = ExecutionRequest.model_validate(payload)
        if requires_motion_safety(request.authority):
            raise ProtocolError("PHYSICAL_MOTION_EXECUTION_REQUEST_V3_REQUIRED")
        return request
    if version == "rolo-execution-request/v3":
        return ExecutionRequestV3.model_validate(payload)
    raise ValueError("execution request schema version is unsupported")


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
        return cls.model_validate({**data, "frame_digest": canonical_json_sha256(digest_payload)})


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
        # Pydantic's JSON helper follows the standard last-key-wins behavior;
        # use the repository-wide strict loader so a signed frame cannot have
        # two logical payloads under duplicate member names.
        return ProtocolFrame.model_validate(loads_unique_json(encoded[4:].decode("utf-8")))
    except (UnicodeDecodeError, ValueError, TypeError) as exc:
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
    def create(cls, *, session_id: str, target_id: str, profile_id: str, ttl_s: int = 3600) -> JourneySession:
        now = datetime.now(timezone.utc)
        return cls(
            session_id=session_id,
            target_id=target_id,
            profile_id=profile_id,
            created_at=now,
            expires_at=now + timedelta(seconds=ttl_s),
        )


class TargetdCallReceipt(_StrictModel):
    # v2 requires the full target-owned execution fence identity.  Legacy v1
    # records are detected by the state store and exposed only as UNKNOWN
    # reconciliation placeholders; they can never become executable again.
    schema_version: Literal["rolo-targetd-call-receipt/v2"]
    idempotency_key: str = Field(pattern=_IDENTIFIER)
    session_id: str = Field(pattern=_IDENTIFIER)
    target_id: str = Field(pattern=_IDENTIFIER)
    bundle_digest: str = Field(pattern=_SHA256)
    request_digest: str = Field(pattern=_SHA256)
    release_digest: str = Field(pattern=_PREFIXED_SHA256)
    context_digest: str = Field(pattern=_PREFIXED_SHA256)
    mapping_confirmation_receipt_digest: str = Field(pattern=_PREFIXED_SHA256)
    authority_head_digest: str = Field(pattern=_SHA256)
    fence_epoch: int = Field(ge=1)
    provider_id: str = Field(pattern=_IDENTIFIER)
    provider_operation: str = Field(pattern=_IDENTIFIER)
    provider_fence_digest: str = Field(pattern=_SHA256)
    status: Literal["ACCEPTED", "STARTED", "SUCCEEDED", "FAILED", "STOPPED", "CANCELLED", "UNKNOWN", "NOT_ACCEPTED"]
    result: dict[str, Any] | None = None
    evidence_refs: list[str] = Field(default_factory=list, max_length=64)
    artifact_refs: list[str] = Field(default_factory=list, max_length=64)
    provider_started_at: datetime | None = None
    updated_at: datetime

    @model_validator(mode="after")
    def validate_times(self) -> TargetdCallReceipt:
        if self.updated_at.tzinfo is None:
            raise ValueError("targetd receipt updated_at must include timezone")
        if self.provider_started_at is not None and self.provider_started_at.tzinfo is None:
            raise ValueError("targetd receipt provider_started_at must include timezone")
        return self


def provider_fence_digest(request: ExecutionRequestLike) -> str:
    """Bind the target-owned provider fence to the complete call/current head."""

    return canonical_json_sha256(
        {
            "schema_version": "rolo-targetd-provider-fence/v1",
            "session_id": request.session_id,
            "idempotency_key": request.idempotency_key,
            "request_digest": request.request_digest(),
            "authority_head_digest": request.authority_head_digest,
            "fence_epoch": request.fence_epoch,
            "provider_id": request.provider_id,
            "provider_operation": request.provider_operation,
        }
    )


def process_control_auth_tag(
    session_token: str,
    *,
    kind: Literal["CANCEL", "STOP"],
    session_id: str,
    call_id: str,
    request_digest: str,
    sequence: int,
) -> str:
    """Authenticate one exact process-worker control on its session stream."""

    if (
        re.fullmatch(_TOKEN, session_token) is None
        or kind not in {"CANCEL", "STOP"}
        or re.fullmatch(_IDENTIFIER, session_id) is None
        or re.fullmatch(_IDENTIFIER, call_id) is None
        or re.fullmatch(_SHA256, request_digest) is None
        or isinstance(sequence, bool)
        or not isinstance(sequence, int)
        or sequence < 0
    ):
        raise ProtocolError("TARGETD_PROCESS_CONTROL_IDENTITY_INVALID")
    digest = canonical_json_sha256(
        {
            "schema_version": "rolo-targetd-process-control/v1",
            "kind": kind,
            "session_id": session_id,
            "call_id": call_id,
            "request_digest": request_digest,
            "sequence": sequence,
        }
    )
    return hmac.new(
        session_token.encode("ascii"),
        digest.encode("ascii"),
        hashlib.sha256,
    ).hexdigest()


def physical_gate_query_auth_tag(
    session_token: str,
    *,
    target_id: str,
    session_id: str,
    call_id: str,
    request_digest: str,
    gate_uri: str | None,
    gate_digest_uri: str | None,
    sequence: int,
) -> str:
    """Authenticate one exact physical gate sidecar read-back query."""

    artifact_pattern = re.compile(
        r"^artifact://targetd/(?:physical-provider-gates|debug-physical-acceptances)/[0-9a-f]{64}/[0-9a-f]{64}$"
    )
    digest_pattern = re.compile(r"^digest://sha256/[0-9a-f]{64}$")
    if (
        re.fullmatch(_TOKEN, session_token) is None
        or re.fullmatch(_IDENTIFIER, target_id) is None
        or re.fullmatch(_IDENTIFIER, session_id) is None
        or re.fullmatch(_IDENTIFIER, call_id) is None
        or re.fullmatch(_SHA256, request_digest) is None
        or (gate_uri is not None and artifact_pattern.fullmatch(gate_uri) is None)
        or (gate_digest_uri is not None and digest_pattern.fullmatch(gate_digest_uri) is None)
        or (gate_uri is None) != (gate_digest_uri is None)
        or isinstance(sequence, bool)
        or not isinstance(sequence, int)
        or sequence < 0
    ):
        raise ProtocolError("TARGETD_PHYSICAL_GATE_QUERY_IDENTITY_INVALID")
    digest = canonical_json_sha256(
        {
            "schema_version": "rolo-targetd-physical-gate-query-auth/v1",
            "kind": "QUERY_GATE",
            "target_id": target_id,
            "session_id": session_id,
            "call_id": call_id,
            "request_digest": request_digest,
            "gate_uri": gate_uri,
            "gate_digest_uri": gate_digest_uri,
            "sequence": sequence,
        }
    )
    return hmac.new(
        session_token.encode("ascii"),
        digest.encode("ascii"),
        hashlib.sha256,
    ).hexdigest()


def physical_prepared_start_auth_tag(
    session_token: str,
    *,
    target_id: str,
    session_id: str,
    call_id: str,
    request_digest: str,
    armed_zero_receipt_digest: str,
    provider_gate_payload_digest: str,
    sequence: int,
) -> str:
    """Authenticate the one allowed release of an exact ARMED_ZERO child."""

    if (
        re.fullmatch(_TOKEN, session_token) is None
        or re.fullmatch(_IDENTIFIER, target_id) is None
        or re.fullmatch(_IDENTIFIER, session_id) is None
        or re.fullmatch(_IDENTIFIER, call_id) is None
        or re.fullmatch(_SHA256, request_digest) is None
        or re.fullmatch(_SHA256, armed_zero_receipt_digest) is None
        or re.fullmatch(_SHA256, provider_gate_payload_digest) is None
        or isinstance(sequence, bool)
        or not isinstance(sequence, int)
        or sequence < 0
    ):
        raise ProtocolError("TARGETD_PHYSICAL_PREPARED_START_IDENTITY_INVALID")
    digest = canonical_json_sha256(
        {
            "schema_version": "rolo-targetd-physical-prepared-start-auth/v1",
            "kind": FrameKind.START_PREPARED_CALL.value,
            "target_id": target_id,
            "session_id": session_id,
            "call_id": call_id,
            "request_digest": request_digest,
            "armed_zero_receipt_digest": armed_zero_receipt_digest,
            "provider_gate_payload_digest": provider_gate_payload_digest,
            "sequence": sequence,
        }
    )
    return hmac.new(
        session_token.encode("ascii"),
        digest.encode("ascii"),
        hashlib.sha256,
    ).hexdigest()


def debug_zero_motion_acceptance_auth_tag(
    session_token: str,
    *,
    target_id: str,
    session_id: str,
    call_id: str,
    request_digest: str,
    armed_zero_receipt_digest: str,
    debug_admission_digest: str,
    sequence: int,
) -> str:
    """Authenticate one exact, zero-motion-only debug acceptance run."""

    if (
        re.fullmatch(_TOKEN, session_token) is None
        or re.fullmatch(_IDENTIFIER, target_id) is None
        or re.fullmatch(_IDENTIFIER, session_id) is None
        or re.fullmatch(_IDENTIFIER, call_id) is None
        or re.fullmatch(_SHA256, request_digest) is None
        or re.fullmatch(_SHA256, armed_zero_receipt_digest) is None
        or re.fullmatch(_PREFIXED_SHA256, debug_admission_digest) is None
        or isinstance(sequence, bool)
        or not isinstance(sequence, int)
        or sequence < 0
    ):
        raise ProtocolError("TARGETD_DEBUG_ZERO_MOTION_ACCEPTANCE_IDENTITY_INVALID")
    digest = canonical_json_sha256(
        {
            "schema_version": "rolo-targetd-debug-zero-motion-acceptance-auth/v1",
            "kind": FrameKind.ACCEPT_DEBUG_ZERO_MOTION.value,
            "target_id": target_id,
            "session_id": session_id,
            "call_id": call_id,
            "request_digest": request_digest,
            "armed_zero_receipt_digest": armed_zero_receipt_digest,
            "debug_admission_digest": debug_admission_digest,
            "sequence": sequence,
        }
    )
    return hmac.new(
        session_token.encode("ascii"),
        digest.encode("ascii"),
        hashlib.sha256,
    ).hexdigest()


class TargetdExecutionAuthorityStore:
    """Read-mostly, monotonic current authority heads provisioned on targetd."""

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root).resolve()

    def _path(self, tool_id: str) -> Path:
        if not isinstance(tool_id, str) or re.fullmatch(_IDENTIFIER, tool_id) is None:
            raise ProtocolError("execution authority tool id is invalid")
        segment = hashlib.sha256(tool_id.encode("utf-8")).hexdigest()
        return self.root / "current" / f"{segment}.json"

    def resolve(self, tool_id: str) -> TargetdExecutionAuthority:
        path = self._path(tool_id)
        with interprocess_lock(path):
            return self._read_unlocked(path, tool_id)

    def publish(self, authority: TargetdExecutionAuthority) -> Path:
        """Provision a strictly monotonic target fence/current head."""

        authority = TargetdExecutionAuthority.model_validate(authority.model_dump(mode="python"))
        path = self._path(authority.tool_id)
        with interprocess_lock(path):
            try:
                current = self._read_unlocked(path, authority.tool_id)
            except KeyError:
                current = None
            if current is not None:
                if current == authority:
                    return path
                if authority.fence_epoch <= current.fence_epoch:
                    raise ProtocolError("execution authority fence epoch must increase")
            atomic_write_text(
                path,
                json.dumps(
                    authority.model_dump(mode="json"),
                    ensure_ascii=False,
                    sort_keys=True,
                    indent=2,
                )
                + "\n",
                acquire_lock=False,
            )
        return path

    def activate(
        self,
        tool_id: str,
        *,
        expected_current_head_digest: str | None,
        build: Callable[[int], TargetdExecutionAuthority],
    ) -> TargetdExecutionAuthority:
        """Atomically derive and publish the next target-owned fence.

        ``build`` receives only the epoch chosen under the target store lock.
        A controller may name the current head it observed, but it can neither
        choose the next epoch nor submit an authority snapshot.  Replaying the
        exact activation is idempotent; changing identity from a stale head is
        rejected.
        """

        path = self._path(tool_id)
        with interprocess_lock(path):
            try:
                current = self._read_unlocked(path, tool_id)
            except KeyError:
                current = None

            if current is not None:
                replay = TargetdExecutionAuthority.model_validate(build(current.fence_epoch).model_dump(mode="python"))
                if replay == current:
                    return current
                if expected_current_head_digest is None or expected_current_head_digest != current.authority_head_digest:
                    raise ProtocolError("EXECUTION_AUTHORITY_ACTIVATION_CAS_FAILED")
                next_epoch = current.fence_epoch + 1
            else:
                if expected_current_head_digest is not None:
                    raise ProtocolError("EXECUTION_AUTHORITY_ACTIVATION_CAS_FAILED")
                next_epoch = 1

            authority = TargetdExecutionAuthority.model_validate(build(next_epoch).model_dump(mode="python"))
            if authority.tool_id != tool_id or authority.fence_epoch != next_epoch:
                raise ProtocolError("execution authority activation builder is invalid")
            atomic_write_text(
                path,
                json.dumps(
                    authority.model_dump(mode="json"),
                    ensure_ascii=False,
                    sort_keys=True,
                    indent=2,
                )
                + "\n",
                acquire_lock=False,
            )
            return authority

    def commit_if_current(
        self,
        expected: TargetdExecutionAuthority,
        commit: Callable[[], Any],
    ) -> Any:
        """Linearize the provider boundary against current-head promotion."""

        expected = TargetdExecutionAuthority.model_validate(expected.model_dump(mode="python"))
        path = self._path(expected.tool_id)
        with interprocess_lock(path):
            current = self._read_unlocked(path, expected.tool_id)
            if current != expected:
                raise ProtocolError("EXECUTION_AUTHORITY_HEAD_STALE")
            return commit()

    @staticmethod
    def _read_unlocked(path: Path, tool_id: str) -> TargetdExecutionAuthority:
        try:
            payload = loads_unique_json(path.read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            raise KeyError(tool_id) from exc
        except (OSError, ValueError) as exc:
            raise ProtocolError("execution authority head is unreadable") from exc
        try:
            authority = TargetdExecutionAuthority.model_validate(payload)
        except ValueError as exc:
            raise ProtocolError("execution authority head is invalid") from exc
        if authority.tool_id != tool_id:
            raise ProtocolError("execution authority head belongs to another tool")
        return authority


class BundleCache:
    """Digest-addressed cache isolated from the target business workspace."""

    def __init__(self, root: Path) -> None:
        self.root = root

    @staticmethod
    def _validate_digest(bundle_digest: object) -> str:
        if not isinstance(bundle_digest, str) or re.fullmatch(_SHA256, bundle_digest) is None:
            raise ProtocolError("TARGETD_BUNDLE_DIGEST_INVALID")
        return bundle_digest

    def _entry_paths(self, bundle_digest: object) -> tuple[Path, Path, Path]:
        digest = self._validate_digest(bundle_digest)
        cache_root = self.root.resolve(strict=False)
        bundle_root = self.root / "bundles"
        entry = bundle_root / digest
        manifest_path = entry / "manifest.json"
        source_path = entry / "source.py"
        try:
            for candidate in (bundle_root, entry, manifest_path, source_path):
                candidate.resolve(strict=False).relative_to(cache_root)
        except (OSError, RuntimeError, ValueError) as exc:
            raise ProtocolError("TARGETD_BUNDLE_CACHE_PATH_UNSAFE") from exc
        self._require_no_links(bundle_root, entry, manifest_path, source_path)
        return entry, manifest_path, source_path

    @staticmethod
    def _require_no_links(*paths: Path) -> None:
        reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
        for path in paths:
            try:
                metadata = os.lstat(path)
            except FileNotFoundError:
                continue
            except OSError as exc:
                raise ProtocolError("TARGETD_BUNDLE_CACHE_PATH_UNSAFE") from exc
            file_attributes = getattr(metadata, "st_file_attributes", 0)
            if stat.S_ISLNK(metadata.st_mode) or (reparse_flag and file_attributes & reparse_flag):
                raise ProtocolError("TARGETD_BUNDLE_CACHE_PATH_UNSAFE")

    @staticmethod
    def _is_regular_file(path: Path) -> bool:
        try:
            metadata = os.lstat(path)
        except FileNotFoundError:
            return False
        except OSError as exc:
            raise ProtocolError("TARGETD_BUNDLE_CACHE_PATH_UNSAFE") from exc
        return stat.S_ISREG(metadata.st_mode)

    def put(self, manifest: ExecutionBundleManifest, source: bytes) -> Path:
        if hashlib.sha256(source).hexdigest() != manifest.source_digest:
            raise ProtocolError("bundle source digest mismatch")
        path, manifest_path, source_path = self._entry_paths(manifest.bundle_digest)
        if path.exists():
            existing, existing_source = self.load(manifest.bundle_digest)
            if existing != manifest or existing_source != source:
                raise ProtocolError("bundle digest is immutable and already committed")
            return path
        path.mkdir(parents=True, exist_ok=True)
        self._entry_paths(manifest.bundle_digest)
        atomic_write_text(manifest_path, json.dumps(manifest.model_dump(mode="json"), sort_keys=True, indent=2) + "\n")
        temp = path / "source.tmp"
        temp.write_bytes(source)
        os.replace(temp, source_path)
        self._entry_paths(manifest.bundle_digest)
        return path

    def has(self, bundle_digest: str) -> bool:
        _, manifest_path, source_path = self._entry_paths(bundle_digest)
        present = self._is_regular_file(manifest_path) and self._is_regular_file(source_path)
        self._entry_paths(bundle_digest)
        return present

    def load(self, bundle_digest: str) -> tuple[ExecutionBundleManifest, bytes]:
        _, manifest_path, source_path = self._entry_paths(bundle_digest)
        try:
            if not self._is_regular_file(manifest_path) or not self._is_regular_file(source_path):
                raise OSError("bundle cache entry files are missing")
            manifest = ExecutionBundleManifest.model_validate(loads_unique_json(manifest_path.read_text(encoding="utf-8")))
            source = source_path.read_bytes()
        except ProtocolError:
            raise
        except (OSError, ValueError) as exc:
            raise ProtocolError(f"bundle cache entry is unreadable: {bundle_digest}") from exc
        self._entry_paths(bundle_digest)
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
            value = loads_unique_json(self.path.read_text(encoding="utf-8"))
            if not isinstance(value, dict):
                raise ValueError("targetd state must be an object")
            for collection in ("sessions", "calls"):
                if collection in value and not isinstance(value[collection], dict):
                    raise ValueError(f"targetd state {collection} must be an object")
            return value
        except FileNotFoundError:
            return {"sessions": {}, "calls": {}}
        # ``loads_unique_json`` raises ``ValueError`` for duplicate object
        # keys (``JSONDecodeError`` is only one subclass of it).  Normalize
        # both malformed and duplicate-key state into the protocol-level
        # error instead of leaking an implementation exception to the daemon.
        except (OSError, ValueError) as exc:
            raise ProtocolError("targetd state is unreadable") from exc

    def save_session(self, session: JourneySession) -> None:
        with interprocess_lock(self.path):
            state = self._read()
            state.setdefault("sessions", {})[session.session_id] = session.model_dump(mode="json")
            self._write(state, acquire_lock=False)

    def create_session(self, session: JourneySession) -> JourneySession:
        """Create a session without allowing public API identity overwrite."""

        with interprocess_lock(self.path):
            state = self._read()
            existing = state.setdefault("sessions", {}).get(session.session_id)
            if existing is not None:
                current = JourneySession.model_validate(existing)
                if current != session:
                    raise ProtocolError("journey session already exists; explicit resume is required")
                return current
            state["sessions"][session.session_id] = session.model_dump(mode="json")
            self._write(state, acquire_lock=False)
            return session

    def load_session(self, session_id: str) -> JourneySession:
        payload = self._read().get("sessions", {}).get(session_id)
        if payload is None:
            raise KeyError(session_id)
        return JourneySession.model_validate(payload)

    def save_receipt(self, receipt: TargetdCallReceipt) -> None:
        with interprocess_lock(self.path):
            state = self._read()
            key = self._receipt_key(receipt.session_id, receipt.idempotency_key)
            state.setdefault("calls", {})[key] = receipt.model_dump(mode="json")
            self._write(state, acquire_lock=False)

    def update_receipt(
        self,
        session_id: str,
        idempotency_key: str,
        update: Callable[[TargetdCallReceipt | None], TargetdCallReceipt],
    ) -> TargetdCallReceipt:
        """Atomically read, transition, and persist one call receipt.

        ``update`` may execute the provider.  Holding this lock across that
        callback is intentional: CANCEL either wins before the provider fence
        and prevents invocation, or is linearly ordered after the terminal
        receipt.  Process isolation/interruptible providers remain a later
        lease-worker slice.
        """

        with interprocess_lock(self.path):
            state = self._read()
            calls = state.setdefault("calls", {})
            key = self._receipt_key(session_id, idempotency_key)
            payload = calls.get(key)
            current = TargetdCallReceipt.model_validate(payload) if payload else None
            updated = update(current)
            if updated.session_id != session_id or updated.idempotency_key != idempotency_key:
                raise ProtocolError("receipt transition changed call identity")
            calls[key] = updated.model_dump(mode="json")
            self._write(state, acquire_lock=False)
            return updated

    def load_receipt(self, session_id: str, idempotency_key: str) -> TargetdCallReceipt | None:
        calls = self._read().get("calls", {})
        payload = calls.get(self._receipt_key(session_id, idempotency_key))
        if payload is None:
            # Pre-hardening state keyed receipts globally by idempotency key.
            # It may be read for reconciliation, but TargetdService refuses to
            # replay it because it has no canonical request digest.
            legacy = calls.get(idempotency_key)
            if isinstance(legacy, dict) and legacy.get("session_id") == session_id:
                # v1 lacks Release/Mapping/fence identity.  Never coerce or
                # silently upgrade it into the executable v2 receipt model.
                raise ProtocolError("legacy targetd receipt requires explicit reconciliation")
        if payload is None:
            return None
        try:
            return TargetdCallReceipt.model_validate(payload)
        except ValueError as exc:
            raise ProtocolError("targetd receipt is invalid or unsupported") from exc

    @staticmethod
    def _receipt_key(session_id: str, idempotency_key: str) -> str:
        return canonical_json_sha256({"session_id": session_id, "idempotency_key": idempotency_key})

    def _write(self, state: dict[str, Any], *, acquire_lock: bool = True) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        atomic_write_text(
            self.path,
            json.dumps(state, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
            acquire_lock=acquire_lock,
        )


def _sign_digest(key: bytes, digest: str) -> str:
    if not key:
        raise ValueError("signing key must not be empty")
    return base64.urlsafe_b64encode(hmac.new(key, digest.encode("ascii"), hashlib.sha256).digest()).decode("ascii").rstrip("=")


def _new_token() -> str:
    return base64.urlsafe_b64encode(secrets.token_bytes(16)).decode("ascii").rstrip("=")
