"""Pure, fail-closed admission checks for a future physical-motion call.

This module only evaluates signed evidence already supplied by a caller.  It
does not connect to a target, inspect ROS, publish a command, or acknowledge a
stop on a target's behalf.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
from collections.abc import Mapping
from datetime import datetime, timezone
from types import MappingProxyType
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

_IDENTIFIER = r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$"
_IDENTITY = r"^/?[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,254}$"
_ROUTE = r"^/[A-Za-z0-9_./-]{1,126}$"
_INTERFACE = r"^[A-Za-z][A-Za-z0-9_]*/[A-Za-z][A-Za-z0-9_]*/[A-Za-z][A-Za-z0-9_]*$"
_SHA256 = r"^sha256:[0-9a-f]{64}$"
_HMAC_SHA256 = r"^hmac-sha256:[0-9a-f]{64}$"
_MAX_CANONICAL_BYTES = 32 * 1024
_MAX_CANONICAL_DEPTH = 8
_MAX_CANONICAL_ENTRIES = 256
_MAX_CONTAINER_ENTRIES = 64
_MAX_STRING_BYTES = 4096
_MAX_INTEGER_ABS = (1 << 63) - 1

EvidenceKind = Literal[
    "OPERATOR_AUTHORIZATION",
    "ONSITE_PRESENCE",
    "SAFE_ZONE_CONFIRMATION",
    "ESTOP_VERIFICATION",
    "ROS_GRAPH_SNAPSHOT",
    "DIRECT_MOTOR_FENCE",
    "TARGET_STOP_ACKNOWLEDGEMENT",
]
DecisionStatus = Literal["ADMITTED", "BLOCKED"]


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


def _require_aware(value: datetime, field: str) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field} must include timezone")


def _json_default(value: object) -> str:
    if isinstance(value, datetime):
        _require_aware(value, "canonical datetime")
        return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    raise TypeError(f"unsupported canonical value: {type(value).__name__}")


def _validate_bounded_json(value: object) -> None:
    entries = 0

    def visit(item: object, depth: int) -> None:
        nonlocal entries
        if depth > _MAX_CANONICAL_DEPTH:
            raise ValueError("canonical payload exceeds maximum depth")
        if item is None or isinstance(item, bool):
            return
        if isinstance(item, str):
            if len(item.encode("utf-8")) > _MAX_STRING_BYTES:
                raise ValueError("canonical string exceeds maximum bytes")
            return
        if isinstance(item, int):
            if abs(item) > _MAX_INTEGER_ABS:
                raise ValueError("canonical integer exceeds maximum magnitude")
            return
        if isinstance(item, float):
            if not math.isfinite(item):
                raise ValueError("canonical number must be finite")
            return
        if isinstance(item, datetime):
            _require_aware(item, "canonical datetime")
            return
        if isinstance(item, Mapping):
            if len(item) > _MAX_CONTAINER_ENTRIES:
                raise ValueError("canonical object exceeds maximum entries")
            entries += len(item)
            if entries > _MAX_CANONICAL_ENTRIES:
                raise ValueError("canonical payload exceeds maximum entries")
            for key, nested in item.items():
                if not isinstance(key, str):
                    raise ValueError("canonical object keys must be strings")
                visit(key, depth + 1)
                visit(nested, depth + 1)
            return
        if isinstance(item, (list, tuple)):
            if len(item) > _MAX_CONTAINER_ENTRIES:
                raise ValueError("canonical array exceeds maximum entries")
            entries += len(item)
            if entries > _MAX_CANONICAL_ENTRIES:
                raise ValueError("canonical payload exceeds maximum entries")
            for nested in item:
                visit(nested, depth + 1)
            return
        raise ValueError("canonical payload contains an unsupported value")

    visit(value, 0)


def _sha256_payload(payload: Mapping[str, Any]) -> str:
    _validate_bounded_json(payload)
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
        default=_json_default,
    ).encode("utf-8")
    if len(encoded) > _MAX_CANONICAL_BYTES:
        raise ValueError("canonical payload exceeds maximum bytes")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def compute_motion_payload_digest(payload: Mapping[str, Any]) -> str:
    """Digest a bounded canonical payload used by motion-safety extensions."""

    return _sha256_payload(payload)


def _is_sha256(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(_SHA256, value) is not None


def compute_ros_graph_digest(
    *,
    target_id: str,
    target_identity: str,
    observed_at: datetime,
    command_route: str,
    command_interface: str,
    publisher_identities: list[str] | tuple[str, ...],
    direct_motor_route: str,
    direct_motor_interface: str,
    direct_motor_publisher_identities: list[str] | tuple[str, ...],
) -> str:
    """Digest the exact command and direct-motor route view used by the gate."""

    _validate_bounded_json(publisher_identities)
    _validate_bounded_json(direct_motor_publisher_identities)
    return _sha256_payload(
        {
            "schema_version": "rolo-motion-ros-graph/v1",
            "target_id": target_id,
            "target_identity": target_identity,
            "observed_at": observed_at,
            "command_route": command_route,
            "command_interface": command_interface,
            "publisher_identities": sorted(publisher_identities),
            "direct_motor_route": direct_motor_route,
            "direct_motor_interface": direct_motor_interface,
            "direct_motor_publisher_identities": sorted(direct_motor_publisher_identities),
        }
    )


def compute_direct_motor_fence_digest(
    *,
    execution_subject_digest: str,
    call_id: str,
    session_id: str,
    target_id: str,
    target_identity: str,
    ros_graph_digest: str,
    command_route: str,
    publisher_identity: str,
    direct_motor_route: str,
    direct_motor_interface: str,
    direct_motor_publisher_identity: str,
    fence_epoch: int,
) -> str:
    """Digest a target-owned fence for one exact call and graph."""

    return _sha256_payload(
        {
            "schema_version": "rolo-direct-motor-fence/v1",
            "execution_subject_digest": execution_subject_digest,
            "call_id": call_id,
            "session_id": session_id,
            "target_id": target_id,
            "target_identity": target_identity,
            "ros_graph_digest": ros_graph_digest,
            "command_route": command_route,
            "publisher_identity": publisher_identity,
            "direct_motor_route": direct_motor_route,
            "direct_motor_interface": direct_motor_interface,
            "direct_motor_publisher_identity": direct_motor_publisher_identity,
            "fence_epoch": fence_epoch,
        }
    )


def compute_stop_action_digest(
    *,
    execution_subject_digest: str,
    call_id: str,
    session_id: str,
    target_id: str,
    target_identity: str,
    ros_graph_digest: str,
    command_route: str,
    publisher_identity: str,
    direct_motor_route: str,
    direct_motor_interface: str,
    direct_motor_publisher_identity: str,
    direct_motor_fence_digest: str,
) -> str:
    """Digest the stop action a target must acknowledge before admission."""

    return _sha256_payload(
        {
            "schema_version": "rolo-target-stop-action/v1",
            "execution_subject_digest": execution_subject_digest,
            "call_id": call_id,
            "session_id": session_id,
            "target_id": target_id,
            "target_identity": target_identity,
            "ros_graph_digest": ros_graph_digest,
            "command_route": command_route,
            "publisher_identity": publisher_identity,
            "direct_motor_route": direct_motor_route,
            "direct_motor_interface": direct_motor_interface,
            "direct_motor_publisher_identity": direct_motor_publisher_identity,
            "direct_motor_fence_digest": direct_motor_fence_digest,
        }
    )


def compute_estop_response_digest(
    *,
    execution_subject_digest: str,
    challenge_digest: str,
    call_id: str,
    session_id: str,
    target_id: str,
    target_identity: str,
    ros_graph_digest: str,
) -> str:
    """Compute the response expected from a signed E-stop verification."""

    return _sha256_payload(
        {
            "schema_version": "rolo-estop-verification-response/v1",
            "execution_subject_digest": execution_subject_digest,
            "challenge_digest": challenge_digest,
            "call_id": call_id,
            "session_id": session_id,
            "target_id": target_id,
            "target_identity": target_identity,
            "ros_graph_digest": ros_graph_digest,
            "engage_verified": True,
            "release_verified": True,
        }
    )


class MotionSafetyIntent(_StrictModel):
    schema_version: Literal["rolo-targetd-motion-intent/v1"] = "rolo-targetd-motion-intent/v1"
    call_id: str = Field(pattern=_IDENTIFIER)
    session_id: str = Field(pattern=_IDENTIFIER)
    target_id: str = Field(pattern=_IDENTIFIER)
    target_identity: str = Field(pattern=_IDENTITY)
    operator_id: str = Field(pattern=_IDENTITY)
    execution_subject_digest: str = Field(pattern=_SHA256)
    requested_at: datetime
    ros_graph_digest: str = Field(pattern=_SHA256)
    command_route: str = Field(pattern=_ROUTE)
    command_interface: str = Field(pattern=_INTERFACE)
    publisher_identity: str = Field(pattern=_IDENTITY)
    direct_motor_route: str = Field(pattern=_ROUTE)
    direct_motor_interface: str = Field(pattern=_INTERFACE)
    direct_motor_publisher_identity: str = Field(pattern=_IDENTITY)
    direct_motor_fence_digest: str = Field(pattern=_SHA256)
    stop_action_digest: str = Field(pattern=_SHA256)

    @model_validator(mode="after")
    def validate_requested_at(self) -> MotionSafetyIntent:
        _require_aware(self.requested_at, "requested_at")
        return self


class MotionSafetyPolicy(_StrictModel):
    """Trusted local policy; it is deliberately separate from call evidence."""

    schema_version: Literal["rolo-targetd-motion-safety-policy/v1"] = "rolo-targetd-motion-safety-policy/v1"
    target_id: str = Field(pattern=_IDENTIFIER)
    target_identity: str = Field(pattern=_IDENTITY)
    site_id: str = Field(pattern=_IDENTITY)
    safe_zone_id: str = Field(pattern=_IDENTITY)
    command_route: str = Field(pattern=_ROUTE)
    command_interface: str = Field(pattern=_INTERFACE)
    allowed_publisher_identity: str = Field(pattern=_IDENTITY)
    direct_motor_route: str = Field(pattern=_ROUTE)
    direct_motor_interface: str = Field(pattern=_INTERFACE)
    allowed_direct_motor_publisher_identity: str = Field(pattern=_IDENTITY)
    operator_authority_id: str = Field(pattern=_IDENTITY)
    presence_authority_id: str = Field(pattern=_IDENTITY)
    safety_authority_id: str = Field(pattern=_IDENTITY)
    graph_authority_id: str = Field(pattern=_IDENTITY)
    target_authority_id: str = Field(pattern=_IDENTITY)
    max_graph_age_s: int = Field(default=5, ge=1, le=60)
    max_attestation_age_s: int = Field(default=30, ge=1, le=300)

    @model_validator(mode="after")
    def validate_independent_authorities(self) -> MotionSafetyPolicy:
        independent_roles = {
            self.operator_authority_id,
            self.presence_authority_id,
            self.safety_authority_id,
            self.target_authority_id,
        }
        if len(independent_roles) != 4:
            raise ValueError("operator, presence, safety, and target authorities must be independent")
        if self.graph_authority_id in {
            self.operator_authority_id,
            self.presence_authority_id,
            self.safety_authority_id,
        }:
            raise ValueError("graph authority may share only the target authority role")
        return self


class SignedMotionEvidence(_StrictModel):
    schema_version: Literal["rolo-targetd-motion-evidence/v1"] = "rolo-targetd-motion-evidence/v1"
    evidence_id: str = Field(pattern=_IDENTIFIER)
    kind: EvidenceKind
    issuer_id: str = Field(pattern=_IDENTITY)
    call_id: str = Field(pattern=_IDENTIFIER)
    session_id: str = Field(pattern=_IDENTIFIER)
    target_id: str = Field(pattern=_IDENTIFIER)
    target_identity: str = Field(pattern=_IDENTITY)
    operator_id: str = Field(pattern=_IDENTITY)
    execution_subject_digest: str = Field(pattern=_SHA256)
    ros_graph_digest: str = Field(pattern=_SHA256)
    issued_at: datetime
    expires_at: datetime
    claims: dict[str, Any] = Field(max_length=16)
    payload_sha256: str = Field(pattern=_SHA256)
    signature_hmac_sha256: str = Field(pattern=_HMAC_SHA256)

    def unsigned_payload(self) -> dict[str, Any]:
        return self.model_dump(
            mode="python",
            exclude={"payload_sha256", "signature_hmac_sha256"},
        )

    @model_validator(mode="after")
    def validate_integrity(self) -> SignedMotionEvidence:
        _require_aware(self.issued_at, "issued_at")
        _require_aware(self.expires_at, "expires_at")
        if self.expires_at <= self.issued_at:
            raise ValueError("evidence expiry must be after issue time")
        try:
            expected = _sha256_payload(self.unsigned_payload())
        except (TypeError, ValueError) as exc:
            raise ValueError("motion evidence payload is not canonical JSON") from exc
        if not hmac.compare_digest(expected, self.payload_sha256):
            raise ValueError("motion evidence payload digest mismatch")
        return self

    @classmethod
    def build(
        cls,
        *,
        evidence_id: str,
        kind: EvidenceKind,
        issuer_id: str,
        call_id: str,
        session_id: str,
        target_id: str,
        target_identity: str,
        operator_id: str,
        execution_subject_digest: str,
        ros_graph_digest: str,
        issued_at: datetime,
        expires_at: datetime,
        claims: dict[str, Any],
        signing_key: bytes,
    ) -> SignedMotionEvidence:
        if not isinstance(signing_key, bytes) or not 32 <= len(signing_key) <= 4096:
            raise ValueError("motion evidence signing key size is outside safe bounds")
        unsigned: dict[str, Any] = {
            "schema_version": "rolo-targetd-motion-evidence/v1",
            "evidence_id": evidence_id,
            "kind": kind,
            "issuer_id": issuer_id,
            "call_id": call_id,
            "session_id": session_id,
            "target_id": target_id,
            "target_identity": target_identity,
            "operator_id": operator_id,
            "execution_subject_digest": execution_subject_digest,
            "ros_graph_digest": ros_graph_digest,
            "issued_at": issued_at,
            "expires_at": expires_at,
            "claims": claims,
        }
        payload_sha256 = _sha256_payload(unsigned)
        signature = hmac.new(
            signing_key,
            payload_sha256.encode("ascii"),
            hashlib.sha256,
        ).hexdigest()
        return cls.model_validate(
            {
                **unsigned,
                "payload_sha256": payload_sha256,
                "signature_hmac_sha256": f"hmac-sha256:{signature}",
            }
        )


_EVIDENCE_FIELDS: tuple[tuple[str, EvidenceKind], ...] = (
    ("operator_authorization", "OPERATOR_AUTHORIZATION"),
    ("onsite_presence", "ONSITE_PRESENCE"),
    ("safe_zone_confirmation", "SAFE_ZONE_CONFIRMATION"),
    ("estop_verification", "ESTOP_VERIFICATION"),
    ("ros_graph_snapshot", "ROS_GRAPH_SNAPSHOT"),
    ("direct_motor_fence", "DIRECT_MOTOR_FENCE"),
    ("target_stop_acknowledgement", "TARGET_STOP_ACKNOWLEDGEMENT"),
)


class MotionSafetyEvidenceBundle(_StrictModel):
    schema_version: Literal["rolo-targetd-motion-evidence-bundle/v1"] = "rolo-targetd-motion-evidence-bundle/v1"
    operator_authorization: SignedMotionEvidence | None = None
    onsite_presence: SignedMotionEvidence | None = None
    safe_zone_confirmation: SignedMotionEvidence | None = None
    estop_verification: SignedMotionEvidence | None = None
    ros_graph_snapshot: SignedMotionEvidence | None = None
    direct_motor_fence: SignedMotionEvidence | None = None
    target_stop_acknowledgement: SignedMotionEvidence | None = None

    @model_validator(mode="after")
    def validate_evidence_kinds(self) -> MotionSafetyEvidenceBundle:
        for field, expected_kind in _EVIDENCE_FIELDS:
            evidence = getattr(self, field)
            if evidence is not None and evidence.kind != expected_kind:
                raise ValueError(f"{field} has the wrong evidence kind")
        return self


class MotionSafetyAdmissionRequest(_StrictModel):
    schema_version: Literal["rolo-targetd-motion-safety-admission/v1"] = "rolo-targetd-motion-safety-admission/v1"
    intent: MotionSafetyIntent
    evidence: MotionSafetyEvidenceBundle = Field(default_factory=MotionSafetyEvidenceBundle)

    @model_validator(mode="after")
    def validate_canonical_bounds(self) -> MotionSafetyAdmissionRequest:
        try:
            _sha256_payload(self.model_dump(mode="python"))
        except (TypeError, ValueError) as exc:
            raise ValueError("motion safety request exceeds canonical limits") from exc
        return self


class MotionSafetyDecision(_StrictModel):
    schema_version: Literal["rolo-targetd-motion-safety-decision/v1"] = "rolo-targetd-motion-safety-decision/v1"
    status: DecisionStatus = "BLOCKED"
    reasons: tuple[str, ...] = ("MOTION_SAFETY_EVIDENCE_REQUIRED",)
    evaluated_at: datetime
    call_id: str | None = Field(default=None, pattern=_IDENTIFIER)
    session_id: str | None = Field(default=None, pattern=_IDENTIFIER)
    target_id: str | None = Field(default=None, pattern=_IDENTIFIER)
    execution_subject_digest: str | None = Field(default=None, pattern=_SHA256)
    ros_graph_digest: str | None = Field(default=None, pattern=_SHA256)
    evidence_digests: tuple[str, ...] = ()

    @model_validator(mode="after")
    def validate_decision(self) -> MotionSafetyDecision:
        _require_aware(self.evaluated_at, "evaluated_at")
        if self.status == "ADMITTED":
            if self.reasons:
                raise ValueError("admitted motion decision cannot contain blockers")
            if None in (
                self.call_id,
                self.session_id,
                self.target_id,
                self.execution_subject_digest,
                self.ros_graph_digest,
            ):
                raise ValueError("admitted motion decision must retain exact identity")
            if len(self.evidence_digests) != len(_EVIDENCE_FIELDS):
                raise ValueError("admitted motion decision requires every evidence digest")
        elif not self.reasons:
            raise ValueError("blocked motion decision requires at least one reason")
        return self

    @property
    def admitted(self) -> bool:
        return self.status == "ADMITTED"


class MotionSafetyTrustStore:
    """In-memory verifier keys supplied by trusted offline configuration."""

    def __init__(self, verifier_keys: Mapping[str, bytes] | None = None) -> None:
        keys: dict[str, bytes] = {}
        if verifier_keys is not None and len(verifier_keys) > 32:
            raise ValueError("motion trust store exceeds maximum verifier entries")
        for issuer_id, key in (verifier_keys or {}).items():
            if re.fullmatch(_IDENTITY, issuer_id) is None:
                raise ValueError("motion verifier issuer identity is invalid")
            if not isinstance(key, bytes) or not 32 <= len(key) <= 4096:
                raise ValueError("motion verifier key size is outside safe bounds")
            keys[issuer_id] = bytes(key)
        self._keys = MappingProxyType(keys)

    def key_for(self, issuer_id: str) -> bytes | None:
        return self._keys.get(issuer_id)

    def verify(self, evidence: SignedMotionEvidence) -> bool:
        return self.verify_payload_signature(
            issuer_id=evidence.issuer_id,
            payload_sha256=evidence.payload_sha256,
            signature_hmac_sha256=evidence.signature_hmac_sha256,
        )

    def verify_payload_signature(
        self,
        *,
        issuer_id: str,
        payload_sha256: str,
        signature_hmac_sha256: str,
    ) -> bool:
        """Verify a detached, canonical-payload signature without trusting claims."""

        if (
            not isinstance(issuer_id, str)
            or re.fullmatch(_IDENTITY, issuer_id) is None
            or not isinstance(payload_sha256, str)
            or re.fullmatch(_SHA256, payload_sha256) is None
            or not isinstance(signature_hmac_sha256, str)
            or re.fullmatch(_HMAC_SHA256, signature_hmac_sha256) is None
        ):
            return False
        key = self.key_for(issuer_id)
        if key is None:
            return False
        expected = hmac.new(
            key,
            payload_sha256.encode("ascii"),
            hashlib.sha256,
        ).hexdigest()
        return hmac.compare_digest(
            f"hmac-sha256:{expected}",
            signature_hmac_sha256,
        )


def _blocked(
    evaluated_at: datetime,
    reasons: list[str] | tuple[str, ...],
    intent: MotionSafetyIntent | None = None,
) -> MotionSafetyDecision:
    unique_reasons = tuple(dict.fromkeys(reasons)) or ("MOTION_SAFETY_BLOCKED",)
    return MotionSafetyDecision(
        status="BLOCKED",
        reasons=unique_reasons,
        evaluated_at=evaluated_at,
        call_id=intent.call_id if intent else None,
        session_id=intent.session_id if intent else None,
        target_id=intent.target_id if intent else None,
        execution_subject_digest=intent.execution_subject_digest if intent else None,
        ros_graph_digest=intent.ros_graph_digest if intent else None,
    )


def _revalidate(model: type[_StrictModel], value: object) -> _StrictModel:
    if isinstance(value, BaseModel):
        value = value.model_dump(mode="python")
    return model.model_validate(value)


def _claims_are_exact(
    evidence: SignedMotionEvidence,
    keys: set[str],
    *,
    reason: str,
    reasons: list[str],
) -> bool:
    if set(evidence.claims) != keys:
        reasons.append(reason)
        return False
    return True


def evaluate_motion_safety(
    request: MotionSafetyAdmissionRequest | Mapping[str, Any] | None = None,
    *,
    policy: MotionSafetyPolicy | Mapping[str, Any] | None = None,
    trust_store: MotionSafetyTrustStore | None = None,
    now: datetime | None = None,
) -> MotionSafetyDecision:
    """Evaluate supplied evidence without performing any target-side action."""

    point = datetime.now(timezone.utc) if now is None else now
    if not isinstance(point, datetime) or point.tzinfo is None or point.utcoffset() is None:
        return _blocked(
            datetime.now(timezone.utc),
            ["EVALUATION_TIME_INVALID"],
        )
    point = point.astimezone(timezone.utc)
    if request is None:
        return _blocked(point, ["MOTION_SAFETY_REQUEST_REQUIRED"])
    try:
        untrusted_request = request.model_dump(mode="python") if isinstance(request, BaseModel) else request
        _validate_bounded_json(untrusted_request)
        parsed_request = _revalidate(MotionSafetyAdmissionRequest, request)
    except Exception:
        return _blocked(point, ["MOTION_SAFETY_REQUEST_INVALID"])
    assert isinstance(parsed_request, MotionSafetyAdmissionRequest)
    intent = parsed_request.intent
    if policy is None:
        return _blocked(point, ["MOTION_SAFETY_POLICY_REQUIRED"], intent)
    try:
        parsed_policy = _revalidate(MotionSafetyPolicy, policy)
    except Exception:
        return _blocked(point, ["MOTION_SAFETY_POLICY_INVALID"], intent)
    assert isinstance(parsed_policy, MotionSafetyPolicy)
    if trust_store is None or not isinstance(trust_store, MotionSafetyTrustStore):
        return _blocked(point, ["MOTION_SAFETY_TRUST_STORE_REQUIRED"], intent)

    reasons: list[str] = []
    if intent.target_id != parsed_policy.target_id:
        reasons.append("TARGET_ID_MISMATCH")
    if intent.target_identity != parsed_policy.target_identity:
        reasons.append("TARGET_IDENTITY_MISMATCH")
    if intent.command_route != parsed_policy.command_route:
        reasons.append("COMMAND_ROUTE_MISMATCH")
    if intent.command_interface != parsed_policy.command_interface:
        reasons.append("COMMAND_INTERFACE_MISMATCH")
    if intent.publisher_identity != parsed_policy.allowed_publisher_identity:
        reasons.append("PUBLISHER_IDENTITY_MISMATCH")
    if intent.direct_motor_route != parsed_policy.direct_motor_route:
        reasons.append("DIRECT_MOTOR_ROUTE_MISMATCH")
    if intent.direct_motor_interface != parsed_policy.direct_motor_interface:
        reasons.append("DIRECT_MOTOR_INTERFACE_MISMATCH")
    if intent.direct_motor_publisher_identity != parsed_policy.allowed_direct_motor_publisher_identity:
        reasons.append("DIRECT_MOTOR_PUBLISHER_IDENTITY_MISMATCH")
    intent_age = (point - intent.requested_at.astimezone(timezone.utc)).total_seconds()
    if intent_age < 0:
        reasons.append("MOTION_INTENT_NOT_YET_VALID")
    elif intent_age > parsed_policy.max_attestation_age_s:
        reasons.append("MOTION_INTENT_STALE")

    role_authorities = {
        "OPERATOR": parsed_policy.operator_authority_id,
        "PRESENCE": parsed_policy.presence_authority_id,
        "SAFETY": parsed_policy.safety_authority_id,
        "TARGET": parsed_policy.target_authority_id,
    }
    role_keys: dict[str, bytes] = {}
    for role, issuer_id in role_authorities.items():
        key = trust_store.key_for(issuer_id)
        if key is None:
            reasons.append(f"{role}_AUTHORITY_KEY_REQUIRED")
        else:
            role_keys[role] = key
    roles = tuple(role_keys)
    for index, left_role in enumerate(roles):
        for right_role in roles[index + 1 :]:
            if hmac.compare_digest(role_keys[left_role], role_keys[right_role]):
                reasons.append(f"{left_role}_{right_role}_AUTHORITY_KEYS_NOT_INDEPENDENT")
    graph_key = trust_store.key_for(parsed_policy.graph_authority_id)
    if graph_key is None:
        reasons.append("GRAPH_AUTHORITY_KEY_REQUIRED")
    elif parsed_policy.graph_authority_id != parsed_policy.target_authority_id:
        for role, key in role_keys.items():
            if hmac.compare_digest(graph_key, key):
                reasons.append(f"GRAPH_{role}_AUTHORITY_KEYS_NOT_INDEPENDENT")

    expected_issuers = {
        "operator_authorization": parsed_policy.operator_authority_id,
        "onsite_presence": parsed_policy.presence_authority_id,
        "safe_zone_confirmation": parsed_policy.safety_authority_id,
        "estop_verification": parsed_policy.safety_authority_id,
        "ros_graph_snapshot": parsed_policy.graph_authority_id,
        "direct_motor_fence": parsed_policy.target_authority_id,
        "target_stop_acknowledgement": parsed_policy.target_authority_id,
    }
    evidence_by_field: dict[str, SignedMotionEvidence] = {}
    for field, expected_kind in _EVIDENCE_FIELDS:
        evidence = getattr(parsed_request.evidence, field)
        label = field.upper()
        if evidence is None:
            reasons.append(f"{label}_REQUIRED")
            continue
        evidence_by_field[field] = evidence
        if evidence.kind != expected_kind:
            reasons.append(f"{label}_KIND_MISMATCH")
        if evidence.issuer_id != expected_issuers[field]:
            reasons.append(f"{label}_ISSUER_MISMATCH")
        if not trust_store.verify(evidence):
            reasons.append(f"{label}_SIGNATURE_INVALID")
        for identity_field in (
            "call_id",
            "session_id",
            "target_id",
            "target_identity",
            "operator_id",
            "execution_subject_digest",
            "ros_graph_digest",
        ):
            if getattr(evidence, identity_field) != getattr(intent, identity_field):
                reasons.append(f"{label}_{identity_field.upper()}_MISMATCH")
        issued = evidence.issued_at.astimezone(timezone.utc)
        expires = evidence.expires_at.astimezone(timezone.utc)
        age = (point - issued).total_seconds()
        max_age = parsed_policy.max_graph_age_s if field == "ros_graph_snapshot" else parsed_policy.max_attestation_age_s
        if age < 0:
            reasons.append(f"{label}_NOT_YET_VALID")
        elif age > max_age or point >= expires:
            reasons.append(f"{label}_STALE")
        if (expires - issued).total_seconds() > max_age:
            reasons.append(f"{label}_FRESHNESS_WINDOW_TOO_WIDE")

    evidence_ids = [item.evidence_id for item in evidence_by_field.values()]
    if len(evidence_ids) != len(set(evidence_ids)):
        reasons.append("MOTION_EVIDENCE_ID_REUSED")

    operator = evidence_by_field.get("operator_authorization")
    if operator is not None and _claims_are_exact(
        operator,
        {"authorization_id", "authorized", "motion_scope", "operator_id"},
        reason="OPERATOR_AUTHORIZATION_CLAIMS_INVALID",
        reasons=reasons,
    ):
        if (
            operator.claims["authorized"] is not True
            or operator.claims["motion_scope"] != "PHYSICAL_MOTION"
            or operator.claims["operator_id"] != intent.operator_id
            or not isinstance(operator.claims["authorization_id"], str)
            or re.fullmatch(_IDENTIFIER, operator.claims["authorization_id"]) is None
        ):
            reasons.append("OPERATOR_AUTHORIZATION_DENIED")

    presence = evidence_by_field.get("onsite_presence")
    if presence is not None and _claims_are_exact(
        presence,
        {"operator_id", "presence_method", "present", "site_id"},
        reason="ONSITE_PRESENCE_CLAIMS_INVALID",
        reasons=reasons,
    ):
        if (
            presence.claims["present"] is not True
            or presence.claims["operator_id"] != intent.operator_id
            or presence.claims["site_id"] != parsed_policy.site_id
            or presence.claims["presence_method"] != "ON_SITE_CHALLENGE"
        ):
            reasons.append("ONSITE_PRESENCE_NOT_CONFIRMED")

    safe_zone = evidence_by_field.get("safe_zone_confirmation")
    if safe_zone is not None and _claims_are_exact(
        safe_zone,
        {"confirmed_clear", "safe_zone_id", "site_id"},
        reason="SAFE_ZONE_CONFIRMATION_CLAIMS_INVALID",
        reasons=reasons,
    ):
        if safe_zone.claims["confirmed_clear"] is not True or safe_zone.claims["site_id"] != parsed_policy.site_id or safe_zone.claims["safe_zone_id"] != parsed_policy.safe_zone_id:
            reasons.append("SAFE_ZONE_NOT_CONFIRMED")

    estop = evidence_by_field.get("estop_verification")
    estop_keys = {
        "available",
        "challenge_digest",
        "engage_verified",
        "release_verified",
        "response_digest",
        "verification_method",
    }
    if estop is not None and _claims_are_exact(
        estop,
        estop_keys,
        reason="ESTOP_VERIFICATION_CLAIMS_INVALID",
        reasons=reasons,
    ):
        challenge = estop.claims["challenge_digest"]
        response = estop.claims["response_digest"]
        if (
            estop.claims["available"] is not True
            or estop.claims["engage_verified"] is not True
            or estop.claims["release_verified"] is not True
            or estop.claims["verification_method"] != "TARGET_CHALLENGE_RESPONSE"
            or not _is_sha256(challenge)
            or not _is_sha256(response)
        ):
            reasons.append("ESTOP_NOT_VERIFIABLE")
        elif response != compute_estop_response_digest(
            execution_subject_digest=intent.execution_subject_digest,
            challenge_digest=challenge,
            call_id=intent.call_id,
            session_id=intent.session_id,
            target_id=intent.target_id,
            target_identity=intent.target_identity,
            ros_graph_digest=intent.ros_graph_digest,
        ):
            reasons.append("ESTOP_RESPONSE_MISMATCH")

    graph = evidence_by_field.get("ros_graph_snapshot")
    graph_keys = {
        "command_interface",
        "command_route",
        "direct_motor_interface",
        "direct_motor_publisher_identities",
        "direct_motor_route",
        "publisher_identities",
    }
    if graph is not None and _claims_are_exact(
        graph,
        graph_keys,
        reason="ROS_GRAPH_SNAPSHOT_CLAIMS_INVALID",
        reasons=reasons,
    ):
        publishers = graph.claims["publisher_identities"]
        direct_publishers = graph.claims["direct_motor_publisher_identities"]
        if graph.claims["command_route"] != parsed_policy.command_route:
            reasons.append("ROS_GRAPH_COMMAND_ROUTE_MISMATCH")
        if graph.claims["command_interface"] != parsed_policy.command_interface:
            reasons.append("ROS_GRAPH_COMMAND_INTERFACE_MISMATCH")
        if graph.claims["direct_motor_route"] != parsed_policy.direct_motor_route:
            reasons.append("ROS_GRAPH_DIRECT_MOTOR_ROUTE_MISMATCH")
        if graph.claims["direct_motor_interface"] != parsed_policy.direct_motor_interface:
            reasons.append("ROS_GRAPH_DIRECT_MOTOR_INTERFACE_MISMATCH")
        if not isinstance(publishers, list) or len(publishers) != 1:
            reasons.append("COMMAND_ROUTE_NOT_EXCLUSIVE")
        if publishers != [parsed_policy.allowed_publisher_identity]:
            reasons.append("COMMAND_ROUTE_PUBLISHER_NOT_ALLOWED")
        if not isinstance(direct_publishers, list) or len(direct_publishers) != 1:
            reasons.append("DIRECT_MOTOR_ROUTE_NOT_EXCLUSIVE")
        if direct_publishers != [parsed_policy.allowed_direct_motor_publisher_identity]:
            reasons.append("DIRECT_MOTOR_ROUTE_PUBLISHER_NOT_ALLOWED")
        publishers_valid = isinstance(publishers, list) and all(isinstance(item, str) for item in publishers)
        direct_publishers_valid = isinstance(direct_publishers, list) and all(isinstance(item, str) for item in direct_publishers)
        if publishers_valid and direct_publishers_valid:
            expected_graph_digest = compute_ros_graph_digest(
                target_id=intent.target_id,
                target_identity=intent.target_identity,
                observed_at=graph.issued_at,
                command_route=graph.claims["command_route"],
                command_interface=graph.claims["command_interface"],
                publisher_identities=publishers,
                direct_motor_route=graph.claims["direct_motor_route"],
                direct_motor_interface=graph.claims["direct_motor_interface"],
                direct_motor_publisher_identities=direct_publishers,
            )
            if intent.ros_graph_digest != expected_graph_digest:
                reasons.append("ROS_GRAPH_DIGEST_MISMATCH")
        else:
            reasons.append("ROS_GRAPH_PUBLISHER_IDENTITIES_INVALID")

    fence = evidence_by_field.get("direct_motor_fence")
    fence_keys = {
        "active",
        "direct_access_blocked",
        "direct_motor_interface",
        "direct_motor_route",
        "fence_digest",
        "fence_epoch",
        "owner_identity",
        "publisher_identity",
    }
    if fence is not None and _claims_are_exact(
        fence,
        fence_keys,
        reason="DIRECT_MOTOR_FENCE_CLAIMS_INVALID",
        reasons=reasons,
    ):
        fence_epoch = fence.claims["fence_epoch"]
        expected_fence = None
        if isinstance(fence_epoch, int) and not isinstance(fence_epoch, bool) and fence_epoch >= 1:
            expected_fence = compute_direct_motor_fence_digest(
                execution_subject_digest=intent.execution_subject_digest,
                call_id=intent.call_id,
                session_id=intent.session_id,
                target_id=intent.target_id,
                target_identity=intent.target_identity,
                ros_graph_digest=intent.ros_graph_digest,
                command_route=parsed_policy.command_route,
                publisher_identity=parsed_policy.allowed_publisher_identity,
                direct_motor_route=parsed_policy.direct_motor_route,
                direct_motor_interface=parsed_policy.direct_motor_interface,
                direct_motor_publisher_identity=(parsed_policy.allowed_direct_motor_publisher_identity),
                fence_epoch=fence_epoch,
            )
        if (
            fence.claims["active"] is not True
            or fence.claims["direct_access_blocked"] is not True
            or fence.claims["owner_identity"] != parsed_policy.target_authority_id
            or fence.claims["direct_motor_route"] != parsed_policy.direct_motor_route
            or fence.claims["direct_motor_interface"] != parsed_policy.direct_motor_interface
            or fence.claims["publisher_identity"] != parsed_policy.allowed_direct_motor_publisher_identity
            or expected_fence is None
            or fence.claims["fence_digest"] != expected_fence
            or intent.direct_motor_fence_digest != expected_fence
        ):
            reasons.append("DIRECT_MOTOR_FENCE_NOT_VERIFIED")

    stop = evidence_by_field.get("target_stop_acknowledgement")
    stop_keys = {
        "acknowledged",
        "owner_identity",
        "stop_action_digest",
        "target_owned",
    }
    if stop is not None and _claims_are_exact(
        stop,
        stop_keys,
        reason="TARGET_STOP_ACKNOWLEDGEMENT_CLAIMS_INVALID",
        reasons=reasons,
    ):
        expected_stop = compute_stop_action_digest(
            execution_subject_digest=intent.execution_subject_digest,
            call_id=intent.call_id,
            session_id=intent.session_id,
            target_id=intent.target_id,
            target_identity=intent.target_identity,
            ros_graph_digest=intent.ros_graph_digest,
            command_route=parsed_policy.command_route,
            publisher_identity=parsed_policy.allowed_publisher_identity,
            direct_motor_route=parsed_policy.direct_motor_route,
            direct_motor_interface=parsed_policy.direct_motor_interface,
            direct_motor_publisher_identity=(parsed_policy.allowed_direct_motor_publisher_identity),
            direct_motor_fence_digest=intent.direct_motor_fence_digest,
        )
        if (
            stop.claims["acknowledged"] is not True
            or stop.claims["target_owned"] is not True
            or stop.claims["owner_identity"] != parsed_policy.target_authority_id
            or stop.claims["stop_action_digest"] != expected_stop
            or intent.stop_action_digest != expected_stop
        ):
            reasons.append("TARGET_STOP_NOT_ACKNOWLEDGED")

    if reasons:
        return _blocked(point, reasons, intent)
    ordered_evidence = [evidence_by_field[field].payload_sha256 for field, _ in _EVIDENCE_FIELDS]
    return MotionSafetyDecision(
        status="ADMITTED",
        reasons=(),
        evaluated_at=point,
        call_id=intent.call_id,
        session_id=intent.session_id,
        target_id=intent.target_id,
        execution_subject_digest=intent.execution_subject_digest,
        ros_graph_digest=intent.ros_graph_digest,
        evidence_digests=tuple(ordered_evidence),
    )


__all__ = [
    "MotionSafetyAdmissionRequest",
    "MotionSafetyDecision",
    "MotionSafetyEvidenceBundle",
    "MotionSafetyIntent",
    "MotionSafetyPolicy",
    "MotionSafetyTrustStore",
    "SignedMotionEvidence",
    "compute_direct_motor_fence_digest",
    "compute_estop_response_digest",
    "compute_motion_payload_digest",
    "compute_ros_graph_digest",
    "compute_stop_action_digest",
    "evaluate_motion_safety",
]
