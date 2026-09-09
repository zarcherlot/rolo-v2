"""Deployable, fail-closed composition for production Mapping authority.

This module contains no endpoint, credential, public key, private key, token,
or permissive local authority.  A deployment supplies mutually authenticated,
bounded transports for its time, identity/KMS, ACL, monotonic ledger-head, and
artifact services.  The adapters below validate and bind every response before
the existing production Mapping store is allowed to use it.

The composition deliberately keeps the external services separate.  Sharing a
transport or a signing trust root between roles is rejected by policy so an ACL
service cannot impersonate an operator, clock, ledger, or artifact authority.
"""

from __future__ import annotations

import base64
import json
import re
import secrets
import threading
import time
from collections.abc import Callable, Mapping
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, field_validator, model_validator

from rolo.dsl.admission import (
    MappingAdmissionIdentity,
    MappingAdmissionScope,
    MappingAuthorityCommand,
    MappingConfirmationReceipt,
    ProductionMappingAdmissionGate,
    ProductionMappingConfirmationStore,
    mapping_digest,
)
from rolo.dsl.candidates import CapabilityCandidate, CapabilityCandidateIndex
from rolo.dsl.canonical import context_digest, dsl_digest
from rolo.dsl.context import ProbeContext
from rolo.dsl.models import DslDocument
from rolo.dsl.parser import parse_document
from rolo.dsl.proposal import MappingProposal

from .authority import (
    MAX_AUTHORITY_EVIDENCE_TTL_S,
    PRODUCTION_AUTHORITY_CLASS,
    AuthorityProviderUnavailableError,
    AuthorityRolePin,
    AuthorityRolePolicy,
    AuthoritySignatureVerifier,
    SignatureAlgorithm,
    SignaturePurpose,
    SignatureVerification,
    SignedAclDecision,
    SignedLedgerHead,
    SignedOperatorAssertion,
    authority_digest,
    authority_signed_payload_bytes,
    authority_signed_payload_digest,
)

TRUSTED_TIME_WITNESS_SCHEMA_VERSION = "rolo-trusted-time-witness/v1"
FOUNDATION_ARTIFACT_SCHEMA_VERSION = "rolo-foundation-artifact/v1"
CURRENT_HEAD_WITNESS_SCHEMA_VERSION = "rolo-current-head-witness/v1"
OPERATION_POLICY_CATALOG_SCHEMA_VERSION = "rolo-operation-policy-catalog/v1"
PRODUCTION_AUTHORITY_COMPOSITION_SCHEMA_VERSION = "rolo-production-authority-composition/v1"
MAPPING_FOUNDATION_REFERENCES_SCHEMA_VERSION = "rolo-mapping-foundation-references/v1"
PREPARED_MAPPING_CONFIRMATION_SCHEMA_VERSION = "rolo-prepared-mapping-confirmation/v1"

MAX_PROVIDER_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_FOUNDATION_PAYLOAD_BYTES = 1024 * 1024
MAX_OPERATION_POLICIES = 512
MAX_DERIVED_SCOPE_OPERATIONS = 32

_DIGEST_PATTERN = r"^sha256:[0-9a-f]{64}$"
_IDENTIFIER_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"
_SIGNATURE_PATTERN = r"^[A-Za-z0-9_-]{32,2048}$"
_TOOL_PATTERN = r"^[a-z][a-z0-9_.-]{1,127}$"
_JSON_MAPPING = TypeAdapter(dict[str, Any])

FoundationKind = Literal[
    "PROPOSAL",
    "CONTEXT",
    "CANDIDATE_INDEX",
    "CANDIDATE",
    "DSL",
    "EVIDENCE",
    "TOOL_CATALOG",
]


class ProductionAuthorityModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ProductionAuthorityCompositionError(ValueError):
    """Stable fail-closed error emitted by the production composition."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class BoundedAuthorityJsonTransport(Protocol):
    """Deployment-owned request transport.

    Implementations are responsible for endpoint authentication, credential
    loading, TLS/Unix-socket policy, and hard I/O cancellation.  The adapter
    also measures elapsed monotonic time and rejects late responses, but that
    check is not a substitute for transport-level cancellation.
    """

    provider_id: str
    authority_class: str

    def request(
        self,
        operation: str,
        payload: Mapping[str, Any],
        *,
        timeout_s: float,
    ) -> Mapping[str, Any]:
        """Return one bounded JSON object or raise on failure."""


def _require_aware_utc(value: datetime, *, label: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise ValueError(f"{label} must be an aware UTC timestamp")
    return value


def _require_normalized_text(value: str, *, label: str, max_length: int = 1024) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > max_length
        or value != value.strip()
        or any(ord(character) < 33 or ord(character) == 127 for character in value)
    ):
        raise ValueError(f"{label} must be normalized and printable")
    return value


def _canonical_size(value: Mapping[str, Any]) -> int:
    try:
        normalized = _JSON_MAPPING.dump_python(dict(value), mode="json")
        encoded = json.dumps(
            normalized,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError("authority response is not canonical JSON") from exc
    return len(encoded)


def _bounded_request(
    transport: BoundedAuthorityJsonTransport,
    operation: str,
    payload: Mapping[str, Any],
    *,
    timeout_s: float,
    monotonic_ns: Callable[[], int],
) -> dict[str, Any]:
    if (
        getattr(transport, "authority_class", None) != PRODUCTION_AUTHORITY_CLASS
        or not isinstance(getattr(transport, "provider_id", None), str)
    ):
        raise ProductionAuthorityCompositionError("PRODUCTION_AUTHORITY_TRANSPORT_UNTRUSTED")
    started = monotonic_ns()
    try:
        raw = transport.request(operation, payload, timeout_s=timeout_s)
    except AuthorityProviderUnavailableError:
        raise
    except (TimeoutError, ConnectionError, OSError) as exc:
        raise AuthorityProviderUnavailableError("production authority provider unavailable") from exc
    elapsed_ns = monotonic_ns() - started
    if elapsed_ns < 0 or elapsed_ns > int(timeout_s * 1_000_000_000):
        raise AuthorityProviderUnavailableError("production authority provider deadline exceeded")
    if not isinstance(raw, Mapping):
        raise ValueError("authority provider response must be a JSON object")
    result = dict(raw)
    if _canonical_size(result) > MAX_PROVIDER_RESPONSE_BYTES:
        raise ValueError("authority provider response exceeds the maximum")
    return result


def _require_pin(
    verification: SignatureVerification,
    artifact: Any,
    pin: AuthorityRolePin,
    *,
    purpose: SignaturePurpose,
    issuer_field: str = "issuer_id",
) -> None:
    issuer_id = getattr(artifact, issuer_field)
    if (
        pin.purpose != purpose
        or issuer_id != pin.issuer_id
        or artifact.key_id != pin.key_id
        or verification.purpose != purpose
        or verification.issuer_id != issuer_id
        or verification.key_id != artifact.key_id
        or verification.algorithm != artifact.algorithm
        or verification.payload_digest != artifact.payload_digest
        or verification.trust_root_digest != pin.trust_root_digest
        or verification.authority_class != PRODUCTION_AUTHORITY_CLASS
        or verification.key_status != "ACTIVE"
        or verification.status != "VERIFIED"
    ):
        raise ProductionAuthorityCompositionError("PRODUCTION_AUTHORITY_ROLE_PIN_MISMATCH")


class TransportSignatureVerifier:
    """AuthoritySignatureVerifier backed by a deployment-owned JSON transport."""

    authority_class = PRODUCTION_AUTHORITY_CLASS

    def __init__(
        self,
        transport: BoundedAuthorityJsonTransport,
        *,
        timeout_s: float,
        monotonic_ns: Callable[[], int] = time.monotonic_ns,
    ) -> None:
        self.transport = transport
        self.provider_id = transport.provider_id
        self.timeout_s = _validated_timeout(timeout_s)
        self._monotonic_ns = monotonic_ns

    def verify(
        self,
        *,
        purpose: SignaturePurpose,
        issuer_id: str,
        key_id: str,
        algorithm: SignatureAlgorithm,
        payload: bytes,
        payload_digest: str,
        signature: str,
        now: datetime,
    ) -> SignatureVerification:
        effective_now = _require_aware_utc(now, label="signature verification time")
        if not isinstance(payload, bytes) or len(payload) > MAX_FOUNDATION_PAYLOAD_BYTES:
            raise ValueError("signature payload is invalid or too large")
        if authority_digest(json.loads(payload.decode("utf-8"))) != payload_digest:
            raise ValueError("signature payload digest mismatch")
        response = _bounded_request(
            self.transport,
            "signature.verify.v1",
            {
                "purpose": purpose,
                "issuer_id": issuer_id,
                "key_id": key_id,
                "algorithm": algorithm,
                "payload_b64": base64.urlsafe_b64encode(payload).decode("ascii"),
                "payload_digest": payload_digest,
                "signature": signature,
                "verification_time": effective_now.isoformat(),
            },
            timeout_s=self.timeout_s,
            monotonic_ns=self._monotonic_ns,
        )
        try:
            verification = SignatureVerification.model_validate(response)
        except ValueError as exc:
            raise ValueError("signature verifier returned invalid evidence") from exc
        if (
            verification.provider_id != self.provider_id
            or verification.purpose != purpose
            or verification.issuer_id != issuer_id
            or verification.key_id != key_id
            or verification.algorithm != algorithm
            or verification.payload_digest != payload_digest
            or verification.verified_at != effective_now
        ):
            raise ValueError("signature verifier response is not request-bound")
        return verification


class TrustedTimeWitness(ProductionAuthorityModel):
    schema_version: Literal["rolo-trusted-time-witness/v1"]
    provider_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    clock_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    sequence: int = Field(ge=1)
    utc_time: datetime
    uncertainty_ms: int = Field(ge=0, le=60_000)
    challenge_digest: str = Field(pattern=_DIGEST_PATTERN)
    issuer_id: str = Field(min_length=1, max_length=256)
    key_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    algorithm: SignatureAlgorithm
    payload_digest: str = Field(pattern=_DIGEST_PATTERN)
    signature: str = Field(pattern=_SIGNATURE_PATTERN)

    @model_validator(mode="after")
    def verify_time_and_digest(self) -> TrustedTimeWitness:
        _require_aware_utc(self.utc_time, label="trusted time")
        if self.payload_digest != authority_signed_payload_digest(self):
            raise ValueError("trusted time payload digest mismatch")
        return self


class TransportTrustedClock:
    """Callable wall clock backed by fresh, challenged, signed witnesses."""

    authority_class = PRODUCTION_AUTHORITY_CLASS

    def __init__(
        self,
        transport: BoundedAuthorityJsonTransport,
        signature_verifier: AuthoritySignatureVerifier,
        *,
        clock_id: str,
        pin: AuthorityRolePin,
        timeout_s: float,
        max_uncertainty_ms: int,
        monotonic_ns: Callable[[], int] = time.monotonic_ns,
    ) -> None:
        self.transport = transport
        self.signature_verifier = signature_verifier
        self.provider_id = transport.provider_id
        self.clock_id = clock_id
        self.pin = pin
        self.timeout_s = _validated_timeout(timeout_s)
        if isinstance(max_uncertainty_ms, bool) or not 0 <= max_uncertainty_ms <= 60_000:
            raise ValueError("max clock uncertainty is invalid")
        self.max_uncertainty_ms = max_uncertainty_ms
        self._monotonic_ns = monotonic_ns
        self._lock = threading.Lock()
        self._last_sequence = 0
        self._last_time: datetime | None = None

    def __call__(self) -> datetime:
        challenge = "sha256:" + secrets.token_hex(32)
        response = _bounded_request(
            self.transport,
            "trusted_time.read.v1",
            {"clock_id": self.clock_id, "challenge_digest": challenge},
            timeout_s=self.timeout_s,
            monotonic_ns=self._monotonic_ns,
        )
        try:
            witness = TrustedTimeWitness.model_validate(response)
        except ValueError as exc:
            raise ProductionAuthorityCompositionError("TRUSTED_TIME_WITNESS_INVALID") from exc
        if (
            witness.provider_id != self.provider_id
            or witness.clock_id != self.clock_id
            or witness.challenge_digest != challenge
            or witness.uncertainty_ms > self.max_uncertainty_ms
        ):
            raise ProductionAuthorityCompositionError("TRUSTED_TIME_WITNESS_MISMATCH")
        try:
            verification = self.signature_verifier.verify(
                purpose="TRUSTED_TIME",
                issuer_id=witness.issuer_id,
                key_id=witness.key_id,
                algorithm=witness.algorithm,
                payload=authority_signed_payload_bytes(witness),
                payload_digest=witness.payload_digest,
                signature=witness.signature,
                now=witness.utc_time,
            )
        except AuthorityProviderUnavailableError:
            raise
        except Exception as exc:
            raise ProductionAuthorityCompositionError("TRUSTED_TIME_SIGNATURE_INVALID") from exc
        _require_pin(verification, witness, self.pin, purpose="TRUSTED_TIME")
        with self._lock:
            if witness.sequence <= self._last_sequence:
                raise ProductionAuthorityCompositionError("TRUSTED_TIME_SEQUENCE_ROLLBACK")
            if self._last_time is not None and (
                witness.utc_time + timedelta(milliseconds=witness.uncertainty_ms)
                < self._last_time
            ):
                raise ProductionAuthorityCompositionError("TRUSTED_TIME_ROLLBACK")
            self._last_sequence = witness.sequence
            if self._last_time is None or witness.utc_time > self._last_time:
                self._last_time = witness.utc_time
            assert self._last_time is not None
            return self._last_time


class BoundOperatorAssertionVerifier:
    """Verify one operator assertion against one exact authority command."""

    authority_class = PRODUCTION_AUTHORITY_CLASS

    def __init__(
        self,
        signature_verifier: AuthoritySignatureVerifier,
        *,
        pin: AuthorityRolePin,
    ) -> None:
        self.signature_verifier = signature_verifier
        self.provider_id = signature_verifier.provider_id
        self.pin = pin

    def verify_bound(
        self,
        assertion: SignedOperatorAssertion,
        *,
        command_digest: str,
        now: datetime,
    ) -> SignatureVerification:
        effective_now = _require_aware_utc(now, label="operator verification time")
        try:
            item = SignedOperatorAssertion.model_validate(assertion)
        except ValueError as exc:
            raise ProductionAuthorityCompositionError("OPERATOR_ASSERTION_INVALID") from exc
        if item.challenge_digest != command_digest:
            raise ProductionAuthorityCompositionError("OPERATOR_ASSERTION_COMMAND_MISMATCH")
        if effective_now < item.issued_at or effective_now >= item.expires_at:
            raise ProductionAuthorityCompositionError("OPERATOR_ASSERTION_INACTIVE")
        try:
            verification = self.signature_verifier.verify(
                purpose="OPERATOR_ASSERTION",
                issuer_id=item.issuer_id,
                key_id=item.key_id,
                algorithm=item.algorithm,
                payload=authority_signed_payload_bytes(item),
                payload_digest=item.payload_digest,
                signature=item.signature,
                now=effective_now,
            )
        except AuthorityProviderUnavailableError:
            raise
        except Exception as exc:
            raise ProductionAuthorityCompositionError("OPERATOR_ASSERTION_SIGNATURE_INVALID") from exc
        _require_pin(verification, item, self.pin, purpose="OPERATOR_ASSERTION")
        return verification


class TransportAclDecisionResolver:
    """Resolve and verify an ACL decision bound to command and operator."""

    authority_class = PRODUCTION_AUTHORITY_CLASS

    def __init__(
        self,
        transport: BoundedAuthorityJsonTransport,
        signature_verifier: AuthoritySignatureVerifier,
        *,
        pin: AuthorityRolePin,
        timeout_s: float,
        monotonic_ns: Callable[[], int] = time.monotonic_ns,
    ) -> None:
        self.transport = transport
        self.signature_verifier = signature_verifier
        self.provider_id = transport.provider_id
        self.pin = pin
        self.timeout_s = _validated_timeout(timeout_s)
        self._monotonic_ns = monotonic_ns

    def resolve(
        self,
        command: MappingAuthorityCommand,
        operator_assertion: SignedOperatorAssertion,
        *,
        now: datetime,
    ) -> SignedAclDecision:
        effective_now = _require_aware_utc(now, label="ACL resolution time")
        response = _bounded_request(
            self.transport,
            "acl.resolve.v1",
            {
                "command": command.model_dump(mode="json"),
                "operator_assertion": operator_assertion.model_dump(mode="json"),
                "resolution_time": effective_now.isoformat(),
            },
            timeout_s=self.timeout_s,
            monotonic_ns=self._monotonic_ns,
        )
        try:
            decision = SignedAclDecision.model_validate(response)
        except ValueError as exc:
            raise ProductionAuthorityCompositionError("ACL_DECISION_INVALID") from exc
        if (
            decision.authority_id != self.pin.issuer_id
            or decision.key_id != self.pin.key_id
            or decision.subject_issuer_id != operator_assertion.issuer_id
            or decision.subject_principal_id != operator_assertion.principal_id
            or decision.action != command.action
            or decision.resource_digest != command.proposal_digest
            or decision.scope_digest != command.scope_digest
            or decision.request_digest != command.command_digest
            or effective_now < decision.issued_at
            or effective_now >= decision.expires_at
        ):
            raise ProductionAuthorityCompositionError("ACL_DECISION_BINDING_MISMATCH")
        try:
            verification = self.signature_verifier.verify(
                purpose="ACL_DECISION",
                issuer_id=decision.authority_id,
                key_id=decision.key_id,
                algorithm=decision.algorithm,
                payload=authority_signed_payload_bytes(decision),
                payload_digest=decision.payload_digest,
                signature=decision.signature,
                now=effective_now,
            )
        except AuthorityProviderUnavailableError:
            raise
        except Exception as exc:
            raise ProductionAuthorityCompositionError("ACL_DECISION_SIGNATURE_INVALID") from exc
        _require_pin(
            verification,
            decision,
            self.pin,
            purpose="ACL_DECISION",
            issuer_field="authority_id",
        )
        return decision


class TransportLedgerHeadAnchor:
    """LedgerHeadAnchorProvider adapter with exact read/CAS response binding."""

    authority_class = PRODUCTION_AUTHORITY_CLASS

    def __init__(
        self,
        transport: BoundedAuthorityJsonTransport,
        *,
        timeout_s: float,
        monotonic_ns: Callable[[], int] = time.monotonic_ns,
    ) -> None:
        self.transport = transport
        self.provider_id = transport.provider_id
        self.timeout_s = _validated_timeout(timeout_s)
        self._monotonic_ns = monotonic_ns

    def read_head(
        self,
        ledger_id: str,
        *,
        minimum_epoch: int,
        challenge_digest: str,
        now: datetime,
    ) -> SignedLedgerHead:
        response = _bounded_request(
            self.transport,
            "ledger_head.read.v1",
            {
                "ledger_id": ledger_id,
                "minimum_epoch": minimum_epoch,
                "challenge_digest": challenge_digest,
                "read_time": _require_aware_utc(now, label="ledger read time").isoformat(),
            },
            timeout_s=self.timeout_s,
            monotonic_ns=self._monotonic_ns,
        )
        try:
            head = SignedLedgerHead.model_validate(response)
        except ValueError as exc:
            raise ValueError("ledger head provider returned invalid evidence") from exc
        if (
            head.anchor_provider_id != self.provider_id
            or head.ledger_id != ledger_id
            or head.epoch < minimum_epoch
            or head.challenge_digest != challenge_digest
        ):
            raise ValueError("ledger head response is not request-bound")
        return head

    def advance(
        self,
        ledger_id: str,
        *,
        expected_anchor_digest: str,
        next_sequence: int,
        next_head_digest: str,
        challenge_digest: str,
        now: datetime,
    ) -> SignedLedgerHead:
        response = _bounded_request(
            self.transport,
            "ledger_head.advance.v1",
            {
                "ledger_id": ledger_id,
                "expected_anchor_digest": expected_anchor_digest,
                "next_sequence": next_sequence,
                "next_head_digest": next_head_digest,
                "challenge_digest": challenge_digest,
                "advance_time": _require_aware_utc(now, label="ledger advance time").isoformat(),
            },
            timeout_s=self.timeout_s,
            monotonic_ns=self._monotonic_ns,
        )
        try:
            head = SignedLedgerHead.model_validate(response)
        except ValueError as exc:
            raise ValueError("ledger head provider returned invalid CAS evidence") from exc
        if (
            head.anchor_provider_id != self.provider_id
            or head.ledger_id != ledger_id
            or head.previous_anchor_digest != expected_anchor_digest
            or head.sequence != next_sequence
            or head.head_digest != next_head_digest
            or head.challenge_digest != challenge_digest
        ):
            raise ValueError("ledger head CAS response is not request-bound")
        return head


class SignedFoundationArtifact(ProductionAuthorityModel):
    """Resolver-signed immutable artifact and its complete verified payload."""

    schema_version: Literal["rolo-foundation-artifact/v1"]
    resolver_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    artifact_kind: FoundationKind
    artifact_ref: str = Field(min_length=1, max_length=1024)
    artifact_digest: str = Field(pattern=_DIGEST_PATTERN)
    content_digest: str = Field(pattern=_DIGEST_PATTERN)
    target_id: str = Field(min_length=1, max_length=128)
    target_fingerprint: str = Field(min_length=1, max_length=256)
    immutable_revision: str = Field(pattern=_IDENTIFIER_PATTERN)
    payload: dict[str, Any]
    issued_at: datetime
    expires_at: datetime
    issuer_id: str = Field(min_length=1, max_length=256)
    key_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    algorithm: SignatureAlgorithm
    payload_digest: str = Field(pattern=_DIGEST_PATTERN)
    signature: str = Field(pattern=_SIGNATURE_PATTERN)

    @field_validator("artifact_ref", "target_id", "target_fingerprint", "issuer_id")
    @classmethod
    def normalized_text(cls, value: str) -> str:
        return _require_normalized_text(value, label="foundation field")

    @model_validator(mode="after")
    def verify_content_and_signature_digest(self) -> SignedFoundationArtifact:
        _require_short_interval(self.issued_at, self.expires_at, label="foundation artifact")
        if _canonical_size(self.payload) > MAX_FOUNDATION_PAYLOAD_BYTES:
            raise ValueError("foundation payload exceeds the maximum")
        if self.content_digest != authority_digest(self.payload):
            raise ValueError("foundation content digest mismatch")
        if self.payload_digest != authority_signed_payload_digest(self):
            raise ValueError("foundation signed payload digest mismatch")
        return self


def current_head_state_digest(value: SignedCurrentHead | Mapping[str, Any]) -> str:
    source = value.model_dump(mode="python") if isinstance(value, BaseModel) else value
    return authority_digest(
        {
            field: source[field]
            for field in (
                "resolver_id",
                "namespace",
                "artifact_kind",
                "artifact_ref",
                "current_artifact_digest",
                "target_id",
                "target_fingerprint",
                "sequence",
                "previous_head_digest",
            )
        }
    )


class SignedCurrentHead(ProductionAuthorityModel):
    """Fresh challenged witness for one resolver-owned current artifact."""

    schema_version: Literal["rolo-current-head-witness/v1"]
    resolver_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    namespace: str = Field(pattern=_IDENTIFIER_PATTERN)
    artifact_kind: FoundationKind
    artifact_ref: str = Field(min_length=1, max_length=1024)
    current_artifact_digest: str = Field(pattern=_DIGEST_PATTERN)
    target_id: str = Field(min_length=1, max_length=128)
    target_fingerprint: str = Field(min_length=1, max_length=256)
    sequence: int = Field(ge=1)
    previous_head_digest: str | None = Field(pattern=_DIGEST_PATTERN)
    head_digest: str = Field(pattern=_DIGEST_PATTERN)
    challenge_digest: str = Field(pattern=_DIGEST_PATTERN)
    witnessed_at: datetime
    expires_at: datetime
    issuer_id: str = Field(min_length=1, max_length=256)
    key_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    algorithm: SignatureAlgorithm
    payload_digest: str = Field(pattern=_DIGEST_PATTERN)
    signature: str = Field(pattern=_SIGNATURE_PATTERN)

    @field_validator("artifact_ref", "target_id", "target_fingerprint", "issuer_id")
    @classmethod
    def normalized_text(cls, value: str) -> str:
        return _require_normalized_text(value, label="current head field")

    @model_validator(mode="after")
    def verify_head_and_signature_digest(self) -> SignedCurrentHead:
        _require_short_interval(
            self.witnessed_at,
            self.expires_at,
            label="current head witness",
            maximum_s=30,
        )
        if self.sequence == 1 and self.previous_head_digest is not None:
            raise ValueError("first current head cannot name a predecessor")
        if self.sequence > 1 and self.previous_head_digest is None:
            raise ValueError("non-first current head requires a predecessor")
        if self.head_digest != current_head_state_digest(self):
            raise ValueError("current head state digest mismatch")
        if self.payload_digest != authority_signed_payload_digest(self):
            raise ValueError("current head signed payload digest mismatch")
        return self


class TransportFoundationResolver:
    """Resolve immutable foundation artifacts and verify resolver signatures."""

    authority_class = PRODUCTION_AUTHORITY_CLASS

    def __init__(
        self,
        transport: BoundedAuthorityJsonTransport,
        signature_verifier: AuthoritySignatureVerifier,
        *,
        pin: AuthorityRolePin,
        timeout_s: float,
        monotonic_ns: Callable[[], int] = time.monotonic_ns,
    ) -> None:
        self.transport = transport
        self.signature_verifier = signature_verifier
        self.provider_id = transport.provider_id
        self.pin = pin
        self.timeout_s = _validated_timeout(timeout_s)
        self._monotonic_ns = monotonic_ns

    def resolve(
        self,
        artifact_kind: FoundationKind,
        artifact_ref: str,
        *,
        now: datetime,
    ) -> SignedFoundationArtifact:
        effective_now = _require_aware_utc(now, label="foundation resolution time")
        response = _bounded_request(
            self.transport,
            "foundation.resolve.v1",
            {
                "artifact_kind": artifact_kind,
                "artifact_ref": artifact_ref,
                "resolution_time": effective_now.isoformat(),
            },
            timeout_s=self.timeout_s,
            monotonic_ns=self._monotonic_ns,
        )
        try:
            artifact = SignedFoundationArtifact.model_validate(response)
        except ValueError as exc:
            raise ProductionAuthorityCompositionError("FOUNDATION_ARTIFACT_INVALID") from exc
        if (
            artifact.resolver_id != self.provider_id
            or artifact.artifact_kind != artifact_kind
            or artifact.artifact_ref != artifact_ref
            or effective_now < artifact.issued_at
            or effective_now >= artifact.expires_at
        ):
            raise ProductionAuthorityCompositionError("FOUNDATION_ARTIFACT_BINDING_MISMATCH")
        try:
            verification = self.signature_verifier.verify(
                purpose="FOUNDATION_ARTIFACT",
                issuer_id=artifact.issuer_id,
                key_id=artifact.key_id,
                algorithm=artifact.algorithm,
                payload=authority_signed_payload_bytes(artifact),
                payload_digest=artifact.payload_digest,
                signature=artifact.signature,
                now=effective_now,
            )
        except AuthorityProviderUnavailableError:
            raise
        except Exception as exc:
            raise ProductionAuthorityCompositionError("FOUNDATION_ARTIFACT_SIGNATURE_INVALID") from exc
        _require_pin(verification, artifact, self.pin, purpose="FOUNDATION_ARTIFACT")
        return artifact


class TransportCurrentHeadResolver:
    """Read a fresh signed current head for an already verified artifact."""

    authority_class = PRODUCTION_AUTHORITY_CLASS

    def __init__(
        self,
        transport: BoundedAuthorityJsonTransport,
        signature_verifier: AuthoritySignatureVerifier,
        *,
        namespace: str,
        pin: AuthorityRolePin,
        timeout_s: float,
        monotonic_ns: Callable[[], int] = time.monotonic_ns,
    ) -> None:
        self.transport = transport
        self.signature_verifier = signature_verifier
        self.provider_id = transport.provider_id
        self.namespace = namespace
        self.pin = pin
        self.timeout_s = _validated_timeout(timeout_s)
        self._monotonic_ns = monotonic_ns
        self._lock = threading.Lock()
        self._observed_heads: dict[
            tuple[str, FoundationKind, str, str, str], tuple[int, str]
        ] = {}

    def require_current(
        self,
        artifact: SignedFoundationArtifact,
        *,
        now: datetime,
    ) -> SignedCurrentHead:
        effective_now = _require_aware_utc(now, label="current head resolution time")
        challenge = "sha256:" + secrets.token_hex(32)
        response = _bounded_request(
            self.transport,
            "current_head.read.v1",
            {
                "namespace": self.namespace,
                "artifact_kind": artifact.artifact_kind,
                "artifact_ref": artifact.artifact_ref,
                "expected_artifact_digest": artifact.artifact_digest,
                "target_id": artifact.target_id,
                "target_fingerprint": artifact.target_fingerprint,
                "challenge_digest": challenge,
                "resolution_time": effective_now.isoformat(),
            },
            timeout_s=self.timeout_s,
            monotonic_ns=self._monotonic_ns,
        )
        try:
            head = SignedCurrentHead.model_validate(response)
        except ValueError as exc:
            raise ProductionAuthorityCompositionError("CURRENT_HEAD_WITNESS_INVALID") from exc
        if (
            head.resolver_id != self.provider_id
            or head.namespace != self.namespace
            or head.artifact_kind != artifact.artifact_kind
            or head.artifact_ref != artifact.artifact_ref
            or head.current_artifact_digest != artifact.artifact_digest
            or head.target_id != artifact.target_id
            or head.target_fingerprint != artifact.target_fingerprint
            or head.challenge_digest != challenge
            or effective_now < head.witnessed_at
            or effective_now >= head.expires_at
        ):
            raise ProductionAuthorityCompositionError("CURRENT_HEAD_BINDING_MISMATCH")
        try:
            verification = self.signature_verifier.verify(
                purpose="CURRENT_HEAD",
                issuer_id=head.issuer_id,
                key_id=head.key_id,
                algorithm=head.algorithm,
                payload=authority_signed_payload_bytes(head),
                payload_digest=head.payload_digest,
                signature=head.signature,
                now=effective_now,
            )
        except AuthorityProviderUnavailableError:
            raise
        except Exception as exc:
            raise ProductionAuthorityCompositionError("CURRENT_HEAD_SIGNATURE_INVALID") from exc
        _require_pin(verification, head, self.pin, purpose="CURRENT_HEAD")
        identity = (
            head.namespace,
            head.artifact_kind,
            head.artifact_ref,
            head.target_id,
            head.target_fingerprint,
        )
        with self._lock:
            previous = self._observed_heads.get(identity)
            if previous is not None:
                previous_sequence, previous_digest = previous
                if head.sequence < previous_sequence:
                    raise ProductionAuthorityCompositionError("CURRENT_HEAD_SEQUENCE_ROLLBACK")
                if head.sequence == previous_sequence and head.head_digest != previous_digest:
                    raise ProductionAuthorityCompositionError("CURRENT_HEAD_EQUIVOCATION")
                if head.sequence > previous_sequence and (
                    head.sequence != previous_sequence + 1
                    or head.previous_head_digest != previous_digest
                ):
                    raise ProductionAuthorityCompositionError("CURRENT_HEAD_CHAIN_GAP")
            self._observed_heads[identity] = (head.sequence, head.head_digest)
        return head


class OperationPolicy(ProductionAuthorityModel):
    operation: str = Field(pattern=_TOOL_PATTERN)
    operation_kind: Literal["OBSERVE", "COMPOSE", "INVOKE", "EXECUTE"]
    provider_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    access: Literal["read", "experimental_write"]
    risk: Literal["R0", "R1", "R2", "R3"]
    dependencies: tuple[str, ...] = Field(default_factory=tuple, max_length=32)
    motion_possible: bool = False

    @field_validator("dependencies")
    @classmethod
    def normalized_dependencies(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(sorted(set(value)))
        if any(re.fullmatch(_TOOL_PATTERN, item) is None for item in normalized):
            raise ValueError("operation policy dependencies are invalid")
        return normalized

    @model_validator(mode="after")
    def verify_safety_floor(self) -> OperationPolicy:
        if self.operation in self.dependencies:
            raise ValueError("operation policy cannot directly depend on itself")
        if self.operation_kind == "OBSERVE" and self.access != "read":
            raise ValueError("OBSERVE policy must be read-only")
        if self.operation_kind == "EXECUTE" and (
            self.access != "experimental_write" or self.risk == "R0"
        ):
            raise ValueError("EXECUTE policy cannot be reported as read/R0")
        if self.motion_possible and (
            self.operation_kind != "EXECUTE"
            or self.access != "experimental_write"
            or self.risk != "R3"
        ):
            raise ValueError("motion-capable policy must be EXECUTE/experimental_write/R3")
        return self


class OperationPolicyCatalog(ProductionAuthorityModel):
    schema_version: Literal["rolo-operation-policy-catalog/v1"]
    catalog_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    target_id: str = Field(min_length=1, max_length=128)
    target_fingerprint: str = Field(min_length=1, max_length=256)
    policies: tuple[OperationPolicy, ...] = Field(min_length=1, max_length=MAX_OPERATION_POLICIES)
    catalog_digest: str = Field(pattern=_DIGEST_PATTERN)

    @model_validator(mode="after")
    def verify_catalog(self) -> OperationPolicyCatalog:
        operations = [item.operation for item in self.policies]
        if len(operations) != len(set(operations)):
            raise ValueError("operation policy catalog contains duplicate operations")
        if self.catalog_digest != mapping_digest(
            self.model_dump(mode="json", exclude={"catalog_digest"})
        ):
            raise ValueError("operation policy catalog digest mismatch")
        return self


class DerivedScopeResolver:
    """The sole deterministic DSL/provider/dependency scope derivation."""

    def derive(
        self,
        dsl: DslDocument,
        catalog: OperationPolicyCatalog,
    ) -> MappingAdmissionScope:
        policies = {item.operation: item for item in catalog.policies}
        root = policies.get(dsl.tool_id)
        if root is None:
            raise ProductionAuthorityCompositionError("DERIVED_SCOPE_ROOT_NOT_TRUSTED")
        if root.operation_kind != dsl.kind.value:
            raise ProductionAuthorityCompositionError("DERIVED_SCOPE_KIND_MISMATCH")
        provider_values = {
            value
            for value in (
                dsl.binding.get("provider_id"),
                dsl.implementation.get("provider_id"),
            )
            if isinstance(value, str) and value
        }
        if provider_values != {root.provider_id}:
            raise ProductionAuthorityCompositionError("DERIVED_SCOPE_PROVIDER_MISMATCH")

        roots = {root.operation}
        steps = dsl.composition.get("steps", ())
        if dsl.kind.value == "COMPOSE":
            if not isinstance(steps, (list, tuple)):
                raise ProductionAuthorityCompositionError("DERIVED_SCOPE_COMPOSITION_INVALID")
            for step in steps:
                if not isinstance(step, Mapping):
                    raise ProductionAuthorityCompositionError("DERIVED_SCOPE_COMPOSITION_INVALID")
                names = {
                    item
                    for item in (step.get("operation"), step.get("tool_id"))
                    if isinstance(item, str) and item
                }
                if len(names) != 1:
                    raise ProductionAuthorityCompositionError("DERIVED_SCOPE_COMPOSITION_INVALID")
                roots.update(names)
        elif steps:
            raise ProductionAuthorityCompositionError("DERIVED_SCOPE_UNEXPECTED_COMPOSITION")

        closure: set[str] = set()
        visiting: set[str] = set()

        def visit(operation: str) -> None:
            if operation in visiting:
                raise ProductionAuthorityCompositionError("DERIVED_SCOPE_DEPENDENCY_CYCLE")
            if operation in closure:
                return
            policy = policies.get(operation)
            if policy is None:
                raise ProductionAuthorityCompositionError("DERIVED_SCOPE_DEPENDENCY_NOT_TRUSTED")
            if len(closure) >= MAX_DERIVED_SCOPE_OPERATIONS:
                raise ProductionAuthorityCompositionError("DERIVED_SCOPE_TOO_LARGE")
            visiting.add(operation)
            for dependency in policy.dependencies:
                visit(dependency)
            visiting.remove(operation)
            closure.add(operation)

        for operation in sorted(roots):
            visit(operation)
        selected = tuple(policies[item] for item in sorted(closure))
        access = (
            "experimental_write"
            if any(item.access == "experimental_write" for item in selected)
            else "read"
        )
        risk = max((item.risk for item in selected), key=("R0", "R1", "R2", "R3").index)
        if dsl.kind.value == "EXECUTE" and (access != "experimental_write" or risk == "R0"):
            raise ProductionAuthorityCompositionError("DERIVED_SCOPE_EXECUTE_UNDERREPORTED")
        return MappingAdmissionScope(
            tool_id=dsl.tool_id,
            operation_kind=dsl.kind,
            operations=tuple(sorted(closure)),
            access=access,
            risk=risk,
        )


class MappingFoundationReferences(ProductionAuthorityModel):
    schema_version: Literal["rolo-mapping-foundation-references/v1"]
    journey_session_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    proposal_ref: str = Field(min_length=1, max_length=1024)
    context_ref: str = Field(min_length=1, max_length=1024)
    candidate_index_ref: str = Field(min_length=1, max_length=1024)
    candidate_ref: str = Field(min_length=1, max_length=1024)
    dsl_ref: str = Field(min_length=1, max_length=1024)
    evidence_ref: str = Field(min_length=1, max_length=1024)
    tool_catalog_ref: str = Field(min_length=1, max_length=1024)

    @field_validator(
        "proposal_ref",
        "context_ref",
        "candidate_index_ref",
        "candidate_ref",
        "dsl_ref",
        "evidence_ref",
        "tool_catalog_ref",
    )
    @classmethod
    def normalized_refs(cls, value: str) -> str:
        return _require_normalized_text(value, label="foundation reference")

    def pairs(self) -> tuple[tuple[FoundationKind, str], ...]:
        return (
            ("PROPOSAL", self.proposal_ref),
            ("CONTEXT", self.context_ref),
            ("CANDIDATE_INDEX", self.candidate_index_ref),
            ("CANDIDATE", self.candidate_ref),
            ("DSL", self.dsl_ref),
            ("EVIDENCE", self.evidence_ref),
            ("TOOL_CATALOG", self.tool_catalog_ref),
        )


class ProductionAuthorityCompositionPolicy(ProductionAuthorityModel):
    schema_version: Literal["rolo-production-authority-composition/v1"]
    authority_roles: AuthorityRolePolicy
    trusted_time: AuthorityRolePin
    foundation_artifact: AuthorityRolePin
    current_head: AuthorityRolePin
    signature_verifier_provider_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    trusted_time_provider_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    acl_resolver_provider_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    ledger_head_provider_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    foundation_resolver_provider_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    current_head_resolver_provider_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    ledger_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    clock_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    current_head_namespace: str = Field(pattern=_IDENTIFIER_PATTERN)
    provider_timeout_ms: int = Field(ge=10, le=30_000)
    max_clock_uncertainty_ms: int = Field(ge=0, le=60_000)

    @model_validator(mode="after")
    def verify_role_isolation(self) -> ProductionAuthorityCompositionPolicy:
        extra = (
            (self.trusted_time, "TRUSTED_TIME"),
            (self.foundation_artifact, "FOUNDATION_ARTIFACT"),
            (self.current_head, "CURRENT_HEAD"),
        )
        if any(pin.purpose != purpose for pin, purpose in extra):
            raise ValueError("production composition role purpose mismatch")
        pins = (
            self.authority_roles.operator_assertion,
            self.authority_roles.acl_decision,
            self.authority_roles.ledger_head,
            self.trusted_time,
            self.foundation_artifact,
            self.current_head,
        )
        for field in ("issuer_id", "key_id", "trust_root_digest"):
            if len({getattr(pin, field) for pin in pins}) != len(pins):
                raise ValueError(f"production authority {field} roles must be isolated")
        role_providers = (
            self.trusted_time_provider_id,
            self.acl_resolver_provider_id,
            self.ledger_head_provider_id,
            self.foundation_resolver_provider_id,
            self.current_head_resolver_provider_id,
        )
        if len(set(role_providers)) != len(role_providers):
            raise ValueError("production role provider identities must be isolated")
        return self


class ResolvedMappingFoundations(ProductionAuthorityModel):
    references: MappingFoundationReferences
    identity: MappingAdmissionIdentity
    derived_scope: MappingAdmissionScope
    artifacts: tuple[SignedFoundationArtifact, ...]
    current_heads: tuple[SignedCurrentHead, ...]
    foundation_set_digest: str = Field(pattern=_DIGEST_PATTERN)
    current_head_set_digest: str = Field(pattern=_DIGEST_PATTERN)
    resolved_at: datetime


class PreparedMappingConfirmation(ProductionAuthorityModel):
    schema_version: Literal["rolo-prepared-mapping-confirmation/v1"]
    references: MappingFoundationReferences
    identity: MappingAdmissionIdentity
    command: MappingAuthorityCommand
    foundation_set_digest: str = Field(pattern=_DIGEST_PATTERN)
    current_head_set_digest: str = Field(pattern=_DIGEST_PATTERN)


class ProductionAuthorityComposition:
    """Construct and drive a production Mapping authority from pinned adapters."""

    def __init__(
        self,
        root: str | Path,
        policy: ProductionAuthorityCompositionPolicy,
        *,
        signature_verifier: AuthoritySignatureVerifier,
        trusted_clock: TransportTrustedClock,
        operator_verifier: BoundOperatorAssertionVerifier,
        acl_resolver: TransportAclDecisionResolver,
        ledger_head: TransportLedgerHeadAnchor,
        foundation_resolver: TransportFoundationResolver,
        current_head_resolver: TransportCurrentHeadResolver,
        scope_resolver: DerivedScopeResolver | None = None,
    ) -> None:
        self.policy = ProductionAuthorityCompositionPolicy.model_validate(
            policy.model_dump(mode="python")
        )
        self.signature_verifier = signature_verifier
        self.clock = trusted_clock
        self.operator_verifier = operator_verifier
        self.acl_resolver = acl_resolver
        self.ledger_head = ledger_head
        self.foundation_resolver = foundation_resolver
        self.current_head_resolver = current_head_resolver
        self.scope_resolver = scope_resolver or DerivedScopeResolver()
        expected = {
            "signature_verifier": self.policy.signature_verifier_provider_id,
            "trusted_clock": self.policy.trusted_time_provider_id,
            "acl_resolver": self.policy.acl_resolver_provider_id,
            "ledger_head": self.policy.ledger_head_provider_id,
            "foundation_resolver": self.policy.foundation_resolver_provider_id,
            "current_head_resolver": self.policy.current_head_resolver_provider_id,
        }
        actual = {
            "signature_verifier": signature_verifier.provider_id,
            "trusted_clock": trusted_clock.provider_id,
            "acl_resolver": acl_resolver.provider_id,
            "ledger_head": ledger_head.provider_id,
            "foundation_resolver": foundation_resolver.provider_id,
            "current_head_resolver": current_head_resolver.provider_id,
        }
        if actual != expected:
            raise ProductionAuthorityCompositionError("PRODUCTION_AUTHORITY_PROVIDER_MISMATCH")
        adapters = (
            signature_verifier,
            trusted_clock,
            operator_verifier,
            acl_resolver,
            ledger_head,
            foundation_resolver,
            current_head_resolver,
        )
        if any(
            getattr(adapter, "authority_class", None) != PRODUCTION_AUTHORITY_CLASS
            for adapter in adapters
        ):
            raise ProductionAuthorityCompositionError("PRODUCTION_AUTHORITY_ADAPTER_UNTRUSTED")
        if any(
            adapter.signature_verifier is not signature_verifier
            for adapter in (
                trusted_clock,
                operator_verifier,
                acl_resolver,
                foundation_resolver,
                current_head_resolver,
            )
        ):
            raise ProductionAuthorityCompositionError("PRODUCTION_AUTHORITY_VERIFIER_MISMATCH")
        configured_timeout_s = self.policy.provider_timeout_ms / 1000
        if any(
            getattr(adapter, "timeout_s", configured_timeout_s) > configured_timeout_s
            for adapter in (
                signature_verifier,
                trusted_clock,
                acl_resolver,
                ledger_head,
                foundation_resolver,
                current_head_resolver,
            )
        ):
            raise ProductionAuthorityCompositionError("PRODUCTION_AUTHORITY_TIMEOUT_POLICY_MISMATCH")
        if trusted_clock.max_uncertainty_ms != self.policy.max_clock_uncertainty_ms:
            raise ProductionAuthorityCompositionError("PRODUCTION_AUTHORITY_CLOCK_POLICY_MISMATCH")
        if (
            trusted_clock.clock_id != self.policy.clock_id
            or current_head_resolver.namespace != self.policy.current_head_namespace
            or trusted_clock.pin != self.policy.trusted_time
            or operator_verifier.pin != self.policy.authority_roles.operator_assertion
            or acl_resolver.pin != self.policy.authority_roles.acl_decision
            or foundation_resolver.pin != self.policy.foundation_artifact
            or current_head_resolver.pin != self.policy.current_head
        ):
            raise ProductionAuthorityCompositionError("PRODUCTION_AUTHORITY_POLICY_MISMATCH")
        self.store = ProductionMappingConfirmationStore(
            root,
            ledger_id=self.policy.ledger_id,
            signature_verifier=signature_verifier,
            head_anchor=ledger_head,
            role_policy=self.policy.authority_roles,
            clock=trusted_clock,
        )
        self.gate = ProductionMappingAdmissionGate(self.store, clock=trusted_clock)

    def resolve_foundations(
        self,
        references: MappingFoundationReferences,
    ) -> ResolvedMappingFoundations:
        references = MappingFoundationReferences.model_validate(references)
        artifacts: list[SignedFoundationArtifact] = []
        heads: list[SignedCurrentHead] = []
        for kind, reference in references.pairs():
            artifact = self.foundation_resolver.resolve(kind, reference, now=self.clock())
            head = self.current_head_resolver.require_current(artifact, now=self.clock())
            artifacts.append(artifact)
            heads.append(head)
        resolved_at = self.clock()
        _require_foundations_active(artifacts, heads, now=resolved_at)
        by_kind = {artifact.artifact_kind: artifact for artifact in artifacts}
        identity, scope = _verify_mapping_foundations(references, by_kind, self.scope_resolver)
        foundation_set_digest = _foundation_set_digest(artifacts)
        current_head_set_digest = _current_head_set_digest(heads)
        return ResolvedMappingFoundations(
            references=references,
            identity=identity,
            derived_scope=scope,
            artifacts=tuple(artifacts),
            current_heads=tuple(heads),
            foundation_set_digest=foundation_set_digest,
            current_head_set_digest=current_head_set_digest,
            resolved_at=resolved_at,
        )

    def prepare_confirmation(
        self,
        references: MappingFoundationReferences,
        *,
        decision_id: str,
        ttl_s: int = 900,
    ) -> PreparedMappingConfirmation:
        resolved = self.resolve_foundations(references)
        command = self.store.prepare_confirm(
            resolved.identity,
            decision_id=decision_id,
            ttl_s=ttl_s,
        )
        return PreparedMappingConfirmation(
            schema_version=PREPARED_MAPPING_CONFIRMATION_SCHEMA_VERSION,
            references=resolved.references,
            identity=resolved.identity,
            command=command,
            foundation_set_digest=resolved.foundation_set_digest,
            current_head_set_digest=resolved.current_head_set_digest,
        )

    def confirm(
        self,
        prepared: PreparedMappingConfirmation,
        operator_assertion: SignedOperatorAssertion,
    ) -> MappingConfirmationReceipt:
        prepared = PreparedMappingConfirmation.model_validate(prepared)
        resolved = self.resolve_foundations(prepared.references)
        if (
            resolved.identity != prepared.identity
            or resolved.foundation_set_digest != prepared.foundation_set_digest
            or resolved.current_head_set_digest != prepared.current_head_set_digest
        ):
            raise ProductionAuthorityCompositionError("MAPPING_FOUNDATION_STATE_CHANGED")
        expected_command = self.store.prepare_confirm(
            resolved.identity,
            decision_id=prepared.command.decision_id,
            ttl_s=prepared.command.requested_ttl_s or 0,
        )
        if expected_command != prepared.command:
            raise ProductionAuthorityCompositionError("MAPPING_AUTHORITY_COMMAND_CHANGED")
        operator_assertion = SignedOperatorAssertion.model_validate(operator_assertion)
        self.operator_verifier.verify_bound(
            operator_assertion,
            command_digest=prepared.command.command_digest,
            now=self.clock(),
        )
        acl_decision = self.acl_resolver.resolve(
            prepared.command,
            operator_assertion,
            now=self.clock(),
        )
        if acl_decision.effect != "ALLOW":
            raise ProductionAuthorityCompositionError("ACL_DECISION_DENIED")
        # Re-read all current heads after authentication/ACL latency.  The
        # Mapping store then performs its own fresh clock and monotonic-ledger
        # checks under its non-stealable lock.
        rechecked_heads = tuple(
            self.current_head_resolver.require_current(artifact, now=self.clock())
            for artifact in resolved.artifacts
        )
        if _current_head_set_digest(rechecked_heads) != prepared.current_head_set_digest:
            raise ProductionAuthorityCompositionError("MAPPING_FOUNDATION_STATE_CHANGED")
        # The seven current-head reads are sequential.  Recheck the complete
        # set against one final trusted timestamp so an early witness cannot
        # expire while the remaining heads are being resolved and still
        # authorize the irreversible Mapping commit.
        _require_foundations_active(
            resolved.artifacts,
            rechecked_heads,
            now=self.clock(),
        )
        return self.store.confirm(
            resolved.identity,
            command=prepared.command,
            operator_assertion=operator_assertion,
            acl_decision=acl_decision,
        )


def compose_production_mapping_authority(
    root: str | Path,
    policy: ProductionAuthorityCompositionPolicy,
    *,
    signature_transport: BoundedAuthorityJsonTransport,
    trusted_time_transport: BoundedAuthorityJsonTransport,
    acl_transport: BoundedAuthorityJsonTransport,
    ledger_head_transport: BoundedAuthorityJsonTransport,
    foundation_transport: BoundedAuthorityJsonTransport,
    current_head_transport: BoundedAuthorityJsonTransport,
    monotonic_ns: Callable[[], int] = time.monotonic_ns,
    scope_resolver: DerivedScopeResolver | None = None,
) -> ProductionAuthorityComposition:
    """Build the complete production authority graph from external transports.

    This is the deployment composition root.  It accepts transport objects,
    never raw credentials or trust material.  Endpoint authentication and key
    loading therefore stay in deployment code; this function only applies the
    checked provider ids, trust-root digests, timeouts, and role isolation in
    ``policy``.
    """

    policy = ProductionAuthorityCompositionPolicy.model_validate(policy)
    timeout_s = policy.provider_timeout_ms / 1000
    signature_verifier = TransportSignatureVerifier(
        signature_transport,
        timeout_s=timeout_s,
        monotonic_ns=monotonic_ns,
    )
    trusted_clock = TransportTrustedClock(
        trusted_time_transport,
        signature_verifier,
        clock_id=policy.clock_id,
        pin=policy.trusted_time,
        timeout_s=timeout_s,
        max_uncertainty_ms=policy.max_clock_uncertainty_ms,
        monotonic_ns=monotonic_ns,
    )
    operator_verifier = BoundOperatorAssertionVerifier(
        signature_verifier,
        pin=policy.authority_roles.operator_assertion,
    )
    acl_resolver = TransportAclDecisionResolver(
        acl_transport,
        signature_verifier,
        pin=policy.authority_roles.acl_decision,
        timeout_s=timeout_s,
        monotonic_ns=monotonic_ns,
    )
    ledger_head = TransportLedgerHeadAnchor(
        ledger_head_transport,
        timeout_s=timeout_s,
        monotonic_ns=monotonic_ns,
    )
    foundation_resolver = TransportFoundationResolver(
        foundation_transport,
        signature_verifier,
        pin=policy.foundation_artifact,
        timeout_s=timeout_s,
        monotonic_ns=monotonic_ns,
    )
    current_head_resolver = TransportCurrentHeadResolver(
        current_head_transport,
        signature_verifier,
        namespace=policy.current_head_namespace,
        pin=policy.current_head,
        timeout_s=timeout_s,
        monotonic_ns=monotonic_ns,
    )
    return ProductionAuthorityComposition(
        root,
        policy,
        signature_verifier=signature_verifier,
        trusted_clock=trusted_clock,
        operator_verifier=operator_verifier,
        acl_resolver=acl_resolver,
        ledger_head=ledger_head,
        foundation_resolver=foundation_resolver,
        current_head_resolver=current_head_resolver,
        scope_resolver=scope_resolver,
    )


def _verify_mapping_foundations(
    references: MappingFoundationReferences,
    artifacts: Mapping[FoundationKind, SignedFoundationArtifact],
    scope_resolver: DerivedScopeResolver,
) -> tuple[MappingAdmissionIdentity, MappingAdmissionScope]:
    if set(artifacts) != {kind for kind, _ in references.pairs()}:
        raise ProductionAuthorityCompositionError("MAPPING_FOUNDATION_SET_INCOMPLETE")
    try:
        proposal = MappingProposal.model_validate(artifacts["PROPOSAL"].payload)
        context = ProbeContext.model_validate(artifacts["CONTEXT"].payload)
        index = CapabilityCandidateIndex.model_validate(artifacts["CANDIDATE_INDEX"].payload)
        candidate = CapabilityCandidate.model_validate(artifacts["CANDIDATE"].payload)
        dsl, report = parse_document(artifacts["DSL"].payload)
        catalog = OperationPolicyCatalog.model_validate(artifacts["TOOL_CATALOG"].payload)
    except ValueError as exc:
        raise ProductionAuthorityCompositionError("MAPPING_FOUNDATION_PAYLOAD_INVALID") from exc
    if dsl is None or not report.ok:
        raise ProductionAuthorityCompositionError("MAPPING_FOUNDATION_DSL_INVALID")
    index.verify()
    proposal.verify()
    domain_digests = {
        "PROPOSAL": proposal.proposal_digest,
        "CONTEXT": context_digest(context),
        "CANDIDATE_INDEX": "sha256:" + index.index_digest,
        "CANDIDATE": mapping_digest(candidate),
        "DSL": dsl_digest(dsl),
        "EVIDENCE": context.evidence_digest,
        "TOOL_CATALOG": catalog.catalog_digest,
    }
    if any(artifacts[kind].artifact_digest != digest for kind, digest in domain_digests.items()):
        raise ProductionAuthorityCompositionError("MAPPING_FOUNDATION_DOMAIN_DIGEST_MISMATCH")
    target_id = proposal.target_id
    target_fingerprint = proposal.target_fingerprint
    if any(
        artifact.target_id != target_id
        or artifact.target_fingerprint != target_fingerprint
        for artifact in artifacts.values()
    ):
        raise ProductionAuthorityCompositionError("MAPPING_FOUNDATION_TARGET_MISMATCH")
    if (
        references.journey_session_id != proposal.journey_session_id
        or context.robot_id != target_id
        or context.target_fingerprint != target_fingerprint
        or index.robot_id != target_id
        or index.target_fingerprint != target_fingerprint
        or catalog.target_id != target_id
        or catalog.target_fingerprint != target_fingerprint
        or dsl.target.robot_id != target_id
        or dsl.target.evidence_digest != context.evidence_digest
        or index.context_digest != domain_digests["CONTEXT"]
        or index.evidence_digest != context.evidence_digest
        or candidate not in index.candidates
        or candidate.candidate_id != proposal.candidate_id
        or candidate.operation != proposal.operation
        or dsl.tool_id != proposal.operation
        or proposal.candidate_index_digest != domain_digests["CANDIDATE_INDEX"]
        or proposal.candidate_digest != domain_digests["CANDIDATE"]
        or proposal.dsl_digest != domain_digests["DSL"]
        or proposal.context_digest != domain_digests["CONTEXT"]
        or proposal.evidence_digest != domain_digests["EVIDENCE"]
        or proposal.available_tool_catalog_digest != domain_digests["TOOL_CATALOG"]
    ):
        raise ProductionAuthorityCompositionError("MAPPING_FOUNDATION_IDENTITY_MISMATCH")
    derived_scope = scope_resolver.derive(dsl, catalog)
    if proposal.scope != derived_scope:
        raise ProductionAuthorityCompositionError("MAPPING_FOUNDATION_SCOPE_MISMATCH")
    return proposal.admission_identity(), derived_scope


def _foundation_set_digest(artifacts: list[SignedFoundationArtifact] | tuple[SignedFoundationArtifact, ...]) -> str:
    return authority_digest(
        {
            "artifacts": [
                {
                    "artifact_kind": item.artifact_kind,
                    "artifact_ref": item.artifact_ref,
                    "artifact_digest": item.artifact_digest,
                    "content_digest": item.content_digest,
                    "immutable_revision": item.immutable_revision,
                    "target_id": item.target_id,
                    "target_fingerprint": item.target_fingerprint,
                }
                for item in sorted(artifacts, key=lambda artifact: artifact.artifact_kind)
            ]
        }
    )


def _current_head_set_digest(heads: tuple[SignedCurrentHead, ...] | list[SignedCurrentHead]) -> str:
    return authority_digest(
        {
            "heads": [
                {
                    "artifact_kind": item.artifact_kind,
                    "artifact_ref": item.artifact_ref,
                    "head_digest": item.head_digest,
                }
                for item in sorted(heads, key=lambda head: head.artifact_kind)
            ]
        }
    )


def _require_short_interval(
    issued_at: datetime,
    expires_at: datetime,
    *,
    label: str,
    maximum_s: int = MAX_AUTHORITY_EVIDENCE_TTL_S,
) -> None:
    _require_aware_utc(issued_at, label=f"{label} issued_at")
    _require_aware_utc(expires_at, label=f"{label} expires_at")
    if expires_at <= issued_at or expires_at - issued_at > timedelta(seconds=maximum_s):
        raise ValueError(f"{label} lifetime is invalid")


def _require_foundations_active(
    artifacts: list[SignedFoundationArtifact]
    | tuple[SignedFoundationArtifact, ...],
    heads: list[SignedCurrentHead] | tuple[SignedCurrentHead, ...],
    *,
    now: datetime,
) -> None:
    effective_now = _require_aware_utc(now, label="foundation active time")
    if any(
        effective_now < artifact.issued_at or effective_now >= artifact.expires_at
        for artifact in artifacts
    ):
        raise ProductionAuthorityCompositionError("FOUNDATION_ARTIFACT_EXPIRED")
    if any(
        effective_now < head.witnessed_at or effective_now >= head.expires_at
        for head in heads
    ):
        raise ProductionAuthorityCompositionError("CURRENT_HEAD_WITNESS_EXPIRED")


def _validated_timeout(value: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0.01 <= value <= 30:
        raise ValueError("provider timeout must be between 0.01 and 30 seconds")
    return float(value)


__all__ = [
    "CURRENT_HEAD_WITNESS_SCHEMA_VERSION",
    "FOUNDATION_ARTIFACT_SCHEMA_VERSION",
    "MAPPING_FOUNDATION_REFERENCES_SCHEMA_VERSION",
    "OPERATION_POLICY_CATALOG_SCHEMA_VERSION",
    "PREPARED_MAPPING_CONFIRMATION_SCHEMA_VERSION",
    "PRODUCTION_AUTHORITY_COMPOSITION_SCHEMA_VERSION",
    "TRUSTED_TIME_WITNESS_SCHEMA_VERSION",
    "BoundOperatorAssertionVerifier",
    "BoundedAuthorityJsonTransport",
    "DerivedScopeResolver",
    "FoundationKind",
    "MappingFoundationReferences",
    "OperationPolicy",
    "OperationPolicyCatalog",
    "PreparedMappingConfirmation",
    "ProductionAuthorityComposition",
    "ProductionAuthorityCompositionError",
    "ProductionAuthorityCompositionPolicy",
    "ResolvedMappingFoundations",
    "SignedCurrentHead",
    "SignedFoundationArtifact",
    "TransportAclDecisionResolver",
    "TransportCurrentHeadResolver",
    "TransportFoundationResolver",
    "TransportLedgerHeadAnchor",
    "TransportSignatureVerifier",
    "TransportTrustedClock",
    "TrustedTimeWitness",
    "compose_production_mapping_authority",
    "current_head_state_digest",
]
