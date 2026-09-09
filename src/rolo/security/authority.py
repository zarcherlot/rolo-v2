"""Production authority contracts for signed identity, ACL, and ledger heads.

This module deliberately contains no keys and no permissive in-process
provider.  Deployments inject adapters backed by their IdP/KMS/JWKS service
and by an independently durable monotonic-head service.  The admission layer
still validates every returned field so a provider response cannot widen the
signed command or its reviewed Mapping scope.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from datetime import datetime, timedelta
from typing import Any, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, field_validator, model_validator

OPERATOR_ASSERTION_SCHEMA_VERSION = "rolo-operator-assertion/v1"
ACL_DECISION_SCHEMA_VERSION = "rolo-acl-decision/v1"
LEDGER_HEAD_SCHEMA_VERSION = "rolo-ledger-head/v1"
PRODUCTION_AUTHORITY_CLASS = "PRODUCTION_EXTERNAL"
MAPPING_AUTHORITY_AUDIENCE = "rolo-mapping-admission"
MAX_AUTHORITY_EVIDENCE_TTL_S = 300
MAX_LEDGER_HEAD_WITNESS_TTL_S = 30
MAX_SIGNATURE_VERIFICATION_AGE_S = 30

_DIGEST_PATTERN = r"^sha256:[0-9a-f]{64}$"
_IDENTIFIER_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"
_SIGNATURE_PATTERN = r"^[A-Za-z0-9_-]{32,2048}$"

SignatureAlgorithm = Literal["EdDSA", "ES256", "RS256"]
SignaturePurpose = Literal[
    "OPERATOR_ASSERTION",
    "ACL_DECISION",
    "LEDGER_HEAD",
    "TRUSTED_TIME",
    "FOUNDATION_ARTIFACT",
    "CURRENT_HEAD",
]
_JSON_MAPPING_ADAPTER = TypeAdapter(dict[str, Any])


class AuthorityModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class AuthorityProviderUnavailableError(RuntimeError):
    """A trusted external authority could not answer before its deadline."""


class AuthorityRolePin(AuthorityModel):
    """Deployment-owned trust assignment for exactly one authority purpose."""

    purpose: SignaturePurpose
    issuer_id: str = Field(min_length=1, max_length=256)
    key_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    trust_root_digest: str = Field(pattern=_DIGEST_PATTERN)

    @field_validator("issuer_id")
    @classmethod
    def normalized_issuer(cls, value: str) -> str:
        if value != value.strip() or any(
            ord(character) < 33 or ord(character) == 127 for character in value
        ):
            raise ValueError("authority role issuer must be normalized and printable")
        return value


class AuthorityRolePolicy(AuthorityModel):
    """Pinned, mutually isolated operator, ACL, and ledger-head roles."""

    operator_assertion: AuthorityRolePin
    acl_decision: AuthorityRolePin
    ledger_head: AuthorityRolePin

    @model_validator(mode="after")
    def verify_purposes_and_isolation(self) -> AuthorityRolePolicy:
        pins = (
            self.operator_assertion,
            self.acl_decision,
            self.ledger_head,
        )
        expected = (
            "OPERATOR_ASSERTION",
            "ACL_DECISION",
            "LEDGER_HEAD",
        )
        if tuple(pin.purpose for pin in pins) != expected:
            raise ValueError("authority role pin purpose mismatch")
        for field in ("issuer_id", "key_id", "trust_root_digest"):
            values = {getattr(pin, field) for pin in pins}
            if len(values) != len(pins):
                raise ValueError(f"authority role {field} values must be mutually isolated")
        return self

    def pin_for(self, purpose: SignaturePurpose) -> AuthorityRolePin:
        return {
            "OPERATOR_ASSERTION": self.operator_assertion,
            "ACL_DECISION": self.acl_decision,
            "LEDGER_HEAD": self.ledger_head,
        }[purpose]


def canonical_authority_bytes(
    value: Mapping[str, Any] | BaseModel,
    *,
    exclude: frozenset[str] = frozenset(),
) -> bytes:
    """Return canonical UTF-8 bytes for an authority artifact."""

    payload = (
        value.model_dump(mode="json", exclude=exclude)
        if isinstance(value, BaseModel)
        else _JSON_MAPPING_ADAPTER.dump_python(
            {key: item for key, item in value.items() if key not in exclude},
            mode="json",
        )
    )
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def authority_digest(
    value: Mapping[str, Any] | BaseModel,
    *,
    exclude: frozenset[str] = frozenset(),
) -> str:
    return "sha256:" + hashlib.sha256(
        canonical_authority_bytes(value, exclude=exclude)
    ).hexdigest()


def authority_signed_payload_bytes(value: Mapping[str, Any] | BaseModel) -> bytes:
    return canonical_authority_bytes(
        value,
        exclude=frozenset({"payload_digest", "signature"}),
    )


def authority_signed_payload_digest(value: Mapping[str, Any] | BaseModel) -> str:
    return authority_digest(
        value,
        exclude=frozenset({"payload_digest", "signature"}),
    )


def ledger_anchor_digest(value: Mapping[str, Any] | BaseModel) -> str:
    """Digest the durable head state, excluding its per-request witness."""

    fields = (
        "schema_version",
        "anchor_provider_id",
        "ledger_id",
        "epoch",
        "sequence",
        "head_digest",
        "previous_anchor_digest",
        "recorded_at",
    )
    source = value.model_dump(mode="python") if isinstance(value, BaseModel) else value
    return authority_digest({field: source[field] for field in fields})


def _validate_utc_interval(
    issued_at: datetime,
    expires_at: datetime,
    *,
    label: str,
) -> None:
    for field, value in (("issued_at", issued_at), ("expires_at", expires_at)):
        if value.tzinfo is None or value.utcoffset() != timedelta(0):
            raise ValueError(f"{label} {field} must be an aware UTC timestamp")
    if expires_at <= issued_at:
        raise ValueError(f"{label} expires_at must be after issued_at")
    if expires_at - issued_at > timedelta(seconds=MAX_AUTHORITY_EVIDENCE_TTL_S):
        raise ValueError(f"{label} lifetime exceeds the maximum")


def _validate_signed_payload(value: BaseModel, *, label: str) -> None:
    if value.model_dump(mode="python").get(
        "payload_digest"
    ) != authority_signed_payload_digest(value):
        raise ValueError(f"{label} payload digest mismatch")


class SignedOperatorAssertion(AuthorityModel):
    """Short-lived externally signed proof of one human operator identity."""

    schema_version: Literal["rolo-operator-assertion/v1"]
    issuer_id: str = Field(min_length=1, max_length=256)
    principal_id: str = Field(min_length=1, max_length=256)
    key_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    algorithm: SignatureAlgorithm
    audience: Literal["rolo-mapping-admission"]
    nonce: str = Field(pattern=_IDENTIFIER_PATTERN)
    challenge_digest: str = Field(pattern=_DIGEST_PATTERN)
    authentication_method: Literal["MFA", "HARDWARE_KEY", "FEDERATED_MFA"]
    issued_at: datetime
    expires_at: datetime
    payload_digest: str = Field(pattern=_DIGEST_PATTERN)
    signature: str = Field(pattern=_SIGNATURE_PATTERN)

    @field_validator("issuer_id", "principal_id")
    @classmethod
    def normalized_identity(cls, value: str) -> str:
        if value != value.strip() or any(
            ord(character) < 33 or ord(character) == 127 for character in value
        ):
            raise ValueError("authority identity must be normalized and printable")
        return value

    @model_validator(mode="after")
    def verify_shape_and_digest(self) -> SignedOperatorAssertion:
        _validate_utc_interval(
            self.issued_at,
            self.expires_at,
            label="operator assertion",
        )
        _validate_signed_payload(self, label="operator assertion")
        return self


class SignedAclDecision(AuthorityModel):
    """Short-lived signed ACL result bound to one exact admission command."""

    schema_version: Literal["rolo-acl-decision/v1"]
    authority_id: str = Field(min_length=1, max_length=256)
    authorization_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    subject_issuer_id: str = Field(min_length=1, max_length=256)
    subject_principal_id: str = Field(min_length=1, max_length=256)
    key_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    algorithm: SignatureAlgorithm
    action: Literal["mapping.confirm", "mapping.reject", "mapping.cancel"]
    resource_digest: str = Field(pattern=_DIGEST_PATTERN)
    scope_digest: str = Field(pattern=_DIGEST_PATTERN)
    request_digest: str = Field(pattern=_DIGEST_PATTERN)
    effect: Literal["ALLOW", "DENY"]
    policy_digest: str = Field(pattern=_DIGEST_PATTERN)
    policy_revision: int = Field(ge=1)
    max_confirmation_ttl_s: int = Field(ge=0, le=86_400)
    issued_at: datetime
    expires_at: datetime
    payload_digest: str = Field(pattern=_DIGEST_PATTERN)
    signature: str = Field(pattern=_SIGNATURE_PATTERN)

    @field_validator(
        "authority_id",
        "subject_issuer_id",
        "subject_principal_id",
    )
    @classmethod
    def normalized_authority_text(cls, value: str) -> str:
        if value != value.strip() or any(
            ord(character) < 33 or ord(character) == 127 for character in value
        ):
            raise ValueError("ACL identity must be normalized and printable")
        return value

    @model_validator(mode="after")
    def verify_shape_and_digest(self) -> SignedAclDecision:
        _validate_utc_interval(
            self.issued_at,
            self.expires_at,
            label="ACL decision",
        )
        _validate_signed_payload(self, label="ACL decision")
        return self


class SignedLedgerHead(AuthorityModel):
    """Externally persisted, signed monotonic witness for one local ledger."""

    schema_version: Literal["rolo-ledger-head/v1"]
    anchor_provider_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    ledger_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    epoch: int = Field(ge=1)
    sequence: int = Field(ge=0)
    head_digest: str | None = Field(pattern=_DIGEST_PATTERN)
    previous_anchor_digest: str | None = Field(pattern=_DIGEST_PATTERN)
    recorded_at: datetime
    anchor_digest: str = Field(pattern=_DIGEST_PATTERN)
    challenge_digest: str = Field(pattern=_DIGEST_PATTERN)
    witnessed_at: datetime
    expires_at: datetime
    issuer_id: str = Field(min_length=1, max_length=256)
    key_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    algorithm: SignatureAlgorithm
    payload_digest: str = Field(pattern=_DIGEST_PATTERN)
    signature: str = Field(pattern=_SIGNATURE_PATTERN)

    @field_validator("issuer_id")
    @classmethod
    def normalized_issuer(cls, value: str) -> str:
        if value != value.strip() or any(
            ord(character) < 33 or ord(character) == 127 for character in value
        ):
            raise ValueError("ledger issuer must be normalized and printable")
        return value

    @model_validator(mode="after")
    def verify_shape_and_digest(self) -> SignedLedgerHead:
        if (
            self.recorded_at.tzinfo is None
            or self.recorded_at.utcoffset() != timedelta(0)
        ):
            raise ValueError("ledger head recorded_at must be an aware UTC timestamp")
        _validate_utc_interval(
            self.witnessed_at,
            self.expires_at,
            label="ledger head witness",
        )
        if self.expires_at - self.witnessed_at > timedelta(
            seconds=MAX_LEDGER_HEAD_WITNESS_TTL_S
        ):
            raise ValueError("ledger head witness lifetime exceeds the maximum")
        if self.recorded_at > self.witnessed_at:
            raise ValueError("ledger head cannot be witnessed before it was recorded")
        if self.sequence == 0:
            if self.head_digest is not None or self.previous_anchor_digest is not None:
                raise ValueError("genesis ledger head cannot reference ledger content")
        elif self.head_digest is None or self.previous_anchor_digest is None:
            raise ValueError("non-genesis ledger head requires head and predecessor digests")
        if self.anchor_digest != ledger_anchor_digest(self):
            raise ValueError("ledger anchor digest mismatch")
        _validate_signed_payload(self, label="ledger head")
        return self


class SignatureVerification(AuthorityModel):
    """Typed result returned by a configured external signature verifier."""

    provider_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    authority_class: Literal["PRODUCTION_EXTERNAL"]
    purpose: SignaturePurpose
    issuer_id: str = Field(min_length=1, max_length=256)
    key_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    algorithm: SignatureAlgorithm
    payload_digest: str = Field(pattern=_DIGEST_PATTERN)
    trust_root_digest: str = Field(pattern=_DIGEST_PATTERN)
    key_status: Literal["ACTIVE"]
    status: Literal["VERIFIED"]
    verified_at: datetime

    @model_validator(mode="after")
    def verify_utc(self) -> SignatureVerification:
        if self.verified_at.tzinfo is None or self.verified_at.utcoffset() != timedelta(0):
            raise ValueError("signature verification time must be aware UTC")
        return self


class AuthoritySignatureVerifier(Protocol):
    """SPI for a deployment-owned IdP/JWKS/KMS signature verifier.

    Adapters must impose a bounded network deadline and translate timeout or
    dependency outages to :class:`AuthorityProviderUnavailableError`.
    Cryptographically invalid or untrusted evidence must use another error so
    admission can distinguish availability from a denied trust decision.
    """

    provider_id: str
    authority_class: str

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
        """Verify signature, trust root, key activity and revocation state."""


class LedgerHeadAnchorProvider(Protocol):
    """SPI for a deployment-owned monotonic head service.

    ``read_head`` must return the latest head, must not return an epoch below
    ``minimum_epoch``, and must sign the supplied one-time challenge in a fresh
    witness. ``advance`` must use compare-and-swap semantics against the stable
    ``expected_anchor_digest`` and return the newly signed authoritative head.
    Adapters use :class:`AuthorityProviderUnavailableError` for bounded
    deadline/dependency failures.
    """

    provider_id: str
    authority_class: str

    def read_head(
        self,
        ledger_id: str,
        *,
        minimum_epoch: int,
        challenge_digest: str,
        now: datetime,
    ) -> SignedLedgerHead:
        """Return the latest externally durable head."""

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
        """Atomically advance exactly one sequence or fail."""


__all__ = [
    "ACL_DECISION_SCHEMA_VERSION",
    "LEDGER_HEAD_SCHEMA_VERSION",
    "MAPPING_AUTHORITY_AUDIENCE",
    "MAX_AUTHORITY_EVIDENCE_TTL_S",
    "MAX_LEDGER_HEAD_WITNESS_TTL_S",
    "MAX_SIGNATURE_VERIFICATION_AGE_S",
    "OPERATOR_ASSERTION_SCHEMA_VERSION",
    "PRODUCTION_AUTHORITY_CLASS",
    "AuthoritySignatureVerifier",
    "AuthorityRolePin",
    "AuthorityRolePolicy",
    "AuthorityProviderUnavailableError",
    "LedgerHeadAnchorProvider",
    "SignatureVerification",
    "SignedAclDecision",
    "SignedLedgerHead",
    "SignedOperatorAssertion",
    "authority_digest",
    "authority_signed_payload_bytes",
    "authority_signed_payload_digest",
    "canonical_authority_bytes",
    "ledger_anchor_digest",
]
