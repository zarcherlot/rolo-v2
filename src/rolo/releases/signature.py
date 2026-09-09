"""Target-owned signature verification contracts for Release mutations.

This module intentionally provides no signer and contains no key material.
Production callers must inject a verifier backed by the target's trust store.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from typing import Any, Literal, Protocol

from pydantic import Field

from rolo.dsl.models import StrictModel

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_IDENTIFIER = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"
PRODUCTION_TARGET_SIGNATURE_AUTHORITY = "PRODUCTION_EXTERNAL"
TargetSignatureAlgorithm = Literal["EdDSA", "ES256", "RS256"]


class ReleaseSignatureError(ValueError):
    """A target signature is missing, malformed, or untrusted."""


class TargetReleaseSignature(StrictModel):
    """Detached target signature over one canonical Release statement."""

    schema_version: Literal["rolo-target-release-signature/v1"] = (
        "rolo-target-release-signature/v1"
    )
    target_id: str = Field(pattern=_IDENTIFIER)
    key_id: str = Field(pattern=_IDENTIFIER)
    algorithm: TargetSignatureAlgorithm
    signed_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    signature: str = Field(pattern=r"^[A-Za-z0-9_-]{32,8192}$")


class TargetSignatureVerification(StrictModel):
    """Bound result from a deployment-owned target trust provider."""

    schema_version: Literal["rolo-target-signature-verification/v1"] = (
        "rolo-target-signature-verification/v1"
    )
    provider_id: str = Field(pattern=_IDENTIFIER)
    authority_class: Literal["PRODUCTION_EXTERNAL"]
    target_id: str = Field(pattern=_IDENTIFIER)
    key_id: str = Field(pattern=_IDENTIFIER)
    algorithm: TargetSignatureAlgorithm
    signed_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    message_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    trust_root_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    key_status: Literal["ACTIVE", "REVOKED", "UNKNOWN"]
    status: Literal["VERIFIED", "REJECTED"]


class TargetSignatureVerifier(Protocol):
    """SPI implemented by a target trust provider; never by this package."""

    provider_id: str
    authority_class: str

    def verify(
        self,
        *,
        target_id: str,
        key_id: str,
        algorithm: TargetSignatureAlgorithm,
        message: bytes,
        message_digest: str,
        signed_digest: str,
        signature: str,
    ) -> TargetSignatureVerification: ...


class TargetReleaseSigner(Protocol):
    """SPI implemented by a target-owned signing provider.

    The statement is the complete CAS-bound Catalog mutation.  This package
    deliberately owns no signing key and never accepts a signer or signature
    from an individual publication request.
    """

    provider_id: str
    authority_class: str

    def sign(
        self,
        *,
        target_id: str,
        statement: Mapping[str, Any],
    ) -> TargetReleaseSignature: ...


def canonical_statement(statement: Mapping[str, Any]) -> bytes:
    """Encode the exact bytes a target signer and verifier bind."""

    return json.dumps(
        dict(statement),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def statement_digest(statement: Mapping[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(canonical_statement(statement)).hexdigest()


def signature_message(
    statement: Mapping[str, Any],
    *,
    target_id: str,
    key_id: str,
    algorithm: TargetSignatureAlgorithm,
) -> bytes:
    """Bind target/key/algorithm metadata as well as the signed statement."""

    return canonical_statement(
        {
            "schema_version": "rolo-target-release-signature-message/v1",
            "target_id": target_id,
            "key_id": key_id,
            "algorithm": algorithm,
            "signed_digest": statement_digest(statement),
            "statement": dict(statement),
        }
    )


def require_target_signature(
    statement: Mapping[str, Any],
    signature: TargetReleaseSignature | Mapping[str, Any] | None,
    verifier: TargetSignatureVerifier | None,
    *,
    expected_target_id: str,
) -> TargetReleaseSignature:
    """Validate identity, digest, and verifier authority for one statement."""

    if signature is None:
        raise ReleaseSignatureError("RELEASE_TARGET_SIGNATURE_REQUIRED")
    try:
        candidate = TargetReleaseSignature.model_validate(
            signature.model_dump(mode="python")
            if isinstance(signature, TargetReleaseSignature)
            else signature
        )
    except ValueError as exc:
        raise ReleaseSignatureError("RELEASE_TARGET_SIGNATURE_INVALID") from exc
    if candidate.target_id != expected_target_id:
        raise ReleaseSignatureError("RELEASE_TARGET_SIGNATURE_IDENTITY_MISMATCH")
    expected_digest = statement_digest(statement)
    if not _DIGEST.fullmatch(candidate.signed_digest) or candidate.signed_digest != expected_digest:
        raise ReleaseSignatureError("RELEASE_TARGET_SIGNATURE_DIGEST_MISMATCH")
    if verifier is None:
        raise ReleaseSignatureError("RELEASE_TARGET_SIGNATURE_VERIFIER_REQUIRED")
    if (
        getattr(verifier, "authority_class", None)
        != PRODUCTION_TARGET_SIGNATURE_AUTHORITY
        or re.fullmatch(_IDENTIFIER, str(getattr(verifier, "provider_id", "")))
        is None
    ):
        raise ReleaseSignatureError("RELEASE_TARGET_SIGNATURE_VERIFIER_UNTRUSTED")
    message = signature_message(
        statement,
        target_id=candidate.target_id,
        key_id=candidate.key_id,
        algorithm=candidate.algorithm,
    )
    message_digest = "sha256:" + hashlib.sha256(message).hexdigest()
    try:
        raw_verification = verifier.verify(
            target_id=candidate.target_id,
            key_id=candidate.key_id,
            algorithm=candidate.algorithm,
            message=message,
            message_digest=message_digest,
            signed_digest=expected_digest,
            signature=candidate.signature,
        )
        verification = TargetSignatureVerification.model_validate(
            raw_verification.model_dump(mode="python")
            if isinstance(raw_verification, TargetSignatureVerification)
            else raw_verification
        )
    except Exception as exc:  # noqa: BLE001 - authority providers fail closed
        raise ReleaseSignatureError("RELEASE_TARGET_SIGNATURE_VERIFICATION_FAILED") from exc
    if (
        verification.provider_id != verifier.provider_id
        or verification.authority_class != PRODUCTION_TARGET_SIGNATURE_AUTHORITY
        or verification.target_id != candidate.target_id
        or verification.key_id != candidate.key_id
        or verification.algorithm != candidate.algorithm
        or verification.signed_digest != expected_digest
        or verification.message_digest != message_digest
    ):
        raise ReleaseSignatureError("RELEASE_TARGET_SIGNATURE_VERIFICATION_MISMATCH")
    if verification.status != "VERIFIED" or verification.key_status != "ACTIVE":
        raise ReleaseSignatureError("RELEASE_TARGET_SIGNATURE_UNTRUSTED")
    return candidate


__all__ = [
    "ReleaseSignatureError",
    "PRODUCTION_TARGET_SIGNATURE_AUTHORITY",
    "TargetReleaseSignature",
    "TargetReleaseSigner",
    "TargetSignatureAlgorithm",
    "TargetSignatureVerification",
    "TargetSignatureVerifier",
    "canonical_statement",
    "require_target_signature",
    "signature_message",
    "statement_digest",
]
