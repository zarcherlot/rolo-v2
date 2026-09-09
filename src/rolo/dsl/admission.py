"""Digest-bound, append-only admission for confirmed Mapping proposals.

The objects in this module are deliberately independent of compiler, release,
and targetd entrypoints.  Those consumers must provide an identity resolved
from their own trusted artifacts and ask :class:`MappingAdmissionGate` to
resolve the receipt from this ledger.  A caller-supplied, self-consistent JSON
receipt is never admission authority.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import stat
from collections.abc import Callable, Mapping
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Literal

from pydantic import Field, field_validator, model_validator

from rolo.core.persistence import atomic_write_text, interprocess_lock
from rolo.security.authority import (
    MAX_SIGNATURE_VERIFICATION_AGE_S,
    PRODUCTION_AUTHORITY_CLASS,
    AuthorityProviderUnavailableError,
    AuthorityRolePolicy,
    AuthoritySignatureVerifier,
    LedgerHeadAnchorProvider,
    SignatureVerification,
    SignedAclDecision,
    SignedLedgerHead,
    SignedOperatorAssertion,
    authority_signed_payload_bytes,
)

from .contracts import (
    MAPPING_AUTHORITY_COMMAND_SCHEMA_VERSION,
    MAPPING_AUTHORITY_PENDING_SCHEMA_VERSION,
    MAPPING_AUTHORITY_RECEIPT_SCHEMA_VERSION,
    MAPPING_CONFIRMATION_RECEIPT_SCHEMA_VERSION,
)
from .models import OperationKind, StrictModel
from .parser import loads_unique_json

MAX_CONFIRMATION_TTL_S = 86_400
MAX_MAPPING_LEDGER_BYTES = 16 * 1024 * 1024
MAX_MAPPING_AUTHORITY_LEDGER_BYTES = 64 * 1024 * 1024
MAX_MAPPING_RECEIPT_BYTES = 64 * 1024
MAX_MAPPING_AUTHORITY_RECEIPT_BYTES = 256 * 1024
MAX_MAPPING_LEDGER_RECEIPTS = 4096
MAX_MAPPING_PENDING_BYTES = 64 * 1024
_DIGEST_PATTERN = r"^sha256:[0-9a-f]{64}$"
_IDENTIFIER_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"


class MappingAdmissionError(ValueError):
    """A stable fail-closed Mapping admission diagnostic."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class MappingAdmissionScope(StrictModel):
    """The exact callable surface reviewed by the confirming actor."""

    tool_id: str = Field(pattern=r"^[a-z][a-z0-9_.-]{1,127}$")
    operation_kind: OperationKind
    operations: tuple[str, ...] = Field(min_length=1, max_length=32)
    access: Literal["read", "experimental_write"]
    risk: Literal["R0", "R1", "R2", "R3"]

    @field_validator("operations")
    @classmethod
    def stable_operations(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if any(not isinstance(item, str) or not item or item != item.strip() or len(item) > 256 for item in value):
            raise ValueError("Mapping admission operations must be normalized strings")
        return tuple(sorted(set(value)))


class MappingAdmissionIdentity(StrictModel):
    """Immutable identity that every post-confirmation consumer must match."""

    journey_session_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    target_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    target_fingerprint: str = Field(min_length=1, max_length=256)
    target_identity_digest: str = Field(pattern=_DIGEST_PATTERN)
    candidate_index_digest: str = Field(pattern=_DIGEST_PATTERN)
    candidate_digest: str = Field(pattern=_DIGEST_PATTERN)
    proposal_digest: str = Field(pattern=_DIGEST_PATTERN)
    dsl_digest: str = Field(pattern=_DIGEST_PATTERN)
    context_digest: str = Field(pattern=_DIGEST_PATTERN)
    evidence_digest: str = Field(pattern=_DIGEST_PATTERN)
    available_tool_catalog_digest: str = Field(pattern=_DIGEST_PATTERN)
    scope: MappingAdmissionScope
    scope_digest: str = Field(pattern=_DIGEST_PATTERN)

    @field_validator("target_fingerprint")
    @classmethod
    def known_target_fingerprint(cls, value: str) -> str:
        if value != value.strip() or value.upper() == "UNKNOWN":
            raise ValueError("Mapping admission requires a known target fingerprint")
        return value

    @model_validator(mode="after")
    def verify_derived_digests(self) -> MappingAdmissionIdentity:
        if self.target_identity_digest != mapping_target_identity_digest(self.target_id, self.target_fingerprint):
            raise ValueError("target identity digest does not match target")
        if self.scope_digest != mapping_scope_digest(self.scope):
            raise ValueError("scope digest does not match scope")
        return self

    @classmethod
    def build(
        cls,
        *,
        journey_session_id: str,
        target_id: str,
        target_fingerprint: str,
        candidate_index_digest: str,
        candidate_digest: str,
        proposal_digest: str,
        dsl_digest: str,
        context_digest: str,
        evidence_digest: str,
        available_tool_catalog_digest: str,
        scope: MappingAdmissionScope,
    ) -> MappingAdmissionIdentity:
        """Build an identity while computing its two derived digests."""

        return cls(
            journey_session_id=journey_session_id,
            target_id=target_id,
            target_fingerprint=target_fingerprint,
            target_identity_digest=mapping_target_identity_digest(target_id, target_fingerprint),
            candidate_index_digest=candidate_index_digest,
            candidate_digest=candidate_digest,
            proposal_digest=proposal_digest,
            dsl_digest=dsl_digest,
            context_digest=context_digest,
            evidence_digest=evidence_digest,
            available_tool_catalog_digest=available_tool_catalog_digest,
            scope=scope,
            scope_digest=mapping_scope_digest(scope),
        )


class MappingConfirmationReceipt(MappingAdmissionIdentity):
    """One immutable decision in the Mapping confirmation hash chain."""

    # No default is intentional.  Missing versions must never be backfilled at
    # this security boundary.
    schema_version: Literal["rolo-mapping-confirmation-receipt/v1"]
    sequence: int = Field(ge=1)
    decision_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    actor_id: str = Field(min_length=1, max_length=256)
    decision: Literal["CONFIRMED", "REJECTED", "CANCELLED"]
    decided_at: datetime
    expires_at: datetime | None
    supersedes_receipt_digest: str | None = Field(pattern=_DIGEST_PATTERN)
    previous_receipt_digest: str | None = Field(pattern=_DIGEST_PATTERN)
    receipt_digest: str = Field(pattern=_DIGEST_PATTERN)

    @field_validator("actor_id")
    @classmethod
    def normalized_actor(cls, value: str) -> str:
        if value != value.strip() or any(ord(character) < 32 for character in value):
            raise ValueError("actor_id must be a normalized printable value")
        return value

    @model_validator(mode="after")
    def verify_decision_and_digest(self) -> MappingConfirmationReceipt:
        if self.decided_at.tzinfo is None or self.decided_at.utcoffset() != timedelta(0):
            raise ValueError("decided_at must be an aware UTC timestamp")
        if self.expires_at is not None and (self.expires_at.tzinfo is None or self.expires_at.utcoffset() != timedelta(0)):
            raise ValueError("expires_at must be an aware UTC timestamp")
        if self.decision == "CONFIRMED":
            if self.expires_at is None or self.expires_at <= self.decided_at:
                raise ValueError("CONFIRMED receipt requires a future expires_at")
            if self.expires_at - self.decided_at > timedelta(seconds=MAX_CONFIRMATION_TTL_S):
                raise ValueError("Mapping confirmation TTL exceeds the maximum")
            if self.supersedes_receipt_digest is not None:
                raise ValueError("CONFIRMED receipt cannot supersede another receipt")
        else:
            if self.expires_at is not None:
                raise ValueError("non-CONFIRMED receipt cannot carry expires_at")
            if self.decision == "CANCELLED":
                if self.supersedes_receipt_digest is None:
                    raise ValueError("CANCELLED receipt must identify its confirmation")
            elif self.supersedes_receipt_digest is not None:
                raise ValueError("REJECTED receipt cannot supersede another receipt")
        if self.sequence == 1 and self.previous_receipt_digest is not None:
            raise ValueError("first Mapping receipt cannot have a predecessor")
        if self.sequence > 1 and self.previous_receipt_digest is None:
            raise ValueError("non-first Mapping receipt requires a predecessor")
        if self.receipt_digest != mapping_confirmation_receipt_digest(self):
            raise ValueError("Mapping confirmation receipt digest mismatch")
        return self

    def admission_identity(self) -> MappingAdmissionIdentity:
        """Return the exact identity authorized or denied by this decision."""

        return MappingAdmissionIdentity.model_validate(
            self.model_dump(
                mode="python",
                include=set(MappingAdmissionIdentity.model_fields),
            )
        )

    @classmethod
    def build(
        cls,
        identity: MappingAdmissionIdentity,
        *,
        sequence: int,
        decision_id: str,
        actor_id: str,
        decision: Literal["CONFIRMED", "REJECTED", "CANCELLED"],
        decided_at: datetime,
        expires_at: datetime | None,
        supersedes_receipt_digest: str | None,
        previous_receipt_digest: str | None,
    ) -> MappingConfirmationReceipt:
        """Construct a receipt and bind its canonical digest."""

        identity_payload = identity.model_dump(mode="python")
        # ``model_construct`` deliberately skips coercion while the digest is
        # being calculated, so retain the already validated nested model.
        identity_payload["scope"] = identity.scope
        provisional = cls.model_construct(
            **identity_payload,
            schema_version=MAPPING_CONFIRMATION_RECEIPT_SCHEMA_VERSION,
            sequence=sequence,
            decision_id=decision_id,
            actor_id=actor_id,
            decision=decision,
            decided_at=decided_at,
            expires_at=expires_at,
            supersedes_receipt_digest=supersedes_receipt_digest,
            previous_receipt_digest=previous_receipt_digest,
            receipt_digest="sha256:" + "0" * 64,
        )
        payload = provisional.model_dump(mode="python")
        payload["receipt_digest"] = mapping_confirmation_receipt_digest(provisional)
        return cls.model_validate(payload)


class MappingAuthorityCommand(StrictModel):
    """Exact production command signed by both the operator and ACL authority."""

    schema_version: Literal["rolo-mapping-authority-command/v1"]
    ledger_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    decision_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    action: Literal["mapping.confirm", "mapping.reject", "mapping.cancel"]
    identity_digest: str = Field(pattern=_DIGEST_PATTERN)
    proposal_digest: str = Field(pattern=_DIGEST_PATTERN)
    scope_digest: str = Field(pattern=_DIGEST_PATTERN)
    confirmation_receipt_digest: str | None = Field(pattern=_DIGEST_PATTERN)
    requested_ttl_s: int | None = Field(ge=1, le=MAX_CONFIRMATION_TTL_S)
    command_digest: str = Field(pattern=_DIGEST_PATTERN)

    @model_validator(mode="after")
    def verify_action_and_digest(self) -> MappingAuthorityCommand:
        if self.action == "mapping.confirm":
            if self.requested_ttl_s is None or self.confirmation_receipt_digest is not None:
                raise ValueError("confirm command requires only requested_ttl_s")
        elif self.requested_ttl_s is not None:
            raise ValueError("non-confirm command cannot request a confirmation TTL")
        elif self.action == "mapping.cancel":
            if self.confirmation_receipt_digest is None:
                raise ValueError("cancel command requires a confirmation receipt")
        elif self.confirmation_receipt_digest is not None:
            raise ValueError("reject command cannot reference a confirmation receipt")
        if self.command_digest != mapping_authority_command_digest(self):
            raise ValueError("Mapping authority command digest mismatch")
        return self

    @classmethod
    def build(
        cls,
        identity: MappingAdmissionIdentity,
        *,
        ledger_id: str,
        decision_id: str,
        action: Literal["mapping.confirm", "mapping.reject", "mapping.cancel"],
        requested_ttl_s: int | None,
        confirmation_receipt_digest: str | None,
    ) -> MappingAuthorityCommand:
        provisional = cls.model_construct(
            schema_version=MAPPING_AUTHORITY_COMMAND_SCHEMA_VERSION,
            ledger_id=ledger_id,
            decision_id=decision_id,
            action=action,
            identity_digest=mapping_digest(identity),
            proposal_digest=identity.proposal_digest,
            scope_digest=identity.scope_digest,
            confirmation_receipt_digest=confirmation_receipt_digest,
            requested_ttl_s=requested_ttl_s,
            command_digest="sha256:" + "0" * 64,
        )
        payload = provisional.model_dump(mode="python")
        payload["command_digest"] = mapping_authority_command_digest(provisional)
        return cls.model_validate(payload)


class MappingAuthorityReceipt(StrictModel):
    """Local evidence for one externally authenticated and authorized append."""

    schema_version: Literal["rolo-mapping-authority-receipt/v1"]
    sequence: int = Field(ge=1)
    mapping_receipt_digest: str = Field(pattern=_DIGEST_PATTERN)
    previous_authority_receipt_digest: str | None = Field(pattern=_DIGEST_PATTERN)
    command: MappingAuthorityCommand
    operator_assertion: SignedOperatorAssertion
    acl_decision: SignedAclDecision
    operator_verification: SignatureVerification
    acl_verification: SignatureVerification
    anchor_provider_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    previous_anchor_epoch: int = Field(ge=1)
    previous_anchor_digest: str = Field(pattern=_DIGEST_PATTERN)
    authority_receipt_digest: str = Field(pattern=_DIGEST_PATTERN)

    @model_validator(mode="after")
    def verify_bindings_and_digest(self) -> MappingAuthorityReceipt:
        if self.sequence == 1 and self.previous_authority_receipt_digest is not None:
            raise ValueError("first Mapping authority receipt cannot have a predecessor")
        if self.sequence > 1 and self.previous_authority_receipt_digest is None:
            raise ValueError("non-first Mapping authority receipt requires a predecessor")
        if self.operator_assertion.challenge_digest != self.command.command_digest:
            raise ValueError("operator assertion is not bound to authority command")
        if self.acl_decision.request_digest != self.command.command_digest:
            raise ValueError("ACL decision is not bound to authority command")
        if self.acl_decision.subject_principal_id != self.operator_assertion.principal_id:
            raise ValueError("operator and ACL principals do not match")
        if self.acl_decision.subject_issuer_id != self.operator_assertion.issuer_id:
            raise ValueError("operator and ACL subject issuers do not match")
        if (
            self.acl_decision.authority_id == self.operator_assertion.issuer_id
            or self.acl_decision.key_id == self.operator_assertion.key_id
            or self.acl_verification.trust_root_digest
            == self.operator_verification.trust_root_digest
        ):
            raise ValueError("operator authentication and ACL roles are not isolated")
        if self.acl_decision.action != self.command.action:
            raise ValueError("ACL action does not match authority command")
        if self.acl_decision.resource_digest != self.command.proposal_digest:
            raise ValueError("ACL resource does not match authority command")
        if self.acl_decision.scope_digest != self.command.scope_digest:
            raise ValueError("ACL scope does not match authority command")
        if self.acl_decision.effect != "ALLOW":
            raise ValueError("authority receipt cannot persist a denied ACL decision")
        _verify_signature_result_binding(
            self.operator_verification,
            purpose="OPERATOR_ASSERTION",
            issuer_id=self.operator_assertion.issuer_id,
            key_id=self.operator_assertion.key_id,
            algorithm=self.operator_assertion.algorithm,
            payload_digest=self.operator_assertion.payload_digest,
        )
        _verify_signature_result_binding(
            self.acl_verification,
            purpose="ACL_DECISION",
            issuer_id=self.acl_decision.authority_id,
            key_id=self.acl_decision.key_id,
            algorithm=self.acl_decision.algorithm,
            payload_digest=self.acl_decision.payload_digest,
        )
        if self.authority_receipt_digest != mapping_authority_receipt_digest(self):
            raise ValueError("Mapping authority receipt digest mismatch")
        return self

    @classmethod
    def build(
        cls,
        *,
        sequence: int,
        mapping_receipt_digest: str,
        previous_authority_receipt_digest: str | None,
        command: MappingAuthorityCommand,
        operator_assertion: SignedOperatorAssertion,
        acl_decision: SignedAclDecision,
        operator_verification: SignatureVerification,
        acl_verification: SignatureVerification,
        anchor_provider_id: str,
        previous_anchor_epoch: int,
        previous_anchor_digest: str,
    ) -> MappingAuthorityReceipt:
        provisional = cls.model_construct(
            schema_version=MAPPING_AUTHORITY_RECEIPT_SCHEMA_VERSION,
            sequence=sequence,
            mapping_receipt_digest=mapping_receipt_digest,
            previous_authority_receipt_digest=previous_authority_receipt_digest,
            command=command,
            operator_assertion=operator_assertion,
            acl_decision=acl_decision,
            operator_verification=operator_verification,
            acl_verification=acl_verification,
            anchor_provider_id=anchor_provider_id,
            previous_anchor_epoch=previous_anchor_epoch,
            previous_anchor_digest=previous_anchor_digest,
            authority_receipt_digest="sha256:" + "0" * 64,
        )
        payload = provisional.model_dump(mode="python")
        payload["authority_receipt_digest"] = mapping_authority_receipt_digest(
            provisional
        )
        return cls.model_validate(payload)


class MappingAuthorityPending(StrictModel):
    """Crash-visible state for a non-atomic local-pair/anchor commit."""

    schema_version: Literal["rolo-mapping-authority-pending/v1"]
    ledger_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    phase: Literal[
        "PREPARED",
        "MAPPING_APPENDED",
        "LOCAL_PAIR_APPENDED",
        "ANCHOR_UNCERTAIN",
    ]
    sequence: int = Field(ge=1)
    mapping_receipt_digest: str = Field(pattern=_DIGEST_PATTERN)
    authority_receipt_digest: str = Field(pattern=_DIGEST_PATTERN)
    expected_anchor_epoch: int = Field(ge=1)
    expected_anchor_digest: str = Field(pattern=_DIGEST_PATTERN)
    next_head_digest: str = Field(pattern=_DIGEST_PATTERN)
    created_at: datetime
    updated_at: datetime
    pending_digest: str = Field(pattern=_DIGEST_PATTERN)

    @model_validator(mode="after")
    def verify_pending_state(self) -> MappingAuthorityPending:
        for field, value in (
            ("created_at", self.created_at),
            ("updated_at", self.updated_at),
        ):
            if value.tzinfo is None or value.utcoffset() != timedelta(0):
                raise ValueError(f"pending {field} must be an aware UTC timestamp")
        if self.updated_at < self.created_at:
            raise ValueError("pending updated_at cannot precede created_at")
        if self.next_head_digest != mapping_production_head_digest(
            self.mapping_receipt_digest,
            self.authority_receipt_digest,
        ):
            raise ValueError("pending production head digest mismatch")
        if self.pending_digest != mapping_authority_pending_digest(self):
            raise ValueError("Mapping authority pending digest mismatch")
        return self

    @classmethod
    def build(
        cls,
        *,
        ledger_id: str,
        phase: Literal[
            "PREPARED",
            "MAPPING_APPENDED",
            "LOCAL_PAIR_APPENDED",
            "ANCHOR_UNCERTAIN",
        ],
        sequence: int,
        mapping_receipt_digest: str,
        authority_receipt_digest: str,
        expected_anchor_epoch: int,
        expected_anchor_digest: str,
        created_at: datetime,
        updated_at: datetime,
    ) -> MappingAuthorityPending:
        provisional = cls.model_construct(
            schema_version=MAPPING_AUTHORITY_PENDING_SCHEMA_VERSION,
            ledger_id=ledger_id,
            phase=phase,
            sequence=sequence,
            mapping_receipt_digest=mapping_receipt_digest,
            authority_receipt_digest=authority_receipt_digest,
            expected_anchor_epoch=expected_anchor_epoch,
            expected_anchor_digest=expected_anchor_digest,
            next_head_digest=mapping_production_head_digest(
                mapping_receipt_digest,
                authority_receipt_digest,
            ),
            created_at=created_at,
            updated_at=updated_at,
            pending_digest="sha256:" + "0" * 64,
        )
        payload = provisional.model_dump(mode="python")
        payload["pending_digest"] = mapping_authority_pending_digest(provisional)
        return cls.model_validate(payload)

    def with_phase(
        self,
        phase: Literal[
            "PREPARED",
            "MAPPING_APPENDED",
            "LOCAL_PAIR_APPENDED",
            "ANCHOR_UNCERTAIN",
        ],
        *,
        updated_at: datetime,
    ) -> MappingAuthorityPending:
        return self.build(
            ledger_id=self.ledger_id,
            phase=phase,
            sequence=self.sequence,
            mapping_receipt_digest=self.mapping_receipt_digest,
            authority_receipt_digest=self.authority_receipt_digest,
            expected_anchor_epoch=self.expected_anchor_epoch,
            expected_anchor_digest=self.expected_anchor_digest,
            created_at=self.created_at,
            updated_at=updated_at,
        )


class MappingAuthorityReconciliationStatus(StrictModel):
    """Bounded diagnostic for a production authority commit boundary."""

    state: Literal[
        "CLEAN",
        "PREPARED_NO_LOCAL_APPEND",
        "LOCAL_PAIR_INCOMPLETE",
        "LOCAL_PENDING_ANCHOR",
        "ANCHOR_COMMIT_UNCERTAIN",
        "DIVERGED",
        "EXTERNAL_UNAVAILABLE",
    ]
    diagnostic_code: str = Field(pattern=r"^[A-Z][A-Z0-9_]{0,127}$")
    pending_phase: str | None = Field(default=None, max_length=32)
    intended_sequence: int | None = Field(default=None, ge=1)
    local_mapping_sequence: int = Field(ge=0)
    local_authority_sequence: int = Field(ge=0)
    external_sequence: int | None = Field(default=None, ge=0)
    external_epoch: int | None = Field(default=None, ge=1)


class MappingConfirmationStore:
    """Local fixture ledger for Mapping confirmation decisions.

    This E2/local type retains the compatibility API used by offline replay
    and explicitly reports ``OFFLINE_FIXTURE`` authority.  It must not be
    deployed as production operator authority.  Production callers use
    :class:`ProductionMappingConfirmationStore`, which has no unsigned actor
    entrypoint.  Every local read still validates the entire hash chain.
    """

    authority_mode = "OFFLINE_FIXTURE"

    def __init__(
        self,
        root: str | Path,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.root = Path(os.path.abspath(os.fspath(root)))
        self.path = self.root / "mapping-confirmations.jsonl"
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    def receipts(self) -> tuple[MappingConfirmationReceipt, ...]:
        """Load and verify every committed receipt in ledger order."""

        with interprocess_lock(self.path):
            return tuple(self._load_unlocked())

    def resolve(self, receipt_digest: str) -> MappingConfirmationReceipt:
        """Resolve only a receipt committed to this trusted ledger."""

        _validate_digest(receipt_digest)
        with interprocess_lock(self.path):
            receipt = self._find_receipt(self._load_unlocked(), receipt_digest)
        if receipt is None:
            raise MappingAdmissionError("MAPPING_CONFIRMATION_NOT_COMMITTED")
        return receipt

    def confirm(
        self,
        identity: MappingAdmissionIdentity,
        *,
        decision_id: str,
        actor_id: str,
        ttl_s: int = 900,
        decided_at: datetime | None = None,
    ) -> MappingConfirmationReceipt:
        """Append or idempotently replay one positive confirmation."""

        if isinstance(ttl_s, bool) or not isinstance(ttl_s, int) or not 1 <= ttl_s <= MAX_CONFIRMATION_TTL_S:
            raise MappingAdmissionError("MAPPING_CONFIRMATION_TTL_INVALID")
        return self._record(
            identity,
            decision_id=decision_id,
            actor_id=actor_id,
            decision="CONFIRMED",
            ttl_s=ttl_s,
            decided_at=decided_at,
        )

    def reject(
        self,
        identity: MappingAdmissionIdentity,
        *,
        decision_id: str,
        actor_id: str,
        decided_at: datetime | None = None,
    ) -> MappingConfirmationReceipt:
        """Append or idempotently replay one terminal rejection."""

        return self._record(
            identity,
            decision_id=decision_id,
            actor_id=actor_id,
            decision="REJECTED",
            ttl_s=None,
            decided_at=decided_at,
        )

    def cancel(
        self,
        confirmation_receipt_digest: str,
        *,
        decision_id: str,
        actor_id: str,
        decided_at: datetime | None = None,
        guard: Callable[[], None] | None = None,
    ) -> MappingConfirmationReceipt:
        """Append a tombstone for one still-active committed confirmation."""

        _validate_digest(confirmation_receipt_digest)
        now = self._validated_time(decided_at)
        with interprocess_lock(self.path):
            receipts = self._load_unlocked()
            confirmation = self._find_receipt(receipts, confirmation_receipt_digest)
            if confirmation is None:
                raise MappingAdmissionError("MAPPING_CONFIRMATION_NOT_COMMITTED")
            if confirmation.decision != "CONFIRMED":
                raise MappingAdmissionError("MAPPING_CONFIRMATION_NOT_CONFIRMED")
            if guard is not None:
                guard()
            existing = self._find_decision(receipts, decision_id)
            if existing is not None:
                if self._same_command(
                    existing,
                    confirmation.admission_identity(),
                    decision="CANCELLED",
                    actor_id=actor_id,
                    ttl_s=None,
                    supersedes_receipt_digest=confirmation_receipt_digest,
                ):
                    return existing
                raise MappingAdmissionError("MAPPING_DECISION_ID_REUSED")
            latest = self._latest_for_proposal(receipts, confirmation.proposal_digest)
            if latest is None or latest.receipt_digest != confirmation.receipt_digest:
                if latest is not None and latest.decision == "CANCELLED":
                    raise MappingAdmissionError("MAPPING_CONFIRMATION_CANCELLED")
                raise MappingAdmissionError("MAPPING_PROPOSAL_TERMINAL")
            assert confirmation.expires_at is not None
            if now >= confirmation.expires_at:
                raise MappingAdmissionError("MAPPING_CONFIRMATION_EXPIRED")
            return self._append_unlocked(
                receipts,
                confirmation.admission_identity(),
                decision_id=decision_id,
                actor_id=actor_id,
                decision="CANCELLED",
                decided_at=now,
                expires_at=None,
                supersedes_receipt_digest=confirmation.receipt_digest,
            )

    def _record(
        self,
        identity: MappingAdmissionIdentity,
        *,
        decision_id: str,
        actor_id: str,
        decision: Literal["CONFIRMED", "REJECTED"],
        ttl_s: int | None,
        decided_at: datetime | None,
    ) -> MappingConfirmationReceipt:
        identity = MappingAdmissionIdentity.model_validate(identity.model_dump(mode="python"))
        now = self._validated_time(decided_at)
        expires_at = now + timedelta(seconds=ttl_s) if ttl_s is not None else None
        with interprocess_lock(self.path):
            receipts = self._load_unlocked()
            existing = self._find_decision(receipts, decision_id)
            if existing is not None:
                if self._same_command(
                    existing,
                    identity,
                    decision=decision,
                    actor_id=actor_id,
                    ttl_s=ttl_s,
                    supersedes_receipt_digest=None,
                ):
                    return existing
                raise MappingAdmissionError("MAPPING_DECISION_ID_REUSED")
            latest = self._latest_for_proposal(receipts, identity.proposal_digest)
            if latest is not None:
                if latest.admission_identity() != identity:
                    raise MappingAdmissionError("MAPPING_PROPOSAL_IDENTITY_CONFLICT")
                raise MappingAdmissionError("MAPPING_PROPOSAL_TERMINAL")
            return self._append_unlocked(
                receipts,
                identity,
                decision_id=decision_id,
                actor_id=actor_id,
                decision=decision,
                decided_at=now,
                expires_at=expires_at,
                supersedes_receipt_digest=None,
            )

    def _append_unlocked(
        self,
        receipts: list[MappingConfirmationReceipt],
        identity: MappingAdmissionIdentity,
        *,
        decision_id: str,
        actor_id: str,
        decision: Literal["CONFIRMED", "REJECTED", "CANCELLED"],
        decided_at: datetime,
        expires_at: datetime | None,
        supersedes_receipt_digest: str | None,
    ) -> MappingConfirmationReceipt:
        if len(receipts) >= MAX_MAPPING_LEDGER_RECEIPTS:
            raise MappingAdmissionError("MAPPING_CONFIRMATION_LEDGER_TOO_LARGE")
        previous = receipts[-1].receipt_digest if receipts else None
        receipt = MappingConfirmationReceipt.build(
            identity,
            sequence=len(receipts) + 1,
            decision_id=decision_id,
            actor_id=actor_id,
            decision=decision,
            decided_at=decided_at,
            expires_at=expires_at,
            supersedes_receipt_digest=supersedes_receipt_digest,
            previous_receipt_digest=previous,
        )
        self.root.mkdir(parents=True, exist_ok=True)
        _append_bounded_jsonl(
            self.path,
            receipt.model_dump_json(),
            max_total_bytes=MAX_MAPPING_LEDGER_BYTES,
            max_line_bytes=MAX_MAPPING_RECEIPT_BYTES,
            untrusted_code="MAPPING_CONFIRMATION_LEDGER_UNTRUSTED",
            too_large_code="MAPPING_CONFIRMATION_LEDGER_TOO_LARGE",
            write_failed_code="MAPPING_CONFIRMATION_LEDGER_WRITE_FAILED",
        )
        return receipt

    def _load_unlocked(self) -> list[MappingConfirmationReceipt]:
        lines = _read_bounded_jsonl(
            self.path,
            max_total_bytes=MAX_MAPPING_LEDGER_BYTES,
            max_line_bytes=MAX_MAPPING_RECEIPT_BYTES,
            max_records=MAX_MAPPING_LEDGER_RECEIPTS,
            untrusted_code="MAPPING_CONFIRMATION_LEDGER_UNTRUSTED",
            unreadable_code="MAPPING_CONFIRMATION_LEDGER_UNREADABLE",
            too_large_code="MAPPING_CONFIRMATION_LEDGER_TOO_LARGE",
            truncated_code="MAPPING_CONFIRMATION_LEDGER_TRUNCATED",
            invalid_code="MAPPING_CONFIRMATION_LEDGER_INVALID",
        )
        receipts: list[MappingConfirmationReceipt] = []
        seen_digests: set[str] = set()
        seen_decisions: set[str] = set()
        states: dict[str, MappingConfirmationReceipt] = {}
        for line in lines:
            try:
                payload = loads_unique_json(line)
                receipt = MappingConfirmationReceipt.model_validate(payload)
            except Exception as exc:
                raise MappingAdmissionError("MAPPING_CONFIRMATION_LEDGER_INVALID") from exc
            expected_sequence = len(receipts) + 1
            expected_previous = receipts[-1].receipt_digest if receipts else None
            if receipt.sequence != expected_sequence or receipt.previous_receipt_digest != expected_previous or receipt.receipt_digest in seen_digests or receipt.decision_id in seen_decisions:
                raise MappingAdmissionError("MAPPING_CONFIRMATION_LEDGER_CHAIN_INVALID")
            previous_state = states.get(receipt.proposal_digest)
            if previous_state is not None:
                if previous_state.admission_identity() != receipt.admission_identity():
                    raise MappingAdmissionError("MAPPING_CONFIRMATION_LEDGER_IDENTITY_CONFLICT")
                if previous_state.decision != "CONFIRMED" or receipt.decision != "CANCELLED" or receipt.supersedes_receipt_digest != previous_state.receipt_digest:
                    raise MappingAdmissionError("MAPPING_CONFIRMATION_LEDGER_TRANSITION_INVALID")
            elif receipt.decision == "CANCELLED":
                raise MappingAdmissionError("MAPPING_CONFIRMATION_LEDGER_TRANSITION_INVALID")
            receipts.append(receipt)
            seen_digests.add(receipt.receipt_digest)
            seen_decisions.add(receipt.decision_id)
            states[receipt.proposal_digest] = receipt
        return receipts

    def _validated_time(self, value: datetime | None) -> datetime:
        result = value if value is not None else self.clock()
        if result.tzinfo is None or result.utcoffset() != timedelta(0):
            raise MappingAdmissionError("MAPPING_CONFIRMATION_TIME_INVALID")
        return result.astimezone(timezone.utc)

    @staticmethod
    def _same_command(
        receipt: MappingConfirmationReceipt,
        identity: MappingAdmissionIdentity,
        *,
        decision: str,
        actor_id: str,
        ttl_s: int | None,
        supersedes_receipt_digest: str | None,
    ) -> bool:
        if receipt.admission_identity() != identity or receipt.decision != decision or receipt.actor_id != actor_id or receipt.supersedes_receipt_digest != supersedes_receipt_digest:
            return False
        if ttl_s is None:
            return receipt.expires_at is None
        assert receipt.expires_at is not None
        return receipt.expires_at - receipt.decided_at == timedelta(seconds=ttl_s)

    @staticmethod
    def _find_receipt(receipts: list[MappingConfirmationReceipt], receipt_digest: str) -> MappingConfirmationReceipt | None:
        return next(
            (item for item in receipts if item.receipt_digest == receipt_digest),
            None,
        )

    @staticmethod
    def _find_decision(receipts: list[MappingConfirmationReceipt], decision_id: str) -> MappingConfirmationReceipt | None:
        return next(
            (item for item in receipts if item.decision_id == decision_id),
            None,
        )

    @staticmethod
    def _latest_for_proposal(receipts: list[MappingConfirmationReceipt], proposal_digest: str) -> MappingConfirmationReceipt | None:
        return next(
            (item for item in reversed(receipts) if item.proposal_digest == proposal_digest),
            None,
        )


class ProductionMappingConfirmationStore:
    """Mapping ledger gated by external identity, ACL, and head authorities.

    This type intentionally does not inherit the fixture/local
    :class:`MappingConfirmationStore`: callers cannot reach an unsigned
    ``confirm(actor_id=...)`` method by accident.  The local ledgers are a
    durable cache of signed evidence; the injected external head remains the
    rollback authority.
    """

    authority_mode = "PRODUCTION_EXTERNAL"

    def __init__(
        self,
        root: str | Path,
        *,
        ledger_id: str,
        signature_verifier: AuthoritySignatureVerifier,
        head_anchor: LedgerHeadAnchorProvider,
        role_policy: AuthorityRolePolicy,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not isinstance(ledger_id, str) or not _is_identifier(ledger_id):
            raise MappingAdmissionError("MAPPING_AUTHORITY_LEDGER_ID_INVALID")
        if (
            getattr(signature_verifier, "authority_class", None)
            != PRODUCTION_AUTHORITY_CLASS
            or not _is_identifier(getattr(signature_verifier, "provider_id", None))
        ):
            raise MappingAdmissionError("MAPPING_SIGNATURE_VERIFIER_UNTRUSTED")
        if (
            getattr(head_anchor, "authority_class", None)
            != PRODUCTION_AUTHORITY_CLASS
            or not _is_identifier(getattr(head_anchor, "provider_id", None))
        ):
            raise MappingAdmissionError("MAPPING_LEDGER_ANCHOR_UNTRUSTED")
        try:
            self.role_policy = AuthorityRolePolicy.model_validate(
                role_policy.model_dump(mode="python")
            )
        except Exception as exc:
            raise MappingAdmissionError("MAPPING_AUTHORITY_ROLE_POLICY_INVALID") from exc
        self.root = Path(os.path.abspath(os.fspath(root)))
        _require_safe_production_root(self.root)
        self.path = self.root / "mapping-confirmations.jsonl"
        self.authority_path = self.root / "mapping-authorities.jsonl"
        self.pending_path = self.root / "mapping-authority-pending.json"
        self.ledger_id = ledger_id
        self.signature_verifier = signature_verifier
        self.head_anchor = head_anchor
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self._ledger = MappingConfirmationStore(self.root, clock=self.clock)

    def _require_safe_paths(self, *, create_root: bool = False) -> None:
        _require_safe_production_root(self.root)
        if create_root:
            try:
                self.root.mkdir(parents=True, exist_ok=True)
            except OSError as exc:
                raise MappingAdmissionError("MAPPING_AUTHORITY_ROOT_UNTRUSTED") from exc
            _require_safe_production_root(self.root)
        for path in (self.path, self.authority_path, self.pending_path):
            _require_regular_or_absent(
                path,
                untrusted_code="MAPPING_AUTHORITY_LEDGER_UNTRUSTED",
            )

    def _lock(self):
        """Use a non-stealable lock around external authority operations."""

        return interprocess_lock(self.path, stale_after_s=None)

    def prepare_confirm(
        self,
        identity: MappingAdmissionIdentity,
        *,
        decision_id: str,
        ttl_s: int = 900,
    ) -> MappingAuthorityCommand:
        if isinstance(ttl_s, bool) or not isinstance(ttl_s, int) or not 1 <= ttl_s <= MAX_CONFIRMATION_TTL_S:
            raise MappingAdmissionError("MAPPING_CONFIRMATION_TTL_INVALID")
        return MappingAuthorityCommand.build(
            _validated_identity(identity),
            ledger_id=self.ledger_id,
            decision_id=decision_id,
            action="mapping.confirm",
            requested_ttl_s=ttl_s,
            confirmation_receipt_digest=None,
        )

    def prepare_reject(
        self,
        identity: MappingAdmissionIdentity,
        *,
        decision_id: str,
    ) -> MappingAuthorityCommand:
        return MappingAuthorityCommand.build(
            _validated_identity(identity),
            ledger_id=self.ledger_id,
            decision_id=decision_id,
            action="mapping.reject",
            requested_ttl_s=None,
            confirmation_receipt_digest=None,
        )

    def prepare_cancel(
        self,
        confirmation_receipt_digest: str,
        expected_identity: MappingAdmissionIdentity,
        *,
        decision_id: str,
        now: datetime | None = None,
    ) -> MappingAuthorityCommand:
        _validate_digest(confirmation_receipt_digest)
        identity = _validated_identity(expected_identity)
        effective_now = self._validated_time(now)
        self._require_safe_paths(create_root=True)
        with self._lock():
            receipts = self._load_verified_unlocked(effective_now)
            MappingAdmissionGate(self)._require_active_from_receipts(
                confirmation_receipt_digest,
                identity,
                receipts,
                effective_now,
            )
        return MappingAuthorityCommand.build(
            identity,
            ledger_id=self.ledger_id,
            decision_id=decision_id,
            action="mapping.cancel",
            requested_ttl_s=None,
            confirmation_receipt_digest=confirmation_receipt_digest,
        )

    def confirm(
        self,
        identity: MappingAdmissionIdentity,
        *,
        command: MappingAuthorityCommand,
        operator_assertion: SignedOperatorAssertion,
        acl_decision: SignedAclDecision,
    ) -> MappingConfirmationReceipt:
        return self._record_authorized(
            _validated_identity(identity),
            command=command,
            operator_assertion=operator_assertion,
            acl_decision=acl_decision,
            expected_action="mapping.confirm",
        )

    def reject(
        self,
        identity: MappingAdmissionIdentity,
        *,
        command: MappingAuthorityCommand,
        operator_assertion: SignedOperatorAssertion,
        acl_decision: SignedAclDecision,
    ) -> MappingConfirmationReceipt:
        return self._record_authorized(
            _validated_identity(identity),
            command=command,
            operator_assertion=operator_assertion,
            acl_decision=acl_decision,
            expected_action="mapping.reject",
        )

    def cancel(
        self,
        confirmation_receipt_digest: str,
        expected_identity: MappingAdmissionIdentity,
        *,
        command: MappingAuthorityCommand,
        operator_assertion: SignedOperatorAssertion,
        acl_decision: SignedAclDecision,
        guard: Callable[[], None] | None = None,
    ) -> MappingConfirmationReceipt:
        _validate_digest(confirmation_receipt_digest)
        identity = _validated_identity(expected_identity)
        if command.confirmation_receipt_digest != confirmation_receipt_digest:
            raise MappingAdmissionError("MAPPING_AUTHORITY_COMMAND_MISMATCH")
        return self._record_authorized(
            identity,
            command=command,
            operator_assertion=operator_assertion,
            acl_decision=acl_decision,
            expected_action="mapping.cancel",
            guard=guard,
        )

    def receipts(self) -> tuple[MappingConfirmationReceipt, ...]:
        effective_now = self._validated_time(None)
        self._require_safe_paths(create_root=True)
        with self._lock():
            return tuple(self._load_verified_unlocked(effective_now))

    def authority_receipts(self) -> tuple[MappingAuthorityReceipt, ...]:
        effective_now = self._validated_time(None)
        self._require_safe_paths(create_root=True)
        with self._lock():
            if self._load_pending_unlocked() is not None:
                raise MappingAdmissionError(
                    "MAPPING_AUTHORITY_RECONCILIATION_REQUIRED"
                )
            receipts = self._ledger._load_unlocked()
            authorities = self._load_authorities_unlocked(receipts)
            self._verify_production_state(receipts, authorities, effective_now)
            return tuple(authorities)

    def resolve(self, receipt_digest: str) -> MappingConfirmationReceipt:
        _validate_digest(receipt_digest)
        effective_now = self._validated_time(None)
        self._require_safe_paths(create_root=True)
        with self._lock():
            receipt = self._ledger._find_receipt(
                self._load_verified_unlocked(effective_now), receipt_digest
            )
        if receipt is None:
            raise MappingAdmissionError("MAPPING_CONFIRMATION_NOT_COMMITTED")
        return receipt

    def reconciliation_status(self) -> MappingAuthorityReconciliationStatus:
        """Return bounded state for an interrupted multi-authority commit."""

        effective_now = self._validated_time(None)
        self._require_safe_paths(create_root=True)
        with self._lock():
            return self._reconciliation_status_unlocked(effective_now)

    def reconcile_pending(self) -> MappingAuthorityReconciliationStatus:
        """Acknowledge only a proven abort or a proven external commit.

        This method never advances an external head.  A local pair whose
        anchor is still behind remains pending for an operator-owned recovery
        workflow; no admission can become active while the marker exists.
        """

        effective_now = self._validated_time(None)
        self._require_safe_paths(create_root=True)
        with self._lock():
            pending = self._load_pending_unlocked()
            status = self._reconciliation_status_unlocked(effective_now)
            if pending is None or status.state not in {
                "PREPARED_NO_LOCAL_APPEND",
                "ANCHOR_COMMIT_UNCERTAIN",
            }:
                return status
            self._remove_pending_unlocked()
            verified = self._reconciliation_status_unlocked(effective_now)
            if verified.state != "CLEAN":
                self._write_pending_unlocked(pending, require_absent=True)
            return verified

    def _reconciliation_status_unlocked(
        self,
        effective_now: datetime,
    ) -> MappingAuthorityReconciliationStatus:
        pending = self._load_pending_unlocked()
        receipts = self._ledger._load_unlocked()
        authorities = self._load_authorities_unlocked(
            receipts,
            require_complete=False,
        )
        mapping_count = len(receipts)
        authority_count = len(authorities)
        if authority_count > mapping_count:
            return self._status(
                "DIVERGED",
                "MAPPING_AUTHORITY_LEDGER_DIVERGED",
                pending,
                mapping_count,
                authority_count,
            )
        try:
            for receipt, authority in zip(receipts, authorities, strict=False):
                self._verify_authority_receipt(
                    receipt,
                    authority,
                    self._validated_time(None),
                )
        except MappingAdmissionError as exc:
            state = (
                "EXTERNAL_UNAVAILABLE"
                if exc.code == "MAPPING_AUTHORITY_VERIFIER_UNAVAILABLE"
                else "DIVERGED"
            )
            return self._status(
                state,
                exc.code,
                pending,
                mapping_count,
                authority_count,
            )
        minimum_epoch = (
            pending.expected_anchor_epoch
            if pending is not None
            else authorities[-1].previous_anchor_epoch + 1
            if authorities
            else 1
        )
        anchor_requested_at = self._validated_time(None)
        challenge_digest = _new_anchor_challenge()
        try:
            raw_anchor = self.head_anchor.read_head(
                self.ledger_id,
                minimum_epoch=minimum_epoch,
                challenge_digest=challenge_digest,
                now=anchor_requested_at,
            )
        except (AuthorityProviderUnavailableError, TimeoutError):
            return self._status(
                "EXTERNAL_UNAVAILABLE",
                "MAPPING_LEDGER_ANCHOR_UNAVAILABLE",
                pending,
                mapping_count,
                authority_count,
            )
        except Exception:
            return self._status(
                "DIVERGED",
                "MAPPING_LEDGER_ANCHOR_INVALID",
                pending,
                mapping_count,
                authority_count,
            )
        try:
            anchor = SignedLedgerHead.model_validate(raw_anchor)
        except Exception:
            return self._status(
                "DIVERGED",
                "MAPPING_LEDGER_ANCHOR_INVALID",
                pending,
                mapping_count,
                authority_count,
            )
        try:
            self._verify_anchor_signature(
                anchor,
                anchor_requested_at,
                expected_challenge_digest=challenge_digest,
            )
        except MappingAdmissionError as exc:
            state = (
                "EXTERNAL_UNAVAILABLE"
                if exc.code == "MAPPING_LEDGER_ANCHOR_VERIFIER_UNAVAILABLE"
                else "DIVERGED"
            )
            return self._status(
                state,
                exc.code,
                pending,
                mapping_count,
                authority_count,
            )
        if (
            anchor.anchor_provider_id != self.head_anchor.provider_id
            or anchor.ledger_id != self.ledger_id
        ):
            return self._status(
                "DIVERGED",
                "MAPPING_LEDGER_ANCHOR_DIVERGED",
                pending,
                mapping_count,
                authority_count,
                anchor,
            )
        if pending is None:
            if mapping_count != authority_count:
                return self._status(
                    "LOCAL_PAIR_INCOMPLETE",
                    "MAPPING_AUTHORITY_LEDGER_INCOMPLETE",
                    None,
                    mapping_count,
                    authority_count,
                    anchor,
                )
            expected_head = (
                mapping_production_head_digest(
                    receipts[-1].receipt_digest,
                    authorities[-1].authority_receipt_digest,
                )
                if receipts
                else None
            )
            expected_previous_anchor = (
                authorities[-1].previous_anchor_digest if authorities else None
            )
            if (
                anchor.sequence == mapping_count
                and anchor.head_digest == expected_head
                and anchor.previous_anchor_digest == expected_previous_anchor
            ):
                return self._status(
                    "CLEAN",
                    "MAPPING_AUTHORITY_STATE_CLEAN",
                    None,
                    mapping_count,
                    authority_count,
                    anchor,
                )
            return self._status(
                "DIVERGED",
                "MAPPING_LEDGER_ANCHOR_DIVERGED",
                None,
                mapping_count,
                authority_count,
                anchor,
            )

        base = pending.sequence - 1
        external_is_base = (
            anchor.epoch == pending.expected_anchor_epoch
            and anchor.sequence == base
            and anchor.anchor_digest == pending.expected_anchor_digest
        )
        external_is_next = (
            anchor.epoch > pending.expected_anchor_epoch
            and anchor.sequence == pending.sequence
            and anchor.head_digest == pending.next_head_digest
            and anchor.previous_anchor_digest == pending.expected_anchor_digest
        )
        local_is_base = mapping_count == authority_count == base
        mapping_matches = (
            mapping_count == pending.sequence
            and receipts[-1].receipt_digest == pending.mapping_receipt_digest
        )
        authority_matches = (
            authority_count == pending.sequence
            and authorities[-1].authority_receipt_digest
            == pending.authority_receipt_digest
        )
        if local_is_base and external_is_base:
            return self._status(
                "PREPARED_NO_LOCAL_APPEND",
                "MAPPING_AUTHORITY_APPEND_NOT_STARTED",
                pending,
                mapping_count,
                authority_count,
                anchor,
            )
        if mapping_matches and authority_count == base:
            return self._status(
                "LOCAL_PAIR_INCOMPLETE",
                "MAPPING_AUTHORITY_LEDGER_INCOMPLETE",
                pending,
                mapping_count,
                authority_count,
                anchor,
            )
        if mapping_matches and authority_matches and external_is_base:
            return self._status(
                "LOCAL_PENDING_ANCHOR",
                "MAPPING_LEDGER_ANCHOR_ADVANCE_REQUIRED",
                pending,
                mapping_count,
                authority_count,
                anchor,
            )
        if mapping_matches and authority_matches and external_is_next:
            return self._status(
                "ANCHOR_COMMIT_UNCERTAIN",
                "MAPPING_LEDGER_ANCHOR_COMMIT_REQUIRES_ACK",
                pending,
                mapping_count,
                authority_count,
                anchor,
            )
        return self._status(
            "DIVERGED",
            "MAPPING_AUTHORITY_LEDGER_DIVERGED",
            pending,
            mapping_count,
            authority_count,
            anchor,
        )

    @staticmethod
    def _status(
        state: Literal[
            "CLEAN",
            "PREPARED_NO_LOCAL_APPEND",
            "LOCAL_PAIR_INCOMPLETE",
            "LOCAL_PENDING_ANCHOR",
            "ANCHOR_COMMIT_UNCERTAIN",
            "DIVERGED",
            "EXTERNAL_UNAVAILABLE",
        ],
        code: str,
        pending: MappingAuthorityPending | None,
        mapping_count: int,
        authority_count: int,
        anchor: SignedLedgerHead | None = None,
    ) -> MappingAuthorityReconciliationStatus:
        return MappingAuthorityReconciliationStatus(
            state=state,
            diagnostic_code=code,
            pending_phase=pending.phase if pending is not None else None,
            intended_sequence=pending.sequence if pending is not None else None,
            local_mapping_sequence=mapping_count,
            local_authority_sequence=authority_count,
            external_sequence=anchor.sequence if anchor is not None else None,
            external_epoch=anchor.epoch if anchor is not None else None,
        )

    def _load_unlocked(self) -> list[MappingConfirmationReceipt]:
        """Compatibility hook used by ``MappingAdmissionGate`` under its lock."""

        return self._load_verified_unlocked(self._validated_time(None))

    def _load_verified_unlocked(
        self,
        effective_now: datetime,
    ) -> list[MappingConfirmationReceipt]:
        receipts, _, _, _ = self._load_verified_state_unlocked(effective_now)
        return receipts

    def _load_verified_state_unlocked(
        self,
        effective_now: datetime,
    ) -> tuple[
        list[MappingConfirmationReceipt],
        list[MappingAuthorityReceipt],
        SignedLedgerHead,
        SignatureVerification,
    ]:
        self._require_safe_paths()
        if self._load_pending_unlocked() is not None:
            raise MappingAdmissionError("MAPPING_AUTHORITY_RECONCILIATION_REQUIRED")
        receipts = self._ledger._load_unlocked()
        authorities = self._load_authorities_unlocked(receipts)
        anchor, anchor_verification = self._verify_production_state(
            receipts,
            authorities,
            effective_now,
        )
        return receipts, authorities, anchor, anchor_verification

    def _record_authorized(
        self,
        identity: MappingAdmissionIdentity,
        *,
        command: MappingAuthorityCommand,
        operator_assertion: SignedOperatorAssertion,
        acl_decision: SignedAclDecision,
        expected_action: Literal[
            "mapping.confirm", "mapping.reject", "mapping.cancel"
        ],
        guard: Callable[[], None] | None = None,
    ) -> MappingConfirmationReceipt:
        try:
            command = MappingAuthorityCommand.model_validate(
                command.model_dump(mode="python")
            )
            operator_assertion = SignedOperatorAssertion.model_validate(
                operator_assertion.model_dump(mode="python")
            )
            acl_decision = SignedAclDecision.model_validate(
                acl_decision.model_dump(mode="python")
            )
        except Exception as exc:
            raise MappingAdmissionError("MAPPING_AUTHORITY_EVIDENCE_INVALID") from exc
        try:
            expected_command = MappingAuthorityCommand.build(
                identity,
                ledger_id=self.ledger_id,
                decision_id=command.decision_id,
                action=expected_action,
                requested_ttl_s=command.requested_ttl_s,
                confirmation_receipt_digest=command.confirmation_receipt_digest,
            )
        except Exception as exc:
            raise MappingAdmissionError("MAPPING_AUTHORITY_COMMAND_MISMATCH") from exc
        if command != expected_command:
            raise MappingAdmissionError("MAPPING_AUTHORITY_COMMAND_MISMATCH")

        # Signature verification may involve an IdP/JWKS/KMS round trip.  Do it
        # before acquiring the ledger lock, then treat its result as a short
        # lease that must still be fresh at every irreversible boundary.
        preflight_started_at = self._validated_time(None)
        operator_verification, acl_verification = self._verify_command_authority(
            command,
            operator_assertion,
            acl_decision,
            preflight_started_at,
        )
        preflight_completed_at = self._validated_time(None)
        self._revalidate_preverified_command_authority(
            command,
            operator_assertion,
            acl_decision,
            operator_verification,
            acl_verification,
            preflight_completed_at,
        )
        self._require_safe_paths(create_root=True)
        with self._lock():
            state_started_at = self._validated_time(None)
            # Rebuild the exact command under the serialization lock as well;
            # the preflight result is never authority for a different input.
            expected_command = MappingAuthorityCommand.build(
                identity,
                ledger_id=self.ledger_id,
                decision_id=command.decision_id,
                action=expected_action,
                requested_ttl_s=command.requested_ttl_s,
                confirmation_receipt_digest=command.confirmation_receipt_digest,
            )
            if command != expected_command:
                raise MappingAdmissionError("MAPPING_AUTHORITY_COMMAND_MISMATCH")
            if self._load_pending_unlocked() is not None:
                raise MappingAdmissionError(
                    "MAPPING_AUTHORITY_RECONCILIATION_REQUIRED"
                )
            receipts = self._ledger._load_unlocked()
            authorities = self._load_authorities_unlocked(receipts)
            current_anchor, current_anchor_verification = self._verify_production_state(
                receipts,
                authorities,
                state_started_at,
            )

            def fresh_transaction_time() -> datetime:
                effective_now = self._validated_time(None)
                self._revalidate_preverified_command_authority(
                    command,
                    operator_assertion,
                    acl_decision,
                    operator_verification,
                    acl_verification,
                    effective_now,
                )
                self._require_anchor_witness_active(current_anchor, effective_now)
                self._require_verification_fresh(
                    current_anchor_verification,
                    effective_now,
                    code="MAPPING_LEDGER_ANCHOR_VERIFICATION_STALE",
                )
                return effective_now

            effective_now = fresh_transaction_time()
            existing = self._ledger._find_decision(receipts, command.decision_id)
            if existing is not None:
                authority = next(
                    (
                        item
                        for item in authorities
                        if item.mapping_receipt_digest == existing.receipt_digest
                    ),
                    None,
                )
                if (
                    existing.admission_identity() == identity
                    and authority is not None
                    and authority.command == command
                    and authority.operator_assertion == operator_assertion
                    and authority.acl_decision == acl_decision
                ):
                    if existing.decision == "CONFIRMED":
                        MappingAdmissionGate(self)._require_active_from_receipts(
                            existing.receipt_digest,
                            identity,
                            receipts,
                            effective_now,
                        )
                    return existing
                raise MappingAdmissionError("MAPPING_DECISION_ID_REUSED")
            if len(receipts) >= MAX_MAPPING_LEDGER_RECEIPTS:
                raise MappingAdmissionError("MAPPING_CONFIRMATION_LEDGER_TOO_LARGE")
            if any(
                item.acl_decision.authorization_id
                == acl_decision.authorization_id
                for item in authorities
            ):
                raise MappingAdmissionError("MAPPING_ACL_AUTHORIZATION_REPLAY")

            supersedes: str | None = None
            if expected_action == "mapping.cancel":
                assert command.confirmation_receipt_digest is not None
                confirmation = self._ledger._find_receipt(
                    receipts, command.confirmation_receipt_digest
                )
                if confirmation is None:
                    raise MappingAdmissionError("MAPPING_CONFIRMATION_NOT_COMMITTED")
                if confirmation.admission_identity() != identity:
                    raise MappingAdmissionError("MAPPING_AUTHORITY_COMMAND_MISMATCH")
                MappingAdmissionGate(self)._require_active_from_receipts(
                    confirmation.receipt_digest,
                    identity,
                    receipts,
                    effective_now,
                )
                if guard is not None:
                    guard()
                supersedes = confirmation.receipt_digest
            else:
                latest = self._ledger._latest_for_proposal(
                    receipts, identity.proposal_digest
                )
                if latest is not None:
                    if latest.admission_identity() != identity:
                        raise MappingAdmissionError("MAPPING_PROPOSAL_IDENTITY_CONFLICT")
                    raise MappingAdmissionError("MAPPING_PROPOSAL_TERMINAL")

            # The guard and all external state verification above may have
            # consumed the remaining credential lifetime.  This is the
            # linearization timestamp for the new receipt and the first
            # pending write.
            effective_now = fresh_transaction_time()
            if expected_action == "mapping.confirm":
                assert command.requested_ttl_s is not None
                if command.requested_ttl_s > acl_decision.max_confirmation_ttl_s:
                    raise MappingAdmissionError("MAPPING_ACL_TTL_EXCEEDED")
                expires_at = effective_now + timedelta(
                    seconds=command.requested_ttl_s
                )
                decision: Literal["CONFIRMED", "REJECTED", "CANCELLED"] = (
                    "CONFIRMED"
                )
            elif expected_action == "mapping.reject":
                expires_at = None
                decision = "REJECTED"
            else:
                expires_at = None
                decision = "CANCELLED"

            receipt = MappingConfirmationReceipt.build(
                identity,
                sequence=len(receipts) + 1,
                decision_id=command.decision_id,
                actor_id=operator_assertion.principal_id,
                decision=decision,
                decided_at=effective_now,
                expires_at=expires_at,
                supersedes_receipt_digest=supersedes,
                previous_receipt_digest=(
                    receipts[-1].receipt_digest if receipts else None
                ),
            )
            authority_receipt = MappingAuthorityReceipt.build(
                sequence=receipt.sequence,
                mapping_receipt_digest=receipt.receipt_digest,
                previous_authority_receipt_digest=(
                    authorities[-1].authority_receipt_digest
                    if authorities
                    else None
                ),
                command=command,
                operator_assertion=operator_assertion,
                acl_decision=acl_decision,
                operator_verification=operator_verification,
                acl_verification=acl_verification,
                anchor_provider_id=self.head_anchor.provider_id,
                previous_anchor_epoch=current_anchor.epoch,
                previous_anchor_digest=current_anchor.anchor_digest,
            )
            next_head_digest = mapping_production_head_digest(
                receipt.receipt_digest,
                authority_receipt.authority_receipt_digest,
            )
            pending = MappingAuthorityPending.build(
                ledger_id=self.ledger_id,
                phase="PREPARED",
                sequence=receipt.sequence,
                mapping_receipt_digest=receipt.receipt_digest,
                authority_receipt_digest=authority_receipt.authority_receipt_digest,
                expected_anchor_epoch=current_anchor.epoch,
                expected_anchor_digest=current_anchor.anchor_digest,
                created_at=effective_now,
                updated_at=effective_now,
            )
            self._write_pending_unlocked(pending, require_absent=True)

            effective_now = fresh_transaction_time()
            self._append_mapping_unlocked(receipt)
            pending = pending.with_phase(
                "MAPPING_APPENDED", updated_at=effective_now
            )
            effective_now = fresh_transaction_time()
            self._write_pending_unlocked(pending)

            effective_now = fresh_transaction_time()
            self._append_authority_unlocked(authority_receipt)
            pending = pending.with_phase(
                "LOCAL_PAIR_APPENDED", updated_at=effective_now
            )
            effective_now = fresh_transaction_time()
            self._write_pending_unlocked(pending)

            effective_now = fresh_transaction_time()
            pending = pending.with_phase("ANCHOR_UNCERTAIN", updated_at=effective_now)
            self._write_pending_unlocked(pending)
            effective_now = fresh_transaction_time()
            challenge_digest = _new_anchor_challenge()
            try:
                raw_next_anchor = self.head_anchor.advance(
                    self.ledger_id,
                    expected_anchor_digest=current_anchor.anchor_digest,
                    next_sequence=receipt.sequence,
                    next_head_digest=next_head_digest,
                    challenge_digest=challenge_digest,
                    now=effective_now,
                )
            except (AuthorityProviderUnavailableError, TimeoutError) as exc:
                raise MappingAdmissionError(
                    "MAPPING_LEDGER_ANCHOR_UNAVAILABLE"
                ) from exc
            except Exception as exc:
                raise MappingAdmissionError("MAPPING_LEDGER_ANCHOR_ADVANCE_FAILED") from exc
            try:
                next_anchor = SignedLedgerHead.model_validate(raw_next_anchor)
            except Exception as exc:
                raise MappingAdmissionError(
                    "MAPPING_LEDGER_ANCHOR_ADVANCE_INVALID"
                ) from exc
            anchor_returned_at = self._validated_time(None)
            self._verify_anchor_signature(
                next_anchor,
                anchor_returned_at,
                expected_challenge_digest=challenge_digest,
            )
            if (
                next_anchor.anchor_provider_id != self.head_anchor.provider_id
                or next_anchor.ledger_id != self.ledger_id
                or next_anchor.epoch <= current_anchor.epoch
                or next_anchor.sequence != receipt.sequence
                or next_anchor.head_digest != next_head_digest
                or next_anchor.previous_anchor_digest
                != current_anchor.anchor_digest
            ):
                raise MappingAdmissionError("MAPPING_LEDGER_ANCHOR_ADVANCE_INVALID")
            self._remove_pending_unlocked()
            return receipt

    def _verify_command_authority(
        self,
        command: MappingAuthorityCommand,
        operator_assertion: SignedOperatorAssertion,
        acl_decision: SignedAclDecision,
        evidence_time: datetime,
        *,
        verification_time: datetime | None = None,
    ) -> tuple[SignatureVerification, SignatureVerification]:
        self._validate_command_authority_claims(
            command,
            operator_assertion,
            acl_decision,
            evidence_time,
        )
        signature_time = verification_time or evidence_time
        operator_verification = self._verify_signed_artifact(
            operator_assertion,
            purpose="OPERATOR_ASSERTION",
            issuer_id=operator_assertion.issuer_id,
            now=signature_time,
        )
        acl_verification = self._verify_signed_artifact(
            acl_decision,
            purpose="ACL_DECISION",
            issuer_id=acl_decision.authority_id,
            now=signature_time,
        )
        self._require_distinct_verification_roles(
            operator_verification,
            acl_verification,
        )
        return operator_verification, acl_verification

    def _validate_command_authority_claims(
        self,
        command: MappingAuthorityCommand,
        operator_assertion: SignedOperatorAssertion,
        acl_decision: SignedAclDecision,
        evidence_time: datetime,
    ) -> None:
        if (
            operator_assertion.challenge_digest != command.command_digest
            or acl_decision.request_digest != command.command_digest
        ):
            raise MappingAdmissionError("MAPPING_AUTHORITY_COMMAND_MISMATCH")
        if acl_decision.subject_principal_id != operator_assertion.principal_id:
            raise MappingAdmissionError("MAPPING_ACL_PRINCIPAL_MISMATCH")
        if acl_decision.subject_issuer_id != operator_assertion.issuer_id:
            raise MappingAdmissionError("MAPPING_ACL_SUBJECT_ISSUER_MISMATCH")
        if (
            acl_decision.authority_id == operator_assertion.issuer_id
            or acl_decision.key_id == operator_assertion.key_id
        ):
            raise MappingAdmissionError("MAPPING_AUTHORITY_ROLE_COLLISION")
        if acl_decision.action != command.action:
            raise MappingAdmissionError("MAPPING_ACL_ACTION_MISMATCH")
        if acl_decision.resource_digest != command.proposal_digest:
            raise MappingAdmissionError("MAPPING_ACL_RESOURCE_MISMATCH")
        if acl_decision.scope_digest != command.scope_digest:
            raise MappingAdmissionError("MAPPING_ACL_SCOPE_MISMATCH")
        if acl_decision.effect != "ALLOW":
            raise MappingAdmissionError("MAPPING_ACL_DENIED")
        for issued_at, expires_at, code in (
            (
                operator_assertion.issued_at,
                operator_assertion.expires_at,
                "MAPPING_OPERATOR_ASSERTION_INACTIVE",
            ),
            (
                acl_decision.issued_at,
                acl_decision.expires_at,
                "MAPPING_ACL_DECISION_INACTIVE",
            ),
        ):
            if not issued_at <= evidence_time < expires_at:
                raise MappingAdmissionError(code)

    def _revalidate_preverified_command_authority(
        self,
        command: MappingAuthorityCommand,
        operator_assertion: SignedOperatorAssertion,
        acl_decision: SignedAclDecision,
        operator_verification: SignatureVerification,
        acl_verification: SignatureVerification,
        effective_now: datetime,
    ) -> None:
        """Recheck time and exact verifier receipts without external calls."""

        self._validate_command_authority_claims(
            command,
            operator_assertion,
            acl_decision,
            effective_now,
        )
        for verification, purpose, issuer_id, artifact in (
            (
                operator_verification,
                "OPERATOR_ASSERTION",
                operator_assertion.issuer_id,
                operator_assertion,
            ),
            (
                acl_verification,
                "ACL_DECISION",
                acl_decision.authority_id,
                acl_decision,
            ),
        ):
            try:
                _verify_signature_result_binding(
                    verification,
                    purpose=purpose,
                    issuer_id=issuer_id,
                    key_id=artifact.key_id,
                    algorithm=artifact.algorithm,
                    payload_digest=artifact.payload_digest,
                )
            except ValueError as exc:
                raise MappingAdmissionError(
                    "MAPPING_AUTHORITY_SIGNATURE_INVALID"
                ) from exc
            self._require_role_pin(
                purpose=purpose,
                issuer_id=issuer_id,
                key_id=artifact.key_id,
                verification=verification,
            )
            self._require_verification_fresh(
                verification,
                effective_now,
                code="MAPPING_AUTHORITY_VERIFICATION_STALE",
            )
        self._require_distinct_verification_roles(
            operator_verification,
            acl_verification,
        )

    @staticmethod
    def _require_distinct_verification_roles(
        operator_verification: SignatureVerification,
        acl_verification: SignatureVerification,
    ) -> None:
        if (
            operator_verification.trust_root_digest
            == acl_verification.trust_root_digest
        ):
            raise MappingAdmissionError("MAPPING_AUTHORITY_ROLE_COLLISION")

    def _verify_signed_artifact(
        self,
        artifact: SignedOperatorAssertion | SignedAclDecision | SignedLedgerHead,
        *,
        purpose: Literal["OPERATOR_ASSERTION", "ACL_DECISION", "LEDGER_HEAD"],
        issuer_id: str,
        now: datetime,
    ) -> SignatureVerification:
        try:
            verification = SignatureVerification.model_validate(
                self.signature_verifier.verify(
                    purpose=purpose,
                    issuer_id=issuer_id,
                    key_id=artifact.key_id,
                    algorithm=artifact.algorithm,
                    payload=authority_signed_payload_bytes(artifact),
                    payload_digest=artifact.payload_digest,
                    signature=artifact.signature,
                    now=now,
                )
            )
        except (AuthorityProviderUnavailableError, TimeoutError) as exc:
            code = (
                "MAPPING_LEDGER_ANCHOR_VERIFIER_UNAVAILABLE"
                if purpose == "LEDGER_HEAD"
                else "MAPPING_AUTHORITY_VERIFIER_UNAVAILABLE"
            )
            raise MappingAdmissionError(code) from exc
        except Exception as exc:
            code = (
                "MAPPING_LEDGER_ANCHOR_SIGNATURE_INVALID"
                if purpose == "LEDGER_HEAD"
                else "MAPPING_AUTHORITY_SIGNATURE_INVALID"
            )
            raise MappingAdmissionError(code) from exc
        if verification.provider_id != self.signature_verifier.provider_id:
            code = (
                "MAPPING_LEDGER_ANCHOR_SIGNATURE_INVALID"
                if purpose == "LEDGER_HEAD"
                else "MAPPING_SIGNATURE_VERIFIER_MISMATCH"
            )
            raise MappingAdmissionError(code)
        try:
            _verify_signature_result_binding(
                verification,
                purpose=purpose,
                issuer_id=issuer_id,
                key_id=artifact.key_id,
                algorithm=artifact.algorithm,
                payload_digest=artifact.payload_digest,
                verified_at=now,
            )
        except ValueError as exc:
            code = (
                "MAPPING_LEDGER_ANCHOR_SIGNATURE_INVALID"
                if purpose == "LEDGER_HEAD"
                else "MAPPING_AUTHORITY_SIGNATURE_INVALID"
            )
            raise MappingAdmissionError(code) from exc
        self._require_role_pin(
            purpose=purpose,
            issuer_id=issuer_id,
            key_id=artifact.key_id,
            verification=verification,
        )
        return verification

    def _require_role_pin(
        self,
        *,
        purpose: Literal["OPERATOR_ASSERTION", "ACL_DECISION", "LEDGER_HEAD"],
        issuer_id: str,
        key_id: str,
        verification: SignatureVerification,
    ) -> None:
        pin = self.role_policy.pin_for(purpose)
        actual = (issuer_id, key_id, verification.trust_root_digest)
        expected = (pin.issuer_id, pin.key_id, pin.trust_root_digest)
        if actual == expected:
            return
        other_pins = tuple(
            self.role_policy.pin_for(other)
            for other in ("OPERATOR_ASSERTION", "ACL_DECISION", "LEDGER_HEAD")
            if other != purpose
        )
        if any(
            issuer_id == other.issuer_id
            or key_id == other.key_id
            or verification.trust_root_digest == other.trust_root_digest
            for other in other_pins
        ):
            raise MappingAdmissionError("MAPPING_AUTHORITY_ROLE_COLLISION")
        raise MappingAdmissionError("MAPPING_AUTHORITY_ROLE_PIN_MISMATCH")

    @staticmethod
    def _require_verification_fresh(
        verification: SignatureVerification,
        effective_now: datetime,
        *,
        code: str,
    ) -> None:
        if (
            verification.verified_at > effective_now
            or effective_now - verification.verified_at
            > timedelta(seconds=MAX_SIGNATURE_VERIFICATION_AGE_S)
        ):
            raise MappingAdmissionError(code)

    def _verify_production_state(
        self,
        receipts: list[MappingConfirmationReceipt],
        authorities: list[MappingAuthorityReceipt],
        _effective_now: datetime,
    ) -> tuple[SignedLedgerHead, SignatureVerification]:
        for receipt, authority in zip(receipts, authorities, strict=True):
            self._verify_authority_receipt(
                receipt,
                authority,
                self._validated_time(None),
            )
        return self._read_verified_anchor_for_state_unlocked(receipts, authorities)

    def _read_verified_anchor_for_state_unlocked(
        self,
        receipts: list[MappingConfirmationReceipt],
        authorities: list[MappingAuthorityReceipt],
    ) -> tuple[SignedLedgerHead, SignatureVerification]:
        """Read a newly challenged signed head for one exact local state."""

        minimum_epoch = (
            authorities[-1].previous_anchor_epoch + 1 if authorities else 1
        )
        anchor_requested_at = self._validated_time(None)
        challenge_digest = _new_anchor_challenge()
        try:
            raw_anchor = self.head_anchor.read_head(
                self.ledger_id,
                minimum_epoch=minimum_epoch,
                challenge_digest=challenge_digest,
                now=anchor_requested_at,
            )
        except (AuthorityProviderUnavailableError, TimeoutError) as exc:
            raise MappingAdmissionError("MAPPING_LEDGER_ANCHOR_UNAVAILABLE") from exc
        except Exception as exc:
            raise MappingAdmissionError("MAPPING_LEDGER_ANCHOR_INVALID") from exc
        try:
            anchor = SignedLedgerHead.model_validate(raw_anchor)
        except Exception as exc:
            raise MappingAdmissionError("MAPPING_LEDGER_ANCHOR_INVALID") from exc
        anchor_verification = self._verify_anchor_signature(
            anchor,
            anchor_requested_at,
            expected_challenge_digest=challenge_digest,
        )
        expected_sequence = len(receipts)
        expected_head = (
            mapping_production_head_digest(
                receipts[-1].receipt_digest,
                authorities[-1].authority_receipt_digest,
            )
            if receipts
            else None
        )
        expected_previous_anchor = (
            authorities[-1].previous_anchor_digest if authorities else None
        )
        if (
            anchor.anchor_provider_id != self.head_anchor.provider_id
            or anchor.ledger_id != self.ledger_id
            or anchor.epoch < minimum_epoch
            or anchor.sequence != expected_sequence
            or anchor.head_digest != expected_head
            or anchor.previous_anchor_digest != expected_previous_anchor
        ):
            raise MappingAdmissionError("MAPPING_LEDGER_ANCHOR_DIVERGED")
        return anchor, anchor_verification

    def _verify_anchor_signature(
        self,
        anchor: SignedLedgerHead,
        effective_now: datetime,
        *,
        expected_challenge_digest: str,
    ) -> SignatureVerification:
        if anchor.challenge_digest != expected_challenge_digest:
            raise MappingAdmissionError("MAPPING_LEDGER_ANCHOR_CHALLENGE_MISMATCH")
        self._require_anchor_witness_active(anchor, effective_now)
        verification = self._verify_signed_artifact(
            anchor,
            purpose="LEDGER_HEAD",
            issuer_id=anchor.issuer_id,
            now=effective_now,
        )
        completed_at = self._validated_time(None)
        self._require_anchor_witness_active(anchor, completed_at)
        self._require_verification_fresh(
            verification,
            completed_at,
            code="MAPPING_LEDGER_ANCHOR_VERIFICATION_STALE",
        )
        return verification

    @staticmethod
    def _require_anchor_witness_active(
        anchor: SignedLedgerHead,
        effective_now: datetime,
    ) -> None:
        if not anchor.witnessed_at <= effective_now < anchor.expires_at:
            raise MappingAdmissionError("MAPPING_LEDGER_ANCHOR_STALE")
        if anchor.recorded_at > effective_now:
            raise MappingAdmissionError("MAPPING_LEDGER_ANCHOR_FROM_FUTURE")

    def _verify_authority_receipt(
        self,
        mapping_receipt: MappingConfirmationReceipt,
        authority_receipt: MappingAuthorityReceipt,
        effective_now: datetime,
    ) -> None:
        command = authority_receipt.command
        expected_action = {
            "CONFIRMED": "mapping.confirm",
            "REJECTED": "mapping.reject",
            "CANCELLED": "mapping.cancel",
        }[mapping_receipt.decision]
        expected_command = MappingAuthorityCommand.build(
            mapping_receipt.admission_identity(),
            ledger_id=self.ledger_id,
            decision_id=mapping_receipt.decision_id,
            action=expected_action,
            requested_ttl_s=(
                int(
                    (mapping_receipt.expires_at - mapping_receipt.decided_at).total_seconds()
                )
                if mapping_receipt.expires_at is not None
                else None
            ),
            confirmation_receipt_digest=mapping_receipt.supersedes_receipt_digest,
        )
        if (
            authority_receipt.sequence != mapping_receipt.sequence
            or authority_receipt.mapping_receipt_digest
            != mapping_receipt.receipt_digest
            or command != expected_command
            or authority_receipt.operator_assertion.principal_id
            != mapping_receipt.actor_id
            or authority_receipt.anchor_provider_id
            != self.head_anchor.provider_id
        ):
            raise MappingAdmissionError("MAPPING_AUTHORITY_LEDGER_BINDING_INVALID")
        try:
            for stored, purpose, issuer_id, artifact in (
                (
                    authority_receipt.operator_verification,
                    "OPERATOR_ASSERTION",
                    authority_receipt.operator_assertion.issuer_id,
                    authority_receipt.operator_assertion,
                ),
                (
                    authority_receipt.acl_verification,
                    "ACL_DECISION",
                    authority_receipt.acl_decision.authority_id,
                    authority_receipt.acl_decision,
                ),
            ):
                if stored.provider_id != self.signature_verifier.provider_id:
                    raise ValueError("stored signature verifier differs from configured provider")
                _verify_signature_result_binding(
                    stored,
                    purpose=purpose,
                    issuer_id=issuer_id,
                    key_id=artifact.key_id,
                    algorithm=artifact.algorithm,
                    payload_digest=artifact.payload_digest,
                    verified_at=mapping_receipt.decided_at,
                )
        except ValueError as exc:
            raise MappingAdmissionError(
                "MAPPING_AUTHORITY_LEDGER_BINDING_INVALID"
            ) from exc
        if (
            command.action == "mapping.confirm"
            and command.requested_ttl_s is not None
            and command.requested_ttl_s
            > authority_receipt.acl_decision.max_confirmation_ttl_s
        ):
            raise MappingAdmissionError("MAPPING_AUTHORITY_LEDGER_BINDING_INVALID")
        operator_verification, acl_verification = self._verify_command_authority(
            command,
            authority_receipt.operator_assertion,
            authority_receipt.acl_decision,
            mapping_receipt.decided_at,
            verification_time=effective_now,
        )
        # Reverification may occur under a rotated trust root.  Exact signed
        # payload identity is mandatory; provider timestamps/evidence may
        # legitimately differ from the original stored verification receipt.
        if (
            operator_verification.payload_digest
            != authority_receipt.operator_verification.payload_digest
            or acl_verification.payload_digest
            != authority_receipt.acl_verification.payload_digest
        ):
            raise MappingAdmissionError("MAPPING_AUTHORITY_LEDGER_BINDING_INVALID")
        if effective_now < mapping_receipt.decided_at:
            raise MappingAdmissionError("MAPPING_CONFIRMATION_NOT_YET_ACTIVE")

    def _load_authorities_unlocked(
        self,
        receipts: list[MappingConfirmationReceipt],
        *,
        require_complete: bool = True,
    ) -> list[MappingAuthorityReceipt]:
        self._require_safe_paths()
        lines = _read_bounded_jsonl(
            self.authority_path,
            max_total_bytes=MAX_MAPPING_AUTHORITY_LEDGER_BYTES,
            max_line_bytes=MAX_MAPPING_AUTHORITY_RECEIPT_BYTES,
            max_records=MAX_MAPPING_LEDGER_RECEIPTS,
            untrusted_code="MAPPING_AUTHORITY_LEDGER_UNTRUSTED",
            unreadable_code="MAPPING_AUTHORITY_LEDGER_UNREADABLE",
            too_large_code="MAPPING_AUTHORITY_LEDGER_TOO_LARGE",
            truncated_code="MAPPING_AUTHORITY_LEDGER_TRUNCATED",
            invalid_code="MAPPING_AUTHORITY_LEDGER_INVALID",
        )
        authorities: list[MappingAuthorityReceipt] = []
        seen_receipts: set[str] = set()
        seen_assertions: set[str] = set()
        seen_authorizations: set[str] = set()
        for line in lines:
            try:
                authority = MappingAuthorityReceipt.model_validate(
                    loads_unique_json(line)
                )
            except Exception as exc:
                raise MappingAdmissionError("MAPPING_AUTHORITY_LEDGER_INVALID") from exc
            expected_sequence = len(authorities) + 1
            expected_previous = (
                authorities[-1].authority_receipt_digest if authorities else None
            )
            if (
                authority.sequence != expected_sequence
                or authority.previous_authority_receipt_digest != expected_previous
                or authority.authority_receipt_digest in seen_receipts
                or authority.operator_assertion.payload_digest in seen_assertions
                or authority.acl_decision.authorization_id in seen_authorizations
                or (
                    authorities
                    and authority.previous_anchor_epoch
                    <= authorities[-1].previous_anchor_epoch
                )
            ):
                raise MappingAdmissionError("MAPPING_AUTHORITY_LEDGER_CHAIN_INVALID")
            authorities.append(authority)
            seen_receipts.add(authority.authority_receipt_digest)
            seen_assertions.add(authority.operator_assertion.payload_digest)
            seen_authorizations.add(authority.acl_decision.authorization_id)
        if require_complete and len(authorities) != len(receipts):
            raise MappingAdmissionError("MAPPING_AUTHORITY_LEDGER_INCOMPLETE")
        return authorities

    def _append_mapping_unlocked(
        self,
        receipt: MappingConfirmationReceipt,
    ) -> None:
        self._require_safe_paths(create_root=True)
        _append_bounded_jsonl(
            self.path,
            receipt.model_dump_json(),
            max_total_bytes=MAX_MAPPING_LEDGER_BYTES,
            max_line_bytes=MAX_MAPPING_RECEIPT_BYTES,
            untrusted_code="MAPPING_AUTHORITY_LEDGER_UNTRUSTED",
            too_large_code="MAPPING_CONFIRMATION_LEDGER_TOO_LARGE",
            write_failed_code="MAPPING_AUTHORITY_MAPPING_APPEND_FAILED",
        )

    def _append_authority_unlocked(
        self,
        authority_receipt: MappingAuthorityReceipt,
    ) -> None:
        self._require_safe_paths(create_root=True)
        _append_bounded_jsonl(
            self.authority_path,
            authority_receipt.model_dump_json(),
            max_total_bytes=MAX_MAPPING_AUTHORITY_LEDGER_BYTES,
            max_line_bytes=MAX_MAPPING_AUTHORITY_RECEIPT_BYTES,
            untrusted_code="MAPPING_AUTHORITY_LEDGER_UNTRUSTED",
            too_large_code="MAPPING_AUTHORITY_LEDGER_TOO_LARGE",
            write_failed_code="MAPPING_AUTHORITY_EVIDENCE_APPEND_FAILED",
        )

    def _load_pending_unlocked(self) -> MappingAuthorityPending | None:
        self._require_safe_paths()
        lines = _read_bounded_jsonl(
            self.pending_path,
            max_total_bytes=MAX_MAPPING_PENDING_BYTES,
            max_line_bytes=MAX_MAPPING_PENDING_BYTES - 1,
            max_records=1,
            untrusted_code="MAPPING_AUTHORITY_PENDING_UNTRUSTED",
            unreadable_code="MAPPING_AUTHORITY_PENDING_UNREADABLE",
            too_large_code="MAPPING_AUTHORITY_PENDING_TOO_LARGE",
            truncated_code="MAPPING_AUTHORITY_PENDING_TRUNCATED",
            invalid_code="MAPPING_AUTHORITY_PENDING_INVALID",
        )
        if not lines:
            return None
        try:
            pending = MappingAuthorityPending.model_validate(loads_unique_json(lines[0]))
        except Exception as exc:
            raise MappingAdmissionError("MAPPING_AUTHORITY_PENDING_INVALID") from exc
        if pending.ledger_id != self.ledger_id:
            raise MappingAdmissionError("MAPPING_AUTHORITY_PENDING_INVALID")
        return pending

    def _write_pending_unlocked(
        self,
        pending: MappingAuthorityPending,
        *,
        require_absent: bool = False,
    ) -> None:
        self._require_safe_paths(create_root=True)
        encoded = pending.model_dump_json() + "\n"
        if len(encoded.encode("utf-8")) > MAX_MAPPING_PENDING_BYTES:
            raise MappingAdmissionError("MAPPING_AUTHORITY_PENDING_TOO_LARGE")
        try:
            atomic_write_text(
                self.pending_path,
                encoded,
                acquire_lock=False,
                require_absent=require_absent,
            )
            if os.name != "nt":
                self.pending_path.chmod(stat.S_IRUSR | stat.S_IWUSR)
        except (FileExistsError, OSError) as exc:
            raise MappingAdmissionError("MAPPING_AUTHORITY_PENDING_WRITE_FAILED") from exc
        metadata = _require_regular_or_absent(
            self.pending_path,
            untrusted_code="MAPPING_AUTHORITY_PENDING_UNTRUSTED",
        )
        if metadata is None or metadata.st_size > MAX_MAPPING_PENDING_BYTES:
            raise MappingAdmissionError("MAPPING_AUTHORITY_PENDING_WRITE_FAILED")

    def _remove_pending_unlocked(self) -> None:
        self._require_safe_paths()
        try:
            self.pending_path.unlink()
        except FileNotFoundError as exc:
            raise MappingAdmissionError("MAPPING_AUTHORITY_PENDING_MISSING") from exc
        except OSError as exc:
            raise MappingAdmissionError("MAPPING_AUTHORITY_PENDING_CLEAR_FAILED") from exc

    def _validated_time(self, value: datetime | None) -> datetime:
        result = value if value is not None else self.clock()
        if result.tzinfo is None or result.utcoffset() != timedelta(0):
            raise MappingAdmissionError("MAPPING_CONFIRMATION_TIME_INVALID")
        return result.astimezone(timezone.utc)


class MappingAdmissionGate:
    """Resolve a committed receipt and match a trusted current identity."""

    _IDENTITY_MISMATCH_CODES = {
        "journey_session_id": "MAPPING_JOURNEY_SESSION_MISMATCH",
        "target_id": "MAPPING_TARGET_ID_MISMATCH",
        "target_fingerprint": "MAPPING_TARGET_FINGERPRINT_MISMATCH",
        "target_identity_digest": "MAPPING_TARGET_IDENTITY_DIGEST_MISMATCH",
        "candidate_index_digest": "MAPPING_CANDIDATE_INDEX_DIGEST_MISMATCH",
        "candidate_digest": "MAPPING_CANDIDATE_DIGEST_MISMATCH",
        "proposal_digest": "MAPPING_PROPOSAL_DIGEST_MISMATCH",
        "dsl_digest": "MAPPING_DSL_DIGEST_MISMATCH",
        "context_digest": "MAPPING_CONTEXT_DIGEST_MISMATCH",
        "evidence_digest": "MAPPING_EVIDENCE_DIGEST_MISMATCH",
        "available_tool_catalog_digest": "MAPPING_CATALOG_DIGEST_MISMATCH",
        "scope": "MAPPING_SCOPE_MISMATCH",
        "scope_digest": "MAPPING_SCOPE_DIGEST_MISMATCH",
    }

    def __init__(
        self,
        store: MappingConfirmationStore | ProductionMappingConfirmationStore,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.store = store
        self.clock = clock or store.clock

    def _lock(self):
        if isinstance(self.store, ProductionMappingConfirmationStore):
            return self.store._lock()
        return interprocess_lock(self.store.path)

    def require_active(
        self,
        receipt_digest: str,
        expected_identity: MappingAdmissionIdentity,
        *,
        now: datetime | None = None,
    ) -> MappingConfirmationReceipt:
        """Return the committed active confirmation or raise a stable code.

        ``expected_identity`` must be resolved from the consumer's trusted
        current Context/Candidate/Proposal/DSL stores.  Constructing it solely
        from caller payload would permit an old, internally consistent Context
        to be replayed after the authority has advanced its current head.
        """

        _validate_digest(receipt_digest)
        expected_identity = MappingAdmissionIdentity.model_validate(expected_identity.model_dump(mode="python"))
        with self._lock():
            receipts = self.store._load_unlocked()
            effective_now = self._validated_now(now)
            return self._require_active_from_receipts(
                receipt_digest,
                expected_identity,
                receipts,
                effective_now,
            )

    def commit_if_active(
        self,
        receipt_digest: str,
        expected_identity: MappingAdmissionIdentity,
        commit: Callable[[], Any],
        *,
        now: datetime | None = None,
    ) -> tuple[MappingConfirmationReceipt, Any]:
        """Linearize a quick artifact commit against cancel/reject writes.

        Expensive backend work must happen before this method.  The callback is
        executed while holding the same interprocess ledger lock used by
        ``cancel`` so either the cancellation wins and no commit occurs, or the
        already-authorized commit wins before the cancellation is appended.
        """

        _validate_digest(receipt_digest)
        expected_identity = MappingAdmissionIdentity.model_validate(expected_identity.model_dump(mode="python"))
        with self._lock():
            receipts = self.store._load_unlocked()
            effective_now = self._validated_now(now)
            receipt = self._require_active_from_receipts(
                receipt_digest,
                expected_identity,
                receipts,
                effective_now,
            )
            return receipt, commit()

    def _validated_now(self, value: datetime | None) -> datetime:
        result = value if value is not None else self.clock()
        if result.tzinfo is None or result.utcoffset() != timedelta(0):
            raise MappingAdmissionError("MAPPING_CONFIRMATION_TIME_INVALID")
        return result.astimezone(timezone.utc)

    def _require_active_from_receipts(
        self,
        receipt_digest: str,
        expected_identity: MappingAdmissionIdentity,
        receipts: list[MappingConfirmationReceipt],
        effective_now: datetime,
    ) -> MappingConfirmationReceipt:
        receipt = MappingConfirmationStore._find_receipt(receipts, receipt_digest)
        if receipt is None:
            raise MappingAdmissionError("MAPPING_CONFIRMATION_NOT_COMMITTED")
        if receipt.decision == "REJECTED":
            raise MappingAdmissionError("MAPPING_CONFIRMATION_REJECTED")
        if receipt.decision == "CANCELLED":
            raise MappingAdmissionError("MAPPING_CONFIRMATION_CANCELLED")
        latest = MappingConfirmationStore._latest_for_proposal(receipts, receipt.proposal_digest)
        if latest is None or latest.receipt_digest != receipt.receipt_digest:
            if latest is not None and latest.decision == "CANCELLED":
                raise MappingAdmissionError("MAPPING_CONFIRMATION_CANCELLED")
            raise MappingAdmissionError("MAPPING_CONFIRMATION_NOT_ACTIVE")
        for field, code in self._IDENTITY_MISMATCH_CODES.items():
            if getattr(receipt, field) != getattr(expected_identity, field):
                raise MappingAdmissionError(code)
        assert receipt.expires_at is not None
        normalized_now = effective_now.astimezone(timezone.utc)
        if normalized_now < receipt.decided_at:
            raise MappingAdmissionError("MAPPING_CONFIRMATION_NOT_YET_ACTIVE")
        if normalized_now >= receipt.expires_at:
            raise MappingAdmissionError("MAPPING_CONFIRMATION_EXPIRED")
        return receipt


class ProductionMappingAdmissionGate(MappingAdmissionGate):
    """Admission gate that cannot be constructed over fixture/local authority."""

    def __init__(
        self,
        store: ProductionMappingConfirmationStore,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not isinstance(store, ProductionMappingConfirmationStore):
            raise MappingAdmissionError("MAPPING_PRODUCTION_AUTHORITY_REQUIRED")
        super().__init__(store, clock=clock)

    def require_active(
        self,
        receipt_digest: str,
        expected_identity: MappingAdmissionIdentity,
        *,
        now: datetime | None = None,
    ) -> MappingConfirmationReceipt:
        """Resolve against a freshly challenged head and trusted clock.

        ``now`` is intentionally ignored at this production boundary; callers
        cannot override the deployment-owned trusted clock.
        """

        del now
        _validate_digest(receipt_digest)
        expected_identity = _validated_identity(expected_identity)
        store = self.store
        assert isinstance(store, ProductionMappingConfirmationStore)
        with self._lock():
            receipt, _, _, _, _, _, _ = (
                self._resolve_active_with_fresh_authority_unlocked(
                    store,
                    receipt_digest,
                    expected_identity,
                )
            )
            return receipt

    def commit_if_active(
        self,
        receipt_digest: str,
        expected_identity: MappingAdmissionIdentity,
        commit: Callable[[], Any],
        *,
        now: datetime | None = None,
    ) -> tuple[MappingConfirmationReceipt, Any]:
        """Run a callback only after a newly challenged signed head read."""

        del now
        _validate_digest(receipt_digest)
        expected_identity = _validated_identity(expected_identity)
        store = self.store
        assert isinstance(store, ProductionMappingConfirmationStore)
        with self._lock():
            (
                receipt,
                authority,
                operator_verification,
                acl_verification,
                anchor,
                head_verification,
                receipts,
            ) = (
                self._resolve_active_with_fresh_authority_unlocked(
                    store,
                    receipt_digest,
                    expected_identity,
                )
            )
            # Sample once more immediately before entering caller code.  No
            # external operation or filesystem write occurs between this
            # witness check and callback invocation.
            store._require_safe_paths()
            if store._ledger._load_unlocked() != receipts:
                raise MappingAdmissionError("MAPPING_LEDGER_ANCHOR_DIVERGED")
            callback_now = store._validated_time(None)
            store._revalidate_preverified_command_authority(
                authority.command,
                authority.operator_assertion,
                authority.acl_decision,
                operator_verification,
                acl_verification,
                callback_now,
            )
            store._require_anchor_witness_active(anchor, callback_now)
            store._require_verification_fresh(
                head_verification,
                callback_now,
                code="MAPPING_LEDGER_ANCHOR_VERIFICATION_STALE",
            )
            self._require_active_from_receipts(
                receipt_digest,
                expected_identity,
                receipts,
                callback_now,
            )
            return receipt, commit()

    def _resolve_active_with_fresh_authority_unlocked(
        self,
        store: ProductionMappingConfirmationStore,
        receipt_digest: str,
        expected_identity: MappingAdmissionIdentity,
    ) -> tuple[
        MappingConfirmationReceipt,
        MappingAuthorityReceipt,
        SignatureVerification,
        SignatureVerification,
        SignedLedgerHead,
        SignatureVerification,
        list[MappingConfirmationReceipt],
    ]:
        state_started_at = store._validated_time(None)
        receipts, authorities, anchor, head_verification = (
            store._load_verified_state_unlocked(state_started_at)
        )
        receipt = self._require_active_from_receipts(
            receipt_digest,
            expected_identity,
            receipts,
            state_started_at,
        )
        authority = next(
            (
                item
                for item in authorities
                if item.mapping_receipt_digest == receipt.receipt_digest
            ),
            None,
        )
        if authority is None:
            raise MappingAdmissionError("MAPPING_AUTHORITY_LEDGER_INCOMPLETE")

        verification_started_at = store._validated_time(None)
        operator_verification, acl_verification = store._verify_command_authority(
            authority.command,
            authority.operator_assertion,
            authority.acl_decision,
            receipt.decided_at,
            verification_time=verification_started_at,
        )
        # The authority verification above may be slow.  Obtain a second,
        # newly challenged external head after it so the callback/return path
        # never relies on the witness sampled at the start of this gate call.
        anchor, head_verification = (
            store._read_verified_anchor_for_state_unlocked(receipts, authorities)
        )
        resolved_at = store._validated_time(None)
        store._revalidate_preverified_command_authority(
            authority.command,
            authority.operator_assertion,
            authority.acl_decision,
            operator_verification,
            acl_verification,
            resolved_at,
        )
        store._require_anchor_witness_active(anchor, resolved_at)
        store._require_verification_fresh(
            head_verification,
            resolved_at,
            code="MAPPING_LEDGER_ANCHOR_VERIFICATION_STALE",
        )
        receipt = self._require_active_from_receipts(
            receipt_digest,
            expected_identity,
            receipts,
            resolved_at,
        )
        return (
            receipt,
            authority,
            operator_verification,
            acl_verification,
            anchor,
            head_verification,
            receipts,
        )


def bind_mapping_admission_gate(
    store: MappingConfirmationStore | ProductionMappingConfirmationStore | None,
    gate: MappingAdmissionGate | None = None,
) -> MappingAdmissionGate | None:
    """Bind a consumer to the exact store and its required authority mode."""

    if store is None:
        if gate is not None:
            raise MappingAdmissionError("MAPPING_ADMISSION_GATE_STORE_MISMATCH")
        return None
    if gate is not None and gate.store is not store:
        raise MappingAdmissionError("MAPPING_ADMISSION_GATE_STORE_MISMATCH")
    if isinstance(store, ProductionMappingConfirmationStore):
        if gate is not None and not isinstance(gate, ProductionMappingAdmissionGate):
            raise MappingAdmissionError("MAPPING_PRODUCTION_AUTHORITY_REQUIRED")
        return gate or ProductionMappingAdmissionGate(store)
    if isinstance(gate, ProductionMappingAdmissionGate):
        raise MappingAdmissionError("MAPPING_ADMISSION_GATE_STORE_MISMATCH")
    return gate or MappingAdmissionGate(store)


def canonical_mapping_bytes(value: Mapping[str, Any] | StrictModel) -> bytes:
    """Canonical UTF-8 bytes for Mapping admission digests."""

    payload = value.model_dump(mode="json") if isinstance(value, StrictModel) else dict(value)
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def mapping_digest(value: Mapping[str, Any] | StrictModel) -> str:
    """Return the canonical digest format used by new Mapping contracts."""

    return "sha256:" + hashlib.sha256(canonical_mapping_bytes(value)).hexdigest()


def mapping_target_identity_digest(target_id: str, target_fingerprint: str) -> str:
    return mapping_digest({"target_fingerprint": target_fingerprint, "target_id": target_id})


def mapping_scope_digest(scope: MappingAdmissionScope | Mapping[str, Any]) -> str:
    normalized = scope if isinstance(scope, MappingAdmissionScope) else MappingAdmissionScope.model_validate(scope)
    return mapping_digest(normalized)


def mapping_confirmation_receipt_digest(
    receipt: MappingConfirmationReceipt | Mapping[str, Any],
) -> str:
    payload = receipt.model_dump(mode="json") if isinstance(receipt, MappingConfirmationReceipt) else dict(receipt)
    payload.pop("receipt_digest", None)
    return mapping_digest(payload)


def mapping_authority_command_digest(
    command: MappingAuthorityCommand | Mapping[str, Any],
) -> str:
    payload = (
        command.model_dump(mode="json")
        if isinstance(command, MappingAuthorityCommand)
        else dict(command)
    )
    payload.pop("command_digest", None)
    return mapping_digest(payload)


def mapping_authority_receipt_digest(
    receipt: MappingAuthorityReceipt | Mapping[str, Any],
) -> str:
    payload = (
        receipt.model_dump(mode="json")
        if isinstance(receipt, MappingAuthorityReceipt)
        else dict(receipt)
    )
    payload.pop("authority_receipt_digest", None)
    return mapping_digest(payload)


def mapping_authority_pending_digest(
    pending: MappingAuthorityPending | Mapping[str, Any],
) -> str:
    payload = (
        pending.model_dump(mode="json")
        if isinstance(pending, MappingAuthorityPending)
        else dict(pending)
    )
    payload.pop("pending_digest", None)
    return mapping_digest(payload)


def mapping_production_head_digest(
    mapping_receipt_digest: str,
    authority_receipt_digest: str,
) -> str:
    _validate_digest(mapping_receipt_digest)
    _validate_digest(authority_receipt_digest)
    return mapping_digest(
        {
            "authority_receipt_digest": authority_receipt_digest,
            "mapping_receipt_digest": mapping_receipt_digest,
        }
    )


def _new_anchor_challenge() -> str:
    return "sha256:" + secrets.token_hex(32)


def _validated_identity(
    identity: MappingAdmissionIdentity,
) -> MappingAdmissionIdentity:
    try:
        return MappingAdmissionIdentity.model_validate(identity.model_dump(mode="python"))
    except Exception as exc:
        raise MappingAdmissionError("MAPPING_AUTHORITY_IDENTITY_INVALID") from exc


def _verify_signature_result_binding(
    verification: SignatureVerification,
    *,
    purpose: str,
    issuer_id: str,
    key_id: str,
    algorithm: str,
    payload_digest: str,
    verified_at: datetime | None = None,
) -> None:
    if (
        verification.purpose != purpose
        or verification.issuer_id != issuer_id
        or verification.key_id != key_id
        or verification.algorithm != algorithm
        or verification.payload_digest != payload_digest
        or verification.authority_class != PRODUCTION_AUTHORITY_CLASS
        or verification.key_status != "ACTIVE"
        or verification.status != "VERIFIED"
        or (verified_at is not None and verification.verified_at != verified_at)
    ):
        raise ValueError("signature verification is not bound to signed payload")


def _is_identifier(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(_IDENTIFIER_PATTERN, value) is not None


def _is_linklike(path: Path, metadata: os.stat_result | None = None) -> bool:
    if path.is_symlink():
        return True
    is_junction = getattr(path, "is_junction", None)
    if callable(is_junction) and is_junction():
        return True
    if metadata is None:
        try:
            metadata = os.lstat(path)
        except FileNotFoundError:
            return False
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return bool(
        reparse_flag
        and getattr(metadata, "st_file_attributes", 0) & reparse_flag
    )


def _require_regular_or_absent(
    path: Path,
    *,
    untrusted_code: str,
) -> os.stat_result | None:
    try:
        metadata = os.lstat(path)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise MappingAdmissionError(untrusted_code) from exc
    if (
        _is_linklike(path, metadata)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
    ):
        raise MappingAdmissionError(untrusted_code)
    return metadata


def _read_bounded_jsonl(
    path: Path,
    *,
    max_total_bytes: int,
    max_line_bytes: int,
    max_records: int,
    untrusted_code: str,
    unreadable_code: str,
    too_large_code: str,
    truncated_code: str,
    invalid_code: str,
) -> list[str]:
    metadata = _require_regular_or_absent(path, untrusted_code=untrusted_code)
    if metadata is None:
        return []
    if metadata.st_size > max_total_bytes:
        raise MappingAdmissionError(too_large_code)
    try:
        with path.open("rb") as stream:
            opened = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_nlink != 1
                or (opened.st_dev, opened.st_ino)
                != (metadata.st_dev, metadata.st_ino)
                or opened.st_size != metadata.st_size
            ):
                raise MappingAdmissionError(untrusted_code)
            content = stream.read(max_total_bytes + 1)
            final = os.fstat(stream.fileno())
    except MappingAdmissionError:
        raise
    except OSError as exc:
        raise MappingAdmissionError(unreadable_code) from exc
    if (
        len(content) > max_total_bytes
        or final.st_size != opened.st_size
        or len(content) != opened.st_size
    ):
        raise MappingAdmissionError(too_large_code)
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise MappingAdmissionError(invalid_code) from exc
    if text and not text.endswith("\n"):
        raise MappingAdmissionError(truncated_code)
    lines = text.splitlines()
    if len(lines) > max_records:
        raise MappingAdmissionError(too_large_code)
    if any(not line for line in lines):
        raise MappingAdmissionError(invalid_code)
    if any(len(line.encode("utf-8")) > max_line_bytes for line in lines):
        raise MappingAdmissionError(too_large_code)
    return lines


def _append_bounded_jsonl(
    path: Path,
    record: str,
    *,
    max_total_bytes: int,
    max_line_bytes: int,
    untrusted_code: str,
    too_large_code: str,
    write_failed_code: str,
) -> None:
    encoded = (record + "\n").encode("utf-8")
    if len(encoded) - 1 > max_line_bytes:
        raise MappingAdmissionError(too_large_code)
    previous = _require_regular_or_absent(path, untrusted_code=untrusted_code)
    previous_size = previous.st_size if previous is not None else 0
    if previous_size + len(encoded) > max_total_bytes:
        raise MappingAdmissionError(too_large_code)
    flags = os.O_APPEND | os.O_CREAT | os.O_WRONLY
    flags |= getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags, 0o600)
        opened = os.fstat(descriptor)
        current = os.lstat(path)
        if (
            _is_linklike(path, current)
            or not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino)
            or opened.st_size != previous_size
        ):
            raise MappingAdmissionError(untrusted_code)
        remaining = memoryview(encoded)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                raise OSError("short append")
            remaining = remaining[written:]
        os.fsync(descriptor)
    except MappingAdmissionError:
        raise
    except OSError as exc:
        raise MappingAdmissionError(write_failed_code) from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _require_safe_production_root(root: Path) -> None:
    for component in (root, *root.parents):
        try:
            metadata = os.lstat(component)
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise MappingAdmissionError("MAPPING_AUTHORITY_ROOT_UNTRUSTED") from exc
        if _is_linklike(component, metadata) or not stat.S_ISDIR(metadata.st_mode):
            raise MappingAdmissionError("MAPPING_AUTHORITY_ROOT_UNTRUSTED")


def _validate_digest(value: str) -> str:
    if not isinstance(value, str) or len(value) != 71 or not value.startswith("sha256:") or any(character not in "0123456789abcdef" for character in value[7:]):
        raise MappingAdmissionError("MAPPING_CONFIRMATION_DIGEST_INVALID")
    return value


__all__ = [
    "MAPPING_CONFIRMATION_RECEIPT_SCHEMA_VERSION",
    "MAPPING_AUTHORITY_COMMAND_SCHEMA_VERSION",
    "MAPPING_AUTHORITY_PENDING_SCHEMA_VERSION",
    "MAPPING_AUTHORITY_RECEIPT_SCHEMA_VERSION",
    "MAX_MAPPING_AUTHORITY_LEDGER_BYTES",
    "MAX_MAPPING_AUTHORITY_RECEIPT_BYTES",
    "MAX_MAPPING_LEDGER_BYTES",
    "MAX_MAPPING_LEDGER_RECEIPTS",
    "MAX_MAPPING_PENDING_BYTES",
    "MAX_MAPPING_RECEIPT_BYTES",
    "MAX_CONFIRMATION_TTL_S",
    "MappingAdmissionError",
    "MappingAdmissionGate",
    "MappingAdmissionIdentity",
    "MappingAdmissionScope",
    "MappingAuthorityCommand",
    "MappingAuthorityPending",
    "MappingAuthorityReconciliationStatus",
    "MappingAuthorityReceipt",
    "MappingConfirmationReceipt",
    "MappingConfirmationStore",
    "ProductionMappingConfirmationStore",
    "ProductionMappingAdmissionGate",
    "bind_mapping_admission_gate",
    "canonical_mapping_bytes",
    "mapping_confirmation_receipt_digest",
    "mapping_authority_command_digest",
    "mapping_authority_pending_digest",
    "mapping_authority_receipt_digest",
    "mapping_digest",
    "mapping_production_head_digest",
    "mapping_scope_digest",
    "mapping_target_identity_digest",
]
