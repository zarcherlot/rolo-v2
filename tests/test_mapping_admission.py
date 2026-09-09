from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Event, Thread

import pytest
from pydantic import ValidationError

import rolo.dsl.admission as admission_module
from rolo.core.persistence import interprocess_lock
from rolo.dsl.admission import (
    MAPPING_CONFIRMATION_RECEIPT_SCHEMA_VERSION,
    MappingAdmissionError,
    MappingAdmissionGate,
    MappingAdmissionIdentity,
    MappingAdmissionScope,
    MappingAuthorityCommand,
    MappingAuthorityPending,
    MappingAuthorityReceipt,
    MappingConfirmationReceipt,
    MappingConfirmationStore,
    ProductionMappingAdmissionGate,
    ProductionMappingConfirmationStore,
    bind_mapping_admission_gate,
    canonical_mapping_bytes,
    mapping_authority_receipt_digest,
    mapping_confirmation_receipt_digest,
    mapping_production_head_digest,
    mapping_scope_digest,
)
from rolo.releases.consumers import TraceConsumer
from rolo.security.authority import (
    ACL_DECISION_SCHEMA_VERSION,
    LEDGER_HEAD_SCHEMA_VERSION,
    OPERATOR_ASSERTION_SCHEMA_VERSION,
    PRODUCTION_AUTHORITY_CLASS,
    AuthorityRolePin,
    AuthorityRolePolicy,
    SignatureVerification,
    SignedAclDecision,
    SignedLedgerHead,
    SignedOperatorAssertion,
    canonical_authority_bytes,
    ledger_anchor_digest,
)
from rolo.targetd.protocol import (
    ProtocolError,
    TargetdExecutionAuthorityStore,
    TargetdMappingCancelRequest,
)
from rolo.targetd.service import TargetdService

NOW = datetime(2026, 9, 8, 4, 0, tzinfo=timezone.utc)


def _digest(character: str) -> str:
    return "sha256:" + character * 64


def _scope(*operations: str) -> MappingAdmissionScope:
    return MappingAdmissionScope(
        tool_id="app.mapping.status",
        operation_kind="OBSERVE",
        operations=operations or ("mapping.status",),
        access="read",
        risk="R0",
    )


def _identity(**updates: object) -> MappingAdmissionIdentity:
    values: dict[str, object] = {
        "journey_session_id": "journey-1",
        "target_id": "landerpi",
        "target_fingerprint": "target-fingerprint-1",
        "candidate_index_digest": _digest("1"),
        "candidate_digest": _digest("2"),
        "proposal_digest": _digest("3"),
        "dsl_digest": _digest("4"),
        "context_digest": _digest("5"),
        "evidence_digest": _digest("6"),
        "available_tool_catalog_digest": _digest("7"),
        "scope": _scope("mapping.status"),
    }
    values.update(updates)
    return MappingAdmissionIdentity.build(**values)  # type: ignore[arg-type]


def _assert_code(code: str, operation) -> None:
    with pytest.raises(MappingAdmissionError) as captured:
        operation()
    assert captured.value.code == code


def test_receipt_schema_is_explicit_and_matches_model() -> None:
    schema = json.loads(
        (
            Path(__file__).parents[1]
            / "schemas/rolo-dsl/v1/mapping-confirmation-receipt.json"
        ).read_text(encoding="utf-8")
    )
    assert schema["additionalProperties"] is False
    assert (
        schema["properties"]["schema_version"]["const"]
        == MAPPING_CONFIRMATION_RECEIPT_SCHEMA_VERSION
    )
    assert set(schema["required"]) == set(MappingConfirmationReceipt.model_fields)
    assert set(schema["properties"]) == set(MappingConfirmationReceipt.model_fields)

    store = MappingConfirmationStore(Path("unused"), clock=lambda: NOW)
    receipt = MappingConfirmationReceipt.build(
        _identity(),
        sequence=1,
        decision_id="decision-1",
        actor_id="operator@example",
        decision="CONFIRMED",
        decided_at=NOW,
        expires_at=NOW + timedelta(minutes=15),
        supersedes_receipt_digest=None,
        previous_receipt_digest=None,
    )
    payload = receipt.model_dump(mode="json")
    payload.pop("schema_version")
    with pytest.raises(ValidationError):
        MappingConfirmationReceipt.model_validate(payload)
    assert store.path.name == "mapping-confirmations.jsonl"


def test_receipt_digest_is_canonical_and_covers_every_unsigned_field() -> None:
    receipt = MappingConfirmationReceipt.build(
        _identity(),
        sequence=1,
        decision_id="decision-1",
        actor_id="operator@example",
        decision="CONFIRMED",
        decided_at=NOW,
        expires_at=NOW + timedelta(minutes=15),
        supersedes_receipt_digest=None,
        previous_receipt_digest=None,
    )
    payload = receipt.model_dump(mode="json")
    reversed_payload = dict(reversed(tuple(payload.items())))
    assert canonical_mapping_bytes(payload) == canonical_mapping_bytes(reversed_payload)
    assert mapping_confirmation_receipt_digest(receipt) == receipt.receipt_digest

    tampered = dict(payload)
    tampered["actor_id"] = "other-operator"
    assert mapping_confirmation_receipt_digest(tampered) != receipt.receipt_digest


def test_committed_confirmation_is_active_and_exact_replay_is_idempotent(
    tmp_path: Path,
) -> None:
    store = MappingConfirmationStore(tmp_path, clock=lambda: NOW)
    identity = _identity()
    first = store.confirm(
        identity,
        decision_id="confirm-1",
        actor_id="operator@example",
        ttl_s=900,
    )
    replay = store.confirm(
        identity,
        decision_id="confirm-1",
        actor_id="operator@example",
        ttl_s=900,
        decided_at=NOW + timedelta(seconds=30),
    )

    assert replay == first
    assert len(store.receipts()) == 1
    assert (
        MappingAdmissionGate(store).require_active(
            first.receipt_digest,
            identity,
            now=NOW + timedelta(minutes=1),
        )
        == first
    )
    assert store.resolve(first.receipt_digest) == first


def test_decision_id_reuse_with_changed_identity_actor_or_ttl_is_blocked(
    tmp_path: Path,
) -> None:
    store = MappingConfirmationStore(tmp_path, clock=lambda: NOW)
    identity = _identity()
    store.confirm(
        identity,
        decision_id="confirm-1",
        actor_id="operator@example",
        ttl_s=900,
    )

    _assert_code(
        "MAPPING_DECISION_ID_REUSED",
        lambda: store.confirm(
            _identity(dsl_digest=_digest("8")),
            decision_id="confirm-1",
            actor_id="operator@example",
            ttl_s=900,
        ),
    )
    _assert_code(
        "MAPPING_DECISION_ID_REUSED",
        lambda: store.confirm(
            identity,
            decision_id="confirm-1",
            actor_id="other-operator",
            ttl_s=900,
        ),
    )
    _assert_code(
        "MAPPING_DECISION_ID_REUSED",
        lambda: store.confirm(
            identity,
            decision_id="confirm-1",
            actor_id="operator@example",
            ttl_s=901,
        ),
    )


def test_rejection_is_terminal_and_never_admitted(tmp_path: Path) -> None:
    store = MappingConfirmationStore(tmp_path, clock=lambda: NOW)
    identity = _identity()
    rejected = store.reject(
        identity,
        decision_id="reject-1",
        actor_id="operator@example",
    )

    _assert_code(
        "MAPPING_CONFIRMATION_REJECTED",
        lambda: MappingAdmissionGate(store).require_active(
            rejected.receipt_digest, identity, now=NOW
        ),
    )
    _assert_code(
        "MAPPING_PROPOSAL_TERMINAL",
        lambda: store.confirm(
            identity,
            decision_id="confirm-after-reject",
            actor_id="operator@example",
        ),
    )


def test_cancellation_is_an_append_only_tombstone_for_old_confirmation(
    tmp_path: Path,
) -> None:
    store = MappingConfirmationStore(tmp_path, clock=lambda: NOW)
    identity = _identity()
    confirmed = store.confirm(
        identity,
        decision_id="confirm-1",
        actor_id="operator@example",
    )
    cancelled = store.cancel(
        confirmed.receipt_digest,
        decision_id="cancel-1",
        actor_id="operator@example",
        decided_at=NOW + timedelta(minutes=1),
    )
    replay = store.cancel(
        confirmed.receipt_digest,
        decision_id="cancel-1",
        actor_id="operator@example",
        decided_at=NOW + timedelta(minutes=2),
    )

    assert replay == cancelled
    assert cancelled.sequence == 2
    assert cancelled.previous_receipt_digest == confirmed.receipt_digest
    assert cancelled.supersedes_receipt_digest == confirmed.receipt_digest
    assert [item.decision for item in store.receipts()] == [
        "CONFIRMED",
        "CANCELLED",
    ]
    _assert_code(
        "MAPPING_CONFIRMATION_CANCELLED",
        lambda: MappingAdmissionGate(store).require_active(
            confirmed.receipt_digest, identity, now=NOW + timedelta(minutes=2)
        ),
    )


def test_expired_and_uncommitted_receipts_fail_closed(tmp_path: Path) -> None:
    store = MappingConfirmationStore(tmp_path, clock=lambda: NOW)
    identity = _identity()
    committed = store.confirm(
        identity,
        decision_id="confirm-1",
        actor_id="operator@example",
        ttl_s=60,
    )
    _assert_code(
        "MAPPING_CONFIRMATION_EXPIRED",
        lambda: MappingAdmissionGate(store).require_active(
            committed.receipt_digest,
            identity,
            now=NOW + timedelta(seconds=60),
        ),
    )
    forged = MappingConfirmationReceipt.build(
        _identity(proposal_digest=_digest("8")),
        sequence=2,
        decision_id="forged",
        actor_id="operator@example",
        decision="CONFIRMED",
        decided_at=NOW,
        expires_at=NOW + timedelta(minutes=15),
        supersedes_receipt_digest=None,
        previous_receipt_digest=committed.receipt_digest,
    )
    _assert_code(
        "MAPPING_CONFIRMATION_NOT_COMMITTED",
        lambda: MappingAdmissionGate(store).require_active(
            forged.receipt_digest,
            forged.admission_identity(),
            now=NOW,
        ),
    )


def test_future_dated_confirmation_is_not_active_before_decision_time(
    tmp_path: Path,
) -> None:
    store = MappingConfirmationStore(tmp_path, clock=lambda: NOW)
    identity = _identity()
    future = store.confirm(
        identity,
        decision_id="future-confirmation",
        actor_id="operator@example",
        ttl_s=60,
        decided_at=NOW + timedelta(days=1),
    )
    _assert_code(
        "MAPPING_CONFIRMATION_NOT_YET_ACTIVE",
        lambda: MappingAdmissionGate(store).require_active(
            future.receipt_digest,
            identity,
            now=NOW,
        ),
    )


def test_commit_rechecks_trusted_clock_after_waiting_for_ledger_lock(
    tmp_path: Path,
) -> None:
    now = [NOW]
    store = MappingConfirmationStore(tmp_path, clock=lambda: now[0])
    identity = _identity()
    receipt = store.confirm(
        identity,
        decision_id="short-confirmation",
        actor_id="operator@example",
        ttl_s=1,
    )
    started = Event()
    committed: list[bool] = []
    errors: list[MappingAdmissionError] = []

    def attempt_commit() -> None:
        started.set()
        try:
            MappingAdmissionGate(store).commit_if_active(
                receipt.receipt_digest,
                identity,
                lambda: committed.append(True),
            )
        except MappingAdmissionError as exc:
            errors.append(exc)

    with interprocess_lock(store.path):
        worker = Thread(target=attempt_commit)
        worker.start()
        assert started.wait(timeout=1)
        now[0] = NOW + timedelta(seconds=2)
    worker.join(timeout=2)

    assert not worker.is_alive()
    assert committed == []
    assert [error.code for error in errors] == ["MAPPING_CONFIRMATION_EXPIRED"]

@pytest.mark.parametrize(
    ("update", "code"),
    [
        ({"journey_session_id": "journey-2"}, "MAPPING_JOURNEY_SESSION_MISMATCH"),
        (
            {"target_id": "other-target", "target_fingerprint": "other-fingerprint"},
            "MAPPING_TARGET_ID_MISMATCH",
        ),
        ({"candidate_digest": _digest("8")}, "MAPPING_CANDIDATE_DIGEST_MISMATCH"),
        ({"proposal_digest": _digest("8")}, "MAPPING_PROPOSAL_DIGEST_MISMATCH"),
        ({"dsl_digest": _digest("8")}, "MAPPING_DSL_DIGEST_MISMATCH"),
        ({"context_digest": _digest("8")}, "MAPPING_CONTEXT_DIGEST_MISMATCH"),
        ({"evidence_digest": _digest("8")}, "MAPPING_EVIDENCE_DIGEST_MISMATCH"),
        (
            {"available_tool_catalog_digest": _digest("8")},
            "MAPPING_CATALOG_DIGEST_MISMATCH",
        ),
        (
            {"scope": _scope("mapping.run", "mapping.status")},
            "MAPPING_SCOPE_MISMATCH",
        ),
    ],
)
def test_identity_drift_and_scope_expansion_are_blocked(
    tmp_path: Path, update: dict[str, object], code: str
) -> None:
    store = MappingConfirmationStore(tmp_path, clock=lambda: NOW)
    confirmed_identity = _identity()
    receipt = store.confirm(
        confirmed_identity,
        decision_id="confirm-1",
        actor_id="operator@example",
    )
    current_identity = _identity(**update)

    _assert_code(
        code,
        lambda: MappingAdmissionGate(store).require_active(
            receipt.receipt_digest, current_identity, now=NOW
        ),
    )


def test_ledger_detects_payload_tampering_and_chain_forks(tmp_path: Path) -> None:
    store = MappingConfirmationStore(tmp_path, clock=lambda: NOW)
    first = store.confirm(
        _identity(),
        decision_id="confirm-1",
        actor_id="operator@example",
    )
    second = store.confirm(
        _identity(proposal_digest=_digest("8")),
        decision_id="confirm-2",
        actor_id="operator@example",
    )
    lines = store.path.read_text(encoding="utf-8").splitlines()
    tampered = json.loads(lines[1])
    tampered["previous_receipt_digest"] = _digest("f")
    tampered["receipt_digest"] = mapping_confirmation_receipt_digest(tampered)
    store.path.write_text(
        lines[0] + "\n" + json.dumps(tampered, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    assert first.receipt_digest != second.receipt_digest
    _assert_code(
        "MAPPING_CONFIRMATION_LEDGER_CHAIN_INVALID",
        store.receipts,
    )


def test_ledger_detects_truncated_tail(tmp_path: Path) -> None:
    store = MappingConfirmationStore(tmp_path, clock=lambda: NOW)
    store.confirm(
        _identity(),
        decision_id="confirm-1",
        actor_id="operator@example",
    )
    store.path.write_text(
        store.path.read_text(encoding="utf-8").rstrip("\n"),
        encoding="utf-8",
    )
    _assert_code("MAPPING_CONFIRMATION_LEDGER_TRUNCATED", store.receipts)


def test_scope_digest_and_receipt_fields_reject_internal_tampering() -> None:
    scope = _scope("mapping.status")
    assert mapping_scope_digest(scope) == mapping_scope_digest(
        scope.model_dump(mode="json")
    )
    identity = _identity()
    with pytest.raises(ValidationError, match="scope digest"):
        MappingAdmissionIdentity.model_validate(
            {**identity.model_dump(mode="json"), "scope_digest": _digest("f")}
        )
    with pytest.raises(ValidationError, match="known target fingerprint"):
        _identity(target_fingerprint="UNKNOWN")


def _fixture_signature(purpose: str, key_id: str, payload: bytes) -> str:
    """Deterministic test-only signature; never exported by production code."""

    return hashlib.sha256(
        purpose.encode("ascii") + b"\0" + key_id.encode("ascii") + b"\0" + payload
    ).hexdigest()


def _signed_authority_artifact(model, payload: dict[str, object], purpose: str):
    signed_payload = canonical_authority_bytes(payload)
    key_id = str(payload["key_id"])
    return model.model_validate(
        {
            **payload,
            "payload_digest": "sha256:" + hashlib.sha256(signed_payload).hexdigest(),
            "signature": _fixture_signature(purpose, key_id, signed_payload),
        }
    )


class _FixtureExternalSignatureVerifier:
    provider_id = "test-external-signatures"
    authority_class = PRODUCTION_AUTHORITY_CLASS

    def __init__(self) -> None:
        self.reject = False
        self.timeout_purpose: str | None = None
        self.on_verify = None
        self.calls: list[str] = []
        self.trust_roots = {
            "OPERATOR_ASSERTION": _digest("d"),
            "ACL_DECISION": _digest("e"),
            "LEDGER_HEAD": _digest("f"),
        }

    def verify(
        self,
        *,
        purpose,
        issuer_id,
        key_id,
        algorithm,
        payload,
        payload_digest,
        signature,
        now,
    ) -> SignatureVerification:
        self.calls.append(purpose)
        if purpose == self.timeout_purpose:
            raise TimeoutError("fixture verifier deadline exceeded")
        actual_digest = "sha256:" + hashlib.sha256(payload).hexdigest()
        if (
            self.reject
            or payload_digest != actual_digest
            or signature != _fixture_signature(purpose, key_id, payload)
        ):
            raise ValueError("fixture signature rejected")
        if self.on_verify is not None:
            self.on_verify(purpose)
        return SignatureVerification(
            provider_id=self.provider_id,
            authority_class=PRODUCTION_AUTHORITY_CLASS,
            purpose=purpose,
            issuer_id=issuer_id,
            key_id=key_id,
            algorithm=algorithm,
            payload_digest=payload_digest,
            trust_root_digest=self.trust_roots[purpose],
            key_status="ACTIVE",
            status="VERIFIED",
            verified_at=now,
        )


def _role_policy() -> AuthorityRolePolicy:
    return AuthorityRolePolicy(
        operator_assertion=AuthorityRolePin(
            purpose="OPERATOR_ASSERTION",
            issuer_id="test-operator-idp",
            key_id="operator-key-1",
            trust_root_digest=_digest("d"),
        ),
        acl_decision=AuthorityRolePin(
            purpose="ACL_DECISION",
            issuer_id="test-acl-authority",
            key_id="acl-key-1",
            trust_root_digest=_digest("e"),
        ),
        ledger_head=AuthorityRolePin(
            purpose="LEDGER_HEAD",
            issuer_id="test-anchor-authority",
            key_id="anchor-key-1",
            trust_root_digest=_digest("f"),
        ),
    )


class _FixtureExternalHeadAnchor:
    provider_id = "test-external-anchor"
    authority_class = PRODUCTION_AUTHORITY_CLASS

    def __init__(self, ledger_id: str) -> None:
        self.fail_advance = False
        self.advance_then_raise = False
        self.ignore_minimum = False
        self.replay_read: SignedLedgerHead | None = None
        self.read_timeout = False
        self.bad_read_signature = False
        self.on_read = None
        self.on_advance_committed = None
        self.witness_clock = None
        self.advance_calls = 0
        self.read_challenges: list[str] = []
        self.head_issuer_id = "test-anchor-authority"
        self.head_key_id = "anchor-key-1"
        self.current = self._head(
            ledger_id=ledger_id,
            epoch=1,
            sequence=0,
            head_digest=None,
            previous_anchor_digest=None,
            recorded_at=NOW - timedelta(seconds=30),
            challenge_digest=_digest("a"),
            witnessed_at=NOW,
        )
        self.history = [self.current]

    def _head(
        self,
        *,
        ledger_id: str,
        epoch: int,
        sequence: int,
        head_digest: str | None,
        previous_anchor_digest: str | None,
        recorded_at: datetime,
        challenge_digest: str,
        witnessed_at: datetime,
    ) -> SignedLedgerHead:
        payload: dict[str, object] = {
            "schema_version": LEDGER_HEAD_SCHEMA_VERSION,
            "anchor_provider_id": self.provider_id,
            "ledger_id": ledger_id,
            "epoch": epoch,
            "sequence": sequence,
            "head_digest": head_digest,
            "previous_anchor_digest": previous_anchor_digest,
            "recorded_at": recorded_at,
            "challenge_digest": challenge_digest,
            "witnessed_at": witnessed_at,
            "expires_at": witnessed_at + timedelta(seconds=20),
            "issuer_id": self.head_issuer_id,
            "key_id": self.head_key_id,
            "algorithm": "EdDSA",
        }
        payload["anchor_digest"] = ledger_anchor_digest(payload)
        return _signed_authority_artifact(
            SignedLedgerHead,
            payload,
            "LEDGER_HEAD",
        )

    def read_head(
        self,
        ledger_id: str,
        *,
        minimum_epoch: int,
        challenge_digest: str,
        now: datetime,
    ) -> SignedLedgerHead:
        assert ledger_id == self.current.ledger_id
        self.read_challenges.append(challenge_digest)
        if self.read_timeout:
            raise TimeoutError("fixture anchor read deadline exceeded")
        if not self.ignore_minimum and self.current.epoch < minimum_epoch:
            raise ValueError("external monotonic floor violated")
        if self.replay_read is not None:
            return self.replay_read
        result = self._head(
            ledger_id=self.current.ledger_id,
            epoch=self.current.epoch,
            sequence=self.current.sequence,
            head_digest=self.current.head_digest,
            previous_anchor_digest=self.current.previous_anchor_digest,
            recorded_at=self.current.recorded_at,
            challenge_digest=challenge_digest,
            witnessed_at=now,
        )
        if self.bad_read_signature:
            return result.model_copy(update={"signature": "f" * 64})
        if self.on_read is not None:
            self.on_read()
        return result

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
        self.advance_calls += 1
        if self.fail_advance:
            raise ValueError("external CAS unavailable")
        if (
            ledger_id != self.current.ledger_id
            or expected_anchor_digest != self.current.anchor_digest
            or next_sequence != self.current.sequence + 1
        ):
            raise ValueError("external CAS conflict")
        if self.on_advance_committed is not None:
            self.on_advance_committed()
        witnessed_at = self.witness_clock() if self.witness_clock is not None else now
        self.current = self._head(
            ledger_id=ledger_id,
            epoch=self.current.epoch + 1,
            sequence=next_sequence,
            head_digest=next_head_digest,
            previous_anchor_digest=self.current.anchor_digest,
            recorded_at=now,
            challenge_digest=challenge_digest,
            witnessed_at=witnessed_at,
        )
        self.history.append(self.current)
        if self.advance_then_raise:
            raise TimeoutError("external CAS response lost")
        return self.current


def _production_store(tmp_path: Path):
    verifier = _FixtureExternalSignatureVerifier()
    anchor = _FixtureExternalHeadAnchor("mapping-ledger-1")
    store = ProductionMappingConfirmationStore(
        tmp_path,
        ledger_id="mapping-ledger-1",
        signature_verifier=verifier,
        head_anchor=anchor,
        role_policy=_role_policy(),
        clock=lambda: NOW,
    )
    return store, verifier, anchor


def _authority_evidence(
    command: MappingAuthorityCommand,
    *,
    nonce: str,
    authorization_id: str,
    effect: str = "ALLOW",
    principal_id: str = "operator:alice",
    operator_issuer_id: str = "test-operator-idp",
    operator_key_id: str = "operator-key-1",
    acl_principal_id: str | None = None,
    acl_subject_issuer_id: str | None = None,
    acl_authority_id: str = "test-acl-authority",
    acl_key_id: str = "acl-key-1",
    acl_scope_digest: str | None = None,
):
    assertion = _signed_authority_artifact(
        SignedOperatorAssertion,
        {
            "schema_version": OPERATOR_ASSERTION_SCHEMA_VERSION,
            "issuer_id": operator_issuer_id,
            "principal_id": principal_id,
            "key_id": operator_key_id,
            "algorithm": "EdDSA",
            "audience": "rolo-mapping-admission",
            "nonce": nonce,
            "challenge_digest": command.command_digest,
            "authentication_method": "HARDWARE_KEY",
            "issued_at": NOW - timedelta(seconds=10),
            "expires_at": NOW + timedelta(minutes=4),
        },
        "OPERATOR_ASSERTION",
    )
    acl = _signed_authority_artifact(
        SignedAclDecision,
        {
            "schema_version": ACL_DECISION_SCHEMA_VERSION,
            "authority_id": acl_authority_id,
            "authorization_id": authorization_id,
            "subject_issuer_id": (
                acl_subject_issuer_id or operator_issuer_id
            ),
            "subject_principal_id": acl_principal_id or principal_id,
            "key_id": acl_key_id,
            "algorithm": "EdDSA",
            "action": command.action,
            "resource_digest": command.proposal_digest,
            "scope_digest": acl_scope_digest or command.scope_digest,
            "request_digest": command.command_digest,
            "effect": effect,
            "policy_digest": _digest("d"),
            "policy_revision": 7,
            "max_confirmation_ttl_s": 900,
            "issued_at": NOW - timedelta(seconds=10),
            "expires_at": NOW + timedelta(minutes=4),
        },
        "ACL_DECISION",
    )
    return assertion, acl


def test_production_authority_schemas_are_strict_and_match_models() -> None:
    root = Path(__file__).parents[1] / "schemas"
    checks = (
        (
            root / "security/operator-assertion.json",
            SignedOperatorAssertion,
            OPERATOR_ASSERTION_SCHEMA_VERSION,
        ),
        (
            root / "security/acl-decision.json",
            SignedAclDecision,
            ACL_DECISION_SCHEMA_VERSION,
        ),
        (
            root / "security/ledger-head.json",
            SignedLedgerHead,
            LEDGER_HEAD_SCHEMA_VERSION,
        ),
        (
            root / "rolo-dsl/v1/mapping-authority-command.json",
            MappingAuthorityCommand,
            "rolo-mapping-authority-command/v1",
        ),
        (
            root / "rolo-dsl/v1/mapping-authority-receipt.json",
            MappingAuthorityReceipt,
            "rolo-mapping-authority-receipt/v1",
        ),
        (
            root / "rolo-dsl/v1/mapping-authority-pending.json",
            MappingAuthorityPending,
            "rolo-mapping-authority-pending/v1",
        ),
    )
    for path, model, version in checks:
        schema = json.loads(path.read_text(encoding="utf-8"))
        assert schema["additionalProperties"] is False
        assert schema["properties"]["schema_version"]["const"] == version
        assert set(schema["properties"]) == set(model.model_fields)
        assert set(schema["required"]) == set(model.model_fields)

    role_schema = json.loads(
        (root / "security/authority-role-policy.json").read_text(encoding="utf-8")
    )
    assert role_schema["additionalProperties"] is False
    assert set(role_schema["properties"]) == set(AuthorityRolePolicy.model_fields)
    assert set(role_schema["required"]) == set(AuthorityRolePolicy.model_fields)


def test_production_confirmation_requires_signed_identity_acl_and_anchor(
    tmp_path: Path,
) -> None:
    store, verifier, anchor = _production_store(tmp_path)
    identity = _identity()
    command = store.prepare_confirm(identity, decision_id="prod-confirm-1", ttl_s=900)
    assertion, acl = _authority_evidence(
        command,
        nonce="operator-nonce-1",
        authorization_id="acl-decision-1",
    )

    receipt = store.confirm(
        identity,
        command=command,
        operator_assertion=assertion,
        acl_decision=acl,
    )
    replay = store.confirm(
        identity,
        command=command,
        operator_assertion=assertion,
        acl_decision=acl,
    )

    assert replay == receipt
    assert receipt.actor_id == "operator:alice"
    assert MappingConfirmationStore.authority_mode == "OFFLINE_FIXTURE"
    assert store.authority_mode == PRODUCTION_AUTHORITY_CLASS
    assert len(store.receipts()) == 1
    authority_receipt = store.authority_receipts()[0]
    assert authority_receipt.command == command
    assert authority_receipt.operator_assertion == assertion
    assert authority_receipt.acl_decision == acl
    assert anchor.current.sequence == 1
    assert anchor.current.head_digest == mapping_production_head_digest(
        receipt.receipt_digest,
        authority_receipt.authority_receipt_digest,
    )
    assert set(verifier.calls) == {
        "OPERATOR_ASSERTION",
        "ACL_DECISION",
        "LEDGER_HEAD",
    }
    assert (
        ProductionMappingAdmissionGate(store).require_active(
            receipt.receipt_digest,
            identity,
            now=NOW + timedelta(minutes=1),
        )
        == receipt
    )


@pytest.mark.parametrize(
    ("change", "code"),
    [
        ("deny", "MAPPING_ACL_DENIED"),
        ("principal", "MAPPING_ACL_PRINCIPAL_MISMATCH"),
        ("scope", "MAPPING_ACL_SCOPE_MISMATCH"),
        ("signature", "MAPPING_AUTHORITY_SIGNATURE_INVALID"),
    ],
)
def test_production_authority_failures_do_not_append(
    tmp_path: Path,
    change: str,
    code: str,
) -> None:
    store, _, anchor = _production_store(tmp_path)
    identity = _identity()
    command = store.prepare_confirm(identity, decision_id="prod-confirm-1", ttl_s=900)
    assertion, acl = _authority_evidence(
        command,
        nonce="operator-nonce-1",
        authorization_id="acl-decision-1",
        effect="DENY" if change == "deny" else "ALLOW",
        acl_principal_id="operator:bob" if change == "principal" else None,
        acl_scope_digest=_digest("a") if change == "scope" else None,
    )
    if change == "signature":
        assertion = assertion.model_copy(update={"signature": "f" * 64})

    _assert_code(
        code,
        lambda: store.confirm(
            identity,
            command=command,
            operator_assertion=assertion,
            acl_decision=acl,
        ),
    )
    assert not store.path.exists()
    assert not store.authority_path.exists()
    assert anchor.current.sequence == 0


def test_lock_wait_rechecks_authority_expiry_before_any_append_or_anchor(
    tmp_path: Path,
) -> None:
    current_time = [NOW]
    verifier = _FixtureExternalSignatureVerifier()
    anchor = _FixtureExternalHeadAnchor("mapping-ledger-1")
    store = ProductionMappingConfirmationStore(
        tmp_path,
        ledger_id="mapping-ledger-1",
        signature_verifier=verifier,
        head_anchor=anchor,
        role_policy=_role_policy(),
        clock=lambda: current_time[0],
    )
    identity = _identity()
    command = store.prepare_confirm(
        identity, decision_id="prod-confirm-after-wait", ttl_s=900
    )
    assertion, acl = _authority_evidence(
        command,
        nonce="operator-nonce-after-wait",
        authorization_id="acl-decision-after-wait",
    )
    started = Event()
    errors: list[MappingAdmissionError] = []

    def attempt_confirm() -> None:
        started.set()
        try:
            store.confirm(
                identity,
                command=command,
                operator_assertion=assertion,
                acl_decision=acl,
            )
        except MappingAdmissionError as exc:
            errors.append(exc)

    with interprocess_lock(store.path):
        worker = Thread(target=attempt_confirm)
        worker.start()
        assert started.wait(timeout=1)
        current_time[0] = NOW + timedelta(minutes=5)
    worker.join(timeout=2)

    assert not worker.is_alive()
    assert [error.code for error in errors] == [
        "MAPPING_OPERATOR_ASSERTION_INACTIVE"
    ]
    assert not store.path.exists()
    assert not store.authority_path.exists()
    assert not store.pending_path.exists()
    assert anchor.current.sequence == 0


def test_slow_verifier_crossing_authority_expiry_is_zero_write(
    tmp_path: Path,
) -> None:
    current_time = [NOW]
    verifier = _FixtureExternalSignatureVerifier()
    anchor = _FixtureExternalHeadAnchor("mapping-ledger-1")
    store = ProductionMappingConfirmationStore(
        tmp_path,
        ledger_id="mapping-ledger-1",
        signature_verifier=verifier,
        head_anchor=anchor,
        role_policy=_role_policy(),
        clock=lambda: current_time[0],
    )
    identity = _identity()
    command = store.prepare_confirm(
        identity,
        decision_id="prod-confirm-slow-verifier",
        ttl_s=900,
    )
    assertion, acl = _authority_evidence(
        command,
        nonce="operator-nonce-slow-verifier",
        authorization_id="acl-decision-slow-verifier",
    )
    verifier.on_verify = lambda purpose: (
        current_time.__setitem__(0, NOW + timedelta(minutes=5))
        if purpose == "OPERATOR_ASSERTION"
        else None
    )

    _assert_code(
        "MAPPING_OPERATOR_ASSERTION_INACTIVE",
        lambda: store.confirm(
            identity,
            command=command,
            operator_assertion=assertion,
            acl_decision=acl,
        ),
    )
    assert not store.path.exists()
    assert not store.authority_path.exists()
    assert not store.pending_path.exists()
    assert anchor.current.sequence == 0
    assert anchor.advance_calls == 0


def test_slow_anchor_commit_crossing_authority_expiry_returns_once_then_is_inactive(
    tmp_path: Path,
) -> None:
    current_time = [NOW]
    verifier = _FixtureExternalSignatureVerifier()
    anchor = _FixtureExternalHeadAnchor("mapping-ledger-1")
    store = ProductionMappingConfirmationStore(
        tmp_path,
        ledger_id="mapping-ledger-1",
        signature_verifier=verifier,
        head_anchor=anchor,
        role_policy=_role_policy(),
        clock=lambda: current_time[0],
    )
    identity = _identity()
    command = store.prepare_confirm(
        identity,
        decision_id="prod-confirm-slow-anchor",
        ttl_s=900,
    )
    assertion, acl = _authority_evidence(
        command,
        nonce="operator-nonce-slow-anchor",
        authorization_id="acl-decision-slow-anchor",
    )
    anchor.on_advance_committed = lambda: current_time.__setitem__(
        0,
        NOW + timedelta(minutes=5),
    )
    # A real anchor timestamps its response with its own trusted clock.  This
    # fixture mirrors that behavior after the simulated slow CAS completes.
    anchor.witness_clock = lambda: current_time[0]

    receipt = store.confirm(
        identity,
        command=command,
        operator_assertion=assertion,
        acl_decision=acl,
    )

    assert receipt.sequence == 1
    assert anchor.current.sequence == 1
    assert anchor.advance_calls == 1
    assert not store.pending_path.exists()
    assert len(store.path.read_text(encoding="utf-8").splitlines()) == 1
    assert len(store.authority_path.read_text(encoding="utf-8").splitlines()) == 1
    _assert_code(
        "MAPPING_OPERATOR_ASSERTION_INACTIVE",
        lambda: ProductionMappingAdmissionGate(store).require_active(
            receipt.receipt_digest,
            identity,
        ),
    )
    _assert_code(
        "MAPPING_OPERATOR_ASSERTION_INACTIVE",
        lambda: store.confirm(
            identity,
            command=command,
            operator_assertion=assertion,
            acl_decision=acl,
        ),
    )
    assert anchor.advance_calls == 1
    assert anchor.current.sequence == 1


def test_production_commit_gate_never_calls_back_after_head_witness_goes_stale(
    tmp_path: Path,
) -> None:
    current_time = [NOW]
    verifier = _FixtureExternalSignatureVerifier()
    anchor = _FixtureExternalHeadAnchor("mapping-ledger-1")
    store = ProductionMappingConfirmationStore(
        tmp_path,
        ledger_id="mapping-ledger-1",
        signature_verifier=verifier,
        head_anchor=anchor,
        role_policy=_role_policy(),
        clock=lambda: current_time[0],
    )
    identity = _identity()
    command = store.prepare_confirm(
        identity,
        decision_id="prod-confirm-before-stale-head",
        ttl_s=900,
    )
    assertion, acl = _authority_evidence(
        command,
        nonce="operator-nonce-before-stale-head",
        authorization_id="acl-decision-before-stale-head",
    )
    receipt = store.confirm(
        identity,
        command=command,
        operator_assertion=assertion,
        acl_decision=acl,
    )
    callbacks: list[str] = []
    anchor.on_read = lambda: current_time.__setitem__(
        0,
        NOW + timedelta(seconds=21),
    )

    _assert_code(
        "MAPPING_LEDGER_ANCHOR_STALE",
        lambda: ProductionMappingAdmissionGate(store).commit_if_active(
            receipt.receipt_digest,
            identity,
            lambda: callbacks.append("executed"),
        ),
    )
    assert callbacks == []


def test_production_commit_gate_refreshes_head_after_slow_authority_verification(
    tmp_path: Path,
) -> None:
    current_time = [NOW]
    verifier = _FixtureExternalSignatureVerifier()
    anchor = _FixtureExternalHeadAnchor("mapping-ledger-1")
    store = ProductionMappingConfirmationStore(
        tmp_path,
        ledger_id="mapping-ledger-1",
        signature_verifier=verifier,
        head_anchor=anchor,
        role_policy=_role_policy(),
        clock=lambda: current_time[0],
    )
    identity = _identity()
    command = store.prepare_confirm(
        identity,
        decision_id="prod-confirm-before-head-refresh",
        ttl_s=900,
    )
    assertion, acl = _authority_evidence(
        command,
        nonce="operator-nonce-before-head-refresh",
        authorization_id="acl-decision-before-head-refresh",
    )
    receipt = store.confirm(
        identity,
        command=command,
        operator_assertion=assertion,
        acl_decision=acl,
    )
    verifier.calls.clear()
    anchor.read_challenges.clear()

    def advance_during_requested_authority(purpose: str) -> None:
        # Historical operator+ACL and the first head are calls 1-3.  Advance
        # while the requested receipt's operator proof is being reverified.
        if purpose == "OPERATOR_ASSERTION" and len(verifier.calls) == 4:
            current_time[0] = NOW + timedelta(seconds=21)

    verifier.on_verify = advance_during_requested_authority
    callbacks: list[str] = []
    _, result = ProductionMappingAdmissionGate(store).commit_if_active(
        receipt.receipt_digest,
        identity,
        lambda: callbacks.append("executed") or "ok",
    )

    assert result == "ok"
    assert callbacks == ["executed"]
    assert len(anchor.read_challenges) == 2
    assert anchor.read_challenges[0] != anchor.read_challenges[1]


def test_fail_closed_lock_never_steals_a_live_owner_by_mtime(
    tmp_path: Path,
) -> None:
    target = tmp_path / "mapping-confirmations.jsonl"
    with interprocess_lock(target, stale_after_s=None):
        lock_paths = tuple(tmp_path.glob(".l*"))
        assert len(lock_paths) == 1
        os.utime(lock_paths[0], (0, 0))
        with pytest.raises(TimeoutError):
            with interprocess_lock(
                target,
                timeout_s=0.05,
                stale_after_s=None,
            ):
                raise AssertionError("a live fail-closed lock was stolen")
    assert not tuple(tmp_path.glob(".l*"))


def test_idempotent_confirmation_rechecks_receipt_expiry(
    tmp_path: Path,
) -> None:
    current_time = [NOW]
    verifier = _FixtureExternalSignatureVerifier()
    anchor = _FixtureExternalHeadAnchor("mapping-ledger-1")
    store = ProductionMappingConfirmationStore(
        tmp_path,
        ledger_id="mapping-ledger-1",
        signature_verifier=verifier,
        head_anchor=anchor,
        role_policy=_role_policy(),
        clock=lambda: current_time[0],
    )
    identity = _identity()
    command = store.prepare_confirm(
        identity, decision_id="prod-short-confirm", ttl_s=1
    )
    assertion, acl = _authority_evidence(
        command,
        nonce="operator-nonce-short-confirm",
        authorization_id="acl-decision-short-confirm",
    )
    store.confirm(
        identity,
        command=command,
        operator_assertion=assertion,
        acl_decision=acl,
    )
    current_time[0] = NOW + timedelta(seconds=1)

    _assert_code(
        "MAPPING_CONFIRMATION_EXPIRED",
        lambda: store.confirm(
            identity,
            command=command,
            operator_assertion=assertion,
            acl_decision=acl,
        ),
    )
    assert len(store.path.read_text(encoding="utf-8").splitlines()) == 1
    assert len(store.authority_path.read_text(encoding="utf-8").splitlines()) == 1
    assert anchor.current.sequence == 1


def test_acl_authorization_id_replay_is_rejected_before_any_write(
    tmp_path: Path,
) -> None:
    store, _, anchor = _production_store(tmp_path)
    first_identity = _identity()
    first_command = store.prepare_confirm(
        first_identity, decision_id="prod-confirm-1", ttl_s=900
    )
    first_assertion, first_acl = _authority_evidence(
        first_command,
        nonce="operator-nonce-1",
        authorization_id="shared-acl-decision",
    )
    store.confirm(
        first_identity,
        command=first_command,
        operator_assertion=first_assertion,
        acl_decision=first_acl,
    )
    second_identity = _identity(proposal_digest=_digest("8"))
    second_command = store.prepare_confirm(
        second_identity, decision_id="prod-confirm-2", ttl_s=900
    )
    second_assertion, second_acl = _authority_evidence(
        second_command,
        nonce="operator-nonce-2",
        authorization_id="shared-acl-decision",
    )

    _assert_code(
        "MAPPING_ACL_AUTHORIZATION_REPLAY",
        lambda: store.confirm(
            second_identity,
            command=second_command,
            operator_assertion=second_assertion,
            acl_decision=second_acl,
        ),
    )
    assert len(store.path.read_text(encoding="utf-8").splitlines()) == 1
    assert len(store.authority_path.read_text(encoding="utf-8").splitlines()) == 1
    assert not store.pending_path.exists()
    assert anchor.current.sequence == 1


@pytest.mark.parametrize(
    ("change", "code"),
    [
        ("subject_issuer", "MAPPING_ACL_SUBJECT_ISSUER_MISMATCH"),
        ("issuer_role", "MAPPING_AUTHORITY_ROLE_COLLISION"),
        ("key_role", "MAPPING_AUTHORITY_ROLE_COLLISION"),
        ("trust_root_role", "MAPPING_AUTHORITY_ROLE_COLLISION"),
    ],
)
def test_operator_and_acl_roles_are_issuer_key_and_trust_root_isolated(
    tmp_path: Path,
    change: str,
    code: str,
) -> None:
    store, verifier, anchor = _production_store(tmp_path)
    identity = _identity()
    command = store.prepare_confirm(
        identity, decision_id="prod-role-isolation", ttl_s=900
    )
    assertion, acl = _authority_evidence(
        command,
        nonce="operator-nonce-role-isolation",
        authorization_id="acl-decision-role-isolation",
        acl_subject_issuer_id=(
            "different-operator-idp" if change == "subject_issuer" else None
        ),
        acl_authority_id=(
            "test-operator-idp" if change == "issuer_role" else "test-acl-authority"
        ),
        acl_key_id=(
            "operator-key-1" if change == "key_role" else "acl-key-1"
        ),
    )
    if change == "trust_root_role":
        verifier.trust_roots["ACL_DECISION"] = verifier.trust_roots[
            "OPERATOR_ASSERTION"
        ]

    _assert_code(
        code,
        lambda: store.confirm(
            identity,
            command=command,
            operator_assertion=assertion,
            acl_decision=acl,
        ),
    )
    assert not store.path.exists()
    assert not store.authority_path.exists()
    assert not store.pending_path.exists()
    assert anchor.current.sequence == 0


def test_ledger_head_cannot_reuse_operator_issuer_key_or_trust_root(
    tmp_path: Path,
) -> None:
    store, verifier, anchor = _production_store(tmp_path)
    anchor.head_issuer_id = "test-operator-idp"
    anchor.head_key_id = "operator-key-1"
    verifier.trust_roots["LEDGER_HEAD"] = verifier.trust_roots[
        "OPERATOR_ASSERTION"
    ]
    identity = _identity()
    command = store.prepare_confirm(
        identity,
        decision_id="prod-head-role-collision",
        ttl_s=900,
    )
    assertion, acl = _authority_evidence(
        command,
        nonce="operator-nonce-head-role-collision",
        authorization_id="acl-decision-head-role-collision",
    )

    _assert_code(
        "MAPPING_AUTHORITY_ROLE_COLLISION",
        lambda: store.confirm(
            identity,
            command=command,
            operator_assertion=assertion,
            acl_decision=acl,
        ),
    )
    assert not store.path.exists()
    assert not store.authority_path.exists()
    assert not store.pending_path.exists()
    assert anchor.current.sequence == 0
    assert anchor.advance_calls == 0


def test_authority_role_policy_requires_three_mutually_isolated_pins() -> None:
    payload = _role_policy().model_dump(mode="python")
    payload["ledger_head"]["trust_root_digest"] = payload["operator_assertion"][
        "trust_root_digest"
    ]
    with pytest.raises(ValidationError, match="mutually isolated"):
        AuthorityRolePolicy.model_validate(payload)


def test_invalid_cancel_authority_never_executes_guard(
    tmp_path: Path,
) -> None:
    store, _, anchor = _production_store(tmp_path)
    identity = _identity()
    confirm_command = store.prepare_confirm(
        identity, decision_id="prod-confirm-before-bad-cancel", ttl_s=900
    )
    confirm_assertion, confirm_acl = _authority_evidence(
        confirm_command,
        nonce="operator-nonce-before-bad-cancel",
        authorization_id="acl-decision-before-bad-cancel",
    )
    confirmed = store.confirm(
        identity,
        command=confirm_command,
        operator_assertion=confirm_assertion,
        acl_decision=confirm_acl,
    )
    cancel_command = store.prepare_cancel(
        confirmed.receipt_digest,
        identity,
        decision_id="prod-bad-cancel",
    )
    cancel_assertion, cancel_acl = _authority_evidence(
        cancel_command,
        nonce="operator-nonce-bad-cancel",
        authorization_id="acl-decision-bad-cancel",
    )
    cancel_assertion = cancel_assertion.model_copy(update={"signature": "f" * 64})
    side_effects: list[str] = []

    _assert_code(
        "MAPPING_AUTHORITY_SIGNATURE_INVALID",
        lambda: store.cancel(
            confirmed.receipt_digest,
            identity,
            command=cancel_command,
            operator_assertion=cancel_assertion,
            acl_decision=cancel_acl,
            guard=lambda: side_effects.append("guard-ran"),
        ),
    )
    assert side_effects == []
    assert len(store.path.read_text(encoding="utf-8").splitlines()) == 1
    assert len(store.authority_path.read_text(encoding="utf-8").splitlines()) == 1
    assert not store.pending_path.exists()
    assert anchor.current.sequence == 1


def test_external_anchor_detects_local_tail_deletion_and_remote_rollback(
    tmp_path: Path,
) -> None:
    store, _, anchor = _production_store(tmp_path)
    first_identity = _identity()
    first_command = store.prepare_confirm(
        first_identity, decision_id="prod-confirm-1", ttl_s=900
    )
    first_assertion, first_acl = _authority_evidence(
        first_command,
        nonce="operator-nonce-1",
        authorization_id="acl-decision-1",
    )
    store.confirm(
        first_identity,
        command=first_command,
        operator_assertion=first_assertion,
        acl_decision=first_acl,
    )
    second_identity = _identity(proposal_digest=_digest("8"))
    second_command = store.prepare_confirm(
        second_identity, decision_id="prod-confirm-2", ttl_s=900
    )
    second_assertion, second_acl = _authority_evidence(
        second_command,
        nonce="operator-nonce-2",
        authorization_id="acl-decision-2",
    )
    store.confirm(
        second_identity,
        command=second_command,
        operator_assertion=second_assertion,
        acl_decision=second_acl,
    )

    mapping_lines = store.path.read_text(encoding="utf-8").splitlines()
    authority_lines = store.authority_path.read_text(encoding="utf-8").splitlines()
    store.path.write_text(mapping_lines[0] + "\n", encoding="utf-8")
    store.authority_path.write_text(authority_lines[0] + "\n", encoding="utf-8")
    _assert_code("MAPPING_LEDGER_ANCHOR_DIVERGED", store.receipts)

    store.path.write_text("\n".join(mapping_lines) + "\n", encoding="utf-8")
    store.authority_path.write_text(
        "\n".join(authority_lines) + "\n", encoding="utf-8"
    )
    anchor.current = anchor.history[1]
    anchor.ignore_minimum = True
    _assert_code("MAPPING_LEDGER_ANCHOR_DIVERGED", store.receipts)


def test_challenged_head_blocks_historical_signed_head_and_dual_ledger_rollback(
    tmp_path: Path,
) -> None:
    store, _, anchor = _production_store(tmp_path)
    for sequence, proposal in ((1, "3"), (2, "8")):
        identity = _identity(proposal_digest=_digest(proposal))
        command = store.prepare_confirm(
            identity,
            decision_id=f"prod-confirm-{sequence}",
            ttl_s=900,
        )
        assertion, acl = _authority_evidence(
            command,
            nonce=f"operator-nonce-{sequence}",
            authorization_id=f"acl-decision-{sequence}",
        )
        store.confirm(
            identity,
            command=command,
            operator_assertion=assertion,
            acl_decision=acl,
        )

    mapping_lines = store.path.read_text(encoding="utf-8").splitlines()
    authority_lines = store.authority_path.read_text(encoding="utf-8").splitlines()
    store.path.write_text(mapping_lines[0] + "\n", encoding="utf-8")
    store.authority_path.write_text(authority_lines[0] + "\n", encoding="utf-8")
    # This is a valid historical signature over exactly the rolled-back local
    # state, but it was issued for an earlier one-time read/advance challenge.
    anchor.replay_read = anchor.history[1]

    _assert_code("MAPPING_LEDGER_ANCHOR_CHALLENGE_MISMATCH", store.receipts)
    status = store.reconciliation_status()
    assert status.state == "DIVERGED"
    assert status.diagnostic_code == "MAPPING_LEDGER_ANCHOR_CHALLENGE_MISMATCH"


def test_head_freshness_and_anchor_failure_classes_are_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, _, anchor = _production_store(tmp_path)
    monkeypatch.setattr(admission_module, "_new_anchor_challenge", lambda: _digest("b"))
    anchor.replay_read = anchor._head(
        ledger_id=anchor.current.ledger_id,
        epoch=anchor.current.epoch,
        sequence=anchor.current.sequence,
        head_digest=anchor.current.head_digest,
        previous_anchor_digest=anchor.current.previous_anchor_digest,
        recorded_at=NOW - timedelta(minutes=2),
        challenge_digest=_digest("b"),
        witnessed_at=NOW - timedelta(minutes=1),
    )
    _assert_code("MAPPING_LEDGER_ANCHOR_STALE", store.receipts)

    anchor.replay_read = None
    anchor.bad_read_signature = True
    _assert_code("MAPPING_LEDGER_ANCHOR_SIGNATURE_INVALID", store.receipts)
    bad_signature_status = store.reconciliation_status()
    assert bad_signature_status.state == "DIVERGED"
    assert (
        bad_signature_status.diagnostic_code
        == "MAPPING_LEDGER_ANCHOR_SIGNATURE_INVALID"
    )

    anchor.bad_read_signature = False
    anchor.read_timeout = True
    _assert_code("MAPPING_LEDGER_ANCHOR_UNAVAILABLE", store.receipts)
    unavailable_status = store.reconciliation_status()
    assert unavailable_status.state == "EXTERNAL_UNAVAILABLE"
    assert unavailable_status.diagnostic_code == "MAPPING_LEDGER_ANCHOR_UNAVAILABLE"


def test_signature_verifier_timeout_is_not_reported_as_invalid_evidence(
    tmp_path: Path,
) -> None:
    store, verifier, anchor = _production_store(tmp_path)
    identity = _identity()
    command = store.prepare_confirm(
        identity, decision_id="prod-verifier-timeout", ttl_s=900
    )
    assertion, acl = _authority_evidence(
        command,
        nonce="operator-nonce-verifier-timeout",
        authorization_id="acl-decision-verifier-timeout",
    )
    verifier.timeout_purpose = "OPERATOR_ASSERTION"

    _assert_code(
        "MAPPING_AUTHORITY_VERIFIER_UNAVAILABLE",
        lambda: store.confirm(
            identity,
            command=command,
            operator_assertion=assertion,
            acl_decision=acl,
        ),
    )
    assert not store.path.exists()
    assert not store.authority_path.exists()
    assert not store.pending_path.exists()
    assert anchor.current.sequence == 0


def test_external_anchor_predecessor_is_bound_to_last_authority_receipt(
    tmp_path: Path,
) -> None:
    store, _, anchor = _production_store(tmp_path)
    identity = _identity()
    command = store.prepare_confirm(
        identity, decision_id="prod-confirm-1", ttl_s=900
    )
    assertion, acl = _authority_evidence(
        command,
        nonce="operator-nonce-1",
        authorization_id="acl-decision-1",
    )
    store.confirm(
        identity,
        command=command,
        operator_assertion=assertion,
        acl_decision=acl,
    )
    anchor.current = anchor._head(
        ledger_id=anchor.current.ledger_id,
        epoch=anchor.current.epoch,
        sequence=anchor.current.sequence,
        head_digest=anchor.current.head_digest,
        previous_anchor_digest=_digest("a"),
        recorded_at=anchor.current.recorded_at,
        challenge_digest=_digest("b"),
        witnessed_at=NOW,
    )

    _assert_code("MAPPING_LEDGER_ANCHOR_DIVERGED", store.receipts)


def test_anchor_advance_failure_never_returns_authority_and_poisoned_cache_fails_closed(
    tmp_path: Path,
) -> None:
    store, _, anchor = _production_store(tmp_path)
    identity = _identity()
    command = store.prepare_confirm(identity, decision_id="prod-confirm-1", ttl_s=900)
    assertion, acl = _authority_evidence(
        command,
        nonce="operator-nonce-1",
        authorization_id="acl-decision-1",
    )
    anchor.fail_advance = True

    _assert_code(
        "MAPPING_LEDGER_ANCHOR_ADVANCE_FAILED",
        lambda: store.confirm(
            identity,
            command=command,
            operator_assertion=assertion,
            acl_decision=acl,
        ),
    )
    assert anchor.current.sequence == 0
    _assert_code("MAPPING_AUTHORITY_RECONCILIATION_REQUIRED", store.receipts)
    status = store.reconciliation_status()
    assert status.state == "LOCAL_PENDING_ANCHOR"
    assert status.local_mapping_sequence == status.local_authority_sequence == 1
    assert store.reconcile_pending() == status


def test_lost_anchor_response_requires_explicit_reconciliation_before_active(
    tmp_path: Path,
) -> None:
    store, _, anchor = _production_store(tmp_path)
    identity = _identity()
    command = store.prepare_confirm(identity, decision_id="prod-confirm-1", ttl_s=900)
    assertion, acl = _authority_evidence(
        command,
        nonce="operator-nonce-1",
        authorization_id="acl-decision-1",
    )
    anchor.advance_then_raise = True

    _assert_code(
        "MAPPING_LEDGER_ANCHOR_UNAVAILABLE",
        lambda: store.confirm(
            identity,
            command=command,
            operator_assertion=assertion,
            acl_decision=acl,
        ),
    )
    assert anchor.current.sequence == 1
    _assert_code(
        "MAPPING_AUTHORITY_RECONCILIATION_REQUIRED",
        lambda: ProductionMappingAdmissionGate(store).require_active(
            store._ledger.receipts()[0].receipt_digest,
            identity,
            now=NOW,
        ),
    )
    status = store.reconciliation_status()
    assert status.state == "ANCHOR_COMMIT_UNCERTAIN"
    assert status.diagnostic_code == "MAPPING_LEDGER_ANCHOR_COMMIT_REQUIRES_ACK"

    reconciled = store.reconcile_pending()
    assert reconciled.state == "CLEAN"
    receipt = store.receipts()[0]
    assert (
        ProductionMappingAdmissionGate(store).require_active(
            receipt.receipt_digest,
            identity,
            now=NOW,
        )
        == receipt
    )


def test_first_local_append_failure_is_pending_but_safely_discardable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, _, anchor = _production_store(tmp_path)
    identity = _identity()
    command = store.prepare_confirm(identity, decision_id="prod-confirm-1", ttl_s=900)
    assertion, acl = _authority_evidence(
        command,
        nonce="operator-nonce-1",
        authorization_id="acl-decision-1",
    )

    def fail_mapping_append(_receipt) -> None:
        raise MappingAdmissionError("MAPPING_AUTHORITY_MAPPING_APPEND_FAILED")

    monkeypatch.setattr(store, "_append_mapping_unlocked", fail_mapping_append)
    _assert_code(
        "MAPPING_AUTHORITY_MAPPING_APPEND_FAILED",
        lambda: store.confirm(
            identity,
            command=command,
            operator_assertion=assertion,
            acl_decision=acl,
        ),
    )
    _assert_code("MAPPING_AUTHORITY_RECONCILIATION_REQUIRED", store.receipts)
    status = store.reconciliation_status()
    assert status.state == "PREPARED_NO_LOCAL_APPEND"
    assert anchor.current.sequence == 0
    assert store.reconcile_pending().state == "CLEAN"
    assert store.receipts() == ()


def test_second_local_append_failure_never_exposes_partial_pair(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, _, anchor = _production_store(tmp_path)
    identity = _identity()
    command = store.prepare_confirm(identity, decision_id="prod-confirm-1", ttl_s=900)
    assertion, acl = _authority_evidence(
        command,
        nonce="operator-nonce-1",
        authorization_id="acl-decision-1",
    )

    def fail_authority_append(_receipt) -> None:
        raise MappingAdmissionError("MAPPING_AUTHORITY_EVIDENCE_APPEND_FAILED")

    monkeypatch.setattr(store, "_append_authority_unlocked", fail_authority_append)
    _assert_code(
        "MAPPING_AUTHORITY_EVIDENCE_APPEND_FAILED",
        lambda: store.confirm(
            identity,
            command=command,
            operator_assertion=assertion,
            acl_decision=acl,
        ),
    )
    _assert_code("MAPPING_AUTHORITY_RECONCILIATION_REQUIRED", store.receipts)
    status = store.reconciliation_status()
    assert status.state == "LOCAL_PAIR_INCOMPLETE"
    assert status.local_mapping_sequence == 1
    assert status.local_authority_sequence == 0
    assert anchor.current.sequence == 0
    assert store.reconcile_pending() == status


def test_production_cancel_requires_new_signed_acl_and_revokes_admission(
    tmp_path: Path,
) -> None:
    store, _, anchor = _production_store(tmp_path)
    identity = _identity()
    confirm_command = store.prepare_confirm(
        identity, decision_id="prod-confirm-1", ttl_s=900
    )
    assertion, acl = _authority_evidence(
        confirm_command,
        nonce="operator-nonce-1",
        authorization_id="acl-decision-1",
    )
    confirmed = store.confirm(
        identity,
        command=confirm_command,
        operator_assertion=assertion,
        acl_decision=acl,
    )
    cancel_command = store.prepare_cancel(
        confirmed.receipt_digest,
        identity,
        decision_id="prod-cancel-1",
    )
    cancel_assertion, cancel_acl = _authority_evidence(
        cancel_command,
        nonce="operator-nonce-2",
        authorization_id="acl-decision-2",
    )
    cancelled = store.cancel(
        confirmed.receipt_digest,
        identity,
        command=cancel_command,
        operator_assertion=cancel_assertion,
        acl_decision=cancel_acl,
    )

    assert cancelled.decision == "CANCELLED"
    assert cancelled.supersedes_receipt_digest == confirmed.receipt_digest
    assert anchor.current.sequence == 2
    _assert_code(
        "MAPPING_CONFIRMATION_CANCELLED",
        lambda: ProductionMappingAdmissionGate(store).require_active(
            confirmed.receipt_digest,
            identity,
            now=NOW,
        ),
    )


def test_production_store_rejects_non_external_provider_configuration(
    tmp_path: Path,
) -> None:
    verifier = _FixtureExternalSignatureVerifier()
    anchor = _FixtureExternalHeadAnchor("mapping-ledger-1")
    verifier.authority_class = "OFFLINE_FIXTURE"
    _assert_code(
        "MAPPING_SIGNATURE_VERIFIER_UNTRUSTED",
        lambda: ProductionMappingConfirmationStore(
            tmp_path,
            ledger_id="mapping-ledger-1",
            signature_verifier=verifier,
            head_anchor=anchor,
            role_policy=_role_policy(),
        ),
    )
    _assert_code(
        "MAPPING_PRODUCTION_AUTHORITY_REQUIRED",
        lambda: ProductionMappingAdmissionGate(MappingConfirmationStore(tmp_path)),  # type: ignore[arg-type]
    )
    valid_verifier = _FixtureExternalSignatureVerifier()
    _assert_code(
        "MAPPING_SIGNATURE_VERIFIER_UNTRUSTED",
        lambda: ProductionMappingConfirmationStore(
            tmp_path / "fixture-verifier",
            ledger_id="mapping-ledger-1",
            signature_verifier=MappingConfirmationStore(tmp_path / "legacy"),  # type: ignore[arg-type]
            head_anchor=anchor,
            role_policy=_role_policy(),
        ),
    )
    _assert_code(
        "MAPPING_LEDGER_ANCHOR_UNTRUSTED",
        lambda: ProductionMappingConfirmationStore(
            tmp_path / "fixture-anchor",
            ledger_id="mapping-ledger-1",
            signature_verifier=valid_verifier,
            head_anchor=MappingConfirmationStore(tmp_path / "legacy"),  # type: ignore[arg-type]
            role_policy=_role_policy(),
        ),
    )


def test_product_consumers_bind_the_exact_production_gate_and_store(
    tmp_path: Path,
) -> None:
    store, _, _ = _production_store(tmp_path / "authority")
    gate = ProductionMappingAdmissionGate(store)
    targetd = TargetdService(
        target_id="landerpi",
        state_root=tmp_path / "targetd",
        confirmation_store=store,
        admission_gate=gate,
    )
    consumer = TraceConsumer(
        confirmation_store=store,
        admission_gate=gate,
    )

    assert targetd.confirmation_store is store
    assert targetd.admission_gate is gate
    assert consumer.confirmation_store is store
    assert consumer.admission_gate is gate
    _assert_code(
        "MAPPING_PRODUCTION_AUTHORITY_REQUIRED",
        lambda: bind_mapping_admission_gate(store, MappingAdmissionGate(store)),
    )


def test_targetd_unsigned_cancel_is_unavailable_for_production_store(
    tmp_path: Path,
) -> None:
    store, _, anchor = _production_store(tmp_path / "authority")
    service = TargetdService(
        target_id="landerpi",
        state_root=tmp_path / "targetd",
        confirmation_store=store,
        execution_authority_store=TargetdExecutionAuthorityStore(
            tmp_path / "execution-authority"
        ),
    )
    request = TargetdMappingCancelRequest(
        schema_version="rolo-targetd-mapping-cancel/v1",
        tool_id="app.mapping.status",
        authority_head_digest="a" * 64,
        mapping_confirmation_receipt_digest=_digest("b"),
        idempotency_key="unsigned-production-cancel",
    )

    with pytest.raises(ProtocolError, match="TARGETD_SIGNED_MAPPING_CANCEL_REQUIRED"):
        service.cancel_mapping(request, session_id="untrusted-session")
    assert not store.path.exists()
    assert not store.authority_path.exists()
    assert not store.pending_path.exists()
    assert anchor.current.sequence == 0


def test_production_root_rejects_regular_file_and_linklike_ancestor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    verifier = _FixtureExternalSignatureVerifier()
    anchor = _FixtureExternalHeadAnchor("mapping-ledger-1")
    root_file = tmp_path / "not-a-directory"
    root_file.write_text("not a directory", encoding="utf-8")
    _assert_code(
        "MAPPING_AUTHORITY_ROOT_UNTRUSTED",
        lambda: ProductionMappingConfirmationStore(
            root_file,
            ledger_id="mapping-ledger-1",
            signature_verifier=verifier,
            head_anchor=anchor,
            role_policy=_role_policy(),
        ),
    )

    ancestor = tmp_path / "junction-like"
    ancestor.mkdir()
    monkeypatch.setattr(
        Path,
        "is_junction",
        lambda path: path == ancestor,
        raising=False,
    )
    _assert_code(
        "MAPPING_AUTHORITY_ROOT_UNTRUSTED",
        lambda: ProductionMappingConfirmationStore(
            ancestor / "admission",
            ledger_id="mapping-ledger-1",
            signature_verifier=verifier,
            head_anchor=anchor,
            role_policy=_role_policy(),
        ),
    )


def test_production_root_is_rechecked_before_each_ledger_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, _, _ = _production_store(tmp_path)
    monkeypatch.setattr(
        Path,
        "is_junction",
        lambda path: path == store.root,
        raising=False,
    )

    _assert_code("MAPPING_AUTHORITY_ROOT_UNTRUSTED", store.receipts)


def test_production_ledger_rejects_hardlinked_file(
    tmp_path: Path,
) -> None:
    store, _, _ = _production_store(tmp_path)
    identity = _identity()
    command = store.prepare_confirm(identity, decision_id="prod-confirm-1", ttl_s=900)
    assertion, acl = _authority_evidence(
        command,
        nonce="operator-nonce-1",
        authorization_id="acl-decision-1",
    )
    store.confirm(
        identity,
        command=command,
        operator_assertion=assertion,
        acl_decision=acl,
    )
    os.link(store.path, tmp_path / "mapping-hardlink.jsonl")

    _assert_code("MAPPING_AUTHORITY_LEDGER_UNTRUSTED", store.receipts)


def test_production_ledger_checks_size_before_json_parsing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, _, _ = _production_store(tmp_path)
    store.root.mkdir(parents=True, exist_ok=True)
    store.path.write_bytes(b"x" * 33)
    monkeypatch.setattr(admission_module, "MAX_MAPPING_LEDGER_BYTES", 32)

    def must_not_parse(_value: str):
        raise AssertionError("oversized ledger reached JSON parser")

    monkeypatch.setattr(admission_module, "loads_unique_json", must_not_parse)
    _assert_code("MAPPING_CONFIRMATION_LEDGER_TOO_LARGE", store.receipts)


@pytest.mark.parametrize(
    ("content", "limit_name", "limit"),
    [
        (b'{}\n{}\n', "MAX_MAPPING_LEDGER_RECEIPTS", 1),
        (b'{"padding":"0123456789"}\n', "MAX_MAPPING_RECEIPT_BYTES", 8),
    ],
)
def test_production_ledger_checks_record_and_line_limits_before_json_parsing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    content: bytes,
    limit_name: str,
    limit: int,
) -> None:
    store, _, _ = _production_store(tmp_path)
    store.root.mkdir(parents=True, exist_ok=True)
    store.path.write_bytes(content)
    monkeypatch.setattr(admission_module, limit_name, limit)

    def must_not_parse(_value: str):
        raise AssertionError("out-of-bounds ledger reached JSON parser")

    monkeypatch.setattr(admission_module, "loads_unique_json", must_not_parse)
    _assert_code("MAPPING_CONFIRMATION_LEDGER_TOO_LARGE", store.receipts)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("provider_id", "other-production-verifier"),
        ("verified_at", "2026-09-08T04:00:01Z"),
    ],
)
def test_stored_signature_verification_is_fully_bound_to_provider_and_time(
    tmp_path: Path,
    field: str,
    value: str,
) -> None:
    store, _, _ = _production_store(tmp_path)
    identity = _identity()
    command = store.prepare_confirm(identity, decision_id="prod-confirm-1", ttl_s=900)
    assertion, acl = _authority_evidence(
        command,
        nonce="operator-nonce-1",
        authorization_id="acl-decision-1",
    )
    store.confirm(
        identity,
        command=command,
        operator_assertion=assertion,
        acl_decision=acl,
    )
    payload = json.loads(store.authority_path.read_text(encoding="utf-8"))
    payload["operator_verification"][field] = value
    payload["authority_receipt_digest"] = mapping_authority_receipt_digest(payload)
    store.authority_path.write_text(
        json.dumps(payload, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    _assert_code("MAPPING_AUTHORITY_LEDGER_BINDING_INVALID", store.receipts)
