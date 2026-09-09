from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from rolo.dsl.admission import MappingAdmissionScope, mapping_digest
from rolo.dsl.candidates import CapabilityCandidate, CapabilityCandidateIndex
from rolo.dsl.canonical import context_digest, dsl_digest
from rolo.dsl.context import ProbeContext
from rolo.dsl.models import DslDocument
from rolo.dsl.parser import parse_document
from rolo.dsl.proposal import MappingProposal
from rolo.security.authority import (
    PRODUCTION_AUTHORITY_CLASS,
    AuthorityProviderUnavailableError,
    AuthorityRolePin,
    AuthorityRolePolicy,
    SignatureVerification,
    SignedOperatorAssertion,
    authority_digest,
    authority_signed_payload_digest,
)
from rolo.security.production import (
    DerivedScopeResolver,
    MappingFoundationReferences,
    OperationPolicy,
    OperationPolicyCatalog,
    ProductionAuthorityCompositionError,
    ProductionAuthorityCompositionPolicy,
    SignedCurrentHead,
    SignedFoundationArtifact,
    TransportCurrentHeadResolver,
    TransportSignatureVerifier,
    TransportTrustedClock,
    TrustedTimeWitness,
    compose_production_mapping_authority,
)

NOW = datetime(2026, 9, 9, 1, 0, tzinfo=timezone.utc)
SIGNATURE = "s" * 64


def _digest(label: str) -> str:
    return authority_digest({"label": label})


def _signed(payload: dict[str, Any]) -> dict[str, Any]:
    def normalize(value: Any) -> Any:
        if isinstance(value, dict):
            return {key: normalize(item) for key, item in value.items()}
        if isinstance(value, list):
            return [normalize(item) for item in value]
        if isinstance(value, tuple):
            return [normalize(item) for item in value]
        if isinstance(value, str) and value.endswith("+00:00") and "T" in value:
            return value[:-6] + "Z"
        return value

    normalized = normalize(payload)
    return {
        **normalized,
        "payload_digest": authority_signed_payload_digest(normalized),
        "signature": SIGNATURE,
    }


class _Transport:
    authority_class = PRODUCTION_AUTHORITY_CLASS

    def __init__(self, provider_id: str, handler: Any) -> None:
        self.provider_id = provider_id
        self.handler = handler
        self.calls: list[tuple[str, dict[str, Any], float]] = []

    def request(
        self,
        operation: str,
        payload: dict[str, Any],
        *,
        timeout_s: float,
    ) -> dict[str, Any]:
        self.calls.append((operation, dict(payload), timeout_s))
        return self.handler(operation, dict(payload))


def _pins() -> dict[str, AuthorityRolePin]:
    purposes = (
        "OPERATOR_ASSERTION",
        "ACL_DECISION",
        "LEDGER_HEAD",
        "TRUSTED_TIME",
        "FOUNDATION_ARTIFACT",
        "CURRENT_HEAD",
    )
    return {
        purpose: AuthorityRolePin(
            purpose=purpose,
            issuer_id=f"issuer-{index}",
            key_id=f"key-{index}",
            trust_root_digest=_digest(f"trust-{index}"),
        )
        for index, purpose in enumerate(purposes, start=1)
    }


def _role_policy(pins: dict[str, AuthorityRolePin]) -> AuthorityRolePolicy:
    return AuthorityRolePolicy(
        operator_assertion=pins["OPERATOR_ASSERTION"],
        acl_decision=pins["ACL_DECISION"],
        ledger_head=pins["LEDGER_HEAD"],
    )


def _signature_verifier(pins: dict[str, AuthorityRolePin]) -> TransportSignatureVerifier:
    def handle(operation: str, request: dict[str, Any]) -> dict[str, Any]:
        assert operation == "signature.verify.v1"
        pin = pins[request["purpose"]]
        return SignatureVerification(
            provider_id="signature-verifier",
            authority_class=PRODUCTION_AUTHORITY_CLASS,
            purpose=request["purpose"],
            issuer_id=request["issuer_id"],
            key_id=request["key_id"],
            algorithm=request["algorithm"],
            payload_digest=request["payload_digest"],
            trust_root_digest=pin.trust_root_digest,
            key_status="ACTIVE",
            status="VERIFIED",
            verified_at=datetime.fromisoformat(request["verification_time"]),
        ).model_dump(mode="json")

    return TransportSignatureVerifier(
        _Transport("signature-verifier", handle),
        timeout_s=1,
    )


def _catalog(*policies: OperationPolicy) -> OperationPolicyCatalog:
    payload = {
        "schema_version": "rolo-operation-policy-catalog/v1",
        "catalog_id": "catalog-1",
        "target_id": "landerpi",
        "target_fingerprint": "ssh-ed25519:fixture",
        "policies": [item.model_dump(mode="json") for item in policies],
    }
    return OperationPolicyCatalog.model_validate(
        {**payload, "catalog_digest": mapping_digest(payload)}
    )


def _foundations() -> tuple[
    MappingFoundationReferences,
    dict[str, dict[str, Any]],
    dict[str, str],
]:
    evidence_digest = _digest("evidence")
    context = ProbeContext(
        robot_id="landerpi",
        target_fingerprint="ssh-ed25519:fixture",
        evidence_digest=evidence_digest,
        evidence_refs=("artifact:evidence",),
        published_tools=({"tool_id": "app.state", "operation": "app.state"},),
        freshness={"observed": "fresh"},
    )
    candidate = CapabilityCandidate(
        candidate_id="candidate-state",
        operation="app.state",
        evidence_refs=("artifact:evidence",),
        confidence=1,
        freshness={"observed": "fresh"},
    )
    index_seed = CapabilityCandidateIndex(
        robot_id="landerpi",
        target_fingerprint="ssh-ed25519:fixture",
        context_digest=context_digest(context),
        evidence_digest=evidence_digest,
        candidates=(candidate,),
        index_digest="0" * 64,
    )
    index = index_seed.model_copy(update={"index_digest": index_seed.computed_digest()})
    dsl_payload = {
        "schema_version": "rolo-dsl/v1",
        "tool_id": "app.state",
        "kind": "OBSERVE",
        "target": {"robot_id": "landerpi", "evidence_digest": evidence_digest},
        "binding": {"provider_id": "ros2-readonly"},
        "evidence_refs": ["artifact:evidence"],
    }
    dsl, report = parse_document(dsl_payload)
    assert dsl is not None and report.ok
    catalog = _catalog(
        OperationPolicy(
            operation="app.state",
            operation_kind="OBSERVE",
            provider_id="ros2-readonly",
            access="read",
            risk="R0",
        )
    )
    scope = MappingAdmissionScope(
        tool_id="app.state",
        operation_kind="OBSERVE",
        operations=("app.state",),
        access="read",
        risk="R0",
    )
    proposal_payload = {
        "schema_version": "rolo-mapping-proposal/v2",
        "journey_session_id": "journey-1",
        "user_goal": "read current state",
        "target_id": "landerpi",
        "target_fingerprint": "ssh-ed25519:fixture",
        "candidate_index_digest": "sha256:" + index.index_digest,
        "candidate_digest": mapping_digest(candidate),
        "candidate_id": candidate.candidate_id,
        "operation": candidate.operation,
        "dsl_digest": dsl_digest(dsl),
        "context_digest": context_digest(context),
        "evidence_digest": evidence_digest,
        "available_tool_catalog_digest": catalog.catalog_digest,
        "scope": scope.model_dump(mode="json"),
        "evidence_refs": ["artifact:evidence"],
        "risks": [],
        "unknowns": [],
        "requested_actions": ["user_confirmation"],
        "status": "PROPOSED",
    }
    proposal = MappingProposal.model_validate(
        {**proposal_payload, "proposal_digest": mapping_digest(proposal_payload)}
    )
    references = MappingFoundationReferences(
        schema_version="rolo-mapping-foundation-references/v1",
        journey_session_id="journey-1",
        proposal_ref="foundation:proposal",
        context_ref="foundation:context",
        candidate_index_ref="foundation:candidate-index",
        candidate_ref="foundation:candidate",
        dsl_ref="foundation:dsl",
        evidence_ref="foundation:evidence",
        tool_catalog_ref="foundation:catalog",
    )
    payloads = {
        "PROPOSAL": proposal.model_dump(mode="json"),
        "CONTEXT": context.model_dump(mode="json"),
        "CANDIDATE_INDEX": index.model_dump(mode="json"),
        "CANDIDATE": candidate.model_dump(mode="json"),
        "DSL": dsl.model_dump(mode="json"),
        "EVIDENCE": {"schema_version": "fixture-evidence/v1", "record": "observed"},
        "TOOL_CATALOG": catalog.model_dump(mode="json"),
    }
    digests = {
        "PROPOSAL": proposal.proposal_digest,
        "CONTEXT": context_digest(context),
        "CANDIDATE_INDEX": "sha256:" + index.index_digest,
        "CANDIDATE": mapping_digest(candidate),
        "DSL": dsl_digest(dsl),
        "EVIDENCE": evidence_digest,
        "TOOL_CATALOG": catalog.catalog_digest,
    }
    return references, payloads, digests


def test_scope_derivation_closes_dependencies_and_takes_worst_policy() -> None:
    dsl = DslDocument(
        tool_id="app.mission",
        kind="COMPOSE",
        target={"robot_id": "landerpi", "evidence_digest": _digest("e")},
        binding={"provider_id": "mission-provider"},
        composition={"steps": [{"tool_id": "app.observe"}, {"operation": "app.move"}]},
    )
    catalog = _catalog(
        OperationPolicy(
            operation="app.mission",
            operation_kind="COMPOSE",
            provider_id="mission-provider",
            access="read",
            risk="R0",
            dependencies=("app.guard",),
        ),
        OperationPolicy(
            operation="app.guard",
            operation_kind="OBSERVE",
            provider_id="guard-provider",
            access="read",
            risk="R1",
        ),
        OperationPolicy(
            operation="app.observe",
            operation_kind="OBSERVE",
            provider_id="ros-provider",
            access="read",
            risk="R0",
        ),
        OperationPolicy(
            operation="app.move",
            operation_kind="EXECUTE",
            provider_id="motion-provider",
            access="experimental_write",
            risk="R3",
            motion_possible=True,
        ),
    )
    scope = DerivedScopeResolver().derive(dsl, catalog)
    assert scope.operations == ("app.guard", "app.mission", "app.move", "app.observe")
    assert scope.access == "experimental_write"
    assert scope.risk == "R3"


def test_execute_policy_cannot_underreport_read_or_r0() -> None:
    with pytest.raises(ValueError, match="cannot be reported"):
        OperationPolicy(
            operation="app.move",
            operation_kind="EXECUTE",
            provider_id="motion-provider",
            access="read",
            risk="R0",
        )


def test_trusted_clock_rejects_replayed_sequence() -> None:
    pins = _pins()
    verifier = _signature_verifier(pins)

    def handle(operation: str, request: dict[str, Any]) -> dict[str, Any]:
        assert operation == "trusted_time.read.v1"
        return _signed(
            {
                "schema_version": "rolo-trusted-time-witness/v1",
                "provider_id": "trusted-time",
                "clock_id": "clock-1",
                "sequence": 1,
                "utc_time": NOW.isoformat(),
                "uncertainty_ms": 1,
                "challenge_digest": request["challenge_digest"],
                "issuer_id": pins["TRUSTED_TIME"].issuer_id,
                "key_id": pins["TRUSTED_TIME"].key_id,
                "algorithm": "EdDSA",
            }
        )

    clock = TransportTrustedClock(
        _Transport("trusted-time", handle),
        verifier,
        clock_id="clock-1",
        pin=pins["TRUSTED_TIME"],
        timeout_s=1,
        max_uncertainty_ms=5,
    )
    assert clock() == NOW
    with pytest.raises(ProductionAuthorityCompositionError) as captured:
        clock()
    assert captured.value.code == "TRUSTED_TIME_SEQUENCE_ROLLBACK"


def test_signature_adapter_rejects_response_not_bound_to_request() -> None:
    def handle(_operation: str, request: dict[str, Any]) -> dict[str, Any]:
        return SignatureVerification(
            provider_id="signature-verifier",
            authority_class=PRODUCTION_AUTHORITY_CLASS,
            purpose=request["purpose"],
            issuer_id=request["issuer_id"],
            key_id=request["key_id"],
            algorithm=request["algorithm"],
            payload_digest=_digest("wrong"),
            trust_root_digest=_digest("trust"),
            key_status="ACTIVE",
            status="VERIFIED",
            verified_at=NOW,
        ).model_dump(mode="json")

    verifier = TransportSignatureVerifier(_Transport("signature-verifier", handle), timeout_s=1)
    payload = b'{"value":1}'
    with pytest.raises(ValueError, match="not request-bound"):
        verifier.verify(
            purpose="OPERATOR_ASSERTION",
            issuer_id="issuer",
            key_id="key",
            algorithm="EdDSA",
            payload=payload,
            payload_digest=authority_digest({"value": 1}),
            signature=SIGNATURE,
            now=NOW,
        )


def test_transport_deadline_is_fail_closed() -> None:
    ticks = iter((0, 20_000_000))
    transport = _Transport("signature-verifier", lambda *_args: {})
    verifier = TransportSignatureVerifier(
        transport,
        timeout_s=0.01,
        monotonic_ns=lambda: next(ticks),
    )
    with pytest.raises(AuthorityProviderUnavailableError):
        verifier.verify(
            purpose="OPERATOR_ASSERTION",
            issuer_id="issuer",
            key_id="key",
            algorithm="EdDSA",
            payload=b"{}",
            payload_digest=authority_digest({}),
            signature=SIGNATURE,
            now=NOW,
        )


def test_composition_derives_scope_and_rejects_early_head_expiry_before_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pins = _pins()
    verifier = _signature_verifier(pins)
    references, payloads, digests = _foundations()
    sequence = 0

    def time_handle(operation: str, request: dict[str, Any]) -> dict[str, Any]:
        nonlocal sequence
        assert operation == "trusted_time.read.v1"
        sequence += 1
        return _signed(
            {
                "schema_version": "rolo-trusted-time-witness/v1",
                "provider_id": "trusted-time",
                "clock_id": "clock-1",
                "sequence": sequence,
                "utc_time": (NOW + timedelta(microseconds=sequence)).isoformat(),
                "uncertainty_ms": 1,
                "challenge_digest": request["challenge_digest"],
                "issuer_id": pins["TRUSTED_TIME"].issuer_id,
                "key_id": pins["TRUSTED_TIME"].key_id,
                "algorithm": "EdDSA",
            }
        )

    clock = TransportTrustedClock(
        _Transport("trusted-time", time_handle),
        verifier,
        clock_id="clock-1",
        pin=pins["TRUSTED_TIME"],
        timeout_s=1,
        max_uncertainty_ms=5,
    )
    refs_by_kind = dict(references.pairs())

    def foundation_handle(operation: str, request: dict[str, Any]) -> dict[str, Any]:
        assert operation == "foundation.resolve.v1"
        kind = request["artifact_kind"]
        assert request["artifact_ref"] == refs_by_kind[kind]
        issued_at = datetime.fromisoformat(request["resolution_time"])
        return _signed(
            {
                "schema_version": "rolo-foundation-artifact/v1",
                "resolver_id": "foundation-resolver",
                "artifact_kind": kind,
                "artifact_ref": request["artifact_ref"],
                "artifact_digest": digests[kind],
                "content_digest": authority_digest(payloads[kind]),
                "target_id": "landerpi",
                "target_fingerprint": "ssh-ed25519:fixture",
                "immutable_revision": f"revision-{kind.lower().replace('_', '-')}",
                "payload": payloads[kind],
                "issued_at": issued_at.isoformat(),
                "expires_at": (issued_at + timedelta(minutes=2)).isoformat(),
                "issuer_id": pins["FOUNDATION_ARTIFACT"].issuer_id,
                "key_id": pins["FOUNDATION_ARTIFACT"].key_id,
                "algorithm": "EdDSA",
            }
        )

    head_requests = 0

    def head_handle(operation: str, request: dict[str, Any]) -> dict[str, Any]:
        nonlocal head_requests
        assert operation == "current_head.read.v1"
        head_requests += 1
        witnessed_at = datetime.fromisoformat(request["resolution_time"])
        state = {
            "resolver_id": "current-head-resolver",
            "namespace": "mapping-foundations",
            "artifact_kind": request["artifact_kind"],
            "artifact_ref": request["artifact_ref"],
            "current_artifact_digest": request["expected_artifact_digest"],
            "target_id": request["target_id"],
            "target_fingerprint": request["target_fingerprint"],
            "sequence": 1,
            "previous_head_digest": None,
        }
        return _signed(
            {
                "schema_version": "rolo-current-head-witness/v1",
                **state,
                "head_digest": authority_digest(state),
                "challenge_digest": request["challenge_digest"],
                "witnessed_at": witnessed_at.isoformat(),
                "expires_at": (
                    witnessed_at
                    + (
                        timedelta(microseconds=2)
                        if head_requests == 15
                        else timedelta(seconds=20)
                    )
                ).isoformat(),
                "issuer_id": pins["CURRENT_HEAD"].issuer_id,
                "key_id": pins["CURRENT_HEAD"].key_id,
                "algorithm": "EdDSA",
            }
        )

    policy = ProductionAuthorityCompositionPolicy(
        schema_version="rolo-production-authority-composition/v1",
        authority_roles=_role_policy(pins),
        trusted_time=pins["TRUSTED_TIME"],
        foundation_artifact=pins["FOUNDATION_ARTIFACT"],
        current_head=pins["CURRENT_HEAD"],
        signature_verifier_provider_id="signature-verifier",
        trusted_time_provider_id="trusted-time",
        acl_resolver_provider_id="acl-resolver",
        ledger_head_provider_id="ledger-head",
        foundation_resolver_provider_id="foundation-resolver",
        current_head_resolver_provider_id="current-head-resolver",
        ledger_id="mapping-ledger",
        clock_id="clock-1",
        current_head_namespace="mapping-foundations",
        provider_timeout_ms=1000,
        max_clock_uncertainty_ms=5,
    )
    composition = compose_production_mapping_authority(
        str(tmp_path / "authority"),
        policy,
        signature_transport=verifier.transport,
        trusted_time_transport=clock.transport,
        acl_transport=_Transport("acl-resolver", lambda *_args: {}),
        ledger_head_transport=_Transport("ledger-head", lambda *_args: {}),
        foundation_transport=_Transport("foundation-resolver", foundation_handle),
        current_head_transport=_Transport("current-head-resolver", head_handle),
    )
    prepared = composition.prepare_confirmation(
        references,
        decision_id="decision-1",
        ttl_s=60,
    )
    assert prepared.identity.scope.access == "read"
    assert prepared.identity.scope.risk == "R0"
    assert prepared.identity.scope.operations == ("app.state",)
    assert prepared.command.proposal_digest == digests["PROPOSAL"]

    operator_assertion = SignedOperatorAssertion.model_validate(
        _signed(
            {
                "schema_version": "rolo-operator-assertion/v1",
                "issuer_id": pins["OPERATOR_ASSERTION"].issuer_id,
                "principal_id": "operator-1",
                "key_id": pins["OPERATOR_ASSERTION"].key_id,
                "algorithm": "EdDSA",
                "audience": "rolo-mapping-admission",
                "nonce": "nonce-1",
                "challenge_digest": prepared.command.command_digest,
                "authentication_method": "HARDWARE_KEY",
                "issued_at": NOW.isoformat(),
                "expires_at": (NOW + timedelta(minutes=5)).isoformat(),
            }
        )
    )

    class _AllowAclResolver:
        @staticmethod
        def resolve(*_args: Any, **_kwargs: Any) -> Any:
            return type("AllowDecision", (), {"effect": "ALLOW"})()

    composition.acl_resolver = _AllowAclResolver()  # type: ignore[assignment]
    monkeypatch.setattr(
        composition.store,
        "confirm",
        lambda *_args, **_kwargs: pytest.fail(
            "expired current-head evidence reached the Mapping commit"
        ),
    )
    with pytest.raises(ProductionAuthorityCompositionError) as captured:
        composition.confirm(prepared, operator_assertion)
    assert captured.value.code == "CURRENT_HEAD_WITNESS_EXPIRED"


def test_current_head_resolver_rejects_noncurrent_artifact() -> None:
    pins = _pins()
    verifier = _signature_verifier(pins)
    artifact = SignedFoundationArtifact.model_validate(
        _signed(
            {
                "schema_version": "rolo-foundation-artifact/v1",
                "resolver_id": "foundation-resolver",
                "artifact_kind": "EVIDENCE",
                "artifact_ref": "foundation:evidence",
                "artifact_digest": _digest("expected"),
                "content_digest": authority_digest({"value": 1}),
                "target_id": "landerpi",
                "target_fingerprint": "ssh-ed25519:fixture",
                "immutable_revision": "revision-1",
                "payload": {"value": 1},
                "issued_at": NOW.isoformat(),
                "expires_at": (NOW + timedelta(minutes=1)).isoformat(),
                "issuer_id": pins["FOUNDATION_ARTIFACT"].issuer_id,
                "key_id": pins["FOUNDATION_ARTIFACT"].key_id,
                "algorithm": "EdDSA",
            }
        )
    )

    def handle(_operation: str, request: dict[str, Any]) -> dict[str, Any]:
        state = {
            "resolver_id": "current-head-resolver",
            "namespace": "mapping-foundations",
            "artifact_kind": request["artifact_kind"],
            "artifact_ref": request["artifact_ref"],
            "current_artifact_digest": _digest("new-current"),
            "target_id": request["target_id"],
            "target_fingerprint": request["target_fingerprint"],
            "sequence": 1,
            "previous_head_digest": None,
        }
        return _signed(
            {
                "schema_version": "rolo-current-head-witness/v1",
                **state,
                "head_digest": authority_digest(state),
                "challenge_digest": request["challenge_digest"],
                "witnessed_at": NOW.isoformat(),
                "expires_at": (NOW + timedelta(seconds=10)).isoformat(),
                "issuer_id": pins["CURRENT_HEAD"].issuer_id,
                "key_id": pins["CURRENT_HEAD"].key_id,
                "algorithm": "EdDSA",
            }
        )

    resolver = TransportCurrentHeadResolver(
        _Transport("current-head-resolver", handle),
        verifier,
        namespace="mapping-foundations",
        pin=pins["CURRENT_HEAD"],
        timeout_s=1,
    )
    with pytest.raises(ProductionAuthorityCompositionError) as captured:
        resolver.require_current(artifact, now=NOW)
    assert captured.value.code == "CURRENT_HEAD_BINDING_MISMATCH"


def test_security_production_schemas_cover_wire_models() -> None:
    root = Path(__file__).parents[1] / "schemas" / "security"
    pairs = {
        "trusted-time-witness.json": TrustedTimeWitness,
        "foundation-artifact.json": SignedFoundationArtifact,
        "current-head-witness.json": SignedCurrentHead,
        "operation-policy-catalog.json": OperationPolicyCatalog,
        "mapping-foundation-references.json": MappingFoundationReferences,
        "production-authority-composition.json": ProductionAuthorityCompositionPolicy,
    }
    for filename, model in pairs.items():
        schema = json.loads((root / filename).read_text(encoding="utf-8"))
        assert set(schema["properties"]) == set(model.model_fields)
        assert set(schema["required"]) == set(model.model_fields)


def test_composition_policy_rejects_cross_role_trust_root() -> None:
    pins = _pins()
    colliding = pins["CURRENT_HEAD"].model_copy(
        update={"trust_root_digest": pins["FOUNDATION_ARTIFACT"].trust_root_digest}
    )
    with pytest.raises(ValueError, match="trust_root_digest roles must be isolated"):
        ProductionAuthorityCompositionPolicy(
            schema_version="rolo-production-authority-composition/v1",
            authority_roles=_role_policy(pins),
            trusted_time=pins["TRUSTED_TIME"],
            foundation_artifact=pins["FOUNDATION_ARTIFACT"],
            current_head=colliding,
            signature_verifier_provider_id="signature-verifier",
            trusted_time_provider_id="trusted-time",
            acl_resolver_provider_id="acl-resolver",
            ledger_head_provider_id="ledger-head",
            foundation_resolver_provider_id="foundation-resolver",
            current_head_resolver_provider_id="current-head-resolver",
            ledger_id="mapping-ledger",
            clock_id="clock-1",
            current_head_namespace="mapping-foundations",
            provider_timeout_ms=1000,
            max_clock_uncertainty_ms=5,
        )
