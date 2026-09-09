from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from rolo.dsl.admission import (
    MappingAdmissionError,
    MappingAdmissionIdentity,
    MappingConfirmationReceipt,
    ProductionMappingAdmissionGate,
    ProductionMappingConfirmationStore,
)
from rolo.dsl.canonical import context_digest, ir_digest
from rolo.dsl.compiler import compile_document
from rolo.dsl.context import ProbeContext
from rolo.dsl.models import DslDocument
from rolo.dsl.report import ConformanceReport
from rolo.dsl.target_conformance import TargetConformanceReport, TargetGateProof
from rolo.releases import (
    ProductionReleasePublisher,
    ReleasePublicationReceipt,
    ReleasePublisher,
    TargetConformanceArtifactError,
    TargetConformanceArtifactReference,
    TargetConformanceArtifactStore,
    TargetReleaseSignature,
    TargetSignatureVerification,
    signature_message,
    statement_digest,
)


def _canonical(value: dict) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _digest_json(value: dict) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


class _StubProductionStore(ProductionMappingConfirmationStore):
    def __init__(self, receipt: MappingConfirmationReceipt) -> None:
        self.receipt = receipt
        self.clock = lambda: receipt.decided_at

    def resolve(self, receipt_digest: str) -> MappingConfirmationReceipt:
        if receipt_digest != self.receipt.receipt_digest:
            raise MappingAdmissionError("MAPPING_CONFIRMATION_NOT_COMMITTED")
        return self.receipt


class _StubProductionGate(ProductionMappingAdmissionGate):
    def __init__(self, store: _StubProductionStore) -> None:
        self.store = store
        self.clock = store.clock
        self.failure: str | None = None
        self.require_calls = 0
        self.commit_calls = 0

    def require_active(
        self,
        receipt_digest: str,
        expected_identity: MappingAdmissionIdentity,
        *,
        now=None,
    ) -> MappingConfirmationReceipt:
        del now
        self.require_calls += 1
        if self.failure is not None:
            raise MappingAdmissionError(self.failure)
        receipt = self.store.resolve(receipt_digest)
        if receipt.admission_identity() != expected_identity:
            raise MappingAdmissionError("MAPPING_CONFIRMATION_IDENTITY_INVALID")
        return receipt

    def commit_if_active(
        self,
        receipt_digest: str,
        expected_identity: MappingAdmissionIdentity,
        commit,
        *,
        now=None,
    ):
        self.commit_calls += 1
        receipt = self.require_active(
            receipt_digest,
            expected_identity,
            now=now,
        )
        return receipt, commit()


class _TargetSignerVerifier:
    provider_id = "test-target-authority"
    authority_class = "PRODUCTION_EXTERNAL"

    def __init__(self) -> None:
        self.key = b"release-target-test-key"
        self.sign_calls: list[dict] = []
        self.on_sign = None

    def sign(self, *, target_id: str, statement: dict) -> TargetReleaseSignature:
        self.sign_calls.append(dict(statement))
        if self.on_sign is not None:
            self.on_sign()
        message = signature_message(
            statement,
            target_id=target_id,
            key_id="release-key-1",
            algorithm="EdDSA",
        )
        return TargetReleaseSignature(
            target_id=target_id,
            key_id="release-key-1",
            algorithm="EdDSA",
            signed_digest=statement_digest(statement),
            signature=hmac.new(self.key, message, hashlib.sha256).hexdigest(),
        )

    def verify(
        self,
        *,
        target_id,
        key_id,
        algorithm,
        message,
        message_digest,
        signed_digest,
        signature,
    ) -> TargetSignatureVerification:
        expected = hmac.new(self.key, message, hashlib.sha256).hexdigest()
        verified = (
            target_id == "r"
            and key_id == "release-key-1"
            and algorithm == "EdDSA"
            and hmac.compare_digest(expected, signature)
        )
        return TargetSignatureVerification(
            provider_id=self.provider_id,
            authority_class=self.authority_class,
            target_id=target_id,
            key_id=key_id,
            algorithm=algorithm,
            signed_digest=signed_digest,
            message_digest=message_digest,
            trust_root_digest="sha256:" + "f" * 64,
            key_status="ACTIVE",
            status="VERIFIED" if verified else "REJECTED",
        )


def _compile_inputs(tmp_path: Path, mapping_confirmation_factory):
    document = DslDocument(
        tool_id="app.release.production",
        kind="OBSERVE",
        target={"robot_id": "r", "evidence_digest": "sha256:" + "e" * 64},
        binding={"resource_id": "route:/state"},
    )
    context = ProbeContext(
        robot_id="r",
        target_fingerprint="target-fingerprint-1",
        evidence_digest=document.target.evidence_digest,
        evidence_refs=("route:/state",),
    )
    confirmed = mapping_confirmation_factory(
        document.model_dump(mode="json"),
        context.model_dump(mode="json"),
        journey_session_id="production-release-1",
        store_root=tmp_path / "mapping-fixture",
    )
    result = compile_document(
        document,
        tmp_path / "compile",
        context=context,
        **confirmed.compiler_kwargs,
    )
    return result, context, confirmed.receipt


def _write_target_artifacts(
    root: Path,
    result,
    context: ProbeContext,
    receipt: MappingConfirmationReceipt,
) -> tuple[TargetConformanceArtifactReference, TargetConformanceReport]:
    cache_key = "1" * 64
    report_fields = {
        "schema_version": "rolo-target-conformance/v3",
        "t1_target_resolve": "PASS",
        "t2_bundle_build": "PASS",
        "t3_runtime_behavior": "PASS",
        "t4_release_integrity": "PASS",
        "tool_id": result.document.tool_id,
        "operation_kind": result.document.kind,
        "target_id": result.document.target.robot_id,
        "target_fingerprint": context.target_fingerprint,
        "target_identity_digest": receipt.target_identity_digest,
        "evidence_digest": result.document.target.evidence_digest,
        "dsl_digest": result.dsl_digest,
        "context_digest": context_digest(context),
        "ir_digest": ir_digest(result.ir),
        "bundle_digest": result.bundle.digest,
        "compile_artifact_digest": "sha256:" + "a" * 64,
        "compiler_version": result.bundle.manifest.compiler_version,
        "compiler_backend_id": result.bundle.manifest.backend_id,
        "compiler_backend_version": result.bundle.manifest.backend_version,
        "runtime_backend_id": "landerpi-runtime",
        "runtime_binding_digest": "sha256:" + "b" * 64,
        "runtime_result_digest": "sha256:" + "c" * 64,
        "required_capabilities": (),
        "required_runtime_capabilities": (),
        "negotiated_capabilities": result.bundle.manifest.negotiated_capabilities,
        "journey_session_id": receipt.journey_session_id,
        "confirmation_receipt_digest": receipt.receipt_digest,
        "conformance_idempotency_key": "sha256:" + cache_key,
        "diagnostics": (),
    }
    proof_payloads = (
        (
            "T1",
            "target-conformance/t1-target-resolve.json",
            {
                "gate": "T1",
                "status": "PASS",
                "target_id": report_fields["target_id"],
                "target_fingerprint": report_fields["target_fingerprint"],
                "target_identity_digest": report_fields["target_identity_digest"],
                "context_digest": report_fields["context_digest"],
                "evidence_digest": report_fields["evidence_digest"],
                "runtime_backend_id": report_fields["runtime_backend_id"],
                "runtime_binding_digest": report_fields["runtime_binding_digest"],
                "required_runtime_capabilities": [],
            },
        ),
        (
            "T2",
            "target-conformance/t2-bundle-build.json",
            {
                "gate": "T2",
                "status": "PASS",
                "dsl_digest": report_fields["dsl_digest"],
                "context_digest": report_fields["context_digest"],
                "ir_digest": report_fields["ir_digest"],
                "bundle_digest": report_fields["bundle_digest"],
                "compile_artifact_digest": report_fields["compile_artifact_digest"],
                "compiler_backend_id": report_fields["compiler_backend_id"],
                "compiler_backend_version": report_fields[
                    "compiler_backend_version"
                ],
            },
        ),
        (
            "T3",
            "target-conformance/t3-runtime-behavior.json",
            {
                "gate": "T3",
                "status": "PASS",
                "runtime_backend_id": report_fields["runtime_backend_id"],
                "runtime_binding_digest": report_fields["runtime_binding_digest"],
                "runtime_result_digest": report_fields["runtime_result_digest"],
                "required_runtime_capabilities": [],
                "conformance_idempotency_key": report_fields[
                    "conformance_idempotency_key"
                ],
            },
        ),
        (
            "T4",
            "target-conformance/t4-release-integrity.json",
            {
                "gate": "T4",
                "status": "PASS",
                "tool_id": report_fields["tool_id"],
                "operation_kind": "OBSERVE",
                "target_identity_digest": report_fields["target_identity_digest"],
                "dsl_digest": report_fields["dsl_digest"],
                "context_digest": report_fields["context_digest"],
                "ir_digest": report_fields["ir_digest"],
                "bundle_digest": report_fields["bundle_digest"],
                "confirmation_receipt_digest": report_fields[
                    "confirmation_receipt_digest"
                ],
            },
        ),
    )
    report = TargetConformanceReport(
        **report_fields,
        proofs=tuple(
            TargetGateProof(
                gate=gate,
                status="PASS",
                evidence_ref=evidence_ref,
                evidence_digest=_digest_json(payload),
            )
            for gate, evidence_ref, payload in proof_payloads
        ),
    )
    conformance_dir = root / cache_key / "target-conformance"
    conformance_dir.mkdir(parents=True)
    for _, evidence_ref, payload in proof_payloads:
        (conformance_dir / Path(evidence_ref).name).write_bytes(_canonical(payload))
    report_payload = report.model_dump(mode="json")
    report_digest = _digest_json(report_payload)
    (conformance_dir / "report.json").write_bytes(_canonical(report_payload))
    result_payload = {
        "phase": "TARGET_CONFORMANCE",
        "status": "PASS",
        "target_conformance": "PASS",
        "cache_key": cache_key,
        "target_conformance_report": report_payload,
        "target_conformance_digest": report_digest,
        "cache_hit": False,
        "conformance_cache_hit": False,
    }
    for field in (
        "tool_id",
        "operation_kind",
        "target_id",
        "target_fingerprint",
        "target_identity_digest",
        "evidence_digest",
        "dsl_digest",
        "context_digest",
        "ir_digest",
        "bundle_digest",
        "compile_artifact_digest",
        "compiler_version",
        "compiler_backend_id",
        "compiler_backend_version",
        "runtime_backend_id",
        "runtime_binding_digest",
        "required_capabilities",
        "required_runtime_capabilities",
        "negotiated_capabilities",
        "journey_session_id",
        "confirmation_receipt_digest",
        "conformance_idempotency_key",
        "diagnostics",
    ):
        result_payload[field] = report_payload[field]
    result_payload["artifact_digest"] = _digest_json(
        {
            key: value
            for key, value in result_payload.items()
            if key not in {"artifact_digest", "cache_hit", "conformance_cache_hit"}
        }
    )
    (conformance_dir / "result.json").write_text(
        json.dumps(result_payload, sort_keys=True),
        encoding="utf-8",
    )
    return (
        TargetConformanceArtifactReference(
            cache_key=cache_key,
            target_conformance_digest=report_digest,
        ),
        report,
    )


def _publisher_fixture(tmp_path: Path, mapping_confirmation_factory):
    result, context, receipt = _compile_inputs(tmp_path, mapping_confirmation_factory)
    artifact_root = tmp_path / "target-cache"
    reference, report = _write_target_artifacts(
        artifact_root,
        result,
        context,
        receipt,
    )
    store = _StubProductionStore(receipt)
    gate = _StubProductionGate(store)
    signer = _TargetSignerVerifier()
    publisher = ProductionReleasePublisher(
        tmp_path / "catalog",
        confirmation_store=store,
        admission_gate=gate,
        artifact_resolver=TargetConformanceArtifactStore(
            artifact_root,
            provider_id="landerpi-artifact-store",
        ),
        target_signer=signer,
        signature_verifier=signer,
    )
    return publisher, signer, gate, result, reference, report, artifact_root


def test_trusted_artifact_store_reloads_proofs_and_rejects_tamper(
    tmp_path: Path,
    mapping_confirmation_factory,
) -> None:
    (
        publisher,
        _,
        _,
        result,
        reference,
        report,
        artifact_root,
    ) = _publisher_fixture(tmp_path, mapping_confirmation_factory)
    resolved = publisher.artifact_resolver.resolve(
        reference,
        expected_target_id=result.document.target.robot_id,
        expected_journey_session_id=report.journey_session_id,
    )
    assert resolved.report == report

    proof_path = (
        artifact_root
        / reference.cache_key
        / "target-conformance"
        / "t3-runtime-behavior.json"
    )
    tampered = json.loads(proof_path.read_text(encoding="utf-8"))
    tampered["runtime_backend_id"] = "forged-runtime"
    proof_path.write_bytes(_canonical(tampered))
    with pytest.raises(
        TargetConformanceArtifactError,
        match="RELEASE_TARGET_PROOF_IDENTITY_MISMATCH",
    ):
        publisher.artifact_resolver.resolve(
            reference,
            expected_target_id="r",
        )


def test_production_publisher_rejects_caller_proof_and_commits_signed_receipt(
    tmp_path: Path,
    mapping_confirmation_factory,
) -> None:
    publisher, signer, gate, result, reference, report, _ = _publisher_fixture(
        tmp_path,
        mapping_confirmation_factory,
    )
    compiler_report = ConformanceReport(
        c1_dsl="PASS",
        c2_evidence="PASS",
        c3_compile="PASS",
        c4_behavior="PASS",
    )
    with pytest.raises(
        ValueError,
        match="RELEASE_TRUSTED_CONFORMANCE_REFERENCE_REQUIRED",
    ):
        publisher.publish_verified(
            result,
            compiler_report,
            report,
            target_fingerprint=report.target_fingerprint,
            compiler_version=report.compiler_version,
            target_compile_artifact_digest=report.compile_artifact_digest,
            compile_context_digest=report.context_digest,
            journey_session_id=report.journey_session_id,
            confirmation_receipt_digest=report.confirmation_receipt_digest,
        )

    publication = publisher.publish_from_trusted_conformance(result, reference)
    assert (
        ReleasePublicationReceipt.model_validate_json(publication.model_dump_json())
        == publication
    )
    assert publication.authority_mode == "PRODUCTION_SIGNED"
    assert publication.target_conformance_artifact == reference
    assert publication.target_signature.signed_digest == statement_digest(
        signer.sign_calls[-1]
    )
    assert gate.commit_calls == 1
    current = publisher.current(publication.release.tool_id)
    assert current == (publication.release_digest, publication.release)
    transaction = json.loads(
        (publisher.root / "catalog-transactions.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()[0]
    )
    assert transaction["target_signature"] == publication.target_signature.model_dump(
        mode="json"
    )
    assert transaction["mutation"] == publication.catalog_mutation.model_dump(mode="json")


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("catalog_sequence", 999),
        ("catalog_transaction_digest", "sha256:" + "c" * 64),
    ],
)
def test_production_publication_receipt_rejects_detached_catalog_identity(
    tmp_path: Path,
    mapping_confirmation_factory,
    field: str,
    replacement: object,
) -> None:
    publisher, _, _, result, reference, _, _ = _publisher_fixture(
        tmp_path,
        mapping_confirmation_factory,
    )
    publication = publisher.publish_from_trusted_conformance(result, reference)
    payload = publication.model_dump(mode="python")
    payload[field] = replacement

    with pytest.raises(ValidationError):
        ReleasePublicationReceipt.model_validate(payload)


def test_production_publication_receipt_rejects_unrelated_target_signature(
    tmp_path: Path,
    mapping_confirmation_factory,
) -> None:
    publisher, _, _, result, reference, _, _ = _publisher_fixture(
        tmp_path,
        mapping_confirmation_factory,
    )
    publication = publisher.publish_from_trusted_conformance(result, reference)
    payload = publication.model_dump(mode="python")
    payload["target_signature"]["signed_digest"] = "sha256:" + "b" * 64

    with pytest.raises(ValidationError):
        ReleasePublicationReceipt.model_validate(payload)


def test_unsigned_publisher_cannot_bind_production_mapping_store(
    tmp_path: Path,
    mapping_confirmation_factory,
) -> None:
    _, _, receipt = _compile_inputs(tmp_path, mapping_confirmation_factory)
    with pytest.raises(
        MappingAdmissionError,
        match="RELEASE_UNSIGNED_PRODUCTION_AUTHORITY_FORBIDDEN",
    ):
        ReleasePublisher(
            tmp_path / "unsigned-catalog",
            confirmation_store=_StubProductionStore(receipt),
        )


def test_production_publish_rechecks_mapping_after_signing(
    tmp_path: Path,
    mapping_confirmation_factory,
) -> None:
    publisher, signer, gate, result, reference, _, _ = _publisher_fixture(
        tmp_path,
        mapping_confirmation_factory,
    )
    signer.on_sign = lambda: setattr(
        gate,
        "failure",
        "MAPPING_CONFIRMATION_CANCELLED",
    )
    with pytest.raises(
        MappingAdmissionError,
        match="MAPPING_CONFIRMATION_CANCELLED",
    ):
        publisher.publish_from_trusted_conformance(result, reference)
    assert publisher.catalog_store.head().sequence == 0
    assert not (publisher.root / "catalog-transactions.jsonl").exists()
    assert len(tuple(publisher.releases.glob("*.json"))) == 1


def test_production_current_and_rollback_revalidate_mapping_freshness(
    tmp_path: Path,
    mapping_confirmation_factory,
) -> None:
    publisher, _, gate, result, reference, _, _ = _publisher_fixture(
        tmp_path,
        mapping_confirmation_factory,
    )
    publication = publisher.publish_from_trusted_conformance(result, reference)
    gate.failure = "MAPPING_CONFIRMATION_EXPIRED"
    with pytest.raises(MappingAdmissionError, match="MAPPING_CONFIRMATION_EXPIRED"):
        publisher.current(publication.release.tool_id)
    with pytest.raises(MappingAdmissionError, match="MAPPING_CONFIRMATION_EXPIRED"):
        publisher.rollback(
            publication.release.tool_id,
            publication.release_digest,
        )
    assert publisher.catalog_store.head().sequence == 1


def test_production_current_and_rollback_reject_tampered_trusted_proof(
    tmp_path: Path,
    mapping_confirmation_factory,
) -> None:
    publisher, _, _, result, reference, _, artifact_root = _publisher_fixture(
        tmp_path,
        mapping_confirmation_factory,
    )
    publication = publisher.publish_from_trusted_conformance(result, reference)
    proof_path = (
        artifact_root
        / reference.cache_key
        / "target-conformance"
        / "t1-target-resolve.json"
    )
    payload = json.loads(proof_path.read_text(encoding="utf-8"))
    payload["target_fingerprint"] = "forged"
    proof_path.write_bytes(_canonical(payload))
    with pytest.raises(TargetConformanceArtifactError):
        publisher.current(publication.release.tool_id)
    with pytest.raises(TargetConformanceArtifactError):
        publisher.rollback(
            publication.release.tool_id,
            publication.release_digest,
        )
    assert publisher.catalog_store.head().sequence == 1
