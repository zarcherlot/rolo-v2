from datetime import datetime, timezone
from pathlib import Path

import pytest

from rolo.dsl.admission import MappingAdmissionIdentity, MappingAdmissionScope, MappingConfirmationStore, mapping_digest
from rolo.dsl.canonical import context_digest, dsl_digest
from rolo.dsl.compiler import compile_document
from rolo.dsl.context import ProbeContext
from rolo.dsl.models import DslDocument
from rolo.dsl.runner import ConformanceRunner
from rolo.releases import ReleasePublisher


def doc():
    return DslDocument(tool_id="app.test", kind="OBSERVE", target={"robot_id": "r", "evidence_digest": "sha256:" + "e" * 64}, binding={"resource_id": "route:/state"})


def ctx():
    return ProbeContext(robot_id="r", target_fingerprint="fp", evidence_digest="sha256:" + "e" * 64, evidence_refs=("route:/state",))


def admission(tmp_path: Path, d: DslDocument, c: ProbeContext):
    now = datetime(2026, 9, 8, 6, 0, tzinfo=timezone.utc)
    store = MappingConfirmationStore(tmp_path / "confirmations", clock=lambda: now)
    identity = MappingAdmissionIdentity.build(
        journey_session_id="mapping-1",
        target_id=d.target.robot_id,
        target_fingerprint=c.target_fingerprint,
        candidate_index_digest=mapping_digest({"index": d.tool_id}),
        candidate_digest=mapping_digest({"candidate": d.tool_id}),
        proposal_digest=mapping_digest({"proposal": d.tool_id}),
        dsl_digest=dsl_digest(d),
        context_digest=context_digest(c),
        evidence_digest=d.target.evidence_digest,
        available_tool_catalog_digest=mapping_digest({"catalog": "empty"}),
        scope=MappingAdmissionScope(tool_id=d.tool_id, operation_kind=d.kind, operations=("route:/state",), access="read", risk="R0"),
    )
    receipt = store.confirm(identity, decision_id="confirm-1", actor_id="operator", ttl_s=900)
    return store, receipt, identity


def compile_and_report(tmp_path: Path, d: DslDocument, c: ProbeContext, store, receipt):
    compiler_admission = {
        "confirmation_store": store,
        "confirmation_receipt_digest": receipt.receipt_digest,
        "journey_session_id": receipt.journey_session_id,
    }
    result = compile_document(
        d,
        tmp_path / "compile",
        context=c,
        **compiler_admission,
    )
    report = ConformanceRunner(tmp_path / "conf").run(
        d,
        c,
        **compiler_admission,
    )
    return result, report


def test_publish_writes_release_and_catalog(tmp_path: Path):
    d, c = doc(), ctx()
    store, receipt, _ = admission(tmp_path, d, c)
    result, report = compile_and_report(tmp_path, d, c, store, receipt)
    release = ReleasePublisher(tmp_path / "catalog", confirmation_store=store)._commit_verified_release(
        result,
        report,
        target_fingerprint="fp",
        compiler_version="rolo-compiler/0.1",
        compile_context_digest=context_digest(c),
        journey_session_id="mapping-1",
        confirmation_receipt_digest=receipt.receipt_digest,
    )
    assert release.status == "PUBLISHED"
    assert release.mapping_confirmation_receipt_digest == receipt.receipt_digest
    assert release.mapping_admission == receipt.admission_identity()
    assert (tmp_path / "catalog" / "tool-catalog.json").exists()


def test_public_publish_rejects_caller_supplied_target_digest(tmp_path: Path):
    d, c = doc(), ctx()
    store, receipt, _ = admission(tmp_path, d, c)
    result, report = compile_and_report(tmp_path, d, c, store, receipt)
    publisher = ReleasePublisher(tmp_path / "catalog", confirmation_store=store)
    with pytest.raises(ValueError, match="RELEASE_TARGET_CONFORMANCE_REQUIRED"):
        publisher.publish(
            result,
            report,
            target_fingerprint="fp",
            compiler_version="rolo-compiler/0.1",
            target_conformance_digest="sha256:" + "f" * 64,
            compile_context_digest=context_digest(c),
            journey_session_id="mapping-1",
            confirmation_receipt_digest=receipt.receipt_digest,
        )
    assert not publisher.catalog_path.exists()


def test_publish_rejects_failed_conformance(tmp_path: Path):
    d, c = doc(), ctx()
    store, receipt, _ = admission(tmp_path, d, c)
    result, report = compile_and_report(tmp_path, d, c, store, receipt)
    report = report.model_copy(update={"c4_behavior": "FAIL"})
    try:
        ReleasePublisher(tmp_path / "catalog", confirmation_store=store)._commit_verified_release(
            result,
            report,
            target_fingerprint="fp",
            compiler_version="rolo-compiler/0.1",
            compile_context_digest=context_digest(c),
            journey_session_id="mapping-1",
            confirmation_receipt_digest=receipt.receipt_digest,
        )
    except ValueError as exc:
        assert str(exc) == "RELEASE_CONFORMANCE_FAILED"
    else:
        raise AssertionError("failed conformance must not publish")


def test_publish_requires_committed_confirmation_before_catalog_write(tmp_path: Path):
    d, c = doc(), ctx()
    compile_store, compile_receipt, _ = admission(tmp_path / "compile-authority", d, c)
    result, report = compile_and_report(tmp_path, d, c, compile_store, compile_receipt)
    publisher = ReleasePublisher(tmp_path / "catalog")
    with pytest.raises(ValueError, match="MAPPING_CONFIRMATION_STORE_REQUIRED"):
        publisher._commit_verified_release(
            result,
            report,
            target_fingerprint="fp",
            compiler_version="rolo-compiler/0.1",
            journey_session_id="mapping-1",
            confirmation_receipt_digest="sha256:" + "0" * 64,
        )
    assert not (tmp_path / "catalog").exists()


def test_publish_rejects_wrong_journey_and_target_before_catalog_write(tmp_path: Path):
    d, c = doc(), ctx()
    store, receipt, _ = admission(tmp_path, d, c)
    result, report = compile_and_report(tmp_path, d, c, store, receipt)
    publisher = ReleasePublisher(tmp_path / "catalog", confirmation_store=store)
    with pytest.raises(ValueError, match="MAPPING_JOURNEY_SESSION_MISMATCH"):
        publisher._commit_verified_release(
            result,
            report,
            target_fingerprint="fp",
            compiler_version="rolo-compiler/0.1",
            journey_session_id="mapping-other",
            confirmation_receipt_digest=receipt.receipt_digest,
        )
    with pytest.raises(ValueError, match="MAPPING_TARGET_FINGERPRINT_MISMATCH"):
        publisher._commit_verified_release(
            result,
            report,
            target_fingerprint="other-target",
            compiler_version="rolo-compiler/0.1",
            journey_session_id="mapping-1",
            confirmation_receipt_digest=receipt.receipt_digest,
        )
    assert not (tmp_path / "catalog").exists()


@pytest.mark.parametrize(
    ("identity_change", "expected_code"),
    [
        ({"dsl_digest": "sha256:" + "1" * 64}, "MAPPING_DSL_DIGEST_MISMATCH"),
        ({"context_digest": "sha256:" + "2" * 64}, "MAPPING_CONTEXT_DIGEST_MISMATCH"),
        ({"evidence_digest": "sha256:" + "3" * 64}, "MAPPING_EVIDENCE_DIGEST_MISMATCH"),
        ({"target_id": "other-target"}, "MAPPING_TARGET_ID_MISMATCH"),
        ({"scope_tool_id": "app.other"}, "MAPPING_SCOPE_MISMATCH"),
        ({"scope_kind": "INVOKE"}, "MAPPING_SCOPE_MISMATCH"),
    ],
)
def test_publish_rejects_receipt_identity_drift_before_catalog_write(tmp_path: Path, identity_change, expected_code):
    d, c = doc(), ctx()
    compile_store, compile_receipt, identity = admission(tmp_path / "seed", d, c)
    scope = MappingAdmissionScope(
        tool_id=identity_change.get("scope_tool_id", identity.scope.tool_id),
        operation_kind=identity_change.get("scope_kind", identity.scope.operation_kind),
        operations=identity.scope.operations,
        access=identity.scope.access,
        risk=identity.scope.risk,
    )
    changed = MappingAdmissionIdentity.build(
        journey_session_id=identity.journey_session_id,
        target_id=identity_change.get("target_id", identity.target_id),
        target_fingerprint=identity.target_fingerprint,
        candidate_index_digest=identity.candidate_index_digest,
        candidate_digest=identity.candidate_digest,
        proposal_digest=identity.proposal_digest,
        dsl_digest=identity_change.get("dsl_digest", identity.dsl_digest),
        context_digest=identity_change.get("context_digest", identity.context_digest),
        evidence_digest=identity_change.get("evidence_digest", identity.evidence_digest),
        available_tool_catalog_digest=identity.available_tool_catalog_digest,
        scope=scope,
    )
    store = MappingConfirmationStore(tmp_path / "changed-confirmation", clock=lambda: datetime(2026, 9, 8, 6, 0, tzinfo=timezone.utc))
    receipt = store.confirm(changed, decision_id="changed-confirmation", actor_id="operator")
    result, report = compile_and_report(tmp_path, d, c, compile_store, compile_receipt)
    catalog_root = tmp_path / "changed-catalog"
    with pytest.raises(ValueError, match=expected_code):
        ReleasePublisher(catalog_root, confirmation_store=store)._commit_verified_release(
            result,
            report,
            target_fingerprint="fp",
            compiler_version="rolo-compiler/0.1",
            journey_session_id="mapping-1",
            confirmation_receipt_digest=receipt.receipt_digest,
        )
    assert not catalog_root.exists()
