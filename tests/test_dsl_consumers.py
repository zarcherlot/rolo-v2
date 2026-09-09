from datetime import datetime, timedelta, timezone

import pytest

from rolo.dsl.admission import (
    MappingAdmissionIdentity,
    MappingAdmissionScope,
    MappingConfirmationStore,
    mapping_digest,
)
from rolo.dsl.canonical import context_digest, dsl_digest
from rolo.dsl.context import ProbeContext
from rolo.dsl.models import DslDocument
from rolo.releases import (
    CertifyConsumer,
    ToolRelease,
    TraceConsumer,
    tool_release_digest,
)


def setup(tmp_path):
    evidence_digest = "sha256:" + "e" * 64
    doc = DslDocument(tool_id="app.test", kind="OBSERVE", target={"robot_id": "r", "evidence_digest": evidence_digest}, binding={"resource_id": "route:/state"})
    context = ProbeContext(robot_id="r", target_fingerprint="fp", evidence_digest=evidence_digest, evidence_refs=("route:/state",))
    now = [datetime(2026, 9, 8, 6, 0, tzinfo=timezone.utc)]
    store = MappingConfirmationStore(tmp_path / "confirmations", clock=lambda: now[0])
    identity = MappingAdmissionIdentity.build(
        journey_session_id="mapping-1",
        target_id="r",
        target_fingerprint="fp",
        candidate_index_digest=mapping_digest({"index": "candidate-index"}),
        candidate_digest=mapping_digest({"candidate": "app.test"}),
        proposal_digest=mapping_digest({"proposal": "app.test"}),
        dsl_digest=dsl_digest(doc),
        context_digest=context_digest(context),
        evidence_digest=evidence_digest,
        available_tool_catalog_digest=mapping_digest({"catalog": "empty"}),
        scope=MappingAdmissionScope(tool_id="app.test", operation_kind="OBSERVE", operations=("route:/state",), access="read", risk="R0"),
    )
    receipt = store.confirm(identity, decision_id="confirm-1", actor_id="operator", ttl_s=900)
    release = ToolRelease(
        tool_id=doc.tool_id,
        target_id=doc.target.robot_id,
        operation_kind=str(doc.kind),
        dsl_digest=dsl_digest(doc),
        ir_digest="sha256:" + "1" * 64,
        probe_evidence_digest=evidence_digest,
        compiler_version="rolo-compiler/0.1",
        generated_bundle_digest="sha256:" + "2" * 64,
        conformance_digest="sha256:" + "3" * 64,
        target_fingerprint="fp",
        compile_context_digest=context_digest(context),
        target_conformance_digest="sha256:" + "4" * 64,
        mapping_confirmation_receipt_digest=receipt.receipt_digest,
        mapping_admission=receipt.admission_identity(),
    )
    return release, store, receipt, now


def test_trace_and_certify_bind_release(tmp_path):
    release, store, receipt, _ = setup(tmp_path)
    release_digest = tool_release_digest(release)
    trace = TraceConsumer(confirmation_store=store).consume(
        release,
        release_digest=release_digest,
        session_id="session-1",
        evidence_digest=release.probe_evidence_digest,
        target_fingerprint="fp",
        compile_context_digest=release.compile_context_digest,
        input={"query": "state"},
    )
    plain_release = release.model_copy(update={"target_conformance_digest": None})
    with pytest.raises(ValueError, match="TARGET_CONFORMANCE_REQUIRED"):
        CertifyConsumer(confirmation_store=store).consume(
            plain_release,
            release_digest=tool_release_digest(plain_release),
            session_id="session-1",
            evidence_digest=release.probe_evidence_digest,
            target_fingerprint="fp",
            compile_context_digest=release.compile_context_digest,
            test_case_id="case-1",
        )
    certify = CertifyConsumer(confirmation_store=store).consume(
        release,
        release_digest=release_digest,
        session_id="session-1",
        evidence_digest=release.probe_evidence_digest,
        target_fingerprint="fp",
        compile_context_digest=release.compile_context_digest,
        test_case_id="case-1",
    )
    assert trace.consumer == "trace" and certify.test_case_id == "case-1"
    assert trace.mapping_confirmation_receipt_digest == receipt.receipt_digest
    assert trace.mapping_admission == release.mapping_admission


def test_consumer_rejects_release_digest_mismatch(tmp_path):
    release, store, _, _ = setup(tmp_path)
    try:
        TraceConsumer(confirmation_store=store).consume(
            release,
            release_digest="sha256:" + "0" * 64,
            session_id="session-1",
            evidence_digest=release.probe_evidence_digest,
            target_fingerprint="fp",
            compile_context_digest=release.compile_context_digest,
        )
    except ValueError as exc:
        assert str(exc) == "RELEASE_DIGEST_MISMATCH"
    else:
        raise AssertionError("mismatched release digest must be rejected")


def test_consumer_rejects_stale_target(tmp_path):
    release, store, _, _ = setup(tmp_path)
    try:
        TraceConsumer(confirmation_store=store).consume(release, release_digest="sha256:release", session_id="s", evidence_digest=release.probe_evidence_digest, target_fingerprint="changed")
    except ValueError as exc:
        assert str(exc) == "TARGET_FINGERPRINT_MISMATCH"
    else:
        raise AssertionError("stale target must be rejected")


def test_consumer_rejects_context_and_mhs_drift(tmp_path):
    release, store, _, _ = setup(tmp_path)
    publisher_release = release.model_copy(update={"compile_context_digest": "ctx-1", "mhs_manifest_digests": ("mhs-1",)})
    try:
        TraceConsumer(confirmation_store=store).consume(
            publisher_release,
            release_digest="sha256:release",
            session_id="s",
            evidence_digest=release.probe_evidence_digest,
            target_fingerprint="fp",
            compile_context_digest="ctx-2",
            mhs_manifest_digests=("mhs-1",),
        )
    except ValueError as exc:
        assert str(exc) == "CONTEXT_DIGEST_MISMATCH"
    else:
        raise AssertionError("context drift must be rejected")
    try:
        TraceConsumer(confirmation_store=store).consume(
            publisher_release,
            release_digest="sha256:release",
            session_id="s",
            evidence_digest=release.probe_evidence_digest,
            target_fingerprint="fp",
            compile_context_digest="ctx-1",
            mhs_manifest_digests=("mhs-2",),
        )
    except ValueError as exc:
        assert str(exc) == "MHS_MANIFEST_DIGEST_MISMATCH"
    else:
        raise AssertionError("MHS drift must be rejected")


def test_consumer_requires_trusted_store_and_revalidates_cancellation(tmp_path):
    release, store, receipt, _ = setup(tmp_path)
    release_digest = tool_release_digest(release)
    with pytest.raises(ValueError, match="MAPPING_CONFIRMATION_STORE_REQUIRED"):
        TraceConsumer().consume(
            release,
            release_digest=release_digest,
            session_id="trace-1",
            evidence_digest=release.probe_evidence_digest,
            target_fingerprint="fp",
            compile_context_digest=release.compile_context_digest,
        )

    store.cancel(receipt.receipt_digest, decision_id="cancel-1", actor_id="operator")
    with pytest.raises(ValueError, match="MAPPING_CONFIRMATION_CANCELLED"):
        TraceConsumer(confirmation_store=store).consume(
            release,
            release_digest=release_digest,
            session_id="trace-1",
            evidence_digest=release.probe_evidence_digest,
            target_fingerprint="fp",
            compile_context_digest=release.compile_context_digest,
        )


def test_consumer_revalidates_expiry_and_release_identity(tmp_path):
    release, store, _, now = setup(tmp_path)
    changed = release.model_copy(update={"dsl_digest": "sha256:" + "0" * 64})
    with pytest.raises(ValueError, match="MAPPING_DSL_DIGEST_MISMATCH"):
        TraceConsumer(confirmation_store=store).consume(
            changed,
            release_digest=tool_release_digest(changed),
            session_id="trace-1",
            evidence_digest=release.probe_evidence_digest,
            target_fingerprint="fp",
            compile_context_digest=release.compile_context_digest,
        )

    now[0] += timedelta(seconds=901)
    with pytest.raises(ValueError, match="MAPPING_CONFIRMATION_EXPIRED"):
        TraceConsumer(confirmation_store=store).consume(
            release,
            release_digest=tool_release_digest(release),
            session_id="trace-1",
            evidence_digest=release.probe_evidence_digest,
            target_fingerprint="fp",
            compile_context_digest=release.compile_context_digest,
        )
