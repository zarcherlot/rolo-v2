import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from rolo.dsl.admission import MappingConfirmationStore
from rolo.dsl.canonical import context_digest, ir_digest
from rolo.dsl.compiler import compile_document
from rolo.dsl.context import ProbeContext
from rolo.dsl.models import DslDocument
from rolo.dsl.runner import ConformanceRunner
from rolo.releases import ReleasePublisher, TargetConformanceReport, TraceConsumer


def _target_report(result, context, confirmed, *, t2="PASS"):
    gates = {"T1": "PASS", "T2": t2, "T3": "PASS", "T4": "PASS"}
    return TargetConformanceReport(
        schema_version="rolo-target-conformance/v3",
        t1_target_resolve=gates["T1"],
        t2_bundle_build=gates["T2"],
        t3_runtime_behavior=gates["T3"],
        t4_release_integrity=gates["T4"],
        tool_id=result.document.tool_id,
        operation_kind=result.document.kind,
        target_id=result.document.target.robot_id,
        target_fingerprint=context.target_fingerprint,
        target_identity_digest=confirmed.receipt.target_identity_digest,
        evidence_digest=result.document.target.evidence_digest,
        dsl_digest=result.dsl_digest,
        context_digest=context_digest(context),
        ir_digest=ir_digest(result.ir),
        bundle_digest=result.bundle.digest,
        compile_artifact_digest="sha256:" + "a" * 64,
        compiler_version=result.bundle.manifest.compiler_version,
        compiler_backend_id=result.bundle.manifest.backend_id,
        compiler_backend_version=result.bundle.manifest.backend_version,
        runtime_backend_id="offline-test",
        runtime_binding_digest="sha256:" + "b" * 64,
        runtime_result_digest="sha256:" + "c" * 64,
        required_capabilities=(),
        required_runtime_capabilities=(),
        negotiated_capabilities=result.bundle.manifest.negotiated_capabilities,
        journey_session_id=confirmed.receipt.journey_session_id,
        confirmation_receipt_digest=confirmed.receipt.receipt_digest,
        conformance_idempotency_key="sha256:" + "d" * 64,
        proofs=tuple(
            {
                "gate": gate,
                "status": status,
                "evidence_ref": f"target-conformance/{gate.lower()}-test.json",
                "evidence_digest": "sha256:" + str(index) * 64,
            }
            for index, (gate, status) in enumerate(gates.items(), start=1)
        ),
    )


def _publish(root: Path, mapping_confirmation_factory, *, target_fingerprint: str):
    document = DslDocument(
        tool_id="app.test",
        kind="OBSERVE",
        target={"robot_id": "r", "evidence_digest": "sha256:" + "e" * 64},
        binding={"resource_id": "route:/state"},
    )
    context = ProbeContext(
        robot_id="r",
        target_fingerprint=target_fingerprint,
        evidence_digest="sha256:" + "e" * 64,
        evidence_refs=("route:/state",),
    )
    confirmed = mapping_confirmation_factory(
        document.model_dump(mode="json"),
        context.model_dump(mode="json"),
        journey_session_id=f"mapping-{target_fingerprint[:8]}",
        store_root=root / "confirmations",
    )
    result = compile_document(
        document,
        root / "compile",
        context=context,
        **confirmed.compiler_kwargs,
    )
    report = ConformanceRunner(root / "conformance").run(
        document,
        context,
        **confirmed.compiler_kwargs,
    )
    release = ReleasePublisher(root / "catalog", confirmation_store=confirmed.store)._commit_verified_release(
        result,
        report,
        target_fingerprint=target_fingerprint,
        compiler_version="rolo-compiler/0.1",
        compile_context_digest=context_digest(context),
        route_digest="route-digest-1",
        journey_session_id=confirmed.receipt.journey_session_id,
        confirmation_receipt_digest=confirmed.receipt.receipt_digest,
    )
    return release, confirmed


def test_target_conformance_requires_mapping_admission_lineage():
    with pytest.raises(ValueError):
        TargetConformanceReport(
            t1_target_resolve="PASS",
            t2_bundle_build="PASS",
            t3_runtime_behavior="PASS",
            t4_release_integrity="PASS",
            target_fingerprint="fp",
        )
    with pytest.raises(ValueError):
        TargetConformanceReport(
            schema_version="rolo-target-conformance/v1",
            t1_target_resolve="PASS",
            t2_bundle_build="PASS",
            t3_runtime_behavior="PASS",
            t4_release_integrity="PASS",
            target_fingerprint="fp",
            journey_session_id="mapping-1",
            confirmation_receipt_digest="sha256:" + "0" * 64,
        )


def test_release_current_load_stale_reasons_and_rollback(tmp_path, mapping_confirmation_factory):
    first, _ = _publish(tmp_path / "first", mapping_confirmation_factory, target_fingerprint="a" * 64)
    second, _ = _publish(tmp_path / "second", mapping_confirmation_factory, target_fingerprint="b" * 64)

    # Both publishers write to their own roots; copy the immutable manifests
    # into one catalog to exercise the lifecycle API without mutating them.
    root = tmp_path / "combined"
    (root / "catalog" / "releases").mkdir(parents=True)
    for release in (first, second):
        digest = "sha256:" + hashlib.sha256(json.dumps(release.model_dump(mode="json"), sort_keys=True).encode()).hexdigest()
        source = tmp_path / ("first" if release is first else "second") / "catalog" / "releases" / f"{digest.removeprefix('sha256:')}.json"
        (root / "catalog" / "releases" / source.name).write_bytes(source.read_bytes())
    publisher = ReleasePublisher(root / "catalog")
    first_digest = "sha256:" + hashlib.sha256(json.dumps(first.model_dump(mode="json"), sort_keys=True).encode()).hexdigest()
    publisher.rollback("app.test", first_digest)
    current = publisher.current("app.test")
    assert current is not None and current[1].target_fingerprint == "a" * 64
    stale_release = publisher.mark_stale("app.test", ("CONTEXT_DIGEST_CHANGED", "CONTEXT_DIGEST_CHANGED"))
    assert stale_release.status == "STALE" and not stale_release.agent_callable
    assert publisher.current("app.test")[1].status == "STALE"
    assert publisher._read_catalog()["tools"]["app.test"]["status"] == "STALE"
    try:
        TraceConsumer().consume(stale_release, release_digest="sha256:release", session_id="s", evidence_digest="sha256:e", target_fingerprint="a" * 64)
    except ValueError as exc:
        assert str(exc) == "RELEASE_NOT_PUBLISHED"
    else:
        raise AssertionError("stale release must not be consumed")
    assert publisher.stale(
        current[1],
        target_fingerprint="b" * 64,
        evidence_digest="sha256:e",
        compiler_version="rolo-compiler/0.1",
        compile_context_digest="ctx-2",
        route_digest="route-digest-2",
        mhs_manifest_digests=("mhs-2",),
    )
    assert "CONTEXT_DIGEST_CHANGED" in publisher.stale_reasons(
        current[1],
        target_fingerprint="a" * 64,
        evidence_digest="sha256:e",
        compiler_version="rolo-compiler/0.1",
        compile_context_digest="ctx-2",
    )


def test_publish_verified_requires_all_target_gates(tmp_path, mapping_confirmation_factory):
    document = DslDocument(
        tool_id="app.test",
        kind="OBSERVE",
        target={"robot_id": "r", "evidence_digest": "sha256:" + "e" * 64},
        binding={"resource_id": "route:/state"},
    )
    context = ProbeContext(robot_id="r", target_fingerprint="fp", evidence_digest="sha256:" + "e" * 64, evidence_refs=("route:/state",))
    confirmed = mapping_confirmation_factory(
        document.model_dump(mode="json"),
        context.model_dump(mode="json"),
        journey_session_id="mapping-verified",
    )
    result = compile_document(
        document,
        tmp_path / "compile",
        context=context,
        **confirmed.compiler_kwargs,
    )
    compiler_report = ConformanceRunner(tmp_path / "conformance").run(
        document,
        context,
        **confirmed.compiler_kwargs,
    )
    publisher = ReleasePublisher(tmp_path / "catalog", confirmation_store=confirmed.store)
    failed = _target_report(result, context, confirmed, t2="FAIL")
    try:
        publisher.publish_verified(
            result,
            compiler_report,
            failed,
            target_fingerprint="fp",
            compiler_version="rolo-compiler/0.1",
            target_compile_artifact_digest=failed.compile_artifact_digest,
            compile_context_digest=context_digest(context),
            journey_session_id="mapping-verified",
            confirmation_receipt_digest=confirmed.receipt.receipt_digest,
        )
    except ValueError as exc:
        assert str(exc) == "RELEASE_TARGET_CONFORMANCE_FAILED"
    else:
        raise AssertionError("failed target conformance must not publish")
    passed = _target_report(result, context, confirmed)
    mismatched = passed.model_copy(update={"journey_session_id": "mapping-other"})
    with pytest.raises(ValueError, match="MAPPING_TARGET_CONFORMANCE_ADMISSION_MISMATCH"):
        publisher.publish_verified(
            result,
            compiler_report,
            mismatched,
            target_fingerprint="fp",
            compiler_version="rolo-compiler/0.1",
            target_compile_artifact_digest=mismatched.compile_artifact_digest,
            compile_context_digest=context_digest(context),
            journey_session_id="mapping-verified",
            confirmation_receipt_digest=confirmed.receipt.receipt_digest,
        )
    assert not publisher.catalog_path.exists()
    release = publisher.publish_verified(
        result,
        compiler_report,
        passed,
        target_fingerprint="fp",
        compiler_version="rolo-compiler/0.1",
        target_compile_artifact_digest=passed.compile_artifact_digest,
        compile_context_digest=context_digest(context),
        journey_session_id="mapping-verified",
        confirmation_receipt_digest=confirmed.receipt.receipt_digest,
    )
    assert release.target_conformance_digest and release.status == "PUBLISHED"


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("tool_id", "app.other"),
        ("operation_kind", "INVOKE"),
        ("target_id", "other-target"),
        ("evidence_digest", "sha256:" + "0" * 64),
        ("dsl_digest", "sha256:" + "1" * 64),
        ("context_digest", "sha256:" + "2" * 64),
        ("ir_digest", "sha256:" + "3" * 64),
        ("bundle_digest", "sha256:" + "4" * 64),
        ("compile_artifact_digest", "sha256:" + "5" * 64),
        ("compiler_backend_id", "forged-backend"),
    ],
)
def test_publish_verified_rejects_target_identity_substitution(tmp_path, mapping_confirmation_factory, field, replacement):
    document = DslDocument(
        tool_id="app.test",
        kind="OBSERVE",
        target={"robot_id": "r", "evidence_digest": "sha256:" + "e" * 64},
        binding={"resource_id": "route:/state"},
    )
    context = ProbeContext(
        robot_id="r",
        target_fingerprint="fp",
        evidence_digest=document.target.evidence_digest,
        evidence_refs=("route:/state",),
    )
    confirmed = mapping_confirmation_factory(
        document.model_dump(mode="json"),
        context.model_dump(mode="json"),
        journey_session_id="mapping-forgery",
    )
    result = compile_document(
        document,
        tmp_path / "compile",
        context=context,
        **confirmed.compiler_kwargs,
    )
    compiler_report = ConformanceRunner(tmp_path / "conformance").run(
        document,
        context,
        **confirmed.compiler_kwargs,
    )
    target_report = _target_report(result, context, confirmed).model_copy(update={field: replacement})
    publisher = ReleasePublisher(tmp_path / "catalog", confirmation_store=confirmed.store)
    with pytest.raises(ValueError, match="RELEASE_TARGET_CONFORMANCE_IDENTITY_MISMATCH"):
        publisher.publish_verified(
            result,
            compiler_report,
            target_report,
            target_fingerprint="fp",
            compiler_version="rolo-compiler/0.1",
            target_compile_artifact_digest=(_target_report(result, context, confirmed).compile_artifact_digest),
            compile_context_digest=context_digest(context),
            journey_session_id="mapping-forgery",
            confirmation_receipt_digest=confirmed.receipt.receipt_digest,
        )
    assert not publisher.catalog_path.exists()


def test_publish_revalidates_cancelled_or_expired_receipt_before_writing(tmp_path, mapping_confirmation_factory):
    document = DslDocument(
        tool_id="app.test",
        kind="OBSERVE",
        target={"robot_id": "r", "evidence_digest": "sha256:" + "e" * 64},
        binding={"resource_id": "route:/state"},
    )
    context = ProbeContext(
        robot_id="r",
        target_fingerprint="fp",
        evidence_digest=document.target.evidence_digest,
        evidence_refs=("route:/state",),
    )
    compile_authority = mapping_confirmation_factory(
        document.model_dump(mode="json"),
        context.model_dump(mode="json"),
        journey_session_id="mapping-compile-fixture",
    )
    result = compile_document(
        document,
        tmp_path / "compile",
        context=context,
        **compile_authority.compiler_kwargs,
    )
    report = ConformanceRunner(tmp_path / "conformance").run(
        document,
        context,
        **compile_authority.compiler_kwargs,
    )

    cancelled = mapping_confirmation_factory(document.model_dump(mode="json"), context.model_dump(mode="json"), journey_session_id="mapping-cancelled")
    cancelled.store.cancel(cancelled.receipt.receipt_digest, decision_id="cancel-release", actor_id="operator")
    cancelled_root = tmp_path / "cancelled-catalog"
    with pytest.raises(ValueError, match="MAPPING_CONFIRMATION_CANCELLED"):
        ReleasePublisher(cancelled_root, confirmation_store=cancelled.store)._commit_verified_release(
            result,
            report,
            target_fingerprint="fp",
            compiler_version="rolo-compiler/0.1",
            journey_session_id="mapping-cancelled",
            confirmation_receipt_digest=cancelled.receipt.receipt_digest,
        )
    assert not cancelled_root.exists()

    active = mapping_confirmation_factory(document.model_dump(mode="json"), context.model_dump(mode="json"), journey_session_id="mapping-expired")
    later = datetime(2026, 9, 8, 4, 0, tzinfo=timezone.utc) + timedelta(seconds=901)
    expired_store = MappingConfirmationStore(active.store.root, clock=lambda: later)
    expired_root = tmp_path / "expired-catalog"
    with pytest.raises(ValueError, match="MAPPING_CONFIRMATION_EXPIRED"):
        ReleasePublisher(expired_root, confirmation_store=expired_store)._commit_verified_release(
            result,
            report,
            target_fingerprint="fp",
            compiler_version="rolo-compiler/0.1",
            journey_session_id="mapping-expired",
            confirmation_receipt_digest=active.receipt.receipt_digest,
        )
    assert not expired_root.exists()
