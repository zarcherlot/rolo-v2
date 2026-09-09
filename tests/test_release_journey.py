from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi import HTTPException

from rolo.dsl.canonical import context_digest, dsl_digest
from rolo.dsl.parser import parse_document
from rolo.mvp.contracts import (
    CatalogTool,
    CertificationCase,
    CertificationSuite,
    CertifyRequest,
    TargetCatalog,
    ToolState,
    TraceCall,
    TraceSessionRequest,
)
from rolo.mvp.http import _services, current_release, register_release_bound_catalog, start_certify
from rolo.releases import PostCompilerJourney, PostCompilerJourneyResult, ReleaseBoundCertify, ReleaseBoundTrace, ReleasePublisher, tool_release_digest
from rolo.targetd.dsl_protocol import DslFrameType
from rolo.targetd.dsl_service import TargetdDslService
from scripts.mvp_release_gate import validate_artifact_index


def values():
    fingerprint = "a" * 64
    evidence_digest = "sha256:" + "e" * 64
    dsl = {
        "tool_id": "app.test",
        "kind": "OBSERVE",
        "target": {"robot_id": "r", "evidence_digest": evidence_digest},
        "binding": {"resource_id": "route:/state"},
    }
    context = {
        "robot_id": "r",
        "target_fingerprint": fingerprint,
        "evidence_digest": evidence_digest,
        "evidence_refs": ["route:/state"],
    }
    return dsl, context


def test_journey_result_rejects_unknown_schema_and_status() -> None:
    with pytest.raises(ValueError):
        PostCompilerJourneyResult.model_validate(
            {
                "schema_version": "rolo-post-compiler-journey-result/v3",
                "status": "PASS",
                "journey_session_id": "j",
                "target_id": "r",
                "dsl_digest": "sha256:dsl",
                "context_digest": "sha256:context",
                "target_compile_status": "PASS",
            }
        )
    with pytest.raises(ValueError):
        PostCompilerJourneyResult.model_validate(
            {
                "status": "UNKNOWN",
                "journey_session_id": "j",
                "target_id": "r",
                "dsl_digest": "sha256:dsl",
                "context_digest": "sha256:context",
                "target_compile_status": "PASS",
            }
        )


def test_blocked_journey_rejects_path_like_identity_before_writing(tmp_path: Path) -> None:
    dsl, context = values()
    publisher = ReleasePublisher(tmp_path / "catalog")
    journey = PostCompilerJourney(
        tmp_path / "journey",
        publisher=publisher,
        offline_replay=True,
    )

    with pytest.raises(ValueError):
        journey.run(
            journey_session_id="../escape",
            target_id="r",
            dsl=dsl,
            context=context,
            target_fingerprint="a" * 64,
        )

    assert not (tmp_path / "escape").exists()
    assert not (tmp_path / "journey" / "journeys").exists()


def test_post_compiler_journey_publishes_and_indexes_all_gates(tmp_path: Path, mapping_confirmation_factory):
    dsl, context = values()
    confirmed = mapping_confirmation_factory(dsl, context, journey_session_id="journey-1")
    publisher = ReleasePublisher(tmp_path / "catalog", confirmation_store=confirmed.store)
    result, release = PostCompilerJourney(tmp_path / "journey", publisher=publisher, offline_replay=True).run(
        journey_session_id="journey-1",
        target_id="r",
        dsl=dsl,
        context=context,
        target_fingerprint="a" * 64,
        confirmation_receipt_digest=confirmed.receipt.receipt_digest,
    )
    assert result.status == "PASS"
    assert release is not None
    assert result.dsl_digest == dsl_digest(parse_document(dsl)[0])
    assert result.context_digest == context_digest(context)
    assert result.target_conformance_digest is not None
    assert result.release_digest is not None
    assert result.confirmation_receipt_digest == confirmed.receipt.receipt_digest
    assert result.proposal_digest == confirmed.receipt.proposal_digest
    assert release.mapping_confirmation_receipt_digest == confirmed.receipt.receipt_digest
    assert release.mapping_admission == confirmed.receipt.admission_identity()
    index = tmp_path / "journey" / "journeys" / "r" / "journey-1" / "artifact-index.json"
    assert index.is_file()
    index_text = index.read_text(encoding="utf-8")
    assert len(index_text) > 0
    assert "release-manifest.json" in index_text
    assert "compiler-conformance.json" in index_text
    assert "mapping-confirmation-receipt.json" in index_text
    receipt_artifact = index.parent / "mapping-confirmation-receipt.json"
    assert receipt_artifact.read_text(encoding="utf-8") == confirmed.receipt.model_dump_json(indent=2) + "\n"
    assert validate_artifact_index(index)["schema_version"] == "rolo-mvp-artifact-index/v2"
    assert publisher.current("app.test")[0] == result.release_digest


def test_post_compiler_journey_digests_the_release_it_published(
    tmp_path: Path,
    mapping_confirmation_factory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dsl, context = values()
    confirmed = mapping_confirmation_factory(dsl, context, journey_session_id="journey-digest")
    publisher = ReleasePublisher(tmp_path / "catalog", confirmation_store=confirmed.store)
    monkeypatch.setattr(
        publisher,
        "current",
        lambda _tool_id: ("sha256:" + "f" * 64, object()),
    )

    result, release = PostCompilerJourney(tmp_path / "journey", publisher=publisher, offline_replay=True).run(
        journey_session_id="journey-digest",
        target_id="r",
        dsl=dsl,
        context=context,
        target_fingerprint="a" * 64,
        confirmation_receipt_digest=confirmed.receipt.receipt_digest,
    )

    assert result.status == "PASS"
    assert release is not None
    assert result.release_digest == tool_release_digest(release)


def test_post_compiler_journey_never_publishes_on_parse_failure(tmp_path: Path, mapping_confirmation_factory):
    valid_dsl, context = values()
    confirmed = mapping_confirmation_factory(valid_dsl, context, journey_session_id="journey-blocked")
    publisher = ReleasePublisher(tmp_path / "catalog", confirmation_store=confirmed.store)
    result, release = PostCompilerJourney(tmp_path / "journey", publisher=publisher, offline_replay=True).run(
        journey_session_id="journey-blocked",
        target_id="r",
        dsl={"tool_id": "app.test", "kind": "UNKNOWN"},
        context=context,
        target_fingerprint="a" * 64,
        confirmation_receipt_digest=confirmed.receipt.receipt_digest,
    )
    assert result.status == "BLOCKED"
    assert release is None
    assert result.confirmation_receipt_digest == confirmed.receipt.receipt_digest
    assert result.proposal_digest == confirmed.receipt.proposal_digest
    assert publisher.current("app.test") is None


def test_post_compiler_journey_requires_confirmation_before_targetd(tmp_path: Path, mapping_confirmation_factory):
    dsl, context = values()
    confirmed = mapping_confirmation_factory(dsl, context)

    class TargetdMustNotRun:
        def handle(self, _frame):
            raise AssertionError("targetd was invoked before Mapping admission")

    publisher = ReleasePublisher(tmp_path / "catalog", confirmation_store=confirmed.store)
    result, release = PostCompilerJourney(
        tmp_path / "journey",
        publisher=publisher,
        targetd=TargetdMustNotRun(),
        offline_replay=True,
    ).run(
        journey_session_id="journey-1",
        target_id="r",
        dsl=dsl,
        context=context,
        target_fingerprint="a" * 64,
    )
    assert result.status == "BLOCKED"
    assert result.diagnostics == ("MAPPING_CONFIRMATION_REQUIRED",)
    assert result.confirmation_receipt_digest is None
    assert result.proposal_digest is None
    assert release is None
    index = tmp_path / "journey" / "journeys" / "r" / "journey-1" / "artifact-index.json"
    assert validate_artifact_index(index)["schema_version"] == "rolo-mvp-artifact-index/v2"
    assert "mapping-confirmation-receipt.json" not in index.read_text(encoding="utf-8")


def test_post_compiler_journey_rejects_receipt_for_another_session_before_targetd(tmp_path: Path, mapping_confirmation_factory):
    dsl, context = values()
    confirmed = mapping_confirmation_factory(dsl, context, journey_session_id="original-journey")

    class TargetdMustNotRun:
        def handle(self, _frame):
            raise AssertionError("targetd was invoked with mismatched Mapping lineage")

    publisher = ReleasePublisher(tmp_path / "catalog", confirmation_store=confirmed.store)
    result, release = PostCompilerJourney(
        tmp_path / "journey",
        publisher=publisher,
        targetd=TargetdMustNotRun(),
        offline_replay=True,
    ).run(
        journey_session_id="replayed-journey",
        target_id="r",
        dsl=dsl,
        context=context,
        target_fingerprint="a" * 64,
        confirmation_receipt_digest=confirmed.receipt.receipt_digest,
    )
    assert result.status == "BLOCKED"
    assert result.diagnostics == ("MAPPING_JOURNEY_SESSION_MISMATCH",)
    assert result.confirmation_receipt_digest == confirmed.receipt.receipt_digest
    assert result.proposal_digest == confirmed.receipt.proposal_digest
    assert release is None
    index = tmp_path / "journey" / "journeys" / "r" / "replayed-journey" / "artifact-index.json"
    assert "mapping-confirmation-receipt.json" in index.read_text(encoding="utf-8")


def test_post_compiler_journey_rejects_targetd_lineage_substitution(tmp_path: Path, mapping_confirmation_factory):
    dsl, context = values()
    confirmed = mapping_confirmation_factory(dsl, context, journey_session_id="journey-tampered-targetd")
    delegate = TargetdDslService(
        tmp_path / "targetd-cache",
        confirmation_store=confirmed.store,
        allow_unbound_runtime=True,
    )

    class TamperedTargetd:
        def handle(self, frame):
            response = delegate.handle(frame)
            if frame.frame_type == DslFrameType.TARGET_COMPILE and response.payload.get("status") == "PASS":
                return response.model_copy(
                    update={
                        "payload": {
                            **response.payload,
                            "confirmation_receipt_digest": "sha256:" + "0" * 64,
                        }
                    }
                )
            return response

    publisher = ReleasePublisher(tmp_path / "catalog", confirmation_store=confirmed.store)
    result, release = PostCompilerJourney(
        tmp_path / "journey",
        publisher=publisher,
        targetd=TamperedTargetd(),
        offline_replay=True,
    ).run(
        journey_session_id="journey-tampered-targetd",
        target_id="r",
        dsl=dsl,
        context=context,
        target_fingerprint="a" * 64,
        confirmation_receipt_digest=confirmed.receipt.receipt_digest,
    )
    assert result.status == "BLOCKED"
    assert result.diagnostics == ("MAPPING_TARGETD_ADMISSION_LINEAGE_MISMATCH",)
    assert release is None
    assert publisher.current("app.test") is None


def test_release_bound_trace_and_certify_reject_non_current_release(tmp_path: Path, mapping_confirmation_factory):
    dsl, context = values()
    confirmed = mapping_confirmation_factory(dsl, context, journey_session_id="journey-2")
    publisher = ReleasePublisher(tmp_path / "catalog", confirmation_store=confirmed.store)
    journey_result, release = PostCompilerJourney(tmp_path / "journey", publisher=publisher, offline_replay=True).run(
        journey_session_id="journey-2",
        target_id="r",
        dsl=dsl,
        context=context,
        target_fingerprint="a" * 64,
        confirmation_receipt_digest=confirmed.receipt.receipt_digest,
    )
    assert release is not None
    release_digest = journey_result.release_digest
    catalog = TargetCatalog(
        target_id="r",
        target_fingerprint="a" * 64,
        snapshot_digest="UNKNOWN",
        generated_at=datetime.now(timezone.utc),
        freshness="fresh",
        tools=[
            CatalogTool(
                tool_id="app.test",
                target_id="r",
                state=ToolState.CALLABLE,
                agent_callable=True,
            )
        ],
    )
    catalog = catalog.with_digest()
    trace = ReleaseBoundTrace(
        catalog,
        publisher,
        release_digest=release_digest,
        target_fingerprint="a" * 64,
        evidence_digest=context["evidence_digest"],
        compile_context_digest=context_digest(context),
        invoker=lambda *_: {"status": "SUCCEEDED"},
    )
    completed, trace_paths = trace.run(
        TraceSessionRequest(target_id="r", catalog_digest=catalog.digest or "", task="inspect state"),
        [TraceCall(tool_id="app.test")],
    )
    assert completed.state.value == "COMPLETED"
    assert trace.bound_invoker.invocations[0].envelope.release_digest == release_digest
    assert trace_paths["index"].is_file()
    assert "release-binding.json" in trace_paths["index"].read_text(encoding="utf-8")

    suite = CertificationSuite(
        schema_version="rolo-mvp-certification-suite/v1",
        suite_id="suite-1",
        target_id="r",
        cases=[
            CertificationCase(
                case_id=f"case-{index:02d}",
                description="observe",
                tool_id="app.test",
                expected={"status": "SUCCEEDED"},
            )
            for index in range(1, 11)
        ],
    )
    certify = ReleaseBoundCertify(
        publisher,
        release_digests={"app.test": release_digest},
        target_fingerprint="a" * 64,
        evidence_digest=context["evidence_digest"],
        compile_context_digest=context_digest(context),
        invoker=lambda *_: {"status": "SUCCEEDED"},
    )
    report, (report_path, _) = certify.run(suite, snapshot_digest="UNKNOWN", output=tmp_path / "certify.json")
    assert report.conclusion == "PASS"
    assert len(certify.invocations) == 10
    certify_index = tmp_path / "artifact-index.json"
    assert certify_index.is_file()
    assert "release-binding.json" in certify_index.read_text(encoding="utf-8")
    original_binding = (tmp_path / "release-binding.json").read_bytes()
    repeated_report, (repeated_path, _) = certify.run(
        suite,
        snapshot_digest="UNKNOWN",
        output=tmp_path / "certify.json",
        session_id="certify-repeat",
    )
    assert repeated_report.conclusion == "PASS"
    assert repeated_path != report_path
    assert (tmp_path / "release-binding.json").read_bytes() == original_binding
    assert repeated_path.with_name(f"{repeated_path.stem}.release-binding.json").is_file()
    assert len(certify.invocations) == 20

    publisher.mark_stale("app.test", ("PROBE_EVIDENCE_CHANGED",))
    stale_report, _ = certify.run(
        suite,
        snapshot_digest="UNKNOWN",
        output=tmp_path / "certify-stale.json",
        session_id="certify-stale",
    )
    assert stale_report.conclusion == "BLOCKED"
    assert stale_report.limitations == ["RELEASE_NOT_CURRENT"]
    assert len(certify.invocations) == 20
    blocked = trace.bound_invoker
    try:
        blocked("app.test", {}, "session-2")
    except ValueError as exc:
        assert str(exc) == "RELEASE_NOT_CURRENT"
    else:
        raise AssertionError("stale current release must be rejected")


def test_http_catalog_can_use_release_bound_invoker(tmp_path: Path, mapping_confirmation_factory):
    dsl, context = values()
    confirmed = mapping_confirmation_factory(dsl, context, journey_session_id="journey-http")
    publisher = ReleasePublisher(tmp_path / "catalog", confirmation_store=confirmed.store)
    journey_result, release = PostCompilerJourney(tmp_path / "journey", publisher=publisher, offline_replay=True).run(
        journey_session_id="journey-http",
        target_id="r",
        dsl=dsl,
        context=context,
        target_fingerprint="a" * 64,
        confirmation_receipt_digest=confirmed.receipt.receipt_digest,
    )
    assert release is not None and journey_result.release_digest is not None
    catalog = TargetCatalog(
        target_id="r",
        target_fingerprint="a" * 64,
        snapshot_digest="UNKNOWN",
        generated_at=datetime.now(timezone.utc),
        freshness="fresh",
        tools=[CatalogTool(tool_id="app.test", target_id="r", state=ToolState.CALLABLE, agent_callable=True)],
    ).with_digest()
    provider_calls = 0

    def invoke(*_args):
        nonlocal provider_calls
        provider_calls += 1
        return {"status": "SUCCEEDED"}

    register_release_bound_catalog(
        catalog,
        publisher=publisher,
        release_digests={"app.test": journey_result.release_digest},
        target_fingerprint="a" * 64,
        evidence_digest=context["evidence_digest"],
        compile_context_digest=journey_result.context_digest,
        invoker=invoke,
        artifact_root=tmp_path / "http-artifacts",
    )
    service = _services["r"]
    session = service.create_session(TraceSessionRequest(target_id="r", catalog_digest=catalog.digest or "", task="inspect"))
    result = service.execute(session.session_id, [TraceCall(tool_id="app.test")])
    assert result.state.value == "COMPLETED"
    read_model = current_release("r", "app.test")
    assert read_model["release_digest"] == journey_result.release_digest
    assert read_model["status"] == "PUBLISHED"

    suite_path = tmp_path / "http-certify-suite.json"
    suite_path.write_text(
        CertificationSuite(
            schema_version="rolo-mvp-certification-suite/v1",
            suite_id="http-certify",
            target_id="r",
            cases=[
                CertificationCase(
                    case_id=f"case-{index:02d}",
                    description="observe",
                    tool_id="app.test",
                    expected={"status": "SUCCEEDED"},
                )
                for index in range(1, 11)
            ],
        ).model_dump_json(indent=2),
        encoding="utf-8",
    )
    calls_before_mismatch = provider_calls
    with pytest.raises(HTTPException, match="RELEASE_DIGEST_MISMATCH"):
        start_certify(
            CertifyRequest(
                schema_version="rolo-certify-request/v1",
                target_id="r",
                suite_ref=str(suite_path),
                release_digest="sha256:" + "f" * 64,
                compile_context_digest=journey_result.context_digest,
                target_fingerprint="a" * 64,
            )
        )
    assert provider_calls == calls_before_mismatch
    certify_result = start_certify(
        CertifyRequest(
            schema_version="rolo-certify-request/v1",
            target_id="r",
            suite_ref=str(suite_path),
            release_digest=journey_result.release_digest,
            compile_context_digest=journey_result.context_digest,
            target_fingerprint="a" * 64,
            session_id="http-certify-run",
        )
    )
    assert certify_result["status"] == "PASS"
    assert certify_result["release_digest"] == journey_result.release_digest
    assert len(certify_result["report"]["results"]) == 10
    assert provider_calls == calls_before_mismatch + 10
