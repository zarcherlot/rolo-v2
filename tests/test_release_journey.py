from datetime import datetime, timezone
from pathlib import Path

from rolo.dsl.canonical import context_digest, dsl_digest
from rolo.dsl.parser import parse_document
from rolo.mvp.contracts import (
    CatalogTool,
    CertificationCase,
    CertificationSuite,
    TargetCatalog,
    ToolState,
    TraceCall,
    TraceSessionRequest,
)
from rolo.mvp.http import _services, current_release, register_release_bound_catalog
from rolo.releases import PostCompilerJourney, ReleaseBoundCertify, ReleaseBoundTrace, ReleasePublisher
from scripts.mvp_release_gate import validate_artifact_index


def values():
    fingerprint = "a" * 64
    dsl = {
        "tool_id": "app.test",
        "kind": "OBSERVE",
        "target": {"robot_id": "r", "evidence_digest": "sha256:e"},
        "binding": {"resource_id": "route:/state"},
    }
    context = {
        "robot_id": "r",
        "target_fingerprint": fingerprint,
        "evidence_digest": "sha256:e",
        "evidence_refs": ["route:/state"],
    }
    return dsl, context


def test_post_compiler_journey_publishes_and_indexes_all_gates(tmp_path: Path):
    dsl, context = values()
    publisher = ReleasePublisher(tmp_path / "catalog")
    result, release = PostCompilerJourney(tmp_path / "journey", publisher=publisher).run(
        journey_session_id="journey-1",
        target_id="r",
        dsl=dsl,
        context=context,
        target_fingerprint="a" * 64,
    )
    assert result.status == "PASS"
    assert release is not None
    assert result.dsl_digest == dsl_digest(parse_document(dsl)[0])
    assert result.context_digest == context_digest(context)
    assert result.target_conformance_digest is not None
    assert result.release_digest is not None
    index = tmp_path / "journey" / "journeys" / "r" / "journey-1" / "artifact-index.json"
    assert index.is_file()
    index_text = index.read_text(encoding="utf-8")
    assert len(index_text) > 0
    assert "release-manifest.json" in index_text
    assert "compiler-conformance.json" in index_text
    assert validate_artifact_index(index)["schema_version"] == "rolo-mvp-artifact-index/v2"
    assert publisher.current("app.test")[0] == result.release_digest


def test_post_compiler_journey_never_publishes_on_parse_failure(tmp_path: Path):
    _, context = values()
    publisher = ReleasePublisher(tmp_path / "catalog")
    result, release = PostCompilerJourney(tmp_path / "journey", publisher=publisher).run(
        journey_session_id="journey-blocked",
        target_id="r",
        dsl={"tool_id": "app.test", "kind": "UNKNOWN"},
        context=context,
        target_fingerprint="a" * 64,
    )
    assert result.status == "BLOCKED"
    assert release is None
    assert publisher.current("app.test") is None


def test_release_bound_trace_and_certify_reject_non_current_release(tmp_path: Path):
    dsl, context = values()
    publisher = ReleasePublisher(tmp_path / "catalog")
    journey_result, release = PostCompilerJourney(tmp_path / "journey", publisher=publisher).run(
        journey_session_id="journey-2",
        target_id="r",
        dsl=dsl,
        context=context,
        target_fingerprint="a" * 64,
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
        evidence_digest="sha256:e",
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
        suite_id="suite-1",
        target_id="r",
        cases=[CertificationCase(case_id="case-1", description="observe", tool_id="app.test", expected={"status": "SUCCEEDED"})],
    )
    certify = ReleaseBoundCertify(
        publisher,
        release_digests={"app.test": release_digest},
        target_fingerprint="a" * 64,
        evidence_digest="sha256:e",
        compile_context_digest=context_digest(context),
        invoker=lambda *_: {"status": "SUCCEEDED"},
    )
    report, _ = certify.run(suite, snapshot_digest="UNKNOWN", output=tmp_path / "certify.json")
    assert report.conclusion == "PASS"
    assert len(certify.invocations) == 1
    certify_index = tmp_path / "artifact-index.json"
    assert certify_index.is_file()
    assert "release-binding.json" in certify_index.read_text(encoding="utf-8")

    publisher.mark_stale("app.test", ("PROBE_EVIDENCE_CHANGED",))
    blocked = trace.bound_invoker
    try:
        blocked("app.test", {}, "session-2")
    except ValueError as exc:
        assert str(exc) == "RELEASE_NOT_CURRENT"
    else:
        raise AssertionError("stale current release must be rejected")


def test_http_catalog_can_use_release_bound_invoker(tmp_path: Path):
    dsl, context = values()
    publisher = ReleasePublisher(tmp_path / "catalog")
    journey_result, release = PostCompilerJourney(tmp_path / "journey", publisher=publisher).run(
        journey_session_id="journey-http",
        target_id="r",
        dsl=dsl,
        context=context,
        target_fingerprint="a" * 64,
    )
    assert release is not None and journey_result.release_digest is not None
    catalog = TargetCatalog(
        target_id="api-r",
        target_fingerprint="a" * 64,
        snapshot_digest="UNKNOWN",
        generated_at=datetime.now(timezone.utc),
        freshness="fresh",
        tools=[CatalogTool(tool_id="app.test", target_id="api-r", state=ToolState.CALLABLE, agent_callable=True)],
    ).with_digest()
    register_release_bound_catalog(
        catalog,
        publisher=publisher,
        release_digests={"app.test": journey_result.release_digest},
        target_fingerprint="a" * 64,
        evidence_digest="sha256:e",
        compile_context_digest=journey_result.context_digest,
        invoker=lambda *_: {"status": "SUCCEEDED"},
    )
    service = _services["api-r"]
    session = service.create_session(TraceSessionRequest(target_id="api-r", catalog_digest=catalog.digest or "", task="inspect"))
    result = service.execute(session.session_id, [TraceCall(tool_id="app.test")])
    assert result.state.value == "COMPLETED"
    read_model = current_release("api-r", "app.test")
    assert read_model["release_digest"] == journey_result.release_digest
    assert read_model["status"] == "PUBLISHED"
