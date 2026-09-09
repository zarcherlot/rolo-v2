from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker

from rolo.dsl.admission import mapping_digest
from rolo.mvp import (
    CatalogTool,
    DurableCertifyRequestStore,
    DurableTraceRequestStore,
    EpisodeStore,
    TargetCatalog,
    TargetdTraceAdapter,
    TargetdTraceResponse,
    ToolState,
    TraceCall,
    TraceSessionRequest,
)
from rolo.releases import ReleaseBoundTrace, ToolRelease, tool_release_digest
from rolo.targetd.certify_adapter import TargetdV2CertifyRequestRecord
from rolo.targetd.protocol import FrameKind, ProtocolFrame, TargetdCallReceipt, TargetdExecutionAuthority, provider_fence_digest


def _fixture(tmp_path: Path, mapping_confirmation_factory):
    fingerprint = "a" * 64
    evidence_digest = "sha256:" + "e" * 64
    context_digest = "sha256:" + "c" * 64
    dsl = {
        "tool_id": "app.observe.odom",
        "kind": "OBSERVE",
        "target": {"robot_id": "mentorpi", "evidence_digest": evidence_digest},
        "binding": {"resource_id": "/odom"},
    }
    context = {
        "robot_id": "mentorpi",
        "target_fingerprint": fingerprint,
        "evidence_digest": evidence_digest,
        "evidence_refs": ["ros2:/odom"],
    }
    confirmed = mapping_confirmation_factory(
        dsl,
        context,
        journey_session_id="trace-targetd",
        operations=("odom.sample",),
        access="read",
        risk="R0",
    )
    identity = confirmed.receipt.admission_identity()
    # Use the authoritative Context digest from the confirmation fixture.
    context_digest = identity.context_digest
    release = ToolRelease(
        tool_id=identity.scope.tool_id,
        target_id=identity.target_id,
        operation_kind="OBSERVE",
        dsl_digest=identity.dsl_digest,
        ir_digest=mapping_digest({"kind": "ir"}),
        probe_evidence_digest=identity.evidence_digest,
        compiler_version="test-compiler/v1",
        generated_bundle_digest=mapping_digest({"kind": "bundle-plan"}),
        conformance_digest=mapping_digest({"kind": "compiler-conformance"}),
        target_fingerprint=identity.target_fingerprint,
        compile_context_digest=context_digest,
        target_conformance_digest=mapping_digest({"kind": "target-conformance"}),
        mapping_confirmation_receipt_digest=confirmed.receipt.receipt_digest,
        mapping_admission=identity,
    )
    release_digest = tool_release_digest(release)
    authority = TargetdExecutionAuthority.build(
        tool_id=release.tool_id,
        target_id=release.target_id or "",
        target_fingerprint=release.target_fingerprint,
        bundle_digest="b" * 64,
        binding_digest="d" * 64,
        surface_digest="f" * 64,
        release_digest=release_digest,
        context_digest=context_digest,
        mapping_confirmation_receipt_digest=confirmed.receipt.receipt_digest,
        mapping_admission=identity,
        catalog_head_digest="sha256:" + "1" * 64,
        provider_id="ros2-readonly",
        provider_operation="odom.sample",
        mode="READ_ONLY",
        fence_epoch=1,
    )

    class Publisher:
        root = tmp_path / "catalog"
        confirmation_store = confirmed.store

        @staticmethod
        def current(tool_id: str):
            return (release_digest, release) if tool_id == release.tool_id else None

    catalog = TargetCatalog(
        target_id="mentorpi",
        target_fingerprint=fingerprint,
        snapshot_digest="2" * 64,
        generated_at=datetime.now(timezone.utc),
        freshness="fresh",
        tools=[
            CatalogTool(
                tool_id=release.tool_id,
                target_id="mentorpi",
                state=ToolState.CALLABLE,
                agent_callable=True,
                timeout_s=30,
            )
        ],
    ).with_digest()
    return Publisher(), catalog, release_digest, authority, evidence_digest, context_digest


def _receipt(request) -> TargetdCallReceipt:
    return TargetdCallReceipt(
        schema_version="rolo-targetd-call-receipt/v2",
        idempotency_key=request.idempotency_key,
        session_id=request.session_id,
        target_id=request.target_id,
        bundle_digest=request.bundle_digest,
        request_digest=request.request_digest(),
        release_digest=request.release_digest,
        context_digest=request.context_digest,
        mapping_confirmation_receipt_digest=request.mapping_confirmation_receipt_digest,
        authority_head_digest=request.authority_head_digest,
        fence_epoch=request.fence_epoch,
        provider_id=request.provider_id,
        provider_operation=request.provider_operation,
        provider_fence_digest=provider_fence_digest(request),
        status="SUCCEEDED",
        result={"status": "SUCCEEDED", "sample_count": 1},
        evidence_refs=["artifact://odom/sample.json"],
        provider_started_at=datetime(2026, 9, 9, 1, 0, tzinfo=timezone.utc),
        updated_at=datetime(2026, 9, 9, 1, 0, 1, tzinfo=timezone.utc),
    )


def _response(request, *, query: bool = False) -> TargetdTraceResponse:
    frame = ProtocolFrame.create(
        kind=FrameKind.RESULT,
        sequence=1,
        session_id=request.session_id,
        run_id=None if query else request.run_id,
        payload={
            "request_kind": "QUERY_CALL" if query else "CALL",
            "ok": True,
            "receipt": _receipt(request).model_dump(mode="json"),
        },
    )
    return TargetdTraceResponse(frame=frame, sequence_correlated=True)


def test_targetd_release_bound_trace_publishes_canonical_receipt_episode_and_index(tmp_path, mapping_confirmation_factory):
    publisher, catalog, release_digest, authority, evidence_digest, context_digest = _fixture(tmp_path, mapping_confirmation_factory)
    requests = DurableTraceRequestStore(tmp_path / "requests")
    seen = []

    def call(request):
        seen.append(request)
        return _response(request)

    adapter = TargetdTraceAdapter(
        authority,
        authority_resolver=lambda _tool_id: authority,
        call=call,
        request_store=requests,
    )
    trace = ReleaseBoundTrace(
        catalog,
        publisher,
        release_digest=release_digest,
        target_fingerprint=authority.target_fingerprint,
        evidence_digest=evidence_digest,
        compile_context_digest=context_digest,
        invoker=adapter,
        artifact_root=tmp_path / "trace",
    )
    session, paths = trace.run(
        TraceSessionRequest(
            target_id="mentorpi",
            catalog_digest=catalog.digest or "",
            task="read one odometry sample",
        ),
        [TraceCall(tool_id=authority.tool_id)],
    )

    assert session.state.value == "COMPLETED"
    assert len(seen) == 1
    assert len(requests) == 1
    assert json.loads(paths["plan"].read_text(encoding="utf-8"))["plan_digest"].startswith("sha256:")
    receipt_paths = [path for key, path in paths.items() if key.startswith("receipt:")]
    assert len(receipt_paths) == 1
    assert "targetd-trace-receipt:sha256:" in paths["events"].read_text(encoding="utf-8")
    assert receipt_paths[0].name in paths["index"].read_text(encoding="utf-8")
    assert trace.last_episode is not None
    payload, artifact = trace.episode_store.download(session.session_id, "trace-plan.json")
    assert hashlib.sha256(payload).hexdigest() == artifact.sha256


def test_restart_reconciles_exact_receipt_without_replaying_call(tmp_path, mapping_confirmation_factory):
    publisher, catalog, release_digest, authority, evidence_digest, context_digest = _fixture(tmp_path, mapping_confirmation_factory)
    request_root = tmp_path / "requests"
    first_requests = []

    def call(request):
        first_requests.append(request)
        return _response(request)

    first_adapter = TargetdTraceAdapter(
        authority,
        authority_resolver=lambda _tool_id: authority,
        call=call,
        request_store=DurableTraceRequestStore(request_root),
    )
    first = ReleaseBoundTrace(
        catalog,
        publisher,
        release_digest=release_digest,
        target_fingerprint=authority.target_fingerprint,
        evidence_digest=evidence_digest,
        compile_context_digest=context_digest,
        invoker=first_adapter,
        artifact_root=tmp_path / "trace",
    )

    def crash_after_receipt(*_args):
        raise RuntimeError("simulated process loss after target receipt")

    first_adapter.trace_receipt_evidence = crash_after_receipt  # type: ignore[method-assign]
    with pytest.raises(RuntimeError, match="simulated process loss"):
        first.run(
            TraceSessionRequest(
                target_id="mentorpi",
                catalog_digest=catalog.digest or "",
                task="read one odometry sample",
            ),
            [TraceCall(tool_id=authority.tool_id)],
        )
    assert len(first_requests) == 1

    queries = []

    def query(key):
        queries.append(key)
        return _response(first_requests[0], query=True)

    second_adapter = TargetdTraceAdapter(
        authority,
        authority_resolver=lambda _tool_id: authority,
        call=lambda _request: pytest.fail("resume must not replay CALL"),
        query=query,
        request_store=DurableTraceRequestStore(request_root),
    )
    second = ReleaseBoundTrace(
        catalog,
        publisher,
        release_digest=release_digest,
        target_fingerprint=authority.target_fingerprint,
        evidence_digest=evidence_digest,
        compile_context_digest=context_digest,
        invoker=second_adapter,
        artifact_root=tmp_path / "trace",
    )
    session, paths = second.resume("trace-targetd")

    assert session.state.value == "COMPLETED"
    assert len(first_requests) == 1
    assert len(queries) == 1
    assert any(event.event == "TOOL_RESULT_RECONCILED" for event in session.events)
    assert paths["index"].is_file()


def test_transport_unknown_is_queried_and_never_replayed(tmp_path, mapping_confirmation_factory):
    publisher, catalog, release_digest, authority, evidence_digest, context_digest = _fixture(tmp_path, mapping_confirmation_factory)
    request_root = tmp_path / "requests"
    submitted = []

    def ambiguous_call(request):
        submitted.append(request)
        raise ConnectionError("response lost after send")

    first = ReleaseBoundTrace(
        catalog,
        publisher,
        release_digest=release_digest,
        target_fingerprint=authority.target_fingerprint,
        evidence_digest=evidence_digest,
        compile_context_digest=context_digest,
        invoker=TargetdTraceAdapter(
            authority,
            authority_resolver=lambda _tool_id: authority,
            call=ambiguous_call,
            request_store=DurableTraceRequestStore(request_root),
        ),
        artifact_root=tmp_path / "trace",
    )
    unknown, _ = first.run(
        TraceSessionRequest(target_id="mentorpi", catalog_digest=catalog.digest or "", task="read odometry"),
        [TraceCall(tool_id=authority.tool_id)],
    )
    assert unknown.state.value == "UNKNOWN"
    assert len(submitted) == 1

    second = ReleaseBoundTrace(
        catalog,
        publisher,
        release_digest=release_digest,
        target_fingerprint=authority.target_fingerprint,
        evidence_digest=evidence_digest,
        compile_context_digest=context_digest,
        invoker=TargetdTraceAdapter(
            authority,
            authority_resolver=lambda _tool_id: authority,
            call=lambda _request: pytest.fail("ambiguous CALL must never be replayed"),
            query=lambda _key: _response(submitted[0], query=True),
            request_store=DurableTraceRequestStore(request_root),
        ),
        artifact_root=tmp_path / "trace",
    )
    completed, _ = second.resume("trace-targetd")
    assert completed.state.value == "COMPLETED"
    assert len(submitted) == 1
    assert any(event.event == "TOOL_RESULT_RECONCILED" for event in completed.events)


def test_durable_certify_request_mapping_survives_restart_and_rejects_tamper(tmp_path):
    now = datetime(2026, 9, 9, 1, 0, tzinfo=timezone.utc)
    payload = b'{"schema_version":"fixture"}'
    record = TargetdV2CertifyRequestRecord(
        request_json=payload,
        content_digest=hashlib.sha256(payload).hexdigest(),
        request_digest="3" * 64,
        created_at=now,
        timeout_s=30,
    )
    root = tmp_path / "certify-requests"
    DurableCertifyRequestStore(root)["certify:key"] = record
    restored = DurableCertifyRequestStore(root)["certify:key"]
    assert restored == record

    path = next(root.glob("*.json"))
    content = json.loads(path.read_text(encoding="utf-8"))
    content["request_digest"] = "4" * 64
    path.write_text(json.dumps(content), encoding="utf-8")
    with pytest.raises(ValueError, match="durable request record is invalid"):
        DurableCertifyRequestStore(root)["certify:key"]


def test_episode_history_is_append_only_and_download_revalidates_object(tmp_path, mapping_confirmation_factory):
    publisher, catalog, release_digest, authority, evidence_digest, context_digest = _fixture(tmp_path, mapping_confirmation_factory)
    trace = ReleaseBoundTrace(
        catalog,
        publisher,
        release_digest=release_digest,
        target_fingerprint=authority.target_fingerprint,
        evidence_digest=evidence_digest,
        compile_context_digest=context_digest,
        invoker=lambda *_args: {"status": "SUCCEEDED"},
        artifact_root=tmp_path / "trace",
        episode_store=EpisodeStore(tmp_path / "episodes"),
    )
    session, _ = trace.run(
        TraceSessionRequest(target_id="mentorpi", catalog_digest=catalog.digest or "", task="inspect"),
        [TraceCall(tool_id=authority.tool_id)],
    )
    latest = trace.episode_store.get(session.session_id)
    assert trace.episode_store.list() == (latest,)
    assert trace.episode_store.history(session.session_id) == (latest,)
    payload, artifact = trace.episode_store.download(session.session_id, "trace-session.json")
    assert hashlib.sha256(payload).hexdigest() == artifact.sha256
    object_path = trace.episode_store.objects / artifact.sha256
    object_path.write_text("tampered", encoding="utf-8")
    with pytest.raises(ValueError, match="digest mismatch|unavailable"):
        trace.episode_store.download(session.session_id, "trace-session.json")


@pytest.mark.parametrize(
    "schema_name",
    [
        "ReleaseBoundTracePlan.schema.json",
        "TargetdTraceReceiptSidecar.schema.json",
        "TargetdDurableRequest.schema.json",
        "EpisodeRevision.schema.json",
    ],
)
def test_new_schemas_are_draft_2020_12(schema_name):
    schema = json.loads((Path("schemas") / schema_name).read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema, format_checker=FormatChecker())
