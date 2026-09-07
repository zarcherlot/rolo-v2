from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from rolo.agent_tools.conformance import ToolConformanceCheck, ToolConformanceReport
from rolo.agent_tools.native_tools import AgentNativeToolDescriptor
from rolo.agent_tools.session import native_catalog_sha256
from rolo.mvp.catalog import build_target_catalog
from rolo.mvp.certify import CertificationRunner
from rolo.mvp.contracts import (
    CertificationCase,
    CertificationSuite,
    SessionState,
    TraceCall,
    TraceSessionRequest,
)
from rolo.mvp.trace import TraceService


def _tool(tool_id: str) -> AgentNativeToolDescriptor:
    return AgentNativeToolDescriptor(
        tool_id=tool_id,
        family="test",
        execution_path="DIRECT_RUNNER",
        executable="echo",
        argv_template=["echo"],
        access="read",
        risk="R0",
        max_duration_s=5,
        max_output_bytes=1000,
        evidence_kind="fixture",
    )


def _catalog():
    descriptors = [_tool("native.application.mapping.run"), _tool("native.os.host.inspect")]
    report = ToolConformanceReport(
        target_id="mentorpi",
        session_id="s1",
        surface_digest=native_catalog_sha256(descriptors),
        status="PASS",
        checks=[ToolConformanceCheck(name="fixture", status="PASS", detail="ok")],
    )
    return build_target_catalog(target_id="mentorpi", descriptors=descriptors, conformance=report, freshness="fresh")


def test_trace_success_and_evidence():
    catalog = _catalog()
    service = TraceService(catalog, lambda tool, args, session: {"status": "SUCCEEDED", "map": "ready"})
    session = service.create_session(TraceSessionRequest(target_id="mentorpi", catalog_digest=catalog.digest or "", task="完成建图"))
    result = service.execute(session.session_id, [TraceCall(tool_id="native.application.mapping.run")])
    assert result.state == SessionState.COMPLETED
    assert result.evidence_ids
    assert any(event.event == "TOOL_RESULT" for event in result.events)


def test_trace_blocks_unobserved_mapping():
    catalog = build_target_catalog(target_id="mentorpi", descriptors=[_tool("native.os.host.inspect")], freshness="fresh")
    service = TraceService(catalog, lambda *_: {"status": "SUCCEEDED"})
    result = service.create_session(TraceSessionRequest(target_id="mentorpi", catalog_digest=catalog.digest or "", task="完成建图"))
    assert result.state == SessionState.BLOCKED


def test_certify_report_has_per_case_results():
    suite = CertificationSuite(
        suite_id="mapping-10",
        target_id="mentorpi",
        cases=[CertificationCase(case_id="case-01", description="mapping status", tool_id="native.application.mapping.run", expected={"status": "SUCCEEDED"})],
    ).with_digest()
    report = CertificationRunner(lambda *_: {"status": "SUCCEEDED"}).run(suite, snapshot_digest="a" * 64)
    assert report.conclusion == "PASS"
    assert report.results[0].status.value == "PASS"
    assert report.results[0].evidence_ids


def test_stale_catalog_is_refused_before_execution():
    catalog = build_target_catalog(target_id="mentorpi", descriptors=[_tool("native.os.host.inspect")])
    service = TraceService(catalog, lambda *_: {"status": "SUCCEEDED"})
    request = TraceSessionRequest(target_id="mentorpi", catalog_digest=catalog.digest or "", task="inspect")
    try:
        service.create_session(request)
    except ValueError as exc:
        assert "stale" in str(exc)
    else:
        raise AssertionError("stale catalog must be refused")


def test_trace_idempotency_key_reuse_is_safe_and_conflicts_are_blocked():
    catalog = _catalog()
    seen: list[tuple[str, str]] = []

    def invoke(tool, args, session, key):
        seen.append((tool, key))
        return {"status": "SUCCEEDED", "value": args.get("value")}

    service = TraceService(catalog, invoke)
    session = service.create_session(
        TraceSessionRequest(target_id="mentorpi", catalog_digest=catalog.digest or "", task="inspect")
    )
    first = service.execute(
        session.session_id,
        [TraceCall(tool_id="native.os.host.inspect", idempotency_key="call-a")],
    )
    # A retry with the same key is served locally and does not invoke the
    # provider a second time.
    service.execute(
        session.session_id,
        [TraceCall(tool_id="native.os.host.inspect", idempotency_key="call-a")],
    )
    assert first.state.value == "COMPLETED"
    assert len(seen) == 1
    assert any(item.event == "TOOL_RESULT_REUSED" for item in first.events)
    try:
        service.execute(
            session.session_id,
            [TraceCall(tool_id="native.application.mapping.run", idempotency_key="call-a")],
        )
    except ValueError as exc:
        assert "idempotency" in str(exc).lower()
    else:
        raise AssertionError("reusing a key with different arguments must be rejected")
    assert session.state.value == "BLOCKED"


def test_trace_diagnosis_is_bounded_and_unknown_requires_resume():
    catalog = _catalog()
    attempts = {"invoke": 0, "diagnose": 0}

    def invoke(*_args):
        attempts["invoke"] += 1
        raise RuntimeError("provider unavailable")

    service = TraceService(catalog, invoke, max_diagnosis_attempts=1)
    session = service.create_session(
        TraceSessionRequest(target_id="mentorpi", catalog_digest=catalog.digest or "", task="inspect")
    )

    def diagnose(*_args):
        attempts["diagnose"] += 1
        raise RuntimeError("diagnostic provider unavailable")

    result = service.execute(
        session.session_id,
        [TraceCall(tool_id="native.os.host.inspect")],
        diagnose=diagnose,
    )
    assert result.state.value == "UNKNOWN"
    assert attempts["diagnose"] == 1
    assert len([item for item in result.events if item.event == "DIAGNOSIS_ATTEMPT"]) == 1
    try:
        service.execute(session.session_id, [TraceCall(tool_id="native.os.host.inspect")])
    except ValueError as exc:
        assert "resume" in str(exc).lower()
    else:
        raise AssertionError("UNKNOWN runs require an explicit resume")


def test_trace_cancel_from_unknown_sends_stop_signal():
    catalog = _catalog()
    stopped: list[tuple[str, str]] = []

    def invoke(*_args):
        raise TimeoutError("transport lost")

    service = TraceService(catalog, invoke, stopper=lambda session, reason: stopped.append((session, reason)))
    session = service.create_session(
        TraceSessionRequest(target_id="mentorpi", catalog_digest=catalog.digest or "", task="inspect")
    )
    assert service.execute(session.session_id, [TraceCall(tool_id="native.os.host.inspect")]).state.value == "UNKNOWN"
    cancelled = service.cancel(session.session_id)
    assert cancelled.state.value == "CANCELLED"
    assert stopped and stopped[0][0] == session.session_id
    assert any(item.event == "STOP_SIGNAL_SENT" for item in cancelled.events)


def test_certify_preserves_provider_blocked_unknown_and_not_run_statuses():
    suite = CertificationSuite(
        suite_id="suite-statuses",
        target_id="mentorpi",
        cases=[
            CertificationCase(case_id="case-1", description="blocked", tool_id="native.application.mapping.run", expected={"status": "SUCCEEDED"}),
            CertificationCase(case_id="case-2", description="not run", tool_id="native.application.mapping.run", expected={"status": "SUCCEEDED"}),
            CertificationCase(case_id="case-3", description="not run", tool_id="native.application.mapping.run", expected={"status": "SUCCEEDED"}),
        ],
    ).with_digest()
    fixed = datetime(2026, 1, 1, tzinfo=timezone.utc)
    report = CertificationRunner(
        lambda *_args: {"status": "BLOCKED", "error": "stale release"},
        clock=lambda: fixed,
        target_id="mentorpi",
    ).run(suite, run_id="certify-statuses", session_id="certify-statuses", fail_fast=True)
    assert [item.status.value for item in report.results] == ["BLOCKED", "NOT_RUN", "NOT_RUN"]
    assert report.conclusion == "BLOCKED"
    assert report.generated_at == fixed
    assert report.results[1].started_at == fixed
    assert report.event_count >= 4


def test_public_connector_routes_trace_and_certify_with_identity_checks(tmp_path: Path):
    from fastapi.testclient import TestClient

    from rolo.api import app
    from rolo.mvp.http import register_catalog

    base = _catalog()
    target_id = "connector-contract"
    tools = [item.model_copy(update={"target_id": target_id}) for item in base.tools]
    catalog = base.model_copy(update={"target_id": target_id, "tools": tools, "digest": None}).with_digest()
    register_catalog(catalog, artifact_root=tmp_path / "artifacts")
    client = TestClient(app)
    response = client.post(
        "/v1/runs",
        json={
            "target_id": target_id,
            "catalog_digest": catalog.digest,
            "task": "inspect",
        },
    )
    assert response.status_code == 200, response.text
    run_id = response.json()["session_id"]
    call_response = client.post(
        f"/v1/runs/{run_id}/tool-calls",
        json={"tool_id": "native.os.host.inspect", "idempotency_key": "connector-call-1"},
    )
    assert call_response.status_code == 200, call_response.text
    events = client.get(f"/v1/runs/{run_id}/events")
    assert events.status_code == 200
    assert events.json()["items"][-1]["run_id"] == run_id

    suite_path = tmp_path / "suite.json"
    suite_path.write_text(
        json.dumps(
            {
                "schema_version": "rolo-mvp-certification-suite/v1",
                "suite_id": "connector-suite",
                "target_id": target_id,
                "cases": [
                    {
                        "case_id": f"case-{index:02d}",
                        "description": "inspect",
                        "tool_id": "native.application.mapping.run",
                        "expected": {"status": "SUCCEEDED"},
                    }
                    for index in range(1, 11)
                ],
            }
        ),
        encoding="utf-8",
    )
    certify_response = client.post(
        "/v1/certify/runs",
        json={"target_id": target_id, "suite_ref": str(suite_path), "session_id": "connector-certify-1"},
    )
    assert certify_response.status_code == 200, certify_response.text
    certify_payload = certify_response.json()
    assert certify_payload["status"] == "PASS"
    index = Path(certify_payload["artifact_paths"]["index"])
    indexed = {item["path"] for item in json.loads(index.read_text(encoding="utf-8"))["artifacts"]}
    assert {"certify-test-suite.json", "certify-events.jsonl", "certify-test-report.html"} <= indexed
    report_response = client.get("/v1/certify/runs/connector-certify-1/report")
    assert report_response.status_code == 200
    assert report_response.json()["report"]["results"]
