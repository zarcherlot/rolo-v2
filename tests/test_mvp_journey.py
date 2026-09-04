from __future__ import annotations

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
