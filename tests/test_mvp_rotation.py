from __future__ import annotations

from pathlib import Path

import pytest

from rolo.agent_tools.conformance import ToolConformanceCheck, ToolConformanceReport
from rolo.agent_tools.native_tools import AgentNativeToolDescriptor, NativeToolParameter
from rolo.agent_tools.session import native_catalog_sha256
from rolo.mvp import RotationDebugRequest, assess_rotation_readiness
from rolo.mvp.catalog import build_target_catalog
from rolo.mvp.contracts import SessionState, TraceSessionRequest
from rolo.mvp.trace import TraceService
from rolo.stages.probe.target_evidence import TargetEvidenceBundle


def _bundle() -> TargetEvidenceBundle:
    path = Path("C:/Users/zarch/AppData/Local/rolo/state/config/target-evidence/mentorpi-live-verify.json")
    if not path.is_file():
        pytest.skip("LanderPi evidence bundle is not available")
    return TargetEvidenceBundle.model_validate_json(path.read_text(encoding="utf-8"))


def test_rotation_request_is_bounded_and_dry_run_by_default() -> None:
    request = RotationDebugRequest(angle_degrees=90, max_speed_rad_s=0.4, timeout_s=10, direction="left")
    assert request.dry_run is True
    assert RotationDebugRequest(angle_degrees=90, max_speed_rad_s=0.4, timeout_s=10, direction="left", dry_run=False).dry_run is False
    with pytest.raises(ValueError):
        RotationDebugRequest(angle_degrees=181, max_speed_rad_s=0.4, timeout_s=10, direction="left")


def test_landerpi_rotation_readiness_is_evidence_bound() -> None:
    assessment = assess_rotation_readiness(_bundle())
    assert assessment.target_id == "mentorpi"
    assert assessment.write_allowed is False
    assert "ros_topic:/cmd_vel" in assessment.matched_routes
    assert assessment.status in {"READY_FOR_SUPERVISED_REVIEW", "BLOCKED"}
    assert any("deferred physical write" in item for item in assessment.limitations)


def test_trace_rotation_is_blocked_without_experimental_write_tool() -> None:
    catalog = build_target_catalog(target_id="mentorpi", descriptors=[], freshness="fresh")
    service = TraceService(catalog, lambda *_: {"status": "SUCCEEDED"})
    session = service.create_session(TraceSessionRequest(target_id="mentorpi", catalog_digest=catalog.digest or "", task="调试地盘旋转"))
    assert session.state == SessionState.BLOCKED
    assert any(event.event == "ROTATION_TOOL_NOT_OBSERVED" for event in session.events)


def test_supervised_trace_can_invoke_registered_experimental_write_tool() -> None:
    descriptor = AgentNativeToolDescriptor(
        tool_id="native.application.base.rotate",
        family="mvp",
        execution_path="DIRECT_RUNNER",
        executable="rotation-driver",
        argv_template=["rotation-driver"],
        access="experimental_write",
        risk="R3",
        max_duration_s=10,
        max_output_bytes=4096,
        evidence_kind="rotation",
        parameters=[NativeToolParameter(name="angle_degrees", kind="integer", required=True)],
    )
    report = ToolConformanceReport(
        target_id="mentorpi",
        session_id="rotation-conformance",
        surface_digest=native_catalog_sha256([descriptor]),
        status="PASS",
        checks=[ToolConformanceCheck(name="rotation", status="PASS", detail="registered")],
    )
    catalog = build_target_catalog(target_id="mentorpi", descriptors=[descriptor], conformance=report, freshness="fresh")
    service = TraceService(catalog, lambda *_: {"status": "SUCCEEDED", "angle_degrees": 90})
    request = TraceSessionRequest(
        target_id="mentorpi",
        catalog_digest=catalog.digest or "",
        task="调试地盘旋转",
        mode="SUPERVISED_FIELD_DEBUG",
        operator_id="operator-1",
        safety_confirmed=True,
    )
    session = service.create_session(request)
    result = service.execute(session.session_id, [{"tool_id": descriptor.tool_id, "arguments": {"angle_degrees": 90}}])
    assert result.state == SessionState.COMPLETED
    assert result.calls == 1
