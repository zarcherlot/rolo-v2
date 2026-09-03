from __future__ import annotations

from datetime import datetime, timedelta, timezone

from rolo.agent_tools.conformance import ToolConformanceCheck, ToolConformanceReport
from rolo.agent_tools.session import NativeToolSessionBudget, NativeToolSessionDescriptor
from rolo.agent_tools.verification_projection import project_tool_verification


def _session() -> NativeToolSessionDescriptor:
    now = datetime.now(timezone.utc)
    return NativeToolSessionDescriptor(
        session_id="session-1",
        nonce="n" * 16,
        robot_id="robot-1",
        stage="probe",
        native_catalog_sha256="a" * 64,
        allowed_tools=["tool.read"],
        policy_version="test",
        budget=NativeToolSessionBudget(max_calls=1, max_elapsed_s=60, max_result_bytes=1000),
        created_at=now,
        expires_at=now + timedelta(minutes=1),
    )


def _report(status: str = "PASS") -> ToolConformanceReport:
    return ToolConformanceReport(
        target_id="robot-1",
        session_id="session-1",
        surface_digest="a" * 64,
        status=status,
        checks=[ToolConformanceCheck(name="catalog", status=status, detail="fixture")],
    )


def test_projection_requires_all_bindings_for_callable_state() -> None:
    result = project_tool_verification(
        _report(), _session(), target_fingerprint="b" * 64, expected_fingerprint="b" * 64
    )
    assert result.agent_callable is True
    assert result.state.value == "VERIFIED"


def test_projection_blocks_failed_conformance_or_identity_mismatch() -> None:
    result = project_tool_verification(
        _report("FAIL"), _session(), target_fingerprint="b" * 64, expected_fingerprint="c" * 64
    )
    assert result.agent_callable is False
    assert result.state.value == "BLOCKED"
    assert len(result.limitations) == 2
