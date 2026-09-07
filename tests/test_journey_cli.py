from __future__ import annotations

import json
from pathlib import Path

from rolo.agent_tools.conformance import ToolConformanceCheck, ToolConformanceReport
from rolo.agent_tools.native_tools import AgentNativeToolDescriptor
from rolo.agent_tools.session import native_catalog_sha256
from rolo.mvp.catalog import build_target_catalog, save_target_catalog
from rolo.mvp.journey_cli import run_certify, run_trace


def _catalog() -> object:
    descriptor = AgentNativeToolDescriptor(
        tool_id="native.os.host.inspect",
        family="test",
        execution_path="DIRECT_RUNNER",
        executable="host-inspect",
        argv_template=["host-inspect"],
        access="read",
        risk="R0",
        max_duration_s=5,
        max_output_bytes=4096,
        evidence_kind="fixture",
    )
    report = ToolConformanceReport(
        target_id="robot-1",
        session_id="surface-1",
        surface_digest=native_catalog_sha256([descriptor]),
        status="PASS",
        checks=[ToolConformanceCheck(name="fixture", status="PASS", detail="ok")],
    )
    return build_target_catalog(
        target_id="robot-1",
        target_fingerprint="UNKNOWN",
        descriptors=[descriptor],
        conformance=report,
        freshness="fresh",
    )


def test_run_trace_persists_replayable_request_and_index(tmp_path: Path) -> None:
    catalog_path = tmp_path / "catalog.json"
    save_target_catalog(_catalog(), catalog_path)  # type: ignore[arg-type]
    calls_path = tmp_path / "calls.json"
    calls_path.write_text(
        json.dumps([{"tool_id": "native.os.host.inspect", "arguments": {}}]),
        encoding="utf-8",
    )
    fixture_path = tmp_path / "results.json"
    fixture_path.write_text(
        json.dumps(
            {
                "schema_version": "rolo-mvp-invocation-fixture/v1",
                "results": {"native.os.host.inspect": {"status": "SUCCEEDED", "value": "ok"}},
            }
        ),
        encoding="utf-8",
    )
    result = run_trace(
        catalog_path=catalog_path,
        calls_path=calls_path,
        result_fixture=fixture_path,
        task="inspect host",
        output=tmp_path / "trace-artifacts",
    )

    assert result["status"] == "COMPLETED"
    assert result["fixture_only"] is True
    index = Path(result["artifact_index"])
    assert index.is_file()
    indexed = json.loads(index.read_text(encoding="utf-8"))
    assert {item["path"] for item in indexed["artifacts"]} >= {
        "trace-session.json",
        "trace-evidence-bundle.json",
        "trace-request.json",
    }


def test_run_certify_records_each_case_and_report_artifacts(tmp_path: Path) -> None:
    suite_path = tmp_path / "suite.json"
    suite_path.write_text(
        json.dumps(
            {
                "schema_version": "rolo-mvp-certification-suite/v1",
                "suite_id": "suite-1",
                "target_id": "robot-1",
                "cases": [
                    {
                        "case_id": "case-01",
                        "description": "inspect",
                        "tool_id": "native.os.host.inspect",
                        "expected": {"status": "SUCCEEDED"},
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    fixture_path = tmp_path / "results.json"
    fixture_path.write_text(
        json.dumps(
            {
                "schema_version": "rolo-mvp-invocation-fixture/v1",
                "results": {"case-01": {"status": "SUCCEEDED"}},
            }
        ),
        encoding="utf-8",
    )
    binding_path = tmp_path / "release-binding.json"
    binding_path.write_text(
        json.dumps(
            {
                "schema_version": "rolo-release-binding/v1",
                "release_digests": {"native.os.host.inspect": "sha256:" + "a" * 64},
                "compile_context_digest": "sha256:" + "b" * 64,
                "target_fingerprint": "UNKNOWN",
            }
        ),
        encoding="utf-8",
    )

    result = run_certify(
        suite_path=suite_path,
        result_fixture=fixture_path,
        output=tmp_path / "certify-report.json",
        require_ten_cases=False,
        release_binding_path=binding_path,
    )

    assert result["status"] == "PASS"
    assert result["case_count"] == 1
    assert result["fixture_only"] is True
    assert result["compile_context_digest"] == "sha256:" + "b" * 64
    index = Path(result["artifact_index"])
    indexed = json.loads(index.read_text(encoding="utf-8"))
    assert {item["path"] for item in indexed["artifacts"]} == {
        "certify-report.json",
        "certify-report.md",
        "certify-request.json",
    }
