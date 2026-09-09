from __future__ import annotations

import json
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import ValidationError as JsonSchemaValidationError

from rolo.agent_tools.conformance import ToolConformanceCheck, ToolConformanceReport
from rolo.agent_tools.native_tools import AgentNativeToolDescriptor
from rolo.agent_tools.session import native_catalog_sha256
from rolo.mvp.catalog import build_target_catalog
from rolo.mvp.certify import CertificationRunner, write_report
from rolo.mvp.contracts import (
    CertificationCase,
    CertificationReport,
    CertificationSuite,
    CertifyRequest,
    SessionState,
    TraceCall,
    TraceSessionRequest,
)
from rolo.mvp.trace import TraceService
from rolo.releases import ReleaseBoundCertify, ReleasePublisher, ToolRelease, tool_release_digest


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
        schema_version="rolo-mvp-certification-suite/v1",
        suite_id="mapping-10",
        target_id="mentorpi",
        cases=[
            CertificationCase(
                case_id=f"case-{index:02d}",
                description="mapping status",
                tool_id="native.application.mapping.run",
                expected={"status": "SUCCEEDED"},
            )
            for index in range(1, 11)
        ],
    ).with_digest()
    report = CertificationRunner(lambda *_: {"status": "SUCCEEDED"}).run(
        suite,
        snapshot_digest="a" * 64,
        release_digests={"native.application.mapping.run": "sha256:" + "b" * 64},
        compile_context_digest="sha256:" + "c" * 64,
        target_fingerprint="d" * 64,
    )
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


def test_certify_emits_pass_fail_blocked_and_not_run_statuses(tmp_path: Path):
    suite = CertificationSuite(
        schema_version="rolo-mvp-certification-suite/v1",
        suite_id="suite-statuses",
        target_id="mentorpi",
        cases=[
            CertificationCase(case_id=f"case-{index}", description="blocked", tool_id="native.application.mapping.run", expected={"status": "SUCCEEDED"})
            for index in range(1, 11)
        ],
    ).with_digest()
    fixed = datetime(2026, 1, 1, tzinfo=timezone.utc)
    provider_calls = 0

    def invoke(*_args):
        nonlocal provider_calls
        provider_calls += 1
        if provider_calls == 1:
            return {"status": "SUCCEEDED"}
        if provider_calls == 2:
            return {"status": "FAILED"}
        raise PermissionError("authorization revoked")

    runner = CertificationRunner(invoke, clock=lambda: fixed, target_id="mentorpi")
    report = runner.run(
        suite,
        run_id="certify-statuses",
        session_id="certify-statuses",
        release_digests={"native.application.mapping.run": "sha256:" + "b" * 64},
        compile_context_digest="sha256:" + "c" * 64,
        target_fingerprint="d" * 64,
        cancellation_check=lambda: provider_calls >= 3,
    )
    assert [item.status.value for item in report.results] == [
        "PASS",
        "FAIL",
        "BLOCKED",
        *("NOT_RUN" for _ in range(7)),
    ]
    assert report.conclusion == "CONDITIONAL"
    assert report.generated_at == fixed
    assert report.results[3].started_at == fixed
    assert report.event_count >= 4
    first_json, _ = write_report(report, tmp_path / "certify.json")
    second_json, _ = write_report(report, tmp_path / "certify.json")
    assert first_json != second_json
    assert first_json.is_file() and second_json.is_file()


def test_certify_missing_or_multiple_release_binding_blocks_before_provider():
    suite = CertificationSuite(
        schema_version="rolo-mvp-certification-suite/v1",
        suite_id="binding-gate",
        target_id="mentorpi",
        cases=[
            CertificationCase(case_id=f"case-{index:02d}", description="inspect", tool_id="native.os.host.inspect")
            for index in range(1, 11)
        ],
    )
    provider_calls = 0

    def invoke(*_args):
        nonlocal provider_calls
        provider_calls += 1
        return {"status": "SUCCEEDED"}

    runner = CertificationRunner(invoke, target_id="mentorpi")
    missing = runner.run(
        suite,
        compile_context_digest="sha256:" + "b" * 64,
        target_fingerprint="c" * 64,
    )
    multiple = runner.run(
        suite,
        release_digests={
            "native.os.host.inspect": "sha256:" + "a" * 64,
            "native.other": "sha256:" + "d" * 64,
        },
        compile_context_digest="sha256:" + "b" * 64,
        target_fingerprint="c" * 64,
    )
    assert missing.conclusion == multiple.conclusion == "BLOCKED"
    assert {item.status.value for item in missing.results + multiple.results} == {"BLOCKED"}
    assert provider_calls == 0


def test_plain_publish_cannot_forge_target_conformance_for_certify(tmp_path: Path):
    publisher = ReleasePublisher(tmp_path / "catalog")
    with pytest.raises(ValueError, match="RELEASE_TARGET_CONFORMANCE_REQUIRED"):
        publisher.publish(  # type: ignore[arg-type]
            object(),
            object(),
            target_conformance_digest="sha256:" + "f" * 64,
        )
    assert not publisher.catalog_path.exists()


def test_release_bound_certify_blocks_unverified_current_before_provider(tmp_path: Path):
    release = ToolRelease(
        tool_id="native.os.host.inspect",
        target_id="mentorpi",
        operation_kind="OBSERVE",
        dsl_digest="sha256:" + "1" * 64,
        ir_digest="sha256:" + "2" * 64,
        probe_evidence_digest="sha256:" + "3" * 64,
        compiler_version="rolo-compiler/0.1",
        generated_bundle_digest="sha256:" + "4" * 64,
        conformance_digest="sha256:" + "5" * 64,
        target_fingerprint="6" * 64,
        compile_context_digest="sha256:" + "7" * 64,
    )
    digest = tool_release_digest(release)

    class CatalogPublisher:
        root = tmp_path / "catalog"
        confirmation_store = None

        @staticmethod
        def current(_tool_id: str):
            return digest, release

    provider_calls = 0

    def invoke(*_args):
        nonlocal provider_calls
        provider_calls += 1
        return {"status": "SUCCEEDED"}

    suite = CertificationSuite(
        schema_version="rolo-mvp-certification-suite/v1",
        suite_id="unverified",
        target_id="mentorpi",
        cases=[
            CertificationCase(case_id=f"case-{index:02d}", description="inspect", tool_id=release.tool_id)
            for index in range(1, 11)
        ],
    )
    certify = ReleaseBoundCertify(
        CatalogPublisher(),  # type: ignore[arg-type]
        release_digests={release.tool_id: digest},
        target_fingerprint=release.target_fingerprint,
        evidence_digest=release.probe_evidence_digest,
        compile_context_digest=release.compile_context_digest,
        invoker=invoke,
    )
    report, _ = certify.run(suite, snapshot_digest="UNKNOWN", output=tmp_path / "certify.json")
    assert report.conclusion == "BLOCKED"
    assert report.limitations == ["TARGET_CONFORMANCE_REQUIRED"]
    assert provider_calls == 0


def test_certify_suite_rejects_nine_eleven_and_mixed_tool_cases():
    def cases(count: int, *, mixed: bool = False):
        return [
            CertificationCase(
                case_id=f"case-{index:02d}",
                description="inspect",
                tool_id="native.other" if mixed and index == count else "native.os.host.inspect",
            )
            for index in range(1, count + 1)
        ]

    with pytest.raises(ValueError):
        CertificationSuite(schema_version="rolo-mvp-certification-suite/v1", suite_id="nine", target_id="mentorpi", cases=cases(9))
    with pytest.raises(ValueError):
        CertificationSuite(schema_version="rolo-mvp-certification-suite/v1", suite_id="eleven", target_id="mentorpi", cases=cases(11))
    with pytest.raises(ValueError, match="one tool"):
        CertificationSuite(schema_version="rolo-mvp-certification-suite/v1", suite_id="mixed", target_id="mentorpi", cases=cases(10, mixed=True))


def test_certification_report_static_schema_matches_runtime_fields():
    schema = json.loads(Path("schemas/CertificationReport.schema.json").read_text(encoding="utf-8"))
    suite_schema = json.loads(Path("schemas/CertificationSuite.schema.json").read_text(encoding="utf-8"))
    suite = CertificationSuite(
        schema_version="rolo-mvp-certification-suite/v1",
        suite_id="schema",
        target_id="mentorpi",
        cases=[
            CertificationCase(case_id=f"case-{index:02d}", description="inspect", tool_id="native.os.host.inspect")
            for index in range(1, 11)
        ],
    )
    report = CertificationRunner(lambda *_: {"status": "SUCCEEDED"}, target_id="mentorpi").run(
        suite,
        release_digests={"native.os.host.inspect": "sha256:" + "a" * 64},
        compile_context_digest="sha256:" + "b" * 64,
        target_fingerprint="c" * 64,
    )
    payload = report.model_dump(mode="json")
    assert set(payload) == set(schema["properties"])
    assert set(payload["results"][0]) == set(schema["properties"]["results"]["items"]["properties"])
    suite_payload = suite.model_dump(mode="json")
    assert set(suite_payload) == set(suite_schema["properties"])
    assert set(suite_payload["cases"][0]) == set(suite_schema["properties"]["cases"]["items"]["properties"])


def test_certification_static_schemas_reject_runtime_invalid_payloads():
    report_schema = json.loads(Path("schemas/CertificationReport.schema.json").read_text(encoding="utf-8"))
    suite_schema = json.loads(Path("schemas/CertificationSuite.schema.json").read_text(encoding="utf-8"))
    request_schema = json.loads(Path("schemas/CertifyRequest.schema.json").read_text(encoding="utf-8"))
    validators = {
        "report": Draft202012Validator(report_schema, format_checker=FormatChecker()),
        "suite": Draft202012Validator(suite_schema, format_checker=FormatChecker()),
        "request": Draft202012Validator(request_schema, format_checker=FormatChecker()),
    }
    for schema in (report_schema, suite_schema, request_schema):
        Draft202012Validator.check_schema(schema)

    suite = CertificationSuite(
        schema_version="rolo-mvp-certification-suite/v1",
        suite_id="schema-negative",
        target_id="mentorpi",
        cases=[
            CertificationCase(case_id=f"case-{index:02d}", description="inspect", tool_id="native.os.host.inspect")
            for index in range(1, 11)
        ],
    ).with_digest()
    suite_payload = suite.model_dump(mode="json")
    validators["suite"].validate(suite_payload)
    duplicate_suite = deepcopy(suite_payload)
    duplicate_suite["cases"][1] = deepcopy(duplicate_suite["cases"][0])
    with pytest.raises(JsonSchemaValidationError):
        validators["suite"].validate(duplicate_suite)
    with pytest.raises(ValueError):
        CertificationSuite.model_validate(duplicate_suite)

    report = CertificationRunner(lambda *_: {"status": "SUCCEEDED"}, target_id="mentorpi").run(
        suite,
        release_digests={"native.os.host.inspect": "sha256:" + "a" * 64},
        compile_context_digest="sha256:" + "b" * 64,
        target_fingerprint="c" * 64,
    )
    report_payload = report.model_dump(mode="json")
    validators["report"].validate(report_payload)

    invalid_reports = []
    duplicate_results = deepcopy(report_payload)
    duplicate_results["results"][1] = deepcopy(duplicate_results["results"][0])
    invalid_reports.append(duplicate_results)
    pass_with_failed_case = deepcopy(report_payload)
    pass_with_failed_case["results"][0]["status"] = "FAIL"
    invalid_reports.append(pass_with_failed_case)
    non_blocked_without_release = deepcopy(report_payload)
    non_blocked_without_release["release_digest"] = None
    invalid_reports.append(non_blocked_without_release)
    invalid_artifact_digest = deepcopy(report_payload)
    invalid_artifact_digest["artifact_digests"] = ["sha256:" + "d" * 64]
    invalid_reports.append(invalid_artifact_digest)
    for payload in invalid_reports:
        with pytest.raises(JsonSchemaValidationError):
            validators["report"].validate(payload)
        with pytest.raises(ValueError):
            CertificationReport.model_validate(payload)

    request_payload = {
        "schema_version": "rolo-certify-request/v1",
        "target_id": "mentorpi",
        "suite_ref": "suite.json",
        "snapshot_digest": "UNKNOWN",
        "release_digest": "sha256:" + "a" * 64,
        "compile_context_digest": "sha256:" + "b" * 64,
        "target_fingerprint": "c" * 64,
        "failure_policy": "continue",
        "session_id": None,
    }
    validators["request"].validate(request_payload)
    for field_name, invalid_value in (("snapshot_digest", "not-a-digest"), ("suite_ref", "x" * 1025)):
        invalid_request = {**request_payload, field_name: invalid_value}
        with pytest.raises(JsonSchemaValidationError):
            validators["request"].validate(invalid_request)
        with pytest.raises(ValueError):
            CertifyRequest.model_validate(invalid_request)


def test_public_connector_refuses_certify_without_release_authority(tmp_path: Path):
    from fastapi.testclient import TestClient

    from rolo.api import app
    from rolo.mvp.http import register_catalog

    base = _catalog()
    target_id = "connector-contract"
    tools = [item.model_copy(update={"target_id": target_id}) for item in base.tools]
    catalog = base.model_copy(
        update={"target_id": target_id, "target_fingerprint": "c" * 64, "tools": tools, "digest": None}
    ).with_digest()
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
        json={
            "schema_version": "rolo-certify-request/v1",
            "target_id": target_id,
            "suite_ref": str(suite_path),
            "session_id": "connector-certify-1",
            "release_digest": "sha256:" + "a" * 64,
            "compile_context_digest": "sha256:" + "b" * 64,
            "target_fingerprint": "c" * 64,
        },
    )
    assert certify_response.status_code == 409, certify_response.text
    assert "RELEASE_AUTHORITY_REQUIRED" in certify_response.text
