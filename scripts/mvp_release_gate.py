from __future__ import annotations

import argparse
import hashlib
import json
import re
import tempfile
from pathlib import Path
from typing import Any

from rolo.agent_tools.conformance import ToolConformanceCheck, ToolConformanceReport
from rolo.agent_tools.native_tools import AgentNativeToolDescriptor
from rolo.agent_tools.session import native_catalog_sha256
from rolo.mvp.catalog import build_target_catalog
from rolo.mvp.certify import CertificationRunner, load_suite, write_report
from rolo.mvp.contracts import SessionState, TraceCall, TraceSessionRequest
from rolo.mvp.trace import TraceService


class ReleaseGateError(RuntimeError):
    """Raised when an offline MVP release gate cannot be satisfied."""


def validate_artifact_index(index_path: Path) -> dict[str, Any]:
    """Validate an artifact-index and every digest it references.

    Paths are resolved relative to the index directory and may not escape it.
    The index itself is deliberately excluded from the list it validates so it
    can remain immutable after generation.
    """
    if index_path.is_symlink() or not index_path.is_file():
        raise ReleaseGateError(f"artifact index is not a regular file: {index_path}")
    try:
        payload = json.loads(index_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ReleaseGateError(f"invalid artifact index: {index_path}") from exc
    if payload.get("schema_version") != "rolo-mvp-artifact-index/v1":
        raise ReleaseGateError("unsupported artifact index schema")
    if not isinstance(payload.get("run_id"), str) or not isinstance(payload.get("target_id"), str):
        raise ReleaseGateError("artifact index must include run_id and target_id")
    entries = payload.get("artifacts")
    if not isinstance(entries, list) or not entries:
        raise ReleaseGateError("artifact index must contain artifacts")
    root = index_path.parent.resolve()
    for entry in entries:
        if not isinstance(entry, dict):
            raise ReleaseGateError("artifact entry must be an object")
        relative = entry.get("path")
        expected = entry.get("sha256")
        if not isinstance(relative, str) or not isinstance(expected, str) or re.fullmatch(r"[0-9a-f]{64}", expected) is None:
            raise ReleaseGateError("artifact entry requires path and sha256")
        candidate = root / relative
        path = candidate.resolve()
        if candidate.is_symlink() or path.parent != root or not path.is_file():
            raise ReleaseGateError(f"artifact path escapes index directory or is missing: {relative}")
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != expected:
            raise ReleaseGateError(f"artifact digest mismatch: {relative}")
    return payload


def _descriptor(tool_id: str) -> AgentNativeToolDescriptor:
    return AgentNativeToolDescriptor(
        tool_id=tool_id,
        family="mvp-replay",
        execution_path="DIRECT_RUNNER",
        executable="fixture",
        argv_template=["fixture"],
        access="read",
        risk="R0",
        max_duration_s=5,
        max_output_bytes=4096,
        evidence_kind="replay",
    )


def _catalog(tool_id: str):
    descriptors = [_descriptor(tool_id)]
    report = ToolConformanceReport(
        target_id="mentorpi",
        session_id="release-gate-replay",
        surface_digest=native_catalog_sha256(descriptors),
        status="PASS",
        checks=[ToolConformanceCheck(name="offline-replay", status="PASS", detail="fixture")],
    )
    return build_target_catalog(
        target_id="mentorpi",
        descriptors=descriptors,
        conformance=report,
        freshness="fresh",
    )


def run_trace_replay(tool_id: str, *, task: str = "完成建图") -> dict[str, str]:
    catalog = _catalog(tool_id)
    service = TraceService(catalog, lambda *_: {"status": "SUCCEEDED"})
    success = service.create_session(
        TraceSessionRequest(target_id="mentorpi", catalog_digest=catalog.digest or "", task=task)
    )
    if service.execute(success.session_id, [TraceCall(tool_id=tool_id)]).state != SessionState.COMPLETED:
        raise ReleaseGateError("trace success replay did not complete")

    attempts = {"count": 0}

    def flaky_invoker(*_: Any) -> dict[str, str]:
        attempts["count"] += 1
        return {"status": "FAILED"} if attempts["count"] == 1 else {"status": "SUCCEEDED"}

    flaky = TraceService(catalog, flaky_invoker)
    recovering = flaky.create_session(
        TraceSessionRequest(target_id="mentorpi", catalog_digest=catalog.digest or "", task=task)
    )
    recovered = flaky.execute(
        recovering.session_id,
        [TraceCall(tool_id=tool_id)],
        diagnose=lambda *_: TraceCall(tool_id=tool_id),
        recover=lambda *_: TraceCall(tool_id=tool_id),
    )
    if recovered.state != SessionState.COMPLETED or not any(e.event == "RECOVERY_ATTEMPT" for e in recovered.events):
        raise ReleaseGateError("trace diagnosis/recovery replay did not complete")
    return {"success": success.state.value, "recovery": recovered.state.value}


def run_release_gate(suite_path: Path, output_dir: Path | None = None) -> dict[str, Any]:
    suite = load_suite(suite_path, target_id="mentorpi", require_ten_cases=True)
    destination = output_dir or Path(tempfile.mkdtemp(prefix="rolo-mvp-release-"))
    destination.mkdir(parents=True, exist_ok=True)

    def invoker(*_: Any) -> dict[str, str]:
        return {"status": "SUCCEEDED"}

    report = CertificationRunner(invoker).run(
        suite,
        snapshot_digest="0" * 64,
        run_id="offline-replay",
        session_id="offline-replay",
    )
    if report.conclusion != "PASS" or len(report.results) != 10:
        raise ReleaseGateError("offline certification replay did not pass all 10 cases")
    report_path, _ = write_report(report, destination / "certify-test-report.json")
    index_payload = validate_artifact_index(destination / "artifact-index.json")
    primary_tool = suite.cases[0].tool_id
    trace_states = run_trace_replay(primary_tool, task="preflight diagnostics")
    return {
        "status": "PASS",
        "suite_digest": suite.digest,
        "report": str(report_path),
        "artifact_index": index_payload["schema_version"],
        "trace": trace_states,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the offline Rolo MVP release gate")
    parser.add_argument("--suite", type=Path, default=Path("examples/chassis-rotation-10.json"))
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args()
    try:
        print(json.dumps(run_release_gate(args.suite, args.output_dir), ensure_ascii=False, indent=2))
    except (ReleaseGateError, FileNotFoundError, ValueError) as exc:
        print(f"MVP release gate FAILED: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
