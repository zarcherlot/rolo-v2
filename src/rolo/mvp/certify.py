from __future__ import annotations

import hashlib
import json
import secrets
from collections.abc import Callable, Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .artifacts import build_artifact_index, write_artifact_index
from .contracts import CaseStatus, CertificationCaseResult, CertificationReport, CertificationSuite


def load_suite(path: Path, *, target_id: str | None = None, require_ten_cases: bool = True) -> CertificationSuite:
    if path.is_symlink() or not path.is_file():
        raise FileNotFoundError(path)
    suite = CertificationSuite.model_validate_json(path.read_text(encoding="utf-8"))
    if target_id is not None and suite.target_id != target_id:
        raise ValueError("certification suite target does not match requested target")
    if require_ten_cases and len(suite.cases) != 10:
        raise ValueError("MVP certification suite must contain exactly 10 cases")
    return suite.with_digest() if suite.digest is None else suite


def _matches(expected: Any, actual: Any) -> bool:
    if expected is None:
        return True
    if isinstance(expected, Mapping) and isinstance(actual, Mapping):
        # Expected mappings are a subset assertion, useful for tool result
        # envelopes that include nondeterministic timestamps.
        if any(str(k).startswith("$") for k in expected):
            if "$eq" in expected:
                return actual == expected["$eq"]
            if "$contains" in expected:
                return expected["$contains"] in actual
        return all(k in actual and _matches(v, actual[k]) for k, v in expected.items())
    if isinstance(expected, list) and isinstance(actual, list):
        return expected == actual
    return expected == actual


class CertificationRunner:
    def __init__(self, invoker: Callable[[str, Mapping[str, Any], str], Any], *, clock: Callable[[], datetime] | None = None) -> None:
        self.invoker = invoker
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    def run(self, suite: CertificationSuite, *, snapshot_digest: str = "UNKNOWN", run_id: str | None = None, session_id: str | None = None) -> CertificationReport:
        if suite.digest is None:
            suite = suite.with_digest()
        session = session_id or f"certify-{secrets.token_urlsafe(10)}"
        results: list[CertificationCaseResult] = []
        for case in suite.cases:
            started = self.clock()
            operation_id = f"{session}:{case.case_id}"
            evidence = [f"certify:{operation_id}"]
            try:
                actual = self.invoker(case.tool_id, case.arguments, session)
                status = CaseStatus.PASS if _matches(case.expected, actual) else CaseStatus.FAIL
                failure = None if status == CaseStatus.PASS else "EXPECTED_MISMATCH"
            except PermissionError as exc:
                actual = {"error": str(exc)}
                status, failure = CaseStatus.BLOCKED, "AUTHORIZATION"
            except TimeoutError as exc:
                actual = {"error": str(exc)}
                status, failure = CaseStatus.UNKNOWN, "TIMEOUT"
            except Exception as exc:
                actual = {"error": str(exc)}
                status, failure = CaseStatus.FAIL, "TOOL_ERROR"
            finished = self.clock()
            elapsed = max(0, int((finished - started).total_seconds() * 1000))
            encoded = json.dumps({"case_id": case.case_id, "expected": case.expected, "actual": actual}, sort_keys=True, separators=(",", ":"))
            digest = hashlib.sha256(encoded.encode()).hexdigest()
            results.append(
                CertificationCaseResult(
                    case_id=case.case_id,
                    expected=case.expected,
                    actual=actual,
                    status=status,
                    operation_ids=[operation_id],
                    evidence_ids=evidence,
                    artifact_digests=[digest],
                    started_at=started,
                    finished_at=finished,
                    elapsed_ms=elapsed,
                    failure_class=failure,
                )
            )
        statuses = {item.status for item in results}
        conclusion = "PASS" if statuses == {CaseStatus.PASS} else ("BLOCKED" if statuses <= {CaseStatus.BLOCKED, CaseStatus.UNKNOWN} else "CONDITIONAL")
        report = CertificationReport(
            run_id=run_id or session,
            target_id=suite.target_id,
            snapshot_digest=snapshot_digest,
            suite_digest=suite.digest or suite.computed_digest(),
            results=results,
            conclusion=conclusion,
        )
        return report.model_copy(update={"artifact_digests": [hashlib.sha256(json.dumps(report.model_dump(mode="json"), sort_keys=True, separators=(",", ":")).encode()).hexdigest()]})


def write_report(
    report: CertificationReport,
    output: Path,
    *,
    signing_secret: bytes | None = None,
    previous_index: str | None = None,
) -> tuple[Path, Path]:
    output.parent.mkdir(parents=True, exist_ok=True)
    json_path = output if output.suffix == ".json" else output.with_suffix(".json")
    md_path = json_path.with_suffix(".md")
    json_path.write_text(json.dumps(report.model_dump(mode="json"), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    lines = [
        f"# Certification report `{report.run_id}`",
        "",
        f"- Target: `{report.target_id}`",
        f"- Conclusion: **{report.conclusion}**",
        f"- Suite digest: `{report.suite_digest}`",
        "",
        "| Case | Status | Expected | Actual | Evidence |",
        "|---|---|---|---|---|",
    ]
    for item in report.results:
        lines.append(f"| {item.case_id} | {item.status.value} | `{json.dumps(item.expected, ensure_ascii=False)}` | `{json.dumps(item.actual, ensure_ascii=False)}` | {', '.join(item.evidence_ids)} |")
    md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    index = build_artifact_index(
        run_id=report.run_id,
        target_id=report.target_id,
        files=[json_path, md_path],
        root=json_path.parent,
        secret=signing_secret,
        previous_index=previous_index,
    )
    write_artifact_index(json_path.with_name("artifact-index.json"), index)
    return json_path, md_path


__all__ = ["CertificationRunner", "load_suite", "write_report"]
