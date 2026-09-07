from __future__ import annotations

import hashlib
import inspect
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
    if path.stat().st_size > 1024 * 1024:
        raise ValueError("certification suite exceeds 1 MiB")
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, Mapping):
        raise ValueError("certification suite must be a JSON object")
    # The targetd rotation fixture is the canonical current MVP input.  Keep
    # the legacy offline runner useful by normalizing its compact argument
    # shape into the v1 certification contract at this boundary.
    if raw.get("schema_version") == "rolo-chassis-rotation-certify/v1":
        raw = {
            "schema_version": "rolo-mvp-certification-suite/v1",
            "suite_id": "chassis-rotation-10",
            "target_id": raw.get("target_id", "mentorpi"),
            "cases": [
                {
                    "case_id": case["case_id"],
                    "description": f"Execute {raw.get('tool_id', 'app.base.rotate')} rotation case",
                    "tool_id": raw.get("tool_id", "app.base.rotate"),
                    "arguments": {
                        "angle_degrees": case["angle_degrees"],
                        "max_speed_rad_s": case["max_speed_rad_s"],
                    },
                    "expected": {"status": "SUCCEEDED"},
                    "timeout_s": 180,
                    "risk": "R2",
                }
                for case in raw.get("cases", [])
            ],
        }
    suite = CertificationSuite.model_validate(raw)
    case_ids = [case.case_id for case in suite.cases]
    if len(case_ids) != len(set(case_ids)):
        raise ValueError("certification suite contains duplicate case_id values")
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
    def __init__(
        self,
        invoker: Callable[..., Any],
        *,
        clock: Callable[[], datetime] | None = None,
        on_event: Callable[[Mapping[str, Any]], Any] | None = None,
        stopper: Callable[..., Any] | None = None,
        target_id: str | None = None,
    ) -> None:
        self.invoker = invoker
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.on_event = on_event
        self.stopper = stopper
        self.target_id = target_id
        self.events: list[dict[str, Any]] = []

    def run(
        self,
        suite: CertificationSuite,
        *,
        snapshot_digest: str = "UNKNOWN",
        run_id: str | None = None,
        session_id: str | None = None,
        compile_context_digest: str | None = None,
        target_fingerprint: str | None = None,
        release_digests: Mapping[str, str] | None = None,
        fail_fast: bool = False,
        continue_on_failure: bool | None = None,
        cancellation_check: Callable[[], bool] | None = None,
        setup: Callable[[CertificationSuite, str], Any] | None = None,
        teardown: Callable[[CertificationSuite, str], Any] | None = None,
    ) -> CertificationReport:
        """Execute a suite with explicit bounded run-control semantics.

        The runner cannot safely kill an arbitrary in-process provider.  A
        provider must enforce its own hard timeout; this layer measures the
        elapsed duration, records ``UNKNOWN/TIMEOUT`` when the contract is
        exceeded, and invokes the optional stop hook.  ``fail_fast`` only
        controls whether later cases are marked ``NOT_RUN``; the default is
        to continue so a ten-case report is complete.
        """

        if suite.digest is None:
            suite = suite.with_digest()
        if continue_on_failure is not None:
            fail_fast = not continue_on_failure
        if not suite.cases:
            raise ValueError("certification suite must contain at least one case")
        session = session_id or f"certify-{secrets.token_urlsafe(10)}"
        self.events = []
        if self.target_id is not None and self.target_id != suite.target_id:
            return self._blocked_setup_report(
                suite,
                session=session,
                run_id=run_id,
                snapshot_digest=snapshot_digest,
                compile_context_digest=compile_context_digest,
                target_fingerprint=target_fingerprint,
                release_digests=release_digests,
                error=ValueError("suite target does not match runner target"),
                fail_fast=fail_fast,
                failure_class="TARGET_MISMATCH",
            )
        # When a release map is supplied, every case must be pinned to one of
        # its entries before any provider call is made.  Failing closed here
        # prevents a partially unbound suite from being reported as a normal
        # execution result.
        if release_digests is not None:
            missing_releases = sorted({case.tool_id for case in suite.cases} - set(release_digests))
            if missing_releases:
                return self._blocked_setup_report(
                    suite,
                    session=session,
                    run_id=run_id,
                    snapshot_digest=snapshot_digest,
                    compile_context_digest=compile_context_digest,
                    target_fingerprint=target_fingerprint,
                    release_digests=release_digests,
                    error=ValueError("missing release digest for: " + ", ".join(missing_releases)),
                    fail_fast=fail_fast,
                    failure_class="RELEASE_BINDING_MISSING",
                )
        if setup is not None:
            try:
                setup(suite, session)
            except Exception as exc:
                return self._blocked_setup_report(
                    suite,
                    session=session,
                    run_id=run_id,
                    snapshot_digest=snapshot_digest,
                    compile_context_digest=compile_context_digest,
                    target_fingerprint=target_fingerprint,
                    release_digests=release_digests,
                    error=exc,
                    fail_fast=fail_fast,
                    failure_class="SETUP_FAILED",
                )
        results: list[CertificationCaseResult] = []
        teardown_failed = False
        try:
            for index, case in enumerate(suite.cases):
                cancelled = False
                if cancellation_check is not None:
                    try:
                        cancelled = bool(cancellation_check())
                    except Exception:
                        cancelled = True
                if cancelled:
                    for item in suite.cases[index:]:
                        result = self._not_run_result(
                            item,
                            session=session,
                            reason="CANCELLED",
                            release_digest=(release_digests or {}).get(item.tool_id),
                            compile_context_digest=compile_context_digest,
                            target_fingerprint=target_fingerprint,
                        )
                        results.append(result)
                        self._emit("CASE_NOT_RUN", session, case_id=item.case_id, operation_id=f"{session}:{item.case_id}", reason="CANCELLED")
                    self._emit("RUN_CANCELLED", session, case_id=case.case_id)
                    break

                started = self.clock()
                operation_id = f"{session}:{case.case_id}"
                evidence = [f"certify:{operation_id}"]
                release_digest = (release_digests or {}).get(case.tool_id)
                self._emit("CASE_STARTED", session, case_id=case.case_id, operation_id=operation_id)
                try:
                    actual = self._call_invoker(case.tool_id, case.arguments, session, operation_id)
                    elapsed_before_finish = max(0.0, (self.clock() - started).total_seconds())
                    if elapsed_before_finish > case.timeout_s:
                        actual = {"status": "UNKNOWN", "error": "case timeout exceeded", "provider_result": actual}
                        status, failure = CaseStatus.UNKNOWN, "TIMEOUT"
                        self._stop(case, session)
                    else:
                        status, failure = self._classify_actual(case.expected, actual)
                        # A provider-reported UNKNOWN/TIMEOUT means the
                        # operation may have reached the target before the
                        # receipt was lost.  Issue the same hard-stop hook as
                        # an exception/elapsed timeout, even when the
                        # expected assertion happens to match the envelope.
                        if status == CaseStatus.UNKNOWN:
                            self._stop(case, session)
                except PermissionError as exc:
                    actual = {"status": "BLOCKED", "error": str(exc)}
                    status, failure = CaseStatus.BLOCKED, "AUTHORIZATION"
                except TimeoutError as exc:
                    actual = {"status": "UNKNOWN", "error": str(exc)}
                    status, failure = CaseStatus.UNKNOWN, "TIMEOUT"
                    self._stop(case, session)
                except Exception as exc:
                    actual = {"status": "FAILED", "error": str(exc)}
                    error_text = str(exc).upper()
                    blocked = any(token in error_text for token in ("BLOCKED", "RELEASE_", "TARGET_", "AUTHORIZATION"))
                    status, failure = (CaseStatus.BLOCKED, "EXECUTION_BLOCKED") if blocked else (CaseStatus.FAIL, "TOOL_ERROR")
                finished = self.clock()
                elapsed = max(0, int((finished - started).total_seconds() * 1000))
                encoded = json.dumps(
                    {
                        "case_id": case.case_id,
                        "expected": case.expected,
                        "actual": actual,
                        "operation_id": operation_id,
                        "release_digest": release_digest,
                        "compile_context_digest": compile_context_digest,
                        "target_fingerprint": target_fingerprint,
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                )
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
                        release_digest=release_digest,
                        compile_context_digest=compile_context_digest,
                        target_fingerprint=target_fingerprint,
                        idempotency_key=operation_id,
                    )
                )
                self._emit("CASE_FINISHED", session, case_id=case.case_id, operation_id=operation_id, status=status.value)
                if fail_fast and status != CaseStatus.PASS:
                    for item in suite.cases[index + 1 :]:
                        result = self._not_run_result(
                            item,
                            session=session,
                            reason="FAIL_FAST",
                            release_digest=(release_digests or {}).get(item.tool_id),
                            compile_context_digest=compile_context_digest,
                            target_fingerprint=target_fingerprint,
                        )
                        results.append(result)
                        self._emit("CASE_NOT_RUN", session, case_id=item.case_id, operation_id=f"{session}:{item.case_id}", reason="FAIL_FAST")
                    self._emit("RUN_STOPPED_FAIL_FAST", session, case_id=case.case_id)
                    break
        finally:
            if teardown is not None:
                try:
                    teardown(suite, session)
                except Exception as exc:
                    teardown_failed = True
                    self._emit("TEARDOWN_FAILED", session, error=type(exc).__name__)
        statuses = {item.status for item in results}
        conclusion = "PASS" if statuses == {CaseStatus.PASS} else ("BLOCKED" if statuses <= {CaseStatus.BLOCKED, CaseStatus.UNKNOWN, CaseStatus.NOT_RUN} else "CONDITIONAL")
        limitations: list[str] = []
        if teardown_failed:
            limitations.append("TEARDOWN_FAILED")
            if conclusion == "PASS":
                conclusion = "CONDITIONAL"
        report = CertificationReport(
            run_id=run_id or session,
            target_id=suite.target_id,
            snapshot_digest=snapshot_digest,
            suite_digest=suite.digest or suite.computed_digest(),
            results=results,
            conclusion=conclusion,
            compile_context_digest=compile_context_digest,
            target_fingerprint=target_fingerprint,
            failure_policy="fail_fast" if fail_fast else "continue",
            event_count=len(self.events),
            generated_at=self.clock(),
            limitations=limitations,
        )
        return report.model_copy(
            update={
                "artifact_digests": [
                    hashlib.sha256(
                        json.dumps(report.model_dump(mode="json"), sort_keys=True, separators=(",", ":")).encode()
                    ).hexdigest()
                ]
            }
        )

    @staticmethod
    def _classify_actual(expected: Any, actual: Any) -> tuple[CaseStatus, str | None]:
        """Map a provider result envelope to the fixed case status model.

        A provider's ``BLOCKED``/``UNKNOWN`` status is a transport or policy
        outcome, not an ordinary expected-value mismatch.  Preserve that
        distinction unless the expected assertion explicitly matches it.
        """

        token = str(actual.get("status", "")).upper() if isinstance(actual, Mapping) else ""
        terminal_statuses = {
            "BLOCKED",
            "DENIED",
            "UNAUTHORIZED",
            "AUTHORIZATION",
            "UNKNOWN",
            "TIMEOUT",
            "DISCONNECTED",
            "UNAVAILABLE",
            "CANCELLED",
            "STOPPED",
            "FAILED",
            "FAIL",
            "ERROR",
        }
        # ``expected=None`` means that no payload fields are asserted; it must
        # not turn a provider refusal/transport uncertainty into PASS.  An
        # explicit expected assertion that matches the provider status (for
        # example ``{"status": "BLOCKED"}``) remains a valid PASS.
        if token in terminal_statuses:
            if expected is not None and _matches(expected, actual):
                return CaseStatus.PASS, None
        elif _matches(expected, actual):
            return CaseStatus.PASS, None
        if token in {"BLOCKED", "DENIED", "UNAUTHORIZED", "AUTHORIZATION"}:
            return CaseStatus.BLOCKED, "EXECUTION_BLOCKED"
        if token in {"UNKNOWN", "TIMEOUT", "DISCONNECTED", "UNAVAILABLE", "CANCELLED", "STOPPED"}:
            return CaseStatus.UNKNOWN, "TIMEOUT" if token == "TIMEOUT" else "EXECUTION_UNKNOWN"
        return CaseStatus.FAIL, "EXPECTED_MISMATCH"

    def _call_invoker(self, tool_id: str, arguments: Mapping[str, Any], session: str, idempotency_key: str) -> Any:
        """Call legacy providers and v2 positional/keyword key providers.

        We inspect once before invocation instead of retrying after a
        ``TypeError``; retrying a physical provider can duplicate an operation.
        """

        try:
            signature = inspect.signature(self.invoker)
            parameters = tuple(signature.parameters.values())
            positional = [
                parameter
                for parameter in parameters
                if parameter.kind in (parameter.POSITIONAL_ONLY, parameter.POSITIONAL_OR_KEYWORD)
            ]
            accepts_varargs = any(parameter.kind == parameter.VAR_POSITIONAL for parameter in parameters)
        except (TypeError, ValueError):
            parameters = ()
            positional = []
            accepts_varargs = True
        if accepts_varargs or len(positional) >= 4:
            return self.invoker(tool_id, arguments, session, idempotency_key)
        keyword_key = next(
            (
                parameter.name
                for parameter in parameters
                if parameter.kind == parameter.KEYWORD_ONLY
                and parameter.name in {"idempotency_key", "operation_id"}
            ),
            None,
        )
        if keyword_key is not None:
            return self.invoker(tool_id, arguments, session, **{keyword_key: idempotency_key})
        if any(parameter.kind == parameter.VAR_KEYWORD for parameter in parameters):
            return self.invoker(tool_id, arguments, session, idempotency_key=idempotency_key)
        return self.invoker(tool_id, arguments, session)

    def _stop(self, case: Any, session: str) -> None:
        if self.stopper is None:
            return
        try:
            signature = inspect.signature(self.stopper)
            positional = [
                parameter
                for parameter in signature.parameters.values()
                if parameter.kind in (parameter.POSITIONAL_ONLY, parameter.POSITIONAL_OR_KEYWORD)
            ]
            accepts_varargs = any(parameter.kind == parameter.VAR_POSITIONAL for parameter in signature.parameters.values())
            if accepts_varargs or len(positional) >= 2:
                # Keep the stop-hook argument order identical to Trace:
                # ``(session_id, reason)``.  Passing the tool first made it
                # impossible for a shared targetd stopper to correlate a
                # certification timeout with its run.
                self.stopper(session, f"case:{case.case_id}")
            elif len(positional) == 1:
                self.stopper(session)
            else:
                self.stopper()
            self._emit("STOP_SIGNAL_SENT", session, case_id=case.case_id, reason="case timeout/unknown")
        except Exception as exc:
            self._emit("STOP_SIGNAL_FAILED", session, case_id=case.case_id, error=type(exc).__name__)

    def _emit(self, event: str, session: str, **payload: Any) -> None:
        item = {
            "schema_version": "rolo-mvp-certify-event/v1",
            "event": event,
            "run_id": session,
            "session_id": session,
            "target_id": self.target_id,
            "created_at": self.clock().isoformat(),
            **payload,
        }
        self.events.append(item)
        if self.on_event is not None:
            try:
                self.on_event(item)
            except Exception:
                # Observability must never change the certification result.
                pass

    def _not_run_result(
        self,
        case: Any,
        *,
        session: str,
        reason: str,
        release_digest: str | None,
        compile_context_digest: str | None,
        target_fingerprint: str | None,
    ) -> CertificationCaseResult:
        now = self.clock()
        operation_id = f"{session}:{case.case_id}"
        evidence = [f"certify:{operation_id}"]
        digest = hashlib.sha256(
            json.dumps(
                {
                    "case_id": case.case_id,
                    "expected": case.expected,
                    "status": "NOT_RUN",
                    "reason": reason,
                    "release_digest": release_digest,
                    "compile_context_digest": compile_context_digest,
                    "target_fingerprint": target_fingerprint,
                },
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            ).encode()
        ).hexdigest()
        return CertificationCaseResult(
            case_id=case.case_id,
            expected=case.expected,
            actual={"status": "NOT_RUN", "reason": reason},
            status=CaseStatus.NOT_RUN,
            operation_ids=[operation_id],
            evidence_ids=evidence,
            artifact_digests=[digest],
            started_at=now,
            finished_at=now,
            elapsed_ms=0,
            failure_class=reason,
            release_digest=release_digest,
            compile_context_digest=compile_context_digest,
            target_fingerprint=target_fingerprint,
            idempotency_key=operation_id,
        )

    def _blocked_setup_report(
        self,
        suite: CertificationSuite,
        *,
        session: str,
        run_id: str | None,
        snapshot_digest: str,
        compile_context_digest: str | None,
        target_fingerprint: str | None,
        release_digests: Mapping[str, str] | None,
        error: Exception,
        fail_fast: bool,
        failure_class: str = "SETUP_FAILED",
    ) -> CertificationReport:
        now = self.clock()
        self._emit("RUN_BLOCKED", session, error_code=failure_class, error=type(error).__name__)
        results = [
            CertificationCaseResult(
                case_id=case.case_id,
                expected=case.expected,
                actual={"status": "BLOCKED", "error": str(error)},
                status=CaseStatus.BLOCKED,
                operation_ids=[f"{session}:{case.case_id}"],
                evidence_ids=[f"certify:{session}:{case.case_id}"],
                artifact_digests=[
                    hashlib.sha256(
                        json.dumps(
                            {
                                "case_id": case.case_id,
                                "status": "BLOCKED",
                                "failure_class": failure_class,
                                "error": str(error),
                            },
                            sort_keys=True,
                            separators=(",", ":"),
                            ensure_ascii=False,
                        ).encode()
                    ).hexdigest()
                ],
                started_at=now,
                finished_at=now,
                elapsed_ms=0,
                failure_class=failure_class,
                release_digest=(release_digests or {}).get(case.tool_id),
                compile_context_digest=compile_context_digest,
                target_fingerprint=target_fingerprint,
                idempotency_key=f"{session}:{case.case_id}",
            )
            for case in suite.cases
        ]
        report = CertificationReport(
            run_id=run_id or session,
            target_id=suite.target_id,
            snapshot_digest=snapshot_digest,
            suite_digest=suite.digest or suite.computed_digest(),
            results=results,
            conclusion="BLOCKED",
            generated_at=now,
            limitations=[failure_class],
            compile_context_digest=compile_context_digest,
            target_fingerprint=target_fingerprint,
            failure_policy="fail_fast" if fail_fast else "continue",
            event_count=len(self.events),
        )
        return report.model_copy(
            update={
                "artifact_digests": [
                    hashlib.sha256(
                        json.dumps(report.model_dump(mode="json"), sort_keys=True, separators=(",", ":")).encode()
                    ).hexdigest()
                ]
            }
        )


def write_report(
    report: CertificationReport,
    output: Path,
    *,
    signing_secret: bytes | None = None,
    previous_index: str | None = None,
) -> tuple[Path, Path]:
    if output.parent.exists() and output.parent.is_symlink():
        raise ValueError("certification report directory must not be a symlink")
    output.parent.mkdir(parents=True, exist_ok=True)
    requested_json = output if output.suffix == ".json" else output.with_suffix(".json")
    json_path = _non_overwriting_path(requested_json, report.run_id)
    md_path = json_path.with_suffix(".md")
    html_path = json_path.with_suffix(".html")
    index_name = "artifact-index.json" if json_path == requested_json else f"{json_path.stem}.artifact-index.json"
    index_path = json_path.with_name(index_name)
    for artifact_path in (json_path, md_path, html_path, index_path):
        if artifact_path.is_symlink():
            raise ValueError(f"certification report artifact must not be a symlink: {artifact_path}")
    json_path.write_text(json.dumps(report.model_dump(mode="json"), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    lines = [
        f"# Certification report `{report.run_id}`",
        "",
        f"- Target: `{report.target_id}`",
        f"- Conclusion: **{report.conclusion}**",
        f"- Suite digest: `{report.suite_digest}`",
        f"- Failure policy: `{report.failure_policy}`",
        f"- Context digest: `{report.compile_context_digest or 'UNKNOWN'}`",
        f"- Target fingerprint: `{report.target_fingerprint or 'UNKNOWN'}`",
        "",
        "| Case | Status | Expected | Actual | Release | Evidence |",
        "|---|---|---|---|---|---|",
    ]
    for item in report.results:
        lines.append(
            f"| {item.case_id} | {item.status.value} | `{json.dumps(item.expected, ensure_ascii=False)}` | "
            f"`{json.dumps(item.actual, ensure_ascii=False)}` | `{item.release_digest or 'UNKNOWN'}` | {', '.join(item.evidence_ids)} |"
        )
    md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    # HTML is a derived view of the same JSON facts.  It is included in the
    # artifact index for convenient local review; no second result model is
    # introduced.
    import html

    rows = "".join(
        "<tr>"
        + "".join(
            f"<td>{html.escape(value)}</td>"
            for value in (
                item.case_id,
                item.status.value,
                json.dumps(item.expected, ensure_ascii=False),
                json.dumps(item.actual, ensure_ascii=False),
                item.release_digest or "UNKNOWN",
                ", ".join(item.evidence_ids),
            )
        )
        + "</tr>"
        for item in report.results
    )
    html_path.write_text(
        "<!doctype html><meta charset='utf-8'><title>Certification report "
        + html.escape(report.run_id)
        + "</title><h1>Certification report <code>"
        + html.escape(report.run_id)
        + "</code></h1><p>Conclusion: <strong>"
        + html.escape(report.conclusion)
        + "</strong></p><table><thead><tr><th>Case</th><th>Status</th><th>Expected</th><th>Actual</th><th>Release</th><th>Evidence</th></tr></thead><tbody>"
        + rows
        + "</tbody></table>\n",
        encoding="utf-8",
    )
    index = build_artifact_index(
        run_id=report.run_id,
        target_id=report.target_id,
        files=[json_path, md_path, html_path],
        root=json_path.parent,
        secret=signing_secret,
        previous_index=previous_index,
    )
    write_artifact_index(index_path, index)
    return json_path, md_path


def _non_overwriting_path(path: Path, run_id: str) -> Path:
    """Choose a stable sibling when a report path already exists.

    Historical certification output is evidence and must never be replaced by
    a later run.  The first invocation keeps the requested path for backwards
    compatibility; subsequent invocations use a run-id suffix and then a
    numeric suffix if that run id was reused.
    """

    def occupied(candidate: Path) -> bool:
        # A partial prior run may have left only a Markdown/HTML/index
        # sidecar.  Treat that as occupied too; otherwise a new report would
        # silently overwrite historical evidence even though its JSON name is
        # free.
        sidecars = (
            candidate,
            candidate.with_suffix(".md"),
            candidate.with_suffix(".html"),
            candidate.with_name("artifact-index.json")
            if candidate == path
            else candidate.with_name(f"{candidate.stem}.artifact-index.json"),
        )
        return any(item.exists() or item.is_symlink() for item in sidecars)

    if not occupied(path):
        return path
    safe_run = "".join(char if char.isalnum() or char in "._-" else "_" for char in run_id)[:96] or "run"
    candidate = path.with_name(f"{path.stem}.{safe_run}{path.suffix}")
    counter = 2
    while occupied(candidate):
        candidate = path.with_name(f"{path.stem}.{safe_run}.{counter}{path.suffix}")
        counter += 1
    return candidate


__all__ = ["CertificationRunner", "load_suite", "write_report"]
