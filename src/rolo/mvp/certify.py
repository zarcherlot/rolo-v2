from __future__ import annotations

import hashlib
import inspect
import json
import os
import re
import secrets
import tempfile
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .artifacts import ArtifactIndex, build_artifact_index
from .contracts import CaseStatus, CertificationCaseResult, CertificationReport, CertificationSuite

_RELEASE_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_CONTEXT_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_TARGET_FINGERPRINT_RE = re.compile(r"^[0-9a-f]{64}$")
_ARTIFACT_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_SNAPSHOT_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$|^UNKNOWN$")
_SAFE_BINDING_FAILURES = frozenset(
    {
        "MULTIPLE_RELEASES_NOT_ALLOWED",
        "RELEASE_NOT_CURRENT",
        "TARGET_ID_MISMATCH",
        "TARGET_FINGERPRINT_MISMATCH",
        "CONTEXT_DIGEST_MISMATCH",
        "TARGET_CONFORMANCE_REQUIRED",
    }
)
_PRECALL_BLOCK_FAILURES = _SAFE_BINDING_FAILURES | {
    "RELEASE_BINDING_MISSING",
    "RELEASE_CURRENT_CHECK_FAILED",
    "RELEASE_DIGEST_INVALID",
    "CONTEXT_BINDING_MISSING",
    "TARGET_BINDING_MISSING",
    "TARGET_MISMATCH",
    "SETUP_FAILED",
}
_SENSITIVE_EVIDENCE_KEY_RE = re.compile(
    r"(?:^|[_-])(raw|detail|secret|password|token|credential)(?:$|[_-])",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class CertificationInvocationContext:
    """Complete per-case identity passed to a typed certification invoker."""

    run_id: str
    session_id: str
    suite_id: str
    suite_digest: str
    case_id: str
    tool_id: str
    target_id: str
    arguments: Mapping[str, Any]
    timeout_s: float
    risk: str
    stop_condition: str
    operation_id: str
    idempotency_key: str
    release_digest: str
    compile_context_digest: str
    target_fingerprint: str


@dataclass(frozen=True)
class CertificationReceiptSidecar:
    """Sanitized receipt evidence frozen as its exact publication bytes."""

    case_id: str
    idempotency_key: str
    canonical_bytes: bytes
    digest: str

    @property
    def payload(self) -> Mapping[str, Any]:
        """Return a fresh decoded copy; callers cannot mutate stored evidence."""

        value = json.loads(self.canonical_bytes)
        if not isinstance(value, Mapping):
            raise ValueError("CERTIFY_RECEIPT_PAYLOAD_INVALID")
        return value


@dataclass(frozen=True)
class ArtifactPlanReservation:
    """Exclusive cooperative reservation for one immutable artifact plan."""

    path: Path
    token: bytes

    def release(self) -> None:
        if self.path.is_symlink() or not self.path.is_file():
            raise ValueError("certification artifact reservation is missing or unsafe")
        if self.path.read_bytes() != self.token:
            raise ValueError("certification artifact reservation identity changed")
        self.path.unlink()


@dataclass(frozen=True)
class CertificationInvocationOutcome:
    """Typed provider result plus optional immutable receipt evidence."""

    actual: Any
    receipt_sidecar: CertificationReceiptSidecar | None = None
    evidence_ids: tuple[str, ...] = ()
    artifact_digests: tuple[str, ...] = ()
    restricted_evidence: bool = False
    target_terminal_status: str | None = None


def certification_idempotency_key(
    *,
    session_id: str,
    run_id: str,
    suite_digest: str,
    case_id: str,
) -> str:
    """Derive one bounded targetd-safe key from the full Certify identity."""

    encoded = json.dumps(
        {
            "schema_version": "rolo-mvp-certify-idempotency/v1",
            "session_id": session_id,
            "run_id": run_id,
            "suite_digest": suite_digest,
            "case_id": case_id,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return f"certify:sha256:{hashlib.sha256(encoded).hexdigest()}"


def certification_receipt_sidecar_text(payload: Mapping[str, Any]) -> str:
    """Return the one canonical byte representation used for receipt files."""

    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ) + "\n"


def validate_certification_run_inputs(
    *,
    snapshot_digest: str,
    run_id: str | None,
) -> None:
    """Validate report-owned inputs before any provider can be invoked."""

    if (
        not isinstance(snapshot_digest, str)
        or _SNAPSHOT_DIGEST_RE.fullmatch(snapshot_digest) is None
    ):
        raise ValueError("certification snapshot digest is invalid")
    if run_id is not None and (
        not isinstance(run_id, str) or not 1 <= len(run_id) <= 128
    ):
        raise ValueError("certification run id is invalid")


def verify_targetd_certification_evidence(
    report: CertificationReport,
    sidecars: list[CertificationReceiptSidecar],
    *,
    receipt_paths: list[Path] | None = None,
    artifact_index: ArtifactIndex | None = None,
) -> None:
    """Cross-check a formal TARGETD_V2 report, receipts, and optional index."""

    # Import lazily to keep the generic MVP Certify module usable without a
    # module-import cycle.  Formal TARGETD_V2 evidence still has to validate
    # against the complete targetd receipt model and the same normalization
    # rules used at the live adapter boundary.
    from rolo.targetd.certify_adapter import TargetdV2CertifyAdapter
    from rolo.targetd.protocol import TargetdCallReceipt

    by_case: dict[str, CertificationReceiptSidecar] = {}
    normalized_actual_by_case: dict[str, dict[str, object]] = {}
    receipt_status_by_case: dict[str, str] = {}
    sessions: set[str] = set()
    for sidecar in sidecars:
        if sidecar.case_id in by_case:
            raise ValueError("TARGETD_CERTIFY_DUPLICATE_CASE_RECEIPT")
        if hashlib.sha256(sidecar.canonical_bytes).hexdigest() != sidecar.digest:
            raise ValueError("TARGETD_CERTIFY_RECEIPT_DIGEST_MISMATCH")
        try:
            payload = sidecar.payload
        except (UnicodeDecodeError, ValueError, TypeError):
            raise ValueError("TARGETD_CERTIFY_RECEIPT_PAYLOAD_INVALID") from None
        receipt = payload.get("receipt")
        if not isinstance(receipt, Mapping):
            raise ValueError("TARGETD_CERTIFY_RECEIPT_PAYLOAD_INVALID")
        if set(payload) != {
            "schema_version",
            "run_id",
            "session_id",
            "suite_id",
            "suite_digest",
            "case_id",
            "operation_id",
            "idempotency_key",
            "receipt",
        }:
            raise ValueError("TARGETD_CERTIFY_RECEIPT_PAYLOAD_INVALID")
        try:
            typed_receipt = TargetdCallReceipt.model_validate(dict(receipt))
            if typed_receipt.status not in {
                "SUCCEEDED",
                "FAILED",
                "STOPPED",
                "CANCELLED",
                "UNKNOWN",
                "NOT_ACCEPTED",
            }:
                raise ValueError
            if (
                typed_receipt.status == "SUCCEEDED"
                and typed_receipt.provider_started_at is None
            ) or (
                typed_receipt.provider_started_at is not None
                and typed_receipt.updated_at < typed_receipt.provider_started_at
            ):
                raise ValueError
            TargetdV2CertifyAdapter._validate_refs(typed_receipt)
            normalized_actual = TargetdV2CertifyAdapter._safe_actual(typed_receipt)
        except (TypeError, ValueError):
            raise ValueError("TARGETD_CERTIFY_RECEIPT_PAYLOAD_INVALID") from None
        session_id = typed_receipt.session_id
        identities = {
            "schema_version": "rolo-certify-targetd-call-receipt-sidecar/v1",
            "run_id": report.run_id,
            "suite_digest": report.suite_digest,
            "case_id": sidecar.case_id,
            "operation_id": sidecar.idempotency_key,
            "idempotency_key": sidecar.idempotency_key,
            "session_id": session_id,
        }
        if (
            not isinstance(session_id, str)
            or not isinstance(payload.get("suite_id"), str)
            or not payload.get("suite_id")
            or any(payload.get(field) != value for field, value in identities.items())
            or typed_receipt.idempotency_key != sidecar.idempotency_key
            or typed_receipt.target_id != report.target_id
            or typed_receipt.release_digest != report.release_digest
            or typed_receipt.context_digest != report.compile_context_digest
        ):
            raise ValueError("TARGETD_CERTIFY_RECEIPT_IDENTITY_MISMATCH")
        sessions.add(session_id)
        by_case[sidecar.case_id] = sidecar
        normalized_actual_by_case[sidecar.case_id] = normalized_actual
        receipt_status_by_case[sidecar.case_id] = typed_receipt.status

    if len({sidecar.digest for sidecar in sidecars}) != len(sidecars):
        raise ValueError("TARGETD_CERTIFY_RECEIPT_DIGEST_DUPLICATE")
    if len(sessions) > 1:
        raise ValueError("TARGETD_CERTIFY_RECEIPT_SESSION_MISMATCH")
    report_case_ids = {item.case_id for item in report.results}
    complete_receipts = set(by_case) == report_case_ids
    precall_block = not sidecars and all(
        item.status == CaseStatus.BLOCKED
        and item.failure_class in _PRECALL_BLOCK_FAILURES
        for item in report.results
    )
    if not complete_receipts and not precall_block:
        raise ValueError("TARGETD_CERTIFY_RECEIPTS_INCOMPLETE")
    for item in report.results:
        sidecar = by_case.get(item.case_id)
        if sidecar is None:
            continue
        receipt_status = receipt_status_by_case[item.case_id]
        normalized_actual = normalized_actual_by_case[item.case_id]
        if (
            item.idempotency_key != sidecar.idempotency_key
            or item.operation_ids != [sidecar.idempotency_key]
            or item.artifact_digests.count(sidecar.digest) != 1
            or item.evidence_ids.count(
                f"targetd-call-receipt:sha256:{sidecar.digest}"
            )
            != 1
            or (
                item.status == CaseStatus.PASS
                and receipt_status != "SUCCEEDED"
            )
        ):
            raise ValueError("TARGETD_CERTIFY_REPORT_RECEIPT_MISMATCH")
        if item.actual != normalized_actual:
            raise ValueError("TARGETD_CERTIFY_REPORT_RECEIPT_RESULT_MISMATCH")

    if receipt_paths is None and artifact_index is None:
        return
    if receipt_paths is None or artifact_index is None:
        raise ValueError("TARGETD_CERTIFY_INDEX_VERIFICATION_INCOMPLETE")
    try:
        verified_index = ArtifactIndex.model_validate(
            artifact_index.model_dump(mode="python")
        )
        verified_index.verify()
    except (AttributeError, TypeError, ValueError):
        raise ValueError("TARGETD_CERTIFY_INDEX_INVALID") from None
    if (
        verified_index.run_id != report.run_id
        or verified_index.target_id != report.target_id
    ):
        raise ValueError("TARGETD_CERTIFY_INDEX_IDENTITY_MISMATCH")
    artifact_index = verified_index
    if len(receipt_paths) != len(sidecars):
        raise ValueError("TARGETD_CERTIFY_RECEIPT_PATH_COUNT_MISMATCH")
    indexed = {
        item.get("path"): item.get("sha256") for item in artifact_index.artifacts
    }
    if len(indexed) != len(artifact_index.artifacts):
        raise ValueError("TARGETD_CERTIFY_INDEX_PATH_DUPLICATE")
    root = receipt_paths[0].parent if receipt_paths else None
    for sidecar, path in zip(sidecars, receipt_paths, strict=True):
        if root is None or path.parent != root:
            raise ValueError("TARGETD_CERTIFY_RECEIPT_PATH_INVALID")
        relative = path.name
        digest_entries = [
            item
            for item in artifact_index.artifacts
            if item.get("sha256") == sidecar.digest
        ]
        if indexed.get(relative) != sidecar.digest or len(digest_entries) != 1:
            raise ValueError("TARGETD_CERTIFY_INDEX_RECEIPT_MISMATCH")


def _validate_typed_evidence_payload(value: Any, *, path: str = "outcome") -> None:
    """Reject sensitive keys and unbounded values from typed target outcomes."""

    if isinstance(value, Mapping):
        if len(value) > 128:
            raise ValueError("CERTIFY_OUTCOME_TOO_LARGE")
        for key, item in value.items():
            if not isinstance(key, str) or _SENSITIVE_EVIDENCE_KEY_RE.search(key):
                raise ValueError("CERTIFY_OUTCOME_SENSITIVE_FIELD")
            _validate_typed_evidence_payload(item, path=f"{path}.{key}")
        return
    if isinstance(value, (list, tuple)):
        if len(value) > 128:
            raise ValueError("CERTIFY_OUTCOME_TOO_LARGE")
        for index, item in enumerate(value):
            _validate_typed_evidence_payload(item, path=f"{path}[{index}]")
        return
    if value is not None and not isinstance(value, (str, int, float, bool)):
        raise ValueError("CERTIFY_OUTCOME_INVALID_VALUE")
    if isinstance(value, str) and len(value) > 4096:
        raise ValueError("CERTIFY_OUTCOME_TOO_LARGE")


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
    if target_id is not None and suite.target_id != target_id:
        raise ValueError("certification suite target does not match requested target")
    if not require_ten_cases:
        raise ValueError("variable certification suites are not supported; exactly 10 cases are required")
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
        self.receipt_sidecars: list[CertificationReceiptSidecar] = []
        self._active_run_id: str | None = None

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
        binding_check: Callable[[], Any] | None = None,
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

        validate_certification_run_inputs(
            snapshot_digest=snapshot_digest,
            run_id=run_id,
        )
        if suite.digest is None:
            suite = suite.with_digest()
        if continue_on_failure is not None:
            fail_fast = not continue_on_failure
        if not suite.cases:
            raise ValueError("certification suite must contain at least one case")
        session = session_id or f"certify-{secrets.token_urlsafe(10)}"
        effective_run_id = run_id or session
        self.events = []
        self.receipt_sidecars = []
        self._active_run_id = effective_run_id
        tool_id = suite.cases[0].tool_id
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
        # The MVP Certify contract is deliberately narrower than Trace: all
        # ten cases consume one exact Release/Context/target identity.  Check
        # the complete identity once before setup or provider invocation.
        binding_failure: tuple[str, str] | None = None
        expected_release_keys = {tool_id}
        actual_release_keys = set(release_digests or {})
        if not release_digests:
            binding_failure = ("RELEASE_BINDING_MISSING", "release digest is required")
        elif actual_release_keys != expected_release_keys:
            binding_failure = (
                "MULTIPLE_RELEASES_NOT_ALLOWED",
                "release binding must contain exactly the suite tool",
            )
        else:
            release_digest = release_digests[tool_id]
            if not _RELEASE_DIGEST_RE.fullmatch(release_digest):
                binding_failure = ("RELEASE_DIGEST_INVALID", "release digest is invalid")
        if binding_failure is None and (
            compile_context_digest is None or not _CONTEXT_DIGEST_RE.fullmatch(compile_context_digest)
        ):
            binding_failure = ("CONTEXT_BINDING_MISSING", "compile context digest is required")
        if binding_failure is None and (
            target_fingerprint is None or not _TARGET_FINGERPRINT_RE.fullmatch(target_fingerprint)
        ):
            binding_failure = ("TARGET_BINDING_MISSING", "target fingerprint is required")
        if binding_failure is not None:
            failure_class, detail = binding_failure
            return self._blocked_setup_report(
                suite,
                session=session,
                run_id=run_id,
                snapshot_digest=snapshot_digest,
                compile_context_digest=compile_context_digest,
                target_fingerprint=target_fingerprint,
                release_digests=release_digests,
                error=ValueError(detail),
                fail_fast=fail_fast,
                failure_class=failure_class,
            )
        if binding_check is not None:
            try:
                binding_check()
            except Exception as exc:
                candidate = str(exc)
                error_code = (
                    candidate
                    if candidate in _SAFE_BINDING_FAILURES
                    else "RELEASE_CURRENT_CHECK_FAILED"
                )
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
                    failure_class=error_code,
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
                            run_id=effective_run_id,
                            suite_digest=suite.digest or suite.computed_digest(),
                            reason="CANCELLED",
                            release_digest=(release_digests or {}).get(item.tool_id),
                            compile_context_digest=compile_context_digest,
                            target_fingerprint=target_fingerprint,
                        )
                        results.append(result)
                        self._emit(
                            "CASE_NOT_RUN",
                            session,
                            case_id=item.case_id,
                            operation_id=result.idempotency_key,
                            reason="CANCELLED",
                        )
                    self._emit("RUN_CANCELLED", session, case_id=case.case_id)
                    break

                started = self.clock()
                idempotency_key = certification_idempotency_key(
                    session_id=session,
                    run_id=effective_run_id,
                    suite_digest=suite.digest or suite.computed_digest(),
                    case_id=case.case_id,
                )
                operation_id = idempotency_key
                evidence = [f"certify:{idempotency_key}"]
                invocation_artifact_digests: list[str] = []
                target_terminal_status: str | None = None
                release_digest = (release_digests or {}).get(case.tool_id)
                self._emit("CASE_STARTED", session, case_id=case.case_id, operation_id=operation_id)
                typed_invoker = callable(getattr(self.invoker, "invoke_certification", None))
                restricted_invoker = bool(
                    getattr(self.invoker, "restricted_evidence", False)
                )
                try:
                    invocation_context = CertificationInvocationContext(
                        run_id=effective_run_id,
                        session_id=session,
                        suite_id=suite.suite_id,
                        suite_digest=suite.digest or suite.computed_digest(),
                        case_id=case.case_id,
                        tool_id=case.tool_id,
                        target_id=suite.target_id,
                        arguments=dict(case.arguments),
                        timeout_s=case.timeout_s,
                        risk=case.risk,
                        stop_condition=case.stop_condition,
                        operation_id=operation_id,
                        idempotency_key=idempotency_key,
                        release_digest=release_digest or "",
                        compile_context_digest=compile_context_digest or "",
                        target_fingerprint=target_fingerprint or "",
                    )
                    invocation_result = self._call_invoker(invocation_context)
                    if typed_invoker:
                        if not isinstance(invocation_result, CertificationInvocationOutcome):
                            raise ValueError("CERTIFY_TYPED_OUTCOME_REQUIRED")
                        if invocation_result.restricted_evidence:
                            _validate_typed_evidence_payload(invocation_result.actual)
                        actual = invocation_result.actual
                        target_terminal_status = invocation_result.target_terminal_status
                        for evidence_id in invocation_result.evidence_ids:
                            if not isinstance(evidence_id, str) or not evidence_id or len(evidence_id) > 512:
                                raise ValueError("CERTIFY_OUTCOME_EVIDENCE_INVALID")
                            evidence.append(evidence_id)
                        for artifact_digest in invocation_result.artifact_digests:
                            if not _ARTIFACT_DIGEST_RE.fullmatch(artifact_digest):
                                raise ValueError("CERTIFY_OUTCOME_DIGEST_INVALID")
                            invocation_artifact_digests.append(artifact_digest)
                        sidecar = invocation_result.receipt_sidecar
                        if sidecar is not None:
                            validated_sidecar = self._validate_receipt_sidecar(
                                sidecar,
                                invocation_context,
                            )
                            self.receipt_sidecars.append(validated_sidecar)
                            invocation_artifact_digests.append(sidecar.digest)
                            evidence.append(f"targetd-call-receipt:sha256:{sidecar.digest}")
                    else:
                        actual = invocation_result
                    elapsed_before_finish = max(0.0, (self.clock() - started).total_seconds())
                    if elapsed_before_finish > case.timeout_s:
                        actual = {"status": "UNKNOWN", "error": "case timeout exceeded", "provider_result": actual}
                        status, failure = CaseStatus.UNKNOWN, "TIMEOUT"
                        self._stop(case, session)
                    else:
                        if target_terminal_status is not None:
                            status, failure = self._classify_target_terminal(
                                target_terminal_status,
                                case.expected,
                                actual,
                            )
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
                    actual = {
                        "status": "BLOCKED",
                        "error": (
                            "CERTIFY_TARGET_AUTHORIZATION_BLOCKED"
                            if restricted_invoker
                            else str(exc)
                        ),
                    }
                    status, failure = CaseStatus.BLOCKED, "AUTHORIZATION"
                except TimeoutError as exc:
                    actual = {
                        "status": "UNKNOWN",
                        "error": "CERTIFY_TARGET_TIMEOUT" if restricted_invoker else str(exc),
                    }
                    status, failure = CaseStatus.UNKNOWN, "TIMEOUT"
                    self._stop(case, session)
                except Exception as exc:
                    safe_error = (
                        "CERTIFY_TARGET_OUTCOME_INVALID" if restricted_invoker else str(exc)
                    )
                    actual = {"status": "FAILED", "error": safe_error}
                    error_text = safe_error.upper()
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
                        tool_id=case.tool_id,
                        expected=case.expected,
                        actual=actual,
                        status=status,
                        operation_ids=[operation_id],
                        evidence_ids=evidence,
                        artifact_digests=list(dict.fromkeys([digest, *invocation_artifact_digests])),
                        started_at=started,
                        finished_at=finished,
                        elapsed_ms=elapsed,
                        failure_class=failure,
                        release_digest=release_digest,
                        compile_context_digest=compile_context_digest,
                        target_fingerprint=target_fingerprint,
                        idempotency_key=idempotency_key,
                    )
                )
                self._emit("CASE_FINISHED", session, case_id=case.case_id, operation_id=operation_id, status=status.value)
                if fail_fast and status != CaseStatus.PASS:
                    for item in suite.cases[index + 1 :]:
                        result = self._not_run_result(
                            item,
                            session=session,
                            run_id=effective_run_id,
                            suite_digest=suite.digest or suite.computed_digest(),
                            reason="FAIL_FAST",
                            release_digest=(release_digests or {}).get(item.tool_id),
                            compile_context_digest=compile_context_digest,
                            target_fingerprint=target_fingerprint,
                        )
                        results.append(result)
                        self._emit(
                            "CASE_NOT_RUN",
                            session,
                            case_id=item.case_id,
                            operation_id=result.idempotency_key,
                            reason="FAIL_FAST",
                        )
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
            run_id=effective_run_id,
            target_id=suite.target_id,
            snapshot_digest=snapshot_digest,
            suite_digest=suite.digest or suite.computed_digest(),
            tool_id=tool_id,
            release_digest=release_digests[tool_id],
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
            "NOT_ACCEPTED",
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
        if token in {
            "BLOCKED",
            "DENIED",
            "UNAUTHORIZED",
            "AUTHORIZATION",
            "NOT_ACCEPTED",
        }:
            return CaseStatus.BLOCKED, "EXECUTION_BLOCKED"
        if token in {"UNKNOWN", "TIMEOUT", "DISCONNECTED", "UNAVAILABLE", "CANCELLED", "STOPPED"}:
            return CaseStatus.UNKNOWN, "TIMEOUT" if token == "TIMEOUT" else "EXECUTION_UNKNOWN"
        return CaseStatus.FAIL, "EXPECTED_MISMATCH"

    @staticmethod
    def _classify_target_terminal(
        terminal_status: str,
        expected: Any,
        actual: Any,
    ) -> tuple[CaseStatus, str | None]:
        """Preserve targetd terminal semantics before expected-value matching."""

        token = terminal_status.upper()
        if token == "SUCCEEDED":
            return (
                (CaseStatus.PASS, None)
                if _matches(expected, actual)
                else (CaseStatus.FAIL, "EXPECTED_MISMATCH")
            )
        if token == "NOT_ACCEPTED":
            return CaseStatus.BLOCKED, "EXECUTION_NOT_ACCEPTED"
        if token == "FAILED":
            return CaseStatus.FAIL, "TARGET_EXECUTION_FAILED"
        if token in {"UNKNOWN", "CANCELLED", "STOPPED"}:
            return CaseStatus.UNKNOWN, "TARGET_EXECUTION_UNKNOWN"
        return CaseStatus.UNKNOWN, "TARGET_RECEIPT_NOT_TERMINAL"

    def _call_invoker(self, context: CertificationInvocationContext) -> Any:
        """Call legacy providers and v2 positional/keyword key providers.

        We inspect once before invocation instead of retrying after a
        ``TypeError``; retrying a physical provider can duplicate an operation.
        """

        typed = getattr(self.invoker, "invoke_certification", None)
        if callable(typed):
            return typed(context)

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
            return self.invoker(
                context.tool_id,
                context.arguments,
                context.session_id,
                context.idempotency_key,
            )
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
            return self.invoker(
                context.tool_id,
                context.arguments,
                context.session_id,
                **{keyword_key: context.idempotency_key},
            )
        if any(parameter.kind == parameter.VAR_KEYWORD for parameter in parameters):
            return self.invoker(
                context.tool_id,
                context.arguments,
                context.session_id,
                idempotency_key=context.idempotency_key,
            )
        return self.invoker(context.tool_id, context.arguments, context.session_id)

    @staticmethod
    def _validate_receipt_sidecar(
        sidecar: CertificationReceiptSidecar,
        context: CertificationInvocationContext,
    ) -> CertificationReceiptSidecar:
        if sidecar.case_id != context.case_id or sidecar.idempotency_key != context.idempotency_key:
            raise ValueError("CERTIFY_RECEIPT_IDENTITY_MISMATCH")
        if not _ARTIFACT_DIGEST_RE.fullmatch(sidecar.digest):
            raise ValueError("CERTIFY_RECEIPT_DIGEST_INVALID")
        if not isinstance(sidecar.canonical_bytes, bytes):
            raise ValueError("CERTIFY_RECEIPT_BYTES_INVALID")
        encoded = bytes(sidecar.canonical_bytes)
        if len(encoded) > 65_536:
            raise ValueError("CERTIFY_RECEIPT_TOO_LARGE")
        try:
            payload = json.loads(encoded)
        except (UnicodeDecodeError, ValueError, TypeError):
            raise ValueError("CERTIFY_RECEIPT_PAYLOAD_INVALID") from None
        if not isinstance(payload, Mapping):
            raise ValueError("CERTIFY_RECEIPT_PAYLOAD_INVALID")
        _validate_typed_evidence_payload(payload, path="receipt_sidecar")
        if certification_receipt_sidecar_text(payload).encode("utf-8") != encoded:
            raise ValueError("CERTIFY_RECEIPT_BYTES_NOT_CANONICAL")
        if hashlib.sha256(encoded).hexdigest() != sidecar.digest:
            raise ValueError("CERTIFY_RECEIPT_DIGEST_MISMATCH")
        return CertificationReceiptSidecar(
            case_id=sidecar.case_id,
            idempotency_key=sidecar.idempotency_key,
            canonical_bytes=encoded,
            digest=sidecar.digest,
        )

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
            "run_id": self._active_run_id or session,
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
        run_id: str,
        suite_digest: str,
        reason: str,
        release_digest: str | None,
        compile_context_digest: str | None,
        target_fingerprint: str | None,
    ) -> CertificationCaseResult:
        now = self.clock()
        idempotency_key = certification_idempotency_key(
            session_id=session,
            run_id=run_id,
            suite_digest=suite_digest,
            case_id=case.case_id,
        )
        operation_id = idempotency_key
        evidence = [f"certify:{idempotency_key}"]
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
            tool_id=case.tool_id,
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
            idempotency_key=idempotency_key,
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
        tool_id = suite.cases[0].tool_id
        safe_error = (
            failure_class
            if bool(getattr(self.invoker, "restricted_evidence", False))
            else str(error)
        )
        release_digest = (release_digests or {}).get(tool_id)
        if release_digest is not None and not _RELEASE_DIGEST_RE.fullmatch(release_digest):
            release_digest = None
        if compile_context_digest is not None and not _CONTEXT_DIGEST_RE.fullmatch(compile_context_digest):
            compile_context_digest = None
        if target_fingerprint is not None and not (
            target_fingerprint == "UNKNOWN" or _TARGET_FINGERPRINT_RE.fullmatch(target_fingerprint)
        ):
            target_fingerprint = None
        self._emit("RUN_BLOCKED", session, error_code=failure_class, error=type(error).__name__)
        results = [
            CertificationCaseResult(
                case_id=case.case_id,
                tool_id=case.tool_id,
                expected=case.expected,
                actual={"status": "BLOCKED", "error": safe_error},
                status=CaseStatus.BLOCKED,
                operation_ids=[
                    certification_idempotency_key(
                        session_id=session,
                        run_id=run_id or session,
                        suite_digest=suite.digest or suite.computed_digest(),
                        case_id=case.case_id,
                    )
                ],
                evidence_ids=[
                    "certify:"
                    + certification_idempotency_key(
                        session_id=session,
                        run_id=run_id or session,
                        suite_digest=suite.digest or suite.computed_digest(),
                        case_id=case.case_id,
                    )
                ],
                artifact_digests=[
                    hashlib.sha256(
                        json.dumps(
                            {
                                "case_id": case.case_id,
                                "status": "BLOCKED",
                                "failure_class": failure_class,
                                "error": safe_error,
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
                release_digest=release_digest,
                compile_context_digest=compile_context_digest,
                target_fingerprint=target_fingerprint,
                idempotency_key=certification_idempotency_key(
                    session_id=session,
                    run_id=run_id or session,
                    suite_digest=suite.digest or suite.computed_digest(),
                    case_id=case.case_id,
                ),
            )
            for case in suite.cases
        ]
        report = CertificationReport(
            run_id=run_id or session,
            target_id=suite.target_id,
            snapshot_digest=snapshot_digest,
            suite_digest=suite.digest or suite.computed_digest(),
            tool_id=tool_id,
            release_digest=release_digest,
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
    write_index: bool = True,
    planned_json_path: Path | None = None,
) -> tuple[Path, Path]:
    if output.parent.exists() and output.parent.is_symlink():
        raise ValueError("certification report directory must not be a symlink")
    output.parent.mkdir(parents=True, exist_ok=True)
    requested_json = output if output.suffix == ".json" else output.with_suffix(".json")
    json_path = planned_json_path or _non_overwriting_path(requested_json, report.run_id)
    if (
        json_path.parent.resolve() != requested_json.parent.resolve()
        or json_path.suffix != ".json"
    ):
        raise ValueError("planned certification report path is outside the output directory")
    md_path = json_path.with_suffix(".md")
    html_path = json_path.with_suffix(".html")
    index_name = "artifact-index.json" if json_path == requested_json else f"{json_path.stem}.artifact-index.json"
    index_path = json_path.with_name(index_name)
    for artifact_path in (json_path, md_path, html_path, index_path):
        if artifact_path.is_symlink():
            raise ValueError(f"certification report artifact must not be a symlink: {artifact_path}")
    write_new_artifact(
        json_path,
        json.dumps(report.model_dump(mode="json"), ensure_ascii=False, indent=2) + "\n",
    )
    lines = [
        f"# Certification report `{report.run_id}`",
        "",
        f"- Target: `{report.target_id}`",
        f"- Conclusion: **{report.conclusion}**",
        f"- Suite digest: `{report.suite_digest}`",
        f"- Tool: `{report.tool_id}`",
        f"- Release digest: `{report.release_digest or 'UNKNOWN'}`",
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
    write_new_artifact(md_path, "\n".join(lines) + "\n")
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
    write_new_artifact(
        html_path,
        "<!doctype html><meta charset='utf-8'><title>Certification report "
        + html.escape(report.run_id)
        + "</title><h1>Certification report <code>"
        + html.escape(report.run_id)
        + "</code></h1><p>Conclusion: <strong>"
        + html.escape(report.conclusion)
        + "</strong></p><table><thead><tr><th>Case</th><th>Status</th><th>Expected</th><th>Actual</th><th>Release</th><th>Evidence</th></tr></thead><tbody>"
        + rows
        + "</tbody></table>\n",
    )
    if write_index:
        index = build_artifact_index(
            run_id=report.run_id,
            target_id=report.target_id,
            files=[json_path, md_path, html_path],
            root=json_path.parent,
            secret=signing_secret,
            previous_index=previous_index,
        )
        write_new_artifact(index_path, index.model_dump_json(indent=2) + "\n")
    return json_path, md_path


def write_new_artifact(path: Path, content: str) -> None:
    """Atomically publish one report artifact without replacing evidence."""

    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".staging", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError as exc:
            raise ValueError(f"certification report artifact already exists: {path}") from exc
    finally:
        temporary.unlink(missing_ok=True)


def select_certification_report_path(output: Path, run_id: str) -> Path:
    """Select the same non-overwriting JSON path used by :func:`write_report`."""

    requested = output if output.suffix == ".json" else output.with_suffix(".json")
    return _non_overwriting_path(requested, run_id)


def preflight_new_artifact_paths(paths: list[Path]) -> None:
    """Fail before publication when any planned artifact is unsafe or occupied."""

    if not paths:
        raise ValueError("certification artifact plan must not be empty")
    normalized = [path.absolute() for path in paths]
    if len(set(normalized)) != len(normalized):
        raise ValueError("certification artifact plan contains duplicate paths")
    parents: set[Path] = set()
    for path in paths:
        if path.is_symlink():
            raise ValueError(f"certification artifact path must not be a symlink: {path}")
        if path.exists():
            raise ValueError(f"certification artifact already exists: {path}")
        parent = path.parent
        parents.add(parent)
        for ancestor in (parent, *parent.parents):
            if ancestor.is_symlink():
                raise ValueError(
                    "certification artifact directory must not contain a symlink: "
                    f"{ancestor}"
                )
            if ancestor.exists() and not ancestor.is_dir():
                raise ValueError(
                    "certification artifact parent is not a directory: "
                    f"{ancestor}"
                )
    for parent in parents:
        parent.mkdir(parents=True, exist_ok=True)
        if parent.is_symlink() or not parent.is_dir():
            raise ValueError(
                f"certification artifact directory is unsafe: {parent}"
            )
        descriptor, probe_name = tempfile.mkstemp(
            prefix=".certify-write-probe.",
            dir=parent,
        )
        os.close(descriptor)
        Path(probe_name).unlink()


def reserve_new_artifact_paths(paths: list[Path]) -> ArtifactPlanReservation:
    """Atomically reserve a preflighted plan until its index is committed."""

    preflight_new_artifact_paths(paths)
    normalized = sorted(str(path.absolute()) for path in paths)
    plan_digest = hashlib.sha256(
        json.dumps(normalized, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    # Every report in one directory may share release-binding/index names.
    # Serialize the whole directory, rather than hashing only the complete
    # plan (two overlapping but non-identical plans must still conflict).
    reservation_path = paths[0].parent / ".certify-publication.reservation"
    token = (
        json.dumps(
            {
                "schema_version": "rolo-certify-artifact-reservation/v1",
                "plan_digest": plan_digest,
                "nonce": secrets.token_hex(16),
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("ascii")
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    try:
        descriptor = os.open(reservation_path, flags, 0o600)
    except FileExistsError as exc:
        raise ValueError("certification artifact plan is already reserved") from exc
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(token)
            handle.flush()
            os.fsync(handle.fileno())
        # Close the preflight/reservation race for cooperating publishers.
        preflight_new_artifact_paths(paths)
    except Exception:
        if (
            reservation_path.is_file()
            and not reservation_path.is_symlink()
            and reservation_path.read_bytes() == token
        ):
            reservation_path.unlink()
        raise
    return ArtifactPlanReservation(path=reservation_path, token=token)


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
        symlink = next((item for item in sidecars if item.is_symlink()), None)
        if symlink is not None:
            raise ValueError(
                f"certification report artifact must not be a symlink: {symlink}"
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


__all__ = [
    "CertificationInvocationContext",
    "CertificationInvocationOutcome",
    "CertificationReceiptSidecar",
    "ArtifactPlanReservation",
    "CertificationRunner",
    "certification_idempotency_key",
    "certification_receipt_sidecar_text",
    "load_suite",
    "preflight_new_artifact_paths",
    "reserve_new_artifact_paths",
    "select_certification_report_path",
    "validate_certification_run_inputs",
    "verify_targetd_certification_evidence",
    "write_new_artifact",
    "write_report",
]
