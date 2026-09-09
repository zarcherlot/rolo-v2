"""Offline Trace/Certify journey runners.

The product CLI deliberately keeps the hardware boundary in the registered
Tool/provider path.  These helpers provide a deterministic replay surface for
the Agent contract: a verified :class:`TargetCatalog` (or certification suite)
is consumed together with an explicit result fixture, and every run writes the
same session/report artifacts that a field adapter would produce.  A missing
fixture entry is represented as ``BLOCKED``; it is never treated as success.
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from rolo.dsl.contracts import RELEASE_BINDING_SCHEMA_VERSION

from .artifacts import build_artifact_index, write_artifact_index
from .catalog import load_target_catalog
from .certify import CertificationRunner, load_suite, write_new_artifact, write_report
from .contracts import (
    CertificationReport,
    CertificationSuite,
    RunMode,
    TargetCatalog,
    TraceCall,
    TraceSessionRequest,
)
from .trace import TraceService

FIXTURE_SCHEMA = "rolo-mvp-invocation-fixture/v1"
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")


def _is_digest(value: str) -> bool:
    return value == "UNKNOWN" or bool(_DIGEST_RE.fullmatch(value))


def _read_json(path: Path) -> Any:
    if path.is_symlink() or not path.is_file():
        raise FileNotFoundError(path)
    # Keep replay inputs bounded.  This also prevents accidentally treating an
    # arbitrary large file as a result source for a physical tool.
    if path.stat().st_size > 512 * 1024:
        raise ValueError(f"fixture exceeds 512 KiB: {path}")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON in {path}: {exc.msg}") from exc


def _fixture_digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _load_release_binding(path: Path | None) -> dict[str, Any]:
    """Load optional release identity without accepting arbitrary fields."""

    if path is None:
        return {}
    raw = _read_json(path)
    if not isinstance(raw, Mapping):
        raise ValueError("release binding must be a JSON object")
    version = raw.get("schema_version")
    if version is not None and version != RELEASE_BINDING_SCHEMA_VERSION:
        raise ValueError(f"unsupported release binding schema: {version}")
    allowed = {
        "schema_version",
        "release_digest",
        "release_digests",
        "target_fingerprint",
        "evidence_digest",
        "compile_context_digest",
        "route_digest",
        "mhs_manifest_digests",
    }
    unknown = sorted(set(raw) - allowed)
    if unknown:
        raise ValueError("release binding contains unknown fields: " + ", ".join(unknown))
    binding = dict(raw)
    release_digests = binding.get("release_digests")
    if release_digests is not None and (
        not isinstance(release_digests, Mapping)
        or any(
            not isinstance(key, str) or not key or not isinstance(value, str) or not value
            for key, value in release_digests.items()
        )
    ):
        raise ValueError("release_digests must be an object of string values")
    for key in (
        "release_digest",
        "target_fingerprint",
        "evidence_digest",
        "compile_context_digest",
        "route_digest",
    ):
        value = binding.get(key)
        if value is not None and (not isinstance(value, str) or not value):
            raise ValueError(f"release binding field {key} must be a string")
    return binding


def _normalise_result_fixture(raw: Any) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Return ordered entries and keyed results from a fixture payload.

    Two shapes are accepted so old hand-written fixtures remain useful:

    ``{"schema_version": ..., "results": [{"tool_id": ..., "result": ...}]}``
    and ``{"results": {"tool-id": {...}}}``.  A top-level list is accepted as
    the ordered form.  Values are intentionally left as JSON values; the Trace
    and Certify contracts validate the surrounding envelopes.
    """

    if isinstance(raw, list):
        source: Any = raw
    elif isinstance(raw, Mapping):
        version = raw.get("schema_version")
        if version is not None and version != FIXTURE_SCHEMA:
            raise ValueError(f"unsupported invocation fixture schema: {version}")
        source = raw.get("results")
    else:
        raise ValueError("invocation fixture must be an object or array")

    ordered: list[dict[str, Any]] = []
    keyed: dict[str, Any] = {}
    if isinstance(source, Mapping):
        for key, value in source.items():
            if not isinstance(key, str) or not key:
                raise ValueError("fixture result keys must be non-empty strings")
            # A mapping value is the result itself.  A wrapper is also allowed
            # for callers that want to retain a tool_id/case_id label.
            if isinstance(value, Mapping) and "result" in value:
                result = value.get("result")
                entry = dict(value)
                entry.setdefault("tool_id", key)
                entry["result"] = result
            else:
                result = value
                entry = {"tool_id": key, "result": result}
            keyed[key] = result
            for alias in (entry.get("tool_id"), entry.get("case_id"), entry.get("operation_id")):
                if isinstance(alias, str) and alias:
                    keyed.setdefault(alias, result)
            ordered.append(entry)
    elif isinstance(source, list):
        for item in source:
            if not isinstance(item, Mapping):
                raise ValueError("ordered fixture entries must be objects")
            if "result" not in item:
                raise ValueError("ordered fixture entry requires result")
            entry = dict(item)
            ordered.append(entry)
            for key in ("tool_id", "case_id", "operation_id"):
                value = entry.get(key)
                if isinstance(value, str) and value:
                    keyed.setdefault(value, entry["result"])
    else:
        raise ValueError("fixture requires a results object or array")
    return ordered, keyed


class FixtureInvoker:
    """Deterministic invoker used only by the offline CLI surface."""

    def __init__(self, ordered: Sequence[Mapping[str, Any]], keyed: Mapping[str, Any]) -> None:
        self._ordered = [dict(item) for item in ordered]
        self._keyed = dict(keyed)
        self._position = 0

    def __call__(self, tool_id: str, arguments: Mapping[str, Any], session_id: str) -> Any:
        del arguments, session_id
        # Prefer an ordered entry when it declares a matching tool.  This
        # permits repeated calls to the same tool to have distinct outcomes.
        if self._position < len(self._ordered):
            entry = self._ordered[self._position]
            declared = entry.get("tool_id")
            if declared is None or declared == tool_id:
                self._position += 1
                return entry.get("result")
        if tool_id in self._keyed:
            return self._keyed[tool_id]
        return {"status": "BLOCKED", "error": "INVOCATION_FIXTURE_MISSING", "tool_id": tool_id}


class _CaseFixtureInvoker:
    """Map one ordered fixture result to each CertificationCase."""

    def __init__(self, suite: CertificationSuite, ordered: Sequence[Mapping[str, Any]], keyed: Mapping[str, Any]) -> None:
        self.suite = suite
        self.ordered = [dict(item) for item in ordered]
        self.keyed = dict(keyed)
        self.position = 0

    def __call__(self, tool_id: str, arguments: Mapping[str, Any], session_id: str) -> Any:
        del arguments, session_id
        case = self.suite.cases[self.position] if self.position < len(self.suite.cases) else None
        if case is not None and case.tool_id != tool_id:
            raise PermissionError(f"BLOCKED: FIXTURE_TOOL_MISMATCH: {tool_id}")
        if case is not None:
            self.position += 1
            # Case id has priority, then tool id.  This allows a ten-case suite
            # to exercise one tool with ten distinct expected outcomes.
            if case.case_id in self.keyed:
                return self.keyed[case.case_id]
        if self.position <= len(self.ordered):
            index = self.position - 1
            if index >= 0 and index < len(self.ordered):
                entry = self.ordered[index]
                declared = entry.get("case_id") or entry.get("tool_id")
                if declared is None or declared == getattr(case, "case_id", None) or declared == tool_id:
                    return entry.get("result")
        if tool_id in self.keyed:
            return self.keyed[tool_id]
        raise PermissionError(
            f"BLOCKED: INVOCATION_FIXTURE_MISSING: {getattr(case, 'case_id', None) or tool_id}"
        )


def _safe_output_root(path: Path) -> Path:
    if path.exists() and path.is_symlink():
        raise ValueError(f"output path must not be a symlink: {path}")
    path.mkdir(parents=True, exist_ok=True)
    if not path.is_dir():
        raise ValueError(f"output path is not a directory: {path}")
    return path.resolve()


def _write_trace_request(
    directory: Path,
    *,
    request: TraceSessionRequest,
    calls: Sequence[TraceCall],
    fixture_digest: str,
    execution_mode: str = "OFFLINE_FIXTURE",
) -> Path:
    path = directory / "trace-request.json"
    if path.is_symlink():
        raise ValueError(f"trace request artifact must not be a symlink: {path}")
    payload = {
        "schema_version": "rolo-mvp-trace-request-record/v1",
        "execution_mode": execution_mode,
        "fixture_only": True,
        "fixture_digest": fixture_digest,
        "request": request.model_dump(mode="json"),
        "calls": [item.model_dump(mode="json") for item in calls],
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    path.write_text(json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return path


def _reindex(
    directory: Path,
    *,
    run_id: str,
    target_id: str,
    files: Sequence[Path],
    exclusive: bool = False,
) -> Path:
    index_path = directory / "artifact-index.json"
    if index_path.is_symlink():
        raise ValueError(f"artifact index must not be a symlink: {index_path}")
    unique = []
    seen: set[Path] = set()
    for path in files:
        if path.is_symlink():
            raise ValueError(f"artifact must not be a symlink: {path}")
        resolved = path.resolve()
        if resolved == index_path.resolve() or resolved in seen or not path.is_file():
            continue
        seen.add(resolved)
        unique.append(path)
    index = build_artifact_index(run_id=run_id, target_id=target_id, files=unique, root=directory)
    if exclusive:
        write_new_artifact(index_path, index.model_dump_json(indent=2) + "\n")
    else:
        write_artifact_index(index_path, index)
    return index_path


def run_trace(
    *,
    catalog_path: Path,
    calls_path: Path,
    result_fixture: Path,
    task: str,
    output: Path,
    mode: RunMode = RunMode.OBSERVATION_ONLY,
    safety_confirmed: bool = False,
    ttl_s: float = 900,
    max_calls: int = 32,
    operator_id: str | None = None,
    target_id: str | None = None,
    release_binding_path: Path | None = None,
) -> dict[str, Any]:
    """Run a replayable Trace session from explicit catalog/call artifacts."""

    catalog = load_target_catalog(catalog_path)
    if not catalog.digest or catalog.digest != catalog.computed_digest():
        raise ValueError("TRACE_BLOCKED: catalog digest is required")
    if not _is_digest(catalog.target_fingerprint) or not _is_digest(catalog.snapshot_digest):
        raise ValueError("TRACE_BLOCKED: catalog identity digest is invalid")
    if target_id is not None and target_id != catalog.target_id:
        raise ValueError("TRACE_BLOCKED: requested target does not match catalog")
    if mode == RunMode.SUPERVISED_FIELD_DEBUG:
        raise ValueError("TRACE_BLOCKED: offline fixture runner cannot execute supervised field mode")
    binding = _load_release_binding(release_binding_path)
    bound_target = binding.get("target_fingerprint")
    if bound_target and bound_target != "UNKNOWN" and not _is_digest(str(bound_target)):
        raise ValueError("TRACE_BLOCKED: release binding target fingerprint is invalid")
    if bound_target and bound_target != "UNKNOWN" and catalog.target_fingerprint != bound_target:
        raise ValueError("TRACE_BLOCKED: release binding target fingerprint differs from catalog")
    if catalog.target_fingerprint == "UNKNOWN" and bound_target not in (None, "UNKNOWN"):
        raise ValueError("TRACE_BLOCKED: catalog target fingerprint is unknown")
    raw_calls = _read_json(calls_path)
    if isinstance(raw_calls, Mapping):
        raw_calls = raw_calls.get("calls")
    if not isinstance(raw_calls, list):
        raise ValueError("trace calls must be a JSON array or an object with calls")
    calls = [TraceCall.model_validate(item) for item in raw_calls]
    if not calls:
        raise ValueError("trace requires at least one call")
    fixture_raw = _read_json(result_fixture)
    ordered, keyed = _normalise_result_fixture(fixture_raw)
    invoker = FixtureInvoker(ordered, keyed)
    request = TraceSessionRequest(
        target_id=catalog.target_id,
        catalog_digest=catalog.digest,
        task=task,
        mode=mode,
        ttl_s=ttl_s,
        max_calls=max_calls,
        operator_id=operator_id,
        safety_confirmed=safety_confirmed,
        release_digest=binding.get("release_digest"),
        compile_context_digest=binding.get("compile_context_digest"),
        target_fingerprint=bound_target,
    )
    output_root = _safe_output_root(output)
    service = TraceService(catalog, invoker, artifact_root=output_root)
    session = service.create_session(request)
    error: str | None = None
    try:
        session = service.execute(session.session_id, calls)
    except (KeyError, ValueError) as exc:
        error = str(exc)
    paths = service.persist_session(session.session_id, output_root)
    directory = Path(paths["session"]).parent
    request_path = _write_trace_request(directory, request=request, calls=calls, fixture_digest=_fixture_digest(result_fixture))
    event_path = directory / "trace-events.jsonl"
    index_path = _reindex(
        directory,
        run_id=session.session_id,
        target_id=session.target_id,
        files=[*paths.values(), request_path, event_path],
    )
    payload: dict[str, Any] = {
        "schema_version": "rolo-mvp-trace-run/v1",
        "status": session.state.value,
        "run_id": session.session_id,
        "target_id": session.target_id,
        "catalog_digest": session.catalog_digest,
        "mode": session.mode.value,
        "fixture_only": True,
        "release_digest": session.release_digest,
        "compile_context_digest": session.compile_context_digest,
        "target_fingerprint": session.target_fingerprint,
        "artifact_paths": {"session": str(paths["session"]), "evidence": str(paths["evidence"]), "request": str(request_path), "index": str(index_path)},
        "artifact_index": str(index_path),
    }
    if error:
        payload["error"] = error
    return payload


def _validate_catalog_for_suite(catalog: TargetCatalog, suite: CertificationSuite) -> None:
    if not catalog.digest or catalog.digest != catalog.computed_digest():
        raise ValueError("CERTIFY_BLOCKED: catalog digest is missing or does not match content")
    if not _is_digest(catalog.snapshot_digest) or not _is_digest(catalog.target_fingerprint):
        raise ValueError("CERTIFY_BLOCKED: catalog identity digest is invalid")
    if catalog.target_id != suite.target_id:
        raise ValueError("CERTIFY_BLOCKED: catalog and suite target differ")
    if catalog.freshness != "fresh":
        raise ValueError("CERTIFY_BLOCKED: catalog is stale or unknown")
    callable_tools = {item.tool_id for item in catalog.tools if item.agent_callable and item.state.value == "CALLABLE"}
    missing = sorted({case.tool_id for case in suite.cases} - callable_tools)
    if missing:
        raise ValueError("CERTIFY_BLOCKED: tools are not callable in catalog: " + ", ".join(missing))


def run_certify(
    *,
    suite_path: Path,
    result_fixture: Path,
    output: Path,
    catalog_path: Path | None = None,
    snapshot_digest: str = "UNKNOWN",
    target_id: str | None = None,
    require_ten_cases: bool = True,
    run_id: str | None = None,
    release_binding_path: Path | None = None,
    fail_fast: bool = False,
) -> dict[str, Any]:
    """Run a fixed certification suite against explicit replay results."""

    suite = load_suite(suite_path, target_id=target_id, require_ten_cases=require_ten_cases)
    binding = _load_release_binding(release_binding_path)
    release_digests = binding.get("release_digests")
    if release_digests is None and binding.get("release_digest") is not None:
        release_digests = {suite.cases[0].tool_id: binding["release_digest"]}
    if not isinstance(release_digests, Mapping) or set(release_digests) != {suite.cases[0].tool_id}:
        raise ValueError("CERTIFY_BLOCKED: release binding must contain exactly the suite tool")
    release_digest = release_digests[suite.cases[0].tool_id]
    if not isinstance(release_digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", release_digest):
        raise ValueError("CERTIFY_BLOCKED: release digest is invalid")
    compile_context_digest = binding.get("compile_context_digest")
    if not isinstance(compile_context_digest, str) or not re.fullmatch(
        r"sha256:[0-9a-f]{64}", compile_context_digest
    ):
        raise ValueError("CERTIFY_BLOCKED: compile context digest is required")
    bound_fingerprint = binding.get("target_fingerprint")
    if not isinstance(bound_fingerprint, str) or not re.fullmatch(r"[0-9a-f]{64}", bound_fingerprint):
        raise ValueError("CERTIFY_BLOCKED: target fingerprint is required")
    catalog = load_target_catalog(catalog_path) if catalog_path is not None else None
    effective_snapshot = snapshot_digest
    effective_target_fingerprint = bound_fingerprint
    if not _is_digest(snapshot_digest):
        raise ValueError("CERTIFY_BLOCKED: snapshot digest is invalid")
    if effective_target_fingerprint not in (None, "UNKNOWN") and not _is_digest(str(effective_target_fingerprint)):
        raise ValueError("CERTIFY_BLOCKED: target fingerprint is invalid")
    if catalog is not None:
        _validate_catalog_for_suite(catalog, suite)
        if (
            snapshot_digest != "UNKNOWN"
            and catalog.snapshot_digest != "UNKNOWN"
            and snapshot_digest != catalog.snapshot_digest
        ):
            raise ValueError("CERTIFY_BLOCKED: snapshot digest differs from catalog")
        if snapshot_digest == "UNKNOWN" and catalog.snapshot_digest != "UNKNOWN":
            effective_snapshot = catalog.snapshot_digest
        if catalog.snapshot_digest == "UNKNOWN" and snapshot_digest != "UNKNOWN":
            raise ValueError("CERTIFY_BLOCKED: catalog snapshot digest is unknown")
        bound_target = binding.get("target_fingerprint")
        if bound_target and bound_target != "UNKNOWN" and catalog.target_fingerprint not in {"UNKNOWN", bound_target}:
            raise ValueError("CERTIFY_BLOCKED: release binding target fingerprint differs from catalog")
        if effective_target_fingerprint in (None, "UNKNOWN") and catalog.target_fingerprint != "UNKNOWN":
            effective_target_fingerprint = catalog.target_fingerprint
        if catalog.target_fingerprint == "UNKNOWN" and effective_target_fingerprint not in (None, "UNKNOWN"):
            raise ValueError("CERTIFY_BLOCKED: catalog target fingerprint is unknown")
    if (
        effective_target_fingerprint not in (None, "UNKNOWN")
        and catalog is not None
        and catalog.target_fingerprint != "UNKNOWN"
        and effective_target_fingerprint != catalog.target_fingerprint
    ):
        raise ValueError("CERTIFY_BLOCKED: target fingerprint differs from catalog")
    fixture_raw = _read_json(result_fixture)
    ordered, keyed = _normalise_result_fixture(fixture_raw)
    invoker = _CaseFixtureInvoker(suite, ordered, keyed)
    runner = CertificationRunner(invoker, target_id=suite.target_id)
    effective_run_id = run_id or f"certify-{secrets.token_urlsafe(10)}"
    report: CertificationReport = runner.run(
        suite,
        snapshot_digest=effective_snapshot,
        run_id=effective_run_id,
        session_id=effective_run_id,
        compile_context_digest=compile_context_digest,
        target_fingerprint=effective_target_fingerprint or (catalog.target_fingerprint if catalog else None),
        release_digests=dict(release_digests),
        fail_fast=fail_fast,
    )
    replay_conclusion = report.conclusion
    report_payload = report.model_dump(mode="json")
    report_payload["limitations"] = list(dict.fromkeys([*report.limitations, "FIXTURE_ONLY_SIMULATION"]))
    # A caller-supplied result fixture can demonstrate deterministic replay,
    # but it cannot prove that a current PUBLISHED Release ran on a target.
    # Keep every per-case outcome while preventing the persisted report from
    # being consumed as a formal PASS.
    if replay_conclusion == "PASS":
        report_payload["conclusion"] = "CONDITIONAL"
    report = CertificationReport.model_validate(report_payload)
    json_output = output if output.suffix == ".json" else output.with_suffix(".json")
    if json_output.exists() and json_output.is_symlink():
        raise ValueError(f"report path must not be a symlink: {json_output}")
    _safe_output_root(json_output.parent)
    json_path, md_path = write_report(report, json_output, write_index=False)
    requested_name = json_output.name
    suffix_name = json_path.name != requested_name
    request_name = "certify-request.json" if not suffix_name else f"{json_path.stem}.certify-request.json"
    suite_name = "certify-test-suite.json" if not suffix_name else f"{json_path.stem}.certify-test-suite.json"
    event_name = "certify-events.jsonl" if not suffix_name else f"{json_path.stem}.certify-events.jsonl"
    request_path = json_path.parent / request_name
    suite_artifact = json_path.parent / suite_name
    event_path = json_path.parent / event_name
    for artifact_path in (request_path, suite_artifact, event_path):
        if artifact_path.is_symlink():
            raise ValueError(f"certification artifact path must not be a symlink: {artifact_path}")
    write_new_artifact(
        suite_artifact,
        json.dumps(suite.model_dump(mode="json"), ensure_ascii=False, sort_keys=True, indent=2) + "\n",
    )
    write_new_artifact(
        event_path,
        "".join(json.dumps(item, ensure_ascii=False, sort_keys=True) + "\n" for item in runner.events),
    )
    write_new_artifact(
        request_path,
        json.dumps(
            {
                "schema_version": "rolo-mvp-certify-request-record/v1",
                "execution_mode": "OFFLINE_FIXTURE",
                "fixture_only": True,
                "fixture_digest": _fixture_digest(result_fixture),
                "suite_path": str(suite_path.resolve()),
                "suite_digest": suite.digest,
                "catalog_path": str(catalog_path.resolve()) if catalog_path else None,
                 "snapshot_digest": effective_snapshot,
                "release_binding": binding or None,
                "failure_policy": "fail_fast" if fail_fast else "continue",
                "created_at": datetime.now(timezone.utc).isoformat(),
            },
            ensure_ascii=False,
            sort_keys=True,
            indent=2,
        )
        + "\n",
    )
    indexed_files: list[Path] = [
        json_path,
        md_path,
        request_path,
        suite_artifact,
        event_path,
        json_path.with_suffix(".html"),
    ]
    index_path = _reindex(
        json_path.parent,
        run_id=report.run_id,
        target_id=report.target_id,
        files=indexed_files,
        exclusive=True,
    )
    return {
        "schema_version": "rolo-mvp-certify-run/v1",
        "status": "SIMULATED_PASS" if replay_conclusion == "PASS" else report.conclusion,
        "execution_mode": "OFFLINE_FIXTURE",
        "run_id": report.run_id,
        "target_id": report.target_id,
        "suite_digest": report.suite_digest,
        "tool_id": report.tool_id,
        "release_digest": report.release_digest,
        "fixture_only": True,
        "compile_context_digest": report.compile_context_digest,
        "target_fingerprint": report.target_fingerprint,
        "case_count": len(report.results),
        "artifact_paths": {
            "report": str(json_path),
            "markdown": str(md_path),
            "html": str(json_path.with_suffix(".html")),
            "suite": str(suite_artifact),
            "events": str(event_path),
            "request": str(request_path),
            "index": str(index_path),
        },
        "artifact_index": str(index_path),
        "report": report.model_dump(mode="json"),
    }


__all__ = ["FIXTURE_SCHEMA", "FixtureInvoker", "run_certify", "run_trace"]
