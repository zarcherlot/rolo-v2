"""Read-only verification and replay of Bootstrap Probe artifacts.

The verifier consumes only the artifacts produced by run_bootstrap_projection.
It never contacts a target, executes a probe, or rewrites an artifact. A
successful report means that the persisted Context and Candidate Index can be
reconstructed from the same digest-bound inputs, not that the target is
currently reachable.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Literal

from pydantic import Field

from .bootstrap import BootstrapDiscoveryResult
from .candidates import CapabilityCandidateIndex, build_candidate_index
from .canonical import context_digest
from .context import ProbeContext
from .models import StrictModel


class BootstrapReplayReport(StrictModel):
    """Stable result returned by verify_bootstrap_artifacts."""

    schema_version: Literal["rolo-bootstrap-replay-report/v1"] = "rolo-bootstrap-replay-report/v1"
    status: Literal["PASS", "BLOCKED"]
    discovery_session_id: str | None = None
    robot_id: str | None = None
    target_fingerprint: str | None = None
    diagnostics: tuple[str, ...] = Field(default_factory=tuple, max_length=64)
    verified_artifacts: tuple[str, ...] = Field(default_factory=tuple, max_length=32)


def verify_bootstrap_artifacts(
    root: str | Path,
    *,
    expected_robot_id: str | None = None,
    expected_target_fingerprint: str | None = None,
) -> BootstrapReplayReport:
    """Verify a persisted Bootstrap projection without mutating it.

    root is the directory containing bootstrap-result.json. All artifact
    references must be local to that directory; absolute paths and traversal
    references are rejected before any file is opened.
    """

    root_path = Path(root).resolve()
    diagnostics: list[str] = []
    verified: list[str] = []
    manifest_path = root_path / "bootstrap-result.json"
    manifest_payload = _read_json(manifest_path, diagnostics, "BOOTSTRAP_MANIFEST")
    if manifest_payload is None:
        return _report(diagnostics, verified)
    try:
        manifest = BootstrapDiscoveryResult.model_validate(manifest_payload)
    except Exception:
        diagnostics.append("BOOTSTRAP_MANIFEST_INVALID")
        return _report(diagnostics, verified)
    if manifest.status != "READY":
        diagnostics.append("BOOTSTRAP_NOT_READY")
    if expected_robot_id is not None and manifest.robot_id != expected_robot_id:
        diagnostics.append("BOOTSTRAP_ROBOT_MISMATCH")
    if expected_target_fingerprint is not None and manifest.target_fingerprint != expected_target_fingerprint:
        diagnostics.append("BOOTSTRAP_TARGET_MISMATCH")
    if manifest.manifest_ref != _ref_for(root_path, manifest_path):
        diagnostics.append("BOOTSTRAP_MANIFEST_REF_MISMATCH")
    else:
        verified.append("bootstrap-result.json")

    context_path = _resolve_ref(root_path, manifest.compile_context_ref, diagnostics, "COMPILE_CONTEXT_REF")
    context_index_path = _resolve_ref(root_path, manifest.compile_context_index_ref, diagnostics, "COMPILE_CONTEXT_INDEX_REF")
    candidate_path = _resolve_ref(root_path, manifest.candidate_index_ref, diagnostics, "CANDIDATE_INDEX_REF")
    if context_path is None or context_index_path is None or candidate_path is None:
        return _report(diagnostics, verified, manifest)

    context_payload = _read_json(context_path, diagnostics, "COMPILE_CONTEXT")
    index_payload = _read_json(context_index_path, diagnostics, "COMPILE_CONTEXT_INDEX")
    candidate_payload = _read_json(candidate_path, diagnostics, "CANDIDATE_INDEX")
    if context_payload is None or index_payload is None or candidate_payload is None:
        return _report(diagnostics, verified, manifest)

    try:
        context = ProbeContext.model_validate(context_payload)
    except Exception:
        diagnostics.append("COMPILE_CONTEXT_INVALID")
        context = None
    try:
        candidate_index = CapabilityCandidateIndex.model_validate(candidate_payload)
    except Exception:
        diagnostics.append("CANDIDATE_INDEX_INVALID")
        candidate_index = None

    if context is not None:
        actual_context_digest = context_digest(context)
        if manifest.compile_context_digest != actual_context_digest:
            diagnostics.append("COMPILE_CONTEXT_DIGEST_MISMATCH")
        if context.robot_id != manifest.robot_id:
            diagnostics.append("COMPILE_CONTEXT_ROBOT_MISMATCH")
        if context.target_fingerprint != manifest.target_fingerprint:
            diagnostics.append("COMPILE_CONTEXT_TARGET_MISMATCH")
        if context.evidence_digest != manifest.evidence_digest:
            diagnostics.append("COMPILE_CONTEXT_EVIDENCE_MISMATCH")
        if _verify_context_index(index_payload, context_path, actual_context_digest):
            verified.extend(("compile-context.json", "artifact-index.json"))
        else:
            diagnostics.append("COMPILE_CONTEXT_INDEX_MISMATCH")

    if candidate_index is not None:
        try:
            candidate_index.verify()
        except ValueError:
            diagnostics.append("CANDIDATE_INDEX_DIGEST_MISMATCH")
        if manifest.candidate_index_digest != candidate_index.index_digest:
            diagnostics.append("CANDIDATE_INDEX_MANIFEST_DIGEST_MISMATCH")
        if candidate_index.robot_id != manifest.robot_id:
            diagnostics.append("CANDIDATE_INDEX_ROBOT_MISMATCH")
        if candidate_index.target_fingerprint != manifest.target_fingerprint:
            diagnostics.append("CANDIDATE_INDEX_TARGET_MISMATCH")
        if candidate_index.evidence_digest != manifest.evidence_digest:
            diagnostics.append("CANDIDATE_INDEX_EVIDENCE_MISMATCH")
        if candidate_index.context_digest != manifest.compile_context_digest:
            diagnostics.append("CANDIDATE_INDEX_CONTEXT_MISMATCH")
        if context is not None:
            rebuilt = build_candidate_index(context)
            if candidate_index.model_dump(mode="json") != rebuilt.model_dump(mode="json"):
                diagnostics.append("CANDIDATE_INDEX_REPLAY_MISMATCH")
            else:
                verified.append("candidate-index.json")

    return _report(diagnostics, verified, manifest)


def replay_bootstrap_artifacts(
    root: str | Path,
    *,
    expected_robot_id: str | None = None,
    expected_target_fingerprint: str | None = None,
) -> BootstrapReplayReport:
    """Descriptive alias for verify_bootstrap_artifacts."""

    return verify_bootstrap_artifacts(
        root,
        expected_robot_id=expected_robot_id,
        expected_target_fingerprint=expected_target_fingerprint,
    )


def _read_json(path: Path, diagnostics: list[str], label: str) -> dict[str, Any] | None:
    try:
        if not path.is_file():
            diagnostics.append(f"{label}_MISSING")
            return None
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        diagnostics.append(f"{label}_UNREADABLE")
        return None
    if not isinstance(value, dict):
        diagnostics.append(f"{label}_INVALID")
        return None
    return value


def _resolve_ref(root: Path, reference: str | None, diagnostics: list[str], label: str) -> Path | None:
    if not isinstance(reference, str) or not reference.startswith("artifact://"):
        diagnostics.append(f"{label}_INVALID")
        return None
    relative = reference.removeprefix("artifact://")
    if not relative or Path(relative).is_absolute():
        diagnostics.append(f"{label}_INVALID")
        return None
    candidate = (root / relative).resolve()
    if not candidate.is_relative_to(root):
        diagnostics.append(f"{label}_OUTSIDE_ROOT")
        return None
    if not candidate.is_file():
        diagnostics.append(f"{label}_MISSING")
        return None
    return candidate


def _ref_for(root: Path, path: Path) -> str:
    return "artifact://" + path.resolve().relative_to(root).as_posix()


def _verify_context_index(index_payload: dict[str, Any], context_path: Path, expected_digest: str) -> bool:
    if index_payload.get("schema_version") != "rolo-compile-context-artifact-index/v1":
        return False
    if index_payload.get("context_digest") != expected_digest:
        return False
    artifacts = index_payload.get("artifacts")
    if not isinstance(artifacts, list):
        return False
    entry = next((item for item in artifacts if isinstance(item, dict) and item.get("path") == "compile-context.json"), None)
    if not isinstance(entry, dict) or not isinstance(entry.get("sha256"), str):
        return False
    encoded = context_path.read_text(encoding="utf-8")
    if encoded.endswith("\n"):
        encoded = encoded[:-1]
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest() == entry["sha256"]


def _report(
    diagnostics: list[str],
    verified: list[str],
    manifest: BootstrapDiscoveryResult | None = None,
) -> BootstrapReplayReport:
    unique_diagnostics = tuple(dict.fromkeys(diagnostics))
    return BootstrapReplayReport(
        status="PASS" if not unique_diagnostics else "BLOCKED",
        discovery_session_id=manifest.discovery_session_id if manifest else None,
        robot_id=manifest.robot_id if manifest else None,
        target_fingerprint=manifest.target_fingerprint if manifest else None,
        diagnostics=unique_diagnostics,
        verified_artifacts=tuple(dict.fromkeys(verified)),
    )


__all__ = ["BootstrapReplayReport", "replay_bootstrap_artifacts", "verify_bootstrap_artifacts"]
