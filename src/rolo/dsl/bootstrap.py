"""Idempotent, read-only Bootstrap Probe artifact orchestration.

The target evidence collector remains responsible for talking to a target.
This module starts only after that evidence has been verified and projects the
single verified bundle into the Compile Context, Candidate Index, and a small
discovery-session manifest that a UI or Agent can follow without guessing
paths or recomputing digests.
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from pydantic import Field

from .candidates import build_candidate_index, persist_candidate_index
from .context_adapter import build_probe_context, persist_compile_context
from .models import StrictModel


class BootstrapProbeProfile(StrictModel):
    """The bounded read-only profile used for the first target probe."""

    schema_version: Literal["rolo-bootstrap-probe-profile/v1"] = "rolo-bootstrap-probe-profile/v1"
    profile_id: str = Field(min_length=1, max_length=128)
    robot_id: str = Field(min_length=1, max_length=128)
    active_probe: Literal["runtime-readonly"] = "runtime-readonly"
    requested_layers: tuple[str, ...] = Field(default=("identity", "os", "middleware", "application"), max_length=16)


class BootstrapDiscoveryResult(StrictModel):
    """Digest-linked output of one verified Bootstrap Probe projection."""

    schema_version: Literal["rolo-bootstrap-discovery-result/v1"] = "rolo-bootstrap-discovery-result/v1"
    status: Literal["READY", "BLOCKED"]
    discovery_session_id: str = Field(min_length=1, max_length=256)
    profile_id: str = Field(min_length=1, max_length=128)
    robot_id: str = Field(min_length=1, max_length=128)
    target_fingerprint: str = Field(min_length=1)
    evidence_digest: str = Field(min_length=1)
    compile_context_digest: str | None = None
    candidate_index_digest: str | None = None
    compile_context_ref: str | None = None
    compile_context_index_ref: str | None = None
    candidate_index_ref: str | None = None
    manifest_ref: str | None = None
    limitations: tuple[str, ...] = ()
    observed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


def run_bootstrap_projection(
    bundle: object,
    artifact_root: str | Path,
    *,
    profile: BootstrapProbeProfile,
    evidence_verified: bool,
) -> tuple[BootstrapDiscoveryResult, dict[str, Path]]:
    """Project one verified evidence bundle into stable Bootstrap artifacts.

    ``evidence_verified`` is deliberately explicit: this function must not be
    used as a shortcut around the target-evidence signature/deployment checks.
    Re-running it with the same profile and evidence digest replaces files via
    ``os.replace`` and produces the same session id and content digests.
    """

    if not evidence_verified:
        raise ValueError("BOOTSTRAP_REQUIRES_VERIFIED_EVIDENCE")
    from rolo.stages.probe.target_evidence import TargetEvidenceBundle

    evidence = bundle if isinstance(bundle, TargetEvidenceBundle) else TargetEvidenceBundle.model_validate(bundle)
    if evidence.robot_id != profile.robot_id:
        raise ValueError("BOOTSTRAP_PROFILE_TARGET_MISMATCH")

    context = build_probe_context(evidence)
    candidate_index = build_candidate_index(context)
    session_material = f"{profile.profile_id}:{evidence.robot_id}:{evidence.payload_sha256}".encode()
    session_id = "bootstrap-" + hashlib.sha256(session_material).hexdigest()[:32]
    root = Path(artifact_root) / "bootstrap" / evidence.robot_id / session_id
    root.mkdir(parents=True, exist_ok=True)
    context_paths = persist_compile_context(context, root / "context")
    candidate_path = persist_candidate_index(candidate_index, root / "candidates")
    context_digest_value = context_digest(context)

    manifest_payload = {
        "schema_version": "rolo-bootstrap-discovery-result/v1",
        "status": "READY",
        "discovery_session_id": session_id,
        "profile_id": profile.profile_id,
        "robot_id": evidence.robot_id,
        "target_fingerprint": evidence.target_host_fingerprint,
        "evidence_digest": evidence.payload_sha256,
        "compile_context_digest": context_digest_value,
        "candidate_index_digest": candidate_index.index_digest,
        "limitations": list(context.limitations),
        "observed_at": evidence.collected_at.isoformat(),
    }
    manifest_path = root / "bootstrap-result.json"
    _atomic_json(manifest_path, manifest_payload)
    result = BootstrapDiscoveryResult(
        **manifest_payload,
        compile_context_ref=_artifact_ref(root, context_paths["context"]),
        compile_context_index_ref=_artifact_ref(root, context_paths["index"]),
        candidate_index_ref=_artifact_ref(root, candidate_path),
        manifest_ref=_artifact_ref(root, manifest_path),
    )
    # Persist the enriched result as the canonical manifest so the returned
    # references and the on-disk artifact cannot diverge.
    _atomic_json(manifest_path, result.model_dump(mode="json"))
    paths = {
        "manifest": manifest_path,
        "context": context_paths["context"],
        "context_index": context_paths["index"],
        "candidates": candidate_path,
    }
    return result, paths


def context_digest(context: object) -> str:
    """Import lazily to keep this module's public surface small."""

    from .canonical import context_digest as calculate

    return calculate(context)


def _artifact_ref(root: Path, path: Path) -> str:
    return "artifact://" + path.relative_to(root).as_posix()


def _atomic_json(path: Path, payload: dict) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, path)


__all__ = ["BootstrapDiscoveryResult", "BootstrapProbeProfile", "run_bootstrap_projection"]
