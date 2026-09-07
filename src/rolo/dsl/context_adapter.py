"""Project Probe evidence into the versioned DSL compile context.

The adapter is deliberately read-only: it only copies evidence that was
actually observed by Probe and leaves unknown fields intact for diagnostics.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from collections.abc import Mapping
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from rolo.stages.probe.target_evidence import TargetEvidenceBundle

from .canonical import context_digest
from .context import ProbeContext


def _records(value: Any) -> tuple[dict[str, Any], ...]:
    if isinstance(value, Mapping):
        nested = next((value[key] for key in ("records", "items", "tools") if isinstance(value.get(key), (list, tuple))), None)
        if nested is not None:
            value = nested
        elif any(key in value for key in ("resource_id", "schema_id", "tool_id", "operation")):
            return (dict(value),)
    if not isinstance(value, (list, tuple)):
        return ()
    records = [dict(item) for item in value if isinstance(item, Mapping)]
    return tuple(sorted(records, key=lambda item: json.dumps(item, sort_keys=True, separators=(",", ":"))))


def build_probe_context(bundle: TargetEvidenceBundle | Mapping[str, Any]) -> ProbeContext:
    """Build a canonical :class:`ProbeContext` from a verified evidence bundle.

    Only route and message schema records present in probe data are projected;
    the complete probe payload remains available through ``evidence_refs`` and
    the evidence digest, so an adapter cannot invent observed capabilities.
    """
    from rolo.stages.probe.target_evidence import TargetEvidenceBundle

    evidence = bundle if isinstance(bundle, TargetEvidenceBundle) else TargetEvidenceBundle.model_validate(bundle)
    routes: list[dict[str, Any]] = []
    schemas: list[dict[str, Any]] = []
    published_tools: list[dict[str, Any]] = []
    mhs_refs: list[str] = []
    mhs_digests: list[str] = []
    runtime_revisions: list[str] = []
    limitations: set[str] = set()
    for probe in evidence.probes.values():
        payload = probe.data
        routes.extend(_records(payload.get("routes")))
        routes.extend(_records(payload.get("route_evidence")))
        schemas.extend(_records(payload.get("message_schemas")))
        published_tools.extend(_records(payload.get("published_tools")))
        published_tools.extend(_records(payload.get("tool_catalog")))
        revision = payload.get("runtime_revision") or payload.get("runtime_version")
        if isinstance(revision, str) and revision:
            runtime_revisions.append(revision)
        mhs = payload.get("mhs_manifest") or payload.get("mhs_manifest_ref")
        if isinstance(mhs, Mapping):
            ref = mhs.get("ref") or mhs.get("artifact_ref") or mhs.get("manifest_ref")
            digest = mhs.get("digest") or mhs.get("sha256") or mhs.get("manifest_digest")
            if isinstance(ref, str):
                mhs_refs.append(ref)
            if isinstance(digest, str):
                mhs_digests.append(digest)
        elif isinstance(mhs, str):
            mhs_refs.append(mhs)
        limitations.update(probe.warnings)
        limitations.update(probe.errors)
    snapshot = evidence.source_snapshot
    if isinstance(snapshot, Mapping):
        revision = snapshot.get("runtime_revision") or snapshot.get("runtime_version")
        if isinstance(revision, str) and revision:
            runtime_revisions.append(revision)
        published_tools.extend(_records(snapshot.get("published_tools")))
        published_tools.extend(_records(snapshot.get("tool_catalog")))
        for key in ("mhs_manifest_refs", "manifest_refs", "mhs_manifest_ref", "manifest_ref"):
            value = snapshot.get(key)
            if isinstance(value, (list, tuple)):
                mhs_refs.extend(item for item in value if isinstance(item, str))
            elif isinstance(value, str):
                mhs_refs.append(value)
        for key in ("mhs_manifest_digests", "manifest_digests", "mhs_manifest_digest", "manifest_digest"):
            value = snapshot.get(key)
            if isinstance(value, (list, tuple)):
                mhs_digests.extend(item for item in value if isinstance(item, str))
            elif isinstance(value, str):
                mhs_digests.append(value)

    context = ProbeContext(
        robot_id=evidence.robot_id,
        target_fingerprint=evidence.target_host_fingerprint,
        runtime_revision=sorted(set(runtime_revisions))[0] if runtime_revisions else None,
        evidence_digest=evidence.payload_sha256,
        # The lifecycle command persists this verified bundle at the stable
        # target-evidence path; keep the context reference resolvable instead
        # of manufacturing a digest-only URI that has no artifact.
        evidence_refs=(f"artifact://target-evidence/{evidence.robot_id}-bundle.json",),
        routes=_unique_records(routes),
        message_schemas=_unique_records(schemas),
        published_tools=_unique_records(published_tools),
        mhs_manifest_refs=tuple(sorted(set(mhs_refs))),
        mhs_manifest_digests=tuple(sorted(set(mhs_digests))),
        freshness={"collected_at": evidence.collected_at.isoformat()},
        limitations=tuple(sorted(limitations)),
    )
    # Force the same canonicalization path used by CompileRequest validation.
    context_digest(context)
    return context


def _unique_records(records: list[dict[str, Any]]) -> tuple[dict[str, Any], ...]:
    """Return stable, duplicate-free records without mutating source evidence."""
    unique: dict[str, dict[str, Any]] = {}
    for record in records:
        key = json.dumps(record, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        unique[key] = record
    return tuple(unique[key] for key in sorted(unique))


def persist_compile_context(
    context: ProbeContext,
    root: str | Path,
    *,
    signing_secret: bytes | None = None,
) -> dict[str, Path]:
    """Persist a canonical compile context and an integrity index atomically."""

    destination = Path(root)
    destination.mkdir(parents=True, exist_ok=True)
    context_path = destination / "compile-context.json"
    index_path = destination / "artifact-index.json"
    payload = context.model_dump(mode="json", exclude_none=True)
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    digest = context_digest(context)
    temporary = context_path.with_suffix(".json.tmp")
    temporary.write_text(encoded + "\n", encoding="utf-8")
    os.replace(temporary, context_path)
    index: dict[str, Any] = {
        "schema_version": "rolo-compile-context-artifact-index/v1",
        "context_digest": digest,
        "artifacts": [{"path": "compile-context.json", "sha256": hashlib.sha256(encoded.encode("utf-8")).hexdigest()}],
    }
    if signing_secret is not None:
        if len(signing_secret) < 16:
            raise ValueError("context signing secret must contain at least 16 bytes")
        index["signature_hmac_sha256"] = hmac.new(signing_secret, digest.encode("ascii"), hashlib.sha256).hexdigest()
    index_tmp = index_path.with_suffix(".json.tmp")
    index_tmp.write_text(json.dumps(index, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    os.replace(index_tmp, index_path)
    return {"context": context_path, "index": index_path}


__all__ = ["build_probe_context", "persist_compile_context"]
