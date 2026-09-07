"""Immutable Tool Release and atomic Tool Catalog publishing."""

import hashlib
import json
import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Literal

from pydantic import Field

from rolo.dsl.canonical import ir_digest
from rolo.dsl.compiler import CompileResult
from rolo.dsl.contracts import TARGET_CONFORMANCE_SCHEMA_VERSION
from rolo.dsl.models import StrictModel
from rolo.dsl.report import ConformanceReport


class ToolRelease(StrictModel):
    tool_id: str = Field(min_length=1)
    operation_kind: str
    dsl_digest: str
    ir_digest: str
    probe_evidence_digest: str
    mhs_manifest_digests: tuple[str, ...] = ()
    compiler_version: str
    generated_bundle_digest: str
    conformance_digest: str
    target_fingerprint: str
    compile_context_digest: str | None = None
    route_digest: str | None = None
    target_conformance_digest: str | None = None
    status: str = "PUBLISHED"
    agent_callable: bool = True


class TargetConformanceReport(StrictModel):
    """Target-side T1-T4 gate consumed by the release publisher."""

    schema_version: Literal["rolo-target-conformance/v1"] = TARGET_CONFORMANCE_SCHEMA_VERSION
    t1_target_resolve: Literal["PASS", "FAIL"]
    t2_bundle_build: Literal["PASS", "FAIL"]
    t3_runtime_behavior: Literal["PASS", "FAIL"]
    t4_release_integrity: Literal["PASS", "FAIL"]
    target_fingerprint: str = Field(min_length=1)
    diagnostics: tuple[str, ...] = ()

    @property
    def passed(self) -> bool:
        return all(
            value == "PASS"
            for value in (
                self.t1_target_resolve,
                self.t2_bundle_build,
                self.t3_runtime_behavior,
                self.t4_release_integrity,
            )
        )


class ReleasePublisher:
    def __init__(self, root: str | Path):
        self.root = Path(root)
        self.releases = self.root / "releases"
        self.catalog_path = self.root / "tool-catalog.json"

    def publish(
        self,
        result: CompileResult,
        conformance: ConformanceReport,
        *,
        target_fingerprint: str,
        compiler_version: str,
        mhs_manifest_digests: tuple[str, ...] = (),
        compile_context_digest: str | None = None,
        route_digest: str | None = None,
        target_conformance_digest: str | None = None,
    ) -> ToolRelease:
        if not conformance.passed or not result.ok:
            raise ValueError("RELEASE_CONFORMANCE_FAILED")
        report_json = json.dumps(conformance.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
        report_digest = "sha256:" + hashlib.sha256(report_json.encode()).hexdigest()
        release = ToolRelease(
            tool_id=result.document.tool_id,
            operation_kind=str(result.document.kind),
            dsl_digest=result.dsl_digest,
            ir_digest=ir_digest(result.ir),
            probe_evidence_digest=result.document.target.evidence_digest,
            mhs_manifest_digests=mhs_manifest_digests,
            compiler_version=compiler_version,
            generated_bundle_digest=result.bundle.digest,
            conformance_digest=report_digest,
            target_fingerprint=target_fingerprint,
            compile_context_digest=compile_context_digest,
            route_digest=route_digest,
            target_conformance_digest=target_conformance_digest,
        )
        release_digest = "sha256:" + hashlib.sha256(json.dumps(release.model_dump(mode="json"), sort_keys=True).encode()).hexdigest()
        self.releases.mkdir(parents=True, exist_ok=True)
        release_file = self.releases / f"{release_digest.removeprefix('sha256:')}.json"
        self._atomic_json(release_file, release.model_dump(mode="json"))
        catalog = self._read_catalog()
        catalog.setdefault("tools", {})[release.tool_id] = {"current": release_digest, "release": release.model_dump(mode="json")}
        self._atomic_json(self.catalog_path, catalog)
        return release

    def publish_verified(
        self,
        result: CompileResult,
        compiler_conformance: ConformanceReport,
        target_conformance: TargetConformanceReport | Mapping[str, Any],
        *,
        target_fingerprint: str,
        compiler_version: str,
        mhs_manifest_digests: tuple[str, ...] = (),
        compile_context_digest: str | None = None,
        route_digest: str | None = None,
    ) -> ToolRelease:
        """Publish only after both offline C1-C4 and target T1-T4 pass."""

        target_report = target_conformance if isinstance(target_conformance, TargetConformanceReport) else TargetConformanceReport.model_validate(target_conformance)
        if not target_report.passed or target_report.target_fingerprint != target_fingerprint:
            raise ValueError("RELEASE_TARGET_CONFORMANCE_FAILED")
        target_json = json.dumps(target_report.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
        target_digest = "sha256:" + hashlib.sha256(target_json.encode()).hexdigest()
        return self.publish(
            result,
            compiler_conformance,
            target_fingerprint=target_fingerprint,
            compiler_version=compiler_version,
            mhs_manifest_digests=mhs_manifest_digests,
            compile_context_digest=compile_context_digest,
            route_digest=route_digest,
            target_conformance_digest=target_digest,
        )

    def stale(
        self,
        release: ToolRelease,
        *,
        target_fingerprint: str,
        evidence_digest: str,
        compiler_version: str,
        compile_context_digest: str | None = None,
        route_digest: str | None = None,
        mhs_manifest_digests: tuple[str, ...] | None = None,
    ) -> bool:
        """Return whether a release no longer matches the current evidence."""

        return bool(self.stale_reasons(
            release,
            target_fingerprint=target_fingerprint,
            evidence_digest=evidence_digest,
            compiler_version=compiler_version,
            compile_context_digest=compile_context_digest,
            route_digest=route_digest,
            mhs_manifest_digests=mhs_manifest_digests,
        ))

    def stale_reasons(
        self,
        release: ToolRelease,
        *,
        target_fingerprint: str,
        evidence_digest: str,
        compiler_version: str,
        compile_context_digest: str | None = None,
        route_digest: str | None = None,
        mhs_manifest_digests: tuple[str, ...] | None = None,
    ) -> tuple[str, ...]:
        reasons: list[str] = []
        if release.target_fingerprint != target_fingerprint:
            reasons.append("TARGET_FINGERPRINT_CHANGED")
        if release.probe_evidence_digest != evidence_digest:
            reasons.append("PROBE_EVIDENCE_CHANGED")
        if release.compiler_version != compiler_version:
            reasons.append("COMPILER_VERSION_CHANGED")
        if release.compile_context_digest is not None and compile_context_digest is not None and release.compile_context_digest != compile_context_digest:
            reasons.append("CONTEXT_DIGEST_CHANGED")
        if release.route_digest is not None and route_digest is not None and release.route_digest != route_digest:
            reasons.append("ROUTE_DIGEST_CHANGED")
        if mhs_manifest_digests is not None and tuple(sorted(set(release.mhs_manifest_digests))) != tuple(sorted(set(mhs_manifest_digests))):
            reasons.append("MHS_MANIFEST_CHANGED")
        return tuple(reasons)

    def current(self, tool_id: str) -> tuple[str, ToolRelease] | None:
        """Load the catalog's current immutable release for one tool."""

        entry = self._read_catalog().get("tools", {}).get(tool_id)
        if not isinstance(entry, dict):
            return None
        digest = entry.get("current")
        if not isinstance(digest, str):
            return None
        release = self.load(digest)
        if entry.get("status") == "STALE":
            release = release.model_copy(update={"status": "STALE", "agent_callable": False})
        return digest, release

    def mark_stale(self, tool_id: str, reasons: tuple[str, ...]) -> ToolRelease:
        """Mark the catalog pointer stale while preserving its immutable manifest."""

        current = self.current(tool_id)
        if current is None:
            raise KeyError(tool_id)
        digest, release = current
        catalog = self._read_catalog()
        entry = catalog.setdefault("tools", {}).setdefault(tool_id, {})
        entry.update({"current": digest, "status": "STALE", "stale_reasons": list(dict.fromkeys(reasons)), "release": release.model_dump(mode="json")})
        self._atomic_json(self.catalog_path, catalog)
        return release.model_copy(update={"status": "STALE", "agent_callable": False})

    def load(self, release_digest: str) -> ToolRelease:
        """Load a release by its catalog digest and verify its filename digest."""

        if not release_digest.startswith("sha256:") or len(release_digest) != 71:
            raise ValueError("RELEASE_DIGEST_INVALID")
        path = self.releases / f"{release_digest.removeprefix('sha256:')}.json"
        if not path.is_file() or path.is_symlink():
            raise FileNotFoundError(release_digest)
        release = ToolRelease.model_validate_json(path.read_text(encoding="utf-8"))
        actual = "sha256:" + hashlib.sha256(json.dumps(release.model_dump(mode="json"), sort_keys=True).encode()).hexdigest()
        if actual != release_digest:
            raise ValueError("RELEASE_DIGEST_MISMATCH")
        return release

    def rollback(self, tool_id: str, release_digest: str) -> ToolRelease:
        """Atomically point a tool back to an existing immutable release."""

        release = self.load(release_digest)
        if release.tool_id != tool_id:
            raise ValueError("RELEASE_TOOL_MISMATCH")
        catalog = self._read_catalog()
        tools = catalog.setdefault("tools", {})
        tools[tool_id] = {"current": release_digest, "release": release.model_dump(mode="json")}
        self._atomic_json(self.catalog_path, catalog)
        return release

    def _read_catalog(self) -> dict[str, Any]:
        if not self.catalog_path.exists():
            return {"schema_version": "rolo-tool-catalog/v1", "tools": {}}
        return json.loads(self.catalog_path.read_text(encoding="utf-8"))

    @staticmethod
    def _atomic_json(path: Path, value: dict[str, Any]) -> None:
        temp = path.with_suffix(path.suffix + ".tmp")
        temp.write_text(json.dumps(value, sort_keys=True, indent=2), encoding="utf-8")
        os.replace(temp, path)
