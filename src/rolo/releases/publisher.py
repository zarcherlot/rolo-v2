"""Immutable Tool Release and atomic Tool Catalog publishing."""

import hashlib
import json
import os
from pathlib import Path
from typing import Any

from pydantic import Field

from rolo.dsl.canonical import ir_digest
from rolo.dsl.compiler import CompileResult
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
    status: str = "PUBLISHED"
    agent_callable: bool = True


class ReleasePublisher:
    def __init__(self, root: str | Path):
        self.root = Path(root)
        self.releases = self.root / "releases"
        self.catalog_path = self.root / "tool-catalog.json"

    def publish(self, result: CompileResult, conformance: ConformanceReport, *, target_fingerprint: str, compiler_version: str, mhs_manifest_digests: tuple[str, ...] = ()) -> ToolRelease:
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
        )
        release_digest = "sha256:" + hashlib.sha256(json.dumps(release.model_dump(mode="json"), sort_keys=True).encode()).hexdigest()
        self.releases.mkdir(parents=True, exist_ok=True)
        release_file = self.releases / f"{release_digest.removeprefix('sha256:')}.json"
        self._atomic_json(release_file, release.model_dump(mode="json"))
        catalog = self._read_catalog()
        catalog.setdefault("tools", {})[release.tool_id] = {"current": release_digest, "release": release.model_dump(mode="json")}
        self._atomic_json(self.catalog_path, catalog)
        return release

    def stale(self, release: ToolRelease, *, target_fingerprint: str, evidence_digest: str, compiler_version: str) -> bool:
        return release.target_fingerprint != target_fingerprint or release.probe_evidence_digest != evidence_digest or release.compiler_version != compiler_version

    def _read_catalog(self) -> dict[str, Any]:
        if not self.catalog_path.exists():
            return {"schema_version": "rolo-tool-catalog/v1", "tools": {}}
        return json.loads(self.catalog_path.read_text(encoding="utf-8"))

    @staticmethod
    def _atomic_json(path: Path, value: dict[str, Any]) -> None:
        temp = path.with_suffix(path.suffix + ".tmp")
        temp.write_text(json.dumps(value, sort_keys=True, indent=2), encoding="utf-8")
        os.replace(temp, path)
