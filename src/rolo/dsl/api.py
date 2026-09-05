"""Typed request/result contracts for controller-side DSL compilation."""
from pathlib import Path
from typing import Any
from .models import StrictModel
from .report import ConformanceReport
class DslCheckRequest(StrictModel):
    dsl: dict[str, Any]
    context: dict[str, Any] = {}
    compiler_version: str = "rolo-compiler/0.1"
class DslCompileRequest(DslCheckRequest):
    dsl_digest: str
    context_digest: str
    target_fingerprint: str
    mhs_manifest_digests: tuple[str, ...] = ()
    source_bundle_digest: str | None = None
class DslCompileResult(StrictModel):
    status: str
    dsl_digest: str
    ir_digest: str | None = None
    bundle_digest: str | None = None
    diagnostics: tuple[str, ...] = ()
    conformance: ConformanceReport | None = None
