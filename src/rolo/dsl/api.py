"""Typed request/result contracts for controller-side DSL compilation."""

from typing import Any, Literal

from pydantic import Field

from .contracts import COMPILE_REQUEST_SCHEMA_VERSION, COMPILE_RESULT_SCHEMA_VERSION
from .models import StrictModel
from .report import ConformanceReport


class DslCheckRequest(StrictModel):
    dsl: dict[str, Any]
    context: dict[str, Any] = Field(default_factory=dict)
    compiler_version: str = "rolo-compiler/0.1"


class DslCompileRequest(DslCheckRequest):
    schema_version: Literal["rolo-dsl-compile-request/v1"] = COMPILE_REQUEST_SCHEMA_VERSION
    request_id: str = Field(default="compile", min_length=1, max_length=256)
    dsl_digest: str
    context_digest: str
    target_fingerprint: str
    mhs_manifest_digests: tuple[str, ...] = ()
    source_bundle_digest: str | None = None
    backend_id: str | None = None
    required_capabilities: tuple[str, ...] = ()


class DslCompileResult(StrictModel):
    schema_version: Literal["rolo-dsl-compile-result/v1"] = COMPILE_RESULT_SCHEMA_VERSION
    status: str
    dsl_digest: str
    context_digest: str | None = None
    target_fingerprint: str | None = None
    compiler_version: str | None = None
    ir_digest: str | None = None
    bundle_digest: str | None = None
    backend_id: str | None = None
    artifacts: dict[str, str] = Field(default_factory=dict, max_length=32)
    diagnostics: tuple[str, ...] = ()
    conformance: ConformanceReport | None = None
