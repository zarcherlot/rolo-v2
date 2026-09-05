"""Public compiler service implementing the DslCompiler contract."""

from pathlib import Path

from .api import DslCheckRequest, DslCompileRequest, DslCompileResult
from .canonical import context_digest, dsl_digest, ir_digest
from .compiler import compile_document
from .conformance_report import report_for
from .frontend import compile_frontend
from .parser import parse_document


class RoloDslCompiler:
    def check(self, request: DslCheckRequest) -> DslCompileResult:
        document, report = parse_document(request.dsl)
        if document is None:
            return DslCompileResult(status="DSL_CHECK_FAILED", dsl_digest="", diagnostics=tuple(item.code for item in report.diagnostics))
        _, report, digest = compile_frontend(document)
        return DslCompileResult(status="PASS" if report.ok else "DSL_CHECK_FAILED", dsl_digest=digest, diagnostics=tuple(item.code for item in report.diagnostics))

    def compile(self, request: DslCompileRequest, output_dir: str | Path) -> DslCompileResult:
        document, report = parse_document(request.dsl)
        if document is None:
            return DslCompileResult(status="DSL_COMPILE_FAILED", dsl_digest=request.dsl_digest, diagnostics=tuple(item.code for item in report.diagnostics))
        actual_dsl_digest = dsl_digest(document)
        if request.dsl_digest != actual_dsl_digest:
            return DslCompileResult(status="DSL_COMPILE_FAILED", dsl_digest=actual_dsl_digest, diagnostics=("DSL_DIGEST_MISMATCH",))
        actual_context_digest = context_digest(request.context)
        if request.context_digest != actual_context_digest:
            return DslCompileResult(status="DSL_COMPILE_FAILED", dsl_digest=actual_dsl_digest, diagnostics=("CONTEXT_DIGEST_MISMATCH",))
        if not request.target_fingerprint:
            return DslCompileResult(status="DSL_COMPILE_FAILED", dsl_digest=actual_dsl_digest, diagnostics=("TARGET_FINGERPRINT_REQUIRED",))
        result = compile_document(document, output_dir, context=request.context)
        conformance = report_for(result, request.context)
        return DslCompileResult(
            status="PASS" if conformance.passed else "DSL_COMPILE_FAILED",
            dsl_digest=result.dsl_digest,
            ir_digest=ir_digest(result.ir) if result.ir else None,
            bundle_digest=result.bundle.digest if result.bundle else None,
            diagnostics=conformance.diagnostics,
            conformance=conformance,
        )
