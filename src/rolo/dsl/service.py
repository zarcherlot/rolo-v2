"""Public compiler service implementing the DslCompiler contract."""
from pathlib import Path
from .api import DslCheckRequest, DslCompileRequest, DslCompileResult
from .compiler import compile_document
from .conformance_report import report_for
from .parser import parse_document
from .canonical import dsl_digest, ir_digest
class RoloDslCompiler:
    def check(self, request: DslCheckRequest) -> DslCompileResult:
        document, report = parse_document(request.dsl)
        if document is None:
            return DslCompileResult(status="DSL_CHECK_FAILED", dsl_digest="", diagnostics=tuple(item.code for item in report.diagnostics))
        return DslCompileResult(status="PASS" if report.ok else "DSL_CHECK_FAILED", dsl_digest=dsl_digest(document), diagnostics=tuple(item.code for item in report.diagnostics))
    def compile(self, request: DslCompileRequest, output_dir: str | Path) -> DslCompileResult:
        document, report = parse_document(request.dsl)
        if document is None:
            return DslCompileResult(status="DSL_COMPILE_FAILED", dsl_digest=request.dsl_digest, diagnostics=tuple(item.code for item in report.diagnostics))
        result = compile_document(document, output_dir, context=request.context)
        conformance = report_for(result, request.context)
        return DslCompileResult(status="PASS" if conformance.passed else "DSL_COMPILE_FAILED", dsl_digest=result.dsl_digest, ir_digest=ir_digest(result.ir) if result.ir else None, bundle_digest=result.bundle.digest if result.bundle else None, diagnostics=conformance.diagnostics, conformance=conformance)
