"""Conformance checks for generated fake bundles."""
from .canonical import ir_digest
from .compiler import CompileResult
from .diagnostics import Diagnostic, DiagnosticReport, DiagnosticSeverity
def conformance(result: CompileResult) -> DiagnosticReport:
    diagnostics = list(result.report.diagnostics)
    if result.bundle is None and result.report.ok:
        diagnostics.append(Diagnostic(code="BUNDLE_MISSING", path="bundle", severity=DiagnosticSeverity.ERROR, message="compile did not produce a bundle"))
    if result.bundle is not None:
        for field in ("tool_id", "kind", "backend_id", "ir_digest"):
            if not result.bundle.manifest.get(field):
                diagnostics.append(Diagnostic(code="MANIFEST_FIELD_MISSING", path=f"bundle.manifest.{field}", severity=DiagnosticSeverity.ERROR, message=f"manifest field {field} is required"))
        if result.ir is not None and result.bundle.manifest.get("ir_digest") != ir_digest(result.ir):
            diagnostics.append(Diagnostic(code="IR_DIGEST_MISMATCH", path="bundle.manifest.ir_digest", severity=DiagnosticSeverity.ERROR, message="bundle does not match canonical IR"))
    return DiagnosticReport(diagnostics=tuple(diagnostics))
