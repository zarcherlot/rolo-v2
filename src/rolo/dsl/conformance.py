"""Conformance checks for generated fake bundles."""
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
    return DiagnosticReport(diagnostics=tuple(diagnostics))
