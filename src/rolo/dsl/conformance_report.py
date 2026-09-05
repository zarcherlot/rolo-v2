"""Build layered C1-C4 conformance from an offline compile result."""
from .canonical import ir_digest
from .compiler import CompileResult
from .diagnostics import DiagnosticReport
from .report import ConformanceReport, GateStatus
from .resolver import resolve_evidence

def report_for(result: CompileResult, context: dict | None = None) -> ConformanceReport:
    c1 = GateStatus.PASS if result.document is not None and result.report.ok else GateStatus.FAIL
    c2 = GateStatus.PASS
    if context is not None and result.document is not None:
        c2 = GateStatus.PASS if resolve_evidence(result.document, context).ok else GateStatus.FAIL
    elif result.document is None:
        c2 = GateStatus.FAIL
    c3 = GateStatus.PASS if result.bundle is not None and result.ir is not None and result.bundle.manifest.get("ir_digest") == ir_digest(result.ir) else GateStatus.FAIL
    c4 = GateStatus.PASS if result.ok else GateStatus.FAIL
    return ConformanceReport(c1_dsl=c1, c2_evidence=c2, c3_compile=c3, c4_behavior=c4, diagnostics=tuple(item.code for item in result.report.diagnostics))
