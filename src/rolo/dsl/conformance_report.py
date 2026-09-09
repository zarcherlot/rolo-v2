"""Build layered C1-C4 conformance from an offline compile result."""

from .canonical import bundle_plan_digest, ir_digest
from .compiler import CompileResult
from .report import ConformanceReport, GateStatus
from .resolver import resolve_evidence


def report_for(result: CompileResult, context: dict | None = None) -> ConformanceReport:
    c1 = GateStatus.PASS if result.document is not None and result.report.ok else GateStatus.FAIL
    c2 = GateStatus.PASS
    if context is not None and result.document is not None:
        c2 = GateStatus.PASS if resolve_evidence(result.document, context).ok else GateStatus.FAIL
    elif result.document is None:
        c2 = GateStatus.FAIL
    c3 = (
        GateStatus.PASS
        if result.bundle is not None
        and result.ir is not None
        and result.bundle.manifest.ir_digest == ir_digest(result.ir)
        and result.bundle.manifest.dsl_digest == result.dsl_digest
        and result.bundle.manifest.tool_id == result.ir.tool_id
        and result.bundle.manifest.kind == result.ir.kind
        and result.bundle.manifest.backend_id == result.bundle.backend_id
        and result.bundle.digest == bundle_plan_digest(result.bundle.manifest)
        else GateStatus.FAIL
    )
    c4 = GateStatus.PASS if result.ok else GateStatus.FAIL
    return ConformanceReport(c1_dsl=c1, c2_evidence=c2, c3_compile=c3, c4_behavior=c4, diagnostics=tuple(item.code for item in result.report.diagnostics))
