"""Offline compiler orchestration and conformance gates."""
from pathlib import Path
from .backends import GeneratedBundle, default_backends
from .diagnostics import Diagnostic, DiagnosticReport, DiagnosticSeverity
from .frontend import compile_frontend
from .parser import parse_document
from .models import DslDocument
class CompileResult:
    def __init__(self, *, document, ir, bundle, report, dsl_digest):
        self.document, self.ir, self.bundle, self.report, self.dsl_digest = document, ir, bundle, report, dsl_digest
    @property
    def ok(self): return self.report.ok and self.bundle is not None

def compile_document(document: DslDocument, output_dir: str | Path) -> CompileResult:
    ir, report, digest = compile_frontend(document)
    if not report.ok or ir is None: return CompileResult(document=document, ir=None, bundle=None, report=report, dsl_digest=digest)
    backend = next((item for item in default_backends() if item.supports(ir)), None)
    if backend is None:
        report = DiagnosticReport(diagnostics=(Diagnostic(code="BACKEND_UNSUPPORTED", path="kind", severity=DiagnosticSeverity.ERROR, message=f"no backend for {ir.kind}"),))
        return CompileResult(document=document, ir=ir, bundle=None, report=report, dsl_digest=digest)
    return CompileResult(document=document, ir=ir, bundle=backend.compile(ir, Path(output_dir)), report=report, dsl_digest=digest)

def compile_text(value, output_dir: str | Path) -> CompileResult:
    document, report = parse_document(value)
    if document is None:
        return CompileResult(document=None, ir=None, bundle=None, report=report, dsl_digest="")
    return compile_document(document, output_dir)
