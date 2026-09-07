from pathlib import Path

from .backends import negotiate_backend
from .diagnostics import Diagnostic, DiagnosticReport, DiagnosticSeverity
from .frontend import compile_frontend
from .models import DslDocument
from .parser import parse_document
from .resolver import resolve_evidence


class CompileResult:
    def __init__(self, *, document, ir, bundle, report, dsl_digest):
        self.document, self.ir, self.bundle, self.report, self.dsl_digest = document, ir, bundle, report, dsl_digest

    @property
    def ok(self):
        return self.report.ok and self.bundle is not None


def compile_document(
    document: DslDocument,
    output_dir: str | Path,
    context: dict | None = None,
    *,
    backend_id: str | None = None,
    required_capabilities: tuple[str, ...] = (),
) -> CompileResult:
    ir, report, digest = compile_frontend(document)
    if context is not None and report.ok:
        report = resolve_evidence(document, context)
    if not report.ok or ir is None:
        return CompileResult(document=document, ir=None, bundle=None, report=report, dsl_digest=digest)
    backend = negotiate_backend(
        ir.kind,
        backend_id=backend_id,
        required_capabilities=required_capabilities,
    )
    if backend is None:
        requested = backend_id or str(ir.kind)
        report = DiagnosticReport(
            diagnostics=(
                Diagnostic(
                    code="BACKEND_UNSUPPORTED",
                    path="kind",
                    severity=DiagnosticSeverity.ERROR,
                    message=f"no backend for {requested}",
                    details={"requested_backend": backend_id, "required_capabilities": list(required_capabilities)},
                ),
            )
        )
        return CompileResult(document=document, ir=ir, bundle=None, report=report, dsl_digest=digest)
    return CompileResult(document=document, ir=ir, bundle=backend.compile(ir, Path(output_dir)), report=report, dsl_digest=digest)


def compile_text(value, output_dir: str | Path, context: dict | None = None) -> CompileResult:
    document, report = parse_document(value)
    if document is None:
        return CompileResult(document=None, ir=None, bundle=None, report=report, dsl_digest="")
    return compile_document(document, output_dir, context=context)
