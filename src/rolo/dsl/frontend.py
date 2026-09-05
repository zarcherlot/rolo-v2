"""Deterministic frontend: parse, validate, lower and digest a DSL document."""
from .canonical import dsl_digest
from .diagnostics import Diagnostic, DiagnosticReport, DiagnosticSeverity
from .ir import CanonicalIR
from .models import DslDocument, OperationKind
def lower(document: DslDocument) -> CanonicalIR:
    return CanonicalIR.model_validate(document.model_dump(exclude={"schema_version", "status"}))
def check_semantics(document: DslDocument) -> DiagnosticReport:
    diagnostics: list[Diagnostic] = []
    if not document.target.evidence_digest.startswith("sha256:"):
        diagnostics.append(Diagnostic(code="EVIDENCE_DIGEST_INVALID", path="target.evidence_digest", severity=DiagnosticSeverity.ERROR, message="evidence_digest must use sha256:<hex> format"))
    if document.kind in (OperationKind.OBSERVE, OperationKind.INVOKE) and not document.binding:
        diagnostics.append(Diagnostic(code="BINDING_REQUIRED", path="binding", severity=DiagnosticSeverity.ERROR, message=f"{document.kind} requires a target binding"))
    if document.kind == OperationKind.COMPOSE and not document.composition:
        diagnostics.append(Diagnostic(code="COMPOSITION_REQUIRED", path="composition", severity=DiagnosticSeverity.ERROR, message="COMPOSE requires a bounded composition graph"))
    if document.kind == OperationKind.EXECUTE and not document.implementation:
        diagnostics.append(Diagnostic(code="IMPLEMENTATION_REQUIRED", path="implementation", severity=DiagnosticSeverity.ERROR, message="EXECUTE requires an implementation contract"))
    return DiagnosticReport(diagnostics=tuple(diagnostics))
def compile_frontend(document: DslDocument) -> tuple[CanonicalIR | None, DiagnosticReport, str]:
    report = check_semantics(document)
    if not report.ok: return None, report, dsl_digest(document)
    return lower(document), report, dsl_digest(document)
