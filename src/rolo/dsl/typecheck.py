"""Static type and safety checks for DSL mappings and bounded composition."""
from .diagnostics import Diagnostic, DiagnosticReport, DiagnosticSeverity
from .models import DslDocument, OperationKind

def check_types(document: DslDocument) -> DiagnosticReport:
    diagnostics: list[Diagnostic] = []
    for key, expression in document.mapping.items():
        if not isinstance(key, str) or not key:
            diagnostics.append(Diagnostic(code="MAPPING_KEY_INVALID", path="mapping", severity=DiagnosticSeverity.ERROR, message="mapping keys must be non-empty strings"))
        if not isinstance(expression, (str, int, float, bool, dict, list)):
            diagnostics.append(Diagnostic(code="MAPPING_VALUE_INVALID", path=f"mapping.{key}", severity=DiagnosticSeverity.ERROR, message="mapping values must be schema-compatible"))
        if isinstance(expression, str) and ("import " in expression or "subprocess" in expression or "shell" in expression):
            diagnostics.append(Diagnostic(code="DYNAMIC_EXPRESSION_FORBIDDEN", path=f"mapping.{key}", severity=DiagnosticSeverity.ERROR, message="dynamic code and shell expressions are forbidden"))
    if document.kind == OperationKind.COMPOSE:
        limits = document.composition.get("limits", {})
        max_steps, max_runtime = limits.get("max_steps"), limits.get("max_runtime_ms")
        if not isinstance(max_steps, int) or max_steps <= 0:
            diagnostics.append(Diagnostic(code="COMPOSITION_MAX_STEPS_REQUIRED", path="composition.limits.max_steps", severity=DiagnosticSeverity.ERROR, message="COMPOSE requires a positive max_steps limit"))
        if not isinstance(max_runtime, int) or max_runtime <= 0:
            diagnostics.append(Diagnostic(code="COMPOSITION_MAX_RUNTIME_REQUIRED", path="composition.limits.max_runtime_ms", severity=DiagnosticSeverity.ERROR, message="COMPOSE requires a positive max_runtime_ms limit"))
    return DiagnosticReport(diagnostics=tuple(diagnostics))
