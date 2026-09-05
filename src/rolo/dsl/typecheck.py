"""Static type and safety checks for DSL mappings, composition, and EXECUTE."""

from .diagnostics import Diagnostic, DiagnosticReport, DiagnosticSeverity
from .models import DslDocument, OperationKind


def _has_cycle(steps: list[dict]) -> bool:
    graph = {step.get("id"): set(step.get("depends_on", ())) for step in steps}
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(node: str) -> bool:
        if node in visiting:
            return True
        if node in visited:
            return False
        visiting.add(node)
        if any(dep in graph and visit(dep) for dep in graph.get(node, ())):
            return True
        visiting.remove(node)
        visited.add(node)
        return False

    return any(visit(node) for node in graph)


def check_types(document: DslDocument) -> DiagnosticReport:
    diagnostics: list[Diagnostic] = []
    for key, expression in document.mapping.items():
        if not isinstance(key, str) or not key:
            diagnostics.append(Diagnostic(code="MAPPING_KEY_INVALID", path="mapping", severity=DiagnosticSeverity.ERROR, message="mapping keys must be non-empty strings"))
        if not isinstance(expression, (str, int, float, bool, dict, list)):
            diagnostics.append(Diagnostic(code="MAPPING_VALUE_INVALID", path=f"mapping.{key}", severity=DiagnosticSeverity.ERROR, message="mapping values must be schema-compatible"))
        if isinstance(expression, str) and any(token in expression for token in ("import ", "subprocess", "shell")):
            diagnostics.append(Diagnostic(code="DYNAMIC_EXPRESSION_FORBIDDEN", path=f"mapping.{key}", severity=DiagnosticSeverity.ERROR, message="dynamic code and shell expressions are forbidden"))
    if document.kind == OperationKind.COMPOSE:
        limits = document.composition.get("limits", {})
        steps = document.composition.get("steps", [])
        max_steps, max_runtime = limits.get("max_steps"), limits.get("max_runtime_ms")
        if not isinstance(max_steps, int) or max_steps <= 0:
            diagnostics.append(
                Diagnostic(code="COMPOSITION_MAX_STEPS_REQUIRED", path="composition.limits.max_steps", severity=DiagnosticSeverity.ERROR, message="COMPOSE requires a positive max_steps limit")
            )
        elif isinstance(steps, list) and len(steps) > max_steps:
            diagnostics.append(Diagnostic(code="COMPOSITION_MAX_STEPS_EXCEEDED", path="composition.steps", severity=DiagnosticSeverity.ERROR, message="composition contains more steps than max_steps"))
        if not isinstance(max_runtime, int) or max_runtime <= 0:
            diagnostics.append(
                Diagnostic(
                    code="COMPOSITION_MAX_RUNTIME_REQUIRED", path="composition.limits.max_runtime_ms", severity=DiagnosticSeverity.ERROR, message="COMPOSE requires a positive max_runtime_ms limit"
                )
            )
        if isinstance(steps, list) and _has_cycle(steps):
            diagnostics.append(Diagnostic(code="COMPOSITION_CYCLE", path="composition.steps", severity=DiagnosticSeverity.ERROR, message="composition graph must be acyclic"))
    if document.kind == OperationKind.EXECUTE:
        implementation = document.implementation
        required = ("source_bundle_digest", "entrypoint", "runtime", "implementation_contract")
        for field in required:
            if not implementation.get(field):
                diagnostics.append(
                    Diagnostic(code="EXECUTE_IMPLEMENTATION_FIELD_REQUIRED", path=f"implementation.{field}", severity=DiagnosticSeverity.ERROR, message=f"EXECUTE requires implementation.{field}")
                )
        digest = implementation.get("source_bundle_digest")
        if digest and not str(digest).startswith("sha256:"):
            diagnostics.append(
                Diagnostic(code="SOURCE_BUNDLE_DIGEST_INVALID", path="implementation.source_bundle_digest", severity=DiagnosticSeverity.ERROR, message="source bundle digest must use sha256:<hex>")
            )
    return DiagnosticReport(diagnostics=tuple(diagnostics))
