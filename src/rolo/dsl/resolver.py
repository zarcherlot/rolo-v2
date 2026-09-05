"""Probe Context reference resolution for the DSL frontend."""

from typing import Any

from .diagnostics import Diagnostic, DiagnosticReport, DiagnosticSeverity
from .models import DslDocument


def resolve_evidence(document: DslDocument, context: dict[str, Any]) -> DiagnosticReport:
    diagnostics: list[Diagnostic] = []
    if context.get("robot_id") != document.target.robot_id:
        diagnostics.append(Diagnostic(code="TARGET_MISMATCH", path="target.robot_id", severity=DiagnosticSeverity.ERROR, message="DSL target does not match Probe Context"))
    if context.get("evidence_digest") != document.target.evidence_digest:
        diagnostics.append(Diagnostic(code="EVIDENCE_DIGEST_MISMATCH", path="target.evidence_digest", severity=DiagnosticSeverity.ERROR, message="DSL evidence digest does not match Probe Context"))
    available = set(context.get("evidence_refs", ()))
    for index, reference in enumerate(document.evidence_refs):
        if reference not in available:
            diagnostics.append(Diagnostic(code="EVIDENCE_REF_NOT_FOUND", path=f"evidence_refs[{index}]", severity=DiagnosticSeverity.ERROR, message=f"reference {reference!r} was not observed"))
    binding_ref = document.binding.get("resource_id")
    if binding_ref and binding_ref not in available:
        diagnostics.append(Diagnostic(code="RESOURCE_NOT_OBSERVED", path="binding.resource_id", severity=DiagnosticSeverity.ERROR, message=f"resource {binding_ref!r} was not observed"))
    return DiagnosticReport(diagnostics=tuple(diagnostics))
