"""Probe Context reference resolution for the DSL frontend."""

from typing import Any

from .context import ProbeContext
from .diagnostics import Diagnostic, DiagnosticReport, DiagnosticSeverity
from .models import DslDocument


def _context(value: ProbeContext | dict[str, Any]) -> ProbeContext:
    return value if isinstance(value, ProbeContext) else ProbeContext.model_validate(value)


def resolve_evidence(document: DslDocument, context: ProbeContext | dict[str, Any]) -> DiagnosticReport:
    probe = _context(context)
    diagnostics: list[Diagnostic] = []
    if probe.robot_id != document.target.robot_id:
        diagnostics.append(Diagnostic(code="TARGET_MISMATCH", path="target.robot_id", severity=DiagnosticSeverity.ERROR, message="DSL target does not match Probe Context"))
    if probe.evidence_digest != document.target.evidence_digest:
        diagnostics.append(Diagnostic(code="EVIDENCE_DIGEST_MISMATCH", path="target.evidence_digest", severity=DiagnosticSeverity.ERROR, message="DSL evidence digest does not match Probe Context"))
    available = set(probe.evidence_refs)
    routes = {item.get("resource_id") for item in probe.routes}
    schemas = {item.get("schema_id") for item in probe.message_schemas}
    available.update(item for item in routes if item)
    for index, reference in enumerate(document.evidence_refs):
        if reference not in available:
            diagnostics.append(Diagnostic(code="EVIDENCE_REF_NOT_FOUND", path=f"evidence_refs[{index}]", severity=DiagnosticSeverity.ERROR, message=f"reference {reference!r} was not observed"))
    binding_ref = document.binding.get("resource_id")
    if binding_ref and binding_ref not in available:
        diagnostics.append(Diagnostic(code="RESOURCE_NOT_OBSERVED", path="binding.resource_id", severity=DiagnosticSeverity.ERROR, message=f"resource {binding_ref!r} was not observed"))
    schema_ref = document.binding.get("message_schema") or document.binding.get("message_type")
    if schema_ref and schema_ref not in schemas:
        diagnostics.append(Diagnostic(code="MESSAGE_SCHEMA_NOT_OBSERVED", path="binding.message_schema", severity=DiagnosticSeverity.ERROR, message=f"message schema {schema_ref!r} was not observed"))
    for index, reference in enumerate((*document.target.mhs_manifest_refs, *document.binding.get("mhs_manifest_refs", []))):
        if reference not in probe.mhs_manifest_refs:
            diagnostics.append(
                Diagnostic(
                    code="MHS_MANIFEST_NOT_REFERENCED",
                    path=f"target.mhs_manifest_refs[{index}]",
                    severity=DiagnosticSeverity.ERROR,
                    message=f"MHS manifest {reference!r} was not present in Probe Context",
                )
            )
    return DiagnosticReport(diagnostics=tuple(diagnostics))
