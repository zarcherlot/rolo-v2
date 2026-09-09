"""Conformance checks for generated fake bundles."""

from .canonical import bundle_plan_digest, ir_digest
from .compiler import CompileResult
from .contracts import BUNDLE_PLAN_SCHEMA_VERSION
from .diagnostics import Diagnostic, DiagnosticReport, DiagnosticSeverity


def conformance(result: CompileResult) -> DiagnosticReport:
    diagnostics = list(result.report.diagnostics)
    if result.bundle is None and result.report.ok:
        diagnostics.append(Diagnostic(code="BUNDLE_MISSING", path="bundle", severity=DiagnosticSeverity.ERROR, message="compile did not produce a bundle"))
    if result.bundle is not None:
        for field in (
            "schema_version",
            "tool_id",
            "kind",
            "target_fingerprint",
            "dsl_digest",
            "context_digest",
            "ir_digest",
            "compiler_version",
            "backend_id",
            "backend_version",
            "entrypoint_contract",
        ):
            if not getattr(result.bundle.manifest, field, None):
                diagnostics.append(Diagnostic(code="MANIFEST_FIELD_MISSING", path=f"bundle.manifest.{field}", severity=DiagnosticSeverity.ERROR, message=f"manifest field {field} is required"))
        if result.bundle.manifest.schema_version != BUNDLE_PLAN_SCHEMA_VERSION:
            diagnostics.append(
                Diagnostic(
                    code="BUNDLE_SCHEMA_VERSION_UNSUPPORTED",
                    path="bundle.manifest.schema_version",
                    severity=DiagnosticSeverity.ERROR,
                    message="bundle plan schema version is unsupported",
                    details={"expected": BUNDLE_PLAN_SCHEMA_VERSION},
                )
            )
        if result.ir is not None and result.bundle.manifest.ir_digest != ir_digest(result.ir):
            diagnostics.append(Diagnostic(code="IR_DIGEST_MISMATCH", path="bundle.manifest.ir_digest", severity=DiagnosticSeverity.ERROR, message="bundle does not match canonical IR"))
        if result.bundle.manifest.dsl_digest != result.dsl_digest:
            diagnostics.append(Diagnostic(code="BUNDLE_DSL_DIGEST_MISMATCH", path="bundle.manifest.dsl_digest", severity=DiagnosticSeverity.ERROR, message="bundle does not match canonical DSL"))
        if result.ir is not None and (result.bundle.manifest.tool_id != result.ir.tool_id or result.bundle.manifest.kind != result.ir.kind):
            diagnostics.append(Diagnostic(code="BUNDLE_IR_IDENTITY_MISMATCH", path="bundle.manifest", severity=DiagnosticSeverity.ERROR, message="bundle tool identity does not match canonical IR"))
        if result.bundle.backend_id != result.bundle.manifest.backend_id:
            diagnostics.append(Diagnostic(code="BUNDLE_BACKEND_MISMATCH", path="bundle.manifest.backend_id", severity=DiagnosticSeverity.ERROR, message="bundle backend does not match its plan"))
        if result.bundle.digest != bundle_plan_digest(result.bundle.manifest):
            diagnostics.append(Diagnostic(code="BUNDLE_DIGEST_MISMATCH", path="bundle.digest", severity=DiagnosticSeverity.ERROR, message="bundle digest does not match the complete canonical plan"))
    return DiagnosticReport(diagnostics=tuple(diagnostics)).stable()
