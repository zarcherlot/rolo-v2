"""Public compiler service implementing the DslCompiler contract."""

from pathlib import Path

from .admission import (
    MappingAdmissionError,
    MappingAdmissionGate,
    MappingAdmissionIdentity,
    MappingConfirmationReceipt,
    MappingConfirmationStore,
)
from .api import DslCheckRequest, DslCompileRequest, DslCompileResult
from .canonical import context_digest, dsl_digest, ir_digest
from .compiler import compile_document
from .conformance_report import report_for
from .context import ProbeContext
from .frontend import compile_frontend
from .parser import parse_document
from .resolver import resolve_evidence


class RoloDslCompiler:
    def __init__(self, admission_store: MappingConfirmationStore | None = None) -> None:
        self.admission_gate = MappingAdmissionGate(admission_store) if admission_store is not None else None

    def check(self, request: DslCheckRequest) -> DslCompileResult:
        document, report = parse_document(request.dsl)
        if document is None:
            return DslCompileResult(
                status="DSL_CHECK_FAILED",
                dsl_digest="",
                context_digest=context_digest(request.context) if request.context else None,
                compiler_version=request.compiler_version,
                diagnostics=tuple(item.code for item in report.diagnostics),
            )
        _, report, digest = compile_frontend(document)
        # A check with a supplied context is the Agent-facing mapping gate,
        # not merely a syntax check. Resolve target/evidence references before
        # presenting the DSL as a repairable candidate.
        if report.ok and request.context:
            try:
                evidence_report = resolve_evidence(document, request.context)
            except ValueError:
                return DslCompileResult(
                    status="DSL_CHECK_FAILED",
                    dsl_digest=digest,
                    context_digest=context_digest(request.context),
                    compiler_version=request.compiler_version,
                    diagnostics=("CONTEXT_INVALID",),
                )
            report = type(report)(diagnostics=(*report.diagnostics, *evidence_report.diagnostics)).stable()
        return DslCompileResult(
            status="PASS" if report.ok else "DSL_CHECK_FAILED",
            dsl_digest=digest,
            context_digest=context_digest(request.context) if request.context else None,
            compiler_version=request.compiler_version,
            diagnostics=tuple(item.code for item in report.diagnostics),
        )

    def compile(self, request: DslCompileRequest, output_dir: str | Path) -> DslCompileResult:
        document, report = parse_document(request.dsl)
        if document is None:
            return DslCompileResult(
                status="DSL_COMPILE_FAILED",
                dsl_digest=request.dsl_digest,
                context_digest=request.context_digest,
                target_fingerprint=request.target_fingerprint,
                compiler_version=request.compiler_version,
                diagnostics=tuple(item.code for item in report.diagnostics),
            )
        try:
            normalized_context = ProbeContext.model_validate(request.context)
        except ValueError:
            return DslCompileResult(
                status="DSL_COMPILE_FAILED",
                dsl_digest=request.dsl_digest,
                context_digest=None,
                target_fingerprint=request.target_fingerprint,
                compiler_version=request.compiler_version,
                diagnostics=("CONTEXT_INVALID",),
            )
        actual_dsl_digest = dsl_digest(document)
        if request.dsl_digest != actual_dsl_digest:
            return DslCompileResult(
                status="DSL_COMPILE_FAILED",
                dsl_digest=actual_dsl_digest,
                context_digest=request.context_digest,
                target_fingerprint=request.target_fingerprint,
                compiler_version=request.compiler_version,
                diagnostics=("DSL_DIGEST_MISMATCH",),
            )
        actual_context_digest = context_digest(normalized_context)
        if request.context_digest != actual_context_digest:
            return DslCompileResult(
                status="DSL_COMPILE_FAILED",
                dsl_digest=actual_dsl_digest,
                context_digest=actual_context_digest,
                target_fingerprint=request.target_fingerprint,
                compiler_version=request.compiler_version,
                diagnostics=("CONTEXT_DIGEST_MISMATCH",),
            )
        if not request.target_fingerprint:
            return DslCompileResult(
                status="DSL_COMPILE_FAILED",
                dsl_digest=actual_dsl_digest,
                context_digest=actual_context_digest,
                target_fingerprint=request.target_fingerprint,
                compiler_version=request.compiler_version,
                diagnostics=("TARGET_FINGERPRINT_REQUIRED",),
            )
        context_target_fingerprint = normalized_context.target_fingerprint
        if context_target_fingerprint != request.target_fingerprint:
            return DslCompileResult(
                status="DSL_COMPILE_FAILED",
                dsl_digest=actual_dsl_digest,
                context_digest=actual_context_digest,
                target_fingerprint=request.target_fingerprint,
                compiler_version=request.compiler_version,
                diagnostics=("TARGET_FINGERPRINT_MISMATCH",),
            )
        if normalized_context.robot_id != document.target.robot_id:
            return DslCompileResult(
                status="DSL_COMPILE_FAILED",
                dsl_digest=actual_dsl_digest,
                context_digest=actual_context_digest,
                target_fingerprint=request.target_fingerprint,
                compiler_version=request.compiler_version,
                confirmation_receipt_digest=request.confirmation_receipt_digest,
                diagnostics=("TARGET_ID_MISMATCH",),
            )
        if normalized_context.evidence_digest != document.target.evidence_digest:
            return DslCompileResult(
                status="DSL_COMPILE_FAILED",
                dsl_digest=actual_dsl_digest,
                context_digest=actual_context_digest,
                target_fingerprint=request.target_fingerprint,
                compiler_version=request.compiler_version,
                confirmation_receipt_digest=request.confirmation_receipt_digest,
                diagnostics=("EVIDENCE_DIGEST_MISMATCH",),
            )
        try:
            self._require_mapping_admission(
                request,
                document=document,
                context=normalized_context,
                dsl_digest_value=actual_dsl_digest,
                context_digest_value=actual_context_digest,
            )
        except MappingAdmissionError as exc:
            return DslCompileResult(
                status="DSL_COMPILE_FAILED",
                dsl_digest=actual_dsl_digest,
                context_digest=actual_context_digest,
                target_fingerprint=request.target_fingerprint,
                compiler_version=request.compiler_version,
                confirmation_receipt_digest=request.confirmation_receipt_digest,
                diagnostics=(exc.code,),
            )
        result = compile_document(
            document,
            output_dir,
            context=normalized_context.model_dump(mode="python"),
            backend_id=request.backend_id,
            required_capabilities=request.required_capabilities,
            compiler_version=request.compiler_version,
            confirmation_store=(
                self.admission_gate.store if self.admission_gate is not None else None
            ),
            confirmation_receipt_digest=request.confirmation_receipt_digest,
            journey_session_id=request.journey_session_id,
        )
        conformance = report_for(result, request.context)
        return DslCompileResult(
            status="PASS" if conformance.passed else "DSL_COMPILE_FAILED",
            dsl_digest=result.dsl_digest,
            context_digest=actual_context_digest,
            target_fingerprint=request.target_fingerprint,
            compiler_version=request.compiler_version,
            ir_digest=ir_digest(result.ir) if result.ir else None,
            bundle_digest=result.bundle.bundle_digest if result.bundle else None,
            backend_id=result.bundle.backend_id if result.bundle else None,
            confirmation_receipt_digest=request.confirmation_receipt_digest,
            artifacts={"bundle_manifest": "manifest.json", "bundle_payload": "bundle-payload.json"} if result.bundle else {},
            diagnostics=conformance.diagnostics,
            conformance=conformance,
        )

    def _require_mapping_admission(
        self,
        request: DslCompileRequest,
        *,
        document,
        context: ProbeContext,
        dsl_digest_value: str,
        context_digest_value: str,
    ) -> MappingConfirmationReceipt:
        if self.admission_gate is None:
            raise MappingAdmissionError("MAPPING_CONFIRMATION_REQUIRED")
        committed = self.admission_gate.store.resolve(request.confirmation_receipt_digest)
        expected_scope = committed.scope.model_copy(
            update={"tool_id": document.tool_id, "operation_kind": document.kind}
        )
        expected = MappingAdmissionIdentity.build(
            journey_session_id=request.journey_session_id,
            target_id=context.robot_id,
            target_fingerprint=request.target_fingerprint,
            candidate_index_digest=committed.candidate_index_digest,
            candidate_digest=committed.candidate_digest,
            proposal_digest=committed.proposal_digest,
            dsl_digest=dsl_digest_value,
            context_digest=context_digest_value,
            evidence_digest=context.evidence_digest,
            available_tool_catalog_digest=committed.available_tool_catalog_digest,
            scope=expected_scope,
        )
        return self.admission_gate.require_active(request.confirmation_receipt_digest, expected)
