import hashlib
import json
import os
import shutil
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

from .admission import (
    MappingAdmissionError,
    MappingAdmissionGate,
    MappingAdmissionIdentity,
    MappingConfirmationReceipt,
    MappingConfirmationStore,
)
from .backends import BackendSpiVersionError, negotiate_backend
from .canonical import bundle_plan_digest, context_digest, dsl_digest, ir_digest
from .context import CompileContext
from .contracts import BACKEND_SPI_VERSION
from .diagnostics import Diagnostic, DiagnosticReport, DiagnosticSeverity
from .frontend import compile_frontend
from .models import DslDocument
from .parser import loads_unique_json, parse_document
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
    context: CompileContext | dict | None = None,
    *,
    backend_id: str | None = None,
    required_capabilities: tuple[str, ...] = (),
    compiler_version: str = "rolo-compiler/0.1",
    confirmation_store: MappingConfirmationStore | None = None,
    confirmation_receipt_digest: str | None = None,
    journey_session_id: str | None = None,
) -> CompileResult:
    digest = dsl_digest(document)
    missing_admission = _missing_compile_admission_code(
        confirmation_store=confirmation_store,
        confirmation_receipt_digest=confirmation_receipt_digest,
        journey_session_id=journey_session_id,
    )
    if missing_admission is not None:
        return CompileResult(
            document=document,
            ir=None,
            bundle=None,
            report=_mapping_admission_error(missing_admission),
            dsl_digest=digest,
        )
    normalized_context = None
    target_fingerprint = None
    if context is not None:
        target_fingerprint = context.target_fingerprint if isinstance(context, CompileContext) else context.get("target_fingerprint")
    if not isinstance(target_fingerprint, str) or not target_fingerprint:
        report = DiagnosticReport(
            diagnostics=(
                Diagnostic(
                    code="TARGET_FINGERPRINT_REQUIRED",
                    path="context.target_fingerprint",
                    severity=DiagnosticSeverity.ERROR,
                    message="compilation requires a target fingerprint from Compile Context",
                ),
            )
        )
    else:
        report = DiagnosticReport()
    if context is not None and report.ok:
        try:
            normalized_context = context if isinstance(context, CompileContext) else CompileContext.model_validate(context)
        except ValueError:
            report = DiagnosticReport(
                diagnostics=(
                    Diagnostic(
                        code="CONTEXT_INVALID",
                        path="context",
                        severity=DiagnosticSeverity.ERROR,
                        message="compilation requires a valid Compile Context",
                    ),
                )
            )
    if not report.ok or normalized_context is None:
        return CompileResult(document=document, ir=None, bundle=None, report=report, dsl_digest=digest)
    try:
        _require_compile_admission(
            document,
            normalized_context,
            digest,
            confirmation_store=confirmation_store,
            confirmation_receipt_digest=confirmation_receipt_digest,
            journey_session_id=journey_session_id,
        )
    except MappingAdmissionError as exc:
        return CompileResult(
            document=document,
            ir=None,
            bundle=None,
            report=_mapping_admission_error(exc.code),
            dsl_digest=digest,
        )

    ir, report, frontend_digest = compile_frontend(document)
    if frontend_digest != digest:
        report = _backend_error("DSL_DIGEST_MISMATCH", "frontend digest does not match the admission identity")
    if report.ok:
        report = resolve_evidence(document, normalized_context)
    if not report.ok or ir is None:
        return CompileResult(document=document, ir=None, bundle=None, report=report, dsl_digest=digest)
    try:
        backend = negotiate_backend(
            ir.kind,
            backend_id=backend_id,
            required_capabilities=required_capabilities,
        )
    except BackendSpiVersionError as exc:
        report = _backend_error(str(exc), "backend negotiation rejected an incompatible SPI version")
        return CompileResult(document=document, ir=ir, bundle=None, report=report, dsl_digest=digest)
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
    compile_v2 = getattr(backend, "compile_v2", None)
    if (
        getattr(backend, "backend_version", None) != BACKEND_SPI_VERSION
        or not callable(compile_v2)
    ):
        report = _backend_error("BACKEND_SPI_VERSION_UNSUPPORTED", "selected backend does not implement rolo-backend-spi/v2")
        return CompileResult(document=document, ir=ir, bundle=None, report=report, dsl_digest=digest)
    assert normalized_context is not None
    try:
        _require_compile_admission(
            document,
            normalized_context,
            digest,
            confirmation_store=confirmation_store,
            confirmation_receipt_digest=confirmation_receipt_digest,
            journey_session_id=journey_session_id,
        )
    except MappingAdmissionError as exc:
        report = _mapping_admission_error(exc.code)
        return CompileResult(document=document, ir=ir, bundle=None, report=report, dsl_digest=digest)

    # A backend never writes directly to the caller-visible path.  The active
    # confirmation is checked both before staging and after backend work, then
    # the complete directory is atomically promoted.  A cancellation or expiry
    # during compilation therefore leaves no committed bundle.
    output_path = Path(output_dir)
    if output_path.exists():
        report = _backend_error("COMPILE_OUTPUT_EXISTS", "compiler output path already exists")
        return CompileResult(document=document, ir=ir, bundle=None, report=report, dsl_digest=digest)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    staging_path = Path(
        tempfile.mkdtemp(
            prefix=f".{output_path.name}.staging-",
            dir=output_path.parent,
        )
    )
    try:
        negotiated_capabilities = tuple(sorted(backend.capabilities()))
        bundle = compile_v2(
            ir,
            staging_path,
            dsl_digest=digest,
            context_digest=context_digest(normalized_context),
            target_fingerprint=target_fingerprint,
            compiler_version=compiler_version,
            negotiated_capabilities=negotiated_capabilities,
            bindings=_resolved_bindings(ir, normalized_context),
            runtime_context=_runtime_context(normalized_context),
        )
        if not backend.conformance(bundle):
            raise ValueError("BACKEND_CONFORMANCE_FAILED")
        _validate_staged_bundle(
            staging_path,
            bundle,
            document=document,
            ir=ir,
            dsl_digest_value=digest,
            context_digest_value=context_digest(normalized_context),
            target_fingerprint=target_fingerprint,
            compiler_version=compiler_version,
            backend_id=backend.backend_id,
            negotiated_capabilities=negotiated_capabilities,
        )
        _require_compile_admission(
            document,
            normalized_context,
            digest,
            confirmation_store=confirmation_store,
            confirmation_receipt_digest=confirmation_receipt_digest,
            journey_session_id=journey_session_id,
            commit=lambda: os.replace(staging_path, output_path),
        )
    except MappingAdmissionError as exc:
        report = _mapping_admission_error(exc.code)
        return CompileResult(document=document, ir=ir, bundle=None, report=report, dsl_digest=digest)
    except BackendSpiVersionError as exc:
        report = _backend_error(str(exc), "selected backend rejected the compiler SPI")
        return CompileResult(document=document, ir=ir, bundle=None, report=report, dsl_digest=digest)
    except ValueError as exc:
        report = _backend_error("BUNDLE_PLAN_INVALID", str(exc))
        return CompileResult(document=document, ir=ir, bundle=None, report=report, dsl_digest=digest)
    except OSError as exc:
        report = _backend_error("COMPILE_ARTIFACT_PROMOTION_FAILED", str(exc))
        return CompileResult(document=document, ir=ir, bundle=None, report=report, dsl_digest=digest)
    finally:
        if staging_path.exists():
            shutil.rmtree(staging_path)
    return CompileResult(document=document, ir=ir, bundle=bundle, report=report, dsl_digest=digest)


def compile_text(
    value,
    output_dir: str | Path,
    context: CompileContext | dict | None = None,
    *,
    compiler_version: str = "rolo-compiler/0.1",
    confirmation_store: MappingConfirmationStore | None = None,
    confirmation_receipt_digest: str | None = None,
    journey_session_id: str | None = None,
) -> CompileResult:
    document, report = parse_document(value)
    if document is None:
        return CompileResult(document=None, ir=None, bundle=None, report=report, dsl_digest="")
    return compile_document(
        document,
        output_dir,
        context=context,
        compiler_version=compiler_version,
        confirmation_store=confirmation_store,
        confirmation_receipt_digest=confirmation_receipt_digest,
        journey_session_id=journey_session_id,
    )


def _backend_error(code: str, message: str) -> DiagnosticReport:
    return DiagnosticReport(
        diagnostics=(
            Diagnostic(
                code=code,
                path="backend",
                severity=DiagnosticSeverity.ERROR,
                message=message,
            ),
        )
    )


def _mapping_admission_error(code: str) -> DiagnosticReport:
    return DiagnosticReport(
        diagnostics=(
            Diagnostic(
                code=code,
                path="mapping_confirmation",
                severity=DiagnosticSeverity.ERROR,
                message="compilation requires an active, exact-match Mapping confirmation",
            ),
        )
    )


def _missing_compile_admission_code(
    *,
    confirmation_store: MappingConfirmationStore | None,
    confirmation_receipt_digest: str | None,
    journey_session_id: str | None,
) -> str | None:
    if confirmation_store is None:
        return "MAPPING_CONFIRMATION_STORE_REQUIRED"
    if not confirmation_receipt_digest:
        return "MAPPING_CONFIRMATION_REQUIRED"
    if not journey_session_id:
        return "MAPPING_JOURNEY_SESSION_REQUIRED"
    return None


def _require_compile_admission(
    document: DslDocument,
    context: CompileContext,
    dsl_digest_value: str,
    *,
    confirmation_store: MappingConfirmationStore | None,
    confirmation_receipt_digest: str | None,
    journey_session_id: str | None,
    commit: Callable[[], Any] | None = None,
) -> MappingConfirmationReceipt:
    if confirmation_store is None:
        raise MappingAdmissionError("MAPPING_CONFIRMATION_STORE_REQUIRED")
    if not confirmation_receipt_digest:
        raise MappingAdmissionError("MAPPING_CONFIRMATION_REQUIRED")
    if not journey_session_id:
        raise MappingAdmissionError("MAPPING_JOURNEY_SESSION_REQUIRED")
    committed = confirmation_store.resolve(confirmation_receipt_digest)
    expected_scope = committed.scope.model_copy(
        update={"tool_id": document.tool_id, "operation_kind": document.kind}
    )
    expected = MappingAdmissionIdentity.build(
        journey_session_id=journey_session_id,
        target_id=context.robot_id,
        target_fingerprint=context.target_fingerprint,
        candidate_index_digest=committed.candidate_index_digest,
        candidate_digest=committed.candidate_digest,
        proposal_digest=committed.proposal_digest,
        dsl_digest=dsl_digest_value,
        context_digest=context_digest(context),
        evidence_digest=context.evidence_digest,
        available_tool_catalog_digest=committed.available_tool_catalog_digest,
        scope=expected_scope,
    )
    gate = MappingAdmissionGate(confirmation_store)
    if commit is None:
        return gate.require_active(confirmation_receipt_digest, expected)
    receipt, _ = gate.commit_if_active(
        confirmation_receipt_digest,
        expected,
        commit,
    )
    return receipt


def _resolved_bindings(ir, context: CompileContext) -> tuple[dict[str, Any], ...]:
    if ir.binding:
        binding = dict(ir.binding)
        resource_id = binding.get("resource_id")
        observed = next((route for route in context.routes if route.get("resource_id") == resource_id), None)
        if observed is not None:
            binding.update(observed)
        return (binding,)
    if str(ir.kind) == "COMPOSE":
        steps = ir.composition.get("steps", ())
        if isinstance(steps, list):
            return tuple(dict(step) for step in steps if isinstance(step, dict))
    return ()


def _runtime_context(context: CompileContext) -> dict[str, Any]:
    return {"runtime_revision": context.runtime_revision} if context.runtime_revision is not None else {}


def _validate_staged_bundle(
    staging_path: Path,
    bundle: Any,
    *,
    document: DslDocument,
    ir: Any,
    dsl_digest_value: str,
    context_digest_value: str,
    target_fingerprint: str,
    compiler_version: str,
    backend_id: str,
    negotiated_capabilities: tuple[str, ...],
) -> None:
    """Validate the exact staged file set before an admission-locked commit."""

    root = staging_path.resolve()
    manifest_path = root / "manifest.json"
    declared = {"manifest.json"}
    try:
        if manifest_path.is_symlink() or not manifest_path.is_file():
            raise ValueError("BUNDLE_MANIFEST_MISSING")
        persisted_manifest = loads_unique_json(manifest_path.read_text(encoding="utf-8"))
        if persisted_manifest != bundle.manifest.model_dump(mode="json"):
            raise ValueError("BUNDLE_MANIFEST_MISMATCH")
        expected_identity = {
            "tool_id": document.tool_id,
            "kind": ir.kind,
            "target_fingerprint": target_fingerprint,
            "dsl_digest": dsl_digest_value,
            "context_digest": context_digest_value,
            "ir_digest": ir_digest(ir),
            "compiler_version": compiler_version,
            "backend_id": backend_id,
            "negotiated_capabilities": negotiated_capabilities,
        }
        for field, expected in expected_identity.items():
            if getattr(bundle.manifest, field) != expected:
                raise ValueError(f"BUNDLE_{field.upper()}_MISMATCH")
        if bundle.backend_id != backend_id:
            raise ValueError("BUNDLE_BACKEND_ID_MISMATCH")
        if bundle.digest != bundle_plan_digest(bundle.manifest):
            raise ValueError("BUNDLE_DIGEST_MISMATCH")
        for artifact in bundle.manifest.artifacts:
            artifact_path = (root / artifact.path).resolve()
            try:
                relative = artifact_path.relative_to(root).as_posix()
            except ValueError as exc:
                raise ValueError("BUNDLE_ARTIFACT_PATH_INVALID") from exc
            if artifact_path.is_symlink() or not artifact_path.is_file():
                raise ValueError("BUNDLE_ARTIFACT_MISSING")
            payload = artifact_path.read_bytes()
            if len(payload) != artifact.size:
                raise ValueError("BUNDLE_ARTIFACT_SIZE_MISMATCH")
            if "sha256:" + hashlib.sha256(payload).hexdigest() != artifact.sha256:
                raise ValueError("BUNDLE_ARTIFACT_DIGEST_MISMATCH")
            declared.add(relative)
        paths = tuple(root.rglob("*"))
        if any(path.is_symlink() for path in paths):
            raise ValueError("BUNDLE_ARTIFACT_SYMLINK_REJECTED")
        actual = {
            path.resolve().relative_to(root).as_posix()
            for path in paths
            if path.is_file()
        }
        if actual != declared:
            raise ValueError("BUNDLE_ARTIFACT_SET_MISMATCH")
    except (AttributeError, KeyError, TypeError, json.JSONDecodeError, OSError) as exc:
        raise ValueError("BUNDLE_STAGE_INVALID") from exc
