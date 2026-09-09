"""Offline targetd DSL service with idempotent compile cache."""

import hashlib
import json
import os
import shutil
import tempfile
from collections.abc import Mapping
from pathlib import Path

from rolo.core.persistence import interprocess_lock
from rolo.dsl.admission import (
    MappingAdmissionError,
    MappingAdmissionGate,
    MappingAdmissionIdentity,
    MappingAdmissionScope,
    MappingConfirmationReceipt,
    MappingConfirmationStore,
    ProductionMappingConfirmationStore,
    bind_mapping_admission_gate,
)
from rolo.dsl.api import DslCheckRequest, DslCompileRequest
from rolo.dsl.bundle_plan import parse_bundle_plan
from rolo.dsl.canonical import bundle_plan_digest, context_digest, dsl_digest
from rolo.dsl.context import ProbeContext
from rolo.dsl.contracts import COMPILE_CONTEXT_SCHEMA_VERSION, DSL_SCHEMA_VERSION, TARGET_CONFORMANCE_SCHEMA_VERSION, require_version
from rolo.dsl.parser import loads_unique_json, parse_document
from rolo.dsl.report import ConformanceReport
from rolo.dsl.service import RoloDslCompiler
from rolo.dsl.source_bundle import SourceBundleManifest
from rolo.dsl.target_conformance import TargetConformanceReport, TargetGateProof

from .dsl_protocol import DslCompilePayload, DslFrame, DslFrameType, DslPutPayload
from .ros2_runtime import Ros2RuntimeResolver
from .runtime_backend import RuntimeBackendRegistry


class TargetdDslService:
    def __init__(
        self,
        cache_dir: str | Path,
        *,
        runtime_resolver: Ros2RuntimeResolver | None = None,
        backend_registry: RuntimeBackendRegistry | None = None,
        confirmation_store: (
            MappingConfirmationStore | ProductionMappingConfirmationStore | None
        ) = None,
        admission_gate: MappingAdmissionGate | None = None,
        allow_unbound_runtime: bool = False,
    ):
        """Create a targetd DSL service.

        Compile and conformance are fail-closed unless a trusted Mapping
        confirmation store is supplied.  Target conformance additionally
        requires both a target runtime resolver and an execution backend
        registry.  The
        ``allow_unbound_runtime`` escape hatch is intentionally explicit for
        offline/fake-target replay only; it must not be enabled by a real
        targetd entrypoint.
        """

        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self._puts: dict[str, DslPutPayload] = {}
        self.compiler = RoloDslCompiler(confirmation_store)
        self.runtime_resolver = runtime_resolver
        self.backend_registry = backend_registry
        self.confirmation_store = confirmation_store
        self.admission_gate = bind_mapping_admission_gate(
            confirmation_store,
            admission_gate,
        )
        self.allow_unbound_runtime = bool(allow_unbound_runtime)

    def handle(self, frame: DslFrame) -> DslFrame:
        if frame.frame_type == DslFrameType.DSL_PUT:
            return self._put(frame)
        if frame.frame_type == DslFrameType.DSL_CHECK:
            return self._check(frame)
        if frame.frame_type == DslFrameType.PLAN_RESOLVE:
            return self._resolve(frame)
        if frame.frame_type == DslFrameType.TARGET_COMPILE:
            return self._compile(frame)
        if frame.frame_type == DslFrameType.TARGET_CONFORMANCE:
            return self._conformance(frame)
        if frame.frame_type == DslFrameType.DSL_COMPILE:
            return self._compile(frame)
        return DslFrame(frame_type=DslFrameType.DSL_EVENT, request_id=frame.request_id, payload={"code": "FRAME_UNSUPPORTED", "message": frame.frame_type})

    def verified_release_inputs(
        self,
        cache_key: str,
        journey_session_id: str,
    ) -> dict[str, object]:
        """Rebuild release inputs solely from target-owned verified cache data.

        The caller supplies only an opaque cache locator and the daemon-owned
        journey session.  Every release identity is reloaded from the compile
        and target-conformance artifacts, rebound to the trusted Mapping
        ledger, and returned only while that confirmation is still active.
        """

        if not isinstance(cache_key, str) or len(cache_key) != 64 or any(character not in "0123456789abcdef" for character in cache_key):
            raise ValueError("VERIFIED_RELEASE_CACHE_KEY_INVALID")
        if not isinstance(journey_session_id, str) or not journey_session_id:
            raise MappingAdmissionError("MAPPING_JOURNEY_SESSION_REQUIRED")
        if self.confirmation_store is None or self.admission_gate is None:
            raise MappingAdmissionError("MAPPING_CONFIRMATION_STORE_REQUIRED")

        artifact_dir = self.cache_dir / cache_key
        conformance_dir = artifact_dir / "target-conformance"
        conformance_lock = self.cache_dir / f"{cache_key}.conformance"
        with interprocess_lock(conformance_lock, timeout_s=60.0):
            self._reject_verified_release_symlinks(artifact_dir, conformance_dir)
            seed = self._load_verified_json(
                artifact_dir / "result.json",
                "VERIFIED_RELEASE_COMPILE_CACHE_INVALID",
            )
            receipt_digest = seed.get("confirmation_receipt_digest")
            if not isinstance(receipt_digest, str):
                raise MappingAdmissionError("MAPPING_CONFIRMATION_DIGEST_INVALID")
            receipt = self.confirmation_store.resolve(receipt_digest)
            expected_identity = self._mapping_identity_from_compile_cache(
                seed,
                journey_session_id,
                receipt,
            )
            _, verified = self.admission_gate.commit_if_active(
                receipt_digest,
                expected_identity,
                lambda: self._verify_release_cache(
                    cache_key,
                    journey_session_id,
                    artifact_dir,
                    conformance_dir,
                    receipt,
                    expected_identity,
                ),
            )
            return verified

    def _put(self, frame: DslFrame) -> DslFrame:
        try:
            payload = DslPutPayload.model_validate(frame.payload)
        except ValueError:
            return self._error(frame, "DSL_PUT_SCHEMA_INVALID", blocked=True)
        try:
            require_version({"schema_version": payload.dsl_schema_version}, "schema_version", DSL_SCHEMA_VERSION)
            require_version(payload.dsl, "schema_version", DSL_SCHEMA_VERSION)
        except ValueError:
            return self._error(frame, "DSL_SCHEMA_VERSION_UNSUPPORTED", blocked=True)
        try:
            require_version({"schema_version": payload.context_schema_version}, "schema_version", COMPILE_CONTEXT_SCHEMA_VERSION)
            require_version(payload.context, "schema_version", COMPILE_CONTEXT_SCHEMA_VERSION)
        except ValueError:
            return self._error(frame, "CONTEXT_SCHEMA_VERSION_UNSUPPORTED", blocked=True)
        try:
            ProbeContext.model_validate(payload.context)
        except ValueError:
            return self._error(frame, "CONTEXT_REQUIRED", blocked=True)
        document, report = parse_document(payload.dsl)
        if document is None or not report.ok or dsl_digest(document) != payload.dsl_digest:
            return self._error(frame, "DSL_DIGEST_MISMATCH")
        if context_digest(payload.context) != payload.context_digest:
            return self._error(frame, "CONTEXT_DIGEST_MISMATCH")
        context_target = payload.context.get("target_fingerprint")
        if context_target is not None and context_target != payload.target_fingerprint:
            return self._error(frame, "TARGET_FINGERPRINT_MISMATCH")
        previous = self._puts.get(payload.dsl_digest)
        if previous is not None and (
            previous.context_digest != payload.context_digest
            or previous.target_fingerprint != payload.target_fingerprint
            or previous.compiler_version != payload.compiler_version
            or previous.journey_session_id != payload.journey_session_id
        ):
            return self._error(frame, "DSL_DIGEST_REBOUND")
        self._puts[payload.dsl_digest] = payload
        return DslFrame(frame_type=DslFrameType.DSL_EVENT, request_id=frame.request_id, payload={"phase": "PUT", "dsl_digest": payload.dsl_digest})

    def _check(self, frame: DslFrame) -> DslFrame:
        digest = frame.payload.get("dsl_digest")
        put = self._puts.get(digest)
        if put is None:
            return self._error(frame, "DSL_NOT_FOUND")
        result = self.compiler.check(DslCheckRequest(dsl=put.dsl, context=put.context, compiler_version=put.compiler_version))
        if result.status == "PASS" and self.runtime_resolver is not None:
            binding = put.dsl.get("binding") if isinstance(put.dsl.get("binding"), dict) else {}
            resource_id = binding.get("resource_id")
            if isinstance(resource_id, str) and (resource_id.startswith("/") or resource_id.startswith("route:/")):
                try:
                    self.runtime_resolver.resolve_binding(binding)
                except ValueError as exc:
                    result = result.model_copy(update={"status": "DSL_CHECK_FAILED", "diagnostics": (str(exc),)})
        if result.status == "PASS" and self.backend_registry is not None:
            try:
                self._resolve_backend(put.dsl)
            except ValueError as exc:
                result = result.model_copy(update={"status": "DSL_CHECK_FAILED", "diagnostics": (str(exc),)})
        return DslFrame(frame_type=DslFrameType.DSL_RESULT, request_id=frame.request_id, payload={"status": result.status, "dsl_digest": result.dsl_digest, "diagnostics": result.diagnostics})

    def _resolve(self, frame: DslFrame) -> DslFrame:
        digest = frame.payload.get("dsl_digest")
        put = self._puts.get(digest)
        if put is None:
            return self._error(frame, "DSL_NOT_FOUND")
        result = self.compiler.check(DslCheckRequest(dsl=put.dsl, context=put.context, compiler_version=put.compiler_version))
        if result.status == "PASS" and self.runtime_resolver is not None:
            binding = put.dsl.get("binding") if isinstance(put.dsl.get("binding"), dict) else {}
            resource_id = binding.get("resource_id")
            if isinstance(resource_id, str) and (resource_id.startswith("/") or resource_id.startswith("route:/")):
                try:
                    self.runtime_resolver.resolve_binding(binding)
                except ValueError as exc:
                    result = result.model_copy(update={"status": "DSL_CHECK_FAILED", "diagnostics": (str(exc),)})
        if result.status == "PASS" and self.backend_registry is not None:
            try:
                self._resolve_backend(put.dsl)
            except ValueError as exc:
                result = result.model_copy(update={"status": "DSL_CHECK_FAILED", "diagnostics": (str(exc),)})
        return DslFrame(
            frame_type=DslFrameType.DSL_RESULT,
            request_id=frame.request_id,
            payload={"phase": "PLAN_RESOLVE", "status": result.status, "dsl_digest": result.dsl_digest, "diagnostics": result.diagnostics},
        )

    def _compile(self, frame: DslFrame) -> DslFrame:
        try:
            payload = DslCompilePayload.model_validate(frame.payload)
        except ValueError:
            return self._error(frame, "DSL_COMPILE_SCHEMA_INVALID", blocked=True)
        put = self._puts.get(payload.dsl_digest)
        if put is None:
            return self._error(frame, "DSL_NOT_FOUND")
        if put.journey_session_id is not None and put.journey_session_id != payload.journey_session_id:
            return self._error(frame, "JOURNEY_SESSION_MISMATCH", blocked=True)
        if payload.context_digest != put.context_digest or payload.target_fingerprint != put.target_fingerprint:
            return self._error(frame, "TARGET_BINDING_MISMATCH")
        try:
            self._require_active_confirmation(put, payload)
        except MappingAdmissionError as exc:
            return self._error(frame, exc.code, blocked=True)
        except ValueError:
            return self._error(
                frame,
                "MAPPING_CONFIRMATION_IDENTITY_INVALID",
                blocked=True,
            )
        try:
            self._validate_source_bundle(put.dsl, payload)
        except ValueError as exc:
            return self._error(frame, str(exc))
        if self.runtime_resolver is not None:
            binding = put.dsl.get("binding") if isinstance(put.dsl.get("binding"), dict) else {}
            resource_id = binding.get("resource_id")
            if isinstance(resource_id, str) and (resource_id.startswith("/") or resource_id.startswith("route:/")):
                try:
                    self.runtime_resolver.resolve_binding(binding)
                except ValueError as exc:
                    return self._error(frame, str(exc))
        required_capabilities = self._normalize_capabilities(payload.required_capabilities)
        required_runtime_capabilities = self._normalize_capabilities(payload.required_runtime_capabilities)
        resolved_backend = None
        if self.backend_registry is not None:
            try:
                resolved_backend = self._resolve_backend(
                    put.dsl,
                    backend_hint=payload.runtime_backend_hint,
                    required_capabilities=required_runtime_capabilities,
                )
            except ValueError as exc:
                return self._error(frame, str(exc))
        key = self._cache_key(
            payload,
            put,
            required_capabilities,
            required_runtime_capabilities,
        )
        artifact_dir = self.cache_dir / key
        result_file = artifact_dir / "result.json"
        compile_lock = self.cache_dir / f"{key}.compile"
        with interprocess_lock(compile_lock):
            if result_file.exists():
                return self._cached_compile_response(
                    frame,
                    put,
                    payload,
                    key=key,
                    artifact_dir=artifact_dir,
                    resolved_backend=resolved_backend,
                )
            try:
                receipt = self._require_active_confirmation(put, payload)
            except MappingAdmissionError as exc:
                return self._error(frame, exc.code, blocked=True)
            except ValueError:
                return self._error(
                    frame,
                    "MAPPING_CONFIRMATION_IDENTITY_INVALID",
                    blocked=True,
                )

            staging_root = Path(tempfile.mkdtemp(prefix=f".{key[:12]}.targetd-", dir=self.cache_dir))
            staged_artifact_dir = staging_root / "compiled"
            try:
                result = self.compiler.compile(
                    DslCompileRequest(
                        schema_version="rolo-dsl-compile-request/v2",
                        request_id=frame.request_id,
                        journey_session_id=payload.journey_session_id,
                        confirmation_receipt_digest=payload.confirmation_receipt_digest,
                        dsl=put.dsl,
                        context=put.context,
                        compiler_version=put.compiler_version,
                        dsl_digest=payload.dsl_digest,
                        context_digest=payload.context_digest,
                        target_fingerprint=payload.target_fingerprint,
                        source_bundle_digest=payload.source_bundle_digest,
                        backend_id=payload.backend_hint,
                        required_capabilities=required_capabilities,
                    ),
                    staged_artifact_dir,
                )
                data = {
                    "phase": "TARGET_COMPILE",
                    "status": result.status,
                    "dsl_digest": result.dsl_digest,
                    "ir_digest": result.ir_digest,
                    "bundle_digest": result.bundle_digest,
                    "context_digest": payload.context_digest,
                    "compiler_version": put.compiler_version,
                    "diagnostics": result.diagnostics,
                    "cache_hit": False,
                    "cache_key": key,
                    "target_id": put.context["robot_id"],
                    "target_fingerprint": payload.target_fingerprint,
                    "target_identity_digest": receipt.target_identity_digest,
                    "evidence_digest": put.context["evidence_digest"],
                    "tool_id": put.dsl["tool_id"],
                    "operation_kind": put.dsl["kind"],
                    "backend_hint": payload.backend_hint,
                    "runtime_backend_hint": payload.runtime_backend_hint,
                    "required_capabilities": required_capabilities,
                    "required_runtime_capabilities": required_runtime_capabilities,
                    "journey_session_id": payload.journey_session_id,
                    "confirmation_receipt_digest": payload.confirmation_receipt_digest,
                }
                if result.status != "PASS" or not staged_artifact_dir.is_dir():
                    data["artifact_digest"] = self._cache_digest(data)
                    return DslFrame(
                        frame_type=DslFrameType.DSL_RESULT,
                        request_id=frame.request_id,
                        payload=data,
                    )
                try:
                    manifest = loads_unique_json((staged_artifact_dir / "manifest.json").read_text(encoding="utf-8"))
                except (OSError, ValueError):
                    return self._error(frame, "COMPILE_MANIFEST_INVALID")
                if not isinstance(manifest, dict):
                    return self._error(frame, "COMPILE_MANIFEST_INVALID")
                runtime_backend_id = resolved_backend.backend_id if resolved_backend is not None else "offline-unbound"
                resolved_binding = resolved_backend.binding if resolved_backend is not None else {"mode": "offline-unbound"}
                data.update(
                    {
                        "compile_artifacts": result.artifacts,
                        "compile_artifact_digest": self._compile_artifact_digest(staged_artifact_dir, result.artifacts),
                        "compiler_backend_id": result.backend_id,
                        "compiler_backend_version": manifest.get("backend_version"),
                        "negotiated_capabilities": manifest.get("negotiated_capabilities", ()),
                        "runtime_backend_id": runtime_backend_id,
                        "runtime_binding_digest": self._json_digest(resolved_binding),
                        # Retained as a compatibility projection for existing
                        # targetd runtime consumers.
                        "backend_id": runtime_backend_id,
                        "resolved_binding": resolved_binding,
                    }
                )
                if any(
                    not isinstance(data.get(field), str) or not data[field]
                    for field in (
                        "ir_digest",
                        "bundle_digest",
                        "compiler_backend_id",
                        "compiler_backend_version",
                    )
                ):
                    return self._error(frame, "COMPILE_IDENTITY_INCOMPLETE")
                data["artifact_digest"] = self._cache_digest(data)

                assert self.admission_gate is not None

                def commit() -> None:
                    if artifact_dir.exists():
                        raise FileExistsError("TARGET_COMPILE_CACHE_EXISTS")
                    (staged_artifact_dir / "result.json").write_text(json.dumps(data, sort_keys=True), encoding="utf-8")
                    os.replace(staged_artifact_dir, artifact_dir)

                try:
                    self.admission_gate.commit_if_active(
                        payload.confirmation_receipt_digest,
                        receipt.admission_identity(),
                        commit,
                    )
                except MappingAdmissionError as exc:
                    return self._error(frame, exc.code, blocked=True)
                return DslFrame(
                    frame_type=DslFrameType.DSL_RESULT,
                    request_id=frame.request_id,
                    payload=data,
                )
            finally:
                shutil.rmtree(staging_root, ignore_errors=True)

    def _cached_compile_response(
        self,
        frame: DslFrame,
        put: DslPutPayload,
        payload: DslCompilePayload,
        *,
        key: str,
        artifact_dir: Path,
        resolved_backend: object | None,
    ) -> DslFrame:
        try:
            self._require_active_confirmation(put, payload)
        except MappingAdmissionError as exc:
            return self._error(frame, exc.code, blocked=True)
        except ValueError:
            return self._error(
                frame,
                "MAPPING_CONFIRMATION_IDENTITY_INVALID",
                blocked=True,
            )
        result_file = artifact_dir / "result.json"
        try:
            data = loads_unique_json(result_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return self._error(frame, "CACHE_ARTIFACT_INVALID")
        if not isinstance(data, dict):
            return self._error(frame, "CACHE_ARTIFACT_INVALID")
        error = self._compile_cache_error(
            data,
            payload,
            expected_key=key,
            artifact_dir=artifact_dir,
            resolved_backend=resolved_backend,
        )
        if error is not None:
            return self._error(
                frame,
                error,
                blocked=error == "CACHE_ADMISSION_MISMATCH",
            )
        data["cache_hit"] = True
        data.setdefault("phase", "TARGET_COMPILE")
        data["artifact_digest"] = self._cache_digest(data)
        return DslFrame(
            frame_type=DslFrameType.DSL_RESULT,
            request_id=frame.request_id,
            payload=data,
        )

    def _conformance(self, frame: DslFrame) -> DslFrame:
        try:
            payload = DslCompilePayload.model_validate(frame.payload)
        except ValueError:
            return self._error(frame, "DSL_CONFORMANCE_SCHEMA_INVALID", blocked=True)
        put = self._puts.get(payload.dsl_digest)
        if put is None:
            return self._error(frame, "DSL_NOT_FOUND")
        if put.journey_session_id is not None and put.journey_session_id != payload.journey_session_id:
            return self._error(frame, "JOURNEY_SESSION_MISMATCH", blocked=True)
        if payload.context_digest != put.context_digest or payload.target_fingerprint != put.target_fingerprint:
            return self._error(frame, "TARGET_BINDING_MISMATCH")
        try:
            self._require_active_confirmation(put, payload)
        except MappingAdmissionError as exc:
            return self._error(frame, exc.code, blocked=True)
        except ValueError:
            return self._error(
                frame,
                "MAPPING_CONFIRMATION_IDENTITY_INVALID",
                blocked=True,
            )
        try:
            self._validate_source_bundle(put.dsl, payload)
        except ValueError as exc:
            return self._error(frame, str(exc))
        if self.runtime_resolver is not None:
            binding = put.dsl.get("binding") if isinstance(put.dsl.get("binding"), dict) else {}
            resource_id = binding.get("resource_id")
            if isinstance(resource_id, str) and (resource_id.startswith("/") or resource_id.startswith("route:/")):
                try:
                    self.runtime_resolver.resolve_binding(binding)
                except ValueError as exc:
                    return self._error(frame, str(exc))
        required_capabilities = self._normalize_capabilities(payload.required_capabilities)
        required_runtime_capabilities = self._normalize_capabilities(payload.required_runtime_capabilities)
        resolved_backend = None
        if self.backend_registry is not None:
            try:
                resolved_backend = self._resolve_backend(
                    put.dsl,
                    backend_hint=payload.runtime_backend_hint,
                    required_capabilities=required_runtime_capabilities,
                )
            except ValueError as exc:
                return self._error(frame, str(exc))
        expected_key = self._cache_key(
            payload,
            put,
            required_capabilities,
            required_runtime_capabilities,
        )
        artifact_dir = self.cache_dir / expected_key
        result_file = artifact_dir / "result.json"
        if not result_file.exists():
            return self._error(frame, "TARGET_COMPILE_REQUIRED")
        conformance_dir = artifact_dir / "target-conformance"
        conformance_result = conformance_dir / "result.json"
        conformance_lock = self.cache_dir / f"{expected_key}.conformance"
        with interprocess_lock(conformance_lock, timeout_s=60.0):
            try:
                receipt = self._require_active_confirmation(put, payload)
            except MappingAdmissionError as exc:
                return self._error(frame, exc.code, blocked=True)
            except ValueError:
                return self._error(
                    frame,
                    "MAPPING_CONFIRMATION_IDENTITY_INVALID",
                    blocked=True,
                )
            if conformance_result.exists():
                return self._cached_conformance_response(
                    frame,
                    put,
                    payload,
                    expected_key=expected_key,
                    artifact_dir=artifact_dir,
                    conformance_dir=conformance_dir,
                    resolved_backend=resolved_backend,
                )
            try:
                data = loads_unique_json(result_file.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                return self._error(frame, "CACHE_ARTIFACT_INVALID")
            if not isinstance(data, dict):
                return self._error(frame, "CACHE_ARTIFACT_INVALID")
            cache_error = self._compile_cache_error(
                data,
                payload,
                expected_key=expected_key,
                artifact_dir=artifact_dir,
                resolved_backend=resolved_backend,
            )
            if cache_error is not None:
                return self._error(
                    frame,
                    cache_error,
                    blocked=cache_error == "CACHE_ADMISSION_MISMATCH",
                )

            assert self.admission_gate is not None
            try:
                _, response = self.admission_gate.commit_if_active(
                    payload.confirmation_receipt_digest,
                    receipt.admission_identity(),
                    lambda: self._execute_and_commit_conformance(
                        frame,
                        put,
                        payload,
                        data,
                        expected_key=expected_key,
                        conformance_dir=conformance_dir,
                        required_capabilities=required_capabilities,
                        required_runtime_capabilities=required_runtime_capabilities,
                    ),
                )
            except MappingAdmissionError as exc:
                return self._error(frame, exc.code, blocked=True)
            return response

    def _execute_and_commit_conformance(
        self,
        frame: DslFrame,
        put: DslPutPayload,
        payload: DslCompilePayload,
        data: dict,
        *,
        expected_key: str,
        conformance_dir: Path,
        required_capabilities: tuple[str, ...],
        required_runtime_capabilities: tuple[str, ...],
    ) -> DslFrame:
        """Run T3 and commit all conformance evidence under one admission lock."""

        status = data.get("status")
        compile_gate = "PASS" if status == "PASS" else "FAIL"
        runtime_gate = compile_gate
        runtime_diagnostics: list[str] = []
        runtime_unbound = self.runtime_resolver is None or self.backend_registry is None
        target_gate = compile_gate
        runtime_result: Mapping[str, object] = {
            "status": "SUCCEEDED",
            "mode": "offline-unbound",
        }
        if runtime_unbound and not self.allow_unbound_runtime:
            target_gate = "FAIL"
            runtime_gate = "FAIL"
            runtime_result = {
                "status": "BLOCKED",
                "error": "TARGET_RUNTIME_UNBOUND",
            }
            runtime_diagnostics.append("TARGET_RUNTIME_UNBOUND")
        elif compile_gate == "PASS" and self.backend_registry is not None:
            document, document_report = parse_document(put.dsl)
            if document is None or not document_report.ok:
                runtime_gate = "FAIL"
                runtime_result = {
                    "status": "FAILED",
                    "error": "DSL_COMPILE_FAILED",
                }
                runtime_diagnostics.append("DSL_COMPILE_FAILED")
            else:
                try:
                    candidate_result = self.backend_registry.execute(
                        document.kind.value,
                        document.binding,
                        {},
                    )
                    if not isinstance(candidate_result, Mapping):
                        raise TypeError("runtime result must be a mapping")
                    # Prove that the result is deterministic JSON before
                    # accepting it as target evidence. Raw observations are
                    # hashed below and are not persisted in the cache.
                    self._json_digest(candidate_result)
                    runtime_result = candidate_result
                    runtime_status = str(candidate_result.get("status", "")).upper()
                    runtime_gate = "PASS" if runtime_status in {"PASS", "PASSED", "SUCCESS", "SUCCEEDED"} else "FAIL"
                    if runtime_gate == "FAIL":
                        runtime_diagnostics.append(str(candidate_result.get("error", "RUNTIME_BEHAVIOR_FAILED")))
                except Exception as exc:
                    runtime_gate = "FAIL"
                    runtime_result = {
                        "status": "FAILED",
                        "error": type(exc).__name__,
                    }
                    runtime_diagnostics.append(f"RUNTIME_BEHAVIOR_FAILED:{type(exc).__name__}:{exc}")

        diagnostics = tuple(dict.fromkeys([*data.get("diagnostics", ()), *runtime_diagnostics]))
        runtime_result_digest = self._json_digest(runtime_result)
        idempotency_key = "sha256:" + expected_key
        proof_payloads = (
            (
                "T1",
                target_gate,
                "target-conformance/t1-target-resolve.json",
                {
                    "gate": "T1",
                    "status": target_gate,
                    "target_id": data["target_id"],
                    "target_fingerprint": data["target_fingerprint"],
                    "target_identity_digest": data["target_identity_digest"],
                    "context_digest": data["context_digest"],
                    "evidence_digest": data["evidence_digest"],
                    "runtime_backend_id": data["runtime_backend_id"],
                    "runtime_binding_digest": data["runtime_binding_digest"],
                    "required_runtime_capabilities": data["required_runtime_capabilities"],
                },
            ),
            (
                "T2",
                compile_gate,
                "target-conformance/t2-bundle-build.json",
                {
                    "gate": "T2",
                    "status": compile_gate,
                    "dsl_digest": data["dsl_digest"],
                    "context_digest": data["context_digest"],
                    "ir_digest": data["ir_digest"],
                    "bundle_digest": data["bundle_digest"],
                    "compile_artifact_digest": data["compile_artifact_digest"],
                    "compiler_backend_id": data["compiler_backend_id"],
                    "compiler_backend_version": data["compiler_backend_version"],
                },
            ),
            (
                "T3",
                runtime_gate,
                "target-conformance/t3-runtime-behavior.json",
                {
                    "gate": "T3",
                    "status": runtime_gate,
                    "runtime_backend_id": data["runtime_backend_id"],
                    "runtime_binding_digest": data["runtime_binding_digest"],
                    "runtime_result_digest": runtime_result_digest,
                    "required_runtime_capabilities": data["required_runtime_capabilities"],
                    "conformance_idempotency_key": idempotency_key,
                },
            ),
            (
                "T4",
                compile_gate,
                "target-conformance/t4-release-integrity.json",
                {
                    "gate": "T4",
                    "status": compile_gate,
                    "tool_id": data["tool_id"],
                    "operation_kind": data["operation_kind"],
                    "target_identity_digest": data["target_identity_digest"],
                    "dsl_digest": data["dsl_digest"],
                    "context_digest": data["context_digest"],
                    "ir_digest": data["ir_digest"],
                    "bundle_digest": data["bundle_digest"],
                    "confirmation_receipt_digest": data["confirmation_receipt_digest"],
                },
            ),
        )
        proofs = tuple(
            TargetGateProof(
                gate=gate_name,
                status=gate_status,
                evidence_ref=evidence_ref,
                evidence_digest=self._json_digest(evidence),
            )
            for gate_name, gate_status, evidence_ref, evidence in proof_payloads
        )
        report = TargetConformanceReport(
            schema_version=TARGET_CONFORMANCE_SCHEMA_VERSION,
            t1_target_resolve=target_gate,
            t2_bundle_build=compile_gate,
            t3_runtime_behavior=runtime_gate,
            t4_release_integrity=compile_gate,
            tool_id=data["tool_id"],
            operation_kind=data["operation_kind"],
            target_id=data["target_id"],
            target_fingerprint=data["target_fingerprint"],
            target_identity_digest=data["target_identity_digest"],
            evidence_digest=data["evidence_digest"],
            dsl_digest=data["dsl_digest"],
            context_digest=data["context_digest"],
            ir_digest=data["ir_digest"],
            bundle_digest=data["bundle_digest"],
            compile_artifact_digest=data["compile_artifact_digest"],
            compiler_version=data["compiler_version"],
            compiler_backend_id=data["compiler_backend_id"],
            compiler_backend_version=data["compiler_backend_version"],
            runtime_backend_id=data["runtime_backend_id"],
            runtime_binding_digest=data["runtime_binding_digest"],
            runtime_result_digest=runtime_result_digest,
            required_capabilities=required_capabilities,
            required_runtime_capabilities=required_runtime_capabilities,
            negotiated_capabilities=data["negotiated_capabilities"],
            journey_session_id=payload.journey_session_id,
            confirmation_receipt_digest=payload.confirmation_receipt_digest,
            conformance_idempotency_key=idempotency_key,
            proofs=proofs,
            diagnostics=diagnostics,
        )
        report_payload = report.model_dump(mode="json")
        report_digest = self._json_digest(report_payload)
        response_data = dict(data)
        response_data.update(
            {
                "phase": "TARGET_CONFORMANCE",
                "target_conformance": "PASS" if report.passed else "FAIL",
                "target_conformance_report": report_payload,
                "target_conformance_digest": report_digest,
                "conformance_idempotency_key": idempotency_key,
                "conformance_cache_hit": False,
            }
        )
        response_data["artifact_digest"] = self._cache_digest(response_data)

        staged_conformance = Path(
            tempfile.mkdtemp(
                prefix=f".{expected_key[:12]}.conformance-",
                dir=self.cache_dir,
            )
        )
        try:
            for (_gate, _status, evidence_ref, evidence), proof in zip(
                proof_payloads,
                proofs,
                strict=True,
            ):
                path = staged_conformance / Path(evidence_ref).name
                path.write_text(
                    json.dumps(
                        evidence,
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                    encoding="utf-8",
                )
                if self._file_digest(path) != proof.evidence_digest:
                    return self._error(frame, "CONFORMANCE_PROOF_WRITE_FAILED")
            (staged_conformance / "report.json").write_text(
                json.dumps(
                    report_payload,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ),
                encoding="utf-8",
            )
            (staged_conformance / "result.json").write_text(
                json.dumps(response_data, sort_keys=True),
                encoding="utf-8",
            )
            if conformance_dir.exists():
                raise FileExistsError("TARGET_CONFORMANCE_CACHE_EXISTS")
            os.replace(staged_conformance, conformance_dir)
        finally:
            shutil.rmtree(staged_conformance, ignore_errors=True)
        return DslFrame(
            frame_type=DslFrameType.DSL_RESULT,
            request_id=frame.request_id,
            payload=response_data,
        )

    def _verify_release_cache(
        self,
        cache_key: str,
        journey_session_id: str,
        artifact_dir: Path,
        conformance_dir: Path,
        receipt: MappingConfirmationReceipt,
        expected_identity: MappingAdmissionIdentity,
    ) -> dict[str, object]:
        """Validate the complete cache snapshot while Mapping is fenced."""

        self._reject_verified_release_symlinks(artifact_dir, conformance_dir)
        compile_data = self._load_verified_json(
            artifact_dir / "result.json",
            "VERIFIED_RELEASE_COMPILE_CACHE_INVALID",
        )
        self._validate_verified_compile_cache(
            compile_data,
            cache_key=cache_key,
            artifact_dir=artifact_dir,
        )
        current_identity = self._mapping_identity_from_compile_cache(
            compile_data,
            journey_session_id,
            receipt,
        )
        if current_identity != expected_identity:
            raise MappingAdmissionError("MAPPING_CONFIRMATION_IDENTITY_INVALID")

        target_report = self._validate_verified_target_conformance(
            compile_data,
            cache_key=cache_key,
            journey_session_id=journey_session_id,
            conformance_dir=conformance_dir,
        )
        diagnostics = compile_data.get("diagnostics")
        if not isinstance(diagnostics, list) or any(not isinstance(item, str) for item in diagnostics):
            raise ValueError("VERIFIED_RELEASE_COMPILE_CACHE_INVALID")
        compiler_conformance = ConformanceReport(
            c1_dsl="PASS",
            c2_evidence="PASS",
            c3_compile="PASS",
            c4_behavior="PASS",
            diagnostics=tuple(diagnostics),
        )
        conformance_json = json.dumps(
            compiler_conformance.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
        )
        conformance_digest = "sha256:" + hashlib.sha256(conformance_json.encode()).hexdigest()
        target_report_payload = target_report.model_dump(mode="json")
        return {
            "cache_key": cache_key,
            "tool_id": compile_data["tool_id"],
            "target_id": compile_data["target_id"],
            "operation_kind": compile_data["operation_kind"],
            "dsl_digest": compile_data["dsl_digest"],
            "ir_digest": compile_data["ir_digest"],
            "bundle_digest": compile_data["bundle_digest"],
            "evidence_digest": compile_data["evidence_digest"],
            "compiler_version": compile_data["compiler_version"],
            "context_digest": compile_data["context_digest"],
            "target_fingerprint": compile_data["target_fingerprint"],
            "target_identity_digest": compile_data["target_identity_digest"],
            "compile_artifact_digest": compile_data["compile_artifact_digest"],
            "target_conformance_digest": self._json_digest(target_report_payload),
            "conformance_digest": conformance_digest,
            "journey_session_id": journey_session_id,
            "mapping_confirmation_receipt_digest": receipt.receipt_digest,
            "mapping_admission": current_identity.model_dump(mode="json"),
            "mapping_confirmation_receipt": receipt.model_dump(mode="json"),
            "compiler_conformance": compiler_conformance.model_dump(mode="json"),
            "target_conformance_report": target_report_payload,
        }

    def _validate_verified_compile_cache(
        self,
        data: dict,
        *,
        cache_key: str,
        artifact_dir: Path,
    ) -> None:
        if data.get("phase") != "TARGET_COMPILE" or data.get("status") != "PASS" or data.get("cache_key") != cache_key or not self._verify_cache_digest(data):
            raise ValueError("VERIFIED_RELEASE_COMPILE_CACHE_INVALID")
        artifacts = data.get("compile_artifacts")
        if not isinstance(artifacts, dict) or not artifacts or any(not isinstance(name, str) or not name or not isinstance(path, str) or not path for name, path in artifacts.items()):
            raise ValueError("VERIFIED_RELEASE_COMPILE_ARTIFACT_INVALID")
        try:
            artifact_digest = self._compile_artifact_digest(
                artifact_dir,
                artifacts,
            )
        except (OSError, ValueError) as exc:
            raise ValueError("VERIFIED_RELEASE_COMPILE_ARTIFACT_INVALID") from exc
        if data.get("compile_artifact_digest") != artifact_digest:
            raise ValueError("VERIFIED_RELEASE_COMPILE_ARTIFACT_DIGEST_MISMATCH")

        manifest_ref = artifacts.get("bundle_manifest")
        if manifest_ref != "manifest.json":
            raise ValueError("VERIFIED_RELEASE_COMPILE_MANIFEST_INVALID")
        manifest_payload = self._load_verified_json(
            artifact_dir / manifest_ref,
            "VERIFIED_RELEASE_COMPILE_MANIFEST_INVALID",
        )
        try:
            manifest = parse_bundle_plan(manifest_payload)
        except (TypeError, ValueError) as exc:
            raise ValueError("VERIFIED_RELEASE_COMPILE_MANIFEST_INVALID") from exc
        if manifest_payload != manifest.model_dump(mode="json"):
            raise ValueError("VERIFIED_RELEASE_COMPILE_MANIFEST_INVALID")
        expected_manifest_identity = {
            "tool_id": data.get("tool_id"),
            "kind": data.get("operation_kind"),
            "target_fingerprint": data.get("target_fingerprint"),
            "dsl_digest": data.get("dsl_digest"),
            "context_digest": data.get("context_digest"),
            "ir_digest": data.get("ir_digest"),
            "compiler_version": data.get("compiler_version"),
            "backend_id": data.get("compiler_backend_id"),
            "backend_version": data.get("compiler_backend_version"),
            "negotiated_capabilities": data.get("negotiated_capabilities"),
        }
        manifest_json = manifest.model_dump(mode="json")
        if any(manifest_json.get(field) != value for field, value in expected_manifest_identity.items()):
            raise ValueError("VERIFIED_RELEASE_COMPILE_IDENTITY_MISMATCH")
        if bundle_plan_digest(manifest) != data.get("bundle_digest"):
            raise ValueError("VERIFIED_RELEASE_BUNDLE_DIGEST_MISMATCH")

        manifest_artifacts = {item.path: item for item in manifest.artifacts}
        if set(artifacts.values()) != {"manifest.json", *manifest_artifacts}:
            raise ValueError("VERIFIED_RELEASE_COMPILE_ARTIFACT_SET_MISMATCH")
        for relative, artifact in manifest_artifacts.items():
            path = artifact_dir / relative
            if path.is_symlink() or not path.is_file():
                raise ValueError("VERIFIED_RELEASE_COMPILE_ARTIFACT_INVALID")
            try:
                payload = path.read_bytes()
            except OSError as exc:
                raise ValueError("VERIFIED_RELEASE_COMPILE_ARTIFACT_INVALID") from exc
            if len(payload) != artifact.size or "sha256:" + hashlib.sha256(payload).hexdigest() != artifact.sha256:
                raise ValueError("VERIFIED_RELEASE_COMPILE_ARTIFACT_DIGEST_MISMATCH")

    def _validate_verified_target_conformance(
        self,
        compile_data: dict,
        *,
        cache_key: str,
        journey_session_id: str,
        conformance_dir: Path,
    ) -> TargetConformanceReport:
        result_path = conformance_dir / "result.json"
        report_path = conformance_dir / "report.json"
        data = self._load_verified_json(
            result_path,
            "VERIFIED_RELEASE_TARGET_CONFORMANCE_INVALID",
        )
        report_payload = self._load_verified_json(
            report_path,
            "VERIFIED_RELEASE_TARGET_CONFORMANCE_INVALID",
        )
        if (
            data.get("phase") != "TARGET_CONFORMANCE"
            or data.get("status") != "PASS"
            or data.get("target_conformance") != "PASS"
            or data.get("cache_key") != cache_key
            or data.get("journey_session_id") != journey_session_id
            or not self._verify_cache_digest(data)
        ):
            raise ValueError("VERIFIED_RELEASE_TARGET_CONFORMANCE_INVALID")
        for field, value in compile_data.items():
            if field not in {"artifact_digest", "phase"} and data.get(field) != value:
                raise ValueError("VERIFIED_RELEASE_TARGET_CONFORMANCE_IDENTITY_MISMATCH")
        if data.get("target_conformance_report") != report_payload:
            raise ValueError("VERIFIED_RELEASE_TARGET_CONFORMANCE_REPORT_MISMATCH")
        try:
            report = TargetConformanceReport.model_validate(report_payload)
        except ValueError as exc:
            raise ValueError("VERIFIED_RELEASE_TARGET_CONFORMANCE_REPORT_INVALID") from exc
        canonical_report = report.model_dump(mode="json")
        if canonical_report != report_payload:
            raise ValueError("VERIFIED_RELEASE_TARGET_CONFORMANCE_REPORT_INVALID")
        target_digest = self._json_digest(canonical_report)
        if data.get("target_conformance_digest") != target_digest or self._file_digest(report_path) != target_digest:
            raise ValueError("VERIFIED_RELEASE_TARGET_CONFORMANCE_DIGEST_MISMATCH")
        if not report.passed:
            raise ValueError("VERIFIED_RELEASE_TARGET_CONFORMANCE_FAILED")

        expected_identity = {
            "tool_id": compile_data.get("tool_id"),
            "operation_kind": compile_data.get("operation_kind"),
            "target_id": compile_data.get("target_id"),
            "target_fingerprint": compile_data.get("target_fingerprint"),
            "target_identity_digest": compile_data.get("target_identity_digest"),
            "evidence_digest": compile_data.get("evidence_digest"),
            "dsl_digest": compile_data.get("dsl_digest"),
            "context_digest": compile_data.get("context_digest"),
            "ir_digest": compile_data.get("ir_digest"),
            "bundle_digest": compile_data.get("bundle_digest"),
            "compile_artifact_digest": compile_data.get("compile_artifact_digest"),
            "compiler_version": compile_data.get("compiler_version"),
            "compiler_backend_id": compile_data.get("compiler_backend_id"),
            "compiler_backend_version": compile_data.get("compiler_backend_version"),
            "runtime_backend_id": compile_data.get("runtime_backend_id"),
            "runtime_binding_digest": compile_data.get("runtime_binding_digest"),
            "required_capabilities": compile_data.get("required_capabilities"),
            "required_runtime_capabilities": compile_data.get("required_runtime_capabilities"),
            "negotiated_capabilities": compile_data.get("negotiated_capabilities"),
            "journey_session_id": journey_session_id,
            "confirmation_receipt_digest": compile_data.get("confirmation_receipt_digest"),
            "conformance_idempotency_key": "sha256:" + cache_key,
            "diagnostics": compile_data.get("diagnostics"),
        }
        if any(canonical_report.get(field) != value for field, value in expected_identity.items()):
            raise ValueError("VERIFIED_RELEASE_TARGET_CONFORMANCE_IDENTITY_MISMATCH")

        expected_proofs = self._expected_verified_proofs(canonical_report)
        if tuple(proof.gate for proof in report.proofs) != tuple(expected_proofs):
            raise ValueError("VERIFIED_RELEASE_TARGET_PROOF_SET_INVALID")
        for proof in report.proofs:
            evidence_ref, expected_payload = expected_proofs[proof.gate]
            if proof.status != "PASS" or proof.evidence_ref != evidence_ref:
                raise ValueError("VERIFIED_RELEASE_TARGET_PROOF_SET_INVALID")
            proof_path = conformance_dir / Path(evidence_ref).name
            proof_payload = self._load_verified_json(
                proof_path,
                "VERIFIED_RELEASE_TARGET_PROOF_INVALID",
            )
            if proof_payload != expected_payload:
                raise ValueError("VERIFIED_RELEASE_TARGET_PROOF_IDENTITY_MISMATCH")
            if self._json_digest(proof_payload) != proof.evidence_digest or self._file_digest(proof_path) != proof.evidence_digest:
                raise ValueError("VERIFIED_RELEASE_TARGET_PROOF_DIGEST_MISMATCH")
        return report

    @staticmethod
    def _expected_verified_proofs(
        report: dict,
    ) -> dict[str, tuple[str, dict[str, object]]]:
        return {
            "T1": (
                "target-conformance/t1-target-resolve.json",
                {
                    "gate": "T1",
                    "status": "PASS",
                    "target_id": report["target_id"],
                    "target_fingerprint": report["target_fingerprint"],
                    "target_identity_digest": report["target_identity_digest"],
                    "context_digest": report["context_digest"],
                    "evidence_digest": report["evidence_digest"],
                    "runtime_backend_id": report["runtime_backend_id"],
                    "runtime_binding_digest": report["runtime_binding_digest"],
                    "required_runtime_capabilities": report["required_runtime_capabilities"],
                },
            ),
            "T2": (
                "target-conformance/t2-bundle-build.json",
                {
                    "gate": "T2",
                    "status": "PASS",
                    "dsl_digest": report["dsl_digest"],
                    "context_digest": report["context_digest"],
                    "ir_digest": report["ir_digest"],
                    "bundle_digest": report["bundle_digest"],
                    "compile_artifact_digest": report["compile_artifact_digest"],
                    "compiler_backend_id": report["compiler_backend_id"],
                    "compiler_backend_version": report["compiler_backend_version"],
                },
            ),
            "T3": (
                "target-conformance/t3-runtime-behavior.json",
                {
                    "gate": "T3",
                    "status": "PASS",
                    "runtime_backend_id": report["runtime_backend_id"],
                    "runtime_binding_digest": report["runtime_binding_digest"],
                    "runtime_result_digest": report["runtime_result_digest"],
                    "required_runtime_capabilities": report["required_runtime_capabilities"],
                    "conformance_idempotency_key": report["conformance_idempotency_key"],
                },
            ),
            "T4": (
                "target-conformance/t4-release-integrity.json",
                {
                    "gate": "T4",
                    "status": "PASS",
                    "tool_id": report["tool_id"],
                    "operation_kind": report["operation_kind"],
                    "target_identity_digest": report["target_identity_digest"],
                    "dsl_digest": report["dsl_digest"],
                    "context_digest": report["context_digest"],
                    "ir_digest": report["ir_digest"],
                    "bundle_digest": report["bundle_digest"],
                    "confirmation_receipt_digest": report["confirmation_receipt_digest"],
                },
            ),
        }

    @staticmethod
    def _mapping_identity_from_compile_cache(
        data: dict,
        journey_session_id: str,
        receipt: MappingConfirmationReceipt,
    ) -> MappingAdmissionIdentity:
        if data.get("journey_session_id") != journey_session_id:
            raise MappingAdmissionError("MAPPING_JOURNEY_SESSION_MISMATCH")
        if data.get("confirmation_receipt_digest") != receipt.receipt_digest:
            raise MappingAdmissionError("MAPPING_CONFIRMATION_IDENTITY_INVALID")
        try:
            scope = MappingAdmissionScope(
                tool_id=data["tool_id"],
                operation_kind=data["operation_kind"],
                operations=receipt.scope.operations,
                access=receipt.scope.access,
                risk=receipt.scope.risk,
            )
            expected = MappingAdmissionIdentity.build(
                journey_session_id=journey_session_id,
                target_id=data["target_id"],
                target_fingerprint=data["target_fingerprint"],
                candidate_index_digest=receipt.candidate_index_digest,
                candidate_digest=receipt.candidate_digest,
                proposal_digest=receipt.proposal_digest,
                dsl_digest=data["dsl_digest"],
                context_digest=data["context_digest"],
                evidence_digest=data["evidence_digest"],
                available_tool_catalog_digest=(receipt.available_tool_catalog_digest),
                scope=scope,
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise MappingAdmissionError("MAPPING_CONFIRMATION_IDENTITY_INVALID") from exc
        if data.get("target_identity_digest") != expected.target_identity_digest:
            raise MappingAdmissionError("MAPPING_TARGET_IDENTITY_DIGEST_MISMATCH")
        return expected

    def _reject_verified_release_symlinks(
        self,
        artifact_dir: Path,
        conformance_dir: Path,
    ) -> None:
        if self.cache_dir.is_symlink() or artifact_dir.is_symlink() or conformance_dir.is_symlink():
            raise ValueError("VERIFIED_RELEASE_CACHE_SYMLINK_REJECTED")
        if not artifact_dir.is_dir() or not conformance_dir.is_dir():
            raise ValueError("VERIFIED_RELEASE_CACHE_INCOMPLETE")
        try:
            if any(path.is_symlink() for path in artifact_dir.rglob("*")):
                raise ValueError("VERIFIED_RELEASE_CACHE_SYMLINK_REJECTED")
        except OSError as exc:
            raise ValueError("VERIFIED_RELEASE_CACHE_INVALID") from exc

    @staticmethod
    def _load_verified_json(path: Path, error_code: str) -> dict:
        if path.is_symlink() or not path.is_file():
            raise ValueError(error_code)
        try:
            payload = loads_unique_json(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise ValueError(error_code) from exc
        if not isinstance(payload, dict):
            raise ValueError(error_code)
        return payload

    def _require_active_confirmation(
        self,
        put: DslPutPayload,
        payload: DslCompilePayload,
    ) -> MappingConfirmationReceipt:
        """Re-resolve the active receipt from targetd's trusted ledger.

        Candidate, proposal and catalog identities are not independently
        available in this v2 targetd frame, so their committed values remain
        ledger-authoritative.  The targetd-owned PUT state does independently
        rebind every identity dimension it can resolve: journey, target, DSL,
        Context, evidence, tool id and operation kind.  Building a fresh
        identity is important because it recomputes the derived target and
        scope digests instead of copying them from the receipt.
        """

        if self.confirmation_store is None or self.admission_gate is None:
            raise MappingAdmissionError("MAPPING_CONFIRMATION_STORE_REQUIRED")
        receipt = self.confirmation_store.resolve(payload.confirmation_receipt_digest)
        document, report = parse_document(put.dsl)
        if document is None or not report.ok:
            raise MappingAdmissionError("MAPPING_CONFIRMATION_IDENTITY_INVALID")
        target_id = put.context.get("robot_id")
        evidence_digest = put.context.get("evidence_digest")
        if not isinstance(target_id, str) or not isinstance(evidence_digest, str):
            raise MappingAdmissionError("MAPPING_CONFIRMATION_IDENTITY_INVALID")
        if document.target.robot_id != target_id:
            raise MappingAdmissionError("MAPPING_TARGET_ID_MISMATCH")
        if document.target.evidence_digest != evidence_digest:
            raise MappingAdmissionError("MAPPING_EVIDENCE_DIGEST_MISMATCH")
        scope = MappingAdmissionScope(
            tool_id=document.tool_id,
            operation_kind=document.kind,
            operations=receipt.scope.operations,
            access=receipt.scope.access,
            risk=receipt.scope.risk,
        )
        expected = MappingAdmissionIdentity.build(
            journey_session_id=payload.journey_session_id,
            target_id=target_id,
            target_fingerprint=put.target_fingerprint,
            candidate_index_digest=receipt.candidate_index_digest,
            candidate_digest=receipt.candidate_digest,
            proposal_digest=receipt.proposal_digest,
            dsl_digest=put.dsl_digest,
            context_digest=put.context_digest,
            evidence_digest=evidence_digest,
            available_tool_catalog_digest=receipt.available_tool_catalog_digest,
            scope=scope,
        )
        return self.admission_gate.require_active(
            payload.confirmation_receipt_digest,
            expected,
        )

    def _cached_conformance_response(
        self,
        frame: DslFrame,
        put: DslPutPayload,
        payload: DslCompilePayload,
        *,
        expected_key: str,
        artifact_dir: Path,
        conformance_dir: Path,
        resolved_backend: object | None,
    ) -> DslFrame:
        try:
            self._require_active_confirmation(put, payload)
            data = loads_unique_json((conformance_dir / "result.json").read_text(encoding="utf-8"))
        except MappingAdmissionError as exc:
            return self._error(frame, exc.code, blocked=True)
        except (OSError, ValueError):
            return self._error(frame, "CONFORMANCE_CACHE_INVALID")
        if not isinstance(data, dict) or not self._verify_cache_digest(data):
            return self._error(frame, "CONFORMANCE_CACHE_INVALID")
        report_payload = data.get("target_conformance_report")
        try:
            report = TargetConformanceReport.model_validate(report_payload)
        except ValueError:
            return self._error(frame, "CONFORMANCE_CACHE_INVALID")
        if (
            data.get("cache_key") != expected_key
            or data.get("journey_session_id") != payload.journey_session_id
            or data.get("confirmation_receipt_digest") != payload.confirmation_receipt_digest
            or data.get("dsl_digest") != payload.dsl_digest
            or data.get("context_digest") != payload.context_digest
            or data.get("target_fingerprint") != payload.target_fingerprint
            or data.get("target_conformance_digest") != self._json_digest(report.model_dump(mode="json"))
        ):
            return self._error(frame, "CONFORMANCE_CACHE_IDENTITY_MISMATCH")
        compile_error = self._compile_cache_error(
            data,
            payload,
            expected_key=expected_key,
            artifact_dir=artifact_dir,
            resolved_backend=resolved_backend,
        )
        if compile_error is not None:
            return self._error(frame, compile_error)
        for proof in report.proofs:
            proof_path = conformance_dir / Path(proof.evidence_ref).name
            if not proof_path.is_file() or proof_path.is_symlink() or self._file_digest(proof_path) != proof.evidence_digest:
                return self._error(frame, "CONFORMANCE_PROOF_DIGEST_MISMATCH")
        data["cache_hit"] = True
        data["conformance_cache_hit"] = True
        data["artifact_digest"] = self._cache_digest(data)
        return DslFrame(
            frame_type=DslFrameType.DSL_RESULT,
            request_id=frame.request_id,
            payload=data,
        )

    def _compile_cache_error(
        self,
        data: dict,
        payload: DslCompilePayload,
        *,
        expected_key: str,
        artifact_dir: Path,
        resolved_backend: object | None,
    ) -> str | None:
        if data.get("cache_key") != expected_key or data.get("dsl_digest") != payload.dsl_digest:
            return "CACHE_DIGEST_MISMATCH"
        if data.get("journey_session_id") != payload.journey_session_id or data.get("confirmation_receipt_digest") != payload.confirmation_receipt_digest:
            return "CACHE_ADMISSION_MISMATCH"
        if not self._verify_cache_digest(data):
            return "CACHE_ARTIFACT_DIGEST_MISMATCH"
        artifacts = data.get("compile_artifacts")
        if not isinstance(artifacts, dict):
            return "CACHE_COMPILE_ARTIFACT_DIGEST_MISMATCH"
        try:
            artifact_digest = self._compile_artifact_digest(artifact_dir, artifacts)
        except (OSError, ValueError):
            return "CACHE_COMPILE_ARTIFACT_DIGEST_MISMATCH"
        if data.get("compile_artifact_digest") != artifact_digest:
            return "CACHE_COMPILE_ARTIFACT_DIGEST_MISMATCH"
        if resolved_backend is not None and data.get("runtime_backend_id") != resolved_backend.backend_id:
            return "BACKEND_DIGEST_MISMATCH"
        return None

    @staticmethod
    def _cache_key(
        payload: DslCompilePayload,
        put: DslPutPayload,
        required_capabilities: tuple[str, ...],
        required_runtime_capabilities: tuple[str, ...],
    ) -> str:
        identity = {
            "schema_version": payload.schema_version,
            "journey_session_id": payload.journey_session_id,
            "confirmation_receipt_digest": payload.confirmation_receipt_digest,
            "dsl_digest": payload.dsl_digest,
            "context_digest": payload.context_digest,
            "target_fingerprint": payload.target_fingerprint,
            "compiler_version": put.compiler_version,
            "backend_hint": payload.backend_hint,
            "runtime_backend_hint": payload.runtime_backend_hint,
            "required_capabilities": required_capabilities,
            "required_runtime_capabilities": required_runtime_capabilities,
            "source_bundle_digest": payload.source_bundle_digest,
        }
        encoded = json.dumps(
            identity,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def _resolve_backend(
        self,
        dsl: dict,
        *,
        backend_hint: str | None = None,
        required_capabilities: tuple[str, ...] = (),
    ) -> object:
        if self.backend_registry is None:
            raise ValueError("BACKEND_UNAVAILABLE")
        document, report = parse_document(dsl)
        if document is None or not report.ok:
            raise ValueError("DSL_COMPILE_FAILED")
        resolved = self.backend_registry.resolve(
            document.kind.value,
            document.binding,
            required_capabilities=required_capabilities,
        )
        if backend_hint is not None and resolved.backend_id != backend_hint:
            raise ValueError("BACKEND_UNSUPPORTED")
        return resolved

    @staticmethod
    def _normalize_capabilities(values: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(sorted({str(value).strip() for value in values if str(value).strip()}))

    @staticmethod
    def _cache_digest(data: dict) -> str:
        payload = {key: value for key, value in data.items() if key not in {"artifact_digest", "cache_hit", "conformance_cache_hit"}}
        encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return "sha256:" + hashlib.sha256(encoded).hexdigest()

    @classmethod
    def _verify_cache_digest(cls, data: dict) -> bool:
        declared = data.get("artifact_digest")
        return isinstance(declared, str) and declared == cls._cache_digest(data)

    @staticmethod
    def _json_digest(value: object) -> str:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return "sha256:" + hashlib.sha256(encoded).hexdigest()

    @staticmethod
    def _file_digest(path: Path) -> str:
        return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()

    @classmethod
    def _compile_artifact_digest(cls, artifact_dir: Path, artifacts: Mapping[str, str]) -> str:
        paths = sorted({str(value) for value in artifacts.values()})
        if not paths:
            raise ValueError("compile artifact set is empty")
        inventory: list[dict[str, object]] = []
        for relative in paths:
            if relative.startswith(("/", "\\")) or ".." in Path(relative).parts:
                raise ValueError("compile artifact path is invalid")
            path = artifact_dir / relative
            if not path.is_file() or path.is_symlink():
                raise ValueError("compile artifact is missing or untrusted")
            inventory.append(
                {
                    "path": relative.replace("\\", "/"),
                    "size": path.stat().st_size,
                    "digest": cls._file_digest(path),
                }
            )
        return cls._json_digest(inventory)

    @staticmethod
    def _validate_source_bundle(dsl: dict, payload: DslCompilePayload) -> None:
        document, report = parse_document(dsl)
        if document is None or not report.ok or document.kind.value != "EXECUTE":
            return
        implementation = document.implementation
        expected_digest = implementation.get("source_bundle_digest")
        if not isinstance(expected_digest, str):
            raise ValueError("SOURCE_BUNDLE_DIGEST_REQUIRED")
        if payload.source_bundle_digest != expected_digest:
            raise ValueError("SOURCE_BUNDLE_DIGEST_MISMATCH")
        if payload.source_bundle_manifest is None:
            raise ValueError("SOURCE_BUNDLE_MANIFEST_REQUIRED")
        if payload.source_bundle_source is None:
            raise ValueError("SOURCE_BUNDLE_SOURCE_REQUIRED")
        if not expected_digest.startswith("sha256:") or len(expected_digest) != 71:
            raise ValueError("SOURCE_BUNDLE_DIGEST_INVALID")
        actual_source_digest = "sha256:" + hashlib.sha256(payload.source_bundle_source.encode("utf-8")).hexdigest()
        if actual_source_digest != expected_digest:
            raise ValueError("SOURCE_BUNDLE_DIGEST_MISMATCH")
        try:
            manifest = SourceBundleManifest.model_validate(payload.source_bundle_manifest)
        except ValueError as exc:
            raise ValueError("SOURCE_BUNDLE_MANIFEST_INVALID") from exc
        if manifest.source_bundle_digest != expected_digest:
            raise ValueError("SOURCE_BUNDLE_DIGEST_MISMATCH")
        for field in ("entrypoint", "runtime", "implementation_contract"):
            declared = implementation.get(field)
            if declared is not None and getattr(manifest, field) != declared:
                raise ValueError("SOURCE_BUNDLE_CONTRACT_MISMATCH")

    def _error(self, frame: DslFrame, code: str, *, blocked: bool = False) -> DslFrame:
        return DslFrame(
            frame_type=DslFrameType.DSL_RESULT,
            request_id=frame.request_id,
            payload={
                "status": "BLOCKED" if blocked else "DSL_COMPILE_FAILED",
                "dsl_digest": "",
                "diagnostics": [code],
            },
        )
