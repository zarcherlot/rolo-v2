"""Offline targetd DSL service with idempotent compile cache."""

import hashlib
import json
import os
from pathlib import Path

from rolo.dsl.api import DslCheckRequest, DslCompileRequest
from rolo.dsl.canonical import context_digest, dsl_digest
from rolo.dsl.context import ProbeContext
from rolo.dsl.contracts import COMPILE_CONTEXT_SCHEMA_VERSION, DSL_SCHEMA_VERSION, TARGET_CONFORMANCE_SCHEMA_VERSION, require_version
from rolo.dsl.parser import parse_document
from rolo.dsl.service import RoloDslCompiler
from rolo.dsl.source_bundle import SourceBundleManifest

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
    ):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self._puts: dict[str, DslPutPayload] = {}
        self.compiler = RoloDslCompiler()
        self.runtime_resolver = runtime_resolver
        self.backend_registry = backend_registry

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
        if payload.context_digest != put.context_digest or payload.target_fingerprint != put.target_fingerprint:
            return self._error(frame, "TARGET_BINDING_MISMATCH")
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
        resolved_backend = None
        if self.backend_registry is not None:
            try:
                resolved_backend = self._resolve_backend(
                    put.dsl,
                    backend_hint=payload.backend_hint,
                    required_capabilities=required_capabilities,
                )
            except ValueError as exc:
                return self._error(frame, str(exc))
        key_data = f"{payload.dsl_digest}:{payload.context_digest}:{payload.target_fingerprint}:{put.compiler_version}:{payload.backend_hint or ''}:{','.join(required_capabilities)}".encode()
        key = hashlib.sha256(key_data).hexdigest()
        artifact_dir = self.cache_dir / key
        result_file = artifact_dir / "result.json"
        if result_file.exists():
            try:
                data = json.loads(result_file.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                return self._error(frame, "CACHE_ARTIFACT_INVALID")
            if data.get("cache_key") != key or data.get("dsl_digest") != payload.dsl_digest:
                return self._error(frame, "CACHE_DIGEST_MISMATCH")
            if not self._verify_cache_digest(data):
                return self._error(frame, "CACHE_ARTIFACT_DIGEST_MISMATCH")
            if resolved_backend is not None and data.get("backend_id") not in {None, resolved_backend.backend_id}:
                return self._error(frame, "BACKEND_DIGEST_MISMATCH")
            if resolved_backend is not None:
                data["backend_id"] = resolved_backend.backend_id
                data["resolved_binding"] = resolved_backend.binding
            data["cache_hit"] = True
            data.setdefault("phase", "TARGET_COMPILE")
            # ``cache_hit`` is transport metadata, not part of the persisted
            # artifact identity.  Recompute the envelope digest after adding
            # any resolved backend projection so callers can verify the
            # returned payload as well as the on-disk cache.
            data["artifact_digest"] = self._cache_digest(data)
            return DslFrame(frame_type=DslFrameType.DSL_RESULT, request_id=frame.request_id, payload=data)
        result = self.compiler.compile(
            DslCompileRequest(
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
            artifact_dir,
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
            "target_fingerprint": payload.target_fingerprint,
            "backend_hint": payload.backend_hint,
        }
        if resolved_backend is not None:
            data["backend_id"] = resolved_backend.backend_id
            data["resolved_binding"] = resolved_backend.binding
        data["artifact_digest"] = self._cache_digest(data)
        artifact_dir.mkdir(parents=True, exist_ok=True)
        temporary = result_file.with_suffix(".json.tmp")
        temporary.write_text(json.dumps(data, sort_keys=True), encoding="utf-8")
        os.replace(temporary, result_file)
        return DslFrame(frame_type=DslFrameType.DSL_RESULT, request_id=frame.request_id, payload=data)

    def _conformance(self, frame: DslFrame) -> DslFrame:
        try:
            payload = DslCompilePayload.model_validate(frame.payload)
        except ValueError:
            return self._error(frame, "DSL_CONFORMANCE_SCHEMA_INVALID", blocked=True)
        put = self._puts.get(payload.dsl_digest)
        if put is None:
            return self._error(frame, "DSL_NOT_FOUND")
        if payload.context_digest != put.context_digest or payload.target_fingerprint != put.target_fingerprint:
            return self._error(frame, "TARGET_BINDING_MISMATCH")
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
        resolved_backend = None
        if self.backend_registry is not None:
            try:
                resolved_backend = self._resolve_backend(
                    put.dsl,
                    backend_hint=payload.backend_hint,
                    required_capabilities=required_capabilities,
                )
            except ValueError as exc:
                return self._error(frame, str(exc))
        key_data = f"{payload.dsl_digest}:{payload.context_digest}:{payload.target_fingerprint}:{put.compiler_version}:{payload.backend_hint or ''}:{','.join(required_capabilities)}".encode()
        result_file = self.cache_dir / hashlib.sha256(key_data).hexdigest() / "result.json"
        if not result_file.exists():
            return self._error(frame, "TARGET_COMPILE_REQUIRED")
        try:
            data = json.loads(result_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return self._error(frame, "CACHE_ARTIFACT_INVALID")
        expected_key = hashlib.sha256(
            f"{payload.dsl_digest}:{payload.context_digest}:{payload.target_fingerprint}:{put.compiler_version}:{payload.backend_hint or ''}:{','.join(required_capabilities)}".encode()
        ).hexdigest()
        if data.get("cache_key") != expected_key or data.get("dsl_digest") != payload.dsl_digest:
            return self._error(frame, "CACHE_DIGEST_MISMATCH")
        if not self._verify_cache_digest(data):
            return self._error(frame, "CACHE_ARTIFACT_DIGEST_MISMATCH")
        status = data.get("status")
        gate = "PASS" if status == "PASS" else "FAIL"
        runtime_gate = gate
        runtime_diagnostics: list[str] = []
        if gate == "PASS" and self.backend_registry is not None:
            document, document_report = parse_document(put.dsl)
            if document is None or not document_report.ok:
                runtime_gate = "FAIL"
                runtime_diagnostics.append("DSL_COMPILE_FAILED")
            else:
                try:
                    runtime_result = self.backend_registry.execute(document.kind.value, document.binding, {})
                    runtime_gate = "PASS" if str(runtime_result.get("status", "PASS")).upper() in {"PASS", "PASSED", "SUCCESS", "SUCCEEDED"} else "FAIL"
                    if runtime_gate == "FAIL":
                        runtime_diagnostics.append(str(runtime_result.get("error", "RUNTIME_BEHAVIOR_FAILED")))
                except ValueError as exc:
                    runtime_gate = "FAIL"
                    runtime_diagnostics.append(str(exc))
        diagnostics = tuple(dict.fromkeys([*data.get("diagnostics", ()), *runtime_diagnostics]))
        report = {
            "schema_version": TARGET_CONFORMANCE_SCHEMA_VERSION,
            "t1_target_resolve": gate,
            "t2_bundle_build": gate,
            "t3_runtime_behavior": runtime_gate,
            "t4_release_integrity": gate,
            "target_fingerprint": payload.target_fingerprint,
            "diagnostics": diagnostics,
        }
        conformance_gate = "PASS" if all(report[key] == "PASS" for key in ("t1_target_resolve", "t2_bundle_build", "t3_runtime_behavior", "t4_release_integrity")) else "FAIL"
        report_digest = "sha256:" + hashlib.sha256(
            json.dumps(report, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        data.update(
            {
                "phase": "TARGET_CONFORMANCE",
                "target_conformance": conformance_gate,
                "target_conformance_report": report,
                "target_conformance_digest": report_digest,
            }
        )
        if resolved_backend is not None:
            data["backend_id"] = resolved_backend.backend_id
            data["resolved_binding"] = resolved_backend.binding
        # The conformance response extends the compile cache envelope with
        # T1-T4 evidence.  Recompute the returned digest after that extension
        # so consumers can verify the complete response rather than only the
        # underlying compile result.
        data["artifact_digest"] = self._cache_digest(data)
        return DslFrame(frame_type=DslFrameType.DSL_RESULT, request_id=frame.request_id, payload=data)

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
        payload = {key: value for key, value in data.items() if key not in {"artifact_digest", "cache_hit"}}
        encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return "sha256:" + hashlib.sha256(encoded).hexdigest()

    @classmethod
    def _verify_cache_digest(cls, data: dict) -> bool:
        declared = data.get("artifact_digest")
        return isinstance(declared, str) and declared == cls._cache_digest(data)

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
