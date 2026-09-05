"""Offline targetd DSL service with idempotent compile cache."""

import hashlib
import json
from pathlib import Path

from rolo.dsl.api import DslCheckRequest, DslCompileRequest
from rolo.dsl.service import RoloDslCompiler

from .dsl_protocol import DslCompilePayload, DslFrame, DslFrameType, DslPutPayload


class TargetdDslService:
    def __init__(self, cache_dir: str | Path):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self._puts: dict[str, DslPutPayload] = {}
        self.compiler = RoloDslCompiler()

    def handle(self, frame: DslFrame) -> DslFrame:
        if frame.frame_type == DslFrameType.DSL_PUT:
            return self._put(frame)
        if frame.frame_type == DslFrameType.DSL_CHECK:
            return self._check(frame)
        if frame.frame_type == DslFrameType.DSL_COMPILE:
            return self._compile(frame)
        return DslFrame(frame_type=DslFrameType.DSL_EVENT, request_id=frame.request_id, payload={"code": "FRAME_UNSUPPORTED", "message": frame.frame_type})

    def _put(self, frame: DslFrame) -> DslFrame:
        payload = DslPutPayload.model_validate(frame.payload)
        self._puts[payload.dsl_digest] = payload
        return DslFrame(frame_type=DslFrameType.DSL_EVENT, request_id=frame.request_id, payload={"phase": "PUT", "dsl_digest": payload.dsl_digest})

    def _check(self, frame: DslFrame) -> DslFrame:
        digest = frame.payload.get("dsl_digest")
        put = self._puts.get(digest)
        if put is None:
            return self._error(frame, "DSL_NOT_FOUND")
        result = self.compiler.check(DslCheckRequest(dsl=put.dsl, context=put.context, compiler_version=put.compiler_version))
        return DslFrame(frame_type=DslFrameType.DSL_RESULT, request_id=frame.request_id, payload={"status": result.status, "dsl_digest": result.dsl_digest, "diagnostics": result.diagnostics})

    def _compile(self, frame: DslFrame) -> DslFrame:
        payload = DslCompilePayload.model_validate(frame.payload)
        put = self._puts.get(payload.dsl_digest)
        if put is None:
            return self._error(frame, "DSL_NOT_FOUND")
        key_data = f"{payload.dsl_digest}:{payload.context_digest}:{payload.target_fingerprint}".encode()
        key = hashlib.sha256(key_data).hexdigest()
        artifact_dir = self.cache_dir / key
        result_file = artifact_dir / "result.json"
        if result_file.exists():
            data = json.loads(result_file.read_text(encoding="utf-8"))
            data["cache_hit"] = True
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
            ),
            artifact_dir,
        )
        data = {"status": result.status, "dsl_digest": result.dsl_digest, "ir_digest": result.ir_digest, "bundle_digest": result.bundle_digest, "diagnostics": result.diagnostics, "cache_hit": False}
        artifact_dir.mkdir(parents=True, exist_ok=True)
        result_file.write_text(json.dumps(data, sort_keys=True), encoding="utf-8")
        return DslFrame(frame_type=DslFrameType.DSL_RESULT, request_id=frame.request_id, payload=data)

    def _error(self, frame: DslFrame, code: str) -> DslFrame:
        return DslFrame(frame_type=DslFrameType.DSL_RESULT, request_id=frame.request_id, payload={"status": "DSL_COMPILE_FAILED", "dsl_digest": "", "diagnostics": [code]})
