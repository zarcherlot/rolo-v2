"""Small stdio daemon for the signed bundle targetd protocol.

The daemon is intentionally transport-only: it validates sessions, bundles,
requests and receipts, then leaves provider-specific execution to a worker.
This makes bootstrap/handoff testable on a real host without granting shell
access or embedding ROS assumptions in targetd.
"""

from __future__ import annotations

import argparse
import base64
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from rolo.core.rotation_evidence import has_verified_rotation_evidence

from .protocol import (
    ExecutionBundleManifest,
    ExecutionRequest,
    FrameKind,
    JourneyPhase,
    JourneySession,
    ProtocolError,
    ProtocolFrame,
    decode_frame,
    encode_frame,
)
from .service import TargetdService
from .worker import (
    MAPPING_TOOL_OPERATIONS,
    Provider,
    PythonBundleWorker,
    RosContainerProvider,
)


def _read_exact(stream, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = stream.read(remaining)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


class TargetdDaemon:
    def __init__(self, service: TargetdService, *, execute_calls: bool = False, provider: Provider | None = None) -> None:
        self.service = service
        self.worker = PythonBundleWorker(provider) if execute_calls else None
        self._sequence = 0
        self._response_sequence = 0
        self._session: JourneySession | None = None

    def serve(self, stdin, stdout) -> None:
        while True:
            header = _read_exact(stdin, 4)
            if not header:
                return
            payload = _read_exact(stdin, int.from_bytes(header, "big"))
            if len(payload) != int.from_bytes(header, "big"):
                raise ProtocolError("targetd input frame is truncated")
            frame = decode_frame(header + payload)
            if frame.sequence != self._sequence:
                raise ProtocolError("targetd input sequence is not monotonic")
            self._sequence += 1
            response = self._handle(frame)
            if frame.kind == FrameKind.CALL and response.payload.get("ok"):
                event = ProtocolFrame.create(
                    kind=FrameKind.EVENT,
                    sequence=self._response_sequence,
                    session_id=frame.session_id,
                    run_id=frame.run_id,
                    payload={"call_id": frame.payload.get("idempotency_key"), "status": "STARTED"},
                )
                self._response_sequence += 1
                stdout.write(encode_frame(event))
            response = ProtocolFrame.create(
                kind=response.kind,
                sequence=self._response_sequence,
                session_id=response.session_id,
                run_id=response.run_id,
                payload=response.payload,
            )
            self._response_sequence += 1
            stdout.write(encode_frame(response))
            stdout.flush()
            if frame.kind == FrameKind.CLOSE_SESSION:
                return

    def _handle(self, frame: ProtocolFrame) -> ProtocolFrame:
        try:
            payload = self._dispatch(frame)
            return ProtocolFrame.create(
                kind=FrameKind.RESULT,
                sequence=self._sequence,
                session_id=frame.session_id,
                run_id=frame.run_id,
                payload={"request_kind": frame.kind.value, "ok": True, **payload},
            )
        except (KeyError, ProtocolError, TypeError, ValueError) as exc:
            return ProtocolFrame.create(
                kind=FrameKind.RESULT,
                sequence=self._sequence,
                session_id=frame.session_id,
                run_id=frame.run_id,
                payload={
                    "request_kind": frame.kind.value,
                    "ok": False,
                    "error": str(exc)[:512],
                },
            )

    def _dispatch(self, frame: ProtocolFrame) -> dict:
        if frame.kind == FrameKind.OPEN_JOURNEY:
            target_id = str(frame.payload.get("target_id", ""))
            profile_id = str(frame.payload.get("profile_id", ""))
            if target_id != self.service.target_id or not profile_id:
                raise ProtocolError("journey target or profile is invalid")
            try:
                session = self.service.state.load_session(frame.session_id)
            except KeyError:
                session = JourneySession.create(
                    session_id=frame.session_id,
                    target_id=target_id,
                    profile_id=profile_id,
                )
                supplied_token = frame.payload.get("resume_token")
                if supplied_token:
                    session = session.model_copy(update={"resume_token": str(supplied_token)})
                supplied_surface = frame.payload.get("surface_digest")
                if supplied_surface is not None:
                    session = session.model_copy(update={"surface_digest": str(supplied_surface)})
                self.service.open_session(session)
            else:
                if session.target_id != target_id or session.profile_id != profile_id:
                    raise ProtocolError("journey session identity conflicts with stored session")
                supplied_surface = frame.payload.get("surface_digest")
                if supplied_surface is not None:
                    supplied_surface = str(supplied_surface)
                    if session.surface_digest not in (None, supplied_surface):
                        raise ProtocolError("journey session surface digest conflicts with stored session")
                    if session.surface_digest is None:
                        session = session.model_copy(update={"surface_digest": supplied_surface})
                        self.service.state.save_session(session)
            self._session = session
            return {"session": session.model_dump(mode="json")}
        if frame.kind == FrameKind.RESUME_SESSION:
            token = str(frame.payload.get("resume_token", ""))
            self._session = self.service.resume_session(frame.session_id, token)
            return {"session": self._session.model_dump(mode="json")}
        if self._session is None or frame.session_id != self._session.session_id:
            raise ProtocolError("journey session is not open")
        if frame.kind == FrameKind.BOOTSTRAP:
            return {"health": self.service.health().model_dump(mode="json")}
        if frame.kind == FrameKind.HANDOFF:
            requested = frame.payload.get("phase", JourneyPhase.PROBE.value)
            phase = JourneyPhase(str(requested))
            self._session = self._session.model_copy(update={"phase": phase})
            self.service.state.save_session(self._session)
            return {"health": self.service.health().model_dump(mode="json"), "phase": phase.value}
        if frame.kind == FrameKind.PHASE_CHANGE:
            phase = JourneyPhase(str(frame.payload.get("phase")))
            self._session = self._session.model_copy(update={"phase": phase})
            self.service.state.save_session(self._session)
            return {"phase": phase.value}
        if frame.kind == FrameKind.HAS:
            digest = str(frame.payload.get("bundle_digest", ""))
            return {"bundle_digest": digest, "present": self.service.has_bundle(digest)}
        if frame.kind == FrameKind.PUT:
            manifest = ExecutionBundleManifest.model_validate(frame.payload["manifest"])
            source = base64.b64decode(str(frame.payload["source_b64"]).encode("ascii"), validate=True)
            self.service.put_bundle(manifest, source)
            return {"bundle_digest": manifest.bundle_digest, "present": True}
        if frame.kind == FrameKind.CALL:
            request = ExecutionRequest.model_validate(frame.payload)
            if request.session_id != frame.session_id:
                raise ProtocolError("execution request session does not match frame")
            if frame.run_id is not None and request.run_id != frame.run_id:
                raise ProtocolError("execution request run does not match frame")
            manifest, source = self.service.cache.load(request.bundle_digest)
            receipt = self.service.accept_call(request, manifest)
            if self.worker is not None and receipt.status == "ACCEPTED":
                started = time.monotonic()
                try:
                    if (
                        manifest.tool_id == "app.base.rotate"
                        and not isinstance(self.worker.provider, RosContainerProvider)
                    ):
                        raise ProtocolError("rotation provider is required")
                    result = self.worker.execute(manifest, source, request.arguments)
                    max_duration = float(manifest.limits.get("max_duration_s", 60))
                    if time.monotonic() - started > max_duration:
                        raise ProtocolError("bundle execution exceeded max_duration_s")
                    terminal_status = self._terminal_status(manifest, result)
                    receipt = self.service.complete_call(
                        request.idempotency_key, status=terminal_status, result=result
                    )
                except Exception as exc:
                    # A worker/provider failure must not leave an ACCEPTED
                    # receipt indefinitely.  ``PythonBundleWorker`` normally
                    # normalizes provider exceptions to ProtocolError, but
                    # limits/result normalization can still raise a built-in
                    # exception after the receipt has been accepted.  Always
                    # persist a terminal failure before returning the frame.
                    receipt = self.service.complete_call(
                        request.idempotency_key, status="FAILED", result={"error": str(exc)}
                    )
            return {"receipt": receipt.model_dump(mode="json")}
        if frame.kind == FrameKind.CANCEL:
            receipt = self.service.cancel_call(str(frame.payload["call_id"]))
            return {"receipt": receipt.model_dump(mode="json")}
        if frame.kind == FrameKind.QUERY_CALL:
            receipt = self.service.query_call(str(frame.payload["call_id"]))
            return {"receipt": receipt.model_dump(mode="json") if receipt else None}
        if frame.kind == FrameKind.CLOSE_SESSION:
            self._session = self._session.model_copy(
                update={"closed": True, "expires_at": datetime.now(timezone.utc)}
            )
            self.service.state.save_session(self._session)
            return {"closed": True}
        raise ProtocolError(f"unsupported targetd frame: {frame.kind.value}")

    @staticmethod
    def _terminal_status(manifest: ExecutionBundleManifest, result: object) -> str:
        """Map a worker result to the persisted receipt without false success.

        Generic EXECUTE bundles may legitimately return an application object
        without a ``status`` field.  Rotation is different: it is a physical
        write and may be marked ``SUCCEEDED`` only when the runtime supplied
        stop and independent-motion evidence.  The raw result remains in the
        receipt for diagnosis/replay.
        """

        if manifest.tool_id in MAPPING_TOOL_OPERATIONS:
            # Mapping is a target-side physical/debug operation too.  Unlike a
            # generic EXECUTE bundle, a missing status must never be promoted
            # to success; the provider contract is deliberately terminal and
            # fail-closed.
            if not isinstance(result, dict) or "status" not in result:
                return "UNKNOWN"
            status = str(result.get("status", "UNKNOWN")).upper()
            if status in {"SUCCEEDED", "SUCCESS", "PASS", "PASSED"}:
                return "SUCCEEDED"
            if status in {"CANCELLED", "STOPPED", "FAILED", "UNKNOWN", "NOT_ACCEPTED"}:
                return status
            if status == "BLOCKED":
                return "FAILED"
            # RUNNING (or any future non-terminal status) cannot be persisted
            # as a TargetdCallReceipt terminal value.
            return "UNKNOWN"
        if manifest.tool_id != "app.base.rotate":
            # Generic bundles may return an application object with no
            # ``status`` member; that remains a successful invocation for
            # backwards compatibility.  When a bundle does declare a status,
            # however, never erase an explicit failure/block/unknown result by
            # unconditionally marking the receipt ``SUCCEEDED``.
            if not isinstance(result, dict) or "status" not in result:
                return "SUCCEEDED"
            status = str(result.get("status", "UNKNOWN")).upper()
            if status in {"SUCCEEDED", "SUCCESS", "PASS", "PASSED"}:
                return "SUCCEEDED"
            if status in {"CANCELLED", "STOPPED", "FAILED", "UNKNOWN", "NOT_ACCEPTED"}:
                return status
            if status == "BLOCKED":
                return "FAILED"
            return "UNKNOWN"
        if not isinstance(result, dict):
            return "UNKNOWN"
        status = str(result.get("status", "UNKNOWN")).upper()
        if status == "SUCCEEDED":
            if (
                result.get("stop_published") is True
                and result.get("physical_stop_verified") is True
                and result.get("stopped_observed") is True
                and has_verified_rotation_evidence(result)
            ):
                return "SUCCEEDED"
            return "UNKNOWN"
        if status in {"CANCELLED", "STOPPED", "FAILED", "UNKNOWN", "NOT_ACCEPTED"}:
            return status
        if status == "BLOCKED":
            return "FAILED"
        return "UNKNOWN"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target-id", required=True)
    parser.add_argument("--state-root", type=Path, required=True)
    parser.add_argument("--signing-key", required=True)
    parser.add_argument("--execute-calls", action="store_true")
    parser.add_argument("--provider", choices=("none", "ros-container"), default="none")
    parser.add_argument("--container", default="MentorPi")
    parser.add_argument("--autonomous-source-confirmed", action="store_true")
    args = parser.parse_args()
    service = TargetdService(
        target_id=args.target_id,
        state_root=args.state_root,
        signing_key=args.signing_key.encode("utf-8"),
    )
    try:
        provider = (
            RosContainerProvider(
                args.container,
                autonomous_source_confirmed=args.autonomous_source_confirmed,
            )
            if args.provider == "ros-container" else None
        )
        TargetdDaemon(service, execute_calls=args.execute_calls, provider=provider).serve(sys.stdin.buffer, sys.stdout.buffer)
    except ProtocolError as exc:
        print(f"targetd protocol error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc


if __name__ == "__main__":
    main()
