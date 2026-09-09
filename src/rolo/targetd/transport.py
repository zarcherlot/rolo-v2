"""SSH stdio framing and journey-session client primitives."""

from __future__ import annotations

import subprocess
import threading
from collections.abc import Callable, Mapping
from typing import BinaryIO, Protocol

from rolo.core.hashing import canonical_json_sha256

from .dsl_protocol import DslFrame, DslFrameType
from .dsl_service import TargetdDslService
from .protocol import (
    ExecutionBundleManifest,
    ExecutionRequestLike,
    FrameKind,
    JourneySession,
    ProtocolError,
    ProtocolFrame,
    TargetdAuthorityActivationRequest,
    TargetdMappingCancelRequest,
    TargetdVerifiedReleaseProvisionRequest,
    debug_zero_motion_acceptance_auth_tag,
    decode_frame,
    encode_frame,
    physical_gate_query_auth_tag,
    physical_prepared_start_auth_tag,
    process_control_auth_tag,
)


class InMemoryTargetdTransport:
    """In-memory transport used for targetd DSL protocol integration tests."""

    def __init__(self, service: TargetdDslService):
        self.service = service
        self.connected = True

    def request(self, frame: DslFrame) -> DslFrame:
        if not self.connected:
            raise ConnectionError("disconnected")
        return self.service.handle(frame)


class JourneyDslTransport:
    """Carry typed DSL requests on an already-open journey channel.

    The generic targetd session remains the sole owner of the SSH stdio
    process, sequence numbers, resume token, and target identity.  DSL frames
    are nested in one ``DSL_REQUEST`` protocol frame instead of starting the
    historical second JSONL daemon/SSH connection.
    """

    def __init__(self, client: JourneySessionClient) -> None:
        self.client = client

    def request(self, frame: DslFrame) -> DslFrame:
        journey_session_id = self.client.session.session_id
        supplied_session_id = frame.payload.get("journey_session_id")
        if supplied_session_id is not None and supplied_session_id != journey_session_id:
            raise ProtocolError("targetd DSL request journey does not match targetd session")
        if frame.frame_type == DslFrameType.DSL_PUT:
            frame = frame.model_copy(
                update={
                    "payload": {
                        **frame.payload,
                        "journey_session_id": journey_session_id,
                    }
                }
            )
        response = self.client.exchange(
            FrameKind.DSL_REQUEST,
            {"frame": frame.model_dump(mode="json")},
        )
        if response.kind != FrameKind.RESULT:
            raise ProtocolError("targetd DSL response is not a RESULT frame")
        if response.payload.get("ok") is not True:
            detail = str(response.payload.get("error", "TARGETD_DSL_REQUEST_FAILED"))
            raise ProtocolError(detail[:512])
        raw = response.payload.get("frame")
        if not isinstance(raw, dict):
            raise ProtocolError("targetd DSL response frame is missing")
        try:
            result = DslFrame.model_validate(raw)
        except ValueError as exc:
            raise ProtocolError("targetd DSL response frame is invalid") from exc
        if result.request_id != frame.request_id:
            raise ProtocolError("targetd DSL response request id does not match")
        return result


class FrameChannel(Protocol):
    def send(self, frame: ProtocolFrame) -> None: ...

    def receive(self) -> ProtocolFrame: ...

    def close(self) -> None: ...


class SshStdioChannel:
    """One fixed-argv SSH process carrying targetd frames over stdin/stdout."""

    def __init__(
        self,
        ssh_argv: list[str],
        *,
        popen_factory: Callable[..., subprocess.Popen[bytes]] | None = None,
    ) -> None:
        if not ssh_argv or any(not token or "\x00" in token for token in ssh_argv):
            raise ValueError("SSH stdio argv must be non-empty and NUL-free")
        self.ssh_argv = tuple(ssh_argv)
        self._popen_factory = popen_factory or subprocess.Popen
        self._process: subprocess.Popen[bytes] | None = None

    def open(self) -> None:
        if self._process is not None:
            raise ProtocolError("SSH stdio channel is already open")
        self._process = self._popen_factory(
            list(self.ssh_argv),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
        )

    def send(self, frame: ProtocolFrame) -> None:
        stream = self._stream("stdin")
        stream.write(encode_frame(frame))
        stream.flush()

    def receive(self) -> ProtocolFrame:
        stream = self._stream("stdout")
        header = _read_exact(stream, 4)
        if not header:
            raise ProtocolError("targetd SSH stdio channel closed")
        size = int.from_bytes(header, "big")
        payload = _read_exact(stream, size)
        if len(payload) != size:
            raise ProtocolError("targetd SSH stdio frame is truncated")
        return decode_frame(header + payload)

    def close(self) -> None:
        process = self._process
        self._process = None
        if process is None:
            return
        if process.stdin is not None:
            process.stdin.close()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.terminate()
            process.wait(timeout=2)

    def _stream(self, name: str) -> BinaryIO:
        if self._process is None:
            raise ProtocolError("SSH stdio channel is not open")
        stream = getattr(self._process, name)
        if stream is None:
            raise ProtocolError(f"SSH stdio {name} is unavailable")
        return stream


class JourneySessionClient:
    """Encode session lifecycle operations onto one reusable frame channel."""

    _MAX_CALL_EVENTS = 4

    def __init__(self, channel: FrameChannel, session: JourneySession) -> None:
        self.channel = channel
        self.session = session
        self._sequence = 0
        # targetd numbers every outbound EVENT/RESULT on one independent,
        # monotonic response stream.  A CALL that starts therefore consumes
        # two response sequence values (STARTED EVENT, then RESULT), while
        # ordinary requests consume one.
        self._response_sequence = 0
        self._poisoned = False
        self.last_events: list[ProtocolFrame] = []
        self._exchange_lock = threading.RLock()

    def open(self) -> ProtocolFrame:
        return self._send(FrameKind.OPEN_JOURNEY, {"target_id": self.session.target_id, "profile_id": self.session.profile_id})

    def bootstrap(self) -> ProtocolFrame:
        return self._send(FrameKind.BOOTSTRAP, {"session_id": self.session.session_id})

    def phase_change(self, phase: str) -> ProtocolFrame:
        return self._send(FrameKind.PHASE_CHANGE, {"phase": phase})

    def call(self, request: ExecutionRequestLike) -> ProtocolFrame:
        if request.session_id != self.session.session_id or request.target_id != self.session.target_id:
            raise ProtocolError("execution request does not belong to journey session")
        return self._send(FrameKind.CALL, request.model_dump(mode="json"), run_id=request.run_id)

    def cancel(self, call_id: str) -> ProtocolFrame:
        return self._send(FrameKind.CANCEL, {"call_id": call_id})

    def close(self) -> ProtocolFrame:
        return self._send(FrameKind.CLOSE_SESSION, {"session_id": self.session.session_id})

    def exchange(self, kind: FrameKind, payload: dict, *, run_id: str | None = None) -> ProtocolFrame:
        """Send one frame and wait for the targetd response on the same channel."""

        with self._exchange_lock:
            return self._exchange_locked(kind, payload, run_id=run_id)

    def _exchange_locked(self, kind: FrameKind, payload: dict, *, run_id: str | None = None) -> ProtocolFrame:
        """Exchange while owning sequence assignment and response demux."""

        self._send(kind, payload, run_id=run_id)
        self.last_events = []
        try:
            while True:
                response = self.channel.receive()
                self._require_response_identity(response, run_id=run_id)
                if response.sequence != self._response_sequence:
                    raise ProtocolError("targetd response sequence is not monotonic")
                self._response_sequence += 1

                if response.kind != FrameKind.EVENT:
                    break
                if kind != FrameKind.CALL:
                    raise ProtocolError("targetd emitted an EVENT for a non-CALL request")
                if len(self.last_events) >= self._MAX_CALL_EVENTS:
                    raise ProtocolError("targetd emitted too many CALL events")
                call_id = payload.get("idempotency_key")
                if not isinstance(call_id, str) or response.payload.get("call_id") != call_id:
                    raise ProtocolError("targetd CALL event does not match idempotency key")
                self.last_events.append(response)

            if response.kind != FrameKind.RESULT:
                raise ProtocolError("targetd response is not a RESULT frame")
            if response.payload.get("request_kind") != kind.value:
                raise ProtocolError("targetd RESULT does not match request kind")
            return response
        except Exception:
            # A consumed or uncertain frame cannot be put back.  Continuing
            # would risk associating a later response with the wrong request.
            self._poisoned = True
            raise

    def _require_response_identity(
        self,
        response: ProtocolFrame,
        *,
        run_id: str | None,
    ) -> None:
        if response.session_id != self.session.session_id:
            raise ProtocolError("targetd response belongs to another journey session")
        if response.run_id != run_id:
            raise ProtocolError("targetd response belongs to another run")

    def put_bundle(self, manifest: ExecutionBundleManifest, source: bytes) -> ProtocolFrame:
        """Upload an immutable signed bundle when the target cache misses it."""
        import base64

        return self.exchange(
            FrameKind.PUT,
            {
                "manifest": manifest.model_dump(mode="json"),
                "source_b64": base64.b64encode(source).decode("ascii"),
            },
        )

    def handoff(self, phase: str = "PROBE") -> ProtocolFrame:
        return self.exchange(FrameKind.HANDOFF, {"phase": phase})

    def call_remote(self, request: ExecutionRequestLike) -> ProtocolFrame:
        return self.exchange(
            FrameKind.CALL,
            request.model_dump(mode="json"),
            run_id=request.run_id,
        )

    def prepare_physical_call_remote(
        self,
        request: ExecutionRequestLike,
    ) -> ProtocolFrame:
        """Spawn the sealed physical worker but leave it ARMED_ZERO."""

        if (
            request.session_id != self.session.session_id
            or request.target_id != self.session.target_id
        ):
            raise ProtocolError(
                "TARGETD_PHYSICAL_PREPARE_SESSION_IDENTITY_MISMATCH"
            )
        return self.exchange(
            FrameKind.PREPARE_PHYSICAL_CALL,
            request.model_dump(mode="json"),
            run_id=request.run_id,
        )

    def accept_debug_zero_motion_remote(
        self,
        *,
        call_id: str,
        request_digest: str,
        armed_zero_receipt_digest: str,
        debug_admission: Mapping[str, object] | object,
    ) -> ProtocolFrame:
        """Run one authenticated target-owned zero-motion rehearsal."""

        from .landerpi_motion_target import DebugOnlyUserAttestedAdmission

        try:
            raw = (
                debug_admission.model_dump(mode="python")
                if callable(getattr(debug_admission, "model_dump", None))
                else dict(debug_admission)
                if isinstance(debug_admission, Mapping)
                else None
            )
            admission = DebugOnlyUserAttestedAdmission.model_validate(raw)
        except (TypeError, ValueError) as exc:
            raise ProtocolError(
                "TARGETD_DEBUG_ZERO_MOTION_ACCEPTANCE_IDENTITY_INVALID"
            ) from exc
        with self._exchange_lock:
            sequence = self._sequence
            return self._exchange_locked(
                FrameKind.ACCEPT_DEBUG_ZERO_MOTION,
                {
                    "call_id": call_id,
                    "target_id": self.session.target_id,
                    "request_digest": request_digest,
                    "armed_zero_receipt_digest": armed_zero_receipt_digest,
                    "debug_admission": admission.model_dump(mode="json"),
                    "debug_admission_digest": admission.payload_sha256,
                    "acceptance_auth": debug_zero_motion_acceptance_auth_tag(
                        self.session.resume_token,
                        target_id=self.session.target_id,
                        session_id=self.session.session_id,
                        call_id=call_id,
                        request_digest=request_digest,
                        armed_zero_receipt_digest=armed_zero_receipt_digest,
                        debug_admission_digest=admission.payload_sha256,
                        sequence=sequence,
                    ),
                },
            )

    def start_prepared_physical_call_remote(
        self,
        *,
        call_id: str,
        request_digest: str,
        armed_zero_receipt_digest: str,
        provider_gate: Mapping[str, object] | object,
    ) -> ProtocolFrame:
        """Release one exact ARMED_ZERO child with session-bound HMAC."""

        raw_gate = (
            provider_gate.model_dump(mode="json")
            if callable(getattr(provider_gate, "model_dump", None))
            else dict(provider_gate)
            if isinstance(provider_gate, Mapping)
            else None
        )
        if not isinstance(raw_gate, dict):
            raise ProtocolError("TARGETD_PHYSICAL_PREPARED_GATE_PAYLOAD_INVALID")
        gate_digest = canonical_json_sha256(raw_gate)
        with self._exchange_lock:
            sequence = self._sequence
            return self._exchange_locked(
                FrameKind.START_PREPARED_CALL,
                {
                    "call_id": call_id,
                    "target_id": self.session.target_id,
                    "request_digest": request_digest,
                    "armed_zero_receipt_digest": armed_zero_receipt_digest,
                    "provider_gate": raw_gate,
                    "provider_gate_payload_digest": gate_digest,
                    "start_auth": physical_prepared_start_auth_tag(
                        self.session.resume_token,
                        target_id=self.session.target_id,
                        session_id=self.session.session_id,
                        call_id=call_id,
                        request_digest=request_digest,
                        armed_zero_receipt_digest=armed_zero_receipt_digest,
                        provider_gate_payload_digest=gate_digest,
                        sequence=sequence,
                    ),
                },
            )

    def cancel_remote(self, call_id: str) -> ProtocolFrame:
        return self.exchange(FrameKind.CANCEL, {"call_id": call_id})

    def interrupt_process_remote(
        self,
        call_id: str,
        request_digest: str,
        *,
        intent: str,
    ) -> ProtocolFrame:
        if intent not in {"CANCEL", "STOP"}:
            raise ProtocolError("TARGETD_PROCESS_CONTROL_INTENT_INVALID")
        kind = FrameKind.CANCEL if intent == "CANCEL" else FrameKind.STOP
        with self._exchange_lock:
            sequence = self._sequence
            return self._exchange_locked(
                kind,
                {
                    "call_id": call_id,
                    "request_digest": request_digest,
                    "control_auth": process_control_auth_tag(
                        self.session.resume_token,
                        kind=intent,
                        session_id=self.session.session_id,
                        call_id=call_id,
                        request_digest=request_digest,
                        sequence=sequence,
                    ),
                },
            )

    def resume(self, resume_token: str) -> ProtocolFrame:
        return self.exchange(
            FrameKind.RESUME_SESSION,
            {"session_id": self.session.session_id, "resume_token": resume_token},
        )

    def query_call(self, idempotency_key: str) -> ProtocolFrame:
        return self.exchange(FrameKind.QUERY_CALL, {"call_id": idempotency_key})

    def query_physical_gate_remote(
        self,
        call_id: str,
        request_digest: str,
        *,
        gate_uri: str | None = None,
        gate_digest_uri: str | None = None,
    ) -> ProtocolFrame:
        """Read back one exact physical gate sidecar without replaying CALL."""

        with self._exchange_lock:
            sequence = self._sequence
            return self._exchange_locked(
                FrameKind.QUERY_CALL,
                {
                    "call_id": call_id,
                    "target_id": self.session.target_id,
                    "request_digest": request_digest,
                    "gate_uri": gate_uri,
                    "gate_digest_uri": gate_digest_uri,
                    "query_gate_auth": physical_gate_query_auth_tag(
                        self.session.resume_token,
                        target_id=self.session.target_id,
                        session_id=self.session.session_id,
                        call_id=call_id,
                        request_digest=request_digest,
                        gate_uri=gate_uri,
                        gate_digest_uri=gate_digest_uri,
                        sequence=sequence,
                    ),
                },
            )

    def activate_authority(
        self,
        request: TargetdAuthorityActivationRequest,
    ) -> ProtocolFrame:
        """Ask targetd to derive and activate a target-owned authority."""

        return self.exchange(
            FrameKind.ACTIVATE_AUTHORITY,
            request.model_dump(mode="json"),
        )

    def provision_verified_release(
        self,
        request: TargetdVerifiedReleaseProvisionRequest,
    ) -> ProtocolFrame:
        """Provision targetd Catalog current from its verified cache."""

        return self.exchange(
            FrameKind.PROVISION_VERIFIED_RELEASE,
            request.model_dump(mode="json"),
        )

    def cancel_mapping(
        self,
        request: TargetdMappingCancelRequest,
    ) -> ProtocolFrame:
        """Cancel the Mapping behind the named target-owned current head."""

        return self.exchange(
            FrameKind.CANCEL_MAPPING,
            request.model_dump(mode="json"),
        )

    def _send(self, kind: FrameKind, payload: dict, *, run_id: str | None = None) -> ProtocolFrame:
        if self._poisoned:
            raise ProtocolError("targetd journey client is unusable after a channel failure")
        frame = ProtocolFrame.create(
            kind=kind,
            sequence=self._sequence,
            session_id=self.session.session_id,
            run_id=run_id,
            payload=payload,
        )
        try:
            self.channel.send(frame)
        except Exception:
            # A failed write may still have delivered a partial or complete
            # frame, so retrying on this channel is never safe.
            self._poisoned = True
            raise
        self._sequence += 1
        return frame


def _read_exact(stream: BinaryIO, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = stream.read(remaining)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)
