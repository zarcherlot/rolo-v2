"""SSH stdio framing and journey-session client primitives."""

from __future__ import annotations

import subprocess
from collections.abc import Callable
from typing import BinaryIO, Protocol

from .dsl_protocol import DslFrame
from .dsl_service import TargetdDslService
from .protocol import (
    ExecutionBundleManifest,
    ExecutionRequest,
    FrameKind,
    JourneySession,
    ProtocolError,
    ProtocolFrame,
    decode_frame,
    encode_frame,
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

    def __init__(self, channel: FrameChannel, session: JourneySession) -> None:
        self.channel = channel
        self.session = session
        self._sequence = 0
        self.last_events: list[ProtocolFrame] = []

    def open(self) -> ProtocolFrame:
        return self._send(FrameKind.OPEN_JOURNEY, {"target_id": self.session.target_id, "profile_id": self.session.profile_id})

    def bootstrap(self) -> ProtocolFrame:
        return self._send(FrameKind.BOOTSTRAP, {"session_id": self.session.session_id})

    def phase_change(self, phase: str) -> ProtocolFrame:
        return self._send(FrameKind.PHASE_CHANGE, {"phase": phase})

    def call(self, request: ExecutionRequest) -> ProtocolFrame:
        if request.session_id != self.session.session_id or request.target_id != self.session.target_id:
            raise ProtocolError("execution request does not belong to journey session")
        return self._send(FrameKind.CALL, request.model_dump(mode="json"), run_id=request.run_id)

    def cancel(self, call_id: str) -> ProtocolFrame:
        return self._send(FrameKind.CANCEL, {"call_id": call_id})

    def close(self) -> ProtocolFrame:
        return self._send(FrameKind.CLOSE_SESSION, {"session_id": self.session.session_id})

    def exchange(
        self, kind: FrameKind, payload: dict, *, run_id: str | None = None
    ) -> ProtocolFrame:
        """Send one frame and wait for the targetd response on the same channel."""

        self._send(kind, payload, run_id=run_id)
        self.last_events = []
        response = self.channel.receive()
        while response.kind == FrameKind.EVENT:
            self.last_events.append(response)
            response = self.channel.receive()
        if response.session_id != self.session.session_id:
            raise ProtocolError("targetd response belongs to another journey session")
        return response

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

    def call_remote(self, request: ExecutionRequest) -> ProtocolFrame:
        return self.exchange(
            FrameKind.CALL,
            request.model_dump(mode="json"),
            run_id=request.run_id,
        )

    def cancel_remote(self, call_id: str) -> ProtocolFrame:
        return self.exchange(FrameKind.CANCEL, {"call_id": call_id})

    def resume(self, resume_token: str) -> ProtocolFrame:
        return self.exchange(
            FrameKind.RESUME_SESSION,
            {"session_id": self.session.session_id, "resume_token": resume_token},
        )

    def query_call(self, idempotency_key: str) -> ProtocolFrame:
        return self.exchange(FrameKind.QUERY_CALL, {"call_id": idempotency_key})

    def _send(self, kind: FrameKind, payload: dict, *, run_id: str | None = None) -> ProtocolFrame:
        frame = ProtocolFrame.create(
            kind=kind,
            sequence=self._sequence,
            session_id=self.session.session_id,
            run_id=run_id,
            payload=payload,
        )
        self.channel.send(frame)
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
