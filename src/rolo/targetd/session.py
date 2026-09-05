"""JSONL codec and transport abstraction for targetd DSL sessions."""

import json
from typing import Protocol

from .dsl_protocol import DslFrame


class FrameCodec:
    @staticmethod
    def encode(frame: DslFrame) -> bytes:
        return (json.dumps(frame.model_dump(mode="json"), sort_keys=True, separators=(",", ":")) + "\n").encode()

    @staticmethod
    def decode(data: bytes | str) -> DslFrame:
        return DslFrame.model_validate(json.loads(data))


class FrameTransport(Protocol):
    def request(self, frame: DslFrame) -> DslFrame: ...


class TargetdSession:
    def __init__(self, transport: FrameTransport):
        self.transport = transport

    def request(self, frame: DslFrame) -> DslFrame:
        try:
            return self.transport.request(frame)
        except Exception as exc:
            raise ConnectionError("TARGETD_SESSION_DISCONNECTED") from exc
