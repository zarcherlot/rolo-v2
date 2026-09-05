"""In-memory transport used for targetd protocol integration tests."""

from .dsl_protocol import DslFrame
from .dsl_service import TargetdDslService


class InMemoryTargetdTransport:
    def __init__(self, service: TargetdDslService):
        self.service = service
        self.connected = True

    def request(self, frame: DslFrame) -> DslFrame:
        if not self.connected:
            raise ConnectionError("disconnected")
        return self.service.handle(frame)
