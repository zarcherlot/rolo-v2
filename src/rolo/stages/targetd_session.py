"""Business-stage facade over the unified targetd journey router."""

from __future__ import annotations

from rolo.targetd import ExecutionBundleManifest, ExecutionRequest, JourneyPhaseRouter, ProtocolFrame


class TargetdStageSession:
    """Expose Probe/Trace/Certify calls through one controller-owned session."""

    def __init__(self, router: JourneyPhaseRouter) -> None:
        self.router = router

    @classmethod
    def from_controller(cls, controller) -> TargetdStageSession:
        """Build the business facade for an already-open journey."""
        return cls(JourneyPhaseRouter(controller))

    def probe(self) -> ProtocolFrame:
        return self.router.enter_probe()

    def trace(self) -> ProtocolFrame:
        return self.router.enter_trace()

    def certify(self) -> ProtocolFrame:
        return self.router.enter_certify()

    def call(self, manifest: ExecutionBundleManifest, source: bytes, request: ExecutionRequest) -> ProtocolFrame:
        return self.router.call(manifest, source, request)
