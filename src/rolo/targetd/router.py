"""Unified Probe/Trace/Certify phase routing over one targetd controller."""

from __future__ import annotations

from .controller import TargetdJourneyController
from .protocol import ExecutionBundleManifest, ExecutionRequest, ProtocolFrame


class JourneyPhaseRouter:
    """Keep phase transitions and Tool calls on one logical journey session."""

    def __init__(self, controller: TargetdJourneyController) -> None:
        self.controller = controller

    def enter_probe(self) -> ProtocolFrame:
        return self.controller.change_phase("PROBE")

    def enter_trace(self) -> ProtocolFrame:
        return self.controller.change_phase("TRACE")

    def enter_certify(self) -> ProtocolFrame:
        return self.controller.change_phase("CERTIFY")

    def call(self, manifest: ExecutionBundleManifest, source: bytes, request: ExecutionRequest) -> ProtocolFrame:
        return self.controller.call(manifest, source, request)
