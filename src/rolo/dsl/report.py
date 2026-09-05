"""Typed conformance layers for offline compiler artifacts."""
from enum import StrEnum
from .models import StrictModel
class GateStatus(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
class ConformanceReport(StrictModel):
    c1_dsl: GateStatus
    c2_evidence: GateStatus
    c3_compile: GateStatus
    c4_behavior: GateStatus
    diagnostics: tuple[str, ...] = ()
    @property
    def passed(self) -> bool:
        return all(item == GateStatus.PASS for item in (self.c1_dsl, self.c2_evidence, self.c3_compile, self.c4_behavior))
