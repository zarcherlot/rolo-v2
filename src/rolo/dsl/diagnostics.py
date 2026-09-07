"""Stable machine-readable diagnostics emitted by the DSL frontend."""

from __future__ import annotations

from typing import Any

from pydantic import Field

from rolo._compat import StrEnum

from .models import StrictModel


class DiagnosticSeverity(StrEnum):
    ERROR = "ERROR"
    WARNING = "WARNING"


class Diagnostic(StrictModel):
    code: str = Field(min_length=1)
    path: str = Field(min_length=1)
    severity: DiagnosticSeverity
    message: str = Field(min_length=1)
    details: dict[str, Any] = Field(default_factory=dict, max_length=32)


class DiagnosticReport(StrictModel):
    diagnostics: tuple[Diagnostic, ...] = ()

    @property
    def ok(self) -> bool:
        return not any(item.severity == DiagnosticSeverity.ERROR for item in self.diagnostics)

    def stable(self) -> DiagnosticReport:
        """Return diagnostics in the contract's deterministic path/code order."""

        return self.model_copy(update={"diagnostics": tuple(sorted(self.diagnostics, key=lambda item: (item.path, item.code, item.severity.value, item.message)))})
