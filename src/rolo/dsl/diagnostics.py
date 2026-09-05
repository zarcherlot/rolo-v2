"""Stable machine-readable diagnostics emitted by the DSL frontend."""

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


class DiagnosticReport(StrictModel):
    diagnostics: tuple[Diagnostic, ...] = ()

    @property
    def ok(self) -> bool:
        return not any(item.severity == DiagnosticSeverity.ERROR for item in self.diagnostics)
