"""Pure YAML/JSON parser for Rolo DSL documents."""

from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from .diagnostics import Diagnostic, DiagnosticReport, DiagnosticSeverity
from .models import DslDocument


def parse_document(value: str | bytes | dict[str, Any]) -> tuple[DslDocument | None, DiagnosticReport]:
    try:
        raw = value if isinstance(value, dict) else yaml.safe_load(value)
        if not isinstance(raw, dict):
            raise ValueError("DSL document must be a mapping")
        return DslDocument.model_validate(raw), DiagnosticReport()
    except (ValueError, TypeError, yaml.YAMLError, ValidationError) as exc:
        return None, DiagnosticReport(diagnostics=(Diagnostic(code="DSL_SCHEMA_INVALID", path="$", severity=DiagnosticSeverity.ERROR, message=str(exc)),))


def parse_file(path: str | Path) -> tuple[DslDocument | None, DiagnosticReport]:
    return parse_document(Path(path).read_text(encoding="utf-8"))
