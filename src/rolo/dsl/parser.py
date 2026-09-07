"""Pure YAML/JSON parser for Rolo DSL documents."""

from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from .diagnostics import Diagnostic, DiagnosticReport, DiagnosticSeverity
from .models import DslDocument


class _UniqueKeyLoader(yaml.SafeLoader):
    """Safe YAML loader that rejects duplicate mapping keys."""


def _construct_unique_mapping(loader: _UniqueKeyLoader, node: yaml.MappingNode, deep: bool = False) -> dict[Any, Any]:
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise ValueError(f"duplicate mapping key: {key!r}")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_UniqueKeyLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_unique_mapping)


def parse_document(value: str | bytes | dict[str, Any]) -> tuple[DslDocument | None, DiagnosticReport]:
    try:
        raw = value if isinstance(value, dict) else yaml.load(value, Loader=_UniqueKeyLoader)
        if not isinstance(raw, dict):
            raise ValueError("DSL document must be a mapping")
        return DslDocument.model_validate(raw), DiagnosticReport()
    except (ValueError, TypeError, UnicodeError, yaml.YAMLError, ValidationError) as exc:
        return None, DiagnosticReport(diagnostics=(Diagnostic(code="DSL_SCHEMA_INVALID", path="$", severity=DiagnosticSeverity.ERROR, message=str(exc)),))


def parse_file(path: str | Path) -> tuple[DslDocument | None, DiagnosticReport]:
    return parse_document(Path(path).read_text(encoding="utf-8"))
