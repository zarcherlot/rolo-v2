"""Pure YAML/JSON parser for Rolo DSL documents."""

import json
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


def _construct_unique_json_mapping(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Build one JSON object while rejecting duplicate member names.

    ``json.loads`` otherwise keeps the last value for duplicate keys.  That
    behavior is dangerous at the DSL/targetd boundary because two producers
    can sign or digest different logical documents while a consumer silently
    sees only one of them.  Keep the same diagnostic wording as the YAML
    loader so callers can share their negative-path assertions.
    """

    mapping: dict[str, Any] = {}
    for key, value in pairs:
        if key in mapping:
            raise ValueError(f"duplicate mapping key: {key!r}")
        mapping[key] = value
    return mapping


def loads_unique_json(value: str | bytes | bytearray) -> Any:
    """Decode JSON without accepting duplicate object member names."""

    return json.loads(value, object_pairs_hook=_construct_unique_json_mapping)


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
