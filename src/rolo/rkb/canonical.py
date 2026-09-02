"""Canonical JSON and JSON Pointer helpers for RKB artifacts.

The artifact boundary deliberately has one implementation of canonicalization.
It is independent of Pydantic so callers can hash both model dumps and legacy
JSON payloads without depending on a particular model version.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from datetime import date, datetime, time
from decimal import Decimal
from typing import Any


def _json_default(value: Any) -> str:
    if isinstance(value, (datetime, date, time)):
        return value.isoformat()
    if isinstance(value, Decimal):
        return str(value)
    if hasattr(value, "value"):
        return str(value.value)
    raise TypeError(f"value is not JSON serializable: {type(value).__name__}")


def canonical_json(value: Any, *, exclude_none: bool = False) -> bytes:
    """Return UTF-8, sorted-key, whitespace-free JSON bytes.

    ``exclude_none`` is recursive and is useful at the artifact boundary.  A
    ``None`` explicitly nested in a fact value is retained by default.
    """

    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="json", exclude_none=exclude_none)
    elif exclude_none:
        value = _without_none(value)
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=_json_default,
        allow_nan=False,
    ).encode("utf-8")


def _without_none(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _without_none(item) for key, item in value.items() if item is not None}
    if isinstance(value, list):
        return [_without_none(item) for item in value]
    if isinstance(value, tuple):
        return [_without_none(item) for item in value]
    return value


def payload_digest(value: Any, *, exclude: Iterable[str] = ("digest",)) -> str:
    """Compute the lower-case SHA-256 digest for an artifact payload."""

    if hasattr(value, "model_dump"):
        payload = value.model_dump(mode="json", exclude=set(exclude), exclude_none=True)
    elif isinstance(value, dict):
        # Exclusions apply to the artifact's top-level fields only.  A nested
        # ``None`` inside Fact.value is an observed value and must remain part
        # of its digest.
        excluded = set(exclude)
        payload = {
            key: item
            for key, item in value.items()
            if key not in excluded and item is not None
        }
    else:
        payload = value
    return hashlib.sha256(canonical_json(payload)).hexdigest()


def json_pointer(document: Any, pointer: str) -> Any:
    """Resolve an RFC 6901 JSON Pointer against a JSON-compatible object."""

    if not isinstance(pointer, str) or (pointer and not pointer.startswith("/")):
        raise ValueError("JSON Pointer must be empty or start with '/'")
    if pointer == "":
        return document
    current = document
    for raw_token in pointer.split("/")[1:]:
        token = raw_token.replace("~1", "/").replace("~0", "~")
        if isinstance(current, list):
            if token == "-" or not token.isdigit():
                raise KeyError(token)
            index = int(token)
            if index >= len(current):
                raise KeyError(token)
            current = current[index]
        elif isinstance(current, dict):
            if token not in current:
                raise KeyError(token)
            current = current[token]
        else:
            raise KeyError(token)
    return current


def resolve_json_pointer(document: Any, pointer: str) -> Any:
    """Descriptive alias for :func:`json_pointer`."""

    return json_pointer(document, pointer)


def pointer_for_fact(fact_index: int, field: str | None = None) -> str:
    """Return a stable pointer into an envelope's ``facts`` array."""

    if fact_index < 0:
        raise ValueError("fact index must be non-negative")
    escaped = "" if field is None else "/" + field.replace("~", "~0").replace("/", "~1")
    return f"/facts/{fact_index}{escaped}"
