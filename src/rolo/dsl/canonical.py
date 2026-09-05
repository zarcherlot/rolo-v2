"""Deterministic serialization and digests for DSL documents, context and IR."""

import hashlib
import json
from typing import Any

from .models import DslDocument


def canonical_dict(document: Any) -> dict[str, Any]:
    if isinstance(document, dict):
        return document
    return document.model_dump(mode="json", exclude_none=True)


def canonical_json(document: Any) -> str:
    return json.dumps(canonical_dict(document), ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def dsl_digest(document: DslDocument) -> str:
    return _digest(document)


def context_digest(context: Any) -> str:
    return _digest(context)


def ir_digest(ir: Any) -> str:
    return _digest(ir)
