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
    if isinstance(document, dict):
        try:
            document = DslDocument.model_validate(document)
        except Exception:
            # Invalid documents are diagnosed by the parser; retaining the
            # raw payload here keeps this low-level helper total for callers
            # that need to fingerprint an invalid request envelope.
            pass
    return _digest(document)


def context_digest(context: Any) -> str:
    # Normalize raw request dictionaries through the frozen context model so
    # omitted defaults and explicit empty collections have one digest.  A
    # malformed payload is left raw and will be rejected by the service layer.
    if isinstance(context, dict):
        try:
            from .context import ProbeContext

            context = ProbeContext.model_validate(context)
        except Exception:
            pass
    return _digest(context)


def ir_digest(ir: Any) -> str:
    return _digest(ir)
