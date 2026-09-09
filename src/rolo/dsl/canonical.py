"""Deterministic serialization and digests for DSL documents, context and IR."""

import hashlib
import json
from typing import Any

from .models import DslDocument


def canonical_dict(document: Any) -> dict[str, Any]:
    if isinstance(document, dict):
        return document
    # Bundle Plan is a closed handoff envelope whose schema requires every
    # field, including the explicit ``source_bundle_ref: null`` sentinel.
    # Other historical DSL models retain their established exclude-none rule.
    from .bundle_plan import BundlePlan

    if isinstance(document, BundlePlan):
        return document.model_dump(mode="json")
    return document.model_dump(mode="json", exclude_none=True)


def canonical_json(document: Any) -> str:
    return json.dumps(canonical_dict(document), ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def canonical_bytes(document: Any) -> bytes:
    """Return the UTF-8 bytes used by every DSL contract digest."""

    return canonical_json(document).encode("utf-8")


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


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


def bundle_plan_digest(plan: Any) -> str:
    """Digest a normalized ``rolo-bundle-plan/v2`` payload in full."""

    from .bundle_plan import parse_bundle_plan

    return _digest(parse_bundle_plan(plan))
