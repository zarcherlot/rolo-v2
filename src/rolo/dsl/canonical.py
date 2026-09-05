"""Deterministic serialization and digests for DSL documents."""

import hashlib
import json
from typing import Any

from .models import DslDocument


def canonical_dict(document: DslDocument) -> dict[str, Any]:
    return document.model_dump(mode="json", exclude_none=True)


def canonical_json(document: DslDocument) -> str:
    return json.dumps(canonical_dict(document), ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def dsl_digest(document: DslDocument) -> str:
    digest = hashlib.sha256(canonical_json(document).encode("utf-8")).hexdigest()
    return f"sha256:{digest}"
