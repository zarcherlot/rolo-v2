"""Canonical intermediate representation for deterministic compilation."""

from typing import Any, Literal

from .contracts import CANONICAL_IR_SCHEMA_VERSION
from .models import OperationKind, StrictModel, TargetBinding


class CanonicalIR(StrictModel):
    schema_version: Literal["rolo-canonical-ir/v1"] = CANONICAL_IR_SCHEMA_VERSION
    tool_id: str
    kind: OperationKind
    target: TargetBinding
    evidence_refs: tuple[str, ...]
    binding: dict[str, Any]
    input_schema: dict[str, Any]
    output_schema: dict[str, Any]
    mapping: dict[str, Any]
    preconditions: tuple[dict[str, Any], ...]
    error_mapping: dict[str, Any]
    composition: dict[str, Any]
    implementation: dict[str, Any]
