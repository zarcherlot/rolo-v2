"""Canonical intermediate representation for deterministic compilation."""
from typing import Any
from .models import OperationKind, StrictModel, TargetBinding
class CanonicalIR(StrictModel):
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
