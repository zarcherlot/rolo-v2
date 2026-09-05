"""Schema-driven generation of Tool input/output validation wrappers."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from typing import Any

from rolo.agent_tools.native_tools import AgentNativeToolDescriptor

from .harness_execution import HarnessCodeBundle, make_code_bundle

_FIELD = re.compile(r"^[a-z][a-z0-9_]{0,63}$")


def generate_contract_source(
    descriptor: AgentNativeToolDescriptor,
    *,
    observation_fields: Sequence[str],
    primitive_source: str,
) -> str:
    """Generate an ``execute(request)`` wrapper from any Tool descriptor.

    ``primitive_source`` must define ``run_primitive(request)``.  The generated
    wrapper owns the descriptor-shaped input and observation-shaped output
    contracts; operation-specific behavior stays in the supplied primitive.
    """

    fields = list(observation_fields)
    if not fields or any(not _FIELD.fullmatch(field) for field in fields):
        raise ValueError("observation_fields must contain safe, non-empty identifiers")
    if len(fields) != len(set(fields)) or "status" not in fields:
        raise ValueError("observation_fields must be unique and include status")
    if not primitive_source.strip():
        raise ValueError("primitive_source is required")
    parameter_specs = [item.model_dump(mode="json") for item in descriptor.parameters]
    encoded_specs = repr(parameter_specs)
    encoded_fields = json.dumps(fields, separators=(",", ":"))
    return f'''from __future__ import annotations
import re
from collections.abc import Mapping

_PARAMETERS = {encoded_specs}
_OUTPUT_FIELDS = {encoded_fields}

{primitive_source.rstrip()}

def _validate_input(request):
    if not isinstance(request, Mapping):
        raise ValueError("request must be an object")
    names = {{item["name"] for item in _PARAMETERS}}
    unknown = sorted(set(request) - names)
    missing = sorted(item["name"] for item in _PARAMETERS if item.get("required", True) and item["name"] not in request)
    if unknown or missing:
        raise ValueError(f"invalid input keys: unknown={{unknown}}, missing={{missing}}")
    values = {{}}
    for item in _PARAMETERS:
        name = item["name"]
        if name not in request:
            continue
        value = request[name]
        kind = item["kind"]
        if kind == "integer" and (isinstance(value, bool) or not isinstance(value, int)):
            raise ValueError(f"{{name}} must be an integer")
        if kind in {{"token", "enum", "path"}} and not isinstance(value, str):
            raise ValueError(f"{{name}} must be a string")
        if kind == "enum" and value not in item.get("choices", []):
            raise ValueError(f"{{name}} is not an allowed choice")
        pattern = item.get("pattern")
        if pattern and not re.fullmatch(pattern, str(value)):
            raise ValueError(f"{{name}} does not match its pattern")
        if isinstance(value, str) and len(value) > item.get("max_length", 128):
            raise ValueError(f"{{name}} exceeds max_length")
        values[name] = value
    return values

def execute(request: Mapping[str, object]) -> Mapping[str, object]:
    result = run_primitive(_validate_input(request))
    if not isinstance(result, Mapping):
        raise ValueError("primitive result must be an object")
    extra = sorted(set(result) - set(_OUTPUT_FIELDS))
    missing = sorted(set(_OUTPUT_FIELDS) - set(result))
    if extra or missing:
        raise ValueError(f"invalid output fields: extra={{extra}}, missing={{missing}}")
    return {{field: result[field] for field in _OUTPUT_FIELDS}}
'''


def build_codegen_artifact(
    descriptor: AgentNativeToolDescriptor,
    *,
    target_id: str,
    evidence_refs: Sequence[str],
    observation_fields: Sequence[str],
    primitive_source: str,
    arguments: Mapping[str, Any],
    binding: Mapping[str, Any] | None = None,
    derived_request: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the generic artifact exchanged by Harness and Probe.

    The descriptor and binding are copied into the artifact as contracts.  The
    generated bundle receives only the validated request object; transport
    details remain in the binding and are never interpolated into shell text.
    """

    source = generate_contract_source(
        descriptor,
        observation_fields=observation_fields,
        primitive_source=primitive_source,
    )
    request = {**dict(arguments), **dict(derived_request or {})}
    bundle: HarnessCodeBundle = make_code_bundle(tool_id=descriptor.tool_id, source=source, request=request)
    descriptor_json = json.dumps(
        descriptor.model_dump(mode="json"), sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )
    if binding is None:
        binding_digest = None
    else:
        binding_json = json.dumps(dict(binding), sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        binding_digest = hashlib.sha256(binding_json.encode("utf-8")).hexdigest()
    return {
        "schema_version": "rolo-harness-codegen-artifact/v1",
        "target_id": target_id,
        "tool_id": descriptor.tool_id,
        "evidence_refs": list(evidence_refs),
        "descriptor_sha256": hashlib.sha256(descriptor_json.encode("utf-8")).hexdigest(),
        "binding_sha256": binding_digest,
        "arguments": dict(arguments),
        "input_contract": {"parameters": [item.model_dump(mode="json") for item in descriptor.parameters]},
        "observation_contract": {"fields": list(observation_fields)},
        "derived_request": dict(derived_request or {}),
        "bundle": bundle.model_dump(mode="json"),
    }


__all__ = ["build_codegen_artifact", "generate_contract_source"]
