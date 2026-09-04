"""Bounded, deterministic context projection for external Agent harnesses."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from .contracts import TargetCatalog, ToolState

_INJECTION_LINE = re.compile(r"(?im)^\s*(?:system|developer|assistant)\s*:\s*.*$")


def _clean(value: Any, *, max_chars: int = 4_000) -> Any:
    if isinstance(value, str):
        value = value.replace("\x00", "")
        value = _INJECTION_LINE.sub("[redacted-untrusted-instruction]", value)
        return value[:max_chars]
    if isinstance(value, Mapping):
        return {str(k): _clean(v, max_chars=max_chars) for k, v in sorted(value.items(), key=lambda i: str(i[0]))}
    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray, str)):
        return [_clean(item, max_chars=max_chars) for item in value[:128]]
    return value


@dataclass(frozen=True)
class AgentContext:
    target_id: str
    target_fingerprint: str
    snapshot_digest: str
    surface_digest: str
    freshness: str
    executable_tools: tuple[dict[str, Any], ...]
    unknown_tools: tuple[dict[str, Any], ...]
    mhs: tuple[dict[str, Any], ...]
    rkb: tuple[dict[str, Any], ...]
    limitations: tuple[str, ...]
    digest: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "rolo-agent-context/v1",
            "target_id": self.target_id,
            "target_fingerprint": self.target_fingerprint,
            "snapshot_digest": self.snapshot_digest,
            "surface_digest": self.surface_digest,
            "freshness": self.freshness,
            "executable_tools": list(self.executable_tools),
            "unknown_tools": list(self.unknown_tools),
            "mhs": list(self.mhs),
            "rkb": list(self.rkb),
            "limitations": list(self.limitations),
            "context_digest": self.digest,
        }


def build_agent_context(
    catalog: TargetCatalog,
    *,
    max_tools: int = 64,
    max_context_bytes: int = 250_000,
) -> AgentContext:
    """Build the only tool context an external harness should receive.

    Callable tools are admitted only when the catalog is fresh and the entry is
    explicitly CALLABLE. All other entries remain visible as non-executable
    unknown context so a capability gap is explainable without becoming an
    authorization path.
    """
    if max_tools < 1 or max_tools > 512:
        raise ValueError("max_tools must be between 1 and 512")
    if max_context_bytes < 4_096 or max_context_bytes > 2_000_000:
        raise ValueError("max_context_bytes must be between 4096 and 2000000")
    tools = sorted(catalog.tools, key=lambda item: item.tool_id)
    executable: list[dict[str, Any]] = []
    unknown: list[dict[str, Any]] = []
    for tool in tools[:max_tools]:
        item = _clean(tool.model_dump(mode="json"))
        if catalog.freshness == "fresh" and tool.state is ToolState.CALLABLE and tool.agent_callable:
            executable.append(item)
        else:
            unknown.append(item)
    limitations = list(catalog.limitations)
    if len(tools) > max_tools:
        limitations.append(f"tool catalog truncated at {max_tools} entries")
    raw = {
        "schema_version": "rolo-agent-context/v1",
        "target_id": catalog.target_id,
        "target_fingerprint": catalog.target_fingerprint,
        "snapshot_digest": catalog.snapshot_digest,
        "surface_digest": "UNKNOWN",
        "freshness": catalog.freshness,
        "executable_tools": executable,
        "unknown_tools": unknown,
        "mhs": [_clean(item.model_dump(mode="json")) for item in catalog.mhs[:256]],
        "rkb": [_clean(item.model_dump(mode="json")) for item in catalog.rkb[:256]],
        "limitations": sorted(set(_clean(item) for item in limitations)),
    }
    encoded = json.dumps(raw, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode()
    if len(encoded) > max_context_bytes:
        raise ValueError("agent context exceeds its size limit")
    digest = hashlib.sha256(encoded).hexdigest()
    return AgentContext(
        target_id=catalog.target_id,
        target_fingerprint=catalog.target_fingerprint,
        snapshot_digest=catalog.snapshot_digest,
        surface_digest="UNKNOWN",
        freshness=catalog.freshness,
        executable_tools=tuple(executable),
        unknown_tools=tuple(unknown),
        mhs=tuple(raw["mhs"]),
        rkb=tuple(raw["rkb"]),
        limitations=tuple(raw["limitations"]),
        digest=digest,
    )


__all__ = ["AgentContext", "build_agent_context"]
