"""Offline backend SPI and deterministic fake bundle generation."""

import json
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from ..canonical import ir_digest
from ..contracts import BUNDLE_PLAN_SCHEMA_VERSION
from ..ir import CanonicalIR


class RoloDslBackend(Protocol):
    backend_id: str
    supported_kinds: tuple[str, ...]

    def supports(self, ir: CanonicalIR) -> bool: ...
    def supports_kind(self, kind: str) -> bool: ...
    def capabilities(self) -> tuple[str, ...]: ...
    def resolve(self, ir: CanonicalIR) -> dict: ...
    def compile(self, ir: CanonicalIR, output_dir: Path) -> "GeneratedBundle": ...
    def conformance(self, bundle: "GeneratedBundle") -> bool: ...


@dataclass(frozen=True)
class GeneratedBundle:
    backend_id: str
    manifest: dict[str, str]
    digest: str


class FakeBackend:
    def __init__(self, backend_id: str, kinds: tuple[str, ...]):
        self.backend_id = backend_id
        self.kinds = tuple(str(kind).upper() for kind in kinds)
        self.supported_kinds = self.kinds

    def capabilities(self) -> tuple[str, ...]:
        """Return stable capability names used by handoff negotiation."""

        return tuple(f"operation:{kind}" for kind in self.supported_kinds)

    def supports(self, ir: CanonicalIR) -> bool:
        return ir.kind in self.kinds

    def supports_kind(self, kind: str) -> bool:
        return str(kind).upper() in self.kinds

    def resolve(self, ir: CanonicalIR) -> dict:
        return {"backend_id": self.backend_id, "tool_id": ir.tool_id, "binding": ir.binding}

    def compile(self, ir: CanonicalIR, output_dir: Path) -> GeneratedBundle:
        digest = ir_digest(ir)
        manifest = {
            "schema_version": BUNDLE_PLAN_SCHEMA_VERSION,
            "tool_id": ir.tool_id,
            "kind": ir.kind,
            "backend_id": self.backend_id,
            "ir_digest": digest,
        }
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "manifest.json").write_text(json.dumps(manifest, sort_keys=True, indent=2), encoding="utf-8")
        return GeneratedBundle(self.backend_id, manifest, digest)

    def conformance(self, bundle: GeneratedBundle) -> bool:
        return bundle.manifest.get("backend_id") == self.backend_id and bool(bundle.digest)


class Ros2ObserveBackend(FakeBackend):
    def __init__(self):
        super().__init__("ros2_observe", ("OBSERVE",))


class Ros2InvokeBackend(FakeBackend):
    def __init__(self):
        super().__init__("ros2_invoke", ("INVOKE",))


class MhsOperationBackend(FakeBackend):
    def __init__(self):
        super().__init__("mhs_operation", ("INVOKE",))


class WorkflowBackend(FakeBackend):
    def __init__(self):
        super().__init__("workflow", ("COMPOSE",))


class GeneratedRuntimeBackend(FakeBackend):
    def __init__(self):
        super().__init__("generated_runtime", ("EXECUTE",))


def default_backends() -> tuple[FakeBackend, ...]:
    return (Ros2ObserveBackend(), Ros2InvokeBackend(), WorkflowBackend(), GeneratedRuntimeBackend())


def backend_capability_matrix(backends: Iterable[RoloDslBackend] | None = None) -> dict[str, dict[str, tuple[str, ...]]]:
    """Return a deterministic, serializable capability advertisement."""

    selected = tuple(backends or default_backends())
    return {
        backend.backend_id: {
            "supported_kinds": tuple(sorted(backend.supported_kinds)),
            "capabilities": tuple(sorted(backend.capabilities())),
        }
        for backend in sorted(selected, key=lambda item: item.backend_id)
    }


def negotiate_backend(
    kind: str,
    *,
    backend_id: str | None = None,
    required_capabilities: Iterable[str] = (),
    backends: Iterable[RoloDslBackend] | None = None,
) -> RoloDslBackend | None:
    """Select a backend only when its advertised capabilities satisfy the request."""

    required = tuple(sorted(set(str(item) for item in required_capabilities)))
    candidates = tuple(backends or default_backends())
    return next(
        (
            backend
            for backend in candidates
            if backend.supports_kind(kind)
            if backend_id is None or backend.backend_id == backend_id
            if all(capability in backend.capabilities() for capability in required)
        ),
        None,
    )
