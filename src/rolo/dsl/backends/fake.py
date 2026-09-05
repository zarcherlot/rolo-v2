"""Offline backend SPI and deterministic fake bundle generation."""

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from ..canonical import ir_digest
from ..ir import CanonicalIR


class RoloDslBackend(Protocol):
    backend_id: str

    def supports(self, ir: CanonicalIR) -> bool: ...
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
        self.backend_id, self.kinds = backend_id, kinds

    def supports(self, ir: CanonicalIR) -> bool:
        return ir.kind in self.kinds

    def resolve(self, ir: CanonicalIR) -> dict:
        return {"backend_id": self.backend_id, "tool_id": ir.tool_id, "binding": ir.binding}

    def compile(self, ir: CanonicalIR, output_dir: Path) -> GeneratedBundle:
        digest = ir_digest(ir)
        manifest = {"tool_id": ir.tool_id, "kind": ir.kind, "backend_id": self.backend_id, "ir_digest": digest}
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
