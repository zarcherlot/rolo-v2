"""Offline backend SPI and deterministic fake bundle generation."""
from dataclasses import dataclass
from pathlib import Path
import hashlib, json
from typing import Protocol
from ..canonical import canonical_json
from ..ir import CanonicalIR
class RoloDslBackend(Protocol):
    backend_id: str
    def supports(self, ir: CanonicalIR) -> bool: ...
    def compile(self, ir: CanonicalIR, output_dir: Path) -> "GeneratedBundle": ...
@dataclass(frozen=True)
class GeneratedBundle:
    backend_id: str
    manifest: dict[str, str]
    digest: str
class FakeBackend:
    def __init__(self, backend_id: str, kinds: tuple[str, ...]): self.backend_id, self.kinds = backend_id, kinds
    def supports(self, ir: CanonicalIR) -> bool: return ir.kind in self.kinds
    def compile(self, ir: CanonicalIR, output_dir: Path) -> GeneratedBundle:
        payload = canonical_json(ir) if hasattr(ir, "model_dump") else json.dumps(ir, sort_keys=True)
        digest = "sha256:" + hashlib.sha256(payload.encode()).hexdigest()
        manifest = {"tool_id": ir.tool_id, "kind": ir.kind, "backend_id": self.backend_id, "ir_digest": digest}
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "manifest.json").write_text(json.dumps(manifest, sort_keys=True, indent=2), encoding="utf-8")
        return GeneratedBundle(self.backend_id, manifest, digest)
def default_backends() -> tuple[FakeBackend, ...]:
    return (FakeBackend("ros2_observe", ("OBSERVE",)), FakeBackend("workflow", ("COMPOSE",)), FakeBackend("ros2_invoke", ("INVOKE",)), FakeBackend("generated_runtime", ("EXECUTE",)))
