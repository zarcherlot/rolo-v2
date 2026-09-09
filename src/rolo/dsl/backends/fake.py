"""Offline backend SPI and deterministic fake bundle generation."""

import hashlib
import json
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from ..bundle_plan import BundleArtifact, BundlePlan, parse_bundle_plan
from ..canonical import bundle_plan_digest, canonical_bytes, ir_digest
from ..contracts import BACKEND_SPI_VERSION, BUNDLE_PLAN_SCHEMA_VERSION
from ..ir import CanonicalIR


class BackendSpiVersionError(ValueError):
    """Raised when the incomplete v1 backend entrypoint is invoked."""


class LegacyRoloDslBackend(Protocol):
    backend_id: str
    supported_kinds: tuple[str, ...]

    def supports(self, ir: CanonicalIR) -> bool: ...
    def supports_kind(self, kind: str) -> bool: ...
    def capabilities(self) -> tuple[str, ...]: ...
    def resolve(self, ir: CanonicalIR) -> dict: ...
    def compile(self, ir: CanonicalIR, output_dir: Path) -> "GeneratedBundle": ...
    def conformance(self, bundle: "GeneratedBundle") -> bool: ...


class RoloDslBackend(LegacyRoloDslBackend, Protocol):
    backend_version: str

    def compile_v2(
        self,
        ir: CanonicalIR,
        output_dir: Path,
        *,
        dsl_digest: str,
        context_digest: str,
        target_fingerprint: str,
        compiler_version: str,
        negotiated_capabilities: tuple[str, ...],
        bindings: tuple[dict[str, Any], ...],
        runtime_context: dict[str, Any],
    ) -> "GeneratedBundle": ...


@dataclass(frozen=True)
class GeneratedBundle:
    backend_id: str
    manifest: BundlePlan
    digest: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "manifest", parse_bundle_plan(self.manifest))

    @property
    def bundle_digest(self) -> str:
        """Compatibility name for consumers that use the public result field."""

        return self.digest


class FakeBackend:
    def __init__(
        self,
        backend_id: str,
        kinds: tuple[str, ...],
        *,
        backend_version: str = BACKEND_SPI_VERSION,
        runtime_requirements: tuple[str, ...] = (),
    ):
        self.backend_id = backend_id
        self.backend_version = backend_version
        self.kinds = tuple(str(kind).upper() for kind in kinds)
        self.supported_kinds = self.kinds
        self.runtime_requirements = tuple(sorted(set(runtime_requirements)))

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
        """Reject the legacy SPI instead of fabricating missing plan identity."""

        del ir, output_dir
        raise BackendSpiVersionError("BACKEND_SPI_V1_RECOMPILE_REQUIRED")

    def compile_v2(
        self,
        ir: CanonicalIR,
        output_dir: Path,
        *,
        dsl_digest: str,
        context_digest: str,
        target_fingerprint: str,
        compiler_version: str,
        negotiated_capabilities: tuple[str, ...],
        bindings: tuple[dict[str, Any], ...],
        runtime_context: dict[str, Any],
    ) -> GeneratedBundle:
        canonical_ir_digest = ir_digest(ir)
        runtime_requirements = tuple(sorted(set((*self.runtime_requirements, *_runtime_requirements(ir)))))
        source_bundle_ref = _string_value(ir.implementation, "source_bundle_ref", "source_bundle_digest") if ir.kind == "EXECUTE" else None
        artifact_payload = {
            "bindings": bindings,
            "runtime_context": runtime_context,
            "runtime_requirements": runtime_requirements,
            "source_bundle_ref": source_bundle_ref,
        }
        artifact_bytes = canonical_bytes(artifact_payload)
        artifact = BundleArtifact(
            path="bundle-payload.json",
            sha256="sha256:" + hashlib.sha256(artifact_bytes).hexdigest(),
            size=len(artifact_bytes),
            role="bundle_payload",
        )
        manifest = BundlePlan(
            schema_version=BUNDLE_PLAN_SCHEMA_VERSION,
            tool_id=ir.tool_id,
            kind=ir.kind,
            target_fingerprint=target_fingerprint,
            dsl_digest=dsl_digest,
            context_digest=context_digest,
            ir_digest=canonical_ir_digest,
            compiler_version=compiler_version,
            backend_id=self.backend_id,
            backend_version=self.backend_version,
            negotiated_capabilities=negotiated_capabilities,
            entrypoint_contract="rolo.tool.invoke/v1",
            bindings=bindings,
            runtime_requirements=runtime_requirements,
            runtime_context=runtime_context,
            source_bundle_ref=source_bundle_ref,
            artifacts=(artifact,),
        )
        digest = bundle_plan_digest(manifest)
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / artifact.path).write_bytes(artifact_bytes)
        (output_dir / "manifest.json").write_text(json.dumps(manifest.model_dump(mode="json"), ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        return GeneratedBundle(self.backend_id, manifest, digest)

    def conformance(self, bundle: GeneratedBundle) -> bool:
        return (
            bundle.backend_id == self.backend_id
            and bundle.manifest.backend_id == self.backend_id
            and bundle.manifest.backend_version == self.backend_version
            and bundle.manifest.negotiated_capabilities == tuple(sorted(self.capabilities()))
            and bundle.digest == bundle_plan_digest(bundle.manifest)
        )


class Ros2ObserveBackend(FakeBackend):
    def __init__(self):
        super().__init__("ros2_observe", ("OBSERVE",), runtime_requirements=("ros2",))


class Ros2InvokeBackend(FakeBackend):
    def __init__(self):
        super().__init__("ros2_invoke", ("INVOKE",), runtime_requirements=("ros2",))


class MhsOperationBackend(FakeBackend):
    def __init__(self):
        super().__init__("mhs_operation", ("INVOKE",), runtime_requirements=("mhs",))


class WorkflowBackend(FakeBackend):
    def __init__(self):
        super().__init__("workflow", ("COMPOSE",))


class GeneratedRuntimeBackend(FakeBackend):
    def __init__(self):
        super().__init__("generated_runtime", ("EXECUTE",))


def default_backends() -> tuple[FakeBackend, ...]:
    return (Ros2ObserveBackend(), Ros2InvokeBackend(), WorkflowBackend(), GeneratedRuntimeBackend())


def backend_capability_matrix(backends: Iterable[RoloDslBackend] | None = None) -> dict[str, dict[str, str | tuple[str, ...]]]:
    """Return a deterministic, serializable capability advertisement."""

    selected = tuple(backends or default_backends())
    return {
        backend.backend_id: {
            "backend_version": backend.backend_version,
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
    """Select a backend only when its SPI and capabilities match exactly.

    A backend method named ``compile_v2`` is not evidence that the backend
    implements the frozen v2 SPI.  Reject an in-scope advertisement with a
    different or missing version before returning any backend so a mixed
    plugin registry cannot silently downgrade the compiler contract.
    """

    required = tuple(sorted(set(str(item) for item in required_capabilities)))
    candidates = tuple(backends or default_backends())
    matching = tuple(
        backend
        for backend in candidates
        if backend.supports_kind(kind)
        if backend_id is None or backend.backend_id == backend_id
        if all(capability in backend.capabilities() for capability in required)
    )
    if any(getattr(backend, "backend_version", None) != BACKEND_SPI_VERSION for backend in matching):
        raise BackendSpiVersionError("BACKEND_SPI_VERSION_UNSUPPORTED")
    return matching[0] if matching else None


def _runtime_requirements(ir: CanonicalIR) -> tuple[str, ...]:
    requirements: list[str] = []
    payloads = (ir.binding, ir.implementation) if ir.kind == "EXECUTE" else (ir.binding,)
    for payload in payloads:
        declared = payload.get("runtime_requirements")
        if isinstance(declared, str):
            requirements.append(declared)
        elif isinstance(declared, (list, tuple)):
            requirements.extend(str(item) for item in declared if str(item))
        runtime = payload.get("runtime")
        if isinstance(runtime, str) and runtime:
            requirements.append(runtime)
    return tuple(sorted(set(requirements)))


def _string_value(payload: dict, *keys: str) -> str | None:
    for key in keys:
        value = payload.get(key)
        if isinstance(value, str) and value:
            return value
    return None
