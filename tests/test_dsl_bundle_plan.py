from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path
from threading import Event, Thread

import pytest
from pydantic import ValidationError

import rolo.dsl.compiler as compiler_module
from rolo.dsl.admission import MappingAdmissionError, MappingConfirmationStore
from rolo.dsl.api import DslCompileRequest
from rolo.dsl.backends import (
    BackendSpiVersionError,
    FakeBackend,
    GeneratedBundle,
    Ros2ObserveBackend,
    negotiate_backend,
)
from rolo.dsl.bundle_plan import BundleArtifact, BundlePlan, BundlePlanVersionError, parse_bundle_plan
from rolo.dsl.canonical import bundle_plan_digest, canonical_bytes, context_digest, dsl_digest
from rolo.dsl.compiler import compile_text
from rolo.dsl.conformance import conformance
from rolo.dsl.contracts import BACKEND_SPI_VERSION, BUNDLE_PLAN_SCHEMA_VERSION, COMPILE_REQUEST_SCHEMA_VERSION, CONTRACT_VERSIONS
from rolo.dsl.frontend import compile_frontend
from rolo.dsl.parser import parse_document
from rolo.dsl.service import RoloDslCompiler


def _observe_document(
    binding: dict | None = None,
    *,
    evidence_digest_value: str = "sha256:" + "e" * 64,
):
    payload = {
        "tool_id": "app.state",
        "kind": "OBSERVE",
        "target": {"robot_id": "r", "evidence_digest": evidence_digest_value},
        "binding": binding or {"resource_id": "route:/state", "protocol": "ros_topic"},
    }
    document, report = parse_document(payload)
    assert document is not None and report.ok
    return document


def _compile_backend(backend, ir, output_dir, document_digest):
    return backend.compile_v2(
        ir,
        output_dir,
        dsl_digest=document_digest,
        context_digest="sha256:" + "3" * 64,
        target_fingerprint="target-1",
        compiler_version="rolo-compiler/0.1",
        negotiated_capabilities=backend.capabilities(),
        bindings=(ir.binding,) if ir.binding else (),
        runtime_context={},
    )


def test_bundle_plan_canonical_golden_vector() -> None:
    plan = BundlePlan(
        schema_version="rolo-bundle-plan/v2",
        tool_id="app.state",
        kind="OBSERVE",
        target_fingerprint="target-1",
        dsl_digest="sha256:" + "1" * 64,
        context_digest="sha256:" + "3" * 64,
        ir_digest="sha256:" + "2" * 64,
        compiler_version="rolo-compiler/0.1",
        backend_id="fake_runtime",
        backend_version="rolo-backend-spi/v2",
        negotiated_capabilities=("operation:OBSERVE",),
        entrypoint_contract="rolo.tool.invoke/v1",
        bindings=({"resource_id": "route:/state", "protocol": "ros_topic"},),
        runtime_requirements=("ros2",),
        runtime_context={},
        source_bundle_ref=None,
        artifacts=(BundleArtifact(path="bundle-payload.json", sha256="sha256:" + "4" * 64, size=42, role="bundle_payload"),),
    )
    assert b'"source_bundle_ref":null' in canonical_bytes(plan)
    assert canonical_bytes(plan) == canonical_bytes(plan.model_dump(mode="json"))
    assert bundle_plan_digest(plan) == "sha256:8f2167bffdc972ff719459219bf4bbabe701726ab3c886ccde099163349f8a37"


def test_bundle_plan_cross_language_golden_fixture() -> None:
    fixture_path = (
        Path(__file__).parent
        / "fixtures"
        / "dsl_contract_pack"
        / "bundle-plan-v2.golden.json"
    )
    fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
    plan = BundlePlan.model_validate(fixture["value"])

    assert fixture["schema_version"] == "rolo-canonical-golden/v1"
    assert fixture["contract"] == BUNDLE_PLAN_SCHEMA_VERSION
    assert canonical_bytes(plan).decode("utf-8") == fixture["canonical_utf8"]
    assert bundle_plan_digest(plan) == fixture["sha256"]


def test_bundle_plan_schema_matches_strict_model() -> None:
    schema = json.loads((Path(__file__).parents[1] / "schemas/rolo-dsl/v1/bundle-plan.json").read_text(encoding="utf-8"))
    fields = set(BundlePlan.model_fields)
    assert schema["additionalProperties"] is False
    assert schema["properties"]["schema_version"]["const"] == BUNDLE_PLAN_SCHEMA_VERSION == "rolo-bundle-plan/v2"
    assert CONTRACT_VERSIONS["backend_spi"] == BACKEND_SPI_VERSION == "rolo-backend-spi/v2"
    assert set(schema["required"]) == fields
    assert set(schema["properties"]) == fields


def test_legacy_plan_and_backend_spi_require_explicit_recompile(tmp_path) -> None:
    legacy = {
        "schema_version": "rolo-bundle-plan/v1",
        "tool_id": "app.state",
        "kind": "OBSERVE",
        "backend_id": "fake_runtime",
        "ir_digest": "sha256:" + "2" * 64,
    }
    with pytest.raises(BundlePlanVersionError, match="BUNDLE_PLAN_V1_RECOMPILE_REQUIRED"):
        parse_bundle_plan(legacy)
    with pytest.raises(BundlePlanVersionError, match="BUNDLE_PLAN_VERSION_REQUIRED"):
        parse_bundle_plan({key: value for key, value in legacy.items() if key != "schema_version"})

    document = _observe_document()
    ir, report, _ = compile_frontend(document)
    assert ir is not None and report.ok
    with pytest.raises(BackendSpiVersionError, match="BACKEND_SPI_V1_RECOMPILE_REQUIRED"):
        FakeBackend("fake_runtime", ("OBSERVE",)).compile(ir, tmp_path)


def test_backend_negotiation_rejects_incompatible_or_missing_spi_version() -> None:
    incompatible = FakeBackend(
        "fake_runtime",
        ("OBSERVE",),
        backend_version="rolo-backend-spi/v1",
    )
    with pytest.raises(BackendSpiVersionError, match="BACKEND_SPI_VERSION_UNSUPPORTED"):
        negotiate_backend("OBSERVE", backends=(incompatible,))

    del incompatible.backend_version
    with pytest.raises(BackendSpiVersionError, match="BACKEND_SPI_VERSION_UNSUPPORTED"):
        negotiate_backend("OBSERVE", backends=(incompatible,))


def test_compiler_rechecks_backend_spi_after_negotiation(
    tmp_path,
    monkeypatch,
    mapping_confirmation_factory,
) -> None:
    document = _observe_document()
    dsl = document.model_dump(mode="json")
    context = {
        "robot_id": "r",
        "target_fingerprint": "target-1",
        "evidence_digest": document.target.evidence_digest,
        "evidence_refs": ["route:/state"],
    }
    confirmed = mapping_confirmation_factory(dsl, context)
    incompatible = FakeBackend(
        "ros2_observe",
        ("OBSERVE",),
        backend_version="rolo-backend-spi/v3",
    )
    monkeypatch.setattr(
        compiler_module,
        "negotiate_backend",
        lambda *_args, **_kwargs: incompatible,
    )

    output = tmp_path / "compile"
    result = compile_text(dsl, output, context, **confirmed.compiler_kwargs)

    assert not result.ok and result.bundle is None
    assert [item.code for item in result.report.diagnostics] == [
        "BACKEND_SPI_VERSION_UNSUPPORTED"
    ]
    assert not output.exists()


def test_bundle_plan_is_strict_and_has_stable_canonical_bytes(tmp_path) -> None:
    document = _observe_document()
    ir, report, document_digest = compile_frontend(document)
    assert ir is not None and report.ok
    bundle = _compile_backend(FakeBackend("fake_runtime", ("OBSERVE",)), ir, tmp_path, document_digest)

    # A caller constructing the same payload with a different key order gets
    # identical bytes and a typed plan rejects undeclared envelope fields.
    payload = bundle.manifest.model_dump(mode="json")
    reordered = dict(reversed(tuple(payload.items())))
    assert canonical_bytes(payload) == canonical_bytes(reordered)
    assert canonical_bytes(bundle.manifest) == canonical_bytes(payload)
    assert bundle_plan_digest(payload) == bundle.digest
    with pytest.raises(ValidationError):
        BundlePlan.model_validate({**payload, "shell": "rm -rf /"})
    with pytest.raises(ValidationError):
        BundlePlan.model_validate({key: value for key, value in payload.items() if key != "source_bundle_ref"})
    with pytest.raises(ValidationError):
        BundlePlan.model_validate({**payload, "bindings": [{"nested": {"shell": "echo unsafe"}}]})
    with pytest.raises(ValidationError):
        BundlePlan.model_validate({**payload, "negotiated_capabilities": []})
    with pytest.raises(ValidationError):
        BundlePlan.model_validate({**payload, "artifacts": []})
    with pytest.raises(ValidationError, match="normalized relative POSIX path"):
        BundlePlan.model_validate(
            {
                **payload,
                "artifacts": [
                    {
                        "path": "nested//bundle-payload.json",
                        "sha256": "sha256:" + "4" * 64,
                        "size": 42,
                        "role": "bundle_payload",
                    }
                ],
            }
        )


def test_bundle_digest_covers_backend_bindings_and_runtime(tmp_path) -> None:
    document = _observe_document()
    ir, report, document_digest = compile_frontend(document)
    assert ir is not None and report.ok
    base = _compile_backend(FakeBackend("backend-a", ("OBSERVE",)), ir, tmp_path / "base", document_digest)
    backend_changed = base.manifest.model_copy(update={"backend_id": "backend-b"})
    backend_version_changed = base.manifest.model_copy(update={"backend_version": "rolo-backend-spi/v3"})
    capability_changed = base.manifest.model_copy(update={"negotiated_capabilities": ("operation:OBSERVE", "feature:new")})
    context_changed = base.manifest.model_copy(update={"context_digest": "sha256:" + "9" * 64})
    binding_changed = base.manifest.model_copy(update={"bindings": ({"resource_id": "route:/other", "protocol": "ros_topic"},)})
    runtime_changed = base.manifest.model_copy(update={"runtime_requirements": ("ros2",)})
    runtime_context_changed = base.manifest.model_copy(update={"runtime_context": {"runtime_revision": "changed"}})
    artifact_changed = base.manifest.model_copy(
        update={"artifacts": (BundleArtifact(path="bundle-payload.json", sha256="sha256:" + "8" * 64, size=1, role="bundle_payload"),)}
    )

    changed = (backend_changed, backend_version_changed, capability_changed, context_changed, binding_changed, runtime_changed, runtime_context_changed, artifact_changed)
    assert all(bundle_plan_digest(plan) != base.digest for plan in changed)
    assert len({bundle_plan_digest(plan) for plan in changed}) == len(changed)


def test_ros_backend_declares_its_runtime_requirement(tmp_path) -> None:
    document = _observe_document()
    ir, report, document_digest = compile_frontend(document)
    assert ir is not None and report.ok
    bundle = _compile_backend(Ros2ObserveBackend(), ir, tmp_path, document_digest)
    assert bundle.manifest.runtime_requirements == ("ros2",)


def test_fake_backend_persists_complete_typed_bundle_plan(tmp_path, mapping_confirmation_factory) -> None:
    dsl = {
        "tool_id": "app.generated",
        "kind": "EXECUTE",
        "target": {"robot_id": "r", "evidence_digest": "sha256:" + "e" * 64},
        "implementation": {
            "source_bundle_digest": "sha256:source",
            "entrypoint": "main:run",
            "runtime": "python3.12",
            "implementation_contract": "v1",
        },
    }
    context = {"robot_id": "r", "target_fingerprint": "target-1", "evidence_digest": "sha256:" + "e" * 64}
    confirmed = mapping_confirmation_factory(dsl, context)
    output = tmp_path / "compile"
    result = compile_text(
        dsl,
        output,
        context,
        **confirmed.compiler_kwargs,
    )

    assert result.ok and result.bundle is not None
    plan = result.bundle.manifest
    assert isinstance(plan, BundlePlan)
    assert plan.target_fingerprint == "target-1"
    assert plan.dsl_digest == result.dsl_digest
    assert plan.context_digest == context_digest({"robot_id": "r", "target_fingerprint": "target-1", "evidence_digest": "sha256:" + "e" * 64})
    assert plan.backend_version == "rolo-backend-spi/v2"
    assert plan.negotiated_capabilities == ("operation:EXECUTE",)
    assert plan.runtime_requirements == ("python3.12",)
    assert plan.source_bundle_ref == "sha256:source"
    assert [artifact.path for artifact in plan.artifacts] == ["bundle-payload.json"]
    artifact = plan.artifacts[0]
    artifact_bytes = (output / artifact.path).read_bytes()
    assert artifact.size == len(artifact_bytes)
    assert artifact.sha256 == "sha256:" + hashlib.sha256(artifact_bytes).hexdigest()
    assert result.bundle.digest == bundle_plan_digest(plan)
    assert json.loads((output / "manifest.json").read_text(encoding="utf-8")) == plan.model_dump(mode="json")


def test_compilation_without_target_fingerprint_fails_closed(tmp_path) -> None:
    result = compile_text(
        _observe_document().model_dump(mode="json"),
        tmp_path / "compile",
        confirmation_store=MappingConfirmationStore(tmp_path / "admission"),
        confirmation_receipt_digest="sha256:" + "0" * 64,
        journey_session_id="journey-missing-target",
    )
    assert not result.ok
    assert result.bundle is None
    assert [item.code for item in result.report.diagnostics] == ["TARGET_FINGERPRINT_REQUIRED"]
    assert not (tmp_path / "compile").exists()


def test_conformance_rejects_plan_digest_tampering(tmp_path, mapping_confirmation_factory) -> None:
    dsl = _observe_document().model_dump(mode="json")
    context = {"robot_id": "r", "target_fingerprint": "target-1", "evidence_digest": "sha256:" + "e" * 64, "evidence_refs": ["route:/state"]}
    confirmed = mapping_confirmation_factory(dsl, context)
    result = compile_text(
        dsl,
        tmp_path / "compile",
        context,
        **confirmed.compiler_kwargs,
    )
    assert result.bundle is not None and conformance(result).ok
    changed_plan = result.bundle.manifest.model_copy(update={"runtime_requirements": ("different-runtime",)})
    result.bundle = replace(result.bundle, manifest=changed_plan)
    assert [item.code for item in conformance(result).diagnostics] == ["BUNDLE_DIGEST_MISMATCH"]


def test_service_keeps_public_bundle_digest_as_plan_digest(tmp_path, mapping_confirmation_factory) -> None:
    evidence_digest_value = "sha256:" + "e" * 64
    document = _observe_document(evidence_digest_value=evidence_digest_value)
    context = {
        "robot_id": "r",
        "target_fingerprint": "target-1",
        "evidence_digest": evidence_digest_value,
        "evidence_refs": ["route:/state"],
    }
    dsl = document.model_dump(mode="json")
    confirmed = mapping_confirmation_factory(dsl, context)
    result = RoloDslCompiler(confirmed.store).compile(
        DslCompileRequest(
            schema_version=COMPILE_REQUEST_SCHEMA_VERSION,
            journey_session_id=confirmed.receipt.journey_session_id,
            confirmation_receipt_digest=confirmed.receipt.receipt_digest,
            dsl=dsl,
            dsl_digest=dsl_digest(document),
            context=context,
            context_digest=context_digest(context),
            target_fingerprint="target-1",
        ),
        tmp_path / "compile",
    )
    persisted = BundlePlan.model_validate(json.loads((tmp_path / "compile" / "manifest.json").read_text(encoding="utf-8")))
    assert result.status == "PASS"
    assert result.bundle_digest == bundle_plan_digest(persisted)


def test_generated_bundle_normalizes_mapping_manifest(tmp_path, mapping_confirmation_factory) -> None:
    dsl = _observe_document().model_dump(mode="json")
    context = {"robot_id": "r", "target_fingerprint": "target-1", "evidence_digest": "sha256:" + "e" * 64, "evidence_refs": ["route:/state"]}
    confirmed = mapping_confirmation_factory(dsl, context)
    result = compile_text(
        dsl,
        tmp_path / "compile",
        context,
        **confirmed.compiler_kwargs,
    )
    assert result.bundle is not None
    copied = GeneratedBundle(result.bundle.backend_id, result.bundle.manifest.model_dump(mode="json"), result.bundle.digest)
    assert isinstance(copied.manifest, BundlePlan)


def test_public_compiler_requires_admission_before_frontend_or_artifacts(tmp_path, monkeypatch) -> None:
    document = _observe_document()
    context = {"robot_id": "r", "target_fingerprint": "target-1", "evidence_digest": document.target.evidence_digest, "evidence_refs": ["route:/state"]}

    def forbidden(*_args, **_kwargs):
        raise AssertionError("compiler internals must not run before Mapping admission")

    monkeypatch.setattr(compiler_module, "compile_frontend", forbidden)
    monkeypatch.setattr(compiler_module, "negotiate_backend", forbidden)
    output = tmp_path / "blocked"
    result = compile_text(document.model_dump(mode="json"), output, context)

    assert not result.ok and result.ir is None and result.bundle is None
    assert [item.code for item in result.report.diagnostics] == [
        "MAPPING_CONFIRMATION_STORE_REQUIRED"
    ]
    assert not output.exists()


def test_compiler_cancellation_during_backend_cleans_staging(
    tmp_path,
    monkeypatch,
    mapping_confirmation_factory,
) -> None:
    document = _observe_document()
    dsl = document.model_dump(mode="json")
    context = {"robot_id": "r", "target_fingerprint": "target-1", "evidence_digest": document.target.evidence_digest, "evidence_refs": ["route:/state"]}
    confirmed = mapping_confirmation_factory(dsl, context)

    class CancellingBackend(FakeBackend):
        def compile_v2(self, *args, **kwargs):
            bundle = super().compile_v2(*args, **kwargs)
            confirmed.store.cancel(
                confirmed.receipt.receipt_digest,
                decision_id="cancel-during-backend",
                actor_id="test-operator",
            )
            return bundle

    monkeypatch.setattr(
        compiler_module,
        "negotiate_backend",
        lambda *_args, **_kwargs: CancellingBackend("ros2_observe", ("OBSERVE",)),
    )
    output = tmp_path / "compile"
    result = compile_text(dsl, output, context, **confirmed.compiler_kwargs)

    assert not result.ok and result.bundle is None
    assert [item.code for item in result.report.diagnostics] == [
        "MAPPING_CONFIRMATION_CANCELLED"
    ]
    assert not output.exists()
    assert not tuple(tmp_path.glob(".compile.staging-*"))


def test_compiler_commit_is_linearized_before_concurrent_cancel(
    tmp_path,
    monkeypatch,
    mapping_confirmation_factory,
) -> None:
    document = _observe_document()
    dsl = document.model_dump(mode="json")
    context = {"robot_id": "r", "target_fingerprint": "target-1", "evidence_digest": document.target.evidence_digest, "evidence_refs": ["route:/state"]}
    confirmed = mapping_confirmation_factory(dsl, context)
    replace_entered = Event()
    cancel_done = Event()
    cancel_errors: list[Exception] = []
    original_replace = compiler_module.os.replace

    def cancel_when_commit_starts() -> None:
        replace_entered.wait(timeout=2)
        try:
            confirmed.store.cancel(
                confirmed.receipt.receipt_digest,
                decision_id="cancel-concurrent-commit",
                actor_id="test-operator",
            )
        except Exception as exc:  # pragma: no cover - asserted below
            cancel_errors.append(exc)
        finally:
            cancel_done.set()

    def delayed_replace(source, destination) -> None:
        replace_entered.set()
        assert not cancel_done.wait(timeout=0.1)
        original_replace(source, destination)

    monkeypatch.setattr(compiler_module.os, "replace", delayed_replace)
    worker = Thread(target=cancel_when_commit_starts)
    worker.start()
    output = tmp_path / "compile"
    result = compile_text(dsl, output, context, **confirmed.compiler_kwargs)
    worker.join(timeout=2)

    assert not worker.is_alive() and not cancel_errors and cancel_done.is_set()
    assert result.ok and (output / "manifest.json").is_file()
    with pytest.raises(MappingAdmissionError, match="MAPPING_CONFIRMATION_CANCELLED"):
        compiler_module._require_compile_admission(
            document,
            compiler_module.CompileContext.model_validate(context),
            result.dsl_digest,
            **confirmed.compiler_kwargs,
        )
