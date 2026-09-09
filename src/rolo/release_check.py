"""Minimal release smoke checks for the product entrypoints."""

from __future__ import annotations

import importlib
import json
from pathlib import Path

try:  # Python 3.10 uses the declared tomli compatibility dependency.
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - exercised on Python 3.10 only
    import tomli as tomllib

from pydantic import BaseModel, Field

from rolo.agent_tools import (
    NativeToolSessionDescriptor,
    ToolConformanceReport,
    ToolPlan,
    reduced_agent_native_catalog,
)
from rolo.core.signed_artifacts import SignedArtifact, SignedArtifactStore
from rolo.dsl.admission import (
    MappingAdmissionIdentity,
    MappingAdmissionScope,
    MappingConfirmationReceipt,
    MappingConfirmationStore,
    mapping_digest,
)
from rolo.dsl.api import DslCheckRequest, DslCompileRequest
from rolo.dsl.candidates import build_candidate_index
from rolo.dsl.canonical import context_digest
from rolo.dsl.context import ProbeContext
from rolo.dsl.contracts import COMPILE_REQUEST_SCHEMA_VERSION
from rolo.dsl.mapping import AdapterMappingRequest
from rolo.dsl.models import DslDocument, OperationKind
from rolo.dsl.proposal import MappingProposal, build_mapping_proposal, persist_mapping_proposal
from rolo.dsl.service import RoloDslCompiler
from rolo.mvp import CertificationReport, TargetCatalog, TraceSessionRequest
from rolo.probe_baseline import (
    BaselineArtifactIndex,
    ProbeBaselineManifest,
    ReadOnlyCompletion,
)
from rolo.releases.journey import PostCompilerJourneyResult
from rolo.releases.publisher import TargetConformanceReport
from rolo.rkb import EvidenceEnvelope
from rolo.stages.probe.application import (
    ApplicationAdapterBundle,
    ApplicationCandidate,
    ApplicationConformanceReport,
    ApplicationOperationAdapterBundle,
    ApplicationOperationCandidate,
    ApplicationOperationConformanceReport,
)
from rolo.stages.probe.target_evidence import TargetEvidenceBundle
from rolo.targetd import (
    ExecutionBundleManifest,
    ExecutionRequest,
    JourneyPhase,
    JourneySession,
    ProtocolFrame,
    TargetdCallReceipt,
    TargetdExecutionAuthority,
    TargetdExecutionAuthorityStore,
)


def _targetd_transport_idempotency_smoke() -> None:
    """Check non-motion targetd v2 admission, fencing, and idempotency."""
    from datetime import datetime, timedelta, timezone
    from tempfile import TemporaryDirectory

    from rolo.targetd import TargetdService

    with TemporaryDirectory(prefix="rolo-targetd-replay-") as root:
        source = b"def execute(arguments): return arguments"
        manifest = ExecutionBundleManifest.build(
            tool_id="app.observe.odom",
            source=source,
            binding_digest="a" * 64,
            signer_key_id="replay",
            signing_key=b"replay-key",
            observation_contract={
                "provider": "ros2-readonly",
                "operation": "odom.sample",
            },
        )
        now = datetime.now(timezone.utc)
        context_value = mapping_digest({"kind": "targetd-release-check-context"})
        mapping_identity = MappingAdmissionIdentity.build(
            journey_session_id="replay-session",
            target_id="replay",
            target_fingerprint="release-check-target-fingerprint",
            candidate_index_digest=mapping_digest({"kind": "candidate-index"}),
            candidate_digest=mapping_digest({"kind": "candidate"}),
            proposal_digest=mapping_digest({"kind": "proposal"}),
            dsl_digest=mapping_digest({"kind": "dsl"}),
            context_digest=context_value,
            evidence_digest=mapping_digest({"kind": "evidence"}),
            available_tool_catalog_digest=mapping_digest({"kind": "available-catalog"}),
            scope=MappingAdmissionScope(
                tool_id=manifest.tool_id,
                operation_kind=OperationKind.OBSERVE,
                operations=("odom.sample",),
                access="read",
                risk="R0",
            ),
        )
        confirmation_store = MappingConfirmationStore(Path(root) / "admission")
        confirmation = confirmation_store.confirm(
            mapping_identity,
            decision_id="targetd-release-check-confirm",
            actor_id="release-check",
            ttl_s=300,
            decided_at=now,
        )
        authority = TargetdExecutionAuthority.build(
            tool_id=manifest.tool_id,
            target_id="replay",
            target_fingerprint=mapping_identity.target_fingerprint,
            bundle_digest=manifest.bundle_digest,
            binding_digest=manifest.binding_digest,
            surface_digest="b" * 64,
            release_digest=mapping_digest({"kind": "release"}),
            context_digest=context_value,
            mapping_confirmation_receipt_digest=confirmation.receipt_digest,
            mapping_admission=mapping_identity,
            catalog_head_digest=mapping_digest({"kind": "catalog-head"}),
            provider_id="ros2-readonly",
            provider_operation="odom.sample",
            mode="REPLAY",
            fence_epoch=1,
        )
        authority_store = TargetdExecutionAuthorityStore(Path(root) / "authority")
        authority_store.publish(authority)
        service = TargetdService(
            target_id="replay",
            state_root=Path(root) / "state",
            signing_key=b"replay-key",
            confirmation_store=confirmation_store,
            execution_authority_store=authority_store,
        )
        session = service.open_session(
            JourneySession.create(session_id="replay-session", target_id="replay", profile_id="replay").model_copy(update={"phase": JourneyPhase.TRACE, "surface_digest": authority.surface_digest})
        )
        service.put_bundle(manifest, source)
        request = ExecutionRequest(
            schema_version="rolo-execution-request/v2",
            run_id="replay-run",
            session_id=session.session_id,
            target_id="replay",
            idempotency_key="replay-call",
            bundle_digest=manifest.bundle_digest,
            binding_digest=manifest.binding_digest,
            surface_digest=authority.surface_digest,
            release_digest=authority.release_digest,
            context_digest=authority.context_digest,
            mapping_confirmation_receipt_digest=authority.mapping_confirmation_receipt_digest,
            authority_head_digest=authority.authority_head_digest,
            fence_epoch=authority.fence_epoch,
            provider_id=authority.provider_id,
            provider_operation=authority.provider_operation,
            authority=authority,
            arguments={},
            mode="REPLAY",
            deadline=datetime.now(timezone.utc) + timedelta(seconds=30),
        )
        service.accept_call(request, manifest, provider_id="ros2-readonly")
        service.start_call(request, manifest, provider_id="ros2-readonly")
        completed = service.execute_provider(
            request,
            manifest,
            provider_id="ros2-readonly",
            execute=lambda: ("SUCCEEDED", {"ok": True}),
        )
        second = service.accept_call(request, manifest, provider_id="ros2-readonly")
        if second != completed or service.query_call(request.session_id, request.idempotency_key) != completed:
            raise ValueError("targetd replay idempotency invariant failed")


def _confirmed_mapping_admission_smoke(root: Path | None = None) -> None:
    """Compile only an exact confirmed Proposal and fail closed after cancel.

    The smoke uses the production Proposal builder, confirmation ledger, and
    compiler boundary.  Supplying ``root`` is useful for tests that need to
    inspect whether a cancelled attempt reached the artifact boundary.
    """
    from tempfile import TemporaryDirectory

    if root is None:
        with TemporaryDirectory(prefix="rolo-mapping-admission-") as temporary:
            _run_confirmed_mapping_admission_smoke(Path(temporary))
        return
    _run_confirmed_mapping_admission_smoke(root)


def _run_confirmed_mapping_admission_smoke(root: Path) -> None:
    from datetime import datetime, timezone

    evidence_digest = "sha256:" + "e" * 64
    context = ProbeContext(
        robot_id="release-check-target",
        target_fingerprint="release-check-fingerprint",
        evidence_digest=evidence_digest,
        evidence_refs=("artifact://release-check/probe-evidence",),
        routes=(
            {
                "operation": "app.release.check",
                "route_id": "app.release.check",
                "resource_id": "route:/release-check/state",
                "evidence_ref": "artifact://release-check/probe-evidence",
            },
        ),
    )
    document = DslDocument(
        tool_id="app.release.check",
        kind="OBSERVE",
        target={
            "robot_id": context.robot_id,
            "evidence_digest": evidence_digest,
        },
        binding={"resource_id": "route:/release-check/state"},
        evidence_refs=("artifact://release-check/probe-evidence",),
    )
    candidate_index = build_candidate_index(context)
    mapping_request = AdapterMappingRequest(
        journey_session_id="release-check-journey",
        user_goal="verify the confirmed Mapping admission boundary",
        context_digest=candidate_index.context_digest,
        available_tool_catalog_digest="sha256:" + "c" * 64,
        operation_candidates=(document.tool_id,),
    )
    proposal = build_mapping_proposal(
        mapping_request,
        candidate_index,
        candidate_index.candidates[0],
        dsl=document,
        context=context,
        scope=MappingAdmissionScope(
            tool_id=document.tool_id,
            operation_kind=document.kind,
            operations=(document.tool_id,),
            access="read",
            risk="R0",
        ),
    )
    persist_mapping_proposal(proposal, root / "proposal-store")

    confirmation_store = MappingConfirmationStore(root / "confirmation-store")
    now = datetime.now(timezone.utc)
    receipt = confirmation_store.confirm(
        proposal.admission_identity(),
        decision_id="release-check-confirm",
        actor_id="release-check",
        ttl_s=300,
        decided_at=now,
    )
    compiler = RoloDslCompiler(confirmation_store)
    checked = compiler.check(
        DslCheckRequest(
            dsl=document.model_dump(mode="json"),
            context=context.model_dump(mode="json"),
        )
    )
    if checked.status != "PASS":
        raise ValueError(f"Mapping proposal pre-check failed: {checked.diagnostics}")
    compile_request = DslCompileRequest(
        schema_version=COMPILE_REQUEST_SCHEMA_VERSION,
        request_id="release-check-compile",
        journey_session_id=proposal.journey_session_id,
        confirmation_receipt_digest=receipt.receipt_digest,
        dsl=document.model_dump(mode="json"),
        context=context.model_dump(mode="json"),
        dsl_digest=proposal.dsl_digest,
        context_digest=context_digest(context),
        target_fingerprint=context.target_fingerprint,
    )
    confirmed_output = root / "confirmed-compile"
    compiled = compiler.compile(compile_request, confirmed_output)
    if (
        compiled.status != "PASS"
        or compiled.confirmation_receipt_digest != receipt.receipt_digest
        or not compiled.artifacts
        or any(not (confirmed_output / relative_path).is_file() for relative_path in compiled.artifacts.values())
    ):
        raise ValueError(f"confirmed Mapping admission did not produce a bound compile result: {compiled.diagnostics}")

    confirmation_store.cancel(
        receipt.receipt_digest,
        decision_id="release-check-cancel",
        actor_id="release-check",
    )
    cancelled_output = root / "cancelled-compile"
    cancelled = compiler.compile(compile_request, cancelled_output)
    if cancelled.status != "DSL_COMPILE_FAILED" or "MAPPING_CONFIRMATION_CANCELLED" not in cancelled.diagnostics or cancelled_output.exists():
        raise ValueError(f"cancelled Mapping confirmation crossed the artifact boundary: status={cancelled.status}, diagnostics={cancelled.diagnostics}")


def _require_schema_version(
    model: type[BaseModel],
    *,
    expected: str,
) -> None:
    schema = model.model_json_schema()
    actual = schema.get("properties", {}).get("schema_version", {}).get("const")
    if actual != expected:
        raise ValueError(f"{model.__name__} schema version mismatch: expected {expected}, got {actual}")


def _certify_fixture_check() -> None:
    """Keep the ten-case chassis rotation replay contract in the release gate."""
    fixture = Path(__file__).resolve().parents[2] / "examples" / "chassis-rotation-10.json"
    payload = json.loads(fixture.read_text(encoding="utf-8"))
    cases = payload.get("cases")
    if not isinstance(cases, list) or len(cases) != 10:
        raise ValueError("chassis rotation certify fixture must contain exactly ten cases")
    for case in cases:
        if not isinstance(case, dict) or {"case_id", "angle_degrees", "max_speed_rad_s"} - set(case):
            raise ValueError("chassis rotation certify fixture case is incomplete")


class ReleaseCheckResult(BaseModel):
    schema_version: str = "rolo-release-check/v1"
    status: str
    checks: list[str] = Field(default_factory=list)
    failures: list[str] = Field(default_factory=list)


def run_release_check(
    pyproject_path: Path | None = None,
    *,
    dist_path: Path | None = None,
    require_artifacts: bool = False,
) -> ReleaseCheckResult:
    checks: list[str] = []
    failures: list[str] = []
    for module in (
        "rolo.product_cli",
        "rolo.cli",
        "rolo.targets.executor",
        "rolo.agent_tools.session_factory",
        "rolo.stages.probe.application",
        "rolo.stages.probe.target_evidence",
        "rolo.rkb",
        "rolo.probe_baseline",
        "rolo.harness",
        "rolo.mvp",
        "rolo.targetd",
        "rolo.core.signed_artifacts",
    ):
        try:
            importlib.import_module(module)
            checks.append(f"import:{module}")
        except Exception as exc:  # pragma: no cover - defensive release boundary
            failures.append(f"import:{module}: {exc}")
    path = pyproject_path or Path(__file__).resolve().parents[2] / "pyproject.toml"
    if path.is_file():
        try:
            scripts = tomllib.loads(path.read_text(encoding="utf-8"))["project"]["scripts"]
            for name in ("rolo", "robotctl"):
                if name not in scripts:
                    failures.append(f"missing console script: {name}")
                else:
                    checks.append(f"console-script:{name}")
        except (OSError, KeyError, TypeError, tomllib.TOMLDecodeError) as exc:
            failures.append(f"pyproject: {exc}")
    else:
        failures.append(f"missing pyproject: {path}")
    try:
        if not reduced_agent_native_catalog():
            failures.append("native catalog is empty")
        else:
            checks.append("native-catalog:registered")
        for model, label in (
            (TargetEvidenceBundle, "target-evidence-bundle"),
            (NativeToolSessionDescriptor, "native-tool-session"),
            (ToolPlan, "tool-plan"),
            (ToolConformanceReport, "tool-conformance"),
            (ApplicationCandidate, "application-candidate"),
            (ApplicationAdapterBundle, "application-adapter-bundle"),
            (ApplicationConformanceReport, "application-conformance"),
            (ApplicationOperationCandidate, "application-operation-candidate"),
            (ApplicationOperationAdapterBundle, "application-operation-adapter-bundle"),
            (ApplicationOperationConformanceReport, "application-operation-conformance"),
            (EvidenceEnvelope, "robot-evidence-envelope"),
            (ProbeBaselineManifest, "probe-baseline-manifest"),
            (BaselineArtifactIndex, "probe-baseline-artifact-index"),
            (ReadOnlyCompletion, "read-only-completion"),
            (TargetCatalog, "mvp-target-catalog"),
            (TraceSessionRequest, "mvp-trace-session-request"),
            (CertificationReport, "mvp-certification-report"),
            (ExecutionBundleManifest, "execution-bundle-manifest"),
            (ExecutionRequest, "execution-request"),
            (JourneySession, "journey-session"),
            (ProtocolFrame, "targetd-protocol-frame"),
            (TargetdCallReceipt, "targetd-call-receipt"),
            (SignedArtifact, "signed-artifact"),
        ):
            model.model_json_schema()
            checks.append(f"schema:{label}")
        for model, label, expected in (
            (MappingProposal, "mapping-proposal-v2", "rolo-mapping-proposal/v2"),
            (
                MappingConfirmationReceipt,
                "mapping-confirmation-receipt-v1",
                "rolo-mapping-confirmation-receipt/v1",
            ),
            (
                DslCompileRequest,
                "dsl-compile-request-v2",
                "rolo-dsl-compile-request/v2",
            ),
            (
                TargetConformanceReport,
                "target-conformance-v3",
                "rolo-target-conformance/v3",
            ),
            (
                PostCompilerJourneyResult,
                "post-compiler-journey-result-v2",
                "rolo-post-compiler-journey-result/v2",
            ),
        ):
            _require_schema_version(model, expected=expected)
            checks.append(f"schema:{label}")
    except (KeyError, TypeError, ValueError) as exc:
        failures.append(f"v2-schemas: {exc}")
    try:
        _targetd_transport_idempotency_smoke()
        checks.append("targetd-transport-idempotency-smoke:passed")
    except (OSError, KeyError, TypeError, ValueError) as exc:
        failures.append(f"targetd-transport-idempotency-smoke: {exc}")
    try:
        _confirmed_mapping_admission_smoke()
        checks.append("mapping-admission:confirmed-and-cancel-fail-closed")
    except Exception as exc:  # pragma: no cover - defensive release boundary
        failures.append(f"mapping-admission: {exc}")
    try:
        _certify_fixture_check()
        checks.append("certify-rotation-fixture:10-cases")
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
        failures.append(f"certify-rotation-fixture: {exc}")
    try:
        from tempfile import TemporaryDirectory

        with TemporaryDirectory(prefix="rolo-artifact-replay-") as root:
            store = SignedArtifactStore(Path(root), {"release": b"release-key"})
            artifact = SignedArtifact.build(artifact_id="replay", version="1", payload={"ok": True}, signer_key_id="release", key=b"release-key")
            store.publish(artifact)
            store.activate("replay", "1")
            store.rollback("replay", "1")
        checks.append("artifact-signature-rollback:passed")
    except (OSError, KeyError, TypeError, ValueError) as exc:
        failures.append(f"artifact-signature-rollback: {exc}")
    if require_artifacts:
        artifact_root = dist_path or path.parent / "dist"
        artifacts = [
            *artifact_root.glob("*.whl"),
            *artifact_root.glob("*.tar.gz"),
        ]
        if not artifacts:
            failures.append(f"missing build artifacts: {artifact_root}")
        else:
            checks.append("build-artifacts:present")
    return ReleaseCheckResult(
        status="PASS" if not failures else "FAIL",
        checks=checks,
        failures=failures,
    )
