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
from rolo.mvp import CertificationReport, TargetCatalog, TraceSessionRequest
from rolo.probe_baseline import (
    BaselineArtifactIndex,
    ProbeBaselineManifest,
    ReadOnlyCompletion,
)
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
    JourneySession,
    ProtocolFrame,
    TargetdCallReceipt,
)


def _targetd_replay_check() -> None:
    """Replay the targetd state invariants without a network or provider."""
    from datetime import datetime, timedelta, timezone
    from tempfile import TemporaryDirectory

    from rolo.targetd import TargetdService

    with TemporaryDirectory(prefix="rolo-targetd-replay-") as root:
        service = TargetdService(target_id="replay", state_root=Path(root), signing_key=b"replay-key")
        session = service.open_session(JourneySession.create(
            session_id="replay-session", target_id="replay", profile_id="replay"
        ))
        source = b"def execute(arguments): return arguments"
        manifest = ExecutionBundleManifest.build(
            tool_id="app.base.rotate", source=source, binding_digest="a" * 64,
            signer_key_id="replay", signing_key=b"replay-key",
        )
        service.put_bundle(manifest, source)
        request = ExecutionRequest(
            run_id="replay-run", session_id=session.session_id, target_id="replay",
            idempotency_key="replay-call", bundle_digest=manifest.bundle_digest,
            binding_digest=manifest.binding_digest, surface_digest="b" * 64,
            arguments={"angle_degrees": 15}, mode="REPLAY",
            deadline=datetime.now(timezone.utc) + timedelta(seconds=30),
        )
        first = service.accept_call(request, manifest)
        second = service.accept_call(request, manifest)
        if first != second or service.query_call(request.idempotency_key) != first:
            raise ValueError("targetd replay idempotency invariant failed")
        service.complete_call(request.idempotency_key, status="SUCCEEDED", result={"ok": True})


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
    except (KeyError, TypeError, ValueError) as exc:
        failures.append(f"v2-schemas: {exc}")
    try:
        _targetd_replay_check()
        checks.append("targetd-replay:passed")
    except (OSError, KeyError, TypeError, ValueError) as exc:
        failures.append(f"targetd-replay: {exc}")
    try:
        _certify_fixture_check()
        checks.append("certify-rotation-fixture:10-cases")
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
        failures.append(f"certify-rotation-fixture: {exc}")
    try:
        from tempfile import TemporaryDirectory

        with TemporaryDirectory(prefix="rolo-artifact-replay-") as root:
            store = SignedArtifactStore(Path(root), {"release": b"release-key"})
            artifact = SignedArtifact.build(
                artifact_id="replay", version="1", payload={"ok": True},
                signer_key_id="release", key=b"release-key"
            )
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
