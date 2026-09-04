"""Minimal release smoke checks for the product entrypoints."""

from __future__ import annotations

import importlib
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
        ):
            model.model_json_schema()
            checks.append(f"schema:{label}")
    except (KeyError, TypeError, ValueError) as exc:
        failures.append(f"v2-schemas: {exc}")
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
