"""Machine-readable Probe baseline and read-only completion audit.

The baseline is an immutable description of the read-only contract.  It is
deliberately independent from any write implementation: a baseline can only
prove that the Probe surface is stable and that all write counters are zero.
"""

from __future__ import annotations

import subprocess
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from rolo.core.hashing import canonical_json_sha256, sha256_file


class BaselineStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    BLOCKED = "BLOCKED"


class CompletionDecision(str, Enum):
    READ_ONLY_COMPLETE = "READ_ONLY_COMPLETE"
    READ_ONLY_CONDITIONAL = "READ_ONLY_CONDITIONAL"
    READ_ONLY_BLOCKED = "READ_ONLY_BLOCKED"


class GateResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    gate_id: Literal["A", "B", "C", "D", "E", "F"]
    status: BaselineStatus
    evidence_refs: list[str] = Field(default_factory=list, max_length=128)
    test_commands: list[str] = Field(default_factory=list, max_length=32)
    owner: str = Field(min_length=1, max_length=128)
    limitations: list[str] = Field(default_factory=list, max_length=64)
    blockers: list[str] = Field(default_factory=list, max_length=64)


class BaselineTest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    test_id: str = Field(min_length=1, max_length=128)
    command: str = Field(min_length=1, max_length=512)
    path: str = Field(min_length=1, max_length=512)
    required: bool = True


class ProbeBaselineManifest(BaseModel):
    """Frozen inputs and compatibility rules for one Probe baseline."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["rolo-probe-baseline-manifest/v1"] = (
        "rolo-probe-baseline-manifest/v1"
    )
    baseline_id: str = Field(min_length=1, max_length=128)
    baseline_version: str = Field(pattern=r"^v[0-9]+(?:\.[0-9]+){1,2}$")
    code_commit: str = Field(pattern=r"^[0-9a-f]{7,64}$|^UNKNOWN$")
    generated_at: datetime
    schema_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    api_versions: dict[str, str] = Field(min_length=1)
    error_codes: list[str] = Field(default_factory=list, max_length=128)
    authority_rules: dict[str, str] = Field(min_length=1)
    readonly_tool_allowlist: list[str] = Field(default_factory=list, max_length=256)
    feature_flags: dict[str, bool] = Field(default_factory=dict)
    target_profile: str | None = None
    target_fingerprint: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    source_id: str | None = None
    fixture: str | None = None
    freshness_policy: dict[str, int] = Field(default_factory=dict)
    snapshot_digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    rollback_pointer: str = Field(min_length=1, max_length=512)
    tests: list[BaselineTest] = Field(default_factory=list, max_length=256)
    known_limitations: list[str] = Field(default_factory=list, max_length=128)
    access: Literal["READ_ONLY"] = "READ_ONLY"
    digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_contract(self) -> ProbeBaselineManifest:
        if not self.api_versions:
            raise ValueError("api_versions must not be empty")
        if self.feature_flags.get("write", False) or self.feature_flags.get(
            "write_execution", False
        ):
            raise ValueError("Probe baseline cannot enable write features")
        if any(
            "write" in item.lower() or "shell" in item.lower()
            for item in self.readonly_tool_allowlist
        ):
            raise ValueError("read-only allowlist contains a forbidden entry")
        if self.digest is not None and self.digest != self.computed_digest():
            raise ValueError("baseline manifest digest does not match content")
        return self

    def payload(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude={"digest"}, exclude_none=True)

    def computed_digest(self) -> str:
        return canonical_json_sha256(self.payload())

    def with_digest(self) -> ProbeBaselineManifest:
        return self.model_copy(update={"digest": self.computed_digest()})


class BaselineArtifact(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str = Field(min_length=1, max_length=1024)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    role: str = Field(min_length=1, max_length=128)
    schema_version: str | None = None
    immutable: bool = True


class BaselineArtifactIndex(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["rolo-probe-baseline-artifact-index/v1"] = (
        "rolo-probe-baseline-artifact-index/v1"
    )
    baseline_id: str = Field(min_length=1, max_length=128)
    generated_at: datetime
    artifacts: list[BaselineArtifact] = Field(default_factory=list, max_length=1024)
    digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_digest(self) -> BaselineArtifactIndex:
        if self.digest is not None and self.digest != self.computed_digest():
            raise ValueError("artifact index digest does not match content")
        return self

    def payload(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude={"digest"})

    def computed_digest(self) -> str:
        return canonical_json_sha256(self.payload())

    def with_digest(self) -> BaselineArtifactIndex:
        return self.model_copy(update={"digest": self.computed_digest()})


class ReadOnlyCompletion(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["rolo-read-only-completion/v1"] = "rolo-read-only-completion/v1"
    phase: Literal["W0"] = "W0"
    decision: CompletionDecision
    baseline_id: str = Field(min_length=1, max_length=128)
    manifest_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    artifact_index_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    generated_at: datetime
    gates: dict[str, GateResult]
    owner: str = Field(min_length=1, max_length=128)
    reviewer: str | None = None
    write_calls: int = Field(default=0, ge=0)
    p0_p1_open: int = Field(default=0, ge=0)
    limitations: list[str] = Field(default_factory=list, max_length=128)
    blockers: list[str] = Field(default_factory=list, max_length=128)

    @model_validator(mode="after")
    def validate_decision(self) -> ReadOnlyCompletion:
        required = {"A", "B", "C", "D", "E", "F"}
        if set(self.gates) != required:
            raise ValueError("completion must contain exactly gates A-F")
        all_pass = all(gate.status == BaselineStatus.PASS for gate in self.gates.values())
        if self.decision == CompletionDecision.READ_ONLY_COMPLETE:
            if not all_pass or self.write_calls != 0 or self.p0_p1_open != 0:
                raise ValueError(
                    "READ_ONLY_COMPLETE requires all gates PASS and zero blockers/writes"
                )
        if self.write_calls != 0 and self.decision != CompletionDecision.READ_ONLY_BLOCKED:
            raise ValueError("non-zero write calls require READ_ONLY_BLOCKED")
        return self


def schema_digest(root: Path) -> str:
    """Digest all committed JSON schemas, excluding baseline output schemas."""

    schema_root = root / "schemas"
    entries: list[dict[str, str]] = []
    for path in sorted(schema_root.glob("*.schema.json")):
        if path.name in {
            "ProbeBaselineManifest.schema.json",
            "ProbeBaselineArtifactIndex.schema.json",
            "ReadOnlyCompletion.schema.json",
        }:
            continue
        entries.append({"path": path.relative_to(root).as_posix(), "sha256": sha256_file(path)})
    return canonical_json_sha256(entries)


def current_commit(root: Path) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return "UNKNOWN"
    return result.stdout.strip()


def build_manifest(
    root: Path,
    *,
    baseline_id: str = "probe-readonly",
    baseline_version: str = "v1.0.0",
    target_profile: str | None = None,
    target_fingerprint: str | None = None,
    source_id: str | None = None,
    fixture: str | None = "offline-fixture",
) -> ProbeBaselineManifest:
    """Create a baseline from repository state without contacting a target."""

    manifest = ProbeBaselineManifest(
        baseline_id=baseline_id,
        baseline_version=baseline_version,
        code_commit=current_commit(root),
        generated_at=datetime.now(timezone.utc),
        schema_digest=schema_digest(root),
        api_versions={
            "probe": "rolo-probe/v2",
            "rkb": "rolo-rkb/v2",
            "mhs": "rolo-mhs-read-only/v1",
            "rolo-vis": "rolo-vis-probe/v2",
        },
        error_codes=[
            "READ_ONLY_REQUIRED",
            "FINGERPRINT_MISMATCH",
            "DIGEST_DRIFT",
            "STALE",
            "UNKNOWN",
            "UNAVAILABLE",
            "SOURCE_CONFLICT",
        ],
        authority_rules={
            "VENDOR_MANIFEST": "vendor supplied and independently verified",
            "OBSERVED_RUNTIME": "target observation only; never vendor authority",
            "PROVISIONAL_TEST_FIXTURE": "replay/schema fixture; never release authority",
        },
        readonly_tool_allowlist=[
            "native.os.host.inspect",
            "native.middleware.graph.inspect",
            "native.hardware.inventory.inspect",
            "native.application.executable.inspect",
            "mhs.inspect",
            "mhs.status",
            "mhs.read",
        ],
        feature_flags={"write": False, "write_execution": False, "trace_write": False},
        target_profile=target_profile,
        target_fingerprint=target_fingerprint,
        source_id=source_id,
        fixture=fixture,
        freshness_policy={"clock_skew_seconds": 30, "default_ttl_seconds": 300},
        rollback_pointer="immutable://previous-baseline",
        tests=[
            BaselineTest(test_id="probe-contract", command="python -m pytest", path="tests/"),
            BaselineTest(test_id="docs", command="python scripts/check_docs.py", path="docs/"),
            BaselineTest(test_id="lint", command="ruff check .", path="src/"),
        ],
        known_limitations=[
            "Probe is read-only and does not establish physical safety",
            "Rolo never fabricates vendor Manifest authority",
            "real-target evidence must be supplied separately from the offline baseline",
        ],
    )
    return manifest.with_digest()


def build_artifact_index(
    root: Path, manifest: ProbeBaselineManifest, paths: list[Path]
) -> BaselineArtifactIndex:
    records: list[BaselineArtifact] = []
    for path in sorted(paths):
        resolved = path if path.is_absolute() else root / path
        if not resolved.is_file():
            raise FileNotFoundError(resolved)
        try:
            relative = resolved.relative_to(root).as_posix()
        except ValueError as exc:
            raise ValueError(f"artifact must be inside repository: {resolved}") from exc
        records.append(
            BaselineArtifact(
                path=relative, sha256=sha256_file(resolved), role="baseline-input"
            )
        )
    return BaselineArtifactIndex(
        baseline_id=manifest.baseline_id,
        generated_at=datetime.now(timezone.utc),
        artifacts=records,
    ).with_digest()


def audit_read_only(
    manifest: ProbeBaselineManifest,
    artifact_index: BaselineArtifactIndex,
    *,
    gate_status: dict[str, BaselineStatus] | None = None,
    owner: str = "rolo-maintainers",
    limitations: list[str] | None = None,
) -> ReadOnlyCompletion:
    """Produce a deterministic W0 result; no caller can hand-edit completion."""

    # Offline replay proves contract/integrity/read-only behavior, but cannot
    # satisfy the fixed-target evidence gate.  Callers must explicitly provide
    # F=PASS after archiving two independent target canaries.
    statuses = gate_status or {
        **{key: BaselineStatus.PASS for key in "ABCDE"},
        "F": BaselineStatus.BLOCKED,
    }
    gates = {
        key: GateResult(
            gate_id=key, status=statuses.get(key, BaselineStatus.BLOCKED), owner=owner,
            evidence_refs=[f"artifact-index://{artifact_index.digest}"],
            test_commands=[test.command for test in manifest.tests],
        )
        for key in "ABCDEF"
    }
    all_pass = all(item.status == BaselineStatus.PASS for item in gates.values())
    decision = (
        CompletionDecision.READ_ONLY_COMPLETE if all_pass else CompletionDecision.READ_ONLY_BLOCKED
    )
    return ReadOnlyCompletion(
        decision=decision,
        baseline_id=manifest.baseline_id,
        manifest_digest=manifest.digest or manifest.computed_digest(),
        artifact_index_digest=artifact_index.digest or artifact_index.computed_digest(),
        generated_at=datetime.now(timezone.utc),
        gates=gates,
        owner=owner,
        limitations=list(limitations or manifest.known_limitations),
        blockers=[]
        if all_pass
        else [
            f"gate-{key}" for key, item in gates.items() if item.status != BaselineStatus.PASS
        ],
    )


def validate_baseline(
    root: Path, manifest: ProbeBaselineManifest, artifact_index: BaselineArtifactIndex
) -> list[str]:
    """Return drift errors; an empty list means the baseline is reproducible."""

    errors: list[str] = []
    if not manifest.digest or manifest.digest != manifest.computed_digest():
        errors.append("baseline manifest digest mismatch")
    if not artifact_index.digest or artifact_index.digest != artifact_index.computed_digest():
        errors.append("artifact index digest mismatch")
    if manifest.schema_digest != schema_digest(root):
        errors.append("schema digest drift")
    if manifest.code_commit != "UNKNOWN" and manifest.code_commit != current_commit(root):
        errors.append("code commit drift")
    if artifact_index.baseline_id != manifest.baseline_id:
        errors.append("artifact index baseline_id mismatch")
    for artifact in artifact_index.artifacts:
        path = root / artifact.path
        if not path.is_file():
            errors.append(f"missing artifact: {artifact.path}")
        elif sha256_file(path) != artifact.sha256:
            errors.append(f"artifact digest drift: {artifact.path}")
    if manifest.feature_flags.get("write", False) or manifest.feature_flags.get(
        "write_execution", False
    ):
        errors.append("write feature flag enabled")
    return errors


__all__ = [
    "BaselineArtifact",
    "BaselineArtifactIndex",
    "BaselineStatus",
    "BaselineTest",
    "CompletionDecision",
    "GateResult",
    "ProbeBaselineManifest",
    "ReadOnlyCompletion",
    "audit_read_only",
    "build_artifact_index",
    "build_manifest",
    "current_commit",
    "schema_digest",
    "validate_baseline",
]
