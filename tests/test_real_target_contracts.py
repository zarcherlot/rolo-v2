from __future__ import annotations

import json
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from rolo.core.artifacts import ArtifactStore
from rolo.core.config import Settings
from rolo.core.hashing import sha256_file
from rolo.stages.agent_runner import StageAgentTask
from rolo.stages.codex_downstream import CodexStageAgentExecutor
from rolo.stages.diagnose.episode import (
    DiagnosisEpisode,
    EpisodeObservation,
    EpisodePhase,
    TargetProvenance,
    validate_published_episode,
)
from rolo.stages.diagnose.service import diagnosis_outcome_status
from rolo.stages.downstream import DownstreamStageService
from rolo.stages.handoffs import DiagnosisHandoff, VerificationHandoff
from rolo.stages.network_preflight import preflight_agent_network
from rolo.stages.real_target import (
    LocalTargetCommandRunner,
    LocalTargetStageExecutor,
    TargetBinding,
    publish_target_binding,
    validate_target_binding,
)
from rolo.stages.verify.acceptance import (
    VerificationCase,
    VerificationCaseResult,
    VerificationEvidencePackage,
    VerificationOracle,
    VerificationPlan,
)
from rolo.stages.verify.service import (
    publish_verification_plan,
    verification_outcome_status,
)
from rolo.target_ref import parse_target_ref
from rolo.targets.profiles import CredentialReference, TargetProfileStore


def _task(reference: str, digest: str) -> StageAgentTask:
    return StageAgentTask(
        stage="verify",
        robot_id="robot-1",
        task="verify",
        input_refs={"diagnosis_handoff": reference},
        input_sha256={"diagnosis_handoff": digest},
        output_contract="robot-verification-handoff/v1",
        provider="codex",
        executor="codex",
        plan_sha256="a" * 64,
    )


def test_materializer_recursively_copies_digest_bound_handoff_refs(tmp_path: Path) -> None:
    artifact_root = tmp_path / "artifacts"
    nested = artifact_root / "diagnose/robot-1/runs/r1/frozen_config.json"
    nested.parent.mkdir(parents=True)
    nested.write_text('{"speed":0.2}\n', encoding="utf-8")
    handoff = artifact_root / "diagnose/robot-1/latest/handoff.json"
    handoff.parent.mkdir(parents=True)
    handoff.write_text(
        json.dumps(
            {
                "frozen_config_ref": "artifact://diagnose/robot-1/runs/r1/frozen_config.json",
                "frozen_config_sha256": sha256_file(nested),
            }
        ),
        encoding="utf-8",
    )
    executor = CodexStageAgentExecutor(
        artifacts=ArtifactStore(artifact_root),
        settings=Settings(_env_file=None),
        stage="verify",
    )

    local = executor._materialize_inputs(
        _task("artifact://diagnose/robot-1/latest/handoff.json", sha256_file(handoff)),
        tmp_path / "workspace",
    )

    manifest = json.loads(Path(local["__manifest__"]).read_text(encoding="utf-8"))
    nested_entry = manifest["artifacts"][
        "artifact://diagnose/robot-1/runs/r1/frozen_config.json"
    ]
    assert Path(nested_entry["local_path"]).read_text(encoding="utf-8") == '{"speed":0.2}\n'
    assert nested_entry["sha256"] == sha256_file(nested)


def test_materializer_rejects_nested_hash_drift(tmp_path: Path) -> None:
    artifact_root = tmp_path / "artifacts"
    nested = artifact_root / "nested.json"
    nested.parent.mkdir(parents=True)
    nested.write_text("{}\n", encoding="utf-8")
    handoff = artifact_root / "handoff.json"
    handoff.write_text(
        json.dumps(
            {
                "evidence_ref": "artifact://nested.json",
                "evidence_sha256": "0" * 64,
            }
        ),
        encoding="utf-8",
    )
    executor = CodexStageAgentExecutor(
        artifacts=ArtifactStore(artifact_root),
        settings=Settings(_env_file=None),
        stage="verify",
    )
    with pytest.raises(ValueError, match="nested artifact hash mismatch"):
        executor._materialize_inputs(
            _task("artifact://handoff.json", sha256_file(handoff)), tmp_path / "workspace"
        )


def test_v2_provenance_rejects_clock_skew_and_cross_target() -> None:
    now = datetime.now(timezone.utc)
    provenance = TargetProvenance(
        schema_version="rolo-target-provenance/v2",
        target_id="robot-1",
        source="local-target",
        probe_runner_version="0.1.0",
        collected_at=now,
        clock_offset_ms=0,
        target_binding_ref="artifact://targets/robot-1/binding.json",
        target_binding_sha256="a" * 64,
        probe_runner_session_id="source-1",
        clock_source="local-monotonic",
        monotonic_ns=1,
    )
    observations = [
        EpisodeObservation(
            sequence=index,
            phase=phase,
            observed_at=now + timedelta(milliseconds=index),
            payload={"status": "READY"},
            provenance=provenance,
        )
        for index, phase in enumerate(EpisodePhase, start=1)
    ]
    DiagnosisEpisode(
        robot_id="robot-1",
        started_at=now,
        ended_at=now + timedelta(seconds=1),
        observations=observations,
    )
    with pytest.raises(ValueError, match="clock offset"):
        TargetProvenance.model_validate(
            {**provenance.model_dump(mode="json"), "clock_offset_ms": 60_001}
        )


def test_local_target_binding_detects_workspace_identity_drift(tmp_path: Path) -> None:
    config = tmp_path / "config"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    TargetProfileStore(config).create(
        robot_id="robot-1",
        target=parse_target_ref(str(workspace)),
        credential=CredentialReference(kind="ssh-agent", reference="ssh-agent:default"),
    )
    artifacts = ArtifactStore(tmp_path / "artifacts")
    binding = TargetBinding.capture(
        settings=Settings(_env_file=None, rolo_config_dir=config),
        robot_id="robot-1",
    )
    path = artifacts.write_json(
        "targets/robot-1/bindings/current.json", binding.model_dump(mode="json")
    )
    validate_target_binding(artifacts.root, f"artifact://{path.relative_to(artifacts.root)}")
    workspace.rmdir()
    workspace.mkdir()
    with pytest.raises(ValueError, match="workspace identity drift"):
        validate_target_binding(
            artifacts.root, f"artifact://{path.relative_to(artifacts.root)}"
        )


def test_local_target_runner_rejects_unknown_or_mutating_operations() -> None:
    runner = LocalTargetCommandRunner()
    with pytest.raises(ValueError, match="not in the read-only allowlist"):
        runner.run("ros.topic.publish", {}, timeout_s=1)


def test_local_target_plan_rejects_write_operation_before_publication(
    tmp_path: Path,
) -> None:
    plan = VerificationPlan(
        robot_id="robot-1",
        cases=[
            VerificationCase(
                case_id="write-topic",
                operation="ros.topic.publish",
                oracle=VerificationOracle(
                    kind="FIELD_EXISTS", path="output"
                ),
            )
        ],
    )

    with pytest.raises(ValueError, match="non-allowlisted operations"):
        publish_verification_plan(
            tmp_path,
            "robot-1",
            plan,
            allowed_operations=LocalTargetCommandRunner.READ_ONLY_OPERATIONS,
        )
    assert not (tmp_path / "verify/robot-1/acceptance-plan.json").exists()


def test_local_target_runner_redacts_bounded_command_output(monkeypatch) -> None:
    monkeypatch.setattr(
        "rolo.stages.real_target.subprocess.run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args[0], 0, b"token=top-secret Bearer abc.def\n", b""
        ),
    )
    result = LocalTargetCommandRunner().run("linux.uname", {}, timeout_s=1)
    assert result["status"] == "READY"
    assert "top-secret" not in str(result)
    assert "abc.def" not in str(result)


def test_agent_network_preflight_uses_explicit_proxy_without_leaking_credentials(
    monkeypatch,
) -> None:
    connected: list[tuple[tuple[str, int], float]] = []

    class _Connection:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

    monkeypatch.setenv("HTTPS_PROXY", "http://user:secret@127.0.0.1:7897")
    monkeypatch.setattr(
        "rolo.stages.network_preflight.socket.create_connection",
        lambda address, timeout: connected.append((address, timeout)) or _Connection(),
    )
    result = preflight_agent_network("https://api.example.test/v1", timeout_s=2)
    assert result.via_proxy is True
    assert connected == [(('127.0.0.1', 7897), 2)]
    assert "secret" not in repr(result)


def test_verify_only_completes_for_v2_all_pass_evidence(tmp_path: Path) -> None:
    provenance = tmp_path / "targets/robot-1/provenance.json"
    provenance.parent.mkdir(parents=True)
    provenance.write_text('{"target_id":"robot-1"}\n', encoding="utf-8")
    result = VerificationCaseResult(
        case_id="doctor",
        operation="ros.doctor.report",
        status="PASS",
        message="ok",
        provenance_ref="artifact://targets/robot-1/provenance.json",
        rollback_status="NOT_REQUIRED",
    )
    evidence = VerificationEvidencePackage(
        robot_id="robot-1",
        run_id="verify-1",
        target_provenance_ref="artifact://targets/robot-1/provenance.json",
        target_provenance_sha256=sha256_file(provenance),
        target_provenance_schema_version="rolo-target-provenance/v2",
        case_results=[result],
        safe_stop="NOT_REQUIRED",
        rollback="NOT_REQUIRED",
    )
    report = {
        "schema_version": "rolo-verification-regression-report/v1",
        "robot_id": "robot-1",
        "run_id": "verify-1",
        "status": "PASS",
        "case_results": [result.model_dump(mode="json")],
        "release_authority": "none",
    }
    assert verification_outcome_status(report, evidence.model_dump(mode="json")) == "COMPLETE"
    report["status"] = "INCONCLUSIVE"
    assert verification_outcome_status(report, evidence.model_dump(mode="json")) == "DEGRADED"


def _local_target_fixture(tmp_path: Path) -> tuple[Settings, ArtifactStore, str]:
    config = tmp_path / "config"
    workspace = tmp_path / "target-workspace"
    workspace.mkdir()
    TargetProfileStore(config).create(
        robot_id="robot-1",
        target=parse_target_ref(str(workspace)),
        credential=CredentialReference(kind="ssh-agent", reference="ssh-agent:default"),
    )
    settings = Settings(
        _env_file=None,
        rolo_config_dir=config,
        rolo_artifact_dir=tmp_path / "artifacts",
    )
    artifacts = ArtifactStore(settings.rolo_artifact_dir)
    return settings, artifacts, publish_target_binding(artifacts, settings, "robot-1")


def _stub_upstream_handoffs(
    artifacts: ArtifactStore, monkeypatch, *, include_diagnosis: bool = False
) -> None:
    adapter = artifacts.write_json("adapt/robot-1/runs/adapt-1/handoff.json", {})
    monkeypatch.setattr(
        "rolo.stages.adapt.conformance.latest_adapter_handoff_path",
        lambda root, robot_id: adapter,
    )
    monkeypatch.setattr(
        "rolo.stages.adapt.conformance.validate_adapter_handoff", lambda *args: None
    )
    monkeypatch.setattr(
        "rolo.stages.handoffs.validate_diagnosis_handoff", lambda *args, **kwargs: None
    )
    if include_diagnosis:
        artifacts.write_json("diagnose/robot-1/latest/handoff.json", {})
        monkeypatch.setattr(
            "rolo.stages.handoffs.validate_verification_handoff",
            lambda *args, **kwargs: None,
        )


def test_local_target_diagnose_materializes_complete_v2_episode(
    tmp_path: Path, monkeypatch
) -> None:
    settings, artifacts, binding_ref = _local_target_fixture(tmp_path)
    _stub_upstream_handoffs(artifacts, monkeypatch)
    binding_path = artifacts.root / binding_ref.removeprefix("artifact://")
    task = StageAgentTask(
        stage="diagnose",
        robot_id="robot-1",
        task="bounded local target diagnosis",
        input_refs={"target_binding": binding_ref},
        input_sha256={"target_binding": sha256_file(binding_path)},
        output_contract="robot-diagnosis-handoff/v1",
        provider="local-target",
        executor="local-target",
        plan_sha256="a" * 64,
    )
    executor = LocalTargetStageExecutor(
        artifacts=artifacts, settings=settings, stage="diagnose"
    )
    monkeypatch.setattr(
        executor.runner,
        "run",
        lambda operation, payload, timeout_s: {
            "operation": operation,
            "status": "READY",
            "returncode": 0,
            "output": "ready",
            "lines": ["ready"],
            "count": 1,
            "environment_limited": False,
            "observed_at": datetime.now(timezone.utc).isoformat(),
        },
    )

    outputs = executor.execute_stage(task, workspace=tmp_path, run_id="diagnose-real-1")
    handoff = DiagnosisHandoff.model_validate_json(
        (artifacts.root / "diagnose/robot-1/latest/handoff.json").read_text(
            encoding="utf-8"
        )
    )
    report = json.loads(
        (artifacts.root / handoff.diagnosis_report_ref.removeprefix("artifact://")).read_text(
            encoding="utf-8"
        )
    )
    episode = validate_published_episode(
        artifacts.root, outputs["episode"], robot_id="robot-1"
    )

    status, reason = diagnosis_outcome_status(artifacts.root, "robot-1", report)
    assert (status.value, reason) == ("COMPLETE", None)
    assert [item.phase for item in episode.observations] == list(EpisodePhase)
    assert all(
        item.provenance.schema_version == "rolo-target-provenance/v2"
        for item in episode.observations
    )


def test_local_target_plan_binds_target_identity_before_authorization(
    tmp_path: Path, monkeypatch
) -> None:
    settings, artifacts, _ = _local_target_fixture(tmp_path)
    settings = settings.model_copy(
        update={
            "coding_agent_provider": "local-target",
            "coding_agent_executor": "local-target",
        }
    )
    artifacts.write_json("diagnose/robot-1/latest/inputs.json", {"robot_id": "robot-1"})
    artifacts.write_json("adapt/robot-1/latest.json", {"robot_id": "robot-1"})
    monkeypatch.setattr(
        "rolo.stages.diagnose.service.validate_adapter_handoff", lambda *args: None
    )

    task = DownstreamStageService(settings, "diagnose").build_task("robot-1")

    assert task.input_refs["target_binding"].startswith("artifact://targets/robot-1/")
    assert task.input_sha256["target_binding"] == sha256_file(
        artifacts.root / task.input_refs["target_binding"].removeprefix("artifact://")
    )


def test_local_target_verify_materializes_all_pass_v2_evidence(
    tmp_path: Path, monkeypatch
) -> None:
    settings, artifacts, binding_ref = _local_target_fixture(tmp_path)
    _stub_upstream_handoffs(artifacts, monkeypatch, include_diagnosis=True)
    plan = VerificationPlan(
        robot_id="robot-1",
        cases=[
            VerificationCase(
                case_id="uname",
                operation="linux.uname",
                oracle=VerificationOracle(
                    kind="FIELD_EQUALS", path="status", expected="READY"
                ),
            )
        ],
    )
    plan_path = artifacts.write_json(
        "verify/robot-1/acceptance-plan.json", plan.model_dump(mode="json")
    )
    plan_ref = "artifact://verify/robot-1/acceptance-plan.json"
    binding_path = artifacts.root / binding_ref.removeprefix("artifact://")
    task = StageAgentTask(
        stage="verify",
        robot_id="robot-1",
        task="bounded local target verification",
        input_refs={"target_binding": binding_ref, "acceptance_plan": plan_ref},
        input_sha256={
            "target_binding": sha256_file(binding_path),
            "acceptance_plan": sha256_file(plan_path),
        },
        output_contract="robot-verification-handoff/v1",
        provider="local-target",
        executor="local-target",
        plan_sha256="b" * 64,
    )
    executor = LocalTargetStageExecutor(
        artifacts=artifacts, settings=settings, stage="verify"
    )
    monkeypatch.setattr(
        executor.runner,
        "run",
        lambda operation, payload, timeout_s: {
            "operation": operation,
            "status": "READY",
            "returncode": 0,
            "output": "ready",
            "lines": ["ready"],
            "count": 1,
            "environment_limited": False,
            "observed_at": datetime.now(timezone.utc).isoformat(),
        },
    )

    executor.execute_stage(task, workspace=tmp_path, run_id="verify-real-1")
    handoff = VerificationHandoff.model_validate_json(
        (artifacts.root / "verify/robot-1/latest/handoff.json").read_text(
            encoding="utf-8"
        )
    )
    report = json.loads(
        (artifacts.root / handoff.regression_report_ref.removeprefix("artifact://")).read_text(
            encoding="utf-8"
        )
    )
    evidence = json.loads(
        (artifacts.root / handoff.evidence_package_ref.removeprefix("artifact://")).read_text(
            encoding="utf-8"
        )
    )

    assert verification_outcome_status(report, evidence) == "COMPLETE"
    assert evidence["target_provenance_schema_version"] == "rolo-target-provenance/v2"
    assert [item["status"] for item in report["case_results"]] == ["PASS"]
