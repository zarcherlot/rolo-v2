from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

import rolo.product_cli as cli
from rolo.dsl.admission import MappingConfirmationStore
from rolo.mvp.rotation import rotation_tool_proposal


def _write(path: Path, payload: object) -> Path:
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _stub_verified_evidence(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    raw_probe = object()
    verified_probe = object()
    bundle = SimpleNamespace(
        robot_id="mentorpi",
        payload_sha256="a" * 64,
        target_host_fingerprint="b" * 64,
        probes={"raw": raw_probe},
    )
    deployment = object()
    verifier_calls: list[tuple[object, object]] = []

    monkeypatch.setattr(
        cli,
        "TargetEvidenceBundle",
        SimpleNamespace(model_validate_json=lambda _: bundle),
    )
    monkeypatch.setattr(cli, "load_deployment", lambda _: deployment)

    def verify(candidate, *, deployment):
        verifier_calls.append((candidate, deployment))
        return {"verified": verified_probe}

    monkeypatch.setattr(cli, "verify_evidence_bundle", verify)
    monkeypatch.setattr(
        cli,
        "get_settings",
        lambda: SimpleNamespace(
            rolo_config_dir=tmp_path / "config",
            rolo_artifact_dir=tmp_path / "artifacts",
        ),
    )
    evidence = _write(tmp_path / "evidence.json", {})
    return bundle, deployment, verified_probe, verifier_calls, evidence


class _RegistrationResult:
    def __init__(self, status: str, error: str | None = None) -> None:
        self.status = status
        self.error = error

    def model_dump(self, *, mode: str) -> dict[str, object]:
        assert mode == "json"
        return {"status": self.status, "error": self.error}


def _registration_args(
    *,
    proposal: Path,
    evidence: Path,
    mapping_proposal: Path,
    mapping_dsl: Path,
    admission_store: Path,
) -> list[str]:
    return [
        "register-tool",
        "--proposal",
        str(proposal),
        "--evidence",
        str(evidence),
        "--mapping-proposal",
        str(mapping_proposal),
        "--mapping-dsl",
        str(mapping_dsl),
        "--admission-store",
        str(admission_store),
        "--confirmation-receipt-digest",
        "sha256:" + "c" * 64,
        "--journey-session-id",
        "journey-1",
    ]


def test_register_tool_passes_verified_mapping_admission_inputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle, deployment, verified_probe, verifier_calls, evidence = (
        _stub_verified_evidence(tmp_path, monkeypatch)
    )
    proposal_path = _write(tmp_path / "proposal.json", {"tool": "proposal"})
    mapping_proposal_path = _write(
        tmp_path / "mapping-proposal.json", {"mapping": "proposal"}
    )
    mapping_dsl_path = _write(
        tmp_path / "mapping-dsl.json", {"schema_version": "mapping-test"}
    )
    admission_store = tmp_path / "admission"
    parsed_proposal = object()
    parsed_mapping_proposal = object()
    monkeypatch.setattr(
        cli,
        "ToolRegistrationProposal",
        SimpleNamespace(model_validate=lambda payload: parsed_proposal),
    )
    monkeypatch.setattr(
        cli,
        "MappingProposal",
        SimpleNamespace(model_validate=lambda payload: parsed_mapping_proposal),
    )

    route = SimpleNamespace(resource_id="ros_topic:/cmd_vel")

    def routes(probe):
        assert probe is verified_probe
        return [route]

    monkeypatch.setattr(cli, "observed_probe_routes", routes)
    captured: dict[str, object] = {}

    def register(parsed, **kwargs):
        captured["parsed"] = parsed
        captured.update(kwargs)
        return _RegistrationResult("REGISTERED")

    monkeypatch.setattr(cli, "register_tool_proposal", register)

    result = CliRunner().invoke(
        cli.app,
        _registration_args(
            proposal=proposal_path,
            evidence=evidence,
            mapping_proposal=mapping_proposal_path,
            mapping_dsl=mapping_dsl_path,
            admission_store=admission_store,
        ),
    )

    assert result.exit_code == 0, result.output
    assert verifier_calls == [(bundle, deployment)]
    assert captured["parsed"] is parsed_proposal
    assert captured["mapping_proposal"] is parsed_mapping_proposal
    assert captured["mapping_dsl"] == {"schema_version": "mapping-test"}
    assert captured["observed_route_ids"] == {"ros_topic:/cmd_vel"}
    assert captured["target_fingerprint"] == bundle.target_host_fingerprint
    assert captured["confirmation_receipt_digest"] == "sha256:" + "c" * 64
    assert captured["journey_session_id"] == "journey-1"
    assert isinstance(captured["confirmation_store"], MappingConfirmationStore)
    assert captured["confirmation_store"].root == admission_store.resolve()


@pytest.mark.parametrize(
    "missing_option",
    [
        "--mapping-proposal",
        "--mapping-dsl",
        "--admission-store",
        "--confirmation-receipt-digest",
        "--journey-session-id",
    ],
)
def test_register_tool_requires_every_mapping_admission_option(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    missing_option: str,
) -> None:
    proposal = _write(tmp_path / "proposal.json", {})
    evidence = _write(tmp_path / "evidence.json", {})
    mapping_proposal = _write(tmp_path / "mapping-proposal.json", {})
    mapping_dsl = _write(tmp_path / "mapping-dsl.json", {})
    args = _registration_args(
        proposal=proposal,
        evidence=evidence,
        mapping_proposal=mapping_proposal,
        mapping_dsl=mapping_dsl,
        admission_store=tmp_path / "admission",
    )
    index = args.index(missing_option)
    del args[index : index + 2]
    monkeypatch.setattr(
        cli,
        "register_tool_proposal",
        lambda *_args, **_kwargs: pytest.fail("registration must not be called"),
    )

    result = CliRunner().invoke(cli.app, args)

    assert result.exit_code == 2
    assert not (tmp_path / "config" / "registered-tools").exists()


def test_register_tool_preserves_blocked_receipt_result(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, _, verified_probe, _, evidence = _stub_verified_evidence(tmp_path, monkeypatch)
    proposal = _write(tmp_path / "proposal.json", {})
    mapping_proposal = _write(tmp_path / "mapping-proposal.json", {})
    mapping_dsl = _write(tmp_path / "mapping-dsl.json", {})
    monkeypatch.setattr(
        cli,
        "ToolRegistrationProposal",
        SimpleNamespace(model_validate=lambda payload: object()),
    )
    monkeypatch.setattr(
        cli,
        "MappingProposal",
        SimpleNamespace(model_validate=lambda payload: object()),
    )
    monkeypatch.setattr(cli, "observed_probe_routes", lambda probe: [] if probe is verified_probe else pytest.fail("raw probe used"))
    monkeypatch.setattr(
        cli,
        "register_tool_proposal",
        lambda *_args, **_kwargs: _RegistrationResult(
            "BLOCKED", "MAPPING_CONFIRMATION_CANCELLED"
        ),
    )

    result = CliRunner().invoke(
        cli.app,
        _registration_args(
            proposal=proposal,
            evidence=evidence,
            mapping_proposal=mapping_proposal,
            mapping_dsl=mapping_dsl,
            admission_store=tmp_path / "admission",
        ),
    )

    assert result.exit_code == 2
    assert "MAPPING_CONFIRMATION_CANCELLED" in result.output
    assert not (tmp_path / "config" / "registered-tools").exists()


@pytest.mark.parametrize("command", ["execute-rotation", "invoke-tool"])
def test_cancelled_admission_before_execution_calls_no_executor_or_provider(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    command: str,
) -> None:
    bundle, _, verified_probe, _, evidence = _stub_verified_evidence(
        tmp_path, monkeypatch
    )
    base = rotation_tool_proposal(
        target_id="mentorpi",
        evidence_ref=f"target-evidence:{bundle.payload_sha256}",
    )
    assert base.binding is not None
    proposal = base.model_copy(update={"binding_digest": base.binding.digest()})
    proposal_path = tmp_path / "rotation-proposal.json"
    proposal_path.write_text(proposal.model_dump_json(), encoding="utf-8")
    arguments_path = _write(
        tmp_path / "arguments.json",
        {"angle_degrees": 15, "max_speed_rad_s": 0.2},
    )
    routes = [
        SimpleNamespace(
            resource_id="ros_topic:/cmd_vel",
            interface_type="geometry_msgs/msg/Twist",
        ),
        SimpleNamespace(
            resource_id="ros_topic:/odom_raw",
            interface_type="nav_msgs/msg/Odometry",
        ),
        SimpleNamespace(
            resource_id="ros_topic:/odom",
            interface_type="nav_msgs/msg/Odometry",
        ),
    ]
    monkeypatch.setattr(
        cli,
        "observed_probe_routes",
        lambda probe: routes
        if probe is verified_probe
        else pytest.fail("routes must come from verified probes"),
    )
    loader_calls: list[dict[str, object]] = []

    def load_registered(*_args, **kwargs):
        loader_calls.append(kwargs)
        return [proposal] if len(loader_calls) == 1 else []

    monkeypatch.setattr(cli, "load_registered_proposals", load_registered)
    executor_calls: list[object] = []
    provider_calls: list[object] = []

    def forbidden_executor(*args, **kwargs):
        executor_calls.append((args, kwargs))
        raise AssertionError("target executor must not be created")

    class ForbiddenProvider:
        def __init__(self, *args, **kwargs) -> None:
            provider_calls.append((args, kwargs))
            raise AssertionError("provider must not be created")

    monkeypatch.setattr(cli, "create_profile_target_executor", forbidden_executor)
    monkeypatch.setattr(cli, "RosBindingExecutor", ForbiddenProvider)
    common = [
        command,
        "--profile",
        "mentorpi",
        "--proposal",
        str(proposal_path),
        "--evidence",
        str(evidence),
        "--admission-store",
        str(tmp_path / "admission"),
        "--safety-confirmed",
    ]
    if command == "execute-rotation":
        args = [
            *common,
            "--angle-degrees",
            "15",
            "--max-speed-rad-s",
            "0.2",
        ]
    else:
        args = [*common, "--arguments", str(arguments_path)]

    result = CliRunner().invoke(cli.app, args)

    assert result.exit_code == 2, result.output
    assert len(loader_calls) == 2
    assert all(
        call["target_fingerprint"] == bundle.target_host_fingerprint
        and isinstance(call["confirmation_store"], MappingConfirmationStore)
        for call in loader_calls
    )
    assert executor_calls == []
    assert provider_calls == []
    assert not (tmp_path / "artifacts").exists()


@pytest.mark.parametrize(
    "args, expected",
    [
        (
            ["target", "tool-surface", "--profile", "mentorpi", "--include-registered"],
            "--evidence",
        ),
        (
            [
                "target",
                "tool-surface",
                "--profile",
                "mentorpi",
                "--include-registered",
                "--evidence",
                "evidence.json",
            ],
            "--admission-store",
        ),
    ],
)
def test_registered_surface_requires_evidence_and_admission_store(
    monkeypatch: pytest.MonkeyPatch,
    args: list[str],
    expected: str,
) -> None:
    monkeypatch.setattr(
        cli,
        "create_profile_native_tool_session",
        lambda *_args, **_kwargs: pytest.fail("session must not be created"),
    )

    result = CliRunner().invoke(cli.app, args)

    assert result.exit_code == 2
    assert expected in result.output
