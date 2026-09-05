from datetime import datetime, timedelta, timezone

import pytest

from rolo.core.models import DiscoveryReport, DiscoveryStatus, ProbeResult
from rolo.discovery_history_read_models import (
    _target_evidence_summary,
    build_discovery_snapshot_collection,
)
from rolo.stages.artifact_paths import ArtifactLayout

NOW = datetime(2026, 8, 20, tzinfo=timezone.utc)


def _report(
    discovery_id: str,
    created_at: datetime,
    *,
    heuristic_mode: str = "disabled",
    heuristic_status: str = "DISABLED",
    inferred_operation_count: int = 0,
    missing_evidence_count: int = 0,
) -> DiscoveryReport:
    return DiscoveryReport(
        discovery_id=discovery_id,
        robot_id="demo",
        status=DiscoveryStatus.PARTIAL,
        platform={},
        capability_manifest={},
        probes={
            "hw": ProbeResult(
                layer="hw",
                status=DiscoveryStatus.SUCCEEDED,
                warnings=["bounded warning"],
            ),
            "ros": ProbeResult(layer="ros", status=DiscoveryStatus.PARTIAL),
            "application": ProbeResult(
                layer="application",
                status=DiscoveryStatus.UNAVAILABLE,
                errors=["probe unavailable"],
            ),
        },
        semantic_bindings={"cmd_vel": {"topic": "/cmd_vel"}},
        operation_candidates=[],
        discovery_mode="ARTIFACT DOC",
        heuristic_analysis_ref="artifact://private/heuristic/summary.json",
        heuristic_mode=heuristic_mode,
        heuristic_status=heuristic_status,
        heuristic_inferred_operation_count=inferred_operation_count,
        heuristic_missing_evidence_count=missing_evidence_count,
        created_at=created_at,
    )


def test_discovery_history_is_manifest_bounded_and_marks_latest(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reports = {
        "disc-old": _report("disc-old", NOW - timedelta(minutes=5)),
        "disc-new": _report("disc-new", NOW),
    }
    runs_root = ArtifactLayout(tmp_path).discovery_latest("demo").parent / "runs"
    for discovery_id in [*reports, "disc-unverified"]:
        (runs_root / discovery_id).mkdir(parents=True)

    monkeypatch.setattr(
        "rolo.discovery_history_read_models.load_latest_report",
        lambda root, robot_id: reports["disc-new"],
    )

    def load_report(root, robot_id, discovery_id):
        if discovery_id == "disc-unverified":
            raise ValueError("manifest mismatch")
        return reports[discovery_id]

    monkeypatch.setattr(
        "rolo.discovery_history_read_models.load_report",
        load_report,
    )

    history = build_discovery_snapshot_collection(
        tmp_path,
        "demo",
        limit=1,
    )

    assert history.schema_version == "rolo-discovery-snapshot-collection/v3"
    assert history.total == 2
    assert history.next_offset == 1
    assert history.excluded_unverified == 1
    assert history.items[0].discovery_id == "disc-new"
    assert history.items[0].is_latest is True
    assert history.items[0].probe_total == 3
    assert history.items[0].observed_probes == 1
    assert history.items[0].partial_probes == 1
    assert history.items[0].unavailable_probes == 1
    assert history.items[0].semantic_bindings == 1
    assert history.items[0].warning_count == 2
    assert history.items[0].discovery_mode == "ARTIFACT_DOC"
    assert history.items[0].heuristic_summary.mode == "disabled"
    assert history.items[0].heuristic_summary.status == "DISABLED"
    assert history.items[0].heuristic_summary.influences_release is False
    assert history.integrity_status == "verified"
    assert "physical outcomes" in " ".join(history.limitations)
    assert "heuristic_analysis_ref" not in history.model_dump_json()
    assert "artifact://private" not in history.model_dump_json()


def test_discovery_history_returns_an_explicit_empty_verified_view(tmp_path) -> None:
    history = build_discovery_snapshot_collection(tmp_path, "demo")

    assert history.items == []
    assert history.total == 0
    assert history.excluded_unverified == 0
    assert any("latest discovery commit marker" in item for item in history.limitations)


@pytest.mark.parametrize(
    ("mode", "status", "inferred", "missing"),
    [
        ("shadow", "AGENT_COMPLETED", 4, 2),
        ("enabled", "FALLBACK", 1, 3),
        ("disabled", "DISABLED", 0, 0),
    ],
)
def test_discovery_history_exposes_only_the_safe_heuristic_summary(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
    status: str,
    inferred: int,
    missing: int,
) -> None:
    report = _report(
        "disc-safe",
        NOW,
        heuristic_mode=mode,
        heuristic_status=status,
        inferred_operation_count=inferred,
        missing_evidence_count=missing,
    )
    runs_root = ArtifactLayout(tmp_path).discovery_latest("demo").parent / "runs"
    (runs_root / report.discovery_id).mkdir(parents=True)
    monkeypatch.setattr(
        "rolo.discovery_history_read_models.load_latest_report",
        lambda root, robot_id: report,
    )
    monkeypatch.setattr(
        "rolo.discovery_history_read_models.load_report",
        lambda root, robot_id, discovery_id: report,
    )

    history = build_discovery_snapshot_collection(tmp_path, "demo")

    safe = history.items[0].heuristic_summary
    assert safe.mode == mode
    assert safe.status == status
    assert safe.inferred_operation_count == inferred
    assert safe.missing_evidence_count == missing
    assert safe.influences_release is False
    assert "heuristic_analysis_ref" not in history.model_dump_json()


def _with_target_evidence(
    report: DiscoveryReport,
    *,
    mode: str,
    collected_at: datetime,
) -> DiscoveryReport:
    binding = {
        "schema_version": "robot-target-evidence-binding/v2",
        "robot_id": report.robot_id,
        "source_id": "source-private",
        "target_host_fingerprint": "a" * 64,
        "bundle_payload_sha256": "b" * 64,
        "access": "READ_ONLY",
        "deployment_mode": mode,
        "collected_at": collected_at.isoformat(),
    }
    probes = dict(report.probes)
    for layer in ("hw", "linux", "ros"):
        current = probes.get(layer) or ProbeResult(
            layer=layer,
            status=DiscoveryStatus.SUCCEEDED,
        )
        probes[layer] = current.model_copy(
            update={"data": {**current.data, "target_evidence": dict(binding)}}
        )
    return report.model_copy(update={"probes": probes})


@pytest.mark.parametrize(
    ("mode", "status", "inferred", "missing"),
    [
        ("experimental", "AGENT_COMPLETED", 1, 0),
        ("shadow", "UNKNOWN", 1, 0),
        ("disabled", "DISABLED", 1, 0),
        ("shadow", "DISABLED", 0, 0),
    ],
)
def test_discovery_history_excludes_unsafe_heuristic_states(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
    status: str,
    inferred: int,
    missing: int,
) -> None:
    report = _report(
        "disc-invalid",
        NOW,
        heuristic_mode=mode,
        heuristic_status=status,
        inferred_operation_count=inferred,
        missing_evidence_count=missing,
    )
    runs_root = ArtifactLayout(tmp_path).discovery_latest("demo").parent / "runs"
    (runs_root / report.discovery_id).mkdir(parents=True)
    monkeypatch.setattr(
        "rolo.discovery_history_read_models.load_latest_report",
        lambda root, robot_id: report,
    )
    monkeypatch.setattr(
        "rolo.discovery_history_read_models.load_report",
        lambda root, robot_id, discovery_id: report,
    )

    history = build_discovery_snapshot_collection(tmp_path, "demo")

    assert history.items == []
    assert history.total == 0
    assert history.excluded_unverified == 1
    assert any("excluded" in item for item in history.limitations)


@pytest.mark.parametrize(
    ("mode", "age", "freshness", "refresh_required"),
    [
        ("local", timedelta(minutes=1), "FRESH", False),
        ("remote", timedelta(minutes=8), "STALE", True),
    ],
)
def test_discovery_history_exposes_only_safe_target_evidence_metadata(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
    age: timedelta,
    freshness: str,
    refresh_required: bool,
) -> None:
    report = _with_target_evidence(
        _report("disc-target", NOW - age),
        mode=mode,
        collected_at=NOW - age,
    )
    runs_root = ArtifactLayout(tmp_path).discovery_latest("demo").parent / "runs"
    (runs_root / report.discovery_id).mkdir(parents=True)
    monkeypatch.setattr(
        "rolo.discovery_history_read_models.load_latest_report",
        lambda root, robot_id: report,
    )
    monkeypatch.setattr(
        "rolo.discovery_history_read_models.load_report",
        lambda root, robot_id, discovery_id: report,
    )

    history = build_discovery_snapshot_collection(
        tmp_path,
        "demo",
        observed_at=NOW,
    )

    target = history.items[0].target_evidence
    assert target is not None
    assert target.deployment_scope == mode.upper()
    assert target.freshness == freshness
    assert target.refresh_required is refresh_required
    assert bool(target.refresh_reason) is refresh_required
    payload = history.model_dump_json()
    for private_value in (
        "source-private",
        "target_host_fingerprint",
        "bundle_payload_sha256",
        "expires_at",
    ):
        assert private_value not in payload


def test_discovery_history_rejects_inconsistent_target_bindings(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report = _with_target_evidence(
        _report("disc-target-mismatch", NOW),
        mode="remote",
        collected_at=NOW,
    )
    ros = report.probes["ros"]
    ros_binding = dict(ros.data["target_evidence"])
    ros_binding["source_id"] = "different-probe_runner"
    report = report.model_copy(
        update={
            "probes": {
                **report.probes,
                "ros": ros.model_copy(
                    update={"data": {**ros.data, "target_evidence": ros_binding}}
                ),
            }
        }
    )
    runs_root = ArtifactLayout(tmp_path).discovery_latest("demo").parent / "runs"
    (runs_root / report.discovery_id).mkdir(parents=True)
    monkeypatch.setattr(
        "rolo.discovery_history_read_models.load_latest_report",
        lambda root, robot_id: report,
    )
    monkeypatch.setattr(
        "rolo.discovery_history_read_models.load_report",
        lambda root, robot_id, discovery_id: report,
    )

    history = build_discovery_snapshot_collection(
        tmp_path,
        "demo",
        observed_at=NOW,
    )

    assert history.items == []
    assert history.excluded_unverified == 1


@pytest.mark.parametrize(
    ("field", "value"),
    [("source_id", ""), ("target_host_fingerprint", "unsafe")],
)
def test_target_evidence_requires_complete_verified_identity(
    field: str,
    value: str,
) -> None:
    report = _with_target_evidence(
        _report("disc-target-invalid-identity", NOW),
        mode="local",
        collected_at=NOW,
    )
    probes = dict(report.probes)
    for layer in ("hw", "linux", "ros"):
        probe = probes[layer]
        binding = {**probe.data["target_evidence"], field: value}
        probes[layer] = probe.model_copy(
            update={"data": {**probe.data, "target_evidence": binding}}
        )
    report = report.model_copy(update={"probes": probes})

    with pytest.raises(ValueError, match="identity"):
        _target_evidence_summary(report, NOW)
