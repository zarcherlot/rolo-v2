from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from rolo.core.artifacts import ArtifactStore
from rolo.core.hashing import canonical_json_sha256, sha256_file
from rolo.stages.diagnose.episode import TargetProvenance
from rolo.stages.verify.legacy_adapter import adapt_legacy_provider_evidence


def _legacy_payload(plan: dict[str, object]) -> dict[str, object]:
    now = datetime.now(timezone.utc)
    return {
        "schema_version": "rolo-verification-evidence/v1",
        "run_id": "verify-target-1",
        "robot_id": "robot-1",
        "status": "PASS",
        "plan": plan,
        "plan_sha256": canonical_json_sha256(plan),
        "case_results": [
            {
                "case_id": "companion-health",
                "operation": "target.companion.health",
                "status": "PASS",
                "message": "ok",
                "observed_at": now.isoformat(),
            }
        ],
        "target_provenance": {
            "schema_version": "rolo-verification-target-provenance/v1",
            "transport": "ssh",
            "host": "robot.example",
            "workspace": "/opt/rolo",
            "known_hosts_sha256": "a" * 64,
            "expected_companion": "rolo-target 0.1.0",
        },
        "started_at": now.isoformat(),
        "completed_at": now.isoformat(),
    }


def _canonical_provenance(root: Path) -> tuple[str, str]:
    binding = root / "targets" / "robot-1" / "bindings" / "current.json"
    binding.parent.mkdir(parents=True)
    binding.write_text('{"binding":"approved"}\n', encoding="utf-8")
    provenance = TargetProvenance(
        schema_version="rolo-target-provenance/v2",
        target_id="robot-1",
        source="p1-ssh-adapter",
        probe_runner_version="0.1.0",
        collected_at=datetime.now(timezone.utc),
        clock_offset_ms=0,
        target_binding_ref="artifact://targets/robot-1/bindings/current.json",
        target_binding_sha256=sha256_file(binding),
        probe_runner_session_id="session-1",
        clock_source="remote-monotonic",
        monotonic_ns=1,
    )
    path = root / "targets" / "robot-1" / "provenance" / "verify-target-1.json"
    path.parent.mkdir(parents=True)
    path.write_text(provenance.model_dump_json() + "\n", encoding="utf-8")
    return "artifact://targets/robot-1/provenance/verify-target-1.json", sha256_file(path)


def test_legacy_provider_evidence_adapts_only_with_canonical_v2_provenance(
    tmp_path: Path,
) -> None:
    provenance_ref, provenance_sha = _canonical_provenance(tmp_path)
    plan = {"robot_id": "robot-1", "cases": ["companion-health"]}

    package, evidence_ref = adapt_legacy_provider_evidence(
        _legacy_payload(plan),
        artifacts=ArtifactStore(tmp_path),
        expected_robot_id="robot-1",
        expected_plan_sha256=canonical_json_sha256(plan),
        target_provenance_ref=provenance_ref,
        target_provenance_sha256=provenance_sha,
        target_provenance_schema_version="rolo-target-provenance/v2",
        safe_stop="NOT_VERIFIED",
        rollback="NOT_VERIFIED",
    )

    assert package.schema_version == "rolo-verification-evidence/v2"
    assert package.target_provenance_ref == provenance_ref
    assert evidence_ref.endswith("adapted-evidence-v2.json")
    assert (tmp_path / evidence_ref.removeprefix("artifact://")).is_file()


def test_legacy_provider_adapter_rejects_stale_provenance_hash(tmp_path: Path) -> None:
    provenance_ref, _ = _canonical_provenance(tmp_path)
    plan = {"robot_id": "robot-1", "cases": ["companion-health"]}

    with pytest.raises(ValueError, match="provenance reference or hash"):
        adapt_legacy_provider_evidence(
            _legacy_payload(plan),
            artifacts=ArtifactStore(tmp_path),
            expected_robot_id="robot-1",
            expected_plan_sha256=canonical_json_sha256(plan),
            target_provenance_ref=provenance_ref,
            target_provenance_sha256="f" * 64,
            target_provenance_schema_version="rolo-target-provenance/v2",
            safe_stop="NOT_VERIFIED",
            rollback="NOT_VERIFIED",
        )


def test_legacy_provider_adapter_rejects_plan_digest_drift(tmp_path: Path) -> None:
    provenance_ref, provenance_sha = _canonical_provenance(tmp_path)
    plan = {"robot_id": "robot-1", "cases": ["companion-health"]}

    with pytest.raises(ValueError, match="plan digest"):
        adapt_legacy_provider_evidence(
            _legacy_payload(plan),
            artifacts=ArtifactStore(tmp_path),
            expected_robot_id="robot-1",
            expected_plan_sha256="e" * 64,
            target_provenance_ref=provenance_ref,
            target_provenance_sha256=provenance_sha,
            target_provenance_schema_version="rolo-target-provenance/v2",
            safe_stop="NOT_VERIFIED",
            rollback="NOT_VERIFIED",
        )
