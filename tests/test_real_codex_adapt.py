import os
import shutil
from pathlib import Path

import pytest

from rolo.core.artifacts import ArtifactStore
from rolo.core.config import Settings
from rolo.core.models import ProbeResult
from rolo.core.registry import RobotRegistry
from rolo.stages.adapt.active_discovery import ActiveDiscoveryInputs, ActiveProbeMode
from rolo.stages.adapt.discovery import DiscoveryService
from rolo.stages.adapt.service import AdaptRunService

pytestmark = pytest.mark.skipif(
    os.environ.get("ROLO_RUN_REAL_CODEX_ADAPT") != "1",
    reason="set ROLO_RUN_REAL_CODEX_ADAPT=1 for the opt-in real Codex acceptance run",
)


def test_real_codex_builds_and_passes_a_route_presence_adapter(tmp_path: Path) -> None:
    executable = shutil.which("codex")
    if executable is None:
        pytest.fail("Codex CLI is not installed")
    artifact_root = tmp_path / "artifacts"
    source_root = tmp_path / "target-evidence"
    source_root.mkdir()
    (source_root / "pyproject.toml").write_text(
        '[project]\nname = "real-codex-adapt"\n', encoding="utf-8"
    )
    (source_root / "driver.py").write_text(
        'node.create_publisher(Twist, "/cmd_vel", 10)\n', encoding="utf-8"
    )
    ros_probe = ProbeResult(
        layer="ros",
        status="SUCCEEDED",
        data={
            "ros_distro": "test",
            "installed_distros": ["test"],
            "domain_id": "0",
            "rmw": "test",
            "nodes": ["/base_controller"],
            "topics": ["/cmd_vel [geometry_msgs/msg/Twist]"],
            "services": [],
            "actions": [],
        },
    )
    registry = RobotRegistry(Path("tests/fixtures/robots"))
    registry.load()
    binding = {
        "robot_id": "demo_diff",
        "source_id": "source-real-codex-test",
        "target_host_fingerprint": "f" * 64,
        "bundle_payload_sha256": "a" * 64,
        "access": "READ_ONLY",
        "deployment_mode": "local",
    }
    DiscoveryService(ArtifactStore(artifact_root)).run(
        robot=registry.get("demo_diff"),
        urdf_path=Path("tests/fixtures/profiles/differential_drive.urdf"),
        active_inputs=ActiveDiscoveryInputs(
            source_roots=[source_root],
            active_probe=ActiveProbeMode.RUNTIME_READONLY,
        ),
        target_probes={
            "hw": ProbeResult(
                layer="hw",
                status="SUCCEEDED",
                data={"components": [], "target_evidence": binding},
            ),
            "linux": ProbeResult(
                layer="linux",
                status="SUCCEEDED",
                data={"target_evidence": binding},
            ),
            "ros": ros_probe.model_copy(
                update={"data": {**ros_probe.data, "target_evidence": binding}}
            ),
        },
    )
    settings = Settings(
        rolo_artifact_dir=artifact_root,
        rolo_output_dir=tmp_path / "adapter-output",
        coding_agent_executable=executable,
        coding_agent_auto_install=False,
        coding_agent_require_auth=False,
        coding_agent_timeout_s=1800,
        wiki_polish_enabled=False,
    )
    service = AdaptRunService(ArtifactStore(artifact_root), settings)
    plan = service.dry_run("demo_diff")
    assert plan.eligible_operations

    summary, summary_path = service.run(
        robot_id="demo_diff",
        scratch_root=tmp_path / "agent-scratch",
        timeout_s=1800,
    )

    assert summary_path.is_file()
    assert (artifact_root / "adapt/demo_diff/runs" / summary.run_id / "gate.json").is_file()
    assert (tmp_path / "adapter-output/robots/demo_diff/current.json").is_file()
