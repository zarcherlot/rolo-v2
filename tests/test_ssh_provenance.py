from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from rolo.core.artifacts import ArtifactStore
from rolo.stages.verify.ssh_provenance import SshTargetProvenanceProbeRunner
from rolo.target_ref import SshTargetRef


class _Result:
    def __init__(self, returncode: int, stdout: str = "") -> None:
        self.returncode = returncode
        self.stdout = stdout


class _Transport:
    def __init__(self, target: SshTargetRef, responses: dict[tuple[str, ...], _Result]) -> None:
        self.target = target
        self.responses = responses
        self.calls: list[tuple[str, ...]] = []

    def execute(self, remote_argv: list[str], *, timeout_s: float) -> _Result:
        del timeout_s
        call = tuple(remote_argv)
        self.calls.append(call)
        return self.responses.get(call, _Result(1))


def _target() -> SshTargetRef:
    return SshTargetRef(host="robot.example", user="robot", workspace="/opt/rolo")


def test_ssh_provenance_probe_runner_publishes_canonical_binding(tmp_path: Path) -> None:
    target = _target()
    transport = _Transport(
        target,
        {
            ("stat", "-c", "%d %i %Z", "/opt/rolo"): _Result(0, "8 12345 1700000000"),
            ("cat", "/etc/machine-id"): _Result(0, "machine-abc\n"),
            ("id", "-un"): _Result(0, "robot\n"),
            ("id", "-u"): _Result(0, "1001\n"),
            ("printenv", "ROS_DOMAIN_ID"): _Result(0, "50\n"),
            ("printenv", "RMW_IMPLEMENTATION"): _Result(0, "rmw_fastrtps_cpp\n"),
        },
    )
    binding, reference, digest = SshTargetProvenanceProbeRunner(target, transport).collect(
        ArtifactStore(tmp_path),
        robot_id="robot-1",
        profile_sha256="a" * 64,
        run_id="run-1",
        clock=lambda: datetime(2026, 8, 29, tzinfo=timezone.utc),
    )

    assert binding.workspace_device == 8
    assert binding.workspace_inode == 12345
    assert binding.workspace_ctime_ns == 1_700_000_000_000_000_000
    assert binding.os_uid == 1001
    assert binding.ros_domain_id == "50"
    assert reference == "artifact://targets/robot-1/bindings/ssh-run-1.json"
    assert len(digest) == 64
    assert len(transport.calls) == 6


def test_ssh_provenance_probe_runner_fails_closed_on_bad_stat(tmp_path: Path) -> None:
    target = _target()
    transport = _Transport(
        target,
        {
            ("stat", "-c", "%d %i %Z", "/opt/rolo"): _Result(0, "not-a-stat"),
        },
    )
    with pytest.raises(ValueError, match="stat"):
        SshTargetProvenanceProbeRunner(target, transport).collect(
            ArtifactStore(tmp_path), robot_id="robot-1", profile_sha256="a" * 64
        )


def test_ssh_provenance_probe_runner_rejects_transport_target_mismatch(tmp_path: Path) -> None:
    target = _target()
    other = SshTargetRef(host="other.example", workspace="/opt/rolo")
    with pytest.raises(ValueError, match="does not match"):
        SshTargetProvenanceProbeRunner(target, _Transport(other, {}))
