from __future__ import annotations

from types import SimpleNamespace

from rolo.mvp import ExecutionBinding, RosBindingExecutor


class FakeTargetExecutor:
    def __init__(self) -> None:
        self.calls: list[list[str]] = []

    def run_bound(self, argv, *, ros_setup_files=()):
        self.calls.append(list(argv))
        return SimpleNamespace(returncode=0, stdout="", stderr="")


def _binding() -> ExecutionBinding:
    return ExecutionBinding(
        kind="ros2_topic",
        command_endpoint="/cmd_vel",
        interface_type="geometry_msgs/msg/Twist",
        stop_strategy="zero_velocity",
        evidence_refs=["target-evidence:" + "a" * 64],
    )


def test_rotate_provider_emits_fixed_publish_and_stop() -> None:
    target = FakeTargetExecutor()
    result = RosBindingExecutor(target).rotate(_binding(), {"angle_degrees": 15, "max_speed_rad_s": 0.2})
    assert result["status"] == "SUCCEEDED"
    assert len(target.calls) == result["publishes"] + 1
    assert target.calls[0][:6] == ["ros2", "topic", "pub", "--once", "/cmd_vel", "geometry_msgs/msg/Twist"]
    assert "z: 0.200000" in target.calls[0][-1]
    assert "z: 0.000000" in target.calls[-1][-1]


def test_rotate_provider_stops_after_publish_failure() -> None:
    class Failing(FakeTargetExecutor):
        def run_bound(self, argv, *, ros_setup_files=()):
            self.calls.append(list(argv))
            return SimpleNamespace(returncode=1, stdout="", stderr="failed") if len(self.calls) == 1 else SimpleNamespace(returncode=0, stdout="", stderr="")

    target = Failing()
    result = RosBindingExecutor(target).rotate(_binding(), {"angle_degrees": 15, "max_speed_rad_s": 0.2})
    assert result["status"] == "FAILED"
    assert len(target.calls) == 2
    assert "z: 0.000000" in target.calls[-1][-1]
