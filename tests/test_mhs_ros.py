from __future__ import annotations

from rolo.mhs_ros import MhsRosSampler


def test_ros_sampler_uses_only_read_only_allowlist_and_binds_topic_info():
    calls: list[list[str]] = []

    def runner(argv, timeout_s):
        del timeout_s
        calls.append(list(argv))
        if argv[1:3] == ["node", "list"]:
            return {"returncode": 0, "stdout": "/aurora930_node\n", "stderr": ""}
        if argv[1:3] == ["topic", "list"]:
            return {"returncode": 0, "stdout": "/scan [sensor_msgs/msg/LaserScan]\n", "stderr": ""}
        if argv[1:3] == ["topic", "info"]:
            return {"returncode": 0, "stdout": "Type: sensor_msgs/msg/LaserScan\n", "stderr": ""}
        return {"returncode": 0, "stdout": "", "stderr": ""}

    snapshot = MhsRosSampler(runner).sample(topic_hints=["/scan"])
    assert snapshot.status == "AVAILABLE"
    assert "/aurora930_node" in snapshot.nodes
    assert snapshot.topic_info["/scan"].startswith("Type:")
    assert all(call[0] == "ros2" for call in calls)
    assert not any("pub" in call for call in calls)


def test_ros_sampler_rejects_non_absolute_topic_hint_without_running_it():
    calls: list[list[str]] = []

    def runner(argv, timeout_s):
        del timeout_s
        calls.append(list(argv))
        return {"returncode": 1, "stdout": "", "stderr": "missing"}

    snapshot = MhsRosSampler(runner).sample(topic_hints=["scan"])
    assert any("topic hint rejected" in item for item in snapshot.limitations)
    assert not any(call[1:3] == ["topic", "info"] for call in calls)


def test_ros_sampler_topic_sample_is_explicit_and_bounded():
    calls: list[list[str]] = []

    def runner(argv, timeout_s):
        del timeout_s
        calls.append(list(argv))
        return {"returncode": 0, "stdout": "ranges: [1.0, 2.0]\n", "stderr": ""}

    observation, payload = MhsRosSampler(runner).sample_topic_once("/scan")
    assert observation.operation == "topic_sample./scan"
    assert payload == "ranges: [1.0, 2.0]\n"
    assert calls == [["ros2", "topic", "echo", "--once", "/scan"]]
