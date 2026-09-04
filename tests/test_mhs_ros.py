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


def test_ros_sampler_topic_sample_can_bind_qos_without_enabling_writes():
    calls: list[list[str]] = []

    def runner(argv, timeout_s):
        del timeout_s
        calls.append(list(argv))
        return {"returncode": 0, "stdout": "data: 1\n", "stderr": ""}

    observation, payload = MhsRosSampler(runner).sample_topic_once(
        "/scan", qos_reliability="best_effort", qos_durability="volatile"
    )
    assert payload == "data: 1\n"
    assert observation.argv == [
        "ros2",
        "topic",
        "echo",
        "--once",
        "--qos-reliability",
        "best_effort",
        "--qos-durability",
        "volatile",
        "/scan",
    ]
    assert not any("pub" in call for call in calls)


def test_ros_sampler_qos_fallback_records_all_failed_attempts():
    calls: list[list[str]] = []

    def runner(argv, timeout_s):
        del timeout_s
        calls.append(list(argv))
        return {"returncode": 124, "stdout": "", "stderr": "timeout"}

    observations, payload = MhsRosSampler(runner).sample_topic_once_with_qos_fallback(
        "/scan", qos_reliabilities=("reliable", "best_effort", "reliable")
    )
    assert payload is None
    assert len(observations) == 2
    assert len(calls) == 2
    assert calls[0][-2:] == ["reliable", "/scan"]
    assert calls[1][-2:] == ["best_effort", "/scan"]


def test_ros_sampler_does_not_treat_empty_success_as_payload():
    def runner(argv, timeout_s):
        del argv, timeout_s
        return {"returncode": 0, "stdout": "\n", "stderr": ""}

    observation, payload = MhsRosSampler(runner).sample_topic_once("/scan")
    assert observation.returncode == 0
    assert payload is None
