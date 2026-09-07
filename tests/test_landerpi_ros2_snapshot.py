import json
from pathlib import Path

from scripts.landerpi_ros2_snapshot import normalize, run


def capture() -> dict:
    return {
        "schema_version": "rolo-ros2-runtime-capture/v1",
        "target_id": "landerpi",
        "observed_at": "2026-09-06T02:19:36Z",
        "distro": "humble",
        "ros2_path": "/opt/ros/humble/bin/ros2",
        "topic_format": "list",
        "topic_output": [
            "/cmd_vel [geometry_msgs/msg/Twist]",
            "/odom [nav_msgs/msg/Odometry]",
            "/scan [sensor_msgs/msg/LaserScan]",
            "/tf [tf2_msgs/msg/TFMessage]",
        ],
        "node_output": ["/robot_api", "diagnostic"],
        "package_output": ["rclpy", "sensor_msgs"],
    }


def test_normalize_is_read_only_and_digest_bound() -> None:
    result = normalize(capture())
    assert result["access"] == "READ_ONLY"
    assert result["runtime_digest"].startswith("sha256:")
    assert [item["endpoint"] for item in result["routes"]] == ["/cmd_vel", "/odom", "/scan", "/tf"]
    assert result["snapshot"]["nodes"] == ["/robot_api"]


def test_run_writes_atomic_observation(tmp_path: Path) -> None:
    source = tmp_path / "capture.json"
    output = tmp_path / "nested" / "observation.json"
    source.write_text(json.dumps(capture()), encoding="utf-8")
    run(source, output)
    written = json.loads(output.read_text(encoding="utf-8"))
    assert written["schema_version"] == "rolo-ros2-runtime-observation/v1"
    assert not output.with_suffix(".json.tmp").exists()


def test_normalize_retains_execution_identity_and_flags_cross_user_capture() -> None:
    payload = capture()
    payload.update({"executor_user": "root", "publisher_user": "ubuntu", "rmw_implementation": "rmw_fastrtps_cpp"})
    result = normalize(payload)
    snapshot = result["snapshot"]
    assert snapshot["executor_user"] == "root"
    assert snapshot["publisher_user"] == "ubuntu"
    assert snapshot["rmw_implementation"] == "rmw_fastrtps_cpp"
    assert any("differs" in item for item in result["limitations"])
