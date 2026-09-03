from datetime import datetime, timezone
import json

from rolo.mhs_fixture import load_fixture_for_manifest
from rolo.mhs_hardware import MhsDeviceClass, MhsDeviceManifest


def test_fixture_loader_matches_ros_transport_and_preserves_metadata(tmp_path):
    manifest = MhsDeviceManifest(
        device_id="lidar-1",
        device_class=MhsDeviceClass.SENSOR,
        name="lidar",
        vendor="example",
        model="ld19",
        interfaces=[
            {
                "id": "scan",
                "kind": "laser_scan",
                "access": "stream",
                "transport_ref": "ros2:///scan",
            }
        ],
    )
    path = tmp_path / "fixture.json"
    path.write_text(
        json.dumps(
            {
                "observed_at": "2026-09-03T00:58:10+08:00",
                "samples": {
                    "/scan": {
                        "interface_id": "scan",
                        "type": "sensor_msgs/msg/LaserScan",
                        "frame_id": "lidar_frame",
                        "source_timestamp": {"sec": 1788368288, "nanosec": 805193620},
                        "ranges_count": 501,
                    },
                    "/unrelated": {"interface_id": "other", "type": "x"},
                },
            }
        ),
        encoding="utf-8",
    )
    samples = load_fixture_for_manifest(path, manifest)
    assert len(samples) == 1
    assert samples[0].interface_id == "scan"
    assert samples[0].value == {"ranges_count": 501}
    assert samples[0].metadata["frame_id"] == "lidar_frame"
    assert samples[0].source_timestamp == datetime.fromtimestamp(
        1788368288.805193620, tz=timezone.utc
    )
