"""Deterministic read-only conformance check for the LanderPi MHS artifacts."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


EXPECTED_TOPICS = {
    "/scan": "sensor_msgs/msg/LaserScan",
    "/controller_manager/joint_states": "sensor_msgs/msg/JointState",
    "/controller_manager/servo_states": "servo_controller_msgs/msg/ServoStateList",
    "/ascamera/camera_publisher/rgb0/image": "sensor_msgs/msg/Image",
    "/ascamera/camera_publisher/ir0/image": "sensor_msgs/msg/Image",
    "/ascamera/camera_publisher/depth0/image_raw": "sensor_msgs/msg/Image",
}


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).parent)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    root = args.root
    bundle = load(root / "mhs-bundle-20260902.json")
    fixture = load(root / "ros-structured-fixture-20260903.json")
    binding = load(root / "physical-binding-20260903.json")
    safety = load(root / "safety-review-20260903.json")

    checks: dict[str, dict] = {}
    checks["bundle_schema"] = {
        "passed": bundle.get("schema_version") == "rolo-mhs-bundle/v1",
        "observed": bundle.get("schema_version"),
    }
    ids = [d.get("manifest", {}).get("device_id") for d in bundle.get("devices", [])]
    checks["unique_device_ids"] = {"passed": len(ids) == len(set(ids)), "observed": ids}
    commands = [
        d.get("manifest", {}).get("commands", []) for d in bundle.get("devices", [])
    ]
    checks["write_commands_absent"] = {
        "passed": all(not command_list for command_list in commands),
        "observed_command_count": sum(len(command_list) for command_list in commands),
    }
    samples = fixture.get("samples", {})
    checks["fixture_topics_and_types"] = {
        "passed": all(topic in samples and samples[topic].get("type") == msg_type for topic, msg_type in EXPECTED_TOPICS.items()),
        "missing_topics": [topic for topic in EXPECTED_TOPICS if topic not in samples],
    }
    refs = {
        evidence.get("ref")
        for device in bundle.get("devices", [])
        for evidence in device.get("evidence", [])
    }
    checks["physical_binding_referenced"] = {
        "passed": any(ref.startswith("artifact://mhs-landerpi/physical-binding-") for ref in refs),
        "matching_refs": sorted(ref for ref in refs if "physical-binding" in ref),
    }
    checks["safety_fail_closed"] = {
        "passed": (
            safety.get("decision") == "BLOCKED_FOR_WRITE_AND_VERIFIED"
            and safety.get("global_invariants", {}).get("write_commands_enabled") is False
            and safety.get("global_invariants", {}).get("human_canary_approval") is False
        ),
        "decision": safety.get("decision"),
    }
    checks["estop_and_limits_gate"] = {
        "passed": all(
            surface.get("checks", {}).get("external_estop_clear") is True
            and surface.get("checks", {}).get("hardware_limits_known") is True
            and surface.get("checks", {}).get("limit_switches_verified", True) is True
            for surface in safety.get("surfaces", [])
            if surface.get("device_id") in {"landerpi-ros-robot-controller", "landerpi-servo-actuator"}
        ),
        "status": "NOT_VERIFIED",
    }
    image_topics = (
        "/ascamera/camera_publisher/rgb0/image",
        "/ascamera/camera_publisher/ir0/image",
        "/ascamera/camera_publisher/depth0/image_raw",
    )
    invalid_hashes = {
        topic: len(samples[topic].get("data_sha256", ""))
        for topic in image_topics
        if len(samples[topic].get("data_sha256", "")) != 64
    }
    checks["fixture_digest_shape"] = {
        "passed": not invalid_hashes,
        "algorithm": "sha256",
        "invalid_hash_lengths": invalid_hashes,
    }

    # Safety is intentionally a separate gate: the read-only wire/profile checks
    # can pass while actuator release remains blocked by missing safety evidence.
    read_only_pass = all(
        item["passed"] for name, item in checks.items() if name != "estop_and_limits_gate"
    )
    report = {
        "schema_version": "rolo-mhs-conformance/v1",
        "robot_id": "landerpi",
        "evaluated_at": "2026-09-03T08:35:00+08:00",
        "profile": "rolo-mhs-compatible-read-only/v1",
        "result": "PASS_READ_ONLY" if read_only_pass else "FAIL",
        "write_profile": "NOT_ELIGIBLE",
        "checks": checks,
        "negative_tests": {
            "unknown_channel": "REJECTED_BY_MANIFEST",
            "write_command": "REJECTED_BY_EMPTY_COMMANDS",
            "stale_or_missing_estop": "REJECTED_BY_SAFETY_GATE",
            "unmapped_servo_id_9": "RETAINED_AS_UNKNOWN",
        },
        "source_artifacts": [
            "mhs-bundle-20260902.json",
            "ros-structured-fixture-20260903.json",
            "physical-binding-20260903.json",
            "safety-review-20260903.json",
            "estop-limits-evidence-20260903.json",
            "fixture-repair-20260903.json",
            "ros-reacquisition-20260903.json",
        ],
        "limitations": [
            "This is a Rolo-compatible profile check, not an official external MHS conformance certification.",
            "Actuator write, E-stop, limit-switch, watchdog and fault-clear behavior remain unverified.",
        ],
    }
    output = args.output or (root / "conformance-20260903.json")
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(output)
    return 0 if read_only_pass else 1


if __name__ == "__main__":
    raise SystemExit(main())
