"""Pure parsing helpers for a target's ROS 2 runtime observations.

The targetd transport is responsible for executing an allowlisted inspection
command in the target container. This module only normalizes its stdout; it
never treats a static fixture as an observed route.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any


def _optional_text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


@dataclass(frozen=True, slots=True)
class Ros2Topic:
    name: str
    interface_type: str

    def as_route(self) -> dict[str, str]:
        return {
            "resource_id": self.name,
            "kind": "ros_topic",
            "endpoint": self.name,
            "interface_type": self.interface_type,
            "evidence_origin": "OBSERVED_RUNTIME",
            "source": "targetd:ros2 topic observation",
        }

    def as_schema(self) -> dict[str, str]:
        return {"schema_id": self.interface_type, "source": "targetd:ros2 topic observation"}


@dataclass(frozen=True, slots=True)
class Ros2RuntimeSnapshot:
    """Normalized, read-only snapshot captured from an authorized ROS2 runtime."""

    distro: str
    ros2_path: str
    topics: tuple[Ros2Topic, ...] = ()
    nodes: tuple[str, ...] = ()
    packages: tuple[str, ...] = ()
    executor_user: str | None = None
    publisher_user: str | None = None
    rmw_implementation: str | None = None

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> Ros2RuntimeSnapshot:
        """Load a snapshot artifact and verify its optional runtime digest."""
        if payload.get("schema_version") != "rolo-ros2-runtime-snapshot/v1":
            raise ValueError("unsupported ROS2 runtime snapshot schema")
        raw_topics = payload.get("topics", [])
        if not isinstance(raw_topics, list):
            raise ValueError("ROS2 runtime snapshot topics must be an array")
        topics: list[Ros2Topic] = []
        for raw in raw_topics:
            if (
                not isinstance(raw, dict)
                or not isinstance(raw.get("name"), str)
                or not isinstance(raw.get("interface_type"), str)
                or not raw["name"].startswith("/")
                or "/" not in raw["interface_type"]
            ):
                raise ValueError("ROS2 runtime snapshot topic is invalid")
            topics.append(Ros2Topic(raw["name"], raw["interface_type"]))
        nodes = payload.get("nodes", [])
        packages = payload.get("packages", [])
        if not isinstance(nodes, list) or not all(isinstance(item, str) for item in nodes):
            raise ValueError("ROS2 runtime snapshot nodes must be an array of strings")
        if not isinstance(packages, list) or not all(isinstance(item, str) for item in packages):
            raise ValueError("ROS2 runtime snapshot packages must be an array of strings")
        snapshot = cls(
            distro=str(payload.get("distro", "")),
            ros2_path=str(payload.get("ros2_path", "")),
            topics=tuple(topics),
            nodes=tuple(nodes),
            packages=tuple(packages),
            executor_user=_optional_text(payload.get("executor_user")),
            publisher_user=_optional_text(payload.get("publisher_user")),
            rmw_implementation=_optional_text(payload.get("rmw_implementation")),
        )
        declared_digest = payload.get("runtime_digest")
        if declared_digest is not None and declared_digest != snapshot.runtime_digest:
            raise ValueError("ROS2 runtime snapshot digest mismatch")
        return snapshot

    def as_dict(self) -> dict[str, Any]:
        """Return the canonical, evidence-friendly snapshot representation."""
        result = {
            "schema_version": "rolo-ros2-runtime-snapshot/v1",
            "distro": self.distro,
            "ros2_path": self.ros2_path,
            "topics": [
                {"name": item.name, "interface_type": item.interface_type}
                for item in sorted(self.topics, key=lambda item: (item.name, item.interface_type))
            ],
            "nodes": sorted(self.nodes),
            "packages": sorted(self.packages),
            "runtime_digest": self.runtime_digest,
        }
        for key in ("executor_user", "publisher_user", "rmw_implementation"):
            value = getattr(self, key)
            if value is not None:
                result[key] = value
        return result

    @property
    def runtime_digest(self) -> str:
        payload = {
            "distro": self.distro,
            "ros2_path": self.ros2_path,
            "topics": [{"name": item.name, "interface_type": item.interface_type} for item in sorted(self.topics, key=lambda item: (item.name, item.interface_type))],
            "nodes": sorted(self.nodes),
            "packages": sorted(self.packages),
        }
        for key in ("executor_user", "publisher_user", "rmw_implementation"):
            value = getattr(self, key)
            if value is not None:
                payload[key] = value
        encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
        return "sha256:" + hashlib.sha256(encoded).hexdigest()


class Ros2RuntimeResolver:
    """Resolve only ROS2 topics present in a captured runtime snapshot."""

    def __init__(self, snapshot: Ros2RuntimeSnapshot) -> None:
        self.snapshot = snapshot

    def resolve_topic(self, name: str, *, interface_type: str | None = None) -> Ros2Topic:
        topic = next((item for item in self.snapshot.topics if item.name == name), None)
        if topic is None:
            raise ValueError("RESOURCE_NOT_OBSERVED")
        if interface_type is not None and topic.interface_type != interface_type:
            raise ValueError("MESSAGE_SCHEMA_MISMATCH")
        return topic

    def resolve_binding(self, binding: dict[str, str]) -> dict[str, str]:
        resource_id = binding.get("resource_id", "")
        if resource_id.startswith("route:"):
            resource_id = resource_id.removeprefix("route:")
        topic = self.resolve_topic(resource_id, interface_type=binding.get("interface_type"))
        return topic.as_route()


def parse_ros2_topic_types(lines: Iterable[str]) -> tuple[Ros2Topic, ...]:
    """Parse ``ros2 topic type`` output into stable, duplicate-free records.

    Each accepted line contains a topic name followed by one interface type,
    separated by whitespace. Diagnostics, blank lines and malformed records
    are ignored so callers can preserve them separately as limitations.
    """
    topics: dict[tuple[str, str], Ros2Topic] = {}
    for raw in lines:
        fields = raw.strip().split()
        if len(fields) != 2:
            continue
        name, interface_type = fields
        if not name.startswith("/") or "/" not in interface_type or " " in interface_type:
            continue
        topics[(name, interface_type)] = Ros2Topic(name, interface_type)
    return tuple(topics[key] for key in sorted(topics))


_TOPIC_LIST_RECORD = re.compile(
    r"^(?P<name>/[^\s]+)\s+\[(?P<interface>[A-Za-z_][A-Za-z0-9_]*(?:/[A-Za-z_][A-Za-z0-9_]*)+)\]$"
)


def parse_ros2_topic_list(lines: Iterable[str]) -> tuple[Ros2Topic, ...]:
    """Parse ``ros2 topic list -t`` output into observed topic records.

    The ROS 2 CLI prints records as ``/topic [pkg/msg/Type]`` while
    ``ros2 topic type`` prints ``/topic pkg/msg/Type``.  Both forms are
    accepted by the runtime adapter, but only syntactically valid records are
    projected into the observed set.  Human diagnostics, wrapped terminal
    fragments, and malformed rows are ignored by design.
    """
    topics: dict[tuple[str, str], Ros2Topic] = {}
    for raw in lines:
        match = _TOPIC_LIST_RECORD.fullmatch(raw.strip())
        if match is None:
            continue
        topic = Ros2Topic(match.group("name"), match.group("interface"))
        topics[(topic.name, topic.interface_type)] = topic
    return tuple(topics[key] for key in sorted(topics))


def parse_ros2_nodes(lines: Iterable[str]) -> tuple[str, ...]:
    """Parse ``ros2 node list`` output into stable node names."""
    return tuple(sorted({line.strip() for line in lines if line.strip().startswith("/")}))


def snapshot_from_cli_output(
    *,
    distro: str,
    ros2_path: str,
    topic_lines: Iterable[str],
    node_lines: Iterable[str] = (),
    package_lines: Iterable[str] = (),
    topic_format: str = "list",
    executor_user: str | None = None,
    publisher_user: str | None = None,
    rmw_implementation: str | None = None,
) -> Ros2RuntimeSnapshot:
    """Build a snapshot from bounded, read-only ROS2 CLI output.

    ``topic_format`` is either ``list`` for ``ros2 topic list -t`` or
    ``types`` for ``ros2 topic type``.  The function intentionally requires
    the caller to provide the command output; it never turns a static catalog
    or a guessed topic into observed runtime evidence.
    """
    if not distro.strip() or not ros2_path.strip():
        raise ValueError("ROS2 runtime identity is incomplete")
    if topic_format == "list":
        topics = parse_ros2_topic_list(topic_lines)
    elif topic_format == "types":
        topics = parse_ros2_topic_types(topic_lines)
    else:
        raise ValueError("topic_format must be 'list' or 'types'")
    if not topics:
        raise ValueError("ROS2 topic output contained no valid observed topics")
    return Ros2RuntimeSnapshot(
        distro=distro.strip(),
        ros2_path=ros2_path.strip(),
        topics=topics,
        nodes=parse_ros2_nodes(node_lines),
        packages=tuple(sorted({line.strip() for line in package_lines if line.strip()})),
        executor_user=_optional_text(executor_user),
        publisher_user=_optional_text(publisher_user),
        rmw_implementation=_optional_text(rmw_implementation),
    )


__all__ = [
    "Ros2RuntimeResolver",
    "Ros2RuntimeSnapshot",
    "Ros2Topic",
    "parse_ros2_nodes",
    "parse_ros2_topic_list",
    "parse_ros2_topic_types",
    "snapshot_from_cli_output",
]
