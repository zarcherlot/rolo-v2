"""Read-only ROS 2 sampling adapter for MHS discovery.

ROS 2 is deliberately confined to this module.  Callers provide a target
runner (local or SSH); the MHS manifest remains middleware-neutral.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Mapping, Sequence
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from .mhs_discovery import redact_secrets


class RosObservation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    operation: str = Field(min_length=1)
    argv: list[str] = Field(min_length=1)
    returncode: int | None = None
    stdout_excerpt: str = ""
    stderr_excerpt: str = ""
    stdout_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    side_effect: str = "none"


class RosGraphSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: str
    nodes: list[str] = Field(default_factory=list)
    topics: list[str] = Field(default_factory=list)
    services: list[str] = Field(default_factory=list)
    actions: list[str] = Field(default_factory=list)
    topic_info: dict[str, str] = Field(default_factory=dict)
    topic_samples: dict[str, str] = Field(default_factory=dict)
    observations: list[RosObservation] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


Runner = Callable[[Sequence[str], float], Mapping[str, Any]]
QosReliability = Literal["system_default", "reliable", "best_effort"]
QosDurability = Literal["system_default", "volatile", "transient_local"]


class MhsRosSampler:
    """Execute only fixed ROS 2 introspection commands through an injected runner."""

    def __init__(self, runner: Runner, *, timeout_s: float = 5.0) -> None:
        if timeout_s <= 0 or timeout_s > 60:
            raise ValueError("timeout_s must be in (0, 60]")
        self.runner = runner
        self.timeout_s = timeout_s

    def _query(self, operation: str, argv: Sequence[str]) -> tuple[RosObservation, str]:
        result = dict(self.runner(argv, self.timeout_s))
        stdout, changed = redact_secrets(str(result.get("stdout") or ""))
        stderr, _ = redact_secrets(str(result.get("stderr") or ""))
        observation = RosObservation(
            operation=operation,
            argv=list(argv),
            returncode=result.get("returncode"),
            stdout_excerpt=stdout[:20_000],
            stderr_excerpt=stderr[:4_000],
            stdout_sha256=hashlib.sha256(stdout.encode()).hexdigest(),
        )
        del changed
        return observation, stdout

    @staticmethod
    def _lines(output: str) -> list[str]:
        return sorted({line.strip() for line in output.splitlines() if line.strip()})[:512]

    def sample(self, *, topic_hints: Sequence[str] = ()) -> RosGraphSnapshot:
        observations: list[RosObservation] = []
        graph: dict[str, list[str]] = {
            key: [] for key in ("nodes", "topics", "services", "actions")
        }
        limitations: list[str] = []
        commands = {
            "nodes": ["ros2", "node", "list", "--no-daemon"],
            "topics": ["ros2", "topic", "list", "-t", "--no-daemon"],
            "services": ["ros2", "service", "list", "-t", "--no-daemon"],
            "actions": ["ros2", "action", "list", "-t"],
        }
        for key, argv in commands.items():
            observation, output = self._query(f"graph.{key}", argv)
            observations.append(observation)
            if observation.returncode == 0:
                graph[key] = self._lines(output)
            else:
                limitations.append(f"{key} query unavailable")
        topic_info: dict[str, str] = {}
        for topic in sorted(set(topic_hints))[:32]:
            if not topic.startswith("/"):
                limitations.append(f"topic hint rejected: {topic}")
                continue
            argv = ["ros2", "topic", "info", "-v", topic]
            observation, output = self._query(f"topic_info.{topic}", argv)
            observations.append(observation)
            if observation.returncode == 0:
                topic_info[topic] = output[:20_000]
            else:
                limitations.append(f"topic info unavailable: {topic}")
        success = any(observation.returncode == 0 for observation in observations)
        return RosGraphSnapshot(
            status="AVAILABLE" if success else "UNAVAILABLE",
            nodes=graph["nodes"],
            topics=graph["topics"],
            services=graph["services"],
            actions=graph["actions"],
            topic_info=topic_info,
            observations=observations,
            limitations=limitations,
        )

    def sample_topic_once(
        self,
        topic: str,
        *,
        qos_reliability: QosReliability = "system_default",
        qos_durability: QosDurability = "system_default",
    ) -> tuple[RosObservation, str | None]:
        """Read one bounded message from an explicitly named absolute topic."""

        if not topic.startswith("/"):
            raise ValueError("topic must be an absolute ROS name")
        argv = ["ros2", "topic", "echo", "--once"]
        if qos_reliability != "system_default":
            argv.extend(["--qos-reliability", qos_reliability])
        if qos_durability != "system_default":
            argv.extend(["--qos-durability", qos_durability])
        argv.append(topic)
        observation, output = self._query(f"topic_sample.{topic}", argv)
        payload = output[:20_000] if observation.returncode == 0 and output.strip() else None
        return observation, payload

    def sample_topic_once_with_qos_fallback(
        self,
        topic: str,
        *,
        qos_reliabilities: Sequence[QosReliability] = ("system_default", "reliable", "best_effort"),
    ) -> tuple[list[RosObservation], str | None]:
        """Try bounded read-only samples with explicit QoS profiles.

        The first successful payload wins.  Every attempt is returned so an
        evidence artifact can distinguish a QoS mismatch from a silent
        publisher.  No publisher, service, action, or parameter operation is
        invoked.
        """

        observations: list[RosObservation] = []
        seen: set[str] = set()
        for reliability in qos_reliabilities:
            if reliability in seen:
                continue
            seen.add(reliability)
            observation, payload = self.sample_topic_once(
                topic, qos_reliability=reliability
            )
            observations.append(observation)
            if payload is not None:
                return observations, payload
        return observations, None


__all__ = [
    "MhsRosSampler",
    "QosDurability",
    "QosReliability",
    "RosGraphSnapshot",
    "RosObservation",
]
