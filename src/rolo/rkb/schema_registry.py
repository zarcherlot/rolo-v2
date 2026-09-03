"""Explicit schema migration and deprecation policy for RKB artifacts."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date


@dataclass(frozen=True)
class SchemaPolicy:
    schema: str
    introduced: date
    deprecated_after: date | None = None
    replacement: str | None = None


class SchemaRegistry:
    def __init__(self, policies: tuple[SchemaPolicy, ...] | None = None) -> None:
        self._policies = {item.schema: item for item in (policies or DEFAULT_POLICIES)}

    def policy(self, schema: str) -> SchemaPolicy:
        try:
            return self._policies[schema]
        except KeyError as exc:
            raise ValueError(f"unknown RKB schema: {schema}") from exc

    def is_readable(self, schema: str, *, on: date | None = None) -> bool:
        policy = self.policy(schema)
        return policy.deprecated_after is None or (on or date.today()) <= policy.deprecated_after

    def migration_target(self, schema: str) -> str | None:
        return self.policy(schema).replacement


DEFAULT_POLICIES = (
    SchemaPolicy("robot-snapshot/v1", date(2026, 1, 1)),
    SchemaPolicy("rkb-episode-metadata/v1", date(2026, 9, 1)),
    SchemaPolicy(
        "TargetEvidenceBundle/v2", date(2025, 1, 1), date(2027, 12, 31),
        "robot-snapshot/v1"
    ),
    SchemaPolicy(
        "TargetEvidenceBundle/v3", date(2025, 1, 1), date(2027, 12, 31),
        "robot-snapshot/v1"
    ),
)
