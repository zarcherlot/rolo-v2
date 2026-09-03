"""Structured, read-only health alerts for RKB-4 operators.

The evaluator never invokes a device route.  It turns persisted counters and
snapshot freshness into bounded alert records suitable for a scheduler.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from .episodes import EpisodeMetrics
from .models import FreshnessStatus, Snapshot


class AlertSeverity(str, Enum):
    WARNING = "warning"
    CRITICAL = "critical"


@dataclass(frozen=True)
class RKBAlert:
    code: str
    severity: AlertSeverity
    message: str
    observed_at: datetime
    value: float | int | str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "rkb4-alert/v1",
            "code": self.code,
            "severity": self.severity.value,
            "message": self.message,
            "observed_at": self.observed_at.astimezone(timezone.utc).isoformat(),
            "value": self.value,
        }


def evaluate_alerts(
    *,
    snapshot: Snapshot | None = None,
    metrics: EpisodeMetrics | Mapping[str, int] | None = None,
    capacity_used_bytes: int | None = None,
    capacity_limit_bytes: int | None = None,
    now: datetime | None = None,
) -> list[RKBAlert]:
    """Return deterministic alerts for freshness, integrity and capacity."""

    point = now or datetime.now(timezone.utc)
    alerts: list[RKBAlert] = []
    if snapshot is not None:
        freshness = snapshot.identity.freshness(now=point)
        if freshness == FreshnessStatus.STALE:
            alerts.append(
                RKBAlert(
                    "snapshot_stale", AlertSeverity.WARNING,
                    "snapshot freshness expired", point, freshness.value
                )
            )
    counters = metrics.as_dict() if isinstance(metrics, EpisodeMetrics) else dict(metrics or {})
    for key, code in (
        ("corrupt_artifacts", "digest_mismatch"),
        ("validation_rejections", "validation_rejection"),
    ):
        value = int(counters.get(key, 0))
        if value > 0:
            alerts.append(
                RKBAlert(code, AlertSeverity.CRITICAL,
                         f"{key} counter is non-zero", point, value)
            )
    if capacity_used_bytes is not None and capacity_limit_bytes:
        ratio = capacity_used_bytes / capacity_limit_bytes
        if ratio >= 0.9:
            alerts.append(
                RKBAlert(
                    "capacity_high_watermark", AlertSeverity.WARNING,
                    "artifact capacity is above 90%", point, round(ratio, 4)
                )
            )
    return alerts
