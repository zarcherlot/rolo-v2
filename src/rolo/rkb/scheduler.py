"""Deployment-neutral periodic alert scheduling primitives."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .alerts import RKBAlert, evaluate_alerts
from .episodes import EpisodeMetrics


@dataclass(frozen=True)
class AlertSchedule:
    interval: timedelta = timedelta(minutes=1)
    watermark: float = 0.9

    def __post_init__(self) -> None:
        if self.interval <= timedelta(0) or not 0 < self.watermark <= 1:
            raise ValueError("interval must be positive and watermark must be in (0, 1]")


def run_alert_cycle(
    metrics_path: Path, *, capacity_used_bytes: int | None = None,
    capacity_limit_bytes: int | None = None, now: datetime | None = None,
    emit: Callable[[RKBAlert], None] | None = None,
) -> list[RKBAlert]:
    """Read durable Episode counters and emit structured alerts once."""

    metrics = EpisodeMetrics()
    if metrics_path.exists():
        import json

        metrics = EpisodeMetrics(**json.loads(metrics_path.read_text(encoding="utf-8")))
    alerts = evaluate_alerts(
        metrics=metrics, capacity_used_bytes=capacity_used_bytes,
        capacity_limit_bytes=capacity_limit_bytes, now=now or datetime.now(timezone.utc)
    )
    if emit is not None:
        for alert in alerts:
            emit(alert)
    return alerts
