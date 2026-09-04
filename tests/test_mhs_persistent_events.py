from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from rolo.mhs_write import (
    MhsWriteResult,
    MhsWriteStatus,
    PersistentMhsWriteEventStore,
)


def _result(event_id: str) -> MhsWriteResult:
    return MhsWriteResult(
        event_id=event_id,
        status=MhsWriteStatus.DENIED,
        request_id=f"request-{event_id}",
        device_id="fixture",
        command_id="stop",
        route="mhs://fixture/stop",
        robot_id="robot",
        target_host_fingerprint="a" * 64,
        observed_at=datetime(2026, 9, 2, tzinfo=timezone.utc),
        reason="fixture denial",
        manifest_sha256="b" * 64,
        driver_sha256="c" * 64,
    )


def test_persistent_event_store_recovers_and_verifies_chain(tmp_path) -> None:
    path = tmp_path / "mhs-events.jsonl"
    first = PersistentMhsWriteEventStore(path)
    first.append(_result("event-1"))
    first.append(_result("event-2"))

    recovered = PersistentMhsWriteEventStore(path)
    assert [event.event_id for event in recovered.events()] == ["event-1", "event-2"]
    recovered.verify()

    path.write_text(path.read_text(encoding="utf-8").replace("fixture denial", "tampered"), encoding="utf-8")
    with pytest.raises(ValueError, match="digest mismatch"):
        PersistentMhsWriteEventStore(path)
