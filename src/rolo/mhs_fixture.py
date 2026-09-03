"""Load sanitized structured MHS fixtures into the read-only replay backend."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .mhs_hardware import MhsDeviceManifest, MhsInterfaceSample


def _source_timestamp(value: Any) -> datetime | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise ValueError("source_timestamp must be an object")
    try:
        sec = int(value["sec"])
        nanosec = int(value["nanosec"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("source_timestamp requires integer sec/nanosec") from exc
    if nanosec < 0 or nanosec >= 1_000_000_000:
        raise ValueError("source_timestamp nanosec is out of range")
    return datetime.fromtimestamp(sec + nanosec / 1_000_000_000, tz=timezone.utc)


def load_fixture_for_manifest(
    path: str | Path, manifest: MhsDeviceManifest
) -> list[MhsInterfaceSample]:
    """Load only the topic samples declared by ``manifest``.

    A fixture may contain samples for several devices.  Matching is performed
    by the manifest interface's ``ros2:///`` transport reference and the
    fixture's topic key; unrelated records are ignored.  Payload bytes are
    expected to be sanitized summaries, not live transport handles.
    """

    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or not isinstance(raw.get("samples"), dict):
        raise ValueError("fixture must contain an object-valued samples field")
    observed_at_raw = raw.get("observed_at")
    if not isinstance(observed_at_raw, str):
        raise ValueError("fixture observed_at is required")
    try:
        observed_at = datetime.fromisoformat(observed_at_raw.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("fixture observed_at must be ISO-8601") from exc
    if observed_at.tzinfo is None:
        raise ValueError("fixture observed_at must include a timezone")

    by_transport = {
        interface.transport_ref: interface
        for interface in manifest.interfaces
        if interface.transport_ref
    }
    samples: list[MhsInterfaceSample] = []
    for topic, record in raw["samples"].items():
        if not isinstance(topic, str) or not isinstance(record, dict):
            raise ValueError("fixture samples must map string topics to objects")
        interface = by_transport.get(f"ros2://{topic}")
        if interface is None:
            continue
        interface_id = record.get("interface_id")
        if interface_id != interface.id:
            raise ValueError(
                f"fixture interface mismatch for {topic}: {interface_id!r} != {interface.id!r}"
            )
        source_timestamp = _source_timestamp(record.get("source_timestamp"))
        value = {
            key: item
            for key, item in record.items()
            if key not in {"interface_id", "type", "frame_id", "source_timestamp"}
        }
        metadata = {
            "topic": topic,
            "type": record.get("type"),
            "frame_id": record.get("frame_id"),
            "fixture": str(path),
        }
        samples.append(
            MhsInterfaceSample(
                interface_id=interface.id,
                value=value,
                observed_at=observed_at,
                source_timestamp=source_timestamp,
                metadata=metadata,
            )
        )
    return samples


__all__ = ["load_fixture_for_manifest"]
