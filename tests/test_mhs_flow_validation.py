from __future__ import annotations

import json
from pathlib import Path

from scripts.validate_mhs_flow import validate


def test_recorded_mhs_round_trip_through_rolo_and_rkb() -> None:
    payload = json.loads(
        (
            Path(__file__).parents[1]
            / "examples"
            / "mhs-landerpi"
            / "canary-20260902.json"
        ).read_text(encoding="utf-8")
    )
    result = validate(
        {
            "device_identity": payload["manifest"],
            "read": payload["read"],
            "status": payload["status"],
            "observed_at_epoch": payload["observed_at_epoch"],
            "device_id": payload["device_id"],
        }
    )
    assert result["status"] == "PASS"
    assert result["write_denied"]
    assert result["query_statuses"] == ["FRESH", "FRESH", "FRESH"]
