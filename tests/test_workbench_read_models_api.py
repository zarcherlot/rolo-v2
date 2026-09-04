from __future__ import annotations

from fastapi.testclient import TestClient

from rolo.api import app


def test_health_is_degraded_without_a_verified_snapshot(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("ROLO_RKB_ROOT", str(tmp_path / "rkb"))
    with TestClient(app) as client:
        response = client.get("/health")
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "DEGRADED"
    assert {
        "rkb.read-model/v1",
        "mhs.inventory-read-model/v1",
        "tool.verification-read-model/v1",
    } <= set(payload["api_features"])


def test_unknown_robot_fails_closed(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("ROLO_RKB_ROOT", str(tmp_path / "rkb"))
    with TestClient(app) as client:
        response = client.get("/v1/robots/robot-unknown/rkb")
    assert response.status_code == 404
    assert response.json() == {"detail": "robot snapshot not found"}
