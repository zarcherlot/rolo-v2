import json

from fastapi.testclient import TestClient

from rolo.api import app


def test_targetd_session_read_model_lists_receipt_artifacts(tmp_path, monkeypatch):
    session_dir = tmp_path / "targetd" / "mentorpi" / "sessions" / "session-1" / "calls"
    session_dir.mkdir(parents=True)
    (session_dir / "call-1.json").write_text(
        json.dumps({"receipt": {"status": "SUCCEEDED"}}), encoding="utf-8"
    )
    (session_dir.parent / "events.jsonl").write_text(
        json.dumps({"status": "STARTED", "idempotency_key": "call-1"}) + "\n",
        encoding="utf-8",
    )
    report_dir = session_dir.parents[2] / "certify"
    report_dir.mkdir(parents=True)
    (report_dir / "report.json").write_text(
        json.dumps({"schema_version": "rolo-targetd-certify-report/v1", "status": "PASS"}),
        encoding="utf-8",
    )
    monkeypatch.setenv("ROLO_ARTIFACT_ROOT", str(tmp_path))
    response = TestClient(app).get("/v1/targetd/mentorpi/sessions/session-1")
    assert response.status_code == 200
    assert response.json()["call_count"] == 1
    assert response.json()["event_count"] == 1
    assert response.json()["certify_reports"][0]["status"] == "PASS"
