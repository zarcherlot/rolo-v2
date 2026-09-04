from fastapi.testclient import TestClient

from rolo.http_server import create_app
from rolo.rkb.mhs_api import MhsEvidenceReadApi


def test_production_http_server_embeds_read_only_mhs_routes() -> None:
    api = MhsEvidenceReadApi()
    fingerprint = "a" * 64
    api.publish_parts(target_fingerprint=fingerprint)
    client = TestClient(create_app(api))

    response = client.get(f"/v1/mhs/{fingerprint}/evidence")
    assert response.status_code == 200
    assert response.json()["access"] == "READ_ONLY"
    assert response.json()["write_operations"] == 0
    assert client.post(f"/v1/mhs/{fingerprint}/evidence").status_code == 405
    cards = client.get(f"/v1/mhs/{fingerprint}/cards")
    assert cards.status_code == 200
    assert cards.json()["access"] == "READ_ONLY"
    assert cards.json()["write_operations"] == 0


def test_production_http_server_lists_targets() -> None:
    client = TestClient(create_app())
    response = client.get("/v1/mhs/targets")
    assert response.status_code == 200
    assert response.json() == {"targets": [], "access": "READ_ONLY", "write_operations": 0}


def test_legacy_asgi_module_reexports_same_application() -> None:
    from rolo.api import app as legacy_app

    client = TestClient(legacy_app)
    assert client.get("/v1/mhs/targets").json() == {
        "targets": [],
        "access": "READ_ONLY",
        "write_operations": 0,
    }
