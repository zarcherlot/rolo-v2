from fastapi.testclient import TestClient

from rolo.rkb.mhs_api import MhsEvidenceReadApi
from rolo.rkb.mhs_http import create_mhs_app


def test_mhs_http_exposes_only_read_routes() -> None:
    api = MhsEvidenceReadApi()
    api.publish_parts(target_fingerprint="a" * 64)
    client = TestClient(create_mhs_app(api))
    response = client.get(f"/v1/mhs/{'a' * 64}/evidence")
    assert response.status_code == 200
    assert response.json()["access"] == "READ_ONLY"
    assert response.json()["write_operations"] == 0
    assert client.post(f"/v1/mhs/{'a' * 64}/evidence").status_code == 405


def test_mhs_http_returns_not_found_without_leaking_mutation_surface() -> None:
    client = TestClient(create_mhs_app())
    response = client.get(f"/v1/mhs/{'b' * 64}/evidence")
    assert response.status_code == 404
