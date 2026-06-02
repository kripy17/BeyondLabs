from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_health_endpoint_returns_ok():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_root_endpoint_identifies_api():
    response = client.get("/")
    assert response.status_code == 200
    payload = response.json()
    assert payload["name"] == "BeyondArch API"
    assert payload["status"] == "running"


def test_expected_router_prefixes_are_registered():
    paths = {getattr(route, "path", "") for route in app.routes}
    for prefix in [
        "/api/recon", "/api/soc", "/api/phishing", "/api/url",
        "/api/utils", "/api/osint", "/api/detection", "/api/network",
    ]:
        assert any(path.startswith(prefix) for path in paths), f"missing route prefix: {prefix}"
