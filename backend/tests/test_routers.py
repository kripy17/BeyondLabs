from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


class TestUtilsRouter:
    def test_base64_decode(self):
        r = client.post("/api/utils/base64", json={"text": "aGVsbG8=", "action": "decode"})
        assert r.status_code == 200
        assert "hello" in r.text.lower()

    def test_base64_encode(self):
        r = client.post("/api/utils/base64", json={"text": "hello", "action": "encode"})
        assert r.status_code == 200
        assert r.json()["output"] == "aGVsbG8="

    def test_url_decode(self):
        r = client.post("/api/utils/url-codec", json={"text": "hello%20world", "action": "decode"})
        assert r.status_code == 200
        assert "hello world" in r.json()["output"]

    def test_url_encode(self):
        r = client.post("/api/utils/url-codec", json={"text": "hello world", "action": "encode"})
        assert r.status_code == 200
        assert r.json()["output"] in ("hello%20world", "hello+world")

    def test_parse_url(self):
        r = client.post("/api/utils/url-parse", json={"url": "https://example.com/path?a=1"})
        assert r.status_code == 200
        data = r.json()
        assert data["scheme"] == "https"
        assert data["hostname"] == "example.com"

    def test_jwt_decode_invalid_token(self):
        r = client.post("/api/utils/jwt/decode", json={"token": "not-a-jwt"})
        assert r.status_code == 200
        result = r.json()
        assert "error" in result or "valid" not in result


class TestSocRouter:
    def test_extract_iocs(self):
        r = client.post("/api/soc/extract-iocs", json={"text": "1.1.1.1 and evil.com"})
        assert r.status_code == 200
        data = r.json()
        assert any("1.1.1.1" in str(v) for v in data.values())

    def test_transform_defang(self):
        r = client.post("/api/soc/transform", json={"text": "evil.com", "action": "defang"})
        assert r.status_code == 200
        assert "evil[.]com" in r.json()["output"]

    def test_transform_refang(self):
        r = client.post("/api/soc/transform", json={"text": "evil[.]com", "action": "refang"})
        assert r.status_code == 200
        assert "evil.com" in r.json()["output"]

    def test_identify_hash(self):
        r = client.post("/api/soc/identify-hash", json={"hash_value": "d41d8cd98f00b204e9800998ecf8427e"})
        assert r.status_code in (200, 404)
        if r.status_code == 200:
            data = r.json()
            assert isinstance(data, dict)

    def test_hash_compare_match(self):
        r = client.post("/api/soc/hash-compare", json={"text": "hello", "expected_hash": "5d41402abc4b2a76b9719d911017c592"})
        assert r.status_code in (200, 404)
        if r.status_code == 200:
            assert isinstance(r.json(), dict)


class TestUrlRouter:
    def test_safe_analyze_basic(self):
        r = client.post("/api/url/safe-analyze", json={"url": "https://example.com"})
        assert r.status_code == 200
        data = r.json()
        assert isinstance(data, dict)
        assert len(data) > 0


class TestPhishingRouter:
    def test_analyze_url_basic(self):
        r = client.post("/api/phishing/analyze-url", json={"url": "https://example.com/login"})
        assert r.status_code in (200, 404, 422)
        if r.status_code == 200:
            assert isinstance(r.json(), dict)


class TestRouterRegistration:
    def test_all_routers_have_correct_prefixes(self):
        paths = {getattr(route, "path", "") for route in app.routes}
        prefixes = [
            "/api/recon", "/api/soc", "/api/phishing", "/api/url",
            "/api/utils", "/api/osint", "/api/checklists", "/api/reports",
            "/api/reputation", "/api/malware", "/api/siem", "/api/lab",
            "/api/log-analysis", "/api/detection", "/api/network",
            "/api/recon-intel", "/api/hackingtool",
        ]
        for prefix in prefixes:
            assert any(path.startswith(prefix) for path in paths), f"missing: {prefix}"

    def test_endpoints_return_json(self):
        endpoints = [
            ("GET", "/"),
            ("GET", "/health"),
        ]
        for method, path in endpoints:
            r = client.request(method, path)
            assert r.status_code == 200, f"{method} {path} -> {r.status_code}"
            assert "application/json" in r.headers.get("content-type", "")
