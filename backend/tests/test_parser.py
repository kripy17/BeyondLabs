from app.services.parser import detect_target_type, normalize_target


def test_detect_target_type_ip():
    assert detect_target_type("192.168.1.1") == "ip"
    assert detect_target_type("10.0.0.1") == "ip"
    assert detect_target_type("8.8.8.8") == "ip"


def test_detect_target_type_domain():
    assert detect_target_type("example.com") == "domain"
    assert detect_target_type("sub.example.org") == "domain"


def test_detect_target_type_url():
    assert detect_target_type("https://example.com/path") == "domain"


def test_normalize_target_basic_domain():
    result = normalize_target("example.com")
    assert result["type"] == "domain"
    assert result["hostname"] == "example.com"
    assert "root_domain" in result


def test_normalize_target_ip():
    result = normalize_target("8.8.8.8")
    assert result["type"] == "ip"
    assert result["hostname"] == "8.8.8.8"


def test_normalize_target_url():
    result = normalize_target("https://www.example.com/path?q=1")
    assert result["type"] == "domain"
    assert result["hostname"] == "www.example.com"
