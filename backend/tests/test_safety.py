from app.services.tool_runner.safety import (
    is_private_or_local_ip,
    hostname_from_target,
    target_is_private_or_local,
    validate_target_text,
    authorization_error,
)


def test_is_private_or_local_ip_detects_private():
    assert is_private_or_local_ip("10.0.0.1") is True
    assert is_private_or_local_ip("192.168.1.1") is True
    assert is_private_or_local_ip("172.16.0.1") is True


def test_is_private_or_local_ip_detects_loopback():
    assert is_private_or_local_ip("127.0.0.1") is True


def test_is_private_or_local_ip_rejects_public():
    assert is_private_or_local_ip("8.8.8.8") is False
    assert is_private_or_local_ip("1.1.1.1") is False


def test_is_private_or_local_ip_rejects_invalid():
    assert is_private_or_local_ip("not-an-ip") is False


def test_hostname_from_target_strips_protocol():
    assert hostname_from_target("https://example.com/path") == "example.com"


def test_hostname_from_target_returns_plain():
    assert hostname_from_target("192.168.1.1") == "192.168.1.1"


def test_hostname_from_target_strips_brackets():
    assert hostname_from_target("[::1]") == "::1"


def test_validate_target_text_rejects_empty():
    assert validate_target_text("") is not None


def test_validate_target_text_rejects_control_chars():
    assert validate_target_text("foo\nbar") is not None
    assert validate_target_text("foo\x00bar") is not None


def test_validate_target_text_accepts_valid():
    assert validate_target_text("example.com") is None
    assert validate_target_text("192.168.1.1") is None
    assert validate_target_text("https://example.com/path?q=1") is None


def test_authorization_error_needs_confirm():
    err = authorization_error("Recon & Enumeration", "example.com", False, False)
    assert err is not None
    assert "confirm" in err.lower()


def test_authorization_error_passes_with_confirm():
    err = authorization_error("Recon & Enumeration", "example.com", True, False)
    assert err is None
