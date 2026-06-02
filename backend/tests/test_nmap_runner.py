import pytest
from app.services.nmap_runner import (
    is_private_or_local_ip,
    target_is_private_or_local,
    validate_custom_nmap_command,
    run_nmap_scan,
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


def test_validate_custom_nmap_command_rejects_shell_chaining():
    cmd, err, _ = validate_custom_nmap_command("nmap target; rm -rf /")
    assert err is not None


def test_validate_custom_nmap_command_rejects_unsafe_flags():
    cmd, err, _ = validate_custom_nmap_command("nmap --script-args foo=bar target")
    assert err is not None
    assert "blocked" in err.lower()


def test_validate_custom_nmap_command_accepts_safe():
    cmd, err, _ = validate_custom_nmap_command("nmap -sV -T3 scanme.nmap.org")
    assert err is None
    assert cmd is not None


def test_run_nmap_scan_rejects_bad_mode():
    result = run_nmap_scan("target", "nonexistent_mode")
    assert "error" in result


def test_run_nmap_scan_rejects_private_default():
    result = run_nmap_scan("10.0.0.1", "quick_tcp")
    assert "error" in result
    assert "private" in str(result.get("error", "")).lower() or "local" in str(result.get("error", "")).lower()
