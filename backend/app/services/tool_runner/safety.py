import ipaddress
import re
import socket
from urllib.parse import urlparse


ACTIVE_GROUPS = {"Recon & Enumeration", "Web Testing", "Password & Credential Lab", "Network / Forensics", "Controlled Workflows"}
PRIVATE_HOSTS = {"localhost", "ip6-localhost"}
TARGET_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.:/?#&=%@+\-]{0,499}$")


def is_private_or_local_ip(value: str) -> bool:
    try:
        parsed = ipaddress.ip_address(value)
        return parsed.is_private or parsed.is_loopback or parsed.is_link_local or parsed.is_multicast
    except ValueError:
        return False


def hostname_from_target(target: str) -> str:
    value = target.strip()
    parsed = urlparse(value if "://" in value else f"//{value}", scheme="")
    host = parsed.hostname or value.split("/")[0]
    return host.strip("[]").lower()


def resolve_ips(hostname: str) -> list[str]:
    try:
        return sorted(set(socket.gethostbyname_ex(hostname)[2]))
    except Exception:
        return []


def target_is_private_or_local(target: str) -> bool:
    hostname = hostname_from_target(target)
    if hostname in PRIVATE_HOSTS or is_private_or_local_ip(hostname):
        return True
    return any(is_private_or_local_ip(ip) for ip in resolve_ips(hostname))


def validate_target_text(target: str) -> str | None:
    if not target:
        return "A target is required for this tool."
    if any(char in target for char in ["\n", "\r", "\x00"]):
        return "Targets must be a single line."
    if not TARGET_PATTERN.match(target):
        return "Target contains unsupported characters."
    return None


def authorization_error(group: str, target: str, confirm_authorization: bool, allow_private: bool) -> str | None:
    if group in ACTIVE_GROUPS and not confirm_authorization:
        return "You must confirm that this is an owned, authorized, or isolated lab target."
    if target and target_is_private_or_local(target) and not allow_private:
        return "Private/local targets are blocked unless local lab mode is enabled."
    return None
