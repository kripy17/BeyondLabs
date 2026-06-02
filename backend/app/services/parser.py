from urllib.parse import urlparse
import ipaddress
import socket
import tldextract

TLD_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=False)


def detect_target_type(target: str) -> str:
    target = target.strip()

    try:
        ipaddress.ip_address(target)
        return "ip"
    except ValueError:
        pass

    parsed = urlparse(target if "://" in target else f"http://{target}")
    hostname = parsed.hostname or target

    try:
        ipaddress.ip_address(hostname)
        return "ip"
    except ValueError:
        return "domain"


def normalize_target(target: str) -> dict:
    target = target.strip()

    parsed = urlparse(target if "://" in target else f"http://{target}")
    hostname = parsed.hostname or target

    extracted = TLD_EXTRACTOR(hostname)

    if extracted.domain and extracted.suffix:
        root_domain = f"{extracted.domain}.{extracted.suffix}"
    else:
        root_domain = hostname

    target_type = detect_target_type(hostname)

    resolved_ips = []

    if target_type == "domain":
        try:
            resolved_ips = list(set(socket.gethostbyname_ex(hostname)[2]))
        except Exception:
            resolved_ips = []

    return {
        "original": target,
        "hostname": hostname,
        "root_domain": root_domain,
        "type": target_type,
        "resolved_ips": resolved_ips,
    }
