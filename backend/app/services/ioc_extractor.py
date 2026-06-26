import math
import re
from urllib.parse import urlparse

URL_RE = re.compile(r'\bhttps?://[^\s<>"\']+', re.IGNORECASE)

SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "pw", "top", "xyz",
    "club", "work", "date", "men", "loan", "win", "bid",
    "trade", "webcam", "download", "review", "stream",
}

SUSPICIOUS_PATH_KEYWORDS = {
    "login", "verify", "reset", "secure", "account", "update",
    "confirm", "signin", "auth", "password", "credential",
    "banking", "payment", "invoice", "billing", "authenticate",
    "session", "recover", "unlock", "validate", "chase",
}

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "shorturl.at", "cli.gs", "pic.twitter.com",
    "tiny.cc", "tr.im", "v.gd", "snipr.com", "x.co",
    "cutt.ly", "rb.gy", "bl.ink", "short.link", "shrtco.de",
    "rebrand.ly",
}

EMAIL_RE = re.compile(
    r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'
)

IPV4_RE = re.compile(
    r'(?<![\w.])(?:25[0-5]|2[0-4]\d|1?\d?\d)'
    r'(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?![\w.])'
)

IPV6_RE = re.compile(
    r'\b(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}\b'
)

DOMAIN_RE = re.compile(
    r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b'
)

HASH_RE = re.compile(
    r'\b[A-Fa-f0-9]{32}\b|'
    r'\b[A-Fa-f0-9]{40}\b|'
    r'\b[A-Fa-f0-9]{64}\b|'
    r'\b[A-Fa-f0-9]{128}\b'
)

CVE_RE = re.compile(
    r'\bCVE-\d{4}-\d{4,7}\b',
    re.IGNORECASE
)


def unique_sorted(items):
    return sorted(set(item.strip() for item in items if item and item.strip()))


def refang_text(text: str) -> str:
    replacements = {
        "hxxps[:]//": "https://",
        "hxxp[:]//": "http://",
        "hxxps://": "https://",
        "hxxp://": "http://",
        "[.]": ".",
        "(.)": ".",
        "{.}": ".",
        "[@]": "@",
        "(at)": "@",
        "[at]": "@",
        "[:]": ":",
    }

    output = text

    for old, new in replacements.items():
        output = output.replace(old, new)

    return output


def defang_text(text: str) -> str:
    output = text

    output = output.replace("https://", "hxxps[:]//")
    output = output.replace("http://", "hxxp[:]//")
    output = output.replace("@", "[@]")
    output = output.replace(".", "[.]")

    return output


def classify_hashes(hashes):
    result = {
        "md5": [],
        "sha1": [],
        "sha256": [],
        "sha512": [],
        "unknown": [],
    }

    for value in hashes:
        length = len(value)

        if length == 32:
            result["md5"].append(value)
        elif length == 40:
            result["sha1"].append(value)
        elif length == 64:
            result["sha256"].append(value)
        elif length == 128:
            result["sha512"].append(value)
        else:
            result["unknown"].append(value)

    return {
        key: unique_sorted(values)
        for key, values in result.items()
    }


def get_domain_from_url(url: str):
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname

        if hostname:
            return hostname.lower()

    except Exception:
        return None

    return None


def url_path_depth(url: str) -> int:
    try:
        parsed = urlparse(url)
        path = parsed.path.strip("/")
        if not path:
            return 0
        return len(path.split("/"))
    except Exception:
        return 0


def get_url_path(url: str) -> str:
    try:
        return urlparse(url).path
    except Exception:
        return ""


def has_suspicious_tld(domain: str) -> bool:
    try:
        tld = domain.rsplit(".", 1)[-1].lower()
        return tld in SUSPICIOUS_TLDS
    except Exception:
        return False


def is_ip_url(url: str) -> bool:
    try:
        hostname = urlparse(url).hostname
        if not hostname:
            return False
        return bool(re.match(
            r'^(?:25[0-5]|2[0-4]\d|1?\d?\d)'
            r'(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}$',
            hostname
        ))
    except Exception:
        return False


def is_shortener_domain(domain: str) -> bool:
    return domain.lower() in SHORTENER_DOMAINS


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    text = text.lower()
    length = len(text)
    freq = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    entropy = -sum(
        (count / length) * math.log2(count / length)
        for count in freq.values()
    )
    return round(entropy, 2)


def find_suspicious_path_keywords(url: str) -> list[str]:
    path = get_url_path(url).lower()
    found = []
    for kw in SUSPICIOUS_PATH_KEYWORDS:
        if kw in path:
            found.append(kw)
    return found


def analyze_url(url: str) -> dict:
    domain = get_domain_from_url(url) or ""
    path = get_url_path(url)
    return {
        "url": url,
        "domain": domain,
        "path": path,
        "depth": url_path_depth(url),
        "suspicious_tld": has_suspicious_tld(domain),
        "ip_based": is_ip_url(url),
        "shortener": is_shortener_domain(domain),
        "entropy": shannon_entropy(url),
        "suspicious_path_keywords": find_suspicious_path_keywords(url),
        "has_port": urlparse(url).port is not None,
        "scheme": urlparse(url).scheme,
    }


def analyze_urls(urls: list[str]) -> dict:
    analyzed = [analyze_url(url) for url in urls]
    return {
        "total_urls": len(analyzed),
        "shorteners_detected": sorted(set(
            a["domain"] for a in analyzed if a["shortener"]
        )),
        "suspicious_tld_detected": sorted(set(
            a["domain"] for a in analyzed if a["suspicious_tld"]
        )),
        "ip_based_count": sum(1 for a in analyzed if a["ip_based"]),
        "ip_based_urls": [a["url"] for a in analyzed if a["ip_based"]],
        "high_entropy_urls": [a["url"] for a in analyzed if a["entropy"] > 4.5],
        "deep_path_urls": [a["url"] for a in analyzed if a["depth"] >= 4],
        "suspicious_path_urls": [
            {
                "url": a["url"],
                "keywords": a["suspicious_path_keywords"],
            }
            for a in analyzed if a["suspicious_path_keywords"]
        ],
        "urls": analyzed,
    }


def extract_iocs(text: str, refang_first: bool = True) -> dict:
    working_text = refang_text(text) if refang_first else text

    urls = unique_sorted(URL_RE.findall(working_text))
    emails = unique_sorted(EMAIL_RE.findall(working_text))
    ipv4s = unique_sorted(IPV4_RE.findall(working_text))
    ipv6s = unique_sorted(IPV6_RE.findall(working_text))
    cves = unique_sorted([cve.upper() for cve in CVE_RE.findall(working_text)])

    raw_hashes = unique_sorted(HASH_RE.findall(working_text))
    hashes = classify_hashes(raw_hashes)

    domains = set(DOMAIN_RE.findall(working_text))

    for url in urls:
        host = get_domain_from_url(url)
        if host:
            domains.add(host)

    for email in emails:
        try:
            domains.add(email.split("@", 1)[1].lower())
        except Exception:
            pass

    # Remove IPs accidentally matched as domains.
    domains = {
        domain.lower()
        for domain in domains
        if domain not in ipv4s
    }

    iocs = {
        "urls": urls,
        "domains": unique_sorted(domains),
        "ipv4": ipv4s,
        "ipv6": ipv6s,
        "emails": emails,
        "hashes": hashes,
        "cves": cves,
    }

    counts = {
        "urls": len(iocs["urls"]),
        "domains": len(iocs["domains"]),
        "ipv4": len(iocs["ipv4"]),
        "ipv6": len(iocs["ipv6"]),
        "emails": len(iocs["emails"]),
        "md5": len(iocs["hashes"]["md5"]),
        "sha1": len(iocs["hashes"]["sha1"]),
        "sha256": len(iocs["hashes"]["sha256"]),
        "sha512": len(iocs["hashes"]["sha512"]),
        "cves": len(iocs["cves"]),
    }

    return {
        "counts": counts,
        "iocs": iocs,
        "defanged_text": defang_text(working_text),
    }
