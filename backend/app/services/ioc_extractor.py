import re
from urllib.parse import urlparse


URL_RE = re.compile(r'\bhttps?://[^\s<>"\']+', re.IGNORECASE)

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
