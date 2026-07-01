import math
import re
from datetime import datetime, timezone


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def unique_sorted(items: list) -> list:
    return sorted(set(item for item in items if item))


def score_findings(findings: list[dict]) -> int:
    score = 100
    penalties = {"high": 30, "medium": 15, "low": 7, "info": 0}
    for finding in findings:
        score -= penalties.get(finding.get("severity", ""), 0)
    return max(score, 0)


def rating_from_score(score: int) -> str:
    if score >= 80:
        return "Low Risk"
    if score >= 55:
        return "Suspicious"
    return "High Risk"


def verdict_from_rating(rating: str | None) -> str:
    normalized = str(rating or "").lower()
    if "high" in normalized or "suspicious" in normalized:
        return "suspicious"
    return "unknown"


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    lowered = value.lower()
    length = len(lowered)
    freq: dict[str, int] = {}
    for ch in lowered:
        freq[ch] = freq.get(ch, 0) + 1
    entropy = -sum((count / length) * math.log2(count / length) for count in freq.values())
    return max(0, entropy)


SUSPICIOUS_TLDS: set[str] = {
    "tk", "ml", "ga", "cf", "gq", "pw", "top", "xyz",
    "club", "work", "date", "men", "loan", "win", "bid",
    "trade", "webcam", "download", "review", "stream",
    "zip", "mov", "click", "support", "country",
    "site", "racing", "science", "party", "faith", "mom",
    "mobi", "cc", "info", "buzz", "online", "live", "sbs",
    "bar", "rest", "cam", "pro", "icu", "cyou", "lol",
    "gdn", "wang", "help", "city", "today", "news",
}

URL_SHORTENERS: set[str] = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "shorturl.at", "cli.gs", "pic.twitter.com",
    "tiny.cc", "tr.im", "v.gd", "snipr.com", "x.co",
    "cutt.ly", "rb.gy", "bl.ink", "short.link", "shrtco.de",
    "rebrand.ly", "s.id", "lnkd.in", "trib.al", "bitly.com",
    "clck.ru", "shorte.st", "bc.vc", "yourls.org",
    "adf.ly", "shrinke.me", "kutt.it", "polr.me", "zws.im",
    "1url.com", "tiny.ie", "xy2.eu", "zip.net", "soo.gd",
    "gg.gg", "scrnch.me", "urlz.fr",
}

IPV4_RE = re.compile(
    r'(?<![\w.])(?:25[0-5]|2[0-4]\d|1?\d?\d)'
    r'(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?![\w.])'
)

IPV6_RE = re.compile(
    r'\b(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}\b'
)

EMAIL_RE = re.compile(
    r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'
)

URL_RE = re.compile(r'\bhttps?://[^\s<>"\']+', re.IGNORECASE)

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
