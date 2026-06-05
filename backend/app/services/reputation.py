import ipaddress
from datetime import datetime, timezone
from urllib.parse import urlparse

from app.services.ioc_extractor import defang_text, refang_text

SUSPICIOUS_TLDS = {
    "zip", "mov", "top", "xyz", "click", "work", "support", "country",
    "gq", "tk", "ml", "cf"
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "cutt.ly", "rebrand.ly", "shorturl.at", "s.id"
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def add_finding(findings, severity, title, detail, recommendation):
    findings.append({
        "severity": severity,
        "title": title,
        "detail": detail,
        "recommendation": recommendation,
    })


def score_findings(findings):
    score = 100
    penalties = {"high": 30, "medium": 15, "low": 7, "info": 0}

    for finding in findings:
        score -= penalties.get(finding["severity"], 0)

    return max(score, 0)


def rating_from_score(score):
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


def finding(
    *,
    indicator: str,
    indicator_type: str,
    verdict: str = "unknown",
    confidence: str = "unknown",
    trust_type: str = "heuristic_inferred",
    source: str = "BeyondArch",
    method: str = "local analysis",
    freshness: str = "point_in_time",
    checked_at: str | None = None,
    summary: str = "Analysis completed.",
    evidence: list[str] | None = None,
    limitations: str = "Review with analyst context before drawing conclusions.",
    recommended_next_step: str = "Correlate with case evidence and logs.",
    raw_details: dict | None = None,
) -> dict:
    return {
        "id": f"{indicator_type}:{indicator}:{source}:{method}:{checked_at or utc_now()}",
        "indicator": indicator,
        "type": indicator_type,
        "verdict": verdict,
        "confidence": confidence,
        "trust_type": trust_type,
        "source": source,
        "method": method,
        "freshness": freshness,
        "checked_at": checked_at or utc_now(),
        "summary": summary,
        "evidence": evidence or [],
        "limitations": limitations,
        "recommended_next_step": recommended_next_step,
        "raw_details": raw_details,
    }


def local_reputation_finding(indicator: str, indicator_type: str, raw: dict) -> dict:
    summary = raw.get("summary", {})
    findings = raw.get("findings", []) if isinstance(raw.get("findings"), list) else []

    return finding(
        indicator=raw.get("normalized") or raw.get("indicator") or indicator,
        indicator_type=indicator_type,
        verdict=verdict_from_rating(summary.get("rating")),
        confidence="medium" if findings else "low",
        trust_type="heuristic_inferred",
        source="BeyondArch local heuristic",
        method="local deterministic scoring",
        freshness="point_in_time",
        summary=(
            f"{summary.get('rating')} based on {summary.get('total_findings', 0)} local finding(s)."
            if summary.get("rating")
            else "Local heuristic completed."
        ),
        evidence=[f"{item.get('severity', 'info')}: {item.get('title', 'Finding')}" for item in findings],
        limitations=raw.get("note") or "Local heuristic checks do not confirm maliciousness.",
        recommended_next_step="Correlate with case evidence, logs, and analyst context.",
        raw_details=raw,
    )


def local_hash_finding(indicator: str, indicator_type: str) -> dict:
    hash_type = {
        32: "MD5",
        40: "SHA1",
        64: "SHA256",
        128: "SHA512",
    }.get(len(indicator.strip()), "unknown")

    return finding(
        indicator=indicator,
        indicator_type=indicator_type,
        verdict="unknown",
        confidence="low",
        trust_type="local_deterministic",
        source="BeyondArch hash classifier",
        method="hash length and hex format identification",
        summary=f"Indicator matches {hash_type} format." if hash_type != "unknown" else "Hash format could not be identified.",
        limitations="Hash format identification is not reputation and does not indicate whether the file is malicious.",
        recommended_next_step="Use static file triage and correlate with file origin, host activity, and case evidence.",
        raw_details={"hash_type": hash_type},
    )


def normalize_indicator_for_type(indicator: str, indicator_type: str) -> str:
    clean = refang_text(indicator.strip())

    if indicator_type in {"domain", "email"}:
        return clean.lower().strip(".")

    if indicator_type == "url":
        return clean

    if indicator_type.startswith("hash") or indicator_type == "hash":
        return clean.lower()

    return clean


async def run_local_reputation(indicator: str, indicator_type: str) -> list[dict]:
    if indicator_type in {"hash", "hash_md5", "hash_sha1", "hash_sha256"}:
        return [local_hash_finding(indicator, indicator_type)]

    if indicator_type == "ip":
        return [local_reputation_finding(indicator, indicator_type, analyze_ip_reputation(indicator))]

    if indicator_type == "domain":
        return [local_reputation_finding(indicator, indicator_type, analyze_domain_reputation(indicator))]

    if indicator_type == "url":
        return [local_reputation_finding(indicator, indicator_type, analyze_url_reputation(indicator))]

    if indicator_type == "email":
        domain = indicator.split("@")[-1].lower()
        raw = analyze_domain_reputation(domain)
        item = local_reputation_finding(domain, "domain", raw)
        item["summary"] = f"Checked sender domain from email indicator. {item['summary']}"
        return [item]

    return [
        finding(
            indicator=indicator,
            indicator_type=indicator_type,
            verdict="unknown",
            confidence="unknown",
            trust_type="local_deterministic",
            source="BeyondArch IOC classifier",
            method="indicator type classification",
            summary="No local reputation workflow is available for this indicator type.",
            limitations="Unsupported indicator types require manual review.",
            recommended_next_step="Extract a URL, domain, IP, hash, or email and retry.",
        )
    ]


async def enrich_indicator_reputation(indicator: str, indicator_type: str) -> dict:
    normalized = normalize_indicator_for_type(indicator, indicator_type)
    findings = await run_local_reputation(normalized, indicator_type)

    return {
        "indicator": indicator,
        "normalized": normalized,
        "type": indicator_type,
        "checked_at": utc_now(),
        "summary": {
            "backend_findings": len(findings),
            "total_findings": len(findings),
            "note": "BeyondArch reputation enrichment runs deterministic backend/local checks only. It does not query external reputation providers.",
        },
        "findings": findings,
    }


def analyze_ip_reputation(ip: str) -> dict:
    findings = []
    clean = ip.strip()

    try:
        parsed = ipaddress.ip_address(clean)
    except Exception:
        return {"valid": False, "error": "Invalid IP address."}

    if parsed.is_private:
        add_finding(findings, "info", "Private IP address", "This IP belongs to a private/internal range.", "Use local context and internal logs for investigation.")

    if parsed.is_loopback:
        add_finding(findings, "info", "Loopback IP address", "This IP points to localhost.", "Verify whether this is expected in the log/source.")

    if parsed.is_multicast:
        add_finding(findings, "low", "Multicast IP address", "This IP is in multicast space.", "Review whether multicast traffic is expected.")

    if parsed.is_reserved:
        add_finding(findings, "low", "Reserved IP address", "This IP is in reserved address space.", "Verify the source of this indicator.")

    score = score_findings(findings)

    return {
        "indicator": clean,
        "type": "ip",
        "version": parsed.version,
        "is_private": parsed.is_private,
        "is_global": parsed.is_global,
        "is_loopback": parsed.is_loopback,
        "is_multicast": parsed.is_multicast,
        "is_reserved": parsed.is_reserved,
        "summary": {
            "score": score,
            "rating": rating_from_score(score),
            "total_findings": len(findings),
        },
        "findings": findings,
        "note": "Backend/local heuristic only. No external IP reputation lookup was performed.",
    }


def analyze_domain_reputation(domain: str) -> dict:
    findings = []
    clean = domain.strip().lower()

    if "://" in clean:
        parsed = urlparse(clean)
        clean = parsed.hostname or clean

    clean = clean.strip(".")
    parts = clean.split(".")
    tld = parts[-1] if len(parts) > 1 else ""

    if len(parts) < 2:
        add_finding(findings, "medium", "Invalid or incomplete domain", "The value does not look like a full domain.", "Provide a full domain such as example.com.")

    if tld in SUSPICIOUS_TLDS:
        add_finding(findings, "low", "Suspicious or commonly abused TLD", f"The domain uses .{tld}.", "Do not treat TLD alone as malicious, but review with extra context.")

    if clean in URL_SHORTENERS:
        add_finding(findings, "medium", "URL shortener domain", f"{clean} is a known URL shortener.", "Expand shortened URLs safely before visiting.")

    if clean.count("-") >= 2:
        add_finding(findings, "low", "Multiple hyphens in domain", "The domain contains multiple hyphens.", "Review for typosquatting or impersonation.")

    if any(char.isdigit() for char in clean):
        add_finding(findings, "info", "Digits in domain", "The domain contains numbers.", "Review for brand impersonation or lookalike naming.")

    score = score_findings(findings)

    return {
        "indicator": clean,
        "type": "domain",
        "tld": tld,
        "summary": {
            "score": score,
            "rating": rating_from_score(score),
            "total_findings": len(findings),
        },
        "findings": findings,
        "note": "Backend/local heuristic only. No WHOIS/RDAP or reputation lookup was performed.",
    }


def analyze_url_reputation(url: str) -> dict:
    refanged = refang_text(url.strip())

    if not refanged.startswith(("http://", "https://")):
        refanged = "http://" + refanged

    parsed = urlparse(refanged)
    hostname = parsed.hostname or ""
    findings = []

    if parsed.scheme != "https":
        add_finding(findings, "medium", "Non-HTTPS URL", f"Detected scheme: {parsed.scheme}", "Be careful with links that do not use HTTPS.")

    if hostname in URL_SHORTENERS:
        add_finding(findings, "medium", "URL shortener detected", f"{hostname} is a known URL shortener.", "Expand safely before visiting.")

    if "@" in parsed.netloc:
        add_finding(findings, "high", "Userinfo symbol in URL", "The URL contains @, which can hide the true destination.", "Inspect the real hostname carefully.")

    domain_result = analyze_domain_reputation(hostname) if hostname else None

    if domain_result:
        findings.extend(domain_result.get("findings", []))

    score = score_findings(findings)

    return {
        "indicator": url,
        "type": "url",
        "normalized": refanged,
        "defanged": defang_text(refanged),
        "hostname": hostname,
        "path": parsed.path,
        "query": parsed.query,
        "summary": {
            "score": score,
            "rating": rating_from_score(score),
            "total_findings": len(findings),
        },
        "findings": findings,
        "note": "Backend/local URL structure analysis only. The URL was not fetched, opened, rendered, or checked against reputation providers.",
    }
