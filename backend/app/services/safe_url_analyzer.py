import base64
import ipaddress
import re
import socket
import ssl
from datetime import datetime, timezone
from html import unescape
from typing import Any
from urllib.parse import parse_qs, unquote, urljoin, urlparse, urlunparse

import httpx

try:
    import tldextract
    _TLD_EXTRACT = tldextract.TLDExtract(suffix_list_urls=())
except Exception:  # pragma: no cover - dependency may be unavailable in minimal local checks
    tldextract = None
    _TLD_EXTRACT = None

from app.services.ioc_extractor import refang_text

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly",
    "rebrand.ly", "shorturl.at", "s.id", "lnkd.in", "trib.al", "rb.gy", "bitly.com",
}

BRAND_TERMS = {
    "microsoft", "office365", "office", "outlook", "onedrive", "sharepoint", "google", "gmail",
    "paypal", "apple", "icloud", "amazon", "bank", "sbi", "hdfc", "icici", "axis",
    "netflix", "instagram", "facebook", "whatsapp", "linkedin", "github", "dropbox", "docusign",
}

CREDENTIAL_TERMS = {
    "login", "signin", "sign-in", "verify", "verification", "account", "security", "secure",
    "reset", "password", "passwd", "credential", "mfa", "2fa", "auth", "authenticate", "confirm",
    "update", "unlock", "invoice", "payment", "wallet", "billing", "recover",
}

SUSPICIOUS_EXTENSIONS = {
    ".exe", ".scr", ".js", ".jse", ".vbs", ".vbe", ".hta", ".bat", ".cmd", ".ps1",
    ".jar", ".msi", ".lnk", ".iso", ".img", ".zip", ".rar", ".7z", ".html", ".htm",
    ".docm", ".xlsm", ".pptm",
}

EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
IPV4_RE = re.compile(r"(?<![\w.])(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?![\w.])")
DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")
URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
NON_DOMAIN_SUFFIXES = {"php", "html", "htm", "asp", "aspx", "jsp", "js", "css", "png", "jpg", "jpeg", "gif", "svg", "ico", "txt", "json", "xml", "pdf"}
TITLE_RE = re.compile(rb"<\s*title[^>]*>(.*?)<\s*/\s*title\s*>", re.IGNORECASE | re.DOTALL)
DEFANG_MARKERS = ("hxxp", "[.]", "(.)", "{.}", "[:]", "[@]", "[at]", "(at)")
MAX_TITLE_BYTES = 131_072


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _unique(items: list[str]) -> list[str]:
    seen: set[str] = set()
    output: list[str] = []
    for item in items:
        value = str(item).strip()
        if value and value not in seen:
            seen.add(value)
            output.append(value)
    return output


def _detect_defanged(value: str) -> bool:
    lowered = value.lower()
    return any(marker in lowered for marker in DEFANG_MARKERS)


def _ensure_url(value: str) -> tuple[str, bool]:
    trimmed = value.strip().strip("<>'\"` ")
    inferred_scheme = False
    if not re.match(r"^[a-z][a-z0-9+.-]*://", trimmed, flags=re.IGNORECASE):
        trimmed = f"https://{trimmed}"
        inferred_scheme = True
    return trimmed, inferred_scheme


def _normalize_url(value: str) -> tuple[str, dict[str, Any]]:
    refanged = refang_text(value.strip())
    with_scheme, inferred_scheme = _ensure_url(refanged)
    parsed = urlparse(with_scheme)
    scheme = (parsed.scheme or "").lower()
    hostname = (parsed.hostname or "").strip(".").lower()

    # Keep URL path/query intact but normalize scheme and host casing for stable analysis.
    netloc = hostname
    if parsed.port:
        netloc = f"{netloc}:{parsed.port}"
    if parsed.username:
        userinfo = parsed.username
        if parsed.password:
            userinfo = f"{userinfo}:***"
        netloc = f"{userinfo}@{netloc}"

    normalized = urlunparse((scheme, netloc, parsed.path or "/", "", parsed.query, parsed.fragment))
    return normalized, {
        "original": value,
        "refanged": refanged,
        "normalized": normalized,
        "inferred_scheme": inferred_scheme,
    }


def _root_domain(hostname: str) -> str:
    if not hostname or _is_ip_literal(hostname):
        return ""
    if _TLD_EXTRACT is not None:
        extracted = _TLD_EXTRACT(hostname)
        if not extracted.suffix:
            return hostname.lower()
        return f"{extracted.domain}.{extracted.suffix}".lower()
    parts = hostname.lower().split(".")
    if len(parts) <= 2:
        return hostname.lower()
    # Fallback keeps common second-level public suffixes together without network/cache dependency.
    if parts[-2] in {"co", "com", "net", "org", "gov", "ac", "edu"} and len(parts[-1]) == 2 and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _is_ip_literal(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname.strip("[]"))
        return True
    except ValueError:
        return False


def _ip_is_blocked(ip_value: str) -> bool:
    try:
        address = ipaddress.ip_address(ip_value)
    except ValueError:
        return True
    return bool(
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    )


def _hostname_is_internal(hostname: str) -> bool:
    host = (hostname or "").strip(".").lower()
    if not host:
        return True
    if host in {"localhost", "metadata.google.internal"}:
        return True
    if host.endswith((".localhost", ".local", ".internal", ".lan", ".home", ".corp")):
        return True
    if host == "169.254.169.254":
        return True
    if _is_ip_literal(host):
        return _ip_is_blocked(host)
    # Single-label hostnames are internal by default for safety.
    return "." not in host


def _resolve_public_addresses(hostname: str, allow_private_targets: bool = False) -> tuple[bool, list[str], str | None]:
    host = (hostname or "").strip("[]")
    if _hostname_is_internal(host) and not allow_private_targets:
        return False, [], "Target is localhost, private, link-local, metadata, or an internal hostname."

    if _is_ip_literal(host):
        if _ip_is_blocked(host) and not allow_private_targets:
            return False, [host], "Target resolved to a private, internal, reserved, or link-local IP address."
        return True, [host], None

    try:
        results = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror as error:
        return False, [], f"DNS resolution failed: {error}"

    addresses = _unique([result[4][0] for result in results])
    if not addresses:
        return False, [], "DNS resolution returned no addresses."

    blocked = [address for address in addresses if _ip_is_blocked(address)]
    if blocked and not allow_private_targets:
        return False, addresses, f"Target resolved to blocked private/internal address(es): {', '.join(blocked)}"

    return True, addresses, None


def _signal(signal_id: str, label: str, severity: str, evidence: str, explanation: str, source: str = "static") -> dict[str, str]:
    return {
        "id": signal_id,
        "label": label,
        "severity": severity,
        "evidence": evidence,
        "explanation": explanation,
        "source": source,
    }


def _clean_base64_candidate(value: str) -> str:
    clean = unquote(str(value or "")).strip().strip("'\"")
    lowered = clean.lower()
    if lowered.startswith("base64:") or lowered.startswith("b64:"):
        clean = clean.split(":", 1)[1].strip()
    if lowered.startswith("data:") and "," in clean:
        clean = clean.rsplit(",", 1)[1].strip()
    clean = re.sub(r"\s+", "", clean)
    return clean.replace("-", "+").replace("_", "/")


def _risk_score(signals: list[dict[str, str]]) -> int:
    weights = {"high": 38, "medium": 18, "low": 7, "info": 0}
    score = sum(weights.get(item.get("severity", "info"), 0) for item in signals)
    # Multiple weak indicators are useful, but avoid pretending local heuristics are reputation.
    if len([item for item in signals if item.get("severity") in {"medium", "high"}]) >= 3:
        score += 8
    return max(0, min(100, score))


def _score_signals(signals: list[dict[str, str]], live_enabled: bool = False) -> tuple[str, str]:
    high = sum(1 for item in signals if item.get("severity") == "high")
    medium = sum(1 for item in signals if item.get("severity") == "medium")
    score = _risk_score(signals)
    if high or score >= 60 or medium >= 3:
        confidence = "high" if live_enabled and (high or score >= 75) else "medium"
        return "suspicious", confidence
    if medium or score >= 12:
        return "needs_review", "medium" if live_enabled or medium >= 2 else "low"
    return "low_risk", "medium"


def _evidence_level(live_enabled: bool, signals: list[dict[str, str]]) -> str:
    source_bits = {item.get("source", "static") for item in signals}
    if live_enabled:
        if "safe_fetch" in source_bits:
            return "Local heuristic + Safe Fetch metadata. External reputation/blocklists were not checked."
        return "Safe Fetch ran, but no extra network risk signals were observed. External reputation was not checked."
    return "Static local heuristic only. No network request or external reputation check was performed."


def _query_params(parsed) -> list[dict[str, Any]]:
    params = parse_qs(parsed.query, keep_blank_values=True)
    return [{"name": key, "values": values} for key, values in params.items()]


def _looks_base64(value: str) -> bool:
    raw = unquote(str(value or "")).strip()
    lowered = raw.lower()
    has_explicit_prefix = lowered.startswith(("b64:", "base64:", "data:"))
    if re.search(r"\s", raw) and not has_explicit_prefix:
        return False
    clean = _clean_base64_candidate(value)
    if len(clean) < 12 or len(clean) % 4 == 1:
        return False
    if not re.fullmatch(r"[A-Za-z0-9+/=]{12,}", clean):
        return False
    try:
        padded = clean + "=" * (-len(clean) % 4)
        decoded = base64.b64decode(padded, validate=False)
        if len(decoded) < 6:
            return False
        printable = sum(1 for byte in decoded if byte in {9, 10, 13} or 32 <= byte <= 126) / len(decoded)
        return printable >= 0.75 or has_explicit_prefix
    except Exception:
        return False


def _decode_base64_preview(value: str) -> str:
    clean = _clean_base64_candidate(value)
    if not _looks_base64(clean):
        return ""
    try:
        padded = clean + "=" * (-len(clean) % 4)
        decoded = base64.b64decode(padded, validate=False)
        preview = decoded.decode("utf-8", errors="replace")
        preview = re.sub(r"\s+", " ", preview).strip()
        return preview[:160]
    except Exception:
        return ""


def _is_domain_candidate(value: str) -> bool:
    candidate = value.strip().strip(".,;:()[]{}<>\"'").lower()
    if not candidate or _is_ip_literal(candidate):
        return False
    parts = candidate.split(".")
    if len(parts) < 2:
        return False
    suffix = parts[-1]
    if suffix in NON_DOMAIN_SUFFIXES:
        return False
    if not re.fullmatch(r"[a-z]{2,24}", suffix):
        return False
    return True


def _detect_extensions(parsed) -> list[str]:
    lowered = unquote(f"{parsed.path}?{parsed.query}".lower())
    hits = [ext for ext in SUSPICIOUS_EXTENSIONS if lowered.endswith(ext) or f"{ext}?" in lowered or f"{ext}&" in lowered]
    return sorted(set(hits))


def _extract_iocs(normalized: str, hostname: str, query_values: list[str]) -> dict[str, list[str]]:
    # Keep the normalized URL as the primary URL IOC, but avoid scanning the path as a
    # generic domain source. Otherwise file names such as index.php become false domains.
    query_text = "\n".join([unquote(value) for value in query_values])
    embedded_urls = URL_RE.findall(query_text)
    domains = []
    for value in DOMAIN_RE.findall(query_text):
        if _is_domain_candidate(value):
            domains.append(value.lower())
    if hostname and not _is_ip_literal(hostname):
        domains.append(hostname)
        root = _root_domain(hostname)
        if root:
            domains.append(root)
    ips = IPV4_RE.findall(query_text)
    if hostname and _is_ip_literal(hostname):
        ips.append(hostname.strip("[]"))
    emails = EMAIL_RE.findall(query_text)
    return {
        "urls": _unique([normalized, *embedded_urls]),
        "domains": _unique([item.lower() for item in domains if not _is_ip_literal(item)]),
        "ips": _unique(ips),
        "emails": _unique([item.lower() for item in emails]),
    }


def analyze_static_url(url: str) -> dict[str, Any]:
    normalized, input_info = _normalize_url(url)
    parsed = urlparse(normalized)
    hostname = (parsed.hostname or "").lower()
    root = _root_domain(hostname)
    params = _query_params(parsed)
    query_values = [value for item in params for value in item["values"]]
    decoded_query_hints = []
    for item in params:
        for value in item["values"]:
            preview = _decode_base64_preview(value)
            if preview:
                decoded_query_hints.append({"parameter": item["name"], "preview": preview})
                break
    decoded_url = unquote(normalized)
    lowered = decoded_url.lower()
    risk_signals: list[dict[str, str]] = []

    if _detect_defanged(input_info["original"]):
        risk_signals.append(_signal("defanged_url", "Defanged URL detected", "info", input_info["original"], "Defanged links are common in analyst handoffs and should be refanged only inside tools."))
    if input_info["inferred_scheme"]:
        risk_signals.append(_signal("scheme_inferred", "URL scheme was inferred", "info", "https:// was added for parsing", "The original input did not include an explicit scheme."))
    if parsed.scheme == "http":
        risk_signals.append(_signal("http_scheme", "HTTP instead of HTTPS", "medium", parsed.scheme, "Plain HTTP links are easier to tamper with and are common in low-quality phishing infrastructure."))
    if _is_ip_literal(hostname):
        risk_signals.append(_signal("ip_hostname", "IP address used as hostname", "medium", hostname, "IP-hosted URLs bypass normal domain trust cues and should be reviewed carefully."))
        if _ip_is_blocked(hostname):
            risk_signals.append(_signal("private_ip_hostname", "Private/internal IP hostname", "high", hostname, "Private, loopback, reserved, or metadata ranges are blocked from Safe Fetch by default."))
    elif _hostname_is_internal(hostname):
        risk_signals.append(_signal("internal_hostname", "Internal-style hostname", "high", hostname, "Localhost, single-label, .local, .internal, .lan, .home, and .corp destinations are blocked from Safe Fetch by default."))
    if hostname.startswith("xn--") or ".xn--" in hostname:
        risk_signals.append(_signal("punycode_host", "Punycode / IDN hostname", "medium", hostname, "Internationalized domains can be used for lookalike or homograph attacks."))
    try:
        idna = hostname.encode("idna").decode("ascii") if hostname else ""
        if idna and idna != hostname and (idna.startswith("xn--") or ".xn--" in idna):
            risk_signals.append(_signal("unicode_idn_host", "Unicode IDN hostname", "medium", hostname, "The hostname converts to a punycode representation and may need visual inspection."))
    except Exception:
        pass
    if hostname in URL_SHORTENERS:
        risk_signals.append(_signal("url_shortener", "URL shortener domain", "medium", hostname, "Shorteners hide the final destination until redirects are inspected safely."))
    subdomain_count = max(0, len(hostname.split(".")) - len(root.split("."))) if root and hostname.endswith(root) else 0
    if subdomain_count >= 4:
        risk_signals.append(_signal("excessive_subdomains", "Excessive subdomains", "low", hostname, "Long subdomain chains can be used to bury the registrable domain."))
    if len(normalized) > 180:
        risk_signals.append(_signal("very_long_url", "Very long URL", "low", f"{len(normalized)} characters", "Long URLs may hide tracking, redirect, or token data."))
    if re.search(r"%[0-9a-f]{2}", input_info["refanged"], flags=re.IGNORECASE):
        risk_signals.append(_signal("encoded_characters", "Encoded characters present", "low", "percent-encoded bytes", "Encoding can obscure URL structure or embedded values."))
    base64_values = [value for value in query_values if _looks_base64(unquote(value))]
    if base64_values:
        risk_signals.append(_signal("base64_query", "Base64-like query value", "medium", base64_values[0][:80], "Encoded query values can hide redirect targets, victim identifiers, or payload markers."))
    emails_in_query = _unique([match.lower() for value in query_values for match in EMAIL_RE.findall(unquote(value))])
    if emails_in_query:
        risk_signals.append(_signal("email_in_query", "Email address in query string", "medium", ", ".join(emails_in_query), "Phishing kits often track or prefill victim identity through query parameters."))
    matched_terms = sorted({term for term in CREDENTIAL_TERMS if term in lowered})
    if matched_terms:
        risk_signals.append(_signal("credential_wording", "Credential/account wording", "medium", ", ".join(matched_terms), "Login, verification, reset, and account wording is common in credential-harvest lures."))
    matched_brands = sorted({term for term in BRAND_TERMS if term in lowered})
    if matched_brands:
        risk_signals.append(_signal("brand_terms", "Brand or service terms", "low", ", ".join(matched_brands), "Brand-like wording can indicate impersonation when the root domain is unrelated."))
        brand_root_match = any(term in root for term in matched_brands if term not in {"bank"})
        if root and not brand_root_match and any(term not in {"bank"} for term in matched_brands):
            severity = "high" if matched_terms else "medium"
            risk_signals.append(_signal(
                "brand_impersonation_mismatch",
                "Brand term on unrelated root domain",
                severity,
                f"brands={', '.join(matched_brands)}; root={root}",
                "Brand or service wording appears even though the registrable domain does not match that brand. This is a common phishing pattern.",
            ))
    suspicious_extensions = _detect_extensions(parsed)
    if suspicious_extensions:
        risk_signals.append(_signal("suspicious_extension", "Suspicious file extension", "high", ", ".join(suspicious_extensions), "URLs that point to script, executable, archive, ISO, or HTML payloads need careful handling."))
    if "@" in parsed.netloc.rsplit("@", 1)[0]:
        risk_signals.append(_signal("userinfo_at", "Userinfo component in URL", "high", parsed.netloc, "The '@' separator can hide the real destination host."))

    extracted_iocs = _extract_iocs(normalized, hostname, query_values)
    static_result = {
        "scheme": parsed.scheme,
        "host": hostname,
        "root_domain": root,
        "port": parsed.port,
        "path": parsed.path,
        "query": parsed.query,
        "query_params": params,
        "fragment": parsed.fragment,
        "emails_found_in_query": emails_in_query,
        "decoded_query_hints": decoded_query_hints,
        "extracted_iocs": extracted_iocs,
        "risk_signals": risk_signals,
        "suspicious_extensions": suspicious_extensions,
    }
    verdict, confidence = _score_signals(risk_signals, live_enabled=False)
    summary = _build_summary(verdict, risk_signals, hostname)
    result = {
        "input": input_info,
        "static_result": static_result,
        "verdict": verdict,
        "confidence": confidence,
        "risk_score": _risk_score(risk_signals),
        "evidence_level": _evidence_level(False, risk_signals),
        "reputation_status": "not_checked",
        "summary": summary,
        "recommended_actions": _recommended_actions(verdict, risk_signals, hostname),
        "limitations": [
            "Static analysis is heuristic and does not prove whether a URL is malicious.",
            "No network request, browser rendering, JavaScript execution, form submission, or file download is performed in static mode.",
            "External reputation, blocklists, sandbox screenshots, and vendor detections are not checked locally.",
        ],
        "checked_at": _now_iso(),
    }
    result["analysis"] = _build_analysis_block(result, live_enabled=False)
    return result


def _score_static(signals: list[dict[str, str]]) -> tuple[str, str]:
    return _score_signals(signals, live_enabled=False)


def _build_summary(verdict: str, signals: list[dict[str, str]], hostname: str) -> str:
    evidence = [item["label"].lower() for item in signals if item["severity"] in {"high", "medium"}]
    if not evidence:
        if verdict == "low_risk":
            return f"No major static risk signals were found for {hostname or 'this URL'}, but this does not establish reputation or safety."
        evidence = [item["label"].lower() for item in signals[:2]]
    joined = ", ".join(evidence[:3])
    if verdict == "suspicious":
        return f"This URL appears suspicious because it shows {joined}."
    return f"This URL needs review because it shows {joined}."


def _recommended_actions(verdict: str, signals: list[dict[str, str]], hostname: str) -> list[str]:
    actions = [
        "Do not open the URL directly in a normal browser session.",
        "Copy the host and root domain into Recon & Exposure for DNS/HTTP/TLS context.",
        "Pivot on the URL, host, and extracted email/IP indicators in proxy, DNS, and mailbox logs.",
    ]
    ids = {item["id"] for item in signals}
    if "url_shortener" in ids:
        actions.append("Use Safe Fetch to inspect the redirect chain before considering any manual review.")
    if "redirect_domain_change" in ids:
        actions.append("Review the final redirect destination and compare the original root domain with the final root domain.")
    if "title_lure" in ids:
        actions.append("Treat the observed page title as lure evidence and capture it in the case notes.")
    if "safe_fetch_blocked" in ids:
        actions.append("Do not retry with private targets enabled unless this is an approved internal assessment.")
    if "suspicious_extension" in ids:
        actions.append("Treat any downloaded file as untrusted and review it only through Attachment Triage/static analysis.")
    if hostname:
        actions.append(f"Record {hostname} as the primary URL host in the case notes.")
    if verdict == "low_risk":
        actions.append("If this came from an email or alert, continue reviewing sender, context, and user-report details.")
    return actions


def _severity_counts(signals: list[dict[str, str]]) -> dict[str, int]:
    return {
        "high": sum(1 for item in signals if item.get("severity") == "high"),
        "medium": sum(1 for item in signals if item.get("severity") == "medium"),
        "low": sum(1 for item in signals if item.get("severity") == "low"),
        "info": sum(1 for item in signals if item.get("severity") == "info"),
    }


def _signal_priority(signals: list[dict[str, str]], limit: int = 5) -> list[dict[str, str]]:
    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    return sorted(signals, key=lambda item: (order.get(item.get("severity", "info"), 9), item.get("label", "")))[:limit]


def _signal_label_list(signals: list[dict[str, str]], limit: int = 3) -> str:
    labels = [item.get("label", "observed signal").lower() for item in _signal_priority(signals, limit)]
    return ", ".join(labels) if labels else "no strong local evidence"


def _analysis_category(signals: list[dict[str, str]], live_result: dict[str, Any]) -> str:
    ids = {item.get("id") for item in signals}
    if "safe_fetch_blocked" in ids or "private_ip_hostname" in ids or "internal_hostname" in ids:
        return "Blocked or internal-target URL"
    if "download_content" in ids or "suspicious_extension" in ids:
        return "Download or payload-delivery risk"
    if "brand_impersonation_mismatch" in ids and ("credential_wording" in ids or "email_in_query" in ids or "title_lure" in ids):
        return "Likely credential-phishing lure"
    if "title_lure" in ids:
        return "Likely lure page"
    if "redirect_domain_change" in ids or "url_shortener" in ids:
        return "Redirect-hiding or destination-shift link"
    if "base64_query" in ids or "email_in_query" in ids or "credential_wording" in ids:
        return "Phishing-style tracking or account lure"
    if live_result.get("enabled") and not ids:
        return "No notable local/network signal"
    return "URL requires contextual review"


def _confidence_reason(verdict: str, confidence: str, live_enabled: bool, signals: list[dict[str, str]]) -> str:
    counts = _severity_counts(signals)
    scope = "static URL structure plus guarded network metadata" if live_enabled else "static URL structure only"
    if verdict == "suspicious":
        return f"{confidence.title()} confidence from {scope}; {counts['high']} high and {counts['medium']} medium signal(s) were observed. No vendor reputation was checked."
    if verdict == "low_risk":
        return f"{confidence.title()} confidence because no high/medium local signals were observed in {scope}. This is not proof of safety."
    return f"{confidence.title()} confidence because {scope} produced review-worthy signals, but not enough to prove maliciousness."


def _primary_concern(signals: list[dict[str, str]], live_result: dict[str, Any]) -> str:
    category = _analysis_category(signals, live_result)
    prioritized = _signal_priority(signals, 1)
    if prioritized:
        signal = prioritized[0]
        evidence = signal.get("evidence")
        if evidence:
            return f"{category}: {signal.get('label')} ({evidence})"
        return f"{category}: {signal.get('label')}"
    if live_result.get("enabled"):
        return "No strong local or Safe Fetch metadata signal was observed."
    return "No strong static signal was observed; final destination and reputation remain unknown."


def _analyst_conclusion(verdict: str, signals: list[dict[str, str]], live_result: dict[str, Any], hostname: str) -> str:
    category = _analysis_category(signals, live_result)
    evidence = _signal_label_list(signals)
    target = hostname or "the URL"
    if verdict == "suspicious":
        return f"Treat {target} as suspicious: {category.lower()} supported by {evidence}."
    if verdict == "low_risk":
        if live_result.get("enabled"):
            return f"No major local or Safe Fetch metadata signal was found for {target}; this does not prove the URL is safe."
        return f"No major static signal was found for {target}; run Safe Fetch or external reputation only if case context requires it."
    return f"{target} needs review: {category.lower()} indicated by {evidence}."


def _next_best_action(verdict: str, signals: list[dict[str, str]], live_result: dict[str, Any], hostname: str) -> str:
    ids = {item.get("id") for item in signals}
    if live_result.get("blocked_reason"):
        return "Record the block reason and do not retry against private/internal destinations unless the assessment explicitly allows it."
    if "download_content" in ids or "suspicious_extension" in ids:
        return "Do not download directly. Send the URL or file reference to Attachment Triage/static malware review."
    if "brand_impersonation_mismatch" in ids or "credential_wording" in ids or "email_in_query" in ids:
        return "Pivot the URL, host, and any email token in proxy/DNS/mailbox logs; capture a report-ready phishing finding."
    if "redirect_domain_change" in ids or "url_shortener" in ids:
        return "Compare original and final domains, then pivot both root domains in Recon and logs."
    if not live_result.get("enabled") and verdict != "low_risk":
        return "Enable Safe Fetch for redirect/header evidence if network metadata would change the case decision."
    if hostname:
        return f"Pivot {hostname} in Recon, DNS/proxy logs, and optional external reputation sources."
    return "Review case context and pivot extracted indicators."


def _missing_evidence(live_enabled: bool) -> list[str]:
    gaps = [
        "No vendor reputation or blocklist result is included.",
        "No browser rendering, screenshot, DOM snapshot, or JavaScript execution is performed.",
        "No files are downloaded or sandboxed.",
    ]
    if not live_enabled:
        gaps.insert(0, "Redirect chain, final host, page title, HTTP headers, and TLS metadata were not collected.")
    return gaps


def _score_breakdown(signals: list[dict[str, str]]) -> list[dict[str, Any]]:
    weights = {"high": 28, "medium": 14, "low": 5, "info": 0}
    rows = []
    for signal in _signal_priority(signals, 12):
        rows.append({
            "signal": signal.get("label", "Signal"),
            "id": signal.get("id", ""),
            "severity": signal.get("severity", "info"),
            "points": weights.get(signal.get("severity", "info"), 0),
            "source": "network_metadata" if signal.get("source") == "safe_fetch" else "url_structure",
            "evidence": signal.get("evidence", "observed"),
            "why_it_matters": signal.get("explanation", "Review this signal in case context."),
        })
    return rows


def _evidence_buckets(signals: list[dict[str, str]]) -> dict[str, list[dict[str, str]]]:
    buckets = {"strong": [], "medium": [], "weak": [], "informational": []}
    for signal in _signal_priority(signals, 20):
        severity = signal.get("severity", "info")
        if severity == "high":
            buckets["strong"].append(signal)
        elif severity == "medium":
            buckets["medium"].append(signal)
        elif severity == "low":
            buckets["weak"].append(signal)
        else:
            buckets["informational"].append(signal)
    return buckets


def _destination_behavior(static_result: dict[str, Any], live_result: dict[str, Any]) -> dict[str, Any]:
    chain = live_result.get("redirect_chain") or []
    original_host = static_result.get("host") or ""
    final_host = live_result.get("final_host") or original_host
    original_root = static_result.get("root_domain") or _root_domain(original_host)
    final_root = _root_domain(final_host)
    headers = live_result.get("headers") or {}
    return {
        "submitted_host": original_host,
        "submitted_root_domain": original_root,
        "final_host": final_host,
        "final_root_domain": final_root,
        "root_domain_changed": bool(original_root and final_root and original_root != final_root),
        "redirect_count": max(0, len(chain) - 1),
        "http_status": live_result.get("status_code") or (chain[-1].get("status_code") if chain else None),
        "content_type": headers.get("content-type", ""),
        "server": headers.get("server", ""),
        "cookie_present": headers.get("set-cookie_present", "false"),
        "page_title": live_result.get("page_title", ""),
        "tls_issuer": (live_result.get("tls") or {}).get("issuer_common_name", ""),
        "blocked_reason": live_result.get("blocked_reason"),
        "browser_rendered": False,
        "javascript_executed": False,
        "forms_submitted": False,
        "files_downloaded": False,
    }


def _soc_queries(static_result: dict[str, Any], live_result: dict[str, Any]) -> list[dict[str, str]]:
    iocs = static_result.get("extracted_iocs") or {}
    domains = _unique([static_result.get("host", ""), static_result.get("root_domain", ""), live_result.get("final_host", ""), *iocs.get("domains", [])])
    urls = _unique([value for value in [live_result.get("final_url", "")] + iocs.get("urls", []) if value])
    quoted_domains = ", ".join(f'"{domain}"' for domain in domains if domain)
    quoted_urls = ", ".join(f'"{url}"' for url in urls if url)
    domain_contains = " OR ".join([f'url_domain=\"{domain}\" OR query=\"{domain}\"' for domain in domains if domain]) or "<domain>"
    return [
        {
            "name": "Proxy / web gateway pivot",
            "query": f"({domain_contains}) OR url IN ({quoted_urls or '<url>'})",
            "purpose": "Find users/systems that requested the submitted or final URL.",
        },
        {
            "name": "DNS pivot",
            "query": f"query IN ({quoted_domains or '<domains>'})",
            "purpose": "Find resolver activity for observed hosts and root domains.",
        },
        {
            "name": "Mail body / URL search",
            "query": f"EmailUrlInfo | where Url has_any (dynamic([{quoted_urls}])) or UrlDomain in~ (dynamic([{quoted_domains}]))",
            "purpose": "Find other messages containing the same URLs or domains.",
        },
        {
            "name": "EDR browser-history pivot",
            "query": " OR ".join([f'BrowserHistoryUrl contains \"{domain}\"' for domain in domains if domain]) or "BrowserHistoryUrl contains <domain>",
            "purpose": "Confirm whether endpoints opened the URL in a browser.",
        },
    ]


def _external_verification_items(static_result: dict[str, Any], live_result: dict[str, Any]) -> list[dict[str, str]]:
    host = static_result.get("root_domain") or static_result.get("host") or ""
    final_host = live_result.get("final_host") or host
    url = live_result.get("final_url") or (static_result.get("extracted_iocs") or {}).get("urls", [""])[0]
    return [
        {"tool": "VirusTotal / URL reputation", "artifact": url or host, "why": "Vendor/community reputation and historical submissions."},
        {"tool": "urlscan / approved sandbox", "artifact": url or host, "why": "Screenshot, DOM, request tree, and loaded resources if policy allows."},
        {"tool": "Google Safe Browsing / URLhaus / PhishTank", "artifact": final_host or host, "why": "Known unsafe-resource, malware URL, and phishing feed corroboration."},
        {"tool": "Talos / Spamhaus / AbuseIPDB", "artifact": final_host or host, "why": "IP/domain reputation and abuse history."},
        {"tool": "dnstwist / typosquat check", "artifact": host, "why": "Brand impersonation, lookalike, and homograph infrastructure review."},
    ]


def _build_analysis_block(result: dict[str, Any], live_enabled: bool) -> dict[str, Any]:
    static_result = result.get("static_result", {})
    live_result = result.get("live_result", {}) or {}
    signals = [*(static_result.get("risk_signals") or []), *((live_result.get("risk_signals") or []) if live_enabled else [])]
    hostname = static_result.get("host", "")
    verdict = result.get("verdict", "needs_review")
    confidence = result.get("confidence", "low")
    score_rows = _score_breakdown(signals)
    destination = _destination_behavior(static_result, live_result)
    confidence_gaps = _missing_evidence(live_enabled)
    if live_enabled and not live_result.get("page_title"):
        confidence_gaps.append("No page title was safely extracted; the page may require rendering or returned non-HTML content.")
    if live_enabled and not live_result.get("redirect_chain"):
        confidence_gaps.append("No redirect/header chain was collected, possibly because resolution or connection failed.")
    return {
        "mode": "static_plus_guarded_metadata" if live_enabled else "static_only",
        "category": _analysis_category(signals, live_result),
        "conclusion": _analyst_conclusion(verdict, signals, live_result, hostname),
        "primary_concern": _primary_concern(signals, live_result),
        "next_best_action": _next_best_action(verdict, signals, live_result, hostname),
        "confidence_reason": _confidence_reason(verdict, confidence, live_enabled, signals),
        "strongest_evidence": _signal_priority(signals, 8),
        "evidence_buckets": _evidence_buckets(signals),
        "score_breakdown": score_rows,
        "score_explanation": "No strong local URL evidence was found." if not score_rows else "Risk is driven by " + ", ".join(row["signal"].lower() for row in score_rows[:3]) + ".",
        "severity_counts": _severity_counts(signals),
        "static_signal_count": len(static_result.get("risk_signals") or []),
        "network_signal_count": len(live_result.get("risk_signals") or []) if live_enabled else 0,
        "destination_behavior": destination,
        "soc_queries": _soc_queries(static_result, live_result),
        "external_verification": _external_verification_items(static_result, live_result),
        "missing_evidence": confidence_gaps,
        "decision_boundaries": [
            "This is a local triage and guarded metadata result, not a complete reputation verdict.",
            "Maliciousness should be confirmed with user-click telemetry, gateway verdicts, endpoint data, or approved reputation/sandbox sources.",
        ],
    }


def _safe_headers(headers: httpx.Headers) -> dict[str, str]:
    output: dict[str, str] = {}
    for key in [
        "server", "content-type", "content-length", "content-disposition", "location", "x-powered-by", "strict-transport-security",
        "content-security-policy", "x-frame-options", "x-content-type-options", "referrer-policy",
    ]:
        value = headers.get(key)
        if value:
            output[key] = value[:500]
    output["set-cookie_present"] = "true" if headers.get("set-cookie") else "false"
    return output


def _extract_title_from_bytes(content: bytes) -> str:
    match = TITLE_RE.search(content[:MAX_TITLE_BYTES])
    if not match:
        return ""
    raw = re.sub(rb"\s+", b" ", match.group(1)).strip()
    try:
        return unescape(raw.decode("utf-8", errors="replace"))[:180]
    except Exception:
        return ""


def _limited_get_title(client: httpx.Client, url: str, timeout_seconds: int) -> tuple[str, dict[str, str]]:
    content = bytearray()
    observed_headers: dict[str, str] = {}
    try:
        with client.stream(
            "GET",
            url,
            timeout=timeout_seconds,
            follow_redirects=False,
            headers={"User-Agent": "BeyondArch-SafeFetch/1.0", "Accept": "text/html,application/xhtml+xml", "Range": f"bytes=0-{MAX_TITLE_BYTES - 1}"},
        ) as response:
            observed_headers = _safe_headers(response.headers)
            content_type = response.headers.get("content-type", "")
            if "text/html" not in content_type.lower():
                return "", observed_headers
            for chunk in response.iter_bytes():
                content.extend(chunk)
                if len(content) >= MAX_TITLE_BYTES:
                    break
    except Exception:
        return "", observed_headers
    return _extract_title_from_bytes(bytes(content)), observed_headers



def _live_risk_signals(static_result: dict[str, Any], live_result: dict[str, Any]) -> list[dict[str, str]]:
    signals: list[dict[str, str]] = []
    if not live_result.get("enabled"):
        return signals
    if live_result.get("blocked_reason"):
        signals.append(_signal(
            "safe_fetch_blocked",
            "Safe Fetch blocked target",
            "high",
            str(live_result.get("blocked_reason", "blocked"))[:180],
            "The guarded fetch refused the target before continuing. This is important case evidence, not a benign result.",
            source="safe_fetch",
        ))
        return signals

    original_root = static_result.get("root_domain") or ""
    final_host = live_result.get("final_host") or ""
    final_root = _root_domain(final_host)
    if original_root and final_root and final_root != original_root:
        signals.append(_signal(
            "redirect_domain_change",
            "Redirect changed root domain",
            "medium",
            f"{original_root} -> {final_root}",
            "A different final registrable domain can be normal for CDNs, but it is important in phishing and shortener analysis.",
            source="safe_fetch",
        ))

    final_url = live_result.get("final_url") or ""
    parsed_final = urlparse(final_url)
    if parsed_final.scheme == "http":
        signals.append(_signal(
            "final_http",
            "Final destination uses HTTP",
            "medium",
            final_url[:180],
            "The final destination is not protected by HTTPS.",
            source="safe_fetch",
        ))

    title = (live_result.get("page_title") or "").strip()
    title_lower = title.lower()
    lure_terms = {
        "download", "free", "crack", "keygen", "serial", "claim", "prize", "reward", "gift",
        "verify", "login", "password", "account", "security", "suspended", "wallet", "invoice",
        "grand theft auto", "gta", "v-bucks", "robux",
    }
    matched_title_terms = sorted(term for term in lure_terms if term in title_lower)
    if matched_title_terms:
        severity = "medium"
        if any(term in title_lower for term in {"crack", "keygen", "grand theft auto", "gta", "v-bucks", "robux"}):
            severity = "high"
        signals.append(_signal(
            "title_lure",
            "Lure-like page title",
            severity,
            title[:180],
            "The limited HTML title contains wording often seen in scams, credential lures, or download bait. This is metadata evidence; the page was not rendered.",
            source="safe_fetch",
        ))

    headers = live_result.get("headers") or {}
    content_type = str(headers.get("content-type", "")).lower()
    content_disposition = str(headers.get("content-disposition", "")).lower()
    risky_types = ("application/octet-stream", "application/x-msdownload", "application/zip", "application/x-rar", "application/x-7z")
    if any(item in content_type for item in risky_types) or "attachment" in content_disposition:
        signals.append(_signal(
            "download_content",
            "Download-like response metadata",
            "high",
            content_type or content_disposition[:180],
            "Safe Fetch observed response metadata that looks like a file delivery path. Do not download automatically.",
            source="safe_fetch",
        ))
    return signals


def _tls_summary(hostname: str, port: int = 443, timeout_seconds: int = 8) -> dict[str, Any]:
    if not hostname or _is_ip_literal(hostname):
        return {}
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=max(2, min(timeout_seconds, 12))) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as secure_sock:
                cert = secure_sock.getpeercert() or {}
    except Exception as error:
        return {"error": str(error)[:180]}

    def first_name(field: str) -> str:
        for item in cert.get(field, []):
            for key, value in item:
                if key == "commonName":
                    return value
        return ""

    san = cert.get("subjectAltName", []) or []
    return {
        "subject_common_name": first_name("subject"),
        "issuer_common_name": first_name("issuer"),
        "not_before": cert.get("notBefore", ""),
        "not_after": cert.get("notAfter", ""),
        "san_count": len(san),
    }


def _run_safe_fetch(start_url: str, max_redirects: int, timeout_seconds: int, allow_private_targets: bool) -> dict[str, Any]:
    parsed = urlparse(start_url)
    if parsed.scheme not in {"http", "https"}:
        return {"enabled": True, "redirect_chain": [], "blocked_reason": "Live Safe Fetch supports http and https URLs only.", "limitations": []}

    ok, addresses, reason = _resolve_public_addresses(parsed.hostname or "", allow_private_targets)
    if not ok:
        return {
            "enabled": True,
            "redirect_chain": [],
            "final_url": "",
            "final_host": parsed.hostname or "",
            "headers": {},
            "tls": {},
            "page_title": "",
            "blocked_reason": reason,
            "resolved_ips": addresses,
            "limitations": ["The request was blocked before any HTTP connection was attempted."],
        }

    chain: list[dict[str, Any]] = []
    current_url = start_url
    final_headers: dict[str, str] = {}
    final_status = None
    blocked_reason = None
    page_title = ""
    final_host = parsed.hostname or ""
    final_url = start_url
    limitations = [
        "Safe Fetch inspects redirect and header metadata only.",
        "It does not execute JavaScript, render a browser page, submit forms, store cookies, or download files automatically.",
    ]

    timeout_seconds = max(2, min(int(timeout_seconds or 8), 20))
    max_redirects = max(0, min(int(max_redirects or 5), 10))

    with httpx.Client(follow_redirects=False, timeout=timeout_seconds, verify=True) as client:
        for hop in range(max_redirects + 1):
            parsed_current = urlparse(current_url)
            final_host = parsed_current.hostname or ""
            ok, resolved, reason = _resolve_public_addresses(final_host, allow_private_targets)
            if not ok:
                blocked_reason = reason
                chain.append({"hop": hop + 1, "url": current_url, "host": final_host, "status_code": None, "notes": reason, "resolved_ips": resolved})
                break

            try:
                response = client.request(
                    "HEAD",
                    current_url,
                    follow_redirects=False,
                    timeout=timeout_seconds,
                    headers={"User-Agent": "BeyondArch-SafeFetch/1.0", "Accept": "*/*"},
                )
            except httpx.HTTPStatusError as error:
                blocked_reason = f"HTTP error: {error}"
                break
            except Exception as error:
                blocked_reason = f"Connection failed: {error}"
                break

            final_status = response.status_code
            final_url = current_url
            final_headers = _safe_headers(response.headers)
            location = response.headers.get("location", "")
            hop_notes = []
            if response.headers.get("set-cookie"):
                hop_notes.append("Set-Cookie present")
            if location:
                hop_notes.append("Redirect location present")
            chain.append({
                "hop": hop + 1,
                "url": current_url,
                "status_code": response.status_code,
                "host": final_host,
                "resolved_ips": resolved,
                "location": location,
                "content_type": response.headers.get("content-type", ""),
                "content_length": response.headers.get("content-length", ""),
                "server": response.headers.get("server", ""),
                "set_cookie_present": bool(response.headers.get("set-cookie")),
                "notes": "; ".join(hop_notes) or "Header metadata collected",
            })

            if response.is_redirect and location:
                next_url = urljoin(current_url, location)
                parsed_next = urlparse(next_url)
                if parsed_next.scheme not in {"http", "https"}:
                    blocked_reason = f"Redirect target uses unsupported scheme: {parsed_next.scheme}"
                    break
                ok, next_addresses, reason = _resolve_public_addresses(parsed_next.hostname or "", allow_private_targets)
                if not ok:
                    blocked_reason = f"Redirect blocked: {reason}"
                    chain[-1]["notes"] = f"Redirect blocked before following: {reason}"
                    chain[-1]["next_resolved_ips"] = next_addresses
                    final_url = current_url
                    final_host = parsed_current.hostname or ""
                    break
                current_url = next_url
                continue

            content_type = response.headers.get("content-type", "")
            if "text/html" in content_type.lower() or not content_type:
                title, observed_headers = _limited_get_title(client, current_url, timeout_seconds)
                if title:
                    page_title = title
                if observed_headers:
                    final_headers = {**final_headers, **observed_headers}
            break
        else:
            blocked_reason = f"Maximum redirect count reached: {max_redirects}"

    parsed_final = urlparse(final_url)
    tls_port = parsed_final.port or 443
    tls = _tls_summary(final_host, tls_port, timeout_seconds) if parsed_final.scheme == "https" and not blocked_reason else {}
    return {
        "enabled": True,
        "redirect_chain": chain,
        "final_url": final_url,
        "final_host": final_host,
        "status_code": final_status,
        "headers": final_headers,
        "tls": tls,
        "page_title": page_title,
        "blocked_reason": blocked_reason,
        "limitations": limitations,
    }


def safe_analyze_url(
    url: str,
    allow_live_fetch: bool = False,
    max_redirects: int = 5,
    timeout_seconds: int = 8,
    allow_private_targets: bool = False,
) -> dict[str, Any]:
    result = analyze_static_url(url)
    if allow_live_fetch:
        result["live_result"] = _run_safe_fetch(
            result["input"]["normalized"],
            max_redirects=max_redirects,
            timeout_seconds=timeout_seconds,
            allow_private_targets=allow_private_targets,
        )
        live_signals = _live_risk_signals(result.get("static_result", {}), result["live_result"])
        result["live_result"]["risk_signals"] = live_signals
        combined_signals = [*(result.get("static_result", {}).get("risk_signals") or []), *live_signals]
        result["verdict"], result["confidence"] = _score_signals(combined_signals, live_enabled=True)
        result["risk_score"] = _risk_score(combined_signals)
        result["evidence_level"] = _evidence_level(True, combined_signals)
        result["summary"] = _build_summary(result["verdict"], combined_signals, result.get("static_result", {}).get("host", ""))
        result["recommended_actions"] = _recommended_actions(result["verdict"], combined_signals, result.get("static_result", {}).get("host", ""))
        if result["live_result"].get("blocked_reason"):
            result["limitations"].append(result["live_result"]["blocked_reason"])
    else:
        result["live_result"] = {
            "enabled": False,
            "redirect_chain": [],
            "final_url": "",
            "final_host": "",
            "headers": {},
            "tls": {},
            "page_title": "",
            "blocked_reason": None,
            "risk_signals": [],
            "limitations": ["Live Safe Fetch was not run. Static mode made zero network requests."],
        }
    result["analysis"] = _build_analysis_block(result, live_enabled=allow_live_fetch)
    return result
