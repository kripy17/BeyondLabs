import re
import html as html_module
from urllib.parse import urlparse

from app.services.ioc_extractor import analyze_urls, defang_text, extract_iocs, refang_text

URGENCY_KEYWORDS = [
    "urgent", "immediately", "action required", "verify now", "expires today",
    "account locked", "suspended", "limited time", "final warning", "security alert",
    "unauthorized login", "suspicious activity", "unusual sign-in", "breach",
]

CREDENTIAL_KEYWORDS = [
    "password", "login", "sign in", "verify your account", "confirm your account",
    "update your credentials", "reset your password", "authentication required",
    "recover your account", "re-activate", "reactivate",
]

PAYMENT_KEYWORDS = [
    "invoice", "payment", "bank", "wire transfer", "refund", "billing",
    "purchase order", "crypto", "wallet", "transaction", "overdue",
    "outstanding payment", "subscription",
]

SENSITIVE_KEYWORDS = [
    "ssn", "aadhaar", "pan card", "passport", "credit card", "otp",
    "one time password", "2fa", "mfa code", "secret code",
    "security question",
]

URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "cutt.ly", "rebrand.ly", "shorturl.at", "s.id",
    "rb.gy", "bl.ink", "short.gy", "clck.ru", "shorte.st",
]

RISKY_EXTENSIONS = [
    ".exe", ".scr", ".bat", ".cmd", ".js", ".jse", ".vbs", ".vbe",
    ".ps1", ".jar", ".msi", ".hta", ".lnk", ".iso", ".img",
    ".docm", ".xlsm", ".pptm",
]

BRAND_DOMAINS = {
    "microsoft": {"microsoft.com", "outlook.com", "live.com", "hotmail.com", "office.com", "office365.com"},
    "google": {"google.com", "gmail.com", "youtube.com", "drive.google.com"},
    "paypal": {"paypal.com", "paypal.me"},
    "apple": {"apple.com", "icloud.com", "me.com"},
    "amazon": {"amazon.com", "amazon.co.uk", "amazon.de", "aws.amazon.com"},
    "netflix": {"netflix.com", "nflx.com"},
    "linkedin": {"linkedin.com"},
    "facebook": {"facebook.com", "fb.com", "meta.com"},
    "github": {"github.com"},
    "dropbox": {"dropbox.com"},
    "docusign": {"docusign.com", "docusign.net"},
    "adobe": {"adobe.com"},
    "salesforce": {"salesforce.com"},
    "wellsfargo": {"wellsfargo.com"},
    "chase": {"chase.com"},
}

ATTACHMENT_RE = re.compile(
    r'\b[\w\-. ]+\.(?:exe|scr|bat|cmd|js|jse|vbs|vbe|ps1|jar|msi|hta|lnk|iso|img|docm|xlsm|pptm|zip|rar|7z|pdf|docx|xlsx)\b',
    re.IGNORECASE,
)

HTML_HREF_RE = re.compile(
    r'href=["\']([^"\']+)["\']',
    re.IGNORECASE,
)

HTML_ANCHOR_TAG_RE = re.compile(
    r'<a\s[^>]*href=["\']([^"\']+)["\'][^>]*>([^<]*)</a>',
    re.IGNORECASE | re.DOTALL,
)

HTML_FORM_RE = re.compile(
    r'<form\s[^>]*action=["\']([^"\']*)["\']',
    re.IGNORECASE,
)

HTML_SUBMIT_RE = re.compile(
    r'<input[^>]*type=["\']submit["\']|id=["\']submit["\']|class=["\'][^"\']*submit[^"\']*["\']|<button[^>]*type=["\']submit["\']',
    re.IGNORECASE,
)

HTML_IMAGE_RE = re.compile(
    r'<img\s[^>]*src=["\']([^"\']+)["\']',
    re.IGNORECASE,
)

HTML_PIXEL_RE = re.compile(
    r'<img[^>]{1,200}?(?:width\s*=\s*["\']?\d["\']?|height\s*=\s*["\']?\d["\']?|1x1|\d+x\d+).*?>',
    re.IGNORECASE | re.DOTALL,
)

ZERO_WIDTH_CHARS = re.compile("[\u200b\u200c\u200d\u2060\u2061\u2062\u2063\u2064\uFEFF]")


def add_finding(findings, severity, title, detail, recommendation, mitre_id=None):
    finding = {
        "severity": severity,
        "title": title,
        "detail": detail,
        "recommendation": recommendation,
    }
    if mitre_id:
        finding["mitre_id"] = mitre_id
    findings.append(finding)


def detect_brand_impersonation(links: list[dict]) -> list[dict]:
    hits = []
    for link in links:
        text = link.get("text", "").strip().lower()
        href = link.get("href", "").lower()
        try:
            parsed = urlparse(href)
            actual_domain = parsed.hostname or ""
        except Exception:
            continue

        if not actual_domain:
            continue

        for brand, legit_domains in BRAND_DOMAINS.items():
            if text and brand in text:
                if not any(legit in actual_domain for legit in legit_domains):
                    hits.append({
                        "brand": brand,
                        "display_text": link.get("text", "")[:60],
                        "href": href[:120],
                        "actual_domain": actual_domain,
                    })
    return hits


def detect_link_mismatches(body: str) -> list[dict]:
    mismatches = []
    for match in HTML_ANCHOR_TAG_RE.finditer(body):
        href = match.group(1).strip()
        text = html_module.unescape(match.group(2).strip())
        if not text:
            continue

        if href.startswith("mailto:"):
            continue

        try:
            parsed = urlparse(href)
            href_domain = parsed.hostname or ""
        except Exception:
            continue

        text_lower = text.lower()
        if href_domain and text_lower and "@" not in text_lower:
            # Check if text mentions domain/host different from href
            for word in re.split(r"[ /\n\r\t,;:!?()\[\]{}]+", text_lower):
                word = word.strip().strip(".")
                if word and "." in word:
                    if word not in href_domain and word not in href:
                        mismatches.append({
                            "display_text": text[:60],
                            "href": href[:120],
                            "likely_domain_in_text": word,
                            "href_domain": href_domain,
                        })
                        break

    return mismatches


def detect_forms(body: str) -> list[dict]:
    forms = []
    for match in HTML_FORM_RE.finditer(body):
        action = match.group(1).strip()
        parsed = urlparse(action) if action else None
        domain = parsed.hostname if parsed else None
        has_submit = bool(HTML_SUBMIT_RE.search(body))

        forms.append({
            "action": action[:200] if action else "(none/self)",
            "action_domain": domain,
            "has_submit_button": has_submit,
        })

    return forms


def detect_tracking_images(body: str) -> list[dict]:
    pixels = []
    for match in HTML_PIXEL_RE.finditer(body):
        tag = match.group(0)
        src_match = re.search(r'src=["\']([^"\']+)["\']', tag)
        if src_match:
            src = src_match.group(1)
            pixels.append({"src": src[:200], "type": "tracking_pixel"})
    return pixels


def detect_zero_width_chars(text: str) -> list[str]:
    found = ZERO_WIDTH_CHARS.findall(text)
    return list(set(found))


def has_html_content(text: str) -> bool:
    return bool(re.search(r'<html|<head|<body|<div|<span|<a\s|<img|<table|<!DOCTYPE', text, re.IGNORECASE))


def extract_html_text(body: str) -> str:
    stripped = re.sub(r'<style[^>]*>.*?</style>', '', body, flags=re.DOTALL | re.IGNORECASE)
    stripped = re.sub(r'<script[^>]*>.*?</script>', '', stripped, flags=re.DOTALL | re.IGNORECASE)
    stripped = re.sub(r'<[^>]+>', ' ', stripped)
    stripped = html_module.unescape(stripped)
    stripped = re.sub(r'\s+', ' ', stripped).strip()
    return stripped


def find_keywords(text: str, keywords: list[str]) -> list[str]:
    lowered = text.lower()
    found = []

    for keyword in keywords:
        if keyword in lowered:
            found.append(keyword)

    return sorted(set(found))


def detect_attachments(text: str) -> list[dict]:
    matches = sorted(set(ATTACHMENT_RE.findall(text)))
    results = []

    for filename in matches:
        lower_name = filename.lower()
        risky = any(lower_name.endswith(ext) for ext in RISKY_EXTENSIONS)

        double_extension = bool(
            re.search(
                r'\.(pdf|doc|docx|xls|xlsx|jpg|png|txt)\.(exe|scr|js|vbs|bat|cmd|ps1|hta)$',
                lower_name
            )
        )

        results.append({
            "filename": filename,
            "risky_extension": risky,
            "double_extension": double_extension,
        })

    return results


def analyze_email_urls(iocs: dict, body: str) -> dict:
    urls = iocs.get("urls", [])
    rich = analyze_urls(urls)
    hrefs = HTML_HREF_RE.findall(body)

    result = dict(rich)
    result["html_hrefs"] = hrefs
    result["urls"] = urls
    return result


def score_findings(findings):
    score = 100

    penalties = {
        "high": 30,
        "medium": 15,
        "low": 7,
        "info": 0,
    }

    for finding in findings:
        score -= penalties.get(finding["severity"], 0)

    return max(score, 0)


def analyze_email_body(body: str, refang_first: bool = True) -> dict:
    working_body = refang_text(body) if refang_first else body

    ioc_result = extract_iocs(working_body, refang_first=False)
    iocs = ioc_result["iocs"]

    has_html = has_html_content(working_body)
    plain_text = extract_html_text(working_body) if has_html else working_body

    urgency_hits = find_keywords(working_body, URGENCY_KEYWORDS)
    credential_hits = find_keywords(working_body, CREDENTIAL_KEYWORDS)
    payment_hits = find_keywords(working_body, PAYMENT_KEYWORDS)
    sensitive_hits = find_keywords(working_body, SENSITIVE_KEYWORDS)

    attachments = detect_attachments(working_body)
    url_analysis = analyze_email_urls(iocs, working_body)
    link_mismatches = detect_link_mismatches(working_body) if has_html else []

    # Build structured link info for brand checks
    links = []
    for match in HTML_ANCHOR_TAG_RE.finditer(working_body):
        href = match.group(1).strip()
        text = html_module.unescape(match.group(2).strip())
        links.append({"href": href, "text": text})
    brand_hits = detect_brand_impersonation(links)

    forms = detect_forms(working_body) if has_html else []
    tracking = detect_tracking_images(working_body) if has_html else []
    zw_chars = detect_zero_width_chars(working_body)

    findings = []

    # Keyword-based findings
    if urgency_hits:
        add_finding(
            findings, "medium",
            "Urgency language detected",
            f"Detected urgency keywords: {', '.join(urgency_hits)}",
            "Treat urgency-based requests carefully and verify through a trusted channel."
        )

    if credential_hits:
        add_finding(
            findings, "high",
            "Credential-harvesting language detected",
            f"Detected credential-related phrases: {', '.join(credential_hits)}",
            "Do not enter credentials through links in the email. Verify the destination manually.",
            mitre_id="T1566.001"
        )

    if payment_hits:
        add_finding(
            findings, "medium",
            "Payment or finance language detected",
            f"Detected finance-related terms: {', '.join(payment_hits)}",
            "Verify payment requests using an independent trusted contact method."
        )

    if sensitive_hits:
        add_finding(
            findings, "high",
            "Sensitive information request detected",
            f"Detected sensitive terms: {', '.join(sensitive_hits)}",
            "Avoid sharing sensitive information through email links or replies.",
            mitre_id="T1566.001"
        )

    # URL and link findings
    if url_analysis["shorteners_detected"]:
        add_finding(
            findings, "medium",
            "URL shortener detected",
            f"Detected shortener domains: {', '.join(url_analysis['shorteners_detected'])}",
            "Expand and inspect shortened URLs safely before visiting."
        )

    if url_analysis["total_urls"] > 0:
        add_finding(
            findings, "info",
            "URLs found in email body",
            f"Detected {url_analysis['total_urls']} URL(s).",
            "Review all URLs and defang them before sharing in reports."
        )

    if link_mismatches:
        for m in link_mismatches[:5]:
            add_finding(
                findings, "high",
                "Link text/URL mismatch",
                f"Text says \"{m['display_text']}\" but links to {m['href_domain']} — may hide the real destination.",
                "Hover before clicking. If the visible text mentions one domain but the link goes elsewhere, it is likely a phishing attempt.",
                mitre_id="T1566.002"
            )

    if brand_hits:
        for b in brand_hits[:5]:
            add_finding(
                findings, "high",
                "Brand impersonation detected",
                f"Text mentions \"{b['brand']}\" but links to {b['actual_domain']}, not a legitimate {b['brand']} domain.",
                "Do not click. Legitimate brand emails link to their real domain. This is a strong phishing indicator.",
                mitre_id="T1566.002"
            )

    if has_html and not plain_text.strip():
        add_finding(
            findings, "medium",
            "HTML-only email with no readable text",
            "The email contains HTML markup but no significant visible text content.",
            "HTML-only emails with hidden text can be used to bypass text-based filters."
        )

    # Form detection
    if forms:
        for f in forms[:3]:
            add_finding(
                findings, "high",
                "Form in email body",
                f"Embedded form submits to {f['action_domain'] or '(same page)'}.",
                "Legitimate organizations do not embed login forms in email. This is credential harvesting.",
                mitre_id="T1566.001"
            )

    # Tracking images
    if tracking:
        add_finding(
            findings, "info",
            "Tracking pixels detected",
            f"Detected {len(tracking)} tracking image(s) — opens can be logged server-side.",
            "Disable remote image loading by default to prevent sender from knowing you opened the email."
        )

    # Unicode / zero-width attacks
    if zw_chars:
        add_finding(
            findings, "medium",
            "Zero-width Unicode characters detected",
            f"Found {len(zw_chars)} zero-width character type(s) — can hide text from scanners.",
            "Zero-width characters can bypass content filters and hide malicious text."
        )

    # Attachment findings
    risky_attachments = [
        item for item in attachments
        if item["risky_extension"] or item["double_extension"]
    ]

    if risky_attachments:
        add_finding(
            findings, "high",
            "Risky attachment indicator detected",
            f"Detected risky attachment names: {', '.join(item['filename'] for item in risky_attachments)}",
            "Do not open attachments. Hash and analyze them in a safe malware-analysis workflow.",
            mitre_id="T1566.001"
        )

    score = score_findings(findings)

    if score >= 80:
        rating = "Low Risk"
    elif score >= 55:
        rating = "Suspicious"
    else:
        rating = "High Risk"

    return {
        "summary": {"score": score, "rating": rating, "total_findings": len(findings)},
        "keyword_hits": {
            "urgency": urgency_hits,
            "credential": credential_hits,
            "payment": payment_hits,
            "sensitive": sensitive_hits,
        },
        "url_analysis": url_analysis,
        "link_mismatches": link_mismatches[:10],
        "brand_impersonation": brand_hits[:10],
        "forms_detected": forms,
        "tracking_images": tracking,
        "zero_width_chars": zw_chars,
        "has_html": has_html,
        "attachments": attachments,
        "iocs": iocs,
        "counts": ioc_result["counts"],
        "findings": findings,
        "defanged_body": defang_text(working_body),
    }
