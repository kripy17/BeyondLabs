import re

from app.services.ioc_extractor import defang_text, extract_iocs, refang_text

URGENCY_KEYWORDS = [
    "urgent", "immediately", "action required", "verify now", "expires today",
    "account locked", "suspended", "limited time", "final warning", "security alert",
]

CREDENTIAL_KEYWORDS = [
    "password", "login", "sign in", "verify your account", "confirm your account",
    "update your credentials", "reset your password", "authentication required",
]

PAYMENT_KEYWORDS = [
    "invoice", "payment", "bank", "wire transfer", "refund", "billing",
    "purchase order", "crypto", "wallet", "transaction",
]

SENSITIVE_KEYWORDS = [
    "ssn", "aadhaar", "pan card", "passport", "credit card", "otp",
    "one time password", "2fa", "mfa code",
]

URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "cutt.ly", "rebrand.ly", "shorturl.at", "s.id",
]

RISKY_EXTENSIONS = [
    ".exe", ".scr", ".bat", ".cmd", ".js", ".jse", ".vbs", ".vbe",
    ".ps1", ".jar", ".msi", ".hta", ".lnk", ".iso", ".img",
    ".docm", ".xlsm", ".pptm",
]

ATTACHMENT_RE = re.compile(
    r'\b[\w\-. ]+\.(?:exe|scr|bat|cmd|js|jse|vbs|vbe|ps1|jar|msi|hta|lnk|iso|img|docm|xlsm|pptm|zip|rar|7z|pdf|docx|xlsx)\b',
    re.IGNORECASE,
)

HTML_HREF_RE = re.compile(
    r'href=["\']([^"\']+)["\']',
    re.IGNORECASE,
)


def add_finding(findings, severity, title, detail, recommendation):
    findings.append({
        "severity": severity,
        "title": title,
        "detail": detail,
        "recommendation": recommendation,
    })


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


def analyze_urls(iocs: dict, body: str) -> dict:
    urls = iocs.get("urls", [])
    domains = iocs.get("domains", [])

    shortener_hits = [
        domain for domain in domains
        if domain.lower() in URL_SHORTENERS
    ]

    hrefs = HTML_HREF_RE.findall(body)

    return {
        "total_urls": len(urls),
        "urls": urls,
        "html_hrefs": hrefs,
        "shorteners_detected": sorted(set(shortener_hits)),
    }


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

    urgency_hits = find_keywords(working_body, URGENCY_KEYWORDS)
    credential_hits = find_keywords(working_body, CREDENTIAL_KEYWORDS)
    payment_hits = find_keywords(working_body, PAYMENT_KEYWORDS)
    sensitive_hits = find_keywords(working_body, SENSITIVE_KEYWORDS)

    attachments = detect_attachments(working_body)
    url_analysis = analyze_urls(iocs, working_body)

    findings = []

    if urgency_hits:
        add_finding(
            findings,
            "medium",
            "Urgency language detected",
            f"Detected urgency keywords: {', '.join(urgency_hits)}",
            "Treat urgency-based requests carefully and verify through a trusted channel."
        )

    if credential_hits:
        add_finding(
            findings,
            "high",
            "Credential-harvesting language detected",
            f"Detected credential-related phrases: {', '.join(credential_hits)}",
            "Do not enter credentials through links in the email. Verify the destination manually."
        )

    if payment_hits:
        add_finding(
            findings,
            "medium",
            "Payment or finance language detected",
            f"Detected finance-related terms: {', '.join(payment_hits)}",
            "Verify payment requests using an independent trusted contact method."
        )

    if sensitive_hits:
        add_finding(
            findings,
            "high",
            "Sensitive information request detected",
            f"Detected sensitive terms: {', '.join(sensitive_hits)}",
            "Avoid sharing sensitive information through email links or replies."
        )

    if url_analysis["shorteners_detected"]:
        add_finding(
            findings,
            "medium",
            "URL shortener detected",
            f"Detected shortener domains: {', '.join(url_analysis['shorteners_detected'])}",
            "Expand and inspect shortened URLs safely before visiting."
        )

    if url_analysis["total_urls"] > 0:
        add_finding(
            findings,
            "info",
            "URLs found in email body",
            f"Detected {url_analysis['total_urls']} URL(s).",
            "Review all URLs and defang them before sharing in reports."
        )

    risky_attachments = [
        item for item in attachments
        if item["risky_extension"] or item["double_extension"]
    ]

    if risky_attachments:
        add_finding(
            findings,
            "high",
            "Risky attachment indicator detected",
            f"Detected risky attachment names: {', '.join(item['filename'] for item in risky_attachments)}",
            "Do not open attachments. Hash and analyze them in a safe malware-analysis workflow."
        )

    score = score_findings(findings)

    if score >= 80:
        rating = "Low Risk"
    elif score >= 55:
        rating = "Suspicious"
    else:
        rating = "High Risk"

    return {
        "summary": {
            "score": score,
            "rating": rating,
            "total_findings": len(findings),
        },
        "keyword_hits": {
            "urgency": urgency_hits,
            "credential": credential_hits,
            "payment": payment_hits,
            "sensitive": sensitive_hits,
        },
        "url_analysis": url_analysis,
        "attachments": attachments,
        "iocs": iocs,
        "counts": ioc_result["counts"],
        "findings": findings,
        "defanged_body": defang_text(working_body),
    }
