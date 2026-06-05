import re
from datetime import datetime

IPV4_RE = re.compile(
    r'\b(?:25[0-5]|2[0-4]\d|1?\d?\d)'
    r'(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b'
)

EMAIL_RE = re.compile(
    r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'
)

URL_RE = re.compile(r'\bhttps?://[^\s<>"\']+', re.IGNORECASE)

LINUX_AUTH_RE = re.compile(
    r'(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+(?P<process>[\w\-/]+)(?:\[\d+\])?:\s+(?P<message>.*)'
)

WEB_LOG_RE = re.compile(
    r'(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<protocol>[^"]+)"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)'
)


SUSPICIOUS_LOG_PATTERNS = {
    "failed_login": ["failed password", "authentication failure", "invalid user", "login failed"],
    "bruteforce": ["too many authentication failures", "maximum authentication attempts"],
    "privilege": ["sudo", "su:", "root"],
    "web_attack": ["../", "union select", "<script", "cmd=", "powershell", "/etc/passwd", "wp-admin"],
    "scanner": ["nmap", "nikto", "sqlmap", "masscan", "zap"],
    "malware": ["mimikatz", "cobalt", "beacon", "meterpreter", "ransom"],
}


def unique_sorted(items):
    return sorted(set(item for item in items if item))


def parse_logs(text: str) -> dict:
    lines = text.splitlines()
    parsed_entries = []
    findings = []

    all_ips = IPV4_RE.findall(text)
    all_emails = EMAIL_RE.findall(text)
    all_urls = URL_RE.findall(text)

    pattern_hits = {}

    lowered = text.lower()
    for category, keywords in SUSPICIOUS_LOG_PATTERNS.items():
        hits = [keyword for keyword in keywords if keyword in lowered]
        if hits:
            pattern_hits[category] = hits
            findings.append({
                "severity": "medium" if category not in ["web_attack", "malware"] else "high",
                "title": f"{category.replace('_', ' ').title()} indicators found",
                "detail": f"Matched: {', '.join(hits)}",
                "recommendation": "Review matching log lines and correlate with user, source IP, and timeline."
            })

    for line in lines[:300]:
        linux_match = LINUX_AUTH_RE.search(line)
        web_match = WEB_LOG_RE.search(line)

        if linux_match:
            data = linux_match.groupdict()
            parsed_entries.append({
                "type": "linux_auth",
                "raw": line,
                "host": data.get("host"),
                "process": data.get("process"),
                "message": data.get("message"),
                "ips": unique_sorted(IPV4_RE.findall(line)),
            })
            continue

        if web_match:
            data = web_match.groupdict()
            status = int(data.get("status", 0))

            parsed_entries.append({
                "type": "web_access",
                "raw": line,
                "source_ip": data.get("ip"),
                "timestamp": data.get("timestamp"),
                "method": data.get("method"),
                "path": data.get("path"),
                "status": status,
                "size": data.get("size"),
            })
            continue

        if line.strip():
            parsed_entries.append({
                "type": "generic",
                "raw": line,
                "ips": unique_sorted(IPV4_RE.findall(line)),
            })

    return {
        "summary": {
            "total_lines": len(lines),
            "parsed_entries": len(parsed_entries),
            "unique_ips": len(unique_sorted(all_ips)),
            "unique_emails": len(unique_sorted(all_emails)),
            "unique_urls": len(unique_sorted(all_urls)),
            "total_findings": len(findings),
        },
        "extracted": {
            "ips": unique_sorted(all_ips),
            "emails": unique_sorted(all_emails),
            "urls": unique_sorted(all_urls),
        },
        "pattern_hits": pattern_hits,
        "findings": findings,
        "entries": parsed_entries,
    }


def parse_user_agent(user_agent: str) -> dict:
    ua = user_agent.strip()
    lowered = ua.lower()

    browser = "Unknown"
    os = "Unknown"
    device = "Desktop/Unknown"
    flags = []

    if "firefox" in lowered:
        browser = "Firefox"
    elif "edg/" in lowered or "edge/" in lowered:
        browser = "Microsoft Edge"
    elif "chrome" in lowered and "chromium" not in lowered:
        browser = "Chrome"
    elif "safari" in lowered and "chrome" not in lowered:
        browser = "Safari"
    elif "curl" in lowered:
        browser = "curl"
        flags.append("Command-line client")
    elif "python-requests" in lowered:
        browser = "python-requests"
        flags.append("Scripted HTTP client")
    elif "wget" in lowered:
        browser = "wget"
        flags.append("Command-line client")

    if "windows" in lowered:
        os = "Windows"
    elif "linux" in lowered:
        os = "Linux"
    elif "android" in lowered:
        os = "Android"
        device = "Mobile"
    elif "iphone" in lowered or "ios" in lowered:
        os = "iOS"
        device = "Mobile"
    elif "mac os" in lowered or "macintosh" in lowered:
        os = "macOS"

    if "bot" in lowered or "crawler" in lowered or "spider" in lowered:
        flags.append("Bot/crawler indicator")

    if "sqlmap" in lowered or "nikto" in lowered or "nmap" in lowered:
        flags.append("Security scanner indicator")

    return {
        "input": ua,
        "browser_or_client": browser,
        "os": os,
        "device": device,
        "flags": flags,
        "suspicious": bool(flags),
    }


def triage_alert(title: str, description: str = "", raw_log: str = "") -> dict:
    combined = f"{title}\n{description}\n{raw_log}".lower()

    categories = {
        "phishing": ["phishing", "spoof", "reply-to", "dmarc", "credential", "email"],
        "malware": ["malware", "trojan", "ransom", "mimikatz", "beacon", "payload"],
        "suspicious_login": ["login", "failed password", "impossible travel", "mfa", "invalid user"],
        "web_attack": ["sql injection", "xss", "path traversal", "../", "union select", "web attack"],
        "data_exfiltration": ["exfil", "large upload", "data transfer", "unusual download"],
        "recon_scanning": ["scan", "nmap", "masscan", "nikto", "enumeration"],
    }

    matched_categories = []

    for category, keywords in categories.items():
        hits = [keyword for keyword in keywords if keyword in combined]
        if hits:
            matched_categories.append({
                "category": category,
                "matched_keywords": hits,
            })

    severity = "low"

    high_words = ["ransom", "mimikatz", "exfil", "critical", "domain admin", "credential theft"]
    medium_words = ["failed", "suspicious", "malware", "phishing", "bruteforce", "scanner"]

    if any(word in combined for word in high_words):
        severity = "high"
    elif any(word in combined for word in medium_words):
        severity = "medium"

    steps = [
        "Preserve original alert details and timestamps.",
        "Identify affected user, host, source IP, and destination.",
        "Extract IOCs from logs and related evidence.",
        "Check whether similar alerts exist in the same time window.",
        "Decide containment action based on confidence and impact.",
    ]

    if matched_categories:
        main_category = matched_categories[0]["category"]
    else:
        main_category = "unknown"

    if main_category == "phishing":
        steps.extend([
            "Analyze email headers, body, URLs, and attachments.",
            "Defang suspicious URLs before sharing.",
            "Search for similar emails across mailboxes.",
        ])
    elif main_category == "malware":
        steps.extend([
            "Collect file hash, path, process tree, and network connections.",
            "Isolate endpoint if active compromise is suspected.",
            "Hunt for the same hash or process across endpoints.",
        ])
    elif main_category == "suspicious_login":
        steps.extend([
            "Check MFA result, source IP, ASN, and impossible travel.",
            "Review post-login activity.",
            "Reset password and revoke sessions if compromise is suspected.",
        ])
    elif main_category == "web_attack":
        steps.extend([
            "Review request path, payload, response status, and source IP.",
            "Check whether exploitation was successful.",
            "Consider WAF/blocking rules if malicious.",
        ])

    return {
        "title": title,
        "detected_category": main_category,
        "severity_suggestion": severity,
        "matched_categories": matched_categories,
        "recommended_steps": steps,
        "report_notes": {
            "summary": f"Alert categorized as {main_category} with suggested severity {severity}.",
            "generated_at_utc": datetime.utcnow().isoformat(),
        }
    }
