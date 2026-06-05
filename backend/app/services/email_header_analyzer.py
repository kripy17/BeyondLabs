import re
from email.parser import Parser
from email.utils import parseaddr

RECEIVED_IP_RE = re.compile(
    r'\b(?:25[0-5]|2[0-4]\d|1?\d?\d)'
    r'(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b'
)


def get_domain_from_email(value: str):
    if not value:
        return None

    _, email_address = parseaddr(value)

    if "@" not in email_address:
        return None

    return email_address.split("@", 1)[1].lower()


def normalize_result(value: str):
    if not value:
        return "not_found"

    lowered = value.lower()

    if "pass" in lowered:
        return "pass"

    if "fail" in lowered:
        return "fail"

    if "softfail" in lowered:
        return "softfail"

    if "neutral" in lowered:
        return "neutral"

    if "none" in lowered:
        return "none"

    return "unknown"


def extract_auth_results(headers):
    auth_headers = headers.get_all("Authentication-Results", [])
    combined = " ".join(auth_headers)

    spf_match = re.search(r'spf=(\w+)', combined, re.IGNORECASE)
    dkim_match = re.search(r'dkim=(\w+)', combined, re.IGNORECASE)
    dmarc_match = re.search(r'dmarc=(\w+)', combined, re.IGNORECASE)

    return {
        "raw": auth_headers,
        "spf": normalize_result(spf_match.group(1)) if spf_match else "not_found",
        "dkim": normalize_result(dkim_match.group(1)) if dkim_match else "not_found",
        "dmarc": normalize_result(dmarc_match.group(1)) if dmarc_match else "not_found",
    }


def extract_received_chain(headers):
    received_headers = headers.get_all("Received", [])
    hops = []

    for index, received in enumerate(received_headers, start=1):
        ips = RECEIVED_IP_RE.findall(received)

        hops.append({
            "hop": index,
            "raw": received,
            "ips": sorted(set(ips)),
        })

    return hops


def add_finding(findings, severity, title, detail, recommendation):
    findings.append({
        "severity": severity,
        "title": title,
        "detail": detail,
        "recommendation": recommendation,
    })


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


def analyze_email_headers(raw_headers: str):
    headers = Parser().parsestr(raw_headers)

    from_value = headers.get("From")
    reply_to = headers.get("Reply-To")
    return_path = headers.get("Return-Path")
    message_id = headers.get("Message-ID")
    subject = headers.get("Subject")
    date = headers.get("Date")
    user_agent = headers.get("User-Agent") or headers.get("X-Mailer")

    from_domain = get_domain_from_email(from_value)
    reply_to_domain = get_domain_from_email(reply_to)
    return_path_domain = get_domain_from_email(return_path)

    auth = extract_auth_results(headers)
    received_chain = extract_received_chain(headers)

    findings = []

    if not from_value:
        add_finding(
            findings,
            "medium",
            "Missing From header",
            "The email does not contain a clear From header.",
            "Treat this as suspicious and verify the source manually."
        )

    if reply_to_domain and from_domain and reply_to_domain != from_domain:
        add_finding(
            findings,
            "medium",
            "Reply-To domain mismatch",
            f"From domain is {from_domain}, but Reply-To domain is {reply_to_domain}.",
            "Verify whether replies are being redirected to an unrelated domain."
        )

    if return_path_domain and from_domain and return_path_domain != from_domain:
        add_finding(
            findings,
            "low",
            "Return-Path domain differs from From domain",
            f"From domain is {from_domain}, but Return-Path domain is {return_path_domain}.",
            "Check whether this is expected for the sender's email infrastructure."
        )

    if auth["spf"] in ["fail", "softfail"]:
        add_finding(
            findings,
            "high",
            "SPF failed",
            f"SPF result is {auth['spf']}.",
            "Treat the sender as suspicious unless other trusted evidence confirms legitimacy."
        )
    elif auth["spf"] == "not_found":
        add_finding(
            findings,
            "info",
            "SPF result not found",
            "No SPF result was found in Authentication-Results.",
            "Check full headers or validate sender domain DNS manually."
        )

    if auth["dkim"] == "fail":
        add_finding(
            findings,
            "high",
            "DKIM failed",
            "DKIM authentication failed.",
            "Treat the message as suspicious and inspect sender authenticity."
        )
    elif auth["dkim"] == "not_found":
        add_finding(
            findings,
            "info",
            "DKIM result not found",
            "No DKIM result was found in Authentication-Results.",
            "Check whether the sender normally signs messages with DKIM."
        )

    if auth["dmarc"] == "fail":
        add_finding(
            findings,
            "high",
            "DMARC failed",
            "DMARC authentication failed.",
            "This is a strong phishing/spoofing indicator."
        )
    elif auth["dmarc"] == "not_found":
        add_finding(
            findings,
            "info",
            "DMARC result not found",
            "No DMARC result was found in Authentication-Results.",
            "Check the sender domain's DMARC policy manually."
        )

    if not message_id:
        add_finding(
            findings,
            "low",
            "Missing Message-ID",
            "The email does not contain a Message-ID header.",
            "Some legitimate systems omit it, but missing Message-ID can be suspicious."
        )

    if len(received_chain) == 0:
        add_finding(
            findings,
            "medium",
            "No Received headers found",
            "No mail routing chain was detected.",
            "Analyze the full raw email source if available."
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
        "headers": {
            "from": from_value,
            "reply_to": reply_to,
            "return_path": return_path,
            "subject": subject,
            "date": date,
            "message_id": message_id,
            "user_agent": user_agent,
        },
        "domains": {
            "from_domain": from_domain,
            "reply_to_domain": reply_to_domain,
            "return_path_domain": return_path_domain,
        },
        "authentication": auth,
        "received_chain": received_chain,
        "findings": findings,
    }
