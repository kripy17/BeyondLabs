import socket
import ssl
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from urllib.parse import urlparse

import httpx

SECURITY_HEADERS = {
    "content-security-policy": ("Medium", "Content-Security-Policy header missing", "Add a CSP tuned to the application to reduce script-injection impact."),
    "strict-transport-security": ("Medium", "Strict-Transport-Security header missing", "Add HSTS after confirming HTTPS is stable for the target."),
    "x-frame-options": ("Low", "X-Frame-Options header missing", "Add X-Frame-Options or a CSP frame-ancestors policy where framing is not intended."),
    "x-content-type-options": ("Low", "X-Content-Type-Options header missing", "Add X-Content-Type-Options: nosniff."),
    "referrer-policy": ("Low", "Referrer-Policy header missing", "Add a Referrer-Policy that limits sensitive URL leakage."),
    "permissions-policy": ("Low", "Permissions-Policy header missing", "Restrict browser features that the app does not need."),
}

SENSITIVE_PATHS = ["/.env", "/.git/HEAD", "/backup.zip", "/server-status", "/admin/", "/login/"]
WEB_FILES = ["/robots.txt", "/sitemap.xml", "/security.txt"]


def _finding(title, severity, evidence, recommendation, source="authorized HTTP probe", limitation="Needs analyst review."):
    return {
        "title": title,
        "severity": severity,
        "evidence": evidence,
        "recommendation": recommendation,
        "source": source,
        "limitation": limitation,
    }


def _host_from_target(target: str) -> tuple[str, str]:
    value = target.strip()
    parsed = urlparse(value if "://" in value else f"https://{value}")
    host = parsed.hostname or value
    scheme = parsed.scheme if parsed.scheme in {"http", "https"} else "https"
    return host, scheme


def _risk(findings: list[dict]) -> str:
    severities = {item.get("severity", "").lower() for item in findings}
    if "high" in severities:
        return "high"
    if "medium" in severities:
        return "medium"
    return "low"


def _tls_certificate(hostname: str, port: int = 443) -> dict:
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=6) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as secure_sock:
                cert = secure_sock.getpeercert()

        sans = [value for key, value in cert.get("subjectAltName", []) if key.lower() == "dns"]
        issuer = {}
        subject = {}
        for row in cert.get("issuer", []):
            for key, value in row:
                issuer[key] = value
        for row in cert.get("subject", []):
            for key, value in row:
                subject[key] = value
        expiry = cert.get("notAfter")
        days_remaining = None
        if expiry:
            expiry_dt = parsedate_to_datetime(expiry)
            if expiry_dt.tzinfo is None:
                expiry_dt = expiry_dt.replace(tzinfo=timezone.utc)
            days_remaining = (expiry_dt - datetime.now(timezone.utc)).days

        return {
            "subject": subject,
            "issuer": issuer,
            "subject_alt_names": sans,
            "not_before": cert.get("notBefore"),
            "not_after": expiry,
            "days_remaining": days_remaining,
            "hostname_mismatch": False,
            "source": "authorized TLS handshake",
            "method": "Python ssl certificate inspection",
            "limitations": "Certificate chain validation uses the local trust store. No CT log or reputation lookup is performed.",
        }
    except Exception as exc:
        return {
            "error": str(exc),
            "hostname_mismatch": "match" in str(exc).lower() and "hostname" in str(exc).lower(),
            "source": "authorized TLS handshake",
            "method": "Python ssl certificate inspection",
            "limitations": "TLS inspection failed or target did not present a trusted certificate.",
        }


def _cookie_findings(headers: httpx.Headers) -> tuple[list[dict], list[dict]]:
    cookies = []
    findings = []
    for raw in headers.get_list("set-cookie"):
        name = raw.split("=", 1)[0].strip()
        lower = raw.lower()
        cookie = {
            "name": name,
            "secure": "secure" in lower,
            "httponly": "httponly" in lower,
            "samesite": "samesite=" in lower,
            "raw_preview": raw[:180],
        }
        cookies.append(cookie)
        if not cookie["secure"]:
            findings.append(_finding("Cookie missing Secure flag", "Low", name, "Set Secure on cookies that should only travel over HTTPS."))
        if not cookie["httponly"]:
            findings.append(_finding("Cookie missing HttpOnly flag", "Low", name, "Set HttpOnly for cookies that do not need JavaScript access."))
        if not cookie["samesite"]:
            findings.append(_finding("Cookie missing SameSite attribute", "Low", name, "Set SameSite=Lax or Strict where application flow allows."))
    return cookies, findings


def _cors_findings(headers: dict) -> list[dict]:
    findings = []
    origin = headers.get("access-control-allow-origin")
    credentials = headers.get("access-control-allow-credentials", "")
    if origin == "*":
        findings.append(_finding(
            "Wildcard CORS origin",
            "Medium",
            "Access-Control-Allow-Origin: *",
            "Review whether wildcard CORS is intended. Restrict allowed origins for sensitive APIs.",
            limitation="This is a needs-review configuration signal, not proof of vulnerability.",
        ))
    if origin and credentials.lower() == "true":
        findings.append(_finding(
            "CORS credentials enabled",
            "Medium",
            f"Origin={origin}; credentials=true",
            "Verify credentialed CORS is required and limited to trusted origins.",
            limitation="This is a needs-review configuration signal, not proof of vulnerability.",
        ))
    return findings


def _fetch_small(client: httpx.Client, url: str, method: str = "GET", max_preview: int = 1500) -> dict:
    try:
        response = client.request(method, url)
        return {
            "url": str(response.url),
            "status_code": response.status_code,
            "found": response.status_code < 400,
            "content_type": response.headers.get("content-type"),
            "preview": response.text[:max_preview] if method == "GET" else "",
        }
    except Exception as exc:
        return {"url": url, "found": False, "error": str(exc)}


def run_web_exposure_review(target: str, confirm_permission: bool, timeout_seconds: int = 8) -> dict:
    if not confirm_permission:
        raise ValueError("Authorization confirmation is required before live web checks.")

    host, scheme = _host_from_target(target)
    base_url = f"{scheme}://{host}"
    findings = []
    checked_at = datetime.now(timezone.utc).isoformat()
    timeout = max(2, min(timeout_seconds, 15))

    result = {
        "target": target,
        "host": host,
        "base_url": base_url,
        "checked_at": checked_at,
        "source": "authorized live checks",
        "method": "HTTP HEAD/GET metadata, TLS certificate inspection, small web-file previews, sensitive-path status checks",
        "limitations": "No JavaScript execution, no browser rendering, no authentication, no brute force, no exploit checks, no external reputation or CVE lookup.",
    }

    with httpx.Client(timeout=timeout, follow_redirects=True, headers={"User-Agent": "BeyondLabs-WebExposure/1.0"}) as client:
        try:
            response = client.head(base_url)
            if response.status_code in {405, 501}:
                response = client.get(base_url, headers={"Range": "bytes=0-0"})
            headers = {key.lower(): value for key, value in response.headers.items()}
            result["http"] = {
                "status_code": response.status_code,
                "final_url": str(response.url),
                "redirect_chain": [
                    {"status_code": hop.status_code, "url": str(hop.url), "location": hop.headers.get("location")}
                    for hop in response.history
                ],
                "server": response.headers.get("server"),
                "content_type": response.headers.get("content-type"),
                "headers": headers,
                "tech_hints": [value for value in [response.headers.get("server"), response.headers.get("x-powered-by")] if value],
            }

            if response.history:
                findings.append(_finding("Redirect chain present", "Informational", f"{len(response.history)} redirect hop(s)", "Review domain changes and HTTP-to-HTTPS behavior."))
            for header, (severity, title, recommendation) in SECURITY_HEADERS.items():
                if header not in headers:
                    findings.append(_finding(title, severity, header, recommendation))
            if response.headers.get("server"):
                findings.append(_finding("Server header exposed", "Informational", response.headers.get("server"), "Consider minimizing version disclosure where practical."))
            cookies, cookie_findings = _cookie_findings(response.headers)
            result["cookies"] = cookies
            findings.extend(cookie_findings)
            findings.extend(_cors_findings(headers))
        except Exception as exc:
            result["http"] = {"error": str(exc)}
            findings.append(_finding("HTTP check failed", "Medium", str(exc), "Verify host, scheme, DNS, firewall path, and authorization scope."))

        result["web_files"] = {path: _fetch_small(client, f"{base_url}{path}") for path in WEB_FILES}
        for path, data in result["web_files"].items():
            if data.get("found"):
                findings.append(_finding(f"{path} reachable", "Informational", data.get("url", path), "Review file content for operational clues and sensitive disclosure."))

        result["sensitive_paths"] = {path: _fetch_small(client, f"{base_url}{path}", method="HEAD") for path in SENSITIVE_PATHS}
        for path, data in result["sensitive_paths"].items():
            if data.get("status_code") in {200, 401, 403}:
                severity = "High" if path in {"/.env", "/.git/HEAD", "/backup.zip"} and data.get("status_code") == 200 else "Medium"
                findings.append(_finding(
                    f"Sensitive path responded: {path}",
                    severity,
                    f"{data.get('status_code')} at {data.get('url', path)}",
                    "Confirm whether this path should be reachable. Restrict, remove, or require authentication as appropriate.",
                    limitation="Status-only check. This does not verify exploitability or data exposure.",
                ))

    result["tls"] = _tls_certificate(host)
    tls = result["tls"]
    if tls.get("error"):
        findings.append(_finding("TLS certificate check needs review", "Medium", tls["error"], "Review certificate trust, hostname, and expiry manually."))
    elif tls.get("days_remaining") is not None:
        if tls["days_remaining"] < 0:
            findings.append(_finding("TLS certificate expired", "High", tls.get("not_after"), "Renew the certificate."))
        elif tls["days_remaining"] <= 30:
            findings.append(_finding("TLS certificate expires soon", "Medium", f"{tls['days_remaining']} day(s) remaining", "Renew before expiry."))

    result["findings"] = findings
    result["risk_level"] = _risk(findings)
    result["summary"] = {
        "finding_count": len(findings),
        "risk_level": result["risk_level"],
        "http_status": result.get("http", {}).get("status_code"),
        "redirect_hops": len(result.get("http", {}).get("redirect_chain", [])),
        "sensitive_paths_reviewed": len(SENSITIVE_PATHS),
    }
    return result
