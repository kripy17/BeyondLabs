from app.services.email_body_analyzer import analyze_email_body
from app.services.email_header_analyzer import analyze_email_headers


def finding_with_source(source: str, finding: dict) -> dict:
    copied = dict(finding)
    copied["source"] = source
    return copied


def calculate_combined_score(header_result: dict | None, body_result: dict | None) -> int:
    scores = []
    weights = []

    if header_result:
        h_score = header_result.get("summary", {}).get("score", 100)
        h_findings = len(header_result.get("findings", []))
        scores.append(h_score)
        weights.append(1.0 + 0.1 * h_findings)

    if body_result:
        b_score = body_result.get("summary", {}).get("score", 100)
        b_findings = len(body_result.get("findings", []))
        scores.append(b_score)
        weights.append(1.0 + 0.15 * b_findings)

    if not scores:
        return 100

    # Weighted average, biased toward worst score
    weighted = sum(s * w for s, w in zip(scores, weights))
    total_weight = sum(weights)
    avg = weighted / total_weight if total_weight else 0

    # Bias toward worst (min) score by averaging min and weighted
    return int((min(scores) + avg) / 2)


def get_rating(score: int, findings: list[dict]) -> str:
    severities = [finding.get("severity") for finding in findings]
    if "high" in severities:
        return "High Risk"
    if score >= 80:
        return "Low Risk"
    if score >= 55:
        return "Suspicious"
    return "High Risk"


def collect_iocs(body_result: dict | None) -> dict:
    if not body_result:
        return {
            "urls": [],
            "domains": [],
            "ipv4": [],
            "ipv6": [],
            "emails": [],
            "hashes": {
                "md5": [],
                "sha1": [],
                "sha256": [],
                "sha512": [],
                "unknown": [],
            },
            "cves": [],
        }

    return body_result.get("iocs", {})


def build_markdown_report(summary: dict, header_result: dict | None, body_result: dict | None, findings: list[dict], iocs: dict) -> str:
    lines = []

    lines.append("# BeyondArch Phishing Analysis Report")
    lines.append("")
    lines.append("## Summary")
    lines.append(f"- Score: {summary.get('score')}")
    lines.append(f"- Rating: {summary.get('rating')}")
    lines.append(f"- Total Findings: {summary.get('total_findings')}")
    lines.append(f"- Header Findings: {summary.get('header_findings', 0)}")
    lines.append(f"- Body Findings: {summary.get('body_findings', 0)}")
    lines.append("")

    if header_result:
        headers = header_result.get("headers", {})
        domains = header_result.get("domains", {})
        auth = header_result.get("authentication", {})

        lines.append("## Header Overview")
        lines.append(f"- From: {headers.get('from')}")
        lines.append(f"- Display Name: {headers.get('from_display_name', 'N/A')}")
        lines.append(f"- Reply-To: {headers.get('reply_to')}")
        lines.append(f"- Return-Path: {headers.get('return_path')}")
        lines.append(f"- Subject: {headers.get('subject')}")
        lines.append(f"- From Domain: {domains.get('from_domain')}")
        lines.append(f"- Reply-To Domain: {domains.get('reply_to_domain')}")
        lines.append(f"- Return-Path Domain: {domains.get('return_path_domain')}")
        lines.append(f"- SPF: {auth.get('spf')}")
        lines.append(f"- DKIM: {auth.get('dkim')} (selector: {auth.get('dkim_selector', 'N/A')})")
        lines.append(f"- DMARC: {auth.get('dmarc')} (policy: {auth.get('dmarc_policy', 'N/A')})")
        lines.append(f"- ARC Present: {header_result.get('arc', {}).get('present', False)}")
        lines.append("")

    if body_result:
        keyword_hits = body_result.get("keyword_hits", {})
        url_analysis = body_result.get("url_analysis", {})

        lines.append("## Body Overview")
        lines.append(f"- HTML Content: {'Yes' if body_result.get('has_html') else 'No'}")
        lines.append(f"- URLs Found: {url_analysis.get('total_urls')}")
        lines.append(f"- URL Shorteners: {', '.join(url_analysis.get('shorteners_detected', [])) or 'None'}")
        lines.append(f"- Link/URL Mismatches: {len(body_result.get('link_mismatches', []))}")
        lines.append(f"- Brand Impersonations: {len(body_result.get('brand_impersonation', []))}")
        lines.append(f"- Forms Embedded: {len(body_result.get('forms_detected', []))}")
        lines.append(f"- Tracking Images: {len(body_result.get('tracking_images', []))}")
        lines.append(f"- Urgency Keywords: {', '.join(keyword_hits.get('urgency', [])) or 'None'}")
        lines.append(f"- Credential Keywords: {', '.join(keyword_hits.get('credential', [])) or 'None'}")
        lines.append(f"- Payment Keywords: {', '.join(keyword_hits.get('payment', [])) or 'None'}")
        lines.append("")

    lines.append("## Findings")

    if findings:
        for finding in findings:
            mitre = f" [{finding.get('mitre_id')}]" if finding.get("mitre_id") else ""
            lines.append(f"- [{finding.get('severity', 'info').upper()}]{mitre} ({finding.get('source')}) {finding.get('title')}: {finding.get('detail')}")
    else:
        lines.append("- No suspicious findings detected.")

    lines.append("")
    lines.append("## Extracted IOCs")
    lines.append(f"- URLs: {', '.join(iocs.get('urls', [])) or 'None'}")
    lines.append(f"- Domains: {', '.join(iocs.get('domains', [])) or 'None'}")
    lines.append(f"- IPv4: {', '.join(iocs.get('ipv4', [])) or 'None'}")
    lines.append(f"- IPv6: {', '.join(iocs.get('ipv6', [])) or 'None'}")
    lines.append(f"- Emails: {', '.join(iocs.get('emails', [])) or 'None'}")
    lines.append(f"- CVEs: {', '.join(iocs.get('cves', [])) or 'None'}")
    lines.append(f"- MD5 Hashes: {len(iocs.get('hashes', {}).get('md5', []))}")
    lines.append(f"- SHA256 Hashes: {len(iocs.get('hashes', {}).get('sha256', []))}")
    lines.append("")

    lines.append("## Recommended Analyst Actions")
    lines.append("- Verify sender identity using a trusted channel.")
    lines.append("- Do not click links directly from the email.")
    lines.append("- Defang URLs before sharing evidence.")
    lines.append("- Check extracted IOCs in approved reputation tools.")
    lines.append("- Preserve original email headers and body as evidence.")

    return "\n".join(lines)


def collect_body_signals(body_result: dict | None) -> dict:
    if not body_result:
        return {}
    return {
        "has_html": body_result.get("has_html", False),
        "link_mismatches": body_result.get("link_mismatches", []),
        "brand_impersonation": body_result.get("brand_impersonation", []),
        "forms_detected": body_result.get("forms_detected", []),
        "tracking_images": body_result.get("tracking_images", []),
        "zero_width_chars": body_result.get("zero_width_chars", []),
    }


def analyze_full_email(headers: str = "", body: str = "", refang_first: bool = True) -> dict:
    header_result = None
    body_result = None

    if headers and headers.strip():
        header_result = analyze_email_headers(headers)

    if body and body.strip():
        body_result = analyze_email_body(body, refang_first=refang_first)

    findings = []

    if header_result:
        findings.extend([
            finding_with_source("headers", finding)
            for finding in header_result.get("findings", [])
        ])

    if body_result:
        findings.extend([
            finding_with_source("body", finding)
            for finding in body_result.get("findings", [])
        ])

    score = calculate_combined_score(header_result, body_result)
    rating = get_rating(score, findings)
    iocs = collect_iocs(body_result)

    summary = {
        "score": score,
        "rating": rating,
        "total_findings": len(findings),
        "header_findings": len(header_result.get("findings", [])) if header_result else 0,
        "body_findings": len(body_result.get("findings", [])) if body_result else 0,
    }

    report_markdown = build_markdown_report(
        summary=summary,
        header_result=header_result,
        body_result=body_result,
        findings=findings,
        iocs=iocs,
    )

    return {
        "summary": summary,
        "header_analysis": header_result,
        "body_analysis": body_result,
        "body_signals": collect_body_signals(body_result),
        "combined_findings": findings,
        "iocs": iocs,
        "report_markdown": report_markdown,
    }
