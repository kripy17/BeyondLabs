from app.services.email_header_analyzer import analyze_email_headers
from app.services.email_body_analyzer import analyze_email_body


def finding_with_source(source: str, finding: dict) -> dict:
    copied = dict(finding)
    copied["source"] = source
    return copied


def calculate_combined_score(header_result: dict | None, body_result: dict | None) -> int:
    scores = []

    if header_result:
        scores.append(header_result.get("summary", {}).get("score", 100))

    if body_result:
        scores.append(body_result.get("summary", {}).get("score", 100))

    if not scores:
        return 100

    return min(scores)


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
    lines.append("")

    if header_result:
        headers = header_result.get("headers", {})
        domains = header_result.get("domains", {})
        auth = header_result.get("authentication", {})

        lines.append("## Header Overview")
        lines.append(f"- From: {headers.get('from')}")
        lines.append(f"- Reply-To: {headers.get('reply_to')}")
        lines.append(f"- Return-Path: {headers.get('return_path')}")
        lines.append(f"- Subject: {headers.get('subject')}")
        lines.append(f"- From Domain: {domains.get('from_domain')}")
        lines.append(f"- Reply-To Domain: {domains.get('reply_to_domain')}")
        lines.append(f"- Return-Path Domain: {domains.get('return_path_domain')}")
        lines.append(f"- SPF: {auth.get('spf')}")
        lines.append(f"- DKIM: {auth.get('dkim')}")
        lines.append(f"- DMARC: {auth.get('dmarc')}")
        lines.append("")

    if body_result:
        keyword_hits = body_result.get("keyword_hits", {})
        url_analysis = body_result.get("url_analysis", {})

        lines.append("## Body Overview")
        lines.append(f"- URLs Found: {url_analysis.get('total_urls')}")
        lines.append(f"- URL Shorteners: {', '.join(url_analysis.get('shorteners_detected', [])) or 'None'}")
        lines.append(f"- Urgency Keywords: {', '.join(keyword_hits.get('urgency', [])) or 'None'}")
        lines.append(f"- Credential Keywords: {', '.join(keyword_hits.get('credential', [])) or 'None'}")
        lines.append(f"- Payment Keywords: {', '.join(keyword_hits.get('payment', [])) or 'None'}")
        lines.append("")

    lines.append("## Findings")

    if findings:
        for finding in findings:
            lines.append(f"- [{finding.get('severity', 'info').upper()}] ({finding.get('source')}) {finding.get('title')}: {finding.get('detail')}")
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
    lines.append("")

    lines.append("## Recommended Analyst Actions")
    lines.append("- Verify sender identity using a trusted channel.")
    lines.append("- Do not click links directly from the email.")
    lines.append("- Defang URLs before sharing evidence.")
    lines.append("- Check extracted IOCs in approved reputation tools.")
    lines.append("- Preserve original email headers and body as evidence.")

    return "\n".join(lines)


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
        "combined_findings": findings,
        "iocs": iocs,
        "report_markdown": report_markdown,
    }
