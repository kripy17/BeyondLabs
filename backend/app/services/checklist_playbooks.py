from datetime import datetime, timezone

CHECKLISTS = {
    "phishing-investigation": {
        "title": "Phishing Investigation Checklist",
        "category": "Phishing",
        "severity_options": ["low", "medium", "high", "critical"],
        "steps": [
            {"id": "sender", "text": "Check From, Reply-To, and Return-Path addresses."},
            {"id": "auth", "text": "Review SPF, DKIM, and DMARC results."},
            {"id": "headers", "text": "Inspect Received headers and sending IPs."},
            {"id": "urls", "text": "Extract and defang all URLs."},
            {"id": "domain", "text": "Check sender domain and linked domains."},
            {"id": "attachments", "text": "Review attachment names, extensions, and hashes safely."},
            {"id": "language", "text": "Look for urgency, credential, payment, or sensitive-data requests."},
            {"id": "similar", "text": "Search for similar emails in the mailbox/SIEM."},
            {"id": "containment", "text": "Block malicious sender/domain/URL if confirmed."},
            {"id": "report", "text": "Document findings and analyst decision."},
        ],
    },
    "suspicious-login": {
        "title": "Suspicious Login Alert",
        "category": "SOC",
        "severity_options": ["low", "medium", "high", "critical"],
        "steps": [
            {"id": "user", "text": "Identify affected user/account."},
            {"id": "source_ip", "text": "Check source IP, ASN, geolocation, and reputation."},
            {"id": "time", "text": "Compare login time with normal user behavior."},
            {"id": "mfa", "text": "Check MFA result and push fatigue indicators."},
            {"id": "impossible_travel", "text": "Check impossible travel or unusual location."},
            {"id": "device", "text": "Review user-agent, device, and browser fingerprint."},
            {"id": "activity", "text": "Review post-login activity."},
            {"id": "reset", "text": "Reset password and revoke sessions if compromise is suspected."},
            {"id": "escalate", "text": "Escalate if confirmed compromise or lateral movement indicators exist."},
        ],
    },
    "malware-alert": {
        "title": "Malware Triage Checklist",
        "category": "Endpoint",
        "severity_options": ["medium", "high", "critical"],
        "steps": [
            {"id": "host", "text": "Identify affected host and user."},
            {"id": "file", "text": "Collect filename, path, hash, and detection name."},
            {"id": "process", "text": "Review process tree and parent process."},
            {"id": "network", "text": "Check network connections and contacted domains/IPs."},
            {"id": "persistence", "text": "Check persistence locations and scheduled tasks."},
            {"id": "isolate", "text": "Isolate endpoint if active compromise is suspected."},
            {"id": "scope", "text": "Search for the same hash/process/domain across environment."},
            {"id": "remediate", "text": "Remove/quarantine malware and verify cleanup."},
        ],
    },
    "log-analysis": {
        "title": "Log Analysis Checklist",
        "category": "Log Analysis",
        "severity_options": ["low", "medium", "high", "critical"],
        "steps": [
            {"id": "source", "text": "Identify log source, parser assumptions, and time window."},
            {"id": "normalize", "text": "Normalize key fields such as timestamp, user, source IP, action, status, and destination."},
            {"id": "filter", "text": "Document filters, query logic, and excluded noise."},
            {"id": "patterns", "text": "Look for spikes, repeated failures, rare users, unusual hosts, and suspicious paths or commands."},
            {"id": "correlate", "text": "Correlate notable events with related alerts, IOCs, users, hosts, and timelines."},
            {"id": "false_positive", "text": "Record likely benign explanations and false-positive conditions."},
            {"id": "limitations", "text": "Document missing logs, parsing gaps, timezone uncertainty, and retention limits."},
            {"id": "report", "text": "Save findings and add report-ready timeline entries."},
        ],
    },
    "pcap-review": {
        "title": "PCAP Review Checklist",
        "category": "Network",
        "severity_options": ["low", "medium", "high", "critical"],
        "steps": [
            {"id": "scope", "text": "Document capture source, time range, interface, and visibility limitations."},
            {"id": "protocols", "text": "Review protocol distribution, top talkers, conversations, and unusual ports."},
            {"id": "dns", "text": "Inspect DNS queries, NXDOMAIN bursts, suspicious domains, and repeated lookups."},
            {"id": "http", "text": "Review HTTP hosts, paths, methods, user-agents, status codes, and payload indicators."},
            {"id": "tls", "text": "Review TLS SNI, certificate subjects, and repeated encrypted destinations."},
            {"id": "beaconing", "text": "Look for periodic connections, low-volume callbacks, and repeated destination patterns."},
            {"id": "iocs", "text": "Extract and save IPs, domains, URLs, hashes, filenames, or protocol artifacts."},
            {"id": "limits", "text": "Document encryption, packet loss, capture filters, and lack of endpoint context."},
        ],
    },
    "ioc-enrichment": {
        "title": "IOC Enrichment Checklist",
        "category": "IOC",
        "severity_options": ["low", "medium", "high", "critical"],
        "steps": [
            {"id": "classify", "text": "Classify each IOC type and preserve original/defanged form."},
            {"id": "local", "text": "Run local deterministic checks before external enrichment."},
            {"id": "backend_only", "text": "Confirm the workflow is using BeyondLabs backend/local checks only."},
            {"id": "context", "text": "Record source tool, source event, first seen time, and related asset/user context."},
            {"id": "confidence", "text": "Assign confidence based on source quality, recency, corroboration, and limitations."},
            {"id": "contradictions", "text": "Document clean, unknown, stale, missing-provider, or conflicting reputation results."},
            {"id": "actions", "text": "Recommend block, monitor, allowlist, or escalate only when evidence supports it."},
            {"id": "save", "text": "Save report-ready findings with method, checked_at, and limitations."},
        ],
    },
    "report-quality": {
        "title": "Report Quality Checklist",
        "category": "Reporting",
        "severity_options": ["low", "medium", "high", "critical"],
        "steps": [
            {"id": "summary", "text": "Executive summary states what happened, impact, confidence, and current status."},
            {"id": "scope", "text": "Scope, time window, affected entities, and data sources are clear."},
            {"id": "evidence", "text": "Findings link back to evidence, tool output, logs, screenshots, or notes."},
            {"id": "timeline", "text": "Timeline entries include timestamps, source, and relevance."},
            {"id": "iocs", "text": "IOCs include type, source, method, checked_at, and confidence."},
            {"id": "limitations", "text": "Limitations and missing telemetry are explicit."},
            {"id": "wording", "text": "Strong wording is supported by evidence and confidence."},
            {"id": "recommendations", "text": "Recommendations are specific, actionable, and proportionate to the evidence."},
        ],
    },
    "web-attack": {
        "title": "Web Attack Alert",
        "category": "Web Security",
        "severity_options": ["low", "medium", "high", "critical"],
        "steps": [
            {"id": "request", "text": "Review request method, path, query, and payload."},
            {"id": "source", "text": "Check source IP and user-agent."},
            {"id": "attack_type", "text": "Identify SQLi, XSS, path traversal, RCE, or scanner behavior."},
            {"id": "response", "text": "Check HTTP response code and response size."},
            {"id": "auth", "text": "Determine whether the request hit authenticated functionality."},
            {"id": "impact", "text": "Look for successful exploitation indicators."},
            {"id": "block", "text": "Block/ratelimit source if malicious and policy allows."},
            {"id": "patch", "text": "Recommend patching or WAF rule tuning if needed."},
        ],
    },
    "incident-response": {
        "title": "Incident Response Checklist",
        "category": "IR",
        "severity_options": ["low", "medium", "high", "critical"],
        "steps": [
            {"id": "identify", "text": "Identify affected assets, users, and initial alert source."},
            {"id": "classify", "text": "Classify incident type and severity."},
            {"id": "preserve", "text": "Preserve logs, timestamps, screenshots, and original evidence."},
            {"id": "contain", "text": "Contain affected systems/accounts."},
            {"id": "eradicate", "text": "Remove malicious artifacts or unauthorized access."},
            {"id": "recover", "text": "Restore normal operations and monitor closely."},
            {"id": "notify", "text": "Notify stakeholders according to policy."},
            {"id": "lessons", "text": "Document lessons learned and preventive actions."},
        ],
    },
}


def list_checklists() -> list:
    return [
        {
            "id": checklist_id,
            "title": data["title"],
            "category": data["category"],
            "total_steps": len(data["steps"]),
        }
        for checklist_id, data in CHECKLISTS.items()
    ]


def get_checklist(checklist_id: str):
    checklist = CHECKLISTS.get(checklist_id)

    if not checklist:
        return None

    return {
        "id": checklist_id,
        **checklist,
    }


def build_checklist_report(checklist_id: str, checked_step_ids: list[str], severity: str, analyst: str, notes: str) -> dict:
    checklist = get_checklist(checklist_id)

    if not checklist:
        return {
            "error": "Checklist not found."
        }

    checked = set(checked_step_ids)

    completed_steps = [
        step for step in checklist["steps"]
        if step["id"] in checked
    ]

    pending_steps = [
        step for step in checklist["steps"]
        if step["id"] not in checked
    ]

    completion_percent = round((len(completed_steps) / len(checklist["steps"])) * 100, 2)

    timestamp = datetime.now(timezone.utc).isoformat()

    lines = [
        f"# BeyondLabs Checklist Report: {checklist['title']}",
        "",
        "## Summary",
        f"- Checklist ID: {checklist_id}",
        f"- Category: {checklist['category']}",
        f"- Severity: {severity}",
        f"- Analyst: {analyst or 'N/A'}",
        f"- Timestamp UTC: {timestamp}",
        f"- Completion: {completion_percent}%",
        "",
        "## Completed Steps",
    ]

    if completed_steps:
        for step in completed_steps:
            lines.append(f"- [x] {step['text']}")
    else:
        lines.append("- None")

    lines.append("")
    lines.append("## Pending Steps")

    if pending_steps:
        for step in pending_steps:
            lines.append(f"- [ ] {step['text']}")
    else:
        lines.append("- None")

    lines.append("")
    lines.append("## Analyst Notes")
    lines.append(notes or "N/A")

    return {
        "checklist_id": checklist_id,
        "title": checklist["title"],
        "severity": severity,
        "analyst": analyst,
        "timestamp_utc": timestamp,
        "completion_percent": completion_percent,
        "completed_steps": completed_steps,
        "pending_steps": pending_steps,
        "notes": notes,
        "report_markdown": "\n".join(lines),
    }
