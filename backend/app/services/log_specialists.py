import re
from collections import Counter, defaultdict
from datetime import datetime, timezone

IPV4_RE = re.compile(
    r'\b(?:25[0-5]|2[0-4]\d|1?\d?\d)'
    r'(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b'
)

LINUX_AUTH_RE = re.compile(
    r'(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+(?P<process>[\w\-/]+)(?:\[\d+\])?:\s+(?P<message>.*)'
)

WEB_LOG_RE = re.compile(
    r'(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<protocol>[^"]+)"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)(?:\s+"(?P<referrer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?'
)

WEB_ATTACK_PATTERNS = {
    "path_traversal": ["../", "..%2f", "%2e%2e", "/etc/passwd", "boot.ini"],
    "sqli": ["union select", "select%20", " or 1=1", "' or '1'='1", "information_schema"],
    "xss": ["<script", "%3cscript", "javascript:", "onerror=", "onload="],
    "command_injection": ["cmd=", "powershell", "wget ", "curl ", "bash -c", ";cat", "|id"],
    "wordpress_probe": ["wp-admin", "wp-login", "xmlrpc.php"],
    "scanner": ["sqlmap", "nikto", "nmap", "masscan", "dirbuster", "gobuster"],
}


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def unique(items):
    return sorted(set(item for item in items if item))


def severity_score(findings):
    score = 100
    for finding in findings:
        sev = finding.get("severity")
        if sev == "critical":
            score -= 40
        elif sev == "high":
            score -= 30
        elif sev == "medium":
            score -= 15
        elif sev == "low":
            score -= 7
    return max(score, 0)


def rating(score, findings):
    if any(f.get("severity") in ["critical", "high"] for f in findings):
        return "High Attention"
    if score >= 80:
        return "Low Signal"
    if score >= 55:
        return "Needs Review"
    return "High Attention"


def analyze_linux_auth_logs(text: str) -> dict:
    lines = [line for line in text.splitlines() if line.strip()]
    events = []
    findings = []

    failed_by_ip = Counter()
    failed_by_user = Counter()
    success_by_ip = Counter()
    invalid_users = Counter()
    sudo_users = Counter()
    root_attempts = 0

    for idx, line in enumerate(lines[:5000], start=1):
        match = LINUX_AUTH_RE.search(line)
        ips = IPV4_RE.findall(line)

        event = {
            "event_id": idx,
            "raw": line,
            "timestamp": None,
            "host": None,
            "process": None,
            "source_ip": ips[0] if ips else None,
            "user": None,
            "action": "unknown",
            "status": "unknown",
        }

        if match:
            data = match.groupdict()
            msg = data.get("message", "")
            msg_lower = msg.lower()

            event.update({
                "timestamp": f"{data.get('month')} {data.get('day')} {data.get('time')}",
                "host": data.get("host"),
                "process": data.get("process"),
            })

            user_match = re.search(r'(?:invalid user|for|user)\s+([A-Za-z0-9_.@-]+)', msg)
            if user_match:
                event["user"] = user_match.group(1)

            if "failed password" in msg_lower or "authentication failure" in msg_lower:
                event["action"] = "login"
                event["status"] = "failed"
                if event["source_ip"]:
                    failed_by_ip[event["source_ip"]] += 1
                if event["user"]:
                    failed_by_user[event["user"]] += 1

            if "accepted password" in msg_lower or "session opened" in msg_lower:
                event["action"] = "login"
                event["status"] = "success"
                if event["source_ip"]:
                    success_by_ip[event["source_ip"]] += 1

            if "invalid user" in msg_lower and event["user"]:
                invalid_users[event["user"]] += 1

            if "sudo" in msg_lower:
                event["action"] = "sudo"
                if event["user"]:
                    sudo_users[event["user"]] += 1

            if "root" in msg_lower:
                root_attempts += 1

        events.append(event)

    for ip, count in failed_by_ip.items():
        if count >= 5:
            findings.append({
                "severity": "high",
                "title": "Possible SSH brute force",
                "detail": f"{count} failed login attempts from {ip}.",
                "recommendation": "Review source IP, block if malicious, and check for successful login after failures.",
                "source_ip": ip,
            })

    for user, count in failed_by_user.items():
        if count >= 5:
            findings.append({
                "severity": "medium",
                "title": "Repeated failures against user",
                "detail": f"{count} failed login attempts targeted {user}.",
                "recommendation": "Check whether this user exists and whether a successful login followed.",
                "user": user,
            })

    if invalid_users:
        findings.append({
            "severity": "medium",
            "title": "Invalid user attempts detected",
            "detail": f"Top invalid users: {invalid_users.most_common(5)}",
            "recommendation": "Review for username enumeration or brute force attempts.",
        })

    if root_attempts:
        findings.append({
            "severity": "medium",
            "title": "Root-related activity detected",
            "detail": f"{root_attempts} log line(s) mention root.",
            "recommendation": "Review root login attempts and sudo activity.",
        })

    score = severity_score(findings)

    return {
        "summary": {
            "analyzed_at": utc_now(),
            "total_lines": len(lines),
            "events": len(events),
            "findings": len(findings),
            "score": score,
            "rating": rating(score, findings),
            "freshness": "user_supplied_log_batch",
            "confidence": "medium",
        },
        "metrics": {
            "top_failed_ips": failed_by_ip.most_common(10),
            "top_failed_users": failed_by_user.most_common(10),
            "top_success_ips": success_by_ip.most_common(10),
            "top_invalid_users": invalid_users.most_common(10),
            "sudo_users": sudo_users.most_common(10),
            "root_related_lines": root_attempts,
        },
        "findings": findings,
        "events": events[:1000],
        "limitations": [
            "Timestamp parsing is source-format dependent.",
            "Only the supplied log batch is analyzed.",
            "Findings are rule-based and should be analyst-reviewed."
        ],
    }


def analyze_web_access_logs(text: str) -> dict:
    lines = [line for line in text.splitlines() if line.strip()]
    events = []
    findings = []

    ips = Counter()
    paths = Counter()
    statuses = Counter()
    methods = Counter()
    user_agents = Counter()
    attacks = defaultdict(list)
    errors_by_ip = Counter()

    for idx, line in enumerate(lines[:5000], start=1):
        match = WEB_LOG_RE.search(line)
        lower = line.lower()

        event = {
            "event_id": idx,
            "raw": line,
            "parsed": False,
            "source_ip": None,
            "timestamp": None,
            "method": None,
            "path": None,
            "status": None,
            "size": None,
            "user_agent": None,
            "attack_indicators": [],
        }

        if match:
            data = match.groupdict()

            event.update({
                "parsed": True,
                "source_ip": data.get("ip"),
                "timestamp": data.get("timestamp"),
                "method": data.get("method"),
                "path": data.get("path"),
                "status": int(data.get("status")),
                "size": data.get("size"),
                "user_agent": data.get("user_agent"),
            })

            if event["source_ip"]:
                ips[event["source_ip"]] += 1
            if event["path"]:
                paths[event["path"]] += 1
            if event["status"]:
                statuses[str(event["status"])] += 1
            if event["method"]:
                methods[event["method"]] += 1
            if event["user_agent"]:
                user_agents[event["user_agent"]] += 1
            if event["status"] in [401, 403, 404, 500]:
                errors_by_ip[event["source_ip"]] += 1

        for category, patterns in WEB_ATTACK_PATTERNS.items():
            matched = [pattern for pattern in patterns if pattern in lower]
            if matched:
                event["attack_indicators"].append({
                    "category": category,
                    "matched": matched,
                })
                attacks[category].append({
                    "event_id": idx,
                    "source_ip": event["source_ip"],
                    "path": event["path"],
                    "matched": matched,
                })

        events.append(event)

    for category, items in attacks.items():
        sev = "high" if category in ["path_traversal", "sqli", "xss", "command_injection"] else "medium"
        findings.append({
            "severity": sev,
            "title": f"{category.replace('_', ' ').title()} indicators detected",
            "detail": f"{len(items)} event(s) matched this category.",
            "recommendation": "Review affected paths, source IPs, response status, and whether exploitation succeeded.",
            "samples": items[:5],
        })

    for ip, count in errors_by_ip.items():
        if count >= 10:
            findings.append({
                "severity": "medium",
                "title": "High error count from one IP",
                "detail": f"{ip} generated {count} 401/403/404/500 responses.",
                "recommendation": "Review for scanning, brute forcing, or directory enumeration.",
                "source_ip": ip,
            })

    score = severity_score(findings)

    return {
        "summary": {
            "analyzed_at": utc_now(),
            "total_lines": len(lines),
            "events": len(events),
            "findings": len(findings),
            "score": score,
            "rating": rating(score, findings),
            "freshness": "user_supplied_log_batch",
            "confidence": "medium",
        },
        "metrics": {
            "top_source_ips": ips.most_common(10),
            "top_paths": paths.most_common(10),
            "status_breakdown": dict(statuses),
            "method_breakdown": dict(methods),
            "top_user_agents": user_agents.most_common(10),
            "attack_categories": {k: len(v) for k, v in attacks.items()},
        },
        "findings": findings,
        "events": events[:1000],
        "limitations": [
            "Supports common access log formats.",
            "Findings are keyword/rule based.",
            "Manual review is needed to confirm exploitation."
        ],
    }
