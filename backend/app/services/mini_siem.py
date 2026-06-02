import json
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from urllib.parse import urlparse

IPV4_RE = re.compile(
    r'\b(?:25[0-5]|2[0-4]\d|1?\d?\d)'
    r'(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b'
)
EMAIL_RE = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b')
URL_RE = re.compile(r'\bhttps?://[^\s<>"\']+', re.IGNORECASE)
ISO_PREFIX_RE = re.compile(r'^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)\s+(?P<body>.*)$')
SYSLOG_RE = re.compile(
    r'^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+(?P<process>[\w\-/.]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<message>.*)$'
)
ISO_SYSLOG_RE = re.compile(
    r'^(?:(?P<source>\w+)\s+)?(?P<process>[\w\-/.]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<message>.*)$'
)
WEB_QUOTED_RE = re.compile(
    r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+\S+\s+\S+\s+'
    r'(?:\[(?P<bracket_time>[^\]]+)\]\s+)?"(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+(?P<protocol>[^"]+)"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)(?:\s+"(?P<referrer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?'
)
WINDOWS_EVENT_RE = re.compile(r'\b(?:EventID|Event\s+ID|event_id)[:= ]+(?P<event_id>\d{3,5})\b', re.IGNORECASE)
PROCESS_ARROW_RE = re.compile(r'(?P<parent>[\w.-]+\.exe)\s*(?:->|spawned|launched)\s*(?P<child>[\w.-]+\.exe)', re.IGNORECASE)
POWERSHELL_ENC_RE = re.compile(r'\b(?:EncodedCommand|-enc\b|-EncodedCommand\b)', re.IGNORECASE)
DOMAIN_RE = re.compile(r'(?<![@\w-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|co|edu|gov|in|dev|app|local)\b', re.IGNORECASE)

FAILED_LOGIN_WORDS = ["failed password", "authentication failure", "invalid user", "login failed", "failed login"]
SUCCESS_LOGIN_WORDS = ["accepted password", "session opened", "successful login", "login success"]
SCANNER_WORDS = ["sqlmap", "nikto", "nmap", "masscan", "zap", "acunetix", "gobuster", "ffuf", "dirbuster"]
WEB_PROBE_PATHS = ["/.env", "/wp-admin", "/backup", "/server-status", "/admin", "/login", "/.git", "/phpmyadmin"]
WEB_ATTACK_WORDS = ["../", "..%2f", "union select", "<script", "javascript:", "/etc/passwd", "cmd=", "xp_cmdshell"]
MALWARE_WORDS = ["mimikatz", "cobalt", "beacon", "meterpreter", "ransom", "keylogger"]
PRIORITY_ORDER = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def unique(items):
    return sorted(set(item for item in items if item))


def parse_timestamp(value):
    if not value:
        return None
    text = str(value).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(text).astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    except Exception:
        pass
    for fmt in ("%d/%b/%Y:%H:%M:%S %z", "%Y-%m-%d %H:%M:%S", "%b %d %H:%M:%S"):
        try:
            dt = datetime.strptime(text, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(year=datetime.now().year, tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
        except Exception:
            continue
    return value


def time_bucket(timestamp, precision="minute"):
    parsed = parse_timestamp(timestamp)
    if not parsed or "T" not in parsed:
        return "unknown"
    if precision == "hour":
        return parsed[:13] + ":00Z"
    return parsed[:16] + ":00Z"


def severity_from_event(event):
    lower = f"{event.get('raw','')} {event.get('event_type','')} {event.get('message','')}".lower()
    if any(word in lower for word in ["critical", "ransom", "mimikatz", "meterpreter", "cobalt", "os credential"]):
        return "critical"
    if any(word in lower for word in ["encodedcommand", "winword.exe -> powershell", "union select", "../", "..%2f", "/etc/passwd"]):
        return "high"
    if event.get("event_type") in {"ssh_failed_login", "invalid_user_login", "web_probe", "scanner_activity", "powershell_suspicious", "edr_process_chain"}:
        return "medium"
    if event.get("event_type") in {"ssh_success_login", "http_request"}:
        return "info"
    return "info"


def headline_for(event):
    etype = event.get("event_type")
    if etype == "ssh_failed_login":
        return f"SSH failed login for {event.get('user') or 'unknown user'} from {event.get('source_ip') or 'unknown source'}"
    if etype == "invalid_user_login":
        return f"SSH invalid-user login attempt for {event.get('user') or 'unknown user'}"
    if etype == "ssh_success_login":
        return f"SSH successful login for {event.get('user') or 'unknown user'} from {event.get('source_ip') or 'unknown source'}"
    if etype == "web_probe":
        return f"Web probing request to {event.get('uri_path') or event.get('path') or 'unknown path'} returned {event.get('status_code') or event.get('status') or 'unknown'}"
    if etype == "http_request":
        return f"HTTP {event.get('method') or ''} {event.get('uri_path') or event.get('path') or ''} returned {event.get('status_code') or event.get('status') or 'unknown'}".strip()
    if etype == "powershell_suspicious":
        return "Suspicious PowerShell command indicator observed"
    if etype == "edr_process_chain":
        return f"Suspicious process chain {event.get('parent_process') or 'parent'} → {event.get('process_name') or 'child'}"
    if etype == "scanner_activity":
        return "Scanner/tool keyword observed in log event"
    if event.get("message"):
        return str(event["message"])[:180]
    return "Generic log event"


def why_for(event):
    etype = event.get("event_type")
    if etype in {"ssh_failed_login", "invalid_user_login"}:
        return "Failed SSH authentication can indicate password guessing, exposed service probing, misconfiguration, or a mistyped user account. Volume and source context decide priority."
    if etype == "ssh_success_login":
        return "A successful login is not inherently malicious, but it becomes important when it follows failures or originates from an unusual source."
    if etype == "web_probe":
        return "Requests for administrative, backup, or hidden paths are common reconnaissance signals. Response status helps determine exposure."
    if etype == "powershell_suspicious":
        return "Encoded PowerShell is often used by administrators and attackers. It requires host, parent process, and command context review."
    if etype == "edr_process_chain":
        return "Office or script interpreters spawning shells can be a strong initial-access or execution signal. Confirm parent/child process lineage."
    if etype == "scanner_activity":
        return "Known scanner/tool strings may indicate authorized testing or hostile reconnaissance. Check ownership and change windows."
    return "This event was normalized from the submitted dataset. Review surrounding events and extracted fields before disposition."


def next_check_for(event):
    etype = event.get("event_type")
    if etype in {"ssh_failed_login", "invalid_user_login"}:
        return "Check count by source IP, targeted users, successful logins after failures, geolocation/reputation if allowed, and whether the host should expose SSH."
    if etype == "ssh_success_login":
        return "Validate expected user, source IP, MFA/session logs, and whether failures from the same source occurred earlier."
    if etype in {"web_probe", "http_request"}:
        return "Review request path, status code, user-agent, response body size, and whether the source repeated similar paths."
    if etype in {"powershell_suspicious", "edr_process_chain"}:
        return "Correlate process tree, script block logs, command line, user session, parent document, and network connections."
    return "Correlate timestamp, host, user, source IP, and adjacent events in the same dataset."


def extract_processes(text):
    return unique(re.findall(r'\b[a-zA-Z0-9_.-]+\.exe\b', text))


def extract_domains(text, urls):
    domains = set()
    for url in urls:
        try:
            host = urlparse(url).hostname
            if host:
                domains.add(host.lower())
        except Exception:
            pass
    for match in DOMAIN_RE.findall(text):
        lower = match.lower()
        # Avoid classifying process names and HTTP version fragments as domains.
        if lower.endswith(".exe") or re.match(r'^\d+\.\d+(?:\.\d+)?$', lower):
            continue
        domains.add(lower)
    return sorted(domains)


def base_event(line, index):
    ips = IPV4_RE.findall(line)
    emails = EMAIL_RE.findall(line)
    urls = URL_RE.findall(line)
    domains = extract_domains(line, urls)
    processes = extract_processes(line)
    return {
        "id": f"event-{index}",
        "event_id": index,
        "index": "main",
        "source": "pasted_logs",
        "sourcetype": "generic_text",
        "category": "generic",
        "event_type": "generic",
        "severity": "info",
        "timestamp": None,
        "time_bucket": "unknown",
        "host": None,
        "user": None,
        "source_ip": ips[0] if ips else None,
        "src_ip": ips[0] if ips else None,
        "destination_ip": None,
        "dest_ip": None,
        "destination_port": None,
        "dest_port": None,
        "process_name": processes[-1] if processes else None,
        "parent_process": None,
        "command_line": None,
        "method": None,
        "uri_path": None,
        "path": None,
        "status_code": None,
        "status": None,
        "outcome": None,
        "action": None,
        "user_agent": None,
        "message": line,
        "headline": None,
        "why_it_matters": None,
        "next_check": None,
        "mitre_candidates": [],
        "raw": line,
        "iocs": {"ips": unique(ips), "emails": unique(emails), "urls": unique(urls), "domains": domains},
    }


def enrich_event(event):
    event["severity"] = severity_from_event(event)
    event["headline"] = headline_for(event)
    event["why_it_matters"] = why_for(event)
    event["next_check"] = next_check_for(event)
    event["time_bucket"] = time_bucket(event.get("timestamp"))
    if event.get("event_type") in {"ssh_failed_login", "invalid_user_login", "ssh_success_login"}:
        event["mitre_candidates"] = ["T1110 Brute Force", "T1021.004 SSH"]
    elif event.get("event_type") in {"powershell_suspicious", "edr_process_chain"}:
        event["mitre_candidates"] = ["T1059.001 PowerShell", "T1204 User Execution"]
    elif event.get("event_type") in {"web_probe", "scanner_activity"}:
        event["mitre_candidates"] = ["T1595 Active Scanning", "T1592 Gather Victim Host Information"]
    return event


def parse_json_event(line, index):
    try:
        data = json.loads(line)
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    event = base_event(line, index)
    msg = data.get("message") or data.get("msg") or data.get("event") or line
    event.update({
        "source": data.get("source") or data.get("index") or "json_upload",
        "sourcetype": data.get("sourcetype") or data.get("event.module") or data.get("log_type") or "json",
        "timestamp": parse_timestamp(data.get("timestamp") or data.get("@timestamp") or data.get("time")),
        "host": data.get("host") or data.get("hostname") or data.get("agent", {}).get("hostname") if isinstance(data.get("agent"), dict) else data.get("host"),
        "source_ip": data.get("src_ip") or data.get("source_ip") or data.get("client_ip") or event.get("source_ip"),
        "src_ip": data.get("src_ip") or data.get("source_ip") or data.get("client_ip") or event.get("source_ip"),
        "destination_ip": data.get("dest_ip") or data.get("destination_ip"),
        "dest_ip": data.get("dest_ip") or data.get("destination_ip"),
        "user": data.get("user") or data.get("username") or data.get("user.name"),
        "process_name": data.get("process_name") or data.get("process", {}).get("name") if isinstance(data.get("process"), dict) else data.get("process_name"),
        "command_line": data.get("command_line") or data.get("process", {}).get("command_line") if isinstance(data.get("process"), dict) else data.get("command_line"),
        "message": msg,
        "raw": line,
    })
    lower = line.lower()
    if any(word in lower for word in FAILED_LOGIN_WORDS):
        event.update({"event_type": "ssh_failed_login", "category": "authentication", "action": "login", "outcome": "failure", "status": "failed", "sourcetype": event.get("sourcetype") or "linux_auth"})
    elif POWERSHELL_ENC_RE.search(line):
        event.update({"event_type": "powershell_suspicious", "category": "endpoint", "action": "process_execution", "sourcetype": "powershell"})
    else:
        event["event_type"] = data.get("event_type") or data.get("event.action") or "json_event"
        event["category"] = data.get("category") or data.get("event.category") or "json"
    return enrich_event(event)


def normalize_line(line: str, index: int) -> dict:
    original = line.rstrip("\n")
    json_event = parse_json_event(original, index)
    if json_event:
        return json_event

    event = base_event(original, index)
    working = original
    iso = ISO_PREFIX_RE.match(working)
    if iso:
        event["timestamp"] = parse_timestamp(iso.group("timestamp"))
        working = iso.group("body")

    web = WEB_QUOTED_RE.search(working)
    if web:
        data = web.groupdict()
        path = data.get("path")
        status_code = int(data.get("status")) if data.get("status") else None
        event.update({
            "source": "web",
            "sourcetype": "web_access",
            "category": "web",
            "event_type": "web_probe" if path and any(path.lower().startswith(p) for p in WEB_PROBE_PATHS) else "http_request",
            "timestamp": parse_timestamp(event.get("timestamp") or data.get("bracket_time")),
            "source_ip": data.get("ip"),
            "src_ip": data.get("ip"),
            "method": data.get("method"),
            "uri_path": path,
            "path": path,
            "status_code": status_code,
            "status": status_code,
            "action": "http_request",
            "outcome": "not_found" if status_code == 404 else ("success" if status_code and status_code < 400 else "error"),
            "user_agent": data.get("user_agent"),
            "message": f'{data.get("method")} {path} returned {status_code}',
        })
        return enrich_event(event)

    syslog = SYSLOG_RE.match(working)
    if syslog:
        data = syslog.groupdict()
        msg = data.get("message", "")
        event.update({
            "timestamp": parse_timestamp(event.get("timestamp") or f"{data.get('month')} {data.get('day')} {data.get('time')}"),
            "host": data.get("host"),
            "process_name": data.get("process"),
            "process": data.get("process"),
            "message": msg,
        })
        working_message = msg
    else:
        compact = ISO_SYSLOG_RE.match(working)
        if compact:
            data = compact.groupdict()
            event.update({
                "source": data.get("source") or event.get("source"),
                "process_name": data.get("process"),
                "process": data.get("process"),
                "message": data.get("message") or working,
            })
            working_message = data.get("message") or working
        else:
            working_message = working

    lower = original.lower()
    msg_lower = working_message.lower()

    invalid_user_match = re.search(r'invalid user\s+([A-Za-z0-9_.@-]+)', working_message, re.IGNORECASE)
    user_match = invalid_user_match or re.search(r'(?:for user|for|user)\s+([A-Za-z0-9_.@-]+)', working_message, re.IGNORECASE)
    if user_match:
        user = user_match.group(1)
        if user.lower() not in {"invalid", "user", "from"}:
            event["user"] = user

    port_match = re.search(r'\bport\s+(\d{1,5})\b', working_message, re.IGNORECASE)
    if port_match:
        event["destination_port"] = int(port_match.group(1))
        event["dest_port"] = int(port_match.group(1))

    process_chain = PROCESS_ARROW_RE.search(original)
    if process_chain:
        event.update({
            "source": "endpoint",
            "sourcetype": "edr_process",
            "category": "endpoint",
            "event_type": "edr_process_chain",
            "parent_process": process_chain.group("parent"),
            "process_name": process_chain.group("child"),
            "action": "process_spawn",
            "outcome": "observed",
        })
    elif POWERSHELL_ENC_RE.search(original) or "powershell" in lower:
        event.update({
            "source": "endpoint",
            "sourcetype": "powershell",
            "category": "endpoint",
            "event_type": "powershell_suspicious" if POWERSHELL_ENC_RE.search(original) else "powershell_activity",
            "process_name": "powershell.exe",
            "action": "process_execution",
            "outcome": "observed",
            "command_line": working_message,
        })
    elif any(word in msg_lower for word in FAILED_LOGIN_WORDS):
        event.update({
            "source": event.get("source") if event.get("source") != "pasted_logs" else "auth",
            "sourcetype": "linux_auth",
            "category": "authentication",
            "event_type": "invalid_user_login" if "invalid user" in msg_lower else "ssh_failed_login",
            "action": "login",
            "outcome": "failure",
            "status": "failed",
        })
    elif any(word in msg_lower for word in SUCCESS_LOGIN_WORDS):
        event.update({
            "source": event.get("source") if event.get("source") != "pasted_logs" else "auth",
            "sourcetype": "linux_auth",
            "category": "authentication",
            "event_type": "ssh_success_login",
            "action": "login",
            "outcome": "success",
            "status": "success",
        })
    elif any(word in lower for word in SCANNER_WORDS):
        event.update({"event_type": "scanner_activity", "category": "recon", "sourcetype": "scanner_indicator", "action": "tool_observed"})
    elif WINDOWS_EVENT_RE.search(original):
        event.update({"event_type": "windows_event", "category": "windows", "sourcetype": "windows_eventlog"})

    if event.get("event_type") == "generic" and event.get("source_ip") and "GET " in original:
        event.update({"event_type": "http_request", "category": "web", "sourcetype": "web_access"})

    return enrich_event(event)


def add_detection(detections, rule_id, title, severity, detail, matched_events, evidence, recommendation, mitre=None, confidence="medium"):
    detections.append({
        "rule_id": rule_id,
        "title": title,
        "severity": severity,
        "detail": detail,
        "matched_event_ids": [event.get("event_id") for event in matched_events],
        "matched_count": len(matched_events),
        "evidence": evidence,
        "recommendation": recommendation,
        "mitre_candidates": mitre or [],
        "confidence": confidence,
        "why_it_matters": detail,
        "next_check": recommendation,
        "generated_at": utc_now(),
    })


def detect_per_event(events):
    detections = []
    for event in events:
        lower = event.get("raw", "").lower()
        if event.get("event_type") in {"powershell_suspicious", "edr_process_chain"}:
            add_detection(
                detections,
                "ENDPOINT_SUSPICIOUS_EXECUTION",
                "Suspicious endpoint execution pattern",
                "high" if event.get("event_type") == "edr_process_chain" else "medium",
                "PowerShell encoding or a suspicious parent/child process chain was observed.",
                [event],
                {"host": event.get("host"), "user": event.get("user"), "process": event.get("process_name"), "raw": event.get("raw")},
                "Correlate process tree, user activity, script block logs, file origin, and outbound network connections.",
                ["T1059.001 PowerShell", "T1204 User Execution"],
                "high",
            )
        if event.get("event_type") == "web_probe" or any(path in lower for path in WEB_PROBE_PATHS):
            add_detection(
                detections,
                "WEB_SENSITIVE_PATH_PROBING",
                "Sensitive web path probing",
                "medium",
                "The request targeted administrative, backup, hidden, or commonly probed web paths.",
                [event],
                {"source_ip": event.get("source_ip"), "path": event.get("uri_path"), "status_code": event.get("status_code")},
                "Review whether the path exists, whether response status changed, and whether the source repeats probing behavior.",
                ["T1595 Active Scanning"],
                "medium",
            )
        if any(word in lower for word in WEB_ATTACK_WORDS):
            add_detection(
                detections,
                "WEB_ATTACK_PATTERN",
                "Web attack pattern detected",
                "high",
                "The log contains a common web attack or exploit-test pattern.",
                [event],
                {"source_ip": event.get("source_ip"), "path": event.get("uri_path"), "raw": event.get("raw")},
                "Review payload, response status, application logs, and whether exploitation succeeded.",
                ["T1190 Exploit Public-Facing Application"],
                "medium",
            )
        if any(word in lower for word in SCANNER_WORDS):
            add_detection(
                detections,
                "SCANNER_INDICATOR",
                "Scanner/tool indicator detected",
                "medium",
                "The event contains a known scanner/tool keyword. This can be authorized or hostile depending on scope.",
                [event],
                {"source_ip": event.get("source_ip"), "raw": event.get("raw")},
                "Confirm whether scanning was authorized and compare against approved testing windows.",
                ["T1595 Active Scanning"],
                "medium",
            )
    return detections


def detect_correlations(events):
    detections = []
    failed_by_ip = defaultdict(list)
    success_by_ip = defaultdict(list)
    web_404_by_ip = defaultdict(list)
    web_probe_by_ip = defaultdict(list)

    for event in events:
        ip = event.get("source_ip")
        if event.get("event_type") in {"ssh_failed_login", "invalid_user_login"} and ip:
            failed_by_ip[ip].append(event)
        if event.get("event_type") == "ssh_success_login" and ip:
            success_by_ip[ip].append(event)
        if event.get("sourcetype") == "web_access" and event.get("status_code") == 404 and ip:
            web_404_by_ip[ip].append(event)
        if event.get("event_type") == "web_probe" and ip:
            web_probe_by_ip[ip].append(event)

    for ip, rows in failed_by_ip.items():
        if len(rows) >= 3:
            add_detection(
                detections,
                "MULTIPLE_FAILED_LOGINS_IP",
                "Multiple failed SSH logins from one source",
                "high" if len(rows) >= 5 else "medium",
                f"{len(rows)} SSH failed-login events were observed from {ip}.",
                rows,
                {"source_ip": ip, "count": len(rows), "users": unique([row.get("user") for row in rows])},
                "Check if the source later succeeded, whether targeted accounts are valid, and whether the service should be Internet-facing.",
                ["T1110 Brute Force", "T1021.004 SSH"],
                "high",
            )
        if rows and success_by_ip.get(ip):
            add_detection(
                detections,
                "SUCCESS_AFTER_FAILURE",
                "Successful login after failed attempts from same source",
                "high",
                f"A successful SSH login from {ip} occurred in the same dataset after failed attempts.",
                rows + success_by_ip[ip],
                {"source_ip": ip, "failed_count": len(rows), "success_count": len(success_by_ip[ip])},
                "Validate account owner, session timeline, MFA, command history, and whether the source IP is expected.",
                ["T1110 Brute Force", "T1078 Valid Accounts"],
                "medium",
            )

    for ip, rows in web_404_by_ip.items():
        if len(rows) >= 2:
            add_detection(
                detections,
                "REPEATED_WEB_404",
                "Repeated web 404 probing",
                "medium",
                f"{len(rows)} HTTP 404 responses were observed from {ip}.",
                rows,
                {"source_ip": ip, "paths": unique([row.get("uri_path") for row in rows])},
                "Review requested paths, user-agent, response sizes, and whether the activity is from an approved scanner.",
                ["T1595 Active Scanning"],
                "medium",
            )

    for ip, rows in web_probe_by_ip.items():
        if len(rows) >= 2:
            add_detection(
                detections,
                "MULTI_PATH_WEB_PROBING",
                "Multiple sensitive web paths from one source",
                "medium",
                f"{len(rows)} sensitive-path requests were observed from {ip}.",
                rows,
                {"source_ip": ip, "paths": unique([row.get("uri_path") for row in rows])},
                "Confirm whether this was authorized content discovery and whether any path returned 200/403.",
                ["T1595 Active Scanning"],
                "medium",
            )

    return detections


def field_counts(events, field):
    values = Counter(str(event.get(field)) for event in events if event.get(field) not in (None, "", []))
    return values.most_common(20)


def build_metrics(events, detections):
    top_fields = {}
    for field in ["source_ip", "user", "host", "event_type", "sourcetype", "severity", "process_name", "uri_path", "status_code", "action", "outcome"]:
        top_fields[field] = field_counts(events, field)
    timeline = defaultdict(lambda: {"events": 0, "high": 0, "medium": 0, "low": 0, "info": 0})
    for event in events:
        key = event.get("time_bucket") or "unknown"
        sev = event.get("severity") or "info"
        timeline[key]["events"] += 1
        if sev in timeline[key]:
            timeline[key][sev] += 1
    return {
        "total_events": len(events),
        "total_detections": len(detections),
        "event_types": dict(Counter(event.get("event_type") for event in events)),
        "sourcetypes": dict(Counter(event.get("sourcetype") for event in events)),
        "severity": dict(Counter(event.get("severity") for event in events)),
        "top_source_ips": top_fields["source_ip"],
        "top_users": top_fields["user"],
        "top_hosts": top_fields["host"],
        "top_paths": top_fields["uri_path"],
        "top_fields": top_fields,
        "timeline": dict(sorted(timeline.items())),
    }


def analyze_logs_siem(text: str) -> dict:
    lines = [line for line in text.splitlines() if line.strip()]
    events = [normalize_line(line, index + 1) for index, line in enumerate(lines[:10000])]
    detections = detect_per_event(events) + detect_correlations(events)
    detections = sorted(detections, key=lambda d: (PRIORITY_ORDER.get(d.get("severity", "info"), 0), d.get("matched_count", 0)), reverse=True)
    metrics = build_metrics(events, detections)

    all_ips, all_urls, all_emails, all_domains = [], [], [], []
    for event in events:
        iocs = event.get("iocs", {})
        all_ips.extend(iocs.get("ips", []))
        all_urls.extend(iocs.get("urls", []))
        all_emails.extend(iocs.get("emails", []))
        all_domains.extend(iocs.get("domains", []))

    confidence = "high" if events and any(event.get("timestamp") for event in events) else "medium"
    return {
        "summary": {
            "analyzed_at": utc_now(),
            "total_input_lines": len(lines),
            "events_normalized": len(events),
            "detections_generated": len(detections),
            "alerts_generated": len(detections),
            "confidence": confidence,
            "freshness": "user_supplied_log_batch",
            "note": "SIEM Workspace normalizes user-supplied logs and runs deterministic local detections. Validate conclusions with asset and environment context.",
        },
        "metrics": metrics,
        "detections": detections,
        "alerts": detections,
        "events": events[:2000],
        "extracted_iocs": {
            "ips": unique(all_ips),
            "urls": unique(all_urls),
            "emails": unique(all_emails),
            "domains": unique(all_domains),
        },
        "limitations": [
            "Local batch analysis only; no live SIEM, EDR, firewall, or cloud telemetry is queried.",
            "SPL support is intentionally a small safe subset for local filtering and summarization.",
            "Timestamp and field extraction depends on available log format and may require analyst validation.",
            "Detections are deterministic hints, not final incident conclusions.",
        ],
    }
