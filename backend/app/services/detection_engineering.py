from datetime import datetime, timezone


MITRE_LOCAL_MAP = [
    {
        "keywords": ["phishing", "credential", "email", "attachment", "link"],
        "technique_id": "T1566",
        "technique": "Phishing",
        "tactic": "Initial Access",
        "confidence": "medium",
    },
    {
        "keywords": ["powershell", "encodedcommand", "-enc", "iex", "downloadstring"],
        "technique_id": "T1059.001",
        "technique": "PowerShell",
        "tactic": "Execution",
        "confidence": "medium",
    },
    {
        "keywords": ["cmd.exe", "command prompt", "shell", "bash"],
        "technique_id": "T1059",
        "technique": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "confidence": "medium",
    },
    {
        "keywords": ["brute force", "failed password", "failed login", "password spraying", "4625"],
        "technique_id": "T1110",
        "technique": "Brute Force",
        "tactic": "Credential Access",
        "confidence": "medium",
    },
    {
        "keywords": ["mimikatz", "credential dump", "lsass", "sekurlsa"],
        "technique_id": "T1003",
        "technique": "OS Credential Dumping",
        "tactic": "Credential Access",
        "confidence": "high",
    },
    {
        "keywords": ["scheduled task", "schtasks"],
        "technique_id": "T1053",
        "technique": "Scheduled Task/Job",
        "tactic": "Persistence",
        "confidence": "medium",
    },
    {
        "keywords": ["service installed", "7045", "new service"],
        "technique_id": "T1543.003",
        "technique": "Windows Service",
        "tactic": "Persistence",
        "confidence": "medium",
    },
    {
        "keywords": ["rundll32", "regsvr32", "mshta"],
        "technique_id": "T1218",
        "technique": "System Binary Proxy Execution",
        "tactic": "Defense Evasion",
        "confidence": "medium",
    },
    {
        "keywords": ["audit log cleared", "1102", "clear logs", "wevtutil cl"],
        "technique_id": "T1070",
        "technique": "Indicator Removal",
        "tactic": "Defense Evasion",
        "confidence": "high",
    },
    {
        "keywords": ["nmap", "masscan", "port scan", "scanner"],
        "technique_id": "T1046",
        "technique": "Network Service Discovery",
        "tactic": "Discovery",
        "confidence": "medium",
    },
    {
        "keywords": ["exfil", "large upload", "data transfer", "unusual outbound"],
        "technique_id": "T1041",
        "technique": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
        "confidence": "low",
    },
]


LOGSOURCE_PRESETS = {
    "windows_process": {
        "product": "windows",
        "category": "process_creation",
        "common_fields": ["Image", "CommandLine", "ParentImage", "User"],
    },
    "windows_security": {
        "product": "windows",
        "service": "security",
        "common_fields": ["EventID", "SubjectUserName", "TargetUserName", "IpAddress"],
    },
    "linux_auth": {
        "product": "linux",
        "service": "auth",
        "common_fields": ["message", "src_ip", "user"],
    },
    "web_access": {
        "product": "webserver",
        "category": "webserver",
        "common_fields": ["src_ip", "cs_method", "cs_uri_stem", "sc_status", "cs_user_agent"],
    },
}


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def map_to_mitre(text: str) -> dict:
    lowered = text.lower()
    matches = []

    for item in MITRE_LOCAL_MAP:
        matched_keywords = [kw for kw in item["keywords"] if kw in lowered]

        if matched_keywords:
            matches.append({
                "technique_id": item["technique_id"],
                "technique": item["technique"],
                "tactic": item["tactic"],
                "confidence": item["confidence"],
                "matched_keywords": matched_keywords,
                "source": "BeyondArch local keyword mapping",
            })

    unique = {}
    for match in matches:
        key = match["technique_id"]
        if key not in unique:
            unique[key] = match
        else:
            unique[key]["matched_keywords"] = sorted(
                set(unique[key]["matched_keywords"] + match["matched_keywords"])
            )

    mapped = list(unique.values())
    structured_mappings = []

    for match in mapped:
        evidence = [
            f"Matched keyword: {keyword}"
            for keyword in match.get("matched_keywords", [])
        ]
        structured_mappings.append({
            "id": f"{match['technique_id']}-{utc_now()}",
            "technique_id": match["technique_id"],
            "technique_name": match["technique"],
            "tactic": match["tactic"],
            "sub_technique": None,
            "confidence": match["confidence"],
            "mapped_from": text[:240],
            "evidence": evidence,
            "reason": "Mapped by local keyword and context matching.",
            "limitations": "This mapping is not confirmed automatically. Validate against logs, alerts, host telemetry, and case evidence.",
            "source_tool": "BeyondArch local MITRE mapper",
            "linked_evidence_ids": [],
            "created_at": utc_now(),
        })

    return {
        "input": text,
        "mapped_at": utc_now(),
        "matches": mapped,
        "structured_mappings": structured_mappings,
        "total_matches": len(mapped),
        "note": "This is a local helper mapping for lab/SOC practice. Analyst validation is required.",
    }


def guess_logsource(description: str) -> str:
    lowered = description.lower()

    if any(x in lowered for x in ["4688", "process", "powershell", "cmd.exe", "commandline"]):
        return "windows_process"

    if any(x in lowered for x in ["4624", "4625", "windows event", "event id", "logon"]):
        return "windows_security"

    if any(x in lowered for x in ["ssh", "auth.log", "failed password", "invalid user"]):
        return "linux_auth"

    if any(x in lowered for x in ["apache", "nginx", "http", "web", "status code", "uri", "user-agent"]):
        return "web_access"

    return "windows_process"


def build_sigma_rule(title: str, description: str, severity: str, logsource_type: str | None = None) -> dict:
    logsource_key = logsource_type or guess_logsource(description)
    logsource = LOGSOURCE_PRESETS.get(logsource_key, LOGSOURCE_PRESETS["windows_process"])

    lowered = description.lower()

    selection = {}

    if "powershell" in lowered:
        selection["CommandLine|contains"] = ["powershell", "-enc", "EncodedCommand", "IEX", "DownloadString"]
    elif "mimikatz" in lowered:
        selection["CommandLine|contains"] = ["mimikatz", "sekurlsa", "lsass"]
    elif "failed password" in lowered or "invalid user" in lowered:
        selection["message|contains"] = ["Failed password", "invalid user", "authentication failure"]
    elif "4625" in lowered:
        selection["EventID"] = 4625
    elif "4624" in lowered:
        selection["EventID"] = 4624
    elif "../" in lowered or "path traversal" in lowered:
        selection["cs_uri_stem|contains"] = ["../", "..%2f", "/etc/passwd"]
    elif "sql injection" in lowered or "union select" in lowered:
        selection["cs_uri_stem|contains"] = ["union select", "information_schema", "' or '1'='1"]
    else:
        selection["keywords|contains"] = description[:120] if description else "suspicious_keyword"

    rule = {
        "title": title,
        "id": "generated-by-beyondarch",
        "status": "experimental",
        "description": description,
        "references": [],
        "author": "BeyondArch",
        "date": utc_now()[:10],
        "logsource": logsource,
        "detection": {
            "selection": selection,
            "condition": "selection",
        },
        "falsepositives": [
            "Administrative activity",
            "Security testing",
            "Expected lab behavior",
        ],
        "level": severity,
        "tags": [],
    }

    mitre = map_to_mitre(description)
    if mitre["matches"]:
        rule["tags"] = [
            f"attack.{item['technique_id'].lower()}"
            for item in mitre["matches"]
        ]

    yaml_lines = []
    for key, value in rule.items():
        yaml_lines.append(f"{key}: {format_yaml_value(value, 0)}")

    return {
        "rule": rule,
        "sigma_yaml": "\n".join(yaml_lines),
        "mitre_mapping": mitre,
        "note": "Generated Sigma-style rule is a starting point. Validate fields against your SIEM/log source before use.",
    }


def format_yaml_value(value, indent):
    spaces = "  " * indent

    if isinstance(value, dict):
        lines = [""]
        for k, v in value.items():
            lines.append(f"{spaces}  {k}: {format_yaml_value(v, indent + 1)}")
        return "\n".join(lines)

    if isinstance(value, list):
        if not value:
            return "[]"
        lines = [""]
        for item in value:
            if isinstance(item, (dict, list)):
                lines.append(f"{spaces}  - {format_yaml_value(item, indent + 1)}")
            else:
                lines.append(f"{spaces}  - {item}")
        return "\n".join(lines)

    if isinstance(value, str):
        if value == "":
            return '""'
        if any(ch in value for ch in [":", "#", "{", "}", "[", "]"]):
            return f'"{value}"'
        return value

    return str(value)
