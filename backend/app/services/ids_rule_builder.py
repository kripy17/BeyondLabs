import re
from datetime import datetime, timezone


VALID_ACTIONS = {"alert", "log", "pass", "drop", "reject", "sdrop"}
VALID_PROTOCOLS = {"tcp", "udp", "icmp", "ip", "http", "tls", "dns"}
VALID_DIRECTIONS = {"->", "<>"}
VALID_ENGINES = {"snort", "suricata", "generic"}


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def escape_rule_text(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def add_option(options: list[str], key: str, value=None):
    if value is None or value == "":
        options.append(f"{key};")
    else:
        options.append(f'{key}:{value};')



def normalize_engine(engine: str) -> str:
    clean = (engine or "snort").strip().lower()
    if clean not in VALID_ENGINES:
        return "generic"
    return clean


def http_uri_keyword(engine: str) -> str:
    if engine == "suricata":
        return "http.uri"
    return "http_uri"


def http_header_keyword(engine: str) -> str:
    if engine == "suricata":
        return "http.header"
    return "http_header"


def build_engine_notes(engine: str) -> list[str]:
    if engine == "suricata":
        return [
            "Generated with Suricata-style HTTP sticky buffer keywords where applicable.",
            "Validate with suricata -T before using in a real ruleset.",
            "Some Snort rules work in Suricata, but keyword behavior can differ."
        ]

    if engine == "snort":
        return [
            "Generated with Snort-style rule keywords.",
            "Use local SIDs >= 1000000 to avoid conflicts.",
            "Validate in your Snort lab before production use."
        ]

    return [
        "Generated as a generic IDS-style rule.",
        "Adjust engine-specific keywords before using in Snort or Suricata.",
        "Validate in a lab before production use."
    ]


def build_ids_rule(data: dict) -> dict:
    engine = normalize_engine(data.get("engine", "snort"))
    action = data.get("action", "alert").strip()
    protocol = data.get("protocol", "tcp").strip()
    src_ip = data.get("src_ip", "any").strip() or "any"
    src_port = data.get("src_port", "any").strip() or "any"
    direction = data.get("direction", "->").strip()
    dst_ip = data.get("dst_ip", "any").strip() or "any"
    dst_port = data.get("dst_port", "any").strip() or "any"

    msg = data.get("msg", "BeyondArch generated IDS rule").strip()
    content = data.get("content", "").strip()
    pcre = data.get("pcre", "").strip()
    flow = data.get("flow", "").strip()
    classtype = data.get("classtype", "trojan-activity").strip()
    priority = data.get("priority", "2").strip()
    sid = data.get("sid", "1000001").strip()
    rev = data.get("rev", "1").strip()
    extra_options = data.get("extra_options", "").strip()
    nocase = bool(data.get("nocase", False))
    http_uri = bool(data.get("http_uri", False))
    http_header = bool(data.get("http_header", False))

    warnings = []

    if data.get("engine") and data.get("engine").strip().lower() not in VALID_ENGINES:
        warnings.append("Unknown engine selected. Falling back to generic IDS style.")

    if action not in VALID_ACTIONS:
        warnings.append(f"Unknown action '{action}'. Common actions: {sorted(VALID_ACTIONS)}")

    if protocol not in VALID_PROTOCOLS:
        warnings.append(f"Unknown protocol '{protocol}'. Common protocols: {sorted(VALID_PROTOCOLS)}")

    if direction not in VALID_DIRECTIONS:
        warnings.append("Direction should usually be -> or <>.")

    if not sid.isdigit():
        warnings.append("SID should be numeric.")

    if sid.isdigit() and int(sid) < 1000000:
        warnings.append("For local rules, use SID >= 1000000 to avoid conflicts with official/community rules.")

    if not content and not pcre:
        warnings.append("Rule has no content or PCRE match. It may be too broad.")

    if protocol == "icmp" and (src_port != "any" or dst_port != "any"):
        warnings.append("ICMP rules usually use ports as any.")

    options = []

    add_option(options, "msg", f'"{escape_rule_text(msg)}"')

    if flow:
        add_option(options, "flow", flow)

    if content:
        add_option(options, "content", f'"{escape_rule_text(content)}"')

        if http_uri:
            add_option(options, http_uri_keyword(engine))

        if http_header:
            add_option(options, http_header_keyword(engine))

        if nocase:
            add_option(options, "nocase")

    if pcre:
        add_option(options, "pcre", f'"{escape_rule_text(pcre)}"')

    if classtype:
        add_option(options, "classtype", classtype)

    if priority:
        add_option(options, "priority", priority)

    if sid:
        add_option(options, "sid", sid)

    if rev:
        add_option(options, "rev", rev)

    if extra_options:
        for raw in extra_options.splitlines():
            raw = raw.strip()
            if raw:
                if not raw.endswith(";"):
                    raw += ";"
                options.append(raw)

    rule = f"{action} {protocol} {src_ip} {src_port} {direction} {dst_ip} {dst_port} ({' '.join(options)})"

    explanation = explain_rule_parts({
        "engine": engine,
        "action": action,
        "protocol": protocol,
        "src_ip": src_ip,
        "src_port": src_port,
        "direction": direction,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "msg": msg,
        "content": content,
        "pcre": pcre,
        "flow": flow,
        "classtype": classtype,
        "priority": priority,
        "sid": sid,
        "rev": rev,
        "nocase": nocase,
        "http_uri": http_uri,
        "http_header": http_header,
    })

    return {
        "generated_at": utc_now(),
        "engine": engine,
        "rule": rule,
        "rule_type": "snort_suricata_style",
        "warnings": warnings,
        "engine_notes": build_engine_notes(engine),
        "explanation": explanation,
        "note": "Validate generated rules in your IDS lab before production use.",
    }


def explain_rule_parts(parts: dict) -> list[str]:
    """Return analyst-oriented guidance instead of a field-by-field restatement."""
    explanation = []
    engine = parts.get("engine", "generic")
    action = parts.get("action", "alert")
    protocol = parts.get("protocol", "tcp")
    src_ip = parts.get("src_ip", "any")
    src_port = parts.get("src_port", "any")
    dst_ip = parts.get("dst_ip", "any")
    dst_port = parts.get("dst_port", "any")
    direction = parts.get("direction", "->")
    content = parts.get("content", "")
    pcre = parts.get("pcre", "")
    flow = parts.get("flow", "")
    classtype = parts.get("classtype", "")
    priority = parts.get("priority", "")
    sid = parts.get("sid", "")
    rev = parts.get("rev", "")

    scope = f"{src_ip}:{src_port} {direction} {dst_ip}:{dst_port}"
    explanation.append(
        f"This is a {engine} style {action} rule for {protocol.upper()} traffic matching the network path {scope}. Treat this as a draft detection rule, not a confirmed incident by itself."
    )

    if content:
        match_area = "packet payload"
        if parts.get("http_uri"):
            match_area = "HTTP request URI"
        elif parts.get("http_header"):
            match_area = "HTTP header area"
        case_note = "case-insensitively" if parts.get("nocase") else "case-sensitively"
        explanation.append(
            f"The main signature condition looks for the literal string '{content}' in the {match_area}, {case_note}. This is useful for simple keyword detections, but it can miss encoded, split, or transformed variants."
        )
    else:
        explanation.append(
            "No literal content match is configured. Without content or PCRE, the rule can become very broad and may create noise. Add a stable protocol field, URI fragment, header, or payload marker where possible."
        )

    if pcre:
        explanation.append(
            f"The PCRE condition adds a regex match ({pcre}). Regex can reduce false positives when tuned well, but review performance impact and test it against benign traffic before production use."
        )

    if flow:
        explanation.append(
            f"The flow constraint is '{flow}'. This should narrow matching to the expected traffic direction/state and usually improves accuracy compared with unconstrained payload matching."
        )
    else:
        explanation.append(
            "No flow option is set. For HTTP/client-server detections, consider using a flow such as to_server,established when supported by the target IDS engine."
        )

    if classtype or priority:
        explanation.append(
            f"Classification is '{classtype or 'unspecified'}' with priority '{priority or 'unspecified'}'. Use these values to control triage severity, but align them with your SOC's severity model and expected asset impact."
        )

    explanation.append(
        "Recommended validation: replay known-benign traffic, then replay a controlled positive sample in a lab. Check alert volume, matched packet fields, and whether the rule fires on the intended evidence only."
    )

    explanation.append(
        "False-positive review: inspect whether normal application paths, scanners, health checks, or admin tools contain the same string or regex pattern. Add anchors, flow, HTTP-specific modifiers, or tighter source/destination scope if needed."
    )

    explanation.append(
        f"Rule management note: local SID {sid or 'N/A'} revision {rev or 'N/A'} should be tracked in version control. Increment rev whenever logic changes and keep local SIDs above 1000000 to avoid conflicts."
    )

    return explanation

def explain_ids_rule(rule: str) -> dict:
    text = rule.strip()
    warnings = []

    header_match = re.match(
        r"^(?P<action>\w+)\s+(?P<protocol>\w+)\s+(?P<src_ip>\S+)\s+(?P<src_port>\S+)\s+"
        r"(?P<direction>->|<>)\s+(?P<dst_ip>\S+)\s+(?P<dst_port>\S+)\s+\((?P<options>.*)\)$",
        text,
    )

    if not header_match:
        return {
            "parsed": False,
            "error": "Could not parse rule header/options. Check rule syntax.",
            "input": rule,
        }

    parts = header_match.groupdict()
    options_text = parts.pop("options")

    options = {}
    raw_options = []

    for opt in options_text.split(";"):
        opt = opt.strip()
        if not opt:
            continue

        raw_options.append(opt)

        if ":" in opt:
            key, value = opt.split(":", 1)
            options[key.strip()] = value.strip().strip('"')
        else:
            options[opt] = True

    if "content" not in options and "pcre" not in options:
        warnings.append("No content or PCRE option found. Rule may be too broad.")

    if "sid" not in options:
        warnings.append("No SID found.")

    parsed = {
        **parts,
        "options": options,
        "raw_options": raw_options,
    }

    explain_parts = {
        "action": parts["action"],
        "protocol": parts["protocol"],
        "src_ip": parts["src_ip"],
        "src_port": parts["src_port"],
        "direction": parts["direction"],
        "dst_ip": parts["dst_ip"],
        "dst_port": parts["dst_port"],
        "msg": options.get("msg", ""),
        "content": options.get("content", ""),
        "pcre": options.get("pcre", ""),
        "flow": options.get("flow", ""),
        "classtype": options.get("classtype", ""),
        "priority": options.get("priority", ""),
        "sid": options.get("sid", ""),
        "rev": options.get("rev", ""),
        "nocase": "nocase" in options,
        "http_uri": "http_uri" in options or "http.uri" in options,
        "http_header": "http_header" in options or "http.header" in options,
    }

    return {
        "parsed": True,
        "input": rule,
        "parsed_rule": parsed,
        "warnings": warnings,
        "explanation": explain_rule_parts(explain_parts),
    }


def ids_rule_templates() -> dict:
    return {
        "suspicious_http_uri": {
            "name": "Suspicious HTTP URI",
            "data": {
                "engine": "snort",
                "action": "alert",
                "protocol": "tcp",
                "src_ip": "any",
                "src_port": "any",
                "direction": "->",
                "dst_ip": "any",
                "dst_port": "80",
                "msg": "Suspicious HTTP URI access",
                "content": "/admin",
                "http_uri": True,
                "nocase": True,
                "classtype": "web-application-attack",
                "priority": "2",
                "sid": "1000001",
                "rev": "1",
            },
        },
        "sql_injection_uri": {
            "name": "SQL Injection Keyword In URI",
            "data": {
                "engine": "snort",
                "action": "alert",
                "protocol": "tcp",
                "src_ip": "any",
                "src_port": "any",
                "direction": "->",
                "dst_ip": "any",
                "dst_port": "80",
                "msg": "Possible SQL injection attempt",
                "content": "union select",
                "http_uri": True,
                "nocase": True,
                "classtype": "web-application-attack",
                "priority": "1",
                "sid": "1000002",
                "rev": "1",
            },
        },
        "suspicious_user_agent": {
            "name": "Suspicious User-Agent",
            "data": {
                "engine": "snort",
                "action": "alert",
                "protocol": "tcp",
                "src_ip": "any",
                "src_port": "any",
                "direction": "->",
                "dst_ip": "any",
                "dst_port": "80",
                "msg": "Suspicious scanner user-agent",
                "content": "sqlmap",
                "http_header": True,
                "nocase": True,
                "classtype": "attempted-recon",
                "priority": "2",
                "sid": "1000003",
                "rev": "1",
            },
        },
        "icmp_ping": {
            "name": "ICMP Ping Detection",
            "data": {
                "engine": "snort",
                "action": "alert",
                "protocol": "icmp",
                "src_ip": "any",
                "src_port": "any",
                "direction": "->",
                "dst_ip": "any",
                "dst_port": "any",
                "msg": "ICMP ping detected",
                "classtype": "misc-activity",
                "priority": "3",
                "sid": "1000004",
                "rev": "1",
            },
        },
    }
