import hashlib
import html
import re
import time
from collections import Counter
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen


ENDPOINT_RE = re.compile(r"(?:(?:https?:)?//[^\s\"'<>]+|/[A-Za-z0-9._~!$&'()*+,;=:@%/-]{2,})")
SECRET_RE = re.compile(
    r"(?P<label>api[_-]?key|secret|token|bearer|password|client[_-]?secret)\s*[:=]\s*[\"']?(?P<value>[A-Za-z0-9_\-./+=]{8,})",
    re.IGNORECASE,
)
WORD_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{2,}")
XSS_RE = re.compile(r"(<script|onerror=|onload=|javascript:|document\.cookie|alert\s*\()", re.IGNORECASE)
SQLI_RE = re.compile(r"('|--|/\*|\bunion\b|\bselect\b|\bsleep\s*\(|\bor\s+1=1\b)", re.IGNORECASE)
FORENSIC_RE = re.compile(r"(AppData|Prefetch|Amcache|ShimCache|RecentDocs|RunMRU|\.lnk|History|Cookies|Downloads|NTUSER\.DAT)", re.IGNORECASE)
STEGO_RE = re.compile(r"(steghide|zsteg|binwalk|exiftool|strings|least significant bit|lsb|metadata|polyglot)", re.IGNORECASE)
NETWORK_CALLBACK_RE = re.compile(r"(nc\s+-e|bash\s+-i|/dev/tcp|powershell.+downloadstring|invoke-expression|meterpreter|reverse\s+shell|callback)", re.IGNORECASE)
DESTRUCTIVE_RE = re.compile(r"(rm\s+-rf|mkfs|dd\s+if=|format\s+[a-z]:|del\s+/[fsq]|cipher\s+/w|vssadmin\s+delete|wevtutil\s+cl)", re.IGNORECASE)
AUTH_ATTACK_RE = re.compile(r"(password\s+spray|credential\s+stuffing|hydra|medusa|patator|failed\s+password|invalid\s+user|account\s+lockout|many\s+failures)", re.IGNORECASE)
SOCIAL_RE = re.compile(r"(login|verify|password|mfa|urgent|invoice|attachment|qr|credential|account\s+suspended|click\s+here)", re.IGNORECASE)


def _checked_at() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _fetch_page(url: str, timeout: int) -> tuple[str, str | None]:
    req = Request(url, headers={"User-Agent": "BeyondArch-LabCrawler/0.1"})
    with urlopen(req, timeout=timeout) as response:
        content_type = response.headers.get("content-type", "")
        body = response.read(500_000)
    if "text/html" not in content_type and "application/xhtml" not in content_type:
        return "", f"Skipped non-HTML response type: {content_type or 'unknown'}"
    return body.decode("utf-8", errors="replace"), None


def run_web_crawler(target: str, inputs: dict, timeout: int) -> dict:
    start = time.perf_counter()
    max_pages = max(1, min(int(inputs.get("max_pages") or 8), 20))
    seed = target if target.startswith(("http://", "https://")) else f"https://{target}"
    origin = urlparse(seed).netloc
    queue = [seed]
    seen = set()
    pages = []
    limitations = [
        "Crawler performs simple HTML fetching only; it does not execute JavaScript, submit forms, or authenticate.",
        "Only same-host links are followed and response bodies are capped.",
    ]

    while queue and len(pages) < max_pages:
        current = queue.pop(0)
        if current in seen:
            continue
        seen.add(current)
        try:
            body, skipped = _fetch_page(current, min(timeout, 12))
            if skipped:
                pages.append({"url": current, "status": "skipped", "reason": skipped})
                continue
        except Exception as exc:
            pages.append({"url": current, "status": "error", "reason": str(exc)})
            continue

        title_match = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
        links = []
        for href in re.findall(r"href=[\"']([^\"']+)", body, re.IGNORECASE):
            absolute = urljoin(current, html.unescape(href))
            parsed = urlparse(absolute)
            if parsed.scheme in {"http", "https"} and parsed.netloc == origin:
                clean = parsed._replace(fragment="").geturl()
                links.append(clean)
                if clean not in seen and clean not in queue:
                    queue.append(clean)
        pages.append({
            "url": current,
            "status": "fetched",
            "title": html.unescape(title_match.group(1)).strip()[:160] if title_match else "",
            "same_host_links": sorted(set(links))[:40],
        })

    return {
        "parsed_summary": {
            "pages_fetched": sum(1 for page in pages if page["status"] == "fetched"),
            "pages_seen": len(seen),
            "queued_remaining": len(queue),
            "pages": pages,
        },
        "raw_output": "\n".join(page["url"] for page in pages),
        "limitations": limitations,
        "duration": round(time.perf_counter() - start, 3),
        "checked_at": _checked_at(),
    }


def run_secretfinder(target: str, inputs: dict, timeout: int) -> dict:
    start = time.perf_counter()
    source = inputs.get("source_text") or ""
    fetched = False
    limitations = [
        "SecretFinder-style analysis identifies candidate endpoints and secret-like strings; it does not validate credentials.",
        "Findings may be false positives and should be handled as sensitive until triaged.",
    ]
    if target and not source:
        url = target if target.startswith(("http://", "https://")) else f"https://{target}"
        try:
            req = Request(url, headers={"User-Agent": "BeyondArch-JSDiscovery/0.1"})
            with urlopen(req, timeout=min(timeout, 12)) as response:
                source = response.read(500_000).decode("utf-8", errors="replace")
            fetched = True
        except Exception as exc:
            return {
                "parsed_summary": {"error": str(exc), "endpoints": [], "secret_candidates": []},
                "raw_output": "",
                "limitations": limitations,
                "duration": round(time.perf_counter() - start, 3),
                "checked_at": _checked_at(),
            }

    endpoints = sorted(set(ENDPOINT_RE.findall(source)))[:120]
    secret_candidates = [
        {"label": match.group("label"), "fingerprint": hashlib.sha256(match.group("value").encode()).hexdigest()[:16]}
        for match in SECRET_RE.finditer(source)
    ][:40]
    return {
        "parsed_summary": {
            "source": "fetched_url" if fetched else "pasted_text",
            "endpoints": endpoints,
            "secret_candidates": secret_candidates,
            "note": "Secret values are fingerprinted rather than echoed to reduce accidental disclosure.",
        },
        "raw_output": "\n".join(endpoints),
        "limitations": limitations,
        "duration": round(time.perf_counter() - start, 3),
        "checked_at": _checked_at(),
    }


def run_wordlist_lab(inputs: dict) -> dict:
    start = time.perf_counter()
    seed_text = inputs.get("seed_text") or ""
    min_len = max(3, min(int(inputs.get("min_length") or 4), 24))
    words = [word.lower() for word in WORD_RE.findall(seed_text) if len(word) >= min_len]
    counts = Counter(words)
    variants = set(counts)
    for word in list(counts)[:200]:
        variants.update({word.capitalize(), f"{word}1", f"{word}!", f"{word}2026"})
    generated = sorted(variants)[:500]
    return {
        "parsed_summary": {
            "unique_base_words": len(counts),
            "generated_count": len(generated),
            "top_terms": counts.most_common(20),
            "generated_preview": generated[:80],
        },
        "raw_output": "\n".join(generated),
        "limitations": [
            "Generated lists are for owned lab password-audit practice only.",
            "This does not crack passwords or test login services.",
        ],
        "duration": round(time.perf_counter() - start, 3),
        "checked_at": _checked_at(),
    }


def run_pattern_lab(tool_id: str, inputs: dict) -> dict:
    start = time.perf_counter()
    text = inputs.get("source_text") or inputs.get("seed_text") or ""
    if tool_id == "xss-sqli-helper":
        xss = sorted(set(match.group(0) for match in XSS_RE.finditer(text)))
        sqli = sorted(set(match.group(0) for match in SQLI_RE.finditer(text)))
        summary = {"xss_indicators": xss, "sqli_indicators": sqli, "indicator_count": len(xss) + len(sqli)}
        limitations = ["Pattern matching supports lab triage and detection writing; it does not prove exploitability."]
    elif tool_id == "forensics-artifact-extractor":
        artifacts = sorted(set(match.group(0) for match in FORENSIC_RE.finditer(text)))
        summary = {"artifact_terms": artifacts, "artifact_count": len(artifacts)}
        limitations = ["Extractor reviews pasted text only; it does not parse disk images or browser databases."]
    else:
        artifacts = sorted(set(match.group(0) for match in STEGO_RE.finditer(text)))
        summary = {"stego_terms": artifacts, "artifact_count": len(artifacts)}
        limitations = ["Steganography lab provides workflow guidance and pasted-output triage only; it does not decode hidden payloads."]
    return {
        "parsed_summary": summary,
        "raw_output": "\n".join(str(item) for item in summary.values()),
        "limitations": limitations,
        "duration": round(time.perf_counter() - start, 3),
        "checked_at": _checked_at(),
    }


def run_controlled_workflow(tool_id: str, inputs: dict) -> dict:
    start = time.perf_counter()
    text = inputs.get("source_text") or inputs.get("seed_text") or inputs.get("scenario") or ""
    lower = text.lower()
    workflows = {
        "payload-risk-workflow": {
            "title": "Payload risk workflow",
            "matched": sorted(set(match.group(0) for match in NETWORK_CALLBACK_RE.finditer(text))),
            "outputs": ["Payload behavior checklist", "EDR telemetry requirements", "Sigma/YARA drafting notes"],
            "recommendations": ["Keep payload handling in an isolated lab.", "Collect process tree, network destination, file hash, and parent command line.", "Draft detections for interpreter abuse, encoded commands, and outbound callbacks."],
        },
        "exploit-risk-workflow": {
            "title": "Exploit validation workflow",
            "matched": [term for term in ["cve", "exploit", "rce", "sqli", "xss", "path traversal", "deserialization"] if term in lower],
            "outputs": ["Validation checklist", "Evidence fields", "False-positive review notes"],
            "recommendations": ["Validate impact with non-destructive checks only.", "Document request path, parameter, response code, and reproduction boundaries.", "Do not generate exploit payloads from this workflow."],
        },
        "reverse-shell-detection-workflow": {
            "title": "Reverse-shell detection workflow",
            "matched": sorted(set(match.group(0) for match in NETWORK_CALLBACK_RE.finditer(text))),
            "outputs": ["Callback indicator checklist", "Process/network pivots", "Detection draft inputs"],
            "recommendations": ["Pivot on child shells, suspicious parent processes, and outbound connections.", "Review DNS/proxy/firewall logs around suspected callback time.", "Do not generate shell payloads."],
        },
        "malware-static-workflow": {
            "title": "Malware static triage workflow",
            "matched": [term for term in ["powershell", "encodedcommand", "autorun", "rundll32", "regsvr32", "schtasks", "mutex", "c2", "inject"] if term in lower],
            "outputs": ["Static triage checklist", "IOC extraction plan", "YARA/Sigma drafting notes"],
            "recommendations": ["Hash the sample, extract strings, classify behavior, and keep execution disabled.", "Send static findings to Attachment Triage or Detection Engineering.", "Do not execute malware or macros."],
        },
        "credential-attack-detection-workflow": {
            "title": "Credential attack detection workflow",
            "matched": sorted(set(match.group(0) for match in AUTH_ATTACK_RE.finditer(text))),
            "outputs": ["Threshold guidance", "Auth-log pivots", "Detection test cases"],
            "recommendations": ["Correlate failures by source IP, username, user-agent, and time window.", "Flag successful login after repeated failures.", "Do not run online brute-force, stuffing, or spray attempts."],
        },
        "stealth-evasion-detection-workflow": {
            "title": "Stealth/evasion detection workflow",
            "matched": [term for term in ["slow scan", "decoy", "fragment", "spoof", "proxy", "evasion", "tamper", "disable", "bypass"] if term in lower],
            "outputs": ["Evasion-risk checklist", "Telemetry gaps", "Detection-hardening notes"],
            "recommendations": ["Look for low-rate distributed probing and unusual scanner fingerprints.", "Tune detections with time-window and source diversity context.", "No stealth or evasion scan flags are generated."],
        },
        "destructive-command-guardrail": {
            "title": "Destructive command guardrail",
            "matched": sorted(set(match.group(0) for match in DESTRUCTIVE_RE.finditer(text))),
            "outputs": ["Risk classification", "Containment notes", "Detection logic hints"],
            "recommendations": ["Treat destructive commands as high risk and validate provenance.", "Preserve shell history, EDR process data, and affected host timeline.", "This workflow never executes commands."],
        },
        "social-engineering-triage-workflow": {
            "title": "Social engineering triage workflow",
            "matched": sorted(set(match.group(0) for match in SOCIAL_RE.finditer(text))),
            "outputs": ["Pretext indicators", "Email/security control checklist", "User-impact reporting notes"],
            "recommendations": ["Review sender alignment, URLs, attachments, and credential-harvest language.", "Route artifacts to Phishing Triage and Detection Engineering.", "No phishing kits, credential collection, or message sending is performed."],
        },
    }
    workflow = workflows.get(tool_id, workflows["exploit-risk-workflow"])
    summary = {
        "status": "controlled_local_workflow",
        "title": workflow["title"],
        "matched_indicators": workflow["matched"],
        "output_artifacts": workflow["outputs"],
        "recommended_actions": workflow["recommendations"],
        "blocked_actions": [
            "No payload, exploit, malware, phishing kit, credential attack, evasion, or destructive command is generated or executed.",
            "Use outputs as review, detection, and reporting support only.",
        ],
    }
    terminal_lines = [
        f"$ beyondarch-controlled-workflow --tool {tool_id}",
        f"[+] Workflow: {workflow['title']}",
        f"[+] Matched indicators: {len(workflow['matched'])}",
        "",
        "Matched indicators:",
        *(f"  - {item}" for item in workflow["matched"][:40]),
        *(["  - none found in pasted evidence"] if not workflow["matched"] else []),
        "",
        "Output artifacts:",
        *(f"  - {item}" for item in workflow["outputs"]),
        "",
        "Recommended actions:",
        *(f"  - {item}" for item in workflow["recommendations"]),
        "",
        "Blocked actions:",
        *(f"  - {item}" for item in summary["blocked_actions"]),
    ]
    return {
        "parsed_summary": summary,
        "raw_output": "\n".join(terminal_lines),
        "limitations": summary["blocked_actions"],
        "duration": round(time.perf_counter() - start, 3),
        "checked_at": _checked_at(),
    }
