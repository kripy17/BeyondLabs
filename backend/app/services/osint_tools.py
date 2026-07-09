import re
from urllib.parse import urlparse

import dns.resolver
import httpx

from app.utils import unique_sorted

USERNAME_PLATFORMS = {
    "github": "https://github.com/{username}",
    "reddit": "https://www.reddit.com/user/{username}",
    "medium": "https://medium.com/@{username}",
    "x_twitter": "https://x.com/{username}",
    "instagram": "https://www.instagram.com/{username}",
    "linkedin": "https://www.linkedin.com/in/{username}",
    "youtube": "https://www.youtube.com/@{username}",
    "tiktok": "https://www.tiktok.com/@{username}",
    "pinterest": "https://www.pinterest.com/{username}",
    "telegram": "https://t.me/{username}",
}

SOCIAL_PATTERNS = {
    "github": r"https?://(?:www\.)?github\.com/[A-Za-z0-9_.-]+",
    "linkedin": r"https?://(?:www\.)?linkedin\.com/(?:company|in)/[A-Za-z0-9_.%-]+",
    "x_twitter": r"https?://(?:www\.)?(?:x\.com|twitter\.com)/[A-Za-z0-9_]+",
    "instagram": r"https?://(?:www\.)?instagram\.com/[A-Za-z0-9_.]+",
    "youtube": r"https?://(?:www\.)?youtube\.com/(?:@|c/|channel/|user/)[A-Za-z0-9_.@-]+",
    "facebook": r"https?://(?:www\.)?facebook\.com/[A-Za-z0-9_.-]+",
    "telegram": r"https?://t\.me/[A-Za-z0-9_]+",
    "discord": r"https?://(?:discord\.gg|discord\.com/invite)/[A-Za-z0-9]+",
}


def username_osint(username: str) -> dict:
    clean = username.strip().lstrip("@")

    links = {
        platform: template.format(username=clean)
        for platform, template in USERNAME_PLATFORMS.items()
    }

    return {
        "username": clean,
        "note": "These are safe public check links. Some platforms require manual verification.",
        "links": links,
    }


def resolve_records(domain: str, record_type: str) -> list[str]:
    try:
        answers = dns.resolver.resolve(domain, record_type, lifetime=5)
        return [answer.to_text() for answer in answers]
    except Exception:
        return []


def email_osint(email: str) -> dict:
    clean = email.strip()

    if "@" not in clean:
        return {
            "valid_format": False,
            "error": "Email must contain @.",
        }

    local, domain = clean.rsplit("@", 1)
    domain = domain.lower()

    mx = resolve_records(domain, "MX")
    txt = resolve_records(domain, "TXT")
    dmarc = resolve_records(f"_dmarc.{domain}", "TXT")

    joined_txt = " ".join(txt).lower()
    joined_dmarc = " ".join(dmarc).lower()

    return {
        "valid_format": True,
        "email": clean,
        "local_part": local,
        "domain": domain,
        "mx_records": mx,
        "txt_records": txt,
        "dmarc_records": dmarc,
        "checks": {
            "has_mx": bool(mx),
            "has_spf": "v=spf1" in joined_txt,
            "has_dmarc": "v=dmarc1" in joined_dmarc,
        },
        "notes": [
            "This does not confirm whether the mailbox exists.",
            "Use only for defensive investigation and email security review."
        ],
    }


def normalize_website(value: str) -> str:
    value = value.strip()

    if not value.startswith(("http://", "https://")):
        value = "https://" + value

    return value


def fetch_homepage(url: str) -> dict:
    headers = {
        "User-Agent": "BeyondLabs/1.0 Defensive OSINT Toolkit"
    }

    try:
        response = httpx.get(
            url,
            timeout=8,
            follow_redirects=True,
            headers=headers,
        )

        return {
            "success": True,
            "url": str(response.url),
            "html": response.text[:300000],
            "status_code": response.status_code,
        }

    except Exception as first_error:
        if url.startswith("https://"):
            fallback = "http://" + url.removeprefix("https://")
            try:
                response = httpx.get(
                    fallback,
                    timeout=8,
                    follow_redirects=True,
                    headers=headers,
                )

                return {
                    "success": True,
                    "url": str(response.url),
                    "html": response.text[:300000],
                    "status_code": response.status_code,
                }
            except Exception:
                pass

        return {
            "success": False,
            "url": url,
            "error": str(first_error),
        }


def social_links_finder(website: str) -> dict:
    url = normalize_website(website)
    fetched = fetch_homepage(url)

    if not fetched.get("success"):
        return fetched

    html = fetched.get("html", "")
    found = {}

    for platform, pattern in SOCIAL_PATTERNS.items():
        matches = re.findall(pattern, html, flags=re.IGNORECASE)
        found[platform] = unique_sorted(matches)

    parsed = urlparse(fetched["url"])

    return {
        "success": True,
        "input": website,
        "final_url": fetched["url"],
        "hostname": parsed.hostname,
        "status_code": fetched.get("status_code"),
        "social_links": found,
        "total_links_found": sum(len(v) for v in found.values()),
    }

import shutil  # noqa: E402
import subprocess  # noqa: E402
from shlex import quote  # noqa: E402

LOCAL_OSINT_TOOLS = {
    "curl": ["curl"],
    "openssl": ["openssl"],
    "file": ["file"],
    "strings": ["strings"],
    "jq": ["jq"],
    "dig": ["dig"],
    "nslookup": ["nslookup"],
    "whois": ["whois"],
    "traceroute": ["traceroute"],
    "mtr": ["mtr"],
    "nmap": ["nmap"],
    "whatweb": ["whatweb"],
    "theharvester": ["theHarvester", "theharvester"],
    "amass": ["amass"],
    "subfinder": ["subfinder"],
    "assetfinder": ["assetfinder"],
    "httpx": ["httpx"],
    "waybackurls": ["waybackurls"],
    "gau": ["gau"],
    "katana": ["katana"],
    "nuclei": ["nuclei"],
    "ffuf": ["ffuf"],
    "gobuster": ["gobuster"],
}

LOCAL_OSINT_TOOL_CATEGORIES = {
    "Core helpers": ["curl", "openssl", "file", "strings", "jq"],
    "DNS/domain metadata": ["dig", "nslookup", "whois", "traceroute", "mtr"],
    "Recommended SOC/recon helpers": ["nmap", "whatweb", "subfinder", "amass", "httpx"],
    "Manual/optional OSINT helpers": ["theharvester", "assetfinder", "waybackurls", "gau", "katana"],
    "Advanced active tools": ["nuclei", "ffuf", "gobuster"],
}

LOCAL_OSINT_TOOL_NOTES = {
    "curl": "HTTP/header checks",
    "openssl": "TLS certificate checks",
    "file": "File type inspection",
    "strings": "Static strings helper from binutils",
    "jq": "JSON inspection",
    "dig": "DNS baseline and mail posture",
    "nslookup": "DNS baseline helper",
    "whois": "WHOIS registration metadata",
    "traceroute": "Network path metadata",
    "mtr": "Path diagnostics if available",
    "nmap": "Authorized bounded scanning",
    "whatweb": "Web technology fingerprinting",
    "subfinder": "Passive subdomain enumeration",
    "amass": "Passive subdomain enumeration",
    "httpx": "HTTP probing helper",
    "theharvester": "Passive email/host/subdomain discovery",
    "assetfinder": "Passive subdomain enumeration",
    "waybackurls": "Archive URL collection",
    "gau": "Archive URL collection",
    "katana": "Crawler helper",
    "nuclei": "Advanced active scanner",
    "ffuf": "Active fuzzing helper",
    "gobuster": "Active discovery helper",
}

SAFE_HARVESTER_SOURCES = {"duckduckgo", "bing", "crtsh", "hackertarget", "rapiddns", "baidu"}

OSINT_TOOL_LABELS = {
    "theharvester": "theHarvester email/subdomain discovery",
    "amass": "Amass passive enum",
    "subfinder": "Subfinder passive enum",
    "assetfinder": "Assetfinder subdomain enum",
    "whois": "WHOIS registration lookup",
    "dig_mx_txt": "DNS mail posture records",
    "dns_basic": "DNS baseline records",
    "http_headers": "HTTP header preview",
    "tls_cert": "TLS certificate preview",
}

TOOL_DESCRIPTIONS = {
    "theharvester": "Collect public emails, hosts, and subdomains from a selected public source.",
    "amass": "Run passive subdomain enumeration using local Amass if installed.",
    "subfinder": "Run passive subdomain enumeration using local Subfinder if installed.",
    "assetfinder": "Collect public subdomains using local Assetfinder if installed.",
    "whois": "Display local WHOIS registration metadata.",
    "dig_mx_txt": "Review MX, TXT, DMARC, SPF, and NS mail posture records.",
    "dns_basic": "Review A, AAAA, CNAME, NS, SOA, MX, and TXT baseline records.",
    "http_headers": "Preview HTTP response headers only; no browser rendering or JavaScript.",
    "tls_cert": "Preview TLS certificate handshake metadata using openssl.",
}


def _which_any(names: list[str]) -> str | None:
    for name in names:
        path = shutil.which(name)
        if path:
            return path
    return None


def local_osint_tool_status() -> dict:
    tools = {}
    for key, candidates in LOCAL_OSINT_TOOLS.items():
        path = _which_any(candidates)
        tools[key] = {
            "available": bool(path),
            "command": candidates[0],
            "path": path or "",
        }
    runnable_map = {
        "theharvester": tools["theharvester"]["available"],
        "amass": tools["amass"]["available"],
        "subfinder": tools["subfinder"]["available"],
        "assetfinder": tools["assetfinder"]["available"],
        "whois": tools["whois"]["available"],
        "dig_mx_txt": tools["dig"]["available"],
        "dns_basic": tools["dig"]["available"],
        "http_headers": tools["curl"]["available"],
        "tls_cert": tools["openssl"]["available"],
    }
    return {
        "tools": tools,
        "categories": {
            category: [
                {
                    "id": tool_id,
                    "command": tools[tool_id]["command"],
                    "available": tools[tool_id]["available"],
                    "path": tools[tool_id]["path"],
                    "note": LOCAL_OSINT_TOOL_NOTES.get(tool_id, ""),
                }
                for tool_id in tool_ids
                if tool_id in tools
            ]
            for category, tool_ids in LOCAL_OSINT_TOOL_CATEGORIES.items()
        },
        "runnable": {
            key: {
                "available": available,
                "label": OSINT_TOOL_LABELS.get(key, key),
                "description": TOOL_DESCRIPTIONS.get(key, ""),
            }
            for key, available in runnable_map.items()
        },
        "available_count": sum(1 for available in runnable_map.values() if available),
        "total_count": len(runnable_map),
        "note": "Local tool availability is checked from the backend PATH. No API keys are used.",
    }


def valid_domain(value: str) -> bool:
    return bool(re.match(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$", value.strip().lower()))


def _clean_domain(domain: str) -> str:
    return domain.strip().lower().replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]


def _run_command(command: list[str], timeout: int = 120, stdin: str | None = None) -> tuple[int, str, str]:
    completed = subprocess.run(command, input=stdin, capture_output=True, text=True, timeout=timeout, shell=False)
    return completed.returncode, completed.stdout[-30000:], completed.stderr[-8000:]


def run_theharvester(domain: str, source: str = "duckduckgo", limit: int = 50, confirm_permission: bool = False) -> dict:
    return run_local_osint_tool("theharvester", domain, source, limit, confirm_permission)


SAFE_OSINT_TOOL_COMMANDS = {
    "theharvester": lambda domain, source, limit: ["theHarvester", "-d", domain, "-b", source, "-l", str(limit)],
    "amass": lambda domain, source, limit: ["amass", "enum", "-passive", "-d", domain],
    "subfinder": lambda domain, source, limit: ["subfinder", "-silent", "-d", domain],
    "assetfinder": lambda domain, source, limit: ["assetfinder", "--subs-only", domain],
    "whois": lambda domain, source, limit: ["whois", domain],
    "dig_mx_txt": lambda domain, source, limit: ["dig", domain, "MX", "+short"],
    "dns_basic": lambda domain, source, limit: ["dig", domain, "A", "+short"],
    "http_headers": lambda domain, source, limit: ["curl", "-I", "-L", "--max-redirs", "5", "--connect-timeout", "6", "--max-time", "15", f"https://{domain}"],
    "tls_cert": lambda domain, source, limit: ["openssl", "s_client", "-connect", f"{domain}:443", "-servername", domain, "-brief"],
}

TOOL_BINARY_KEYS = {
    "theharvester": "theharvester",
    "amass": "amass",
    "subfinder": "subfinder",
    "assetfinder": "assetfinder",
    "whois": "whois",
    "dig_mx_txt": "dig",
    "dns_basic": "dig",
    "http_headers": "curl",
    "tls_cert": "openssl",
}


def _run_dig_bundle(tool_path: str, domain: str, bundle: str) -> dict:
    if bundle == "mail":
        records = [
            ("MX", [tool_path, domain, "MX", "+short"]),
            ("TXT", [tool_path, domain, "TXT", "+short"]),
            ("DMARC", [tool_path, f"_dmarc.{domain}", "TXT", "+short"]),
            ("NS", [tool_path, domain, "NS", "+short"]),
        ]
        command_label = f"dig {quote(domain)} MX/TXT/NS +short; dig _dmarc.{quote(domain)} TXT +short"
    else:
        records = [
            ("A", [tool_path, domain, "A", "+short"]),
            ("AAAA", [tool_path, domain, "AAAA", "+short"]),
            ("CNAME", [tool_path, domain, "CNAME", "+short"]),
            ("NS", [tool_path, domain, "NS", "+short"]),
            ("SOA", [tool_path, domain, "SOA", "+short"]),
            ("MX", [tool_path, domain, "MX", "+short"]),
            ("TXT", [tool_path, domain, "TXT", "+short"]),
        ]
        command_label = f"dig {quote(domain)} A/AAAA/CNAME/NS/SOA/MX/TXT +short"

    outputs = []
    return_code = 0
    for name, cmd in records:
        completed = subprocess.run(cmd, capture_output=True, text=True, timeout=20, shell=False)
        return_code = max(return_code, completed.returncode)
        outputs.append(f"## {name}\n{completed.stdout.strip() or completed.stderr.strip() or 'No records returned.'}")
    return {
        "success": return_code == 0,
        "domain": domain,
        "command": command_label,
        "return_code": return_code,
        "stdout": "\n\n".join(outputs),
        "stderr": "",
    }


def run_local_osint_tool(tool_id: str, domain: str, source: str = "duckduckgo", limit: int = 50, confirm_permission: bool = False) -> dict:
    clean_tool = (tool_id or "").strip().lower()
    clean_domain = _clean_domain(domain)
    clean_source = source.strip().lower() or "duckduckgo"
    safe_limit = max(10, min(int(limit or 50), 200))

    if clean_tool not in SAFE_OSINT_TOOL_COMMANDS:
        return {"success": False, "error": "Unsupported local OSINT tool.", "allowed_tools": sorted(SAFE_OSINT_TOOL_COMMANDS.keys())}
    if not valid_domain(clean_domain):
        return {"success": False, "error": "Enter a single valid domain such as example.com."}
    if clean_tool == "theharvester" and clean_source not in SAFE_HARVESTER_SOURCES:
        return {"success": False, "error": f"Unsupported source. Allowed: {sorted(SAFE_HARVESTER_SOURCES)}"}

    binary_key = TOOL_BINARY_KEYS.get(clean_tool, clean_tool)
    tool_path = _which_any(LOCAL_OSINT_TOOLS.get(binary_key, [binary_key]))
    command = SAFE_OSINT_TOOL_COMMANDS[clean_tool](clean_domain, clean_source, safe_limit)
    if tool_path:
        command[0] = tool_path

    if not tool_path:
        return {
            "success": False,
            "tool": clean_tool,
            "tool_label": OSINT_TOOL_LABELS.get(clean_tool, clean_tool),
            "domain": clean_domain,
            "error": f"{OSINT_TOOL_LABELS.get(clean_tool, clean_tool)} is not installed or not available in the backend PATH.",
            "command_preview": " ".join(quote(part) for part in command),
            "install_hint": "Install the tool locally and restart the backend so BeyondLabs can find it.",
        }

    try:
        if clean_tool in {"dig_mx_txt", "dns_basic"}:
            result = _run_dig_bundle(tool_path, clean_domain, "mail" if clean_tool == "dig_mx_txt" else "basic")
            result.update({
                "tool": clean_tool,
                "tool_label": OSINT_TOOL_LABELS.get(clean_tool, clean_tool),
                "note": "Local dig wrapper only. No API keys are used by BeyondLabs.",
            })
            return result

        timeout = 30 if clean_tool in {"whois", "http_headers", "tls_cert"} else 120
        stdin = "" if clean_tool == "tls_cert" else None
        return_code, stdout, stderr = _run_command(command, timeout=timeout, stdin=stdin)
        return {
            "success": return_code == 0,
            "tool": clean_tool,
            "tool_label": OSINT_TOOL_LABELS.get(clean_tool, clean_tool),
            "domain": clean_domain,
            "source": clean_source,
            "limit": safe_limit,
            "command": " ".join(quote(part) for part in command),
            "return_code": return_code,
            "stdout": stdout,
            "stderr": stderr,
            "note": "Local backend wrapper only. No API keys are used by BeyondLabs.",
        }
    except subprocess.TimeoutExpired:
        return {"success": False, "tool": clean_tool, "domain": clean_domain, "error": "Local OSINT tool timed out.", "command": " ".join(quote(part) for part in command)}
    except Exception as exc:
        return {"success": False, "tool": clean_tool, "domain": clean_domain, "error": str(exc), "command": " ".join(quote(part) for part in command)}
