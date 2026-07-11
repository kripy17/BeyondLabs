import asyncio
import json
import subprocess
from urllib.request import urlopen, Request
from urllib.error import URLError


async def whois_lookup(domain: str) -> dict | None:
    """Run system whois command for a domain."""
    if not domain:
        return None
    try:
        proc = await asyncio.create_subprocess_exec(
            "whois", domain,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            timeout=15,
        )
        stdout, stderr = await proc.communicate()
        output = stdout.decode("utf-8", errors="replace")[:16000]
        if proc.returncode != 0:
            return {"domain": domain, "raw": "", "error": stderr.decode("utf-8", errors="replace")[:500]}
        return {
            "domain": domain,
            "raw": output,
            "registrar": _extract_whois_field(output, "Registrar:"),
            "creation_date": _extract_whois_field(output, "Creation Date:"),
            "expiry_date": _extract_whois_field(output, "Registry Expiry Date:"),
            "name_servers": _extract_whois_list(output, "Name Server:"),
            "status": _extract_whois_list(output, "Domain Status:"),
            "organization": _extract_whois_field(output, "OrgName:") or _extract_whois_field(output, "Registrant Organization:"),
        }
    except (asyncio.TimeoutError, FileNotFoundError, OSError) as e:
        return {"domain": domain, "raw": "", "error": str(e)}


async def rdap_lookup(ip: str) -> dict | None:
    """Query ARIN RDAP API for an IP."""
    if not ip:
        return None
    try:
        req = Request(
            f"https://rdap.arin.net/registry/ip/{ip}",
            headers={"User-Agent": "BeyondLabs/1.0", "Accept": "application/json"},
        )
        resp = urlopen(req, timeout=10)
        data = json.loads(resp.read().decode())
        entities = data.get("entities", [])
        org = ""
        handle = data.get("handle", "")
        start_addr = data.get("startAddress", "")
        end_addr = data.get("endAddress", "")
        name = data.get("name", "")
        for e in entities:
            if e.get("roles", []) and "registrant" in e.get("roles", []):
                for vcard in e.get("vcardArray", []) if isinstance(e.get("vcardArray"), list) else []:
                    if isinstance(vcard, list):
                        for item in vcard:
                            if isinstance(item, list) and len(item) > 3 and item[0] == "fn":
                                org = item[3] or ""
        return {
            "ip": ip,
            "handle": handle,
            "range": f"{start_addr} - {end_addr}" if start_addr and end_addr else "",
            "name": name,
            "organization": org,
            "raw": json.dumps(data, indent=2)[:16000],
        }
    except (URLError, json.JSONDecodeError, OSError) as e:
        return {"ip": ip, "error": str(e)}


def _extract_whois_field(output: str, field: str) -> str:
    for line in output.splitlines():
        if line.strip().startswith(field):
            return line.split(field, 1)[-1].strip()
    return ""


def _extract_whois_list(output: str, field: str) -> list[str]:
    vals = []
    for line in output.splitlines():
        if line.strip().startswith(field):
            v = line.split(field, 1)[-1].strip()
            if v:
                vals.append(v)
    return vals
