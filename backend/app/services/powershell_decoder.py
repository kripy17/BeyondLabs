import base64
import re
from urllib.parse import unquote

SUSPICIOUS_TOKENS = [
    "invoke-expression", "iex", "downloadstring", "downloadfile",
    "frombase64string", "new-object", "net.webclient",
    "start-process", "bypass", "hidden", "encodedcommand",
    "invoke-webrequest", "curl", "wget", "certutil",
    "rundll32", "regsvr32", "schtasks", "mimikatz",
]


def extract_encoded_command(command: str) -> str | None:
    patterns = [
        r"-(?:enc|encodedcommand|e)\s+([A-Za-z0-9+/=]+)",
        r"/(?:enc|encodedcommand|e)\s+([A-Za-z0-9+/=]+)",
    ]

    for pattern in patterns:
        match = re.search(pattern, command, re.IGNORECASE)
        if match:
            return match.group(1)

    return None


def decode_powershell_base64(value: str) -> dict:
    clean = value.strip()

    try:
        raw = base64.b64decode(clean)

        decoded_utf16 = raw.decode("utf-16le", errors="replace")
        decoded_utf8 = raw.decode("utf-8", errors="replace")

        best = decoded_utf16 if decoded_utf16.count("\x00") < decoded_utf8.count("\x00") else decoded_utf8

        return {
            "success": True,
            "decoded": best,
            "utf16le": decoded_utf16,
            "utf8": decoded_utf8,
        }

    except Exception as e:
        return {
            "success": False,
            "error": str(e),
        }


def analyze_powershell(command: str) -> dict:
    url_decoded = unquote(command)
    encoded_value = extract_encoded_command(url_decoded)

    decoded = None
    decoded_text = ""

    if encoded_value:
        decoded = decode_powershell_base64(encoded_value)
        if decoded.get("success"):
            decoded_text = decoded.get("decoded", "")

    combined = f"{url_decoded}\n{decoded_text}".lower()

    hits = sorted(set(token for token in SUSPICIOUS_TOKENS if token in combined))

    findings = []

    if encoded_value:
        findings.append({
            "severity": "medium",
            "title": "Encoded PowerShell command detected",
            "detail": "The command contains -EncodedCommand or similar syntax.",
            "recommendation": "Decode and review the command before execution."
        })

    if hits:
        findings.append({
            "severity": "high" if any(x in hits for x in ["mimikatz", "downloadstring", "frombase64string", "iex"]) else "medium",
            "title": "Suspicious PowerShell tokens detected",
            "detail": ", ".join(hits),
            "recommendation": "Review for download cradle, execution bypass, or credential theft behavior."
        })

    return {
        "input": command,
        "url_decoded_input": url_decoded,
        "encoded_command_found": bool(encoded_value),
        "encoded_value": encoded_value,
        "decoded": decoded,
        "suspicious_tokens": hits,
        "findings": findings,
        "safety_note": "BeyondLabs only decodes/analyzes PowerShell text. It does not execute commands."
    }
