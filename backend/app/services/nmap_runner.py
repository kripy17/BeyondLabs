import ipaddress
import re
import shlex
import shutil
import socket
import subprocess
from shlex import quote

ALLOWED_SCAN_MODES = {
    "aggressive_inventory": {
        "label": "Service, Version & OS (-A)",
        "args": ["-Pn", "-T3", "-A", "--top-ports", "100"],
    },
    "quick_tcp": {
        "label": "Quick TCP Triage",
        "args": ["-Pn", "-T3", "--top-ports", "100"],
    },
    "full_tcp": {
        "label": "Full TCP Port Scan",
        "args": ["-Pn", "-T3", "-p-"],
    },
    "service_version": {
        "label": "Service & Version Detection",
        "args": ["-Pn", "-T3", "-sV"],
    },
    "os_detection": {
        "label": "OS Detection",
        "args": ["-Pn", "-T3", "-O"],
    },
    "udp_focused": {
        "label": "UDP Focused Scan",
        "args": ["-Pn", "-T3", "-sU", "-p", "53,67,68,69,123,137,161,500,4500"],
    },
    "web_exposure": {
        "label": "Web Exposure Scan",
        "args": ["-Pn", "-T3", "-sV", "-p", "80,443,8080,8443,8000,3000,5000,9000", "--script", "http-title,http-headers,http-server-header,ssl-cert,ssl-enum-ciphers"],
    },
    "internal_inventory": {
        "label": "Internal Inventory Scan",
        "args": ["-T3", "-sV", "--top-ports", "200"],
    },
    "windows_smb": {
        "label": "Windows/SMB Exposure Review",
        "args": ["-Pn", "-T3", "-sV", "-p", "135,139,445,3389,5985,5986", "--script", "smb-os-discovery,smb-protocols,smb2-security-mode,rdp-enum-encryption"],
    },
    "linux_ssh": {
        "label": "Linux/SSH Exposure Review",
        "args": ["-Pn", "-T3", "-sV", "-p", "22,2222"],
    },
    "mail_server": {
        "label": "Mail Server Exposure Review",
        "args": ["-Pn", "-T3", "-sV", "-p", "25,465,587,110,995,143,993"],
    },
    "dns_exposure": {
        "label": "DNS Exposure Review",
        "args": ["-Pn", "-T3", "-sV", "-sU", "-sT", "-p", "T:53,U:53", "--script", "dns-recursion"],
    },
    "safe_scripts": {
        "label": "Safe NSE Script Scan",
        "args": ["-Pn", "-T3", "-sV", "--script", "default,safe"],
    },
}


def is_private_or_local_ip(ip: str) -> bool:
    try:
        parsed = ipaddress.ip_address(ip)
        return (
            parsed.is_private
            or parsed.is_loopback
            or parsed.is_link_local
            or parsed.is_multicast
        )
    except ValueError:
        return False


def resolve_target_ips(target: str) -> list[str]:
    try:
        return list(set(socket.gethostbyname_ex(target)[2]))
    except Exception:
        return []


def target_is_private_or_local(target: str) -> bool:
    if is_private_or_local_ip(target):
        return True

    resolved_ips = resolve_target_ips(target)
    return any(is_private_or_local_ip(ip) for ip in resolved_ips)



BLOCKED_CUSTOM_FLAGS = {
    "-T5",
    "-iL",
    "--script-args",
    "--script-args-file",
    "--min-rate",
    "--max-rate",
    "--spoof-mac",
    "--data-length",
    "-D",
    "-S",
    "--source-port",
}

BLOCKED_SCRIPT_WORDS = {
    "vuln",
    "exploit",
    "brute",
    "auth",
    "malware",
    "dos",
    "fuzzer",
    "broadcast",
    "external",
}

OPTIONS_WITH_VALUES = {
    "-p", "--top-ports", "--max-retries", "--host-timeout", "--scan-delay",
    "-oN", "-oX", "-oG", "-oA", "-oS", "--stylesheet", "--exclude", "--dns-servers",
    "--script", "--version-intensity", "--min-parallelism", "--max-parallelism",
}


def _looks_like_target(token: str) -> bool:
    if not token or token.startswith("-"):
        return False
    if "/" in token and not re.match(r"^[A-Za-z0-9_.:-]+/\d{1,2}$", token):
        return False
    return bool(re.match(r"^[A-Za-z0-9_.:-]+(?:/\d{1,2})?$", token))


def _custom_targets(tokens: list[str]) -> list[str]:
    targets = []
    skip_next = False
    for index, token in enumerate(tokens[1:], start=1):
        if skip_next:
            skip_next = False
            continue
        base = token.split("=", 1)[0]
        if base in OPTIONS_WITH_VALUES and "=" not in token:
            skip_next = True
            continue
        if token.startswith("-"):
            continue
        if index > 0 and tokens[index - 1].split("=", 1)[0] in OPTIONS_WITH_VALUES:
            continue
        if _looks_like_target(token):
            targets.append(token)
    return targets


def validate_custom_nmap_command(command: str, allow_private: bool = False) -> tuple[list[str] | None, str | None, list[str]]:
    clean = (command or "").strip()
    if not clean:
        return None, "Enter an nmap command.", []
    if any(char in clean for char in [";", "&&", "||", "`", "$(", "|", ">", "<"]):
        return None, "Shell chaining/redirection is blocked. Enter a single nmap command only.", []
    try:
        tokens = shlex.split(clean)
    except ValueError as exc:
        return None, f"Could not parse command: {exc}", []
    if not tokens or tokens[0] != "nmap":
        return None, "Custom command must start with 'nmap'.", []
    lowered = [token.lower() for token in tokens]
    for flag in BLOCKED_CUSTOM_FLAGS:
        if flag.lower() in lowered or any(item.startswith(flag.lower() + "=") for item in lowered):
            return None, f"Blocked option for portfolio-safe execution: {flag}", []
    for token in lowered:
        if token.startswith("--script") or token == "-sC" or token == "--script=default":
            script_value = token.split("=", 1)[1] if "=" in token else ""
            if any(word in script_value for word in BLOCKED_SCRIPT_WORDS):
                return None, "Unsafe NSE script category blocked. Use default/safe/http-title/http-headers/ssl-cert style scripts only.", []
    targets = _custom_targets(tokens)
    if not targets:
        return None, "Could not identify a target in the custom nmap command.", []
    if len(targets) > 3:
        return None, "Limit custom commands to three targets or fewer.", targets
    if any(target_is_private_or_local(target) for target in targets) and not allow_private:
        return None, "Private/local targets are blocked unless local mode is enabled.", targets
    return tokens, None, targets


def run_custom_nmap_command(command: str, allow_private: bool = False) -> dict:
    if shutil.which("nmap") is None:
        return {"success": False, "error": "Nmap is not installed or not available in PATH."}
    tokens, error, targets = validate_custom_nmap_command(command, allow_private=allow_private)
    if error:
        return {"success": False, "error": error, "targets": targets}
    try:
        completed = subprocess.run(tokens, capture_output=True, text=True, timeout=120, shell=False)
        return {
            "success": completed.returncode == 0,
            "mode": "custom",
            "mode_label": "Custom Nmap command",
            "command": " ".join(quote(part) for part in tokens),
            "command_args": tokens,
            "targets": targets,
            "return_code": completed.returncode,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
            "output_format": "normal",
            "safety_notes": [
                "Executed as a single nmap process with shell chaining disabled.",
                "High-risk NSE categories and evasion/spoofing flags are blocked.",
                "Validate scope and save raw output as evidence.",
            ],
        }
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "Custom Nmap command timed out after 120 seconds.", "command": " ".join(quote(part) for part in tokens), "targets": targets}
    except Exception as exc:
        return {"success": False, "error": str(exc), "command": " ".join(quote(part) for part in tokens), "targets": targets}

def build_nmap_command(target: str, mode: str, flags: str = "") -> str:
    if mode == "custom":
        return flags
    if mode not in ALLOWED_SCAN_MODES:
        mode = "quick_tcp"
    scan_config = ALLOWED_SCAN_MODES[mode]
    command = ["nmap", *scan_config["args"], target]
    cmd = shlex.join(command)
    if flags:
        cmd = f"{cmd} {flags}"
    return cmd


def run_nmap_scan(target: str, mode: str, allow_private: bool = False) -> dict:
    if shutil.which("nmap") is None:
        return {
            "success": False,
            "error": "Nmap is not installed or not available in PATH.",
        }

    if mode not in ALLOWED_SCAN_MODES:
        return {
            "success": False,
            "error": "Invalid scan mode.",
            "allowed_modes": list(ALLOWED_SCAN_MODES.keys()),
        }

    if target_is_private_or_local(target) and not allow_private:
        return {
            "success": False,
            "error": "Private/local targets are blocked unless local mode is enabled.",
        }

    scan_config = ALLOWED_SCAN_MODES[mode]
    command = ["nmap", *scan_config["args"], target]

    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=120,
            shell=False,
        )

        return {
            "success": completed.returncode == 0,
            "mode": mode,
            "mode_label": scan_config["label"],
            "command": " ".join(quote(part) for part in command),
            "command_args": command,
            "return_code": completed.returncode,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
            "output_format": "normal",
        }

    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "error": "Nmap scan timed out.",
            "command": " ".join(quote(part) for part in command),
            "command_args": command,
        }

    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "command": " ".join(quote(part) for part in command),
            "command_args": command,
        }
