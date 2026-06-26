import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


HACKINGTOOL_DIR = None


def _find_hackingtool_dir():
    candidates = [
        "/home/kripy/Projects/hackingtool",
        str(Path(__file__).resolve().parent.parent.parent.parent / "hackingtool"),
        str(Path.home() / "Projects" / "hackingtool"),
        "/opt/hackingtool",
    ]
    for path in candidates:
        if Path(path).joinpath("hackingtool.py").exists():
            return path
    return None


def _ensure_dir():
    global HACKINGTOOL_DIR
    if HACKINGTOOL_DIR:
        return HACKINGTOOL_DIR
    HACKINGTOOL_DIR = _find_hackingtool_dir()
    return HACKINGTOOL_DIR


def get_categories():
    ht_dir = _ensure_dir()
    if not ht_dir:
        return {"installed": False, "categories": [],
                "note": "hackingtool not found. Clone into ~/Projects/hackingtool or /opt/hackingtool"}

    categories = [
        {"id": "information_gathering", "name": "Information Gathering", "icon": "search", "tools": [
            {"id": "nmap", "name": "Nmap", "binary": "nmap"},
            {"id": "theharvester", "name": "theHarvester", "binary": "theharvester"},
            {"id": "amass", "name": "Amass", "binary": "amass"},
            {"id": "sublist3r", "name": "Sublist3r", "binary": "sublist3r"},
            {"id": "maigret", "name": "Maigret", "binary": "maigret"},
            {"id": "reconspider", "name": "ReconSpider", "binary": "ReconSpider"},
            {"id": "shodanfy", "name": "Shodanfy", "binary": "shodanfy"},
            {"id": "dnsrecon", "name": "DNSRecon", "binary": "dnsrecon"},
            {"id": "recon_ng", "name": "Recon-ng", "binary": "recon-ng"},
        ]},
        {"id": "web_attack", "name": "Web Attack", "icon": "globe", "tools": [
            {"id": "nuclei", "name": "Nuclei", "binary": "nuclei"},
            {"id": "nikto", "name": "Nikto", "binary": "nikto"},
            {"id": "dirb", "name": "Dirb", "binary": "dirb"},
            {"id": "gobuster", "name": "Gobuster", "binary": "gobuster"},
            {"id": "ffuf", "name": "Ffuf", "binary": "ffuf"},
            {"id": "wafw00f", "name": "Wafw00f", "binary": "wafw00f"},
            {"id": "zap", "name": "OWASP ZAP", "binary": "zap"},
            {"id": "katana", "name": "Katana", "binary": "katana"},
            {"id": "sqlmap", "name": "SQLMap", "binary": "sqlmap"},
            {"id": "whatweb", "name": "WhatWeb", "binary": "whatweb"},
            {"id": "wpscan", "name": "WPScan", "binary": "wpscan"},
            {"id": "wfuzz", "name": "WFuzz", "binary": "wfuzz"},
        ]},
        {"id": "password_attacks", "name": "Password & Cracking", "icon": "lock", "tools": [
            {"id": "hydra", "name": "Hydra", "binary": "hydra"},
            {"id": "crunch", "name": "Crunch", "binary": "crunch"},
            {"id": "cewl", "name": "CeWL", "binary": "cewl"},
            {"id": "john", "name": "John the Ripper", "binary": "john"},
            {"id": "hashcat", "name": "Hashcat", "binary": "hashcat"},
        ]},
        {"id": "forensics", "name": "Forensics", "icon": "search", "tools": [
            {"id": "volatility3", "name": "Volatility 3", "binary": "vol"},
            {"id": "binwalk", "name": "Binwalk", "binary": "binwalk"},
            {"id": "bulk_extractor", "name": "Bulk Extractor", "binary": "bulk_extractor"},
            {"id": "foremost", "name": "Foremost", "binary": "foremost"},
            {"id": "testdisk", "name": "TestDisk", "binary": "testdisk"},
        ]},
        {"id": "wireless", "name": "Wireless Attack", "icon": "wifi", "tools": [
            {"id": "wifite", "name": "Wifite", "binary": "wifite"},
            {"id": "airgeddon", "name": "Airgeddon", "binary": "airgeddon"},
            {"id": "bettercap", "name": "Bettercap", "binary": "bettercap"},
            {"id": "aircrack_ng", "name": "Aircrack-ng", "binary": "aircrack-ng"},
        ]},
        {"id": "exploit", "name": "Exploit Frameworks", "icon": "zap", "tools": [
            {"id": "routersploit", "name": "RouterSploit", "binary": "routersploit"},
            {"id": "commix", "name": "Commix", "binary": "commix"},
            {"id": "searchsploit", "name": "SearchSploit", "binary": "searchsploit"},
            {"id": "metasploit", "name": "Metasploit (msfconsole)", "binary": "msfconsole"},
        ]},
        {"id": "reverse_engineering", "name": "Reverse Engineering", "icon": "code", "tools": [
            {"id": "ghidra", "name": "Ghidra", "binary": "ghidra"},
            {"id": "radare2", "name": "Radare2", "binary": "r2"},
            {"id": "jadx", "name": "JadX", "binary": "jadx"},
            {"id": "apktool", "name": "Apktool", "binary": "apktool"},
        ]},
        {"id": "payload", "name": "Payload Creation", "icon": "package", "tools": [
            {"id": "msfpc", "name": "MSFvenom Payload Creator", "binary": "msfpc"},
        ]},
        {"id": "wordlist", "name": "Wordlist Generator", "icon": "file-text", "tools": [
            {"id": "cupp", "name": "Cupp", "binary": "cupp"},
        ]},
        {"id": "cloud_security", "name": "Cloud Security", "icon": "cloud", "tools": [
            {"id": "prowler", "name": "Prowler", "binary": "prowler"},
            {"id": "trivy", "name": "Trivy", "binary": "trivy"},
        ]},
        {"id": "active_directory", "name": "Active Directory", "icon": "server", "tools": [
            {"id": "bloodhound", "name": "BloodHound", "binary": "bloodhound"},
            {"id": "impacket", "name": "Impacket", "binary": "impacket"},
            {"id": "responder", "name": "Responder", "binary": "responder"},
        ]},
        {"id": "steganography", "name": "Steganography", "icon": "image", "tools": [
            {"id": "stegocracker", "name": "StegoCracker", "binary": "stegocracker"},
        ]},
    ]

    for cat in categories:
        for tool in cat["tools"]:
            tool["installed"] = _check_tool(tool["binary"])

    return {
        "installed": True,
        "ht_dir": ht_dir,
        "categories": categories,
        "total_tools": sum(len(c["tools"]) for c in categories),
    }


def _check_tool(binary: str) -> bool:
    try:
        result = subprocess.run(
            ["which", binary],
            capture_output=True, text=True, timeout=5,
        )
        return result.returncode == 0
    except Exception:
        return False


def run_tool(category_id: str, tool_id: str, target: str = "", args: str = "") -> dict:
    ht_dir = _ensure_dir()
    if not ht_dir:
        return {"error": "hackingtool not found"}

    tool_map = {}
    for cat in get_categories().get("categories", []):
        for tool in cat["tools"]:
            tool_map[tool["id"]] = tool

    tool = tool_map.get(tool_id)
    if not tool:
        return {"error": f"Tool '{tool_id}' not found"}

    binary = tool.get("binary", tool_id)
    if not _check_tool(binary):
        return {
            "error": f"'{binary}' is not installed",
            "tool_id": tool_id,
            "suggestion": f"Install via hackingtool or your package manager",
        }

    cmd_parts = [binary]
    if target:
        cmd_parts.append(target)
    if args:
        cmd_parts.extend(args.split())

    try:
        result = subprocess.run(
            cmd_parts,
            capture_output=True,
            text=True,
            timeout=120,
        )
        return {
            "tool_id": tool_id,
            "command": " ".join(cmd_parts),
            "status": "completed" if result.returncode == 0 else "failed",
            "return_code": result.returncode,
            "stdout": result.stdout[:50000],
            "stderr": result.stderr[:2000],
        }
    except subprocess.TimeoutExpired:
        return {
            "tool_id": tool_id,
            "command": " ".join(cmd_parts),
            "status": "timeout",
            "stdout": "Command timed out after 120 seconds.",
        }
    except Exception as e:
        return {
            "tool_id": tool_id,
            "status": "error",
            "error": str(e),
        }
