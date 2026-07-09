import shlex
import shutil
import subprocess
import time
from pathlib import Path

from app.services.tool_runner.parsers.generic import parse_generic_output
from app.services.tool_runner.registry import get_tool
from app.services.tool_runner.safety import authorization_error, hostname_from_target, validate_target_text
from app.services.tool_runner.schemas import ToolRunRequest
from app.services.tool_runner.tools.local_labs import (
    run_controlled_workflow,
    run_pattern_lab,
    run_secretfinder,
    run_web_crawler,
    run_wordlist_lab,
)


def _checked_at() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _command_preview(command: list[str]) -> str:
    return " ".join(shlex.quote(part) for part in command)


def _base_result(tool, request: ToolRunRequest, started_at: str, command: list[str] | None = None) -> dict:
    return {
        "tool": tool.name,
        "tool_id": tool.id,
        "target": request.target,
        "profile": request.profile,
        "command_preview": _command_preview(command) if command else "",
        "started_at": started_at,
        "duration": 0,
        "exit_code": None,
        "parsed_summary": {},
        "raw_output": "",
        "limitations": tool.limitations,
        "detection_notes": {
            "defender_artifacts": tool.defender_artifacts,
            "detection_ideas": tool.detection_ideas,
        },
        "mitre_mapping": tool.mitre_mapping,
        "report_actions": tool.report_actions,
        "source": "BeyondLabs Offensive Lab",
        "method": "allowlisted runner" if tool.kind == "cli" else f"{tool.kind} lab helper",
        "confidence": "analyst-review-required",
        "checked_at": _checked_at(),
    }


def _wordlist_path(request: ToolRunRequest) -> str | None:
    value = str(request.inputs.get("wordlist_path") or "").strip()
    if not value:
        return None
    path = Path(value).expanduser()
    if not path.is_file():
        return None
    return str(path)


def _hash_file_path(request: ToolRunRequest) -> str | None:
    value = str(request.inputs.get("hash_file_path") or "").strip()
    if not value:
        return None
    path = Path(value).expanduser()
    if not path.is_file():
        return None
    return str(path)


def build_command(tool_id: str, request: ToolRunRequest) -> tuple[list[str] | None, str | None]:
    target = request.target.strip()
    hostname = hostname_from_target(target)

    if tool_id == "nmap":
        profiles = {
            "top100": ["nmap", "-Pn", "-sV", "--top-ports", "100", hostname],
            "service": ["nmap", "-sV", "-T3", hostname],
            "safe_scripts": ["nmap", "--script", "safe", "-sV", "-T3", hostname],
        }
        return profiles.get(request.profile), None
    if tool_id == "whatweb":
        return ["whatweb", "--no-errors", target], None
    if tool_id == "gobuster-dir":
        wordlist = _wordlist_path(request)
        if not wordlist:
            return None, "Gobuster requires inputs.wordlist_path pointing to an existing local wordlist."
        return ["gobuster", "dir", "-u", target, "-w", wordlist, "-t", "10", "--no-error"], None
    if tool_id == "ffuf-dir":
        wordlist = _wordlist_path(request)
        if not wordlist:
            return None, "ffuf requires inputs.wordlist_path pointing to an existing local wordlist."
        fuzz_url = target if "FUZZ" in target else target.rstrip("/") + "/FUZZ"
        return ["ffuf", "-u", fuzz_url, "-w", wordlist, "-rate", "50", "-ac"], None
    if tool_id == "nikto":
        return ["nikto", "-host", target, "-nointeractive"], None
    if tool_id == "nuclei":
        return ["nuclei", "-u", target, "-severity", "info,low", "-silent"], None
    if tool_id == "sqlmap-lab":
        return ["sqlmap", "-u", target, "--batch", "--level", "1", "--risk", "1", "--smart"], None
    if tool_id == "john-audit":
        hash_file = _hash_file_path(request)
        if not hash_file:
            return None, "John audit requires inputs.hash_file_path pointing to an existing local hash file."
        return ["john", "--show", hash_file], None
    return None, "No command builder is available for this tool."


def _knowledge_result(tool, request: ToolRunRequest, started_at: str) -> dict:
    result = _base_result(tool, request, started_at)
    result["parsed_summary"] = {
        "purpose": tool.purpose,
        "authorized_lab_usage": tool.usage_note,
        "backend_runner": False,
        "status": "knowledge-only",
        "learning_objectives": tool.knowledge.get("learning_objectives", []),
        "safe_lab_scope": tool.knowledge.get("safe_lab_scope", []),
        "not_implemented": tool.knowledge.get("not_implemented", []),
        "workflow": tool.knowledge.get("workflow", []),
        "practice_prompts": tool.knowledge.get("practice_prompts", []),
    }
    result["knowledge"] = tool.knowledge
    result["limitations"] = tool.limitations
    return result


def _local_result(tool, request: ToolRunRequest, started_at: str) -> dict:
    result = _base_result(tool, request, started_at)
    if tool.id == "web-crawler":
        local = run_web_crawler(request.target.strip(), request.inputs, request.timeout_seconds)
    elif tool.id == "secretfinder-js":
        local = run_secretfinder(request.target.strip(), request.inputs, request.timeout_seconds)
    elif tool.id == "wordlist-lab":
        local = run_wordlist_lab(request.inputs)
    elif tool.id in {"xss-sqli-helper", "forensics-artifact-extractor", "stego-lab"}:
        local = run_pattern_lab(tool.id, request.inputs)
    elif tool.id in {
        "payload-risk-workflow",
        "exploit-risk-workflow",
        "reverse-shell-detection-workflow",
        "malware-static-workflow",
        "credential-attack-detection-workflow",
        "stealth-evasion-detection-workflow",
        "destructive-command-guardrail",
        "social-engineering-triage-workflow",
    }:
        local = run_controlled_workflow(tool.id, request.inputs)
    else:
        local = {
            "parsed_summary": {"error": "No local helper is available for this tool."},
            "raw_output": "",
            "limitations": tool.limitations,
            "duration": 0,
            "checked_at": _checked_at(),
        }
    result.update(local)
    result["checked_at"] = local.get("checked_at", result["checked_at"])
    return result


def run_tool(request: ToolRunRequest) -> dict:
    started_at = _checked_at()
    start = time.perf_counter()
    tool = get_tool(request.tool_id)
    if tool is None:
        return {
            "error": "Tool is not in the allowed Offensive Lab registry.",
            "allowed": False,
            "checked_at": started_at,
        }

    if tool.kind == "knowledge":
        return _knowledge_result(tool, request, started_at)

    no_target_local_tools = {
        "wordlist-lab",
        "secretfinder-js",
        "xss-sqli-helper",
        "forensics-artifact-extractor",
        "stego-lab",
        "payload-risk-workflow",
        "exploit-risk-workflow",
        "reverse-shell-detection-workflow",
        "malware-static-workflow",
        "credential-attack-detection-workflow",
        "stealth-evasion-detection-workflow",
        "destructive-command-guardrail",
        "social-engineering-triage-workflow",
    }
    if tool.kind in {"cli", "local"} and tool.group != "Password & Credential Lab":
        target_error = validate_target_text(request.target.strip())
        if tool.id not in no_target_local_tools and target_error:
            result = _base_result(tool, request, started_at)
            result["limitations"] = [target_error, *tool.limitations]
            return result

    auth_error = authorization_error(tool.group, request.target.strip(), request.confirm_authorization, request.allow_private)
    if auth_error:
        result = _base_result(tool, request, started_at)
        result["limitations"] = [auth_error, *tool.limitations]
        return result

    if tool.kind == "local":
        return _local_result(tool, request, started_at)

    if not tool.cli_name or shutil.which(tool.cli_name) is None:
        result = _base_result(tool, request, started_at)
        result["limitations"] = [f"{tool.cli_name or tool.name} is not installed or not available in PATH.", *tool.limitations]
        result["parsed_summary"] = {"status": "missing_cli", "backend_runner": True}
        return result

    command, command_error = build_command(tool.id, request)
    if command_error or not command:
        result = _base_result(tool, request, started_at)
        result["limitations"] = [command_error or "Unable to build command.", *tool.limitations]
        return result

    result = _base_result(tool, request, started_at, command)
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=request.timeout_seconds,
            shell=False,
        )
        stdout = completed.stdout or ""
        stderr = completed.stderr or ""
        result["duration"] = round(time.perf_counter() - start, 3)
        result["exit_code"] = completed.returncode
        result["raw_output"] = "\n".join(part for part in [stdout, stderr] if part)
        result["parsed_summary"] = parse_generic_output(tool.id, stdout, stderr)
        return result
    except subprocess.TimeoutExpired as exc:
        result["duration"] = round(time.perf_counter() - start, 3)
        result["limitations"] = [f"{tool.name} timed out after {request.timeout_seconds} seconds.", *tool.limitations]
        result["raw_output"] = (exc.stdout or "") + (exc.stderr or "")
        return result
