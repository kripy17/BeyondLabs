#!/usr/bin/env bash

# Shared optional helper inventory for install.sh and doctor.sh.
# Format: group|command candidates|pacman package|category|description
TOOL_ROWS=(
  "core|curl|curl|Core helpers|HTTP/header checks"
  "core|openssl|openssl|Core helpers|TLS certificate checks"
  "core|file|file|Core helpers|File type inspection"
  "core|strings|binutils|Core helpers|Static strings helper"
  "core|jq|jq|Core helpers|JSON inspection"
  "core|__python_pip__|python-pip|Core helpers|Python package helper"
  "core|__python_venv__|python|Core helpers|Python virtual environment support"
  "dns|dig nslookup|bind|DNS/domain metadata|DNS baseline and mail posture"
  "dns|whois|whois|DNS/domain metadata|WHOIS registration metadata"
  "dns|traceroute|traceroute|DNS/domain metadata|Network path metadata"
  "dns|mtr|mtr|DNS/domain metadata|Path diagnostics if available"
  "recommended|nmap|nmap|Recommended SOC/recon helpers|Authorized bounded scanning"
  "recommended|whatweb|whatweb|Recommended SOC/recon helpers|Web technology fingerprinting"
  "recommended|subfinder|subfinder|Recommended SOC/recon helpers|Passive subdomain enumeration"
  "recommended|amass|amass|Recommended SOC/recon helpers|Passive subdomain enumeration"
  "recommended|httpx|httpx-toolkit|Recommended SOC/recon helpers|HTTP probing helper"
  "manual|theHarvester theharvester|theharvester|Manual/optional OSINT helpers|Passive email/host/subdomain discovery"
  "manual|assetfinder|assetfinder|Manual/optional OSINT helpers|Passive subdomain enumeration"
  "manual|waybackurls|waybackurls|Manual/optional OSINT helpers|Archive URL collection"
  "manual|gau|gau|Manual/optional OSINT helpers|Archive URL collection"
  "manual|katana|katana|Manual/optional OSINT helpers|Crawler helper"
  "advanced|nuclei|nuclei|Advanced active tools|Advanced template scanner"
  "advanced|ffuf|ffuf|Advanced active tools|Active fuzzing helper"
  "advanced|gobuster|gobuster|Advanced active tools|Active discovery helper"
)

tool_available() {
  local names="$1" name py_bin
  if [[ "$names" == "__python_pip__" ]]; then
    if [[ -n "${PYTHON_BIN:-}" ]]; then "$PYTHON_BIN" -m pip --version >/dev/null 2>&1; return $?; fi
    if command -v python3 >/dev/null 2>&1; then py_bin="$(command -v python3)"
    elif command -v python >/dev/null 2>&1; then py_bin="$(command -v python)"
    else return 1
    fi
    "$py_bin" -m pip --version >/dev/null 2>&1
    return $?
  fi
  if [[ "$names" == "__python_venv__" ]]; then
    if [[ -n "${PYTHON_BIN:-}" ]]; then "$PYTHON_BIN" -m venv --help >/dev/null 2>&1; return $?; fi
    if command -v python3 >/dev/null 2>&1; then py_bin="$(command -v python3)"
    elif command -v python >/dev/null 2>&1; then py_bin="$(command -v python)"
    else return 1
    fi
    "$py_bin" -m venv --help >/dev/null 2>&1
    return $?
  fi
  for name in $names; do
    command -v "$name" >/dev/null 2>&1 && return 0
  done
  return 1
}

display_tool() {
  case "$1" in
    "__python_pip__") printf 'python -m pip' ;;
    "__python_venv__") printf 'python -m venv' ;;
    "dig nslookup") printf 'dig/nslookup' ;;
    "theHarvester theharvester") printf 'theHarvester' ;;
    *) printf '%s' "${1%% *}" ;;
  esac
}

tool_group_label() {
  case "$1" in
    core) printf 'Core helpers' ;;
    dns) printf 'DNS/domain metadata' ;;
    recommended) printf 'Recommended SOC/recon helpers' ;;
    manual) printf 'Manual/optional OSINT helpers' ;;
    advanced) printf 'Advanced active tools' ;;
    *) printf '%s' "$1" ;;
  esac
}
