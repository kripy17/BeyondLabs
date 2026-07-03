#!/usr/bin/env bash

# Shared optional helper inventory for install.sh and doctor.sh.
# Format: group|command candidates|pacman package|brew package|category|description

detect_platform() {
  case "$(uname -s)" in
    Darwin)
      PKG_MGR="brew"
      PKG_MGR_NAME="Homebrew"
      PKG_MGR_INSTALL="brew install"
      PKG_MGR_SEARCH="brew info"
      PKG_MGR_UPDATE="brew update"
      PKG_MGR_UPGRADE="brew upgrade"
      ;;
    Linux)
      if command -v pacman >/dev/null 2>&1; then
        PKG_MGR="pacman"
        PKG_MGR_NAME="pacman (Arch Linux)"
        PKG_MGR_INSTALL="sudo pacman -S --needed"
        PKG_MGR_SEARCH="pacman -Si"
        PKG_MGR_UPDATE="sudo pacman -Syu"
        PKG_MGR_UPGRADE="sudo pacman -Syu"
      elif command -v apt-get >/dev/null 2>&1; then
        PKG_MGR="apt"
        PKG_MGR_NAME="apt (Debian/Ubuntu)"
        PKG_MGR_INSTALL="sudo apt-get install -y"
        PKG_MGR_SEARCH="apt-cache show"
        PKG_MGR_UPDATE="sudo apt-get update"
        PKG_MGR_UPGRADE="sudo apt-get upgrade -y"
      elif command -v dnf >/dev/null 2>&1; then
        PKG_MGR="dnf"
        PKG_MGR_NAME="dnf (Fedora)"
        PKG_MGR_INSTALL="sudo dnf install -y"
        PKG_MGR_SEARCH="dnf info"
        PKG_MGR_UPDATE="sudo dnf check-update"
        PKG_MGR_UPGRADE="sudo dnf upgrade -y"
      else
        PKG_MGR="unknown"
        PKG_MGR_NAME="unknown"
        PKG_MGR_INSTALL=""
        PKG_MGR_SEARCH=""
        PKG_MGR_UPDATE=""
        PKG_MGR_UPGRADE=""
      fi
      ;;
    *)
      PKG_MGR="unknown"
      PKG_MGR_NAME="unknown"
      PKG_MGR_INSTALL=""
      PKG_MGR_SEARCH=""
      PKG_MGR_UPDATE=""
      PKG_MGR_UPGRADE=""
      ;;
  esac
}

# Call once so PKG_MGR vars are available globally
detect_platform

# group|bins|pacman_pkg|brew_pkg|category|description
TOOL_ROWS=(
  "core|curl|curl|curl|Core helpers|HTTP/header checks"
  "core|openssl|openssl|openssl|Core helpers|TLS certificate checks"
  "core|file|file|file|Core helpers|File type inspection"
  "core|strings|binutils|binutils|Core helpers|Static strings helper"
  "core|jq|jq|jq|Core helpers|JSON inspection"
  "core|__python_pip__|python-pip|python|Core helpers|Python package helper"
  "core|__python_venv__|python|python|Core helpers|Python virtual environment support"
  "dns|dig nslookup|bind|bind|DNS/domain metadata|DNS baseline and mail posture"
  "dns|whois|whois|whois|DNS/domain metadata|WHOIS registration metadata"
  "dns|traceroute|traceroute|traceroute|DNS/domain metadata|Network path metadata"
  "dns|mtr|mtr|mtr|DNS/domain metadata|Path diagnostics if available"
  "recommended|nmap|nmap|nmap|Recommended SOC/recon helpers|Authorized bounded scanning"
  "recommended|whatweb|whatweb|whatweb|Recommended SOC/recon helpers|Web technology fingerprinting"
  "recommended|subfinder|subfinder|subfinder|Recommended SOC/recon helpers|Passive subdomain enumeration"
  "recommended|amass|amass|amass|Recommended SOC/recon helpers|Passive subdomain enumeration"
  "recommended|httpx|httpx-toolkit|httpx|Recommended SOC/recon helpers|HTTP probing helper"
  "manual|theHarvester theharvester|theharvester|theharvester|Manual/optional OSINT helpers|Passive email/host/subdomain discovery"
  "manual|assetfinder|assetfinder|assetfinder|Manual/optional OSINT helpers|Passive subdomain enumeration"
  "manual|waybackurls|waybackurls|waybackurls|Manual/optional OSINT helpers|Archive URL collection"
  "manual|gau|gau|gau|Manual/optional OSINT helpers|Archive URL collection"
  "manual|katana|katana|katana|Manual/optional OSINT helpers|Crawler helper"
  "advanced|nuclei|nuclei|nuclei|Advanced active tools|Advanced template scanner"
  "advanced|ffuf|ffuf|ffuf|Advanced active tools|Active fuzzing helper"
  "advanced|gobuster|gobuster|gobuster|Advanced active tools|Active discovery helper"
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

pkg_available() {
  local pacman_pkg="$1" brew_pkg="$2"
  case "$PKG_MGR" in
    pacman) pacman -Si "$pacman_pkg" >/dev/null 2>&1; return $? ;;
    brew)   brew info "$brew_pkg" >/dev/null 2>&1; return $? ;;
    apt)    apt-cache show "$pacman_pkg" >/dev/null 2>&1; return $? ;;
    dnf)    dnf info "$pacman_pkg" >/dev/null 2>&1; return $? ;;
    *)      return 1 ;;
  esac
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
