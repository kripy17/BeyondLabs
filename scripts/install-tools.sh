#!/usr/bin/env bash
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'

echo -e "${CYAN}╔════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║    BeyondLabs — Tool Installer            ║${NC}"
echo -e "${CYAN}║    Installs SOC/recon dependencies        ║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════════╝${NC}"
echo ""

detect_pkg() {
  if command -v apt-get &>/dev/null; then
    PKG="apt"; INSTALL="sudo apt-get install -y"
  elif command -v brew &>/dev/null; then
    PKG="brew"; INSTALL="brew install"
  elif command -v dnf &>/dev/null; then
    PKG="dnf"; INSTALL="sudo dnf install -y"
  elif command -v pacman &>/dev/null; then
    PKG="pacman"; INSTALL="sudo pacman -S --noconfirm"
  else
    echo -e "${RED}No supported package manager found.${NC}"
    echo -e "${YELLOW}Supported: apt (Debian/Ubuntu), brew (macOS), dnf (Fedora), pacman (Arch)${NC}"
    exit 1
  fi
  echo -e "${GREEN}Detected package manager: ${PKG}${NC}"
}

pkg_name() {
  case "$PKG" in
    apt)    echo "$1" ;;
    brew)   echo "$1" ;;
    dnf)    echo "$1" ;;
    pacman) echo "$1" ;;
  esac
}

install_group() {
  local group_name="$1"; shift
  local pkgs=("$@")
  echo ""
  echo -e "${BLUE}── ${group_name} ──${NC}"
  local missing=()
  for p in "${pkgs[@]}"; do
    if command -v "$p" &>/dev/null; then
      echo -e "  ${GREEN}✓${NC} $p already installed"
    else
      missing+=("$p")
    fi
  done
  if [ ${#missing[@]} -eq 0 ]; then
    echo -e "  ${GREEN}All installed.${NC}"
    return
  fi
  echo -e "  ${YELLOW}Missing:${NC} ${missing[*]}"
  read -r -p "  Install these ${#missing[@]} tools? [Y/n] " ans
  if [[ "$ans" =~ ^[Nn] ]]; then
    echo -e "  ${YELLOW}Skipped.${NC}"
    return
  fi
  for p in "${missing[@]}"; do
    echo -ne "  Installing ${p}... "
    if $INSTALL "$(pkg_name "$p")" &>/dev/null; then
      echo -e "${GREEN}done${NC}"
    else
      echo -e "${RED}failed${NC}"
      echo -e "  ${YELLOW}  Try: ${INSTALL} $(pkg_name "$p")${NC}"
    fi
  done
}

detect_pkg

echo ""
echo -e "${CYAN}Tool groups:${NC}"
echo "  1) Core helpers (curl, openssl, file, strings, jq)"
echo "  2) DNS/domain (dig, nslookup, whois, traceroute)"
echo "  3) Recon/scanning (nmap, whatweb, subfinder, amass, httpx)"
echo "  4) OSINT (theHarvester, assetfinder, waybackurls, gau, katana)"
echo "  5) Advanced active (nuclei, ffuf, gobuster)"
echo "  6) All of the above"
echo "  7) Skip — exit"
echo ""

read -r -p "Choose [1-7]: " choice

case "$choice" in
  1) install_group "Core helpers" curl openssl file strings jq ;;
  2) install_group "DNS/domain" dig nslookup whois traceroute ;;
  3) install_group "Recon/scanning" nmap whatweb subfinder amass httpx ;;
  4) install_group "OSINT" theHarvester assetfinder waybackurls gau katana ;;
  5) install_group "Advanced active" nuclei ffuf gobuster ;;
  6)
    install_group "Core helpers" curl openssl file strings jq
    install_group "DNS/domain" dig nslookup whois traceroute
    install_group "Recon/scanning" nmap whatweb subfinder amass httpx
    install_group "OSINT" theHarvester assetfinder waybackurls gau katana
    install_group "Advanced active" nuclei ffuf gobuster
    ;;
  7) echo "bye."; exit 0 ;;
  *) echo -e "${RED}Invalid choice.${NC}"; exit 1 ;;
esac

echo ""
echo -e "${GREEN}╔════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║    Done. Some tools may need a restart.   ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════╝${NC}"
