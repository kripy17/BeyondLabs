# BeyondArch terminal UI helpers — visual toolkit
# Source with: . scripts/terminal-ui.sh

C_RESET='\033[0m'
C_BOLD='\033[1m'
C_DIM='\033[2m'
C_ITALIC='\033[3m'
C_CYAN='\033[0;36m'
C_GREEN='\033[0;32m'
C_YELLOW='\033[0;33m'
C_RED='\033[0;31m'
C_MAGENTA='\033[0;35m'
C_BLUE='\033[0;34m'

BA_RESET="$C_RESET"
BA_BOLD="$C_BOLD"
BA_DIM="$C_DIM"
BA_CYAN="$C_CYAN"
BA_GREEN="$C_GREEN"
BA_YELLOW="$C_YELLOW"
BA_RED="$C_RED"
BA_BLUE="$C_CYAN"
BA_MAGENTA="$C_MAGENTA"

# ── Dividers ──────────────────────────────────────────────────
ba_hr()     { echo -e "  ${C_DIM}──────────────────────────────────────────────${C_RESET}"; }
ba_hr_thin(){ echo -e "  ${C_DIM}･ ･ ･ ･ ･ ･ ･ ･ ･ ･ ･ ･ ･ ･ ･ ･ ･ ･ ･ ･ ･ ･ ･ ･ ･ ･ ･ ･ ･ ･${C_RESET}"; }

# ── Header / Logo ──────────────────────────────────────────────
ba_logo() {
  echo -e "${C_CYAN}"
  echo '  ██████╗ ███████╗██╗   ██╗ ██████╗ ███╗   ██╗██████╗ '
  echo '  ██╔══██╗██╔════╝╚██╗ ██╔╝██╔═══██╗████╗  ██║██╔══██╗'
  echo '  ██████╔╝█████╗   ╚████╔╝ ██║   ██║██╔██╗ ██║██████╔╝'
  echo '  ██╔══██╗██╔══╝    ╚██╔╝  ██║   ██║██║╚██╗██║██╔══██╗'
  echo '  ██████╔╝███████╗   ██║   ╚██████╔╝██║ ╚████║██████╔╝'
  echo '  ╚═════╝ ╚══════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═══╝╚═════╝ '
  echo -e "${C_RESET}"
}

ba_header() {
  local label="$1"; shift
  echo ""
  echo -e "  ${C_BOLD}${C_CYAN}${label}${C_RESET}"
  [[ $# -gt 0 ]] && echo -e "  ${C_DIM}$*${C_RESET}"
  ba_hr
}

# ── Compact header (no logo, single label line) ─────────────────
ba_compact_header() {
  local label="$1"
  echo ""
  echo -e "  ${C_BOLD}${C_CYAN}BeyondArch${C_RESET} ${C_DIM}— ${label}${C_RESET}"
  ba_hr
}

# ── Usage header ────────────────────────────────────────────────
ba_usage_header() {
  local label="$1"
  echo ""
  echo -e "  ${C_BOLD}${C_CYAN}BeyondArch${C_RESET} ${C_DIM}— ${label}${C_RESET}"
  echo -e "  ${C_DIM}──────────────────────────────────────────────${C_RESET}"
}

# ── Section ────────────────────────────────────────────────────
ba_section() {
  local num="$1"; shift
  echo ""
  echo -e "  ${C_BOLD}${C_CYAN}[${num}]${C_RESET} ${C_BOLD}$*${C_RESET}"
  echo -e "  ${C_DIM}──────────────────────────────────────────────${C_RESET}"
}

# ── Status markers ──────────────────────────────────────────────
ba_ok()      { echo -e "  ${C_GREEN}●${C_RESET} $*"; }
ba_info()    { echo -e "  ${C_CYAN}◆${C_RESET} $*"; }
ba_warn()    { echo -e "  ${C_YELLOW}▲${C_RESET} $*"; }
ba_err()     { echo -e "  ${C_RED}■${C_RESET} $*" >&2; }
ba_muted()   { echo -e "  ${C_DIM}$*${C_RESET}"; }

ba_prompt()  { printf "\n  ${C_CYAN}?${C_RESET} ${C_BOLD}%s${C_RESET} " "$*" >&2; }
ba_phase()   { echo -en "${C_DIM}  ${C_RESET}"; }

# ── Status line (inline update) ─────────────────────────────────
ba_status_line() {
  local label="$1"; shift
  printf '\r  %s[%s]%s %s' "${C_CYAN}" "${C_RESET}$*" "${C_RESET}" "$label"
}

# ── Spinner ────────────────────────────────────────────────────
ba_spin() {
  local label="$1"; shift
  local log_file
  log_file="$(mktemp -t beyondarch.XXXXXX.log)"
  if [[ -t 1 ]]; then
    ("$@") >"$log_file" 2>&1 &
    local pid=$!
    local i=0
    while kill -0 "$pid" 2>/dev/null; do
      case $((i % 4)) in
        0) printf '\r  %s⡿%s %s' "${C_CYAN}" "${C_RESET}" "$label" ;;
        1) printf '\r  %s⣾%s %s' "${C_CYAN}" "${C_RESET}" "$label" ;;
        2) printf '\r  %s⣽%s %s' "${C_CYAN}" "${C_RESET}" "$label" ;;
        3) printf '\r  %s⣻%s %s' "${C_CYAN}" "${C_RESET}" "$label" ;;
      esac
      sleep 0.12
      i=$((i + 1))
    done
    printf '\r'
    if wait "$pid"; then
      ba_ok "$label"
      rm -f "$log_file"
      return 0
    fi
  else
    if "$@" >"$log_file" 2>&1; then
      ba_ok "$label"
      rm -f "$log_file"
      return 0
    fi
  fi
  ba_err "$label failed"
  sed -n '1,120p' "$log_file" >&2
  rm -f "$log_file"
  return 1
}

# ── Box ─────────────────────────────────────────────────────────
ba_box() {
  local title="$1"; shift
  local width=46
  local pad=$(( (width - ${#title} - 2) / 2 ))
  printf '\n'
  printf '  %s┌%s┐%s\n' "${C_CYAN}" "$(printf '─%.0s' $(seq 1 $width))" "${C_RESET}"
  printf '  %s│%s%s%s│%s\n' "${C_CYAN}" "$(printf ' %.0s' $(seq 1 $pad))" "${C_BOLD}${title}${C_RESET}${C_CYAN}" "$(printf ' %.0s' $(seq 1 $((width - pad - ${#title}))))" "${C_RESET}"
  printf '  %s└%s┘%s\n' "${C_CYAN}" "$(printf '─%.0s' $(seq 1 $width))" "${C_RESET}"
}

ba_subbox() {
  local title="$1"
  local width=46
  printf '  %s├─ %s ─%s\n' "${C_DIM}" "$title" "$(printf '─%.0s' $(seq 1 $((width - ${#title} - 5))))${C_RESET}"
}

# ── Summary panel ───────────────────────────────────────────────
ba_summary() {
  local pass="$1" warn="$2" fail="$3" info="${4:-0}"
  ba_hr
  echo -e "  ${C_GREEN}●${C_RESET} ${C_BOLD}${pass}${C_RESET} passed  ${C_YELLOW}▲${C_RESET} ${C_BOLD}${warn}${C_RESET} warnings  ${C_RED}■${C_RESET} ${C_BOLD}${fail}${C_RESET} errors  ${C_CYAN}◆${C_RESET} ${C_BOLD}${info}${C_RESET} info"
}

# ── Key-value table ─────────────────────────────────────────────
ba_kv() {
  local key="$1" value="$2"
  printf '  %s%-20s%s %s\n' "${C_DIM}" "$key" "${C_RESET}" "$value"
}

# ── URL / link ──────────────────────────────────────────────────
ba_url() {
  echo -e "  ${C_CYAN}┃${C_RESET}  $*"
}

# ── Exit marker ────────────────────────────────────────────────
ba_done() {
  echo ""
  echo -e "  ${C_GREEN}●${C_RESET} ${C_BOLD}$*${C_RESET}"
}
