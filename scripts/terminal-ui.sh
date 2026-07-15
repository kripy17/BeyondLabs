# BeyondLabs terminal UI toolkit — signature visual identity
# Source with: . scripts/terminal-ui.sh
#
# One shared palette + one shared logo. Every entry script (install.sh,
# run.sh, doctor.sh, reset-workspace.sh, demo-workflow.sh) sources this file
# instead of redefining its own colors or banner — that duplication is how
# the old rebrand drifted out of sync in the first place.

C_RESET='\033[0m'
C_BOLD='\033[1m'
C_DIM='\033[2m'
C_ITALIC='\033[3m'

# Signature accent: amber, not the cyan every other CLI tool defaults to.
# Kept under the old variable names so nothing else has to change.
C_CYAN='\033[38;5;214m'      # signature amber accent
C_BLUE='\033[38;5;214m'      # alias, same accent
C_YELLOW='\033[38;5;179m'    # warm gold — warnings
C_GREEN='\033[38;5;108m'     # muted sage — success
C_RED='\033[38;5;203m'       # coral — errors
C_MAGENTA='\033[38;5;138m'   # muted rose — used sparingly
C_GREY='\033[38;5;245m'

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
ba_hr()      { echo -e "  ${C_DIM}──────────────────────────────────────────────${C_RESET}"; }
ba_hr_bold() { echo -e "  ${C_CYAN}══════════════════════════════════════════════${C_RESET}"; }
ba_hr_thin() { echo -e "  ${C_DIM}･ ･ ･ ･ ･ ･ ･ ･ ･ ･ ･ ･ ･ ･ ･ ･ ･ ･ ･ ･ ･ ･ ･ ･ ･ ･ ･ ･ ･ ･${C_RESET}"; }

# ── Boot sequence ─────────────────────────────────────────────
# A handful of faux system lines with timestamps before the logo, echoing
# the boot-sequence intro already used on the BeyondLabs web frontend.
# Silent (skips animation) when not attached to a real terminal.
ba_boot() {
  local line
  for line in "$@"; do
    echo -e "  ${C_DIM}$(date +%H:%M:%S)${C_RESET}  ${C_GREY}${line}${C_RESET}"
    [[ -t 1 ]] && sleep 0.05
  done
}

# ── Header / Logo ──────────────────────────────────────────────
# Single canonical logo. Do NOT redefine ba_logo() in individual scripts —
# that's exactly how the old banner went stale in three different places.
ba_logo() {
  echo ""
  echo -e "${C_CYAN}${C_BOLD}"
  echo '  ██████╗ ███████╗██╗   ██╗ ██████╗ ███╗   ██╗██████╗ ██╗      █████╗ ██████╗ ███████╗'
  echo '  ██╔══██╗██╔════╝╚██╗ ██╔╝██╔═══██╗████╗  ██║██╔══██╗██║     ██╔══██╗██╔══██╗██╔════╝'
  echo '  ██████╔╝█████╗   ╚████╔╝ ██║   ██║██╔██╗ ██║██║  ██║██║     ███████║██████╔╝███████╗'
  echo '  ██╔══██╗██╔══╝    ╚██╔╝  ██║   ██║██║╚██╗██║██║  ██║██║     ██╔══██║██╔══██╗╚════██║'
  echo '  ██████╔╝███████╗   ██║   ╚██████╔╝██║ ╚████║██████╔╝███████╗██║  ██║██████╔╝███████║'
  echo '  ╚═════╝ ╚══════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═══╝╚═════╝ ╚══════╝╚═╝  ╚═╝╚═════╝ ╚══════╝'
  echo -e "${C_RESET}"
}

# Logo + tagline strip, framed with dotted scan marks instead of a plain
# subtitle line. Pass a tagline (defaults to the standard one) and version.
ba_banner() {
  local tagline="${1:-Local SOC Investigation Workbench}"
  local version="${2:-v0.1.0}"
  ba_logo
  echo -e "  ${C_GREY}┈┈┈${C_RESET} ${C_BOLD}${tagline}${C_RESET} ${C_GREY}┈┈┈${C_RESET} ${C_DIM}${version}${C_RESET}"
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
  echo -e "  ${C_BOLD}${C_CYAN}BeyondLabs${C_RESET} ${C_DIM}— ${label}${C_RESET}"
  ba_hr
}

# ── Usage header ────────────────────────────────────────────────
ba_usage_header() {
  local label="$1"
  echo ""
  echo -e "  ${C_BOLD}${C_CYAN}BeyondLabs${C_RESET} ${C_DIM}— ${label}${C_RESET}"
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
  log_file="$(mktemp -t beyondlabs.XXXXXX.log)"
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
  printf '  %s╭%s╮%s\n' "${C_CYAN}" "$(printf '─%.0s' $(seq 1 $width))" "${C_RESET}"
  printf '  %s│%s%s%s│%s\n' "${C_CYAN}" "$(printf ' %.0s' $(seq 1 $pad))" "${C_BOLD}${title}${C_RESET}${C_CYAN}" "$(printf ' %.0s' $(seq 1 $((width - pad - ${#title}))))" "${C_RESET}"
  printf '  %s╰%s╯%s\n' "${C_CYAN}" "$(printf '─%.0s' $(seq 1 $width))" "${C_RESET}"
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
