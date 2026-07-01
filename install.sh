#!/usr/bin/env bash
# BeyondArch — setup wizard
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="$ROOT_DIR/backend"
FRONTEND_DIR="$ROOT_DIR/frontend"
UI_HELPER="$ROOT_DIR/scripts/terminal-ui.sh"
TOOL_INVENTORY="$ROOT_DIR/scripts/tool-inventory.sh"
STATE_DIR="$ROOT_DIR/.beyondarch"
INSTALLED_TOOLS_STATE="$STATE_DIR/installed-tools.txt"
START_TS=$(date +%s)
PYTHON_BIN="${PYTHON_BIN:-}"
ASSUME_YES=0
PROFILE=""
NO_TOOLS=0
ADVANCED_ACTIVE=0
_STEP=0
_INTERRUPTED=0

# ── Inline colors for pre-source errors ─────────────────────────
_R='\033[0;31m' _D='\033[2m' _X='\033[0m'

if [[ ! -f "$UI_HELPER" ]]; then
  printf "${_R}  ✖${_X}  Missing scripts/terminal-ui.sh\n" >&2
  printf "     ${_D}Run this script from the BeyondArch project root.${_X}\n" >&2
  exit 1
fi
if [[ ! -f "$TOOL_INVENTORY" ]]; then
  printf "${_R}  ✖${_X}  Missing scripts/tool-inventory.sh\n" >&2
  printf "     ${_D}Run this script from the BeyondArch project root.${_X}\n" >&2
  exit 1
fi

# shellcheck source=scripts/terminal-ui.sh
. "$UI_HELPER"
# shellcheck source=scripts/tool-inventory.sh
. "$TOOL_INVENTORY"
unset _R _D _X

# ── Override ba_logo with correct BEYONDARCH banner ──────────────
ba_logo() {
  echo ""
  echo -e "${C_CYAN}${C_BOLD}"
  echo '  ██████╗ ███████╗██╗   ██╗ ██████╗ ███╗   ██╗██████╗  █████╗ ██████╗  ██████╗██╗  ██╗'
  echo '  ██╔══██╗██╔════╝╚██╗ ██╔╝██╔═══██╗████╗  ██║██╔══██╗██╔══██╗██╔══██╗██╔════╝██║  ██║'
  echo '  ██████╔╝█████╗   ╚████╔╝ ██║   ██║██╔██╗ ██║██║  ██║███████║██████╔╝██║     ███████║'
  echo '  ██╔══██╗██╔══╝    ╚██╔╝  ██║   ██║██║╚██╗██║██║  ██║██╔══██║██╔══██╗██║     ██╔══██║'
  echo '  ██████╔╝███████╗   ██║   ╚██████╔╝██║ ╚████║██████╔╝██║  ██║██║  ██║╚██████╗██║  ██║'
  echo '  ╚═════╝ ╚══════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═══╝╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝'
  echo -e "${C_RESET}"
}

# ── Cleanup trap ─────────────────────────────────────────────────
_cleanup() {
  if [[ $_INTERRUPTED -eq 1 ]]; then
    echo ""
    ba_warn "Setup interrupted — no permanent changes were committed"
    echo ""
  fi
}
_on_interrupt() { _INTERRUPTED=1; exit 130; }
trap _cleanup EXIT
trap _on_interrupt INT TERM

# ── Helpers ──────────────────────────────────────────────────────
next_section() {
  _STEP=$(( _STEP + 1 ))
  ba_section "$(printf '%02d' "$_STEP")" "$1"
}

usage() {
  ba_usage_header "setup wizard"
  cat <<'EOF'
Usage: ./install.sh [options]

Options:
  -y, --yes                 Run app dependency setup without prompts.
      --profile app         App dependencies only.
      --profile recommended App dependencies plus safe SOC helpers.
      --profile full        App dependencies plus analyst helper checks.
      --profile custom      Choose helper categories interactively.
      --no-tools            Skip optional system helper tools.
      --help                Show this help.

Plain ./install.sh starts the guided interactive setup wizard.
Optional system packages are installed only after explicit confirmation.
Advanced active tools are never installed by default.
EOF
}

# ── Argument parsing ─────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    -y|--yes)    ASSUME_YES=1 ;;
    --profile)
      [[ $# -ge 2 ]] || { ba_err "--profile requires: app, recommended, full, or custom"; exit 2; }
      PROFILE="$2"; shift ;;
    --no-tools)  NO_TOOLS=1 ;;
    --help|-h)   usage; exit 0 ;;
    *)           ba_err "Unknown option: $1"; usage; exit 2 ;;
  esac
  shift
done

case "$PROFILE" in
  ""|app|recommended|full|custom) ;;
  *) ba_err "Unknown profile '$PROFILE'"; usage; exit 2 ;;
esac
if [[ "$NO_TOOLS" -eq 1 && -n "$PROFILE" && "$PROFILE" != "app" ]]; then
  ba_warn "--no-tools overrides optional helper selection from profile '$PROFILE'"
fi
if [[ "$ASSUME_YES" -eq 1 && "$PROFILE" == "custom" ]]; then
  ba_err "--profile custom requires an interactive terminal; remove --yes or choose a different profile"
  exit 2
fi

# ── Utility ──────────────────────────────────────────────────────
is_interactive() { [[ -t 0 && "$ASSUME_YES" -eq 0 ]]; }

confirm() {
  local prompt="$1" answer=""
  [[ -t 0 ]] || return 1
  printf "  ${C_CYAN}?${C_RESET}  %s ${C_DIM}[y/N]${C_RESET} " "$prompt"
  read -r answer
  case "$answer" in y|Y|yes|YES) return 0 ;; *) return 1 ;; esac
}

find_python() {
  [[ -n "$PYTHON_BIN" ]] && return 0
  if   command -v python3 >/dev/null 2>&1; then PYTHON_BIN="$(command -v python3)"
  elif command -v python  >/dev/null 2>&1; then PYTHON_BIN="$(command -v python)"
  else return 1
  fi
}

# ── Spinner ──────────────────────────────────────────────────────
spin_run() {
  local label="$1"; shift
  local log_file elapsed
  log_file="$(mktemp -t beyondarch-install.XXXXXX.log)"
  local step_ts; step_ts=$(date +%s)
  ba_phase "$label"
  if [[ -t 1 ]]; then
    ("$@") >"$log_file" 2>&1 &
    local pid=$! frames='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏' i=0
    while kill -0 "$pid" 2>/dev/null; do
      printf '\r  %s%s%s  %s' "$BA_BLUE" "${frames:i++%10:1}" "$BA_RESET" "$label"
      sleep 0.1
    done
    printf '\r'
    elapsed=$(( $(date +%s) - step_ts ))
    if wait "$pid"; then
      ba_ok "$label  ${C_DIM}(${elapsed}s)${C_RESET}"
      rm -f "$log_file"
      return 0
    fi
  else
    if "$@" >"$log_file" 2>&1; then
      elapsed=$(( $(date +%s) - step_ts ))
      ba_ok "$label  ${C_DIM}(${elapsed}s)${C_RESET}"
      rm -f "$log_file"
      return 0
    fi
    elapsed=$(( $(date +%s) - step_ts ))
  fi
  elapsed=$(( $(date +%s) - step_ts ))
  echo ""
  ba_err "$label failed after ${elapsed}s"
  echo ""
  printf "  ${C_DIM}Last output:${C_RESET}\n\n"
  tail -30 "$log_file" | sed "s/^/    /" >&2
  echo ""
  ba_info "Full log retained: ${C_DIM}${log_file}${C_RESET}"
  echo ""
  return 1
}

# ── Profile helpers ──────────────────────────────────────────────
SELECTED_GROUPS=""

profile_label() {
  case "$1" in
    app)         printf 'App only' ;;
    recommended) printf 'Recommended SOC setup' ;;
    full)        printf 'Full analyst setup' ;;
    custom)      printf 'Custom' ;;
  esac
}

select_profile_interactive() {
  next_section "Setup profile"
  echo ""
  printf "  ${C_CYAN}1${C_RESET}  ${C_BOLD}App only${C_RESET}\n"
  printf "     ${C_DIM}backend venv + requirements, frontend npm deps, script permissions${C_RESET}\n\n"
  printf "  ${C_CYAN}2${C_RESET}  ${C_BOLD}Recommended SOC setup${C_RESET}  ${C_DIM}← default${C_RESET}\n"
  printf "     ${C_DIM}app dependencies + safe SOC helper tools where available${C_RESET}\n\n"
  printf "  ${C_CYAN}3${C_RESET}  ${C_BOLD}Full analyst setup${C_RESET}\n"
  printf "     ${C_DIM}recommended + OSINT/recon helpers; active tools asked separately${C_RESET}\n\n"
  printf "  ${C_CYAN}4${C_RESET}  ${C_BOLD}Custom${C_RESET}\n"
  printf "     ${C_DIM}choose helper categories interactively${C_RESET}\n\n"
  local choice=""
  printf "  ${C_CYAN}?${C_RESET}  Select profile ${C_DIM}[1-4, default: 2]${C_RESET} "
  read -r choice
  case "$choice" in
    1)    PROFILE="app" ;;
    2|"") PROFILE="recommended" ;;
    3)    PROFILE="full" ;;
    4)    PROFILE="custom" ;;
    *)    ba_warn "Unrecognized choice '$choice' — defaulting to Recommended SOC setup"
          PROFILE="recommended" ;;
  esac
  ba_ok "Profile set: ${C_BOLD}$(profile_label "$PROFILE")${C_RESET}"
}

select_groups() {
  SELECTED_GROUPS=""
  [[ "$NO_TOOLS" -eq 1 ]] && return 0
  case "$PROFILE" in
    app)         SELECTED_GROUPS="" ;;
    recommended) SELECTED_GROUPS="core dns recommended" ;;
    full)        SELECTED_GROUPS="core dns recommended manual" ;;
    custom)
      confirm "Include core helpers?"          && SELECTED_GROUPS="$SELECTED_GROUPS core"
      confirm "Include DNS/domain helpers?"    && SELECTED_GROUPS="$SELECTED_GROUPS dns"
      confirm "Include recon/OSINT helpers?"   && SELECTED_GROUPS="$SELECTED_GROUPS recommended manual"
      confirm "Skip all system tools?"         && SELECTED_GROUPS=""
      ;;
  esac
  if [[ "$PROFILE" == "full" || "$PROFILE" == "custom" ]]; then
    if is_interactive && confirm "Review advanced active tools for installation?"; then
      ADVANCED_ACTIVE=1
      SELECTED_GROUPS="$SELECTED_GROUPS advanced"
    else
      ADVANCED_ACTIVE=0
    fi
  fi
}

group_selected() {
  local wanted="$1" group
  for group in $SELECTED_GROUPS; do [[ "$group" == "$wanted" ]] && return 0; done
  return 1
}

declare -a PACMAN_PACKAGES=()
declare -a MANUAL_TOOLS=()
declare -a SKIPPED_TOOLS=()
declare -a PRESENT_TOOLS=()
declare -a SELECTED_MISSING=()

plan_tools() {
  local row group bins pkg category note display
  PACMAN_PACKAGES=(); MANUAL_TOOLS=(); SKIPPED_TOOLS=(); PRESENT_TOOLS=(); SELECTED_MISSING=()
  for row in "${TOOL_ROWS[@]}"; do
    IFS='|' read -r group bins pkg category note <<<"$row"
    display="$(display_tool "$bins")"
    if ! group_selected "$group"; then
      SKIPPED_TOOLS+=("$display")
      continue
    fi
    if tool_available "$bins"; then
      PRESENT_TOOLS+=("$display")
      continue
    fi
    SELECTED_MISSING+=("$display")
    if command -v pacman >/dev/null 2>&1 && pacman -Si "$pkg" >/dev/null 2>&1; then
      PACMAN_PACKAGES+=("$pkg")
    else
      MANUAL_TOOLS+=("$display ($note)")
    fi
  done
}

unique_words() {
  [[ "$#" -eq 0 ]] && return 0
  printf '%s\n' "$@" | sort -u | tr '\n' ' ' | sed 's/[[:space:]]$//'
}

print_list_or_none() {
  local label="$1"; shift
  printf "  ${C_DIM}%-30s${C_RESET}  " "$label"
  if [[ "$#" -eq 0 ]]; then
    printf "${C_DIM}none${C_RESET}\n"
  else
    printf "${C_DIM}"; unique_words "$@"; printf "${C_RESET}\n"
  fi
}

# ── System update check ──────────────────────────────────────────
check_system_updates() {
  command -v pacman >/dev/null 2>&1 || return 0
  next_section "System update check"
  local updates="" count
  if command -v checkupdates >/dev/null 2>&1; then
    updates="$(checkupdates 2>/dev/null || true)"
  else
    ba_info "checkupdates not found — using pacman -Qu"
    updates="$(pacman -Qu 2>/dev/null || true)"
  fi
  if [[ -z "$updates" ]]; then
    ba_ok "System is up to date — no pending package updates"
    return 0
  fi
  count="$(printf '%s\n' "$updates" | sed '/^$/d' | wc -l)"
  ba_warn "${count} pending package update(s) detected"
  if is_interactive && confirm "Run sudo pacman -Syu now?"; then
    sudo pacman -Syu
    ba_ok "System update completed"
  else
    ba_info "Skipped — run manually: ${C_BOLD}sudo pacman -Syu${C_RESET}"
  fi
}

# ── Pacman package install ───────────────────────────────────────
install_pacman_packages() {
  if [[ "${#PACMAN_PACKAGES[@]}" -eq 0 ]]; then
    ba_info "No selected missing helper packages available through pacman"
    return 0
  fi
  local packages
  packages="$(unique_words "${PACMAN_PACKAGES[@]}")"
  ba_info "Packages to install: ${C_BOLD}${packages}${C_RESET}"
  if [[ "$ASSUME_YES" -eq 1 ]]; then
    # shellcheck disable=SC2086
    sudo pacman -S --needed $packages
    ba_ok "Optional pacman packages installed"
    record_installed_packages "$packages"
    return 0
  fi
  if confirm "Install with sudo pacman -S --needed?"; then
    # shellcheck disable=SC2086
    sudo pacman -S --needed $packages
    ba_ok "Optional pacman packages installed"
    record_installed_packages "$packages"
  else
    ba_info "Optional helper installation skipped"
  fi
}

record_installed_packages() {
  local packages="$1" package group row bins pkg category note
  mkdir -p "$STATE_DIR"
  touch "$INSTALLED_TOOLS_STATE"
  for package in $packages; do
    group="optional"
    for row in "${TOOL_ROWS[@]}"; do
      IFS='|' read -r group_candidate bins pkg category note <<<"$row"
      if [[ "$pkg" == "$package" ]]; then
        group="$group_candidate"
        break
      fi
    done
    if ! grep -Eq "^${group}\\|${package}$" "$INSTALLED_TOOLS_STATE" 2>/dev/null; then
      printf '%s|%s\n' "$group" "$package" >>"$INSTALLED_TOOLS_STATE"
    fi
  done
  ba_ok "Install state recorded → ${C_DIM}.beyondarch/installed-tools.txt${C_RESET}"
}

# ════════════════════════════════════════════════════════════════
#   MAIN
# ════════════════════════════════════════════════════════════════
ba_logo
echo -e "  ${C_DIM}Local SOC Investigation Workbench — Setup Wizard${C_RESET}"
echo ""

# ── Preflight ────────────────────────────────────────────────────
next_section "Preflight"
echo ""
[[ "$ROOT_DIR" == "$(pwd -P)" ]] \
  && ba_ok "Project root: ${C_DIM}${ROOT_DIR}${C_RESET}" \
  || ba_info "Script root: ${C_DIM}${ROOT_DIR}${C_RESET}"
[[ -d "$BACKEND_DIR" ]]  && ba_ok "backend/ found"  \
  || { ba_err "backend/ not found — is this the project root?";  exit 1; }
[[ -d "$FRONTEND_DIR" ]] && ba_ok "frontend/ found" \
  || { ba_err "frontend/ not found — is this the project root?"; exit 1; }
find_python \
  && ba_ok "$("$PYTHON_BIN" --version 2>&1)  ${C_DIM}$(command -v "$PYTHON_BIN")${C_RESET}" \
  || { ba_err "Python 3 not found — install with: sudo pacman -S python"; exit 1; }
command -v node >/dev/null 2>&1 \
  && ba_ok "Node.js $(node --version)  ${C_DIM}$(command -v node)${C_RESET}" \
  || { ba_err "Node.js not found — install with: sudo pacman -S nodejs npm"; exit 1; }
command -v npm >/dev/null 2>&1 \
  && ba_ok "npm $(npm --version)  ${C_DIM}$(command -v npm)${C_RESET}" \
  || { ba_err "npm not found — install with: sudo pacman -S nodejs npm"; exit 1; }
command -v pacman >/dev/null 2>&1 \
  && ba_ok "Arch Linux detected — pacman available" \
  || ba_info "pacman not found — optional helper guidance will be manual"
echo ""

if is_interactive; then
  ba_info "This wizard installs local app dependencies and selected SOC helper tools."
  confirm "Start BeyondArch setup?" || { ba_info "Setup cancelled"; exit 0; }
fi

# ── Profile ──────────────────────────────────────────────────────
if [[ -z "$PROFILE" ]]; then
  if is_interactive; then select_profile_interactive; else PROFILE="app"; fi
fi
select_groups
plan_tools
check_system_updates

# ── Setup summary ────────────────────────────────────────────────
next_section "Setup summary"
echo ""
printf "  ${C_DIM}%-28s${C_RESET}  %s\n" "Profile"     "$(profile_label "$PROFILE")"
printf "  ${C_DIM}%-28s${C_RESET}  %s\n" "App deps"    "backend venv, requirements, frontend npm"
printf "  ${C_DIM}%-28s${C_RESET}  %s\n" "Scripts"     "install, run, doctor, reset, demo, scripts/*.sh"
echo ""
print_list_or_none "Helpers already present"   "${PRESENT_TOOLS[@]}"
print_list_or_none "Pacman packages available" "${PACMAN_PACKAGES[@]}"
print_list_or_none "Manual install needed"     "${MANUAL_TOOLS[@]}"
print_list_or_none "Skipped helper checks"     "${SKIPPED_TOOLS[@]}"
echo ""
if [[ "$ADVANCED_ACTIVE" -eq 0 ]]; then
  ba_info "Advanced active tools skipped — confirm separately to include."
fi

if is_interactive; then
  confirm "Proceed with this plan?" || { ba_info "Setup cancelled"; exit 0; }
fi

# ── Application dependencies ─────────────────────────────────────
next_section "Application dependencies"
echo ""
if [[ ! -x "$BACKEND_DIR/.venv/bin/python" ]]; then
  spin_run "Creating backend virtual environment" "$PYTHON_BIN" -m venv "$BACKEND_DIR/.venv"
else
  ba_ok "backend/.venv already exists — skipping creation"
fi
spin_run "Upgrading pip" "$BACKEND_DIR/.venv/bin/python" -m pip install --upgrade pip
spin_run "Installing backend requirements" \
  "$BACKEND_DIR/.venv/bin/python" -m pip install -r "$BACKEND_DIR/requirements.txt"
if [[ -f "$BACKEND_DIR/requirements-dev.txt" ]]; then
  spin_run "Installing dev requirements" \
    "$BACKEND_DIR/.venv/bin/python" -m pip install -r "$BACKEND_DIR/requirements-dev.txt"
else
  ba_info "No requirements-dev.txt found — skipping dev dependencies"
fi
if [[ -f "$FRONTEND_DIR/package-lock.json" ]]; then
  spin_run "Installing frontend dependencies  ${C_DIM}(npm ci)${C_RESET}" \
    bash -c "cd '$FRONTEND_DIR' && npm ci --include=dev"
else
  spin_run "Installing frontend dependencies  ${C_DIM}(npm install)${C_RESET}" \
    bash -c "cd '$FRONTEND_DIR' && npm install --include=dev"
fi
echo ""

# ── Script permissions ───────────────────────────────────────────
next_section "Script permissions"
chmod +x \
  "$ROOT_DIR"/install.sh \
  "$ROOT_DIR"/run.sh \
  "$ROOT_DIR"/doctor.sh \
  "$ROOT_DIR"/reset-workspace.sh \
  "$ROOT_DIR"/demo-workflow.sh 2>/dev/null || true
if compgen -G "$ROOT_DIR/scripts/*.sh" >/dev/null; then
  chmod +x "$ROOT_DIR"/scripts/*.sh
fi
ba_ok "All project scripts marked executable"

# ── Optional helper tools ────────────────────────────────────────
next_section "Optional helper tools"
if [[ -n "$SELECTED_GROUPS" ]]; then
  install_pacman_packages
  if [[ "${#MANUAL_TOOLS[@]}" -gt 0 ]]; then
    echo ""
    ba_warn "Some selected helpers require manual installation:"
    printf "  ${C_DIM}→${C_RESET}  %s\n" "${MANUAL_TOOLS[@]}"
  fi
else
  ba_info "System helper tools skipped for this profile"
fi

# ── Quick validation ─────────────────────────────────────────────
next_section "Quick validation"
echo ""
spin_run "Compiling backend (syntax check)" \
  bash -c "cd '$BACKEND_DIR' && '$BACKEND_DIR/.venv/bin/python' -m compileall -q app"
if [[ -x "$FRONTEND_DIR/node_modules/.bin/vite" ]]; then
  spin_run "Building frontend" bash -c "cd '$FRONTEND_DIR' && npm run build"
else
  ba_warn "Vite binary not found — skipping frontend build check"
fi
echo ""

# ── Done ─────────────────────────────────────────────────────────
next_section "Setup complete"
echo ""
ba_ok "backend/.venv + requirements installed"
ba_ok "frontend/node_modules installed"
ba_ok "Project scripts are executable"
[[ -n "$SELECTED_GROUPS" ]] && ba_ok "Optional helpers checked${PACMAN_PACKAGES:+/installed}"
echo ""
_elapsed=$(( $(date +%s) - START_TS ))
ba_ok "Completed in ${_elapsed}s"
echo ""
ba_hr
echo -e "  ${C_CYAN}┃${C_RESET}"
echo -e "  ${C_CYAN}┃${C_RESET}  ${C_BOLD}Launch   ${C_RESET}  ${C_DIM}./run.sh${C_RESET}"
echo -e "  ${C_CYAN}┃${C_RESET}  ${C_BOLD}Doctor   ${C_RESET}  ${C_DIM}./doctor.sh${C_RESET}"
echo -e "  ${C_CYAN}┃${C_RESET}  ${C_BOLD}Demo     ${C_RESET}  ${C_DIM}./demo-workflow.sh${C_RESET}"
echo -e "  ${C_CYAN}┃${C_RESET}"
echo -e "  ${C_CYAN}┃${C_RESET}  ${C_BOLD}Frontend ${C_RESET}  ${C_GREEN}http://localhost:5173${C_RESET}"
echo -e "  ${C_CYAN}┃${C_RESET}  ${C_BOLD}API Docs ${C_RESET}  ${C_DIM}http://localhost:8000/docs${C_RESET}"
echo -e "  ${C_CYAN}┃${C_RESET}"
echo ""