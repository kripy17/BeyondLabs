#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="$ROOT_DIR/backend"
FRONTEND_DIR="$ROOT_DIR/frontend"
UI_HELPER="$ROOT_DIR/scripts/terminal-ui.sh"
TOOL_INVENTORY="$ROOT_DIR/scripts/tool-inventory.sh"
STATE_DIR="$ROOT_DIR/.beyondarch"
INSTALLED_TOOLS_STATE="$STATE_DIR/installed-tools.txt"
PYTHON_BIN="${PYTHON_BIN:-}"
ASSUME_YES=0
PROFILE=""
NO_TOOLS=0
ADVANCED_ACTIVE=0

if [[ ! -f "$UI_HELPER" ]]; then
  echo "Missing terminal UI helper: $UI_HELPER" >&2
  exit 1
fi
if [[ ! -f "$TOOL_INVENTORY" ]]; then
  echo "Missing tool inventory helper: $TOOL_INVENTORY" >&2
  exit 1
fi
# shellcheck source=scripts/terminal-ui.sh
. "$UI_HELPER"
# shellcheck source=scripts/tool-inventory.sh
. "$TOOL_INVENTORY"

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

while [[ $# -gt 0 ]]; do
  case "$1" in
    -y|--yes) ASSUME_YES=1 ;;
    --profile)
      [[ $# -ge 2 ]] || { ba_err "--profile requires app, recommended, full, or custom"; exit 2; }
      PROFILE="$2"; shift ;;
    --no-tools) NO_TOOLS=1 ;;
    --help|-h) usage; exit 0 ;;
    *) ba_err "Unknown option: $1"; usage; exit 2 ;;
  esac
  shift
done

case "$PROFILE" in
  ""|app|recommended|full|custom) ;;
  *) ba_err "Unknown profile: $PROFILE"; usage; exit 2 ;;
esac
if [[ "$NO_TOOLS" -eq 1 && "$PROFILE" != "" && "$PROFILE" != "app" ]]; then
  ba_warn "--no-tools overrides optional helper selection"
fi
if [[ "$ASSUME_YES" -eq 1 && "$PROFILE" == "custom" ]]; then
  ba_err "--profile custom requires an interactive terminal"
  exit 2
fi

is_interactive() { [[ -t 0 && "$ASSUME_YES" -eq 0 ]]; }

confirm() {
  local prompt="$1"
  local answer=""
  [[ -t 0 ]] || return 1
  ba_prompt "$prompt [y/N] "
  read -r answer
  case "$answer" in y|Y|yes|YES) return 0 ;; *) return 1 ;; esac
}

find_python() {
  if [[ -n "$PYTHON_BIN" ]]; then return 0; fi
  if command -v python3 >/dev/null 2>&1; then PYTHON_BIN="$(command -v python3)"
  elif command -v python >/dev/null 2>&1; then PYTHON_BIN="$(command -v python)"
  else return 1
  fi
}

spin_run() {
  local label="$1"; shift
  local log_file
  log_file="$(mktemp -t beyondarch-install.XXXXXX.log)"
  ba_phase "$label"
  if [[ -t 1 ]]; then
    ("$@") >"$log_file" 2>&1 &
    local pid=$!
    local frames='|/-\'
    local i=0
    while kill -0 "$pid" 2>/dev/null; do
      printf '\r%s[%s]%s %s' "$BA_BLUE" "${frames:i++%4:1}" "$BA_RESET" "$label"
      sleep 0.15
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
  ba_err "$label failed. Log follows:"
  sed -n '1,220p' "$log_file" >&2
  rm -f "$log_file"
  return 1
}

SELECTED_GROUPS=""
profile_label() {
  case "$1" in
    app) printf 'App only' ;;
    recommended) printf 'Recommended SOC setup' ;;
    full) printf 'Full analyst helper setup' ;;
    custom) printf 'Custom setup' ;;
  esac
}

select_profile_interactive() {
  local choice=""
  ba_section "02" "Setup profile"
  cat <<'EOF'
1) App only
   backend venv, backend requirements, frontend npm dependencies, script permissions

2) Recommended SOC setup
   app dependencies plus safe helper tools where available

3) Full analyst helper setup
   recommended setup plus OSINT/recon helper checks; active tools ask separately

4) Custom
   choose helper categories
EOF
  ba_prompt "Choose setup profile [1-4] "
  read -r choice
  case "$choice" in
    1) PROFILE="app" ;;
    2|"") PROFILE="recommended" ;;
    3) PROFILE="full" ;;
    4) PROFILE="custom" ;;
    *) ba_warn "Unknown choice; using Recommended SOC setup"; PROFILE="recommended" ;;
  esac
}

select_groups() {
  SELECTED_GROUPS=""
  [[ "$NO_TOOLS" -eq 1 ]] && return 0
  case "$PROFILE" in
    app) SELECTED_GROUPS="" ;;
    recommended) SELECTED_GROUPS="core dns recommended" ;;
    full) SELECTED_GROUPS="core dns recommended manual" ;;
    custom)
      confirm "Include Core helpers?" && SELECTED_GROUPS="$SELECTED_GROUPS core"
      confirm "Include DNS/domain metadata helpers?" && SELECTED_GROUPS="$SELECTED_GROUPS dns"
      confirm "Include Recon/OSINT helpers?" && SELECTED_GROUPS="$SELECTED_GROUPS recommended manual"
      confirm "Skip system tools?" && SELECTED_GROUPS=""
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
  if [[ "$#" -eq 0 ]]; then return 0; fi
  printf '%s\n' "$@" | sort -u | tr '\n' ' ' | sed 's/[[:space:]]$//'
}

print_list_or_none() {
  local label="$1"; shift
  printf '%-34s ' "$label"
  if [[ "$#" -eq 0 ]]; then printf 'none\n'; else unique_words "$@"; printf '\n'; fi
}

check_system_updates() {
  command -v pacman >/dev/null 2>&1 || return 0
  ba_section "03" "System update check"
  if ! command -v checkupdates >/dev/null 2>&1; then
    ba_info "checkupdates not found; using pacman -Qu for local update status"
  fi
  local updates=""
  if command -v checkupdates >/dev/null 2>&1; then
    updates="$(checkupdates 2>/dev/null || true)"
  else
    updates="$(pacman -Qu 2>/dev/null || true)"
  fi
  if [[ -z "$updates" ]]; then
    ba_ok "System package database reports no pending package updates"
    return 0
  fi
  local count
  count="$(printf '%s\n' "$updates" | sed '/^$/d' | wc -l)"
  ba_warn "$count package update(s) appear to be pending"
  if is_interactive && confirm "Run system update now with sudo pacman -Syu?"; then
    sudo pacman -Syu
    ba_ok "System update command completed"
  else
    ba_info "System update skipped. Recommended command: sudo pacman -Syu"
  fi
}

install_pacman_packages() {
  [[ "${#PACMAN_PACKAGES[@]}" -eq 0 ]] && { ba_info "No selected missing helper packages available through pacman"; return 0; }
  local packages
  packages="$(unique_words "${PACMAN_PACKAGES[@]}")"
  ba_info "Selected pacman packages: $packages"
  if [[ "$ASSUME_YES" -eq 1 ]]; then
    sudo pacman -S --needed $packages
    ba_ok "Optional pacman package installation finished"
    record_installed_packages "$packages"
    return 0
  fi
  if confirm "Install selected helper packages with sudo pacman -S --needed?"; then
    sudo pacman -S --needed $packages
    ba_ok "Optional pacman package installation finished"
    record_installed_packages "$packages"
  else
    ba_info "Optional helper package installation skipped"
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
  ba_ok "Recorded optional tool install state: .beyondarch/installed-tools.txt"
}

ba_logo
echo -e "  ${C_DIM}Local SOC analyst toolkit — setup wizard${C_RESET}"
echo ""

ba_section "01" "Preflight"
[[ "$ROOT_DIR" == "$(pwd -P)" ]] && ba_ok "Project root: $ROOT_DIR" || ba_info "Script root: $ROOT_DIR"
[[ -d "$BACKEND_DIR" ]] && ba_ok "backend/ exists" || { ba_err "backend/ missing"; exit 1; }
[[ -d "$FRONTEND_DIR" ]] && ba_ok "frontend/ exists" || { ba_err "frontend/ missing"; exit 1; }
find_python && ba_ok "$("$PYTHON_BIN" --version 2>&1)" || { ba_err "Python 3 is required"; exit 1; }
command -v node >/dev/null 2>&1 && ba_ok "Node.js $(node --version)" || { ba_err "Node.js is required"; exit 1; }
command -v npm >/dev/null 2>&1 && ba_ok "npm $(npm --version)" || { ba_err "npm is required"; exit 1; }
command -v pacman >/dev/null 2>&1 && ba_ok "Arch package manager detected: pacman" || ba_info "pacman not detected; optional helper install guidance will be manual"

if is_interactive; then
  ba_info "The setup wizard will prepare local app dependencies and selected helper tools."
  confirm "Start BeyondArch setup now?" || { ba_info "Setup cancelled"; exit 0; }
fi

if [[ -z "$PROFILE" ]]; then
  if is_interactive; then select_profile_interactive; else PROFILE="app"; fi
fi
select_groups
plan_tools
check_system_updates

ba_section "04" "Setup summary"
printf '%-34s %s\n' "Profile" "$(profile_label "$PROFILE")"
printf '%-34s %s\n' "App dependencies" "backend venv, backend requirements, frontend npm dependencies"
printf '%-34s %s\n' "Script permissions" "install, run, run-beyondarch, doctor, reset, demo, scripts/*.sh"
print_list_or_none "Helpers already present" "${PRESENT_TOOLS[@]}"
print_list_or_none "Pacman packages available" "${PACMAN_PACKAGES[@]}"
print_list_or_none "Manual install notes" "${MANUAL_TOOLS[@]}"
print_list_or_none "Skipped helper checks" "${SKIPPED_TOOLS[@]}"
if [[ "$ADVANCED_ACTIVE" -eq 0 ]]; then
  ba_info "Advanced active tools are skipped unless separately confirmed."
fi

if is_interactive; then
  confirm "Proceed with this setup plan?" || { ba_info "Setup cancelled"; exit 0; }
fi

ba_section "05" "Application dependencies"
if [[ ! -x "$BACKEND_DIR/.venv/bin/python" ]]; then
  spin_run "Creating backend virtual environment" "$PYTHON_BIN" -m venv "$BACKEND_DIR/.venv"
else
  ba_ok "backend/.venv already exists"
fi
spin_run "Upgrading backend pip" "$BACKEND_DIR/.venv/bin/python" -m pip install --upgrade pip
spin_run "Installing backend requirements" "$BACKEND_DIR/.venv/bin/python" -m pip install -r "$BACKEND_DIR/requirements.txt"
spin_run "Installing dev requirements" "$BACKEND_DIR/.venv/bin/python" -m pip install -r "$BACKEND_DIR/requirements-dev.txt"
if [[ -f "$FRONTEND_DIR/package-lock.json" ]]; then
  spin_run "Installing frontend npm dependencies" bash -c "cd '$FRONTEND_DIR' && npm ci --include=dev"
else
  spin_run "Installing frontend npm dependencies" bash -c "cd '$FRONTEND_DIR' && npm install --include=dev"
fi

ba_section "06" "Script permissions"
chmod +x "$ROOT_DIR"/install.sh "$ROOT_DIR"/run.sh "$ROOT_DIR"/run-beyondarch.zsh "$ROOT_DIR"/doctor.sh "$ROOT_DIR"/reset-workspace.sh "$ROOT_DIR"/demo-workflow.sh 2>/dev/null || true
if compgen -G "$ROOT_DIR/scripts/*.sh" >/dev/null; then
  chmod +x "$ROOT_DIR"/scripts/*.sh
fi
ba_ok "Project scripts are executable"

ba_section "07" "Optional helper tools"
if [[ -n "$SELECTED_GROUPS" ]]; then
  install_pacman_packages
  [[ "${#MANUAL_TOOLS[@]}" -gt 0 ]] && { ba_warn "Some selected helpers require manual install:"; printf '  - %s\n' "${MANUAL_TOOLS[@]}"; }
else
  ba_info "System helper tools skipped for this profile"
fi

ba_section "08" "Quick validation"
spin_run "Compiling backend app" bash -c "cd '$BACKEND_DIR' && '$BACKEND_DIR/.venv/bin/python' -m compileall -q app"
if [[ -x "$FRONTEND_DIR/node_modules/.bin/vite" ]]; then
  spin_run "Building frontend" bash -c "cd '$FRONTEND_DIR' && npm run build"
else
  ba_warn "Skipped frontend build because Vite is missing"
fi

ba_section "09" "Setup complete"
echo ""
ba_ok "backend/.venv ＋ requirements"
ba_ok "frontend/node_modules"
ba_ok "Root scripts executable"
[[ -n "$SELECTED_GROUPS" ]] && ba_ok "Optional helpers checked${PACMAN_PACKAGES:+/installed}"
echo ""
ba_hr
echo -e "  ${C_CYAN}┃${C_RESET}  ${C_BOLD}Launch   ${C_RESET}  ${C_DIM}./run.sh${C_RESET}"
echo -e "  ${C_CYAN}┃${C_RESET}  ${C_BOLD}Doctor   ${C_RESET}  ${C_DIM}./doctor.sh${C_RESET}"
echo -e "  ${C_CYAN}┃${C_RESET}  ${C_BOLD}Demo     ${C_RESET}  ${C_DIM}./demo-workflow.sh${C_RESET}"
echo -e "  ${C_CYAN}┃${C_RESET}"
echo -e "  ${C_CYAN}┃${C_RESET}  ${C_BOLD}Frontend ${C_RESET}  ${C_DIM}http://localhost:5173${C_RESET}"
echo -e "  ${C_CYAN}┃${C_RESET}  ${C_BOLD}Backend  ${C_RESET}  ${C_DIM}http://localhost:8000/docs${C_RESET}"
echo ""
