#!/usr/bin/env bash
# BeyondLabs — system health check
set -uo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="$ROOT_DIR/backend"
FRONTEND_DIR="$ROOT_DIR/frontend"
UI_HELPER="$ROOT_DIR/scripts/terminal-ui.sh"
TOOL_INVENTORY="$ROOT_DIR/scripts/tool-inventory.sh"
BACKEND_URL="${BACKEND_URL:-http://127.0.0.1:8000}"
FRONTEND_URL="${FRONTEND_URL:-http://127.0.0.1:5173}"
START_TS=$(date +%s)
_STEP=0
_LINT_LOG=""
_BUILD_LOG=""

# ── Inline colors for pre-source errors ─────────────────────────
_R='\033[0;31m' _D='\033[2m' _X='\033[0m'

if [[ ! -f "$UI_HELPER" ]]; then
  printf "${_R}  ✖${_X}  Missing scripts/terminal-ui.sh\n" >&2
  printf "     ${_D}Run this script from the BeyondLabs project root.${_X}\n" >&2
  exit 1
fi
if [[ ! -f "$TOOL_INVENTORY" ]]; then
  printf "${_R}  ✖${_X}  Missing scripts/tool-inventory.sh\n" >&2
  printf "     ${_D}Run this script from the BeyondLabs project root.${_X}\n" >&2
  exit 1
fi

. "$UI_HELPER"
. "$TOOL_INVENTORY"
unset _R _D _X

# ── Override ba_logo with correct BEYONDLABS banner ──────────────
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

# ── Cleanup ──────────────────────────────────────────────────────
_cleanup() { rm -f "$_LINT_LOG" "$_BUILD_LOG" 2>/dev/null || true; }
trap _cleanup EXIT

# ── Helpers ──────────────────────────────────────────────────────
next_section() {
  _STEP=$(( _STEP + 1 ))
  ba_section "$(printf '%02d' "$_STEP")" "$1"
}

PASS=0; WARN=0; FAIL=0; INFO=0
ok()   { PASS=$(( PASS + 1 )); ba_ok   "$1"; }
warn() { WARN=$(( WARN + 1 )); ba_warn "$1"; }
err()  { FAIL=$(( FAIL + 1 )); ba_err  "$1"; }
info() { INFO=$(( INFO + 1 )); ba_info "$1"; }

port_listening() {
  local port="$1"
  if command -v ss >/dev/null 2>&1; then
    ss -ltn 2>/dev/null | awk '{print $4}' | grep -Eq "[:.]$port$"
  elif command -v lsof >/dev/null 2>&1; then
    lsof -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1
  else
    return 2
  fi
}

# ════════════════════════════════════════════════════════════════
#   MAIN
# ════════════════════════════════════════════════════════════════
ba_logo
echo -e "  ${C_DIM}System Health Dashboard  —  $(date '+%Y-%m-%d %H:%M:%S')${C_RESET}"
echo ""

# ── 01: Project layout ───────────────────────────────────────────
next_section "Project layout"
echo ""
[[ -d "$BACKEND_DIR" ]]  \
  && ok  "backend/  ${C_DIM}${BACKEND_DIR}${C_RESET}"   \
  || err "backend/ missing"
[[ -d "$FRONTEND_DIR" ]] \
  && ok  "frontend/  ${C_DIM}${FRONTEND_DIR}${C_RESET}" \
  || err "frontend/ missing"
[[ -f "$BACKEND_DIR/requirements.txt" ]] \
  && ok  "backend/requirements.txt" \
  || err "backend/requirements.txt missing"
[[ -f "$FRONTEND_DIR/package.json" ]] \
  && ok  "frontend/package.json" \
  || err "frontend/package.json missing"
[[ -f "$BACKEND_DIR/.env" ]] \
  && ok  "backend/.env" \
  || warn "backend/.env missing — copy from .env.example"
[[ -f "$UI_HELPER" ]]      && ok "scripts/terminal-ui.sh"   || err "scripts/terminal-ui.sh missing"
[[ -f "$TOOL_INVENTORY" ]] && ok "scripts/tool-inventory.sh" || err "scripts/tool-inventory.sh missing"
echo ""

# ── 02: Required runtimes ────────────────────────────────────────
next_section "Required runtimes"
echo ""
if command -v python3 >/dev/null 2>&1; then
  ok "$(python3 --version 2>&1)  ${C_DIM}$(command -v python3)${C_RESET}"
elif command -v python >/dev/null 2>&1; then
  ok "$(python --version 2>&1)  ${C_DIM}$(command -v python)${C_RESET}"
else
  case "$PKG_MGR" in
    pacman) err "Python 3 missing — install with: $PKG_MGR_INSTALL python" ;;
    brew)   err "Python 3 missing — install with: $PKG_MGR_INSTALL python" ;;
    apt)    err "Python 3 missing — install with: $PKG_MGR_INSTALL python3" ;;
    *)      err "Python 3 missing — install from python.org or your package manager" ;;
  esac
fi
command -v node >/dev/null 2>&1 \
  && ok  "Node.js $(node --version)  ${C_DIM}$(command -v node)${C_RESET}" \
  || err "Node.js missing — install from nodejs.org or your package manager"
command -v npm >/dev/null 2>&1 \
  && ok  "npm $(npm --version)  ${C_DIM}$(command -v npm)${C_RESET}" \
  || err "npm missing — install from nodejs.org or your package manager"
[[ "$PKG_MGR" != "unknown" ]] \
  && info "${PKG_MGR_NAME} detected" \
  || info "No supported package manager detected"
echo ""

# ── 03: Backend environment ──────────────────────────────────────
next_section "Backend environment"
echo ""
if [[ -x "$BACKEND_DIR/.venv/bin/python" ]]; then
  _venv_py="$BACKEND_DIR/.venv/bin/python"
  _venv_ver="$("$_venv_py" --version 2>&1)"
  ok "backend/.venv  ${C_DIM}${_venv_ver}${C_RESET}"
  (cd "$BACKEND_DIR" && "$_venv_py" -m compileall -q app 2>/dev/null) \
    && ok  "Backend syntax check passed" \
    || err "Backend compile failed — check app/ for syntax errors"
  "$_venv_py" -c "import pytest" 2>/dev/null \
    && ok  "pytest available" \
    || warn "pytest missing — run: pip install -r requirements-dev.txt"
  "$_venv_py" -c "import ruff" 2>/dev/null \
    && ok  "ruff available" \
    || warn "ruff missing — run: pip install -r requirements-dev.txt"
else
  warn "backend/.venv missing — run: ./install.sh"
fi
echo ""

# ── 04: Frontend readiness ───────────────────────────────────────
next_section "Frontend readiness"
echo ""
if [[ -d "$FRONTEND_DIR/node_modules" ]]; then
  ok "node_modules"
  if [[ -x "$FRONTEND_DIR/node_modules/.bin/vite" ]]; then
    _vite_ver=$("$FRONTEND_DIR/node_modules/.bin/vite" --version 2>/dev/null || echo "?")
    ok "Vite ${_vite_ver}"
  else
    warn "Vite binary missing — run: ./install.sh"
  fi
  if [[ -f "$FRONTEND_DIR/package-lock.json" ]]; then
    ok "package-lock.json  ${C_DIM}(npm)${C_RESET}"
  elif [[ -f "$FRONTEND_DIR/yarn.lock" ]]; then
    ok "yarn.lock  ${C_DIM}(yarn)${C_RESET}"
  elif [[ -f "$FRONTEND_DIR/pnpm-lock.yaml" ]]; then
    ok "pnpm-lock.yaml  ${C_DIM}(pnpm)${C_RESET}"
  else
    info "No lock file found — install may not be reproducible"
  fi
else
  warn "node_modules missing — run: ./install.sh"
fi
echo ""

# ── 05: Optional tools ───────────────────────────────────────────
next_section "Optional tools"
echo ""
for row in "${TOOL_ROWS[@]}"; do
  IFS='|' read -r group bins pkg brew_pkg category note <<<"$row"
  _label="$(display_tool "$bins")"
  if tool_available "$bins"; then
    ok "${C_DIM}[${category}]${C_RESET}  ${_label}"
  elif pkg_available "$pkg" "$brew_pkg"; then
    warn "${C_DIM}[${category}]${C_RESET}  ${_label}  ${C_DIM}→ ${PKG_MGR_INSTALL} ${pkg}${C_RESET}"
  else
    warn "${C_DIM}[${category}]${C_RESET}  ${_label}  ${C_DIM}→ install manually${C_RESET}"
  fi
done
echo ""

# ── 06: Script permissions ───────────────────────────────────────
next_section "Script permissions"
echo ""
PERMISSION_FIXES=()
for _script in install.sh run.sh doctor.sh reset-workspace.sh demo-workflow.sh; do
  if [[ ! -f "$ROOT_DIR/$_script" ]]; then
    info "$_script not found — skipping"
  elif [[ -x "$ROOT_DIR/$_script" ]]; then
    ok "$_script"
  else
    warn "$_script not executable"
    PERMISSION_FIXES+=("$_script")
  fi
done
if compgen -G "$ROOT_DIR/scripts/*.sh" >/dev/null; then
  for _script_path in "$ROOT_DIR"/scripts/*.sh; do
    _script="scripts/$(basename "$_script_path")"
    if [[ -x "$_script_path" ]]; then
      ok "$_script"
    else
      warn "$_script not executable"
      PERMISSION_FIXES+=("$_script")
    fi
  done
fi
if [[ "${#PERMISSION_FIXES[@]}" -gt 0 ]]; then
  echo ""
  warn "Fix with: chmod +x ${PERMISSION_FIXES[*]}"
fi
echo ""

# ── 07: Build checks ─────────────────────────────────────────────
next_section "Build checks"
echo ""
if [[ -d "$FRONTEND_DIR/node_modules" ]]; then
  _LINT_LOG="$(mktemp -t beyondlabs-lint.XXXXXX.log)"
  _BUILD_LOG="$(mktemp -t beyondlabs-build.XXXXXX.log)"

  _ts=$(date +%s)
  if (cd "$FRONTEND_DIR" && npm run lint >"$_LINT_LOG" 2>&1); then
    _e=$(( $(date +%s) - _ts ))
    ok "Lint passed  ${C_DIM}(${_e}s)${C_RESET}"
    rm -f "$_LINT_LOG"; _LINT_LOG=""
  else
    _e=$(( $(date +%s) - _ts ))
    err "Lint failed  ${C_DIM}(${_e}s)${C_RESET}"
    echo ""
    tail -20 "$_LINT_LOG" | sed 's/^/    /'
    echo ""
    ba_info "Full log: ${C_DIM}${_LINT_LOG}${C_RESET}"
  fi

  _ts=$(date +%s)
  if (cd "$FRONTEND_DIR" && npm run build >"$_BUILD_LOG" 2>&1); then
    _e=$(( $(date +%s) - _ts ))
    ok "Build passed  ${C_DIM}(${_e}s)${C_RESET}"
    rm -f "$_BUILD_LOG"; _BUILD_LOG=""
  else
    _e=$(( $(date +%s) - _ts ))
    err "Build failed  ${C_DIM}(${_e}s)${C_RESET}"
    echo ""
    tail -20 "$_BUILD_LOG" | sed 's/^/    /'
    echo ""
    ba_info "Full log: ${C_DIM}${_BUILD_LOG}${C_RESET}"
  fi
else
  warn "Lint/build skipped — node_modules missing; run: ./install.sh"
fi
echo ""

# ── 08: Live services ────────────────────────────────────────────
next_section "Live services"
echo ""
if command -v curl >/dev/null 2>&1; then
  _bs=$(curl -o /dev/null -w "%{http_code}" -fs --max-time 2 "$BACKEND_URL/health" 2>/dev/null || echo "000")
  if [[ "$_bs" == "200" ]]; then
    ok "Backend responding  ${C_DIM}:8000  HTTP ${_bs}${C_RESET}"
  else
    info "Backend not running  ${C_DIM}:8000  HTTP ${_bs} — start with ./run.sh${C_RESET}"
  fi
  _fs=$(curl -o /dev/null -w "%{http_code}" -fs --max-time 2 "$FRONTEND_URL" 2>/dev/null || echo "000")
  if [[ "$_fs" == "200" ]]; then
    ok "Frontend responding  ${C_DIM}:5173  HTTP ${_fs}${C_RESET}"
  else
    info "Frontend not running  ${C_DIM}:5173  HTTP ${_fs} — start with ./run.sh${C_RESET}"
  fi
else
  warn "curl not found — live HTTP checks skipped"
fi
port_listening 8000 && ok "Port 8000 listening" || info "Port 8000 not listening"
port_listening 5173 && ok "Port 5173 listening" || info "Port 5173 not listening"
echo ""

# ── 09: Summary ──────────────────────────────────────────────────
next_section "Summary"
_elapsed=$(( $(date +%s) - START_TS ))
echo ""
ba_hr
echo ""
echo -e "  ${C_GREEN}✔${C_RESET}  ${C_BOLD}${PASS}${C_RESET} passed    ${C_YELLOW}▲${C_RESET}  ${C_BOLD}${WARN}${C_RESET} warnings    ${C_RED}✖${C_RESET}  ${C_BOLD}${FAIL}${C_RESET} failed    ${C_DIM}${_elapsed}s${C_RESET}"
echo ""
ba_summary "$PASS" "$WARN" "$FAIL" "$INFO"
echo ""
if [[ "$FAIL" -gt 0 ]]; then
  echo -e "  ${C_CYAN}┃${C_RESET}  ${C_BOLD}Resolve failures:${C_RESET}  ${C_DIM}./install.sh${C_RESET}"
  echo ""
  exit 1
fi
[[ "$WARN" -gt 0 ]] && echo -e "  ${C_YELLOW}▲${C_RESET}  Warnings present — review above for optional fixes"
echo -e "  ${C_GREEN}●${C_RESET}  ${C_BOLD}BeyondLabs health check passed${C_RESET}"
echo ""