#!/usr/bin/env bash
set -uo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="$ROOT_DIR/backend"
FRONTEND_DIR="$ROOT_DIR/frontend"
UI_HELPER="$ROOT_DIR/scripts/terminal-ui.sh"
TOOL_INVENTORY="$ROOT_DIR/scripts/tool-inventory.sh"
BACKEND_URL="${BACKEND_URL:-http://127.0.0.1:8000}"
FRONTEND_URL="${FRONTEND_URL:-http://127.0.0.1:5173}"

if [[ ! -f "$UI_HELPER" ]]; then
  echo "Missing terminal UI helper: $UI_HELPER" >&2; exit 1
fi
if [[ ! -f "$TOOL_INVENTORY" ]]; then
  echo "Missing tool inventory helper: $TOOL_INVENTORY" >&2; exit 1
fi
. "$UI_HELPER"
. "$TOOL_INVENTORY"

PASS=0; WARN=0; FAIL=0; INFO=0
ok()   { PASS=$((PASS + 1)); ba_ok "$1"; }
warn() { WARN=$((WARN + 1)); ba_warn "$1"; }
err()  { FAIL=$((FAIL + 1)); ba_err "$1"; }
info() { INFO=$((INFO + 1)); ba_info "$1"; }

port_listening() {
  local port="$1"
  if command -v ss >/dev/null 2>&1; then
    ss -ltn 2>/dev/null | awk '{print $4}' | grep -Eq "[:.]$port$"
  elif command -v lsof >/dev/null 2>&1; then
    lsof -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1
  else return 2; fi
}

# ── Header ──────────────────────────────────────────────────────
ba_logo
echo -e "  ${C_DIM}System health dashboard${C_RESET}"
echo ""

# ── 01: Project layout ──────────────────────────────────────────
ba_section "01" "Project layout"
[[ -d "$BACKEND_DIR" ]]     && ok "backend/"             || err "backend/ missing"
[[ -d "$FRONTEND_DIR" ]]    && ok "frontend/"            || err "frontend/ missing"
[[ -f "$BACKEND_DIR/requirements.txt" ]] && ok "backend/requirements.txt" || err "backend/requirements.txt missing"
[[ -f "$FRONTEND_DIR/package.json" ]]   && ok "frontend/package.json"   || err "frontend/package.json missing"
[[ -f "$UI_HELPER" ]]       && ok "scripts/terminal-ui.sh"

# ── 02: Required runtimes ───────────────────────────────────────
ba_section "02" "Required runtimes"
if command -v python3 >/dev/null 2>&1; then
  ok "Python $(python3 --version 2>&1)"
elif command -v python >/dev/null 2>&1; then
  ok "Python $(python --version 2>&1)"
else err "Python 3 missing — run ./install.sh"; fi

command -v node >/dev/null 2>&1 && ok "Node.js $(node --version)"  || err "Node.js missing"
command -v npm  >/dev/null 2>&1 && ok "npm $(npm --version)"       || err "npm missing"
command -v pacman >/dev/null 2>&1 && info "pacman detected"        || info "pacman not detected"

# ── 03: Backend environment ─────────────────────────────────────
ba_section "03" "Backend environment"
if [[ -x "$BACKEND_DIR/.venv/bin/python" ]]; then
  ok "backend/.venv"
  VENV_PY="$BACKEND_DIR/.venv/bin/python"
  (cd "$BACKEND_DIR" && "$VENV_PY" -m compileall -q app) && ok "Backend compiles" || err "Backend compile failed"
  "$VENV_PY" -c "import pytest" 2>/dev/null && ok "pytest installed" || warn "pytest missing — run: pip install -r requirements-dev.txt"
  "$VENV_PY" -c "import ruff" 2>/dev/null && ok "ruff installed" || warn "ruff missing — run: pip install -r requirements-dev.txt"
else
  warn "backend/.venv missing — run ./install.sh"
fi

# ── 04: Frontend readiness ──────────────────────────────────────
ba_section "04" "Frontend readiness"
if [[ -d "$FRONTEND_DIR/node_modules" ]]; then
  ok "node_modules"
  [[ -x "$FRONTEND_DIR/node_modules/.bin/vite" ]] && ok "Vite binary" || warn "Vite missing"
  [[ -f "$FRONTEND_DIR/package-lock.json" ]] && ok "package-lock.json" || info "package-lock.json missing"
else
  warn "node_modules missing — run ./install.sh"
fi

# ── 05: Optional helpers ────────────────────────────────────────
ba_section "05" "Optional tools"
for row in "${TOOL_ROWS[@]}"; do
  IFS='|' read -r group bins pkg category note <<<"$row"
  label="$(display_tool "$bins")"
  if tool_available "$bins"; then
    ok "${category}: ${label}"
  else
    if command -v pacman >/dev/null 2>&1 && pacman -Si "$pkg" >/dev/null 2>&1; then
      warn "${category}: ${label} optional — sudo pacman -S ${pkg}"
    else
      warn "${category}: ${label} optional — install manually"
    fi
  fi
done

# ── 06: Script permissions ──────────────────────────────────────
ba_section "06" "Script permissions"
PERMISSION_FIXES=()
for script in install.sh run.sh run-beyondarch.zsh doctor.sh reset-workspace.sh demo-workflow.sh; do
  if [[ -x "$ROOT_DIR/$script" ]]; then ok "$script"; else warn "$script not executable"; PERMISSION_FIXES+=("$script"); fi
done
for script_path in "$ROOT_DIR"/scripts/*.sh; do
  script="scripts/$(basename "$script_path")"
  if [[ -x "$script_path" ]]; then ok "$script"; else warn "$script not executable"; PERMISSION_FIXES+=("$script"); fi
done
[[ "${#PERMISSION_FIXES[@]}" -gt 0 ]] && warn "chmod +x ${PERMISSION_FIXES[*]}"

# ── 07: Route and build checks ─────────────────────────────────
ba_section "07" "Build checks"
if [[ -d "$FRONTEND_DIR/node_modules" ]]; then
  (cd "$FRONTEND_DIR" && npm run lint >/tmp/beyondarch-lint.log 2>&1) && ok "Lint passed" || err "Lint failed — see /tmp/beyondarch-lint.log"
  (cd "$FRONTEND_DIR" && npm run build >/tmp/beyondarch-build.log 2>&1) && ok "Build passed" || err "Build failed — see /tmp/beyondarch-build.log"
else
  warn "Lint/build skipped (node_modules missing)"
fi

# ── 08: Live services ───────────────────────────────────────────
ba_section "08" "Live services"
if command -v curl >/dev/null 2>&1; then
  curl -fsS "$BACKEND_URL/health" >/dev/null 2>&1 && ok "Backend responds at :8000" || info "Backend not running"
  curl -fsS "$FRONTEND_URL" >/dev/null 2>&1 && ok "Frontend responds at :5173" || info "Frontend not running"
else warn "curl missing — live checks skipped"; fi
port_listening 8000 && ok "Port 8000 listening"  || info "Port 8000 not listening"
port_listening 5173 && ok "Port 5173 listening"  || info "Port 5173 not listening"

# ── 09: Summary ─────────────────────────────────────────────────
ba_section "09" "Summary"
ba_hr
ba_summary "$PASS" "$WARN" "$FAIL" "$INFO"
echo ""
if [[ "$FAIL" -gt 0 ]]; then
  echo -e "  ${C_CYAN}┃${C_RESET}  ${C_BOLD}Recommended:${C_RESET}  ${C_DIM}./install.sh${C_RESET}"
  exit 1
fi
echo -e "  ${C_GREEN}●${C_RESET} BeyondArch health check passed"
echo ""
