#!/usr/bin/env bash
# BeyondLabs — start backend and frontend together
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FRONTEND="$ROOT_DIR/frontend"
BACKEND="$ROOT_DIR/backend"
PIDS=()
START_TS=$(date +%s)

# ── Args ───────────────────────────────────────────────────────
RUN_FRONTEND=true
RUN_BACKEND=true
for arg in "$@"; do
  case "$arg" in
    --frontend-only) RUN_BACKEND=false ;;
    --backend-only)  RUN_FRONTEND=false ;;
    --help|-h)
      echo "Usage: $0 [--frontend-only | --backend-only]"
      exit 0 ;;
  esac
done

# ── Visual toolkit ────────────────────────────────────────────────
# Shared with install.sh / doctor.sh — one palette, one logo, no drift.
UI_HELPER="$ROOT_DIR/scripts/terminal-ui.sh"
if [[ -f "$UI_HELPER" ]]; then
  . "$UI_HELPER"
else
  # Minimal inline fallback if scripts/terminal-ui.sh isn't present.
  C_RESET='\033[0m'; C_BOLD='\033[1m'; C_DIM='\033[2m'
  C_CYAN='\033[38;5;214m'; C_GREEN='\033[38;5;108m'
  C_YELLOW='\033[38;5;179m'; C_RED='\033[38;5;203m'
  ba_ok()   { echo -e "  ${C_GREEN}●${C_RESET}  $*"; }
  ba_info() { echo -e "  ${C_CYAN}◆${C_RESET}  $*"; }
  ba_warn() { echo -e "  ${C_YELLOW}▲${C_RESET}  $*"; }
  ba_hr()   { echo -e "  ${C_DIM}────────────────────────────────────────────────${C_RESET}"; }
  ba_boot() { for l in "$@"; do echo -e "  ${C_DIM}$l${C_RESET}"; done; }
  ba_banner() { echo -e "  ${C_CYAN}${C_BOLD}BeyondLabs${C_RESET}"; }
fi
C_WHITE='\033[38;5;253m'
info()  { ba_info "$*"; }
ok()    { ba_ok "$*"; }
warn()  { ba_warn "$*"; }
die()   { echo -e "\n  ${C_RED}✖${C_RESET}  $*\n" >&2; exit 1; }
sep()   { ba_hr; }

# ── Cleanup ─────────────────────────────────────────────────────
cleanup() {
  local code=$?
  local elapsed=$(( $(date +%s) - START_TS ))
  echo ""
  sep
  for pid in "${PIDS[@]}"; do
    kill "$pid" 2>/dev/null && ok "Stopped PID ${pid}" || true
  done
  wait 2>/dev/null
  if [[ $code -eq 0 || $code -eq 130 ]]; then
    ok "Session ended cleanly  ${C_DIM}(${elapsed}s)${C_RESET}"
  else
    warn "Exited with code ${C_BOLD}${code}${C_RESET}  ${C_DIM}(${elapsed}s)${C_RESET}"
  fi
  echo ""
}
trap cleanup INT TERM EXIT

# ── Banner ──────────────────────────────────────────────────────
ba_boot \
  "boot://env      resolving backend + frontend targets" \
  "boot://launch   starting local services"
ba_banner
sep
echo ""

# ── Auto-create .env ────────────────────────────────────────────
if [[ ! -f "$BACKEND/.env" ]]; then
  if [[ -f "$BACKEND/.env.example" ]]; then
    cp "$BACKEND/.env.example" "$BACKEND/.env"
    ok "Created ${C_DIM}backend/.env${C_RESET} from example"
  else
    warn "No ${C_DIM}.env${C_RESET} or ${C_DIM}.env.example${C_RESET} found in backend — proceeding anyway"
  fi
fi

# ── Load backend host/port from .env (falls back to safe defaults) ──
BACKEND_HOST="127.0.0.1"
BACKEND_PORT="8000"
if [[ -f "$BACKEND/.env" ]]; then
  _env_host="$(grep -E '^BEYONDLABS_BACKEND_HOST=' "$BACKEND/.env" | tail -1 | cut -d= -f2- | tr -d '\r')"
  _env_port="$(grep -E '^BEYONDLABS_BACKEND_PORT=' "$BACKEND/.env" | tail -1 | cut -d= -f2- | tr -d '\r')"
  [[ -n "$_env_host" ]] && BACKEND_HOST="$_env_host"
  [[ -n "$_env_port" ]] && BACKEND_PORT="$_env_port"
  unset _env_host _env_port
fi

# ── Preflight ───────────────────────────────────────────────────
info "Running preflight checks…"
echo ""

if $RUN_BACKEND; then
  if command -v python3 >/dev/null 2>&1; then
    ok "Python 3  ${C_DIM}$(python3 --version)${C_RESET}"
  else
    die "Python 3 not found — run ${C_BOLD}./install.sh${C_RESET}"
  fi
  [[ -d "$BACKEND/.venv" ]] || die "Backend venv missing — run ${C_BOLD}./install.sh${C_RESET}"
  ok "Backend venv found"
fi

if $RUN_FRONTEND; then
  if command -v node >/dev/null 2>&1; then
    ok "Node.js  ${C_DIM}$(node --version)${C_RESET}"
  else
    die "Node.js not found — run ${C_BOLD}./install.sh${C_RESET}"
  fi
  [[ -d "$FRONTEND/node_modules" ]] || die "Frontend deps missing — run ${C_BOLD}./install.sh${C_RESET}"
  ok "Frontend node_modules found"
fi

echo ""
sep
echo ""

# ── Launch Backend ───────────────────────────────────────────────
if $RUN_BACKEND; then
  info "Starting backend…"
  cd "$BACKEND"
  .venv/bin/uvicorn app.main:app \
    --host "$BACKEND_HOST" \
    --port "$BACKEND_PORT" \
    --reload \
    --log-level warning \
    2>&1 | sed "s/^/  ${C_DIM}[backend]${C_RESET} /" &
  BACKEND_PID=$!
  PIDS+=($BACKEND_PID)
  cd "$ROOT_DIR"
  ok "Backend  started  ${C_DIM}PID ${BACKEND_PID}${C_RESET}"

  info "Waiting for backend to become ready…"
  READY=0
  for i in $(seq 1 20); do
    if curl -sf "http://${BACKEND_HOST}:${BACKEND_PORT}/docs" >/dev/null 2>&1; then
      READY=1; break
    fi
    sleep 0.5
  done
  if [[ $READY -eq 0 ]]; then
    warn "Backend did not respond in 10s — frontend launching anyway"
  else
    ok "Backend is live"
  fi
  echo ""
fi

# ── Launch Frontend ──────────────────────────────────────────────
if $RUN_FRONTEND; then
  info "Starting frontend…"
  cd "$FRONTEND"
  npm run dev 2>&1 | sed "s/^/  ${C_DIM}[frontend]${C_RESET} /" &
  FRONTEND_PID=$!
  PIDS+=($FRONTEND_PID)
  cd "$ROOT_DIR"
  ok "Frontend started  ${C_DIM}PID ${FRONTEND_PID}${C_RESET}"

  info "Opening browser…"
  sleep 2
  xdg-open "http://localhost:5173" 2>/dev/null || open "http://localhost:5173" 2>/dev/null || true
  ok "Browser opened"
fi

# ── Access Info ──────────────────────────────────────────────────
echo ""
sep
echo ""
echo -e "  ${C_CYAN}${C_BOLD}◈  Access Points${C_RESET}"
echo ""
$RUN_FRONTEND && echo -e "  ${C_CYAN}┃${C_RESET}  ${C_BOLD}Frontend${C_RESET}   ${C_GREEN}http://localhost:5173${C_RESET}"
$RUN_BACKEND  && echo -e "  ${C_CYAN}┃${C_RESET}  ${C_BOLD}Backend ${C_RESET}   ${C_GREEN}http://${BACKEND_HOST}:${BACKEND_PORT}${C_RESET}"
$RUN_BACKEND  && echo -e "  ${C_CYAN}┃${C_RESET}  ${C_BOLD}API Docs${C_RESET}   ${C_DIM}http://${BACKEND_HOST}:${BACKEND_PORT}/docs${C_RESET}"
echo ""
sep
echo ""
echo -e "  ${C_DIM}Press Ctrl+C to stop all services${C_RESET}"
echo ""

wait