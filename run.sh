#!/usr/bin/env bash
# BeyondArch — start backend and frontend together
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

# ── Colors ──────────────────────────────────────────────────────
C_RESET='\033[0m'; C_BOLD='\033[1m'; C_DIM='\033[2m'
C_CYAN='\033[0;36m'; C_GREEN='\033[0;32m'
C_YELLOW='\033[0;33m'; C_RED='\033[0;31m'
C_WHITE='\033[0;37m'

# ── Helpers ─────────────────────────────────────────────────────
info()  { echo -e "  ${C_CYAN}◆${C_RESET}  $*"; }
ok()    { echo -e "  ${C_GREEN}✔${C_RESET}  $*"; }
warn()  { echo -e "  ${C_YELLOW}▲${C_RESET}  $*"; }
die()   { echo -e "\n  ${C_RED}✖${C_RESET}  $*\n" >&2; exit 1; }
sep()   { echo -e "  ${C_DIM}────────────────────────────────────────────────${C_RESET}"; }

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
echo ""
echo -e "${C_CYAN}${C_BOLD}"
echo '  ██████╗ ███████╗██╗   ██╗ ██████╗ ███╗   ██╗██████╗  █████╗ ██████╗  ██████╗██╗  ██╗'
echo '  ██╔══██╗██╔════╝╚██╗ ██╔╝██╔═══██╗████╗  ██║██╔══██╗██╔══██╗██╔══██╗██╔════╝██║  ██║'
echo '  ██████╔╝█████╗   ╚████╔╝ ██║   ██║██╔██╗ ██║██║  ██║███████║██████╔╝██║     ███████║'
echo '  ██╔══██╗██╔══╝    ╚██╔╝  ██║   ██║██║╚██╗██║██║  ██║██╔══██║██╔══██╗██║     ██╔══██║'
echo '  ██████╔╝███████╗   ██║   ╚██████╔╝██║ ╚████║██████╔╝██║  ██║██║  ██║╚██████╗██║  ██║'
echo '  ╚═════╝ ╚══════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═══╝╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝'
echo -e "${C_RESET}"
echo -e "  ${C_WHITE}${C_BOLD}Local SOC Investigation Workbench${C_RESET}  ${C_DIM}v0.1.0${C_RESET}"
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
    --host 127.0.0.1 \
    --port 8000 \
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
    if curl -sf http://127.0.0.1:8000/docs >/dev/null 2>&1; then
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
fi

# ── Access Info ──────────────────────────────────────────────────
echo ""
sep
echo ""
echo -e "  ${C_CYAN}${C_BOLD}◈  Access Points${C_RESET}"
echo ""
$RUN_FRONTEND && echo -e "  ${C_CYAN}┃${C_RESET}  ${C_BOLD}Frontend${C_RESET}   ${C_GREEN}http://localhost:5173${C_RESET}"
$RUN_BACKEND  && echo -e "  ${C_CYAN}┃${C_RESET}  ${C_BOLD}Backend ${C_RESET}   ${C_GREEN}http://localhost:8000${C_RESET}"
$RUN_BACKEND  && echo -e "  ${C_CYAN}┃${C_RESET}  ${C_BOLD}API Docs${C_RESET}   ${C_DIM}http://localhost:8000/docs${C_RESET}"
echo ""
sep
echo ""
echo -e "  ${C_DIM}Press Ctrl+C to stop all services${C_RESET}"
echo ""

wait