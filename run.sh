#!/usr/bin/env bash
# BeyondArch — start backend and frontend together
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FRONTEND="$ROOT_DIR/frontend"
BACKEND="$ROOT_DIR/backend"
PIDS=()
START_TS=$(date +%s)

# ── Inline colors for standalone use (no deps) ─────────────────
C_RESET='\033[0m'; C_BOLD='\033[1m'; C_DIM='\033[2m'
C_CYAN='\033[0;36m'; C_GREEN='\033[0;32m'; C_YELLOW='\033[0;33m'; C_RED='\033[0;31m'

cleanup() {
  local code=$?
  local elapsed=$(($(date +%s) - START_TS))
  printf '\n'
  for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null || true; done
  wait 2>/dev/null
  if [[ $code -eq 0 ]]; then
    echo -e "  ${C_GREEN}●${C_RESET} Stopped cleanly  ${C_DIM}(${elapsed}s)${C_RESET}"
  else
    echo -e "  ${C_YELLOW}▲${C_RESET} Exited with code ${code}  ${C_DIM}(${elapsed}s)${C_RESET}"
  fi
}
trap cleanup INT TERM EXIT

# ── Visual helpers ──────────────────────────────────────────────
info() { echo -e "  ${C_CYAN}◆${C_RESET} $*"; }
ok()   { echo -e "  ${C_GREEN}●${C_RESET} $*"; }
die()  { echo -e "  ${C_RED}■${C_RESET} $*" >&2; exit 1; }

# ── Banner ──────────────────────────────────────────────────────
echo ""
echo -e "${C_CYAN}"
echo '  ██████╗ ███████╗██╗   ██╗ ██████╗ ███╗   ██╗██████╗ '
echo '  ██╔══██╗██╔════╝╚██╗ ██╔╝██╔═══██╗████╗  ██║██╔══██╗'
echo '  ██████╔╝█████╗   ╚████╔╝ ██║   ██║██╔██╗ ██║██████╔╝'
echo '  ██╔══██╗██╔══╝    ╚██╔╝  ██║   ██║██║╚██╗██║██╔══██╗'
echo '  ██████╔╝███████╗   ██║   ╚██████╔╝██║ ╚████║██████╔╝'
echo '  ╚═════╝ ╚══════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═══╝╚═════╝ '
echo -e "${C_RESET}"
echo -e "  ${C_DIM}Local SOC analyst workbench${C_RESET}"
echo -e "  ${C_DIM}──────────────────────────────────────────────${C_RESET}"
echo ""

# ── Auto-create .env ────────────────────────────────────────────
if [[ ! -f "$BACKEND/.env" && -f "$BACKEND/.env.example" ]]; then
  cp "$BACKEND/.env.example" "$BACKEND/.env"
  info "Created backend/.env from example"
fi

# ── Preflight ───────────────────────────────────────────────────
command -v node >/dev/null 2>&1 || die "Node.js not found — run ./install.sh"
if [[ ! -d "$BACKEND/.venv" ]]; then die "Backend venv missing — run ./install.sh"; fi
if [[ ! -d "$FRONTEND/node_modules" ]]; then die "Frontend deps missing — run ./install.sh"; fi

# ── Launch ───────────────────────────────────────────────────────
cd "$BACKEND"
.venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload &
PIDS+=($!)
cd "$ROOT_DIR"
info "Backend   — uvicorn :8000"

sleep 1

cd "$FRONTEND"
npm run dev &
PIDS+=($!)
cd "$ROOT_DIR"
info "Frontend  — vite    :5173"

echo ""
echo -e "  ${C_CYAN}┃${C_RESET}  ${C_BOLD}Frontend${C_RESET}  ${C_DIM}http://localhost:5173${C_RESET}"
echo -e "  ${C_CYAN}┃${C_RESET}  ${C_BOLD}Backend ${C_RESET}  ${C_DIM}http://localhost:8000/docs${C_RESET}"
echo ""
echo -e "  ${C_DIM}Ctrl+C to stop${C_RESET}"
echo ""

wait
