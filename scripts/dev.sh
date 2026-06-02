#!/usr/bin/env bash
# BeyondArch dev starter — Arch Linux
# Usage: ./dev.sh [--backend-only | --frontend-only]
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FRONTEND="$REPO_ROOT/frontend"
BACKEND="$REPO_ROOT/backend"
BACKEND_ENV="$BACKEND/.env"
BACKEND_ENV_EXAMPLE="$BACKEND/.env.example"

# ── colors ─────────────────────────────────────────────────────────────────
C_RESET='\033[0m'; C_CYAN='\033[0;36m'; C_GREEN='\033[0;32m'
C_YELLOW='\033[0;33m'; C_RED='\033[0;31m'; C_BOLD='\033[1m'
info()  { echo -e "${C_CYAN}▸${C_RESET} $*"; }
ok()    { echo -e "${C_GREEN}✓${C_RESET} $*"; }
warn()  { echo -e "${C_YELLOW}⚠${C_RESET} $*"; }
die()   { echo -e "${C_RED}✗${C_RESET} $*" >&2; exit 1; }
banner(){ echo -e "\n${C_BOLD}${C_CYAN}BeyondArch — dev${C_RESET}\n"; }

# ── args ────────────────────────────────────────────────────────────────────
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

banner

# ── preflight ───────────────────────────────────────────────────────────────
command -v node >/dev/null 2>&1 || die "node not found. Install: sudo pacman -S nodejs"
command -v npm  >/dev/null 2>&1 || die "npm not found.  Install: sudo pacman -S npm"
command -v python3 >/dev/null 2>&1 || die "python3 not found. Install: sudo pacman -S python"

NODE_VER=$(node -e "process.stdout.write(process.versions.node.split('.')[0])")
[[ "$NODE_VER" -ge 18 ]] || warn "Node $NODE_VER detected. v18+ recommended."

# ── .env setup ──────────────────────────────────────────────────────────────
if [[ ! -f "$BACKEND_ENV" && -f "$BACKEND_ENV_EXAMPLE" ]]; then
  cp "$BACKEND_ENV_EXAMPLE" "$BACKEND_ENV"
  ok "Created backend/.env from example"
fi

# ── frontend deps ───────────────────────────────────────────────────────────
if $RUN_FRONTEND; then
  if [[ ! -d "$FRONTEND/node_modules" ]]; then
    info "Installing frontend deps…"
    (cd "$FRONTEND" && npm install)
    ok "Frontend deps installed"
  else
    ok "Frontend node_modules present"
  fi
fi

# ── backend venv ────────────────────────────────────────────────────────────
if $RUN_BACKEND; then
  if [[ ! -d "$BACKEND/.venv" ]]; then
    info "Creating Python venv…"
    python3 -m venv "$BACKEND/.venv"
    ok "Venv created"
  fi
  info "Installing backend deps…"
  "$BACKEND/.venv/bin/pip" install -q -r "$BACKEND/requirements.txt"
  ok "Backend deps ready"
fi

# ── launch ──────────────────────────────────────────────────────────────────
PIDS=()

cleanup() {
  echo -e "\n${C_YELLOW}Stopping…${C_RESET}"
  for pid in "${PIDS[@]}"; do
    kill "$pid" 2>/dev/null || true
  done
  wait 2>/dev/null
  echo -e "${C_GREEN}Stopped.${C_RESET}"
}
trap cleanup INT TERM EXIT

if $RUN_BACKEND; then
  info "Starting backend on :8000"
  cd "$BACKEND"
  .venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload &
  PIDS+=($!)
  cd "$REPO_ROOT"
fi

if $RUN_FRONTEND; then
  # Small delay so backend port is ready before Vite proxy attempts connect
  sleep 1
  info "Starting frontend on :5173"
  cd "$FRONTEND"
  npm run dev &
  PIDS+=($!)
  cd "$REPO_ROOT"
fi

echo ""
$RUN_FRONTEND && echo -e "  ${C_CYAN}Frontend${C_RESET}  http://localhost:5173"
$RUN_BACKEND  && echo -e "  ${C_CYAN}Backend ${C_RESET}  http://localhost:8000/docs"
echo ""
echo -e "  ${C_YELLOW}Ctrl+C to stop${C_RESET}"
echo ""

wait
