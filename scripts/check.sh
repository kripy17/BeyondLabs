#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

PASS=0
WARN=0
FAIL=0

ok() { PASS=$((PASS + 1)); printf '[✓] %s\n' "$1"; }
warn() { WARN=$((WARN + 1)); printf '[!] %s\n' "$1"; }
err() { FAIL=$((FAIL + 1)); printf '[x] %s\n' "$1" >&2; }

run_required() {
  local label="$1"; shift
  printf '[~] %s\n' "$label"
  if "$@"; then ok "$label"; else err "$label"; return 1; fi
}

run_optional() {
  local label="$1"; shift
  printf '[~] %s\n' "$label"
  if "$@"; then ok "$label"; else warn "$label failed or is unavailable"; fi
}

cleanup_generated() {
  rm -rf "$ROOT_DIR/frontend/dist" "$ROOT_DIR/frontend/test-results" "$ROOT_DIR/frontend/playwright-report" "$ROOT_DIR/test-results" "$ROOT_DIR/playwright-report"
}
trap cleanup_generated EXIT

printf '\nBeyondArch project checks\n\n'

run_required "Bash syntax checks" bash -n install.sh run.sh doctor.sh reset-workspace.sh demo-workflow.sh scripts/terminal-ui.sh scripts/tool-inventory.sh scripts/check.sh

if command -v pwsh >/dev/null 2>&1; then
  run_required "PowerShell parse checks" pwsh -NoProfile -Command '
    $ErrorActionPreference = "Stop"
    foreach ($file in @("install.ps1", "run.ps1", "doctor.ps1", "uninstall.ps1")) {
      $tokens = $null
      $errors = $null
      [System.Management.Automation.Language.Parser]::ParseFile((Join-Path (Get-Location) $file), [ref]$tokens, [ref]$errors) | Out-Null
      if ($errors.Count -gt 0) { throw "$file parse failed: $($errors[0].Message)" }
    }
  '
else
  warn "pwsh not available; skipped PowerShell parse checks"
fi

if [[ -x backend/.venv/bin/python ]]; then
  PYTHON_CHECK="$ROOT_DIR/backend/.venv/bin/python"
elif command -v python3 >/dev/null 2>&1; then
  PYTHON_CHECK="$(command -v python3)"
elif command -v python >/dev/null 2>&1; then
  PYTHON_CHECK="$(command -v python)"
else
  PYTHON_CHECK=""
fi

if [[ -n "$PYTHON_CHECK" ]]; then
  run_required "Backend compile check" "$PYTHON_CHECK" -m compileall -q backend/app
  if "$PYTHON_CHECK" -m pytest --version >/dev/null 2>&1 && [[ -d backend/tests ]]; then
    run_optional "Backend pytest" bash -c "cd backend && '$PYTHON_CHECK' -m pytest"
  else
    warn "pytest not available or backend/tests missing; skipped backend pytest"
  fi
else
  err "Python missing; backend checks skipped"
fi

if [[ -d frontend/node_modules ]]; then
  run_required "Frontend lint" bash -c "cd frontend && npm run lint"
  run_required "Frontend build" bash -c "cd frontend && npm run build"
  if [[ -f frontend/playwright.config.js ]]; then
    run_optional "Playwright smoke tests" bash -c "cd frontend && npm run test:smoke"
  else
    warn "frontend/playwright.config.js missing; skipped Playwright smoke tests"
  fi
else
  warn "frontend/node_modules missing; skipped frontend lint/build/smoke. Run ./install.sh first."
fi

printf '\nSummary: OK=%s Warnings=%s Errors=%s\n' "$PASS" "$WARN" "$FAIL"
if [[ "$FAIL" -gt 0 ]]; then
  exit 1
fi
