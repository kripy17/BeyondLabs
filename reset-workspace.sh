#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UI_HELPER="$ROOT_DIR/scripts/terminal-ui.sh"
ASSUME_YES=0
DRY_RUN=0

[[ -f "$UI_HELPER" ]] || { echo "Missing: $UI_HELPER" >&2; exit 1; }
. "$UI_HELPER"

usage() {
  ba_usage_header "workspace reset"
  cat <<'EOF'
Usage: ./reset-workspace.sh [options]

Options:
  --yes, -y   Run cleanup without confirmation.
  --dry-run   Show what would be removed.
  --help      Show this help.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --yes|-y) ASSUME_YES=1 ;;
    --dry-run) DRY_RUN=1 ;;
    --help|-h) usage; exit 0 ;;
    *) ba_err "Unknown option: $1"; usage; exit 2 ;;
  esac
  shift
done

confirm() {
  local answer=""
  [[ -t 0 ]] || return 1
  ba_prompt "Continue cleanup? [y/N] "
  read -r answer
  case "$answer" in y|Y|yes|YES) return 0 ;; *) return 1 ;; esac
}

collect_targets() {
  find "$ROOT_DIR" \
    \( -path "$ROOT_DIR/.git" -o -path "$ROOT_DIR/frontend/node_modules" -o -path "$ROOT_DIR/backend/.venv" \) -prune -o \
    \( -type d \( -name __pycache__ -o -name .pytest_cache -o -name .ruff_cache -o -name .vite \) -print \)
  find "$ROOT_DIR" \
    \( -path "$ROOT_DIR/.git" -o -path "$ROOT_DIR/frontend/node_modules" -o -path "$ROOT_DIR/backend/.venv" \) -prune -o \
    \( -type f \( -name '*.pyc' -o -name '*.pyo' \) -print \)
  for path in "$ROOT_DIR/frontend/dist" "$ROOT_DIR/exports" "$ROOT_DIR/reports" "$ROOT_DIR/timeline-exports"; do
    [[ -e "$path" ]] && printf '%s\n' "$path"
  done
}

ba_compact_header "workspace reset"
echo -e "  ${C_YELLOW}▲${C_RESET} Removes local runtime/cache/build output only."
echo -e "  ${C_CYAN}◆${C_RESET} Preserved: source, .git, configs, .venv, node_modules"
echo -e "  ${C_CYAN}◆${C_RESET} Browser localStorage must be cleared from Settings workspace"
echo ""

mapfile -t TARGETS < <(collect_targets | sort -u)
ba_section "01" "Cleanup plan"
if [[ "${#TARGETS[@]}" -eq 0 ]]; then
  ba_ok "No cleanup targets found"
  exit 0
fi
echo -e "  ${C_DIM}Targets found: ${#TARGETS[@]}${C_RESET}"
printf '%s\n' "${TARGETS[@]}" | sed "s#^$ROOT_DIR/#  #"

if [[ "$DRY_RUN" -eq 1 ]]; then
  echo ""
  ba_info "Dry run complete; nothing removed"
  exit 0
fi

if [[ "$ASSUME_YES" -ne 1 ]]; then
  confirm || { ba_info "Cleanup cancelled"; exit 0; }
fi

ba_section "02" "Cleanup"
for path in "${TARGETS[@]}"; do
  if [[ "$path" == "$ROOT_DIR/.git"* || "$path" == "$ROOT_DIR/backend/.venv"* || "$path" == "$ROOT_DIR/frontend/node_modules"* ]]; then
    ba_warn "Skipped protected: ${path#$ROOT_DIR/}"
    continue
  fi
  rm -rf "$path"
  ba_ok "Removed ${path#$ROOT_DIR/}"
done

mapfile -t AFTER < <(collect_targets | sort -u)
echo ""
ba_section "03" "Summary"
echo -e "  ${C_CYAN}┃${C_RESET}  ${C_BOLD}Before${C_RESET}  ${#TARGETS[@]} targets"
echo -e "  ${C_CYAN}┃${C_RESET}  ${C_BOLD}After ${C_RESET}  ${#AFTER[@]} targets"
echo -e "  ${C_CYAN}┃${C_RESET}"
echo -e "  ${C_CYAN}┃${C_RESET}  Recheck: ${C_BOLD}./doctor.sh${C_RESET}"
echo ""
