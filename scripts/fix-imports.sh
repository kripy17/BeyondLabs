#!/usr/bin/env bash
# fix-imports.sh — restores the 4 broken files and re-applies imports cleanly
# Run from repo root: ./scripts/fix-imports.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$REPO_ROOT/frontend/src"
BACKUP_ROOT="$REPO_ROOT/.script-backups"

C_RESET='\033[0m'; C_CYAN='\033[0;36m'; C_GREEN='\033[0;32m'
C_YELLOW='\033[0;33m'; C_RED='\033[0;31m'; C_BOLD='\033[1m'; C_DIM='\033[2m'
info() { echo -e "${C_CYAN}▸${C_RESET} $*"; }
ok()   { echo -e "${C_GREEN}✓${C_RESET} $*"; }
warn() { echo -e "${C_YELLOW}⚠${C_RESET} $*"; }
die()  { echo -e "${C_RED}✗${C_RESET} $*" >&2; exit 1; }

echo -e "\n${C_BOLD}${C_CYAN}BeyondArch — fix-imports${C_RESET}\n"

# ── 1. Find latest backup dir ─────────────────────────────────────────────────
[[ -d "$BACKUP_ROOT" ]] || die "No backup dir found at $BACKUP_ROOT. Can't restore."

LATEST_BACKUP=$(ls -td "$BACKUP_ROOT"/2* 2>/dev/null | head -1)
[[ -n "$LATEST_BACKUP" ]] || die "No timestamped backup dirs found in $BACKUP_ROOT"

info "Using backup: $LATEST_BACKUP"
echo ""

# ── 2. Files that broke ───────────────────────────────────────────────────────
BROKEN_FILES=(
  "pages/detection/InvestigationTimelinePage.jsx"
  "pages/recon/NmapRunnerPage.jsx"
  "pages/recon/ReconExposurePage.jsx"
  "pages/triage/PhishingTriagePage.jsx"
)

# ── 3. Restore each from backup ───────────────────────────────────────────────
info "Restoring from backup..."
for rel in "${BROKEN_FILES[@]}"; do
  bak="$LATEST_BACKUP/$(basename "$rel").bak"
  dest="$SRC/$rel"
  if [[ -f "$bak" ]]; then
    cp "$bak" "$dest"
    ok "Restored: $rel"
  else
    warn "Backup not found for $rel — skipping restore"
  fi
done
echo ""

# ── 4. Determine import path per file ─────────────────────────────────────────
# domUtils.js is at src/lib/domUtils.js
UTILS="$SRC/lib/domUtils.js"
[[ -f "$UTILS" ]] || die "domUtils.js not found at $UTILS — run extract-utils.sh first to create it."

# Given a .jsx path, return relative import path to domUtils.js
rel_path() {
  python3 -c "
import os, sys
fdir = os.path.dirname(os.path.abspath(sys.argv[1]))
tgt  = os.path.abspath(sys.argv[2])
rel  = os.path.relpath(tgt, fdir)
if not rel.startswith('.'): rel = './' + rel
print(rel)
" "$1" "$UTILS"
}

# ── 5. What does each file actually need to import? ───────────────────────────
# Scan what functions from domUtils each file uses
needs_import() {
  local f="$1"
  local fns=()
  grep -q '\bdownloadText\b' "$f" && fns+=("downloadText")
  grep -q '\bcopyText\b'     "$f" && fns+=("copyText")
  grep -q '\bescapeHtml\b'   "$f" && fns+=("escapeHtml")
  grep -q '\bnormalizeHash\b' "$f" && fns+=("normalizeHash")
  # join with ", "
  local IFS=", "
  echo "${fns[*]}"
}

# ── 6. Insert import after last existing import line (reliable sed approach) ──
insert_import_after_last_import() {
  local file="$1"
  local import_line="$2"

  # Already imported? Skip.
  grep -qF "$import_line" "$file" && return 0

  # Find last line number starting with 'import '
  last_import_line=$(grep -n '^import ' "$file" | tail -1 | cut -d: -f1)

  if [[ -z "$last_import_line" ]]; then
    # No imports at all — prepend
    tmpfile=$(mktemp)
    { echo "$import_line"; echo ""; cat "$file"; } > "$tmpfile"
    mv "$tmpfile" "$file"
  else
    # Insert after last import line using awk (works on Arch, no BSD sed needed)
    tmpfile=$(mktemp)
    awk -v n="$last_import_line" -v line="$import_line" \
      'NR==n{print; print line; next} 1' "$file" > "$tmpfile"
    mv "$tmpfile" "$file"
  fi
}

# ── 7. Patch each file ────────────────────────────────────────────────────────
info "Adding imports..."
for rel in "${BROKEN_FILES[@]}"; do
  dest="$SRC/$rel"
  [[ -f "$dest" ]] || { warn "File not found: $dest"; continue; }

  fns="$(needs_import "$dest")"
  if [[ -z "$fns" ]]; then
    warn "$rel — no domUtils functions used, skipping"
    continue
  fi

  ipath="$(rel_path "$dest" "$UTILS")"
  import_line="import { ${fns} } from \"${ipath}\""

  insert_import_after_last_import "$dest" "$import_line"
  ok "$(basename "$rel")  →  import { ${fns} }"
done

echo ""

# ── 8. NOTE: local function definitions still exist in these files ─────────────
echo -e "${C_YELLOW}NOTE:${C_RESET} The original local function definitions are still in these files."
echo -e "They won't conflict (import shadows them in module scope) but they're dead code."
echo ""
echo -e "To clean them up manually, search each file for:"
echo -e "  ${C_DIM}function downloadText${C_RESET}  and  ${C_DIM}async function copyText${C_RESET}"
echo -e "and delete those function bodies (they're now imported from domUtils.js)."
echo ""
echo -e "${C_BOLD}Verify:${C_RESET}"
echo -e "  cd $REPO_ROOT/frontend && npm run lint"
echo ""
