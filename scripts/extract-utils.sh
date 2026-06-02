#!/usr/bin/env bash
# BeyondArch — extract shared utils
# Creates frontend/src/lib/domUtils.js and patches all imports automatically.
# Safe: backs up each file before patching. Run from repo root.
# Usage: ./scripts/extract-utils.sh [--dry-run]
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$REPO_ROOT/frontend/src"
UTILS_FILE="$SRC/lib/domUtils.js"
BACKUP_DIR="$REPO_ROOT/.script-backups/$(date +%Y%m%d-%H%M%S)"

DRY_RUN=false
for arg in "$@"; do [[ "$arg" == "--dry-run" ]] && DRY_RUN=true; done

C_RESET='\033[0m'; C_CYAN='\033[0;36m'; C_GREEN='\033[0;32m'
C_YELLOW='\033[0;33m'; C_RED='\033[0;31m'; C_BOLD='\033[1m'; C_DIM='\033[2m'
info() { echo -e "${C_CYAN}▸${C_RESET} $*"; }
ok()   { echo -e "${C_GREEN}✓${C_RESET} $*"; }
warn() { echo -e "${C_YELLOW}⚠${C_RESET} $*"; }
die()  { echo -e "${C_RED}✗${C_RESET} $*" >&2; exit 1; }
dim()  { echo -e "  ${C_DIM}$*${C_RESET}"; }

echo -e "\n${C_BOLD}${C_CYAN}BeyondArch — extract-utils${C_RESET}"
$DRY_RUN && warn "DRY RUN — no files will be written"
echo ""

# ── 1. Guard ─────────────────────────────────────────────────────────────────
[[ -d "$SRC" ]] || die "frontend/src not found. Run from repo root."
command -v sed  >/dev/null 2>&1 || die "sed not found"
command -v grep >/dev/null 2>&1 || die "grep not found"

if [[ -f "$UTILS_FILE" ]]; then
  warn "$UTILS_FILE already exists. Skipping creation (will only patch imports)."
  SKIP_CREATE=true
else
  SKIP_CREATE=false
fi

# ── 2. Create domUtils.js ─────────────────────────────────────────────────────
UTILS_CONTENT='/**
 * domUtils.js — shared browser utility functions
 * Extracted from duplicate definitions across 11+ page files.
 * Import with: import { downloadText, copyText } from "@/lib/domUtils"
 * (or adjust relative path per file depth)
 */

/**
 * Trigger a browser file download with text content.
 * @param {string} filename
 * @param {string} content
 * @param {string} [type]
 */
export function downloadText(filename, content, type = "text/plain") {
  const blob = new Blob([content], { type })
  const url = URL.createObjectURL(blob)
  const link = document.createElement("a")
  link.href = url
  link.download = filename
  link.click()
  URL.revokeObjectURL(url)
}

/**
 * Copy text to clipboard and optionally set a notice string.
 * Signature matches the most common usage: copyText(value, setNotice, label)
 * @param {string} text
 * @param {Function|null} setNotice  — setState setter, called with "label copied."
 * @param {string} [label]
 */
export async function copyText(text, setNotice, label = "Copied") {
  if (!text) return
  await navigator.clipboard.writeText(String(text))
  setNotice?.(`${label} copied.`)
}

/**
 * Escape HTML special characters.
 * @param {string} value
 * @returns {string}
 */
export function escapeHtml(value = "") {
  return String(value).replace(
    /[&<>"'\'']/g,
    (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'\''": "&#39;" }[char] || char)
  )
}

/**
 * Normalise a hash string (lowercase, strip whitespace).
 * @param {string} value
 * @returns {string}
 */
export function normalizeHash(value = "") {
  return value.trim().replace(/\s+/g, "").toLowerCase()
}
'

if ! $SKIP_CREATE; then
  if $DRY_RUN; then
    info "Would create: $UTILS_FILE"
  else
    mkdir -p "$SRC/lib"
    echo "$UTILS_CONTENT" > "$UTILS_FILE"
    ok "Created $UTILS_FILE"
  fi
fi

# ── 3. Files to patch ─────────────────────────────────────────────────────────
# Map: file → functions it defines locally that should be removed + imported
declare -A FILE_FUNS

while IFS= read -r filepath; do
  funs=""
  grep -q "^function downloadText\|^async function downloadText" "$filepath" 2>/dev/null && funs="$funs downloadText"
  grep -q "^function copyText\|^async function copyText" "$filepath" 2>/dev/null && funs="$funs copyText"
  grep -q "^function escapeHtml" "$filepath" 2>/dev/null && funs="$funs escapeHtml"
  grep -q "^function normalizeHash" "$filepath" 2>/dev/null && funs="$funs normalizeHash"
  funs="${funs# }"  # trim leading space
  [[ -n "$funs" ]] && FILE_FUNS["$filepath"]="$funs"
done < <(find "$SRC" -name "*.jsx" -not -path "*/node_modules/*")

echo -e "${C_BOLD}Files to patch (${#FILE_FUNS[@]}):${C_RESET}"
for f in "${!FILE_FUNS[@]}"; do
  dim "$(basename "$f")  →  remove: ${FILE_FUNS[$f]}"
done
echo ""

# ── 4. Compute relative import path ──────────────────────────────────────────
rel_import_path() {
  local file_dir target_dir
  file_dir="$(dirname "$1")"
  target_dir="$(dirname "$UTILS_FILE")"
  python3 -c "
import os, sys
src = sys.argv[1]
tgt = sys.argv[2] + '/domUtils.js'
rel = os.path.relpath(tgt, src)
# ensure starts with ./
if not rel.startswith('.'):
    rel = './' + rel
print(rel)
" "$file_dir" "$target_dir"
}

# ── 5. Backup + patch each file ───────────────────────────────────────────────
PATCHED=0
ERRORS=0

for filepath in "${!FILE_FUNS[@]}"; do
  rel="${filepath#$SRC/}"
  funs="${FILE_FUNS[$filepath]}"
  import_path="$(rel_import_path "$filepath")"

  # Build the named imports string
  import_names=$(echo "$funs" | tr ' ' '\n' | sort | tr '\n' ',' | sed 's/,/, /g; s/, $//')
  import_line="import { ${import_names} } from \"${import_path}\""

  if $DRY_RUN; then
    info "Would patch: $rel"
    dim "  add import: $import_line"
    dim "  remove:     $funs"
    continue
  fi

  # Backup
  mkdir -p "$BACKUP_DIR"
  cp "$filepath" "$BACKUP_DIR/$(basename "$filepath").bak"

  # Remove function bodies (single-pass python for reliability)
  python3 - "$filepath" "$funs" "$import_line" <<'PYEOF'
import sys, re

filepath = sys.argv[1]
funs_to_remove = sys.argv[2].split()
import_line = sys.argv[3]

with open(filepath, 'r') as fh:
    src = fh.read()

original = src

# Remove each function definition (handles multi-line bodies via brace counting)
for fn in funs_to_remove:
    # Match: optional 'async ', 'function fnName', then everything up to matching closing brace
    pattern = rf'(?:async\s+)?function\s+{re.escape(fn)}\s*\([^)]*\)\s*\{{'
    m = re.search(pattern, src)
    if not m:
        continue
    start = m.start()
    # Find matching closing brace
    depth = 0
    i = m.start()
    in_string = None
    while i < len(src):
        c = src[i]
        if in_string:
            if c == '\\':
                i += 2
                continue
            if c == in_string:
                in_string = None
        else:
            if c in ('"', "'", '`'):
                in_string = c
            elif c == '{':
                depth += 1
            elif c == '}':
                depth -= 1
                if depth == 0:
                    end = i + 1
                    # consume trailing newline
                    while end < len(src) and src[end] in ('\n', '\r'):
                        end += 1
                    src = src[:start] + src[end:]
                    break
        i += 1

# Add import line after the last existing import line (or after first line if none)
lines = src.split('\n')
last_import_idx = -1
for idx, line in enumerate(lines):
    if line.strip().startswith('import '):
        last_import_idx = idx

# Check if import already exists
already_imported = any(import_line.split('"')[0].split('{')[1].strip().split('}')[0] in l for l in lines if l.strip().startswith('import'))

if last_import_idx >= 0 and not already_imported:
    lines.insert(last_import_idx + 1, import_line)
    src = '\n'.join(lines)

if src != original:
    with open(filepath, 'w') as fh:
        fh.write(src)
    print(f"PATCHED: {filepath}")
else:
    print(f"UNCHANGED: {filepath}")
PYEOF

  status=$?
  if [[ $status -eq 0 ]]; then
    ok "$rel"
    PATCHED=$((PATCHED + 1))
  else
    warn "Error patching $rel — backup at $BACKUP_DIR/$(basename "$filepath").bak"
    ERRORS=$((ERRORS + 1))
  fi
done

# ── 6. Summary ────────────────────────────────────────────────────────────────
echo ""
if $DRY_RUN; then
  info "Dry run complete. Re-run without --dry-run to apply."
else
  ok "Patched:  $PATCHED files"
  [[ $ERRORS -gt 0 ]] && warn "Errors:   $ERRORS files — check backups in $BACKUP_DIR"
  echo ""
  info "Backups saved to: $BACKUP_DIR"
  info "Run 'npm run lint' inside frontend/ to verify no broken imports."
fi
echo ""
