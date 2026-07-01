#!/usr/bin/env bash
# BeyondArch audit — finds duplications, large files, style inconsistencies
# Usage: ./scripts/audit.sh [--from REPO_ROOT]
set -euo pipefail

REPO_ROOT="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
SRC="$REPO_ROOT/frontend/src"
STYLES_CSS="$SRC/styles.css"

C_RESET='\033[0m'; C_CYAN='\033[0;36m'; C_GREEN='\033[0;32m'
C_YELLOW='\033[0;33m'; C_RED='\033[0;31m'; C_BOLD='\033[1m'; C_DIM='\033[2m'
C_MAGENTA='\033[0;35m'

section() { echo -e "\n${C_BOLD}${C_CYAN}── $* ${C_RESET}${C_DIM}────────────────────────────────${C_RESET}"; }
item()    { echo -e "  ${C_YELLOW}▸${C_RESET} $*"; }
ok()      { echo -e "  ${C_GREEN}✓${C_RESET} $*"; }
bad()     { echo -e "  ${C_RED}✗${C_RESET} $*"; }
dim()     { echo -e "  ${C_DIM}$*${C_RESET}"; }

echo -e "\n${C_BOLD}${C_MAGENTA}BeyondArch Codebase Audit${C_RESET}"
echo -e "${C_DIM}$SRC${C_RESET}"

# ── 1. File sizes ────────────────────────────────────────────────────────────
section "JSX file sizes (sorted)"
find "$SRC" -name "*.jsx" | while read -r f; do
  lines=$(wc -l < "$f")
  rel="${f#$SRC/}"
  if   [[ $lines -gt 1500 ]]; then echo "  ${C_RED}${lines}${C_RESET}  $rel"
  elif [[ $lines -gt 800  ]]; then echo "  ${C_YELLOW}${lines}${C_RESET}  $rel"
  elif [[ $lines -gt 400  ]]; then echo "  ${C_DIM}${lines}${C_RESET}  $rel"
  else                              echo "  ${lines}  $rel"
  fi
done | sort -rn

# ── 2. CSS file sizes ────────────────────────────────────────────────────────
section "Styles"
if [[ -f "$STYLES_CSS" ]]; then
  lines=$(wc -l < "$STYLES_CSS")
  echo "  styles.css  (${lines} lines)"
else
  echo "  (no styles.css found at $STYLES_CSS)"
fi

# ── 3. Duplicate functions ────────────────────────────────────────────────────
section "Duplicate function definitions"
DUPS=(
  "function downloadText"
  "function copyText\|async function copyText"
  "function escapeHtml"
  "function normalizeHash"
  "localStorage.setItem.*pendingArtifact\|PENDING_KEY"
)
LABELS=(
  "downloadText"
  "copyText"
  "escapeHtml"
  "normalizeHash"
  "pendingArtifact localStorage"
)

for i in "${!DUPS[@]}"; do
  count=$(grep -rn "${DUPS[$i]}" "$SRC" --include="*.jsx" 2>/dev/null | wc -l)
  files=$(grep -rln "${DUPS[$i]}" "$SRC" --include="*.jsx" 2>/dev/null | wc -l)
  if [[ $count -gt 1 ]]; then
    bad "${LABELS[$i]}: ${count} definitions across ${files} files"
    grep -rln "${DUPS[$i]}" "$SRC" --include="*.jsx" 2>/dev/null | while read -r f; do
      dim "    $(basename "$f")"
    done
  else
    ok "${LABELS[$i]}: ok"
  fi
done

# ── 4. Raw JSON dumps in output ───────────────────────────────────────────────
section "Raw JSON.stringify in JSX render (output panel smell)"
grep -rn "JSON.stringify.*null.*2.*}" "$SRC" --include="*.jsx" | while read -r line; do
  file=$(echo "$line" | cut -d: -f1 | sed "s|$SRC/||")
  lineno=$(echo "$line" | cut -d: -f2)
  item "${file}:${lineno}"
done

# ── 5. Styling approach inconsistency ────────────────────────────────────────
section "Styling approach per file"
echo -e "  ${C_DIM}(ba-ds-* = design system | pt-* = phishing scope | tw = raw Tailwind inline)${C_RESET}"
find "$SRC/pages" "$SRC/components" -name "*.jsx" 2>/dev/null | sort | while read -r f; do
  rel="${f#$SRC/}"
  has_bads=$(grep -c "ba-ds-\|ba-workbench\|ba-panel" "$f" 2>/dev/null || echo 0)
  has_pt=$(grep -c '"pt-' "$f" 2>/dev/null || echo 0)
  has_tw=$(grep -c 'className=.*rounded-xl\|className=.*bg-black\|className=.*text-zinc' "$f" 2>/dev/null || echo 0)
  flags=""
  [[ $has_bads -gt 0 ]] && flags="${flags}${C_GREEN}ba-ds${C_RESET} "
  [[ $has_pt -gt 0   ]] && flags="${flags}${C_YELLOW}pt-*${C_RESET} "
  [[ $has_tw -gt 0   ]] && flags="${flags}${C_RED}tailwind-inline${C_RESET} "
  [[ -z "$flags" ]] && flags="${C_DIM}no class pattern${C_RESET}"
  echo -e "  $rel  →  $flags"
done

# ── 6. Unstyled <details> usage ───────────────────────────────────────────────
section "<details> / <summary> usage (browser-native, unstyled)"
grep -rn "<details\|<summary" "$SRC" --include="*.jsx" | while read -r line; do
  file=$(echo "$line" | cut -d: -f1 | sed "s|$SRC/||")
  lineno=$(echo "$line" | cut -d: -f2)
  item "${file}:${lineno}"
done

# ── 7. CSS @import usage ──────────────────────────────────────────────────────
section "CSS @import usage"
if [[ -f "$STYLES_CSS" ]]; then
  imports=$(grep -c "@import" "$STYLES_CSS" 2>/dev/null || echo 0)
  if [[ $imports -gt 0 ]]; then
    item "styles.css has $imports @import rules"
  else
    ok "No @import in styles.css"
  fi
fi

# ── 8. Summary ────────────────────────────────────────────────────────────────
section "Summary"
JSX_COUNT=$(find "$SRC" -name "*.jsx" | wc -l)
BIG_FILES=$(find "$SRC" -name "*.jsx" | xargs wc -l 2>/dev/null | awk '$1>800' | wc -l)

echo ""
echo -e "  JSX files:     ${JSX_COUNT}"
echo -e "  Large (>800):  ${C_YELLOW}${BIG_FILES}${C_RESET}  files may need component extraction"
echo ""
