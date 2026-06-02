#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UI_HELPER="$ROOT_DIR/scripts/terminal-ui.sh"
BACKEND_URL="${BACKEND_URL:-http://127.0.0.1:8000}"
FRONTEND_URL="${FRONTEND_URL:-http://127.0.0.1:5173}"

[[ -f "$UI_HELPER" ]] || { echo "Missing: $UI_HELPER" >&2; exit 1; }
. "$UI_HELPER"

ba_compact_header "guided local SOC demo"

ba_section "01" "Service status"
if command -v curl >/dev/null 2>&1 && curl -fsS "$FRONTEND_URL" >/dev/null 2>&1; then
  ba_ok "Frontend reachable: $FRONTEND_URL"
else
  ba_info "Frontend not running — start with ./run.sh"
fi
if command -v curl >/dev/null 2>&1 && curl -fsS "$BACKEND_URL/health" >/dev/null 2>&1; then
  ba_ok "Backend reachable: $BACKEND_URL"
else
  ba_info "Backend not running — start with ./run.sh"
fi

ba_section "02" "Demo flow"
cat <<'EOF'
Artifact Intake
  Paste mixed artifact → route URL, attachment, command, IP, event

Phishing Triage
  Review sender/domain mismatch, lure language, auth hints, disposition

Safe URL Analyzer
  Static review first; guarded metadata checks when appropriate

Attachment Triage
  Filename, macro/script indicators, hashes, strings — no execution

Detection & MITRE
  Map evidence to ATT&CK candidates, draft detection logic

Case & Report
  Add findings as evidence, export Markdown timeline/report
EOF

ba_section "03" "Sample input"
cat <<'EOF'
From: IT Helpdesk <security@micros0ft-login.com>
Reply-To: helpdesk-reset@outlook-security.example
Subject: Urgent mailbox validation required
URL: hxxp://micros0ft-login[.]com/login
Attachment: invoice.docm
Command: powershell -NoP -W Hidden -EncodedCommand SQBFAFgA
EventCode=4688
Source IP: 192.168.56.10
User-Agent: Mozilla/5.0 curl/8.1
Observed hash: 44d88612fea8a8f36de82e1278abb02f
EOF

ba_section "04" "Page-specific samples"
cat <<'EOF'
OSINT Tools domain: example.com
Safe URL Analyzer URL: hxxps://example[.]com/login?session=reset
Attachment Triage filename: Q2_invoice_update.docm
Detection & MITRE evidence: Encoded PowerShell spawned by office document
Case & Report title: Phishing triage - mailbox validation lure
Nmap Runner lab target: scanme.nmap.org or owned/private lab host only
EOF

echo ""
ba_section "05" "Next"
echo ""
echo -e "  ${C_CYAN}┃${C_RESET}  ${C_BOLD}Launch   ${C_RESET}  ${C_DIM}./run.sh${C_RESET}"
echo -e "  ${C_CYAN}┃${C_RESET}  ${C_BOLD}Health   ${C_RESET}  ${C_DIM}./doctor.sh${C_RESET}"
echo ""
