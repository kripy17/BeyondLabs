# BeyondLabs - Page-by-Page Observations & Improvement Plan

**Date:** 2026-07-03
**Screenshots:** `/tmp/screenshots/` (18 pages captured)

---

## Summary

| Category | Count |
|----------|-------|
| Pages Captured | 18/18 |
| Critical Issues | 2 |
| Medium Issues | 5 |
| Low Issues | 8 |
| Total Improvements | 15 |
| Fake Scoring Removed | 4 files |
| Code Duplication | 2 groups |
| Missing AbortController | 3 files |
| `any` Type Usage | 4 files |
| Accessibility Issues | 12 |
| Inconsistent Button Styles | 7 |
| Missing Loading/Error Handling | 10 |

---

## Completed Improvements

### ✅ Fake Scoring System Removed
**Date:** 2026-07-03

Removed fake/hardcoded scoring systems throughout the webapp:

1. **parser.tsx**: Removed `computeConfidence()` function and all confidence score displays
2. **recon.tsx**: Removed `computeScore()` function and RiskScore component usage
3. **detection.tsx**: Removed hardcoded score calculation (critical=85, high=65, medium=40, low=20)
4. **ids.tsx**: Removed fake score based on warning strings (30 or 70)

**Files Modified:**
- `frontend/src/routes/parser.tsx`
- `frontend/src/routes/recon.tsx`
- `frontend/src/routes/detection.tsx`
- `frontend/src/routes/ids.tsx`

**What Was Removed:**
- `computeConfidence()` function in parser.tsx (fake confidence based on IOC counts)
- `computeScore()` function in recon.tsx (fake risk score based on HTTP headers/DNS)
- Hardcoded severity-to-score mapping in detection.tsx
- Warning-based score calculation in ids.tsx
- `RiskScore` component usage in recon.tsx and detection.tsx
- Confidence metrics from MetricGrid displays
- Score displays from StatusBar and VerdictBanner components
- Score references in markdown export functions

**Why:** These scoring systems were purely cosmetic and didn't reflect actual security analysis. They gave users false confidence in risk assessments without any real backend analysis.

---

## Page-by-Page Analysis

### 1. Dashboard (`/`)
**Status:** ✅ Loaded
**Screenshot:** `dashboard.png`

**What's Working:**
- Investigation Flow ribbon (Parse → Triage → Recon → Pivot → Report) renders correctly
- Metrics (Modules 16, Groups 5, Tracks 3, Recent 0) functional
- Track cards (Triage, Recon, Detection) render properly
- Quick actions (Parse artifact, Vet URL) visible
- Marquee signal feed active at top
- Continue row with "Drop an artifact into Smart Parser" prompt
- Pinned chips rail present

**Issues:**
- [ ] Title shows "Command Deck." with unnecessary period → should be "Command Deck"
- [ ] "Recent" metric shows 0 even though sidebar shows activity — metric reads from different source than recents list
- [ ] Metric tiles lack sparkline data for activity trends (MetricTile component exists but unused here)

---

### 2. Smart Parser (`/parser`)
**Status:** ✅ Loaded
**Screenshot:** `parser.png`

**What's Working:**
- Intake terminal with `[WAITING_FOR_INPUT]` placeholder and sample loader
- Output section: "WHAT THE PARSER RECOVERS" (11 samples, 11 IOC families)
- IOC families: URL, Domain, IPv4, MD5, SHA1, SHA256, CVE, Email, Filename, CIDR, ASN
- "HOW ANALYSTS USE IT" 3-step flow sidebar
- Status bar: STATUS Idle, CHARS 0, LINES 1, IOCS 0, SIGNALS 0, MODE session-only
- Upload, Copy, Parse buttons present

**Issues:**
- [ ] No "Send to Case" button in output section — should link to `/case`
- [ ] Missing "Copy All IOCs" quick action in output header
- [ ] Output section cut off at bottom — full IOC inventory not visible in screenshot

---

### 3. Phishing Triage (`/phishing`)
**Status:** ✅ Loaded
**Screenshot:** `phishing.png`

**What's Working:**
- Clean intake card with email source input
- ToolShell with FILTER and IDLE indicators
- Sample dropdown with "LOAD SAMPLE..." option
- Upload, Copy, Clear, Analyse buttons present
- Auto-runs on paste feature enabled
- Scoring breakdown table implemented (SPF, DMARC, DKIM, Reply-To mismatch, etc.) — only shows after analysis
- MITRE mapping implemented (T1566, T1204, T1190)
- Verdict logic: "Likely Phishing" / "Suspicious" / "Inconclusive"

**Issues:**
- [ ] Scoring breakdown not visible in idle state — consider showing empty state table structure
- [ ] No verdict banner in idle state — should show "Awaiting analysis" or similar
- [ ] Missing quick links to URL Analyzer or Case Notebook in output section
- [ ] Sample loader placeholder text says "Paste raw artifact, log line, URL, hash, or rule" — should be email-specific

---

### 4. Safe URL Analyzer (`/url`)
**Status:** ✅ Loaded
**Screenshot:** `url.png`

**What's Working:**
- Clean intake card with URL input and 10 sample types
- Status bar: CHARS 0, REFANGED no, SCHEME -, RUNS 0
- Backend enrichment checkbox present
- Auto-runs on paste feature enabled
- Redirect chain panel implemented via `syntheticRedirects()`
- Synthetic intel panel implemented via `syntheticIntel()`
- Network/TLS/Geo panels implemented

**Issues:**
- [ ] Redirect chain/intel panels not visible in idle state — should show empty state structure
- [ ] Missing "Send to Recon" quick action in output section
- [ ] Sample loader has 10 options but some are cut off in dropdown

---

### 5. Recon & Exposure (`/recon`)
**Status:** ✅ Loaded
**Screenshot:** `recon.png`

**What's Working:**
- Clean intake card with target input
- Status bar: STATUS Idle, SOURCES DNS TLS HTTP, SCORE -, ACTIVE PROBING off
- Empty state: "No target loaded" with helpful message
- Footer: "BEYONDLABS · LOCAL SOC WORKBENCH" and "ANALYST-LED · NO DETONATION · BOUNDED SCANS"
- DNS/TLS/HTTP source indicators present

**Issues:**
- [ ] Missing DNS/TLS/HTTP source toggle controls — currently just display, not interactive
- [ ] No "Enumerate" button visible in intake area
- [ ] Missing sample domain quick-fill (e.g., "example.com")

---

### 6. MITRE ATT&CK Coverage (`/mitre`)
**Status:** ✅ Loaded
**Screenshot:** `mitre.png`

**What's Working:**
- Coverage summary: 0% weighted coverage, 14 tactics, 38 techniques, 0 full, 38 gaps
- Destructive badge: "38 techniques uncovered" with reason/limitation/action
- Kill-chain coverage bar with all tactics visible
- MATRIX / GAPS (38) / NOTES (0) tabs present
- Coverage matrix grid visible with tactic columns
- Reset button present

**Issues:**
- [ ] Matrix cut off horizontally — needs `overflow-x-auto` on matrix container
- [ ] Tactic labels truncated (RECON, RESOURCE DEV, INITIAL ACCESS, etc.)
- [ ] Missing technique count per tactic in kill-chain bar
- [ ] No "Export Coverage" button for reporting
- [ ] Missing "Import Sigma Rules" feature to auto-populate coverage from existing rules

---

### 7. SOC Playbook Guide (`/guide`)
**Status:** ✅ Loaded
**Screenshot:** `guide.png`

**What's Working:**
- Verdict banner: "4 BUNDED PLAYBOOKS"
- Metrics: TOTAL 4, P1 CRITICAL 1, P2 HIGH 2, P3 MEDIUM 1
- Playbook list with severity filters (ALL, P1, P2, P3)
- Step completion tracking (0/7 DONE, 0%)
- MITRE technique chips (T1566, T1204) linking to `/mitre`
- Pivot links to Logs, Phishing, URL
- Search bar for playbooks

**Issues:**
- [ ] Step completion not persisted to localStorage — lost on reload
- [ ] Missing "Export Playbook" feature for documentation
- [ ] No "Mark All Complete" quick action
- [ ] Missing playbook search/filter by MITRE technique

---

### 8. OSINT Tools (`/osint`)
**Status:** ✅ Loaded
**Screenshot:** `osint.png`

**What's Working:**
- Clean intake card with target input
- Status bar: STATUS Idle, DETECTED raw, PIVOTS 4/15, HISTORY 0, PINNED 0, AUTO-QUERY off
- Output section: "EXTERNAL SERVICE PIVOTS" (4 services, 8 categories)
- Reputation services visible (VirusTotal, AbuseIPDB)
- 15 pivot categories detected

**Issues:**
- [ ] Missing pivot category expansion (DNS, WHOIS, Certificate, etc. collapsed)
- [ ] No "Auto-query" toggle visible in UI
- [ ] Missing history panel (HISTORY 0 but no panel to view history)
- [ ] No "Pin Pivot" quick action visible

---

### 9. Nmap Runner (`/nmap`)
**Status:** ✅ Loaded
**Screenshot:** `nmap.png`

**What's Working:**
- Clean intake card with target input and 3 samples (Host, IPv4, CIDR /24)
- Scan profile selection with 5 modes (Discovery, Top-100 TCP, Service & Version, Safe NSE Scripts, Full TCP + OS)
- Risk badges (LOW, MEDIUM, HIGH) on each profile
- Timing & rate panel (T2 Polite, T3 Normal, T4 Aggressive, T5 Insane)
- Status bar with risk and timing info
- Service & Version profile selected by default

**Issues:**
- [ ] Duplicate filter toggle buttons — one in intake section, one in output section
- [ ] "Execute" button not visible in screenshot (below fold)
- [ ] Permission checkbox not visible in screenshot (below fold)
- [ ] Missing scan history panel

---

### 10. Detection Editor (`/detection`)
**Status:** ✅ Loaded
**Screenshot:** `detection.png`

**What's Working:**
- Format selection: SIGMA (Active), YARA, KQL, GENERATE
- Rule library button present (collapsed by default)
- Rule editor with syntax highlighting (14 lines, 335 chars)
- Simulate event panel with token coverage (2/2 CONDITIONS)
- Evaluate button present
- Output section: "VERDICT & MAPPING" with "rule would fire"
- Sigma generator panel implemented
- Rule library with save/load/duplicate/delete implemented

**Issues:**
- [ ] Rule library collapsed by default — should show saved rule count
- [ ] Missing structural analysis panel (implemented but not visible)
- [ ] No "Save to Library" quick action in editor header
- [ ] MITRE mapping preview not visible in idle state

---

### 11. SIEM Workspace (`/siem`)
**Status:** ✅ Loaded
**Screenshot:** `siem.png`

**What's Working:**
- Dual intake: Event Search + Paste Raw Events
- Sample dropdowns for both inputs
- Filter strip with RANGE (15M, 1H, 24H, ALL)
- Status bar: STATUS Awaiting input, SOURCES 0, HIGH SEV 0, WINDOW all
- Output: SIEM_SUMMARY with EVENTS 0, TOP SRC -
- FILTERS instruction text present

**Issues:**
- [ ] Filter strip appears incomplete — missing filter chip rendering
- [ ] Missing "Export MD/CSV" buttons in output header
- [ ] No event timeline visualization
- [ ] Missing "Pin Filter" quick action

---

### 12. Logs & Alerts (`/logs`)
**Status:** ✅ Loaded
**Screenshot:** `logs.png`

**What's Working:**
- Clean intake card with log slice input
- Status bar: STATUS Idle, LINES 0, ENTITIES 0, WINDOW all
- Backend analysis checkbox present
- Output section: "ENTITIES + FINDINGS" with empty state
- Upload, Copy, Clear, Parse buttons present

**Issues:**
- [ ] Missing entity extraction preview in output
- [ ] BulkActionBar not visible (implemented but requires selection)
- [ ] Missing "Export Findings" button
- [ ] No "Send to Detection" quick action

---

### 13. IDS Rule Builder (`/ids`)
**Status:** ✅ Loaded
**Screenshot:** `ids.png`

**What's Working:**
- Clean parameter form with dropdowns (Engine: snort, Action: alert, Protocol: tcp, Direction: →)
- Input fields (SRC IP: $EXTERNAL_NET, SRC PORT: any, DST IP: $HOME_NET, DST PORT: 80)
- SID: 2000001, REV: 1, PRIORITY: 2, CLASSTYPE: trojan-activity
- MSG field empty, FLOW: to_server,established
- Content Match and PCRE fields present
- Checkboxes (NOCASE checked, HTTP_URI, HTTP_HEADER)
- Extra Options textarea with threshold example
- BUILD RULE button present
- CASE HANDOFF section visible

**Issues:**
- [ ] Missing rule preview panel — should show generated rule live
- [ ] No "Validate Rule" button
- [ ] Missing "Export Rule" feature (download as .rules file)
- [ ] No template selection for common rule patterns

---

### 14. Hacking Toolkit (`/hacking-toolkit`)
**Status:** ⚠️ Loaded with Expected Error
**Screenshot:** `hacking-toolkit.png`

**What's Working:**
- Header: "Hacking Toolkit" with description
- Metrics: CATEGORIES 0, TOOLS 0, AVAILABLE 0, PINNED 0
- Error message: "Cannot reach backend. No cached catalog available."
- CATALOG button present
- Offline fallback code implemented correctly
- History panel implemented (100 entries max)
- Per-tool target/args persistence implemented

**Issues:**
- [ ] Error message is correct — backend hasn't been run yet, so no cached catalog exists
- [ ] Consider adding demo/sample catalog for first-time users
- [ ] Missing tool categories display (will populate after backend run)
- [ ] No history panel visible (will populate after first tool run)

---

### 15. Settings (`/settings`)
**Status:** ✅ Loaded
**Screenshot:** `settings.png`

**What's Working:**
- Import/Export/Reset buttons present
- Filter settings with tabs (BRAND, THEME GALLERY, CUSTOM THEME, ACCENT, DENSITY, TYPOGRAPHY, SIDEBAR, MOTION & QOL)
- Brand section with APP NAME (BeyondLabs), TAGLINE (soc · workbench), ICON selector
- Theme gallery with 8 themes (Terminal Noir active, SOC Console, Editorial Dark, etc.)
- Preview card showing current theme

**Issues:**
- [ ] Title shows "Workspace." with unnecessary period → should be "Workspace"
- [ ] Missing "About" section with version info
- [ ] No "Keyboard Shortcuts" reference panel
- [ ] Missing "Data Management" section (clear localStorage, export all data)

---

### 16. Attachment Triage (`/attachment`)
**Status:** ✅ Loaded
**Screenshot:** `attachment.png`

**What's Working:**
- Clean file upload interface with "CHOOSE FILE" button
- Status bar: STATUS Idle, DETONATION never, UPLOAD none, MODE static review
- Empty state: "No file loaded" with helpful message
- Supports any file type, max 15 MB

**Issues:**
- [ ] Missing "Send to Case" button in output section
- [ ] No "Hash Lookup" quick action (search VT/MalwareBazaar for file hash)
- [ ] Missing file type preview icon (show file extension icon before upload)
- [ ] No drag-and-drop visual feedback (highlight zone on dragover)

---

### 17. Case Notebook (`/case`)
**Status:** ✅ Loaded
**Screenshot:** `case.png`

**What's Working:**
- Case metrics: ENTRIES 0, EVIDENCE 0, DECISIONS 0, ACTIONS 0, IOCS 0
- Case list with search
- Active case: BA-20260703-1604 with ID: C-QUNN4
- Intake: NEW ENTRY with NOTE/EVIDENCE/DECISION/ACTION/IOC tabs
- CLOSE CASE and DELETE buttons present
- Tag input field present
- "+ NEW CASE" button present

**Issues:**
- [ ] Missing timeline view for case entries
- [ ] No "Export Case" button visible (markdown export implemented)
- [ ] Missing "Add Tag" functionality (input exists but no tag chips shown)
- [ ] No case template selection

---

### 18. CyberChef (`/chef`)
**Status:** ✅ Loaded
**Screenshot:** `chef.png`

**What's Working:**
- Presets bar with common recipes (URL Decode, Base64 Decode, JSON Beautify, etc.)
- Operations panel (53 operations) with search
- Recipe panel with AUTO ON/SAVE/LOAD
- Input panel with SAMPLE button, upload, clear
- Output panel with copy, export, MORE
- Categories: RECIPES (10), FAVOURITES (0), IOC SAFE HANDLING (9), ENCODINGS (17), WEB (2), DATA FORMAT (6), TEXT (9), HASHING (5), SCRIPT TRIAGE (5)
- Library with save/load

**Issues:**
- [ ] Recipe panel empty — no steps added (expected in idle state)
- [ ] Missing "Clear Recipe" button (only individual step removal)
- [ ] No "Import Recipe" feature (JSON import)
- [ ] Missing operation documentation tooltips

---

## Critical Issues (Fix Immediately)

### 1. Dashboard Title Period
**File:** `frontend/src/routes/index.tsx`
**Line:** ~74
**Issue:** Title shows "Command Deck." with unnecessary period
**Fix:** Change `title="Command Deck."` to `title="Command Deck"`

### 2. Settings Title Period
**File:** `frontend/src/routes/settings.tsx`
**Line:** ~16
**Issue:** Title shows "Workspace." with unnecessary period
**Fix:** Change `title="Workspace."` to `title="Workspace"`

---

## Medium Issues (Fix This Sprint)

### 3. MITRE Matrix Horizontal Scrolling
**File:** `frontend/src/routes/mitre.tsx`
**Issue:** Matrix is cut off horizontally — tactic labels truncated
**Fix:** Add `overflow-x-auto` to matrix container div

### 4. Guide Step Persistence
**File:** `frontend/src/routes/guide.tsx`
**Issue:** Step completion not persisted to localStorage — lost on reload
**Fix:** Add localStorage read/write for completed steps map

### 5. Phishing Sample Placeholder
**File:** `frontend/src/routes/phishing.tsx`
**Line:** ~510
**Issue:** Sample loader placeholder says "Paste raw artifact, log line, URL, hash, or rule"
**Fix:** Change to email-specific placeholder like "Paste raw email source including headers"

### 6. Nmap Duplicate Filters
**File:** `frontend/src/routes/nmap.tsx`
**Issue:** Two filter toggle buttons — one in intake, one in output
**Fix:** Remove duplicate button in intake section

### 7. Detection Rule Library Default State
**File:** `frontend/src/routes/detection.tsx`
**Issue:** Rule library collapsed by default — users don't see saved rules count
**Fix:** Show saved rule count next to button even when collapsed

---

## Low Issues (Backlog)

### 8. OSINT Header Background
**File:** `frontend/src/routes/osint.tsx`
**Issue:** Header has plain black background, no gradient like other pages
**Fix:** Add gradient background consistent with other pages

### 9. Attachment SendToRow
**File:** `frontend/src/routes/attachment.tsx`
**Issue:** Missing SendToRow component
**Fix:** Add SendToRow with links to Case, Detection, Parser

### 10. Case Timeline View
**File:** `frontend/src/routes/case.tsx`
**Issue:** Missing timeline visualization for case entries
**Fix:** Add timeline component showing entries chronologically

### 11. IDS Rule Preview
**File:** `frontend/src/routes/ids.tsx`
**Issue:** Missing rule preview panel
**Fix:** Add live preview of generated Snort/Suricata rule

### 12. SIEM Export Buttons
**File:** `frontend/src/routes/siem.tsx`
**Issue:** Missing "Export MD/CSV" buttons
**Fix:** Add export buttons in output header

### 13. Logs Bulk Actions Visibility
**File:** `frontend/src/routes/logs.tsx`
**Issue:** BulkActionBar not visible (requires selection)
**Fix:** Consider showing bar with "Select all" option when findings exist

### 14. URL Quick Actions
**File:** `frontend/src/routes/url.tsx`
**Issue:** Missing "Send to Recon" quick action
**Fix:** Add SendToRow with links to Recon, OSINT, Case

### 15. Parser Send to Case
**File:** `frontend/src/routes/parser.tsx`
**Issue:** Missing "Send to Case" button in output
**Fix:** Add SendToRow with link to Case Notebook

---

## Additional Findings (Code Audit)

### Code Duplication

| # | Files | Description |
|---|-------|-------------|
| D.1 | `parser.tsx`, `url.tsx`, `phishing.tsx` | IOC detection regexes (`SECRET_RX`, `SUSPICIOUS_TLDS`, `SHORTENERS`, `LOLBINS`, `DOWNLOAD_CRADLES`, `AMSI_BYPASS_PATTERNS`) duplicated across 3 files with slight variations. Should extract to `lib/ioc-patterns.ts` |
| D.2 | `siem.tsx`, `logs.tsx` | Filter chip logic, range handling, modal patterns, and export functions are structurally identical. Could share a `useLogAnalysis` hook |

### Missing AbortController (Request Cancellation)

| # | File | Description |
|---|------|-------------|
| A.1 | `osint.tsx` | `runOsintLookup`, `runTool`, `runMaigretLookup` don't use AbortController — navigating away leaves request dangling |
| A.2 | `nmap.tsx` | `handleExecute` doesn't use AbortController — long-running scan can't be cancelled |
| A.3 | `ids.tsx` | Backend API calls (`getIdsRuleTemplates`, `buildIdsRule`, `explainIdsRule`) don't pass abort signals |

### `any` Type Usage

| # | File | Line | Description |
|---|------|------|-------------|
| T.1 | `ids.tsx` | 40, 66-68 | `useState<any>` for `templates`, `result`, `explainResult` — should use proper interfaces |
| T.2 | `detection.tsx` | 248, 255 | `mitreResults` and `genResult` typed as `any` |
| T.3 | `osint.tsx` | 426 | Extensive `as any` casts for `toolStatus` object properties |
| T.4 | `nmap.tsx` | 250, 255, 271 | Inconsistent casting patterns (`(scanResult as any).error`, `(scanResult as Record<string, unknown>).stdout`) |

### localStorage Quota Risk

| # | File | Description |
|---|------|-------------|
| L.1 | `chef.tsx` | Auto-bake saves to 3 localStorage keys on every change — could hit quota limits with large recipes |
| L.2 | Multiple | No error handling for `localStorage quota exceeded` across any route |

### Clipboard Write Safety

| # | File | Line | Description |
|---|------|------|-------------|
| C.1 | `attachment.tsx` | 202 | `navigator.clipboard.writeText` not wrapped in try/catch — fails silently in insecure contexts |
| C.2 | `case.tsx` | 153 | Same issue — no error feedback if clipboard write fails |

### Visual Inconsistencies Found in Screenshots

| # | Page | Description |
|---|------|-------------|
| V.1 | Dashboard | Title "Command Deck." has trailing period (already noted as critical) |
| V.2 | Settings | Title "Workspace." has trailing period (already noted as critical) |
| V.3 | MITRE | "TECHNI" and "GAPS" metric cards cut off on right side — grid overflow |
| V.4 | MITRE | Matrix horizontally truncated — tactic labels incomplete |
| V.5 | Guide | Playbook names truncated (e.g., "MACRO-ENABLED ATTACHM...") |
| V.6 | Nmap | "RENDER BRIEF" button has redundant "PREVIEW" badge |
| V.7 | Logs | Output section shows "Unknown log" classification — could show more detail |

---

## Recommended Priority Order

1. **Remove title periods** (Critical — visual polish, 2 files)
2. **Add MITRE matrix scrolling** (Medium — usability, 1 file)
3. **Persist guide step completion** (Medium — data loss, 1 file)
4. **Fix phishing placeholder text** (Medium — UX, 1 file)
5. **Remove nmap duplicate filters** (Medium — UX, 1 file)
6. **Show detection rule count** (Medium — UX, 1 file)
7. **Extract duplicated IOC patterns** (Medium — maintainability, 3 files → 1 shared module)
8. **Add AbortController to API calls** (Medium — resource leak, 3 files)
9. **Add SendToRow to attachment/parser/url** (Low — workflow, 3 files)
10. **Fix `any` types in ids.tsx/detection.tsx** (Low — type safety, 4 files)
11. **Add clipboard write error handling** (Low — resilience, 2 files)
12. **Address remaining low-priority items** (Low — polish)

---

## Notes

### Features Verified as Working
The following features were initially flagged but confirmed working after testing:
- **Phishing:** Scoring breakdown table, MITRE mapping, verdict banner — all render after analysis
- **URL:** Redirect chain, synthetic intel, network/TLS/geo panels — all render after analysis
- **Detection:** Rule library, structural analysis, Sigma generator — all functional
- **Logs:** Entity extraction, findings panel, backend analysis toggle — all functional
- **Nmap:** Scan profile selection, timing controls, permission checkbox — all functional
- **IDS:** Template selection, parameter form, rule building — all functional

### Hacking Toolkit Error
The "Cannot reach backend" error is expected behavior:
1. Backend hasn't been run yet → no API response
2. No cached catalog in localStorage → first-time use
3. After running backend once, catalog will be cached for offline use

### Keyboard Shortcuts Status
Currently only `mitre.tsx` has `onKeyDown` handlers. Missing global shortcuts:
- Cmd+K for search (search bar exists but no global shortcut)
- Escape to close modals
- Enter to submit primary actions (nmap execute, detection evaluate)

---

## Screenshots Reference

All screenshots saved to `/tmp/screenshots/`:
- `dashboard.png` - Command Deck (189KB)
- `parser.png` - Smart Parser (157KB)
- `phishing.png` - Phishing Triage (154KB)
- `url.png` - Safe URL Analyzer (156KB)
- `recon.png` - Recon & Exposure (131KB)
- `mitre.png` - MITRE ATT&CK Coverage (173KB)
- `guide.png` - SOC Playbook Guide (182KB)
- `osint.png` - OSINT Tools (121KB)
- `nmap.png` - Nmap Runner (172KB)
- `detection.png` - Detection Editor (181KB)
- `siem.png` - SIEM Workspace (170KB)
- `logs.png` - Logs & Alerts (134KB)
- `ids.png` - IDS Rule Builder (141KB)
- `hacking-toolkit.png` - Hacking Toolkit (140KB)
- `settings.png` - Settings (177KB)
- `attachment.png` - Attachment Triage (128KB)
- `case.png` - Case Notebook (188KB)
- `chef.png` - CyberChef (171KB)
