<div align="center">

# BeyondArch

### Local-first SOC Analyst Workbench

React + Vite frontend, FastAPI backend, privacy-aware browser investigation state, and explicit local helper tools for defensive analysis.

</div>

---

## Overview

BeyondArch is a local SOC workbench for artifact intake, phishing review, safe URL analysis, static attachment triage, recon notes, SIEM-style log review, detection engineering, MITRE mapping, SOC reference, CyberChef-style transforms, and case/report handoff.

Recommended investigation flow:

```text
Artifact Intake -> Phishing / URL / Recon / Logs -> Timeline + Notes + Findings -> Case Report Export
```

Core modules:

| Area | Workspaces |
| --- | --- |
| Triage | Artifact Intake, Phishing Triage, Safe URL Analyzer, Attachment Triage |
| Recon | Recon & Exposure, OSINT Tools, Nmap Runner |
| SIEM | SIEM Workspace, Logs & Alerts |
| Tools | CyberChef / Utilities |
| Detection | Detection & MITRE, Detection Workspace, SOC Guide, Case & Report |

## Safety Model

BeyondArch is local-first and analyst-led.

- No malware execution or attachment detonation.
- No phishing sending, credential capture, brute force, exploit automation, or unbounded scanning.
- Safe URL workflows default to static review.
- Recon and scan helpers are explicit, bounded, and intended only for owned, lab, or authorized targets.
- External reputation is not faked. If a provider is unavailable, the UI should say so.
- Browser storage is convenient workspace state, not a secure evidence vault.

## Investigation Data Storage

BeyondArch includes an investigation persistence setting:

```text
Do not store analyzed data
Store during current browser session only
Store locally and restore after browser restart
```

Default: **session only**. Use **Settings -> Storage & Backup** to change persistence, clear investigation data, or export/import a JSON case backup.

## Install And Run

Linux/macOS:

```bash
./install.sh
./run.sh
```

Recommended SOC helper profile:

```bash
./install.sh --profile recommended
```

Windows PowerShell:

```powershell
.\install.ps1
.\run.ps1
```

Default URLs:

```text
Frontend: http://127.0.0.1:5173
Backend:  http://127.0.0.1:8000
API Docs: http://127.0.0.1:8000/docs
```

Normally `./install.sh` sets script permissions automatically. If needed:

```bash
chmod +x install.sh run.sh doctor.sh reset-workspace.sh demo-workflow.sh scripts/*.sh
```

If PowerShell blocks scripts, run PowerShell as your user and use:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

## Troubleshooting

### `uvicorn: command not found`

Run the installer or recreate the backend virtual environment:

```bash
cd backend
rm -rf .venv
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cd ..
./run.sh
```

`run.sh` starts both the backend and frontend together.

### Copied project folder fails to run

Do not copy dependency folders between paths. Recreate them in the copied folder:

```bash
cd backend && rm -rf .venv && python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt
cd ../frontend && rm -rf node_modules && npm ci --include=dev
```

### Frontend build issues after copy

Remove copied dependencies and reinstall:

```bash
cd frontend
rm -rf node_modules dist
npm ci --include=dev
npm run build
```

## Health Checks

```bash
./doctor.sh
./scripts/check.sh
```

Windows:

```powershell
.\doctor.ps1
```

`scripts/check.sh` runs available syntax checks, backend compile, frontend lint/build, pytest when configured and available, and Playwright smoke tests when frontend dependencies are installed.

## Optional Helper Tools

The OSINT page, installer, doctor, and README use the same helper categories:

| Category | Tools |
| --- | --- |
| Core helpers | `curl`, `openssl`, `file`, `strings`/`binutils`, `jq`, Python `pip`/`venv` |
| DNS/domain metadata | `dig`/`nslookup`, `whois`, `traceroute`, `mtr` |
| Recommended SOC/recon helpers | `nmap`, `whatweb`, `subfinder`, `amass`, `httpx`/`httpx-toolkit` |
| Manual/optional OSINT helpers | `theHarvester`, `assetfinder`, `waybackurls`, `gau`, `katana` |
| Advanced active tools | `nuclei`, `ffuf`, `gobuster` |

Plain `./install.sh` includes a guided profile menu. Optional system tools are not installed without confirmation. Advanced active tools are skipped unless separately confirmed. On non-pacman systems, BeyondArch prints manual guidance instead of failing.

## Demo Workflow

Print a guided local SOC demo path:

```bash
./demo-workflow.sh
```

Suggested demo route:

```text
Artifact Intake -> Phishing Triage -> Safe URL Analyzer -> Logs & Alerts -> Detection Workspace -> Case & Report
```

Quick samples are available through page sample buttons, or paste a suspicious email/URL/log line into Artifact Intake.

## Manual Development

Backend:

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m uvicorn app.main:app --reload
```

Frontend:

```bash
cd frontend
npm ci --include=dev
npm run dev
```

## Repository Layout

```text
backend/                  FastAPI app and tests
frontend/                 React + Vite app and Playwright smoke tests
frontend/src/components/  Shared shell, home, investigation, URL, recon, and IDS components
frontend/src/pages/       Routed workspaces
frontend/src/lib/         Analysis engines, stores, routing, and local knowledge
scripts/                  Shared terminal helpers and project check runner
install.sh                Linux/macOS setup wizard
run.sh                    Linux/macOS default launcher (backend + frontend)
doctor.sh                 Linux/macOS health checker
reset-workspace.sh        safe local cache cleanup
demo-workflow.sh          guided demo path
uninstall.ps1             Windows uninstaller (PowerShell)
```

## Known Limitations

- BeyondArch provides local/static triage signals, not absolute threat intelligence verdicts.
- External reputation providers are not faked; unavailable sources are shown as limitations.
- Browser storage is not a forensics-grade evidence vault.
- Active scanning must only be used against owned, lab, or explicitly authorized targets.
- Some large frontend pages are intentionally left monolithic for stability and can be split later.

## Release Checklist

Before a checkpoint or GitHub release:

```bash
./scripts/check.sh
git status --short
```

Confirm:

- no generated dependency/build/cache folders are tracked
- screenshots have been added to the repository or the README intentionally omits them
- README commands match actual scripts
- optional helper warnings are documented and non-fatal
- storage/privacy behavior has been manually checked
- demo flow works end-to-end: Intake -> analysis -> Send to case -> report export
