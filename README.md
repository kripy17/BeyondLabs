<div align="center">

# BeyondArch

**Local-first SOC Analyst Workbench**

[![React](https://img.shields.io/badge/React-20232A?logo=react&logoColor=61DAFB)](https://react.dev)
[![Vite](https://img.shields.io/badge/Vite-646CFF?logo=vite&logoColor=fff)](https://vite.dev)
[![FastAPI](https://img.shields.io/badge/FastAPI-009688?logo=fastapi&logoColor=fff)](https://fastapi.tiangolo.com)
[![Python](https://img.shields.io/badge/Python-3776AB?logo=python&logoColor=fff)](https://python.org)
[![TypeScript](https://img.shields.io/badge/TypeScript-3178C6?logo=typescript&logoColor=fff)](https://typescriptlang.org)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![PRs](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

---

Artifact triage. Phishing review. SIEM log analysis. Detection engineering.
All **local-first**, **privacy-preserving**, and **analyst-led**.

</div>

---

## Features

| Capability | What it does |
|-----------|-------------|
| **Artifact Intake** | Paste hashes, IPs, URLs, emails — auto-extract IOCs with defang/refang |
| **Phishing Triage** | Analyse email headers, auth (SPF/DKIM/DMARC), URLs, and body signals |
| **Safe URL Analysis** | Static URL dissection — scheme, host, path, params, TLD scoring |
| **Attachment Triage** | Static metadata extraction for common document formats |
| **SIEM Workspace** | Paste syslog/JSONL/CSV event streams with filter, pivot, and export |
| **Logs & Alerts** | Parse auth logs, web access logs, IDS alerts, firewall logs |
| **Detection Engineering** | Build Suricata/Snort rules from templates with lint + explain |
| **MITRE ATT&CK** | Interactive coverage matrix with localStorage persistence |
| **SOC Guide** | Command reference, event ID lookup, detection patterns |
| **Recon & OSINT** | Bounded DNS/whois/nmap workflows for authorized targets |
| **CyberChef / Chef** | Encoding, decoding, hashing, compression, string manipulation |
| **Case & Report** | Timeline + analyst notes + markdown report export with handoff chain |

---

## Quick Start

```bash
./install.sh
./run.sh
```

| URL | Service |
|-----|---------|
| http://127.0.0.1:5173 | Frontend (React + Vite) |
| http://127.0.0.1:8000 | Backend API (FastAPI) |
| http://127.0.0.1:8000/docs | Interactive API docs |

Recommended SOC profile:

```bash
./install.sh --profile recommended
```

### Windows

```powershell
.\install.ps1
.\run.ps1
```

---

## Investigation Flow

```text
                    ┌──────────────────────┐
                    │   Artifact Intake     │
                    │ (hash, URL, email,    │
                    │  IP, log line, file)  │
                    └──────────┬───────────┘
                               │
                    ┌──────────▼───────────┐
                    │   Triage Workspace   │
                    │ Phishing · URL · Att.│
                    └──────────┬───────────┘
                               │
                    ┌──────────▼───────────┐
                    │   SIEM + Log Review  │
                    │ Filter · Pivot ·     │
                    │ Detection Matching   │
                    └──────────┬───────────┘
                               │
                    ┌──────────▼───────────┐
                    │ Detection & MITRE    │
                    │ Rule Building ·      │
                    │ Coverage Mapping     │
                    └──────────┬───────────┘
                               │
                    ┌──────────▼───────────┐
                    │ Case & Report        │
                    │ Timeline · Notes ·   │
                    │ Markdown Export      │
                    └──────────────────────┘
```

Every workspace connects through **`beyondarch.pendingArtifact`** — a localStorage handoff channel. Send findings between pages without losing context.

---

## Safety Model

BeyondArch is designed for defensive analysts who need **honest, local signals** — not fabricated threat intelligence.

- No malware execution or attachment detonation
- No phishing sending, credential capture, or brute force automation
- Safe URL workflows default to **static review**
- External enrichment is **opt-in** — providers show limitations when unavailable
- Recon and scan tools require explicit confirmation and are bounded to authorized targets
- Browser storage is workspace state, not a secure evidence vault

---

## Storage

| Mode | Behaviour |
|------|-----------|
| **Session only** (default) | Cleared when browser closes |
| **Persist** | Restored across browser restarts |
| **None** | No analysis data stored at all |

Change persistence via **Settings → Storage & Backup**. Export/import JSON case backups there too.

---

## Repo Layout

```
backend/                  FastAPI app — routers, services, SOC analysis engine
frontend/                 React + Vite app — components, pages, lib
├── src/components/       Shared shell, workspace, and UI components
├── src/pages/            Routed workspace pages
├── src/lib/              Analysis engines, stores, routing, local knowledge
├── src/api/              Backend API client layer
scripts/                  Terminal helpers, project checks
install.sh                Linux/macOS setup wizard
run.sh                    Default launcher (backend + frontend)
doctor.sh                 Health checker
reset-workspace.sh        Safe local cache cleanup
demo-workflow.sh          Guided demo path
install.ps1               Windows PowerShell installer
```

---

## Health Checks

```bash
./doctor.sh
```

Runs syntax checks, backend compile, frontend lint/build, and pytest where available.

---

## Demo Workflow

```bash
./demo-workflow.sh
```

Quick demo route:

```
Artifact Intake → Phishing Triage → Safe URL Analyzer → Logs & Alerts → Detection Workspace → Case & Report
```

Use any sample button across pages to kickstart a walkthrough.

---

## Development

```bash
# Backend
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload

# Frontend (separate terminal)
cd frontend
npm ci --include=dev
npm run dev
```

Frontend checks:
```bash
npm run lint
npm run build
```

Backend checks:
```bash
python -m compileall app
```

---

## Host Dependencies

| Category | Tools |
|----------|-------|
| Core | `curl`, `openssl`, `file`, `strings`/`binutils`, `jq`, Python `pip`/`venv` |
| DNS/domain | `dig`/`nslookup`, `whois`, `traceroute`, `mtr` |
| Recommended SOC | `nmap`, `whatweb`, `subfinder`, `amass`, `httpx`/`httpx-toolkit` |
| Optional OSINT | `theHarvester`, `assetfinder`, `waybackurls`, `gau`, `katana` |
| Advanced (opt-in) | `nuclei`, `ffuf`, `gobuster` |

Plain `./install.sh` walks through a guided profile. Optional tools are never installed without confirmation. On non-pacman systems, BeyondArch prints manual guidance instead of failing.

---

## Known Limitations

- BeyondArch provides **local/static triage signals**, not absolute threat intelligence verdicts
- External reputation providers are not faked; unavailable sources show limitations inline
- Browser storage is convenient workspace state, not a forensics-grade evidence vault
- Active scanning must only be used against owned, lab, or explicitly authorised targets
- Some frontend pages are intentionally monolithic for stability — plan to split when patterns stabilise

---

## Release Checklist

```bash
./doctor.sh
git status --short
```

Confirm:
- No generated dependency/build/cache folders are tracked
- Screenshots are committed or the README intentionally omits them
- README commands match actual scripts
- Optional helper warnings are documented and non-fatal
- Storage/privacy behaviour matches the documented model
- Demo flow works end-to-end: Intake → Analysis → Send to Case → Export

---

<div align="center">

Built for analysts who need **local control** over their investigation workflow.

[Report Bug](../../issues) · [Request Feature](../../issues) · [Contributing](CONTRIBUTING.md)

</div>
