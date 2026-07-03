<div align="center">

# BeyondArch

**Local-First SOC Analyst Workbench**

Artifact triage · Phishing review · SIEM log analysis · Detection engineering
— all local-first, privacy-preserving, and analyst-led.

[![React](https://img.shields.io/badge/React-20232A?style=for-the-badge&logo=react&logoColor=61DAFB)](https://react.dev)
[![Vite](https://img.shields.io/badge/Vite-646CFF?style=for-the-badge&logo=vite&logoColor=fff)](https://vite.dev)
[![FastAPI](https://img.shields.io/badge/FastAPI-009688?style=for-the-badge&logo=fastapi&logoColor=fff)](https://fastapi.tiangolo.com)
[![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=fff)](https://python.org)
[![TypeScript](https://img.shields.io/badge/TypeScript-3178C6?style=for-the-badge&logo=typescript&logoColor=fff)](https://typescriptlang.org)
[![License: MIT](https://img.shields.io/badge/license-MIT-8B0000?style=for-the-badge&labelColor=000000)](LICENSE)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-8B0000?style=for-the-badge&labelColor=000000)](CONTRIBUTING.md)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-000000?style=for-the-badge&logo=linux&logoColor=eeeeee)]()

**[Quick Start](#quick-start)** &nbsp;·&nbsp; **[Features](#features)** &nbsp;·&nbsp; **[Architecture](#investigation-flow)** &nbsp;·&nbsp; **[Safety Model](#safety-model)** &nbsp;·&nbsp; **[Contributing](CONTRIBUTING.md)**

</div>

<br>

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Settings & Customization](#settings--customization)
- [Investigation Flow](#investigation-flow)
- [Quick Start](#quick-start)
- [Safety Model](#safety-model)
- [Storage](#storage)
- [Repo Layout](#repo-layout)
- [Health Checks](#health-checks)
- [Demo Workflow](#demo-workflow)
- [Development](#development)
- [Host Dependencies](#host-dependencies)
- [Known Limitations](#known-limitations)
- [Release Checklist](#release-checklist)

---

## Overview

BeyondArch is a **local-first** workbench for defensive analysts. It handles artifact intake, phishing triage, SIEM log review, and detection engineering — end to end, on your own machine, with nothing shipped off to a third party. It runs on **Linux**, **macOS**, and **Windows**.

Every signal it surfaces is meant to be **honest and local**, never fabricated — see [Safety Model](#safety-model) for the specifics.

---

## Features

### Triage & Analysis
| Capability | What it does |
|-----------|-------------|
| **Artifact Intake** | Paste hashes, IPs, URLs, emails — auto-extract IOCs with defang/refang |
| **Phishing Triage** | Analyse email headers, auth (SPF/DKIM/DMARC), URLs, and body signals |
| **Safe URL Analysis** | Static URL dissection — scheme, host, path, params, TLD scoring |
| **Attachment Triage** | Static metadata extraction for common document formats |

### SIEM, Detection & Alerts
| Capability | What it does |
|-----------|-------------|
| **SIEM Workspace** | Paste syslog/JSONL/CSV event streams with filter, pivot, and export |
| **Logs & Alerts** | Parse auth logs, web access logs, IDS alerts, firewall logs |
| **Detection Engineering** | Build Suricata/Snort/Sigma/YARA/KQL rules from templates with lint + explain |
| **MITRE ATT&CK** | Interactive coverage matrix with localStorage persistence |
| **IDS Alerts** | Parse, categorize, and investigate IDS/IPS alert feeds |

### Recon & Toolkit
| Capability | What it does |
|-----------|-------------|
| **Recon & OSINT** | Bounded DNS/whois/nmap workflows for authorized targets |
| **Nmap Runner** | Interactive nmap scan interface with preset profiles and output parsing |
| **Hacking Toolkit** | Curated tool catalog (nmap, metasploit, hashcat, sqlmap, etc.) with preset args and run history |
| **CyberChef / Chef** | Encoding, decoding, hashing, compression, string manipulation |

### Reference & Reporting
| Capability | What it does |
|-----------|-------------|
| **SOC Guide** | Command reference, event ID lookup, detection patterns |
| **Case & Report** | Timeline + analyst notes + markdown report export with handoff chain |

### Workspace
| Capability | What it does |
|-----------|-------------|
| **Settings** | Full workspace customization — see [below](#settings--customization) |

---

## Settings & Customization

| Feature | Details |
|---------|---------|
| **Theme Gallery** | 7 themes: Aurora Tactical, Terminal Noir, SOC Console, Editorial Dark, Solar Flare, Brutalist Light, Custom |
| **Custom Theme Builder** | Tweak every color token — background, foreground, card, border, accent, surface — with live preview |
| **Accent Presets** | 16+ accent colors across amber, cyan, emerald, fuchsia, indigo, lime, pink, rose, sky, violet, etc. |
| **Typography** | 12+ mono/UI font pairs — JetBrains Mono, Space Grotesk, Inter, Outfit, Geist, IBM Plex Mono, Fira Code, DM Sans, Manrope, Plus Jakarta Sans, Sora, Source Code Pro, Space Mono |
| **Density Control** | Comfortable, Compact, or Ultra-compact spacing |
| **Sidebar** | Pin/unpin workspaces, reorder groups, hide workspaces |
| **Motion & QoL** | Status bar toggle, scroll indicators, copy button visibility |
| **Storage & Backup** | Session-only / Persist / None modes; JSON export/import |

---

## Investigation Flow

```
                    ┌───────────────────────┐
                    │   Artifact Intake     │
                    │ (hash, URL, email,    │
                    │  IP, log line, file)  │
                    └──────────┬────────────┘
                               │
                    ┌──────────▼────────────┐
                    │   Triage Workspace    │
                    │ Phishing · URL · Att. │
                    └──────────┬────────────┘
                               │
                    ┌──────────▼────────────┐
                    │   SIEM + Log Review   │
                    │ Filter · Pivot ·      │
                    │ Detection Matching    │
                    └──────────┬────────────┘
                               │
                    ┌──────────▼────────────┐
                    │  Detection & MITRE    │
                    │ Rule Building ·       │
                    │ Coverage Mapping      │
                    └──────────┬────────────┘
                               │
                    ┌──────────▼────────────┐
                    │   Case & Report       │
                    │ Timeline · Notes ·    │
                    │ Markdown Export       │
                    └───────────────────────┘
```

Every workspace connects through **`beyondarch.pendingArtifact`** — a localStorage handoff channel. Send findings between pages without losing context.

---

## Quick Start

Requires **Python 3.10+**, **Node.js 18+**, and **npm**.

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

### Linux / macOS

The setup detects your package manager automatically — `pacman` (Arch), `apt` (Debian/Ubuntu), `dnf` (Fedora), or `brew` (macOS).

```bash
./install.sh
./run.sh
```

### Windows

```powershell
.\install.ps1
.\run.ps1
```

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
| Recommended SOC | `nmap`, `whatweb`, `subfinder`, `amass`, `httpx` |
| Optional OSINT | `theHarvester`, `assetfinder`, `waybackurls`, `gau`, `katana` |
| Advanced (opt-in) | `nuclei`, `ffuf`, `gobuster` |

Plain `./install.sh` walks through a guided profile. Optional tools are never installed without confirmation. On Linux, `pacman`/`apt`/`dnf` is detected automatically; on macOS, `brew` is used. Systems without a supported package manager print manual guidance instead of failing. On Windows, use the PowerShell scripts.

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
