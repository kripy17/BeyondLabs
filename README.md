<div align="center">
  <img src=".github/assets/banner.svg" alt="BeyondArch" width="100%">
</div>

<div align="center">

<p>
Artifact triage · Phishing review · SIEM log analysis · Detection engineering<br>
all local-first, privacy-preserving, and analyst-led.
</p>

[![React](https://img.shields.io/badge/React-20232A?style=for-the-badge&logo=react&logoColor=61DAFB)](https://react.dev)
[![Vite](https://img.shields.io/badge/Vite-646CFF?style=for-the-badge&logo=vite&logoColor=fff)](https://vite.dev)
[![FastAPI](https://img.shields.io/badge/FastAPI-009688?style=for-the-badge&logo=fastapi&logoColor=fff)](https://fastapi.tiangolo.com)
[![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=fff)](https://python.org)
[![TypeScript](https://img.shields.io/badge/TypeScript-3178C6?style=for-the-badge&logo=typescript&logoColor=fff)](https://typescriptlang.org)

[![License: MIT](https://img.shields.io/badge/license-MIT-8B0000?style=for-the-badge&labelColor=000000)](LICENSE)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-8B0000?style=for-the-badge&labelColor=000000)](CONTRIBUTING.md)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-000000?style=for-the-badge&logo=linux&logoColor=eeeeee)]()

**[Quick Start](#quick-start)** · **[Features](#features)** · **[Architecture](#investigation-flow)** · **[Safety Model](#safety-model)** · **[Contributing](CONTRIBUTING.md)**

</div>

---

## Table of Contents

- [Overview](#overview)
- [Screenshots](#screenshots)
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
- [FAQ](#faq)
- [Release Checklist](#release-checklist)

---

## Overview

BeyondArch is a local-first workbench for defensive analysts. It handles artifact intake, phishing triage, SIEM log review, and detection engineering — end to end, on your own machine, with nothing shipped off to a third party. It runs on Linux, macOS, and Windows.

Most SOC practice tooling means either standing up a full lab or pasting artifacts into someone else's cloud dashboard. BeyondArch skips both: every workspace runs against your own machine, and nothing leaves it unless you explicitly turn on external enrichment.

| | |
|---|---|
| **Frontend** | React + Vite |
| **Backend** | FastAPI (Python) |
| **Platforms** | Linux · macOS · Windows |
| **Storage** | Local browser only — session / persist / none |
| **License** | MIT |

---

## Screenshots

<table>
<tr>
<td align="center" width="50%">
<img src=".github/assets/screenshot-placeholder.svg" width="100%"/><br/>
<sub><b>Artifact Intake</b> — IOC extraction with defang/refang</sub>
</td>
<td align="center" width="50%">
<img src=".github/assets/screenshot-placeholder.svg" width="100%"/><br/>
<sub><b>SIEM Workspace</b> — filter, pivot & export</sub>
</td>
</tr>
<tr>
<td align="center" width="50%">
<img src=".github/assets/screenshot-placeholder.svg" width="100%"/><br/>
<sub><b>Detection Engineering</b> — rule builder with lint & explain</sub>
</td>
<td align="center" width="50%">
<img src=".github/assets/screenshot-placeholder.svg" width="100%"/><br/>
<sub><b>Case & Report</b> — timeline, notes & markdown export</sub>
</td>
</tr>
</table>

<sub>Placeholders — swap the files in `.github/assets/` once real captures are ready.</sub>

---

## Features

16 workspaces across 5 categories. Drop into any one on its own, or run the full pipeline end to end.

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

```mermaid
%%{init: {'theme':'base', 'themeVariables': {
  'primaryColor':'#180000',
  'primaryBorderColor':'#7a1f1f',
  'primaryTextColor':'#f0f0f0',
  'lineColor':'#7a1f1f',
  'fontFamily':'JetBrains Mono, Fira Code, monospace',
  'fontSize':'13px'
}}}%%
flowchart TD
    A["Artifact Intake<br/>hash · URL · email · IP · log · file"] --> B["Triage Workspace<br/>Phishing · URL · Attachment"]
    B --> C["SIEM + Log Review<br/>Filter · Pivot · Detection Matching"]
    C --> D["Detection & MITRE<br/>Rule Building · Coverage Mapping"]
    D --> E["Case & Report<br/>Timeline · Notes · Markdown Export"]
```

Every workspace connects through `beyondarch.pendingArtifact` — a localStorage handoff channel. Send findings between pages without losing context.

### System Architecture

```mermaid
%%{init: {'theme':'base', 'themeVariables': {
  'primaryColor':'#180000',
  'primaryBorderColor':'#7a1f1f',
  'primaryTextColor':'#f0f0f0',
  'lineColor':'#7a1f1f',
  'fontFamily':'JetBrains Mono, Fira Code, monospace',
  'fontSize':'13px'
}}}%%
flowchart LR
    subgraph Browser["Frontend — React + Vite"]
        UI["Workspace UI"]
        LS[("localStorage<br/>session / persist / none")]
    end
    subgraph Server["Backend — FastAPI"]
        API["REST API"]
        ENGINE["SOC Analysis Engine"]
    end
    EXT[("External Enrichment<br/>opt-in only")]

    UI <--> API
    UI <--> LS
    API <--> ENGINE
    UI -.optional.-> EXT
```

Frontend and backend talk over a local REST API. Nothing leaves the machine unless external enrichment is explicitly turned on.

---

## Quick Start

Requires Python 3.10+, Node.js 18+, and npm.

```bash
./install.sh
./run.sh
```

| URL | Service |
|-----|---------|
| http://127.0.0.1:5173 | Frontend (React + Vite) |
| http://127.0.0.1:8000 | Backend API (FastAPI) |
| http://127.0.0.1:8000/docs | Interactive API docs |

Recommended SOC profile — pulls in the full toolkit (`nmap`, `whatweb`, `subfinder`, `amass`, `httpx`) in one step:

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

> [!WARNING]
> Recon and scanning tools require explicit confirmation and must only be run against owned, lab, or explicitly authorized targets.

BeyondArch is designed for defensive analysts who need honest, local signals — not fabricated threat intelligence.

- No malware execution or attachment detonation
- No phishing sending, credential capture, or brute force automation
- Safe URL workflows default to static review
- External enrichment is opt-in — providers show limitations when unavailable
- Browser storage is workspace state, not a secure evidence vault

---

## Storage

| Mode | Behaviour |
|------|-----------|
| **Session only** (default) | Cleared when browser closes |
| **Persist** | Restored across browser restarts |
| **None** | No analysis data stored at all |

Change persistence via Settings → Storage & Backup. Export/import JSON case backups there too.

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

<details>
<summary>Backend & frontend setup commands</summary>

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

</details>

---

## Host Dependencies

<details>
<summary>Full tool list by category</summary>

| Category | Tools |
|----------|-------|
| Core | `curl`, `openssl`, `file`, `strings`/`binutils`, `jq`, Python `pip`/`venv` |
| DNS/domain | `dig`/`nslookup`, `whois`, `traceroute`, `mtr` |
| Recommended SOC | `nmap`, `whatweb`, `subfinder`, `amass`, `httpx` |
| Optional OSINT | `theHarvester`, `assetfinder`, `waybackurls`, `gau`, `katana` |
| Advanced (opt-in) | `nuclei`, `ffuf`, `gobuster` |

Plain `./install.sh` walks through a guided profile. Optional tools are never installed without confirmation. On Linux, `pacman`/`apt`/`dnf` is detected automatically; on macOS, `brew` is used. Systems without a supported package manager print manual guidance instead of failing. On Windows, use the PowerShell scripts.

</details>

---

## Known Limitations

- BeyondArch provides local/static triage signals, not absolute threat intelligence verdicts
- External reputation providers are not faked; unavailable sources show limitations inline
- Browser storage is convenient workspace state, not a forensics-grade evidence vault
- Active scanning must only be used against owned, lab, or explicitly authorised targets
- Some frontend pages are intentionally monolithic for stability — plan to split when patterns stabilise

---

## FAQ

**Does BeyondArch send my data anywhere?**
No. Analysis runs in your browser and your local FastAPI backend. The only exception is external enrichment, which is opt-in and off by default.

**What platforms are supported?**
Linux, macOS, and Windows — `install.sh`/`run.sh` on Linux/macOS, `install.ps1`/`run.ps1` on Windows.

**Is browser storage safe to use as an evidence store?**
No. It's convenient workspace state, not a forensics-grade evidence vault. Use Settings → Storage & Backup to export case data as JSON if you need to keep it.

**Can I point the recon and scanning tools at any target?**
No. They require explicit confirmation before running and are bounded to owned, lab, or explicitly authorized targets.

**What if I don't want anything persisted at all?**
Set Storage mode to None in Settings — no analysis data is stored.

---

## Release Checklist

<details>
<summary>Pre-release commands & checklist</summary>

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

</details>

---

<div align="center">

Built for analysts who need local control over their investigation workflow.

[Report Bug](../../issues) · [Request Feature](../../issues) · [Contributing](CONTRIBUTING.md)

</div>
