# Repository Guidelines

## Project Overview

BeyondArch is a local-first SOC analyst workbench for artifact triage, phishing review, safe URL analysis, static attachment triage, recon notes, SIEM-style log review, detection engineering, MITRE mapping, IDS rule drafting, SOC command/event reference, and local case timelines.

Tech stack:
- Frontend: React + Vite
- Backend: FastAPI
- Storage: browser `localStorage` for lightweight workspace state
- Target environment: Linux / Arch-friendly local development

Keep BeyondArch separate from ArchLabs. BeyondArch is the serious analyst toolkit; practice/lab generation belongs in ArchLabs unless explicitly requested.

## Non-Negotiable Safety Rules

- Do not fake threat-intelligence, malware, scan, API, or reputation results.
- Do not execute uploaded files, malware, scripts, macros, or attachments.
- Do not add phishing sending, credential capture, brute force, exploit automation, spoofing, or unbounded scanning.
- Safe URL workflows must default to static review; guarded metadata checks must be explicit.
- Attachment triage must remain static-only.
- Network/scanning helpers must be bounded and clearly intended for owned, lab, or authorized targets.
- Do not hardcode secrets, API keys, tokens, or sensitive indicators.
- Do not automatically send private indicators to third-party services.

## UI/Workflow Direction

- Keep the dark SOC-console visual language consistent across pages.
- Prefer compact layouts: input/editor on the left, controls/actions on the right when possible.
- Collapse samples, raw details, verbose scoring, and advanced sections by default.
- Use practical analyst wording: evidence, limitations, next action, false-positive risk, tuning notes.
- Keep handoff actions connected through `beyondarch.pendingArtifact` and the Case Timeline.

## Project Structure

- `frontend/src/App.jsx` owns the app shell, route state, and navigation.
- `frontend/src/pages/` contains page-level React views.
- `frontend/src/components/` contains reusable UI/workflow components.
- `frontend/src/lib/` contains shared helpers and local workflow engines.
- `frontend/src/api/backend.js` centralizes API calls.
- `backend/app/main.py` creates the FastAPI app.
- `backend/app/routers/` contains route modules.
- `backend/app/services/` contains service logic.

## Development Commands

Root scripts:
- `./install.sh` installs frontend/backend dependencies.
- `./run-beyondarch.zsh` starts backend and frontend together.
- `./doctor.sh` checks project health.
- `./reset-workspace.sh` removes generated local runtime files.
- `./demo-workflow.sh` prints a short demo path.

Frontend:
- `cd frontend && npm install`
- `npm run dev`
- `npm run lint`
- `npm run build`

Backend:
- `cd backend`
- `python3 -m venv .venv`
- `source .venv/bin/activate`
- `pip install -r requirements.txt`
- `uvicorn app.main:app --reload`

## Codex / Agent Protocol

When using Codex or another coding agent:
1. Read this file and `README.md` first.
2. Inspect the current implementation before editing.
3. Keep changes scoped and avoid unrelated redesigns.
4. Run relevant checks before completion.
5. Summarize changed files, commands run, validation result, and limitations.

## Commit / PR Guidance

Use focused commits such as:
- `feat: add timeline handoff to phishing triage`
- `fix: preserve safe-url analyzer route handoff`
- `ui: compact SIEM intake controls`
- `docs: update README safety model`

Pull requests should include:
- summary
- screenshots for visible UI changes
- validation commands
- known limitations
- safety impact, if any

## graphify

This project has a knowledge graph at graphify-out/ with god nodes, community structure, and cross-file relationships.

When the user types `/graphify`, invoke the `skill` tool with `skill: "graphify"` before doing anything else.

Rules:
- For codebase questions, first run `graphify query "<question>"` when graphify-out/graph.json exists. Use `graphify path "<A>" "<B>"` for relationships and `graphify explain "<concept>"` for focused concepts. These return a scoped subgraph, usually much smaller than GRAPH_REPORT.md or raw grep output.
- Dirty graphify-out/ files are expected after hooks or incremental updates; dirty graph files are not a reason to skip graphify. Only skip graphify if the task is about stale or incorrect graph output, or the user explicitly says not to use it.
- If graphify-out/wiki/index.md exists, use it for broad navigation instead of raw source browsing.
- Read graphify-out/GRAPH_REPORT.md only for broad architecture review or when query/path/explain do not surface enough context.
- After modifying code, run `graphify update .` to keep the graph current (AST-only, no API cost).
