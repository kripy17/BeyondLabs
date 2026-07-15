# BeyondLabs Vision

BeyondLabs is a **local-first SOC investigation and threat analysis platform**.

The goal is not a collection of cybersecurity utilities. The goal is an analyst workspace where investigations move through:

```
Artifact → Analysis → Findings → IOC/Evidence → Case → Timeline → Detection → Report
```

---

## Principles

1. **Case-centric workflow** — Cases are the center of investigations. Every analyzer should be able to create or attach to a case.
2. **Integration over feature count** — Do not add isolated tools unless they improve the analyst workflow. The platform already has enough capabilities.
3. **Preserve existing functionality** — Prefer incremental refactors over rewrites. Do not break working routes.
4. **SOC-first identity** — The product should feel like Splunk/Sentinel/Security Onion/TheHive, not a pentesting toolkit.

---

## Navigation Model

| Area | Purpose |
|---|---|
| **Investigation** | Things that create or consume investigation evidence. |
| **SIEM** | Monitoring, alerts, correlation, hunting. Separate workflow from investigation. |
| **Detection** | Creating, testing, and improving detections from findings. |
| **Intelligence** | Threat enrichment and context. |
| **Tools** | Standalone analyst utilities. Never auto-attach to cases. |
| **Resources** | Reference material (SOC guides, runbooks). |
| **System** | Settings and configuration. |

Only expose routes that exist. Future concepts must not create empty nav entries.

---

## Core Objects

```
Case         — Central investigation container.
Artifact     — Raw input: email, file, URL, log, PCAP.
Evidence     — An artifact with case context.
Finding      — Analysis result: SPF failure, suspicious behavior.
IOC          — Indicator: IP, domain, hash, URL, JA3, CVE.
TimelineEvent— Timestamped record of investigation activity.
Detection    — Rule (Sigma, YARA) derived from a finding or IOC.
Report       — Structured summary of an investigation.
```

---

## Development Rules

1. Understand existing code before changing it.
2. Prefer minimal changes. A 5-line fix beats a 50-line abstraction.
3. Do not create abstractions only for future possibilities.
4. Validate ideas with one workflow before generalizing.
5. Run `npm run build` and `tsc --noEmit` before committing.
6. Log decisions to `docs/ARCHITECTURE_DECISIONS.md` rather than relying on chat history.

---

## Companion Documents

| Document | Purpose |
|---|---|
| `docs/PAGE_SPECIFICATIONS.md` | What each page does, produces, and connects to. |
| `docs/WORKFLOW_DESIGN.md` | Data flows between modules. |
| `docs/ARCHITECTURE_DECISIONS.md` | Decision history with rationale. |

Before implementing any feature:
1. Read this document.
2. Read the relevant `PAGE_SPECIFICATIONS.md` section.
3. Check `WORKFLOW_DESIGN.md` for expected data flow.
4. Check `ARCHITECTURE_DECISIONS.md` for previous decisions.

If a proposed change conflicts with these documents, explain the conflict before implementing.
