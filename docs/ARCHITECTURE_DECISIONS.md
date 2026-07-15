# Architecture Decisions

Record of architectural and product decisions with rationale.

---

## 2026-07-14

### Navigation Consolidation

**Decision:** Restructure navigation from 9 flat groups to 5 operational areas + Resources + System.

**Reason:** The old navigation was a feature inventory. The new grouping represents analyst workflows.

**Groups:**
- Investigation (operational workflow)
- SIEM (monitoring workflow)
- Detection (engineering workflow)
- Intelligence (enrichment workflow)
- Tools (analyst utilities)
- Resources (reference)
- System (settings)

---

### Parser belongs under Investigation/Triage

**Decision:** Parser is an Investigation/Triage module, not a Tool.

**Reason:** It transforms raw input into structured investigation data. It should eventually be part of Artifact Intake — the user should think "I have an artifact" rather than "I need to open Parser."

---

### PCAP belongs under Investigation

**Decision:** PCAP Analysis moves from Tools to Investigation.

**Reason:** PCAP produces investigation evidence (connections, DNS, IPs, sessions, indicators, timeline events). It is not a general utility.

---

### OSINT, Recon, Nmap, Hacking Toolkit, Terminal remain in Tools

**Decision:** Keep these as Tools outside the investigation pipeline.

**Reason:** They are analyst utilities that do not define the investigation workflow. They can optionally send results to a case but should not depend on the investigation system or auto-attach to cases.

---

### MITRE stays under Detection

**Decision:** MITRE is a Detection module, not Intelligence.

**Reason:** The use case is "finding → MITRE technique → detection rule", not a MITRE encyclopedia. Intelligence enrichment is secondary.

---

### Intelligence has one nav entry until sub-routes exist

**Decision:** IOC Search is the single Intelligence nav entry.

**Reason:** CVE, Threat Actors, JA3, hashes all route to `/intel`. Splitting nav entries before separate views exist creates dead entries.

---

### Hash lookup removed from primary navigation

**Decision:** Remove Hash Lookup from sidebar. Keep the route working.

**Reason:** Hash lookup is an enrichment action, not a destination. Accessible via Command Palette, context actions on hashes, and search results.

---

### Evidence is a domain concept, not a nav entry

**Decision:** Do not create an Evidence nav entry yet.

**Reason:** No dedicated Evidence view exists. Add when the Case workspace supports an evidence view. The concept should exist in shared types but not in navigation.

---

### No nested sidebar sub-groups

**Decision:** Keep one-level grouping in sidebar.

**Reason:** The GroupBlock component only supports one level. Adding nesting adds code complexity without immediate workflow benefit. Can be revisited when Investigation workspace grows.

---

### Sidebar collapse state persisted in localStorage

**Decision:** Use localStorage per-group for expand/collapse state.

**Reason:** Dashboard and Investigation default expanded; others default collapsed. State persists across sessions per-group. Key format: `ba.sidebar.group.{label}`.

---

### Do not rename routes or move component files during nav restructuring

**Decision:** Navigation changes isolated from page implementation.

**Reason:** Route stability enables incremental refactoring. Renaming routes or moving files creates unnecessary risk. Navigation is a separate concern from page layout.

---

### Use relative import for translateSigma/listSigmaBackends

**Decision:** Use `../api/detection` instead of `@/api/detection` for these two exports.

**Reason:** TypeScript 5.9.3 path alias resolution fails for `translateSigma` and `listSigmaBackends` from `@/api/detection`. Other exports from the same file work fine. Vite build is unaffected. This is a TSC bug, not a code issue.

---

### Phase 0 before architecture changes

**Decision:** Fix existing bugs before introducing new architecture.

**Fixed:**
- 28+ typecheck errors across 8+ routes
- SectionBar children rendering bug (invisible intake/filter content)
- copyText function shadowing in hacking-toolkit.tsx and snippets.tsx
- PageShell meta type missing info/accent tones
- Missing lucide-react imports
- Chips, Panel props, LockerItem type union

**Verified:**
- All 12 async routes have loading indicators + error rendering
- SIEM BarChart binds to real backend data
- Triage PieChart binds to localStorage items
- Guide route is complete static content
- `npm run build` and `tsc --noEmit` pass

---

### Separate vision doc from detailed specs

**Decision:** Keep `BEYONDLABS_VISION.md` as a concise north star. Detailed specifications live in `docs/`.

**Reason:** The vision doc must be readable in 2 minutes by any AI agent or contributor. Detailed page specs, workflows, and decision history belong in separate documents under `docs/`.

---

## Template for Future Decisions

```markdown
### YYYY-MM-DD — Title

**Decision:** [The decision made.]

**Reason:** [Why this decision was made, including alternatives considered.]

**Date:** YYYY-MM-DD
```
