import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useCallback, useMemo, useState } from "react";
import { PageShell } from "@/components/PageShell";
import { ResultBanner, SectionBar, Panel, SendToRow, Chip, EvidenceCard } from "@/components/soc/Workspace";
import { sendArtifact } from "@/lib/handoff";
import { Target, ArrowRight, Database, ShieldAlert, RotateCcw, Search, StickyNote } from "lucide-react";

export const Route = createFileRoute("/mitre")({ component: MitrePage });

type Cov = "none" | "partial" | "full";
type Technique = { id: string; name: string };
type Tactic = { id: string; name: string; techniques: Technique[] };
const TACTICS: Tactic[] = [
  { id: "TA0043", name: "Recon",             techniques: [{ id: "T1595",     name: "Active Scanning" },          { id: "T1589", name: "Gather Victim Identity" }, { id: "T1592", name: "Gather Victim Host Info" }] },
  { id: "TA0042", name: "Resource Dev",      techniques: [{ id: "T1583",     name: "Acquire Infrastructure" },   { id: "T1587", name: "Develop Capabilities" }] },
  { id: "TA0001", name: "Initial Access",    techniques: [{ id: "T1566",     name: "Phishing" },                 { id: "T1190", name: "Exploit Public-Facing Application" }, { id: "T1078", name: "Valid Accounts" }] },
  { id: "TA0002", name: "Execution",         techniques: [{ id: "T1059.001", name: "PowerShell" },               { id: "T1059.003", name: "Windows Command Shell" }, { id: "T1204", name: "User Execution" }, { id: "T1053", name: "Scheduled Task/Job" }] },
  { id: "TA0003", name: "Persistence",       techniques: [{ id: "T1547",     name: "Boot or Logon Autostart" }, { id: "T1136", name: "Create Account" }, { id: "T1053", name: "Scheduled Task/Job" }] },
  { id: "TA0004", name: "Privilege Escalation", techniques: [{ id: "T1068",  name: "Exploitation for Privilege Escalation" }, { id: "T1055", name: "Process Injection" }, { id: "T1053", name: "Scheduled Task/Job" }] },
  { id: "TA0005", name: "Defense Evasion",   techniques: [{ id: "T1027",     name: "Obfuscated Files or Information" }, { id: "T1070", name: "Indicator Removal" }, { id: "T1218", name: "Signed Binary Proxy Execution" }] },
  { id: "TA0006", name: "Credential Access", techniques: [{ id: "T1110",     name: "Brute Force" },              { id: "T1003", name: "OS Credential Dumping" }, { id: "T1555", name: "Credentials from Password Stores" }, { id: "T1552", name: "Unsecured Credentials" }] },
  { id: "TA0007", name: "Discovery",         techniques: [{ id: "T1018",     name: "Remote System Discovery" }, { id: "T1082", name: "System Information Discovery" }] },
  { id: "TA0008", name: "Lateral Movement",  techniques: [{ id: "T1021",     name: "Remote Services" },          { id: "T1091", name: "Replication Through Removable Media" }] },
  { id: "TA0009", name: "Collection",        techniques: [{ id: "T1114",     name: "Email Collection" },         { id: "T1005", name: "Data from Local System" }] },
  { id: "TA0011", name: "C2",                techniques: [{ id: "T1071",     name: "Application Layer Protocol" }, { id: "T1573", name: "Encrypted Channel" }, { id: "T1095", name: "Non-Application Layer Protocol" }] },
  { id: "TA0010", name: "Exfiltration",      techniques: [{ id: "T1041",     name: "Exfiltration Over C2 Channel" }, { id: "T1567", name: "Exfiltration Over Web Service" }] },
  { id: "TA0040", name: "Impact",            techniques: [{ id: "T1490",     name: "Inhibit System Recovery" },  { id: "T1498", name: "Network Denial of Service" }] },
];

const COV_KEY = "beyondarch.mitre.coverage.v3";
const NOTE_KEY = "beyondarch.mitre.notes.v3";

const tone: Record<Cov, "default" | "warning" | "success"> = { none: "default", partial: "warning", full: "success" };
const cell: Record<Cov, string> = {
  none:    "border-border/50 bg-background/30 text-muted-foreground hover:border-warning/30",
  partial: "border-warning/40 bg-warning/10 text-warning hover:border-warning/60",
  full:    "border-success/40 bg-success/15 text-success hover:border-success/60",
};

function loadCov(): Record<string, Cov> {
  try { return JSON.parse(localStorage.getItem(COV_KEY) || "{}"); } catch { return {}; }
}
function saveCov(map: Record<string, Cov>) {
  localStorage.setItem(COV_KEY, JSON.stringify(map));
}
function loadNotes(): Record<string, string> {
  try { return JSON.parse(localStorage.getItem(NOTE_KEY) || "{}"); } catch { return {}; }
}
function saveNotes(map: Record<string, string>) {
  localStorage.setItem(NOTE_KEY, JSON.stringify(map));
}
function nextCov(c: Cov): Cov {
  if (c === "none") return "partial";
  if (c === "partial") return "full";
  return "none";
}
function techKey(tacticId: string, techId: string) { return `${tacticId}::${techId}`; }

function MitrePage() {
  const navigate = useNavigate();
  const [filter, setFilter] = useState<Cov | "all">("all");
  const [tab, setTab] = useState<"matrix" | "gaps" | "notes">("matrix");
  const [selected, setSelected] = useState<{ tactic: Tactic; tech: Technique; cov: Cov } | null>(null);
  const [cov, setCov] = useState<Record<string, Cov>>(loadCov);
  const [notes, setNotes] = useState<Record<string, string>>(loadNotes);
  const [noteDraft, setNoteDraft] = useState("");
  const [noteTech, setNoteTech] = useState<string | null>(null);
  const [search, setSearch] = useState("");

  const cycleCov = useCallback((tacticId: string, techId: string) => {
    setCov((prev) => {
      const key = techKey(tacticId, techId);
      const next = { ...prev, [key]: nextCov(prev[key] || "none") };
      saveCov(next);
      return next;
    });
  }, []);

  const resetAll = useCallback(() => {
    setCov({});
    localStorage.removeItem(COV_KEY);
  }, []);

  const getTechCov = useCallback((tacticId: string, techId: string): Cov => {
    return cov[techKey(tacticId, techId)] || "none";
  }, [cov]);

  const stats = useMemo(() => {
    const all = TACTICS.flatMap((t) => t.techniques);
    const n = all.filter((t) => getTechCov(t.id, t.id) === "none").length;
    const p = all.filter((t) => getTechCov(t.id, t.id) === "partial").length;
    const f = all.filter((t) => getTechCov(t.id, t.id) === "full").length;
    return { total: all.length, full: f, partial: p, none: n };
  }, [getTechCov]);

  const pct = Math.round(((stats.full + stats.partial * 0.5) / stats.total) * 100);

  const tacticPct = (t: Tactic) => {
    const total = t.techniques.length;
    const score = t.techniques.reduce((s, x) => {
      const c = getTechCov(t.id, x.id);
      return s + (c === "full" ? 1 : c === "partial" ? 0.5 : 0);
    }, 0);
    return total ? score / total : 0;
  };

  const gaps = useMemo(() =>
    TACTICS.flatMap((t) =>
      t.techniques
        .filter((x) => getTechCov(t.id, x.id) === "none")
        .map((x) => ({ tactic: t.name, tacticId: t.id, ...x }))
    ), [getTechCov]);

  const partials = useMemo(() =>
    TACTICS.flatMap((t) =>
      t.techniques
        .filter((x) => getTechCov(t.id, x.id) === "partial")
        .map((x) => ({ tactic: t.name, tacticId: t.id, ...x }))
    ), [getTechCov]);

  const allTechniques = useMemo(() =>
    TACTICS.flatMap((t) => t.techniques.map((x) => ({ tactic: t.name, tacticId: t.id, ...x }))),
  []);

  const filteredGaps = useMemo(() => {
    const q = search.trim().toLowerCase();
    if (!q) return gaps;
    return gaps.filter(x => x.id.toLowerCase().includes(q) || x.name.toLowerCase().includes(q) || x.tactic.toLowerCase().includes(q));
  }, [gaps, search]);

  const gapFindings = useMemo(() => {
    const f: { sev: "destructive" | "warning" | "info"; title: string; reason: string; action: string }[] = [];
    if (gaps.length) f.push({ sev: "destructive", title: `${gaps.length} techniques uncovered`, reason: `Gaps: ${gaps.slice(0, 8).map((x) => x.id).join(", ")}${gaps.length > 8 ? "…" : ""}`, action: "Prioritise detection sprints for uncovered techniques." });
    if (partials.length) f.push({ sev: "warning", title: `${partials.length} techniques partially covered`, reason: `Partial: ${partials.slice(0, 8).map((x) => x.id).join(", ")}${partials.length > 8 ? "…" : ""}`, action: "Flesh out detection logic to full coverage." });
    if (stats.full >= stats.total * 0.5) f.push({ sev: "info", title: `${pct}% weighted coverage`, reason: `${stats.full} full, ${stats.partial} partial, ${stats.none} none.`, action: "Maintain coverage with regular atomic test validation." });
    if (!f.length) f.push({ sev: "info", title: "No coverage data", reason: "All techniques are unrated.", action: "Click technique cells to mark coverage status." });
    return f;
  }, [gaps, partials, stats, pct]);

  function saveNote(techId: string) {
    if (!noteDraft.trim()) return;
    setNotes(prev => {
      const next = { ...prev, [techId]: noteDraft.trim() };
      saveNotes(next);
      return next;
    });
    setNoteDraft("");
    setNoteTech(null);
  }

  return (
    <PageShell
      eyebrow="DETECTION / MITRE"
      title="MITRE ATT&CK Coverage"
      description="Interactive coverage matrix — click techniques to cycle none → partial → full. Stored locally in your browser."
      crumbs={[{ label: "Detection" }, { label: "MITRE" }]}
    >
      <ResultBanner
        badge="coverage"
        title={`${pct}% weighted coverage`}
        subtitle={`${stats.full} full · ${stats.partial} partial · ${stats.none} none`}
        metrics={[
          { label: "Tactics",    value: TACTICS.length, tone: "primary" },
          { label: "Techniques", value: stats.total },
          { label: "Full",       value: stats.full, tone: "success" },
          { label: "Gaps",       value: stats.none, tone: "warning" },
        ]}
      />

      <div className="grid gap-3 md:grid-cols-2">
        {gapFindings.map((f, i) => (
          <EvidenceCard key={i} severity={f.sev} title={f.title} reason={f.reason} action={f.action} limitation="Click technique cells to update status. Coverage data is stored in browser localStorage." />
        ))}
      </div>

      <div className="mb-3 flex items-center justify-between">
        <Panel title="Kill-chain coverage" icon={Target} meta="click a tactic bar for details" bodyClassName="!p-0">
          <div className="flex items-stretch gap-1 overflow-x-auto p-3 pt-0">
            {TACTICS.map((t) => {
              const c = tacticPct(t);
              return (
                <div key={t.id} className="min-w-[96px] flex-1">
                  <div className="mb-1 flex items-center justify-between">
                    <span className="text-mono text-[9.5px] uppercase tracking-widest text-muted-foreground">{t.name}</span>
                    <span className="text-mono text-[9.5px] text-foreground/80">{Math.round(c * 100)}%</span>
                  </div>
                  <div className="h-2.5 overflow-hidden rounded-sm bg-border/40">
                    <div className={"h-full " + (c >= 0.7 ? "bg-success" : c >= 0.34 ? "bg-warning" : "bg-destructive/70")} style={{ width: `${c * 100}%` }} />
                  </div>
                  <div className="mt-1 text-mono text-[9px] text-muted-foreground">{t.id}</div>
                </div>
              );
            })}
          </div>
        </Panel>
      </div>

      <div className="mb-3 flex items-center gap-2">
        {(["matrix", "gaps", "notes"] as const).map((t) => (
          <button key={t} onClick={() => { setTab(t); setSearch(""); }}
            className={"rounded border px-2.5 py-1 text-mono text-[10px] uppercase tracking-widest " + (tab === t ? "border-primary bg-primary/15 text-primary" : "border-border text-muted-foreground hover:text-foreground")}>
            {t} {t === "gaps" ? `(${gaps.length})` : t === "notes" ? `(${Object.keys(notes).length})` : ""}
          </button>
        ))}
        <div className="ml-auto flex items-center gap-1">
          {tab !== "matrix" && (
            <div className="relative">
              <Search className="pointer-events-none absolute left-2 top-1/2 h-3 w-3 -translate-y-1/2 text-muted-foreground" />
              <input
                value={search} onChange={e => setSearch(e.target.value)}
                placeholder="filter…"
                className="h-7 w-40 rounded border border-border bg-background/60 pl-6 pr-2 text-mono text-[10px] text-foreground outline-none placeholder:text-muted-foreground/60 focus:border-primary/50"
              />
            </div>
          )}
          <button onClick={resetAll} className="inline-flex items-center gap-1 rounded border border-border px-1.5 py-0.5 text-mono text-[10px] uppercase text-muted-foreground hover:text-foreground">
            <RotateCcw className="h-3 w-3" /> reset
          </button>
        </div>
      </div>

      {tab === "matrix" && (
        <>
          <SectionBar id="MX" label="Coverage matrix" meta={`filter: ${filter}`}
            action={
              <div className="flex items-center gap-1">
                {(["all", "full", "partial", "none"] as const).map((f) => (
                  <button key={f} onClick={() => setFilter(f)} className={"rounded border px-1.5 py-0.5 text-mono text-[10px] uppercase " + (filter === f ? "border-primary bg-primary/15 text-primary" : "border-border text-muted-foreground hover:text-foreground")}>{f}</button>
                ))}
              </div>
            }
          />
          <div className="-mx-1 overflow-x-auto px-1 pb-1">
            <div className="grid min-w-[920px] grid-cols-5 gap-2 xl:min-w-0">
              {TACTICS.map((t) => {
                const ts = t.techniques.filter((x) => {
                  const c = getTechCov(t.id, x.id);
                  return filter === "all" || c === filter;
                });
                const c = tacticPct(t);
                return (
                  <Panel key={t.id} title={t.name} meta={t.id} bodyClassName="p-1.5">
                    <div className="mb-1.5 h-1 overflow-hidden rounded-sm bg-border/40">
                      <div className={"h-full transition-all " + (c >= 0.7 ? "bg-success" : c >= 0.34 ? "bg-warning" : "bg-destructive/70")} style={{ width: `${c * 100}%` }} />
                    </div>
                    <ul className="space-y-1">
                      {ts.length === 0 ? <li className="px-1 py-2 text-mono text-[10px] text-muted-foreground">—</li> : ts.map((x) => {
                        const currentCov = getTechCov(t.id, x.id);
                        const isSel = selected?.tech.id === x.id;
                        return (
                          <li key={x.id}>
                            <button
                              onClick={() => { cycleCov(t.id, x.id); setSelected({ tactic: t, tech: x, cov: currentCov }); }}
                              onContextMenu={(e) => { e.preventDefault(); setSelected({ tactic: t, tech: x, cov: currentCov }); }}
                              className={"group w-full rounded border px-2 py-1.5 text-left transition-all hover:-translate-y-px hover:shadow-[0_0_0_1px_hsl(var(--primary)/0.4)] " + cell[currentCov] + (isSel ? " ring-1 ring-primary" : "")}
                            >
                              <div className="flex items-center justify-between gap-1">
                                <span className="text-mono text-[10px] opacity-80">{x.id}</span>
                                <Chip tone={tone[currentCov]}>{currentCov[0]}</Chip>
                              </div>
                              <div className="mt-0.5 truncate text-[11px] text-foreground/90">{x.name}</div>
                            </button>
                          </li>
                        );
                      })}
                    </ul>
                  </Panel>
                );
              })}
            </div>
          </div>

          <Panel title="Technique detail" icon={Target}>
            {!selected ? (
              <p className="text-mono text-[11px] text-muted-foreground">Click any technique cell to cycle through coverage states (none → partial → full) or right-click to inspect.</p>
            ) : (
              <div className="grid gap-3 sm:grid-cols-[1fr_auto]">
                <div>
                  <div className="text-mono text-[10px] uppercase tracking-widest text-muted-foreground">{selected.tactic.name} · {selected.tactic.id}</div>
                  <div className="mt-0.5 text-lg text-foreground">{selected.tech.id} <span className="text-foreground/70">— {selected.tech.name}</span></div>
                  <div className="mt-2 flex items-center gap-2">
                    <Chip tone={tone[selected.cov]}>{selected.cov}</Chip>
                    <span className="text-mono text-[10px] text-muted-foreground">click to toggle</span>
                  </div>
                  {notes[selected.tech.id] && (
                    <div className="mt-2 rounded border border-border/50 bg-card/40 p-2 text-mono text-[11px] text-foreground/80">
                      <span className="text-[10px] uppercase tracking-widest text-muted-foreground">note</span>
                      <p className="mt-1">{notes[selected.tech.id]}</p>
                    </div>
                  )}
                </div>
                <div className="flex items-start gap-2">
                  {noteTech !== selected.tech.id ? (
                    <button onClick={() => { setNoteTech(selected.tech.id); setNoteDraft(notes[selected.tech.id] || ""); }}
                      className="inline-flex items-center gap-1 rounded border border-border px-2 py-1 text-mono text-[10px] uppercase text-muted-foreground hover:text-foreground">
                      <StickyNote className="h-3 w-3" /> {notes[selected.tech.id] ? "edit note" : "add note"}
                    </button>
                  ) : (
                    <div className="flex items-center gap-1">
                      <input
                        autoFocus
                        value={noteDraft}
                        onChange={e => setNoteDraft(e.target.value)}
                        onKeyDown={e => { if (e.key === "Enter") saveNote(selected.tech.id); if (e.key === "Escape") { setNoteTech(null); setNoteDraft(""); } }}
                        placeholder="note…"
                        className="w-36 rounded border border-border bg-background/60 px-1.5 py-1 text-mono text-[10px] text-foreground outline-none focus:border-primary/50"
                      />
                      <button onClick={() => saveNote(selected.tech.id)} className="rounded border border-success/50 bg-success/10 px-1.5 py-1 text-mono text-[10px] text-success">ok</button>
                    </div>
                  )}
                  <button onClick={() => { sendArtifact({ kind: "raw", value: `${selected.tech.id} — ${selected.tech.name}`, source: "/mitre" }); navigate({ to: "/detection" }); }} className="inline-flex items-center gap-1 rounded border border-primary/40 bg-primary/10 px-2 py-1 text-mono text-[11px] uppercase tracking-widest text-primary hover:bg-primary/20">
                    <ShieldAlert className="h-3 w-3" /> send to detection
                  </button>
                </div>
              </div>
            )}
          </Panel>
        </>
      )}

      {tab === "gaps" && (
        <>
          <SectionBar id="GP" label={`Gaps · ${gaps.length} uncovered`} meta="techniques with no coverage" />
          {filteredGaps.length === 0 ? (
            <div className="rounded border border-border/50 bg-card/30 p-6 text-center text-mono text-[11px] text-muted-foreground">No uncovered techniques match the filter.</div>
          ) : (
            <div className="grid gap-2 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4">
              {filteredGaps.map((g) => (
                <div key={g.id} className="rounded border border-border/50 bg-card/30 px-3 py-2">
                  <div className="flex items-center justify-between">
                    <Chip tone="default">{g.id}</Chip>
                    <span className="text-mono text-[9.5px] text-muted-foreground">{g.tactic}</span>
                  </div>
                  <div className="mt-1 text-[12px] text-foreground/85">{g.name}</div>
                </div>
              ))}
            </div>
          )}
        </>
      )}

      {tab === "notes" && (
        <>
          <SectionBar id="NT" label={`Notes · ${Object.keys(notes).length}`} meta="per-technique observations" />
          {Object.keys(notes).length === 0 ? (
            <div className="rounded border border-border/50 bg-card/30 p-6 text-center text-mono text-[11px] text-muted-foreground">No notes yet. Click a technique in the matrix and add a note.</div>
          ) : (
            <div className="grid gap-2 sm:grid-cols-2 md:grid-cols-3">
              {Object.entries(notes).map(([techId, noteText]) => {
                const t = allTechniques.find(x => x.id === techId);
                return (
                  <div key={techId} className="rounded border border-border/50 bg-card/30 px-3 py-2">
                    <div className="flex items-center justify-between">
                      <Chip tone="warning">{techId}</Chip>
                      {t && <span className="text-mono text-[9.5px] text-muted-foreground">{t.tactic}</span>}
                    </div>
                    {t && <div className="mt-0.5 text-[11px] text-foreground/70">{t.name}</div>}
                    <p className="mt-1.5 text-[11.5px] text-foreground/90">{noteText}</p>
                  </div>
                );
              })}
            </div>
          )}
        </>
      )}

      <SendToRow targets={[
        { label: "Detection Editor", to: "/detection", icon: ShieldAlert },
        { label: "SOC Guide",        to: "/guide",     icon: ArrowRight },
        { label: "Case Notebook",    to: "/case",      icon: Database },
      ]} />
    </PageShell>
  );
}
