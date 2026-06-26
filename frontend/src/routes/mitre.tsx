import { createFileRoute } from "@tanstack/react-router";
import { useMemo, useState } from "react";
import { PageShell } from "@/components/PageShell";
import { ResultBanner, SectionBar, Panel, SendToRow, Chip, RiskScore, EvidenceCard } from "@/components/soc/Workspace";
import { PreviewBadge } from "@/components/PreviewBadge";
import { sendArtifact } from "@/lib/handoff";
import { Target, ArrowRight, Database, ShieldAlert, Activity, FileEdit, FlaskConical, ClipboardCheck, Grid3x3, Play, CircleDot, CircleCheck, CircleX, Clock } from "lucide-react";

export const Route = createFileRoute("/mitre")({ component: MitrePage });

type Cov = "none" | "partial" | "full";
type Technique = { id: string; name: string; cov: Cov };
type Tactic = { id: string; name: string; techniques: Technique[] };
const TACTICS: Tactic[] = [
  { id: "TA0043", name: "Recon",             techniques: [{ id: "T1595",     name: "Active Scanning",          cov: "partial" }, { id: "T1589", name: "Gather Victim Identity",      cov: "none" }] },
  { id: "TA0042", name: "Resource Dev",      techniques: [{ id: "T1583",     name: "Acquire Infrastructure",   cov: "none" }] },
  { id: "TA0001", name: "Initial Access",    techniques: [{ id: "T1566",     name: "Phishing",                 cov: "full" }, { id: "T1190", name: "Exploit Public-Facing",       cov: "partial" }] },
  { id: "TA0002", name: "Execution",         techniques: [{ id: "T1059.001", name: "PowerShell",               cov: "full" }, { id: "T1059.003", name: "Windows Cmd",             cov: "partial" }, { id: "T1204", name: "User Execution", cov: "partial" }] },
  { id: "TA0003", name: "Persistence",       techniques: [{ id: "T1547",     name: "Boot/Logon Autostart",     cov: "partial" }, { id: "T1136", name: "Create Account",           cov: "none" }] },
  { id: "TA0004", name: "Privilege Esc",     techniques: [{ id: "T1068",     name: "Exploit for Priv Esc",     cov: "none" }, { id: "T1055", name: "Process Injection",          cov: "partial" }] },
  { id: "TA0005", name: "Defense Evasion",   techniques: [{ id: "T1027",     name: "Obfuscated Files",         cov: "partial" }, { id: "T1070", name: "Indicator Removal",       cov: "none" }] },
  { id: "TA0006", name: "Credential Access", techniques: [{ id: "T1110",     name: "Brute Force",              cov: "full" }, { id: "T1003", name: "OS Credential Dumping",      cov: "partial" }] },
  { id: "TA0007", name: "Discovery",         techniques: [{ id: "T1018",     name: "Remote System Discovery",  cov: "partial" }] },
  { id: "TA0011", name: "C2",                techniques: [{ id: "T1071",     name: "Application Layer Protocol", cov: "partial" }, { id: "T1095", name: "Non-App Layer",         cov: "none" }] },
];

const tone: Record<Cov, "default" | "warning" | "success"> = { none: "default", partial: "warning", full: "success" };
const cell: Record<Cov, string> = { none: "border-border/50 bg-background/30 text-muted-foreground", partial: "border-warning/40 bg-warning/10 text-warning", full: "border-success/40 bg-success/15 text-success" };

const EVENTS = [
  { t: "2h ago",  tech: "T1059.001", title: "PowerShell encoded command",     host: "WIN-FIN-04",  sev: "high" as const },
  { t: "4h ago",  tech: "T1566",     title: "Phishing lure clicked",         host: "user@corp",   sev: "medium" as const },
  { t: "9h ago",  tech: "T1110",     title: "Spray against VPN portal",      host: "vpn.corp",    sev: "high" as const },
  { t: "1d ago",  tech: "T1027",     title: "Heavily packed binary executed", host: "WIN-DEV-12",  sev: "medium" as const },
  { t: "2d ago",  tech: "T1071",     title: "Beaconing to rare TLD",          host: "WIN-FIN-04",  sev: "low" as const },
];
const DRAFTS = [
  { id: "DR-014", tech: "T1136",     title: "New local admin created (4720→4732)", owner: "kripy",  state: "review" as const },
  { id: "DR-013", tech: "T1070",     title: "Security log cleared (1102)",          owner: "mei",    state: "draft" as const },
  { id: "DR-012", tech: "T1583",     title: "DNS-over-HTTPS to fresh domains",      owner: "alex",   state: "draft" as const },
];
const LABS = [
  { id: "LAB-08", scenario: "Spearphish → macro → PowerShell stager", maps: ["T1566", "T1059.001"], ttl: "ready" as const },
  { id: "LAB-07", scenario: "Cred spray against SSO",                 maps: ["T1110"],              ttl: "ready" as const },
  { id: "LAB-06", scenario: "DLL side-loading via signed app",        maps: ["T1574"],              ttl: "queued" as const },
];
const TESTS = [
  { id: "AT-T1059.001-1", tech: "T1059.001", name: "Encoded PowerShell",            result: "detected" as const,    last: "today" },
  { id: "AT-T1059.001-3", tech: "T1059.001", name: "AMSI bypass via reflection",    result: "missed" as const,      last: "today" },
  { id: "AT-T1566-2",     tech: "T1566",     name: "OAuth consent phish",           result: "detected" as const,    last: "yesterday" },
  { id: "AT-T1110-1",     tech: "T1110",     name: "Spray (3 attempts/user)",       result: "partial" as const,     last: "yesterday" },
  { id: "AT-T1027-1",     tech: "T1027",     name: "UPX-packed binary",             result: "missed" as const,      last: "3d ago" },
];

type Tab = "matrix" | "events" | "drafts" | "lab" | "tests";

function MitrePage() {
  const [filter, setFilter] = useState<Cov | "all">("all");
  const [selected, setSelected] = useState<{ tactic: Tactic; tech: Technique } | null>(null);
  const [tab, setTab] = useState<Tab>("matrix");

  const stats = useMemo(() => {
    const all = TACTICS.flatMap((t) => t.techniques);
    return { total: all.length, full: all.filter((t) => t.cov === "full").length, partial: all.filter((t) => t.cov === "partial").length, none: all.filter((t) => t.cov === "none").length };
  }, []);
  const pct = Math.round(((stats.full + stats.partial * 0.5) / stats.total) * 100);

  const tacticPct = (t: Tactic) => {
    const total = t.techniques.length;
    const score = t.techniques.reduce((s, x) => s + (x.cov === "full" ? 1 : x.cov === "partial" ? 0.5 : 0), 0);
    return total ? score / total : 0;
  };

  const TABS: { id: Tab; label: string; icon: typeof Grid3x3; count?: number }[] = [
    { id: "matrix", label: "Matrix",   icon: Grid3x3,        count: stats.total },
    { id: "events", label: "Events",   icon: Activity,       count: EVENTS.length },
    { id: "drafts", label: "Drafts",   icon: FileEdit,       count: DRAFTS.length },
    { id: "lab",    label: "Lab",      icon: FlaskConical,   count: LABS.length },
    { id: "tests",  label: "Testing",  icon: ClipboardCheck, count: TESTS.length },
  ];

  // Findings from coverage gaps
  const gapFindings = useMemo(() => {
    const f: { sev: "destructive" | "warning" | "info"; title: string; reason: string; action: string }[] = [];
    const gaps = TACTICS.flatMap((t) => t.techniques.filter((x) => x.cov === "none"));
    const partials = TACTICS.flatMap((t) => t.techniques.filter((x) => x.cov === "partial"));
    if (gaps.length) f.push({ sev: "destructive", title: `${gaps.length} techniques have no coverage`, reason: `Gaps: ${gaps.map((x) => x.id).join(", ")}`, action: "Prioritise detection sprints for uncovered techniques." });
    if (partials.length) f.push({ sev: "warning", title: `${partials.length} techniques have partial coverage`, reason: `Partial: ${partials.map((x) => x.id).join(", ")}`, action: "Flesh out detection logic to full coverage." });
    if (stats.full >= stats.total * 0.5) f.push({ sev: "info", title: `${pct}% weighted coverage`, reason: `${stats.full} full, ${stats.partial} partial, ${stats.none} none.`, action: "Maintain coverage with regular atomic test validation." });
    if (!f.length) f.push({ sev: "info", title: "No coverage data", reason: "All techniques are unrated.", action: "Start mapping detection logic to techniques." });
    return f;
  }, [stats, pct]);

  return (
    <PageShell
      eyebrow="DETECTION / MITRE"
      title="MITRE ATT&CK Coverage"
      description="Coverage matrix, recent events, draft detections, purple-team labs, and atomic test results."
      crumbs={[{ label: "Detection" }, { label: "MITRE" }]}
    >
      <RiskScore score={pct} label="Coverage Score" confidence={pct < 30 ? "low" : pct < 60 ? "moderate" : pct < 80 ? "high" : "very high"} tone={pct < 30 ? "destructive" : pct < 60 ? "warning" : "success"} />
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
          <EvidenceCard key={i} severity={f.sev} title={f.title} reason={f.reason} action={f.action} limitation="Manual coverage ratings — may not reflect in-production detection state." />
        ))}
      </div>

      {/* Tab strip */}
      <div className="flex flex-wrap items-center gap-1 rounded-md border border-border bg-card/40 px-1.5 py-1">
        {TABS.map((t) => {
          const Icon = t.icon;
          const active = tab === t.id;
          return (
            <button
              key={t.id}
              onClick={() => setTab(t.id)}
              className={"group inline-flex items-center gap-1.5 rounded px-2.5 py-1 text-mono text-[11px] uppercase tracking-widest transition-colors " + (active ? "bg-primary/15 text-primary" : "text-muted-foreground hover:bg-background/60 hover:text-foreground")}
            >
              <Icon className="h-3.5 w-3.5" />
              {t.label}
              {typeof t.count === "number" && (
                <span className={"rounded-full px-1.5 text-[9px] " + (active ? "bg-primary/20 text-primary" : "bg-background/60 text-muted-foreground")}>{t.count}</span>
              )}
            </button>
          );
        })}
        <span className="ml-auto pr-1.5"><PreviewBadge label="non-matrix tabs · demo" /></span>
      </div>

      {tab === "matrix" && (
        <>
          {/* Kill-chain ribbon */}
          <Panel title="Kill-chain coverage" icon={Target} meta="tactics left → right">
            <div className="flex items-stretch gap-1 overflow-x-auto">
              {TACTICS.map((t) => {
                const c = tacticPct(t);
                return (
                  <div key={t.id} className="min-w-[112px] flex-1">
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

          <SectionBar id="OT" label="Coverage matrix" meta={`filter: ${filter}`} action={
            <div className="flex gap-1">
              {(["all", "full", "partial", "none"] as const).map((f) => (
                <button key={f} onClick={() => setFilter(f)} className={"rounded border px-1.5 py-0.5 text-mono text-[10px] uppercase " + (filter === f ? "border-primary bg-primary/15 text-primary" : "border-border text-muted-foreground hover:text-foreground")}>{f}</button>
              ))}
            </div>
          } />

          <div className="-mx-1 overflow-x-auto px-1 pb-1">
            <div className="grid min-w-[920px] grid-cols-5 gap-2 xl:min-w-0">
              {TACTICS.map((t) => {
                const ts = t.techniques.filter((x) => filter === "all" || x.cov === filter);
                const c = tacticPct(t);
                return (
                  <Panel key={t.id} title={t.name} meta={t.id} bodyClassName="p-1.5">
                    <div className="mb-1.5 h-1 overflow-hidden rounded-sm bg-border/40">
                      <div className={"h-full transition-all " + (c >= 0.7 ? "bg-success" : c >= 0.34 ? "bg-warning" : "bg-destructive/70")} style={{ width: `${c * 100}%` }} />
                    </div>
                    <ul className="space-y-1">
                      {ts.length === 0 ? <li className="px-1 py-2 text-mono text-[10px] text-muted-foreground">—</li> : ts.map((x) => {
                        const isSel = selected?.tech.id === x.id;
                        return (
                          <li key={x.id}>
                            <button
                              onClick={() => setSelected({ tactic: t, tech: x })}
                              className={"group w-full rounded border px-2 py-1.5 text-left transition-all hover:-translate-y-px hover:shadow-[0_0_0_1px_hsl(var(--primary)/0.4)] " + cell[x.cov] + (isSel ? " ring-1 ring-primary" : "")}
                            >
                              <div className="flex items-center justify-between gap-1">
                                <span className="text-mono text-[10px] opacity-80">{x.id}</span>
                                <Chip tone={tone[x.cov]}>{x.cov[0]}</Chip>
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

          {/* Detail */}
          <Panel title="Technique detail" icon={Target}>
            {!selected ? (
              <p className="text-mono text-[11px] text-muted-foreground">Click any technique cell to inspect coverage details.</p>
            ) : (
              <div className="grid gap-3 sm:grid-cols-[1fr_auto]">
                <div>
                  <div className="text-mono text-[10px] uppercase tracking-widest text-muted-foreground">{selected.tactic.name} · {selected.tactic.id}</div>
                  <div className="mt-0.5 text-lg text-foreground">{selected.tech.id} <span className="text-foreground/70">— {selected.tech.name}</span></div>
                  <div className="mt-2 text-[12px] text-muted-foreground">
                    {selected.tech.cov === "full"    && "Detection logic is in place with validated test traffic and an enriched alert chain."}
                    {selected.tech.cov === "partial" && "Some signal exists but coverage has known blind spots. Recommend a focused detection sprint."}
                    {selected.tech.cov === "none"    && "No detection currently maps to this technique. Treat as a gap and route to the detection editor."}
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <Chip tone={tone[selected.tech.cov]}>{selected.tech.cov}</Chip>
                  <a href="/detection" onClick={() => sendArtifact({ kind: "raw", value: `${selected.tech.id} — ${selected.tech.name}`, source: "/mitre" })} className="inline-flex items-center gap-1 rounded border border-primary/40 bg-primary/10 px-2 py-1 text-mono text-[11px] uppercase tracking-widest text-primary">
                    <ShieldAlert className="h-3 w-3" /> send to detection
                  </a>
                </div>
              </div>
            )}
          </Panel>
        </>
      )}

      {tab === "events" && (
        <Panel title="Recent technique sightings" icon={Activity} meta={`${EVENTS.length} events · 7d`} actions={<PreviewBadge />}>
          <ul className="divide-y divide-border/40">
            {EVENTS.map((e, i) => (
              <li key={i} className="grid grid-cols-[64px_88px_1fr_auto_auto] items-center gap-2 py-2 text-[12px]">
                <span className="text-mono text-[10px] uppercase tracking-widest text-muted-foreground">{e.t}</span>
                <code className="text-mono text-[11px] text-primary">{e.tech}</code>
                <span className="truncate text-foreground/90">{e.title}</span>
                <span className="text-mono text-[10px] text-muted-foreground">{e.host}</span>
                <Chip tone={e.sev === "high" ? "destructive" : e.sev === "medium" ? "warning" : "default"}>{e.sev}</Chip>
              </li>
            ))}
          </ul>
        </Panel>
      )}

      {tab === "drafts" && (
        <Panel title="Draft detections targeting gaps" icon={FileEdit} meta={`${DRAFTS.length} drafts`} actions={<PreviewBadge />}>
          <ul className="divide-y divide-border/40">
            {DRAFTS.map((d) => (
              <li key={d.id} className="flex items-center gap-3 py-2 text-[12px]">
                <code className="text-mono text-[10px] text-muted-foreground">{d.id}</code>
                <code className="text-mono text-[11px] text-primary">{d.tech}</code>
                <span className="flex-1 truncate text-foreground/90">{d.title}</span>
                <span className="text-mono text-[10px] text-muted-foreground">{d.owner}</span>
                <Chip tone={d.state === "review" ? "warning" : "default"}>{d.state}</Chip>
                <a href="/detection" className="inline-flex items-center gap-1 rounded border border-border bg-background/40 px-2 py-0.5 text-mono text-[10px] uppercase tracking-widest text-muted-foreground hover:border-primary/50 hover:text-primary"><ShieldAlert className="h-3 w-3" /> open</a>
              </li>
            ))}
          </ul>
        </Panel>
      )}

      {tab === "lab" && (
        <div className="grid gap-3 md:grid-cols-2">
          {LABS.map((l) => (
            <Panel key={l.id} title={l.id} icon={FlaskConical} meta={l.ttl} actions={<PreviewBadge label="lab · demo" />}>
              <p className="text-[12px] text-foreground/90">{l.scenario}</p>
              <div className="mt-2 flex flex-wrap items-center gap-1">
                {l.maps.map((m) => <code key={m} className="rounded border border-primary/40 bg-primary/10 px-1.5 py-0.5 text-mono text-[10px] text-primary">{m}</code>)}
              </div>
              <div className="mt-3 flex items-center gap-2">
                <button className="inline-flex items-center gap-1 rounded border border-primary/40 bg-primary/10 px-2 py-1 text-mono text-[10px] uppercase tracking-widest text-primary hover:bg-primary/20">
                  <Play className="h-3 w-3" /> arm scenario
                </button>
                <span className="text-mono text-[10px] text-muted-foreground">runs locally · stub</span>
              </div>
            </Panel>
          ))}
        </div>
      )}

      {tab === "tests" && (
        <Panel title="Atomic test results" icon={ClipboardCheck} meta={`${TESTS.length} tests · last sweep`} actions={<PreviewBadge />}>
          <div className="grid grid-cols-[1fr_auto_auto_auto] gap-x-3 gap-y-1 text-[12px]">
            <div className="text-mono text-[10px] uppercase tracking-widest text-muted-foreground">test</div>
            <div className="text-mono text-[10px] uppercase tracking-widest text-muted-foreground">tech</div>
            <div className="text-mono text-[10px] uppercase tracking-widest text-muted-foreground">last</div>
            <div className="text-mono text-[10px] uppercase tracking-widest text-muted-foreground">result</div>
            {TESTS.map((t) => {
              const Icon = t.result === "detected" ? CircleCheck : t.result === "missed" ? CircleX : CircleDot;
              const color = t.result === "detected" ? "text-success" : t.result === "missed" ? "text-destructive" : "text-warning";
              return (
                <div key={t.id} className="contents">
                  <div className="truncate text-foreground/90"><code className="text-mono text-[10px] text-muted-foreground">{t.id}</code> · {t.name}</div>
                  <code className="text-mono text-[11px] text-primary">{t.tech}</code>
                  <span className="inline-flex items-center gap-1 text-mono text-[10px] text-muted-foreground"><Clock className="h-3 w-3" />{t.last}</span>
                  <span className={"inline-flex items-center gap-1 text-mono text-[10px] uppercase tracking-widest " + color}><Icon className="h-3 w-3" />{t.result}</span>
                </div>
              );
            })}
          </div>
        </Panel>
      )}

      <SendToRow targets={[
        { label: "Detection Editor", to: "/detection", icon: ShieldAlert },
        { label: "SOC Guide",        to: "/guide",     icon: ArrowRight },
        { label: "Case Notebook",    to: "/case",      icon: Database },
      ]} />
    </PageShell>
  );
}
