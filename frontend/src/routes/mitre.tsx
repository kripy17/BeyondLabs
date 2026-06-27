import { createFileRoute } from "@tanstack/react-router";
import { useMemo, useState } from "react";
import { PageShell } from "@/components/PageShell";
import { ResultBanner, SectionBar, Panel, SendToRow, Chip, RiskScore, EvidenceCard } from "@/components/soc/Workspace";
import { sendArtifact } from "@/lib/handoff";
import { Target, ArrowRight, Database, ShieldAlert, Grid3x3 } from "lucide-react";

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

function MitrePage() {
  const [filter, setFilter] = useState<Cov | "all">("all");
  const [selected, setSelected] = useState<{ tactic: Tactic; tech: Technique } | null>(null);

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
      description="Coverage matrix — techniques mapped to detection status."
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

      <SendToRow targets={[
        { label: "Detection Editor", to: "/detection", icon: ShieldAlert },
        { label: "SOC Guide",        to: "/guide",     icon: ArrowRight },
        { label: "Case Notebook",    to: "/case",      icon: Database },
      ]} />
    </PageShell>
  );
}
