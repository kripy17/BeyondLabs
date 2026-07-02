import { createFileRoute, Link } from "@tanstack/react-router";
import { useMemo, useState } from "react";
import { PageShell } from "@/components/PageShell";
import { SectionBar, Panel, Chip, SendToRow, VerdictBanner, MetricGrid } from "@/components/soc/Workspace";
import { BookOpen, ArrowRight, Database, ShieldAlert, Search, CircleCheck as CheckCircle2, Circle, TriangleAlert as AlertTriangle, ShieldOff, Mail, MailWarning as FileWarning, Activity, KeyRound, ListFilter as Filter, ShieldCheck } from "lucide-react";

export const Route = createFileRoute("/guide")({ component: GuidePage });

type Severity = "P1" | "P2" | "P3";
type Playbook = {
  id: string; title: string; severity: Severity; eta: string; category: string;
  icon: typeof Mail; summary: string; steps: { text: string; pivot?: { to: string; label: string } }[];
};

const PLAYBOOKS: Playbook[] = [
  { id: "phish", title: "Phishing email reported", severity: "P2", eta: "15m", category: "Email", icon: Mail,
    summary: "User-reported lure: confirm verdict, scrub URLs, contain account exposure, document.",
    steps: [
      { text: "Pause any new inbox rules and forwarders on the reporting account.", pivot: { to: "/logs", label: "Logs" } },
      { text: "Pull full message source including raw headers." },
      { text: "Run through Phishing Triage; capture verdict, reasons, and IOCs.", pivot: { to: "/phishing", label: "Phishing" } },
      { text: "Refang and review embedded URLs in Safe URL Analyzer.", pivot: { to: "/url", label: "URL" } },
      { text: "Pivot sender / reply-to / URL across mail and proxy logs.", pivot: { to: "/logs", label: "Logs" } },
      { text: "Notify the user; reset credentials and revoke sessions if they interacted." },
      { text: "Document the finding chain in the Case Notebook.", pivot: { to: "/case", label: "Case" } },
    ],
  },
  { id: "ssh", title: "SSH brute-force surge", severity: "P3", eta: "10m", category: "Network", icon: KeyRound,
    summary: "Spike in failed SSH attempts — confirm source, block, audit successes.",
    steps: [
      { text: "Confirm the source IP, geo, and target account list.", pivot: { to: "/osint", label: "OSINT" } },
      { text: "Block source at perimeter or fail2ban." },
      { text: "Audit for any successful logins from the same source over the last 30 days.", pivot: { to: "/siem", label: "SIEM" } },
      { text: "Reset credentials and revoke keys for any matched accounts." },
      { text: "Add a detection lead under T1110 if missing.", pivot: { to: "/detection", label: "Detection" } },
    ],
  },
  { id: "macro", title: "Macro-enabled attachment delivered", severity: "P2", eta: "20m", category: "Email", icon: FileWarning,
    summary: "Quarantine, hash, and contain before any user contact.",
    steps: [
      { text: "Quarantine the message at the mail gateway." },
      { text: "Hash the file and pivot in Attachment Triage.", pivot: { to: "/attachment", label: "Attachment" } },
      { text: "Confirm no execution via EDR process trees.", pivot: { to: "/logs", label: "Logs" } },
      { text: "Block hash, sender, and URL across the stack." },
      { text: "Update macro policy if exposure is recurring." },
    ],
  },
  { id: "c2", title: "Outbound C2-like beacon", severity: "P1", eta: "30m", category: "Network", icon: Activity,
    summary: "Suspected command-and-control: cut traffic, snapshot, escalate.",
    steps: [
      { text: "Capture host, user, destination, port, and beacon cadence." },
      { text: "Sever outbound traffic at proxy or firewall." },
      { text: "Snapshot endpoint memory if your EDR supports it." },
      { text: "Cross-check destination in Recon & Exposure.", pivot: { to: "/recon", label: "Recon" } },
      { text: "Open an incident review with the on-call lead.", pivot: { to: "/case", label: "Case" } },
    ],
  },
];

const SEV_COLOR: Record<Severity, "destructive" | "warning" | "default"> = { P1: "destructive", P2: "warning", P3: "default" };

function GuidePage() {
  const [activeId, setActiveId] = useState<string>(PLAYBOOKS[0].id);
  const [query, setQuery] = useState("");
  const [sev, setSev] = useState<Severity | "ALL">("ALL");
  const [done, setDone] = useState<Record<string, Set<number>>>({});

  const list = useMemo(() => PLAYBOOKS.filter((p) =>
    (sev === "ALL" || p.severity === sev) &&
    (!query.trim() || (p.title + " " + p.summary + " " + p.category).toLowerCase().includes(query.toLowerCase()))
  ), [query, sev]);

  const active = PLAYBOOKS.find((p) => p.id === activeId) ?? PLAYBOOKS[0];
  const activeDone = done[active.id] ?? new Set<number>();
  const progress = Math.round((activeDone.size / active.steps.length) * 100);

  const toggle = (i: number) => {
    setDone((d) => {
      const next = new Set(d[active.id] ?? []);
      next.has(i) ? next.delete(i) : next.add(i);
      return { ...d, [active.id]: next };
    });
  };

  const counts: Record<Severity, number> = { P1: 0, P2: 0, P3: 0 };
  PLAYBOOKS.forEach((p) => { counts[p.severity] += 1; });

  return (
    <PageShell
      eyebrow="DETECTION / GUIDE"
      title="SOC Playbook Guide"
      description="Bite-sized response playbooks — pick a scenario, work the steps, pivot into the right tool."
      crumbs={[{ label: "Detection" }, { label: "Guide" }]}
    >
      {/* Verdict Banner */}
      <VerdictBanner
        verdict={`${PLAYBOOKS.length} bundled playbooks`}
        tone="success"
        icon={ShieldCheck}
        details={[
          `${counts.P1} P1 critical · ${counts.P2} P2 high · ${counts.P3} P3 medium`,
          "Linear, actionable, and wired into the rest of the workbench",
        ]}
      />

      {/* Metrics */}
      <MetricGrid
        columns={4}
        metrics={[
          { label: "Total", value: PLAYBOOKS.length, tone: "primary", icon: BookOpen },
          { label: "P1 critical", value: counts.P1, tone: "destructive" },
          { label: "P2 high", value: counts.P2, tone: "warning" },
          { label: "P3 medium", value: counts.P3 },
        ]}
      />

      <SectionBar id="IN" label="Filter · pick a scenario" meta={`${list.length} match${list.length === 1 ? "" : "es"}`} />

      <div className="grid gap-3 lg:grid-cols-[18rem_1fr]">
        {/* Left rail: search + severity filter + playbook list */}
        <div className="space-y-2">
          <Panel>
            <div className="flex items-center gap-2 rounded border border-border/60 bg-background/60 px-2">
              <Search className="h-3.5 w-3.5 text-muted-foreground" />
              <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="search playbooks…" className="w-full bg-transparent py-1.5 text-mono text-[11px] outline-none placeholder:text-muted-foreground/60" />
            </div>
            <div className="mt-2 flex items-center gap-1">
              <Filter className="h-3 w-3 text-muted-foreground" />
              {(["ALL", "P1", "P2", "P3"] as const).map((s) => (
                <button key={s} onClick={() => setSev(s)} className={"rounded border px-1.5 py-0.5 text-mono text-[10px] uppercase tracking-widest " + (sev === s ? "border-primary bg-primary/15 text-primary" : "border-border/60 text-muted-foreground hover:text-foreground")}>{s.toLowerCase()}</button>
              ))}
            </div>
          </Panel>

          <Panel bodyClassName="p-1.5">
            <ul className="space-y-1">
              {list.map((p) => {
                const Icon = p.icon;
                const isActive = p.id === active.id;
                const pDone = done[p.id]?.size ?? 0;
                return (
                  <li key={p.id}>
                    <button
                      onClick={() => setActiveId(p.id)}
                      className={
                        "group flex w-full items-start gap-2 rounded-md border px-2 py-2 text-left transition-colors " +
                        (isActive ? "border-primary/50 bg-primary/10" : "border-transparent hover:border-border hover:bg-card/60")
                      }
                    >
                      <Icon className={"mt-0.5 h-3.5 w-3.5 shrink-0 " + (isActive ? "text-primary" : "text-muted-foreground")} />
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center justify-between gap-2">
                          <span className="truncate text-mono text-[11px] uppercase tracking-widest text-foreground/90">{p.title}</span>
                          <Chip tone={SEV_COLOR[p.severity]}>{p.severity}</Chip>
                        </div>
                        <div className="mt-0.5 flex items-center gap-2 text-mono text-[10px] text-muted-foreground">
                          <span>{p.category}</span>
                          <span>·</span>
                          <span>~{p.eta}</span>
                          <span>·</span>
                          <span>{pDone}/{p.steps.length}</span>
                        </div>
                      </div>
                    </button>
                  </li>
                );
              })}
              {list.length === 0 && (
                <li className="px-3 py-6 text-center text-mono text-[10.5px] uppercase tracking-widest text-muted-foreground">no playbooks match</li>
              )}
            </ul>
          </Panel>
        </div>

        {/* Right: active playbook detail */}
        <div className="space-y-3">
          <Panel
            title={active.title}
            icon={BookOpen}
            meta={`${active.category} · ~${active.eta}`}
            actions={<Chip tone={SEV_COLOR[active.severity]}>{active.severity}</Chip>}
          >
            <p className="mb-3 text-[12px] leading-relaxed text-foreground/80">{active.summary}</p>

            <div className="mb-3 flex items-center gap-3">
              <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-border/40">
                <div className="h-full bg-primary transition-all" style={{ width: `${progress}%` }} />
              </div>
              <span className="text-mono text-[10px] uppercase tracking-widest text-muted-foreground">{activeDone.size}/{active.steps.length} done · {progress}%</span>
            </div>

            <ol className="space-y-1.5">
              {active.steps.map((s, i) => {
                const isDone = activeDone.has(i);
                return (
                  <li key={i} className={"group flex items-start gap-3 rounded border px-2.5 py-2 transition-colors " + (isDone ? "border-success/30 bg-success/5" : "border-border/50 bg-card/40 hover:border-primary/30")}>
                    <button onClick={() => toggle(i)} aria-label="toggle step" className="mt-0.5 shrink-0">
                      {isDone ? <CheckCircle2 className="h-4 w-4 text-success" /> : <Circle className="h-4 w-4 text-muted-foreground group-hover:text-primary" />}
                    </button>
                    <span className="mt-0.5 text-mono text-[10.5px] text-primary">{String(i + 1).padStart(2, "0")}</span>
                    <span className={"flex-1 text-[12px] leading-snug " + (isDone ? "text-muted-foreground line-through" : "text-foreground/90")}>{s.text}</span>
                    {s.pivot && (
                      <Link to={s.pivot.to} className="ml-2 inline-flex items-center gap-1 rounded border border-primary/40 bg-primary/10 px-1.5 py-0.5 text-mono text-[10px] uppercase tracking-widest text-primary opacity-80 hover:opacity-100">
                        {s.pivot.label} <ArrowRight className="h-3 w-3" />
                      </Link>
                    )}
                  </li>
                );
              })}
            </ol>
          </Panel>

          <div className="grid gap-3 md:grid-cols-2">
            <Panel title="Always" icon={CheckCircle2}>
              <ul className="space-y-1.5 text-[12px] text-foreground/85">
                <li className="flex items-start gap-2"><CheckCircle2 className="mt-0.5 h-3.5 w-3.5 shrink-0 text-success" /> Preserve evidence before remediation.</li>
                <li className="flex items-start gap-2"><CheckCircle2 className="mt-0.5 h-3.5 w-3.5 shrink-0 text-success" /> Log decisions in the Case Notebook with timestamps.</li>
                <li className="flex items-start gap-2"><CheckCircle2 className="mt-0.5 h-3.5 w-3.5 shrink-0 text-success" /> Pivot IOCs across at least two independent sources.</li>
              </ul>
            </Panel>
            <Panel title="Never" icon={ShieldOff}>
              <ul className="space-y-1.5 text-[12px] text-foreground/85">
                <li className="flex items-start gap-2"><AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-destructive" /> Open or detonate unknown files on your workstation.</li>
                <li className="flex items-start gap-2"><AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-destructive" /> Submit corporate samples to public sandboxes without approval.</li>
                <li className="flex items-start gap-2"><AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-destructive" /> Notify suspected insiders before evidence is preserved.</li>
              </ul>
            </Panel>
          </div>
        </div>
      </div>

      <SendToRow targets={[
        { label: "MITRE Coverage", to: "/mitre", icon: ArrowRight },
        { label: "Detection Editor", to: "/detection", icon: ShieldAlert },
        { label: "Case Notebook", to: "/case", icon: Database },
      ]} />
    </PageShell>
  );
}
