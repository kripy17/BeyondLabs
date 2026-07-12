import { createFileRoute, Link } from "@tanstack/react-router";
import { PageShell } from "@/components/PageShell";
import { Button } from "@/components/ui/button";
import { ALL_ITEMS, findItem, type WorkspaceItem } from "@/lib/workspaces";
import { useRecents, clearRecents } from "@/lib/recents";
import { usePrefs } from "@/lib/prefs";
import { NumberTicker } from "@/components/magic/NumberTicker";
import { toast } from "sonner";

import { AnimatedGrid } from "@/components/magic/AnimatedGrid";
import { Marquee } from "@/components/magic/Marquee";
import { WorkflowRibbon } from "@/components/soc/WorkflowRibbon";
import { MetricGrid } from "@/components/output";
import {
  ArrowRight, Plus, ArrowUpRight, Wand2, Radar, Target, Pin, Clock,
  Keyboard, ShieldCheck, Zap, Eraser, Activity,
  Cpu, WifiOff, CircleDot, Compass, LayoutGrid, type LucideIcon,
} from "lucide-react";
import { useEffect, useMemo, useState } from "react";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "Command Deck — BeyondLabs" },
      { name: "description", content: "Local-first SOC analyst workbench. Pick a track or jump into a workspace." },
    ],
  }),
  component: Dashboard,
});

type Track = {
  id: string; label: string; tag: string; blurb: string; url: string;
  icon: LucideIcon; stages: string[];
};

const TRACKS: Track[] = [
  { id: "01", label: "Investigate", tag: "parse → osint",   url: "/parser",    icon: Wand2,
    blurb: "Normalize IOCs, score phishing, vet URLs & attachments — plus OSINT lookups.",
    stages: ["parse", "enrich", "pivot", "verdict"] },
  { id: "02", label: "Recon",     tag: "map the surface",  url: "/recon",     icon: Radar,
    blurb: "Enumerate subdomains, certs and OSINT. Run bounded port scans.",
    stages: ["scope", "enumerate", "scan", "report"] },
  { id: "03", label: "Detection", tag: "rule → coverage",  url: "/detection", icon: Target,
    blurb: "Author Sigma & YARA, map to ATT&CK, track gaps, draft handoff.",
    stages: ["author", "simulate", "map", "handoff"] },
];

const QUICK_ACTIONS: { label: string; url: string; icon: LucideIcon; hint: string }[] = [
  { label: "Investigation",  url: "/parser",   icon: Wand2,       hint: "I" },
  { label: "Score phish",    url: "/phishing", icon: ShieldCheck, hint: "F" },
  { label: "Vet URL",        url: "/url",      icon: Zap,         hint: "U" },
  { label: "Open SIEM",      url: "/siem",     icon: Activity,    hint: "S" },
];

const TIPS = [
  "Paste any artifact into Investigation to auto-extract IOCs and run OSINT lookups.",
  "Phishing Triage scores Auth-Results, headers and body locally.",
  "Detection Workspace lints Sigma & YARA as you type.",
  "Everything runs in-browser. Nothing leaves the tab.",
];

const omittedGroups = new Set(["Overview", "System"]);

function Dashboard() {
  const recents = useRecents();
  const { prefs } = usePrefs();
  const pinned = prefs.sidebar.pinned.map(findItem).filter((x): x is WorkspaceItem => !!x);
  const recentItems = recents.map(findItem).filter((x): x is WorkspaceItem => !!x);
  const allModules = ALL_ITEMS.filter((i) => !omittedGroups.has(i.group));
  const groupCount = new Set(allModules.map((m) => m.group)).size;

  return (
    <PageShell
      eyebrow="// workbench · session"
      title="Command Deck"
      description="Pick a track, resume recent work, or jump straight into any workspace. Everything stays on this machine."
      actions={
        <Button asChild size="sm" className="text-mono gap-1.5">
          <Link to="/parser">
            <Plus className="h-3.5 w-3.5" /> new session
            <ArrowRight className="h-3.5 w-3.5" />
          </Link>
        </Button>
      }
    >
      {/* 1 · Command strip — live status, session id, env, palette hint */}
      {prefs.dashboardSections.commandStrip && <CommandStrip />}

      {/* 1b · Investigation flow ribbon */}
      {prefs.dashboardSections.workflowRibbon && <WorkflowRibbon />}

      {/* 2 · Dashboard metrics */}
      {prefs.dashboardSections.metrics && (
        <MetricGrid
          columns={4}
          metrics={[
            { label: "Modules", value: allModules.length, tone: "primary", icon: LayoutGrid },
            { label: "Groups", value: groupCount, tone: "info" },
            { label: "Tracks", value: TRACKS.length, tone: "accent" },
            { label: "Recent", value: recents.length, tone: recents.length > 0 ? "warning" : "default", icon: Clock },
          ]}
        />
      )}

      {/* 3 · Continue + quick actions */}
      {prefs.dashboardSections.continueRow && <ContinueRow item={recentItems[0]} />}

      {/* 3a · Pinned chips (if any) */}
      {prefs.dashboardSections.pinned && pinned.length > 0 && <PinnedRail items={pinned} />}

      {/* 4 · Tracks */}
      {prefs.dashboardSections.tracks && (
        <section>
          <SectionHeader icon={Compass} label="start a track" hint="3 guided paths" />
          <div className="grid gap-3 ba-stagger sm:grid-cols-2 lg:grid-cols-3">
            {TRACKS.map((t) => <TrackCard key={t.id} t={t} />)}
          </div>
        </section>
      )}

      {/* 5 · Workspaces — uniform 5-col tile grid (no nested group bento) */}
      {prefs.dashboardSections.workspaces && (
        <section>
          <SectionHeader
            icon={LayoutGrid} label="workspaces"
            hint={<><NumberTicker value={allModules.length} /> modules · <NumberTicker value={groupCount} /> groups</>}
          />
          <div className="grid gap-2.5 ba-stagger grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-5">
            {allModules.map((m) => <ModuleTile key={m.url} m={m} />)}
          </div>
        </section>
      )}

      {/* 6 · Footer utility row — recents + tips, balanced */}
      {prefs.dashboardSections.footer && (
        <section className="grid gap-3 sm:grid-cols-2">
          <Panel
            label="recent activity" icon={Clock}
            right={
              recentItems.length > 0 ? (
                <button onClick={() => { clearRecents(); toast("Recents cleared"); }} className="text-mono inline-flex items-center gap-1 text-[10px] text-muted-foreground hover:text-foreground">
                  <Eraser className="h-3 w-3" /> clear
                </button>
              ) : null
            }
          >
            {recentItems.length === 0 ? (
              <EmptyHint icon={Clock} text="No activity yet — your last 8 workspaces will appear here." />
            ) : (
              <ul className="divide-y divide-border/50">
                {recentItems.slice(0, 6).map((it, i) => (
                  <li key={it.url}>
                    <Link to={it.url} className="group flex items-center gap-2.5 px-3 py-2 transition-colors hover:bg-background/40">
                      <span className="text-mono w-5 shrink-0 text-[10px] text-muted-foreground/70">{String(i + 1).padStart(2, "0")}</span>
                      <it.icon className="h-3.5 w-3.5 text-primary/90" />
                      <span className="min-w-0 flex-1 truncate text-mono ba-text-base text-foreground">{it.title}</span>
                      <span className="text-mono text-[9.5px] uppercase tracking-widest text-muted-foreground">{it.group}</span>
                      <ArrowUpRight className="h-3 w-3 text-muted-foreground opacity-0 transition-opacity group-hover:opacity-100" />
                    </Link>
                  </li>
                ))}
              </ul>
            )}
          </Panel>

          <Panel label="tips & shortcuts" icon={Keyboard}>
            <div className="grid gap-0 divide-y divide-border/50">
              <ShortcutRow keys={["⌘", "K"]} label="Command palette" />
              <ShortcutRow keys={["/"]}      label="Focus top search" />
              <ShortcutRow keys={["G", "P"]} label="Go to Smart Parser" />
              <ShortcutRow keys={["G", "S"]} label="Go to Settings" />
            </div>
            <div className="border-t border-border/50 px-3 py-2.5">
              <div className="text-mono mb-1.5 text-[9.5px] uppercase tracking-[0.22em] text-muted-foreground">// tip</div>
              <RotatingTip />
            </div>
          </Panel>
        </section>
      )}
    </PageShell>
  );
}

/* ----------------------------- Command strip ------------------------------ */

const SIGNALS = [
  "SPF/DMARC fail on example-login.com · 08:23:14",
  "Sigma T1059.001 match · PowerShell encode detected",
  "YARA cred_stealer.rule hit on invoice.docm",
  "SSH brute-force surge from 185.220.101.7 · 47 attempts",
  "C2 beacon interval detected · 192.168.1.220 → 203.0.113.88:8443",
  "New TLD .click registration for paypa1-verify.com",
  "Suricata ET CNNIC alert · outbound to known-bad ASN",
  "DNS query for xn--pple-43d.com · typo-squat candidate",
];

function CommandStrip() {
  const [now, setNow] = useState<Date>(() => new Date());
  useEffect(() => {
    const id = setInterval(() => setNow(new Date()), 30_000);
    return () => clearInterval(id);
  }, []);
  const sessionId = useMemo(
    () => "0x" + Math.floor(Math.random() * 0xffff).toString(16).toUpperCase().padStart(4, "0"),
    []
  );
  const time = now.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  const day  = now.toLocaleDateString([], { weekday: "short", month: "short", day: "2-digit" });

  return (
    <section className="relative overflow-hidden rounded-md border border-border bg-card/40">
      <div className="absolute inset-0 ba-hero-fx opacity-40" aria-hidden />
      <AnimatedGrid cols={32} rows={6} active={7} />
      <div className="relative flex flex-wrap items-center gap-x-4 gap-y-2 px-3 py-2.5 text-mono text-[11.5px]">
        <span className="inline-flex items-center gap-1.5 rounded border border-success/40 bg-success/10 px-1.5 py-0.5 text-[10px] uppercase tracking-widest text-success">
          <CircleDot className="h-2.5 w-2.5 animate-pulse" /> ready
        </span>
        <StripCell label="session" value={sessionId} accent />
        <StripCell label="clock" value={`${day} · ${time}`} />
        <StripCell label="env" value="local · browser" icon={Cpu} />
        <StripCell label="net" value="offline-safe" icon={WifiOff} tone="muted" />
        <div className="ml-auto flex items-center gap-2">
          <span className="text-[10px] uppercase tracking-[0.22em] text-muted-foreground">
            no upload · no detonation
          </span>
        </div>
      </div>
      <div className="border-t border-border/50 bg-background/40">
        <Marquee speed={45} className="py-1.5">
          {SIGNALS.map((s, i) => (
            <span key={i} className="mx-3 inline-flex items-center gap-1.5 text-mono text-[10.5px] text-muted-foreground">
              <CircleDot className="h-2 w-2 text-primary/70" /> {s}
            </span>
          ))}
        </Marquee>
      </div>
    </section>
  );
}


function StripCell({
  label, value, accent, icon: Icon, tone,
}: { label: string; value: string; accent?: boolean; icon?: LucideIcon; tone?: "muted" }) {
  return (
    <div className="flex items-center gap-1.5">
      {Icon && <Icon className="h-3 w-3 text-muted-foreground" />}
      <span className="text-[9.5px] uppercase tracking-[0.22em] text-muted-foreground">{label}</span>
      <span className={
        "ba-text-base font-semibold " +
        (accent ? "text-primary" : tone === "muted" ? "text-foreground/70" : "text-foreground")
      }>{value}</span>
    </div>
  );
}

/* ------------------------------ Continue row ------------------------------ */

function ContinueRow({ item }: { item?: WorkspaceItem }) {
  return (
    <section className="grid gap-2.5 lg:grid-cols-[minmax(0,1.4fr)_minmax(0,1fr)]">
      {/* Continue */}
      {item ? (
        <Link
          to={item.url}
          className="group flex items-center gap-3 rounded-md border border-border bg-card/50 p-3 transition-colors hover:border-primary/50 hover:bg-card/70"
        >
          <span className="grid h-11 w-11 shrink-0 place-items-center rounded-md border border-primary/40 bg-primary/10 text-primary">
            <item.icon className="h-5 w-5" />
          </span>
          <div className="min-w-0 flex-1">
            <div className="text-mono text-[9.5px] uppercase tracking-[0.22em] text-muted-foreground">
              continue · {item.group.toLowerCase()}
            </div>
            <div className="text-mono text-[13.5px] font-semibold text-foreground">{item.title}</div>
            <p className="truncate text-[11.5px] text-muted-foreground">{item.desc}</p>
          </div>
          <span className="inline-flex shrink-0 items-center gap-1 text-mono ba-text-sm text-primary opacity-80 transition-all group-hover:translate-x-0.5">
            resume <ArrowUpRight className="h-3 w-3" />
          </span>
        </Link>
      ) : (
        <div className="flex flex-wrap items-center gap-3 rounded-md border border-dashed border-border bg-card/30 p-3">
          <span className="grid h-11 w-11 shrink-0 place-items-center rounded-md border border-border bg-background/40 text-muted-foreground">
            <Wand2 className="h-5 w-5" />
          </span>
          <div className="min-w-0 flex-1">
            <div className="text-mono text-[9.5px] uppercase tracking-[0.22em] text-muted-foreground">start here</div>
            <div className="text-mono ba-text-base text-foreground">Drop an artifact into Smart Parser</div>
            <p className="truncate text-[11.5px] text-muted-foreground">Open a workspace and it'll become your resume point.</p>
          </div>
          <Link to="/parser" className="inline-flex shrink-0 items-center gap-1 text-mono ba-text-sm text-primary hover:translate-x-0.5 transition-transform">
            open <ArrowUpRight className="h-3 w-3" />
          </Link>
        </div>
      )}

      {/* Quick actions — 2×2 grid keeps labels readable */}
      <div className="grid grid-cols-2 gap-2">
        {QUICK_ACTIONS.map((a) => (
          <Link
            key={a.url}
            to={a.url}
            className="group flex items-center gap-2 rounded-md border border-border bg-card/40 px-2.5 py-2.5 text-mono text-[11.5px] text-foreground transition-all hover:-translate-y-0.5 hover:border-primary/50 hover:bg-card/70"
          >
            <span className="grid h-7 w-7 shrink-0 place-items-center rounded border border-border bg-background/50 text-primary/85 transition-colors group-hover:border-primary/50 group-hover:text-primary">
              <a.icon className="h-3.5 w-3.5" />
            </span>
            <span className="min-w-0 flex-1 truncate">{a.label}</span>
            <kbd className="rounded border border-divider-strong bg-background/60 px-1 text-[9.5px] uppercase tracking-widest text-muted-foreground group-hover:border-primary/40">
              {a.hint}
            </kbd>
          </Link>
        ))}
      </div>
    </section>
  );
}

/* --------------------------------- Track ---------------------------------- */

function TrackCard({ t }: { t: Track }) {
  return (
    <Link
      to={t.url}
      className="group relative flex flex-col overflow-hidden rounded-md border border-border bg-card/60 p-4 transition-all hover:-translate-y-0.5 hover:border-primary/50 hover:bg-card hover:shadow-glow"
    >
      <span className="pointer-events-none absolute inset-0 opacity-0 transition-opacity duration-500 group-hover:opacity-100 ba-shimmer" aria-hidden />
      {/* Corner tag */}
      <span className="absolute right-0 top-0 px-2 py-0.5 text-mono text-[9.5px] tracking-[0.22em] text-muted-foreground border-l border-b border-divider-strong rounded-bl-md bg-background/40">
        track · {t.id}
      </span>

      <div className="grid h-11 w-11 place-items-center rounded-md border border-primary/40 bg-primary/10 text-primary transition-all duration-300 group-hover:rotate-[-4deg] group-hover:border-primary/60">
        <t.icon className="h-5 w-5" />
      </div>

      <div className="mt-3 flex items-baseline justify-between gap-2">
        <h3 className="text-mono text-[15px] font-semibold tracking-tight">{t.label}</h3>
        <span className="text-mono text-[10px] uppercase tracking-[0.18em] text-muted-foreground">{t.tag}</span>
      </div>
      <p className="mt-1.5 text-[12.5px] leading-relaxed text-muted-foreground">{t.blurb}</p>

      {/* Stage rail */}
      <ol className="mt-3 flex items-center gap-0.5">
        {t.stages.map((s, i) => (
          <li key={s} className="flex flex-1 items-center gap-0.5">
            <span className="grid h-4 w-4 place-items-center rounded-full border border-border bg-background/70 text-mono text-[9px] text-muted-foreground transition-colors group-hover:border-primary/50 group-hover:text-primary">
              {i + 1}
            </span>
            <span className="text-mono text-[10px] uppercase tracking-widest text-muted-foreground/90 transition-colors group-hover:text-foreground/90">
              {s}
            </span>
            {i < t.stages.length - 1 && <span className="mx-0.5 h-px flex-1 bg-border/70 group-hover:bg-primary/30" />}
          </li>
        ))}
      </ol>

      <div className="mt-4 flex items-center gap-1.5 text-mono ba-text-sm text-primary opacity-70 transition-all group-hover:translate-x-0.5 group-hover:opacity-100">
        open track <ArrowUpRight className="h-3 w-3" />
      </div>
    </Link>
  );
}

/* ------------------------------ Module tile ------------------------------- */

function ModuleTile({ m }: { m: WorkspaceItem }) {
  return (
    <Link
      to={m.url}
      className="group relative flex flex-col overflow-hidden rounded-md border border-divider-strong bg-card/40 p-3 transition-all hover:-translate-y-0.5 hover:border-primary/50 hover:bg-card/70 hover:shadow-glow"
    >
      <div className="flex items-center gap-2">
        <span className="grid h-8 w-8 shrink-0 place-items-center rounded border border-border bg-background/60 text-primary/90 transition-colors group-hover:border-primary/50 group-hover:text-primary">
          <m.icon className="h-3.5 w-3.5" />
        </span>
        <span className="ml-auto text-mono text-[9px] uppercase tracking-[0.22em] text-muted-foreground/80">
          {m.group}
        </span>
      </div>
      <div className="mt-2 text-mono text-[12.5px] font-semibold leading-tight text-foreground">{m.title}</div>
      <p className="mt-1 line-clamp-2 text-[11px] leading-snug text-muted-foreground">{m.desc}</p>
      <div className="mt-2 flex items-center text-mono text-[10px] text-muted-foreground opacity-0 transition-all group-hover:opacity-100">
        open <ArrowUpRight className="ml-1 h-3 w-3" />
      </div>
    </Link>
  );
}

/* ----------------------------- Pinned chip rail ---------------------------- */

function PinnedRail({ items }: { items: WorkspaceItem[] }) {
  return (
    <section className="flex items-center gap-2 overflow-x-auto rounded-md border border-divider-strong bg-card/30 px-3 py-2">
      <span className="text-mono flex shrink-0 items-center gap-1.5 text-[10px] uppercase tracking-[0.22em] text-muted-foreground">
        <Pin className="h-3 w-3" /> pinned
      </span>
      <div className="h-4 w-px shrink-0 bg-border/70" />
      <div className="flex flex-wrap items-center gap-1.5">
        {items.map((it) => (
          <Link
            key={it.url}
            to={it.url}
            className="group inline-flex items-center gap-1.5 rounded border border-border bg-background/50 px-2 py-1 text-mono text-[11.5px] text-foreground transition-all hover:-translate-y-0.5 hover:border-primary/50 hover:text-primary"
          >
            <it.icon className="h-3 w-3 text-primary/80" />
            {it.title}
          </Link>
        ))}
      </div>
    </section>
  );
}

/* ------------------------------ Building blocks ---------------------------- */

function Panel({
  label, icon: Icon, right, children, className,
}: { label: string; icon: LucideIcon; right?: React.ReactNode; children: React.ReactNode; className?: string }) {
  return (
    <section className={"overflow-hidden rounded-md border border-divider-strong bg-card/40 " + (className ?? "")}>
      <header className="flex items-center gap-2 border-b border-divider-strong px-3 py-2">
        <span className="grid h-5 w-5 place-items-center rounded-sm border border-primary/40 bg-primary/10 text-primary">
          <Icon className="h-3 w-3" strokeWidth={2.25} />
        </span>
        <h3 className="text-mono ba-text-sm uppercase tracking-[0.22em] text-foreground/90">{label}</h3>
        <div className="ml-auto">{right}</div>
      </header>
      {children}
    </section>
  );
}

function SectionHeader({ icon: Icon, label, hint }: { icon: LucideIcon; label: string; hint?: React.ReactNode }) {
  return (
    <div className="mb-3 flex items-center gap-3">
      <span className="grid h-5 w-5 place-items-center rounded-sm border border-primary/40 bg-primary/10 text-primary">
        <Icon className="h-3 w-3" strokeWidth={2.25} />
      </span>
      <h2 className="text-mono ba-text-sm uppercase tracking-[0.22em] text-foreground/90">{label}</h2>
      <div className="h-px flex-1 border-t border-dashed border-border" />
      {hint && <span className="text-mono text-[10px] tracking-widest text-muted-foreground">{hint}</span>}
    </div>
  );
}

function EmptyHint({ icon: Icon, text }: { icon: LucideIcon; text: string }) {
  return (
    <div className="flex items-center gap-2 px-3 py-5 text-mono text-[11.5px] text-muted-foreground">
      <Icon className="h-3.5 w-3.5" />
      {text}
    </div>
  );
}

function ShortcutRow({ keys, label }: { keys: string[]; label: string }) {
  return (
    <div className="flex items-center gap-2 px-3 py-1.5 text-mono text-[11.5px]">
      <span className="min-w-0 flex-1 text-foreground/90">{label}</span>
      <span className="flex items-center gap-1">
        {keys.map((k, i) => (
          <kbd key={i} className="rounded border border-divider-strong bg-background/60 px-1.5 py-px text-[10px] uppercase tracking-widest text-muted-foreground">
            {k}
          </kbd>
        ))}
      </span>
    </div>
  );
}

function RotatingTip() {
  const [i, setI] = useState(0);
  useEffect(() => {
    const id = setInterval(() => setI((x) => (x + 1) % TIPS.length), 6000);
    return () => clearInterval(id);
  }, []);
  return (
    <p key={i} className="ba-fade-in ba-text-base leading-relaxed text-foreground/85">
      {TIPS[i]}
    </p>
  );
}
