import { createFileRoute } from "@tanstack/react-router";
import { useMemo, useState } from "react";
import { PageShell } from "@/components/PageShell";
import { Panel, SectionBar, Chip } from "@/components/soc";
import { Empty } from "@/components/output";
import { getTimelineEvents, clearTimeline, type TimelineEvent } from "@/lib/timeline";
import { Trash2, Clock, Filter, X } from "lucide-react";

export const Route = createFileRoute("/timeline")({ component: TimelinePage });

const SOURCE_COLORS: Record<string, "primary" | "warning" | "success" | "destructive" | "info" | "default"> = {
  nmap: "destructive",
  parser: "warning",
  url: "primary",
  phishing: "warning",
  recon: "info",
};

function dateGroup(ts: string): string {
  const d = new Date(ts);
  const now = new Date();
  const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
  const yesterday = new Date(today.getTime() - 86400000);
  const eventDate = new Date(d.getFullYear(), d.getMonth(), d.getDate());
  if (eventDate.getTime() === today.getTime()) return "Today";
  if (eventDate.getTime() === yesterday.getTime()) return "Yesterday";
  return d.toLocaleDateString("en-US", { month: "long", day: "numeric", year: "numeric" });
}

function formatTime(ts: string): string {
  const d = new Date(ts);
  return `${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}`;
}

function TimelinePage() {
  const [filterSource, setFilterSource] = useState<string | null>(null);
  const [refreshKey, setRefreshKey] = useState(0);

  const events = useMemo(() => {
    const all = getTimelineEvents();
    return filterSource ? all.filter((e) => e.source === filterSource) : all;
  }, [filterSource, refreshKey]);

  const sources = useMemo(() => {
    const s = new Set(getTimelineEvents().map((e) => e.source));
    return Array.from(s).sort();
  }, [refreshKey]);

  const grouped = useMemo(() => {
    const map = new Map<string, TimelineEvent[]>();
    for (const e of events) {
      const g = dateGroup(e.ts);
      if (!map.has(g)) map.set(g, []);
      map.get(g)!.push(e);
    }
    return Array.from(map.entries());
  }, [events]);

  function handleClear() {
    clearTimeline();
    setRefreshKey((k) => k + 1);
  }

  return (
    <PageShell
      eyebrow="OPS / TIMELINE"
      title="Investigation Timeline"
      description="Auto-captured history of every tool action across workspaces — no manual entry needed."
      crumbs={[{ label: "Ops" }, { label: "Timeline" }]}
      meta={[
        { label: "events", value: String(getTimelineEvents().length), tone: "primary" },
        ...(filterSource ? [{ label: "filter", value: filterSource, tone: "warning" as const }] : []),
      ]}
      actions={
        getTimelineEvents().length > 0 ? (
          <button onClick={handleClear} className="inline-flex items-center gap-1.5 rounded-md border border-destructive/40 bg-destructive/10 px-2.5 py-1 text-mono ba-text-2xs uppercase tracking-widest text-destructive hover:bg-destructive/20">
            <Trash2 className="h-3 w-3" /> clear timeline
          </button>
        ) : undefined
      }
    >
      {sources.length > 0 && (
        <div className="flex flex-wrap items-center gap-1.5 mb-4">
          <Filter className="h-3 w-3 text-muted-foreground" />
          <button onClick={() => setFilterSource(null)} className={"rounded border px-2 py-0.5 text-mono ba-text-2xs uppercase tracking-widest transition-colors " + (!filterSource ? "border-primary bg-primary/15 text-primary" : "border-divider-strong bg-card/40 text-muted-foreground hover:text-foreground")}>all</button>
          {sources.map((s) => (
            <button key={s} onClick={() => setFilterSource(s === filterSource ? null : s)} className={"rounded border px-2 py-0.5 text-mono ba-text-2xs uppercase tracking-widest transition-colors " + (filterSource === s ? "border-primary bg-primary/15 text-primary" : "border-divider-strong bg-card/40 text-muted-foreground hover:text-foreground")}>
              {s}
              {filterSource === s && <X className="ml-1 inline h-2.5 w-2.5" />}
            </button>
          ))}
        </div>
      )}

      {events.length === 0 ? (
        <Empty icon={Clock} title="No timeline events yet" hint="Run tools across workspaces — events auto-capture here. Try Nmap, Parser, URL Analyzer, Phishing Triage, or Recon." />
      ) : (
        <div className="space-y-6">
          {grouped.map(([group, items]) => (
            <div key={group}>
              <SectionBar id="DT" label={group} meta={`${items.length} event${items.length === 1 ? "" : "s"}`} priority="secondary" />
              <Panel bodyClassName="p-0">
                <ul className="divide-y divide-border/50">
                  {items.map((e) => (
                    <li key={e.id} className="grid grid-cols-[60px_auto_1fr] items-start gap-3 px-4 py-2.5 hover:bg-card/30">
                      <div className="text-mono ba-text-2xs text-muted-foreground tabular-nums pt-0.5">{formatTime(e.ts)}</div>
                      <div className="flex items-center gap-1.5 flex-wrap pt-0.5">
                        <Chip tone={SOURCE_COLORS[e.source] ?? "default"}>{e.source}</Chip>
                        <span className="text-mono ba-text-sm font-semibold text-foreground/90">{e.verb}</span>
                      </div>
                      <div className="min-w-0 pt-0.5">
                        <div className="text-mono ba-text-sm text-foreground/80">{e.detail}</div>
                        {(e.target || e.result) && (
                          <div className="mt-0.5 flex flex-wrap items-center gap-2 text-mono ba-text-2xs text-muted-foreground">
                            {e.target && <code className="truncate max-w-[240px] rounded border border-border/50 bg-background/40 px-1.5 py-0.5">{e.target}</code>}
                            {e.result && <span className="text-muted-foreground/70">→ {e.result}</span>}
                          </div>
                        )}
                      </div>
                    </li>
                  ))}
                </ul>
              </Panel>
            </div>
          ))}
        </div>
      )}
    </PageShell>
  );
}
