import { createFileRoute } from "@tanstack/react-router";
import { useCallback, useEffect, useMemo, useState } from "react";
import { PageShell } from "@/components/PageShell";
import { SectionBar, Chip } from "@/components/soc";
import { Empty } from "@/components/output";
import { getTimelineEvents, clearTimeline, type TimelineEvent } from "@/lib/timeline";
import { toast } from "sonner";
import { Activity, Search, Trash2, RefreshCw, Download } from "lucide-react";

export const Route = createFileRoute("/activity")({ component: ActivityPage });

function groupEvents(events: TimelineEvent[]): { label: string; events: TimelineEvent[] }[] {
  const now = new Date();
  const today = now.toDateString();
  const yesterday = new Date(now);
  yesterday.setDate(yesterday.getDate() - 1);
  const yStr = yesterday.toDateString();
  const groups = new Map<string, TimelineEvent[]>();
  for (const ev of events) {
    const d = new Date(ev.ts);
    const key = d.toDateString() === today ? "Today" : d.toDateString() === yStr ? "Yesterday" : d.toLocaleDateString("en-US", { weekday: "long", month: "long", day: "numeric" });
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key)!.push(ev);
  }
  return Array.from(groups.entries()).map(([label, evts]) => ({ label, events: evts }));
}

function ActivityPage() {
  const [events, setEvents] = useState<TimelineEvent[]>([]);
  const [filterSource, setFilterSource] = useState<string>("all");
  const [searchText, setSearchText] = useState("");

  useEffect(() => {
    function handleKey(e: KeyboardEvent) {
      if (e.key === "Escape" && searchText) { setSearchText(""); }
    }
    window.addEventListener("keydown", handleKey);
    return () => window.removeEventListener("keydown", handleKey);
  }, [searchText]);

  const refresh = useCallback(() => {
    const all = getTimelineEvents();
    all.sort((a, b) => new Date(b.ts).getTime() - new Date(a.ts).getTime());
    setEvents(all);
  }, []);

  useEffect(() => { refresh(); }, [refresh]);

  useEffect(() => {
    const onFocus = () => refresh();
    const onVisibility = () => { if (!document.hidden) refresh(); };
    window.addEventListener("focus", onFocus);
    document.addEventListener("visibilitychange", onVisibility);
    return () => {
      window.removeEventListener("focus", onFocus);
      document.removeEventListener("visibilitychange", onVisibility);
    };
  }, [refresh]);

  const filtered = useMemo(() => {
    let e = events;
    if (filterSource !== "all") e = e.filter((ev) => ev.source === filterSource);
    if (searchText.trim()) {
      const q = searchText.toLowerCase();
      e = e.filter((ev) =>
        ev.detail.toLowerCase().includes(q) ||
        ev.source.toLowerCase().includes(q) ||
        ev.verb.toLowerCase().includes(q) ||
        (ev.result && ev.result.toLowerCase().includes(q))
      );
    }
    return e;
  }, [events, filterSource, searchText]);

  const sources = useMemo(() => Array.from(new Set(events.map((e) => e.source))).sort(), [events]);
  const stats = useMemo(() => ({
    total: events.length,
    sources: sources.length,
    range: events.length > 1
      ? `${new Date(events[events.length - 1].ts).toLocaleDateString()} — ${new Date(events[0].ts).toLocaleDateString()}`
      : events.length === 1 ? new Date(events[0].ts).toLocaleDateString() : "—",
  }), [events, sources]);

  const grouped = useMemo(() => groupEvents(filtered), [filtered]);

  const sourceTone = (s: string): "default" | "primary" | "warning" | "destructive" | "success" | "info" => {
    const m: Record<string, "default" | "primary" | "warning" | "destructive" | "success" | "info"> = {
      parser: "warning", phishing: "destructive", url: "warning",
      recon: "info", chef: "primary", siem: "info", nmap: "warning",
      sigma: "primary", diff: "info", tool: "default",
    };
    return m[s] || "default";
  };

  function handleExport() {
    const md = [
      "# Activity Feed",
      "",
      `**Total events:** ${stats.total} · **Sources:** ${stats.sources} · **Range:** ${stats.range}`,
      "",
      ...grouped.flatMap((g) => [
        `## ${g.label} (${g.events.length} events)`,
        "",
        ...g.events.map((ev) => {
          const ts = new Date(ev.ts).toLocaleString();
          return `- **${ts}** — \`${ev.source}\` **${ev.verb}** — ${ev.detail}${ev.result ? ` → ${ev.result}` : ""}`;
        }),
        "",
      ]),
    ].join("\n");
    const blob = new Blob([md], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a"); a.href = url; a.download = `activity-${Date.now()}.md`; a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <PageShell
      eyebrow="OPS"
      title="Activity Feed"
      description="Local event log — no sync, no server. Captures every tool run, extraction, and analysis."
      crumbs={[{ label: "Ops" }, { label: "Activity" }]}
      meta={[
        { label: "Events", value: String(stats.total), tone: "primary" },
        { label: "Sources", value: String(stats.sources) },
        { label: "Range", value: stats.range, tone: "muted" },
      ]}
    >
      <div className="flex items-center gap-2 mb-3">
        <div className="relative flex-1">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground/60" />
          <input
            value={searchText}
            onChange={(e) => setSearchText(e.target.value)}
            placeholder="Search events…"
            className="h-8 w-full rounded border border-border bg-background/60 pl-8 pr-2 text-mono text-[11px] text-foreground outline-none placeholder:text-muted-foreground/50 focus:border-primary/50"
          />
        </div>
        <select
          value={filterSource}
          onChange={(e) => setFilterSource(e.target.value)}
          className="h-8 rounded border border-border bg-background/60 px-2 text-mono text-[10px] uppercase tracking-widest text-foreground outline-none focus:border-primary/50"
        >
          <option value="all">All sources</option>
          {sources.map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
        <button onClick={refresh} className="inline-flex h-8 w-8 items-center justify-center rounded border border-border text-muted-foreground hover:text-foreground">
          <RefreshCw className="h-3.5 w-3.5" />
        </button>
        <button onClick={handleExport} className="inline-flex items-center gap-1 rounded border border-border px-2 py-0.5 text-mono ba-text-2xs uppercase text-muted-foreground hover:text-foreground">
          <Download className="h-3 w-3" /> md
        </button>
        <button
          onClick={() => {
            const snapshot = getTimelineEvents();
            clearTimeline();
            refresh();
            toast("Timeline cleared", {
              action: {
                label: "Undo",
                onClick: () => {
                  try { localStorage.setItem("ba.timeline", JSON.stringify(snapshot)); refresh(); } catch {}
                },
              },
            });
          }}
          className="inline-flex h-8 items-center gap-1 rounded border border-destructive/40 bg-destructive/10 px-2 text-mono text-[10px] uppercase tracking-widest text-destructive hover:bg-destructive/20"
        >
          <Trash2 className="h-3 w-3" /> clear
        </button>
      </div>

      {grouped.length === 0 ? (
        <Empty icon={Activity} title="No activity yet" hint="Timeline events are recorded as you use tools: parsing IOCs, analyzing URLs, running nmap scans, etc." />
      ) : (
        <div className="space-y-6">
          {grouped.map((group) => (
            <div key={group.label}>
              <SectionBar id={`DAY-${group.label}`} label={group.label} meta={`${group.events.length} event${group.events.length === 1 ? "" : "s"}`} />
              <div className="relative space-y-0">
                {group.events.map((ev, i) => {
                  const ts = new Date(ev.ts);
                  const timeStr = ts.toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit", second: "2-digit" });
                  return (
                    <div key={ev.id} className="group relative flex gap-3 py-1.5 pl-8 hover:bg-card/20 rounded-sm transition-colors">
                      <div className="absolute left-2.5 top-2.5 flex flex-col items-center">
                        <div className="z-10 h-2 w-2 rounded-full bg-primary/50 ring-2 ring-background" />
                        {i < group.events.length - 1 && <div className="mt-1 h-full w-px bg-border/40" />}
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 flex-wrap">
                          <Chip tone={sourceTone(ev.source)}>{ev.source}</Chip>
                          <span className="text-mono text-[10px] uppercase tracking-widest text-muted-foreground/60">{ev.verb}</span>
                          <span className="ml-auto text-mono text-[10px] text-muted-foreground/40 group-hover:text-muted-foreground/70">{timeStr}</span>
                        </div>
                        <p className="mt-0.5 text-mono ba-text-sm text-foreground/85 leading-snug">{ev.detail}</p>
                        {ev.result && (
                          <p className="mt-0.5 text-mono ba-text-2xs text-muted-foreground/70">{ev.result}</p>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          ))}
        </div>
      )}
    </PageShell>
  );
}
