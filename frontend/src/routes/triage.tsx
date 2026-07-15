import { createFileRoute } from "@tanstack/react-router";
import { useCallback, useEffect, useMemo, useState } from "react";
import { PageShell } from "@/components/PageShell";
import { Panel, SectionBar, SendToRow, Chip } from "@/components/soc";
import { StatusBar } from "@/components/output";
import { usePanelNav } from "@/lib/usePanelNav";
import { sendToCase } from "@/lib/handoff";
import { pushTimelineEvent } from "@/lib/timeline";
import { copyText } from "@/lib/copy";
import { toast } from "sonner";
import { ChartContainer, ChartTooltip, ChartTooltipContent, type ChartConfig } from "@/components/ui/chart";
import { PieChart, Pie, Cell } from "recharts";
import {
  AlertTriangle, CheckCircle, XCircle, Eye, ArrowUpRight,
  Trash2, Plus, MessageSquare, Download,
} from "lucide-react";
import { type Severity } from "@/lib/severity";
import {
  type TriageItem, type TriageStatus,
  STATUS_TONE, STATUS_ORDER, STATUSES,
  loadItems, saveItems, genId, statusLabel,
} from "@/data/triage";

export const Route = createFileRoute("/triage")({ component: TriagePage });

const SEV_ORDER: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

function TriagePage() {
  const [items, setItems] = useState<TriageItem[]>(() => loadItems());
  const [filterStatus, setFilterStatus] = useState<TriageStatus | "all">("all");
  const [filterSev, setFilterSev] = useState<Severity | "all">("all");
  const [sortBy, setSortBy] = useState<"ts" | "severity" | "status">("ts");
  const [newTitle, setNewTitle] = useState("");
  const [newDesc, setNewDesc] = useState("");
  const [newSev, setNewSev] = useState<Severity>("medium");
  const [noteDraft, setNoteDraft] = useState("");

  const persist = useCallback((next: TriageItem[]) => {
    setItems(next);
    saveItems(next);
  }, []);

  const addItem = useCallback(() => {
    if (!newTitle.trim()) { toast.error("Title is required"); return; }
    const item: TriageItem = {
      id: genId(),
      ts: new Date().toISOString(),
      title: newTitle.trim(),
      description: newDesc.trim(),
      severity: newSev,
      source: "manual",
      status: "open",
      notes: "",
      tags: [],
      updated: Date.now(),
    };
    persist([item, ...items]);
    setNewTitle("");
    setNewDesc("");
    setNewSev("medium");
    toast.success("Item added to triage queue");
    pushTimelineEvent({ source: "triage", verb: "added", detail: item.title, target: "triage", result: statusLabel("open") });
  }, [newTitle, newDesc, newSev, items, persist]);

  const updateStatus = useCallback((id: string, status: TriageStatus) => {
    const next = items.map((i) => i.id === id ? { ...i, status, updated: Date.now() } : i);
    persist(next);
    pushTimelineEvent({ source: "triage", verb: "status_changed", detail: `${items.find((i) => i.id === id)?.title} → ${statusLabel(status)}`, target: "triage" });
    if (status === "escalated") {
      const item = items.find((i) => i.id === id);
      if (item) {
        sendToCase({ body: `**Escalated from Triage**\n\n**${item.title}**\n${item.description}\n\n*Source: ${item.source}*`, source: "triage", kind: "decision" });
        toast.success("Escalated to case");
      }
    }
  }, [items, persist]);

  const addNote = useCallback((id: string) => {
    if (!noteDraft.trim()) return;
    const next = items.map((i) => i.id === id ? { ...i, notes: i.notes + (i.notes ? "\n---\n" : "") + `[${new Date().toLocaleString()}] ${noteDraft.trim()}`, updated: Date.now() } : i);
    persist(next);
    setNoteDraft("");
    toast.success("Note added");
  }, [noteDraft, items, persist]);

  const removeItem = useCallback((id: string) => {
    const next = items.filter((i) => i.id !== id);
    persist(next);
    toast.success("Item removed");
  }, [items, persist]);

  const exportQueue = useCallback(() => {
    const blob = new Blob([JSON.stringify(items, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = `triage-queue-${new Date().toISOString().slice(0, 10)}.json`;
    a.click(); URL.revokeObjectURL(url);
    toast.success("Queue exported");
  }, [items]);

  const filtered = useMemo(() => {
    let result = [...items];
    if (filterStatus !== "all") result = result.filter((i) => i.status === filterStatus);
    if (filterSev !== "all") result = result.filter((i) => i.severity === filterSev);
    if (sortBy === "ts") result.sort((a, b) => new Date(b.ts).getTime() - new Date(a.ts).getTime());
    else if (sortBy === "severity") result.sort((a, b) => SEV_ORDER[b.severity] - SEV_ORDER[a.severity]);
    else if (sortBy === "status") result.sort((a, b) => STATUS_ORDER[a.status] - STATUS_ORDER[b.status]);
    return result;
  }, [items, filterStatus, filterSev, sortBy]);

  const { index, setIndex, selected } = usePanelNav(filtered, {
    onCopy: (item) => {
      const text = `${item.title}\n${item.description}\nSev: ${item.severity} | Status: ${statusLabel(item.status)}`;
      copyText(text);
      toast.success("Copied to clipboard");
    },
    onAttach: (item) => {
      sendToCase({ body: `**From Triage Queue**\n\n**${item.title}**\n${item.description}\n\n*Severity: ${item.severity} | Source: ${item.source}*`, source: "triage", kind: "evidence" });
      toast.success("Sent to case");
    },
  });

  useEffect(() => {
    function handleKey(e: KeyboardEvent) {
      if (e.key === "Escape") { setIndex(-1); }
    }
    window.addEventListener("keydown", handleKey);
    return () => window.removeEventListener("keydown", handleKey);
  }, [setIndex]);

  const counts = useMemo(() => ({
    total: items.length,
    open: items.filter((i) => i.status === "open").length,
    in_review: items.filter((i) => i.status === "in_review").length,
    escalated: items.filter((i) => i.status === "escalated").length,
    dismissed: items.filter((i) => i.status === "dismissed").length,
    high: items.filter((i) => i.severity === "high" || i.severity === "critical").length,
  }), [items]);

  return (
    <PageShell
      eyebrow="// triage"
      title="Triage Queue"
      description="Review, prioritize, and disposition security events. Use j/k to navigate, y to copy, c to send to case."
      crumbs={[{ label: "Triage" }]}
      actions={
        <button onClick={exportQueue} className="inline-flex items-center gap-1.5 rounded border border-border bg-card/60 px-2 py-1 text-mono ba-text-2xs uppercase tracking-widest text-muted-foreground transition-colors hover:border-primary/40 hover:text-foreground">
          <Download className="h-3 w-3" /> export
        </button>
      }
    >
      <StatusBar
        stats={[
          { label: "total", value: counts.total, tone: counts.total > 0 ? "default" : "muted" },
          { label: "open", value: counts.open, tone: counts.open > 0 ? "warning" : "muted" },
          { label: "in review", value: counts.in_review, tone: counts.in_review > 0 ? "primary" : "muted" },
          { label: "escalated", value: counts.escalated, tone: counts.escalated > 0 ? "destructive" : "muted" },
          { label: "dismissed", value: counts.dismissed, tone: "muted" },
          { label: "high/critical", value: counts.high, tone: counts.high > 0 ? "destructive" : "muted" },
        ]}
      />

      <SectionBar id="IN" label="intake" icon={Plus} meta="add item">
        <div className="mt-3 space-y-3">
          <div className="flex gap-3">
            <input
              value={newTitle}
              onChange={(e) => setNewTitle(e.target.value)}
              onKeyDown={(e) => { if (e.key === "Enter") addItem(); }}
              placeholder="Item title…"
              className="min-w-0 flex-1 rounded border border-border bg-background/60 px-3 py-2 text-mono ba-text-sm text-foreground outline-none placeholder:text-muted-foreground/60 focus:border-primary/50"
            />
            <select
              value={newSev}
              onChange={(e) => setNewSev(e.target.value as Severity)}
              className="w-28 appearance-none rounded border border-border bg-card/60 px-2 py-2 text-mono ba-text-2xs uppercase tracking-widest text-foreground outline-none"
            >
              <option value="info">info</option>
              <option value="low">low</option>
              <option value="medium">medium</option>
              <option value="high">high</option>
              <option value="critical">critical</option>
            </select>
            <button
              onClick={addItem}
              className="inline-flex items-center gap-1.5 rounded border border-primary/50 bg-primary/10 px-3 py-2 text-mono ba-text-2xs uppercase tracking-widest text-primary transition-colors hover:bg-primary/20"
            >
              <Plus className="h-3 w-3" /> add
            </button>
          </div>
          <textarea
            value={newDesc}
            onChange={(e) => setNewDesc(e.target.value)}
            placeholder="Description (optional)…"
            rows={2}
            className="w-full resize-none rounded border border-border bg-background/60 px-3 py-2 text-mono ba-text-sm text-foreground outline-none placeholder:text-muted-foreground/60 focus:border-primary/50"
          />
        </div>
      </SectionBar>

      <SectionBar id="FL" label="filter" icon={AlertTriangle}>
        <div className="mt-3 flex flex-wrap items-center gap-2">
          <span className="text-mono ba-text-2xs uppercase tracking-widest text-muted-foreground">status</span>
          {["all" as const, ...STATUSES].map((s) => (
            <button
              key={s}
              onClick={() => setFilterStatus(s)}
              className={"rounded border px-2 py-1 text-mono ba-text-2xs uppercase tracking-widest transition-colors " + (filterStatus === s ? "border-primary bg-primary/15 text-primary" : "border-border/50 text-muted-foreground hover:text-foreground")}
            >
              {s === "all" ? "all" : statusLabel(s)}
            </button>
          ))}
          <span className="ml-2 text-mono ba-text-2xs uppercase tracking-widest text-muted-foreground">severity</span>
          {["all" as const, "info", "low", "medium", "high", "critical"].map((s) => (
            <button
              key={s}
              onClick={() => setFilterSev(s as Severity | "all")}
              className={"rounded border px-2 py-1 text-mono ba-text-2xs uppercase tracking-widest transition-colors " + (filterSev === s ? "border-primary bg-primary/15 text-primary" : "border-border/50 text-muted-foreground hover:text-foreground")}
            >
              {s}
            </button>
          ))}
          <span className="ml-2 text-mono ba-text-2xs uppercase tracking-widest text-muted-foreground">sort</span>
          <select
            value={sortBy}
            onChange={(e) => setSortBy(e.target.value as "ts" | "severity" | "status")}
            className="rounded border border-border bg-card/60 px-2 py-1 text-mono ba-text-2xs uppercase tracking-widest text-foreground outline-none"
          >
            <option value="ts">newest</option>
            <option value="severity">severity</option>
            <option value="status">status</option>
          </select>
        </div>
      </SectionBar>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-[1fr_380px]">
        <div className="space-y-1">
          {filtered.length === 0 ? (
            <div className="flex items-center justify-center rounded border border-dashed border-border/50 bg-background/30 py-12">
              <span className="text-mono ba-text-2xs uppercase tracking-widest text-muted-foreground/60">
                {items.length === 0 ? "queue is empty — add items above" : "no items match filters"}
              </span>
            </div>
          ) : (
            filtered.map((item, i) => (
              <div
                key={item.id}
                onClick={() => setIndex(i)}
                className={"group flex cursor-pointer items-start gap-3 rounded-md border px-3 py-2.5 transition-all " + (index === i ? "border-primary/60 bg-primary/[0.06] shadow-[0_0_12px_-4px_hsl(var(--primary)/0.3)]" : "border-transparent bg-transparent hover:border-border/60 hover:bg-accent/10")}
              >
                <div className="flex h-5 w-5 shrink-0 items-center justify-center">
                  {item.status === "dismissed" ? <XCircle className="h-4 w-4 text-muted-foreground/50" /> :
                   item.status === "escalated" ? <ArrowUpRight className="h-4 w-4 text-destructive" /> :
                   item.status === "in_review" ? <Eye className="h-4 w-4 text-primary" /> :
                   <AlertTriangle className={"h-4 w-4 " + (item.severity === "high" || item.severity === "critical" ? "text-destructive" : item.severity === "medium" ? "text-warning" : "text-muted-foreground")} />}
                </div>
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <span className="truncate text-mono ba-text-sm font-medium text-foreground">{item.title}</span>
                    <Chip tone={item.severity === "critical" || item.severity === "high" ? "destructive" : item.severity === "medium" ? "warning" : "default"}>
                      {item.severity}
                    </Chip>
                    <Chip tone={STATUS_TONE[item.status] as "default" | "warning" | "destructive" | "info" | "success"}>
                      {statusLabel(item.status)}
                    </Chip>
                  </div>
                  {item.description && (
                    <div className="mt-0.5 truncate text-mono ba-text-sm text-muted-foreground/70">{item.description}</div>
                  )}
                  <div className="mt-0.5 flex items-center gap-2 text-mono ba-text-2xs text-muted-foreground/50">
                    <span>{new Date(item.ts).toLocaleString()}</span>
                    <span>·</span>
                    <span className="capitalize">{item.source}</span>
                    {item.notes && <><span>·</span><span>{item.notes.split("\n").length} note(s)</span></>}
                  </div>
                </div>
                <div className="flex shrink-0 items-center gap-1 opacity-0 transition-opacity group-hover:opacity-100">
                  {item.status === "open" && (
                    <button onClick={(e) => { e.stopPropagation(); updateStatus(item.id, "in_review"); }} title="Review" className="rounded p-1 text-muted-foreground hover:bg-primary/10 hover:text-primary">
                      <Eye className="h-3.5 w-3.5" />
                    </button>
                  )}
                  {item.status === "in_review" && (
                    <button onClick={(e) => { e.stopPropagation(); updateStatus(item.id, "escalated"); }} title="Escalate to case" className="rounded p-1 text-muted-foreground hover:bg-destructive/10 hover:text-destructive">
                      <ArrowUpRight className="h-3.5 w-3.5" />
                    </button>
                  )}
                  {(item.status === "open" || item.status === "in_review") && (
                    <button onClick={(e) => { e.stopPropagation(); updateStatus(item.id, "dismissed"); }} title="Dismiss" className="rounded p-1 text-muted-foreground hover:bg-muted-foreground/10 hover:text-muted-foreground">
                      <XCircle className="h-3.5 w-3.5" />
                    </button>
                  )}
                  <button onClick={(e) => { e.stopPropagation(); removeItem(item.id); }} title="Remove" className="rounded p-1 text-muted-foreground hover:bg-destructive/10 hover:text-destructive">
                    <Trash2 className="h-3.5 w-3.5" />
                  </button>
                </div>
              </div>
            ))
          )}
        </div>

        <div className="space-y-4">
          {/* Severity distribution donut */}
          {items.length > 0 && (() => {
            const sevChartConfig = {
              critical: { label: "Critical", color: "hsl(var(--destructive))" },
              high: { label: "High", color: "hsl(0 72% 51% / 0.7)" },
              medium: { label: "Medium", color: "hsl(var(--warning))" },
              low: { label: "Low", color: "hsl(var(--success))" },
              info: { label: "Info", color: "hsl(var(--muted-foreground) / 0.4)" },
            } satisfies ChartConfig;
            const pieData = (["critical", "high", "medium", "low", "info"] as const)
              .map((s) => ({ name: s, value: items.filter((i) => i.severity === s).length, color: sevChartConfig[s].color }))
              .filter((d) => d.value > 0);
            if (pieData.length === 0) return null;
            return (
              <Panel title="Severity Distribution" icon={AlertTriangle} priority="secondary" collapsible>
                <ChartContainer config={sevChartConfig} className="mx-auto aspect-square w-full max-w-[200px]">
                  <PieChart>
                    <Pie data={pieData} dataKey="value" nameKey="name" cx="50%" cy="50%" innerRadius={45} outerRadius={80} paddingAngle={2}>
                      {pieData.map((entry, i) => (
                        <Cell key={i} fill={entry.color} />
                      ))}
                    </Pie>
                    <ChartTooltip content={<ChartTooltipContent />} />
                  </PieChart>
                </ChartContainer>
                <div className="mt-1 flex flex-wrap justify-center gap-2">
                  {pieData.map((d) => (
                    <div key={d.name} className="flex items-center gap-1">
                      <span className="h-2 w-2 rounded-sm" style={{ backgroundColor: d.color }} />
                      <span className="text-mono ba-text-2xs capitalize text-muted-foreground">{d.name}</span>
                      <span className="text-mono ba-text-sm font-medium text-foreground/90">{d.value}</span>
                    </div>
                  ))}
                </div>
              </Panel>
            );
          })()}

          {selected ? (
            <Panel title="Detail" icon={AlertTriangle}>
              <div className="space-y-3">
                <div>
                  <div className="flex items-center gap-2">
                    <h3 className="text-mono ba-text-base font-bold text-foreground">{selected.title}</h3>
                  </div>
                </div>

                <div className="flex flex-wrap gap-2">
                  <Chip tone={selected.severity === "critical" || selected.severity === "high" ? "destructive" : selected.severity === "medium" ? "warning" : "default"}>
                    {selected.severity}
                  </Chip>
                  <Chip tone={STATUS_TONE[selected.status] as "default" | "warning" | "destructive" | "info" | "success"}>
                    {statusLabel(selected.status)}
                  </Chip>
                  <Chip tone="default">{selected.source}</Chip>
                </div>

                {selected.description && (
                  <div>
                    <div className="text-mono ba-text-2xs uppercase tracking-widest text-muted-foreground">description</div>
                    <p className="mt-1 text-mono ba-text-sm text-foreground/80 whitespace-pre-wrap">{selected.description}</p>
                  </div>
                )}

                <div className="space-y-1">
                  <div className="flex gap-2">
                    {selected.status === "open" && (
                      <button onClick={() => updateStatus(selected.id, "in_review")} className="inline-flex items-center gap-1.5 rounded border border-primary/50 bg-primary/10 px-2.5 py-1.5 text-mono ba-text-2xs uppercase tracking-widest text-primary transition-colors hover:bg-primary/20">
                        <Eye className="h-3 w-3" /> start review
                      </button>
                    )}
                    {selected.status === "in_review" && (
                      <button onClick={() => updateStatus(selected.id, "escalated")} className="inline-flex items-center gap-1.5 rounded border border-destructive/50 bg-destructive/10 px-2.5 py-1.5 text-mono ba-text-2xs uppercase tracking-widest text-destructive transition-colors hover:bg-destructive/20">
                        <ArrowUpRight className="h-3 w-3" /> escalate to case
                      </button>
                    )}
                    {(selected.status === "open" || selected.status === "in_review") && (
                      <button onClick={() => updateStatus(selected.id, "dismissed")} className="inline-flex items-center gap-1.5 rounded border border-border bg-card/60 px-2.5 py-1.5 text-mono ba-text-2xs uppercase tracking-widest text-muted-foreground transition-colors hover:text-foreground">
                        <XCircle className="h-3 w-3" /> dismiss
                      </button>
                    )}
                    {selected.status === "dismissed" && (
                      <button onClick={() => updateStatus(selected.id, "open")} className="inline-flex items-center gap-1.5 rounded border border-border bg-card/60 px-2.5 py-1.5 text-mono ba-text-2xs uppercase tracking-widest text-muted-foreground transition-colors hover:text-foreground">
                        <CheckCircle className="h-3 w-3" /> reopen
                      </button>
                    )}
                  </div>
                </div>

                <div>
                  <div className="text-mono ba-text-2xs uppercase tracking-widest text-muted-foreground">notes</div>
                  <div className="mt-1 max-h-32 overflow-y-auto whitespace-pre-wrap text-mono ba-text-sm text-foreground/70">
                    {selected.notes || <span className="italic text-muted-foreground/50">No notes</span>}
                  </div>
                  <div className="mt-2 flex gap-2">
                    <textarea
                      value={noteDraft}
                      onChange={(e) => setNoteDraft(e.target.value)}
                      placeholder="Add note…"
                      rows={2}
                      className="min-w-0 flex-1 resize-none rounded border border-border bg-background/60 px-2 py-1.5 text-mono ba-text-sm text-foreground outline-none placeholder:text-muted-foreground/60 focus:border-primary/50"
                    />
                    <button
                      onClick={() => addNote(selected.id)}
                      disabled={!noteDraft.trim()}
                      className="inline-flex items-center gap-1 rounded border border-primary/50 bg-primary/10 px-2 py-1.5 text-mono ba-text-2xs uppercase tracking-widest text-primary transition-colors hover:bg-primary/20 disabled:opacity-40"
                    >
                      <MessageSquare className="h-3 w-3" /> add
                    </button>
                  </div>
                </div>

                <div className="border-t border-border pt-2 text-mono ba-text-2xs text-muted-foreground/60">
                  <div>Created: {new Date(selected.ts).toLocaleString()}</div>
                  <div>Updated: {new Date(selected.updated).toLocaleString()}</div>
                  <div>ID: {selected.id}</div>
                </div>
              </div>
            </Panel>
          ) : (
            <Panel title="Detail" icon={AlertTriangle}>
              <div className="flex items-center justify-center py-12">
                <span className="text-mono ba-text-2xs uppercase tracking-widest text-muted-foreground/60">
                  {filtered.length > 0 ? "select an item (j/k)" : "queue is empty"}
                </span>
              </div>
            </Panel>
          )}
        </div>
      </div>

      <SendToRow
        targets={[
          { label: "Case & Report", to: "/case", icon: ArrowUpRight, onClick: () => { if (selected) { sendToCase({ body: `**From Triage Queue**\n\n**${selected.title}**\n${selected.description}\n\n*Severity: ${selected.severity} | Source: ${selected.source}*`, source: "triage", kind: "evidence" }); toast.success("Sent to case"); } } },
          { label: "Detection", to: "/detection", icon: AlertTriangle },
          { label: "SIEM", to: "/siem", icon: Eye },
        ]}
      />
    </PageShell>
  );
}
