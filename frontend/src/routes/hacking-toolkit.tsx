import { useEffect, useMemo, useState, useRef, useCallback } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { PageShell } from "@/components/PageShell";
import { getHackingtoolCategories, runHackingtoolTool } from "@/api/backend";
import { Panel, SectionBar, Chip, Field, SendToRow } from "@/components/soc";
import { Empty, ResultBanner } from "@/components/output";
import { useOutputFilter, OutputFilterBar, OutputFilter } from "@/components/soc/OutputFilter";
import { PreviewBadge } from "@/components/PreviewBadge";
import { sendArtifact, takePendingArtifact } from "@/lib/handoff";
import { pushTimelineEvent } from "@/lib/timeline";
import { copyText } from "@/lib/copy";
import { useLocker } from "@/lib/locker";
import { toast } from "sonner";
import { PanelSkeleton } from "@/components/Skeleton";
import { TerminalOutput } from "@/components/soc/TerminalOutput";
import { NmapOutput } from "@/components/output/NmapOutput";
import {
  Swords, Search, Terminal, Copy, Check,
  X, AlertTriangle, ChevronRight, Sparkles, Pin, PinOff,
  Loader2, Bug, History, Clock, Trash2, Download,
} from "lucide-react";
import {
  ICON_MAP, TONE_MAP, PRESETS, TOOL_SCHEMAS,
  buildArgsFromSchema, defaultFieldValues, getTargetFromSchema,
  loadHistory, saveHistory, loadCachedCatalog,
  genId, CACHE_KEY, CACHE_TTL, PIN_KEY, HISTORY_KEY, MAX_HISTORY,
  type ToolSchema, type BackendTool, type BackendCategory, type HistoryEntry,
} from "@/data/hacking-toolkit";

export const Route = createFileRoute("/hacking-toolkit")({ component: HackingToolkitPage });

function renderGroupedFields(
  schema: ToolSchema,
  toolId: string,
  getFieldVals: (id: string) => Record<string, any>,
  setFieldVal: (toolId: string, key: string, val: any) => void,
) {
  const groups = new Map<string, ToolInputField[]>();
  schema.fields.forEach(f => {
    const g = f.group || "General";
    if (!groups.has(g)) groups.set(g, []);
    groups.get(g)!.push(f);
  });
  return (
    <div className="divide-y divide-border">
      {[...groups.keys()].map(groupName => (
        <div key={groupName} className="p-3">
          <div className="mb-2 flex items-center gap-2">
            <span className="text-mono text-[10px] font-semibold uppercase tracking-widest text-muted-foreground/60">{groupName}</span>
            <span className="h-px flex-1 bg-divider-soft" />
          </div>
          <div className="grid gap-x-3 gap-y-2.5 grid-cols-[repeat(auto-fill,minmax(200px,1fr))]">
            {groups.get(groupName)!.map(f => {
              const val = getFieldVals(toolId)[f.key] ?? f.defaultValue ?? (f.type === "toggle" ? false : "");
              return (
                <div key={f.key}>
                  <label className="mb-1 block text-mono text-[10px] uppercase tracking-widest text-muted-foreground">{f.label}</label>
                  {f.type === "toggle" ? (
                    <button
                      onClick={() => setFieldVal(toolId, f.key, !val)}
                      className={"inline-flex items-center gap-1.5 rounded border px-2 py-1 text-mono ba-text-sm transition-colors " + (val ? "border-primary/50 bg-primary/15 text-primary" : "border-border text-muted-foreground hover:text-foreground")}
                    >
                      <span className={"h-3 w-3 rounded border " + (val ? "border-primary bg-primary" : "border-border")}>
                        {val && <Check className="h-2.5 w-2.5 text-background" />}
                      </span>
                      {f.label}
                    </button>
                  ) : f.type === "dropdown" ? (
                    <select
                      value={String(val)}
                      onChange={e => setFieldVal(toolId, f.key, e.target.value)}
                      className="w-full rounded-md border border-border bg-background/60 px-2 py-1.5 text-mono ba-text-base text-foreground outline-none focus:border-primary/50"
                    >
                      {f.options?.map(o => (
                        <option key={o.value} value={o.value}>{o.label}</option>
                      ))}
                    </select>
                  ) : (
                    <input
                      type={f.type === "number" ? "number" : "text"}
                      value={String(val)}
                      onChange={e => setFieldVal(toolId, f.key, f.type === "number" ? Number(e.target.value) : e.target.value)}
                      placeholder={f.placeholder}
                      spellCheck={false}
                      className="w-full rounded-md border border-border bg-background/60 px-2 py-1.5 text-mono ba-text-base text-foreground outline-none placeholder:text-muted-foreground/50 focus:border-primary/50"
                    />
                  )}
                  {f.hint && (
                    <p className="mt-0.5 text-mono text-[9px] leading-tight text-muted-foreground/60">{f.hint}</p>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      ))}
    </div>
  );
}

function HackingToolkitPage() {
  const { filterText, setFilterText, showFilter, setShowFilter, toggleFilter } = useOutputFilter();
  const locker = useLocker();
  const [cats, setCats] = useState<BackendCategory[] | null>(null);
  const [loading, setLoading] = useState(true);
  const [backendError, setBackendError] = useState<string | null>(null);
  const [installed, setInstalled] = useState(false);
  const [offline, setOffline] = useState(false);
  const [activeCatId, setActiveCatId] = useState<string>("");
  const [activeToolId, setActiveToolId] = useState<string>("");
  const [search, setSearch] = useState("");
  const [targets, setTargets] = useState<Record<string, string>>(() => {
    try { return JSON.parse(localStorage.getItem("ba.hacking.targets.v2") || "{}"); } catch { return {}; }
  });
  const [argsMap, setArgsMap] = useState<Record<string, string>>(() => {
    try { return JSON.parse(localStorage.getItem("ba.hacking.args.v2") || "{}"); } catch { return {}; }
  });
  const [outputs, setOutputs] = useState<Record<string, { command: string; status: string; body: string } | null>>({});
  const [running, setRunning] = useState<string | null>(null);
  const [copied, setCopied] = useState<string | null>(null);
  const [pinned, setPinned] = useState<Set<string>>(new Set());
  const [history, setHistory] = useState<HistoryEntry[]>(() => loadHistory());
  const [showHistory, setShowHistory] = useState(false);
  const [historyFilter, setHistoryFilter] = useState("");
  const [fieldValues, setFieldValues] = useState<Record<string, Record<string, any>>>({});
  const [nmapConfirmed, setNmapConfirmed] = useState(false);
  const [nmapMode, setNmapMode] = useState("service");
  const [scanStartTime, setScanStartTime] = useState<number | null>(null);
  const abortRef = useRef<AbortController | null>(null);

  const cancelRun = () => {
    abortRef.current?.abort();
    abortRef.current = null;
  };

  const handleClear = useCallback(() => {
    setSearch("");
    setActiveCatId("");
    setActiveToolId("");
    toast("Cleared");
  }, []);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") handleClear();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [handleClear]);

  const NMAP_MODES = useMemo(() => [
    { k: "discovery", label: "Discovery",         args: "-sn -PE -PA80,443",                          risk: "low",    desc: "ICMP & ACK host discovery — no port probes." },
    { k: "fast",      label: "Top-100 TCP",       args: "-sS --top-ports 100 -Pn",                    risk: "medium", desc: "SYN scan of the 100 most common TCP ports." },
    { k: "service",   label: "Service & version", args: "-sV -sC --top-ports 1000 -Pn",               risk: "medium", desc: "Version detection + default NSE on common ports." },
    { k: "vuln",      label: "Safe NSE scripts",  args: "-sV --script default,safe --top-ports 200 -Pn", risk: "high", desc: "Safe NSE scripts. Noisy — explicit auth only." },
    { k: "full",      label: "Full TCP + OS",     args: "-sS -p- -O -sV -Pn",                         risk: "high",   desc: "Every TCP port + OS fingerprint. Slow and loud." },
  ] as const, []);

  const NMAP_TIMINGS = useMemo(() => [
    { k: "T2", label: "Polite",      hint: "stealth · low rate" },
    { k: "T3", label: "Normal",      hint: "default" },
    { k: "T4", label: "Aggressive",  hint: "lab / authorised" },
    { k: "T5", label: "Insane",      hint: "very loud" },
  ] as const, []);

  const [nmapTiming, setNmapTiming] = useState<(typeof NMAP_TIMINGS)[number]["k"]>("T3");

  function NmapProgress({ startTime }: { startTime: number }) {
    const [elapsed, setElapsed] = useState(0);
    const [phase, setPhase] = useState<"indeterminate" | "determinate">("indeterminate");
    const estimatedSeconds = 30;
    useEffect(() => {
      const interval = setInterval(() => {
        const e = (Date.now() - startTime) / 1000;
        setElapsed(e);
        if (e >= 5) setPhase("determinate");
      }, 100);
      return () => clearInterval(interval);
    }, [startTime]);
    const pct = phase === "determinate" ? Math.min(95, (elapsed / estimatedSeconds) * 100) : null;
    return (
      <div className="w-full space-y-1">
        <div className="h-1 w-full overflow-hidden rounded-full bg-muted/30">
          <div
            className={
              "h-full rounded-full transition-all duration-300 " +
              (phase === "indeterminate"
                ? "w-1/3 animate-[ba-shimmer_1.5s_ease-in-out_infinite] bg-gradient-to-r from-primary/40 via-primary to-primary/40"
                : "bg-primary")
            }
            style={pct !== null ? { width: `${pct}%` } : undefined}
          />
        </div>
        <div className="flex justify-between text-mono ba-text-2xs text-muted-foreground">
          <span>{phase === "indeterminate" ? "Starting nmap scan…" : `Scanning… ${Math.round(elapsed)}s / ${estimatedSeconds}s`}</span>
        </div>
      </div>
    );
  }

  function getFieldVals(toolId: string): Record<string, any> {
    return fieldValues[toolId] ?? defaultFieldValues(toolId);
  }
  function setFieldVal(toolId: string, key: string, val: any) {
    setFieldValues(prev => ({ ...prev, [toolId]: { ...(prev[toolId] ?? defaultFieldValues(toolId)), [key]: val } }));
  }

  /* Persist targets/args */
  useEffect(() => { try { localStorage.setItem("ba.hacking.targets.v2", JSON.stringify(targets)); } catch {} }, [targets]);
  useEffect(() => { try { localStorage.setItem("ba.hacking.args.v2", JSON.stringify(argsMap)); } catch {} }, [argsMap]);

  /* Load catalog */
  useEffect(() => {
    getHackingtoolCategories()
      .then((res: any) => {
        if (res.categories) {
          setCats(res.categories);
          setInstalled(res.installed ?? false);
          setOffline(false);
          try { localStorage.setItem(CACHE_KEY, JSON.stringify({ _cachedAt: Date.now(), categories: res.categories })); } catch {}
          if (res.categories.length > 0) {
            setActiveCatId("");
            setActiveToolId("");
          }
        }
        setLoading(false);
      })
      .catch((err: any) => {
        /* Offline fallback: load cached catalog */
        const cached = loadCachedCatalog();
        if (cached) {
          setCats(cached);
          setInstalled(false);
          setOffline(true);
          if (cached.length > 0) {
            setActiveCatId("");
            setActiveToolId("");
          }
        } else {
          setBackendError(err?.message || "Cannot reach backend");
        }
        setLoading(false);
      });
  }, []);

  useEffect(() => {
    try { const raw = localStorage.getItem(PIN_KEY); if (raw) setPinned(new Set(JSON.parse(raw))); } catch {}
  }, []);
  useEffect(() => {
    try { localStorage.setItem(PIN_KEY, JSON.stringify([...pinned])); } catch {}
  }, [pinned]);

  useEffect(() => {
    const h = takePendingArtifact();
    if (h?.value) setTargets((p) => ({ ...p, [activeToolId]: h.value }));
  }, [activeToolId]);

  const allTools = useMemo(() => {
    if (!cats) return [];
    return cats.flatMap((c) => c.tools.map((t) => ({ ...t, catId: c.id, catName: c.name })));
  }, [cats]);

  const totalTools = allTools.length;
  const installedCount = allTools.filter((t) => t.installed).length;
  const pinnedCount = pinned.size;

  const lower = search.trim().toLowerCase();
  const filteredCats = useMemo(() => {
    if (!cats) return [];
    if (!lower) return cats;
    return cats.map((c) => ({
      ...c,
      tools: c.tools.filter((t) =>
        t.name.toLowerCase().includes(lower) ||
        t.binary.toLowerCase().includes(lower) ||
        t.id.toLowerCase().includes(lower) ||
        c.name.toLowerCase().includes(lower),
      ),
    })).filter((c) => c.tools.length > 0);
  }, [cats, lower]);

  const activeCat = cats?.find((c) => c.id === activeCatId);
  const activeTool = activeCat?.tools.find((t) => t.id === activeToolId);
  const schema = activeTool ? TOOL_SCHEMAS[activeTool.id] : null;

  const target = activeTool ? (schema ? getTargetFromSchema(activeTool.id, getFieldVals(activeTool.id)) : (targets[activeTool.id] ?? "")) : "";
  const args = activeTool ? (argsMap[activeTool.id] ?? (schema ? buildArgsFromSchema(activeTool.id, getFieldVals(activeTool.id)) : "")) : "";
  const effectiveArgs = activeTool && activeTool.id === "nmap" ? [args, `-${nmapTiming}`].filter(Boolean).join(" ") : args;
  const cmd = activeTool ? [activeTool.binary, target, effectiveArgs].filter(Boolean).join(" ") : "";
  const output = activeTool ? outputs[activeTool.id] : null;

  function selectTool(catId: string, toolId: string) {
    setActiveCatId(catId);
    setActiveToolId(toolId);
  }

  function togglePin(toolId: string) {
    setPinned((prev) => {
      const next = new Set(prev);
      if (next.has(toolId)) next.delete(toolId); else next.add(toolId);
      return next;
    });
  }

  function applyPreset(args: string) {
    if (!activeTool) return;
    setArgsMap((p) => ({ ...p, [activeTool.id]: args }));
  }

  async function run() {
    if (!activeTool || !activeCat) return;
    if (activeTool.id === "nmap" && !nmapConfirmed) {
      toast.error("Confirm you have permission to scan this target first.");
      return;
    }
    abortRef.current?.abort();
    const controller = new AbortController();
    abortRef.current = controller;
    setRunning(activeTool.id);
    setScanStartTime(Date.now());
    setOutputs((p) => ({ ...p, [activeTool.id]: null }));
    try {
      const res: any = await runHackingtoolTool({
        categoryId: activeCat.id,
        toolId: activeTool.id,
        target,
        args: effectiveArgs,
        signal: controller.signal,
      });
      const body = res.stdout || res.stderr || res.error || JSON.stringify(res, null, 2);
      const status = res.error ? "error" : (res.status === "completed" ? "completed" : "failed");
      const entry: HistoryEntry = {
        id: genId(),
        toolId: activeTool.id,
        toolName: activeTool.name,
        binary: activeTool.binary,
        catName: activeCat.name,
        target, args: effectiveArgs,
        command: res.command || cmd,
        status,
        body,
        ts: Date.now(),
      };
      setHistory(prev => { const next = [entry, ...prev].slice(0, MAX_HISTORY); saveHistory(next); return next; });
      setOutputs((p) => ({
        ...p,
        [activeTool.id]: {
          command: res.command || cmd,
          status,
          body,
        },
      }));
      if (activeTool.id === "nmap" && status === "completed") {
        const portCount = (body.match(/^\d+\/(tcp|udp)\s+open/m) || []).length;
        pushTimelineEvent({ source: "nmap", verb: "scanned", detail: `${target} — ${NMAP_MODES.find(m => m.k === nmapMode)?.label ?? "scan"} (${portCount} open ports)`, target });
      }
    } catch (err: any) {
      const body = err?.message || "API call failed";
      const entry: HistoryEntry = {
        id: genId(), toolId: activeTool.id, toolName: activeTool.name,
        binary: activeTool.binary, catName: activeCat.name,
        target, args: effectiveArgs, command: cmd, status: "error", body, ts: Date.now(),
      };
      setHistory(prev => { const next = [entry, ...prev].slice(0, MAX_HISTORY); saveHistory(next); return next; });
      setOutputs((p) => ({
        ...p,
        [activeTool.id]: { command: cmd, status: "error", body },
      }));
    } finally {
      setRunning(null);
    }
  }

  async function copyText(key: string, text: string) {
    try { await copyText(text); setCopied(key); setTimeout(() => setCopied(null), 1200); } catch {}
  }

  const presets = activeTool ? (PRESETS[activeTool.id] ?? []) : [];

  const metaItems: { label: string; value: string; tone?: "default" | "primary" | "warning" | "destructive" | "success" }[] = [
    { label: "categories", value: String(cats?.length ?? 0), tone: "primary" },
    { label: "tools", value: String(totalTools), tone: "primary" },
    { label: "available", value: String(installedCount), tone: installedCount > 0 ? "success" : "default" },
    { label: "pinned", value: String(pinnedCount), tone: pinnedCount > 0 ? "success" : "default" },
  ];

  function handleExport() {
    if (!output) return;
    const md = [
      `# Hacking Toolkit — ${activeTool?.name ?? "Tool"} Output`,
      "",
      `**Command:** \`${output.command}\``,
      `**Status:** ${output.status}`,
      `**Target:** ${target || "(none)"}`,
      `**Timestamp:** ${new Date().toISOString()}`,
      "",
      "## Output",
      "",
      "```",
      output.body,
      "```",
      "",
    ].join("\n");
    const blob = new Blob([md], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a"); a.href = url; a.download = `hacking-${activeTool?.id ?? "tool"}-${Date.now()}.md`; a.click();
    URL.revokeObjectURL(url);
  }

  const historyLc = historyFilter.trim().toLowerCase();
  const filteredHistory = historyLc
    ? history.filter(h => h.toolName.toLowerCase().includes(historyLc) || h.target.toLowerCase().includes(historyLc) || h.command.toLowerCase().includes(historyLc))
    : history;

  const clearHistory = () => { setHistory([]); saveHistory([]); };
  const replayHistory = (h: HistoryEntry) => {
    const cat = cats?.find(c => c.tools.some(t => t.id === h.toolId));
    if (cat) { setActiveCatId(cat.id); setActiveToolId(h.toolId); }
    setTargets(p => ({ ...p, [h.toolId]: h.target }));
    setArgsMap(p => ({ ...p, [h.toolId]: h.args }));
    setShowHistory(false);
  };

  return (
    <PageShell
      eyebrow="Offensive"
      title="Hacking Toolkit"
      description="Browse 50+ offensive-security tools by category, build commands with presets, and run against locally installed binaries via the BeyondLabs backend."
      crumbs={[{ label: "Workbench", href: "/" }, { label: "Offensive" }, { label: "Hacking Toolkit" }]}
      meta={metaItems}
      actions={<div className="flex items-center gap-1.5"><button onClick={handleExport} className="inline-flex items-center gap-1 rounded border border-border px-2 py-0.5 text-mono ba-text-2xs uppercase text-muted-foreground hover:text-foreground"><Download className="h-3 w-3" /> md</button><PreviewBadge label={offline ? "offline catalog" : (installed ? "live backend" : "catalog")} /></div>}
    >
      {loading && (
        <div className="space-y-3">
          <PanelSkeleton title lines={4} />
          <PanelSkeleton title lines={2} />
        </div>
      )}

      {!loading && backendError && !cats && (
        <Panel className="border-warning/30 bg-warning/5">
          <div className="flex items-start gap-3 px-4 py-2.5">
            <span className="grid h-7 w-7 shrink-0 place-items-center rounded border border-warning/40 bg-warning/15 text-warning">
              <AlertTriangle className="h-3.5 w-3.5" />
            </span>
            <div className="min-w-0 ba-text-base leading-relaxed text-foreground/85">
              <span className="font-semibold text-warning">Cannot reach backend.</span>{" "}
              No cached catalog available. Start the FastAPI server to use toolkit features.{" "}
              <code className="text-mono ba-text-sm text-foreground">cd backend && uvicorn app.main:app --reload</code>
            </div>
          </div>
        </Panel>
      )}

      {offline && (
        <Panel className="border-warning/30 bg-warning/5">
          <div className="flex items-start gap-3 px-4 py-2.5">
            <span className="grid h-7 w-7 shrink-0 place-items-center rounded border border-warning/40 bg-warning/15 text-warning">
              <AlertTriangle className="h-3.5 w-3.5" />
            </span>
            <div className="min-w-0 ba-text-base leading-relaxed text-foreground/85">
              <span className="font-semibold text-warning">Offline mode.</span>{" "}
              Backend unreachable — showing cached tool catalog. Tool execution requires the backend.{" "}
              <code className="text-mono ba-text-sm text-foreground">cd backend && uvicorn app.main:app --reload</code>
            </div>
          </div>
        </Panel>
      )}

      {!loading && !backendError && cats && (
        <>
          {!installed && !offline && (
            <Panel className="border-warning/30 bg-warning/5">
              <div className="flex items-start gap-3 px-4 py-2.5">
                <span className="grid h-7 w-7 shrink-0 place-items-center rounded border border-warning/40 bg-warning/15 text-warning">
                  <AlertTriangle className="h-3.5 w-3.5" />
                </span>
                <div className="min-w-0 ba-text-base leading-relaxed text-foreground/85">
                  <span className="font-semibold text-warning">hackingtool directory not found.</span>{" "}
                  The catalog is shown but binaries are not checked. Clone into{" "}
                  <code className="text-mono ba-text-sm text-foreground">~/Projects/hackingtool</code> to enable installed-tool detection.
                </div>
              </div>
            </Panel>
          )}

          <div className="grid gap-4 grid-cols-[minmax(0,18rem)_minmax(0,1fr)]">
            {/* ── Left rail ── */}
            <div className="space-y-3 sticky top-16 self-start">
              <Panel bodyClassName="p-0">
                <div className="border-b border-border p-2">
                  <div className="relative">
                    <Search className="pointer-events-none absolute left-2 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
                    <input
                      value={search}
                      onChange={(e) => setSearch(e.target.value)}
                      placeholder="search tools, binaries…"
                      spellCheck={false}
                      className="w-full rounded-md border border-border bg-background/60 py-1.5 pl-7 pr-7 text-mono ba-text-sm text-foreground outline-none placeholder:text-muted-foreground/60 focus:border-primary/50"
                    />
                    {search && (
                      <button onClick={() => setSearch("")} className="absolute right-1 top-1/2 -translate-y-1/2 rounded p-1 text-muted-foreground hover:text-foreground" aria-label="clear">
                        <X className="h-3 w-3" />
                      </button>
                    )}
                  </div>
                </div>

                {pinnedCount > 0 && (
                  <div className="border-b border-divider-strong p-2">
                    <div className="mb-1.5 flex items-center gap-1.5 text-mono ba-text-3xs uppercase tracking-widest text-muted-foreground">
                      <Pin className="h-3 w-3 text-primary" /> pinned
                    </div>
                    <ul className="space-y-0.5">
                      {[...pinned].map((tid) => {
                        const cat = cats?.find((c) => c.tools.some((t) => t.id === tid));
                        const t = cat?.tools.find((x) => x.id === tid);
                        if (!cat || !t) return null;
                        const active = t.id === activeToolId;
                        return (
                          <li key={tid}>
                            <button
                              onClick={() => selectTool(cat.id, t.id)}
                              className={"flex w-full items-center gap-2 rounded px-2 py-1 text-left text-mono ba-text-sm transition-colors " + (active ? "bg-primary/10 text-primary" : "text-foreground/80 hover:bg-accent/40 hover:text-foreground")}
                            >
                              <span className="truncate">{t.name}</span>
                              <span className="ml-auto truncate ba-text-3xs text-muted-foreground">{cat.name}</span>
                            </button>
                          </li>
                        );
                      })}
                    </ul>
                  </div>
                )}

                <nav className="max-h-[calc(100vh-22rem)] overflow-auto p-2">
                  {filteredCats.length === 0 && (
                    <div className="px-2 py-6 text-center text-mono ba-text-sm text-muted-foreground">
                      no tools match <span className="text-foreground">{search}</span>
                    </div>
                  )}
                  {filteredCats.map((cat) => {
                    const Icon = ICON_MAP[cat.icon] || Search;
                    const open = cat.id === activeCatId || !!lower;
                    const toneCls =
                      TONE_MAP[cat.id] === "primary" ? "text-primary" :
                      TONE_MAP[cat.id] === "warning" ? "text-warning" :
                      TONE_MAP[cat.id] === "destructive" ? "text-destructive" :
                      TONE_MAP[cat.id] === "success" ? "text-success" :
                      TONE_MAP[cat.id] === "accent" ? "text-accent" : "text-info";
                    return (
                      <div key={cat.id} className="mb-1.5">
                        <button
                          onClick={() => setActiveCatId((id) => (id === cat.id ? "" : cat.id))}
                          className={"group flex w-full items-center gap-2 rounded-md border border-transparent px-2 py-1.5 text-left transition-colors hover:border-border hover:bg-accent/30 " + (open ? "border-border bg-card/60" : "")}
                        >
                          <span className={"grid h-6 w-6 place-items-center rounded border border-border bg-background/60 " + toneCls}>
                            <Icon className="h-3.5 w-3.5" />
                          </span>
                          <span className="flex-1 truncate text-mono ba-text-sm font-semibold uppercase tracking-widest text-foreground/90">
                            {cat.name}
                          </span>
                          <span className="text-mono ba-text-3xs text-muted-foreground">{cat.tools.length}</span>
                          <ChevronRight className={"h-3 w-3 text-muted-foreground transition-transform " + (open ? "rotate-90" : "")} />
                        </button>
                        {open && (
                          <ul className="mt-1 space-y-0.5 pl-2">
                            {cat.tools.map((t) => {
                              const active = t.id === activeToolId;
                              return (
                                <li key={t.id}>
                                  <button
                                    onClick={() => selectTool(cat.id, t.id)}
                                    className={"group/r relative flex w-full items-center gap-2 rounded px-2 py-1 text-left text-mono ba-text-sm transition-colors " + (active ? "bg-primary/10 text-primary" : "text-foreground/75 hover:bg-accent/40 hover:text-foreground")}
                                  >
                                    <span aria-hidden className={"h-1.5 w-1.5 shrink-0 rounded-full " + (active ? "bg-primary shadow-[0_0_8px_var(--primary)]" : "bg-muted-foreground/30")} />
                                    <span className="truncate">{t.name}</span>
                                    {t.installed && (
                                      <span className="ml-auto h-1.5 w-1.5 shrink-0 rounded-full bg-success" title="installed" />
                                    )}
                                    <span className="ml-1 truncate ba-text-3xs text-muted-foreground/80">{t.binary}</span>
                                    {pinned.has(t.id) && <Pin className="h-2.5 w-2.5 fill-primary text-primary" />}
                                  </button>
                                </li>
                              );
                            })}
                          </ul>
                        )}
                      </div>
                    );
                  })}
                </nav>
              </Panel>
            </div>

            {/* ── Right column ── */}
            <div className="min-w-0 space-y-4">
              {!activeTool ? (
                <Empty icon={Terminal} title="No tool selected" hint="Hacking Toolkit provides 50+ offensive security tools grouped by category — recon, web, forensics, exploit, password attacks, and more. Select a tool from the left rail, configure flags or presets, and run against locally installed binaries." />
              ) : (
                <>
                  {/* Tool header */}
                  <Panel>
                    <div className="flex flex-wrap items-start justify-between gap-3 px-4 py-3">
                      <div className="flex min-w-0 items-start gap-3">
                        <span className="grid h-10 w-10 shrink-0 place-items-center rounded-md border border-primary/40 bg-primary/10 text-primary shadow-[0_0_0_3px_color-mix(in_oklab,var(--primary)_8%,transparent)]">
                          <Swords className="h-4 w-4" />
                        </span>
                        <div className="min-w-0">
                          <div className="flex flex-wrap items-center gap-2">
                            <h2 className="truncate text-mono text-base font-semibold text-foreground">{activeTool.name}</h2>
                            <Chip tone="default">{activeCat?.name ?? ""}</Chip>
                            <Chip tone={activeTool.installed ? "success" : "warning"}>{activeTool.installed ? "installed" : "not detected"}</Chip>
                          </div>
                          <div className="mt-1.5 inline-flex items-center gap-1.5 rounded border border-divider-strong bg-background/40 px-1.5 py-0.5 text-mono text-[10px] text-muted-foreground">
                            <Terminal className="h-3 w-3 text-primary/70" />
                            <span className="text-foreground/80">{activeTool.binary}</span>
                          </div>
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        <button
                          onClick={() => togglePin(activeTool.id)}
                          className="inline-flex items-center gap-1 rounded border border-border bg-card/40 px-2 py-1 text-mono text-[10px] uppercase tracking-widest text-muted-foreground hover:border-primary/50 hover:text-primary"
                        >
                          {pinned.has(activeTool.id) ? <><PinOff className="h-3 w-3" /> unpin</> : <><Pin className="h-3 w-3" /> pin</>}
                        </button>
                      </div>
                    </div>
                  </Panel>

                  {/* Intake */}
                  <div>
                    <SectionBar id="IN" label="Intake" meta={schema ? "structured inputs" : "target · args · preset"} />
                    <Panel bodyClassName="p-0">
                      {schema ? renderGroupedFields(schema, activeTool.id, getFieldVals, setFieldVal) : (
                        <div className="grid gap-0 grid-cols-[1fr_1fr]">
                          <div className="border-b border-divider-strong p-3 border-b-0 border-r">
                            <label className="mb-1 block text-mono text-[10px] uppercase tracking-widest text-muted-foreground">Target</label>
                            <input
                              value={target}
                              onChange={(e) => setTargets((p) => ({ ...p, [activeTool.id]: e.target.value }))}
                              placeholder="example.com · 10.0.0.1 · https://app"
                              spellCheck={false}
                              className="w-full rounded-md border border-border bg-background/60 px-2 py-1.5 text-mono ba-text-base text-foreground outline-none placeholder:text-muted-foreground/50 focus:border-primary/50"
                            />
                          </div>
                          <div className="p-3">
                            <label className="mb-1 block text-mono text-[10px] uppercase tracking-widest text-muted-foreground">Args</label>
                            <input
                              value={args}
                              onChange={(e) => setArgsMap((p) => ({ ...p, [activeTool.id]: e.target.value }))}
                              placeholder="-sV -p 22,80,443 (optional)"
                              spellCheck={false}
                              className="w-full rounded-md border border-border bg-background/60 px-2 py-1.5 text-mono ba-text-base text-foreground outline-none placeholder:text-muted-foreground/50 focus:border-primary/50"
                            />
                          </div>
                        </div>
                      )}

                      {presets.length > 0 && (
                        <div className="flex flex-wrap items-center gap-1.5 border-t border-border bg-muted/15 px-3 py-2">
                          <span className="text-mono text-[10px] uppercase tracking-widest text-muted-foreground">
                            <Sparkles className="mr-1 inline h-3 w-3 text-primary" /> presets
                          </span>
                          {presets.map((p) => (
                            <button
                              key={p.label}
                              onClick={() => applyPreset(p.args)}
                              className="rounded border border-border bg-background/60 px-2 py-0.5 text-mono text-[10px] text-foreground/85 transition-colors hover:border-primary/50 hover:bg-primary/10 hover:text-primary"
                            >
                              {p.label}
                            </button>
                          ))}
                        </div>
                      )}

                      {activeTool.id === "nmap" && (
                        <div className="border-t border-border bg-muted/10 px-3 py-2 space-y-2">
                          <div>
                            <label className="mb-1 block text-mono text-[10px] uppercase tracking-widest text-muted-foreground">Scan mode</label>
                            <div className="flex flex-wrap gap-1">
                              {NMAP_MODES.map((m) => (
                                <button
                                  key={m.k}
                                  onClick={() => { setNmapMode(m.k); setArgsMap((p) => ({ ...p, nmap: [m.args, `-${nmapTiming}`].filter(Boolean).join(" ") })); }}
                                  className={"rounded border px-2 py-1 text-mono text-[10px] transition-colors " + (nmapMode === m.k ? "border-primary/50 bg-primary/15 text-primary" : "border-divider-strong bg-background/40 text-muted-foreground hover:text-foreground")}
                                  title={m.desc}
                                >
                                  {m.label}
                                </button>
                              ))}
                            </div>
                          </div>
                          <div className="flex items-center gap-3">
                            <label className="text-mono text-[10px] uppercase tracking-widest text-muted-foreground">Timing</label>
                            <div className="flex gap-1">
                              {NMAP_TIMINGS.map((t) => (
                                <button
                                  key={t.k}
                                  onClick={() => { setNmapTiming(t.k); setArgsMap((p) => { const base = p.nmap ?? NMAP_MODES.find(m => m.k === nmapMode)?.args ?? ""; return { ...p, nmap: [base, `-${t.k}`].filter(Boolean).join(" ") }; }) }}
                                  className={"rounded border px-2 py-0.5 text-mono text-[10px] transition-colors " + (nmapTiming === t.k ? "border-primary/50 bg-primary/15 text-primary" : "border-divider-strong bg-background/40 text-muted-foreground hover:text-foreground")}
                                  title={t.hint}
                                >
                                  -{t.k}
                                </button>
                              ))}
                            </div>
                          </div>
                          <label className="flex items-center gap-2 cursor-pointer">
                            <input
                              type="checkbox"
                              checked={nmapConfirmed}
                              onChange={(e) => setNmapConfirmed(e.target.checked)}
                              className="h-3.5 w-3.5 rounded border-border accent-primary"
                            />
                            <span className="text-mono text-[10px] text-muted-foreground">I own or have permission to scan this target</span>
                          </label>
                          {running === activeTool.id && scanStartTime && (
                            <NmapProgress startTime={scanStartTime} />
                          )}
                        </div>
                      )}
                      <div className="flex flex-wrap items-center gap-2 border-t border-border bg-background/40 px-3 py-2">
                        <span className="text-mono text-[10px] uppercase tracking-widest text-muted-foreground">cmd</span>
                        <code className="min-w-0 flex-1 truncate rounded border border-divider-strong bg-background/70 px-2 py-1 text-mono ba-text-sm text-foreground/90">
                          <span className="text-primary/70">$</span> {cmd || activeTool.binary}
                        </code>
                        <button
                          onClick={() => copyText("cmd", cmd || activeTool.binary)}
                          className="inline-flex items-center gap-1 rounded border border-border px-2 py-1 text-mono text-[10px] uppercase tracking-widest text-muted-foreground hover:border-primary/50 hover:text-primary"
                          title="Copy command"
                        >
                          {copied === "cmd" ? <Check className="h-3 w-3 text-success" /> : <Copy className="h-3 w-3" />} copy
                        </button>
                        {running === activeTool.id && (
                          <button
                            onClick={cancelRun}
                            className="inline-flex items-center gap-1 rounded border border-destructive/40 bg-destructive/10 px-2.5 py-1 text-mono ba-text-sm font-semibold uppercase tracking-widest text-destructive transition-colors hover:bg-destructive/20"
                          >
                            <X className="h-3 w-3" /> cancel
                          </button>
                        )}
                        <button
                          onClick={run}
                          disabled={running === activeTool.id || offline}
                          className="inline-flex items-center gap-1.5 rounded border border-primary/50 bg-primary/10 px-3 py-1 text-mono ba-text-sm font-semibold uppercase tracking-widest text-primary transition-colors hover:bg-primary/20 disabled:opacity-50"
                        >
                          {running === activeTool.id ? <Loader2 className="h-3 w-3 animate-spin" /> : <Bug className="h-3 w-3" />}
                          {running === activeTool.id ? "running…" : "run"}
                        </button>
                        {offline && <span className="text-mono ba-text-3xs text-muted-foreground">(offline — cannot run)</span>}
                      </div>
                    </Panel>
                  </div>

                  {/* Output + History */}
                  <div>
                    <div className="flex items-center gap-2">
                      <SectionBar id="OT" label="Output" meta={output ? output.status : "no run yet"} />
                      <button
                        onClick={toggleFilter}
                        className={"inline-flex shrink-0 items-center gap-1 rounded border px-2 py-1 text-mono text-[10px] uppercase tracking-widest transition-colors " + (showFilter ? "border-primary/50 bg-primary/10 text-primary" : "border-divider-strong text-muted-foreground hover:border-primary/40 hover:text-primary")}
                      >
                        <Search className="h-3 w-3" />
                        filter
                      </button>
                      <button
                        onClick={() => setShowHistory(s => !s)}
                        className={"inline-flex shrink-0 items-center gap-1 rounded border px-2 py-1 text-mono text-[10px] uppercase tracking-widest transition-colors " + (showHistory ? "border-primary/50 bg-primary/10 text-primary" : "border-divider-strong text-muted-foreground hover:border-primary/40 hover:text-primary")}
                      >
                        <History className="h-3 w-3" />
                        history
                        {history.length > 0 && <Chip tone={showHistory ? "primary" : "default"}>{history.length}</Chip>}
                      </button>
                    </div>

                    {showFilter && (
                      <OutputFilterBar
                        filterText={filterText}
                        onChange={setFilterText}
                        onClear={() => setFilterText("")}
                        onClose={() => { setShowFilter(false); setFilterText(""); }}
                      />
                    )}

                    {showHistory && (
                      <Panel title="Command history" icon={History} meta={`${history.length} entries`} className="mb-3" actions={
                        history.length > 0 && (
                          <button onClick={clearHistory} className="inline-flex items-center gap-1 rounded border border-border px-2 py-0.5 text-mono text-[10px] uppercase text-muted-foreground hover:text-destructive">
                            <Trash2 className="h-3 w-3" /> clear all
                          </button>
                        )
                      }>
                        <div className="relative mb-2">
                          <Search className="pointer-events-none absolute left-2 top-1/2 h-3 w-3 -translate-y-1/2 text-muted-foreground" />
                          <input
                            value={historyFilter}
                            onChange={e => setHistoryFilter(e.target.value)}
                            placeholder="filter history…"
                            className="h-7 w-full rounded border border-border bg-background/60 pl-6 pr-2 text-mono text-[10px] text-foreground outline-none placeholder:text-muted-foreground/60 focus:border-primary/50"
                          />
                        </div>
                        {filteredHistory.length === 0 ? (
                          <div className="py-4 text-center text-mono ba-text-sm text-muted-foreground">{history.length === 0 ? "No runs yet. Run a tool to see history here." : "No entries match the filter."}</div>
                        ) : (
                          <div className="max-h-80 space-y-1 overflow-auto">
                            {filteredHistory.map(h => (
                              <div key={h.id} className="group flex items-start justify-between gap-2 rounded border border-divider-soft bg-background/30 px-2.5 py-1.5 hover:border-primary/30">
                                <div className="min-w-0 flex-1">
                                  <div className="flex items-center gap-2">
                                    <span className="text-mono ba-text-sm font-semibold text-foreground/85">{h.toolName}</span>
                                    <Chip tone={h.status === "completed" ? "success" : h.status === "error" ? "destructive" : "warning"}>{h.status}</Chip>
                                  </div>
                                  <div className="mt-0.5 truncate text-mono text-[10px] text-muted-foreground">
                                    <span className="text-primary/70">$</span> {h.command}
                                  </div>
                                  <div className="flex items-center gap-2 text-mono ba-text-3xs text-muted-foreground">
                                    <Clock className="inline h-2.5 w-2.5" />
                                    <span>{new Date(h.ts).toLocaleString()}</span>
                                    <span>· {h.catName}</span>
                                    <span>· {h.body.length} b</span>
                                  </div>
                                </div>
                                <div className="flex shrink-0 items-center gap-1 opacity-0 transition-opacity group-hover:opacity-100">
                                  <button onClick={() => replayHistory(h)} className="rounded border border-border px-1.5 py-0.5 text-mono ba-text-3xs uppercase text-muted-foreground hover:text-primary" title="Replay">replay</button>
                                  <button onClick={() => copyText(h.id, h.body)} className="rounded border border-border px-1.5 py-0.5 text-mono ba-text-3xs uppercase text-muted-foreground hover:text-primary" title="Copy output">{copied === h.id ? <Check className="h-3 w-3 text-success" /> : <Copy className="h-3 w-3" />}</button>
                                </div>
                              </div>
                            ))}
                          </div>
                        )}
                      </Panel>
                    )}

                    <OutputFilter query={filterText.toLowerCase()}>
                    {!output ? (
                      <Empty
                        icon={Terminal}
                        title="No execution recorded"
                        hint="Hacking Toolkit wraps local CLI tools (nmap, whois, dig, curl, jq, and more) via the backend. Pick a tool from the left rail and set a target to run."
                      />
                    ) : (
                      <>
                        <div className="pointer-events-none select-none">
                          <ResultBanner
                            badge={output.status}
                            caseId={activeTool.binary}
                            title={`${activeTool.name} — ${output.status === "completed" ? "execution result" : output.status === "error" ? "execution failed" : "output"}`}
                            subtitle={output.status === "completed" ? "Binary ran on the local host via BeyondLabs backend." : output.status === "error" ? "The tool returned an error or is not installed." : "The tool produced output with non-zero exit code."}
                            metrics={[
                              { label: "lines", value: String(output.body.split("\n").length), tone: "primary" },
                              { label: "bytes", value: output.body.length.toLocaleString(), tone: "default" },
                              { label: "status", value: output.status, tone: output.status === "completed" ? "success" : "warning" },
                              { label: "tool", value: activeTool.binary, tone: "default" },
                            ]}
                          />
                        </div>

                        <Panel icon={Terminal} title="Raw output" meta={`${output.body.split('\n').length} lines`} collapsible storageKey="ba.panel.hacking.raw" defaultCollapsed={output.body.split('\n').length > 50}>
                        <TerminalOutput
                          command={output.command}
                          body={output.body}
                          status={output.status}
                          onClear={() => setOutputs((p) => ({ ...p, [activeTool.id]: null }))}
                          filename={`hacking-${activeTool.id}.txt`}
                        />
                        </Panel>

                        {activeTool.id === "nmap" && (
                          <div className="mt-3 space-y-3">
                            <NmapOutput
                              body={output.body}
                              command={output.command}
                              target={target}
                              status={output.status}
                            />
                          </div>
                        )}

                        {target && (
                          <div className="mt-3">
                             <SendToRow
                              targets={[
                                { label: "OSINT Tools", to: "/osint", onClick: () => sendArtifact({ kind: "raw", value: target, source: "/hacking-toolkit" }) },
                                { label: "URL Analyzer", to: "/url", onClick: () => sendArtifact({ kind: "raw", value: target, source: "/hacking-toolkit" }) },
                                { label: "Recon", to: "/recon", onClick: () => sendArtifact({ kind: "raw", value: target, source: "/hacking-toolkit" }) },
                                { label: "Tool Terminal", to: "/terminal", onClick: () => sendArtifact({ kind: "raw", value: target, source: "/hacking-toolkit" }) },
                              ]}
                            />
                          </div>
                        )}

                        <div className="mt-3">
                          <Panel title="Tool facts" icon={Terminal} collapsible storageKey="ba.panel.hacking.facts" defaultCollapsed>
                            <div className="grid gap-x-6 grid-cols-2">
                              <Field label="binary" value={<code className="text-mono">{activeTool.binary}</code>} />
                              <Field label="category" value={activeCat?.name ?? ""} />
                              <Field label="id" value={<code className="text-mono">{activeTool.id}</code>} tone="muted" />
                              <Field label="presets" value={String(presets.length)} tone={presets.length ? "primary" : "muted"} />
                              <Field label="installed" value={activeTool.installed ? "yes" : "no"} tone={activeTool.installed ? "success" : "warning"} />
                              <Field label="pinned" value={pinned.has(activeTool.id) ? "yes" : "no"} tone={pinned.has(activeTool.id) ? "success" : "muted"} />
                            </div>
                          </Panel>
                        </div>
                        <div className="mt-3">
                          <Panel title="IOC Locker" icon={Terminal} collapsible storageKey="ba.panel.hacking.iocs" defaultCollapsed>
                            <div className="flex flex-wrap gap-2 p-3">
                              <button
                                onClick={() => {
                                  const text = output?.body ?? "";
                                  const ips = text.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) ?? [];
                                  const unique = [...new Set(ips)];
                                  unique.forEach(ip => locker.add({ value: ip, type: "ipv4", source: "/hacking-toolkit" }));
                                  toast(`Sent ${unique.length} IPs to locker`);
                                }}
                                className="rounded border border-border bg-background/60 px-2.5 py-1 text-mono text-[10px] uppercase tracking-widest text-foreground/85 transition-colors hover:border-primary/50 hover:bg-primary/10 hover:text-primary"
                              >
                                IPs → locker
                              </button>
                              <button
                                onClick={() => {
                                  const text = output?.body ?? "";
                                  const domains = text.match(/[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z]{2,})+/g) ?? [];
                                  const unique = [...new Set(domains)];
                                  unique.forEach(d => locker.add({ value: d, type: "domain", source: "/hacking-toolkit" }));
                                  toast(`Sent ${unique.length} domains to locker`);
                                }}
                                className="rounded border border-border bg-background/60 px-2.5 py-1 text-mono text-[10px] uppercase tracking-widest text-foreground/85 transition-colors hover:border-primary/50 hover:bg-primary/10 hover:text-primary"
                              >
                                Domains → locker
                              </button>
                              <button
                                onClick={() => {
                                  const text = output?.body ?? "";
                                  const ips = text.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) ?? [];
                                  const domains = text.match(/[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z]{2,})+/g) ?? [];
                                  const hashes = text.match(/\b[a-f0-9]{32}\b|\b[a-f0-9]{40}\b|\b[a-f0-9]{64}\b/gi) ?? [];
                                  const all = [...new Set([...ips, ...domains, ...hashes])];
                                  all.forEach(v => {
                                    const type = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(v) ? "ipv4" : /^[a-f0-9]{32}$/i.test(v) ? "md5" : /^[a-f0-9]{40}$/i.test(v) ? "sha1" : /^[a-f0-9]{64}$/i.test(v) ? "sha256" : "domain";
                                    locker.add({ value: v, type: type as any, source: "/hacking-toolkit" });
                                  });
                                  toast(`Sent ${all.length} IOCs to locker`);
                                }}
                                className="rounded border border-border bg-background/60 px-2.5 py-1 text-mono text-[10px] uppercase tracking-widest text-foreground/85 transition-colors hover:border-primary/50 hover:bg-primary/10 hover:text-primary"
                              >
                                All IOCs → locker
                              </button>
                            </div>
                          </Panel>
                        </div>
                      </>
                    )}
                    </OutputFilter>
                  </div>
                </>
              )}
            </div>
          </div>
        </>
      )}
    </PageShell>
  );
}


