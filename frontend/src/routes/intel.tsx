import { createFileRoute, useSearch } from "@tanstack/react-router";
import { useEffect, useMemo, useState, useCallback } from "react";
import { PageShell } from "@/components/PageShell";
import { Panel, Chip, SendToRow } from "@/components/soc";
import { Empty } from "@/components/output";
import { Search, Copy, Check, ChevronLeft, ChevronRight, Database, Download, Bug, Users, Hash, Fingerprint, AlertTriangle, ExternalLink, Filter, Monitor, ArrowLeft, Eye } from "lucide-react";
import { toast } from "sonner";
import { pushTimelineEvent } from "@/lib/timeline";
import { useLocker, guessType } from "@/lib/locker";
import { copyText } from "@/lib/copy";
import { sendToCase } from "@/lib/handoff";
import { usePanelNav } from "@/lib/usePanelNav";
import { CVE_DB, PAGE_SIZE, cvssColor, cvssBg, ACTORS, techniqueLabel, genMarkdown, detectType, validateHash, mockResult, TONE, JA3_DB, UA_DB } from "@/data/intel";

export const Route = createFileRoute("/intel")({ component: IntelPage });

type IntelTab = "cve" | "actors" | "hash" | "ja3";
const TABS: { id: IntelTab; label: string; icon: typeof Bug }[] = [
  { id: "cve", label: "CVE Database", icon: Bug },
  { id: "actors", label: "Threat Actors", icon: Users },
  { id: "hash", label: "Hash Lookup", icon: Hash },
  { id: "ja3", label: "JA3/UA", icon: Fingerprint },
];

function IntelPage() {
  const search = useSearch({ from: Route.id, select: (s: Record<string, string>) => s.tab as IntelTab | undefined });
  const [tab, setTab] = useState<IntelTab>(search || "cve");

  const meta = useMemo(() => {
    if (tab === "cve") return [
      { label: "total", value: String(CVE_DB.length), tone: "primary" as const },
      { label: "critical", value: String(CVE_DB.filter(c => c.cvss >= 9).length), tone: "destructive" as const },
    ];
    if (tab === "actors") return [{ label: "actors", value: String(ACTORS.length), tone: "primary" as const }];
    if (tab === "ja3") return [
      { label: "JA3/JA4", value: String(JA3_DB.length), tone: "primary" as const },
      { label: "UA", value: String(UA_DB.length), tone: "primary" as const },
    ];
    return undefined;
  }, [tab]);

  return (
    <PageShell
      eyebrow="TOOLS / INTELLIGENCE LOOKUP"
      title="Intelligence Lookup"
      description="CVE database, threat actors, hash reputation, and TLS fingerprint lookup — unified."
      crumbs={[{ label: "Tools" }, { label: "Intel" }]}
      meta={meta}
    >
      <div className="flex items-center gap-2 mb-4">
        {TABS.map((t) => (
          <button key={t.id} onClick={() => setTab(t.id)}
            className={"rounded border px-3 py-1.5 text-mono ba-text-2xs uppercase tracking-widest transition-colors " + (tab === t.id ? "border-primary bg-primary/15 text-primary" : "border-border bg-card/40 text-muted-foreground hover:text-foreground")}>
            <t.icon className="mr-1 inline h-3 w-3" /> {t.label}
          </button>
        ))}
      </div>

      {tab === "cve" && <CveTab />}
      {tab === "actors" && <ActorsTab />}
      {tab === "hash" && <HashTab />}
      {tab === "ja3" && <Ja3Tab />}
    </PageShell>
  );
}

/* ─── CVE Tab ─── */

function CveTab() {
  const locker = useLocker();
  const [query, setQuery] = useState("");
  const [selectedVendor, setSelectedVendor] = useState<string | null>(null);
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [sortBy, setSortBy] = useState<"cvss" | "epss" | "published">("cvss");
  const [page, setPage] = useState(0);
  const [copiedId, setCopiedId] = useState("");

  useEffect(() => {
    function handleKey(e: KeyboardEvent) { if (e.key === "Escape") { setQuery(""); setSelectedVendor(null); setSeverityFilter("all"); } }
    window.addEventListener("keydown", handleKey);
    return () => window.removeEventListener("keydown", handleKey);
  }, []);

  const vendors = useMemo(() => Array.from(new Set(CVE_DB.map((c) => c.vendor))).sort(), []);

  const filtered = useMemo(() => {
    let r = CVE_DB;
    if (query.trim()) { const q = query.toLowerCase(); r = r.filter((c) => c.id.toLowerCase().includes(q) || c.description.toLowerCase().includes(q) || c.vendor.toLowerCase().includes(q)); }
    if (selectedVendor) r = r.filter((c) => c.vendor === selectedVendor);
    if (severityFilter === "critical") r = r.filter((c) => c.cvss >= 9);
    else if (severityFilter === "high") r = r.filter((c) => c.cvss >= 7 && c.cvss < 9);
    else if (severityFilter === "medium") r = r.filter((c) => c.cvss >= 4 && c.cvss < 7);
    else if (severityFilter === "low") r = r.filter((c) => c.cvss < 4);
    r.sort((a, b) => { if (sortBy === "cvss") return b.cvss - a.cvss; if (sortBy === "epss") return b.epss - a.epss; return new Date(b.published).getTime() - new Date(a.published).getTime(); });
    return r;
  }, [query, selectedVendor, severityFilter, sortBy]);

  const totalPages = Math.ceil(filtered.length / PAGE_SIZE);
  const paged = useMemo(() => filtered.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE), [filtered, page]);
  const { index: selectedIndex } = usePanelNav(paged, { onCopy: (item) => copyText(item.id), onAttach: (item) => sendToCase({ body: JSON.stringify(item), source: "/intel", kind: "evidence" }) });

  useEffect(() => { setPage(0); }, [query, selectedVendor, severityFilter, sortBy]);
  const stats = useMemo(() => ({ total: CVE_DB.length, filtered: filtered.length, critical: filtered.filter((c) => c.cvss >= 9).length }), [filtered]);

  function handleExport() {
    const md = ["# CVE Database Search Results", "", `**Query:** ${query || "(none)"} · **Filtered:** ${stats.filtered} of ${stats.total}`, "",
      ...filtered.map((c) => [`## ${c.id}`, `- **CVSS:** ${c.cvss.toFixed(1)}`, `- **EPSS:** ${(c.epss * 100).toFixed(0)}%`, `- **KEV:** ${c.kev ? "Yes" : "No"}`, `- **Vendor:** ${c.vendor}`, `- **Published:** ${c.published}`, `- **Affected:** ${c.affected}`, `- **Description:** ${c.description}`, `- **Exploits:** ${[c.exploit.metasploit && "Metasploit", c.exploit.nuclei && "Nuclei", c.exploit.exploitDb && "ExploitDB"].filter(Boolean).join(", ") || "None"}`, ""].join("\n"))].join("\n");
    const blob = new Blob([md], { type: "text/markdown" });
    const a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = `cve-${Date.now()}.md`; a.click();
  }

  return (
    <>
      <div className="flex flex-wrap items-center gap-2 mb-3">
        <div className="relative flex-1 min-w-[200px] max-w-sm">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
          <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search CVE ID, description, or vendor…" className="w-full rounded border border-border bg-background/60 py-1.5 pl-8 pr-3 font-mono text-sm text-foreground outline-none placeholder:text-muted-foreground/60 focus:border-primary/50" />
        </div>
        <div className="flex items-center gap-1">
          {(["all", "critical", "high", "medium", "low"] as const).map((s) => (
            <button key={s} onClick={() => setSeverityFilter(s)}
              className={"rounded border px-2 py-1 text-mono text-[10px] uppercase tracking-widest " + (severityFilter === s ? "border-primary bg-primary/15 text-primary" : "border-border text-muted-foreground hover:text-foreground")}>
              {s === "critical" ? "9+" : s === "high" ? "7-8.9" : s === "medium" ? "4-6.9" : s === "low" ? "<4" : "all"}
            </button>
          ))}
        </div>
        <select value={selectedVendor || ""} onChange={(e) => setSelectedVendor(e.target.value || null)} className="rounded border border-border bg-background/60 px-2 py-1.5 font-mono text-sm text-foreground outline-none focus:border-primary/50">
          <option value="">All vendors</option>
          {vendors.map((v) => <option key={v} value={v}>{v}</option>)}
        </select>
        <select value={sortBy} onChange={(e) => setSortBy(e.target.value as any)} className="rounded border border-border bg-background/60 px-2 py-1.5 font-mono text-sm text-foreground outline-none focus:border-primary/50">
          <option value="cvss">Sort: CVSS</option>
          <option value="epss">Sort: EPSS</option>
          <option value="published">Sort: Date</option>
        </select>
      </div>

      <div className="flex items-center gap-3 px-1 mb-2 text-mono text-[10px] text-muted-foreground">
        <span>{stats.filtered} of {stats.total} CVEs</span>
        {stats.critical > 0 && <><span className="text-border/60">·</span><span className="text-destructive">{stats.critical} critical</span></>}
      </div>

      <div className="space-y-2">
        {paged.map((cve, i) => (
          <div key={cve.id} className={`group rounded-lg border border-border/60 bg-card/40 p-4 transition-colors hover:border-primary/30${selectedIndex === i ? " ring-1 ring-primary/50" : ""}`}>
            <div className="flex items-start justify-between gap-4">
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="font-mono text-sm font-bold text-primary">{cve.id}</span>
                  <button onClick={() => { locker.add({ value: cve.id, type: "cve", source: "/intel" }); toast("Added CVE to locker"); }} className="grid h-5 w-5 place-items-center rounded text-muted-foreground hover:text-primary opacity-0 group-hover:opacity-100 transition-opacity" title="Add to locker"><Database className="h-3 w-3" /></button>
                  <button onClick={() => { copyText(cve.id); setCopiedId(cve.id); setTimeout(() => setCopiedId(""), 1200); }} className="grid h-5 w-5 place-items-center rounded text-muted-foreground hover:text-primary opacity-0 group-hover:opacity-100 transition-opacity">{copiedId === cve.id ? <Check className="h-3 w-3 text-success" /> : <Copy className="h-3 w-3" />}</button>
                  <Chip tone={cve.kev ? "destructive" : "default"}>{cve.kev ? "KEV" : "Known"}</Chip>
                  {cve.exploit.metasploit && <Chip tone="destructive">Metasploit</Chip>}
                  {cve.exploit.nuclei && <Chip tone="warning">Nuclei</Chip>}
                  {cve.exploit.exploitDb && <Chip tone="primary">EDB</Chip>}
                </div>
                <div className="mt-1 text-sm text-foreground/80">{cve.description}</div>
                <div className="mt-1.5 flex flex-wrap items-center gap-3 font-mono text-[11px] text-muted-foreground">
                  <span>{cve.vendor}</span><span>{cve.published}</span><span>{cve.affected}</span>
                </div>
              </div>
              <div className="flex flex-col items-end gap-2 shrink-0">
                <div className={`rounded-md border px-3 py-1 text-center ${cvssBg(cve.cvss)}`}>
                  <div className={`font-mono text-lg font-bold ${cvssColor(cve.cvss)}`}>{cve.cvss.toFixed(1)}</div>
                  <div className="font-mono text-[9px] uppercase tracking-widest text-muted-foreground">CVSS</div>
                </div>
                <div className="w-28">
                  <div className="flex items-center justify-between font-mono text-[9px] text-muted-foreground mb-0.5"><span>EPSS</span><span>{(cve.epss * 100).toFixed(0)}%</span></div>
                  <div className="h-1.5 w-full rounded-full bg-border/50">
                    <div className={`h-1.5 rounded-full ${cve.epss >= 0.9 ? "bg-red-500" : cve.epss >= 0.7 ? "bg-orange-500" : cve.epss >= 0.4 ? "bg-yellow-500" : "bg-green-500"}`} style={{ width: `${cve.epss * 100}%` }} />
                  </div>
                </div>
              </div>
            </div>
          </div>
        ))}
        {filtered.length === 0 && <Empty icon={Search} title="No CVEs found" hint="Try a different search term, severity, or clear vendor filter." />}
      </div>

      {totalPages > 1 && (
        <div className="flex items-center justify-center gap-2 mt-4">
          <button onClick={() => setPage((p) => Math.max(0, p - 1))} disabled={page === 0} className="inline-flex items-center gap-1 rounded border border-border px-2 py-1 text-mono text-[10px] uppercase text-muted-foreground hover:text-foreground disabled:opacity-30"><ChevronLeft className="h-3 w-3" /> Prev</button>
          <span className="text-mono text-[11px] text-muted-foreground">Page {page + 1} of {totalPages}</span>
          <button onClick={() => setPage((p) => Math.min(totalPages - 1, p + 1))} disabled={page >= totalPages - 1} className="inline-flex items-center gap-1 rounded border border-border px-2 py-1 text-mono text-[10px] uppercase text-muted-foreground hover:text-foreground disabled:opacity-30">Next <ChevronRight className="h-3 w-3" /></button>
        </div>
      )}

      <div className="mt-4 flex items-center gap-2">
        <button onClick={handleExport} className="inline-flex items-center gap-1 rounded border border-border px-2 py-0.5 text-mono ba-text-2xs uppercase text-muted-foreground hover:text-foreground"><Download className="h-3 w-3" /> md</button>
        <SendToRow targets={[{ label: "Detection Editor", to: "/detection", icon: Search }, { label: "Case Notebook", to: "/case", icon: Database }]} />
      </div>
    </>
  );
}

/* ─── Threat Actors Tab ─── */

function ActorsTab() {
  const locker = useLocker();
  const [query, setQuery] = useState("");
  const [selectedTechnique, setSelectedTechnique] = useState<string | null>(null);
  const [selectedActor, setSelectedActor] = useState<string | null>(null);
  const [copied, setCopied] = useState("");

  useEffect(() => {
    if (selectedActor) pushTimelineEvent({ source: "intel", verb: "viewed", detail: `Viewed threat actor: ${selectedActor}`, target: selectedActor });
  }, [selectedActor]);

  useEffect(() => {
    function handleKey(e: KeyboardEvent) { if (e.key === "Escape" && selectedActor) { setSelectedActor(null); e.preventDefault(); } }
    window.addEventListener("keydown", handleKey);
    return () => window.removeEventListener("keydown", handleKey);
  }, [selectedActor]);

  const allTechniques = useMemo(() => Array.from(new Set(ACTORS.flatMap((a) => a.techniques))).sort(), []);

  const filtered = useMemo(() => {
    let r = ACTORS;
    if (query.trim()) { const q = query.toLowerCase(); r = r.filter((a) => a.name.toLowerCase().includes(q) || a.aliases.some((al) => al.toLowerCase().includes(q)) || a.techniques.some((t) => t.toLowerCase().includes(q)) || a.tools.some((tl) => tl.toLowerCase().includes(q))); }
    if (selectedTechnique) r = r.filter((a) => a.techniques.includes(selectedTechnique));
    return r;
  }, [query, selectedTechnique]);

  const selected = useMemo(() => ACTORS.find((a) => a.name === selectedActor) || null, [selectedActor]);
  const reverseTech = useMemo(() => selectedTechnique ? ACTORS.filter((a) => a.techniques.includes(selectedTechnique)).map((a) => a.name) : [], [selectedTechnique]);

  const addToLocker = useCallback((value: string) => { locker.add({ value, type: guessType(value), source: "intel" }); }, [locker]);

  function exportMarkdown(actor: typeof ACTORS[0]) {
    const md = genMarkdown(actor);
    const blob = new Blob([md], { type: "text/markdown" });
    const a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = `threat-actor-${actor.name.toLowerCase().replace(/\s+/g, "-")}.md`; a.click();
  }

  return (
    <div className="grid grid-cols-[280px_1fr] gap-4">
      <div className="space-y-3">
        <Panel title="Technique Filter" priority="secondary" bodyClassName="p-0">
          <div className="divide-y divide-border/50 max-h-80 overflow-y-auto">
            <button onClick={() => setSelectedTechnique(null)} className={"w-full px-3 py-1.5 text-left text-mono text-[11px] " + (!selectedTechnique ? "bg-primary/10 text-primary" : "text-muted-foreground hover:text-foreground")}>All techniques</button>
            {allTechniques.map((t) => (
              <button key={t} onClick={() => setSelectedTechnique(t === selectedTechnique ? null : t)} className={"w-full px-3 py-1.5 text-left font-mono text-[11px] " + (selectedTechnique === t ? "bg-primary/10 text-primary" : "text-muted-foreground hover:text-foreground")}>
                {techniqueLabel[t] || t}
                <span className="ml-1 text-[9px] opacity-60">({ACTORS.filter((a) => a.techniques.includes(t)).length})</span>
              </button>
            ))}
          </div>
        </Panel>
        {selectedTechnique && reverseTech.length > 0 && (
          <Panel title={`Used by (${reverseTech.length})`} priority="secondary">
            <div className="flex flex-wrap gap-1">{reverseTech.map((n) => <Chip key={n} tone="warning">{n}</Chip>)}</div>
          </Panel>
        )}
      </div>

      <div className="space-y-4">
        <div className="relative">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
          <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search actor, alias, technique, or tool…" className="w-full rounded border border-border bg-background/60 py-1.5 pl-8 pr-3 font-mono text-sm text-foreground outline-none placeholder:text-muted-foreground/60 focus:border-primary/50" />
        </div>

        {selected ? (
          <div className="space-y-4">
            <button onClick={() => setSelectedActor(null)} className="inline-flex items-center gap-1 rounded border border-border px-2 py-1 text-mono ba-text-2xs uppercase text-muted-foreground hover:text-foreground"><ArrowLeft className="h-3 w-3" /> Back to list</button>
            <Panel title={selected.name} actions={
              <div className="flex items-center gap-1">
                <button onClick={() => exportMarkdown(selected)} className="inline-flex items-center gap-1 rounded border border-border px-2 py-0.5 text-mono ba-text-2xs uppercase text-muted-foreground hover:text-foreground"><Download className="h-3 w-3" /> MD</button>
                <button onClick={() => { copyText(JSON.stringify(selected, null, 2)); setCopied(selected.name); setTimeout(() => setCopied(""), 1200); }} className="inline-flex items-center gap-1 rounded border border-border px-2 py-0.5 text-mono ba-text-2xs uppercase text-muted-foreground hover:text-foreground">{copied === selected.name ? <><Check className="h-3 w-3 text-success" /> copied</> : <><Copy className="h-3 w-3" /> JSON</>}</button>
              </div>
            }>
              <div className="space-y-3">
                <div className="flex flex-wrap gap-1.5">{selected.aliases.map((a) => <Chip key={a} tone="primary">{a}</Chip>)}</div>
                <div className="grid grid-cols-3 gap-3 font-mono text-sm">
                  <div><span className="text-[10px] uppercase tracking-widest text-muted-foreground">Origin</span><div className="text-foreground/90">{selected.origin}</div></div>
                  <div><span className="text-[10px] uppercase tracking-widest text-muted-foreground">Motivation</span><div className="text-foreground/90">{selected.motivation}</div></div>
                  <div><span className="text-[10px] uppercase tracking-widest text-muted-foreground">First Seen</span><div className="text-foreground/90">{selected.firstSeen}</div></div>
                </div>
                <div><span className="text-[10px] uppercase tracking-widest text-muted-foreground">Techniques</span>
                  <div className="mt-1 flex flex-wrap gap-1">{selected.techniques.map((t) => <Chip key={t} tone="warning">{techniqueLabel[t] || t}</Chip>)}</div>
                </div>
                <div><span className="text-[10px] uppercase tracking-widest text-muted-foreground">Tools</span>
                  <div className="mt-1 flex flex-wrap gap-1">{selected.tools.map((t) => <button key={t} onClick={() => addToLocker(t)} className="rounded bg-destructive/10 px-2.5 py-0.5 text-mono text-[11px] text-destructive transition-colors hover:bg-destructive/20">{t}</button>)}</div>
                </div>
                <div><span className="text-[10px] uppercase tracking-widest text-muted-foreground">Targets</span>
                  <div className="mt-1 flex flex-wrap gap-1">{selected.targets.map((t) => <Chip key={t} tone="default">{t}</Chip>)}</div>
                </div>
                <div><span className="text-[10px] uppercase tracking-widest text-muted-foreground">Campaigns</span>
                  <div className="mt-1 flex flex-wrap gap-1">{selected.campaigns.map((c) => <button key={c} onClick={() => { locker.add({ value: c, type: "text", source: "/intel" }); toast(`Added ${c} to locker`); }} className="rounded border border-border/50 bg-card/40 px-2 py-0.5 font-mono ba-text-2xs text-muted-foreground hover:text-foreground">{c}</button>)}</div>
                </div>
              </div>
            </Panel>
            <SendToRow targets={[
              { label: "case", to: `/case?note=${encodeURIComponent(`${selected.name} (${selected.aliases[0]}) — ${selected.motivation}, origin: ${selected.origin}, first seen: ${selected.firstSeen}. Tools: ${selected.tools.join(", ")}. Techniques: ${selected.techniques.join(", ")}.`)}`, icon: Eye },
              { label: "detection", to: `/detection?note=${encodeURIComponent(`Threat actor ${selected.name} (${selected.aliases[0]}) — techniques: ${selected.techniques.join(", ")}, tools: ${selected.tools.join(", ")}`)}`, icon: Search },
            ]} />
          </div>
        ) : (
          <div className="space-y-2">
            {filtered.map((actor) => (
              <button key={actor.name} onClick={() => setSelectedActor(actor.name)} className="w-full rounded-lg border border-border/60 bg-card/40 p-3 text-left transition-colors hover:border-primary/30">
                <div className="flex items-start justify-between gap-2">
                  <div>
                    <div className="font-mono text-sm font-bold text-foreground/90">{actor.name}</div>
                    <div className="mt-0.5 text-[11px] text-muted-foreground">{actor.aliases.slice(0, 3).join(", ")}{actor.aliases.length > 3 ? "…" : ""}</div>
                  </div>
                  <div className="flex items-center gap-1.5 shrink-0">
                    <button onClick={(e) => { e.stopPropagation(); locker.add({ value: actor.name, type: "text", source: "/intel" }); toast(`Added ${actor.name} to locker`); }} className="rounded border border-border/50 bg-card/40 px-1.5 py-0.5 text-mono ba-text-2xs uppercase text-muted-foreground hover:text-foreground">+</button>
                    <Chip tone="default">{actor.origin}</Chip>
                    <Chip tone={actor.motivation.includes("Financial") ? "warning" : "primary"}>{actor.motivation.split("/")[0]}</Chip>
                  </div>
                </div>
                <div className="mt-2 flex flex-wrap gap-1">
                  {actor.techniques.slice(0, 4).map((t) => <Chip key={t} tone="warning">{t}</Chip>)}
                  {actor.techniques.length > 4 && <Chip tone="default">+{actor.techniques.length - 4}</Chip>}
                </div>
              </button>
            ))}
            {filtered.length === 0 && <Empty icon={Users} title="No actors found" hint="Try a different search term or clear the technique filter." />}
          </div>
        )}
      </div>
    </div>
  );
}

/* ─── Hash Lookup Tab ─── */

function VerdictBar({ detections, total }: { detections: number; total: number }) {
  const pct = total > 0 ? (detections / total) * 100 : 0;
  const color = pct > 30 ? "bg-destructive" : pct > 5 ? "bg-warning" : "bg-success";
  return (
    <div className="flex items-center gap-2">
      <div className="h-1.5 w-16 rounded-full bg-border/50">
        <div className={`h-1.5 rounded-full ${color}`} style={{ width: `${Math.min(pct, 100)}%` }} />
      </div>
      <span className={detections > 0 ? "text-destructive" : "text-muted-foreground"}>{detections}/{total}</span>
    </div>
  );
}

function HashTab() {
  const locker = useLocker();
  const [input, setInput] = useState("");
  const [lookedUp, setLookedUp] = useState(false);
  const [copied, setCopied] = useState("");

  useEffect(() => {
    function handleKey(e: KeyboardEvent) { if (e.key === "Escape" && lookedUp) { setInput(""); setLookedUp(false); } }
    window.addEventListener("keydown", handleKey);
    return () => window.removeEventListener("keydown", handleKey);
  }, [lookedUp]);

  const hashes = useMemo(() => input.split("\n").map((s) => s.trim()).filter((s) => s.length > 0), [input]);
  const validHashes = useMemo(() => hashes.filter(h => validateHash(h).valid), [hashes]);
  const invalidHashes = useMemo(() => hashes.filter(h => !validateHash(h).valid).map(h => ({ hash: h, reason: validateHash(h).reason! })), [hashes]);

  const typeBreakdown = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const h of hashes) { const t = detectType(h); counts[t] = (counts[t] || 0) + 1; }
    return counts;
  }, [hashes]);

  const results = useMemo(() => lookedUp ? validHashes.map(mockResult) : [], [validHashes, lookedUp]);
  const { index: selectedIndex } = usePanelNav(results, { onCopy: (item) => copyText(item.hash), onAttach: (item) => sendToCase({ body: JSON.stringify(item), source: "/intel", kind: "evidence" }) });

  const stats = useMemo(() => {
    if (!results.length) return null;
    return { total: results.length, malicious: results.filter((r) => r.verdict === "malicious").length, suspicious: results.filter((r) => r.verdict === "suspicious").length, clean: results.filter((r) => r.verdict === "clean").length };
  }, [results]);

  function handleLookup() {
    if (validHashes.length === 0) return;
    setLookedUp(true);
    pushTimelineEvent({ source: "intel", verb: "hash-lookup", detail: `Looked up ${validHashes.length} hash${validHashes.length > 1 ? "es" : ""}`, result: `${validHashes.filter(h => mockResult(h).verdict === "malicious").length} malicious` });
  }

  function handleExportCsv() {
    const rows = results.map((r) => `${r.hash},${r.type},${r.verdict},${r.firstSeen},${r.avDetections},${r.avTotal},${r.malware}`);
    const blob = new Blob([["hash,type,verdict,first_seen,av_detections,av_total,malware", ...rows].join("\n")], { type: "text/csv;charset=utf-8" });
    const a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = "hash-lookup.csv"; a.click();
  }

  return (
    <>
      <Panel title="Input Hashes">
        <textarea value={input} onChange={(e) => { setInput(e.target.value); setLookedUp(false); }}
          placeholder="Paste hashes, one per line:&#10;d41d8cd98f00b204e9800998ecf8427e&#10;e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
          className="h-36 w-full resize-y rounded border border-border bg-background/60 p-3 font-mono text-sm text-foreground outline-none placeholder:text-muted-foreground/60 focus:border-primary/50" />
        <div className="mt-2 flex items-center justify-between flex-wrap gap-2">
          <div className="flex items-center gap-3 text-mono text-[10px] text-muted-foreground">
            <span>{hashes.length} hash{hashes.length !== 1 ? "es" : ""}</span>
            {hashes.length > 0 && (<>{Object.entries(typeBreakdown).map(([type, count]) => <span key={type}>{count} {type}</span>)}</>)}
            {invalidHashes.length > 0 && <><span className="text-border/60">·</span><span className="text-warning flex items-center gap-1"><AlertTriangle className="h-3 w-3" /> {invalidHashes.length} invalid</span></>}
          </div>
          <div className="flex items-center gap-2">
            <button onClick={handleLookup} disabled={validHashes.length === 0} className="inline-flex items-center gap-1 rounded border border-primary/40 bg-primary/10 px-3 py-1.5 text-mono ba-text-2xs uppercase tracking-widest text-primary hover:bg-primary/20 disabled:opacity-40"><Search className="h-3.5 w-3.5" /> Lookup All</button>
            {results.length > 0 && <button onClick={() => { results.forEach(r => locker.add({ value: r.hash, type: r.type.toLowerCase() as any, source: "/intel" })); toast(`Added ${results.length} hashes to locker`); }} className="inline-flex items-center gap-1 rounded border border-border/50 bg-card/40 px-2 py-1.5 text-mono ba-text-2xs uppercase tracking-widest text-muted-foreground hover:text-primary"><Database className="h-3 w-3" /> all to locker</button>}
            {results.length > 0 && <button onClick={handleExportCsv} className="inline-flex items-center gap-1 rounded border border-border px-2 py-1.5 text-mono ba-text-2xs uppercase text-muted-foreground hover:text-foreground"><Download className="h-3 w-3" /> CSV</button>}
          </div>
        </div>
        {invalidHashes.length > 0 && !lookedUp && (
          <div className="mt-2 space-y-0.5">
            {invalidHashes.slice(0, 3).map(({ hash, reason }) => (
              <div key={hash} className="flex items-center gap-1 text-mono text-[10px] text-warning"><AlertTriangle className="h-2.5 w-2.5" /><span className="truncate">{hash}</span><span className="text-muted-foreground">— {reason}</span></div>
            ))}
            {invalidHashes.length > 3 && <div className="text-mono text-[10px] text-muted-foreground">…and {invalidHashes.length - 3} more</div>}
          </div>
        )}
      </Panel>

      {results.length > 0 && stats && (
        <>
          {(["malicious", "suspicious", "clean", "unknown"] as const).map((v) => {
            const count = stats[v as keyof typeof stats] as number;
            if (!count) return null;
            return (
              <div key={v} className="flex items-center gap-2 px-1 mt-2">
                <button onClick={() => { copyText(results.filter(r => r.verdict === v).map(r => r.hash).join("\n")); toast(`Copied ${count} ${v} hashes`); }} className="flex items-center gap-1 rounded border border-border/60 bg-card/30 px-2 py-0.5 text-mono text-[10px] text-muted-foreground hover:text-foreground"><Filter className="h-2.5 w-2.5" /><Chip tone={TONE[v]}>{count} {v}</Chip></button>
              </div>
            );
          })}

          <Panel title="Results" bodyClassName="p-0">
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead><tr className="border-b border-border text-left text-mono ba-text-2xs uppercase tracking-widest text-muted-foreground"><th className="px-3 py-2">Hash</th><th className="px-3 py-2">Type</th><th className="px-3 py-2">Verdict</th><th className="px-3 py-2">AV Detection</th><th className="px-3 py-2">Malware</th><th className="px-3 py-2">First Seen</th><th className="px-3 py-2 w-20"></th></tr></thead>
                <tbody className="divide-y divide-border/50">
                  {results.map((r, i) => (
                    <tr key={i} className={`group hover:bg-card/30${selectedIndex === i ? " bg-primary/5" : ""}`}>
                      <td className="px-3 py-2"><code className="font-mono text-sm text-foreground/90">{r.hash.slice(0, 20)}…</code></td>
                      <td className="px-3 py-2"><Chip tone="default">{r.type}</Chip></td>
                      <td className="px-3 py-2"><Chip tone={TONE[r.verdict]}>{r.verdict}</Chip></td>
                      <td className="px-3 py-2"><VerdictBar detections={r.avDetections} total={r.avTotal} /></td>
                      <td className="px-3 py-2 font-mono text-sm text-foreground/80">{r.malware}</td>
                      <td className="px-3 py-2 font-mono text-[11px] text-muted-foreground">{r.firstSeen}</td>
                      <td className="px-3 py-2">
                        <div className="flex items-center gap-1 opacity-0 transition-opacity group-hover:opacity-100">
                          <button onClick={() => { locker.add({ value: r.hash, type: r.type.toLowerCase() as any, source: "/intel" }); toast("Added to locker"); }} className="grid h-6 w-6 place-items-center rounded text-muted-foreground hover:text-primary" title="Add to locker"><Database className="h-3 w-3" /></button>
                          <button onClick={() => { copyText(r.hash); setCopied(r.hash); setTimeout(() => setCopied(""), 1200); }} className="grid h-6 w-6 place-items-center rounded text-muted-foreground hover:text-primary">{copied === r.hash ? <Check className="h-3 w-3 text-success" /> : <Copy className="h-3 w-3" />}</button>
                          <a href={`https://www.virustotal.com/gui/search/${r.hash}`} target="_blank" rel="noopener noreferrer" className="grid h-6 w-6 place-items-center rounded text-muted-foreground hover:text-primary"><ExternalLink className="h-3 w-3" /></a>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="border-t border-border bg-card/30 px-3 py-1.5 text-right text-mono text-[10px] text-muted-foreground">
              {stats.malicious > 0 ? `${stats.malicious}/${stats.total} malicious (${Math.round((stats.malicious / stats.total) * 100)}%)` : `${stats.total} hashes checked — all clear`}
            </div>
          </Panel>
        </>
      )}

      {lookedUp && results.length === 0 && <Empty icon={Hash} title="No valid hashes to look up" hint="Paste one or more valid hashes above and click Lookup All. Supported: MD5, SHA1, SHA256, SHA512." />}
      {lookedUp && results.length > 0 && <SendToRow targets={[{ label: "Detection Editor", to: "/detection", icon: Search }, { label: "Case Notebook", to: "/case", icon: Hash }]} />}
    </>
  );
}

/* ─── JA3/UA Tab ─── */

function Ja3Tab() {
  const locker = useLocker();
  const [ja3Query, setJa3Query] = useState("");
  const [uaQuery, setUaQuery] = useState("");
  const [tab, setTab] = useState<"ja3" | "ua">("ja3");
  const [copiedHash, setCopiedHash] = useState("");

  useEffect(() => {
    function handleKey(e: KeyboardEvent) { if (e.key === "Escape") { setJa3Query(""); setUaQuery(""); } }
    window.addEventListener("keydown", handleKey);
    return () => window.removeEventListener("keydown", handleKey);
  }, []);

  const ja3Filtered = useMemo(() => {
    const q = ja3Query.toLowerCase();
    return !q ? JA3_DB : JA3_DB.filter((e) => e.hash.toLowerCase().includes(q) || e.malware.toLowerCase().includes(q));
  }, [ja3Query]);

  const ja3Stats = useMemo(() => ({ total: JA3_DB.length, ja3: JA3_DB.filter((e) => e.type === "JA3").length, ja4: JA3_DB.filter((e) => e.type === "JA4").length, filtered: ja3Filtered.length }), [ja3Filtered]);

  const uaFiltered = useMemo(() => {
    const q = uaQuery.toLowerCase();
    return !q ? UA_DB : UA_DB.filter((e) => e.ua.toLowerCase().includes(q) || e.type.toLowerCase().includes(q) || e.os.toLowerCase().includes(q));
  }, [uaQuery]);

  const uaStats = useMemo(() => ({ total: UA_DB.length, filtered: uaFiltered.length, types: new Set(UA_DB.map((e) => e.type)).size }), [uaFiltered]);

  useEffect(() => { if (tab === "ja3" && ja3Query) pushTimelineEvent({ source: "intel", verb: "ja3-searched", detail: `ja3: ${ja3Query}`, result: `${ja3Filtered.length} results` }); }, [ja3Filtered, tab, ja3Query]);
  useEffect(() => { if (tab === "ua" && uaQuery) pushTimelineEvent({ source: "intel", verb: "ua-searched", detail: `ua: ${uaQuery}`, result: `${uaFiltered.length} results` }); }, [uaFiltered, tab, uaQuery]);

  function copyAll() {
    const text = (tab === "ja3" ? ja3Filtered : uaFiltered).map((e: any) => e.hash || e.ua).join("\n");
    copyText(text);
    setCopiedHash("__all__");
    setTimeout(() => setCopiedHash(""), 1200);
  }

  function handleExport() {
    const md = tab === "ja3"
      ? ["# JA3/JA4 Fingerprint Lookup Results", "", `**Showing:** ${ja3Filtered.length} of ${ja3Stats.total} entries`, "",
          ...(ja3Filtered as typeof JA3_DB).map((e) => [`## ${e.hash.slice(0, 32)}...`, `- **Type:** ${e.type}`, `- **Malware:** ${e.malware}`, `- **First Seen:** ${e.firstSeen}`, `- **Last Seen:** ${e.lastSeen}`, ""].join("\n"))].join("\n")
      : ["# User-Agent Lookup Results", "", `**Showing:** ${uaFiltered.length} of ${uaStats.total} entries`, "",
          ...(uaFiltered as typeof UA_DB).map((e) => [`## ${e.ua.slice(0, 80)}...`, `- **Type:** ${e.type}`, `- **OS:** ${e.os}`, `- **Frequency:** ${e.freq}`, ""].join("\n"))].join("\n");
    const blob = new Blob([md], { type: "text/markdown" });
    const a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = `ja3-ua-${Date.now()}.md`; a.click();
  }

  return (
    <>
      <div className="flex items-center gap-2 mb-4">
        <button onClick={() => setTab("ja3")} className={"rounded border px-3 py-1.5 text-mono ba-text-2xs uppercase tracking-widest transition-colors " + (tab === "ja3" ? "border-primary bg-primary/15 text-primary" : "border-border bg-card/40 text-muted-foreground hover:text-foreground")}><Fingerprint className="mr-1 inline h-3 w-3" /> JA3/JA4</button>
        <button onClick={() => setTab("ua")} className={"rounded border px-3 py-1.5 text-mono ba-text-2xs uppercase tracking-widest transition-colors " + (tab === "ua" ? "border-primary bg-primary/15 text-primary" : "border-border bg-card/40 text-muted-foreground hover:text-foreground")}><Monitor className="mr-1 inline h-3 w-3" /> User-Agent</button>
      </div>

      {tab === "ja3" ? (
        <Panel title="JA3/JA4 Fingerprints" bodyClassName="p-0" actions={
          <button onClick={copyAll} className="inline-flex items-center gap-1 rounded border border-border px-2 py-0.5 text-mono ba-text-2xs uppercase text-muted-foreground hover:text-foreground">
            {copiedHash === "__all__" ? <><Check className="h-3 w-3 text-success" /> copied</> : <><Copy className="h-3 w-3" /> copy all</>}
          </button>
        }>
          <div className="border-b border-border p-2">
            <div className="flex items-center gap-2">
              <div className="relative flex-1">
                <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
                <input value={ja3Query} onChange={(e) => setJa3Query(e.target.value)} placeholder="Search hash or malware family…" className="w-full rounded border border-border bg-background/60 py-1.5 pl-8 pr-3 font-mono text-sm text-foreground outline-none placeholder:text-muted-foreground/60 focus:border-primary/50" />
              </div>
              <span className="text-mono text-[10px] text-muted-foreground whitespace-nowrap">{ja3Stats.filtered}/{ja3Stats.total} · {ja3Stats.ja3} JA3 · {ja3Stats.ja4} JA4</span>
            </div>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead><tr className="border-b border-border text-left text-mono ba-text-2xs uppercase tracking-widest text-muted-foreground"><th className="px-3 py-2">Hash</th><th className="px-3 py-2">Type</th><th className="px-3 py-2">Malware</th><th className="px-3 py-2">First Seen</th><th className="px-3 py-2">Last Seen</th><th className="px-3 py-2 w-10"></th><th className="px-3 py-2 w-10"></th></tr></thead>
              <tbody className="divide-y divide-border/50">
                {ja3Filtered.map((e, i) => (
                  <tr key={i} className="group hover:bg-card/30">
                    <td className="px-3 py-2"><code className="font-mono text-[11px] text-foreground/90">{e.hash.slice(0, 32)}…</code></td>
                    <td className="px-3 py-2"><Chip tone={e.type === "JA4" ? "warning" : "primary"}>{e.type}</Chip></td>
                    <td className="px-3 py-2"><span className="font-mono text-sm text-foreground/90">{e.malware}</span></td>
                    <td className="px-3 py-2 font-mono text-[11px] text-muted-foreground">{e.firstSeen}</td>
                    <td className="px-3 py-2 font-mono text-[11px] text-muted-foreground">{e.lastSeen}</td>
                    <td className="px-3 py-2"><button onClick={() => { locker.add({ value: e.hash, type: "ja3", source: "/intel" }); toast("Added hash to locker"); }} className="opacity-0 group-hover:opacity-100 grid h-6 w-6 place-items-center rounded text-muted-foreground hover:text-primary"><Database className="h-3 w-3" /></button></td>
                    <td className="px-3 py-2"><button onClick={() => { copyText(e.hash); setCopiedHash(e.hash); setTimeout(() => setCopiedHash(""), 1200); }} className="opacity-0 group-hover:opacity-100 grid h-6 w-6 place-items-center rounded text-muted-foreground hover:text-primary">{copiedHash === e.hash ? <Check className="h-3 w-3 text-success" /> : <Copy className="h-3 w-3" />}</button></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>
      ) : (
        <Panel title="User-Agent Database" bodyClassName="p-0" actions={
          <span className="text-mono text-[10px] text-muted-foreground">{uaStats.filtered}/{uaStats.total} · {uaStats.types} types</span>
        }>
          <div className="border-b border-border p-2">
            <div className="relative">
              <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
              <input value={uaQuery} onChange={(e) => setUaQuery(e.target.value)} placeholder="Search UA string, type, or OS…" className="w-full rounded border border-border bg-background/60 py-1.5 pl-8 pr-3 font-mono text-sm text-foreground outline-none placeholder:text-muted-foreground/60 focus:border-primary/50" />
            </div>
          </div>
          <div className="overflow-x-auto max-h-[70vh] overflow-y-auto">
            <table className="w-full">
              <thead><tr className="border-b border-border text-left text-mono ba-text-2xs uppercase tracking-widest text-muted-foreground sticky top-0 bg-background"><th className="px-3 py-2">User-Agent</th><th className="px-3 py-2 w-20">Type</th><th className="px-3 py-2 w-20">OS</th><th className="px-3 py-2 w-24">Frequency</th><th className="px-3 py-2 w-10"></th></tr></thead>
              <tbody className="divide-y divide-border/50">
                {uaFiltered.map((e, i) => (
                  <tr key={i} className="group hover:bg-card/30">
                    <td className="max-w-xs px-3 py-2"><code className="block truncate font-mono text-[11px] text-foreground/90" title={e.ua}>{e.ua}</code></td>
                    <td className="px-3 py-2"><Chip tone={e.type === "Scanner" ? "destructive" : e.type === "Bot" ? "warning" : e.type === "Library" ? "primary" : "default"}>{e.type}</Chip></td>
                    <td className="px-3 py-2 font-mono text-[11px] text-muted-foreground">{e.os}</td>
                    <td className="px-3 py-2"><Chip tone={e.freq === "Very High" ? "success" : e.freq === "High" ? "primary" : "default"}>{e.freq}</Chip></td>
                    <td className="px-3 py-2"><button onClick={() => { locker.add({ value: e.ua, type: "ua", source: "/intel" }); toast("Added UA to locker"); }} className="opacity-0 group-hover:opacity-100 grid h-6 w-6 place-items-center rounded text-muted-foreground hover:text-primary"><Database className="h-3 w-3" /></button></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>
      )}

      <div className="mt-4 flex items-center gap-2">
        <button onClick={handleExport} className="inline-flex items-center gap-1 rounded border border-border px-2 py-0.5 text-mono ba-text-2xs uppercase text-muted-foreground hover:text-foreground"><Download className="h-3 w-3" /> md</button>
        <SendToRow targets={[{ label: "Detection Editor", to: "/detection", icon: Search }, { label: "Case Notebook", to: "/case", icon: Database }]} />
      </div>
    </>
  );
}
