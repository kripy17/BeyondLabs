import { useEffect, useMemo, useState } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { PageShell } from "@/components/PageShell";
import { getHackingtoolCategories, runHackingtoolTool } from "@/api/backend";
import {
  Panel, SectionBar, Chip, Field, Empty, ResultBanner, SendToRow,
} from "@/components/soc/Workspace";
import { PreviewBadge } from "@/components/PreviewBadge";
import { sendArtifact, takePendingArtifact } from "@/lib/handoff";
import type { LucideIcon } from "lucide-react";
import {
  Swords, Search, Globe2, KeyRound, Microscope, Wifi, Zap, Code2, Package,
  FileText, Cloud, Server, Image as ImageIcon, Terminal, Play, Copy, Check,
  X, AlertTriangle, ShieldAlert, ChevronRight, Sparkles, Send, Pin, PinOff,
  Loader2, Bug,
} from "lucide-react";

export const Route = createFileRoute("/hacking-toolkit")({ component: HackingToolkitPage });

const ICON_MAP: Record<string, LucideIcon> = {
  search: Search, globe: Globe2, lock: KeyRound, wifi: Wifi, zap: Zap,
  code: Code2, package: Package, "file-text": FileText, cloud: Cloud,
  server: Server, image: ImageIcon,
};

const TONE_MAP: Record<string, "primary" | "warning" | "destructive" | "success" | "info" | "accent"> = {
  information_gathering: "info",
  web_attack: "primary",
  password_attacks: "warning",
  forensics: "accent",
  wireless: "info",
  exploit: "destructive",
  reverse_engineering: "primary",
  payload: "warning",
  wordlist: "accent",
  cloud_security: "info",
  active_directory: "destructive",
  steganography: "accent",
};

const PRESETS: Record<string, { label: string; args: string }[]> = {
  nmap: [{ label: "Quick", args: "-sV -T4 -F" }, { label: "Full A+O", args: "-sS -sV -sC -A -O" }, { label: "Stealth", args: "-sS -T2" }, { label: "Top-100", args: "--top-ports 100 -sV" }],
  sqlmap: [{ label: "Check inj", args: "--batch --level=1" }, { label: "Dump DBs", args: "--batch --dbs" }, { label: "Full L3 R2", args: "--batch --level=3 --risk=2" }],
  nuclei: [{ label: "All sev", args: "-severity low,medium,high,critical" }, { label: "Tech tag", args: "-tags tech" }],
  nikto: [{ label: "Default", args: "-ssl -Format txt" }, { label: "Tuning 1-3", args: "-Tuning 1 2 3" }],
  gobuster: [{ label: "Dir common", args: "dir -w /usr/share/wordlists/dirb/common.txt" }, { label: "DNS subs", args: "dns -w /usr/share/wordlists/dns/subdomains-top1million-5000.txt" }],
  ffuf: [{ label: "Dir fuzz", args: "-w /usr/share/wordlists/dirb/common.txt -u FUZZ" }],
  hydra: [{ label: "SSH root", args: "-l root -P /usr/share/wordlists/rockyou.txt ssh" }, { label: "HTTP admin", args: "-l admin -P /usr/share/wordlists/rockyou.txt http-post-form" }],
  dirb: [{ label: "Common", args: "/usr/share/wordlists/dirb/common.txt" }, { label: "Big", args: "/usr/share/wordlists/dirb/big.txt" }],
  wpscan: [{ label: "Quick", args: "--enumerate vp,vt,u" }, { label: "Full", args: "--enumerate ap,at,cb,dbe" }],
  whatweb: [{ label: "Aggressive L3", args: "--aggression 3" }],
  wafw00f: [{ label: "Default", args: "" }],
  dnsrecon: [{ label: "Std", args: "-t std" }, { label: "Brute", args: "-t brt -D /usr/share/wordlists/dns/subdomains-top1million-5000.txt" }],
  theharvester: [{ label: "Google 50", args: "-b google -l 50" }, { label: "All 100", args: "-b all -l 100" }],
  amass: [{ label: "Passive", args: "-passive" }, { label: "Active", args: "-active" }],
  sublist3r: [{ label: "Default", args: "" }],
};

const PIN_KEY = "ba.hacking.pinned";

type BackendTool = { id: string; name: string; binary: string; installed: boolean };
type BackendCategory = { id: string; name: string; icon: string; tools: BackendTool[] };

function HackingToolkitPage() {
  const [cats, setCats] = useState<BackendCategory[] | null>(null);
  const [loading, setLoading] = useState(true);
  const [backendError, setBackendError] = useState<string | null>(null);
  const [installed, setInstalled] = useState(false);
  const [activeCatId, setActiveCatId] = useState<string>("");
  const [activeToolId, setActiveToolId] = useState<string>("");
  const [search, setSearch] = useState("");
  const [targets, setTargets] = useState<Record<string, string>>({});
  const [argsMap, setArgsMap] = useState<Record<string, string>>({});
  const [outputs, setOutputs] = useState<Record<string, { command: string; status: string; body: string } | null>>({});
  const [running, setRunning] = useState<string | null>(null);
  const [copied, setCopied] = useState<string | null>(null);
  const [pinned, setPinned] = useState<Set<string>>(new Set());

  useEffect(() => {
    getHackingtoolCategories()
      .then((res: any) => {
        if (res.categories) {
          setCats(res.categories);
          setInstalled(res.installed ?? false);
          if (res.categories.length > 0) {
            setActiveCatId(res.categories[0].id);
            if (res.categories[0].tools.length > 0) {
              setActiveToolId(res.categories[0].tools[0].id);
            }
          }
        }
        setLoading(false);
      })
      .catch((err: any) => {
        setBackendError(err?.message || "Cannot reach backend");
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

  const target = activeTool ? (targets[activeTool.id] ?? "") : "";
  const args = activeTool ? (argsMap[activeTool.id] ?? "") : "";
  const cmd = activeTool ? [activeTool.binary, target, args].filter(Boolean).join(" ") : "";
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
    setRunning(activeTool.id);
    setOutputs((p) => ({ ...p, [activeTool.id]: null }));
    try {
      const res: any = await runHackingtoolTool({
        categoryId: activeCat.id,
        toolId: activeTool.id,
        target,
        args,
      });
      const body = res.stdout || res.stderr || res.error || JSON.stringify(res, null, 2);
      setOutputs((p) => ({
        ...p,
        [activeTool.id]: {
          command: res.command || cmd,
          status: res.error ? "error" : (res.status === "completed" ? "completed" : "failed"),
          body,
        },
      }));
    } catch (err: any) {
      setOutputs((p) => ({
        ...p,
        [activeTool.id]: { command: cmd, status: "error", body: err?.message || "API call failed" },
      }));
    } finally {
      setRunning(null);
    }
  }

  async function copyText(key: string, text: string) {
    try { await navigator.clipboard.writeText(text); setCopied(key); setTimeout(() => setCopied(null), 1200); } catch {}
  }

  const presets = activeTool ? (PRESETS[activeTool.id] ?? []) : [];

  const metaItems: { label: string; value: string; tone?: "default" | "primary" | "warning" | "destructive" | "success" }[] = [
    { label: "categories", value: String(cats?.length ?? 0), tone: "primary" },
    { label: "tools", value: String(totalTools), tone: "primary" },
    { label: "available", value: String(installedCount), tone: installedCount > 0 ? "success" : "default" },
    { label: "pinned", value: String(pinnedCount), tone: pinnedCount > 0 ? "success" : "default" },
  ];

  return (
    <PageShell
      eyebrow="Offensive"
      title="Hacking Toolkit"
      description="Browse 50+ offensive-security tools by category, build commands with presets, and run against locally installed binaries via the BeyondArch backend."
      crumbs={[{ label: "Workbench", href: "/" }, { label: "Offensive" }, { label: "Hacking Toolkit" }]}
      meta={metaItems}
      actions={<PreviewBadge label={installed ? "live backend" : "offline catalog"} />}
    >
      {loading && (
        <Panel className="flex items-center gap-2">
          <Loader2 className="h-3.5 w-3.5 animate-spin text-primary" />
          <span className="text-mono text-[11px] text-muted-foreground">Checking local tool environment…</span>
        </Panel>
      )}

      {!loading && backendError && (
        <Panel className="border-warning/30 bg-warning/5">
          <div className="flex items-start gap-3 px-4 py-2.5">
            <span className="grid h-7 w-7 shrink-0 place-items-center rounded border border-warning/40 bg-warning/15 text-warning">
              <AlertTriangle className="h-3.5 w-3.5" />
            </span>
            <div className="min-w-0 text-[12px] leading-relaxed text-foreground/85">
              <span className="font-semibold text-warning">Cannot reach backend.</span>{" "}
              Start the FastAPI server to check locally installed tools and run real binaries.{" "}
              <code className="text-mono text-[11px] text-foreground">cd backend && uvicorn app.main:app --reload</code>
            </div>
          </div>
        </Panel>
      )}

      {!loading && !backendError && cats && (
        <>
          {!installed && (
            <Panel className="border-warning/30 bg-warning/5">
              <div className="flex items-start gap-3 px-4 py-2.5">
                <span className="grid h-7 w-7 shrink-0 place-items-center rounded border border-warning/40 bg-warning/15 text-warning">
                  <AlertTriangle className="h-3.5 w-3.5" />
                </span>
                <div className="min-w-0 text-[12px] leading-relaxed text-foreground/85">
                  <span className="font-semibold text-warning">hackingtool directory not found.</span>{" "}
                  The catalog is shown but binaries are not checked. Clone into{" "}
                  <code className="text-mono text-[11px] text-foreground">~/Projects/hackingtool</code> to enable installed-tool detection.
                </div>
              </div>
            </Panel>
          )}

          {/* Two-column workspace */}
          <div className="grid gap-4 lg:grid-cols-[minmax(0,18rem)_minmax(0,1fr)]">
            {/* ── Left rail: categories + tools ── */}
            <div className="space-y-3 lg:sticky lg:top-16 lg:self-start">
              <Panel bodyClassName="p-0">
                <div className="border-b border-border p-2">
                  <div className="relative">
                    <Search className="pointer-events-none absolute left-2 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
                    <input
                      value={search}
                      onChange={(e) => setSearch(e.target.value)}
                      placeholder="search tools, binaries…"
                      spellCheck={false}
                      className="w-full rounded-md border border-border bg-background/60 py-1.5 pl-7 pr-7 text-mono text-[11px] text-foreground outline-none placeholder:text-muted-foreground/60 focus:border-primary/50"
                    />
                    {search && (
                      <button onClick={() => setSearch("")} className="absolute right-1 top-1/2 -translate-y-1/2 rounded p-1 text-muted-foreground hover:text-foreground" aria-label="clear">
                        <X className="h-3 w-3" />
                      </button>
                    )}
                  </div>
                </div>

                {pinnedCount > 0 && (
                  <div className="border-b border-border/70 p-2">
                    <div className="mb-1.5 flex items-center gap-1.5 text-mono text-[9px] uppercase tracking-widest text-muted-foreground">
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
                              className={"flex w-full items-center gap-2 rounded px-2 py-1 text-left text-mono text-[11px] transition-colors " + (active ? "bg-primary/10 text-primary" : "text-foreground/80 hover:bg-accent/40 hover:text-foreground")}
                            >
                              <span className="truncate">{t.name}</span>
                              <span className="ml-auto truncate text-[9px] text-muted-foreground">{cat.name}</span>
                            </button>
                          </li>
                        );
                      })}
                    </ul>
                  </div>
                )}

                <nav className="max-h-[calc(100vh-22rem)] overflow-auto p-2">
                  {filteredCats.length === 0 && (
                    <div className="px-2 py-6 text-center text-mono text-[11px] text-muted-foreground">
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
                          <span className="flex-1 truncate text-mono text-[11px] font-semibold uppercase tracking-widest text-foreground/90">
                            {cat.name}
                          </span>
                          <span className="text-mono text-[9px] text-muted-foreground">{cat.tools.length}</span>
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
                                    className={"group/r relative flex w-full items-center gap-2 rounded px-2 py-1 text-left text-mono text-[11px] transition-colors " + (active ? "bg-primary/10 text-primary" : "text-foreground/75 hover:bg-accent/40 hover:text-foreground")}
                                  >
                                    <span aria-hidden className={"h-1.5 w-1.5 shrink-0 rounded-full " + (active ? "bg-primary shadow-[0_0_8px_var(--primary)]" : "bg-muted-foreground/30")} />
                                    <span className="truncate">{t.name}</span>
                                    {t.installed && (
                                      <span className="ml-auto h-1.5 w-1.5 shrink-0 rounded-full bg-success" title="installed" />
                                    )}
                                    <span className="ml-1 truncate text-[9px] text-muted-foreground/80">{t.binary}</span>
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

            {/* ── Right column: detail + intake + output ── */}
            <div className="min-w-0 space-y-4">
              {!activeTool ? (
                <Empty icon={Terminal} title="No tool selected" hint="Choose a tool from the left rail to get started." />
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
                          <div className="mt-1.5 inline-flex items-center gap-1.5 rounded border border-border/60 bg-background/40 px-1.5 py-0.5 text-mono text-[10px] text-muted-foreground">
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
                    <SectionBar id="IN" label="Intake" meta="target · args · preset" />
                    <Panel bodyClassName="p-0">
                      <div className="grid gap-0 md:grid-cols-[1fr_1fr]">
                        <div className="border-b border-border/60 p-3 md:border-b-0 md:border-r">
                          <label className="mb-1 block text-mono text-[10px] uppercase tracking-widest text-muted-foreground">Target</label>
                          <input
                            value={target}
                            onChange={(e) => setTargets((p) => ({ ...p, [activeTool.id]: e.target.value }))}
                            placeholder="example.com · 10.0.0.1 · https://app"
                            spellCheck={false}
                            className="w-full rounded-md border border-border bg-background/60 px-2 py-1.5 text-mono text-[12px] text-foreground outline-none placeholder:text-muted-foreground/50 focus:border-primary/50"
                          />
                        </div>
                        <div className="p-3">
                          <label className="mb-1 block text-mono text-[10px] uppercase tracking-widest text-muted-foreground">Args</label>
                          <input
                            value={args}
                            onChange={(e) => setArgsMap((p) => ({ ...p, [activeTool.id]: e.target.value }))}
                            placeholder="-sV -p 22,80,443 (optional)"
                            spellCheck={false}
                            className="w-full rounded-md border border-border bg-background/60 px-2 py-1.5 text-mono text-[12px] text-foreground outline-none placeholder:text-muted-foreground/50 focus:border-primary/50"
                          />
                        </div>
                      </div>

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

                      <div className="flex flex-wrap items-center gap-2 border-t border-border bg-background/40 px-3 py-2">
                        <span className="text-mono text-[10px] uppercase tracking-widest text-muted-foreground">cmd</span>
                        <code className="min-w-0 flex-1 truncate rounded border border-border/70 bg-background/70 px-2 py-1 text-mono text-[11px] text-foreground/90">
                          <span className="text-primary/70">$</span> {cmd || activeTool.binary}
                        </code>
                        <button
                          onClick={() => copyText("cmd", cmd || activeTool.binary)}
                          className="inline-flex items-center gap-1 rounded border border-border px-2 py-1 text-mono text-[10px] uppercase tracking-widest text-muted-foreground hover:border-primary/50 hover:text-primary"
                          title="Copy command"
                        >
                          {copied === "cmd" ? <Check className="h-3 w-3 text-success" /> : <Copy className="h-3 w-3" />} copy
                        </button>
                        <button
                          onClick={run}
                          disabled={running === activeTool.id}
                          className="inline-flex items-center gap-1.5 rounded border border-primary/50 bg-primary/10 px-3 py-1 text-mono text-[11px] font-semibold uppercase tracking-widest text-primary transition-colors hover:bg-primary/20 disabled:opacity-50"
                        >
                          {running === activeTool.id ? <Loader2 className="h-3 w-3 animate-spin" /> : <Bug className="h-3 w-3" />}
                          {running === activeTool.id ? "running…" : "run"}
                        </button>
                      </div>
                    </Panel>
                  </div>

                  {/* Output */}
                  <div>
                    <SectionBar id="OT" label="Output" meta={output ? output.status : "no run yet"} />
                    {!output ? (
                      <Empty
                        icon={Terminal}
                        title="No execution recorded"
                        hint="Choose a tool, set a target, and press run. Output comes from locally installed binaries via the backend."
                      />
                    ) : (
                      <>
                        <ResultBanner
                          badge={output.status}
                          caseId={activeTool.binary}
                          title={`${activeTool.name} — ${output.status === "completed" ? "execution result" : output.status === "error" ? "execution failed" : "output"}`}
                          subtitle={output.status === "completed" ? "Binary ran on the local host via BeyondArch backend." : output.status === "error" ? "The tool returned an error or is not installed." : "The tool produced output with non-zero exit code."}
                          metrics={[
                            { label: "lines", value: String(output.body.split("\n").length), tone: "primary" },
                            { label: "bytes", value: output.body.length.toLocaleString(), tone: "default" },
                            { label: "status", value: output.status, tone: output.status === "completed" ? "success" : "warning" },
                            { label: "tool", value: activeTool.binary, tone: "default" },
                          ]}
                        />

                        <Panel className="mt-3" bodyClassName="p-0">
                          <div className="flex items-center justify-between border-b border-border bg-muted/20 px-3 py-2">
                            <span className="truncate text-mono text-[10px] uppercase tracking-widest text-muted-foreground">
                              <span className="text-primary/70">$</span> {output.command}
                            </span>
                            <div className="flex items-center gap-1.5">
                              <button
                                onClick={() => copyText("out", output.body)}
                                className="inline-flex items-center gap-1 rounded border border-border px-1.5 py-0.5 text-mono text-[10px] uppercase tracking-widest text-muted-foreground hover:border-primary/50 hover:text-primary"
                              >
                                {copied === "out" ? <Check className="h-3 w-3 text-success" /> : <Copy className="h-3 w-3" />} copy
                              </button>
                              <button
                                onClick={() => setOutputs((p) => ({ ...p, [activeTool.id]: null }))}
                                className="inline-flex items-center gap-1 rounded border border-border px-1.5 py-0.5 text-mono text-[10px] uppercase tracking-widest text-muted-foreground hover:border-destructive/50 hover:text-destructive"
                              >
                                <X className="h-3 w-3" /> clear
                              </button>
                            </div>
                          </div>
                          <pre className="max-h-96 overflow-auto whitespace-pre-wrap bg-background/40 px-4 py-3 text-mono text-[11.5px] leading-relaxed text-foreground/90">
{output.body}
                          </pre>
                        </Panel>

                        {target && (
                          <div className="mt-3">
                            <SendToRow
                              targets={[
                                { label: "Nmap Runner", to: "/nmap", onClick: () => sendArtifact({ kind: "raw", value: target, source: "/hacking-toolkit" }) },
                                { label: "OSINT Tools", to: "/osint", onClick: () => sendArtifact({ kind: "raw", value: target, source: "/hacking-toolkit" }) },
                                { label: "URL Analyzer", to: "/url", onClick: () => sendArtifact({ kind: "raw", value: target, source: "/hacking-toolkit" }) },
                                { label: "Recon", to: "/recon", onClick: () => sendArtifact({ kind: "raw", value: target, source: "/hacking-toolkit" }) },
                              ]}
                            />
                          </div>
                        )}
                      </>
                    )}
                  </div>

                  {/* Tool facts */}
                  <div>
                    <SectionBar id="CF" label="Tool facts" />
                    <Panel bodyClassName="px-4 py-3">
                      <div className="grid gap-x-6 sm:grid-cols-2">
                        <Field label="binary" value={<code className="text-mono">{activeTool.binary}</code>} />
                        <Field label="category" value={activeCat?.name ?? ""} />
                        <Field label="id" value={<code className="text-mono">{activeTool.id}</code>} tone="muted" />
                        <Field label="presets" value={String(presets.length)} tone={presets.length ? "primary" : "muted"} />
                        <Field label="installed" value={activeTool.installed ? "yes" : "no"} tone={activeTool.installed ? "success" : "warning"} />
                        <Field label="pinned" value={pinned.has(activeTool.id) ? "yes" : "no"} tone={pinned.has(activeTool.id) ? "success" : "muted"} />
                      </div>
                    </Panel>
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
