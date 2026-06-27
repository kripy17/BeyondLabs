import { useEffect, useState, useMemo } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { PageShell } from "@/components/PageShell";
import { getHackingtoolCategories, runHackingtoolTool } from "@/api/backend";
import { Loader2, Terminal, Bug, AlertTriangle, Copy, X, Search, Check } from "lucide-react";

export const Route = createFileRoute("/hacking-toolkit")({
  component: HackingToolkitPage,
});

const PRESETS: Record<string, { label: string; args: string }[]> = {
  nmap: [
    { label: "Quick -sV -T4 -F", args: "-sV -T4 -F" },
    { label: "Full -A -O -sC", args: "-sS -sV -sC -A -O" },
    { label: "Stealth -sS -T2", args: "-sS -T2" },
    { label: "Top 100 ports", args: "--top-ports 100 -sV" },
  ],
  sqlmap: [
    { label: "Check injection", args: "--batch --level=1" },
    { label: "Dump DBs", args: "--batch --dbs" },
    { label: "Full enum L3 R2", args: "--batch --level=3 --risk=2" },
  ],
  nuclei: [
    { label: "All severities", args: "-severity low,medium,high,critical" },
    { label: "Tech detection", args: "-tags tech" },
  ],
  nikto: [
    { label: "Default +ssl", args: "-ssl -Format txt" },
    { label: "Tuning 1 2 3", args: "-Tuning 1 2 3" },
  ],
  gobuster: [
    { label: "Dir common.txt", args: "dir -w /usr/share/wordlists/dirb/common.txt" },
    { label: "DNS subdomains", args: "dns -w /usr/share/wordlists/dns/subdomains-top1million-5000.txt" },
  ],
  ffuf: [
    { label: "Dir fuzz common", args: "-w /usr/share/wordlists/dirb/common.txt -u FUZZ" },
  ],
  hydra: [
    { label: "SSH root brute", args: "-l root -P /usr/share/wordlists/rockyou.txt ssh" },
    { label: "HTTP form admin", args: "-l admin -P /usr/share/wordlists/rockyou.txt http-post-form" },
  ],
  dirb: [
    { label: "Common wordlist", args: "/usr/share/wordlists/dirb/common.txt" },
    { label: "Big wordlist", args: "/usr/share/wordlists/dirb/big.txt" },
  ],
  wpscan: [
    { label: "Quick enum vp,vt,u", args: "--enumerate vp,vt,u" },
    { label: "Full enum", args: "--enumerate ap,at,cb,dbe" },
  ],
  whatweb: [
    { label: "Aggressive L3", args: "--aggression 3" },
  ],
  wafw00f: [
    { label: "Default check", args: "" },
  ],
  dnsrecon: [
    { label: "Standard std", args: "-t std" },
    { label: "Brute subdomains", args: "-t brt -D /usr/share/wordlists/dns/subdomains-top1million-5000.txt" },
  ],
  theharvester: [
    { label: "Basic google 50", args: "-b google -l 50" },
    { label: "All sources 100", args: "-b all -l 100" },
  ],
  amass: [
    { label: "Passive only", args: "-passive" },
    { label: "Active enum", args: "-active" },
  ],
  sublist3r: [
    { label: "Default scan", args: "" },
  ],
};

function HackingToolkitPage() {
  const [cats, setCats] = useState<Record<string, unknown> | null>(null);
  const [loading, setLoading] = useState(true);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [search, setSearch] = useState("");
  const [targets, setTargets] = useState<Record<string, string>>({});
  const [argsMap, setArgsMap] = useState<Record<string, string>>({});
  const [running, setRunning] = useState<string | null>(null);
  const [outputs, setOutputs] = useState<Record<string, Record<string, unknown> | null>>({});
  const [copied, setCopied] = useState<string | null>(null);

  useEffect(() => {
    getHackingtoolCategories()
      .then((res) => { setCats(res); setLoading(false); })
      .catch(() => { setLoading(false); });
  }, []);

  const allCats: { id: string; name: string; icon: string; tools: { id: string; name: string; binary: string; installed: boolean }[] }[] =
    (cats as any)?.categories ?? [];

  const lowerSearch = search.toLowerCase();

  const filteredCats = useMemo(() => {
    if (!lowerSearch) return allCats;
    return allCats
      .map((cat) => ({
        ...cat,
        tools: cat.tools.filter(
          (t) =>
            t.name.toLowerCase().includes(lowerSearch) ||
            t.binary.toLowerCase().includes(lowerSearch) ||
            t.id.toLowerCase().includes(lowerSearch),
        ),
      }))
      .filter((cat) => cat.tools.length > 0);
  }, [allCats, lowerSearch]);

  const categories = lowerSearch ? filteredCats : allCats;

  useEffect(() => {
    if (!lowerSearch) {
      setExpanded(new Set());
      return;
    }
    setExpanded(new Set(categories.map((c) => c.id)));
  }, [lowerSearch, categories]);

  function toggleCat(id: string) {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  async function handleRun(catId: string, toolId: string) {
    setRunning(toolId);
    setOutputs((prev) => ({ ...prev, [toolId]: null }));
    try {
      const res = await runHackingtoolTool({
        categoryId: catId,
        toolId,
        target: targets[toolId] ?? "",
        args: argsMap[toolId] ?? "",
      });
      setOutputs((prev) => ({ ...prev, [toolId]: res }));
    } catch {
      setOutputs((prev) => ({ ...prev, [toolId]: { error: "API call failed" } }));
    } finally {
      setRunning(null);
    }
  }

  function applyPreset(toolId: string, args: string) {
    setArgsMap((prev) => ({ ...prev, [toolId]: args }));
  }

  async function copyOutput(toolId: string, text: string) {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(toolId);
      setTimeout(() => setCopied(null), 1500);
    } catch {
      // fallback
    }
  }

  function clearOutput(toolId: string) {
    setOutputs((prev) => ({ ...prev, [toolId]: null }));
  }

  const installedCount = allCats.reduce((s, c) => s + c.tools.filter((t) => t.installed).length, 0);
  const totalCount = allCats.reduce((s, c) => s + c.tools.length, 0);

  return (
    <PageShell
      title="Hacking Toolkit"
      subtitle="Offensive security tools — fetched from your local environment"
    >
      {loading ? (
        <div className="flex items-center gap-2 rounded border border-border bg-card/40 px-4 py-3 text-mono text-[11px] text-muted-foreground">
          <Loader2 className="h-3.5 w-3.5 animate-spin" />
          Checking local tool environment…
        </div>
      ) : !cats ? (
        <div className="rounded border border-warning/40 bg-warning/10 px-4 py-3 text-mono text-[11px]">
          <span className="font-semibold text-warning">Cannot reach backend.</span> Start the server to check locally installed tools.
        </div>
      ) : !(cats as any).installed ? (
        <div className="rounded border border-warning/40 bg-warning/10 px-4 py-3 text-mono text-[11px] space-y-1">
          <div className="flex items-center gap-2 text-warning"><AlertTriangle className="h-3.5 w-3.5" /> hackingtool directory not found</div>
          <div className="text-muted-foreground">{(cats as any).note}</div>
        </div>
      ) : (
        <div className="mb-4 flex items-center gap-2 rounded border border-border bg-card/40 px-3 py-2 text-mono text-[11px] text-muted-foreground">
          <Terminal className="h-3.5 w-3.5 text-primary" />
          <span><strong className="text-foreground">{installedCount}/{totalCount}</strong> tools available on this host</span>
        </div>
      )}

      <div className="mb-4">
        <div className="relative max-w-md">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
          <input
            className="w-full pl-8 pr-3 py-2 text-xs font-mono bg-background border border-border rounded focus:outline-none focus:border-primary/50 text-foreground placeholder:text-muted-foreground/40"
            placeholder="Search tools by name, binary, or id…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
      </div>

      <div className="max-w-5xl mx-auto space-y-3">
        {categories.map((cat) => {
          const isOpen = expanded.has(cat.id);
          return (
            <div key={cat.id} className="border border-border bg-card/60 rounded-lg overflow-hidden">
              <button
                className="w-full flex items-center gap-2 px-4 py-3 text-left hover:bg-accent/30 transition-colors"
                onClick={() => toggleCat(cat.id)}
              >
                <span className="text-sm text-foreground/80">{
                  cat.icon === "search" ? "🔍" : cat.icon === "globe" ? "🌐" : cat.icon === "lock" ? "🔑" : cat.icon === "wifi" ? "📡" : cat.icon === "zap" ? "⚡" : cat.icon === "code" ? "💻" : cat.icon === "package" ? "📦" : cat.icon === "file-text" ? "📄" : cat.icon === "cloud" ? "☁️" : cat.icon === "server" ? "🖥️" : cat.icon === "image" ? "🖼️" : "🛠️"
                }</span>
                <span className="font-semibold text-sm text-foreground">{cat.name}</span>
                <span className="ml-2 text-mono text-[10px] text-muted-foreground">{cat.tools.filter((t) => t.installed).length}/{cat.tools.length} avail</span>
                <span className="ml-auto text-muted-foreground transition-transform" style={{ transform: isOpen ? "rotate(90deg)" : undefined }}>▸</span>
              </button>

              {isOpen && (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3 p-4 border-t border-border">
                  {cat.tools.map((tool) => {
                    const out = outputs[tool.id];
                    const isRunning = running === tool.id;
                    const cmdPreview = [tool.binary, targets[tool.id], argsMap[tool.id]].filter(Boolean).join(" ");

                    return (
                      <div key={tool.id} className="border border-border bg-card/40 rounded-md p-4 space-y-3">
                        <div className="flex items-center justify-between gap-2">
                          <div>
                            <div className="flex items-center gap-1.5">
                              <h4 className="text-sm font-semibold text-foreground">{tool.name}</h4>
                              <span className={"inline-block h-1.5 w-1.5 rounded-full " + (tool.installed ? "bg-success" : "bg-muted-foreground/40")} />
                            </div>
                            <div className="text-mono text-[9px] uppercase tracking-widest text-muted-foreground">{tool.binary}{!tool.installed ? " (not installed)" : ""}</div>
                          </div>
                        </div>

                        <div>
                          <label className="block text-mono text-[10px] uppercase tracking-widest text-muted-foreground mb-0.5">Target</label>
                          <input
                            className="w-full px-2 py-1.5 text-xs font-mono bg-background border border-border rounded focus:outline-none focus:border-primary/50 text-foreground placeholder:text-muted-foreground/50"
                            placeholder="example.com · 10.0.0.1"
                            value={targets[tool.id] ?? ""}
                            onChange={(e) => setTargets((p) => ({ ...p, [tool.id]: e.target.value }))}
                          />
                        </div>

                        <div>
                          <label className="block text-mono text-[10px] uppercase tracking-widest text-muted-foreground mb-0.5">Args</label>
                          <div className="flex gap-1.5 flex-wrap mb-1.5">
                            {(PRESETS[tool.id] ?? []).map((p) => (
                              <button
                                key={p.label}
                                onClick={() => applyPreset(tool.id, p.args)}
                                className="px-2 py-0.5 text-mono text-[9px] bg-accent/30 text-accent-foreground border border-border rounded hover:bg-accent/50 transition-colors"
                              >
                                {p.label}
                              </button>
                            ))}
                          </div>
                          <input
                            className="w-full px-2 py-1.5 text-xs font-mono bg-background border border-border rounded focus:outline-none focus:border-primary/50 text-foreground placeholder:text-muted-foreground/50"
                            placeholder="-sV -p 22,80,443 (optional)"
                            value={argsMap[tool.id] ?? ""}
                            onChange={(e) => setArgsMap((p) => ({ ...p, [tool.id]: e.target.value }))}
                          />
                        </div>

                        {cmdPreview && (
                          <div className="text-mono text-[10px] text-muted-foreground bg-background/60 border border-border/60 rounded px-2 py-1 truncate">
                            <span className="text-primary/70">$</span> {cmdPreview}
                          </div>
                        )}

                        <div className="flex items-center gap-2">
                          <button
                            onClick={() => handleRun(cat.id, tool.id)}
                            disabled={!tool.installed || isRunning}
                            className="inline-flex items-center gap-1.5 px-3 py-1 text-xs font-medium bg-primary/10 text-primary border border-primary/20 rounded hover:bg-primary/20 transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
                          >
                            {isRunning ? <Loader2 className="h-3 w-3 animate-spin" /> : <Bug className="h-3 w-3" />}
                            {isRunning ? "running…" : "Run"}
                          </button>
                        </div>

                        {out && (
                          <div>
                            {(out as any).error ? (
                              <div className="rounded border border-destructive/40 bg-destructive/10 px-3 py-2 text-mono text-[11px] text-destructive">{(out as any).error}</div>
                            ) : (
                              <div className="space-y-1">
                                <div className="flex items-center gap-2 text-mono text-[10px] text-muted-foreground">
                                  <Terminal className="h-3 w-3 flex-shrink-0" />
                                  <span className="truncate">{(out as any).command ?? ""}</span>
                                  <span className={"ml-auto uppercase " + ((out as any).status === "completed" ? "text-success" : "text-warning")}>{(out as any).status ?? ""}</span>
                                  <button
                                    onClick={() => clearOutput(tool.id)}
                                    className="p-0.5 hover:text-foreground transition-colors"
                                    title="Clear output"
                                  >
                                    <X className="h-3 w-3" />
                                  </button>
                                </div>
                                <div className="relative group">
                                  <pre className="text-xs font-mono bg-background/80 border border-border rounded p-3 overflow-x-auto max-h-64 whitespace-pre-wrap text-foreground/90">
                                    {(out as any).stdout || (out as any).stderr || (out as any).error || JSON.stringify(out, null, 2)}
                                  </pre>
                                  <button
                                    onClick={() => copyOutput(tool.id, (out as any).stdout || (out as any).stderr || "")}
                                    className="absolute top-1.5 right-1.5 p-1 bg-background/80 border border-border rounded opacity-0 group-hover:opacity-100 hover:bg-accent/30 transition-all"
                                    title="Copy output"
                                  >
                                    {copied === tool.id ? <Check className="h-3 w-3 text-success" /> : <Copy className="h-3 w-3" />}
                                  </button>
                                </div>
                              </div>
                            )}
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          );
        })}

        {categories.length === 0 && search && (
          <div className="rounded border border-border bg-card/40 px-4 py-6 text-center text-mono text-[11px] text-muted-foreground">
            No tools match <strong className="text-foreground">{search}</strong>
          </div>
        )}
      </div>
    </PageShell>
  );
}
