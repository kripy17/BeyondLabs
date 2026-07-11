import { createFileRoute } from "@tanstack/react-router";
import { useEffect, useState } from "react";
import { PageShell } from "@/components/PageShell";
import { IntakeCard, SectionBar, Panel, Chip, SendToRow, StatusBar } from "@/components/soc/Workspace";
import { TerminalOutput } from "@/components/soc/TerminalOutput";
import { useOutputFilter, OutputFilterBar, OutputFilter } from "@/components/soc/OutputFilter";
import { useLocker } from "@/lib/locker";
import { takePendingArtifact } from "@/lib/handoff";
import { runReconNmapScan } from "@/api/backend";
import { toast } from "sonner";
import {
  Server, Terminal, ArrowRight, Zap, ShieldAlert, Copy, Check,
  Gauge, FileCode2, Globe2, Crosshair, Download, Loader2, Search, Database,
} from "lucide-react";

export const Route = createFileRoute("/nmap")({ component: NmapPage });

type NmapScanResult = { stdout?: string; stderr?: string; error?: string; success?: boolean };

const MODES = {
  discovery: { label: "Discovery",         args: "-sn -PE -PA80,443",                          risk: "low",    desc: "ICMP & ACK host discovery — no port probes.",          backend: "quick_tcp" },
  fast:      { label: "Top-100 TCP",       args: "-sS --top-ports 100 -Pn",                    risk: "medium", desc: "SYN scan of the 100 most common TCP ports.",           backend: "quick_tcp" },
  service:   { label: "Service & version", args: "-sV -sC --top-ports 1000 -Pn",               risk: "medium", desc: "Version detection + default NSE on common ports.",    backend: "service_version" },
  vuln:      { label: "Safe NSE scripts",  args: "-sV --script default,safe --top-ports 200 -Pn", risk: "high", desc: "Safe NSE scripts. Noisy — explicit auth only.",       backend: "safe_scripts" },
  full:      { label: "Full TCP + OS",     args: "-sS -p- -O -sV -Pn",                         risk: "high",   desc: "Every TCP port + OS fingerprint. Slow and loud.",     backend: "full_tcp" },
} as const;
type ModeKey = keyof typeof MODES;

function parseNmapPorts(stdout: string): { port: string; state: string; service: string }[] {
  const ports: { port: string; state: string; service: string }[] = [];
  const lines = stdout.split("\n");
  let inPorts = false;
  for (const line of lines) {
    if (/^PORT\s+STATE\s+SERVICE/i.test(line)) { inPorts = true; continue; }
    if (!inPorts) continue;
    if (/^\d+\/(tcp|udp)\s+/.test(line)) {
      const parts = line.trim().split(/\s{2,}|\t+/);
      const [portProto, state, ...rest] = parts;
      const svc = parts.length >= 3 ? parts.slice(1).find((p) => /^[a-z]/.test(p)) || rest[0] || "" : "";
      ports.push({ port: portProto || "", state: state || "", service: svc });
    }
    if (/^$|^#|^MAC|^TRACEROUTE|^OS|^Too many|^Warning/i.test(line) && ports.length > 0) break;
  }
  return ports;
}

function portRiskTone(service: string): "destructive" | "warning" | "success" | "default" {
  const svc = service.toLowerCase().trim();
  if (["netbios-ssn","microsoft-ds","kdc","kerberos","ldaps","domain","rpc","epmap","msrpc"].some((p) => svc.startsWith(p))) return "success";
  if (["ssh","telnet","rdp","vnc","mysql","mssql","oracle","smb","netbios","ldap","snmp","ftp"].some((p) => svc.startsWith(p))) return "destructive";
  if (["http","https","http-proxy","http-alt","www","nginx","apache","iis","tomcat","dns","smtp","pop3","imap","redis","memcached"].some((p) => svc.startsWith(p))) return "warning";
  return "default";
}

function genJsonExport(target: string, mode: ModeKey, timing: TimingKey, result: Record<string, unknown> | null): string {
  const scan = result?.scan as NmapScanResult | undefined;
  const stdout = scan?.stdout ?? "";
  const truncated = stdout.length > 10000;
  const ports = parseNmapPorts(stdout);
  const ips = stdout.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || [];
  const uniqueIps = [...new Set(ips)].filter((ip) => ip !== target && !ip.startsWith("127.") && !ip.startsWith("10.") && !ip.startsWith("192.168.") && !ip.startsWith("172."));
  if (truncated) toast.warning("Output truncated — full export not available");
  return JSON.stringify({
    version: "1.0", ts: new Date().toISOString(), target,
    mode: MODES[mode].label, timing: `-${timing}`,
    ports: ports.slice(0, 200), discoveredIps: uniqueIps,
    raw: stdout.slice(0, 10000),
    truncated,
  }, null, 2);
}

const HISTORY_KEY = "ba.nmap.history";

const TIMINGS = [
  { k: "T2", label: "Polite",      hint: "stealth · low rate" },
  { k: "T3", label: "Normal",      hint: "default" },
  { k: "T4", label: "Aggressive",  hint: "lab / authorised" },
  { k: "T5", label: "Insane",      hint: "very loud" },
] as const;
type TimingKey = typeof TIMINGS[number]["k"];

function genReport(target: string, mode: ModeKey, timing: TimingKey, realOutput: string | null): string {
  if (!realOutput) return "# Nmap Scan\n\nRun the scan to generate a report.";
  return [
    `# Nmap Scan Report`,
    `**Target:** ${target}`,
    `**Profile:** ${MODES[mode].label}`,
    `**Timing:** -${timing}`,
    `**Source:** live scan`,
    "", "## Raw Output", "```", realOutput.slice(0, 5000), "```",
    "", "## Command",
    `nmap ${MODES[mode].args} -${timing} ${target}`,
  ].join("\n");
}

function NmapPage() {
  const [target, setTarget] = useState("");
  const [mode, setMode] = useState<ModeKey>("service");
  const [timing, setTiming] = useState<TimingKey>("T3");
  const [copied, setCopied] = useState<string | null>(null);
  const [confirmed, setConfirmed] = useState(false);
  const [running, setRunning] = useState(false);
  const [realResult, setRealResult] = useState<Record<string, unknown> | null>(null);
  const [history, setHistory] = useState<string[]>([]);

  const locker = useLocker();
  const { filterText, setFilterText, showFilter, setShowFilter, toggleFilter } = useOutputFilter();
  useEffect(() => { const h = takePendingArtifact(); if (h?.value) setTarget(h.value); }, []);
  useEffect(() => { try { setHistory(JSON.parse(localStorage.getItem(HISTORY_KEY) || "[]")); } catch {} }, []);

  const has = target.trim().length > 0;
  const cmd = `nmap ${MODES[mode].args} -${timing} ${has ? target : "<target>"}`;

  const copy = (text: string, key: string) => {
    navigator.clipboard?.writeText(text);
    setCopied(key);
    setTimeout(() => setCopied((c) => (c === key ? null : c)), 1100);
  };

  async function handleExecute() {
    if (!has) return;
    setRunning(true);
    setRealResult(null);
    try {
      const res = await runReconNmapScan({
        target: target.trim(),
        mode: MODES[mode].backend,
        confirmPermission: confirmed,
      });
      setRealResult(res as Record<string, unknown>);
      setHistory((prev) => { const next = [target.trim(), ...prev.filter((p) => p !== target.trim())].slice(0, 8); try { localStorage.setItem(HISTORY_KEY, JSON.stringify(next)); } catch {} return next; });
      toast.success("Scan complete", { description: `${target} — ${MODES[mode].label}` });
    } catch {
      setRealResult({ error: "Scan request failed" });
      toast.error("Scan failed", { description: target });
    } finally {
      setRunning(false);
    }
  }

  const scanResult = realResult?.scan as NmapScanResult | undefined;

  return (
    <PageShell
      eyebrow="RECON / NMAP"
      title="Nmap Runner"
      description="Compose bounded nmap commands and scan targets you own or have permission to test."
      crumbs={[{ label: "Recon" }, { label: "Nmap" }]}
    >
      <SectionBar id="IN" label="Intake · target & profile" meta={`${MODES[mode].risk} risk · ${timing}`} />

      <IntakeCard
        icon={Crosshair}
        title="Target"
        value={target}
        onChange={setTarget}
        rows={2}
        placeholder="example.com · 198.51.100.1 · 10.0.0.0/24"
        samples={[
          { key: "h", label: "Host",   hint: "scanme.nmap.org" },
          { key: "i", label: "IPv4",   hint: "198.51.100.1" },
          { key: "c", label: "CIDR /24", hint: "10.0.0.0/24" },
        ]}
        onLoadSample={(k) => setTarget(k === "h" ? "scanme.nmap.org" : k === "i" ? "198.51.100.1" : "10.0.0.0/24")}
        run={{ label: "render brief", icon: Zap, hint: has ? "preview" : "enter target", onClick: () => {}, disabled: !has }}
        onClear={() => setTarget("")}
        showCopy
      />

      <div className="grid gap-3 grid-cols-[1.4fr_1fr]">
        <Panel icon={FileCode2} title="Scan profile" meta={`risk: ${MODES[mode].risk}`}>
          <div className="grid gap-1.5 grid-cols-2">
            {(Object.keys(MODES) as ModeKey[]).map((k) => {
              const m = MODES[k];
              const sel = mode === k;
              return (
                <button
                  key={k}
                  onClick={() => setMode(k)}
                  className={"rounded border px-2.5 py-2 text-left transition " + (sel ? "border-primary bg-primary/5 shadow-[0_0_0_1px_hsl(var(--primary)/0.25)]" : "border-border/60 hover:border-primary/40 hover:bg-primary/[0.03]")}
                >
                  <div className="flex items-center justify-between">
                    <span className="text-mono text-[11px] uppercase tracking-widest text-foreground">{m.label}</span>
                    <Chip tone={m.risk === "high" ? "destructive" : m.risk === "medium" ? "warning" : "success"}>{m.risk}</Chip>
                  </div>
                  <code className="mt-1 block truncate text-mono text-[10px] text-primary">{m.args}</code>
                  <div className="mt-1 line-clamp-2 text-mono text-[10.5px] text-muted-foreground">{m.desc}</div>
                </button>
              );
            })}
          </div>
        </Panel>

        <Panel icon={Gauge} title="Timing & rate" meta="-T0…-T5">
          <div className="grid gap-1.5">
            {TIMINGS.map((t) => {
              const sel = timing === t.k;
              return (
                <button
                  key={t.k}
                  onClick={() => setTiming(t.k)}
                  className={"flex items-center justify-between gap-2 rounded border px-2.5 py-1.5 text-left transition " + (sel ? "border-primary bg-primary/5" : "border-border/60 hover:border-primary/40")}
                >
                  <span className="flex items-center gap-2">
                    <span className="rounded border border-border/60 bg-background/60 px-1.5 py-0.5 text-mono text-[10px] text-primary">-{t.k}</span>
                    <span className="text-mono text-[11.5px] text-foreground/90">{t.label}</span>
                  </span>
                  <span className="text-mono text-[10px] text-muted-foreground">{t.hint}</span>
                </button>
              );
            })}
          </div>
        </Panel>
      </div>

      <StatusBar stats={[
        { label: "Target",   value: has ? target : "—", tone: has ? "primary" : "muted" },
        { label: "Profile",  value: MODES[mode].label },
        { label: "Timing",   value: `-${timing}` },
        { label: "Risk",     value: MODES[mode].risk, tone: MODES[mode].risk === "high" ? "warning" : MODES[mode].risk === "medium" ? "warning" : "success" },
      ]} />

      {has && (
        <div className="flex flex-wrap items-center gap-3 rounded border border-border bg-card/40 px-4 py-3">
          <label className="flex items-center gap-2 cursor-pointer">
            <input
              type="checkbox"
              checked={confirmed}
              onChange={(e) => setConfirmed(e.target.checked)}
              className="h-4 w-4 accent-accent"
            />
            <span className="text-mono text-[11px] text-foreground/80">I own or have permission to scan this target</span>
          </label>
          <button
            onClick={handleExecute}
            disabled={!confirmed || running}
            className="inline-flex items-center gap-1.5 px-4 py-1.5 text-xs font-medium bg-primary/10 text-primary border border-primary/20 rounded hover:bg-primary/20 transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
          >
            {running ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Zap className="h-3.5 w-3.5" />}
            {running ? "scanning…" : "Execute scan"}
          </button>
        </div>
      )}

      {showFilter && (
        <OutputFilterBar
          filterText={filterText}
          onChange={setFilterText}
          onClear={() => setFilterText("")}
          onClose={() => { setShowFilter(false); setFilterText(""); }}
        />
      )}

      <OutputFilter query={filterText.toLowerCase()}>
      <div className="flex items-center gap-2">
        <SectionBar id="CM" label="Command" meta={MODES[mode].args} />
        <button
          onClick={toggleFilter}
          className={"inline-flex shrink-0 items-center gap-1 rounded border px-2 py-1 text-mono text-[10px] uppercase tracking-widest transition-colors " + (showFilter ? "border-primary/50 bg-primary/10 text-primary" : "border-border/60 text-muted-foreground hover:border-primary/40 hover:text-primary")}
          title="Toggle output filter (⌘F)"
        >
          <Search className="h-3 w-3" />
          filter
        </button>
      </div>
      <Panel icon={Terminal} title="Command" meta={`${MODES[mode].args.split(/\s+/).length + 2} flags`} actions={
        <div className="flex items-center gap-1">
          <button onClick={() => copy(cmd, "cmd")} className="inline-flex items-center gap-1 rounded border border-border bg-background/60 px-2 py-0.5 text-mono text-[10px] uppercase hover:border-primary/40 hover:text-primary">
            {copied === "cmd" ? <><Check className="h-3 w-3 text-success" /> copied</> : <><Copy className="h-3 w-3" /> copy</>}
          </button>
        </div>
      }>
        <pre className="overflow-x-auto rounded border border-border/50 bg-background/60 p-3 text-mono text-[12.5px] text-primary"><span className="text-muted-foreground">$ </span>{cmd}</pre>
        <div className="mt-2 flex flex-wrap items-center gap-1 text-mono text-[10px] text-muted-foreground">
          flags:
          {cmd.replace(/^nmap\s+/,"").split(/\s+/).slice(0,-1).map((f, i) => (
            <span key={i} className="rounded border border-border/60 bg-background/60 px-1.5 py-0.5 text-foreground/80">{f}</span>
          ))}
        </div>
      </Panel>

      <SectionBar id="OT" label="Output" meta={realResult ? "live scan" : "pre-scan"} />

      {!has ? (
        <Panel><p className="text-mono text-[11px] text-muted-foreground">Enter a target to configure a scan.</p></Panel>
      ) : running ? (
        <Panel icon={Loader2} meta="in progress">
          <div className="flex flex-col items-center gap-3 py-6">
            <span className="relative flex h-10 w-10">
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-primary/30" />
              <span className="relative inline-flex h-10 w-10 items-center justify-center rounded-full bg-primary/10">
                <Crosshair className="h-4 w-4 text-primary" />
              </span>
            </span>
            <p className="text-mono text-[11px] text-muted-foreground">Scanning {target}…</p>
          </div>
        </Panel>
      ) : realResult ? (
        scanResult ? (
          scanResult.error ? (
            <Panel>
              <div className="rounded border border-destructive/40 bg-destructive/10 px-3 py-2 text-mono text-[11px] text-destructive">{scanResult.error}</div>
            </Panel>
          ) : (
            <TerminalOutput
              command={cmd}
              body={scanResult.stdout || scanResult.stderr || JSON.stringify(scanResult, null, 2)}
              stderr={scanResult.stderr}
              status={scanResult.success ? "completed" : "failed"}
              onClear={() => setRealResult(null)}
              filename={`nmap-${target}.txt`}
            />
          )
        ) : null
      ) : (
        <Panel><p className="text-mono text-[11px] text-muted-foreground">Confirm permission and execute the scan to see results.</p></Panel>
      )}

      {history.length > 0 && (
        <Panel icon={Database} title="Recent targets" meta={`${history.length} targets`} collapsible storageKey="ba.panel.nmap.history" defaultCollapsed>
          <div className="flex flex-wrap gap-1.5">
            {history.map((h) => (
              <button key={h} onClick={() => setTarget(h)} className="inline-flex items-center gap-1 rounded border border-border/60 bg-background/40 px-2 py-0.5 text-mono text-[10px] text-muted-foreground hover:border-primary/50 hover:text-primary">
                {h}
              </button>
            ))}
          </div>
        </Panel>
      )}

      {realResult && scanResult && scanResult.stdout && (() => {
        const ports = parseNmapPorts(scanResult.stdout);
        const ips = [...new Set(scanResult.stdout.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || [])]
          .filter((ip) => ip !== target && !ip.startsWith("127.") && !ip.startsWith("10.") && !ip.startsWith("192.168.") && !ip.startsWith("172."));
        return (
          <>
          {ports.length > 0 && (
            <Panel icon={Server} title="Port summary" meta={`${ports.length} open port(s)`}>
              <div className="mb-2 flex items-center gap-3 text-mono text-[10px] text-muted-foreground">
                <span className="flex items-center gap-1"><span className="inline-block h-2 w-2 rounded bg-destructive/60" /> danger</span>
                <span className="flex items-center gap-1"><span className="inline-block h-2 w-2 rounded bg-warning/60" /> web-exposed</span>
                <span className="flex items-center gap-1"><span className="inline-block h-2 w-2 rounded bg-success/60" /> trusted</span>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-mono text-[11px]">
                  <thead><tr className="border-b border-border/60 text-left text-[10px] uppercase tracking-widest text-muted-foreground"><th className="px-2 py-1">Port</th><th className="px-2 py-1">State</th><th className="px-2 py-1">Service</th></tr></thead>
                  <tbody>
                    {ports.slice(0, 50).map((p, i) => (
                      <tr key={i} className={"border-b border-border/30 hover:bg-primary/[0.02] " + ({ destructive: "border-l-2 border-l-destructive bg-destructive/[0.02]", warning: "border-l-2 border-l-warning bg-warning/[0.02]", success: "border-l-2 border-l-success bg-success/[0.02]", transparent: "" }[portRiskTone(p.service)] ?? "")}>
                        <td className="px-2 py-1 text-foreground/90 font-mono">{p.port}</td>
                        <td className="px-2 py-1"><Chip tone={p.state === "open" ? "destructive" : p.state === "filtered" ? "warning" : "default"}>{p.state}</Chip></td>
                        <td className="px-2 py-1 text-muted-foreground">{p.service}</td>
                      </tr>
                    ))}
                    {ports.length > 50 && <tr><td colSpan={3} className="px-2 py-1 text-muted-foreground italic">… {ports.length - 50} more</td></tr>}
                  </tbody>
                </table>
              </div>
            </Panel>
          )}
          {ips.length > 0 && (
            <Panel icon={Globe2} title="Discovered IPs" meta={`${ips.length} address(es)`} actions={
              <button onClick={() => { ips.forEach((ip) => locker.add({ value: ip, type: "ipv4", source: "/nmap" })); toast(`Added ${ips.length} IPs to locker`); }} className="inline-flex items-center gap-1 rounded border border-border/50 bg-card/40 px-2 py-0.5 text-mono text-[9px] uppercase tracking-widest text-muted-foreground hover:bg-card/70 hover:text-foreground">+ locker</button>
            }>
              <div className="flex flex-wrap gap-1.5">
                {ips.map((ip) => (
                  <span key={ip} className="group inline-flex items-center gap-1 rounded border border-border/60 bg-background/40 px-2 py-0.5 text-mono text-[11px] text-foreground/90">
                    {ip}
                    <button onClick={() => locker.add({ value: ip, type: "ipv4", source: "/nmap" })} className="rounded p-0.5 text-muted-foreground/60 opacity-0 transition-opacity hover:text-primary group-hover:opacity-100" title="add to locker">+</button>
                  </span>
                ))}
              </div>
            </Panel>
          )}
          <Panel title="Export" meta="report" collapsible storageKey="ba.panel.nmap.export" defaultCollapsed>
            <div className="flex flex-wrap gap-2">
              <button onClick={() => { const md = genReport(target, mode, timing, scanResult.stdout as string); const blob = new Blob([md], { type: "text/markdown" }); const url = URL.createObjectURL(blob); const a = document.createElement("a"); a.href = url; a.download = `nmap-${target}-${Date.now()}.md`; a.click(); URL.revokeObjectURL(url); }} className="inline-flex items-center gap-1.5 rounded border border-primary/40 bg-primary/10 px-2.5 py-1.5 text-mono text-[10px] uppercase tracking-widest text-primary transition-all hover:bg-primary/20"><Download className="h-3 w-3" /> Markdown Report</button>
              <button onClick={() => { const json = genJsonExport(target, mode, timing, realResult); const blob = new Blob([json], { type: "application/json" }); const url = URL.createObjectURL(blob); const a = document.createElement("a"); a.href = url; a.download = `nmap-${target}.json`; a.click(); URL.revokeObjectURL(url); }} className="inline-flex items-center gap-1.5 rounded border border-primary/40 bg-primary/10 px-2.5 py-1.5 text-mono text-[10px] uppercase tracking-widest text-primary transition-all hover:bg-primary/20"><Download className="h-3 w-3" /> JSON Export</button>
            </div>
          </Panel>
          </>
        );
      })()}

      <SendToRow targets={[
        { label: "Recon Exposure", to: "/recon",     icon: ArrowRight },
        { label: "Detection",      to: "/detection", icon: ShieldAlert },
        { label: "Case Notebook",  to: "/case",      icon: Server },
        { label: "OSINT pivot",    to: "/osint",     icon: Globe2 },
      ]} />
      </OutputFilter>
    </PageShell>
  );
}
