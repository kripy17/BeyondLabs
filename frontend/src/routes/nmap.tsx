import { createFileRoute } from "@tanstack/react-router";
import { useEffect, useRef, useState, useCallback } from "react";
import { z } from "zod";
import { useMutation } from "@tanstack/react-query";
import { PageShell } from "@/components/PageShell";
import { IntakeCard, SectionBar, Panel, Chip, SendToRow } from "@/components/soc";
import { StatusBar, DataTable, CodeBlock } from "@/components/output";
import { TerminalOutput } from "@/components/soc/TerminalOutput";
import { useOutputFilter, OutputFilterBar, OutputFilter } from "@/components/soc/OutputFilter";
import { useLocker } from "@/lib/locker";
import { useResultCache } from "@/lib/result-cache";
import { useStreamingNmap } from "@/lib/useStreamingNmap";
import { computeNmapDiff, type PortChange } from "@/lib/diff";
import { AttachButton } from "@/components/AttachButton";
import { takePendingArtifact } from "@/lib/handoff";
import { copyText } from "@/lib/copy";
import { pushTimelineEvent } from "@/lib/timeline";
import { runReconNmapScan } from "@/api/backend";
import { toast } from "sonner";
import {
  Server, Terminal, ArrowRight, Zap, ShieldAlert, Copy, Check,
  Gauge, FileCode2, Globe2, Crosshair, Download, Loader2, Search, Database, X,
} from "lucide-react";
import { ExplainThisButton } from "@/components/ExplainThis";

const nmapTargetSchema = z.string().refine(
  (val) => {
    if (!val.trim()) return true;
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(val)) return true;
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}$/.test(val)) return true;
    if (/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*\.[a-z]{2,}$/i.test(val)) return true;
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}-\d{1,3}$/.test(val)) return true;
    return false;
  },
  { message: "Invalid target: use IP (1.2.3.4), CIDR (1.2.3.0/24), hostname (example.com), or range (1.2.3.1-20)" }
);

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

function ScanProgress({ startTime, estimatedSeconds }: { startTime: number; estimatedSeconds: number }) {
  const [elapsed, setElapsed] = useState(0);
  const [phase, setPhase] = useState<"indeterminate" | "determinate">("indeterminate");

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
        <span>{phase === "indeterminate" ? "Starting scan…" : `Scanning… ${Math.round(elapsed)}s / ${estimatedSeconds}s`}</span>
      </div>
    </div>
  );
}

function NmapPage() {
  const [target, setTarget] = useState("");
  const [mode, setMode] = useState<ModeKey>("service");
  const [timing, setTiming] = useState<TimingKey>("T3");
  const [copied, setCopied] = useState<string | null>(null);
  const [confirmed, setConfirmed] = useState(false);
  const [targetError, setTargetError] = useState<string | null>(null);
  const [history, setHistory] = useState<string[]>([]);
  const cache = useResultCache<Record<string, unknown>>("nmap");
  const [portChanges, setPortChanges] = useState<PortChange[]>([]);
  const [scanMeta, setScanMeta] = useState<{ startTime: number; mode: ModeKey } | null>(null);
  const abortRef = useRef<AbortController | null>(null);

  const cancelScan = () => {
    abortRef.current?.abort();
    abortRef.current = null;
  };

  const scanMutation = useMutation({
    mutationFn: ({ target, mode, confirmPermission }: { target: string; mode: string; confirmPermission: boolean }) =>
      runReconNmapScan({ target, mode, confirmPermission, signal: abortRef.current?.signal ?? undefined }),
    onSuccess: (res) => {
      setScanMeta(null);
      const data = res as Record<string, unknown>;
      cache.save(data);
      const newScan = data?.scan as NmapScanResult | undefined;
      if (newScan?.stdout) {
        const prevRaw = sessionStorage.getItem("ba.nmap.prev_ports");
        if (prevRaw) {
          try {
            const prevPorts = JSON.parse(prevRaw) as { port: string; state: string; service: string }[];
            const newPorts = parseNmapPorts(newScan.stdout);
            const toNumeric = (p: { port: string; state: string; service: string }) => ({
              port: parseInt(p.port.split("/")[0], 10), state: p.state, service: p.service || undefined,
            });
            setPortChanges(computeNmapDiff({ ports: prevPorts.map(toNumeric) }, { ports: newPorts.map(toNumeric) }));
          } catch {}
        }
      } else {
        setPortChanges([]);
      }
      const targetStr = (data as Record<string, unknown>)?.target as string ?? "";
      const modeStr = (data as Record<string, unknown>)?.mode as string ?? "";
      setHistory((prev) => { const next = [targetStr, ...prev.filter((p) => p !== targetStr)].slice(0, 8); try { localStorage.setItem(HISTORY_KEY, JSON.stringify(next)); } catch {} return next; });
      pushTimelineEvent({ source: "nmap", verb: "scanned", detail: `Scanned ${targetStr} (${modeStr})`, target: targetStr, result: `${newScan?.stdout ? parseNmapPorts(newScan.stdout).length : 0} ports found` });
      toast.success("Scan complete", { description: `${targetStr} — ${modeStr}` });
    },
    onError: (err: Error) => {
      setScanMeta(null);
      toast.error(err.message, { description: (err as any).suggestion });
      setPortChanges([]);
    },
  });

  const handleClear = useCallback(() => {
    setTarget("");
    setTargetError(null);
    scanMutation.reset();
    setPortChanges([]);
    toast("Cleared");
  }, [scanMutation]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") handleClear();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [handleClear]);

  const stream = useStreamingNmap();
  const locker = useLocker();
  const { filterText, setFilterText, showFilter, setShowFilter, toggleFilter } = useOutputFilter();
  useEffect(() => { const h = takePendingArtifact(); if (h?.value) setTarget(h.value); }, []);
  useEffect(() => { try { setHistory(JSON.parse(localStorage.getItem(HISTORY_KEY) || "[]")); } catch {} }, []);

  const has = target.trim().length > 0;
  const cmd = `nmap ${MODES[mode].args} -${timing} ${has ? target : "<target>"}`;

  const copy = (text: string, key: string) => {
    copyText(text);
    setCopied(key);
    setTimeout(() => setCopied((c) => (c === key ? null : c)), 1100);
  };

  function validateTarget(val: string) {
    const result = nmapTargetSchema.safeParse(val);
    if (!result.success && val.trim()) {
      setTargetError(result.error.issues[0].message);
    } else {
      setTargetError(null);
    }
  }

  function handleExecute() {
    if (!has) return;
    setScanMeta({ startTime: Date.now(), mode });

    abortRef.current?.abort();
    const controller = new AbortController();
    abortRef.current = controller;

    if (scanMutation.data) {
      const scanR = scanMutation.data.scan as NmapScanResult | undefined;
      if (scanR?.stdout) {
        try { sessionStorage.setItem("ba.nmap.prev_ports", JSON.stringify(parseNmapPorts(scanR.stdout))); } catch {}
      }
    }

    stream.start(target.trim(), MODES[mode].backend, `-${timing}`);
    scanMutation.mutate({
      target: target.trim(),
      mode: MODES[mode].backend,
      confirmPermission: confirmed,
    });
  }

  function handleCancel() {
    cancelScan();
    scanMutation.reset();
  }

  const scanResult = scanMutation.data?.scan as NmapScanResult | undefined;

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
        onChange={(v: string) => { setTarget(v); validateTarget(v); }}
        rows={2}
        placeholder="example.com · 198.51.100.1 · 10.0.0.0/24"
        samples={[
          { key: "h", label: "Host",   hint: "scanme.nmap.org" },
          { key: "i", label: "IPv4",   hint: "198.51.100.1" },
          { key: "c", label: "CIDR /24", hint: "10.0.0.0/24" },
        ]}
        onLoadSample={(k) => setTarget(k === "h" ? "scanme.nmap.org" : k === "i" ? "198.51.100.1" : "10.0.0.0/24")}
            run={{ label: "render brief", icon: Zap, hint: has ? "preview" : "enter target", onClick: () => {}, disabled: !has || !!targetError }}
        onClear={() => setTarget("")}
        showCopy
      />

      {targetError && (
        <div className="-mt-2 mb-2 rounded border border-destructive/30 bg-destructive/10 px-3 py-1.5 text-mono ba-text-sm text-destructive">
          {targetError}
        </div>
      )}

      <div className="grid gap-3 grid-cols-[1.4fr_1fr]">
        <Panel icon={FileCode2} title="Scan profile" meta={`risk: ${MODES[mode].risk}`} priority="secondary">
          <div className="grid gap-1.5 grid-cols-2">
            {(Object.keys(MODES) as ModeKey[]).map((k) => {
              const m = MODES[k];
              const sel = mode === k;
              return (
                <button
                  key={k}
                  onClick={() => setMode(k)}
                  className={"rounded border px-2.5 py-2 text-left transition " + (sel ? "border-primary bg-primary/5 shadow-[0_0_0_1px_hsl(var(--primary)/0.25)]" : "border-divider-strong hover:border-primary/40 hover:bg-primary/[0.03]")}
                >
                  <div className="flex items-center justify-between">
                    <span className="text-mono ba-text-sm uppercase tracking-widest text-foreground">{m.label}</span>
                    <Chip tone={m.risk === "high" ? "destructive" : m.risk === "medium" ? "warning" : "success"}>{m.risk}</Chip>
                  </div>
                  <code className="mt-1 block truncate text-mono text-[10px] text-primary">{m.args}</code>
                  <div className="mt-1 line-clamp-2 text-mono text-[10.5px] text-muted-foreground">{m.desc}</div>
                </button>
              );
            })}
          </div>
        </Panel>

        <Panel icon={Gauge} title="Timing & rate" meta="-T0…-T5" priority="secondary">
          <div className="grid gap-1.5">
            {TIMINGS.map((t) => {
              const sel = timing === t.k;
              return (
                <button
                  key={t.k}
                  onClick={() => setTiming(t.k)}
                  className={"flex items-center justify-between gap-2 rounded border px-2.5 py-1.5 text-left transition " + (sel ? "border-primary bg-primary/5" : "border-divider-strong hover:border-primary/40")}
                >
                  <span className="flex items-center gap-2">
                    <span className="rounded border border-divider-strong bg-background/60 px-1.5 py-0.5 text-mono text-[10px] text-primary">-{t.k}</span>
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
        <div className="rounded border border-divider-strong bg-card/50 p-4 space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-mono ba-text-2xs uppercase tracking-widest text-muted-foreground">Scan Authorization</span>
            <Chip tone="destructive">REQUIRED</Chip>
          </div>
          <div className="grid gap-2 text-mono ba-text-sm">
            <div className="flex items-center gap-2">
              <span className="text-muted-foreground">Target:</span>
              <code className="px-1.5 py-0.5 rounded border border-border/50 bg-background/60 text-foreground/90">{target}</code>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-muted-foreground">Profile:</span>
              <span className="text-foreground/80">{MODES[mode].label}</span>
              <Chip tone={MODES[mode].risk === "high" ? "destructive" : MODES[mode].risk === "medium" ? "warning" : "success"}>{MODES[mode].risk}</Chip>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-muted-foreground">Est. time:</span>
              <span className="text-foreground/80">{mode === "full" ? "~10 min" : mode === "vuln" ? "~5 min" : mode === "service" ? "~2 min" : mode === "fast" ? "~30s" : "~15s"}</span>
            </div>
          </div>
          <label className="flex items-center gap-2 cursor-pointer py-1">
            <input
              type="checkbox"
              checked={confirmed}
              onChange={(e) => setConfirmed(e.target.checked)}
              className="h-4 w-4 accent-accent"
            />
            <span className="text-mono ba-text-sm text-foreground/80">I own or have permission to scan this target</span>
          </label>
          <div className="flex justify-end gap-2">
            {scanMutation.isPending && (
              <button
                onClick={handleCancel}
                className="inline-flex items-center gap-1.5 px-4 py-1.5 text-xs font-medium bg-destructive/10 text-destructive border border-destructive/20 rounded hover:bg-destructive/20 transition-colors"
              >
                <X className="h-3.5 w-3.5" />
                cancel
              </button>
            )}
            <button
              onClick={handleExecute}
              disabled={!confirmed || scanMutation.isPending || !!targetError}
              className="inline-flex items-center gap-1.5 px-4 py-1.5 text-xs font-medium bg-primary/10 text-primary border border-primary/20 rounded hover:bg-primary/20 transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
            >
              {scanMutation.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Zap className="h-3.5 w-3.5" />}
              {scanMutation.isPending ? "scanning…" : "Execute scan"}
            </button>
          </div>
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
        <SectionBar id="CM" label="Command" meta={MODES[mode].args} priority="secondary" />
        <button
          onClick={toggleFilter}
          className={"inline-flex shrink-0 items-center gap-1 rounded border px-2 py-1 text-mono text-[10px] uppercase tracking-widest transition-colors " + (showFilter ? "border-primary/50 bg-primary/10 text-primary" : "border-divider-strong text-muted-foreground hover:border-primary/40 hover:text-primary")}
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
        <CodeBlock language="shell">{`$ ${cmd}`}</CodeBlock>
        <div className="mt-2 flex flex-wrap items-center gap-1 text-mono text-[10px] text-muted-foreground">
          flags:
          {cmd.replace(/^nmap\s+/,"").split(/\s+/).slice(0,-1).map((f, i) => (
            <span key={i} className="rounded border border-divider-strong bg-background/60 px-1.5 py-0.5 text-foreground/80">{f}</span>
          ))}
        </div>
      </Panel>

      <SectionBar id="OT" label="Output" meta={scanMutation.data ? (cache.agoLabel ? `${cache.agoLabel}` : "live scan") : "pre-scan"} action={scanMutation.data ? <><AttachButton body={JSON.stringify(scanMutation.data)} kind="evidence" source="/nmap" label="case" /></> : undefined} />

      {!has ? (
        <Panel priority="secondary"><p className="text-mono ba-text-sm text-muted-foreground">Enter a target to configure a scan.</p></Panel>
      ) : scanMutation.isPending ? (
        <Panel icon={Loader2} meta="in progress" priority="secondary" bodyClassName="p-4">
          <ScanProgress
            startTime={scanMeta?.startTime ?? Date.now()}
            estimatedSeconds={
              scanMeta?.mode === "full" ? 600 :
              scanMeta?.mode === "vuln" ? 300 :
              scanMeta?.mode === "service" ? 120 :
              scanMeta?.mode === "fast" ? 30 : 15
            }
          />
        </Panel>
      ) : scanMutation.data ? (
        scanResult ? (
          scanResult.error ? (
            <Panel priority="secondary">
              <div className="rounded border border-destructive/40 bg-destructive/10 px-3 py-2 text-mono ba-text-sm text-destructive">{scanResult.error}</div>
            </Panel>
          ) : (
            <Panel icon={Terminal} title="Raw scan output" meta={scanResult.stdout ? `${scanResult.stdout.split('\n').length} lines` : ''}
              actions={<ExplainThisButton kind="nmap" input={scanResult.stdout || scanResult.stderr || ""} />}
              collapsible storageKey="ba.panel.nmap.raw" defaultCollapsed={scanResult.stdout ? scanResult.stdout.split('\n').length > 50 : false}>
            <TerminalOutput
              command={cmd}
              body={scanResult.stdout || scanResult.stderr || JSON.stringify(scanResult, null, 2)}
              stderr={scanResult.stderr}
              status={scanResult.success ? "completed" : "failed"}
              onClear={() => scanMutation.reset()}
              filename={`nmap-${target}.txt`}
            />
            </Panel>
          )
        ) : null
      ) : (
        <Panel priority="secondary"><p className="text-mono ba-text-sm text-muted-foreground">Confirm permission and execute the scan to see results.</p></Panel>
      )}

      {(stream.running || stream.lines.length > 0) && (
        <Panel icon={Terminal} title="Streaming output" meta={stream.running ? "live" : `${stream.lines.length} lines`}>
          {stream.running && <div className="mb-2 flex items-center gap-2 text-mono text-[10px] text-success"><span className="inline-block h-2 w-2 rounded-full bg-success animate-pulse" /> streaming…</div>}
          {stream.error && <div className="mb-2 rounded border border-destructive/40 bg-destructive/10 px-3 py-2 text-mono ba-text-sm text-destructive">{stream.error}</div>}
          <CodeBlock language="shell" maxHeight="12rem">{stream.lines.slice(-50).join("\n")}</CodeBlock>
          {stream.lines.length > 50 && <div className="mt-1 text-mono text-[10px] text-muted-foreground">… {stream.lines.length - 50} more lines</div>}
        </Panel>
      )}

      {history.length > 0 && (
        <Panel icon={Database} title="Recent targets" meta={`${history.length} targets`} priority="secondary" collapsible storageKey="ba.panel.nmap.history" defaultCollapsed>
          <div className="flex flex-wrap gap-1.5">
            {history.map((h) => (
              <button key={h} onClick={() => setTarget(h)} className="inline-flex items-center gap-1 rounded border border-divider-strong bg-background/40 px-2 py-0.5 text-mono text-[10px] text-muted-foreground hover:border-primary/50 hover:text-primary">
                {h}
              </button>
            ))}
          </div>
        </Panel>
      )}

      {scanMutation.data && scanResult && scanResult.stdout && (() => {
        const ports = parseNmapPorts(scanResult.stdout);
        const ips = [...new Set(scanResult.stdout.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || [])]
          .filter((ip) => ip !== target && !ip.startsWith("127.") && !ip.startsWith("10.") && !ip.startsWith("192.168.") && !ip.startsWith("172."));
        return (
          <>
          {portChanges.length > 0 && (
            <div className="mb-2 rounded border border-border/50 bg-card/50 p-3">
              <div className="mb-2 flex items-center gap-2">
                <span className="text-mono text-[10px] uppercase tracking-widest text-muted-foreground">changes since last scan</span>
                <Chip tone="default">{portChanges.length}</Chip>
              </div>
              <div className="space-y-0.5">
                {portChanges.map((pc) => (
                  <div key={pc.port} className="flex items-center gap-2 text-mono text-[12px]">
                    {pc.type === "added" && <span className="w-4 shrink-0 text-success">+</span>}
                    {pc.type === "removed" && <span className="w-4 shrink-0 text-destructive">−</span>}
                    {pc.type === "changed" && <span className="w-4 shrink-0 text-warning">~</span>}
                    <span className="text-foreground/90">{pc.port}/tcp</span>
                    <span className={pc.type === "added" ? "text-success" : pc.type === "removed" ? "text-destructive" : "text-warning"}>
                      {pc.type === "changed" ? `${pc.oldState} → ${pc.newState}` : (pc.newState || pc.oldState)}
                    </span>
                    {pc.service && <span className="text-muted-foreground">{pc.service}</span>}
                  </div>
                ))}
              </div>
            </div>
          )}
          {ports.length > 0 && (
            <Panel icon={Server} title="Port summary" meta={`${ports.length} open port(s)${portChanges.length ? ` · ${portChanges.length} change${portChanges.length !== 1 ? 's' : ''}` : ''}`}>
              <div className="mb-2 flex items-center gap-3 text-mono text-[10px] text-muted-foreground">
                <span className="flex items-center gap-1"><span className="inline-block h-2 w-2 rounded bg-destructive/60" /> danger</span>
                <span className="flex items-center gap-1"><span className="inline-block h-2 w-2 rounded bg-warning/60" /> web-exposed</span>
                <span className="flex items-center gap-1"><span className="inline-block h-2 w-2 rounded bg-success/60" /> trusted</span>
              </div>
              <DataTable
                columns={[
                  { key: "port", label: "Port", align: "right", sortable: true, width: "80px", render: (p: any) => <span className="font-mono tabular-nums text-foreground/90">{p.port}</span> },
                  { key: "state", label: "State", sortable: true, width: "100px", render: (p: any) => <Chip tone={p.state === "open" ? "destructive" : p.state === "filtered" ? "warning" : "default"}>{p.state}</Chip> },
                  { key: "service", label: "Service", sortable: true, render: (p: any) => <span className="text-foreground/80">{p.service}</span> },
                ]}
                rows={ports.slice(0, 50)}
              />
            </Panel>
          )}
          {ips.length > 0 && (
            <Panel icon={Globe2} title="Discovered IPs" meta={`${ips.length} address(es)`} priority="secondary" actions={
              <button onClick={() => { ips.forEach((ip) => locker.add({ value: ip, type: "ipv4", source: "/nmap" })); toast(`Added ${ips.length} IPs to locker`); }} className="inline-flex items-center gap-1 rounded border border-border/50 bg-card/40 px-2 py-0.5 text-mono text-[9px] uppercase tracking-widest text-muted-foreground hover:bg-card/70 hover:text-foreground">+ locker</button>
            }>
              <div className="flex flex-wrap gap-1.5">
                {ips.map((ip) => (
                  <span key={ip} className="group inline-flex items-center gap-1 rounded border border-divider-strong bg-background/40 px-2 py-0.5 text-mono ba-text-sm text-foreground/90">
                    {ip}
                    <button onClick={() => locker.add({ value: ip, type: "ipv4", source: "/nmap" })} className="rounded p-0.5 text-muted-foreground/60 opacity-0 transition-opacity hover:text-primary group-hover:opacity-100" title="add to locker">+</button>
                  </span>
                ))}
              </div>
            </Panel>
          )}
          <Panel title="Export" meta="report" priority="secondary" collapsible storageKey="ba.panel.nmap.export" defaultCollapsed>
            <div className="flex flex-wrap gap-2">
              <button onClick={() => { const md = genReport(target, mode, timing, scanResult.stdout as string); const blob = new Blob([md], { type: "text/markdown" }); const url = URL.createObjectURL(blob); const a = document.createElement("a"); a.href = url; a.download = `nmap-${target}-${Date.now()}.md`; a.click(); URL.revokeObjectURL(url); }} className="inline-flex items-center gap-1.5 rounded border border-primary/40 bg-primary/10 px-2.5 py-1.5 text-mono text-[10px] uppercase tracking-widest text-primary transition-all hover:bg-primary/20"><Download className="h-3 w-3" /> Markdown Report</button>
              <button onClick={() => { const json = genJsonExport(target, mode, timing, scanMutation.data); const blob = new Blob([json], { type: "application/json" }); const url = URL.createObjectURL(blob); const a = document.createElement("a"); a.href = url; a.download = `nmap-${target}.json`; a.click(); URL.revokeObjectURL(url); }} className="inline-flex items-center gap-1.5 rounded border border-primary/40 bg-primary/10 px-2.5 py-1.5 text-mono text-[10px] uppercase tracking-widest text-primary transition-all hover:bg-primary/20"><Download className="h-3 w-3" /> JSON Export</button>
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
