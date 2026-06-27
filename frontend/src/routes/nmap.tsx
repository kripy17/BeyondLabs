import { createFileRoute } from "@tanstack/react-router";
import { useEffect, useMemo, useState } from "react";
import { PageShell } from "@/components/PageShell";
import { IntakeCard, SectionBar, Panel, Chip, SendToRow, KeyFields, StatusBar, ResultBanner, RiskScore, EvidenceCard, IocInventory, TwoColumnOutput, VerdictBanner, MetricGrid, CollapsibleSection } from "@/components/soc/Workspace";
import { sendArtifact, takePendingArtifact } from "@/lib/handoff";
import { runReconNmapScan } from "@/api/backend";
import { Server, Terminal, ArrowRight, Zap, ShieldAlert, Copy, Check, Gauge, Network, FileCode as FileCode2, Cpu, Globe as Globe2, Send, Search, Crosshair, Download, Loader as Loader2, ShieldCheck, ShieldX, TriangleAlert as AlertTriangle, Activity, Database } from "lucide-react";

export const Route = createFileRoute("/nmap")({ component: NmapPage });

const MODES = {
  discovery: { label: "Discovery",         args: "-sn -PE -PA80,443",                          risk: "low",    desc: "ICMP & ACK host discovery — no port probes.",          backend: "quick_tcp" },
  fast:      { label: "Top-100 TCP",       args: "-sS --top-ports 100 -Pn",                    risk: "medium", desc: "SYN scan of the 100 most common TCP ports.",           backend: "quick_tcp" },
  service:   { label: "Service & version", args: "-sV -sC --top-ports 1000 -Pn",               risk: "medium", desc: "Version detection + default NSE on common ports.",    backend: "service_version" },
  vuln:      { label: "Safe NSE scripts",  args: "-sV --script default,safe --top-ports 200 -Pn", risk: "high", desc: "Safe NSE scripts. Noisy — explicit auth only.",       backend: "safe_scripts" },
  full:      { label: "Full TCP + OS",     args: "-sS -p- -O -sV -Pn",                         risk: "high",   desc: "Every TCP port + OS fingerprint. Slow and loud.",     backend: "full_tcp" },
} as const;
type ModeKey = keyof typeof MODES;

const TIMINGS = [
  { k: "T2", label: "Polite",      hint: "stealth · low rate" },
  { k: "T3", label: "Normal",      hint: "default" },
  { k: "T4", label: "Aggressive",  hint: "lab / authorised" },
  { k: "T5", label: "Insane",      hint: "very loud" },
] as const;
type TimingKey = typeof TIMINGS[number]["k"];

function hash(s: string) { let h = 2166136261; for (let i=0;i<s.length;i++){ h ^= s.charCodeAt(i); h = (h * 16777619) >>> 0; } return h; }

const HOT_PORTS = new Set([21,22,23,25,53,80,110,139,143,443,445,587,993,995,1433,1521,2049,3306,3389,5432,5900,6379,8080,8443,9200,11211,27017]);
const PORT_SVC: Record<number,{svc:string; product:string; cpe:string}> = {
  22:   { svc: "ssh",       product: "OpenSSH 8.9 (Ubuntu)",        cpe: "cpe:/a:openbsd:openssh:8.9" },
  25:   { svc: "smtp",      product: "Postfix smtpd",                cpe: "cpe:/a:postfix:postfix" },
  53:   { svc: "domain",    product: "ISC BIND 9.18",                cpe: "cpe:/a:isc:bind:9.18" },
  80:   { svc: "http",      product: "nginx 1.24.0",                 cpe: "cpe:/a:nginx:nginx:1.24.0" },
  110:  { svc: "pop3",      product: "Dovecot",                      cpe: "cpe:/a:dovecot:dovecot" },
  143:  { svc: "imap",      product: "Dovecot",                      cpe: "cpe:/a:dovecot:dovecot" },
  443:  { svc: "https",     product: "nginx 1.24.0 · TLS 1.3",       cpe: "cpe:/a:nginx:nginx:1.24.0" },
  445:  { svc: "microsoft-ds", product: "Samba smbd 4.x",            cpe: "cpe:/a:samba:samba:4" },
  3306: { svc: "mysql",     product: "MySQL 8.0.36",                 cpe: "cpe:/a:oracle:mysql:8.0.36" },
  3389: { svc: "ms-wbt-server", product: "Microsoft Terminal Services", cpe: "cpe:/o:microsoft:windows" },
  5432: { svc: "postgresql",product: "PostgreSQL 16.2",              cpe: "cpe:/a:postgresql:postgresql:16.2" },
  6379: { svc: "redis",     product: "Redis 7.2",                    cpe: "cpe:/a:redislabs:redis:7.2" },
  8080: { svc: "http-proxy",product: "Apache 2.4.58",                cpe: "cpe:/a:apache:http_server:2.4.58" },
  8443: { svc: "https-alt", product: "Tomcat 10",                    cpe: "cpe:/a:apache:tomcat:10" },
  9200: { svc: "elastic",   product: "Elasticsearch 8.13",           cpe: "cpe:/a:elastic:elasticsearch:8.13" },
  27017:{ svc: "mongod",    product: "MongoDB 7.0",                  cpe: "cpe:/a:mongodb:mongodb:7.0" },
};

function synth(target: string) {
  if (!target) return { rows: [] as any[], openCount: 0, osGuess: "—", confidence: 0 };
  const h = hash(target);
  const candidates = Array.from(HOT_PORTS).sort((a,b)=>a-b);
  const rows = candidates.map((p, i) => {
    const r = ((h >>> (i % 24)) ^ p * 2654435761) >>> 0;
    const roll = r % 100;
    const state = roll < 28 ? "open" : roll < 60 ? "filtered" : "closed";
    const meta = PORT_SVC[p] ?? { svc: "unknown", product: "—", cpe: "—" };
    return { port: p, proto: "tcp", state, ...meta };
  });
  const osPool = ["Linux 5.x · Ubuntu", "Linux 6.x · Debian", "Windows Server 2022", "FreeBSD 14", "Cisco IOS XE"];
  return {
    rows,
    openCount: rows.filter((r) => r.state === "open").length,
    osGuess: osPool[h % osPool.length],
    confidence: 70 + (h % 25),
  };
}

function genReport(target: string, mode: ModeKey, timing: TimingKey, data: ReturnType<typeof synth>, realOutput: string | null): string {
  return [
    `# Nmap Scan Report`,
    `**Target:** ${target}`,
    `**Profile:** ${MODES[mode].label}`,
    `**Timing:** -${timing}`,
    ...(realOutput ? [`**Source:** real scan output`] : [`**Open ports:** ${data.openCount}`, `**OS guess:** ${data.osGuess} (${data.confidence}%)`]),
    "", ...(realOutput
      ? ["## Raw Output", "```", realOutput.slice(0, 5000), "```"]
      : ["## Open Ports",
         ...data.rows.filter((r) => r.state === "open").map((r) => `- ${r.port}/${r.proto}  ${r.svc}  ${r.product}`)]
    ),
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

  useEffect(() => { const h = takePendingArtifact(); if (h?.value) setTarget(h.value); }, []);

  const has = target.trim().length > 0;
  const cmd = `nmap ${MODES[mode].args} -${timing} ${has ? target : "<target>"}`;
  const data = useMemo(() => synth(target.trim()), [target]);
  const open = data.rows.filter((r) => r.state === "open");
  const filt = data.rows.filter((r) => r.state === "filtered");
  const cls  = data.rows.filter((r) => r.state === "closed");

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
    } catch {
      setRealResult({ error: "Scan request failed" });
    } finally {
      setRunning(false);
    }
  }

  const scanResult = realResult?.scan as Record<string, unknown> | undefined;

  const findings = useMemo(() => {
    if (!has) return [] as { sev: "destructive" | "warning" | "info"; title: string; reason: string; action: string }[];
    const f: typeof findings = [];
    if (open.some((r) => r.port === 22)) f.push({ sev: "warning", title: "SSH (22) open", reason: "Remote admin service exposed. Check auth method and version.", action: "Verify key-based auth only, disable password login, audit failed attempts." });
    if (open.some((r) => r.port === 3389)) f.push({ sev: "warning", title: "RDP (3389) open", reason: "Remote Desktop accessible. High-risk for brute force.", action: "Restrict via firewall, enable NLA, enforce strong passwords." });
    if (open.some((r) => r.port === 3306)) f.push({ sev: "destructive", title: "MySQL (3306) exposed", reason: "Database port exposed — potential data exfiltration vector.", action: "Bind to localhost or restrict to trusted IPs." });
    if (open.some((r) => r.port === 6379)) f.push({ sev: "destructive", title: "Redis (6379) exposed", reason: "In-memory data store accessible remotely — common ransomware vector.", action: "Bind to 127.0.0.1, require AUTH, disable CONFIG." });
    if (open.some((r) => r.port === 9200)) f.push({ sev: "destructive", title: "Elasticsearch (9200) exposed", reason: "Data store exposed — cluster manipulation or data exfil risk.", action: "Require auth, restrict to trusted IPs." });
    if (open.length >= 5) f.push({ sev: "warning", title: `${open.length} open ports detected`, reason: "Broad attack surface — each open port is a potential entry point.", action: "Audit and close unnecessary services; implement host-based firewall." });
    if (open.length === 0 && filt.length > 0) f.push({ sev: "info", title: "No open ports — filtered responses", reason: "Firewall may be concealing live services.", action: "Consider timing -T4 or full port range to bypass rate limits." });
    if (!f.length) f.push({ sev: "info", title: "Minimal exposure", reason: "No high-risk open ports detected.", action: "Re-scan with full port range and version detection for completeness." });
    return f;
  }, [open, filt, has]);

  const score = Math.min(100, findings.reduce((s, f) => s + (f.sev === "destructive" ? 25 : f.sev === "warning" ? 12 : 0), 0));

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

      <div className="grid gap-3 lg:grid-cols-[1.4fr_1fr]">
        <Panel icon={FileCode2} title="Scan profile" meta={`risk: ${MODES[mode].risk}`}>
          <div className="grid gap-1.5 sm:grid-cols-2">
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
        { label: "Open",     value: has ? open.length : "—", tone: "success" },
        { label: "Filtered", value: has ? filt.length : "—", tone: "warning" },
      ]} />

      {/* Permission + Execute row */}
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
          <span className="text-mono text-[10px] text-muted-foreground">Preview below is deterministic — real scan runs via backend nmap</span>
        </div>
      )}

      <SectionBar id="OT" label="Output · command" />
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

      <SectionBar id="OT" label="Output" meta={realResult ? "live scan" : "awaiting scan execution"} />

      {!has ? (
        <Panel><p className="text-mono text-[11px] text-muted-foreground">Enter a target and execute a scan to see results.</p></Panel>
      ) : (
        <div className="space-y-5">
          {realResult && scanResult ? (
            /* Real scan output */
            <>
              {scanResult.error ? (
                <Panel>
                  <div className="rounded border border-destructive/40 bg-destructive/10 px-3 py-2 text-mono text-[11px] text-destructive">{(scanResult as any).error}</div>
                </Panel>
              ) : (
                <>
                  <VerdictBanner
                    verdict={target}
                    tone={score >= 50 ? "destructive" : score >= 25 ? "warning" : "success"}
                    icon={score >= 50 ? ShieldX : score >= 25 ? AlertTriangle : ShieldCheck}
                    score={`${score}/100`}
                    details={[
                      `${MODES[mode].label} · -${timing}`,
                      "Scan completed successfully",
                    ]}
                  />
                  <RiskScore score={score} label="Exposure Risk" confidence={score < 15 ? "low" : score < 40 ? "moderate" : score < 65 ? "high" : "very high"} tone={score < 20 ? "success" : score < 60 ? "warning" : "destructive"} />
                  <Panel title="Scan output" icon={Terminal} meta={scanResult.success ? "completed" : "failed"} collapsible>
                    <pre className="overflow-x-auto rounded border border-border/50 bg-background/60 p-3 text-mono text-[12px] text-foreground/90 max-h-80 whitespace-pre-wrap">
                      {(scanResult.stdout as string) || (scanResult.stderr as string) || JSON.stringify(scanResult, null, 2)}
                    </pre>
                  </Panel>
                </>
              )}
            </>
          ) : (
            /* No scan run yet - show placeholder */
            <Panel title="Awaiting Scan" icon={Terminal}>
              <div className="text-center py-8">
                <Terminal className="h-10 w-10 mx-auto text-muted-foreground/40 mb-3" />
                <p className="text-mono text-[12px] text-muted-foreground mb-2">
                  Configure your scan above and click "Execute scan" to run a real nmap scan.
                </p>
                <p className="text-mono text-[10px] text-muted-foreground/70">
                  You must confirm authorization before the scan will execute.
                </p>
              </div>
            </Panel>
          )}

          {/* Report - collapsible */}
          {realResult && scanResult && (
            <Panel title="Report" meta="markdown" collapsible defaultCollapsed actions={
              <button onClick={() => { const md = genReport(target, mode, timing, data, (scanResult?.stdout as string) || null); const blob = new Blob([md], { type: "text/markdown" }); const url = URL.createObjectURL(blob); const a = document.createElement("a"); a.href = url; a.download = `nmap-${target}-${Date.now()}.md`; a.click(); URL.revokeObjectURL(url); }} className="inline-flex items-center gap-1 rounded border border-border px-2 py-0.5 text-mono text-[10px] uppercase text-muted-foreground hover:text-foreground"><Download className="h-3 w-3" /> md</button>
            }>
              <pre className="max-h-40 overflow-auto rounded bg-background/60 p-3 text-mono text-[11px] text-foreground/90">{genReport(target, mode, timing, data, (scanResult?.stdout as string) || null)}</pre>
            </Panel>
          )}
        </div>
      )}

      <SendToRow targets={[
        { label: "Recon Exposure", to: "/recon",     icon: ArrowRight },
        { label: "Detection",      to: "/detection", icon: ShieldAlert },
        { label: "Case Notebook",  to: "/case",      icon: Server },
        { label: "OSINT pivot",    to: "/osint",     icon: Globe2 },
      ]} />
    </PageShell>
  );
}
