import { createFileRoute } from "@tanstack/react-router";
import { useEffect, useMemo, useState } from "react";
import { PageShell } from "@/components/PageShell";
import { IntakeCard, SectionBar, Panel, Chip, SendToRow, KeyFields, StatusBar, ResultBanner, RiskScore, EvidenceCard, IocInventory } from "@/components/soc/Workspace";
import { PreviewBadge } from "@/components/PreviewBadge";
import { sendArtifact, takePendingArtifact } from "@/lib/handoff";
import {
  Server, Terminal, ArrowRight, Zap, Database, ShieldAlert, Copy, Check, Play,
  Gauge, Activity, Network, FileCode2, Cpu, Globe2, Send, Search, Crosshair, Download, Hash,
} from "lucide-react";

export const Route = createFileRoute("/nmap")({ component: NmapPage });

const MODES = {
  discovery: { label: "Discovery",         args: "-sn -PE -PA80,443",                          risk: "low",    desc: "ICMP & ACK host discovery — no port probes.",          scripts: [] as string[] },
  fast:      { label: "Top-100 TCP",       args: "-sS --top-ports 100 -Pn",                    risk: "medium", desc: "SYN scan of the 100 most common TCP ports.",           scripts: [] },
  service:   { label: "Service & version", args: "-sV -sC --top-ports 1000 -Pn",               risk: "medium", desc: "Version detection + default NSE on common ports.",    scripts: ["http-title","ssh-hostkey","ssl-cert","banner"] },
  vuln:      { label: "Vuln scripts",      args: "-sV --script vuln --top-ports 200 -Pn",      risk: "high",   desc: "NSE vuln scripts. Noisy — explicit auth only.",       scripts: ["http-vuln-cve2017-5638","smb-vuln-ms17-010","ssl-heartbleed","http-shellshock"] },
  full:      { label: "Full TCP + OS",     args: "-sS -p- -O -sV -Pn",                         risk: "high",   desc: "Every TCP port + OS fingerprint. Slow and loud.",     scripts: ["smb-os-discovery"] },
} as const;
type ModeKey = keyof typeof MODES;

const TIMINGS = [
  { k: "T2", label: "Polite",      hint: "stealth · low rate" },
  { k: "T3", label: "Normal",      hint: "default" },
  { k: "T4", label: "Aggressive",  hint: "lab / authorised" },
  { k: "T5", label: "Insane",      hint: "very loud" },
] as const;
type TimingKey = typeof TIMINGS[number]["k"];

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

function hash(s: string) { let h = 2166136261; for (let i=0;i<s.length;i++){ h ^= s.charCodeAt(i); h = (h * 16777619) >>> 0; } return h; }
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

function genReport(target: string, mode: ModeKey, timing: TimingKey, data: ReturnType<typeof synth>): string {
  return [
    `# Nmap Scan Report`,
    `**Target:** ${target}`,
    `**Profile:** ${MODES[mode].label}`,
    `**Timing:** -${timing}`,
    `**Open ports:** ${data.openCount}`,
    `**OS guess:** ${data.osGuess} (${data.confidence}%)`,
    "", "## Open Ports",
    ...data.rows.filter((r) => r.state === "open").map((r) => `- ${r.port}/${r.proto}  ${r.svc}  ${r.product}`),
    "", "## Command",
    `nmap ${MODES[mode].args} -${timing} ${target}`,
  ].join("\n");
}

function NmapPage() {
  const [target, setTarget] = useState("");
  const [mode, setMode] = useState<ModeKey>("service");
  const [timing, setTiming] = useState<TimingKey>("T3");
  const [copied, setCopied] = useState<string | null>(null);

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

  const findings = useMemo(() => {
    if (!has) return [] as { sev: "destructive" | "warning" | "info"; title: string; reason: string; action: string }[];
    const f: typeof findings = [];
    if (open.some((r) => r.port === 22)) f.push({ sev: "warning", title: "SSH (22) open", reason: "Remote admin service exposed. Check auth method and version.", action: "Verify key-based auth only, disable password login, audit failed attempts." });
    if (open.some((r) => r.port === 3389)) f.push({ sev: "warning", title: "RDP (3389) open", reason: "Remote Desktop accessible from scan source. High-risk for brute force.", action: "Restrict via firewall, enable NLA, enforce strong passwords." });
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
      description="Compose bounded nmap commands and preview a deterministic synthetic brief. No scan is executed from this UI."
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
        run={{ label: "render brief", icon: Zap, hint: has ? "synthetic" : "enter target", onClick: () => {}, disabled: !has }}
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

      <SectionBar id="OT" label="Output · generated command" />
      <Panel icon={Terminal} title="Command" meta={`${MODES[mode].args.split(/\s+/).length + 2} flags`} actions={
        <div className="flex items-center gap-1">
          <button onClick={() => copy(cmd, "cmd")} className="inline-flex items-center gap-1 rounded border border-border bg-background/60 px-2 py-0.5 text-mono text-[10px] uppercase hover:border-primary/40 hover:text-primary">
            {copied === "cmd" ? <><Check className="h-3 w-3 text-success" /> copied</> : <><Copy className="h-3 w-3" /> copy</>}
          </button>
          <PreviewBadge label="not executed" />
        </div>
      }>
        <pre className="overflow-x-auto rounded border border-border/50 bg-background/60 p-3 text-mono text-[12.5px] text-primary"><span className="text-muted-foreground">$ </span>{cmd}</pre>
        <div className="mt-2 flex flex-wrap items-center gap-1 text-mono text-[10px] text-muted-foreground">
          flags:
          {cmd.replace(/^nmap\s+/,"").split(/\s+/).slice(0,-1).map((f, i) => (
            <span key={i} className="rounded border border-border/60 bg-background/60 px-1.5 py-0.5 text-foreground/80">{f}</span>
          ))}
        </div>
        {MODES[mode].scripts.length > 0 && (
          <div className="mt-2 flex flex-wrap items-center gap-1 text-mono text-[10px] text-muted-foreground">
            NSE scripts:
            {MODES[mode].scripts.map((s) => (
              <span key={s} className="rounded border border-accent/40 bg-accent/10 px-1.5 py-0.5 text-accent">{s}</span>
            ))}
          </div>
        )}
      </Panel>

      <SectionBar id="OT" label="Output · synthetic brief" meta="deterministic from target — not a real scan" />

      {!has ? (
        <Panel><p className="text-mono text-[11px] text-muted-foreground">Enter a target to render the synthetic brief.</p></Panel>
      ) : (
        <>
          <RiskScore score={score} label="Exposure Risk" confidence={score < 15 ? "low" : score < 40 ? "moderate" : score < 65 ? "high" : "very high"} tone={score < 20 ? "success" : score < 60 ? "warning" : "destructive"} />
          <ResultBanner
            badge="nmap_preview"
            title={target}
            subtitle={`${MODES[mode].label} · -${timing} · ${data.rows.length} probed ports · ${data.osGuess} (${data.confidence}% conf.)`}
            metrics={[
              { label: "Open",     value: open.length, tone: "success" },
              { label: "Filtered", value: filt.length, tone: "warning" },
              { label: "Closed",   value: cls.length },
              { label: "Hot svc",  value: open.filter((r) => HOT_PORTS.has(r.port)).length, tone: "primary" },
            ]}
          />

          <Panel>
            <KeyFields items={[
              { label: "Target",     value: target,             tone: "primary" },
              { label: "Profile",    value: MODES[mode].label },
              { label: "Timing",     value: `-${timing}` },
              { label: "OS guess",   value: data.osGuess,       tone: "primary" },
              { label: "Confidence", value: `${data.confidence}%` },
              { label: "Risk class", value: MODES[mode].risk,   tone: MODES[mode].risk === "high" ? "destructive" : "warning" },
            ]} />
          </Panel>

          {/* Evidence cards */}
          <div className="grid gap-3 md:grid-cols-2">
            {findings.map((f, i) => (
              <EvidenceCard key={i} severity={f.sev} title={f.title} reason={f.reason} action={f.action} limitation="Synthetic preview — run actual scan to confirm." />
            ))}
          </div>

          <div className="grid gap-3 lg:grid-cols-[1.5fr_1fr]">
            <Panel icon={Network} title="Port table" meta={`${data.rows.length} rows · ${open.length} open`}>
              <div className="overflow-x-auto rounded border border-border/50">
                <table className="w-full text-mono text-[11.5px]">
                  <thead className="bg-background/40 text-[10px] uppercase tracking-widest text-muted-foreground">
                    <tr>
                      <th className="px-2 py-1 text-left">port</th>
                      <th className="px-2 py-1 text-left">proto</th>
                      <th className="px-2 py-1 text-left">state</th>
                      <th className="px-2 py-1 text-left">service</th>
                      <th className="px-2 py-1 text-left">product</th>
                      <th className="px-2 py-1 text-left">cpe</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.rows.map((r, i) => (
                      <tr key={r.port} className={"border-t border-border/40 " + (i % 2 ? "bg-background/20" : "") + " hover:bg-primary/[0.04]"}>
                        <td className="px-2 py-1.5 text-foreground/90">{r.port}</td>
                        <td className="px-2 py-1.5 text-muted-foreground">{r.proto}</td>
                        <td className="px-2 py-1.5"><Chip tone={r.state === "open" ? "success" : r.state === "filtered" ? "warning" : "default"}>{r.state}</Chip></td>
                        <td className="px-2 py-1.5 text-foreground/90">{r.svc}</td>
                        <td className="px-2 py-1.5 text-muted-foreground">{r.state === "open" ? r.product : "—"}</td>
                        <td className="px-2 py-1.5 text-muted-foreground/80 truncate max-w-[18ch]" title={r.cpe}>{r.state === "open" ? r.cpe : "—"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </Panel>

            <div className="space-y-3">
              <Panel icon={Activity} title="Port heatmap" meta="0 – 1023">
                <div className="grid grid-cols-[repeat(32,minmax(0,1fr))] gap-[2px]">
                  {Array.from({ length: 1024 }).map((_, p) => {
                    const found = data.rows.find((x) => x.port === p);
                    let c = "bg-background/40";
                    if (found?.state === "open") c = "bg-success";
                    else if (found?.state === "filtered") c = "bg-warning/80";
                    else if (found?.state === "closed") c = "bg-destructive/70";
                    else if (HOT_PORTS.has(p)) c = "bg-primary/15";
                    return <span key={p} title={`port ${p}${found ? ` · ${found.state}` : ""}`} className={"aspect-square rounded-[1px] " + c} />;
                  })}
                </div>
                <div className="mt-2 flex flex-wrap items-center gap-2 text-mono text-[10px] text-muted-foreground">
                  <span className="inline-flex items-center gap-1"><span className="inline-block h-2 w-2 rounded-[1px] bg-success" /> open</span>
                  <span className="inline-flex items-center gap-1"><span className="inline-block h-2 w-2 rounded-[1px] bg-warning/80" /> filtered</span>
                  <span className="inline-flex items-center gap-1"><span className="inline-block h-2 w-2 rounded-[1px] bg-destructive/70" /> closed</span>
                  <span className="inline-flex items-center gap-1"><span className="inline-block h-2 w-2 rounded-[1px] bg-primary/30" /> well-known</span>
                </div>
              </Panel>

              <Panel icon={Cpu} title="OS fingerprint" meta={`${data.confidence}% conf.`}>
                <div className="space-y-1.5">
                  <div className="text-mono text-[12px] text-foreground/90">{data.osGuess}</div>
                  <div className="h-1.5 w-full overflow-hidden rounded bg-background/60">
                    <div className="h-full bg-primary/70" style={{ width: `${data.confidence}%` }} />
                  </div>
                  <div className="text-mono text-[10px] text-muted-foreground">derived from open service banners</div>
                </div>
              </Panel>
            </div>
          </div>

          {/* Report export */}
          <Panel title="Report" meta="markdown" actions={
            <button onClick={() => { const md = genReport(target, mode, timing, data); const blob = new Blob([md], { type: "text/markdown" }); const url = URL.createObjectURL(blob); const a = document.createElement("a"); a.href = url; a.download = `nmap-${target}-${Date.now()}.md`; a.click(); URL.revokeObjectURL(url); }} className="inline-flex items-center gap-1 rounded border border-border px-2 py-0.5 text-mono text-[10px] uppercase text-muted-foreground hover:text-foreground"><Download className="h-3 w-3" /> md</button>
          }>
            <pre className="max-h-40 overflow-auto rounded bg-background/60 p-3 text-mono text-[11px] text-foreground/90">{genReport(target, mode, timing, data)}</pre>
          </Panel>

          <IocInventory groups={[
            { kind: "Open Ports", items: open.map((r) => `${r.port}/${r.svc}`), tone: "warning" },
            { kind: "Services", items: open.map((r) => r.product).filter((p) => p !== "—"), tone: "info" },
            { kind: "OS Guess", items: [data.osGuess] },
          ]} onSendTo={() => {}} />

          {open.length > 0 && (
            <Panel icon={Send} title="Pivot open services" meta="hand off to another tool">
              <div className="grid gap-1.5 sm:grid-cols-2 lg:grid-cols-3">
                {open.slice(0, 9).map((r) => {
                  const isWeb = r.port === 80 || r.port === 443 || r.port === 8080 || r.port === 8443;
                  const url = `${r.port === 443 || r.port === 8443 ? "https" : "http"}://${target}${(r.port === 80 || r.port === 443) ? "" : `:${r.port}`}`;
                  return (
                    <div key={r.port} className="flex items-center justify-between gap-2 rounded border border-border/60 bg-background/40 px-2.5 py-1.5">
                      <div className="min-w-0">
                        <div className="text-mono text-[11.5px] text-foreground/90">:{r.port} · {r.svc}</div>
                        <div className="truncate text-mono text-[10px] text-muted-foreground">{r.product}</div>
                      </div>
                      <div className="flex items-center gap-1">
                        {isWeb && (
                          <button
                            onClick={() => { sendArtifact({ kind: "url", value: url, source: "/nmap" }); window.location.assign("/url"); }}
                            className="inline-flex items-center gap-1 rounded border border-border/60 px-1.5 py-0.5 text-mono text-[10px] text-muted-foreground hover:border-primary/40 hover:text-primary"
                            title="Open in URL Analyzer"
                          >
                            <Globe2 className="h-3 w-3" /> url
                          </button>
                        )}
                        <button
                          onClick={() => { sendArtifact({ kind: "domain", value: target, source: "/nmap" }); window.location.assign("/osint"); }}
                          className="inline-flex items-center gap-1 rounded border border-border/60 px-1.5 py-0.5 text-mono text-[10px] text-muted-foreground hover:border-primary/40 hover:text-primary"
                          title="OSINT pivot"
                        >
                          <Search className="h-3 w-3" /> osint
                        </button>
                      </div>
                    </div>
                  );
                })}
              </div>
            </Panel>
          )}
        </>
      )}

      <SendToRow targets={[
        { label: "Recon Exposure", to: "/recon",     icon: ArrowRight },
        { label: "Detection",      to: "/detection", icon: ShieldAlert },
        { label: "Case Notebook",  to: "/case",      icon: Database },
        { label: "OSINT pivot",    to: "/osint",     icon: Server },
      ]} />
    </PageShell>
  );
}
