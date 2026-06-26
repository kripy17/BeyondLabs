import { createFileRoute } from "@tanstack/react-router";
import { useMemo, useState } from "react";
import { PageShell } from "@/components/PageShell";
import {
  IntakeCard, StatusBar, ResultBanner, SectionBar, Panel, SendToRow,
  Empty, Chip, EvidenceCard, IocInventory,
} from "@/components/soc/Workspace";
import {
  Database, Search, ArrowRight, Zap, ShieldAlert, Activity, Filter,
  Download, Clock, X, ListFilter, FileText, Crosshair, Bug, ExternalLink,
  Hash, Globe, Network, User, AlertTriangle,
} from "lucide-react";

export const Route = createFileRoute("/siem")({ component: SiemPage });

type Event = {
  ts: string; min: number;
  src: string; dst: string; user: string; sig: string;
  sev: "low" | "med" | "high";
};

const BASE_EVENTS: Event[] = [
  { ts: "10:10:10", min: 0, src: "8.8.8.8",        dst: "10.0.0.5",   user: "admin", sig: "sshd Failed password",     sev: "med" },
  { ts: "10:10:14", min: 0, src: "8.8.8.8",        dst: "10.0.0.5",   user: "admin", sig: "sshd Failed password",     sev: "med" },
  { ts: "10:10:42", min: 0, src: "8.8.8.8",        dst: "10.0.0.5",   user: "admin", sig: "sshd Failed password",     sev: "med" },
  { ts: "10:11:44", min: 1, src: "1.1.1.1",        dst: "10.0.0.5",   user: "root",  sig: "sshd Accepted password",   sev: "high" },
  { ts: "10:12:00", min: 2, src: "198.51.100.23",  dst: "10.0.0.5",   user: "-",     sig: "ET WEB_SERVER SQLi",       sev: "high" },
  { ts: "10:12:11", min: 2, src: "198.51.100.23",  dst: "10.0.0.5",   user: "-",     sig: "ET WEB_SERVER SQLi",       sev: "high" },
  { ts: "10:13:21", min: 3, src: "10.0.0.5",       dst: "203.0.113.44", user: "root", sig: "Outbound 4444",            sev: "high" },
  { ts: "10:13:48", min: 3, src: "10.0.0.5",       dst: "203.0.113.44", user: "root", sig: "Outbound 4444",            sev: "high" },
  { ts: "10:14:02", min: 4, src: "10.0.0.5",       dst: "203.0.113.44", user: "root", sig: "Beacon-like cadence",      sev: "high" },
  { ts: "10:14:31", min: 4, src: "10.0.0.5",       dst: "203.0.113.44", user: "root", sig: "Beacon-like cadence",      sev: "high" },
];

const SAMPLE_STREAMS: Record<string, { label: string; events: Event[] }> = {
  ssh_brute: {
    label: "SSH brute force",
    events: [
      { ts: "09:00:01", min: 0,  src: "45.33.32.156", dst: "10.0.0.22",  user: "root",    sig: "sshd Failed password", sev: "med" },
      { ts: "09:00:05", min: 0,  src: "45.33.32.156", dst: "10.0.0.22",  user: "admin",   sig: "sshd Failed password", sev: "med" },
      { ts: "09:00:12", min: 0,  src: "45.33.32.156", dst: "10.0.0.22",  user: "svc_db",  sig: "sshd Failed password", sev: "med" },
      { ts: "09:00:22", min: 0,  src: "45.33.32.156", dst: "10.0.0.22",  user: "ubuntu",  sig: "sshd Failed password", sev: "med" },
      { ts: "09:01:00", min: 1,  src: "185.94.188.22", dst: "10.0.0.22", user: "root",    sig: "sshd Failed password", sev: "med" },
      { ts: "09:01:03", min: 1,  src: "185.94.188.22", dst: "10.0.0.22", user: "admin",   sig: "sshd Failed password", sev: "med" },
      { ts: "09:01:44", min: 1,  src: "45.33.32.156", dst: "10.0.0.22",  user: "root",    sig: "sshd Failed password", sev: "med" },
      { ts: "09:02:10", min: 2,  src: "45.33.32.156", dst: "10.0.0.22",  user: "root",    sig: "sshd Failed password", sev: "med" },
      { ts: "09:02:50", min: 2,  src: "185.94.188.22", dst: "10.0.0.22", user: "svc",     sig: "sshd Accepted password", sev: "high" },
      { ts: "09:03:30", min: 3,  src: "10.0.0.22",     dst: "203.0.113.88", user: "svc",  sig: "Outbound 4444", sev: "high" },
    ],
  },
  beacon: {
    label: "C2 beacon",
    events: [
      { ts: "11:00:00", min: 0, src: "10.0.0.15", dst: "51.15.0.100", user: "svc_web", sig: "HTTPS outbound (75B)", sev: "low" },
      { ts: "11:05:00", min: 5, src: "10.0.0.15", dst: "51.15.0.100", user: "svc_web", sig: "HTTPS outbound (82B)", sev: "low" },
      { ts: "11:10:02", min: 10, src: "10.0.0.15", dst: "51.15.0.100", user: "svc_web", sig: "HTTPS outbound (78B)", sev: "low" },
      { ts: "11:15:01", min: 15, src: "10.0.0.15", dst: "51.15.0.100", user: "svc_web", sig: "HTTPS outbound (80B)", sev: "low" },
      { ts: "11:16:00", min: 16, src: "10.0.0.15", dst: "51.15.0.100", user: "svc_web", sig: "DNS query beacon.example.com", sev: "med" },
      { ts: "11:20:00", min: 20, src: "10.0.0.15", dst: "51.15.0.100", user: "svc_web", sig: "HTTPS outbound (1.2KB)", sev: "med" },
      { ts: "11:25:00", min: 25, src: "10.0.0.15", dst: "51.15.0.100", user: "svc_web", sig: "HTTPS outbound (64KB)", sev: "high" },
      { ts: "11:25:30", min: 25, src: "10.0.0.15", dst: "51.15.0.100", user: "svc_web", sig: "Data exfil pattern", sev: "high" },
    ],
  },
  web_attack: {
    label: "Web app attack",
    events: [
      { ts: "12:00:01", min: 0,  src: "91.121.87.34", dst: "10.0.0.10", user: "-",  sig: "ET WEB_SERVER /admin/login brute", sev: "med" },
      { ts: "12:00:03", min: 0,  src: "91.121.87.34", dst: "10.0.0.10", user: "-",  sig: "ET WEB_SERVER /admin/login brute", sev: "med" },
      { ts: "12:00:15", min: 0,  src: "91.121.87.34", dst: "10.0.0.10", user: "-",  sig: "ET WEB_SERVER /admin/login brute", sev: "med" },
      { ts: "12:01:00", min: 1,  src: "91.121.87.34", dst: "10.0.0.10", user: "-",  sig: "ET WEB_SERVER SQLi attempt", sev: "high" },
      { ts: "12:01:02", min: 1,  src: "91.121.87.34", dst: "10.0.0.10", user: "-",  sig: "ET WEB_SERVER LFI attempt", sev: "high" },
      { ts: "12:01:44", min: 1,  src: "91.121.87.34", dst: "10.0.0.10", user: "-",  sig: "ET WEB_SERVER RCE probe", sev: "high" },
      { ts: "12:02:10", min: 2,  src: "91.121.87.34", dst: "10.0.0.10", user: "-",  sig: "Outbound reverse shell", sev: "critical" },
      { ts: "12:02:30", min: 2,  src: "10.0.0.10",    dst: "5.5.5.100",  user: "www-data", sig: "Beacon-like cadence", sev: "high" },
    ],
  },
};

const SEV_TONE: Record<string, "default" | "warning" | "destructive"> = { low: "default", med: "warning", high: "destructive" };
const SEV_ORDER: Record<string, number> = { low: 1, med: 2, high: 3, critical: 4 };

const PASTE_SAMPLE = `{"ts":"10:15:01","src":"45.33.32.156","dst":"10.0.0.7","user":"svc_db","sig":"Failed MFA","sev":"high"}
{"ts":"10:15:09","src":"45.33.32.156","dst":"10.0.0.7","user":"svc_db","sig":"Failed MFA","sev":"high"}
{"ts":"10:15:42","src":"10.0.0.7","dst":"8.8.8.8","user":"svc_db","sig":"DNS exfil pattern","sev":"med"}`;

type Range = "15m" | "1h" | "24h" | "all";
const RANGE_MIN: Record<Range, number> = { "15m": 15, "1h": 60, "24h": 24 * 60, all: Number.POSITIVE_INFINITY };

const IPV4 = /\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b/g;

function parsePastedEvents(raw: string, startMin: number): Event[] {
  const out: Event[] = [];
  let m = startMin;
  for (const lineRaw of raw.split(/\r?\n/)) {
    const line = lineRaw.trim();
    if (!line) continue;
    if (line.startsWith("{")) {
      try {
        const j = JSON.parse(line);
        const tsRaw = String(j.ts ?? j.timestamp ?? "—");
        out.push({
          ts: tsRaw.length >= 19 ? tsRaw.slice(11, 19) : tsRaw,
          min: m++,
          src: String(j.src ?? j.src_ip ?? j.source ?? "—"),
          dst: String(j.dst ?? j.dest_ip ?? j.destination ?? "—"),
          user: String(j.user ?? j.account ?? "-"),
          sig: String(j.sig ?? j.signature ?? j.alert?.signature ?? j.message ?? "—"),
          sev: (j.sev ?? (j.severity === 1 ? "low" : j.severity === 2 ? "high" : "med")) as Event["sev"],
        });
        continue;
      } catch {}
    }
    const ips = line.match(IPV4) ?? [];
    const sigMatch = line.match(/(?:signature|alert|message)["\s:=]+([^"|,]+)/i);
    const userMatch = line.match(/(?:user|account|Account Name:)\s*([A-Za-z0-9_.-]+)/i);
    const sev: Event["sev"] = /fail|error|alert|sqli|exploit/i.test(line) ? "high" : /warn/i.test(line) ? "med" : "low";
    out.push({
      ts: line.match(/\d{2}:\d{2}:\d{2}/)?.[0] ?? "—",
      min: m++,
      src: ips[0] ?? "—",
      dst: ips[1] ?? "—",
      user: userMatch?.[1] ?? "-",
      sig: (sigMatch?.[1] ?? line).trim().slice(0, 80),
      sev,
    });
  }
  return out;
}

const FIELDS = ["src", "dst", "user", "sig", "sev"] as const;
type Field = (typeof FIELDS)[number];
type FilterChip = { field: Field; value: string };

function toCsv(rows: Event[]): string {
  const header = ["ts", "src", "dst", "user", "sig", "sev"].join(",");
  const esc = (s: unknown) => {
    const v = String(s ?? "");
    return /[",\n]/.test(v) ? `"${v.replace(/"/g, '""')}"` : v;
  };
  return [header, ...rows.map((r) => [r.ts, r.src, r.dst, r.user, r.sig, r.sev].map(esc).join(","))].join("\n");
}

function download(name: string, body: string, mime = "text/csv") {
  const blob = new Blob([body], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = name; document.body.appendChild(a); a.click(); a.remove();
  URL.revokeObjectURL(url);
}

/* ── Analysis engine ── */

interface Finding {
  sev: "destructive" | "warning" | "info";
  title: string; reason: string; action: string;
}

interface MitreMap {
  id: string; name: string;
}

const SIG_MITRE: Record<string, MitreMap> = {
  "sshd Failed password": { id: "T1110", name: "Brute Force" },
  "sshd Accepted password": { id: "T1078", name: "Valid Accounts" },
  "SQLi": { id: "T1190", name: "Exploit Public-Facing Application" },
  "LFI attempt": { id: "T1190", name: "Exploit Public-Facing Application" },
  "RCE probe": { id: "T1190", name: "Exploit Public-Facing Application" },
  "Outbound": { id: "T1572", name: "Protocol Tunneling" },
  "Beacon": { id: "T1071", name: "Application Layer Protocol" },
  "Data exfil": { id: "T1048", name: "Exfiltration Over Alternative Protocol" },
  "Failed MFA": { id: "T1556", name: "Modify Authentication Process" },
  "DNS exfil": { id: "T1048", name: "Exfiltration Over Alternative Protocol" },
  "reverse shell": { id: "T1059", name: "Command and Scripting Interpreter" },
  "HTTPS outbound": { id: "T1071.001", name: "Web Protocols" },
  "DNS query": { id: "T1071.004", name: "DNS" },
};

function deriveFindings(events: Event[]): { findings: Finding[]; mitre: MitreMap[]; iocs: { kind: string; items: string[]; tone?: "warning" | "destructive" | "info" | "primary" }[] } {
  const findings: Finding[] = [];
  const mitreSet = new Map<string, MitreMap>();
  const iocsMap = new Map<string, { kind: string; items: Set<string>; tone?: "warning" | "destructive" | "info" | "primary" }>();

  const failedSsh = events.filter((e) => e.sig.includes("Failed password"));
  const srcCounts = new Map<string, number>();
  for (const e of failedSsh) srcCounts.set(e.src, (srcCounts.get(e.src) || 0) + 1);
  for (const [src, count] of srcCounts) {
    if (count >= 3) findings.push({ sev: "warning", title: `SSH brute force from ${src}`, reason: `${count} failed attempts — credential stuffing or password spray.`, action: "Block source IP at perimeter; review auth logs for successful logins from the same source." });
    if (count >= 5) findings.push({ sev: "destructive", title: `Sustained SSH brute force from ${src}`, reason: `${count} failed attempts exceed threshold — active brute force in progress.`, action: "Immediate block; correlate with IDS/IPS hits from same source." });
  }

  const accepted = events.filter((e) => e.sig.includes("Accepted password"));
  for (const e of accepted) {
    findings.push({ sev: "destructive", title: `External auth success — ${e.src} logged in as ${e.user}`, reason: "External IP authenticated after failed attempts — credential compromise or successful brute force.", action: "Force password reset for affected account; review lateral movement." });
  }

  const sqli = events.filter((e) => e.sig.includes("SQLi") || e.sig.includes("LFI") || e.sig.includes("RCE"));
  if (sqli.length >= 2) findings.push({ sev: "destructive", title: `Web application attack — ${sqli.length} SQLi/LFI/RCE hits`, reason: "Multiple web exploit probes detected from external source — active scanning or targeted exploitation.", action: "Review WAF logs; patch vulnerable endpoints; block source IP." });

  const outbound = events.filter((e) => e.sig.includes("Outbound") || e.sig.includes("reverse shell"));
  if (outbound.length >= 2) findings.push({ sev: "destructive", title: "Reverse shell / tunnel detected", reason: "Internal host initiated outbound connection on non-standard port — possible backdoor or C2 tunnel.", action: "Isolate host; capture memory/network artifacts; incident response escalation." });

  const beacons = events.filter((e) => e.sig.includes("Beacon") || e.sig.includes("beacon"));
  if (beacons.length) findings.push({ sev: "warning", title: "C2 beacon cadence detected", reason: "Periodic outbound connections at regular intervals from internal host — C2 beacon pattern.", action: "Review DNS/Proxy logs for associated domains; check for data staging on host." });

  const exfil = events.filter((e) => e.sig.includes("exfil") || e.sig.includes("Exfil"));
  if (exfil.length) findings.push({ sev: "destructive", title: "Data exfiltration pattern", reason: "DNS or HTTPS traffic consistent with exfiltration behaviour from compromised host.", action: "Capture full packet capture; identify data types accessed by compromised account." });

  const mfaFails = events.filter((e) => e.sig.includes("Failed MFA"));
  if (mfaFails.length >= 2) findings.push({ sev: "warning", title: `MFA failure burst — ${mfaFails.length} events`, reason: "Multiple MFA failures indicate credential compromise or MFA fatigue attack.", action: "Force re-authentication; check device trust; alert user." });

  const brute = events.filter((e) => e.sig.includes("brute") || e.sig.includes("Brute"));
  if (brute.length >= 3) findings.push({ sev: "warning", title: "Web login brute force", reason: `${brute.length} login attempts against /admin endpoint — credential stuffing.`, action: "Rate-limit /admin; enforce CAPTCHA after 3 failures; block source IP." });

  if (!findings.length) findings.push({ sev: "info", title: "No notable findings", reason: "Event stream does not match any correlation rules.", action: "Widen time range or adjust filter chips." });

  for (const e of events) {
    for (const [keyword, m] of Object.entries(SIG_MITRE)) {
      if (e.sig.includes(keyword)) {
        mitreSet.set(m.id, m);
        break;
      }
    }
  }

  const allIps = new Set<string>();
  const allUsers = new Set<string>();
  const allSigs = new Set<string>();
  for (const e of events) {
    if (e.src && e.src !== "—") allIps.add(e.src);
    if (e.dst && e.dst !== "—") allIps.add(e.dst);
    if (e.user && e.user !== "-") allUsers.add(e.user);
    if (e.sig && e.sig !== "—") allSigs.add(e.sig);
  }
  if (allIps.size) iocsMap.set("IPs", { kind: "IPs", items: allIps, tone: "warning" });
  if (allUsers.size) iocsMap.set("Users", { kind: "Users", items: allUsers, tone: "info" });
  if (allSigs.size) iocsMap.set("Signatures", { kind: "Signatures", items: allSigs, tone: "default" });

  return { findings, mitre: Array.from(mitreSet.values()), iocs: Array.from(iocsMap.values()) };
}

function genMarkdownReport(filtered: Event[], findings: Finding[], mitre: MitreMap[]): string {
  const lines = [
    `# SIEM Event Report`,
    `**Events:** ${filtered.length}`,
    `**Generated:** ${new Date().toISOString()}`,
    "",
    "## Findings",
    ...findings.map((f) => `- [${f.sev.toUpperCase()}] ${f.title} — ${f.reason}`),
  ];
  if (mitre.length) lines.push("", "## MITRE ATT&CK", ...mitre.map((m) => `- ${m.id}: ${m.name}`));
  const highSev = filtered.filter((e) => e.sev === "high");
  if (highSev.length) {
    lines.push("", "## High-Severity Events", ...highSev.map((e) => `- ${e.ts} | ${e.src}→${e.dst} | ${e.user} | ${e.sig}`));
  }
  lines.push("", "## All Events", ...filtered.map((e) => `- ${e.ts} | ${e.src}→${e.dst} | ${e.user} | ${e.sig} | ${e.sev}`));
  return lines.join("\n");
}

function SiemPage() {
  const [q, setQ] = useState("");
  const [pasted, setPasted] = useState("");
  const [range, setRange] = useState<Range>("all");
  const [chips, setChips] = useState<FilterChip[]>([]);
  const [stream, setStream] = useState<string>("");

  const activeEvents = useMemo<Event[]>(() => {
    if (stream && SAMPLE_STREAMS[stream]) return SAMPLE_STREAMS[stream].events;
    const extra = pasted.trim() ? parsePastedEvents(pasted, BASE_EVENTS.length) : [];
    return [...BASE_EVENTS, ...extra];
  }, [stream, pasted]);

  const maxMin = useMemo(() => activeEvents.reduce((m, e) => Math.max(m, e.min), 0), [activeEvents]);

  const filtered = useMemo(() => {
    const t = q.trim().toLowerCase();
    const rangeMin = RANGE_MIN[range];
    return activeEvents.filter((e) => {
      if (Number.isFinite(rangeMin) && maxMin - e.min > rangeMin) return false;
      for (const c of chips) {
        if (String(e[c.field]).toLowerCase() !== c.value.toLowerCase()) return false;
      }
      if (!t) return true;
      return Object.values(e).join(" ").toLowerCase().includes(t);
    });
  }, [activeEvents, q, chips, range, maxMin]);

  const has = filtered.length > 0;

  const { findings, mitre, iocs } = useMemo(() => deriveFindings(filtered), [filtered]);

  const histo = useMemo(() => {
    const bins = new Map<number, { min: number; high: number; med: number; low: number }>();
    filtered.forEach((e) => {
      const b = bins.get(e.min) ?? { min: e.min, high: 0, med: 0, low: 0 };
      b[e.sev]++;
      bins.set(e.min, b);
    });
    return Array.from(bins.values()).sort((a, b) => a.min - b.min);
  }, [filtered]);
  const maxBin = Math.max(1, ...histo.map((b) => b.high + b.med + b.low));

  const fieldSummary = useMemo(() => {
    return FIELDS.map((f) => {
      const counts = new Map<string, number>();
      filtered.forEach((e) => { const v = String(e[f]); counts.set(v, (counts.get(v) ?? 0) + 1); });
      const top = Array.from(counts.entries()).sort((a, b) => b[1] - a[1]).slice(0, 5);
      return { field: f, unique: counts.size, top };
    });
  }, [filtered]);

  const addChip = (field: Field, value: string) => {
    setChips((prev) => (prev.some((c) => c.field === field && c.value === value) ? prev : [...prev, { field, value }]));
  };
  const removeChip = (i: number) => setChips((prev) => prev.filter((_, j) => j !== i));
  const exportCsv = () => download(`siem-events-${Date.now()}.csv`, toCsv(filtered));
  const exportReport = () => {
    const md = genMarkdownReport(filtered, findings, mitre);
    const blob = new Blob([md], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = `siem-report-${Date.now()}.md`;
    a.click(); URL.revokeObjectURL(url);
  };

  const highCount = filtered.filter((e) => e.sev === "high").length;
  const fieldTopSrc = fieldSummary.find((f) => f.field === "src")?.top[0]?.[0] ?? "—";

  return (
    <PageShell
      eyebrow="SIEM / WORKSPACE"
      title="SIEM Workspace"
      description="Query, filter, and analyse event streams — paste logs, load samples, and pivot on findings."
      crumbs={[{ label: "SIEM" }, { label: "Workspace" }]}
    >
      <SectionBar id="IN" label="Intake · query + paste" meta={`${filtered.length} / ${activeEvents.length} events`} />

      <div className="grid gap-3 lg:grid-cols-2">
        <IntakeCard
          icon={Search}
          title="Event Search"
          value={q}
          onChange={setQ}
          rows={2}
          placeholder='src:8.8.8.8 OR user:root OR sig:"SQLi"'
          samples={[
            { key: "sqli",  label: "SQLi",     hint: 'sig:"SQLi"' },
            { key: "root",  label: "Root login", hint: "user:root" },
            { key: "ext",   label: "Egress IP", hint: "src:8.8.8.8" },
          ]}
          onLoadSample={(k) => setQ(k === "sqli" ? 'sig:"SQLi"' : k === "root" ? "user:root" : "src:8.8.8.8")}
          run={{ label: "run", icon: Zap, hint: "⌘↵", onClick: () => {}, disabled: !q.trim() }}
          onClear={() => { setQ(""); setChips([]); }}
          showCopy={false}
        />
        <IntakeCard
          icon={FileText}
          title="Paste raw events"
          value={pasted}
          onChange={setPasted}
          rows={6}
          placeholder="JSONL alerts, syslog lines, or CSV — mapped to src/dst/user/sig/sev"
          samples={[
            { key: "demo", label: "JSONL demo" },
            { key: "ssh",  label: "SSH brute", hint: stream === "ssh_brute" ? "loaded" : "" },
            { key: "beacon", label: "C2 beacon", hint: stream === "beacon" ? "loaded" : "" },
            { key: "web",  label: "Web attack", hint: stream === "web_attack" ? "loaded" : "" },
          ]}
          onLoadSample={(k) => {
            if (k === "ssh" || k === "beacon" || k === "web") { setStream(k); setPasted(""); }
            else setPasted(PASTE_SAMPLE);
          }}
          onFile={(txt) => setPasted(txt)}
          fileAccept=".log,.json,.jsonl,.txt"
          run={{ label: "ingest", icon: Zap, hint: "⌘↵", onClick: () => {}, disabled: !pasted.trim() }}
          onClear={() => { setPasted(""); setStream(""); }}
          showCopy={false}
        />
      </div>

      <Panel title="Filter strip" icon={ListFilter} meta={`${chips.length} chip(s)`} actions={
        <div className="flex items-center gap-1.5">
          <button onClick={exportReport} disabled={!has} className="inline-flex items-center gap-1 rounded border border-border px-2 py-0.5 text-mono text-[10px] uppercase tracking-widest text-muted-foreground hover:text-foreground disabled:opacity-40">
            <Hash className="h-3 w-3" /> MD
          </button>
          <button onClick={exportCsv} disabled={!has} className="inline-flex items-center gap-1 rounded border border-border px-2 py-0.5 text-mono text-[10px] uppercase tracking-widest text-muted-foreground hover:text-foreground disabled:opacity-40">
            <Download className="h-3 w-3" /> CSV
          </button>
        </div>
      }>
        <div className="flex flex-wrap items-center gap-2">
          <span className="inline-flex items-center gap-1 text-mono text-[10px] uppercase tracking-widest text-muted-foreground"><Clock className="h-3 w-3" /> range</span>
          {(["15m", "1h", "24h", "all"] as Range[]).map((r) => (
            <button
              key={r}
              onClick={() => setRange(r)}
              className={"rounded border px-2 py-0.5 text-mono text-[10px] uppercase tracking-widest " + (range === r ? "border-primary bg-primary/10 text-primary" : "border-border text-muted-foreground hover:text-foreground")}
            >{r}</button>
          ))}
          <span className="mx-2 h-3 w-px bg-border" />
          <span className="text-mono text-[10px] uppercase tracking-widest text-muted-foreground">filters</span>
          {chips.length === 0 ? (
            <span className="text-mono text-[10px] text-muted-foreground/70">click any value to pin a filter</span>
          ) : (
            chips.map((c, i) => (
              <span key={i} className="inline-flex items-center gap-1 rounded border border-primary/40 bg-primary/10 px-2 py-0.5 text-mono text-[10px] text-primary">
                <span className="text-primary/70">{c.field}=</span>{c.value}
                <button onClick={() => removeChip(i)} className="ml-0.5 hover:text-foreground" aria-label="remove filter"><X className="h-3 w-3" /></button>
              </span>
            ))
          )}
          {chips.length > 0 && <button onClick={() => setChips([])} className="ml-1 text-mono text-[10px] uppercase tracking-widest text-muted-foreground hover:text-destructive">clear all</button>}
        </div>
      </Panel>

      <StatusBar stats={[
        { label: "Status",   value: has ? "Streaming" : "No match", tone: has ? "success" : "warning" },
        { label: "Sources",  value: new Set(filtered.map((e) => e.src)).size },
        { label: "High sev", value: highCount, tone: highCount ? "warning" : "default" },
        { label: "Window",   value: range },
      ]} />

      <SectionBar id="OT" label="Output · events + analysis" meta={`${findings.length} finding(s) · ${mitre.length} mitre`} />

      <ResultBanner
        badge="siem_summary"
        title={`${filtered.length} events`}
        subtitle={stream ? SAMPLE_STREAMS[stream]?.label : chips.length ? `Filtered by ${chips.map((c) => `${c.field}=${c.value}`).join(" · ")}` : "Click cells to pin filters; use range pills to scope."}
        metrics={[
          { label: "Events",   value: filtered.length, tone: "primary" },
          { label: "Top src",  value: fieldTopSrc },
          { label: "Highest",  value: highCount, tone: highCount ? "warning" : "default" },
          { label: "Findings", value: findings.length, tone: findings.some((f) => f.sev === "destructive") ? "destructive" : findings.some((f) => f.sev === "warning") ? "warning" : "default" },
        ]}
      />

      {/* Timeline */}
      <Panel title="Event timeline" icon={Activity} meta={`${histo.length} bucket(s)`}>
        {histo.length === 0 ? (
          <Empty title="No events in range" hint="Widen the time range or remove a filter chip." />
        ) : (
          <div className="flex items-end gap-1.5">
            {histo.map((b) => {
              const total = b.high + b.med + b.low;
              return (
                <div key={b.min} className="flex flex-1 flex-col items-center gap-1">
                  <div className="flex h-28 w-full items-end overflow-hidden rounded border border-border/40 bg-background/40">
                    <div className="flex w-full flex-col-reverse" style={{ height: `${(total / maxBin) * 100}%` }}>
                      {b.high > 0 && <div className="bg-destructive/80" style={{ flex: b.high }} title={`high: ${b.high}`} />}
                      {b.med  > 0 && <div className="bg-warning/80"     style={{ flex: b.med  }} title={`med:  ${b.med}`} />}
                      {b.low  > 0 && <div className="bg-success/70"     style={{ flex: b.low  }} title={`low:  ${b.low}`} />}
                    </div>
                  </div>
                  <div className="text-mono text-[10px] text-muted-foreground">t+{b.min}m</div>
                  <div className="text-mono text-[10px] text-foreground/80">{total}</div>
                </div>
              );
            })}
          </div>
        )}
      </Panel>

      <div className="grid gap-3 lg:grid-cols-[2fr_1fr]">
        <Panel title="Events" icon={Activity} actions={<Chip tone="primary"><Filter className="h-3 w-3" /> {q || `${filtered.length} rows`}</Chip>}>
          <div className="max-h-[480px] overflow-auto rounded border border-border/40">
            <table className="w-full text-mono text-[11px]">
              <thead className="sticky top-0 z-10 bg-background/95 text-[10px] uppercase tracking-widest text-muted-foreground backdrop-blur">
                <tr>
                  <th className="px-2 py-1.5 text-left">ts</th>
                  <th className="px-2 py-1.5 text-left">src</th>
                  <th className="px-2 py-1.5 text-left">dst</th>
                  <th className="px-2 py-1.5 text-left">user</th>
                  <th className="px-2 py-1.5 text-left">signature</th>
                  <th className="px-2 py-1.5 text-left">sev</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((e, i) => (
                  <tr key={i} className={"border-t border-border/40 transition-colors hover:bg-primary/[0.06] " + (i % 2 === 1 ? "bg-background/30" : "")}>
                    <td className="px-2 py-1.5 text-muted-foreground tabular-nums">{e.ts}</td>
                    <td className="px-2 py-1.5"><button onClick={() => addChip("src", e.src)} className="text-foreground/90 underline decoration-dotted decoration-border underline-offset-2 hover:text-primary hover:decoration-primary">{e.src}</button></td>
                    <td className="px-2 py-1.5"><button onClick={() => addChip("dst", e.dst)} className="text-foreground/90 underline decoration-dotted decoration-border underline-offset-2 hover:text-primary hover:decoration-primary">{e.dst}</button></td>
                    <td className="px-2 py-1.5"><button onClick={() => addChip("user", e.user)} className="text-foreground/90 underline decoration-dotted decoration-border underline-offset-2 hover:text-primary hover:decoration-primary">{e.user}</button></td>
                    <td className="px-2 py-1.5"><button onClick={() => addChip("sig", e.sig)} className="text-left text-foreground/85 hover:text-primary">{e.sig}</button></td>
                    <td className="px-2 py-1.5"><button onClick={() => addChip("sev", e.sev)}><Chip tone={SEV_TONE[e.sev]}>{e.sev}</Chip></button></td>
                  </tr>
                ))}
              </tbody>
            </table>
            {filtered.length === 0 && (
              <div className="px-3 py-6 text-center"><Empty title="No events match this query" hint="Loosen the time range, remove a chip, or clear the search." /></div>
            )}
          </div>
        </Panel>

        <Panel title="Field summary" icon={ListFilter} meta="top values per field">
          <div className="space-y-3">
            {fieldSummary.map((f) => (
              <div key={f.field}>
                <div className="flex items-center justify-between text-mono text-[10px] uppercase tracking-widest text-muted-foreground">
                  <span>{f.field}</span>
                  <span>{f.unique} unique</span>
                </div>
                <ul className="mt-1 space-y-1">
                  {f.top.length === 0 ? (
                    <li className="text-mono text-[11px] text-muted-foreground/60">—</li>
                  ) : f.top.map(([v, n]) => (
                    <li key={v} className="space-y-0.5">
                      <div className="flex items-center justify-between gap-2">
                        <button onClick={() => addChip(f.field, v)} className="truncate text-mono text-[11px] text-foreground/90 hover:text-primary" title={v}>{v}</button>
                        <span className="text-mono text-[10px] text-muted-foreground tabular-nums">{n}</span>
                      </div>
                      <div className="h-1 overflow-hidden rounded-sm bg-border/40">
                        <div className="h-full bg-primary/70" style={{ width: `${(n / f.top[0][1]) * 100}%` }} />
                      </div>
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>
        </Panel>
      </div>

      {/* Findings */}
      {findings.length > 0 && (
        <div className="grid gap-3 md:grid-cols-2">
          {findings.map((f, i) => (
            <EvidenceCard key={i} severity={f.sev} title={f.title} reason={f.reason} action={f.action} limitation="Correlation based on available event fields — confirm with full packet capture." />
          ))}
        </div>
      )}

      {/* MITRE ATT&CK */}
      {mitre.length > 0 && (
        <Panel title="MITRE ATT&CK Mapping" icon={Crosshair} meta={`${mitre.length} technique${mitre.length === 1 ? "" : "s"}`}>
          <div className="flex flex-wrap gap-2">
            {mitre.map((m) => (
              <span key={m.id} className="inline-flex items-center gap-1.5 rounded border border-border/60 bg-card/40 px-2 py-1 text-mono text-[11px] text-foreground/85">
                <Bug className="h-3 w-3 text-destructive" />
                <span className="font-semibold">{m.id}</span>
                <span className="text-muted-foreground">:</span>
                <span>{m.name}</span>
              </span>
            ))}
          </div>
        </Panel>
      )}

      {/* IOC Inventory */}
      {iocs.length > 0 && (
        <IocInventory
          groups={iocs.map((g) => ({
            kind: g.kind,
            items: Array.from(g.items),
            tone: g.tone,
          }))}
          onSendTo={() => {}}
        />
      )}

      <SendToRow targets={[
        { label: "Logs & Alerts",  to: "/logs",      icon: Database },
        { label: "Detection",      to: "/detection", icon: ShieldAlert },
        { label: "MITRE Coverage", to: "/mitre",     icon: ArrowRight },
        { label: "Case Notebook",  to: "/case",      icon: ArrowRight },
      ]} />
    </PageShell>
  );
}
