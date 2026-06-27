import { createFileRoute } from "@tanstack/react-router";
import { useCallback, useEffect, useMemo, useRef, useState, Fragment } from "react";
import { analyzeSiemText } from "@/api/backend";
import { PageShell } from "@/components/PageShell";
import {
  IntakeCard, StatusBar, ResultBanner, SectionBar, Panel, SendToRow,
  Empty, Chip, EvidenceCard, IocInventory,
} from "@/components/soc/Workspace";
import {
  Database, Search, ArrowRight, Zap, ShieldAlert, Activity, Filter,
  Download, Clock, X, ListFilter, FileText, Crosshair, Bug, ExternalLink, Loader2,
  Hash, Globe, Network, User, AlertTriangle, ChevronDown, ChevronRight,
  Minus, Plus,
} from "lucide-react";

export const Route = createFileRoute("/siem")({ component: SiemPage });

type Event = {
  ts: string; min: number;
  src: string; dst: string; user: string; sig: string;
  sev: "low" | "med" | "high" | "critical";
};

const SEV_TONE: Record<string, "default" | "warning" | "destructive"> = { low: "default", med: "warning", high: "destructive" };

const SAMPLE_TEXTS: Record<string, string> = {
  demo: `{"ts":"2025-01-15T10:15:01Z","src_ip":"45.33.32.156","user":"svc_db","message":"Failed password for svc_db from 45.33.32.156 port 22 ssh2"}
{"ts":"2025-01-15T10:15:09Z","src_ip":"45.33.32.156","user":"svc_db","message":"Failed password for svc_db from 45.33.32.156 port 22 ssh2"}
{"ts":"2025-01-15T10:15:42Z","src_ip":"10.0.0.7","message":"DNS query for exfil.example.com"}`,
  ssh: `Mar 15 10:10:10 webserver sshd[1234]: Failed password for root from 45.33.32.156 port 22 ssh2
Mar 15 10:10:11 webserver sshd[1234]: Failed password for admin from 45.33.32.156 port 22 ssh2
Mar 15 10:10:14 webserver sshd[1235]: Failed password for root from 45.33.32.156 port 22 ssh2
Mar 15 10:10:42 webserver sshd[1236]: Failed password for svc_db from 45.33.32.156 port 22 ssh2
Mar 15 10:11:00 webserver sshd[1237]: Failed password for ubuntu from 185.94.188.22 port 22 ssh2
Mar 15 10:11:03 webserver sshd[1238]: Failed password for admin from 185.94.188.22 port 22 ssh2
Mar 15 10:11:10 webserver sshd[1239]: Failed password for root from 45.33.32.156 port 22 ssh2
Mar 15 10:12:00 webserver sshd[1240]: Failed password for root from 45.33.32.156 port 22 ssh2
Mar 15 10:12:50 webserver sshd[1241]: Accepted password for svc from 185.94.188.22 port 22 ssh2
Mar 15 10:13:30 webserver sshd[1242]: Accepted password for root from 185.94.188.22 port 22 ssh2`,
  beacon: `2025-01-15T11:00:00Z web01 curl[5678]: HTTPS outbound to 51.15.0.100:443 (75B)
2025-01-15T11:05:00Z web01 curl[5679]: HTTPS outbound to 51.15.0.100:443 (82B)
2025-01-15T11:10:02Z web01 curl[5680]: HTTPS outbound to 51.15.0.100:443 (78B)
2025-01-15T11:15:01Z web01 curl[5681]: HTTPS outbound to 51.15.0.100:443 (80B)
2025-01-15T11:16:00Z web01 curl[5682]: DNS query for beacon.example.com
2025-01-15T11:20:00Z web01 curl[5683]: HTTPS outbound to 51.15.0.100:443 (1.2KB)
2025-01-15T11:25:00Z web01 curl[5684]: HTTPS outbound to 51.15.0.100:443 (64KB)`,
  web: `91.121.87.34 - - [15/Jan/2025:12:00:01 +0000] "GET /admin/login HTTP/1.1" 200 1234 "-" "Mozilla/5.0"
91.121.87.34 - - [15/Jan/2025:12:00:15 +0000] "GET /admin/login HTTP/1.1" 200 1234 "-" "Mozilla/5.0"
91.121.87.34 - - [15/Jan/2025:12:00:22 +0000] "GET /admin/login HTTP/1.1" 200 1234 "-" "Mozilla/5.0"
91.121.87.34 - - [15/Jan/2025:12:01:00 +0000] "GET /etc/passwd HTTP/1.1" 404 456 "-" "sqlmap/1.6"
91.121.87.34 - - [15/Jan/2025:12:01:02 +0000] "GET /..%2f..%2fetc/passwd HTTP/1.1" 404 456 "-" "sqlmap/1.6"
91.121.87.34 - - [15/Jan/2025:12:01:44 +0000] "POST /cmd HTTP/1.1" 500 789 "-" "sqlmap/1.6"
91.121.87.34 - - [15/Jan/2025:12:02:10 +0000] "POST /revshell HTTP/1.1" 200 1200 "-" "Mozilla/5.0"
10.0.0.10 - www-data [15/Jan/2025:12:02:30 +0000] "GET /health HTTP/1.1" 200 300 "-" "curl/7.68"`,
};

function backendToEvent(be: Record<string, unknown>, idx: number): Event {
  const raw = String(be.raw ?? be.message ?? "");
  return {
    ts: typeof be.timestamp === "string" && be.timestamp.length >= 19 ? be.timestamp.slice(11, 19) : String(be.time_bucket ?? "—"),
    min: idx,
    src: String(be.src_ip ?? be.source_ip ?? "—"),
    dst: String(be.dest_ip ?? be.destination_ip ?? "—"),
    user: String(be.user ?? "-"),
    sig: raw.slice(0, 120),
    sev: (be.severity === "critical" || be.severity === "high" ? "high" : be.severity === "medium" ? "med" : "low") as Event["sev"],
  };
}

type Range = "15m" | "1h" | "24h" | "all";
const RANGE_MIN: Record<Range, number> = { "15m": 15, "1h": 60, "24h": 24 * 60, all: Number.POSITIVE_INFINITY };

const IPV4 = /\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b/g;

const LOCALSTORE_CHIPS = "beyondarch.siem.chips";
const LOCALSTORE_KEYWORD = "beyondarch.siem.keyword";
const LOCALSTORE_RANGE = "beyondarch.siem.range";

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
    const direct = localStorage.getItem("beyondarch.siem.prefill") || "";
    if (direct) {
      localStorage.removeItem("beyondarch.siem.prefill");
      return direct;
    }
    const raw = localStorage.getItem("beyondarch.pendingArtifact");
    if (!raw) return "";
    const pending = JSON.parse(raw);
    const target = String(pending?.target || pending?.page || pending?.destination || "").toLowerCase();
    const shouldLoad = target.includes("siem") || target.includes("logs") || pending?.type === "siem" || pending?.type === "log" || pending?.type === "event";
    if (!shouldLoad) return "";
    localStorage.removeItem("beyondarch.pendingArtifact");
    const value = pending?.content || pending?.text || pending?.raw_input || pending?.value || pending?.query || pending?.rule || pending?.event;
    if (typeof value === "string") return value;
    return value ? JSON.stringify(value, null, 2) : "";
  } catch { return ""; }
}

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
type FilterChip = { field: string; value: string };

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

function copy(val: string) {
  navigator.clipboard?.writeText(val ?? "");
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

const TACTIC_FROM_ID: Record<string, string> = {
  T1110: "Credential Access", T1078: "Defense Evasion", T1190: "Initial Access",
  T1572: "Command and Control", T1071: "Command and Control", T1048: "Exfiltration",
  T1556: "Credential Access", T1059: "Execution",
};

function deriveFindings(events: Event[]): { findings: Finding[]; mitre: MitreMap[]; tacticCoverage: { tactic: string; techniques: string[]; count: number }[]; iocs: { kind: string; items: string[]; tone?: "warning" | "destructive" | "info" | "primary" }[] } {
  const toArr = (v: Iterable<string>) => Array.from(v);
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

  const sigMitre = new Map<string, string[]>();
  for (const e of events) {
    for (const [keyword, m] of Object.entries(SIG_MITRE)) {
      if (e.sig.includes(keyword)) {
        mitreSet.set(m.id, m);
        const existing = sigMitre.get(e.sig) ?? [];
        if (!existing.includes(m.id)) existing.push(m.id);
        sigMitre.set(e.sig, existing);
        break;
      }
    }
  }

  const tacticMap = new Map<string, { techniques: Set<string>; count: number }>();
  for (const m of mitreSet.values()) {
    const tactic = TACTIC_FROM_ID[m.id] ?? "Other";
    if (!tacticMap.has(tactic)) tacticMap.set(tactic, { techniques: new Set(), count: 0 });
    const entry = tacticMap.get(tactic)!;
    entry.techniques.add(m.id);
    entry.count++;
  }
  const tacticCoverage = Array.from(tacticMap.entries())
    .map(([tactic, data]) => ({ tactic, techniques: Array.from(data.techniques), count: data.count }))
    .sort((a, b) => b.count - a.count);

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
  if (allSigs.size) iocsMap.set("Signatures", { kind: "Signatures", items: allSigs });

  return { findings, mitre: Array.from(mitreSet.values()), tacticCoverage, iocs: Array.from(iocsMap.values()).map((g) => ({ ...g, items: toArr(g.items) })) };
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

function generateSiemNarrative(filtered: Event[], events: Event[], findings: Finding[]): string {
  if (!events.length) return "No data to summarize.";
  const highCount = filtered.filter((e) => e.sev === "high").length;
  const uniqueSrcs = new Set(events.map((e) => e.src).filter(Boolean)).size;
  const uniqueSigs = new Set(events.map((e) => e.sig).filter(Boolean)).size;
  const times = filtered.map((e) => e.ts).filter(Boolean);
  const timeRange = times.length ? `${times[0]} → ${times[times.length - 1]}` : "N/A";
  const lines = [
    "## SIEM Dataset Summary",
    "",
    `**Time Range:** ${timeRange}`,
    `**Total Events:** ${events.length}`,
    `**Visible Events:** ${filtered.length}`,
    `**Unique Sources:** ${uniqueSrcs}`,
    `**Signature Types:** ${uniqueSigs}`,
    `**High-Severity Events:** ${highCount}`,
    `**Detections Generated:** ${findings.length}`,
    "",
  ];
  if (findings.length) {
    lines.push("### Detection Findings", "");
    findings.slice(0, 8).forEach((d, i) => {
      lines.push(`${i + 1}. **${d.sev.toUpperCase()}** ${d.title} — ${d.reason}`);
    });
    lines.push("");
  }
  lines.push("### Analyst Notes", "");
  if (highCount >= 3) {
    lines.push("**Alert:** High concentration of high-severity events warrants immediate review. Correlate sources and timelines for incident declaration.");
  } else if (highCount >= 1) {
    lines.push("**Note:** Isolated high-severity events present. Validate against surrounding context before escalation.");
  } else {
    lines.push("**Note:** No high-severity events in this dataset. Proceed with standard triage workflow.");
  }
  if (uniqueSrcs <= 2 && events.length > 10) {
    lines.push("**Observation:** Low source diversity suggests targeted activity from a small number of hosts or IPs.");
  }
  return lines.join("\n");
}

function sendArtifactClick(page: string, content: string) {
  try {
    localStorage.setItem("beyondarch.pendingArtifact", JSON.stringify({
      type: "siem_events",
      content,
      target: page,
      source: "SIEM Workspace",
      created_at: new Date().toISOString(),
    }));
  } catch {}
}

function SiemPage() {
  const [q, setQ] = useState("");
  const [pasted, setPasted] = useState(() => readInitialPrefill());
  const [range, setRange] = useState<Range>(() => loadPersist<Range>(LOCALSTORE_RANGE, "all"));
  const [chips, setChips] = useState<FilterChip[]>(() => loadPersist<FilterChip[]>(LOCALSTORE_CHIPS, []));
  const [apiEvents, setApiEvents] = useState<Event[]>([]);
  const [loading, setLoading] = useState(false);
  const [notice, setNotice] = useState("");
  const [modal, setModal] = useState<{ title: string; subtitle?: string; data: unknown } | null>(null);
  const [expanded, setExpanded] = useState<number | null>(null);
  const [showNarrative, setShowNarrative] = useState(false);
  const noticeTimer = useRef<ReturnType<typeof setTimeout>>(undefined);

  const flash = (msg: string) => {
    setNotice(msg);
    clearTimeout(noticeTimer.current);
    noticeTimer.current = setTimeout(() => setNotice(""), 4000);
  };

  const ingest = useCallback(async (text: string) => {
    if (!text.trim()) return;
    setLoading(true);
    try {
      const result = await analyzeSiemText(text);
      const events = ((result as any).events || []).map(backendToEvent);
      setApiEvents(events);
      flash(`Ingested ${events.length} events via backend`);
    } catch {
      flash("Backend unavailable — parsed locally");
      setApiEvents(parsePastedEvents(text, 0));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (pasted) { flash("Loaded pending artifact from handoff — auto-ingesting"); ingest(pasted); }
  }, []);

  useEffect(() => { savePersist(LOCALSTORE_RANGE, range); }, [range]);
  useEffect(() => { savePersist(LOCALSTORE_CHIPS, chips); }, [chips]);
  useEffect(() => { savePersist(LOCALSTORE_KEYWORD, q); }, [q]);

  const activeEvents = apiEvents;

  const maxMin = useMemo(() => activeEvents.reduce((m, e) => Math.max(m, e.min), 0), [activeEvents]);

  const filtered = useMemo(() => {
    const t = q.trim().toLowerCase();
    const rangeMin = RANGE_MIN[range];
    return activeEvents.filter((e) => {
      if (Number.isFinite(rangeMin) && maxMin - e.min > rangeMin) return false;
      for (const c of chips) {
        if (String(e[c.field as keyof Event]).toLowerCase() !== c.value.toLowerCase()) return false;
      }
      if (!t) return true;
      return Object.values(e).join(" ").toLowerCase().includes(t);
    });
  }, [activeEvents, q, chips, range, maxMin]);

  const has = filtered.length > 0;

  const { findings, mitre, tacticCoverage, iocs } = useMemo(() => deriveFindings(filtered), [filtered]);

  const histo = useMemo(() => {
    const bins = new Map<number, { min: number; high: number; med: number; low: number }>();
    const sevKey = (s: string) => s === "critical" ? "high" : s as "high" | "med" | "low";
    filtered.forEach((e) => {
      const b = bins.get(e.min) ?? { min: e.min, high: 0, med: 0, low: 0 };
      b[sevKey(e.sev)]++;
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

  const addChip = (field: string, value: string) => {
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

  const narrative = useMemo(() => generateSiemNarrative(filtered, activeEvents, findings), [filtered, activeEvents, findings]);

  const handleSendTo = (page: string) => {
    sendArtifactClick(page, filtered.slice(0, 25).map((r) => JSON.stringify(r)).join("\n"));
    flash(`Sent events to ${page}`);
  };

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
            { key: "ssh",  label: "SSH brute" },
            { key: "beacon", label: "C2 beacon" },
            { key: "web",  label: "Web attack" },
          ]}
          onLoadSample={(k) => {
            const sample = SAMPLE_TEXTS[k];
            if (sample) { setPasted(sample); ingest(sample); }
          }}
          onFile={(txt) => { setPasted(txt); ingest(txt); }}
          fileAccept=".log,.json,.jsonl,.txt"
          run={{ label: loading ? "ingesting..." : "ingest", icon: loading ? Loader2 : Zap, hint: "⌘↵", onClick: () => ingest(pasted), disabled: loading || !pasted.trim() }}
          onClear={() => { setPasted(""); setApiEvents([]); }}
          showCopy={false}
        />
      </div>

      {/* Notice banner */}
      {notice && (
        <div className="flex items-center gap-2 rounded-md border border-primary/30 bg-primary/10 px-3 py-2">
          <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-primary" />
          <span className="flex-1 text-mono text-[11px] text-primary">{notice}</span>
          <button onClick={() => setNotice("")} className="text-primary/60 hover:text-primary" aria-label="dismiss"><X className="h-3 w-3" /></button>
        </div>
      )}

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
        { label: "Status",   value: loading ? "Loading..." : has ? "Ready" : "Awaiting input", tone: loading ? "warning" : has ? "success" : "default" },
        { label: "Sources",  value: new Set(filtered.map((e) => e.src)).size },
        { label: "High sev", value: highCount, tone: highCount ? "warning" : "default" },
        { label: "Window",   value: range },
      ]} />

      <SectionBar id="OT" label="Output · events + analysis" meta={`${findings.length} finding(s) · ${mitre.length} mitre`} />

      {/* AnalystOutputCard-style summary */}
      <ResultBanner
        badge="siem_summary"
        title={`${filtered.length} events · ${findings.length} detection lead(s)`}
        subtitle={activeEvents.length ? `${activeEvents.length} total event(s) · ` + (chips.length ? `filtered: ${chips.map((c) => `${c.field}=${c.value}`).join(" · ")}` : "click cells to pin filters, use range pills to scope") : "Paste logs above and click ingest to begin."}
        reasons={[
          `${activeEvents.length} total event(s), ${filtered.length} visible`,
          fieldTopSrc !== "—" ? `Top source: ${fieldTopSrc}` : "",
          findings.find((f) => f.sev === "destructive") ? `Destructive finding: ${findings.find((f) => f.sev === "destructive")?.title}` : "",
          `${mitre.length} MITRE technique(s) mapped`,
        ].filter(Boolean) as string[]}
        metrics={[
          { label: "Events",   value: filtered.length, tone: "primary" },
          { label: "Top src",  value: fieldTopSrc },
          { label: "Highest",  value: highCount, tone: highCount ? "warning" : "default" },
          { label: "Findings", value: findings.length, tone: findings.some((f) => f.sev === "destructive") ? "destructive" : findings.some((f) => f.sev === "warning") ? "warning" : "default" },
        ]}
      />

      {/* SIEM Summary Narrative toggle */}
      {has && (
        <Panel title="SIEM Summary Narrative" icon={FileText}>
          <button
            onClick={() => setShowNarrative(!showNarrative)}
            className="inline-flex items-center gap-1 rounded border border-primary/40 bg-primary/10 px-2.5 py-1 text-mono text-[10px] uppercase tracking-widest text-primary transition-colors hover:bg-primary/20"
          >
            {showNarrative ? "Hide" : "Generate"} SIEM Summary
          </button>
          {showNarrative && (
            <div className="mt-3 rounded border border-border/60 bg-background/60 p-3">
              <pre className="whitespace-pre-wrap text-mono text-[11px] leading-relaxed text-foreground/90">{narrative}</pre>
              <button
                onClick={() => { copy(narrative); flash("Summary copied"); }}
                className="mt-2 inline-flex items-center gap-1 rounded border border-border bg-card/60 px-2 py-0.5 text-mono text-[10px] uppercase tracking-widest text-muted-foreground hover:text-foreground"
              >Copy Summary</button>
            </div>
          )}
        </Panel>
      )}

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
          <div className="max-h-[600px] overflow-auto rounded border border-border/40">
            <table className="w-full text-mono text-[11px]">
              <thead className="sticky top-0 z-10 bg-background/95 text-[10px] uppercase tracking-widest text-muted-foreground backdrop-blur">
                <tr>
                  <th className="w-5 px-1 py-1.5" />
                  <th className="px-2 py-1.5 text-left">ts</th>
                  <th className="px-2 py-1.5 text-left">src</th>
                  <th className="px-2 py-1.5 text-left">dst</th>
                  <th className="px-2 py-1.5 text-left">user</th>
                  <th className="px-2 py-1.5 text-left">signature</th>
                  <th className="px-2 py-1.5 text-left">sev</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((e, i) => {
                  const isExpanded = expanded === i;
                  return (
                    <Fragment key={i}>
                      <tr
                        className={"border-t border-border/40 transition-colors hover:bg-primary/[0.06] cursor-pointer " + (i % 2 === 1 ? "bg-background/30" : "") + (isExpanded ? " bg-primary/5" : "")}
                        onClick={() => setExpanded(isExpanded ? null : i)}
                      >
                        <td className="px-1 py-1.5 text-muted-foreground/60">
                          {isExpanded ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />}
                        </td>
                        <td className="px-2 py-1.5 text-muted-foreground tabular-nums">{e.ts}</td>
                        <td className="px-2 py-1.5"><button onClick={(ev) => { ev.stopPropagation(); addChip("src", e.src); }} className="text-foreground/90 underline decoration-dotted decoration-border underline-offset-2 hover:text-primary hover:decoration-primary">{e.src}</button></td>
                        <td className="px-2 py-1.5"><button onClick={(ev) => { ev.stopPropagation(); addChip("dst", e.dst); }} className="text-foreground/90 underline decoration-dotted decoration-border underline-offset-2 hover:text-primary hover:decoration-primary">{e.dst}</button></td>
                        <td className="px-2 py-1.5"><button onClick={(ev) => { ev.stopPropagation(); addChip("user", e.user); }} className="text-foreground/90 underline decoration-dotted decoration-border underline-offset-2 hover:text-primary hover:decoration-primary">{e.user}</button></td>
                        <td className="px-2 py-1.5"><button onClick={(ev) => { ev.stopPropagation(); addChip("sig", e.sig); }} className="text-left text-foreground/85 hover:text-primary">{e.sig}</button></td>
                        <td className="px-2 py-1.5"><button onClick={(ev) => { ev.stopPropagation(); addChip("sev", e.sev); }}><Chip tone={SEV_TONE[e.sev]}>{e.sev}</Chip></button></td>
                      </tr>
                      {/* Expanded event detail */}
                      {isExpanded && (
                        <tr className="bg-card/30">
                          <td colSpan={7} className="border-t border-border/30 px-3 py-3">
                            <EventExpanded event={e} onFilter={addChip} onSendTo={handleSendTo} onShowJson={() => setModal({ title: "Event Detail", subtitle: `${e.ts} | ${e.sig}`, data: e })} />
                          </td>
                        </tr>
                      )}
                    </Fragment>
                  );
                })}
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

      {/* MITRE ATT&CK — grouped by tactic */}
      {tacticCoverage.length > 0 && (
        <Panel title="MITRE ATT&CK Tactic Coverage" icon={Crosshair} meta={`${tacticCoverage.length} tactic(s) · ${mitre.length} technique(s)`}>
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {tacticCoverage.map((t) => (
              <div key={t.tactic} className="rounded border border-border/60 bg-card/40 px-3 py-2.5">
                <div className="flex items-center justify-between gap-2">
                  <span className="text-mono text-[11px] font-semibold text-foreground/90">{t.tactic}</span>
                  <Chip tone={t.count >= 3 ? "destructive" : t.count >= 2 ? "warning" : "info"}>{t.count}</Chip>
                </div>
                <div className="mt-1.5 flex flex-wrap gap-1">
                  {t.techniques.map((tid) => (
                    <span key={tid} className="rounded border border-border/50 bg-background/40 px-1.5 py-0.5 text-mono text-[10px] text-muted-foreground">{tid}</span>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </Panel>
      )}

      {/* MITRE flat list (kept for full reference) */}
      {mitre.length > 0 && (
        <Panel title="MITRE ATT&CK Techniques" icon={Crosshair} meta={`${mitre.length} technique${mitre.length === 1 ? "" : "s"}`}>
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

      {/* Modal */}
      {modal && (
        <div className="fixed inset-0 z-50 grid place-items-center bg-black/60 backdrop-blur-sm" onMouseDown={() => setModal(null)}>
          <div className="max-h-[80vh] w-full max-w-2xl overflow-auto rounded-lg border border-border bg-card p-5 shadow-2xl" onMouseDown={(e) => e.stopPropagation()}>
            <div className="flex items-start justify-between gap-3">
              <div>
                <div className="text-mono text-[10px] uppercase tracking-widest text-primary">Details</div>
                <h2 className="text-mono text-[14px] font-semibold text-foreground">{modal.title}</h2>
                {modal.subtitle && <p className="text-mono text-[11px] text-muted-foreground">{modal.subtitle}</p>}
              </div>
              <button onClick={() => setModal(null)} className="text-muted-foreground hover:text-foreground" aria-label="Close"><X className="h-4 w-4" /></button>
            </div>
            <pre className="mt-4 overflow-x-auto rounded border border-border/60 bg-background/60 p-3 text-mono text-[11px] leading-relaxed text-foreground/90">{JSON.stringify(modal.data, null, 2)}</pre>
            <div className="mt-3 flex justify-end gap-2">
              <button onClick={() => { copy(JSON.stringify(modal.data, null, 2)); flash("JSON copied"); }} className="rounded border border-border bg-card/60 px-2 py-1 text-mono text-[10px] uppercase tracking-widest text-muted-foreground hover:text-foreground">Copy JSON</button>
              <button onClick={() => setModal(null)} className="rounded border border-border bg-card/60 px-2 py-1 text-mono text-[10px] uppercase tracking-widest text-muted-foreground hover:text-foreground">Close</button>
            </div>
          </div>
        </div>
      )}
    </PageShell>
  );
}

/* ── Expanded event detail (SplunkEventExpanded equivalent) ── */
function EventExpanded({ event, onFilter, onSendTo, onShowJson }: {
  event: Event;
  onFilter: (field: string, value: string) => void;
  onSendTo: (page: string) => void;
  onShowJson: () => void;
}) {
  const entries = [
    { field: "ts" as const, label: "_time", value: event.ts },
    { field: "src" as const, label: "src_ip", value: event.src },
    { field: "dst" as const, label: "dest_ip", value: event.dst },
    { field: "user" as const, label: "user", value: event.user },
    { field: "sig" as const, label: "signature", value: event.sig },
    { field: "sev" as const, label: "severity", value: event.sev },
  ];

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap gap-1.5">
        <button onClick={onShowJson} className="inline-flex items-center gap-1 rounded border border-border bg-card/60 px-2 py-0.5 text-mono text-[10px] uppercase tracking-widest text-muted-foreground hover:text-foreground">JSON</button>
        <button onClick={() => onSendTo("logs-alerts")} className="inline-flex items-center gap-1 rounded border border-border bg-card/60 px-2 py-0.5 text-mono text-[10px] uppercase tracking-widest text-muted-foreground hover:text-foreground">Logs & Alerts</button>
        <button onClick={() => onSendTo("detection-mitre")} className="inline-flex items-center gap-1 rounded border border-border bg-card/60 px-2 py-0.5 text-mono text-[10px] uppercase tracking-widest text-muted-foreground hover:text-foreground">Detection & MITRE</button>
        <button onClick={() => onSendTo("soc-guide")} className="inline-flex items-center gap-1 rounded border border-border bg-card/60 px-2 py-0.5 text-mono text-[10px] uppercase tracking-widest text-muted-foreground hover:text-foreground">SOC Guide</button>
      </div>
      <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
        {entries.map(({ field, label, value }) => (
          <button
            key={field}
            onClick={() => onFilter(field, value)}
            className="group flex flex-col items-start gap-0.5 rounded border border-border/50 bg-background/40 px-2.5 py-1.5 text-left transition-colors hover:border-primary/50 hover:bg-primary/[0.04]"
          >
            <span className="text-mono text-[9px] uppercase tracking-widest text-muted-foreground">{label}</span>
            <span className="w-full truncate text-mono text-[11px] text-foreground/90 group-hover:text-primary">{value}</span>
          </button>
        ))}
      </div>
    </div>
  );
}
