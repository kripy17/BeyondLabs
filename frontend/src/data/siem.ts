import { type Severity } from "@/lib/severity";

export type SiemEvent = {
  ts: string; min: number;
  src: string; dst: string; user: string; sig: string;
  sev: Severity;
};

export const SEV_TONE: Record<string, "default" | "warning" | "destructive"> = { low: "default", medium: "warning", high: "destructive" };

export const SAMPLE_TEXTS: Record<string, string> = {
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

export function backendToEvent(be: Record<string, unknown>, idx: number): SiemEvent {
  const raw = String(be.raw ?? be.message ?? "");
  const ts = typeof be.timestamp === "string" && be.timestamp.length >= 19 ? be.timestamp : "";
  return {
    ts: ts ? ts.slice(11, 19) : String(be.time_bucket ?? "—"),
    min: ts ? parseInt(ts.slice(11, 13), 10) * 60 + parseInt(ts.slice(14, 16), 10) : idx,
    src: String(be.src_ip ?? be.source_ip ?? "—"),
    dst: String(be.dest_ip ?? be.destination_ip ?? "—"),
    user: String(be.user ?? "-"),
    sig: raw.slice(0, 120),
    sev: (be.severity === "critical" || be.severity === "high" ? "high" : be.severity === "medium" ? "medium" : "low") as SiemEvent["sev"],
  };
}

export type Range = "15m" | "1h" | "24h" | "all";
export const RANGE_MIN: Record<Range, number> = { "15m": 15, "1h": 60, "24h": 24 * 60, all: Number.POSITIVE_INFINITY };

export const IPV4 = /\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b/g;

export const LOCALSTORE_CHIPS = "beyondlabs.siem.chips";
export const LOCALSTORE_KEYWORD = "beyondlabs.siem.keyword";
export const LOCALSTORE_RANGE = "beyondlabs.siem.range";

export function loadPersist<T>(key: string, fallback: T): T {
  try {
    const raw = localStorage.getItem(key);
    return raw ? (JSON.parse(raw) as T) : fallback;
  } catch { return fallback; }
}

export function savePersist(key: string, value: unknown) {
  try { localStorage.setItem(key, JSON.stringify(value)); } catch {}
}

export function readInitialPrefill(): string {
  try {
    const direct = localStorage.getItem("beyondlabs.siem.prefill") || "";
    if (direct) {
      localStorage.removeItem("beyondlabs.siem.prefill");
      return direct;
    }
    const raw = localStorage.getItem("beyondlabs.pendingArtifact");
    if (!raw) return "";
    const pending = JSON.parse(raw);
    const target = String(pending?.target || pending?.page || pending?.destination || "").toLowerCase();
    const shouldLoad = target.includes("siem") || target.includes("logs") || pending?.type === "siem" || pending?.type === "log" || pending?.type === "event";
    if (!shouldLoad) return "";
    localStorage.removeItem("beyondlabs.pendingArtifact");
    const value = pending?.content || pending?.text || pending?.raw_input || pending?.value || pending?.query || pending?.rule || pending?.event;
    if (typeof value === "string") return value;
    return value ? JSON.stringify(value, null, 2) : "";
  } catch { return ""; }
}

export function parsePastedEvents(raw: string, startMin: number): SiemEvent[] {
  const out: SiemEvent[] = [];
  let m = startMin;
  for (const lineRaw of raw.split(/\r?\n/)) {
    const line = lineRaw.trim();
    if (!line) continue;
    if (line.startsWith("{")) {
      try {
        const j = JSON.parse(line);
        const tsRaw = String(j.ts ?? j.timestamp ?? "—");
        const parsedMin = tsRaw.length >= 19 ? parseInt(tsRaw.slice(11, 13), 10) * 60 + parseInt(tsRaw.slice(14, 16), 10) : m;
        out.push({
          ts: tsRaw.length >= 19 ? tsRaw.slice(11, 19) : tsRaw,
          min: parsedMin,
          src: String(j.src ?? j.src_ip ?? j.source ?? "—"),
          dst: String(j.dst ?? j.dest_ip ?? j.destination ?? "—"),
          user: String(j.user ?? j.account ?? "-"),
          sig: String(j.sig ?? j.signature ?? j.alert?.signature ?? j.message ?? "—"),
          sev: (j.sev ?? (j.severity === 1 ? "low" : j.severity === 2 ? "high" : "medium")) as SiemEvent["sev"],
        });
        continue;
      } catch {}
    }
    const ips = line.match(IPV4) ?? [];
    const sigMatch = line.match(/(?:signature|alert|message)["\s:=]+([^"|,]+)/i);
    const userMatch = line.match(/(?:user|account|Account Name:)\s*([A-Za-z0-9_.-]+)/i);
    const sev: SiemEvent["sev"] = /fail|error|alert|sqli|exploit/i.test(line) ? "high" : /warn/i.test(line) ? "medium" : "low";
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

export const FIELDS = ["src", "dst", "user", "sig", "sev"] as const;
export type FilterChip = { field: string; value: string };

export function toCsv(rows: SiemEvent[]): string {
  const header = ["ts", "src", "dst", "user", "sig", "sev"].join(",");
  const esc = (s: unknown) => {
    const v = String(s ?? "");
    return /[",\n]/.test(v) ? `"${v.replace(/"/g, '""')}"` : v;
  };
  return [header, ...rows.map((r) => [r.ts, r.src, r.dst, r.user, r.sig, r.sev].map(esc).join(","))].join("\n");
}

export function download(name: string, body: string, mime = "text/csv") {
  const blob = new Blob([body], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = name; document.body.appendChild(a); a.click(); a.remove();
  URL.revokeObjectURL(url);
}

export function copy(val: string) {
  // deprecated — use copyText from @/lib/copy instead
}

export interface Finding {
  sev: "destructive" | "warning" | "info";
  title: string; reason: string; action: string;
}

export function genMarkdownReport(filtered: SiemEvent[], findings: Finding[], mitre: string[]): string {
  const lines = [
    `# SIEM Event Report`,
    `**Events:** ${filtered.length}`,
    `**Generated:** ${new Date().toISOString()}`,
    "",
    "## Findings",
    ...findings.map((f) => `- [${f.sev.toUpperCase()}] ${f.title} — ${f.reason}`),
  ];
  if (mitre.length) lines.push("", "## MITRE ATT&CK", ...mitre.map((m) => `- ${m}`));
  const highSev = filtered.filter((e) => e.sev === "high");
  if (highSev.length) {
    lines.push("", "## High-Severity Events", ...highSev.map((e) => `- ${e.ts} | ${e.src}→${e.dst} | ${e.user} | ${e.sig}`));
  }
  lines.push("", "## All Events", ...filtered.map((e) => `- ${e.ts} | ${e.src}→${e.dst} | ${e.user} | ${e.sig} | ${e.sev}`));
  return lines.join("\n");
}

export const TACTIC_MAP: Record<string, string> = {
  T1110: "Credential Access", T1078: "Defense Evasion", T1190: "Initial Access",
  T1572: "Command and Control", T1071: "Command and Control", T1048: "Exfiltration",
  T1556: "Credential Access", T1059: "Execution", T1204: "Execution",
  T1021: "Lateral Movement", T1595: "Reconnaissance", T1592: "Reconnaissance",
};

export const SEV_MAP: Record<string, "destructive" | "warning" | "info"> = {
  critical: "destructive", high: "destructive",
  medium: "warning", low: "info", info: "info",
};

export function detectionsToFindings(detections: any[]): Finding[] {
  return detections.map((d) => ({
    sev: SEV_MAP[d.severity] ?? "info",
    title: d.title,
    reason: d.detail || d.why_it_matters,
    action: d.recommendation || d.next_check,
  }));
}

export function buildMetricsNarrative(metrics: any, events: SiemEvent[], findings: Finding[]): string {
  if (!metrics) return "No analysis data available.";
  const lines = [
    "## SIEM Dataset Summary",
    "",
    `**Total Events:** ${metrics.total_events ?? 0}`,
    `**Detections Generated:** ${metrics.total_detections ?? 0}`,
    ...(metrics.top_source_ips?.length ? [`**Top Source IP:** ${metrics.top_source_ips[0]?.[0] ?? "—"} (${metrics.top_source_ips[0]?.[1] ?? 0} events)`] : []),
    ...(metrics.top_users?.length ? [`**Top User:** ${metrics.top_users[0]?.[0] ?? "—"}`] : []),
    ...(metrics.top_hosts?.length ? [`**Top Host:** ${metrics.top_hosts[0]?.[0] ?? "—"}`] : []),
    "",
    "### Detection Findings",
    "",
    ...findings.slice(0, 8).map((d, i) => `${i + 1}. **${d.sev.toUpperCase()}** ${d.title} — ${d.reason}`),
    "",
    "### Analyst Notes",
    "",
  ];
  const highCount = events.filter((e) => e.sev === "high").length;
  if (highCount >= 3) {
    lines.push("**Alert:** High concentration of high-severity events warrants immediate review.");
  } else if (highCount >= 1) {
    lines.push("**Note:** Isolated high-severity events present. Validate before escalation.");
  } else {
    lines.push("**Note:** No high-severity events. Proceed with standard triage workflow.");
  }
  return lines.join("\n");
}

export function sendArtifactClick(page: string, content: string) {
  try {
    localStorage.setItem("beyondlabs.pendingArtifact", JSON.stringify({
      type: "siem_events",
      content,
      target: page,
      source: "SIEM Workspace",
      created_at: new Date().toISOString(),
    }));
  } catch {}
}
