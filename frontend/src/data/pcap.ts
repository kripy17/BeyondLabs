import { type Severity } from "@/lib/severity";

export type Finding = { severity: Severity; title: string; detail: string; recommendation: string };

export interface PcapBackendResult {
  status: string; filename: string; sha256: string;
  summary: { packets: number; unique_ips: number; dns_queries: number; http_requests: number; tls_sni: number; findings: number };
  top_ips: { ip: string; packets: number }[];
  dns_queries: string[];
  http_requests: { src?: string; dst?: string; method: string; path: string; host: string; user_agent?: string }[];
  tls_server_names: string[];
  beaconing_candidates: { src: string; dst: string; packets: number }[];
  findings: Finding[];
  iocs: { ips: string[]; domains: string[]; urls: string[] };
  limitations: string[];
}

export type ProtoBreakdown = { protocol: string; packets: number; percentage: number };
export type TopTalker = { ip: string; packets: number; bytes: string; role: string };
export type Suspicious = { indicator: string; severity: Severity; detail: string };
export type ParsedText = {
  topTalkers: TopTalker[]; protocols: ProtoBreakdown[]; suspicious: Suspicious[];
  dnsQueries: string[]; ips: string[]; totalPackets: number;
};

export const SAMPLE_OUTPUTS: Record<string, string> = {
  "tcpdump sample": `12:34:56.789012 IP 192.168.1.100.443 > 10.0.0.2.52341: Flags [P.], seq 1:1460, ack 1, win 8192
12:34:56.789112 IP 185.220.101.44.4443 > 192.168.1.100.49152: Flags [S], seq 12345, win 65535
12:34:56.789212 IP 10.0.0.2.52341 > 192.168.1.100.443: Flags [.], ack 1461, win 8192
12:34:57.001234 IP 192.168.1.100.49152 > 185.220.101.44.4443: Flags [S.], seq 54321, ack 12346, win 65535
12:34:57.001334 IP 185.220.101.44.4443 > 192.168.1.100.49152: Flags [P.], seq 1:512, ack 1, win 8192
12:34:57.001434 IP 192.168.1.100.49152 > 185.220.101.44.4443: Flags [.], ack 513, win 8192
12:34:57.501234 IP 192.168.1.100.49153 > 8.8.8.8.53: 1234+ A? evil-payload.ru
12:34:57.501334 IP 8.8.8.8.53 > 192.168.1.100.49153: 1234 NXDomain 0/1/0 (95)
12:34:58.001234 IP 10.0.0.1.67 > 192.168.1.100.68: BOOTP/DHCP, Reply
12:34:58.101234 IP 192.168.1.100.49154 > 203.0.113.55.80: Flags [S], seq 11111, win 65535
12:34:58.101334 IP 203.0.113.55.80 > 192.168.1.100.49154: Flags [S.], seq 22222, ack 11112, win 65535
12:34:58.201234 IP 192.168.1.100.49154 > 203.0.113.55.80: Flags [P.], seq 1:289, ack 1, win 8192
12:34:58.201334 IP 203.0.113.55.80 > 192.168.1.100.49154: Flags [P.], seq 1:445, ack 290, win 8192
12:34:59.001234 IP 192.168.1.100.49155 > 185.220.101.44.53: 5678+ A? evil-payload.ru`,
  "tshark HTTP sample": `1   0.000000 192.168.1.100 → 203.0.113.55 HTTP GET /index.html
2   0.001234 203.0.113.55 → 192.168.1.100 HTTP HTTP/1.1 200 OK (text/html)
3   0.010000 192.168.1.100 → 203.0.113.55 HTTP POST /login.php (application/x-www-form-urlencoded)
4   0.011234 203.0.113.55 → 192.168.1.100 HTTP HTTP/1.1 302 Found (text/html)
5   0.100000 192.168.1.100 → 185.220.101.44 TLSv1.2 Client Hello (SNI=evil-payload.ru)
6   0.101234 185.220.101.44 → 192.168.1.100 TLSv1.2 Server Hello
7   0.200000 192.168.1.100 → 8.8.8.8 DNS Standard query A google.com
8   0.201234 8.8.8.8 → 192.168.1.100 DNS Standard query response A 142.250.80.46
9   1.000000 10.0.0.1 → 192.168.1.100 ICMP Echo (ping) reply
10  2.000000 192.168.1.100 → 185.220.101.44 TLSv1.2 Application Data`,
};

export function parsePcapText(text: string): ParsedText | null {
  const lines = text.trim().split("\n").filter(Boolean);
  if (lines.length < 2) return null;

  const ipSet = new Set<string>();
  const ipCount = new Map<string, number>();
  const protoCount = new Map<string, number>();
  const dnsSet = new Set<string>();
  const suspicious: Suspicious[] = [];
  for (const line of lines) {
    const ipMatches = line.matchAll(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/g);
    const ipsInLine: string[] = [];
    for (const m of ipMatches) {
      if (!ipSet.has(m[1])) ipSet.add(m[1]);
      ipsInLine.push(m[1]);
      ipCount.set(m[1], (ipCount.get(m[1]) || 0) + 1);
    }

    if (/DNS|dns/i.test(line)) {
      const dnsMatch = line.match(/\b[A-Za-z0-9][\w.-]*\.[a-z]{2,}\b/i);
      if (dnsMatch) dnsSet.add(dnsMatch[0].toLowerCase());
    }
    if (/TLS|tls/i.test(line)) {
      protoCount.set("TLS", (protoCount.get("TLS") || 0) + 1);
    } else if (/HTTP/i.test(line) && !/HTTPS/i.test(line)) {
      protoCount.set("HTTP", (protoCount.get("HTTP") || 0) + 1);
    } else if (/DNS|dns/i.test(line)) {
      protoCount.set("DNS", (protoCount.get("DNS") || 0) + 1);
    } else if (/ICMP|icmp/i.test(line)) {
      protoCount.set("ICMP", (protoCount.get("ICMP") || 0) + 1);
    } else {
      protoCount.set("TCP/UDP", (protoCount.get("TCP/UDP") || 0) + 1);
    }

    if (/evil|malicious|malware|c2|suspicious/i.test(line) || /185\.220\.101\./.test(line)) {
      let detail = "";
      if (/TLS|tls/i.test(line)) detail = "Encrypted connection to known suspicious host";
      else if (/DNS/i.test(line)) detail = "DNS query to suspicious destination";
      else detail = "Unusual connection pattern detected";
      suspicious.push({
        indicator: `Connection to suspicious host in ${ipsInLine.filter(ip => /185\.220\.101\./.test(ip) || /203\.0\.113\./.test(ip)).join(", ") || ipsInLine.slice(-1)[0] || "unknown"}`,
        severity: "high",
        detail,
      });
    }
  }

  const topTalkers: TopTalker[] = [...ipCount.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 6)
    .map(([ip, count]) => ({
      ip, packets: count,
      bytes: `${(count * 0.6).toFixed(1)} KB`,
      role: /^10\./.test(ip) ? "Internal" : /^192\.168\./.test(ip) ? "Internal" : /^8\.8\.8\.|^1\.1\.1\./.test(ip) ? "DNS" : /185\.220\.101\./.test(ip) ? "External (suspicious)" : /203\.0\.113\./.test(ip) ? "External" : /^0\.0\.0\.0|^127\./.test(ip) ? "Local" : "External",
    }));

  const totalPackets = lines.length;
  const protocols: ProtoBreakdown[] = [...protoCount.entries()]
    .sort((a, b) => b[1] - a[1])
    .map(([protocol, packets]) => ({
      protocol, packets,
      percentage: Math.round((packets / totalPackets) * 1000) / 10,
    }));

  return {
    topTalkers, protocols,
    suspicious: suspicious.slice(0, 5),
    dnsQueries: [...dnsSet].slice(0, 8),
    ips: [...ipSet],
    totalPackets,
  };
}

export function pcapSeverityTone(s: Severity): "destructive" | "warning" | "success" | "info" {
  if (s === "high") return "destructive";
  if (s === "medium") return "warning";
  if (s === "low") return "info";
  return "success";
}

export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

export function generateMdReport(r: PcapBackendResult): string {
  const lines = [
    `# PCAP Analysis Report`,
    `**File:** \`${r.filename}\``,
    `**SHA-256:** \`${r.sha256}\``,
    `**Generated:** ${new Date().toISOString()}`,
    "", "## Summary",
    `- Packets: ${r.summary.packets}`,
    `- Unique IPs: ${r.summary.unique_ips}`,
    `- DNS Queries: ${r.summary.dns_queries}`,
    `- HTTP Requests: ${r.summary.http_requests}`,
    `- TLS SNI: ${r.summary.tls_sni}`,
    `- Findings: ${r.summary.findings}`,
  ];
  if (r.findings.length) {
    lines.push("", "## Findings", ...r.findings.map((f) => `- [${f.severity.toUpperCase()}] ${f.title} — ${f.detail}`));
  }
  if (r.dns_queries.length) {
    lines.push("", "## DNS Queries", ...r.dns_queries.map((q) => `- ${q}`));
  }
  if (r.http_requests.length) {
    lines.push("", "## HTTP Requests", ...r.http_requests.map((h) => `- ${h.method} ${h.host}${h.path}`));
  }
  if (r.beaconing_candidates.length) {
    lines.push("", "## Beaconing Candidates", ...r.beaconing_candidates.map((b) => `- ${b.src} → ${b.dst} (${b.packets} packets)`));
  }
  return lines.join("\n");
}

export function generateTextMdReport(t: ParsedText): string {
  const lines = [
    `# PCAP Text Analysis Report`,
    `**Generated:** ${new Date().toISOString()}`,
    "", "## Summary",
    `- Total Lines: ${t.totalPackets}`,
    `- Unique IPs: ${t.ips.length}`,
    `- Protocols: ${t.protocols.length}`,
    `- DNS Queries: ${t.dnsQueries.length}`,
    `- Suspicious Indicators: ${t.suspicious.length}`,
  ];
  if (t.topTalkers.length) {
    lines.push("", "## Top Talkers", ...t.topTalkers.map((tt) => `- ${tt.ip} — ${tt.packets} packets (${tt.bytes}, ${tt.role})`));
  }
  if (t.suspicious.length) {
    lines.push("", "## Suspicious Indicators", ...t.suspicious.map((s) => `- [${s.severity.toUpperCase()}] ${s.indicator} — ${s.detail}`));
  }
  if (t.dnsQueries.length) {
    lines.push("", "## DNS Queries", ...t.dnsQueries.map((q) => `- ${q}`));
  }
  return lines.join("\n");
}
