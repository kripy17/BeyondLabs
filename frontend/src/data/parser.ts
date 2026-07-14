import { SUSPICIOUS_TLDS, SHORTENERS, LOLBINS, DOWNLOAD_CRADLES, AMSI_BYPASS_PATTERNS, refang, entropy, scanSecrets, type Secret } from "@/lib/ioc-patterns";
import { Link2, Globe, Network, Hash, AtSign, Bug, Crosshair, Terminal } from "lucide-react";

export const IOC_KIND_MAP: Record<string, string> = {
  URL: "url", Domain: "domain", IPv4: "ip", Email: "email",
  MD5: "hash", SHA256: "hash", CVE: "raw", ATTACK: "raw", MAC: "raw", Base64: "raw",
};

export const SAMPLES: Record<string, { label: string; text: string }> = {
  phishing: { label: "Phishing email", text: "From: Security Team <security-alert@example-login.com>\nTo: user@example.org\nSubject: Password reset required\nAuthentication-Results: spf=fail dkim=fail dmarc=fail\nReply-To: Security Team <security-alert@example-login.com>\nReceived: from mail.example-login.com (203.0.113.44)\n\nPlease verify your account at hxxps[:]//login.example-login[.]com/reset?id=1234" },
  headers: { label: "Email headers only", text: "From: security@example.com\nTo: user@example.org\nSubject: Urgent password reset\nReturn-Path: bounce@example-login.com\nReply-To: support@example-login.com\nReceived-SPF: fail\nAuthentication-Results: spf=fail dkim=none dmarc=fail" },
  iocs: { label: "Mixed IOCs", text: "hxxps[:]//phish.example[.]com/login\nexample[.]net\n198[.]51[.]100[.]23\n44d88612fea8a8f36de82e1278abb02f\n275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f\nCVE-2024-12345\nT1566.002\nanalyst@corp.local\nSK-ABC123DEF456GHIJ7890\nghp_abc123def456ghi789jkl012mno345pqr678st" },
  linux: { label: "Linux SSH auth", text: "Apr 25 10:10:10 arch sshd[123]: Failed password for invalid user admin from 8.8.8.8 port 4444 ssh2\nApr 25 10:11:44 arch sshd[124]: Accepted password for root from 1.1.1.1 port 55910 ssh2" },
  windows: { label: "Windows 4688", text: "Event ID: 4688\nProvider: Microsoft-Windows-Security-Auditing\nNew Process Name: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\nCommand Line: powershell.exe -NoP -EncodedCommand SQBFAFgA\nAccount Name: krish" },
  suricata: { label: "Suricata EVE", text: '{"timestamp":"2026-04-25T10:12:00Z","event_type":"alert","src_ip":"198.51.100.23","dest_ip":"10.0.0.5","alert":{"signature":"ET WEB_SERVER Possible SQL Injection","severity":2}}' },
  access: { label: "Web log SQLi", text: '198.51.100.23 - - [25/Apr/2026:10:12:00 +0530] "GET /../../etc/passwd HTTP/1.1" 404 123 "-" "sqlmap/1.7"' },
  powershell: { label: "PowerShell encoded", text: "powershell.exe -NoP -W Hidden -EncodedCommand SQBFAFgA" },
  secrets: { label: "Code w/ secrets", text: 'const apiKey = "AIzaSyD-example";\nGITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz1234567890\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE' },
  sigma: { label: "Sigma rule", text: "title: Suspicious PowerShell Encoded Command\nid: 6f1f0c20-1111-4444-8888-123456789abc\nlogsource:\n  product: windows\n  category: process_creation\ndetection:\n  selection:\n    CommandLine|contains: '-EncodedCommand'\n  condition: selection\ntags:\n  - attack.t1059.001" },
  notes: { label: "Analyst notes", text: "10:04 - User reported suspicious password reset email.\n10:08 - Extracted URL hxxps[:]//login.example[.]com/reset\nFinding: Sender domain does not match expected organization.\nNext step: collect headers and draft user-facing summary." },
  email_headers: { label: "Sample email headers", text: "From: \"Security Team\" <security@company.com>\nTo: user@example.org\nSubject: Urgent: Action required on your account\nDate: Mon, 15 Jun 2026 09:23:45 +0000\nReturn-Path: bounce@phish-target.tk\nReply-To: security-verify@phish-target.tk\nReceived: from mx.phish-target.tk (203.0.113.50) by mx.company.com with ESMTPS id ABC123\nReceived-SPF: fail (domain of phish-target.tk does not designate 203.0.113.50 as permitted sender)\nAuthentication-Results: mx.company.com; spf=fail smtp.mailfrom=phish-target.tk; dkim=none; dmarc=fail\nDKIM-Signature: v=1; a=rsa-sha256; d=phish-target.tk; s=selector1;\n bh=2bd0e4a8c9f1b3d5e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9;\nX-Priority: 1 (Highest)\nMIME-Version: 1.0\nContent-Type: text/plain; charset=\"UTF-8\"\n\nDear User,\n\nWe detected suspicious activity on your account. Please verify your identity immediately by clicking the link below:\n\nhttps://login-company.secure-phish.tk/verify?token=abc123def456\n\nFailure to verify within 24 hours will result in account suspension.\n\nThank you,\nSecurity Team" },
  ioc_list: { label: "Sample IOC list", text: "45.33.32.156\n185.94.188.22\n91.121.87.34\n198.51.100.23\n203.0.113.44\n51.15.0.100\nhxxps[:]//evil[.]com/setup.exe\nhxxps[:]//phish-login[.]tk/verify\nhttp://185[.]220[.]101[.]161/payload.ps1\nhxxp://malware[.]download/payload\nexample[.]net\nmalicious[.]com\nphish-target[.]tk\nevil-host[.]ru\n7e0eaa6c2a2c7a0d5c4a3d8e9f0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a\na1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2\n44d88612fea8a8f36de82e1278abb02f\nCVE-2024-1234\nCVE-2025-5678\nT1566.002\nT1059.001\nT1204\nphish@evil-host[.]ru\nadmin@malicious[.]com" },
  sysmon: {
    label: "Sysmon EVTX (XML)",
    text: `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
<System>
<Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385F-C22A-43E0-BF4C-06F5698FFBD9}"/>
<EventID>1</EventID>
<Version>5</Version>
<Level>4</Level>
<Task>1</Task>
<Opcode>0</Opcode>
<Keywords>0x8000000000000000</Keywords>
<TimeCreated SystemTime="2025-06-15T10:30:00.123456Z"/>
<EventRecordID>12345</EventRecordID>
<Computer>DC01.corp.local</Computer>
</System>
<EventData>
<Data Name="UtcTime">2025-06-15 10:30:00.123</Data>
<Data Name="ProcessGuid">{A123-B456-C789-D012}</Data>
<Data Name="ProcessId">4523</Data>
<Data Name="Image">C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>
<Data Name="CommandLine">powershell.exe -nop -w hidden -enc SQBFAFgA</Data>
<Data Name="CurrentDirectory">C:\\Users\\analyst\\</Data>
<Data Name="User">CORP\\analyst</Data>
<Data Name="LogonGuid">{E456-F789-A012-B345}</Data>
<Data Name="LogonId">0x3E7</Data>
<Data Name="TerminalSessionId">1</Data>
<Data Name="IntegrityLevel">High</Data>
<Data Name="Hashes">MD5=44d88612fea8a8f36de82e1278abb02f,SHA256=a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2</Data>
<Data Name="ParentProcessGuid">{B789-C012-D345-E678}</Data>
<Data Name="ParentProcessId">1234</Data>
<Data Name="ParentImage">C:\\Windows\\System32\\cmd.exe</Data>
<Data Name="ParentCommandLine">cmd.exe /c start powershell</Data>
<Data Name="ParentUser">CORP\\analyst</Data>
</EventData>
</Event>`,
  },
};

export const RX = {
  URL:    /\b(?:hxxps?|https?):\/\/[^\s)>"']+/gi,
  Domain: /\b(?:[a-z0-9-]+\[?\.\]?){1,5}[a-z]{2,}\b/gi,
  IPv4:   /\b(?:\d{1,3}\[?\.\]?){3}\d{1,3}\b/g,
  MD5:    /\b[a-f0-9]{32}\b/gi,
  SHA256: /\b[a-f0-9]{64}\b/gi,
  Email:  /\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b/gi,
  CVE:    /CVE-\d{4}-\d{4,}/gi,
  ATTACK: /\bT\d{4}(?:\.\d{3})?\b/g,
};

export const RX_MAC = /\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b/g;
export const RX_B64 = /\b(?:[A-Za-z0-9+/]{40,}(?:==|=)?)\b/g;

export function autoDetectInputType(text: string): { label: string; tone: "primary" | "success" | "warning" | "info" | "default" } | null {
  const t = text.trim();
  if (!t) return null;
  if (/@/.test(t) && /\./.test(t) && (/From:|To:|Subject:/i.test(t) || /@[a-z0-9.-]+\.[a-z]{2,}/i.test(t)))
    return { label: "Phishing email", tone: "warning" };
  if (!t.includes("\n") && /:\/\//.test(t))
    return { label: "URL", tone: "info" };
  if (/^Begin/i.test(t) || /MIME/i.test(t))
    return { label: "Email / EML", tone: "primary" };
  if (/^\d{1,3}\.\d{1,3}\./.test(t))
    return { label: "IP address", tone: "info" };
  if (/\[\d|sshd|systemd/i.test(t))
    return { label: "Log file", tone: "primary" };
  const lines = t.split("\n");
  if (lines.length > 1 && /\b[a-f0-9]{32}\b|\b[a-f0-9]{40}\b|\b[a-f0-9]{64}\b/i.test(t))
    return { label: "IOC list", tone: "warning" };
  return null;
}

export const MITRE_MAP: Record<string, { id: string; name: string }[]> = {
  URL: [{ id: "T1566", name: "Phishing" }],
  Email: [{ id: "T1566", name: "Phishing" }],
  CVE: [{ id: "T1190", name: "Exploit Public-Facing Application" }],
  ATTACK: [],
  MD5: [{ id: "T1204", name: "User Execution" }],
  SHA256: [{ id: "T1204", name: "User Execution" }],
  Domain: [{ id: "T1583.001", name: "Acquire Infrastructure: Domains" }],
  IPv4: [{ id: "T1071", name: "Application Layer Protocol" }],
};

export const KIND_META: Record<string, { icon: any; tone: "default" | "primary" | "warning" | "destructive"; pivot?: string }> = {
  URL:    { icon: Link2,   tone: "warning",     pivot: "/url" },
  Domain: { icon: Globe,   tone: "default",     pivot: "/recon" },
  IPv4:   { icon: Network, tone: "default",     pivot: "/recon" },
  MD5:    { icon: Hash,    tone: "primary",     pivot: "/attachment" },
  SHA256: { icon: Hash,    tone: "primary",     pivot: "/attachment" },
  Email:  { icon: AtSign,  tone: "default",     pivot: "/phishing" },
  CVE:    { icon: Bug,     tone: "destructive" },
  ATTACK: { icon: Crosshair, tone: "destructive", pivot: "/mitre" },
  MAC: { icon: Hash, tone: "default", pivot: "/logs" },
  Base64: { icon: Terminal, tone: "warning", pivot: "/parser" },
};

export interface Signal { title: string; severity: "info" | "warning" | "destructive" | "success"; reason?: string; action?: string; }
export interface CmdFinding { type: string; detail: string; }

export function dedupSignals(sigs: Signal[]): Signal[] {
  const seen = new Set<string>();
  return sigs.filter((s) => { const k = s.title; if (seen.has(k)) return false; seen.add(k); return true; });
}

export function genEmailSignals(t: string): Signal[] {
  const s: Signal[] = [];
  if (/spf=fail/i.test(t) || /dkim=fail/i.test(t) || /dmarc=fail/i.test(t))
    s.push({ title: "SPF/DKIM/DMARC failure", severity: "warning", reason: "Authentication-Results show one or more checks failed", action: "Review headers for spoofing indicators" });
  const reply = t.match(/Reply-To:\s*(.+)/i);
  const from = t.match(/From:\s*(.+)/i);
  if (reply && from && reply[1] !== from[1])
    s.push({ title: "Reply-To mismatch", severity: "warning", reason: `Reply-To differs from From header`, action: "Verify sender in Phishing Triage" });
  if (/\b(urgent|immediately|password reset|verify your account|suspended|unusual activity|click here|limited time)\b/i.test(t))
    s.push({ title: "Urgency pressure", severity: "warning", reason: "Message contains urgency keywords common in phishing", action: "Flag for social engineering review" });
  return s;
}

export function genUrlSignals(urls: string[]): Signal[] {
  const s: Signal[] = [];
  for (const u of urls) {
    try {
      const parsed = new URL(refang(u));
      const host = parsed.hostname;
      const tld = host.split(".").pop()?.toLowerCase();
      if (tld && SUSPICIOUS_TLDS.has(tld))
        s.push({ title: "Suspicious TLD", severity: "warning", reason: `URL uses high-risk TLD .${tld}`, action: "Investigate domain reputation" });
      if (SHORTENERS.has(host.replace(/^www\./, "")))
        s.push({ title: "URL shortener", severity: "warning", reason: "Shortened URL hides final destination", action: "Expand with Safe URL Analyzer" });
      if (parsed.username || parsed.password)
        s.push({ title: "Embedded credentials in URL", severity: "destructive", reason: "URL contains embedded user:pass@ credentials", action: "Do not use shared credentials; investigate" });
      if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host))
        s.push({ title: "IP-based URL", severity: "warning", reason: "URL uses raw IP instead of domain", action: "Check IP reputation" });
      const path = parsed.pathname + parsed.search;
      if (path.length > 20 && entropy(path) > 4.5)
        s.push({ title: "Suspicious URL entropy", severity: "info", reason: "URL path has high randomness (entropy > 4.5)", action: "Review URL structure for encoding or exfiltration" });
    } catch { /* noop */ }
  }
  return dedupSignals(s);
}

export function genCmdSignals(t: string): Signal[] {
  const s: Signal[] = [];
  const tLower = t.toLowerCase();
  if (/-EncodedCommand\b|-e\s+[A-Za-z0-9+/=]{20,}/i.test(t))
    s.push({ title: "Encoded PowerShell command", severity: "destructive", reason: "Base64-encoded PowerShell detected - common malware evasion", action: "Decode and review in Logs & Alerts" });
  if (AMSI_BYPASS_PATTERNS.some((p) => tLower.includes(p)))
    s.push({ title: "AMSI bypass attempt", severity: "destructive", reason: "AMSI bypass pattern detected - attacker disabling script monitoring", action: "Escalate for immediate review" });
  if (DOWNLOAD_CRADLES.some((c) => tLower.includes(c)))
    s.push({ title: "Download cradle", severity: "destructive", reason: "Remote download pattern detected - possible payload staging", action: "Extract URL and submit to Safe URL Analyzer" });
  if (/-WindowStyle\s+(Hidden|Minimized)|-w\s+(Hidden|Minimized)/i.test(t))
    s.push({ title: "Hidden execution", severity: "warning", reason: "Process configured to run without visible window", action: "Review process tree in Logs & Alerts" });
  if (LOLBINS.some((b) => tLower.includes(b)))
    s.push({ title: "LOLBin execution", severity: "warning", reason: "Living-off-the-land binary detected - commonly abused by attackers", action: "Correlate with parent process" });
  if (/-NoProfile|-NoP|-ExecutionPolicy\s+Bypass/i.test(t))
    s.push({ title: "Suspicious PowerShell flags", severity: "warning", reason: "PowerShell launched with bypass flags - reduces execution restrictions", action: "Review full command line" });
  return s;
}

export function genGeneralSignals(iocs: Record<string, string[]>): Signal[] {
  const s: Signal[] = [];
  const active = Object.values(iocs).filter((v) => v.length).length;
  if (active >= 4) s.push({ title: "Multiple IOC types", severity: "info", reason: `${active} IOC families detected - broad indicator diversity`, action: "Correlate across workspaces" });
  if (iocs.SHA256.length || iocs.MD5.length) s.push({ title: "File hashes present", severity: "info", reason: "Hashes available for attachment triage and reputation lookup", action: "Send to Attachment Triage" });
  if (iocs.CVE.length) s.push({ title: "CVE references", severity: "warning", reason: `${iocs.CVE.length} known vulnerabilities referenced`, action: "Check patch status and applicable CVEs" });
  if (iocs.ATTACK.length) s.push({ title: "MITRE ATT&CK IDs found", severity: "info", reason: `${iocs.ATTACK.length} technique IDs found - map to detection coverage`, action: "Review MITRE coverage gaps" });
  return s;
}

export function scanCmdLines(t: string): CmdFinding[] {
  const f: CmdFinding[] = [];
  const tLower = t.toLowerCase();
  for (const bin of LOLBINS) if (tLower.includes(bin)) { f.push({ type: "lolbin", detail: bin }); break; }
  if (DOWNLOAD_CRADLES.some((c) => tLower.includes(c))) f.push({ type: "download", detail: "Download cradle" });
  if (/-EncodedCommand\b/i.test(t)) f.push({ type: "encoded", detail: "Encoded PowerShell" });
  if (AMSI_BYPASS_PATTERNS.some((p) => tLower.includes(p))) f.push({ type: "amsi", detail: "AMSI bypass" });
  if (/-WindowStyle\s+(Hidden|Minimized)/i.test(t)) f.push({ type: "hidden", detail: "Hidden window" });
  return f;
}

export function collectSignals(input: string, iocs: Record<string, string[]>): Signal[] {
  return [
    ...genEmailSignals(input),
    ...genUrlSignals(iocs.URL),
    ...genCmdSignals(input),
    ...genGeneralSignals(iocs),
  ];
}

export function collectMitre(iocs: Record<string, string[]>, signals: Signal[], cmds: CmdFinding[]): { id: string; name: string; source: string }[] {
  const m: { id: string; name: string; source: string }[] = [];
  const seen = new Set<string>();
  for (const [kind, entries] of Object.entries(MITRE_MAP)) {
    if (iocs[kind]?.length) {
      for (const e of entries) {
        if (!seen.has(e.id) && e.id) { seen.add(e.id); m.push({ ...e, source: kind }); }
      }
    }
  }
  for (const s of signals) {
    const mid = s.title === "Encoded PowerShell command" ? "T1027" : s.title === "AMSI bypass attempt" ? "T1562.001" : s.title === "Download cradle" ? "T1105" : s.title === "LOLBin execution" ? "T1059" : s.title === "Hidden execution" ? "T1564" : s.title === "SPF/DKIM/DMARC failure" ? "T1566" : s.title === "Reply-To mismatch" ? "T1566" : s.title === "Suspicious TLD" ? "T1583.001" : null;
    if (mid && !seen.has(mid)) { seen.add(mid); m.push({ id: mid, name: s.title, source: "signal" }); }
  }
  const cmd: Record<string, string> = { encoded: "T1027", amsi: "T1562.001", download: "T1105", lolbin: "T1059", hidden: "T1564" };
  for (const c of cmds) {
    const mid = cmd[c.type];
    if (mid && !seen.has(mid)) { seen.add(mid); m.push({ id: mid, name: c.detail, source: "cmd" }); }
  }
  return m;
}

export function genMarkdownExport(input: string, iocs: Record<string, string[]>, signals: Signal[], total: number, family: string, primary: string, secrets: Secret[], cmds: CmdFinding[], mitre: { id: string; name: string }[]): string {
  const lines = [
    `# Smart Parser Report — ${primary}`,
    `**Family:** ${family}  **IOCs:** ${total}`,
    "",
    "## Indicators",
    ...Object.entries(iocs).filter(([, v]) => v.length).flatMap(([k, v]) => [`### ${k} (${v.length})`, ...v.map((i) => `- \`${i}\``), ""]),
  ];
  if (signals.length) {
    lines.push("## Signals");
    for (const s of signals) lines.push(`- [${s.severity.toUpperCase()}] ${s.title}${s.reason ? ` — ${s.reason}` : ""}`);
    lines.push("");
  }
  if (secrets.length) {
    lines.push("## Secrets", ...secrets.map((s) => `- ${s.type}: \`${s.value}\``), "");
  }
  if (mitre.length) {
    lines.push("## MITRE ATT&CK", ...mitre.map((m) => `- ${m.id}: ${m.name}`), "");
  }
  return lines.join("\n");
}

export function genJsonExport(input: string, iocs: Record<string, string[]>, signals: Signal[], total: number, family: string, primary: string, secrets: Secret[], cmds: CmdFinding[], mitre: { id: string; name: string }[]): string {
  const data = {
    version: "1.0",
    generated: new Date().toISOString(),
    classification: { family, primary },
    indicators: iocs,
    signals: signals.map(s => ({ severity: s.severity, title: s.title, reason: s.reason, action: s.action })),
    secrets: secrets.map(s => ({ type: s.type, value: s.value })),
    commandAnalysis: cmds.map(c => ({ type: c.type, detail: c.detail })),
    mitre: mitre.map(m => ({ id: m.id, name: m.name })),
    stats: { total, lines: input.split("\n").length },
  };
  return JSON.stringify(data, null, 2);
}

export const OSINT_TOOLS_PER_KIND: Record<string, { label: string; url: (v: string) => string }[]> = {
  URL: [
    { label: "VirusTotal", url: (v) => `https://www.virustotal.com/gui/search/${encodeURIComponent(v)}` },
    { label: "urlscan.io", url: (v) => `https://urlscan.io/search/#${encodeURIComponent(v)}` },
  ],
  Domain: [
    { label: "VirusTotal", url: (v) => `https://www.virustotal.com/gui/domain/${encodeURIComponent(v)}` },
    { label: "crt.sh", url: (v) => `https://crt.sh/?q=${encodeURIComponent(v)}` },
    { label: "Shodan", url: (v) => `https://www.shodan.io/search?query=${encodeURIComponent(v)}` },
    { label: "SecurityTrails", url: (v) => `https://securitytrails.com/list/apex_domain/${encodeURIComponent(v)}` },
    { label: "ViewDNS", url: (v) => `https://viewdns.info/reverseip/?host=${encodeURIComponent(v)}` },
    { label: "DNSDumpster", url: (v) => `https://dnsdumpster.com/domain/${encodeURIComponent(v)}` },
    { label: "BuiltWith", url: (v) => `https://builtwith.com/${encodeURIComponent(v)}` },
    { label: "WhoisXML", url: (v) => `https://whois.whoisxmlapi.com/lookup?domain=${encodeURIComponent(v)}` },
    { label: "Pulsedive", url: (v) => `https://pulsedive.com/indicator/?query=${encodeURIComponent(v)}` },
    { label: "Talos", url: (v) => `https://talosintelligence.com/reputation_center/lookup?search=${encodeURIComponent(v)}` },
    { label: "Wayback", url: (v) => `https://web.archive.org/web/*/${encodeURIComponent(v)}` },
  ],
  IPv4: [
    { label: "VirusTotal", url: (v) => `https://www.virustotal.com/gui/ip-address/${encodeURIComponent(v)}` },
    { label: "AbuseIPDB", url: (v) => `https://www.abuseipdb.com/check/${encodeURIComponent(v)}` },
    { label: "Shodan", url: (v) => `https://www.shodan.io/host/${encodeURIComponent(v)}` },
    { label: "GreyNoise", url: (v) => `https://viz.greynoise.io/ip/${encodeURIComponent(v)}` },
    { label: "Censys", url: (v) => `https://search.censys.io/search?q=${encodeURIComponent(v)}` },
    { label: "LeakIX", url: (v) => `https://leakix.net/search?q=${encodeURIComponent(v)}` },
  ],
  MD5: [
    { label: "VirusTotal", url: (v) => `https://www.virustotal.com/gui/search/${encodeURIComponent(v)}` },
    { label: "AlienVault OTX", url: (v) => `https://otx.alienvault.com/browse/global/pulses?q=${encodeURIComponent(v)}` },
  ],
  SHA256: [
    { label: "VirusTotal", url: (v) => `https://www.virustotal.com/gui/search/${encodeURIComponent(v)}` },
    { label: "AlienVault OTX", url: (v) => `https://otx.alienvault.com/browse/global/pulses?q=${encodeURIComponent(v)}` },
  ],
  Email: [
    { label: "Have I Been Pwned", url: (v) => `https://haveibeenpwned.com/account/${encodeURIComponent(v)}` },
    { label: "DeHashed", url: (v) => `https://dehashed.com/search?query=${encodeURIComponent(v)}` },
    { label: "Hunter.io", url: (v) => `https://hunter.io/search/${encodeURIComponent(v)}` },
  ],
};
