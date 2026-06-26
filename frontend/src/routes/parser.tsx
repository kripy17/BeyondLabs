import { createFileRoute } from "@tanstack/react-router";
import { useMemo, useState } from "react";
import { PageShell } from "@/components/PageShell";
import {
  IntakeCard, StatusBar, ResultBanner, SendToRow, SectionBar, Panel, Chip,
  EvidenceCard, RiskScore,
} from "@/components/soc/Workspace";
import {
  Zap, Terminal, ArrowRight, Database, Mail, Link2,
  FileWarning, Activity, Globe, Hash, AtSign, Bug, Crosshair, Network, Copy, Check,
  Sparkles, FileText, Workflow, AlertTriangle, ShieldAlert, Key, Download,
} from "lucide-react";

export const Route = createFileRoute("/parser")({ component: ParserPage });

const SAMPLES: Record<string, { label: string; text: string }> = {
  phishing: { label: "Phishing email", text: "From: Security Team <security-alert@example-login.com>\nTo: user@example.org\nSubject: Password reset required\nAuthentication-Results: spf=fail dkim=fail dmarc=fail\nReply-To: Security Team <security-alert@example-login.com>\nReceived: from mail.example-login.com (203.0.113.44)\n\nPlease verify your account at hxxps[:]//login.example-login[.]com/reset?id=1234" },
  headers: { label: "Email headers only", text: "From: security@example.com\nTo: user@example.org\nSubject: Urgent password reset\nReturn-Path: bounce@example-login.com\nReply-To: support@example-login.com\nReceived-SPF: fail\nAuthentication-Results: spf=fail dkim=none dmarc=fail" },
  iocs: { label: "Mixed IOCs", text: "hxxps[:]//phish.example[.]com/login\nexample[.]net\n198[.]51[.]100[.]23\n44d88612fea8a8f36de82e1278abb02f\n275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f\nCVE-2024-12345\nT1566.002\nanalyst@corp.local\nSK-ABC123DEF456GHIJ7890\nghp_abc123def456ghi789jkl012mno345pqr678st" },
  linux: { label: "Linux SSH auth", text: "Apr 25 10:10:10 arch sshd[123]: Failed password for invalid user admin from 8.8.8.8 port 4444 ssh2\nApr 25 10:11:44 arch sshd[124]: Accepted password for root from 1.1.1.1 port 55910 ssh2" },
  windows: { label: "Windows 4688", text: "Event ID: 4688\nProvider: Microsoft-Windows-Security-Auditing\nNew Process Name: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\nCommand Line: powershell.exe -NoP -EncodedCommand SQBFAFgA\nAccount Name: krish" },
  suricata: { label: "Suricata EVE", text: '{"timestamp":"2026-04-25T10:12:00Z","event_type":"alert","src_ip":"198.51.100.23","dest_ip":"10.0.0.5","alert":{"signature":"ET WEB_SERVER Possible SQL Injection","severity":2}}' },
  access: { label: "Web log SQLi", text: '198.51.100.23 - - [25/Apr/2026:10:12:00 +0530] "GET /../../etc/passwd HTTP/1.1" 404 123 "-" "sqlmap/1.7"' },
  powershell: { label: "PowerShell encoded", text: "powershell.exe -NoP -W Hidden -EncodedCommand SQBFAFgA" },
  secrets: { label: "Code w/ secrets", text: "const apiKey = \"AIzaSyD-example\";\nGITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz1234567890\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE" },
  sigma: { label: "Sigma rule", text: "title: Suspicious PowerShell Encoded Command\nid: 6f1f0c20-1111-4444-8888-123456789abc\nlogsource:\n  product: windows\n  category: process_creation\ndetection:\n  selection:\n    CommandLine|contains: '-EncodedCommand'\n  condition: selection\ntags:\n  - attack.t1059.001" },
  notes: { label: "Analyst notes", text: "10:04 - User reported suspicious password reset email.\n10:08 - Extracted URL hxxps[:]//login.example[.]com/reset\nFinding: Sender domain does not match expected organization.\nNext step: collect headers and draft user-facing summary." },
};

const RX = {
  URL:    /\b(?:hxxps?|https?):\/\/[^\s)>"']+/gi,
  Domain: /\b(?:[a-z0-9-]+\[?\.\]?){1,5}[a-z]{2,}\b/gi,
  IPv4:   /\b(?:\d{1,3}\[?\.\]?){3}\d{1,3}\b/g,
  MD5:    /\b[a-f0-9]{32}\b/gi,
  SHA256: /\b[a-f0-9]{64}\b/gi,
  Email:  /\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b/gi,
  CVE:    /CVE-\d{4}-\d{4,}/gi,
  ATTACK: /\bT\d{4}(?:\.\d{3})?\b/g,
};

const SECRET_RX: { type: string; re: RegExp }[] = [
  { type: "AWS Access Key", re: /AKIA[0-9A-Z]{16}\b/g },
  { type: "GitHub Token", re: /(?:ghp_|gho_|ghu_|ghs_|ghr_)[a-zA-Z0-9]{36}\b|github_pat_[a-zA-Z0-9_]{22,}\b/g },
  { type: "JWT Token", re: /eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/g },
  { type: "Slack Token", re: /xox[baprs]-[a-zA-Z0-9-]{10,48}\b/g },
  { type: "Private Key", re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g },
  { type: "Discord Token", re: /[MN][a-zA-Z0-9_-]{23,25}\.[a-zA-Z0-9_-]{6,7}\.[a-zA-Z0-9_-]{27,}/g },
];

const SUSPICIOUS_TLDS = new Set(["tk","ml","ga","cf","gq","xyz","top","download","review","work","date","men","loan","win","bid","cam","click","quest","trade","webcam","science","party","gdn","racing","accountant","country","faith","online","site","rest","cyou","bond","bar"]);
const SHORTENERS = new Set(["bit.ly","tinyurl.com","ow.ly","is.gd","buff.ly","shorturl.at","cutt.ly","t.co","goo.gl","tiny.cc","cli.gs","url.ie","rb.gy","short.link","shrten.com","v.gd","snipr.com","snipurl.com"]);
const LOLBINS = ["powershell","cmd.exe","wscript","cscript","mshta","regsvr32","rundll32","wmic","certutil","bitsadmin","msiexec","scrcons","wshom.ocx","shell32"];
const DOWNLOAD_CRADLES = ["Invoke-WebRequest","iwr","wget","curl","Invoke-RestMethod","irm","Start-BitsTransfer","bitsadmin /transfer","(new-object system.net.webclient).downloadstring","(new-object system.net.webclient).downloadfile","System.Net.WebClient","XMLHttpRequest","WinHttp.WinHttpRequest"];
const AMSI_BYPASS_PATTERNS = ["amsiutils","amsiinitfailed","system.management.automation.amsiutils","etw"];

const MITRE_MAP: Record<string, { id: string; name: string }[]> = {
  URL: [{ id: "T1566", name: "Phishing" }],
  Email: [{ id: "T1566", name: "Phishing" }],
  CVE: [{ id: "T1190", name: "Exploit Public-Facing Application" }],
  ATTACK: [],
  MD5: [{ id: "T1204", name: "User Execution" }],
  SHA256: [{ id: "T1204", name: "User Execution" }],
  Domain: [{ id: "T1583.001", name: "Acquire Infrastructure: Domains" }],
  IPv4: [{ id: "T1071", name: "Application Layer Protocol" }],
};

const KIND_META: Record<string, { icon: any; tone: "default" | "primary" | "warning" | "destructive"; pivot?: string }> = {
  URL:    { icon: Link2,   tone: "warning",     pivot: "/url" },
  Domain: { icon: Globe,   tone: "default",     pivot: "/osint" },
  IPv4:   { icon: Network, tone: "default",     pivot: "/osint" },
  MD5:    { icon: Hash,    tone: "primary",     pivot: "/attachment" },
  SHA256: { icon: Hash,    tone: "primary",     pivot: "/attachment" },
  Email:  { icon: AtSign,  tone: "default",     pivot: "/phishing" },
  CVE:    { icon: Bug,     tone: "destructive" },
  ATTACK: { icon: Crosshair, tone: "destructive", pivot: "/mitre" },
};

interface Signal { title: string; severity: "info" | "warning" | "destructive" | "success"; reason?: string; action?: string; }
interface Secret { type: string; value: string; }
interface CmdFinding { type: string; detail: string; }

function refang(s: string) { return s.replace(/\[\.\]/g, ".").replace(/\(\.\)/g, ".").replace(/\{\.\}/g, ".").replace(/\bhxxp/gi, "http"); }
function defang(s: string) { const r = refang(s); return r.replace(/\./g, "[.]").replace(/\bhttp/gi, "hxxp"); }

function entropy(s: string): number {
  const freq: Record<string, number> = {};
  for (const c of s) freq[c] = (freq[c] || 0) + 1;
  return -Object.values(freq).reduce((sum, n) => { const p = n / s.length; return sum + p * Math.log2(p); }, 0);
}

function dedupSignals(sigs: Signal[]): Signal[] {
  const seen = new Set<string>();
  return sigs.filter((s) => { const k = s.title; if (seen.has(k)) return false; seen.add(k); return true; });
}

function genEmailSignals(t: string): Signal[] {
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

function genUrlSignals(urls: string[]): Signal[] {
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

function genCmdSignals(t: string): Signal[] {
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

function genGeneralSignals(iocs: Record<string, string[]>, total: number): Signal[] {
  const s: Signal[] = [];
  const active = Object.values(iocs).filter((v) => v.length).length;
  if (active >= 4) s.push({ title: "Multiple IOC types", severity: "info", reason: `${active} IOC families detected - broad indicator diversity`, action: "Correlate across workspaces" });
  if (iocs.SHA256.length || iocs.MD5.length) s.push({ title: "File hashes present", severity: "info", reason: "Hashes available for attachment triage and reputation lookup", action: "Send to Attachment Triage" });
  if (iocs.CVE.length) s.push({ title: "CVE references", severity: "warning", reason: `${iocs.CVE.length} known vulnerabilities referenced`, action: "Check patch status and applicable CVEs" });
  if (iocs.ATTACK.length) s.push({ title: "MITRE ATT&CK IDs found", severity: "info", reason: `${iocs.ATTACK.length} technique IDs found - map to detection coverage`, action: "Review MITRE coverage gaps" });
  return s;
}

function scanSecrets(t: string): Secret[] {
  const found: Secret[] = [];
  for (const { type, re } of SECRET_RX) {
    const matches = t.match(re);
    if (matches) {
      for (const m of new Set(matches)) {
        const masked = m.length > 12 ? m.slice(0, 6) + "*".repeat(m.length - 12) + m.slice(-6) : m;
        found.push({ type, value: masked });
      }
    }
  }
  return found;
}

function scanCmdLines(t: string): CmdFinding[] {
  const f: CmdFinding[] = [];
  const tLower = t.toLowerCase();
  for (const bin of LOLBINS) if (tLower.includes(bin)) { f.push({ type: "lolbin", detail: bin }); break; }
  if (DOWNLOAD_CRADLES.some((c) => tLower.includes(c))) f.push({ type: "download", detail: "Download cradle" });
  if (/-EncodedCommand\b/i.test(t)) f.push({ type: "encoded", detail: "Encoded PowerShell" });
  if (AMSI_BYPASS_PATTERNS.some((p) => tLower.includes(p))) f.push({ type: "amsi", detail: "AMSI bypass" });
  if (/-WindowStyle\s+(Hidden|Minimized)/i.test(t)) f.push({ type: "hidden", detail: "Hidden window" });
  return f;
}

function collectSignals(input: string, iocs: Record<string, string[]>, total: number): Signal[] {
  return [
    ...genEmailSignals(input),
    ...genUrlSignals(iocs.URL),
    ...genCmdSignals(input),
    ...genGeneralSignals(iocs, total),
  ];
}

function collectMitre(iocs: Record<string, string[]>, signals: Signal[], cmds: CmdFinding[]): { id: string; name: string; source: string }[] {
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

function computeConfidence(iocs: Record<string, string[]>, signals: Signal[], secrets: Secret[], cmds: CmdFinding[]): { score: number; breakdown: string[] } {
  let score = 10;
  const b: string[] = ["Base confidence: 10%"];
  const active = Object.values(iocs).filter((v) => v.length).length;
  if (iocs.URL.length || iocs.Domain.length || iocs.Email.length) { score += 15; b.push("Communication indicators: +15%"); }
  if (iocs.MD5.length || iocs.SHA256.length) { score += 15; b.push("File hashes: +15%"); }
  if (active >= 3) { score += 10 * Math.min(active - 2, 3); b.push(`IOC diversity (${active} types): +${10 * Math.min(active - 2, 3)}%`); }
  const sigScore = signals.filter((s) => s.severity === "destructive").length * 15 + signals.filter((s) => s.severity === "warning").length * 8 + signals.filter((s) => s.severity === "info").length * 3;
  if (sigScore > 0) { const added = Math.min(sigScore, 30); score += added; b.push(`Signal severity: +${added}%`); }
  if (secrets.length > 0) { score += 10; b.push("Secrets/credentials found: +10%"); }
  if (cmds.length > 0) { score += 10; b.push("Command line findings: +10%"); }
  if (/From:|Subject:|Authentication-Results/i.test(iocs.URL.length ? "" : "")) {} 
  return { score: Math.min(95, Math.round(score)), breakdown: b };
}

function genMarkdownExport(input: string, iocs: Record<string, string[]>, signals: Signal[], total: number, family: string, primary: string, confScore: number, secrets: Secret[], cmds: CmdFinding[], mitre: { id: string; name: string }[]): string {
  const lines = [
    `# Smart Parser Report — ${primary}`,
    `**Family:** ${family}  **IOCs:** ${total}  **Confidence:** ${confScore}%`,
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

function ParserPage() {
  const [input, setInput] = useState("");
  const [tab, setTab] = useState<string>("ALL");
  const [defanged, setDefanged] = useState(true);
  const [copied, setCopied] = useState<string>("");

  const result = useMemo(() => {
    const t = input.trim();
    if (!t) return null;
    const find = (re: RegExp) => Array.from(new Set(t.match(re) ?? []));
    const iocs: Record<string, string[]> = {
      URL: find(RX.URL),
      Domain: find(RX.Domain),
      IPv4: find(RX.IPv4).filter((v) => v.split(/[.\[\]]/).every((x) => !x || +x <= 255)),
      MD5: find(RX.MD5).filter((h) => h.length === 32),
      SHA256: find(RX.SHA256),
      Email: find(RX.Email),
      CVE: find(RX.CVE),
      ATTACK: find(RX.ATTACK),
    };
    const lines = t.split("\n").length;
    const total = Object.values(iocs).reduce((a, b) => a + b.length, 0);

    let family = "Unknown / Notes"; let primary = "Unknown Artifact";
    const reasons: string[] = [];
    if (/From:|Subject:|Authentication-Results/i.test(t)) { family = "Email / Phishing"; primary = "Suspicious Email"; reasons.push("Email envelope headers detected"); }
    if (/Event ID:|sshd\[/.test(t)) { family = "Log / Endpoint"; primary = "Endpoint Log Event"; reasons.push("Log event grammar matched"); }
    if (/event_type.*alert|signature/.test(t)) { family = "Network / Sensor"; primary = "Sensor Alert"; reasons.push("Suricata EVE JSON detected"); }
    if (/^title:|detection:|condition:/m.test(t)) { family = "Detection Rule"; primary = "Sigma-like Rule"; reasons.push("Sigma keys present"); }
    if (/^GET |^POST |^HTTP\/|sqlmap|User-Agent/i.test(t) && /HTTP\/\d\.\d/.test(t)) { family = "Web / Proxy Log"; primary = "HTTP Request Log"; reasons.push("Web log grammar detected"); }
    if (iocs.SHA256.length || iocs.MD5.length) reasons.push("File hashes recovered");
    if (iocs.URL.length) reasons.push("URLs extracted for safe review");

    const secrets = scanSecrets(t);
    const cmds = scanCmdLines(t);
    const signals = collectSignals(t, iocs, total);
    const mitre = collectMitre(iocs, signals, cmds);
    const conf = computeConfidence(iocs, signals, secrets, cmds);
    const urlAnalysis = iocs.URL.length ? iocs.URL.map((u) => {
      try {
        const parsed = new URL(refang(u));
        const host = parsed.hostname;
        const tld = host.split(".").pop()?.toLowerCase();
        return { value: u, host, tld, ipBased: /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host), shortener: SHORTENERS.has(host.replace(/^www\./, "")), suspiciousTld: tld ? SUSPICIOUS_TLDS.has(tld) : false, hasCreds: !!(parsed.username || parsed.password), pathEntropy: entropy(parsed.pathname + parsed.search) };
      } catch { return null; }
    }).filter(Boolean) : [];

    return { family, primary, reasons, lines, total, iocs, secrets, cmds, signals, mitre, conf, urlAnalysis };
  }, [input]);

  const copy = (k: string, txt: string) => { navigator.clipboard.writeText(txt); setCopied(k); setTimeout(() => setCopied(""), 1200); };

  const kinds = result ? Object.entries(result.iocs).filter(([, v]) => v.length) : [];
  const visible = result ? (tab === "ALL" ? kinds : kinds.filter(([k]) => k === tab)) : [];
  const transform = defanged ? defang : refang;

  return (
    <PageShell
      eyebrow="TRIAGE / SMART PARSER"
      title="Smart Parser"
      description="Paste a raw artifact — log, email, IOC list, or rule. The parser surfaces structured indicators and routes you onward."
      crumbs={[{ label: "Triage" }, { label: "Smart Parser" }]}
    >
      <SectionBar id="IN" label="Intake · raw artifact" meta={`${input.length} chars`} />
      <IntakeCard
        icon={Terminal}
        title="Input Terminal"
        value={input}
        onChange={setInput}
        onPaste={(t) => setInput(t)}
        samples={[
          { key: "phishing", label: "Phishing email", hint: "headers + suspicious link" },
          { key: "headers",  label: "Email headers", hint: "auth results + reply-to" },
          { key: "iocs",     label: "Mixed IOCs",     hint: "urls, hashes, CVEs, ATT&CK" },
          { key: "linux",    label: "Linux SSH auth", hint: "failed password + accept" },
          { key: "windows",  label: "Windows 4688",   hint: "EID 4688 process creation" },
          { key: "suricata", label: "Suricata EVE",   hint: "JSON sensor alert" },
          { key: "access",   label: "Web log SQLi",   hint: "SQL injection attempt" },
          { key: "powershell", label: "PowerShell",   hint: "encoded command" },
          { key: "secrets",  label: "Code w/ secrets", hint: "API keys + tokens" },
          { key: "sigma",    label: "Sigma rule",     hint: "detection rule" },
          { key: "notes",    label: "Analyst notes",  hint: "timeline entries" },
        ]}
        onLoadSample={(k) => setInput(SAMPLES[k].text)}
        onFile={(txt) => setInput(txt)}
        run={{ label: "parse", icon: Zap, hint: "⌘↵", onClick: () => { /* auto-parsed */ }, disabled: !input.trim() }}
      />

      <StatusBar
        stats={[
          { label: "Status", value: input.trim() ? "Ready" : "Idle", tone: input.trim() ? "success" : "muted" },
          { label: "Chars", value: input.length.toLocaleString() },
          { label: "Lines", value: input.split("\n").length },
          { label: "IOCs", value: result?.total ?? 0, tone: result?.total ? "warning" : "muted" },
          { label: "Signals", value: result?.signals.length ?? 0, tone: result?.signals.length ? "warning" : "muted" },
          { label: "Mode", value: "session-only", tone: "primary" },
        ]}
      />

      <SectionBar id="OT" label="Output · detected" meta={result ? `${result.total} indicators · ${result.signals.length} signals · ${result.conf.score}% confidence` : "awaiting input"} />
      {!result ? (
        <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
          <Panel title="What the parser recovers" icon={Sparkles} meta="11 samples · 11 IOC families">
            <ul className="grid grid-cols-2 gap-1.5">
              {Object.entries(KIND_META).map(([k, m]) => (
                <li key={k} className="flex items-center gap-2 rounded border border-border/50 bg-card/40 px-2 py-1.5">
                  <m.icon className="h-3.5 w-3.5 text-primary/80 shrink-0" />
                  <span className="text-mono text-[11px] text-foreground/85">{k}</span>
                  {m.pivot && <span className="ml-auto text-mono text-[9px] uppercase tracking-widest text-muted-foreground">→ {m.pivot.slice(1)}</span>}
                </li>
              ))}
            </ul>
          </Panel>
          <Panel title="How analysts use it" icon={Workflow} meta="3-step flow">
            <ol className="space-y-2.5">
              {[
                { i: "01", t: "Paste anything", d: "Email headers, log lines, IOC dumps, Sigma rules, EVE JSON — the parser auto-classifies the family." },
                { i: "02", t: "Inspect inventory", d: "URLs, domains, IPs, hashes, emails, CVEs and ATT&CK IDs are extracted, de-duped, and defanged for safe sharing." },
                { i: "03", t: "Pivot or hand off", d: "One-click pivots to URL, Phishing, Attachment, OSINT, MITRE, or the Case Notebook." },
              ].map((s) => (
                <li key={s.i} className="flex gap-3">
                  <span className="text-mono text-[10px] font-semibold text-primary/80">{s.i}</span>
                  <div>
                    <div className="text-mono text-[11px] uppercase tracking-widest text-foreground">{s.t}</div>
                    <p className="mt-0.5 text-[12px] leading-snug text-muted-foreground">{s.d}</p>
                  </div>
                </li>
              ))}
            </ol>
            <div className="mt-3 flex flex-wrap items-center gap-1.5 border-t border-border/50 pt-3">
              <span className="text-mono text-[10px] uppercase tracking-widest text-muted-foreground">try sample:</span>
              {Object.entries(SAMPLES).map(([k, v]) => (
                <button key={k} onClick={() => setInput(v.text)} className="rounded border border-border bg-card/60 px-2 py-0.5 text-mono text-[10px] uppercase tracking-widest text-muted-foreground hover:border-primary/40 hover:text-primary">{v.label}</button>
              ))}
            </div>
          </Panel>
        </div>
      ) : (
        <div className="space-y-4">
          <ResultBanner
            badge="artifact_parsed"
            caseId={`BA-${result.primary.slice(0, 2).toUpperCase()}${result.lines}`}
            title={result.primary}
            subtitle={result.family}
            reasons={result.reasons}
            metrics={[
              { label: "Family", value: result.family.split(" / ")[0], tone: "primary" },
              { label: "IOCs", value: result.total, tone: "warning" },
              { label: "Signals", value: result.signals.length, tone: result.signals.length >= 3 ? "destructive" : "warning" },
              { label: "Confidence", value: result.conf.score >= 70 ? "high" : result.conf.score >= 40 ? "medium" : "low", tone: result.conf.score >= 70 ? "success" : result.conf.score >= 40 ? "warning" : "default" },
            ]}
          />

          {/* Summary one-liner */}
          <div className="flex items-start gap-3 rounded-md border border-primary/20 bg-primary/5 px-3 py-2.5">
            <FileText className="mt-0.5 h-3.5 w-3.5 text-primary shrink-0" />
            <p className="text-[12px] leading-snug text-foreground/90">
              <span className="text-mono text-[10px] uppercase tracking-widest text-primary">summary · </span>
              Parsed a <strong className="text-foreground">{result.family.toLowerCase()}</strong> artifact across {result.lines} line{result.lines === 1 ? "" : "s"}. Recovered <strong className="text-foreground">{result.total}</strong> indicator{result.total === 1 ? "" : "s"} across {kinds.length} famil{kinds.length === 1 ? "y" : "ies"} with <strong className="text-foreground">{result.conf.score}%</strong> confidence.
              {result.signals.length ? ` ${result.signals.length} signal${result.signals.length === 1 ? "" : "s"} generated.` : ""}
              {result.secrets.length ? ` ${result.secrets.length} potential secret${result.secrets.length === 1 ? "" : "s"} redacted.` : ""}
            </p>
          </div>

          {/* IOC Spectrum */}
          <Panel title="IOC Spectrum" icon={Activity} meta={`${kinds.length} active · ${8 - kinds.length} idle`}>
            <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-4">
              {kinds.map(([k, v]) => {
                const meta = KIND_META[k];
                return (
                  <button
                    key={k}
                    onClick={() => setTab(tab === k ? "ALL" : k)}
                    className={
                      "group flex items-center gap-2.5 rounded-md border px-3 py-2.5 text-left transition-all " +
                      (tab === k ? "border-primary/70 bg-primary/10" : "border-primary/25 bg-primary/[0.04] hover:border-primary/50 hover:bg-primary/[0.08]")
                    }
                  >
                    <span className="grid h-7 w-7 place-items-center rounded border border-primary/40 bg-background/60">
                      <meta.icon className="h-3.5 w-3.5 text-primary" />
                    </span>
                    <span className="flex flex-col min-w-0">
                      <span className="text-mono text-[10px] uppercase tracking-widest text-muted-foreground">{k}</span>
                      <span className="text-mono text-[13px] font-semibold text-foreground">{v.length}</span>
                    </span>
                    <ArrowRight className="ml-auto h-3 w-3 text-muted-foreground transition-transform group-hover:translate-x-0.5 group-hover:text-primary" />
                  </button>
                );
              })}
            </div>
            {kinds.length < 8 && (
              <div className="mt-3 flex flex-wrap items-center gap-1.5 border-t border-border/50 pt-2.5">
                <span className="text-mono text-[10px] uppercase tracking-widest text-muted-foreground">no hits:</span>
                {Object.entries(result.iocs).filter(([, v]) => !v.length).map(([k]) => (
                  <span key={k} className="rounded border border-border/60 bg-card/40 px-1.5 py-0.5 text-mono text-[10px] uppercase tracking-widest text-muted-foreground/70">{k}</span>
                ))}
              </div>
            )}
          </Panel>

          {/* Confidence + Signals */}
          <div className="grid gap-4 lg:grid-cols-[280px_minmax(0,1fr)]">
            <RiskScore score={result.conf.score} label="Confidence" confidence={result.conf.score >= 70 ? "High" : result.conf.score >= 40 ? "Medium" : "Low"} tone={result.conf.score >= 70 ? "success" : result.conf.score >= 40 ? "warning" : "destructive"} />
            <Panel title="Findings & Signals" icon={AlertTriangle} meta={`${result.signals.length} total`}>
              {result.signals.length === 0 ? (
                <p className="text-mono text-[11px] text-muted-foreground">No signals generated for this artifact.</p>
              ) : (
                <div className="space-y-2 max-h-[320px] overflow-y-auto pr-1">
                  {result.signals.map((sig, i) => (
                    <EvidenceCard key={i} severity={sig.severity} title={sig.title} reason={sig.reason} action={sig.action} />
                  ))}
                </div>
              )}
            </Panel>
          </div>

          {/* Secrets + CMD analysis */}
          {result.secrets.length > 0 || result.cmds.length > 0 ? (
            <div className="grid gap-4 lg:grid-cols-2">
              {result.secrets.length > 0 && (
                <Panel title="Secrets Detected" icon={Key} meta={`${result.secrets.length} potential exposure`}>
                  <div className="space-y-1.5">
                    {result.secrets.map((s, i) => (
                      <div key={i} className="flex items-center justify-between gap-2 rounded border border-destructive/30 bg-destructive/5 px-2.5 py-1.5">
                        <span className="text-mono text-[10px] uppercase tracking-widest text-destructive">{s.type}</span>
                        <code className="text-mono text-[11px] text-foreground/80">{s.value}</code>
                      </div>
                    ))}
                  </div>
                </Panel>
              )}
              {result.cmds.length > 0 && (
                <Panel title="Command Line Analysis" icon={Terminal} meta={`${result.cmds.length} findings`}>
                  <div className="space-y-1.5">
                    {result.cmds.map((c, i) => (
                      <div key={i} className="flex items-center gap-2 rounded border border-warning/30 bg-warning/5 px-2.5 py-1.5">
                        <ShieldAlert className="h-3.5 w-3.5 text-warning shrink-0" />
                        <span className="text-mono text-[10px] uppercase tracking-widest text-warning">{c.type}</span>
                        <span className="text-mono text-[11px] text-foreground/80">{c.detail}</span>
                      </div>
                    ))}
                  </div>
                </Panel>
              )}
            </div>
          ) : null}

          {/* URL analysis */}
          {result.urlAnalysis.length > 0 && (
            <Panel title="URL Deep Analysis" icon={Link2} meta={`${result.urlAnalysis.length} URLs`}>
              <div className="space-y-2">
                {result.urlAnalysis.map((u: any, i: number) => (
                  <div key={i} className="flex flex-wrap items-center gap-2 rounded border border-border/50 bg-card/40 px-3 py-2">
                    <code className="min-w-0 flex-1 truncate text-mono text-[11px] text-foreground/90">{defang ? defang(u.value) : refang(u.value)}</code>
                    <div className="flex flex-wrap items-center gap-1">
                      {u.suspiciousTld && <Chip tone="warning">suspicious TLD</Chip>}
                      {u.shortener && <Chip tone="warning">shortener</Chip>}
                      {u.ipBased && <Chip tone="warning">IP-based</Chip>}
                      {u.hasCreds && <Chip tone="destructive">embedded creds</Chip>}
                      {u.pathEntropy > 4.5 && <Chip tone="info">high entropy</Chip>}
                      {!u.suspiciousTld && !u.shortener && !u.ipBased && !u.hasCreds && u.pathEntropy <= 4.5 && <Chip tone="success">clean</Chip>}
                    </div>
                  </div>
                ))}
              </div>
            </Panel>
          )}

          {/* MITRE Mapping */}
          {result.mitre.length > 0 && (
            <Panel title="MITRE ATT&CK Mapping" icon={Crosshair} meta={`${result.mitre.length} techniques`}>
              <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
                {result.mitre.map((m: any, i: number) => (
                  <div key={i} className="flex items-center gap-2.5 rounded border border-border/50 bg-card/40 px-3 py-2">
                    <span className="grid h-7 w-7 place-items-center rounded border border-destructive/40 bg-destructive/10">
                      <Crosshair className="h-3.5 w-3.5 text-destructive" />
                    </span>
                    <div>
                      <div className="text-mono text-[10px] font-semibold uppercase tracking-widest text-destructive">{m.id}</div>
                      <div className="text-mono text-[11px] text-foreground/80">{m.name}</div>
                    </div>
                    <Chip tone="info">{m.source}</Chip>
                  </div>
                ))}
              </div>
            </Panel>
          )}

          {/* Tabbed IOC explorer */}
          <Panel>
            <div className="-mt-1 mb-3 flex flex-wrap items-center justify-between gap-2 border-b border-border/50 pb-2">
              <div className="flex flex-wrap items-center gap-1">
                <button onClick={() => setTab("ALL")} className={tabBtn(tab === "ALL")}>all · {result.total}</button>
                {kinds.map(([k, v]) => (
                  <button key={k} onClick={() => setTab(k)} className={tabBtn(tab === k)}>{k.toLowerCase()} · {v.length}</button>
                ))}
              </div>
              <div className="flex items-center gap-1">
                <span className="text-mono text-[10px] uppercase tracking-widest text-muted-foreground">render</span>
                <button onClick={() => setDefanged(true)} className={toggleBtn(defanged)}>defang</button>
                <button onClick={() => setDefanged(false)} className={toggleBtn(!defanged)}>raw</button>
              </div>
            </div>

            <div className="space-y-4">
              {visible.map(([kind, items]) => {
                const meta = KIND_META[kind];
                const Icon = meta.icon;
                const allText = items.map(transform).join("\n");
                return (
                  <div key={kind}>
                    <div className="mb-1.5 flex items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <Icon className="h-3.5 w-3.5 text-primary" />
                        <span className="text-mono text-[11px] uppercase tracking-widest text-foreground">{kind}</span>
                        <Chip tone={meta.tone}>{items.length}</Chip>
                      </div>
                      <div className="flex items-center gap-1">
                        <button onClick={() => copy(kind, allText)} className="inline-flex items-center gap-1 rounded border border-border bg-card/60 px-1.5 py-0.5 text-mono text-[10px] uppercase tracking-widest text-muted-foreground hover:text-foreground">
                          {copied === kind ? <><Check className="h-3 w-3" /> copied</> : <><Copy className="h-3 w-3" /> copy all</>}
                        </button>
                        {meta.pivot && (
                          <a href={meta.pivot} className="inline-flex items-center gap-1 rounded border border-primary/40 bg-primary/10 px-1.5 py-0.5 text-mono text-[10px] uppercase tracking-widest text-primary hover:bg-primary/20">
                            pivot <ArrowRight className="h-3 w-3" />
                          </a>
                        )}
                      </div>
                    </div>
                    <ul className="grid gap-1 sm:grid-cols-2">
                      {items.map((it) => (
                        <li key={it} className="group flex items-center justify-between gap-2 rounded border border-border/50 bg-card/40 px-2 py-1 hover:border-primary/40 hover:bg-card/70">
                          <code className="truncate text-mono text-[11px] text-foreground/90">{transform(it)}</code>
                          <button onClick={() => copy(it, transform(it))} className="opacity-0 transition-opacity group-hover:opacity-100">
                            {copied === it ? <Check className="h-3 w-3 text-success" /> : <Copy className="h-3 w-3 text-muted-foreground hover:text-foreground" />}
                          </button>
                        </li>
                      ))}
                    </ul>
                  </div>
                );
              })}
            </div>
          </Panel>

          {/* Export + Handoff */}
          <div className="grid gap-4 lg:grid-cols-[1fr_2fr]">
            <Panel title="Export Report" icon={Download}>
              <button
                onClick={() => {
                  const md = genMarkdownExport(input, result.iocs, result.signals, result.total, result.family, result.primary, result.conf.score, result.secrets, result.cmds, result.mitre);
                  const blob = new Blob([md], { type: "text/markdown" });
                  const url = URL.createObjectURL(blob);
                  const a = document.createElement("a"); a.href = url; a.download = `parser-report-${Date.now()}.md`; a.click();
                  URL.revokeObjectURL(url);
                }}
                className="group inline-flex w-full items-center justify-center gap-2 rounded border border-primary/50 bg-primary/10 px-4 py-2 text-mono text-[10px] uppercase tracking-widest text-primary transition-all hover:bg-primary/20"
              >
                <Download className="h-3.5 w-3.5" />
                Download Markdown
              </button>
              <p className="mt-2 text-[11px] text-muted-foreground">Includes all indicators, signals, secrets, and MITRE mapping.</p>
            </Panel>
            <SendToRow targets={[
              { label: "Phishing Triage", to: "/phishing", icon: Mail },
              { label: "Safe URL Analyzer", to: "/url", icon: Link2 },
              { label: "Attachment Triage", to: "/attachment", icon: FileWarning },
              { label: "Detection & MITRE", to: "/mitre", icon: Crosshair },
              { label: "Logs & Alerts", to: "/logs", icon: Database },
            ]} />
          </div>
        </div>
      )}
    </PageShell>
  );
}

const tabBtn = (active: boolean) =>
  "rounded border px-2 py-0.5 text-mono text-[10px] uppercase tracking-widest transition-colors " +
  (active ? "border-primary/60 bg-primary/15 text-primary" : "border-border/60 bg-card/40 text-muted-foreground hover:text-foreground");

const toggleBtn = (active: boolean) =>
  "rounded border px-1.5 py-0.5 text-mono text-[10px] uppercase tracking-widest " +
  (active ? "border-primary/60 bg-primary/15 text-primary" : "border-border/60 bg-card/40 text-muted-foreground hover:text-foreground");
