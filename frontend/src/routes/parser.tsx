import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { useEffect, useMemo, useRef, useState, useCallback } from "react";
import { useMutation } from "@tanstack/react-query";
import { PageShell } from "@/components/PageShell";
import { IntakeCard, SendToRow, SectionBar, Panel, Chip } from "@/components/soc";
import { StatusBar, ResultBanner, EvidenceCard } from "@/components/output";
import {
  Zap, Terminal, ArrowRight, Database, Mail, Link2,
  FileWarning, Activity, Globe, Hash, AtSign, Bug, Crosshair, Network, Copy, Check,
  Sparkles, FileText, Workflow, AlertTriangle, ShieldAlert, Key, Download,
  Scan, Loader2,
} from "lucide-react";
import { SECRET_RX, SUSPICIOUS_TLDS, SHORTENERS, LOLBINS, DOWNLOAD_CRADLES, AMSI_BYPASS_PATTERNS, refang, defang, entropy, scanSecrets, type Secret } from "@/lib/ioc-patterns";
import { useLocker, type LockerItem } from "@/lib/locker";
import { IocChip } from "@/components/IocChip";
import { AttachButton } from "@/components/AttachButton";
import { usePanelNav } from "@/lib/usePanelNav";
import { sendToCase } from "@/lib/handoff";

const IOC_KIND_MAP: Record<string, string> = {
  URL: "url", Domain: "domain", IPv4: "ip", Email: "email",
  MD5: "hash", SHA256: "hash", CVE: "raw", ATTACK: "raw", MAC: "raw", Base64: "raw",
};
import { analyzeFullEmail } from "@/api/phishing";
import { passiveRecon } from "@/api/recon";
import { pushTimelineEvent } from "@/lib/timeline";
import { mapMitre } from "@/api/detection";
import { OsintTools } from "@/components/OsintTools";
import { toast } from "sonner";

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

  email_headers: { label: "Sample email headers", text: "From: \"Security Team\" <security@company.com>\nTo: user@example.org\nSubject: Urgent: Action required on your account\nDate: Mon, 15 Jun 2026 09:23:45 +0000\nReturn-Path: bounce@phish-target.tk\nReply-To: security-verify@phish-target.tk\nReceived: from mx.phish-target.tk (203.0.113.50) by mx.company.com with ESMTPS id ABC123\nReceived-SPF: fail (domain of phish-target.tk does not designate 203.0.113.50 as permitted sender)\nAuthentication-Results: mx.company.com; spf=fail smtp.mailfrom=phish-target.tk; dkim=none; dmarc=fail\nDKIM-Signature: v=1; a=rsa-sha256; d=phish-target.tk; s=selector1;\n bh=2bd0e4a8c9f1b3d5e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9;\nX-Priority: 1 (Highest)\nMIME-Version: 1.0\nContent-Type: text/plain; charset=\"UTF-8\"\n\nDear User,\n\nWe detected suspicious activity on your account. Please verify your identity immediately by clicking the link below:\n\nhttps://login-company.secure-phish.tk/verify?token=abc123def456\n\nFailure to verify within 24 hours will result in account suspension.\n\nThank you,\nSecurity Team" },

  ioc_list: { label: "Sample IOC list", text: "45.33.32.156\n185.94.188.22\n91.121.87.34\n198.51.100.23\n203.0.113.44\n51.15.0.100\nhxxps[:]//evil[.]com/setup.exe\nhxxps[:]//phish-login[.]tk/verify\nhttp://185[.]220[.]101[.]161/payload.ps1\nhxxp://malware[.]download/payload\nexample[.]net\nmalicious[.]com\nphish-target[.]tk\nevil-host[.]ru\n7e0eaa6c2a2c7a0d5c4a3d8e9f0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a\na1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2\n44d88612fea8a8f36de82e1278abb02f\nCVE-2024-1234\nCVE-2025-5678\nT1566.002\nT1059.001\nT1204\nphish@evil-host[.]ru\nadmin@malicious[.]com" },
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

const RX_MAC = /\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b/g;
const RX_B64 = /\b(?:[A-Za-z0-9+/]{40,}(?:==|=)?)\b/g;

function autoDetectInputType(text: string): { label: string; tone: "primary" | "success" | "warning" | "info" | "default" } | null {
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

interface Signal { title: string; severity: "info" | "warning" | "destructive" | "success"; reason?: string; action?: string; }
interface CmdFinding { type: string; detail: string; }

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

function genMarkdownExport(input: string, iocs: Record<string, string[]>, signals: Signal[], total: number, family: string, primary: string, secrets: Secret[], cmds: CmdFinding[], mitre: { id: string; name: string }[]): string {
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

function genJsonExport(input: string, iocs: Record<string, string[]>, signals: Signal[], total: number, family: string, primary: string, secrets: Secret[], cmds: CmdFinding[], mitre: { id: string; name: string }[]): string {
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

function ParserPage() {
  const [input, setInput] = useState("");
  const [tab, setTab] = useState<string>("ALL");
  const [focusedKind, setFocusedKind] = useState<string | null>(null);
  const [defanged, setDefanged] = useState(true);
  const [copied, setCopied] = useState<string>("");
  const deepScanMutation = useMutation({
    mutationFn: async ({ inputText, hasDomains, hasIps, hasEmails }: { inputText: string; hasDomains: boolean; hasIps: boolean; hasEmails: boolean }) => {
      const r: Record<string, unknown> = {};
      const run = async (label: string, fn: () => Promise<unknown>) => {
        try { r[label] = await fn(); } catch { r[label] = { error: "unavailable" }; }
      };
      const promises: Promise<void>[] = [];
      if (hasDomains || hasIps) promises.push(run("recon", () => passiveRecon(inputText)));
      if (hasEmails) {
        const lines = inputText.trim().split("\n");
        const headerEnd = lines.findIndex((l) => l.trim() === "");
        const headers = headerEnd > 0 ? lines.slice(0, headerEnd).join("\n") : inputText.trim();
        const body = headerEnd > 0 ? lines.slice(headerEnd).join("\n") : "";
        promises.push(run("phishing", () => analyzeFullEmail(headers, body, true)));
      }
      promises.push(run("mitre", () => mapMitre(inputText)));
      await Promise.all(promises);
      return r;
    },
    onSuccess: () => { toast.success("Deep scan complete"); },
  });
  const locker = useLocker();

  const inputType = useMemo(() => autoDetectInputType(input), [input]);

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
      MAC: Array.from(new Set(t.match(RX_MAC) ?? [])),
      Base64: Array.from(new Set((t.match(RX_B64) ?? []).filter((s: string) => s.length % 4 === 0 && !/^[a-f0-9]{32,64}$/i.test(s)))),
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
    const urlAnalysis = iocs.URL.length ? iocs.URL.map((u) => {
      try {
        const parsed = new URL(refang(u));
        const host = parsed.hostname;
        const tld = host.split(".").pop()?.toLowerCase();
        return { value: u, host, tld, ipBased: /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host), shortener: SHORTENERS.has(host.replace(/^www\./, "")), suspiciousTld: tld ? SUSPICIOUS_TLDS.has(tld) : false, hasCreds: !!(parsed.username || parsed.password), pathEntropy: entropy(parsed.pathname + parsed.search) };
      } catch { return null; }
    }).filter(Boolean) : [];

    return { family, primary, reasons, lines, total, iocs, secrets, cmds, signals, mitre, urlAnalysis };
  }, [input]);

  const pushedRef = useRef(0);
  useEffect(() => {
    if (result && result.total > 0 && pushedRef.current !== result.total + result.lines) {
      pushedRef.current = result.total + result.lines;
      pushTimelineEvent({ source: "parser", verb: "extracted", detail: `Extracted ${result.total} IOCs from ${result.family}`, result: `${result.total} indicators` });
    }
  }, [result]);

  const copy = (k: string, txt: string) => { try { navigator.clipboard.writeText(txt); } catch {/* noop */} setCopied(k); setTimeout(() => setCopied(""), 1200); };

  const kinds = result ? Object.entries(result.iocs).filter(([, v]) => v.length) : [];
  const visible = result ? (tab === "ALL" ? kinds : kinds.filter(([k]) => k === tab)) : [];
  const transform = defanged ? defang : refang;

  const flatIocs = useMemo(() => {
    return visible.flatMap(([kind, items]) =>
      (items as string[]).map((value) => ({ value, kind }))
    );
  }, [visible]);

  const navigate = useNavigate();
  const { index: iocIndex, selected: selectedIoc } = usePanelNav(flatIocs, {
    onCopy: (item) => {
      navigator.clipboard.writeText(transform(item.value));
      toast.success("Copied");
    },
    onEnrich: (item) => {
      navigate({ to: "/recon", search: { q: item.value } });
    },
    onAttach: (item) => {
      const kind = IOC_KIND_MAP[item.kind] ?? "raw";
      sendToCase({ body: item.value, source: "/parser", kind });
      toast.success("Sent to case");
    },
    onContext: (item) => {
      toast(`Context: ${item.value}`);
    },
  });

  const hasIps = (result?.iocs.IPv4.length ?? 0) > 0;
  const hasDomains = (result?.iocs.Domain.length ?? 0) > 0;
  const hasEmails = (result?.iocs.Email.length ?? 0) > 0;
  const canDeepScan = hasIps || hasDomains || hasEmails;

  const handleDeepScan = useCallback(() => {
    if (!result) return;
    deepScanMutation.mutate({
      inputText: input.trim(),
      hasDomains,
      hasIps,
      hasEmails,
    });
  }, [result, input, hasDomains, hasIps, hasEmails]);

  function quickLookups(): { label: string; url: string }[] {
    const all: { label: string; url: string }[] = [];
    const add = (label: string, url: string) => all.push({ label, url });
    if (hasDomains || hasIps) {
      add("VirusTotal", `https://www.virustotal.com/gui/search/${encodeURIComponent(input.trim())}`);
      if (hasDomains) {
        add("crt.sh", `https://crt.sh/?q=${encodeURIComponent(input.trim())}`);
        add("Shodan", `https://www.shodan.io/search?query=${encodeURIComponent(input.trim())}`);
      }
      if (hasIps) {
        add("AbuseIPDB", `https://www.abuseipdb.com/check/${encodeURIComponent(input.trim())}`);
        add("GreyNoise", `https://viz.greynoise.io/ip/${encodeURIComponent(input.trim())}`);
      }
    }
    if (result?.iocs.URL.length) {
      add("VirusTotal", `https://www.virustotal.com/gui/search/${encodeURIComponent(input.trim())}`);
      add("urlscan.io", `https://urlscan.io/search/#${encodeURIComponent(input.trim())}`);
    }
    if (result?.iocs.MD5.length || result?.iocs.SHA256.length) {
      add("VirusTotal", `https://www.virustotal.com/gui/search/${encodeURIComponent(input.trim())}`);
      add("AlienVault OTX", `https://otx.alienvault.com/browse/global/pulses?q=${encodeURIComponent(input.trim())}`);
    }
    add("Google", `https://www.google.com/search?q=${encodeURIComponent(input.trim())}`);
    return all;
  }

  const reportMd = useMemo(() => {
    if (!result) return "";
    const lines = [
      `# Smart Parser Report`,
      `**Family:** ${result.family}  **Primary:** ${result.primary}  **IOCs:** ${result.total}`,
      `**Generated:** ${new Date().toISOString()}`,
      "",
    ];
    for (const [kind, items] of Object.entries(result.iocs)) {
      if (items.length) lines.push(`## ${kind} (${items.length})`, ...items.map((i: string) => `- ${i}`), "");
    }
    if (result.signals.length) lines.push("## Signals", ...result.signals.map((s: any) => `- [${s.severity.toUpperCase()}] ${s.title}${s.reason ? " — " + s.reason : ""}`));
    if (deepScanMutation.data?.recon) {
      const r = deepScanMutation.data.recon as Record<string, unknown>;
      lines.push("", "## Reconnaissance", `- Target: ${(r.target as Record<string, string>)?.hostname ?? "—"}`);
    }
    if (deepScanMutation.data?.phishing) {
      const p = deepScanMutation.data.phishing as Record<string, unknown>;
      lines.push("", "## Phishing Analysis", `- Verdict: ${(p as Record<string, string>).verdict ?? "—"}`);
    }
    return lines.join("\n");
  }, [result, deepScanMutation.data]);

  return (
    <PageShell
      eyebrow="INVESTIGATION"
      title="Investigation"
      description="Analyze artifacts, extract IOCs, and run OSINT lookups — all from one workspace."
      crumbs={[{ label: "Investigation" }, { label: "Parser" }]}
    >
      <SectionBar id="IN" label="Intake · raw artifact" meta={`${input.length} chars`} action={inputType && <Chip tone={inputType.tone}>{inputType.label}</Chip>} />
      <IntakeCard
        icon={Terminal}
        title="Input Terminal"
        value={input}
        onChange={(t) => { setInput(t); deepScanMutation.reset(); }}
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
          { key: "email_headers", label: "Sample email headers", hint: "full headers + auth results" },
          { key: "ioc_list", label: "Sample IOC list", hint: "IPs, hashes, domains, CVEs" },
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

      <SectionBar id="OT" label="Output · detected" meta={result ? `${result.total} indicators · ${result.signals.length} signals` : "awaiting input"} action={result ? <AttachButton body={JSON.stringify(result.iocs, null, 2)} kind="evidence" source="/parser" /> : undefined} />
      {!result ? (
        <div className="grid gap-4 grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
          <Panel title="What the parser recovers" icon={Sparkles} meta="11 samples · 11 IOC families" priority="secondary">
            <ul className="grid grid-cols-2 gap-1.5">
              {Object.entries(KIND_META).map(([k, m]) => (
                <li key={k} className="flex items-center gap-2 rounded border border-border/50 bg-card/40 px-2 py-1.5">
                  <m.icon className="h-3.5 w-3.5 text-primary/80 shrink-0" />
                  <span className="text-mono ba-text-sm text-foreground/85">{k}</span>
                  {m.pivot && <span className="ml-auto text-mono text-[9px] uppercase tracking-widest text-muted-foreground">→ {m.pivot.slice(1)}</span>}
                </li>
              ))}
            </ul>
          </Panel>
          <Panel title="How analysts use it" icon={Workflow} meta="3-step flow" priority="secondary">
            <ol className="space-y-2.5">
              {[
                { i: "01", t: "Paste anything", d: "Email headers, log lines, IOC dumps, Sigma rules, EVE JSON — the parser auto-classifies the family." },
                { i: "02", t: "Inspect inventory", d: "URLs, domains, IPs, hashes, emails, CVEs and ATT&CK IDs are extracted, de-duped, and defanged for safe sharing." },
                { i: "03", t: "Pivot or hand off", d: "One-click pivots to URL, Phishing, Attachment, Recon, MITRE, or the Case Notebook." },
              ].map((s) => (
                <li key={s.i} className="flex gap-3">
                  <span className="text-mono ba-text-2xs font-semibold text-primary/80">{s.i}</span>
                  <div>
                    <div className="text-mono ba-text-sm uppercase tracking-widest text-foreground">{s.t}</div>
                    <p className="mt-0.5 ba-text-base leading-snug text-muted-foreground">{s.d}</p>
                  </div>
                </li>
              ))}
            </ol>

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
            ]}
          />

          {/* Summary one-liner */}
          <div className="flex items-start gap-3 rounded-md border border-primary/20 bg-primary/5 px-3 py-2.5">
            <FileText className="mt-0.5 h-3.5 w-3.5 text-primary shrink-0" />
            <p className="ba-text-base leading-snug text-foreground/90">
              <span className="text-mono ba-text-2xs uppercase tracking-widest text-primary">summary · </span>
              Parsed a <strong className="text-foreground">{result.family.toLowerCase()}</strong> artifact across {result.lines} line{result.lines === 1 ? "" : "s"}. Recovered <strong className="text-foreground">{result.total}</strong> indicator{result.total === 1 ? "" : "s"} across {kinds.length} famil{kinds.length === 1 ? "y" : "ies"}.
              {result.signals.length ? ` ${result.signals.length} signal${result.signals.length === 1 ? "" : "s"} generated.` : ""}
              {result.secrets.length ? ` ${result.secrets.length} potential secret${result.secrets.length === 1 ? "" : "s"} redacted.` : ""}
            </p>
          </div>

          {/* Deep Scan */}
          {canDeepScan && (
            <div className="flex items-center justify-between rounded-md border border-dashed border-primary/30 bg-primary/[0.02] px-3.5 py-2.5">
              <div className="flex items-center gap-2.5">
                <Scan className="h-4 w-4 text-primary/70" />
                <div>
                  <span className="text-mono ba-text-2xs uppercase tracking-widest text-primary">deep scan available</span>
                  <p className="text-[11px] text-muted-foreground/80 mt-0.5">
                    {hasDomains && hasIps ? "Domains and IPs" : hasDomains ? "Domains" : hasIps ? "IPs" : ""}
                    {hasEmails ? `${hasDomains || hasIps ? " and " : ""}Email headers` : ""} detected — run passive recon, phishing check, and MITRE enrichment.
                  </p>
                </div>
              </div>
              <button
                onClick={handleDeepScan}
                disabled={deepScanMutation.isPending}
                className="inline-flex items-center gap-1.5 rounded border border-primary/50 bg-primary/10 px-3 py-1.5 text-mono ba-text-2xs uppercase tracking-widest text-primary transition-colors hover:bg-primary/20 disabled:opacity-40 shrink-0"
              >
                {deepScanMutation.isPending ? <Loader2 className="h-3 w-3 animate-spin" /> : <Scan className="h-3 w-3" />}
                {deepScanMutation.isPending ? "scanning..." : "deep scan"}
              </button>
            </div>
          )}

          {/* IOC Spectrum */}
          <Panel title="IOC Spectrum" icon={Activity} meta={`${kinds.length} active · ${8 - kinds.length} idle`}>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
              {kinds.map(([k, v]) => {
                const meta = KIND_META[k];
                return (
                  <button
                    key={k}
                    onClick={() => setFocusedKind(k)}
                    title={`Click to focus ${k} detail view`}
                    className={
                      "group flex items-center gap-2.5 rounded-md border px-3 py-2.5 text-left transition-all " +
                      (tab === k ? "border-primary/70 bg-primary/10" : "border-primary/25 bg-primary/[0.04] hover:border-primary/50 hover:bg-primary/[0.08]")
                    }
                  >
                    <span className="grid h-7 w-7 place-items-center rounded border border-primary/40 bg-background/60">
                      <meta.icon className="h-3.5 w-3.5 text-primary" />
                    </span>
                    <span className="flex flex-col min-w-0">
                      <span className="text-mono ba-text-2xs uppercase tracking-widest text-muted-foreground">{k}</span>
                      <span className="text-mono ba-text-base font-semibold text-foreground">{v.length}</span>
                    </span>
                    <ArrowRight className="ml-auto h-3 w-3 text-muted-foreground transition-transform group-hover:translate-x-0.5 group-hover:text-primary" />
                  </button>
                );
              })}
            </div>
            {kinds.length < 8 && (
              <div className="mt-3 flex flex-wrap items-center gap-1.5 border-t border-border/50 pt-2.5">
                <span className="text-mono ba-text-2xs uppercase tracking-widest text-muted-foreground">no hits:</span>
                {Object.entries(result.iocs).filter(([, v]) => !v.length).map(([k]) => (
                  <span key={k} className="rounded border border-divider-strong bg-card/40 px-1.5 py-0.5 text-mono ba-text-2xs uppercase tracking-widest text-muted-foreground/70">{k}</span>
                ))}
              </div>
            )}
          </Panel>

          {/* Zoomed detail view */}
          {focusedKind && (() => {
            const k = focusedKind;
            const items = result.iocs[k];
            const meta = KIND_META[k as keyof typeof KIND_META];
            if (!meta || !items?.length) return null;
            const Icon = meta.icon;
            const allText = items.map(transform).join("\n");
            return (
              <Panel
                title={`Detail · ${k}`}
                icon={Icon}
                meta={`${items.length} item${items.length === 1 ? "" : "s"}`}
                actions={
                  <button onClick={() => setFocusedKind(null)}
                    className="rounded border border-primary/40 bg-primary/10 px-2 py-0.5 text-mono ba-text-2xs uppercase tracking-widest text-primary hover:bg-primary/20">
                    zoom out
                  </button>
                }
              >
                <div className="space-y-2">
                  <div className="flex items-center justify-between gap-2">
                    <div className="flex items-center gap-2 text-mono ba-text-2xs uppercase tracking-widest text-muted-foreground">
                      <span>{k}</span>
                      <Chip tone={meta.tone}>{items.length}</Chip>
                    </div>
                    <div className="flex items-center gap-1.5">
                      <button onClick={() => copy(k, allText)} className="inline-flex items-center gap-1 rounded border border-border bg-card/60 px-2 py-1 text-mono ba-text-2xs uppercase tracking-widest text-muted-foreground hover:text-foreground">
                        {copied === k ? <><Check className="h-3 w-3" /> copied</> : <><Copy className="h-3 w-3" /> copy all</>}
                      </button>
                      <button onClick={() => { items.forEach((v: string) => locker.add({ value: v, type: k.toLowerCase() as LockerItem["type"], source: "/parser" })); }} className="inline-flex items-center gap-1 rounded border border-divider-strong bg-card/60 px-2 py-1 text-mono ba-text-2xs uppercase tracking-widest text-muted-foreground hover:text-primary">
                        <Hash className="h-3 w-3" /> locker
                      </button>
                      {meta.pivot && (
                        <Link to={meta.pivot} className="inline-flex items-center gap-1 rounded border border-primary/40 bg-primary/10 px-2 py-1 text-mono ba-text-2xs uppercase tracking-widest text-primary hover:bg-primary/20">
                          pivot <ArrowRight className="h-3 w-3" />
                        </Link>
                      )}
                    </div>
                  </div>
                  <div className="max-h-[50vh] overflow-y-auto rounded border border-border/50 bg-background/40">
                    {items.map((it: string, idx: number) => (
                      <div key={idx} className={`flex items-center justify-between gap-2 border-b border-divider-soft px-3 py-1.5 transition-colors ${
                        selectedIoc && selectedIoc.value === it && selectedIoc.kind === k
                          ? "bg-primary/5 ring-1 ring-primary/30"
                          : "hover:bg-primary/[0.03]"
                      }`}>
                        <IocChip kind={(IOC_KIND_MAP[k] ?? "raw") as any} value={transform(it)} />
                        <div className="flex items-center gap-1">
                          {k === "URL" && (
                            <Link to="/url" className="rounded border border-primary/30 bg-primary/10 px-1.5 py-0.5 text-mono text-[9px] uppercase tracking-widest text-primary hover:bg-primary/20">analyze</Link>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </Panel>
            );
          })()}

          {/* Confidence + Signals */}
          <div className="grid gap-4 grid-cols-[280px_minmax(0,1fr)]">
            <Panel title="Findings & Signals" icon={AlertTriangle} meta={`${result.signals.length} total`}>
              {result.signals.length === 0 ? (
                <p className="text-mono ba-text-sm text-muted-foreground">No signals generated for this artifact.</p>
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
            <div className="grid gap-4 grid-cols-2">
              {result.secrets.length > 0 && (
                <Panel title="Secrets Detected" icon={Key} meta={`${result.secrets.length} potential exposure`} priority="secondary">
                  <div className="space-y-1.5">
                    {result.secrets.map((s, i) => (
                      <div key={i} className="flex items-center justify-between gap-2 rounded border border-destructive/30 bg-destructive/5 px-2.5 py-1.5">
                        <span className="text-mono ba-text-2xs uppercase tracking-widest text-destructive">{s.type}</span>
                        <code className="text-mono ba-text-sm text-foreground/80">{s.value}</code>
                      </div>
                    ))}
                  </div>
                </Panel>
              )}
              {result.cmds.length > 0 && (
                <Panel title="Command Line Analysis" icon={Terminal} meta={`${result.cmds.length} findings`} priority="secondary">
                  <div className="space-y-1.5">
                    {result.cmds.map((c, i) => (
                      <div key={i} className="flex items-center gap-2 rounded border border-warning/30 bg-warning/5 px-2.5 py-1.5">
                        <ShieldAlert className="h-3.5 w-3.5 text-warning shrink-0" />
                        <span className="text-mono ba-text-2xs uppercase tracking-widest text-warning">{c.type}</span>
                        <span className="text-mono ba-text-sm text-foreground/80">{c.detail}</span>
                      </div>
                    ))}
                  </div>
                </Panel>
              )}
            </div>
          ) : null}

          {/* URL analysis */}
          {result.urlAnalysis.length > 0 && (
            <Panel title="URL Deep Analysis" icon={Link2} meta={`${result.urlAnalysis.length} URLs`} priority="secondary">
              <div className="space-y-2">
                {result.urlAnalysis.map((u: any, i: number) => (
                  <div key={i} className="flex flex-wrap items-center gap-2 rounded border border-border/50 bg-card/40 px-3 py-2">
                    <code className="min-w-0 flex-1 truncate text-mono ba-text-sm text-foreground/90">{defang ? defang(u.value) : refang(u.value)}</code>
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
            <Panel title="MITRE ATT&CK Mapping" icon={Crosshair} meta={`${result.mitre.length} techniques`} priority="secondary">
              <div className="grid gap-2 grid-cols-3">
                {result.mitre.map((m: any, i: number) => (
                  <div key={i} className="flex items-center gap-2.5 rounded border border-border/50 bg-card/40 px-3 py-2">
                    <span className="grid h-7 w-7 place-items-center rounded border border-destructive/40 bg-destructive/10">
                      <Crosshair className="h-3.5 w-3.5 text-destructive" />
                    </span>
                    <div>
                      <div className="text-mono ba-text-2xs font-semibold uppercase tracking-widest text-destructive">{m.id}</div>
                      <div className="text-mono ba-text-sm text-foreground/80">{m.name}</div>
                    </div>
                    <Chip tone="info">{m.source}</Chip>
                  </div>
                ))}
              </div>
            </Panel>
          )}

          {/* External Lookups */}
          {result && (hasDomains || hasIps || result.iocs.URL.length || result.iocs.MD5.length || result.iocs.SHA256.length) && (() => {
            const lookups = quickLookups();
            return (
              <Panel title="External Lookups" icon={Globe} meta={`${lookups.length} source(s)`} priority="secondary" collapsible storageKey="ba.panel.parser.lookups">
                <div className="flex flex-wrap gap-1.5">
                  {lookups.map((l) => (
                    <a key={l.label} href={l.url} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 rounded border border-divider-strong bg-card/40 px-2.5 py-1 text-mono ba-text-2xs uppercase tracking-widest text-muted-foreground transition-colors hover:border-primary/50 hover:text-primary">
                      <Globe className="h-3 w-3" /> {l.label}
                    </a>
                  ))}
                </div>
              </Panel>
            );
          })()}

          {/* Deep Scan Results */}
          {deepScanMutation.data && (
            <>
              {deepScanMutation.data.phishing && !(deepScanMutation.data.phishing as Record<string, string>).error && (
                <Panel title="Phishing Analysis" icon={Mail} meta="from deep scan" priority="secondary">
                  <div className="space-y-1">
                    {[["Verdict", (deepScanMutation.data.phishing as Record<string, string>).verdict], ["SPF", (deepScanMutation.data.phishing as any)?.authentication?.spf], ["DKIM", (deepScanMutation.data.phishing as any)?.authentication?.dkim], ["DMARC", (deepScanMutation.data.phishing as any)?.authentication?.dmarc]].filter(([, v]) => v).map(([k, v]) => (
                      <div key={k} className="flex items-center gap-2 text-mono ba-text-sm">
                        <span className="text-muted-foreground uppercase tracking-widest ba-text-2xs">{k}</span>
                        <span className="text-foreground/90">{v}</span>
                      </div>
                    ))}
                  </div>
                </Panel>
              )}
              {deepScanMutation.data.recon && !(deepScanMutation.data.recon as Record<string, string>).error && (
                <Panel title="Recon Results" icon={Globe} meta="from deep scan" priority="secondary">
                  <div className="space-y-1">
                    {[["Target", (deepScanMutation.data.recon as any)?.target?.hostname], ["Type", (deepScanMutation.data.recon as any)?.target?.type], ["HTTP Status", (deepScanMutation.data.recon as any)?.http?.status_code], ["TLS", (deepScanMutation.data.recon as any)?.ssl ? "Present" : null]].filter(([, v]) => v).map(([k, v]) => (
                      <div key={k} className="flex items-center gap-2 text-mono ba-text-sm">
                        <span className="text-muted-foreground uppercase tracking-widest ba-text-2xs">{k}</span>
                        <span className="text-foreground/90">{v}</span>
                      </div>
                    ))}
                  </div>
                </Panel>
              )}
              {deepScanMutation.data.mitre && !(deepScanMutation.data.mitre as Record<string, string>).error && (
                <Panel title="MITRE ATT&CK Mapping (API)" icon={Crosshair} meta="from deep scan" priority="secondary">
                  {(deepScanMutation.data.mitre as any)?.matches?.length > 0 ? (
                    <div className="flex flex-wrap gap-1.5">
                      {((deepScanMutation.data.mitre as any).matches as any[]).map((m: any) => (
                        <Chip key={m.technique_id} tone="warning">{m.technique_id} — {m.technique}</Chip>
                      ))}
                    </div>
                  ) : (
                    <p className="text-mono ba-text-sm text-muted-foreground">No MITRE techniques matched.</p>
                  )}
                </Panel>
              )}
            </>
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
                <span className="text-mono ba-text-2xs uppercase tracking-widest text-muted-foreground">render</span>
                <button onClick={() => setDefanged(true)} className={toggleBtn(defanged)}>defang</button>
                <button onClick={() => setDefanged(false)} className={toggleBtn(!defanged)}>raw</button>
              </div>
            </div>

            <div className="mb-2 text-mono text-[10px] uppercase tracking-[0.22em] text-muted-foreground/70">j/k navigate · y copy · c attach · e enrich · . context</div>
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
                        <span className="text-mono ba-text-sm uppercase tracking-widest text-foreground">{kind}</span>
                        <Chip tone={meta.tone}>{items.length}</Chip>
                      </div>
                      <div className="flex items-center gap-1">
                        <button onClick={() => copy(kind, allText)} className="inline-flex items-center gap-1 rounded border border-border bg-card/60 px-1.5 py-0.5 text-mono ba-text-2xs uppercase tracking-widest text-muted-foreground hover:text-foreground">
                          {copied === kind ? <><Check className="h-3 w-3" /> copied</> : <><Copy className="h-3 w-3" /> copy all</>}
                        </button>
                        <button onClick={() => { items.forEach((v: string) => locker.add({ value: v, type: kind.toLowerCase() as LockerItem["type"], source: "/parser" })); }} className="inline-flex items-center gap-1 rounded border border-divider-strong bg-card/60 px-1.5 py-0.5 text-mono ba-text-2xs uppercase tracking-widest text-muted-foreground hover:text-primary">
                          <Hash className="h-3 w-3" /> locker
                        </button>
                        {meta.pivot && (
                          <Link to={meta.pivot} className="inline-flex items-center gap-1 rounded border border-primary/40 bg-primary/10 px-1.5 py-0.5 text-mono ba-text-2xs uppercase tracking-widest text-primary hover:bg-primary/20">
                            pivot <ArrowRight className="h-3 w-3" />
                          </Link>
                        )}
                      </div>
                    </div>
                    <ul className="grid gap-1 grid-cols-2">
                      {items.map((it) => (
                        <li key={it} className={`group flex items-center justify-between gap-2 rounded border px-2 py-1 transition-colors ${
                          selectedIoc && selectedIoc.value === it && selectedIoc.kind === kind
                            ? "border-primary/50 bg-primary/5 ring-1 ring-primary/30"
                            : "border-border/50 bg-card/40 hover:border-primary/40 hover:bg-card/70"
                        }`}>
                          <code className="truncate text-mono ba-text-sm text-foreground/90">{transform(it)}</code>
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
          <div className="grid gap-4 grid-cols-[1fr_2fr]">
            <Panel title="Export Report" icon={Download} priority="secondary">
              <button
                onClick={() => {
                  const md = genMarkdownExport(input, result.iocs, result.signals, result.total, result.family, result.primary, result.secrets, result.cmds, result.mitre);
                  const blob = new Blob([md], { type: "text/markdown" });
                  const url = URL.createObjectURL(blob);
                  const a = document.createElement("a"); a.href = url; a.download = `parser-report-${Date.now()}.md`; a.click();
                  URL.revokeObjectURL(url);
                }}
                className="group inline-flex w-full items-center justify-center gap-2 rounded border border-primary/50 bg-primary/10 px-4 py-2 text-mono ba-text-2xs uppercase tracking-widest text-primary transition-all hover:bg-primary/20"
              >
                <Download className="h-3.5 w-3.5" />
                Download Markdown
              </button>
              <button onClick={() => { const json = genJsonExport(input, result.iocs, result.signals, result.total, result.family, result.primary, result.secrets, result.cmds, result.mitre); const blob = new Blob([json], { type: "application/json" }); const url = URL.createObjectURL(blob); const a = document.createElement("a"); a.href = url; a.download = `parser-report-${Date.now()}.json`; a.click(); URL.revokeObjectURL(url); }} className="group inline-flex w-full items-center justify-center gap-2 rounded border border-primary/50 bg-primary/10 px-4 py-2 text-mono ba-text-2xs uppercase tracking-widest text-primary transition-all hover:bg-primary/20">
                <Download className="h-3.5 w-3.5" /> Download JSON
              </button>
              <button onClick={() => { navigator.clipboard.writeText(reportMd); toast.success("Report copied"); }} className="group inline-flex w-full items-center justify-center gap-2 rounded border border-primary/30 bg-primary/5 px-4 py-2 text-mono ba-text-2xs uppercase tracking-widest text-primary transition-all hover:bg-primary/15">
                <Copy className="h-3.5 w-3.5" /> Copy Summary
              </button>
              <p className="mt-2 text-[11px] text-muted-foreground">Includes all indicators, signals, secrets, and MITRE mapping.</p>
            </Panel>
            <SendToRow targets={[
              { label: "Recon & Exposure", to: "/recon", icon: Globe },
              { label: "Phishing Triage", to: "/phishing", icon: Mail },
              { label: "Safe URL Analyzer", to: "/url", icon: Link2 },
              { label: "Attachment Triage", to: "/attachment", icon: FileWarning },
              { label: "Detection & MITRE", to: "/mitre", icon: Crosshair },
              { label: "Case Notebook", to: "/case", icon: ArrowRight },
            ]} />
          </div>
        </div>
      )}
      <div className="mt-8 border-t border-divider-strong pt-6">
        <OsintTools showSectionBars />
      </div>
    </PageShell>
  );
}

const tabBtn = (active: boolean) =>
  "rounded border px-2 py-0.5 text-mono ba-text-2xs uppercase tracking-widest transition-colors " +
  (active ? "border-primary/60 bg-primary/15 text-primary" : "border-divider-strong bg-card/40 text-muted-foreground hover:text-foreground");

const toggleBtn = (active: boolean) =>
  "rounded border px-1.5 py-0.5 text-mono ba-text-2xs uppercase tracking-widest " +
  (active ? "border-primary/60 bg-primary/15 text-primary" : "border-divider-strong bg-card/40 text-muted-foreground hover:text-foreground");
