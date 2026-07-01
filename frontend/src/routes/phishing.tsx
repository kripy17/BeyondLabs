import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useEffect, useMemo, useRef, useState } from "react";
import { PageShell } from "@/components/PageShell";
import { ToolShell, type ToolState } from "@/components/soc/ToolShell";
import { IntakeCard, KeyFields, SectionBar, Panel, Empty, EvidenceCard, ResultBanner, SendToRow, Chip, IocInventory } from "@/components/soc/Workspace";
import { PreviewBadge } from "@/components/PreviewBadge";
import { takePendingArtifact, sendArtifact } from "@/lib/handoff";
import { safeAnalyzeUrl } from "@/api/backend";
import { Skeleton } from "@/components/ui/skeleton";
import { toast } from "sonner";
import { Mail, ShieldAlert, ShieldCheck, Link2, Database, ArrowRight, CheckCircle2, XCircle, MinusCircle, AlertTriangle, FileText, Hash, Crosshair, Download, Key, Network, FlaskConical } from "lucide-react";

export const Route = createFileRoute("/phishing")({ component: PhishingPage });

const SAMPLES = {
  lure: `From: Security Team <security-alert@example-login.com>
To: user@example.org
Subject: URGENT: Password reset required within 24h
Return-Path: bounce@example-login.com
Reply-To: support@example-login.com
Authentication-Results: mx.example.org; spf=fail smtp.mailfrom=example-login.com; dkim=fail; dmarc=fail
Received: from mail.example-login.com (203.0.113.44) by mx.example.org with ESMTPS
Received: from edge01.example-login.com (198.51.100.7) by mail.example-login.com

Dear customer,
Please verify your account immediately at hxxps[:]//login.example-login[.]com/reset?id=1234
Failure to act will result in account suspension.
Reference: 44d88612fea8a8f36de82e1278abb02f
Contact security@example-login.com for help.`,

  bec: `From: Jane Doe <jane.doe@acmme-corp.com>
To: finance@acme-corp.com
Subject: Re: Wire transfer for vendor onboarding
Return-Path: jane.doe@acmme-corp.com
Reply-To: jane.doe.cfo@gmail.com
Authentication-Results: mx.acme-corp.com; spf=pass smtp.mailfrom=acmme-corp.com; dkim=softfail; dmarc=fail
Received: from smtp-relay.gmail.com (209.85.220.41) by mx.acme-corp.com
Received: from mail.acmme-corp.com (192.0.2.88) by smtp-relay.gmail.com
Content-Type: multipart/mixed; boundary="----=_Part_123"

Hi team,
Quick request before my flight — please process the wire for our new vendor today.
Bank details attached. Confirm once sent, I'll sign the invoice on landing.
Thanks, Jane (sent from mobile)`,

  invoice: `From: Billing <billing@invoice-portal[.]net>
To: ap@example.org
Subject: Invoice INV-90213 ready for download
Return-Path: noreply@invoice-portal.net
Reply-To: billing@invoice-portal.net
Authentication-Results: mx.example.org; spf=pass smtp.mailfrom=invoice-portal.net; dkim=pass; dmarc=pass
Received: from mta-12.invoice-portal.net (192.0.2.201) by mx.example.org
Content-Disposition: attachment; filename=invoice.pdf

Hello,
Your invoice is available: https://invoice-portal.net/download?ref=INV-90213
SHA-1 attached: 275a021bbfb6489e54d471899f7db9d1663fc695
Pay before due date to avoid late fees.`,

  html: `From: Newsletter <noreply@phish-mg.tk>
To: user@example.org
Subject: Your account has been suspended
Return-Path: bounce@phish-mg.tk
Reply-To: support@phish-mg.tk
Authentication-Results: mx.example.org; spf=fail; dkim=none; dmarc=fail
Received: from mail.phish-mg.tk (185.220.101.44) by mx.example.org
Content-Type: text/html; charset=utf-8

<html>
<body>
<form action="hxxps[:]//login.example[.]com/verify" method="POST">
  <h2>Security Alert</h2>
  <p>Your account has been suspended due to unusual activity.</p>
  <input type="hidden" name="token" value="ghp_abcdefghijklmnopqrstuvwxyz1234567890">
  <label>Email: <input type="text" name="email"></label>
  <label>Password: <input type="password" name="pass"></label>
  <button type="submit">Verify Now</button>
</form>
</body>
</html>`,
};

const RX = {
  URL:    /\b(?:hxxps?|https?):\/\/[^\s)>"']+/gi,
  Domain: /\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b/gi,
  IPv4:   /\b(?:\d{1,3}\.){3}\d{1,3}\b/g,
  MD5:    /\b[a-f0-9]{32}\b/gi,
  SHA256: /\b[a-f0-9]{64}\b/gi,
  Email:  /\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b/gi,
  CVE:    /CVE-\d{4}-\d{4,}/gi,
  ATTACK: /\bT\d{4}(?:\.\d{3})?\b/g,
};

const SENDER_TLDS = new Set(["tk","ml","ga","cf","gq","xyz","top","download","review","work","date","men","loan","win","bid","cam","click","quest","trade","webcam","cyou","bond"]);
const SUSPICIOUS_TLDS = new Set(["tk","ml","ga","cf","gq","xyz","top","download","review","work","date","men","loan","win","bid","cam","click","quest","trade","webcam","science","party","gdn","racing","accountant","country","faith","online","site","rest","cyou","bond","bar"]);
const SHORTENERS = new Set(["bit.ly","tinyurl.com","ow.ly","is.gd","buff.ly","shorturl.at","cutt.ly","t.co","goo.gl","tiny.cc","cli.gs","url.ie","rb.gy","short.link"]);
const LOLBINS = ["powershell","cmd.exe","wscript","cscript","mshta","regsvr32","rundll32","wmic","certutil","bitsadmin","msiexec"];
const DOWNLOAD_CRADLES = ["Invoke-WebRequest","iwr","wget","curl","Invoke-RestMethod","irm","Start-BitsTransfer","(new-object system.net.webclient).downloadstring"];
const AMSI_BYPASS_PATTERNS = ["amsiutils","amsiinitfailed","system.management.automation.amsiutils"];

const SECRET_RX: { type: string; re: RegExp }[] = [
  { type: "AWS Access Key", re: /AKIA[0-9A-Z]{16}\b/g },
  { type: "GitHub Token", re: /(?:ghp_|gho_|ghu_|ghs_|ghr_)[a-zA-Z0-9]{36}\b/g },
  { type: "JWT Token", re: /eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/g },
  { type: "Slack Token", re: /xox[baprs]-[a-zA-Z0-9-]{10,48}\b/g },
  { type: "Private Key", re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g },
];

type AuthState = "pass" | "fail" | "softfail" | "none";

function AuthTile({ name, state }: { name: string; state: AuthState }) {
  const cfg =
    state === "pass" ? { Icon: CheckCircle2, cls: "border-success/50 bg-success/10 text-success", label: "PASS" } :
    state === "fail" ? { Icon: XCircle, cls: "border-destructive/50 bg-destructive/10 text-destructive", label: "FAIL" } :
    state === "softfail" ? { Icon: AlertTriangle, cls: "border-warning/50 bg-warning/10 text-warning", label: "SOFTFAIL" } :
                       { Icon: MinusCircle, cls: "border-border bg-card/40 text-muted-foreground", label: "\u2014" };
  const { Icon, cls, label } = cfg;
  return (
    <div className={"flex items-center justify-between gap-2 rounded-md border px-3 py-2 " + cls}>
      <div className="flex items-center gap-2">
        <Icon className="h-4 w-4" />
        <span className="text-mono text-[11px] uppercase tracking-widest">{name}</span>
      </div>
      <span className="text-mono text-[11px] font-semibold tabular-nums">{label}</span>
    </div>
  );
}

function detectAuth(input: string, family: "spf" | "dkim" | "dmarc"): AuthState {
  const hasAuth = /Authentication-Results:/i.test(input);
  if (!hasAuth) return "none";
  const rx = new RegExp(family + "=([a-z]+)", "i");
  const m = input.match(rx);
  const v = m?.[1]?.toLowerCase();
  if (v === "pass") return "pass";
  if (v === "softfail" || v === "neutral" || v === "policy" || v === "temperror" || v === "permerror") return "softfail";
  if (v === "fail" || v === "none") return "fail";
  return "none";
}

function refang(s: string) { return s.replace(/\[\.\]/g, ".").replace(/\(\.\)/g, ".").replace(/\{\.\}/g, ".").replace(/\bhxxp/gi, "http"); }
function defang(s: string) { const r = refang(s); return r.replace(/\./g, "[.]").replace(/\bhttp/gi, "hxxp"); }

function entropy(s: string): number {
  const freq: Record<string, number> = {};
  for (const c of s) freq[c] = (freq[c] || 0) + 1;
  return -Object.values(freq).reduce((sum, n) => { const p = n / s.length; return sum + p * Math.log2(p); }, 0);
}

function extractBody(input: string): string {
  const parts = input.split(/\r?\n\r?\n/);
  return parts.length > 1 ? parts.slice(1).join("\n\n").trim() : "";
}

function extractHeaders(input: string): string {
  return input.split(/\r?\n\r?\n/)[0] || input;
}

function detectAttachments(input: string): { hasAttachments: boolean; detail: string[] } {
  const d: string[] = [];
  if (/Content-Type:\s*multipart\//i.test(input)) d.push("Multipart content (may carry attachments)");
  const dispos = Array.from(input.matchAll(/Content-Disposition:\s*attachment;?\s*(.*)/gi));
  for (const m of dispos) d.push(`Attachment: ${m[1]?.trim() || "unnamed"}`);
  return { hasAttachments: d.length > 0, detail: d };
}

function scanSecrets(t: string): { type: string; value: string }[] {
  const found: { type: string; value: string }[] = [];
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

function getDomain(email: string): string {
  const m = email.match(/@([^\s>]+)/);
  return m ? m[1].toLowerCase().replace(/[\[\]]/g, "") : "";
}

function detectLookalike(from: string, replyTo: string, returnPath: string): string[] {
  const flags: string[] = [];
  const fromDomain = getDomain(from);
  const replyDomain = getDomain(replyTo);
  const pathDomain = getDomain(returnPath);
  if (fromDomain && replyDomain && fromDomain !== replyDomain) flags.push(`Reply-To domain (${replyDomain}) differs from From domain (${fromDomain})`);
  if (fromDomain && pathDomain && fromDomain !== pathDomain) flags.push(`Return-Path domain (${pathDomain}) differs from From domain (${fromDomain})`);
  return flags;
}

function isLookalike(domain: string, known: string): boolean {
  if (!domain || !known) return false;
  const d = domain.toLowerCase().replace(/[\[\]]/g, "");
  const k = known.toLowerCase().replace(/[\[\]]/g, "");
  if (d === k) return false;
  const edits = (a: string, b: string): number => {
    const m = a.length, n = b.length;
    const dp: number[][] = Array.from({ length: m + 1 }, () => Array(n + 1).fill(0));
    for (let i = 0; i <= m; i++) dp[i][0] = i;
    for (let j = 0; j <= n; j++) dp[0][j] = j;
    for (let i = 1; i <= m; i++) for (let j = 1; j <= n; j++)
      dp[i][j] = a[i - 1] === b[j - 1] ? dp[i - 1][j - 1] : 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
    return dp[m][n];
  };
  const dist = edits(d, k);
  const maxLen = Math.max(d.length, k.length);
  return dist > 0 && dist <= 2 && maxLen > 5;
}

function stripHtml(html: string): string {
  return html.replace(/<[^>]*>/g, "");
}

function analyzeUrls(urls: string[]): { value: string; suspicious: boolean; badges: { label: string; tone: "warning" | "destructive" | "info" | "success" }[] }[] {
  return urls.map((u) => {
    const badges: { label: string; tone: "warning" | "destructive" | "info" | "success" }[] = [];
    try {
      const parsed = new URL(refang(u));
      const host = parsed.hostname;
      const tld = host.split(".").pop()?.toLowerCase();
      if (tld && SUSPICIOUS_TLDS.has(tld)) badges.push({ label: "suspicious TLD", tone: "warning" });
      if (SHORTENERS.has(host.replace(/^www\./, ""))) badges.push({ label: "shortener", tone: "warning" });
      if (parsed.username || parsed.password) badges.push({ label: "embedded creds", tone: "destructive" });
      if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host)) badges.push({ label: "IP-based", tone: "warning" });
      if (entropy(parsed.pathname + parsed.search) > 4.5) badges.push({ label: "high entropy", tone: "info" });
    } catch {}
    return { value: u, suspicious: badges.length > 0, badges };
  });
}

function genMarkdown(input: string, data: any, iocs: any): string {
  const lines = [
    `# Phishing Triage Report`,
    `**Verdict:** ${data.verdict}`,
    `**SPF:** ${data.spf}  **DKIM:** ${data.dkim}  **DMARC:** ${data.dmarc}`,
    "",
    "## Findings",
    ...data.findings.map((f: any) => `- [${f.sev.toUpperCase()}] ${f.t} — ${f.r}`),
    "",
  ];
  if (iocs) {
    lines.push("## Indicators");
    for (const [k, v] of Object.entries(iocs) as [string, string[]][]) if (v.length) lines.push(`### ${k} (${v.length})`, ...v.map((i) => `- \`${i}\``), "");
  }
  lines.push("---", "Generated by BeyondArch Phishing Triage");
  return lines.join("\n");
}

function LoadingSkeleton() {
  return (
    <div className="space-y-4">
      <div className="rounded-md border border-border bg-card/40 p-4">
        <Skeleton className="mb-2 h-4 w-1/4" />
        <Skeleton className="mb-1 h-8 w-1/3" />
        <Skeleton className="h-4 w-1/2" />
      </div>
      <div className="grid gap-4 sm:grid-cols-3">
        {[1, 2, 3].map((i) => (
          <div key={i} className="rounded-md border border-border bg-card/40 p-4">
            <Skeleton className="mb-2 h-3 w-1/3" />
            <Skeleton className="h-6 w-1/4" />
          </div>
        ))}
      </div>
      <div className="grid gap-4 md:grid-cols-2">
        {[1, 2].map((i) => (
          <div key={i} className="rounded-md border border-border bg-card/40 p-4">
            <Skeleton className="mb-2 h-3 w-1/3" />
            <Skeleton className="mb-1 h-4 w-3/4" />
            <Skeleton className="mb-1 h-4 w-1/2" />
            <Skeleton className="h-4 w-2/3" />
          </div>
        ))}
      </div>
    </div>
  );
}

function EmptyPreview() {
  const cards = [
    ["Sender Identity", "From, Reply-To, Return-Path, display-name mismatches"],
    ["Header Authentication", "SPF, DKIM, DMARC, Received path, auth results"],
    ["Extracted URLs", "Visible text, actual href, defanged targets"],
    ["Lure Signals", "Urgency, credential request, brand impersonation"],
    ["Case Findings", "Report-ready summary, limitations, next steps"],
  ];
  return (
    <Panel title="Awaiting Analysis" icon={FlaskConical} meta="expected output structure">
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
        {cards.map(([title, text]) => (
          <div key={title} className="rounded-md border border-dashed border-border/60 bg-card/30 p-3">
            <div className="text-mono text-[10px] font-semibold uppercase tracking-widest text-foreground/80">{title}</div>
            <p className="mt-1 text-[11px] text-muted-foreground">{text}</p>
          </div>
        ))}
      </div>
    </Panel>
  );
}

function PhishingPage() {
  const pendingRef = useRef(takePendingArtifact());
  const [input, setInput] = useState(() => {
    const p = pendingRef.current;
    return p?.kind === "email" || p?.kind === "raw" || p?.kind === "ioc" ? (p.value ?? "") : "";
  });
  const [loading, setLoading] = useState<string | null>(null);
  const [notice, setNotice] = useState<string>("");
  const [runs, setRuns] = useState(() => pendingRef.current ? 1 : 0);
  const navigate = useNavigate();
  const has = input.trim().length > 0;
  const committed = runs > 0 && has;

  useEffect(() => {
    if (pendingRef.current && input) {
      setNotice(`Loaded ${pendingRef.current.kind} from ${pendingRef.current.source}`);
      pendingRef.current = null;
    }
  }, []);

  const flashNotice = (msg: string) => {
    setNotice(msg);
    setTimeout(() => setNotice(""), 3000);
  };

  const data = useMemo(() => {
    if (!committed) return null;
    const refanged = refang(input);
    const spf = detectAuth(input, "spf");
    const dkim = detectAuth(input, "dkim");
    const dmarc = detectAuth(input, "dmarc");
    const fromLine = (input.match(/From:\s*(.+)/i)?.[1] ?? "").trim();
    const replyLine = (input.match(/Reply-To:\s*(.+)/i)?.[1] ?? "").trim();
    const pathLine = (input.match(/Return-Path:\s*(.+)/i)?.[1] ?? "").trim();
    const fromDomain = getDomain(fromLine);
    const replyDomain = getDomain(replyLine);
    const replyMismatch = !!(fromDomain && replyDomain && fromDomain !== replyDomain);
    const defangedUrl = /hxxps?:\/\/|\[\.\]/i.test(input);
    const urgency = /urgent|immediately|within \d+h|suspend|today|asap|before my flight/i.test(input);

    const body = extractBody(input);
    const headers = extractHeaders(input);
    const bodyLower = body.toLowerCase();
    const hasForm = /<form/i.test(body) || /<input.*type=["']?(?:text|password|email)["' ]/i.test(body);
    const hasPasswordField = /<input.*type=["']?password["' ]/i.test(body) || /password/i.test(bodyLower);
    const hasHtmlForm = /<form\s/i.test(body);
    const hasAttachment = detectAttachments(input);
    const envelopeFlags = detectLookalike(fromLine, replyLine, pathLine);
    const hasLookalike = envelopeFlags.length > 0;

    const emailUniq = <T,>(a: T[]) => Array.from(new Set(a));
    const iocs = (() => {
      const urls = emailUniq((refanged.match(RX.URL) ?? []).map((u: string) => defang(u)));
      const emails = emailUniq(refanged.match(RX.Email) ?? []);
      const ips = emailUniq(refanged.match(RX.IPv4) ?? []);
      const md5 = emailUniq(refanged.match(RX.MD5)?.filter((h: string) => h.length === 32) ?? []);
      const sha256 = emailUniq(refanged.match(RX.SHA256) ?? []);
      const cve = emailUniq(refanged.match(RX.CVE) ?? []);
      const attack = emailUniq(refanged.match(RX.ATTACK) ?? []);
      const domains = emailUniq(
        (refanged.match(RX.Domain) ?? [])
          .filter((d: string) => !ips.includes(d) && !emails.some((e: string) => e.toLowerCase().includes(d.toLowerCase())))
          .map((d: string) => defang(d))
      );
      return { urls, domains, ips, hashes: [...md5, ...sha256], emails, cve, attack };
    })();

    const secrets = scanSecrets(body || input);

    const urlAnalysis = iocs.urls.length ? analyzeUrls(iocs.urls) : [];

    const findings = [
      spf === "fail" && { sev: "destructive" as const, t: "SPF authentication failed", r: "Sender server is not authorised for the domain.", a: "Treat the From: address as untrusted." },
      spf === "softfail" && { sev: "warning" as const, t: "SPF soft-fail", r: "Sending IP is not in the SPF record but policy is permissive (~all).", a: "Tighten SPF policy and inspect originating IP." },
      dmarc === "fail" && { sev: "destructive" as const, t: "DMARC alignment failed", r: "Sender policy denies delivery — likely spoof.", a: "Quarantine similar messages at the gateway." },
      dkim === "fail" && { sev: "warning" as const, t: "DKIM signature not validated", r: "Body integrity not guaranteed.", a: "Pivot on Received: hops for true source." },
      dkim === "softfail" && { sev: "info" as const, t: "DKIM soft-fail / neutral", r: "Selector responded but signature did not cleanly verify.", a: "Confirm key rotation on the sending domain." },
      replyMismatch && { sev: "warning" as const, t: "Reply-To masquerades as sender", r: "Reply traffic diverts to a different lookalike domain.", a: "Block both domains and notify the user." },
      defangedUrl && { sev: "info" as const, t: "Defanged URL detected", r: "Indicator was sanitised by the submitter.", a: "Re-fang in Safe URL Analyzer, never click directly." },
      urgency && { sev: "info" as const, t: "Urgency / coercion language", r: "Social-engineering pressure tactic.", a: "Include in user training and report draft." },
      hasForm && { sev: "destructive" as const, t: "HTML form in email body", r: "Email contains a form — credential harvesting risk.", a: "Verify form action URL and inspect in Phishing Triage." },
      hasPasswordField && { sev: "destructive" as const, t: "Password field in email", r: "Body contains password input — likely credential harvesting.", a: "Escalate; do not submit credentials." },
      hasAttachment.hasAttachments && { sev: "warning" as const, t: "Email carries attachments", r: hasAttachment.detail.length ? hasAttachment.detail.join("; ") : "Multipart content detected.", a: "Submit to Attachment Triage before opening." },
      fromDomain && SENDER_TLDS.has(fromDomain.split(".").pop() || "") && { sev: "warning" as const, t: "Sender TLD is high-risk", r: `Sender domain uses suspicious TLD .${fromDomain.split(".").pop()}`, a: "Investigate domain registration in OSINT." },
      hasLookalike && { sev: "warning" as const, t: "Envelope domain mismatch", r: envelopeFlags.join("; "), a: "Verify sender identity out-of-band." },
      ...genBodySignals(body, iocs),
    ].filter(Boolean) as { sev: "destructive" | "warning" | "info"; t: string; r: string; a: string }[];

    const breakdown = [
      { signal: "SPF",             weight: spf === "fail" ? 30 : spf === "softfail" ? 12 : 0,     state: spf },
      { signal: "DMARC",           weight: dmarc === "fail" ? 30 : dmarc === "softfail" ? 10 : 0, state: dmarc },
      { signal: "DKIM",            weight: dkim === "fail" ? 10 : dkim === "softfail" ? 4 : 0,    state: dkim },
      { signal: "Reply-To mismatch", weight: replyMismatch ? 15 : 0, state: replyMismatch ? "fail" as const : "pass" as const },
      { signal: "Defanged URL",    weight: defangedUrl ? 10 : 0,    state: defangedUrl ? "fail" as const : "pass" as const },
      { signal: "Urgency / coercion", weight: urgency ? 10 : 0,     state: urgency ? "fail" as const : "pass" as const },
      { signal: "HTML form",       weight: hasForm ? 25 : 0,        state: hasForm ? "fail" as const : "pass" as const },
      { signal: "Password field",  weight: hasPasswordField ? 25 : 0, state: hasPasswordField ? "fail" as const : "pass" as const },
      { signal: "Attachments",     weight: hasAttachment.hasAttachments ? 10 : 0, state: hasAttachment.hasAttachments ? "fail" as const : "pass" as const },
      { signal: "Sender TLD risk", weight: fromDomain && SENDER_TLDS.has(fromDomain.split(".").pop() || "") ? 10 : 0, state: "fail" as const },
      { signal: "Envelope mismatch", weight: hasLookalike ? 15 : 0, state: hasLookalike ? "fail" as const : "pass" as const },
    ];
    const destructiveCount = findings.filter((f) => f.sev === "destructive").length;
    const warningCount = findings.filter((f) => f.sev === "warning").length;
    const verdict = destructiveCount > 0 || (spf === "fail" && dmarc === "fail") ? "Likely Phishing" : warningCount > 0 || spf === "softfail" || dmarc === "softfail" ? "Suspicious" : "Inconclusive";
    const tone = destructiveCount > 0 || (spf === "fail" && dmarc === "fail") ? "destructive" as const : warningCount > 0 ? "warning" as const : "success" as const;

    const mitre = [] as { id: string; name: string; source: string }[];
    const seen = new Set<string>();
    const addMitre = (id: string, name: string, source: string) => { if (!seen.has(id)) { seen.add(id); mitre.push({ id, name, source }); } };
    if (spf === "fail" || dmarc === "fail") addMitre("T1566", "Phishing", "auth");
    if (hasForm || hasPasswordField) addMitre("T1566", "Phishing: Credential Harvesting", "body");
    if (hasAttachment.hasAttachments) addMitre("T1204", "User Execution", "attachment");
    if (iocs.cve.length) addMitre("T1190", "Exploit Public-Facing Application", "ioc");
    if (iocs.attack.length) for (const a of iocs.attack) addMitre(a, "Technique referenced", "ioc");

    return { spf, dkim, dmarc, replyMismatch, defangedUrl, urgency, findings, verdict, tone, breakdown, body, headers, hasForm, hasPasswordField, hasHtmlForm, hasAttachment, envelopeFlags, hasLookalike, iocs, secrets, urlAnalysis, mitre, fromDomain, fromLine, replyLine, pathLine };
  }, [committed, input]);

  const handoff = (kind: string, value: string, to: string) => {
    sendArtifact({ kind, value, source: "/phishing" });
    navigate({ to });
  };

  const state: ToolState = loading ? "parsing" : !has ? "idle" : !data ? "idle" : "ready";

  const run = async () => {
    if (loading || !has) return;
    setRuns((r) => r + 1);
    setLoading("analysing");
    setNotice("");
    try {
      const refanged = refang(input);
      const urls = Array.from(new Set(refanged.match(RX.URL) ?? [])).slice(0, 3);
      if (urls.length > 0) {
        await Promise.all(urls.map((url) =>
          safeAnalyzeUrl({
            url,
            allow_live_fetch: true,
            max_redirects: 3,
            timeout_seconds: 6,
            allow_private_targets: false,
          }).catch(() => null)
        ));
      }
      flashNotice("Analysis complete");
      toast.success("Phishing analysis complete");
    } catch {
      flashNotice("Analysis completed (partial)");
      toast.error("Phishing analysis completed with errors");
    } finally {
      setLoading(null);
    }
  };

  const clear = () => { setInput(""); setRuns(0); setNotice(""); };

  return (
    <PageShell
      eyebrow="TRIAGE / PHISHING"
      title="Phishing Triage"
      description="Static-only inspection of email envelope, auth results, body, and embedded indicators. No links followed."
      crumbs={[{ label: "Triage" }, { label: "Phishing" }]}
    >
      <ToolShell
        icon={Mail}
        title="Phishing Triage"
        purpose="Static analysis of email envelope, authentication and body lures."
        state={state}
        layout="stack"
        canRun={has && !loading}
        onRun={run}
        onClear={clear}
        intake={
          <>
            <SectionBar id="IN" label="Intake · raw email source" meta="paste full source incl. headers" />
            <IntakeCard
              icon={Mail}
              title="Email Source"
              value={input}
              onChange={setInput}
              onPaste={(t) => { setInput(t); setRuns((r) => r + 1); }}
              samples={[
                { key: "lure", label: "Credential lure", hint: "spf/dkim/dmarc fail" },
                { key: "bec", label: "BEC wire request", hint: "lookalike domain, attachment" },
                { key: "invoice", label: "Invoice / portal", hint: "all auth pass, attachment" },
                { key: "html", label: "HTML form phish", hint: "form, password field, secrets" },
              ]}
              onLoadSample={(key) => {
                const s = SAMPLES[key as keyof typeof SAMPLES] ?? SAMPLES.lure;
                setInput(s);
                setRuns((r) => r + 1);
              }}
              onFile={(txt) => { setInput(txt); setRuns((r) => r + 1); }}
              fileAccept=".eml,.txt,.msg,.log"
              run={{ label: "analyse", icon: ShieldAlert, hint: "\u2318\u21B5", onClick: run, disabled: !has || !!loading }}
              onClear={clear}
              rows={10}
              notice={notice || undefined}
            />
          </>
        }
        output={
          loading ? <LoadingSkeleton /> : !data ? (
            has ? <Empty icon={ShieldAlert} title="Press analyse or paste to run" hint="Paste the full email source above to compute the risk verdict." /> : <EmptyPreview />
          ) : (
            <div className="space-y-4">

              <ResultBanner
                badge={data.tone === "destructive" ? "likely phishing" : data.tone === "warning" ? "suspicious" : "inconclusive"}
                caseId={`BA-PH-${String(data.findings.length).padStart(2, "0")}`}
                title={data.verdict}
                subtitle="Authentication snapshot computed from the message's Authentication-Results header."
                reasons={data.findings.slice(0, 3).map((f) => f.t)}
                metrics={[
                  { label: "Findings", value: data.findings.length, tone: data.findings.length > 0 ? "warning" : "success" },
                  { label: "SPF",   value: data.spf.toUpperCase(),   tone: data.spf === "fail" ? "destructive" : data.spf === "softfail" ? "warning" : data.spf === "pass" ? "success" : "default" },
                  { label: "DKIM",  value: data.dkim.toUpperCase(),  tone: data.dkim === "fail" ? "destructive" : data.dkim === "softfail" ? "warning" : data.dkim === "pass" ? "success" : "default" },
                  { label: "DMARC", value: data.dmarc.toUpperCase(), tone: data.dmarc === "fail" ? "destructive" : data.dmarc === "softfail" ? "warning" : data.dmarc === "pass" ? "success" : "default" },
                ]}
              />

              <Panel title="Authentication detail" icon={ShieldCheck} meta="SPF \u00B7 DKIM \u00B7 DMARC" actions={<PreviewBadge />}>
                <div className="grid gap-2 sm:grid-cols-3">
                  <AuthTile name="SPF" state={data.spf} />
                  <AuthTile name="DKIM" state={data.dkim} />
                  <AuthTile name="DMARC" state={data.dmarc} />
                </div>
              </Panel>

              <Panel title="Sender Identity" icon={ShieldCheck}>
                <KeyFields items={[
                  { label: "From", value: data.fromLine || "\u2014" },
                  { label: "Reply-To", value: data.replyLine || "\u2014", tone: data.replyMismatch ? "warning" : "default" },
                  { label: "Return-Path", value: data.pathLine || "\u2014" },
                  { label: "Subject", value: (input.match(/Subject:\s*(.+)/i)?.[1] ?? "\u2014").trim() },
                  { label: "Sender TLD", value: data.fromDomain ? `.${data.fromDomain.split(".").pop()}` : "\u2014", tone: data.fromDomain && SENDER_TLDS.has(data.fromDomain.split(".").pop() || "") ? "warning" : "default" },
                  { label: "Authentication", value: data.spf === "fail" || data.dmarc === "fail" ? "FAIL" : data.spf === "softfail" || data.dmarc === "softfail" || data.dkim === "softfail" ? "SOFTFAIL" : "pass", tone: data.spf === "fail" || data.dmarc === "fail" ? "destructive" : data.spf === "softfail" || data.dmarc === "softfail" || data.dkim === "softfail" ? "warning" : "success" },
                  ...(data.hasAttachment.hasAttachments ? [{ label: "Attachment", value: data.hasAttachment.detail.join("; "), tone: "warning" }] : []),
                ]} />
              </Panel>

              {/* Body content */}
              {data.body && (
                <Panel title="Email Body" icon={FileText} meta={data.hasHtmlForm ? "contains HTML" : "plain text"}>
                  {data.hasHtmlForm ? (
                    <pre className="max-h-[280px] overflow-auto rounded border border-border/50 bg-background/60 p-2.5 text-mono text-[11px] leading-relaxed text-foreground/80 whitespace-pre-wrap">{data.body}</pre>
                  ) : (
                    <pre className="max-h-[200px] overflow-auto rounded border border-border/50 bg-background/60 p-2.5 text-mono text-[11px] leading-relaxed text-foreground/80 whitespace-pre-wrap">{data.body}</pre>
                  )}
                </Panel>
              )}

              {/* Delivery path */}
              {(() => {
                const hops = Array.from(input.matchAll(/Received:\s*from\s+([^\s]+)\s*(?:\(([^)]+)\))?/gi)).map((m) => ({ host: m[1], detail: m[2] ?? "" }));
                return (
                  <Panel title="Delivery Path" meta={`${hops.length} hop${hops.length === 1 ? "" : "s"}`}>
                    {hops.length === 0 ? (
                      <p className="text-mono text-[11px] text-muted-foreground">No Received: hops found.</p>
                    ) : (
                      <ol className="relative space-y-2 border-l border-border/60 pl-3">
                        {hops.map((h, i) => (
                          <li key={i} className="relative">
                            <span className="absolute -left-[15px] top-1 grid h-2 w-2 place-items-center rounded-full bg-primary ring-2 ring-background" />
                            <div className="flex flex-wrap items-baseline gap-2">
                              <Chip tone="primary">hop {hops.length - i}</Chip>
                              <code className="text-mono text-[11px] text-foreground/90">{h.host}</code>
                              {h.detail && <code className="text-mono text-[10px] text-muted-foreground">{h.detail}</code>}
                            </div>
                          </li>
                        ))}
                      </ol>
                    )}
                  </Panel>
                );
              })()}

              {/* URL analysis */}
              {data.urlAnalysis.length > 0 && (
                <Panel title="URL Deep Analysis" icon={Link2} meta={`${data.urlAnalysis.length} URL${data.urlAnalysis.length === 1 ? "" : "s"}`}>
                  <div className="space-y-2">
                    {data.urlAnalysis.map((u: any, i: number) => (
                      <div key={i} className="flex flex-wrap items-center gap-2 rounded border border-border/50 bg-card/40 px-3 py-2">
                        <code className="min-w-0 flex-1 truncate text-mono text-[11px] text-foreground/90">{defang(u.value)}</code>
                        <div className="flex flex-wrap items-center gap-1">
                          {u.badges.length === 0 && <Chip tone="success">clean</Chip>}
                          {u.badges.map((b: any, j: number) => (
                            <Chip key={j} tone={b.tone}>{b.label}</Chip>
                          ))}
                        </div>
                      </div>
                    ))}
                  </div>
                </Panel>
              )}

              {/* Secrets in body */}
              {data.secrets.length > 0 && (
                <Panel title="Secrets Detected in Body" icon={Key} meta={`${data.secrets.length} potential exposure`}>
                  <div className="space-y-1.5">
                    {data.secrets.map((s: any, i: number) => (
                      <div key={i} className="flex items-center justify-between gap-2 rounded border border-destructive/30 bg-destructive/5 px-2.5 py-1.5">
                        <span className="text-mono text-[10px] uppercase tracking-widest text-destructive">{s.type}</span>
                        <code className="text-mono text-[11px] text-foreground/80">{s.value}</code>
                      </div>
                    ))}
                  </div>
                </Panel>
              )}

              {/* IOC inventory */}
              {data.iocs && (
                <>
                  <SectionBar id="IO" label="IOC inventory" meta="urls · domains · ips · hashes · emails · cve · attack" />
                  <IocInventory
                    onSendTo={(kind, value) => {
                      const map: Record<string, string> = { urls: "/url", domains: "/osint", ips: "/osint", hashes: "/attachment", emails: "/osint", cve: "/detection", attack: "/detection" };
                      handoff(kind.toLowerCase(), value, map[kind.toLowerCase()] ?? "/case");
                    }}
                    groups={[
                      { kind: "urls", items: data.iocs.urls, tone: "destructive" },
                      { kind: "domains", items: data.iocs.domains, tone: "warning" },
                      { kind: "ips", items: data.iocs.ips, tone: "info" },
                      { kind: "hashes", items: data.iocs.hashes, tone: "primary" },
                      { kind: "emails", items: data.iocs.emails, tone: "success" },
                      ...(data.iocs.cve.length ? [{ kind: "cve" as const, items: data.iocs.cve, tone: "destructive" as const }] : []),
                      ...(data.iocs.attack.length ? [{ kind: "attack" as const, items: data.iocs.attack, tone: "destructive" as const }] : []),
                    ]}
                  />
                </>
              )}

              {/* MITRE */}
              {data.mitre.length > 0 && (
                <Panel title="MITRE ATT&CK Mapping" icon={Crosshair} meta={`${data.mitre.length} technique${data.mitre.length === 1 ? "" : "s"}`}>
                  <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
                    {data.mitre.map((m: any, i: number) => (
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

              {/* Evidence cards */}
              <SectionBar id="EV" label="Evidence cards" meta="reason · limitation · action" />
              <div className="grid gap-3 md:grid-cols-2">
                {data.findings.length === 0 ? <Empty title="No suspicious patterns triggered" /> : data.findings.map((f, i) => (
                  <EvidenceCard key={i} severity={f.sev} title={f.t} reason={f.r} action={f.a} limitation="Heuristic — confirm against gateway logs and user report." />
                ))}
              </div>



              {/* Raw panels */}
              <div className="grid gap-3 lg:grid-cols-2">
                <Panel icon={ShieldCheck} title="Authentication-Results · raw" meta="parsed verbatim">
                  <pre className="overflow-x-auto rounded border border-border/50 bg-background/60 p-2.5 text-mono text-[11px] text-foreground/85 whitespace-pre-wrap">
                    {(input.match(/Authentication-Results:[^\n]*(?:\n\s+[^\n]+)*/gi) ?? ["— none found —"]).join("\n\n")}
                  </pre>
                </Panel>
                <Panel icon={Hash} title="Message identifiers" meta="for de-duplication & search">
                  <KeyFields items={[
                    { label: "Message-ID",     value: (input.match(/Message-ID:\s*<([^>]+)>/i)?.[1] ?? "—") },
                    { label: "X-Mailer",       value: (input.match(/X-Mailer:\s*(.+)/i)?.[1]?.trim() ?? "—") },
                    { label: "Date",           value: (input.match(/^Date:\s*(.+)$/im)?.[1]?.trim() ?? "—") },
                    { label: "MIME-Version",   value: (input.match(/MIME-Version:\s*(.+)/i)?.[1]?.trim() ?? "—") },
                    { label: "Content-Type",   value: (input.match(/Content-Type:\s*([^;\n]+)/i)?.[1]?.trim() ?? "—") },
                  ]} />
                </Panel>
              </div>

              <Panel icon={FileText} title="Raw headers" meta="everything before the first blank line" actions={<PreviewBadge label="verbatim" />}>
                <pre className="max-h-[320px] overflow-auto rounded border border-border/50 bg-background/60 p-2.5 text-mono text-[10.5px] leading-relaxed text-foreground/80 whitespace-pre-wrap">
                  {extractHeaders(input) || "— empty —"}
                </pre>
              </Panel>

              {/* Export + Handoff */}
              <div className="grid gap-3 lg:grid-cols-[200px_1fr]">
                <Panel title="Export" icon={Download}>
                  <button
                    onClick={() => {
                      const md = genMarkdown(input, data, data.iocs);
                      const blob = new Blob([md], { type: "text/markdown" });
                      const url = URL.createObjectURL(blob);
                      const a = document.createElement("a"); a.href = url; a.download = `phishing-report-${Date.now()}.md`; a.click();
                      URL.revokeObjectURL(url);
                    }}
                    className="group inline-flex w-full items-center justify-center gap-2 rounded border border-primary/50 bg-primary/10 px-3 py-2 text-mono text-[10px] uppercase tracking-widest text-primary transition-all hover:bg-primary/20"
                  >
                    <Download className="h-3.5 w-3.5" /> MD
                  </button>
                </Panel>
                <SendToRow targets={[
                  { label: "Safe URL Analyzer", to: "/url", icon: Link2 },
                  { label: "Attachment Triage", to: "/attachment", icon: FileText },
                  { label: "Detection & MITRE", to: "/detection", icon: ShieldAlert },
                  { label: "Logs & Alerts", to: "/logs", icon: Database },
                ]} />
              </div>
            </div>
          )
        }
      />
    </PageShell>
  );
}

function genBodySignals(body: string, iocs: any): { sev: "destructive" | "warning" | "info"; t: string; r: string; a: string }[] {
  const s: { sev: "destructive" | "warning" | "info"; t: string; r: string; a: string }[] = [];
  const lower = body.toLowerCase();
  if (/<form/i.test(body) && /action\s*=\s*["']?https?:\/\//i.test(body))
    s.push({ sev: "destructive", t: "Form submits data to external URL", r: "Email contains a form that posts to an external server.", a: "Verify form action URL before any interaction." });
  if (iocs.urls.length > 1 && /https?:\/\/[^\s]+/i.test(body) && /<a\s/i.test(body))
    s.push({ sev: "warning", t: "Multiple embedded links in body", r: "Body contains multiple hyperlinks with potential mismatched display text.", a: "Inspect each link's href vs visible text." });
  if (/click here|download now|login|sign in|update (your )?(account|billing|payment)|confirm/i.test(lower))
    s.push({ sev: "warning", t: "Call-to-action language in body", r: "Body contains action-oriented phrases common in phishing lures.", a: "Cross-reference with known legitimate communications." });
  if (/\$\d[\d,]*\.?\d*|payment|invoice|wire|transfer|bank|reimbursement/i.test(lower))
    s.push({ sev: "info", t: "Financial language detected", r: "Body references payments, invoices, or wire transfers.", a: "Confirm with sender via out-of-band channel." });
  return s;
}

export default PhishingPage;
