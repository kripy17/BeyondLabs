import { SUSPICIOUS_TLDS, SHORTENERS, refang, defang, entropy, scanSecrets } from "@/lib/ioc-patterns";
import { CheckCircle2, XCircle, AlertTriangle, MinusCircle, FileText, Download, Copy, Check, FlaskConical, Activity, Panel } from "lucide-react"; // prettier-ignore

export const SAMPLES: Record<string, string> = {
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

  suspicious_invoice: `From: Accounts Payable <invoices@acmecorp-billing[.]net>
To: finance@example.org
Subject: INV-2024-8932 — Overdue payment notice
Return-Path: noreply@acmecorp-billing.net
Reply-To: disputes@acmecorp-billing.net
Authentication-Results: mx.example.org; spf=softfail smtp.mailfrom=acmecorp-billing.net; dkim=neutral; dmarc=fail
Received: from mail.acmecorp-billing.net (198.51.100.99) by mx.example.org with ESMTPS

Dear Finance Department,

Your invoice INV-2024-8932 for $12,847.50 is now overdue.
To avoid service interruption and late fees, please process payment immediately.

View and pay your invoice here: hxxps[:]//acmecorp-billing[.]net/pay/invoice/INV-2024-8932

Reference: 7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b
If you have already paid, please disregard this notice.

Accounts Receivable
ACMECorp Billing Portal
disputes@acmecorp-billing.net`,

  account_alert: `From: Security Alerts <alert@secure-verify[.]tk>
To: user@example.org
Subject: Security Alert: Unusual sign-in detected
Return-Path: bounce@secure-verify.tk
Reply-To: support@secure-verify.tk
Authentication-Results: mx.example.org; spf=fail smtp.mailfrom=secure-verify.tk; dkim=none; dmarc=fail
Received: from mail.secure-verify.tk (203.0.113.77) by mx.example.org with ESMTPS

We detected a sign-in attempt from an unfamiliar device or location.

• Location: Moscow, Russia
• Device: Windows 10 / Chrome 124
• Time: April 15, 2026 3:42 AM UTC

If this was not you, your account may be compromised.

Secure your account now: hxxps[:]//secure-verify[.]tk/account/recovery?id=U2FsdGVkX18

This is an automated security alert. Do not reply to this message.

— Account Security Team`,
};

export const RX = {
  URL:    /\b(?:hxxps?|https?):\/\/[^\s)>"']+/gi,
  Domain: /\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b/gi,
  IPv4:   /\b(?:\d{1,3}\.){3}\d{1,3}\b/g,
  MD5:    /\b[a-f0-9]{32}\b/gi,
  SHA256: /\b[a-f0-9]{64}\b/gi,
  Email:  /\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b/gi,
  CVE:    /CVE-\d{4}-\d{4,}/gi,
  ATTACK: /\bT\d{4}(?:\.\d{3})?\b/g,
};

export const SENDER_TLDS = new Set(["tk","ml","ga","cf","gq","xyz","top","download","review","work","date","men","loan","win","bid","cam","click","quest","trade","webcam","cyou","bond"]);

export const BRAND_KEYWORDS = ["paypal", "apple", "google", "microsoft", "amazon", "netflix", "facebook", "instagram", "linkedin", "twitter", "x.com", "dropbox", "adobe", "dhl", "fedex", "ups", "usps", "bank of america", "chase", "wells fargo", "citi", "capital one", "american express", "visa", "mastercard", "github", "gitlab", "bitbucket", "slack", "zoom", "teams", "office 365", "microsoft 365", "outlook", "gmail", "yahoo", "aol"];

export type AuthState = "pass" | "fail" | "softfail" | "none";

export function getDomain(email: string): string {
  const m = email.match(/@([^\s>]+)/);
  return m ? m[1].toLowerCase().replace(/[\[\]]/g, "") : "";
}

export function detectAuth(input: string, family: "spf" | "dkim" | "dmarc"): AuthState {
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

export function extractBody(input: string): string {
  const parts = input.split(/\r?\n\r?\n/);
  return parts.length > 1 ? parts.slice(1).join("\n\n").trim() : "";
}

export function extractHeaders(input: string): string {
  return input.split(/\r?\n\r?\n/)[0] || input;
}

export function detectAttachments(input: string): { hasAttachments: boolean; detail: string[] } {
  const d: string[] = [];
  if (/Content-Type:\s*multipart\//i.test(input)) d.push("Multipart content (may carry attachments)");
  const dispos = Array.from(input.matchAll(/Content-Disposition:\s*attachment;?\s*(.*)/gi));
  for (const m of dispos) d.push(`Attachment: ${m[1]?.trim() || "unnamed"}`);
  return { hasAttachments: d.length > 0, detail: d };
}

export function detectLookalike(from: string, replyTo: string, returnPath: string): string[] {
  const flags: string[] = [];
  const fromDomain = getDomain(from);
  const replyDomain = getDomain(replyTo);
  const pathDomain = getDomain(returnPath);
  if (fromDomain && replyDomain && fromDomain !== replyDomain) flags.push(`Reply-To domain (${replyDomain}) differs from From domain (${fromDomain})`);
  if (fromDomain && pathDomain && fromDomain !== pathDomain) flags.push(`Return-Path domain (${pathDomain}) differs from From domain (${fromDomain})`);
  return flags;
}

export function analyzeUrls(urls: string[]): { value: string; suspicious: boolean; badges: { label: string; tone: "warning" | "destructive" | "info" | "success" }[] }[] {
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

export function htmlToText(html: string): string {
  return html
    .replace(/<br\s*\/?>/gi, "\n")
    .replace(/<[^>]*>/g, "")
    .replace(/&nbsp;/g, " ")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&amp;/g, "&")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}

export function genMarkdown(input: string, data: any, iocs: any): string {
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
  lines.push("---", "Generated by BeyondLabs Phishing Triage");
  return lines.join("\n");
}

export function genJsonExport(data: any, _iocs: any): string {
  const exportData = {
    version: "1.0",
    generated: new Date().toISOString(),
    verdict: data.verdict,
    authentication: { spf: data.spf, dkim: data.dkim, dmarc: data.dmarc },
    findings: data.findings.map((f: any) => ({ severity: f.sev, title: f.t, reason: f.r, action: f.a })),
    iocs: { ...data.iocs },
    secrets: data.secrets.map((s: any) => ({ type: s.type, value: s.value })),
    mitre: data.mitre.map((m: any) => ({ id: m.id, name: m.name, source: m.source })),
    signalBreakdown: data.breakdown.map((b: any) => ({ signal: b.signal, state: b.state, weight: b.weight })),
  };
  return JSON.stringify(exportData, null, 2);
}

export function genBodySignals(body: string, iocs: { urls: string[] }): { sev: "destructive" | "warning" | "info"; t: string; r: string; a: string }[] {
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

export function buildFromApi(apiResult: Record<string, any> | null, input: string, committed: boolean) {
  if (!apiResult || !committed) return null;
  const body = extractBody(input);
  const headers = extractHeaders(input);

  const ha = apiResult.header_analysis || {};
  const bs = apiResult.body_signals || {};
  const auth = ha.authentication || {};
  const hdrs = ha.headers || {};
  const doms = ha.domains || {};

  const spf: AuthState = auth.spf === "pass" ? "pass" : auth.spf === "softfail" ? "softfail" : auth.spf === "fail" || auth.spf === "not_found" ? "fail" : "none";
  const dkim: AuthState = auth.dkim === "pass" ? "pass" : auth.dkim === "softfail" ? "softfail" : auth.dkim === "fail" || auth.dkim === "not_found" ? "fail" : "none";
  const dmarc: AuthState = auth.dmarc === "pass" ? "pass" : auth.dmarc === "softfail" ? "softfail" : auth.dmarc === "fail" || auth.dmarc === "not_found" ? "fail" : "none";

  const combined = apiResult.combined_findings || [];
  const findings = combined.map((f: any) => ({
    sev: f.severity === "high" ? "destructive" as const : f.severity === "medium" ? "warning" as const : "info" as const,
    t: f.title,
    r: f.description || f.detail,
    a: f.recommendation || f.action,
  }));

  const destructiveCount = findings.filter((f: any) => f.sev === "destructive").length;
  const warningCount = findings.filter((f: any) => f.sev === "warning").length;
  const hasCriticalAuth = spf === "fail" && dmarc === "fail";
  const verdict = destructiveCount > 0 || hasCriticalAuth ? "Likely Phishing" : warningCount > 0 ? "Suspicious" : "Inconclusive";
  const tone = destructiveCount > 0 || hasCriticalAuth ? "destructive" as const : warningCount > 0 ? "warning" as const : "success" as const;

  const fromLine = hdrs.from || (input.match(/From:\s*(.+)/i)?.[1] ?? "").trim();
  const replyLine = hdrs.reply_to || (input.match(/Reply-To:\s*(.+)/i)?.[1] ?? "").trim();
  const pathLine = hdrs.return_path || (input.match(/Return-Path:\s*(.+)/i)?.[1] ?? "").trim();

  const iocs = apiResult.iocs || {};
  const urlAnalysis = (iocs.urls || []).map((u: string) => {
    const badges: { label: string; tone: "warning" | "destructive" | "info" | "success" }[] = [];
    try {
      const parsed = new URL(refang(u));
      const host = parsed.hostname;
      const tld = host.split(".").pop()?.toLowerCase();
      if (tld && SUSPICIOUS_TLDS.has(tld)) badges.push({ label: "suspicious TLD", tone: "warning" });
      if (SHORTENERS.has(host.replace(/^www\./, ""))) badges.push({ label: "shortener", tone: "warning" });
      if (parsed.username || parsed.password) badges.push({ label: "embedded creds", tone: "destructive" });
    } catch {}
    return { value: u, suspicious: badges.length > 0, badges };
  });

  const hasAttachment = detectAttachments(input);
  const envelopeFlags = detectLookalike(fromLine, replyLine, pathLine);

  const mitre: { id: string; name: string; source: string }[] = [];
  const mitreSeen = new Set<string>();
  for (const f of combined) {
    const mid = f.mitre_id;
    if (mid && !mitreSeen.has(mid)) {
      mitreSeen.add(mid);
      mitre.push({ id: mid, name: f.mitre_name || mid, source: f.source || "analysis" });
    }
  }

  return {
    spf, dkim, dmarc,
    replyMismatch: !!(doms.from_domain && doms.reply_to_domain && doms.from_domain !== doms.reply_to_domain),
    defangedUrl: /hxxps?:\/\/|\[\.\]/i.test(input),
    urgency: /urgent|immediately|within \d+h|suspend|today|asap|before my flight/i.test(input),
    findings, verdict, tone,
    breakdown: [],
    body, headers,
    hasForm: (bs.forms_detected || []).length > 0 || /<form/i.test(body),
    hasPasswordField: (bs.forms_detected || []).some((f: string) => /password/i.test(f)) || /<input.*type=["']?password["' ]/i.test(body),
    hasHtmlForm: bs.has_html || /<form\s/i.test(body),
    hasAttachment, envelopeFlags,
    hasLookalike: envelopeFlags.length > 0,
    iocs: {
      urls: iocs.urls || [],
      domains: iocs.domains || [],
      ips: iocs.ipv4 || [],
      hashes: [...(iocs.hashes?.md5 || []), ...(iocs.hashes?.sha256 || [])],
      emails: iocs.emails || [],
      cve: iocs.cves || [],
      attack: [],
    },
    secrets: scanSecrets(body || input),
    urlAnalysis,
    mitre,
    fromDomain: doms.from_domain,
    fromLine, replyLine, pathLine,
  };
}
