import { createFileRoute } from "@tanstack/react-router";
import { useState } from "react";
import { PageShell } from "@/components/PageShell";
import {
  IntakeCard, StatusBar, ResultBanner, KeyFields, SectionBar,
  Panel, SendToRow, Empty, Chip, RiskScore, EvidenceCard, IocInventory,
} from "@/components/soc/Workspace";
import {
  Globe2, Search, ShieldAlert, Database, ArrowRight, Zap, Eraser,
  Server, Lock, FileSearch, Link2, Mail, AlertTriangle, Crosshair,
  Bug, ExternalLink, Download, Hash, Network, Cpu,
} from "lucide-react";

export const Route = createFileRoute("/recon")({ component: ReconPage });

type TargetKey = "phish" | "bank" | "startup" | "cdn";

interface ReconTarget {
  target: string;
  org?: string;
  screenshot?: string;
  whois: { registrar: string; created: string; expires: string; country: string; status: string; emails: string[]; org: string };
  dns: { A: string[]; AAAA: string[]; MX: string[]; NS: string[]; TXT: string[]; CNAME: string[] };
  tls: { issuer: string; subject: string; validFrom: string; validTo: string; sans: string[]; selfSigned: boolean };
  http: { status: number; server: string; redirects: number; headers: Record<string, string> };
  subdomains: { name: string; ip: string; resolved: boolean }[];
  tech: { name: string; category: string; version?: string }[];
  ctLogs: { logName: string; loggedAt: string }[];
  ports: { port: number; service: string; state: string }[];
  messages: { label: string; value: string; tone?: "default" | "primary" | "success" | "warning" | "destructive" | "muted" }[];
  mitre: { id: string; name: string }[];
}

const WHOIS_GATE = ["clientHold", "serverHold", "redemptionPeriod", "pendingDelete"];

function classifyDomainAge(created: string): number {
  const createdDate = new Date(created).getTime();
  const ageMs = Date.now() - createdDate;
  return Math.max(0, Math.floor(ageMs / (1000 * 60 * 60 * 24 * 365)));
}

const TARGETS: Record<TargetKey, ReconTarget> = {
  phish: {
    target: "secure-login.example-bank.xyz",
    org: "—",
    whois: { registrar: "NameCheap, Inc.", created: "2026-03-15", expires: "2027-03-15", country: "PA", status: "clientHold", emails: ["abuse@namecheap.com", "admin@privacy-protection.example"], org: "Privacy Protection Services" },
    dns: { A: ["198.51.100.44", "198.51.100.45"], AAAA: [], MX: ["mx1.protonmail.ch"], NS: ["ns1.hostmonster.com", "ns2.hostmonster.com"], TXT: ["v=spf1 -all", "google-site-verification=abc123"], CNAME: [] },
    tls: { issuer: "Let's Encrypt E3", subject: "CN = *.example-bank.xyz", validFrom: "2026-04-01", validTo: "2026-06-30", sans: ["secure-login.example-bank.xyz", "www.example-bank.xyz"], selfSigned: false },
    http: { status: 200, server: "nginx/1.24.0", redirects: 2, headers: { "Strict-Transport-Security": "missing", "Content-Security-Policy": "missing", "X-Frame-Options": "DENY", "X-Content-Type-Options": "missing", "Referrer-Policy": "missing", "Server": "nginx/1.24.0" } },
    subdomains: [
      { name: "secure-login.example-bank.xyz", ip: "198.51.100.44", resolved: true },
      { name: "www.example-bank.xyz", ip: "198.51.100.45", resolved: true },
      { name: "mail.example-bank.xyz", ip: "185.94.188.22", resolved: true },
      { name: "cdn.example-bank.xyz", ip: "", resolved: false },
    ],
    tech: [
      { name: "nginx", category: "web-server", version: "1.24.0" },
      { name: "Let's Encrypt", category: "ca" },
      { name: "ProtonMail", category: "email-provider" },
    ],
    ctLogs: [
      { logName: "Google Argon 2025", loggedAt: "2026-04-01T08:00:00Z" },
      { logName: "Cloudflare 'Nimbus 2025'", loggedAt: "2026-04-01T08:05:00Z" },
    ],
    ports: [
      { port: 80, service: "http", state: "open" },
      { port: 443, service: "https", state: "open" },
      { port: 25, service: "smtp", state: "open" },
    ],
    messages: [
      { label: "Domain Age", value: "<3 months", tone: "destructive" },
      { label: "Registrar Country", value: "PA (Panama)", tone: "warning" },
      { label: "DNSSEC", value: "not configured", tone: "warning" },
      { label: "SPF", value: "v=spf1 -all (hard fail)", tone: "info" },
      { label: "DMARC", value: "not configured", tone: "warning" },
    ],
    mitre: [
      { id: "T1583.001", name: "Acquire Infrastructure: Domains" },
      { id: "T1583.002", name: "Acquire Infrastructure: DNS" },
      { id: "T1583.003", name: "Acquire Infrastructure: Virtual Private Server" },
      { id: "T1587.002", name: "Develop Capabilities: Code Signing Certificates" },
    ],
  },
  bank: {
    target: "online.bankofexample.com",
    org: "Bank of Example, Inc.",
    whois: { registrar: "MarkMonitor, Inc.", created: "2005-06-14", expires: "2028-06-14", country: "US", status: "ok", emails: ["abuse@markmonitor.com", "hostmaster@bankofexample.com"], org: "Bank of Example, Inc." },
    dns: { A: ["203.0.113.10", "203.0.113.11"], AAAA: ["2001:db8::1"], MX: ["mx1.bankofexample.com", "mx2.bankofexample.com"], NS: ["ns1.markmonitor.com", "ns2.markmonitor.com"], TXT: ["v=spf1 include:_spf.bankofexample.com ~all", "google-site-verification=xyz789", "MS=ms123456"], CNAME: [] },
    tls: { issuer: "DigiCert EV SSL", subject: "CN = online.bankofexample.com", validFrom: "2025-11-01", validTo: "2026-11-30", sans: ["online.bankofexample.com", "www.bankofexample.com", "m.bankofexample.com"], selfSigned: false },
    http: { status: 200, server: "cloudflare", redirects: 0, headers: { "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload", "Content-Security-Policy": "default-src 'self'; script-src 'self' static.bankofexample.com", "X-Frame-Options": "SAMEORIGIN", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "strict-origin-when-cross-origin", "Server": "cloudflare" } },
    subdomains: [
      { name: "online.bankofexample.com", ip: "203.0.113.10", resolved: true },
      { name: "www.bankofexample.com", ip: "203.0.113.10", resolved: true },
      { name: "m.bankofexample.com", ip: "203.0.113.11", resolved: true },
      { name: "api.bankofexample.com", ip: "203.0.113.20", resolved: true },
      { name: "mail.bankofexample.com", ip: "203.0.113.30", resolved: true },
      { name: "cdn.bankofexample.com", ip: "203.0.113.40", resolved: true },
    ],
    tech: [
      { name: "Cloudflare", category: "cdn" },
      { name: "DigiCert EV", category: "ca" },
      { name: "Apache", category: "web-server" },
      { name: "Microsoft 365", category: "email-provider" },
    ],
    ctLogs: [
      { logName: "Google Argon 2024", loggedAt: "2025-11-01T12:00:00Z" },
      { logName: "Google Xenon 2024", loggedAt: "2025-11-01T12:01:00Z" },
    ],
    ports: [
      { port: 80, service: "http", state: "redirect" },
      { port: 443, service: "https", state: "open" },
      { port: 8443, service: "https-alt", state: "open" },
    ],
    messages: [
      { label: "Domain Age", value: "~21 years", tone: "success" },
      { label: "Registrar Country", value: "US", tone: "success" },
      { label: "DNSSEC", value: "configured", tone: "success" },
      { label: "SPF", value: "~all (soft fail)", tone: "info" },
      { label: "DMARC", value: "p=reject", tone: "success" },
    ],
    mitre: [],
  },
  startup: {
    target: "app.nebula-startup.io",
    org: "Nebula Startup LLC",
    whois: { registrar: "NameCheap, Inc.", created: "2025-04-20", expires: "2027-04-20", country: "US", status: "ok", emails: ["abuse@namecheap.com"], org: "Nebula Startup LLC" },
    dns: { A: ["192.0.2.100"], AAAA: [], MX: ["mx1.forwardemail.net"], NS: ["dns1.registrar-servers.com", "dns2.registrar-servers.com"], TXT: ["v=spf1 include:spf.forwardemail.net ~all", "google-site-verification=abc456"], CNAME: ["www → app.nebula-startup.io"] },
    tls: { issuer: "Cloudflare ECC CA-3", subject: "CN = *.nebula-startup.io", validFrom: "2026-01-10", validTo: "2026-07-10", sans: ["*.nebula-startup.io", "nebula-startup.io"], selfSigned: false },
    http: { status: 302, server: "cloudflare", redirects: 1, headers: { "Strict-Transport-Security": "max-age=31536000", "Content-Security-Policy": "missing", "X-Frame-Options": "missing", "X-Content-Type-Options": "missing", "Referrer-Policy": "no-referrer", "Server": "cloudflare" } },
    subdomains: [
      { name: "app.nebula-startup.io", ip: "192.0.2.100", resolved: true },
      { name: "www.nebula-startup.io", ip: "192.0.2.100", resolved: true },
      { name: "blog.nebula-startup.io", ip: "192.0.2.101", resolved: true },
      { name: "docs.nebula-startup.io", ip: "", resolved: false },
    ],
    tech: [
      { name: "Cloudflare", category: "cdn" },
      { name: "Vercel", category: "hosting" },
      { name: "Forward Email", category: "email-provider" },
      { name: "Next.js", category: "framework" },
    ],
    ctLogs: [
      { logName: "Cloudflare 'Nimbus 2025'", loggedAt: "2026-01-10T06:00:00Z" },
    ],
    ports: [
      { port: 80, service: "http", state: "redirect" },
      { port: 443, service: "https", state: "open" },
    ],
    messages: [
      { label: "Domain Age", value: "~14 months", tone: "warning" },
      { label: "Registrar Country", value: "US", tone: "success" },
      { label: "DNSSEC", value: "not configured", tone: "warning" },
      { label: "SPF", value: "~all (soft fail)", tone: "info" },
      { label: "DMARC", value: "not configured", tone: "warning" },
    ],
    mitre: [
      { id: "T1595", name: "Active Scanning" },
    ],
  },
  cdn: {
    target: "edge-cdn.cdn-provider.net",
    org: "CDN Provider, Corp.",
    whois: { registrar: "Cloudflare, Inc.", created: "2010-08-01", expires: "2028-08-01", country: "US", status: "ok", emails: ["abuse@cloudflare.com"], org: "CDN Provider, Corp." },
    dns: { A: ["104.16.0.10", "104.16.1.10"], AAAA: ["2606:4700::6810:0a", "2606:4700::6810:1a"], MX: [], NS: ["ns1.cloudflare.com", "ns2.cloudflare.com"], TXT: ["v=spf1 -all"], CNAME: [] },
    tls: { issuer: "Cloudflare ECC CA-3", subject: "CN = *.cdn-provider.net", validFrom: "2026-03-01", validTo: "2027-03-01", sans: ["*.cdn-provider.net", "cdn-provider.net"], selfSigned: false },
    http: { status: 200, server: "cloudflare", redirects: 0, headers: { "Strict-Transport-Security": "max-age=31536000; preload", "Content-Security-Policy": "default-src 'none'", "X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer", "Server": "cloudflare" } },
    subdomains: [
      { name: "edge-cdn.cdn-provider.net", ip: "104.16.0.10", resolved: true },
      { name: "static.cdn-provider.net", ip: "104.16.0.11", resolved: true },
      { name: "api.cdn-provider.net", ip: "104.16.0.12", resolved: true },
    ],
    tech: [
      { name: "Cloudflare Enterprise", category: "cdn" },
      { name: "nginx", category: "web-server" },
    ],
    ctLogs: [
      { logName: "Google Argon 2025", loggedAt: "2026-03-01T04:00:00Z" },
      { logName: "DigiCert CT Log", loggedAt: "2026-03-01T04:05:00Z" },
    ],
    ports: [
      { port: 80, service: "http", state: "redirect" },
      { port: 443, service: "https", state: "open" },
    ],
    messages: [
      { label: "Domain Age", value: "~16 years", tone: "success" },
      { label: "Registrar Country", value: "US", tone: "success" },
      { label: "DNSSEC", value: "configured", tone: "success" },
      { label: "SPF", value: "v=spf1 -all (hard fail)", tone: "info" },
      { label: "DMARC", value: "p=reject", tone: "success" },
    ],
    mitre: [],
  },
};

function findSignals(data: ReconTarget): { sev: "destructive" | "warning" | "info" | "success"; t: string; r: string; a: string }[] {
  const signals: { sev: "destructive" | "warning" | "info" | "success"; t: string; r: string; a: string }[] = [];
  const ageYears = classifyDomainAge(data.whois.created);
  if (ageYears < 1) signals.push({ sev: "warning", t: "Domain registered <12 months ago", r: `Registered ${data.whois.created} — typical lifespan for phishing infrastructure.`, a: "Treat as low-trust; verify through secondary channels." });
  if (data.whois.country === "PA" || data.whois.country === "RU" || data.whois.country === "CN") signals.push({ sev: "warning", t: "Registrant country: " + data.whois.country, r: "Domain registered in a jurisdiction associated with higher fraud registration rates.", a: "Factor into overall trust score." });
  if (WHOIS_GATE.includes(data.whois.status)) signals.push({ sev: "warning", t: "Registrar status: " + data.whois.status, r: "Registrar hold/lock can indicate abuse complaint or dispute.", a: "Cross-reference with threat intel for prior reports." });
  if (data.tls.selfSigned) signals.push({ sev: "destructive", t: "Self-signed TLS certificate", r: "No CA validation — common in testing environments or MiTM setups.", a: "Verify certificate chain for production surface." });
  if (data.tls.subject.startsWith("CN = *.")) signals.push({ sev: "info", t: "Wildcard TLS certificate", r: "Covers any subdomain — pivots across siblings cheap for attackers.", a: "Enumerate SANs for related infrastructure." });
  const ageDays = Math.floor((Date.now() - new Date(data.tls.validFrom).getTime()) / (1000 * 60 * 60 * 24));
  if (ageDays < 30) signals.push({ sev: "info", t: "TLS certificate issued recently", r: `Issued ${ageDays} day(s) ago — may indicate renewed infrastructure.`, a: "Check CT logs for related domain issuance." });
  const missingHeaders = Object.entries(data.http.headers).filter(([k, v]) => v === "missing" && k !== "Server").length;
  if (missingHeaders >= 3) signals.push({ sev: "warning", t: `${missingHeaders} security headers missing`, r: "HSTS / CSP / X-Frame-Options / X-Content-Type-Options / Referrer-Policy gaps increase phishing surface.", a: "Note hardening posture in report." });
  else if (missingHeaders >= 1) signals.push({ sev: "info", t: `${missingHeaders} security header(s) missing`, r: "Partial hardening — check individual headers for gaps.", a: "Recommend HSTS and CSP for production." });
  if (data.http.status === 302 || data.http.status === 301) signals.push({ sev: "info", t: "HTTP redirect on root", r: "Root resolves via redirect — landing page may differ from index.", a: "Follow redirect chain for full exposure picture." });
  if (data.subdomains.length > 4) signals.push({ sev: "info", t: `${data.subdomains.length} subdomains discovered`, r: "Broad subdomain surface increases attack perimeter.", a: "Catalog all subdomains for continuous monitoring." });
  if (data.dns.AAAA.length === 0) signals.push({ sev: "info", t: "No IPv6 DNS records", r: "AAAA records absent — host not reachable over IPv6.", a: "Low risk; note for completeness." });
  if (!signals.length) signals.push({ sev: "success", t: "No notable risk signals", r: "Domain passes basic passive recon checks.", a: "Proceed with active scanning if authorized." });
  return signals;
}

function genMarkdownExport(data: ReconTarget, score: number, signals: any[]): string {
  const lines = [
    `# Reconnaissance Report`,
    `**Target:** \`${data.target}\``,
    `**Score:** ${score}/100`,
    `**Generated:** ${new Date().toISOString()}`,
    "", "## WHOIS / RDAP",
    `- Registrar: ${data.whois.registrar}`,
    `- Created: ${data.whois.created}`,
    `- Expires: ${data.whois.expires}`,
    `- Country: ${data.whois.country}`,
    `- Status: ${data.whois.status}`,
    `- Org: ${data.whois.org}`,
    "", "## DNS Records",
  ];
  for (const [rr, vals] of Object.entries(data.dns)) {
    if (vals.length) lines.push(`- ${rr}: ${(vals as string[]).join(", ")}`);
  }
  lines.push("", "## TLS Certificate",
    `- Issuer: ${data.tls.issuer}`,
    `- Subject: ${data.tls.subject}`,
    `- Valid: ${data.tls.validFrom} → ${data.tls.validTo}`,
    `- SANs: ${data.tls.sans.join(", ")}`,
    "", "## HTTP Headers",
    `- Status: ${data.http.status}`,
    `- Server: ${data.http.server}`,
    `- Redirects: ${data.http.redirects}`);
  for (const [k, v] of Object.entries(data.http.headers)) lines.push(`- ${k}: ${v}`);
  if (data.subdomains.length) {
    lines.push("", "## Subdomains", ...data.subdomains.map((s) => `- ${s.name} → ${s.ip || "(unresolved)"}`));
  }
  if (data.tech.length) {
    lines.push("", "## Technology Stack", ...data.tech.map((t) => `- ${t.name} ${t.version || ""} (${t.category})`));
  }
  lines.push("", "## Signals", ...signals.map((s: any) => `- [${s.sev.toUpperCase()}] ${s.t}`));
  if (data.mitre.length) {
    lines.push("", "## MITRE ATT&CK", ...data.mitre.map((m) => `- ${m.id}: ${m.name}`));
  }
  return lines.join("\n");
}

function computeScore(data: ReconTarget): { score: number; confidence: string; tone: "success" | "warning" | "destructive" } {
  let score = 0;
  const ageYears = classifyDomainAge(data.whois.created);
  if (ageYears < 1) score += 20;
  else if (ageYears < 2) score += 10;
  if (WHOIS_GATE.includes(data.whois.status)) score += 10;
  if (data.whois.country === "PA" || data.whois.country === "RU" || data.whois.country === "CN") score += 10;
  if (data.tls.selfSigned) score += 15;
  const missingHeaders = Object.entries(data.http.headers).filter(([k, v]) => v === "missing" && k !== "Server").length;
  score += missingHeaders * 4;
  const unresolved = data.subdomains.filter((s) => !s.resolved).length;
  score += unresolved * 2;
  if (data.tls.validTo && new Date(data.tls.validTo).getTime() - Date.now() < 30 * 24 * 60 * 60 * 1000) score += 8;
  const total = Math.min(100, score);
  const tone = total < 20 ? "success" : total < 50 ? "warning" : "destructive";
  const confidence = total < 15 ? "low" : total < 40 ? "moderate" : total < 70 ? "high" : "very high";
  return { score: total, confidence, tone };
}

function ReconPage() {
  const [key, setKey] = useState<TargetKey | "">("");
  const data: ReconTarget | null = key ? TARGETS[key as TargetKey] : null;
  const analysis = data ? computeScore(data) : null;
  const signals = data ? findSignals(data) : [];

  return (
    <PageShell
      eyebrow="RECON / EXPOSURE"
      title="Recon & Exposure"
      description="Passive reconnaissance — WHOIS, DNS, TLS, HTTP headers, subdomain enumeration, and technology stack identification. No active probing."
      crumbs={[{ label: "Recon" }, { label: "Exposure" }]}
    >
      <SectionBar id="IN" label="Intake · target" meta={data ? data.target : "no target loaded"} />
      <IntakeCard
        icon={Globe2}
        title="Target"
        value={data ? data.target : ""}
        onChange={() => {}}
        rows={2}
        placeholder="example.com"
        samples={[
          { key: "phish", label: "secure-login.example-bank.xyz", hint: "suspicious domain" },
          { key: "bank", label: "online.bankofexample.com", hint: "legit bank" },
          { key: "startup", label: "app.nebula-startup.io", hint: "recent startup" },
          { key: "cdn", label: "edge-cdn.cdn-provider.net", hint: "CDN edge" },
        ]}
        onLoadSample={(k) => setKey(k as TargetKey)}
        run={{ label: "enumerate", icon: Zap, hint: "⌘↵", onClick: () => {}, disabled: !data }}
        onClear={() => setKey("")}
        showCopy={false}
      />

      <StatusBar stats={[
        { label: "Status", value: data ? "Snapshot ready" : "Idle", tone: data ? "success" : "muted" },
        { label: "Sources", value: "WHOIS · DNS · TLS · HTTP", tone: "primary" },
        { label: "Score", value: analysis ? `${analysis.score}/100` : "—", tone: analysis?.tone },
        { label: "Active probing", value: "off", tone: "muted" },
      ]} />

      <SectionBar id="OT" label="Output · passive snapshot" meta={data ? `${signals.length} signals · ${data.subdomains.length} subdomains · ${data.ports.length} ports` : "load a target to populate"} />

      {!data ? (
        <Empty icon={Globe2} title="No target loaded" hint="Choose a synthetic sample above to render the passive reconnaissance surface." />
      ) : (
        <div className="space-y-4">
          <ResultBanner
            badge="passive_recon"
            caseId={`BA-RC-${data.target.length}`}
            title={data.target}
            subtitle={data.org ? `${data.org} — ${data.whois.country}` : `Registered: ${data.whois.created} · ${data.whois.country}`}
            reasons={signals.slice(0, 3).map((s) => s.t)}
            metrics={[
              { label: "Age", value: `${classifyDomainAge(data.whois.created)}y`, tone: classifyDomainAge(data.whois.created) < 1 ? "warning" : "success" },
              { label: "Subdomains", value: data.subdomains.length, tone: data.subdomains.length > 4 ? "warning" : "default" },
              { label: "Tech", value: data.tech.length },
              { label: "Hdr gaps", value: Object.entries(data.http.headers).filter(([k, v]) => v === "missing" && k !== "Server").length, tone: "warning" },
            ]}
          />

          {/* Risk Score */}
          <RiskScore
            score={analysis!.score}
            label="Exposure Risk"
            confidence={analysis!.confidence}
            tone={analysis!.tone}
          />

          {/* WHOIS / RDAP */}
          <Panel title="WHOIS / RDAP" icon={Search} meta={data.whois.registrar}>
            <KeyFields items={[
              { label: "Registrar", value: data.whois.registrar },
              { label: "Created", value: data.whois.created, tone: classifyDomainAge(data.whois.created) < 1 ? "warning" : "success" },
              { label: "Expires", value: data.whois.expires },
              { label: "Country", value: data.whois.country, tone: data.whois.country === "US" ? "success" : "warning" },
              { label: "Status", value: data.whois.status, tone: WHOIS_GATE.includes(data.whois.status) ? "warning" : "default" },
              { label: "Org", value: data.whois.org, tone: data.whois.org === "—" ? "muted" : "default" },
              { label: "Contacts", value: data.whois.emails.join(", "), tone: "muted" },
            ]} />
          </Panel>

          {/* DNS Records */}
          <Panel title="DNS Records" icon={Network} meta={`${Object.values(data.dns).flat().length} RRs`}>
            <div className="grid gap-2 sm:grid-cols-2">
              {Object.entries(data.dns).map(([rr, vals]) =>
                vals.length > 0 && (
                  <div key={rr} className="rounded border border-border/60 bg-card/50 p-2.5">
                    <div className="flex items-center gap-1.5 mb-1">
                      <Chip tone="primary">{rr}</Chip>
                      <span className="text-mono text-[10px] text-muted-foreground">×{vals.length}</span>
                    </div>
                    <div className="space-y-0.5">
                      {(vals as string[]).map((v) => (
                        <div key={v} className="text-mono text-[10.5px] text-foreground/85 leading-snug">{v}</div>
                      ))}
                    </div>
                  </div>
                )
              )}
            </div>
          </Panel>

          {/* TLS Certificate */}
          {data.tls && (
            <Panel title="TLS Certificate" icon={Lock} meta={`${data.tls.sans.length} SANs`}>
              <KeyFields items={[
                { label: "Issuer", value: data.tls.issuer },
                { label: "Subject", value: data.tls.subject },
                { label: "Valid from", value: data.tls.validFrom },
                { label: "Valid to", value: data.tls.validTo, tone: new Date(data.tls.validTo).getTime() - Date.now() < 30 * 24 * 60 * 60 * 1000 ? "warning" : "default" },
                { label: "SANs", value: data.tls.sans.join(", "), tone: "muted" },
                { label: "Self-signed", value: data.tls.selfSigned ? "YES" : "no", tone: data.tls.selfSigned ? "destructive" : "success" },
              ]} />
            </Panel>
          )}

          {/* HTTP Headers */}
          <Panel title="HTTP Headers" icon={Server} meta={`${data.http.status} · ${data.http.server}`}>
            <KeyFields items={[
              { label: "Status", value: data.http.status, tone: data.http.status === 200 ? "success" : "warning" },
              { label: "Server", value: data.http.server },
              { label: "Redirects", value: data.http.redirects },
              ...Object.entries(data.http.headers).filter(([k]) => k !== "Server").map(([k, v]) => ({
                label: k, value: v, tone: (v === "missing" ? "warning" : v === "nosniff" || v.includes("preload") || v.includes("SAMEORIGIN") ? "success" : "default") as "warning" | "success" | "default",
              })),
            ]} />
          </Panel>

          {/* Subdomains */}
          <Panel title="Subdomain Enumeration" icon={Link2} meta={`${data.subdomains.filter((s) => s.resolved).length} resolved · ${data.subdomains.filter((s) => !s.resolved).length} unresolved`}>
            <div className="space-y-1">
              {data.subdomains.map((s) => (
                <div key={s.name} className="flex items-center justify-between gap-2 border-b border-border/40 py-1 text-mono text-[11px]">
                  <div className="flex items-center gap-2 min-w-0">
                    {s.resolved ? (
                      <span className="h-1.5 w-1.5 shrink-0 rounded-full bg-success/70" />
                    ) : (
                      <span className="h-1.5 w-1.5 shrink-0 rounded-full bg-muted-foreground/40" />
                    )}
                    <code className="text-foreground/90 truncate">{s.name}</code>
                  </div>
                  <span className={"shrink-0 text-mono text-[10px] " + (s.resolved ? "text-foreground/70" : "text-muted-foreground")}>
                    {s.resolved ? s.ip : "unresolved"}
                  </span>
                </div>
              ))}
            </div>
          </Panel>

          {/* Technology Stack */}
          <Panel title="Technology Stack" icon={Cpu} meta={`${data.tech.length} component(s)`}>
            <div className="flex flex-wrap gap-2">
              {data.tech.map((t) => (
                <span key={t.name} className="inline-flex items-center gap-1.5 rounded border border-border/60 bg-card/40 px-2 py-1 text-mono text-[11px] text-foreground/85">
                  {t.version ? `${t.name} ${t.version}` : t.name}
                  <Chip tone="default">{t.category}</Chip>
                </span>
              ))}
            </div>
          </Panel>

          {/* Ports */}
          <Panel title="Ports / Services" icon={Server} meta={`${data.ports.length} open`}>
            <div className="grid gap-2 sm:grid-cols-3">
              {data.ports.map((p) => (
                <div key={p.port} className="rounded border border-border/60 bg-card/50 p-2.5 text-center">
                  <div className="text-mono text-[13px] font-semibold text-foreground">{p.port}</div>
                  <div className="text-mono text-[10px] uppercase tracking-widest text-foreground/80">{p.service}</div>
                  <Chip tone={p.state === "open" ? "warning" : "default"}>{p.state}</Chip>
                </div>
              ))}
            </div>
          </Panel>

          {/* CT Logs */}
          {data.ctLogs.length > 0 && (
            <Panel title="Certificate Transparency" icon={FileSearch} meta={`${data.ctLogs.length} log(s)`}>
              <ul className="space-y-1">
                {data.ctLogs.map((e) => (
                  <li key={e.logName + e.loggedAt} className="flex items-center justify-between gap-2 border-b border-border/40 py-1 text-mono text-[11px]">
                    <span className="text-foreground/90">{e.logName}</span>
                    <span className="text-muted-foreground">{new Date(e.loggedAt).toLocaleDateString()}</span>
                  </li>
                ))}
              </ul>
            </Panel>
          )}

          {/* Recon Messages */}
          <Panel title="Observations" icon={AlertTriangle} meta={`${data.messages.length}`}>
            <KeyFields items={data.messages} />
          </Panel>

          {/* IOC Inventory */}
          <IocInventory
            groups={[
              { kind: "Domain", items: [data.target], tone: "primary" },
              ...(data.dns.A.length ? [{ kind: "IPv4", items: data.dns.A, tone: "warning" as const }] : []),
              ...(data.dns.AAAA.length ? [{ kind: "IPv6", items: data.dns.AAAA, tone: "info" as const }] : []),
              ...(data.dns.MX.length ? [{ kind: "Mail", items: data.dns.MX, tone: "default" as const }] : []),
              ...(data.subdomains.filter((s) => s.resolved).length ? [{ kind: "Subdomain", items: data.subdomains.filter((s) => s.resolved).map((s) => s.name), tone: "info" as const }] : []),
            ]}
            onSendTo={() => {}}
          />

          {/* MITRE ATT&CK */}
          {data.mitre.length > 0 && (
            <Panel title="MITRE ATT&CK Mapping" icon={Crosshair} meta={`${data.mitre.length} technique${data.mitre.length === 1 ? "" : "s"}`}>
              <div className="flex flex-wrap gap-2">
                {data.mitre.map((m) => (
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

          {/* Evidence Cards */}
          <div className="grid gap-3 md:grid-cols-2">
            {signals.map((s, i) => (
              <EvidenceCard key={i} severity={s.sev} title={s.t} reason={s.r} action={s.a} limitation="Passive snapshot — re-verify before any action." />
            ))}
          </div>

          {/* Export */}
          <Panel title="Export" icon={Download}>
            <div className="flex flex-wrap gap-2">
              <button
                onClick={() => {
                  const md = genMarkdownExport(data, analysis!.score, signals);
                  const blob = new Blob([md], { type: "text/markdown" });
                  const url = URL.createObjectURL(blob);
                  const a = document.createElement("a");
                  a.href = url; a.download = `recon-${data.target}.md`;
                  a.click(); URL.revokeObjectURL(url);
                }}
                className="inline-flex items-center gap-1.5 rounded border border-primary/40 bg-primary/10 px-2.5 py-1.5 text-mono text-[10px] uppercase tracking-widest text-primary transition-all hover:bg-primary/20 hover:shadow-[0_0_12px_-2px_hsl(var(--primary)/0.45)]"
              >
                <Download className="h-3 w-3" /> Download Markdown Report
              </button>
              <button
                onClick={() => {
                  const md = genMarkdownExport(data, analysis!.score, signals);
                  navigator.clipboard.writeText(md);
                }}
                className="inline-flex items-center gap-1.5 rounded border border-border bg-card/60 px-2.5 py-1.5 text-mono text-[10px] uppercase tracking-widest text-muted-foreground transition-colors hover:border-primary/40 hover:text-foreground"
              >
                <Hash className="h-3 w-3" /> Copy Report
              </button>
            </div>
          </Panel>

          <SendToRow targets={[
            { label: "OSINT Toolkit", to: "/osint", icon: FileSearch },
            { label: "Nmap Runner", to: "/nmap", icon: Server },
            { label: "Detection", to: "/detection", icon: ShieldAlert },
            { label: "Logs & Alerts", to: "/logs", icon: Database },
            { label: "Case Notebook", to: "/case", icon: ArrowRight },
          ]} />
        </div>
      )}
    </PageShell>
  );
}
