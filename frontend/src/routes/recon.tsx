import { createFileRoute } from "@tanstack/react-router";
import { useState } from "react";
import { PageShell } from "@/components/PageShell";
import { IntakeCard, SectionBar, Panel, SendToRow, Chip, IocInventory } from "@/components/soc";
import { StatusBar, KeyFields, Empty, EvidenceCard, TwoColumnOutput, MetricGrid, CollapsibleSection } from "@/components/output";
import { useOutputFilter, OutputFilterBar, OutputFilter } from "@/components/soc/OutputFilter";
import { useLocker } from "@/lib/locker";
import { CopyInline } from "@/components/CopyButton";
import { toast } from "sonner";
import { Globe as Globe2, Search, ShieldAlert, Database, ArrowRight, Zap, Server, Lock, FileSearch, TriangleAlert as AlertTriangle, Download, Hash, Network, Activity, ExternalLink, Terminal, Globe, AtSign, ScrollText, History, KeyRound, Award, Copy, Check } from "lucide-react";
import { passiveRecon } from "@/api/backend";
import { sendToCase } from "@/lib/handoff";
import { pushTimelineEvent } from "@/lib/timeline";

export const Route = createFileRoute("/recon")({ component: ReconPage });

interface DnsData {
  A: string[]; AAAA: string[]; MX: string[]; NS: string[]; TXT: string[]; CNAME: string[];
}

interface HttpResult {
  url: string; status_code: number; server: string | null; content_type: string | null;
  redirect_count?: number; headers: Record<string, string>;
}

/* ── Compact OSINT tools for inline integration ── */
type OsintKind = "domain" | "ipv4";
type OsintTool = { id: string; label: string; cat: string; tagline: string; href: (v: string) => string; supports: OsintKind[] };
const OSINT_TOOLS: OsintTool[] = [
  { id: "vt", label: "VirusTotal", cat: "Reputation", tagline: "Hash / URL / IP reputation aggregate.", supports: ["domain","ipv4"], href: (v) => `https://www.virustotal.com/gui/search/${encodeURIComponent(v)}` },
  { id: "abuseipdb", label: "AbuseIPDB", cat: "Reputation", tagline: "IP abuse confidence score.", supports: ["ipv4"], href: (v) => `https://www.abuseipdb.com/check/${encodeURIComponent(v)}` },
  { id: "otx", label: "AlienVault OTX", cat: "Reputation", tagline: "Threat-intel pulses & indicators.", supports: ["domain","ipv4"], href: (v) => `https://otx.alienvault.com/browse/global/pulses?q=${encodeURIComponent(v)}` },
  { id: "shodan", label: "Shodan", cat: "Exposure", tagline: "Internet-facing service map.", supports: ["domain","ipv4"], href: (v) => `https://www.shodan.io/search?query=${encodeURIComponent(v)}` },
  { id: "censys", label: "Censys", cat: "Exposure", tagline: "Host & certificate search.", supports: ["domain","ipv4"], href: (v) => `https://search.censys.io/search?q=${encodeURIComponent(v)}` },
  { id: "greynoise", label: "GreyNoise", cat: "Exposure", tagline: "Internet scanner / noise context.", supports: ["ipv4"], href: (v) => `https://viz.greynoise.io/ip/${encodeURIComponent(v)}` },
  { id: "crtsh", label: "crt.sh", cat: "Certificates", tagline: "CT log certificate history.", supports: ["domain"], href: (v) => `https://crt.sh/?q=${encodeURIComponent(v)}` },
  { id: "securitytrails", label: "SecurityTrails", cat: "DNS", tagline: "Historic DNS & subdomain graph.", supports: ["domain","ipv4"], href: (v) => `https://securitytrails.com/list/apex_domain/${encodeURIComponent(v)}` },
  { id: "whoisxml", label: "WhoisXML", cat: "WHOIS", tagline: "Registration & registrar.", supports: ["domain"], href: (v) => `https://whois.whoisxmlapi.com/lookup?domain=${encodeURIComponent(v)}` },
  { id: "urlscan", label: "urlscan.io", cat: "URL", tagline: "Render & analyse a URL safely.", supports: ["domain"], href: (v) => `https://urlscan.io/search/#${encodeURIComponent(v)}` },
  { id: "viewdns", label: "ViewDNS reverse-ip", cat: "DNS", tagline: "Find siblings on a shared host.", supports: ["domain","ipv4"], href: (v) => `https://viewdns.info/reverseip/?host=${encodeURIComponent(v)}` },
  { id: "pulsedive", label: "Pulsedive", cat: "Threat Intel", tagline: "Threat indicator scoring.", supports: ["domain","ipv4"], href: (v) => `https://pulsedive.com/indicator/?query=${encodeURIComponent(v)}` },
  { id: "talos", label: "Talos Intelligence", cat: "Threat Intel", tagline: "Cisco threat intelligence.", supports: ["domain","ipv4"], href: (v) => `https://talosintelligence.com/reputation_center/lookup?search=${encodeURIComponent(v)}` },
  { id: "domaintools", label: "DomainTools", cat: "WHOIS", tagline: "WHOIS history & domain profile.", supports: ["domain","ipv4"], href: (v) => `https://whois.domaintools.com/${encodeURIComponent(v)}` },
  { id: "leakix", label: "LeakIX", cat: "Discovery", tagline: "Open data & leak index.", supports: ["domain","ipv4"], href: (v) => `https://leakix.net/search?q=${encodeURIComponent(v)}` },
  { id: "intelx", label: "IntelX", cat: "Discovery", tagline: "Dark web & data leak search.", supports: ["domain","ipv4"], href: (v) => `https://intelx.io/?s=${encodeURIComponent(v)}` },
  { id: "google", label: "Google dork", cat: "Search", tagline: "Indexed surface for a host.", supports: ["domain","ipv4"], href: (v) => `https://www.google.com/search?q=site%3A${encodeURIComponent(v)}` },
  { id: "github", label: "GitHub code", cat: "Search", tagline: "Leaked refs & config snippets.", supports: ["domain","ipv4"], href: (v) => `https://github.com/search?q=${encodeURIComponent(v)}&type=code` },
  { id: "wayback", label: "Wayback Machine", cat: "Archive", tagline: "Historical page snapshots.", supports: ["domain"], href: (v) => `https://web.archive.org/web/*/${encodeURIComponent(v)}` },
];
const OSINT_CATS = Array.from(new Set(OSINT_TOOLS.map((t) => t.cat)));
const OSINT_CAT_META: Record<string, { tone: "primary" | "warning" | "success" | "info" | "accent" }> = {
  Reputation:   { tone: "warning" },
  Exposure:     { tone: "info" },
  Certificates: { tone: "accent" },
  DNS:          { tone: "primary" },
  WHOIS:        { tone: "primary" },
  "Threat Intel": { tone: "warning" },
  Discovery:    { tone: "primary" },
  Search:       { tone: "info" },
  Archive:      { tone: "info" },
  URL:          { tone: "primary" },
};

interface SslResult {
  subject: Record<string, string>; issuer: Record<string, string>;
  not_before: string; not_after: string; subject_alt_names: [string, string][];
}

interface ReconApiResult {
  target: { original: string; hostname: string; root_domain: string; type: string };
  dns: { records: Record<string, string[]>; errors: Record<string, string> } | null;
  http: HttpResult | { error: string } | null;
  ssl: SslResult | { error: string } | null;
  whois: { skipped: string } | null;
  rdap: { skipped: string } | null;
  warning?: string;
}

function flattenDns(dns: { records: Record<string, string[]> } | null): DnsData {
  const r = dns?.records ?? {};
  return { A: r.A || [], AAAA: r.AAAA || [], MX: r.MX || [], NS: r.NS || [], TXT: r.TXT || [], CNAME: r.CNAME || [] };
}

function getHttp(http: ReconApiResult["http"]): HttpResult | null {
  return http && "error" in http ? null : http as HttpResult | null;
}

function getSsl(ssl: ReconApiResult["ssl"]): SslResult | null {
  return ssl && "error" in ssl ? null : ssl as SslResult | null;
}

function findSignals(api: ReconApiResult): { sev: "destructive" | "warning" | "info" | "success"; t: string; r: string; a: string }[] {
  const signals: { sev: "destructive" | "warning" | "info" | "success"; t: string; r: string; a: string }[] = [];
  const http = getHttp(api.http);
  const ssl = getSsl(api.ssl);
  const dns = flattenDns(api.dns);

  if (ssl) {
    if (Object.values(ssl.subject).some((v) => v.startsWith("*."))) {
      signals.push({ sev: "info", t: "Wildcard TLS certificate", r: "Covers any subdomain — pivots across siblings cheap for attackers.", a: "Enumerate SANs for related infrastructure." });
    }
    if (ssl.not_after) {
      const expiryMs = new Date(ssl.not_after).getTime();
      const daysLeft = Math.floor((expiryMs - Date.now()) / (1000 * 60 * 60 * 24));
      if (daysLeft < 0) signals.push({ sev: "warning", t: "TLS certificate expired", r: `Expired ${Math.abs(daysLeft)} day(s) ago.`, a: "Verify current certificate and renewal process." });
      else if (daysLeft < 14) signals.push({ sev: "warning", t: `TLS certificate expires in ${daysLeft} day(s)`, r: "Certificate nearing expiry.", a: "Renew before expiration to avoid trust errors." });
      else if (daysLeft < 30) signals.push({ sev: "info", t: "TLS certificate expiring soon", r: `Expires in ${daysLeft} day(s).`, a: "Plan renewal window." });
    }
    if (ssl.not_before) {
      const ageDays = Math.floor((Date.now() - new Date(ssl.not_before).getTime()) / (1000 * 60 * 60 * 24));
      if (ageDays < 14) signals.push({ sev: "info", t: "TLS certificate issued recently", r: `Issued ${ageDays} day(s) ago — may indicate renewed infrastructure.`, a: "Check CT logs for related domain issuance." });
    }
  }

  if (http) {
    const h = http.headers;
    const absent = ["strict-transport-security", "content-security-policy", "x-frame-options", "x-content-type-options", "referrer-policy"]
      .filter((k) => !h[k]).length;
    if (absent >= 3) signals.push({ sev: "warning", t: `${absent} security headers absent`, r: "HSTS / CSP / X-Frame-Options / X-Content-Type-Options / Referrer-Policy gaps increase attack surface.", a: "Note hardening posture in report." });
    else if (absent >= 1) signals.push({ sev: "info", t: `${absent} security header(s) absent`, r: "Partial hardening — check individual headers for gaps.", a: "Recommend HSTS and CSP for production." });
    if (http.status_code === 301 || http.status_code === 302) signals.push({ sev: "info", t: "HTTP redirect on root", r: "Root resolves via redirect — landing page may differ from index.", a: "Follow redirect chain for full exposure picture." });
  }

  if (dns.AAAA.length === 0 && (dns.A.length > 0)) signals.push({ sev: "info", t: "No IPv6 DNS records", r: "AAAA records absent — host not reachable over IPv6.", a: "Low risk; note for completeness." });
  if (dns.A.length > 0 && dns.A.length < 2) signals.push({ sev: "info", t: "Single A record", r: `Only ${dns.A.length} A record(s) — no redundancy.`, a: "Verify expected DNS configuration." });

  if (!signals.length) signals.push({ sev: "success", t: "No notable risk signals", r: "Target passes basic passive recon checks.", a: "Proceed with active scanning if authorized." });
  return signals;
}

function genJsonExport(api: ReconApiResult, targetStr: string): string {
  const http = getHttp(api.http);
  const ssl = getSsl(api.ssl);
  const dns = flattenDns(api.dns);
  const iocs: Record<string, string[]> = {
    Domain: [targetStr],
    ...(dns.A.length ? { IPv4: dns.A } : {}),
    ...(dns.AAAA.length ? { IPv6: dns.AAAA } : {}),
    ...(dns.MX.length ? { Mail: dns.MX } : {}),
    ...(dns.NS.length ? { Nameserver: dns.NS } : {}),
    ...(ssl ? { SAN: (ssl.subject_alt_names || []).map(([, v]) => v) } : {}),
  };
  return JSON.stringify({
    version: "1.0", ts: new Date().toISOString(), target: targetStr,
    dns, ssl, http, iocs,
  }, null, 2);
}

function genMarkdownExport(api: ReconApiResult, targetStr: string, signals: any[]): string {
  const http = getHttp(api.http);
  const ssl = getSsl(api.ssl);
  const dns = flattenDns(api.dns);
  const lines = [
    `# Reconnaissance Report`,
    `**Target:** \`${targetStr}\``,
    `**Generated:** ${new Date().toISOString()}`,
    "", "## DNS Records",
  ];
  for (const [rr, vals] of Object.entries(dns)) {
    if (vals.length) lines.push(`- ${rr}: ${vals.join(", ")}`);
  }
  if (ssl) {
    lines.push("", "## TLS Certificate",
      `- Issuer: ${Object.entries(ssl.issuer).map(([k, v]) => `${k}=${v}`).join(", ")}`,
      `- Subject: ${Object.entries(ssl.subject).map(([k, v]) => `${k}=${v}`).join(", ")}`,
      `- Valid: ${ssl.not_before} → ${ssl.not_after}`,
      `- SANs: ${(ssl.subject_alt_names || []).map(([, v]) => v).join(", ")}`);
  }
  if (http) {
    lines.push("", "## HTTP Headers",
      `- URL: ${http.url}`,
      `- Status: ${http.status_code}`,
      `- Server: ${http.server || "—"}`);
    for (const [k, v] of Object.entries(http.headers)) lines.push(`- ${k}: ${v}`);
  }
  lines.push("", "## Signals", ...signals.map((s: any) => `- [${s.sev.toUpperCase()}] ${s.t}`));
  return lines.join("\n");
}

function ReconPage() {
  const [target, setTarget] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const { filterText, setFilterText, showFilter, setShowFilter, toggleFilter } = useOutputFilter();
  const locker = useLocker();
  const [result, setResult] = useState<ReconApiResult | null>(null);


  const dns = result ? flattenDns(result.dns) : null;
  const http = result ? getHttp(result.http) : null;
  const ssl = result ? getSsl(result.ssl) : null;
  const signals = result ? findSignals(result) : [];

  /* ── OSINT tools inline ── */
  const osintTarget = result?.target?.hostname || target;
  const isIp = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(osintTarget);
  const osintKind = isIp ? "ipv4" as const : "domain" as const;

  async function handleRun() {
    if (!target.trim()) return;
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const res = await passiveRecon(target.trim());
      setResult(res as unknown as ReconApiResult);
      pushTimelineEvent({ source: "recon", verb: "enumerated", detail: `Enumerated ${target.trim()}`, target: target.trim() });
      toast.success("Recon complete", { description: target.trim() });
    } catch (e: any) {
      const msg = e?.suggestion ? `${e.message} — ${e.suggestion}` : (e?.message || "passive recon failed");
      setError(msg);
      toast.error(e?.message || "Recon failed", { description: e?.suggestion || target.trim() });
    } finally {
      setLoading(false);
    }
  }

  return (
    <PageShell
      eyebrow="RECON"
      title="Reconnaissance"
      description="Passive reconnaissance — DNS, TLS, HTTP headers — with per‑IP OSINT lookups built into DNS records."
      crumbs={[{ label: "Recon" }, { label: "Passive" }]}
      jumps={[{ label: "Port Scan", to: "/nmap" }]}
    >
      <SectionBar id="IN" label="Intake · target" meta={target ? target : "enter a target"} />
      <IntakeCard
        icon={Globe2}
        title="Target"
        value={target}
        onChange={(v) => { setTarget(v); setResult(null); setError(null); }}
        rows={2}
        placeholder="example.com"
        samples={[
          { key: "h", label: "example.com" },
          { key: "i", label: "198.51.100.1" },
          { key: "g", label: "google.com" },
        ]}
        onLoadSample={(k) => setTarget(k === "h" ? "example.com" : k === "i" ? "198.51.100.1" : "google.com")}
        run={{ label: loading ? "probing..." : "enumerate", icon: Zap, hint: "⌘↵", onClick: handleRun, disabled: !target.trim() || loading }}
        onClear={() => { setTarget(""); setResult(null); setError(null); }}
        showCopy={false}
      />

      <StatusBar stats={[
        { label: "Status", value: loading ? "probing..." : error ? "error" : result ? "Snapshot ready" : "Idle", tone: error ? "destructive" : loading ? "warning" : result ? "success" : "muted" },
        { label: "Sources", value: "DNS · TLS · HTTP · WHOIS", tone: "primary" },
        { label: "Active probing", value: "off", tone: "muted" },
      ]} />

      <SectionBar id="OT" label="Output · recon snapshot" meta={result ? `${signals.length} signals` : "enter a target to populate"} />

      {showFilter && (
        <OutputFilterBar
          filterText={filterText}
          onChange={setFilterText}
          onClear={() => setFilterText("")}
          onClose={() => { setShowFilter(false); setFilterText(""); }}
        />
      )}

      {!result && !loading && !error && (
        <Empty icon={Globe2} title="No target loaded" hint="Recon resolves DNS records (A/AAAA/MX/NS/TXT), fetches WHOIS data, probes HTTP headers and TLS certificates, and checks subdomain sources. Enter a domain above and click enumerate." />
      )}

      {loading && (
        <Panel title="Probing" icon={Search} priority="secondary">
          <p className="text-mono ba-text-sm text-muted-foreground">Resolving DNS, looking up WHOIS, probing HTTP, fetching TLS certificate...</p>
        </Panel>
      )}

      {error && (
        <Panel title="Error" icon={AlertTriangle} priority="secondary">
          <p className="text-mono ba-text-sm text-destructive">{error}</p>
        </Panel>
      )}

      {result && !loading && (
        <OutputFilter query={filterText.toLowerCase()}>
        <div className="space-y-5">
          {/* Metrics Overview */}
          <MetricGrid
            columns={4}
            metrics={[
              { label: "DNS RRs", value: dns ? Object.values(dns).flat().length : 0, tone: "primary", icon: Network },
              { label: "TLS", value: ssl ? "Valid" : "None", tone: ssl ? "success" : "muted", icon: Lock },
              { label: "HTTP", value: http ? http.status_code : "—", tone: http && http.status_code < 400 ? "success" : http ? "warning" : "default", icon: Server },
              { label: "Signals", value: signals.length, tone: signals.some((s) => s.sev === "destructive" || s.sev === "warning") ? "warning" : "default", icon: Activity },
              { label: "IPv4", value: dns?.A?.length ?? 0 },
              { label: "IPv6", value: dns?.AAAA?.length ?? 0, tone: dns?.AAAA?.length ? "success" : "default" },
              { label: "MX", value: dns?.MX?.length ?? 0 },
              { label: "SANs", value: ssl?.subject_alt_names?.length ?? 0 },
            ]}
          />

          {result.warning && (
            <Panel title="Warning" icon={AlertTriangle} priority="secondary">
              <p className="text-mono ba-text-sm text-muted-foreground">{result.warning}</p>
            </Panel>
          )}

          {result.whois && "skipped" in result.whois && (
            <Panel title="WHOIS / RDAP" icon={Search} meta="not available" priority="secondary" collapsible storageKey="ba.panel.recon.whois" defaultCollapsed>
              <p className="text-mono ba-text-sm text-muted-foreground">{(result.whois as any).skipped}</p>
            </Panel>
          )}
          {result.whois && !("skipped" in result.whois) && (result.whois as any).raw && (
            <Panel title="WHOIS" icon={Search} meta={(result.whois as any).registrar ? (result.whois as any).registrar : "registered"} priority="secondary" collapsible storageKey="ba.panel.recon.whois" defaultCollapsed>
              <div className="space-y-2">
                {((result.whois as any).registrar && (
                  <div className="grid grid-cols-2 gap-2">
                    {(result.whois as any).registrar && <KeyFields items={[{ label: "Registrar", value: (result.whois as any).registrar }]} />}
                    {(result.whois as any).organization && <KeyFields items={[{ label: "Organization", value: (result.whois as any).organization }]} />}
                  </div>
                ))}
                <div className="grid grid-cols-2 gap-2">
                  {(result.whois as any).creation_date && <KeyFields items={[{ label: "Created", value: (result.whois as any).creation_date }]} />}
                  {(result.whois as any).expiry_date && <KeyFields items={[{ label: "Expires", value: (result.whois as any).expiry_date }]} />}
                </div>
                {(result.whois as any).name_servers?.length > 0 && (
                  <div>
                    <span className="text-mono text-[10px] uppercase tracking-widest text-muted-foreground">Name Servers</span>
                    <div className="mt-1 flex flex-wrap gap-1">
                      {(result.whois as any).name_servers.map((ns: string) => <Chip key={ns}>{ns}</Chip>)}
                    </div>
                  </div>
                )}
                {(result.whois as any).status?.length > 0 && (
                  <div>
                    <span className="text-mono text-[10px] uppercase tracking-widest text-muted-foreground">Domain Status</span>
                    <div className="mt-1 flex flex-wrap gap-1">
                      {(result.whois as any).status.map((s: string) => <Chip key={s} tone="info">{s}</Chip>)}
                    </div>
                  </div>
                )}
                <button onClick={() => navigator.clipboard.writeText((result.whois as any).raw)} className="inline-flex items-center gap-1 rounded border border-border/50 bg-card/40 px-2 py-1 text-mono ba-text-3xs uppercase tracking-widest text-muted-foreground hover:bg-card/70 hover:text-foreground"><Copy className="h-3 w-3" /> copy raw WHOIS</button>
              </div>
            </Panel>
          )}
          {result.rdap && !("skipped" in result.rdap) && (result.rdap as any).handle && (
            <Panel title="RDAP" icon={Search} meta={(result.rdap as any).organization || "registered"} priority="secondary" collapsible storageKey="ba.panel.recon.rdap">
              <KeyFields items={[
                { label: "Handle", value: (result.rdap as any).handle },
                ...((result.rdap as any).range ? [{ label: "Range", value: (result.rdap as any).range }] : []),
                ...((result.rdap as any).organization ? [{ label: "Organization", value: (result.rdap as any).organization }] : []),
                ...((result.rdap as any).name ? [{ label: "Name", value: (result.rdap as any).name }] : []),
              ]} />
              <button onClick={() => navigator.clipboard.writeText((result.rdap as any).raw)} className="mt-2 inline-flex items-center gap-1 rounded border border-border/50 bg-card/40 px-2 py-1 text-mono ba-text-3xs uppercase tracking-widest text-muted-foreground hover:bg-card/70 hover:text-foreground"><Copy className="h-3 w-3" /> copy raw RDAP</button>
            </Panel>
          )}

          {/* DNS + TLS side-by-side */}
          {dns && (dns.A.length > 0 || dns.AAAA.length > 0) && ssl && (
            <TwoColumnOutput
              ratio="1:1"
              left={
                <Panel title="DNS Records" icon={Network} meta={`${Object.values(dns).flat().length} RRs`} actions={
                  <div className="flex items-center gap-1">
                    <a href={`https://crt.sh/?q=${encodeURIComponent(result?.target?.hostname || target)}`} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 rounded border border-border/50 px-1.5 py-0.5 text-mono ba-text-3xs uppercase tracking-widest text-muted-foreground hover:text-primary hover:border-primary/40"><ExternalLink className="h-2.5 w-2.5" /> crt.sh</a>
                    <a href={`https://securitytrails.com/list/apex_domain/${encodeURIComponent(result?.target?.root_domain || target)}`} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 rounded border border-border/50 px-1.5 py-0.5 text-mono ba-text-3xs uppercase tracking-widest text-muted-foreground hover:text-primary hover:border-primary/40"><ExternalLink className="h-2.5 w-2.5" /> SecurityTrails</a>
                  </div>
                }>
                  <div className="grid gap-2 grid-cols-2">
                    {Object.entries(dns).filter(([, vals]) => vals.length > 0).map(([rr, vals]) => (
                      <div key={rr} className="rounded border border-divider-strong bg-card/50 p-2.5">
                        <div className="mb-1 flex items-center gap-1.5">
                          <Chip tone="primary">{rr}</Chip>
                          <span className="text-mono text-[10px] text-muted-foreground">×{vals.length}</span>
                        </div>
                        <div className="space-y-0.5">
                          {(vals as string[]).map((v) => {
                            const isIp = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(v);
                            return (
                              <div key={v} className="group flex items-center gap-1">
                                <span className="text-mono text-[10.5px] text-foreground/85 leading-snug">{v}</span>
                                <CopyInline value={v} />
                                {isIp && (
                                  <div className="ml-auto hidden gap-0.5 group-hover:flex">
                                    <a href={`https://www.abuseipdb.com/check/${encodeURIComponent(v)}`} target="_blank" rel="noopener noreferrer" className="rounded border border-divider-soft bg-card/50 px-1 py-0.5 text-mono text-[8px] uppercase tracking-widest text-muted-foreground hover:text-primary hover:border-primary/40" title="AbuseIPDB">Abuse</a>
                                    <a href={`https://www.shodan.io/search?query=${encodeURIComponent(v)}`} target="_blank" rel="noopener noreferrer" className="rounded border border-divider-soft bg-card/50 px-1 py-0.5 text-mono text-[8px] uppercase tracking-widest text-muted-foreground hover:text-primary hover:border-primary/40" title="Shodan">Shodan</a>
                                    <a href={`https://viz.greynoise.io/ip/${encodeURIComponent(v)}`} target="_blank" rel="noopener noreferrer" className="rounded border border-divider-soft bg-card/50 px-1 py-0.5 text-mono text-[8px] uppercase tracking-widest text-muted-foreground hover:text-primary hover:border-primary/40" title="GreyNoise">GN</a>
                                    <button onClick={() => { locker.add({ value: v, type: "ipv4", source: "/recon" }); toast(`Added ${v} to locker`); }} className="rounded border border-divider-soft bg-card/50 px-1 py-0.5 text-mono text-[8px] uppercase tracking-widest text-muted-foreground hover:text-primary hover:border-primary/40" title="add to locker">L</button>
                                  </div>
                                )}
                              </div>
                            );
                          })}
                        </div>
                      </div>
                    ))}
                  </div>
                </Panel>
              }
              right={
                <Panel title="TLS Certificate" icon={Lock} meta={`${(ssl.subject_alt_names || []).length} SANs`} actions={
                  <div className="flex items-center gap-1">
                    <a href={`https://www.virustotal.com/gui/search/${encodeURIComponent(result?.target?.hostname || target)}`} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 rounded border border-border/50 px-1.5 py-0.5 text-mono ba-text-3xs uppercase tracking-widest text-muted-foreground hover:text-primary hover:border-primary/40"><ExternalLink className="h-2.5 w-2.5" /> VT</a>
                    <a href={`https://crt.sh/?q=${encodeURIComponent(result?.target?.hostname || target)}`} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 rounded border border-border/50 px-1.5 py-0.5 text-mono ba-text-3xs uppercase tracking-widest text-muted-foreground hover:text-primary hover:border-primary/40"><ExternalLink className="h-2.5 w-2.5" /> crt.sh</a>
                  </div>
                }>
                  <KeyFields items={[
                    { label: "Issuer", value: Object.entries(ssl.issuer).map(([k, v]) => `${k}=${v}`).join(", ") },
                    { label: "Subject", value: Object.entries(ssl.subject).map(([k, v]) => `${k}=${v}`).join(", ") },
                    { label: "Valid from", value: ssl.not_before },
                    { label: "Valid to", value: ssl.not_after, tone: ssl.not_after && new Date(ssl.not_after).getTime() - Date.now() < 30 * 24 * 60 * 60 * 1000 ? "warning" : "default" },
                    { label: "SANs", value: (ssl.subject_alt_names || []).map(([, v]) => v).join(", "), tone: "muted" },
                  ]} />
                </Panel>
              }
            />
          )}

          {/* DNS-only panel if no TLS */}
          {dns && (dns.A.length > 0 || dns.AAAA.length > 0) && !ssl && (
            <Panel title="DNS Records" icon={Network} meta={`${Object.values(dns).flat().length} RRs`} actions={
              <div className="flex items-center gap-1">
                <a href={`https://crt.sh/?q=${encodeURIComponent(result?.target?.hostname || target)}`} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 rounded border border-border/50 px-1.5 py-0.5 text-mono ba-text-3xs uppercase tracking-widest text-muted-foreground hover:text-primary hover:border-primary/40"><ExternalLink className="h-2.5 w-2.5" /> crt.sh</a>
              </div>
            }>
              <div className="grid gap-2 grid-cols-3">
                {Object.entries(dns).filter(([, vals]) => vals.length > 0).map(([rr, vals]) => (
                  <div key={rr} className="rounded border border-divider-strong bg-card/50 p-2.5">
                    <div className="mb-1 flex items-center gap-1.5">
                      <Chip tone="primary">{rr}</Chip>
                      <span className="text-mono text-[10px] text-muted-foreground">×{vals.length}</span>
                    </div>
                    <div className="space-y-0.5">
                      {(vals as string[]).map((v) => {
                        const isIp = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(v);
                        return (
                          <div key={v} className="group flex items-center gap-1">
                            <span className="text-mono text-[10.5px] text-foreground/85 leading-snug">{v}</span>
                            <CopyInline value={v} />
                            {isIp && (
                              <div className="ml-auto hidden gap-0.5 group-hover:flex">
                                <a href={`https://www.abuseipdb.com/check/${encodeURIComponent(v)}`} target="_blank" rel="noopener noreferrer" className="rounded border border-divider-soft bg-card/50 px-1 py-0.5 text-mono text-[8px] uppercase tracking-widest text-muted-foreground hover:text-primary hover:border-primary/40" title="AbuseIPDB">Abuse</a>
                                <a href={`https://www.shodan.io/search?query=${encodeURIComponent(v)}`} target="_blank" rel="noopener noreferrer" className="rounded border border-divider-soft bg-card/50 px-1 py-0.5 text-mono text-[8px] uppercase tracking-widest text-muted-foreground hover:text-primary hover:border-primary/40" title="Shodan">Shodan</a>
                                <a href={`https://viz.greynoise.io/ip/${encodeURIComponent(v)}`} target="_blank" rel="noopener noreferrer" className="rounded border border-divider-soft bg-card/50 px-1 py-0.5 text-mono text-[8px] uppercase tracking-widest text-muted-foreground hover:text-primary hover:border-primary/40" title="GreyNoise">GN</a>
                                <button onClick={() => { locker.add({ value: v, type: "ipv4", source: "/recon" }); toast(`Added ${v} to locker`); }} className="rounded border border-divider-soft bg-card/50 px-1 py-0.5 text-mono text-[8px] uppercase tracking-widest text-muted-foreground hover:text-primary hover:border-primary/40" title="add to locker">L</button>
                              </div>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  </div>
                ))}
              </div>
            </Panel>
          )}

          {/* TLS-only panel if no DNS */}
          {ssl && !(dns && (dns.A.length > 0 || dns.AAAA.length > 0)) && (
            <Panel title="TLS Certificate" icon={Lock} meta={`${(ssl.subject_alt_names || []).length} SANs`} actions={
              <div className="flex items-center gap-1">
                <a href={`https://www.virustotal.com/gui/search/${encodeURIComponent(result?.target?.hostname || target)}`} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 rounded border border-border/50 px-1.5 py-0.5 text-mono ba-text-3xs uppercase tracking-widest text-muted-foreground hover:text-primary hover:border-primary/40"><ExternalLink className="h-2.5 w-2.5" /> VT</a>
                <a href={`https://crt.sh/?q=${encodeURIComponent(result?.target?.hostname || target)}`} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 rounded border border-border/50 px-1.5 py-0.5 text-mono ba-text-3xs uppercase tracking-widest text-muted-foreground hover:text-primary hover:border-primary/40"><ExternalLink className="h-2.5 w-2.5" /> crt.sh</a>
              </div>
            }>
              <KeyFields items={[
                { label: "Issuer", value: Object.entries(ssl.issuer).map(([k, v]) => `${k}=${v}`).join(", ") },
                { label: "Subject", value: Object.entries(ssl.subject).map(([k, v]) => `${k}=${v}`).join(", ") },
                { label: "Valid from", value: ssl.not_before },
                { label: "Valid to", value: ssl.not_after, tone: ssl.not_after && new Date(ssl.not_after).getTime() - Date.now() < 30 * 24 * 60 * 60 * 1000 ? "warning" : "default" },
                { label: "SANs", value: (ssl.subject_alt_names || []).map(([, v]) => v).join(", "), tone: "muted" },
              ]} />
            </Panel>
          )}

          {/* HTTP Headers - collapsible for long lists */}
          {http && (
            <Panel title="HTTP Headers" icon={Server} meta={`${http.status_code} · ${http.server || "unknown"}`} collapsible storageKey="ba.panel.recon.http" defaultCollapsed={Object.keys(http.headers).length > 10}>
              <KeyFields items={[
                { label: "URL", value: http.url },
                { label: "Status", value: http.status_code, tone: http.status_code < 400 ? "success" : "warning" },
                { label: "Server", value: http.server || "—" },
                { label: "Content-Type", value: http.content_type || "—" },
                ...Object.entries(http.headers).filter(([k]) => k !== "server" && k !== "Server").map(([k, v]) => ({
                  label: k, value: v || "(empty)", tone: (v ? "default" : "warning") as "warning" | "success" | "default",
                })),
              ]} />
            </Panel>
          )}

          {/* IOC Inventory */}
          {dns && (dns.A.length > 0 || dns.AAAA.length > 0) && (
            <CollapsibleSection id="IO" label="IOC Inventory" meta={`${(dns.A.length + dns.AAAA.length + dns.MX.length + dns.NS.length + 1)} indicators`} icon={Database}>
              <IocInventory
                groups={[
                  { kind: "Domain", items: [target], tone: "primary" as const },
                  ...(dns.A.length ? [{ kind: "IPv4", items: dns.A, tone: "warning" as const }] : []),
                  ...(dns.AAAA.length ? [{ kind: "IPv6", items: dns.AAAA, tone: "info" as const }] : []),
                  ...(dns.MX.length ? [{ kind: "Mail", items: dns.MX, tone: "default" as const }] : []),
                  ...(dns.NS.length ? [{ kind: "Nameserver", items: dns.NS, tone: "default" as const }] : []),
                ]}
                onSendTo={(v) => { try { localStorage.setItem("beyondlabs.pendingArtifact", JSON.stringify({ type: "ioc", value: v, source: "/recon" })); toast(`Sent ${v} to pending`); } catch {} }}
              />
              {result && (
                <div className="mt-1 flex flex-wrap gap-1.5">
                  {[["Domain", [target]], ...(dns.A.length ? [["IPv4", dns.A]] : []), ...(dns.AAAA.length ? [["IPv6", dns.AAAA]] : []), ...(dns.MX.length ? [["Mail", dns.MX]] : []), ...(dns.NS.length ? [["Nameserver", dns.NS]] : [])].map(([kindName, items]) => (
                    <button
                      key={kindName as string}
                      onClick={() => { const t = kindName === "Domain" ? "domain" : kindName === "IPv4" ? "ipv4" : kindName === "IPv6" ? "ipv6" : kindName === "Mail" ? "domain" : kindName === "Nameserver" ? "domain" : "unknown"; (items as string[]).forEach((v) => locker.add({ value: v, type: t, source: "/recon" })); toast(`Added ${(items as string[]).length} ${kindName} to locker`); }}
                      className="inline-flex items-center gap-1 rounded border border-border/50 bg-card/40 px-2 py-1 text-mono ba-text-3xs uppercase tracking-widest text-muted-foreground hover:bg-card/70 hover:text-foreground"
                    >
                      + {kindName as string} ({(items as string[]).length})
                    </button>
                  ))}
                  {ssl && (ssl.subject_alt_names || []).length > 0 && (
                    <button
                      onClick={() => { (ssl.subject_alt_names || []).forEach(([, v]) => locker.add({ value: v, type: "domain", source: "/recon" })); toast(`Added ${ssl.subject_alt_names?.length ?? 0} SANs to locker`); }}
                      className="inline-flex items-center gap-1 rounded border border-border/50 bg-card/40 px-2 py-1 text-mono ba-text-3xs uppercase tracking-widest text-muted-foreground hover:bg-card/70 hover:text-foreground"
                    >
                      + SANs ({ssl.subject_alt_names?.length ?? 0})
                    </button>
                  )}
                </div>
              )}
            </CollapsibleSection>
          )}

          {/* Signals */}
          {signals.length > 0 && (
            <CollapsibleSection id="SG" label="Risk Signals" meta={`${signals.length} signal(s)`} icon={AlertTriangle}>
              <div className="grid gap-3 grid-cols-2">
                {signals.map((s, i) => (
                  <EvidenceCard key={i} severity={s.sev} title={s.t} reason={s.r} action={s.a} limitation="Passive snapshot — re-verify before any action." />
                ))}
              </div>
            </CollapsibleSection>
          )}

          {/* Export */}
          {result.target.hostname && (
            <Panel title="Export" icon={Download} priority="secondary" collapsible storageKey="ba.panel.recon.export" defaultCollapsed>
              <div className="flex flex-wrap gap-2">
                <button
                  onClick={() => {
                    const md = genMarkdownExport(result, target, signals);
                    const blob = new Blob([md], { type: "text/markdown" });
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement("a");
                    a.href = url; a.download = `recon-${target}.md`;
                    a.click(); URL.revokeObjectURL(url);
                  }}
                  className="inline-flex items-center gap-1.5 rounded border border-primary/40 bg-primary/10 px-2.5 py-1.5 text-mono text-[10px] uppercase tracking-widest text-primary transition-all hover:bg-primary/20 hover:shadow-[0_0_12px_-2px_hsl(var(--primary)/0.45)]"
                >
                  <Download className="h-3 w-3" /> Download Markdown Report
                </button>
                <button
                  onClick={() => {
                    const md = genMarkdownExport(result, target, signals);
                    try { navigator.clipboard.writeText(md); } catch {/* noop */}
                  }}
                  className="inline-flex items-center gap-1.5 rounded border border-border bg-card/60 px-2.5 py-1.5 text-mono text-[10px] uppercase tracking-widest text-muted-foreground transition-colors hover:border-primary/40 hover:text-foreground"
                >
                  <Hash className="h-3 w-3" /> Copy Report
                </button>
                <button
                  onClick={() => {
                    const json = genJsonExport(result, target);
                    const blob = new Blob([json], { type: "application/json" });
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement("a");
                    a.href = url; a.download = `recon-${target}.json`;
                    a.click(); URL.revokeObjectURL(url);
                  }}
                  className="inline-flex items-center gap-1.5 rounded border border-primary/40 bg-primary/10 px-2.5 py-1.5 text-mono text-[10px] uppercase tracking-widest text-primary transition-all hover:bg-primary/20 hover:shadow-[0_0_12px_-2px_hsl(var(--primary)/0.45)]"
                >
                  <Download className="h-3 w-3" /> JSON Export
                </button>
              </div>
            </Panel>
          )}

          {/* ── OSINT Tool Links (inline from Recon target) ── */}
          <SectionBar id="OT" label="OSINT Tool Links" meta={`${osintKind} · ${result?.target?.hostname ? "auto" : "from target"}`} priority="secondary" />
          <div className="mb-2 flex flex-wrap items-center gap-1.5">
            <button onClick={() => { locker.add({ value: osintTarget, type: osintKind, source: "/recon" }); toast(`Added ${osintTarget} to locker`); }} className="inline-flex items-center gap-1 rounded border border-border/50 bg-card/40 px-2 py-1 text-mono ba-text-3xs uppercase tracking-widest text-muted-foreground hover:bg-card/70 hover:text-foreground"><Hash className="h-3 w-3" /> locker target</button>
            <button onClick={() => { const links = OSINT_TOOLS.filter(t => t.supports.includes(osintKind)).map(t => `${t.label}: ${t.href(osintTarget)}`).join("\n"); navigator.clipboard.writeText(links); toast("Copied all OSINT links"); }} className="inline-flex items-center gap-1 rounded border border-border/50 bg-card/40 px-2 py-1 text-mono ba-text-3xs uppercase tracking-widest text-muted-foreground hover:bg-card/70 hover:text-foreground"><Copy className="h-3 w-3" /> copy all links</button>
            <button onClick={() => sendToCase({ body: `OSINT pivot links for ${osintTarget}\n\n${OSINT_TOOLS.filter(t => t.supports.includes(osintKind)).map(t => `- [${t.label}](${t.href(osintTarget)})`).join("\n")}`, source: "/recon", kind: "evidence" })} className="inline-flex items-center gap-1 rounded border border-border/50 bg-card/40 px-2 py-1 text-mono ba-text-3xs uppercase tracking-widest text-muted-foreground hover:bg-card/70 hover:text-foreground"><Database className="h-3 w-3" /> send to case</button>
          </div>
          <Panel title="External Service Pivots" icon={ExternalLink} priority="secondary" collapsible storageKey="ba.panel.recon.osint-links">
            <div className="grid gap-3 grid-cols-1 lg:grid-cols-2 xl:grid-cols-3">
              {OSINT_CATS.map((c) => {
                const items = OSINT_TOOLS.filter((t) => t.cat === c && t.supports.includes(osintKind));
                if (!items.length) return null;
                const meta = OSINT_CAT_META[c] ?? { tone: "primary" as const };
                return (
                  <Panel key={c} title={c} icon={ExternalLink} meta={`${items.length} tools`}>
                    <ul className="space-y-1">
                      {items.map((t) => (
                        <li key={t.id}>
                          <a href={t.href(osintTarget)} target="_blank" rel="noopener noreferrer"
                            className="group flex items-center gap-2 rounded border border-divider-strong bg-background/30 px-2 py-1.5 hover:-translate-y-px hover:border-primary/50 hover:bg-primary/5 transition-all"
                          >
                            <ExternalLink className="h-3 w-3 shrink-0 text-muted-foreground group-hover:text-primary" />
                            <div className="min-w-0">
                              <div className="text-mono ba-text-sm text-foreground/90 group-hover:text-primary">{t.label}</div>
                              <div className="truncate text-mono ba-text-3xs text-muted-foreground">{t.tagline}</div>
                            </div>
                          </a>
                        </li>
                      ))}
                    </ul>
                  </Panel>
                );
              })}
            </div>
          </Panel>

          {/* ── CLI Commands for target ── */}
          <SectionBar id="CL" label="OSINT CLI Commands" meta={`tuned for ${osintKind}`} priority="raw" />
          <Panel title="Suggested CLI" icon={Terminal} priority="secondary" collapsible storageKey="ba.panel.recon.osint-cli">
            <ul className="divide-y divide-border/40 overflow-hidden rounded border border-divider-strong bg-background/40">
              {(osintKind === "ipv4" ? [
                { label: "Reverse DNS",     cmd: `dig -x ${osintTarget} +short` },
                { label: "WHOIS",           cmd: `whois ${osintTarget}` },
                { label: "Open ports",      cmd: `nmap -sS -Pn -T4 --top-ports 50 ${osintTarget}` },
                { label: "Full scan",       cmd: `nmap -sV -sC -A ${osintTarget}` },
                { label: "TLS banner",      cmd: `openssl s_client -connect ${osintTarget}:443 </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -dates` },
                { label: "Traceroute",      cmd: `mtr -rn -c 5 ${osintTarget}` },
                { label: "theHarvester",    cmd: `theHarvester -d ${osintTarget} -b all` },
              ] : [
                { label: "DNS A",           cmd: `dig +short ${osintTarget}` },
                { label: "WHOIS",           cmd: `whois ${osintTarget}` },
                { label: "MX records",      cmd: `host -t MX ${osintTarget}` },
                { label: "HTTP headers",    cmd: `curl -sI https://${osintTarget}` },
                { label: "TLS chain",       cmd: `openssl s_client -connect ${osintTarget}:443 -servername ${osintTarget} </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -dates` },
                { label: "theHarvester",    cmd: `theHarvester -d ${osintTarget} -b all` },
                { label: "Amass enum",      cmd: `amass enum -d ${osintTarget}` },
                { label: "Sublist3r",       cmd: `sublist3r -d ${osintTarget}` },
                { label: "assetfinder",     cmd: `assetfinder --subs-only ${osintTarget}` },
                { label: "WhatWeb",         cmd: `whatweb ${osintTarget}` },
              ]).map((line, i) => (
                <li key={i} className="group grid grid-cols-[auto_1fr_auto] items-center gap-2 px-3 py-1.5">
                  <span className="rounded border border-divider-strong bg-background/70 px-1 py-px text-mono ba-text-3xs uppercase tracking-widest text-muted-foreground">{String(i + 1).padStart(2, "0")}</span>
                  <div className="min-w-0">
                    <div className="truncate text-mono text-[10px] uppercase tracking-widest text-muted-foreground">{line.label}</div>
                    <div className="truncate text-mono text-[11.5px] text-foreground/90"><span className="select-none text-muted-foreground/60">$ </span>{line.cmd}</div>
                  </div>
                </li>
              ))}
            </ul>
          </Panel>

          <SendToRow targets={[
            { label: "Nmap Runner", to: "/nmap", icon: Server },
            { label: "Detection", to: "/detection", icon: ShieldAlert },
            { label: "SIEM", to: "/siem", icon: Activity },
            { label: "Case Notebook", to: "/case", icon: ArrowRight, onClick: () => sendToCase({ body: JSON.stringify(result, null, 2), source: "/recon", kind: "evidence" }) },
          ]} />
        </div>
        </OutputFilter>
      )}
    </PageShell>
  );
}
