import { createFileRoute } from "@tanstack/react-router";
import { useState } from "react";
import { PageShell } from "@/components/PageShell";
import {
  IntakeCard, StatusBar, KeyFields, SectionBar,
  Panel, SendToRow, Empty, Chip, RiskScore, EvidenceCard, IocInventory,
  TwoColumnOutput, VerdictBanner, MetricGrid, CollapsibleSection,
} from "@/components/soc/Workspace";
import { toast } from "sonner";
import { Globe as Globe2, Search, ShieldAlert, Database, ArrowRight, Zap, Server, Lock, FileSearch, TriangleAlert as AlertTriangle, Download, Hash, Network, ShieldCheck, ShieldX, Activity } from "lucide-react";
import { passiveRecon } from "@/api/backend";

export const Route = createFileRoute("/recon")({ component: ReconPage });

interface DnsData {
  A: string[]; AAAA: string[]; MX: string[]; NS: string[]; TXT: string[]; CNAME: string[];
}

interface HttpResult {
  url: string; status_code: number; server: string | null; content_type: string | null;
  redirect_count?: number; headers: Record<string, string>;
}

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

function genMarkdownExport(api: ReconApiResult, targetStr: string, score: number, signals: any[]): string {
  const http = getHttp(api.http);
  const ssl = getSsl(api.ssl);
  const dns = flattenDns(api.dns);
  const lines = [
    `# Reconnaissance Report`,
    `**Target:** \`${targetStr}\``,
    `**Score:** ${score}/100`,
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

function computeScore(api: ReconApiResult): { score: number; confidence: string; tone: "success" | "warning" | "destructive" } {
  let score = 0;
  const http = getHttp(api.http);
  const ssl = getSsl(api.ssl);
  const dns = flattenDns(api.dns);
  if (!ssl) score += 10;
  if (http) {
    const h = http.headers;
    const absent = ["strict-transport-security", "content-security-policy", "x-frame-options", "x-content-type-options", "referrer-policy"]
      .filter((k) => !h[k]).length;
    score += absent * 4;
    if (http.status_code === 301 || http.status_code === 302) score += 5;
  }
  if (dns.A.length === 0 && dns.AAAA.length === 0) score += 15;
  if (dns.MX.length === 0) score += 3;
  const total = Math.min(100, score);
  const tone = total < 20 ? "success" : total < 50 ? "warning" : "destructive";
  const confidence = total < 15 ? "low" : total < 40 ? "moderate" : total < 70 ? "high" : "very high";
  return { score: total, confidence, tone };
}

function ReconPage() {
  const [target, setTarget] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ReconApiResult | null>(null);

  const dns = result ? flattenDns(result.dns) : null;
  const http = result ? getHttp(result.http) : null;
  const ssl = result ? getSsl(result.ssl) : null;
  const signals = result ? findSignals(result) : [];
  const analysis = result ? computeScore(result) : null;

  async function handleRun() {
    if (!target.trim()) return;
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const res = await passiveRecon(target.trim());
      setResult(res as ReconApiResult);
      toast.success("Recon complete", { description: target.trim() });
    } catch (e: any) {
      setError(e?.message || "passive recon failed");
      toast.error("Recon failed", { description: target.trim() });
    } finally {
      setLoading(false);
    }
  }

  return (
    <PageShell
      eyebrow="RECON / EXPOSURE"
      title="Recon & Exposure"
      description="Passive reconnaissance — DNS, TLS, HTTP headers. No active probing."
      crumbs={[{ label: "Recon" }, { label: "Exposure" }]}
    >
      <SectionBar id="IN" label="Intake · target" meta={target ? target : "enter a target"} />
      <IntakeCard
        icon={Globe2}
        title="Target"
        value={target}
        onChange={(v) => { setTarget(v); setResult(null); setError(null); }}
        rows={2}
        placeholder="example.com"
        run={{ label: loading ? "probing..." : "enumerate", icon: Zap, hint: "⌘↵", onClick: handleRun, disabled: !target.trim() || loading }}
        onClear={() => { setTarget(""); setResult(null); setError(null); }}
        showCopy={false}
      />

      <StatusBar stats={[
        { label: "Status", value: loading ? "probing..." : error ? "error" : result ? "Snapshot ready" : "Idle", tone: error ? "destructive" : loading ? "warning" : result ? "success" : "muted" },
        { label: "Sources", value: "DNS · TLS · HTTP", tone: "primary" },
        { label: "Score", value: analysis ? `${analysis.score}/100` : "—", tone: analysis?.tone },
        { label: "Active probing", value: "off", tone: "muted" },
      ]} />

      <SectionBar id="OT" label="Output · passive snapshot" meta={result ? `${signals.length} signals` : "enter a target to populate"} />

      {!result && !loading && !error && (
        <Empty icon={Globe2} title="No target loaded" hint="Enter a domain above and click enumerate to run passive recon." />
      )}

      {loading && (
        <Panel title="Probing" icon={Search}>
          <p className="text-mono text-[11px] text-muted-foreground">Resolving DNS, probing HTTP, fetching TLS certificate...</p>
        </Panel>
      )}

      {error && (
        <Panel title="Error" icon={AlertTriangle}>
          <p className="text-mono text-[11px] text-destructive">{error}</p>
        </Panel>
      )}

      {result && !loading && (
        <div className="space-y-5">
          {/* Verdict Banner */}
          <VerdictBanner
            verdict={result.target.hostname || target}
            tone={analysis?.tone ?? "success"}
            icon={analysis?.tone === "destructive" ? ShieldX : analysis?.tone === "warning" ? AlertTriangle : ShieldCheck}
            score={analysis ? `${analysis.score}/100` : undefined}
            details={[
              result.target.type === "domain" ? `Root: ${result.target.root_domain}` : `Type: ${result.target.type}`,
              dns ? `${Object.values(dns).flat().length} DNS records` : "",
              ssl ? "TLS certificate present" : "",
              http ? `HTTP ${http.status_code}` : "",
              signals.some((s) => s.sev === "destructive" || s.sev === "warning") ? `${signals.filter((s) => s.sev === "destructive" || s.sev === "warning").length} risk signal(s)` : "",
            ].filter(Boolean)}
          />

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

          {/* Risk Score */}
          {analysis && (
            <RiskScore score={analysis.score} label="Exposure Risk" confidence={analysis.confidence} tone={analysis.tone} />
          )}

          {result.warning && (
            <Panel title="Warning" icon={AlertTriangle}>
              <p className="text-mono text-[11px] text-muted-foreground">{result.warning}</p>
            </Panel>
          )}

          {result.whois && "skipped" in result.whois && (
            <Panel title="WHOIS / RDAP" icon={Search} meta="skipped — passive mode">
              <p className="text-mono text-[11px] text-muted-foreground">{result.whois.skipped}</p>
            </Panel>
          )}

          {/* DNS + TLS side-by-side */}
          {dns && (dns.A.length > 0 || dns.AAAA.length > 0) && ssl && (
            <TwoColumnOutput
              ratio="1:1"
              left={
                <Panel title="DNS Records" icon={Network} meta={`${Object.values(dns).flat().length} RRs`}>
                  <div className="grid gap-2 sm:grid-cols-2">
                    {Object.entries(dns).filter(([, vals]) => vals.length > 0).map(([rr, vals]) => (
                      <div key={rr} className="rounded border border-border/60 bg-card/50 p-2.5">
                        <div className="mb-1 flex items-center gap-1.5">
                          <Chip tone="primary">{rr}</Chip>
                          <span className="text-mono text-[10px] text-muted-foreground">×{vals.length}</span>
                        </div>
                        <div className="space-y-0.5">
                          {(vals as string[]).map((v) => (
                            <div key={v} className="text-mono text-[10.5px] text-foreground/85 leading-snug">{v}</div>
                          ))}
                        </div>
                      </div>
                    ))}
                  </div>
                </Panel>
              }
              right={
                <Panel title="TLS Certificate" icon={Lock} meta={`${(ssl.subject_alt_names || []).length} SANs`}>
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
            <Panel title="DNS Records" icon={Network} meta={`${Object.values(dns).flat().length} RRs`}>
              <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
                {Object.entries(dns).filter(([, vals]) => vals.length > 0).map(([rr, vals]) => (
                  <div key={rr} className="rounded border border-border/60 bg-card/50 p-2.5">
                    <div className="mb-1 flex items-center gap-1.5">
                      <Chip tone="primary">{rr}</Chip>
                      <span className="text-mono text-[10px] text-muted-foreground">×{vals.length}</span>
                    </div>
                    <div className="space-y-0.5">
                      {(vals as string[]).map((v) => (
                        <div key={v} className="text-mono text-[10.5px] text-foreground/85 leading-snug">{v}</div>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </Panel>
          )}

          {/* TLS-only panel if no DNS */}
          {ssl && !(dns && (dns.A.length > 0 || dns.AAAA.length > 0)) && (
            <Panel title="TLS Certificate" icon={Lock} meta={`${(ssl.subject_alt_names || []).length} SANs`}>
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
            <Panel title="HTTP Headers" icon={Server} meta={`${http.status_code} · ${http.server || "unknown"}`} collapsible defaultCollapsed={Object.keys(http.headers).length > 10}>
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
                onSendTo={(v) => { try { localStorage.setItem("beyondarch.pendingArtifact", JSON.stringify({ type: "ioc", value: v, source: "/recon" })); flash(`Sent ${v} to pending`); } catch {} }}
              />
            </CollapsibleSection>
          )}

          {/* Signals */}
          {signals.length > 0 && (
            <CollapsibleSection id="SG" label="Risk Signals" meta={`${signals.length} signal(s)`} icon={AlertTriangle}>
              <div className="grid gap-3 md:grid-cols-2">
                {signals.map((s, i) => (
                  <EvidenceCard key={i} severity={s.sev} title={s.t} reason={s.r} action={s.a} limitation="Passive snapshot — re-verify before any action." />
                ))}
              </div>
            </CollapsibleSection>
          )}

          {/* Export */}
          {result.target.hostname && (
            <Panel title="Export" icon={Download}>
              <div className="flex flex-wrap gap-2">
                <button
                  onClick={() => {
                    const md = genMarkdownExport(result, target, analysis!.score, signals);
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
                    const md = genMarkdownExport(result, target, analysis!.score, signals);
                    navigator.clipboard.writeText(md);
                  }}
                  className="inline-flex items-center gap-1.5 rounded border border-border bg-card/60 px-2.5 py-1.5 text-mono text-[10px] uppercase tracking-widest text-muted-foreground transition-colors hover:border-primary/40 hover:text-foreground"
                >
                  <Hash className="h-3 w-3" /> Copy Report
                </button>
              </div>
            </Panel>
          )}

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
