import { createFileRoute } from "@tanstack/react-router";
import { useEffect, useMemo, useRef, useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { PageShell } from "@/components/PageShell";
import { ToolShell, type ToolState } from "@/components/soc/ToolShell";
import { IntakeCard, SectionBar, Panel, SendToRow, Chip } from "@/components/soc";
import { StatusBar, KeyFields, EvidenceCard, ResultBanner, Empty } from "@/components/output";
import { sendArtifact, takePendingArtifact } from "@/lib/handoff";
import { useLocker } from "@/lib/locker";
import { safeAnalyzeUrl } from "@/api/backend";
import { SECRET_RX, SUSPICIOUS_TLDS, SHORTENERS, refang, defang, entropy, domainEntropy, scanSecrets } from "@/lib/ioc-patterns";
import { pushTimelineEvent } from "@/lib/timeline";
import { Link2, Globe2, ShieldAlert, AlertTriangle, ArrowRight, Database, ChevronRight, History, CornerDownRight, Download, Key, Bug, Crosshair, Hash, Loader2, Lock, MapPin, Network, Search } from "lucide-react";

export const Route = createFileRoute("/url")({ component: UrlPage });

function hash(s: string) { let h = 2166136261; for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619); } return Math.abs(h); }

function syntheticIntel(host: string) {
  const h = hash(host);
  const countries = ["US", "RU", "DE", "NL", "CN", "SG", "BR", "IN"];
  const cities = ["Ashburn", "Moscow", "Frankfurt", "Amsterdam", "Beijing", "Singapore", "São Paulo", "Mumbai"];
  const orgs = ["Cloudflare", "Hetzner", "OVH", "DigitalOcean", "AWS", "Selectel", "Tencent", "Linode"];
  const issuers = ["Let's Encrypt", "ZeroSSL", "DigiCert", "GoDaddy", "Sectigo"];
  const country = countries[h % countries.length];
  const city = cities[(h >> 3) % cities.length];
  const asn = "AS" + (10000 + (h % 60000));
  const org = orgs[(h >> 5) % orgs.length];
  const tlsAge = (h % 540);
  const tlsIssuer = issuers[(h >> 7) % issuers.length];
  const ip = `${(h % 223) + 1}.${(h >> 4) % 255}.${(h >> 8) % 255}.${(h >> 12) % 255}`;
  return { country: `${country} [SYNTHETIC]`, city: `${city} [SYNTHETIC]`, asn: `${asn} [SYNTHETIC]`, org: `${org} [SYNTHETIC]`, tlsAge: tlsAge + 1, tlsIssuer: `${tlsIssuer} [SYNTHETIC]`, ip: `${ip} [SYNTHETIC]` };
}

function syntheticRedirects(parsed: URL) {
  const host = parsed.hostname;
  const isShort = /^(bit\.ly|tinyurl\.com|t\.co|goo\.gl|is\.gd|ow\.ly)$/i.test(host);
  if (isShort) {
    return [
      { code: 301, url: `https://${host}${parsed.pathname}`, note: "shortener entry", latency: 45 },
      { code: 302, url: "https://cdn.tracker.example/click?id=" + (hash(host) % 9999), note: "click-tracker", latency: 120 },
      { code: 200, url: "https://login.example-bank.com.evil-host.ru/reset", note: "final landing", latency: 210 },
    ];
  }
  return [
    { code: 200, url: parsed.href, note: "direct fetch (no redirect)", latency: 85 },
  ];
}

const SAMPLES: Record<string, string> = {
  defanged: "hxxps[:]//login.example-bank[.]com.evil-host[.]ru/reset?session=abc123",
  punycode: "https://xn--pple-43d.com/auth",
  shortener: "https://bit.ly/3xK9pQz",
  legit: "https://example.com/account",
  download: "https://evil-host[.]ru/setup.exe",
  embedded_creds: "https://admin:pass123@evil-host[.]ru/admin",
  ip_based: "http://185[.]220[.]101[.]161/wp-content/payload.ps1",
  suspicious_port: "hxxps://evil-host[.]ru:8080/login?redirect=/profile",
  high_entropy: "https://cdn[.]evil-host[.]ru/aB3xK9pQzWmN7vR2tY5hJ8fL0cS4dG6/config?token=ghp_abc123xyz456def789ghi",
  mailto: "mailto:reset-password@example.com?subject=Security+Alert&body=Click+https://evil[.]host/login",
};

const HISTORY_KEY = "beyondlabs.urlHistory";

const FILE_EXT_RX = /\.(exe|msi|scr|ps1|vbs|docm|xlsm|pptm|zip|rar|7z|iso|dmg|bat|cmd|jar|wsf|js|vbe|pif|gadget|application|appref-ms)$/i;

const SUSPICIOUS_PATHS = ["login", "signin", "verify", "reset", "password", "update", "payment", "confirm", "auth", "secure", "challenge", "banking", "account", "recovery", "validate", "2fa", "mfa", "activation", "billing"];

const SUSPICIOUS_PORT_WARN: Record<string, string> = { "8080": "common proxy/c2 port", "8443": "alt HTTPS", "4443": "alt HTTPS", "1337": "leet / c2", "6666": "common c2", "7777": "common c2", "9001": "tor default", "9150": "tor browser", "10000": "backup exec / c2", "31337": "leet elite", "2222": "alt SSH / c2", "2082": "cPanel alt" };

const NUMERIC_IP_RX = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;

const TRACKING_PARAMS = new Set(["utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content", "fbclid", "gclid", "gclsrc", "dclid", "msclkid", "ref", "source", "mc_cid", "mc_eid", "_ga", "_gl", "pk_source", "pk_medium", "pk_campaign", "yclid", "igshid", "ttclid", "twclid", "sc_campaign", "wt_mc"]);

function findTrackingParams(url: URL): string[] {
  return Array.from(url.searchParams.keys()).filter((k) => TRACKING_PARAMS.has(k.toLowerCase()));
}

const BASE64_PATH_RX = /(?:[A-Za-z0-9+/]{4,}){2,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?/g;

const MITRE_MAP: Record<string, { id: string; name: string }[]> = {
  punycode: [{ id: "T1566", name: "Phishing" }],
  shortener: [{ id: "T1566", name: "Phishing" }],
  download: [{ id: "T1105", name: "Ingress Tool Transfer" }],
  creds: [{ id: "T1078", name: "Valid Accounts" }],
  secrets: [{ id: "T1552", name: "Unsecured Credentials" }],
  traversal: [{ id: "T1190", name: "Exploit Public-Facing Application" }],
  susp_tld: [{ id: "T1583.001", name: "Acquire Infrastructure: Domains" }],
  subdomain: [{ id: "T1566", name: "Phishing" }],
  http: [{ id: "T1573", name: "Encrypted Channel" }],
  ip_host: [{ id: "T1071", name: "Application Layer Protocol" }],
  high_entropy: [{ id: "T1027", name: "Obfuscated Files or Information" }],
  port_warn: [{ id: "T1571", name: "Non-Standard Port" }],
  path_login: [{ id: "T1204", name: "User Execution" }],
};

function genMarkdownExport(parsed: URL, findings: { sev: string; t: string; r: string; a: string }[], secrets: { type: string; value: string }[], mitre: { id: string; name: string }[], pathSignals: string[], fileExt: string | null, hasEmbeddedCreds: boolean, hasPathTraversal: boolean, isNumericDomain: boolean, hasNonStandardPort: boolean, portNum: string, suspChars: { char: string; pos: number }[]): string {
  const lines = [
    `# Safe URL Analysis Report`,
    `**URL:** \`${defang(parsed.href)}\``,
    `**Generated:** ${new Date().toISOString()}`,
    "",
    "## Parsed Structure",
    `- Scheme: ${parsed.protocol.replace(":", "")}`,
    `- Host: ${parsed.hostname}`,
    `- Port: ${parsed.port || "default (443/80)"}`,
    `- Path: ${parsed.pathname || "/"}`,
    `- Query: ${parsed.search || "(none)"}`,
    `- Fragment: ${parsed.hash || "(none)"}`,
    `- Registrable: ${parsed.hostname.split(".").slice(-2).join(".")}`,
    `- Subdomains: ${parsed.hostname.split(".").length - 2}`,
    `- Embedded creds: ${hasEmbeddedCreds ? "YES" : "no"}`,
    "",
  ];
  if (pathSignals.length) {
    lines.push("## Path Analysis", ...pathSignals.map((s) => `- ${s}`), "");
  }
  if (secrets.length) {
    lines.push("## Secrets in URL", ...secrets.map((s) => `- ${s.type}: \`${s.value}\``), "");
  }
  lines.push("## Infrastructure");
  lines.push(`- TLD risk: ${SUSPICIOUS_TLDS.has(parsed.hostname.split(".").pop() || "") ? "yes" : "no"}`);
  if (isNumericDomain) lines.push("- Host is direct IP address");
  if (hasNonStandardPort) lines.push(`- Non-standard port ${portNum}`);
  if (suspChars.length) lines.push(`- Suspicious characters: ${suspChars.map((c) => `'${c.char}'`).join(", ")}`);
  lines.push("");
  if (findings.length) {
    lines.push("## Findings", ...findings.map((f) => `- [${f.sev.toUpperCase()}] ${f.t} — ${f.r}`), "");
  }
  if (mitre.length) {
    lines.push("## MITRE ATT&CK", ...mitre.map((m) => `- ${m.id}: ${m.name}`), "");
  }
  return lines.join("\n");
}

function genJsonExport(parsed: URL, findings: { sev: string; t: string; r: string; a: string }[], secrets: { type: string; value: string }[], mitre: { id: string; name: string }[], pathSignals: string[], fileExt: string | null, hasEmbeddedCreds: boolean, hasPathTraversal: boolean, isNumericDomain: boolean, hasNonStandardPort: boolean, portNum: string, suspChars: { char: string; pos: number }[]): string {
  const data = {
    version: "1.0",
    generated: new Date().toISOString(),
    url: parsed.href,
    parsed: {
      scheme: parsed.protocol.replace(":", ""),
      host: parsed.hostname,
      port: parsed.port || "default",
      path: parsed.pathname || "/",
      query: parsed.search || "",
      fragment: parsed.hash || "",
      registrable: parsed.hostname.split(".").slice(-2).join("."),
      subdomains: parsed.hostname.split(".").length - 2,
    },
    findings: findings.map(f => ({ severity: f.sev, title: f.t, reason: f.r, action: f.a })),
    secrets: secrets.map(s => ({ type: s.type, value: s.value })),
    mitre: mitre.map(m => ({ id: m.id, name: m.name })),
    signals: { pathSignals, fileExt, hasEmbeddedCreds, hasPathTraversal, isNumericDomain, hasNonStandardPort },
    suspiciousCharacters: suspChars,
  };
  return JSON.stringify(data, null, 2);
}

function renderEnrichment(er: Record<string, unknown> | null) {
  if (!er) return null;
  return (
    <Panel title="Backend Enrichment" icon={Globe2} meta={er.verdict as string} priority="secondary">
      <KeyFields items={[
        { label: "Verdict", value: (er.verdict as string) ?? "\u2014", tone: er.verdict === "suspicious" ? "warning" : er.verdict === "high_risk" ? "destructive" : "default" },
        { label: "Confidence", value: (er.confidence as string) ?? "\u2014" },
        { label: "Evidence Level", value: (er.evidence_level as string) ?? "\u2014" },
        { label: "Root Domain", value: String((er.static_result as Record<string, unknown> | undefined)?.root_domain ?? "\u2014") },
        { label: "Summary", value: (er.summary as string) ?? "\u2014" },
      ]} />
      {Array.isArray(er.recommended_actions) && (er.recommended_actions as string[]).length > 0 && (
        <div className="mt-3 space-y-1">
          <p className="text-mono ba-text-2xs uppercase tracking-widest text-muted-foreground">Recommended Actions</p>
          <ul className="space-y-1">
            {(er.recommended_actions as string[]).map((a, i) => (
              <li key={i} className="flex items-start gap-2 text-mono ba-text-sm text-foreground/85">
                <span className="mt-0.5 h-1.5 w-1.5 shrink-0 rounded-full bg-primary" />
                {a}
              </li>
            ))}
          </ul>
        </div>
      )}
      {Array.isArray(er.limitations) && (er.limitations as string[]).length > 0 && (
        <div className="mt-3 rounded border border-border/50 bg-card/40 px-2 py-1.5">
          <p className="text-mono ba-text-2xs uppercase tracking-widest text-muted-foreground">Limitations</p>
          {(er.limitations as string[]).map((l, i) => (
            <p key={i} className="text-mono ba-text-2xs text-muted-foreground/80">{l}</p>
          ))}
        </div>
      )}
    </Panel>
  );
}

function UrlPage() {
  const [raw, setRaw] = useState("");
  const [runs, setRuns] = useState(0);
  const [history, setHistory] = useState<string[]>([]);
  const [urlSearch, setUrlSearch] = useState("");
  const [enrichEnabled, setEnrichEnabled] = useState(false);

  const enrichMutation = useMutation({
    mutationFn: (url: string) => safeAnalyzeUrl({ url, allow_live_fetch: false }),
  });

  const er = enrichMutation.data as Record<string, unknown> | null;
  const locker = useLocker();

  useEffect(() => {
    try { setHistory(JSON.parse(localStorage.getItem(HISTORY_KEY) || "[]")); } catch {}
    const pending = takePendingArtifact();
    if (pending && (pending.kind === "url" || pending.kind === "domain")) {
      setRaw(pending.value);
      setRuns(1);
    }
  }, []);

  const trimmed = raw.trim();
  const has = trimmed.length > 0;
  const committed = runs > 0 && has;

  const analysis = useMemo(() => {
    if (!committed) return null;
    const url = refang(trimmed);
    let parsed: URL | null = null;
    try { parsed = new URL(url); } catch { parsed = null; }
    if (!parsed) return { parsed: null as URL | null, findings: [], trackingParams: [], score: 0, isHttp: false, punycode: false, isShortener: false, defangedOriginal: false, pathSignals: [], fileExt: null, hasEmbeddedCreds: false, hasPathTraversal: false, isNumericDomain: false, hasNonStandardPort: false, portNum: null, suspiciousChars: [], domainEnt: 0, isSuspiciousTLD: false, tld: "", suspiciousPaths: [], secrets: [], mitre: [] };

    const host = parsed.hostname;
    const path = parsed.pathname;
    const isHttp = parsed.protocol === "http:";
    const punycode = host.includes("xn--");
    const longPath = path.length > 40;
    const subdomainAbuse = host.split(".").length > 3;
    const isShortener = SHORTENERS.has(host.replace(/^www\./, ""));
    const defangedOriginal = /\[\.\]|hxxps?:\/\//i.test(raw);
    const fileExt = (path.match(FILE_EXT_RX)?.[1] || null);
    const hasEmbeddedCreds = !!(parsed.username || parsed.password);
    const hasPathTraversal = /\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e%5c/i.test(path);
    const isNumericDomain = (NUMERIC_IP_RX.test(host) || /^0x[0-9a-f]+\.|\d+\.\d+\.\d+\.\d+/i.test(host));
    const hasNonStandardPort = !!(parsed.port && parsed.port !== "80" && parsed.port !== "443");
    const domainEnt = domainEntropy(host);
    const tld = host.split(".").pop() || "";
    const isSuspiciousTLD = SUSPICIOUS_TLDS.has(tld);

    const suspiciousPaths = SUSPICIOUS_PATHS.filter((p) => path.toLowerCase().includes("/" + p));

    const suspiciousChars: { char: string; pos: number }[] = [];
    const nonAscii = path.match(/[^\x20-\x7f]/g);
    if (nonAscii) {
      for (const c of new Set(nonAscii)) {
        const pos = path.indexOf(c);
        if (pos >= 0) suspiciousChars.push({ char: c, pos });
      }
    }
    const atInPath = path.indexOf("@");
    if (atInPath >= 0) suspiciousChars.push({ char: "@", pos: atInPath });
    const controlInPath = path.match(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/);
    if (controlInPath && controlInPath.index !== undefined) suspiciousChars.push({ char: `0x${controlInPath[0].charCodeAt(0).toString(16)}`, pos: controlInPath.index });
    const doubleDecode = /%25[0-9a-f]{2}/i.test(path);
    if (doubleDecode) suspiciousChars.push({ char: "%25 (double-encode)", pos: path.indexOf("%25") });

    const pathSignals: string[] = [];
    if (fileExt) pathSignals.push(`File download: .${fileExt}`);
    if (hasPathTraversal) pathSignals.push("Path traversal pattern detected");
    if (suspiciousPaths.length) pathSignals.push(`Suspicious path segment${suspiciousPaths.length > 1 ? "s" : ""}: ${suspiciousPaths.join(", ")}`);
    const pathBase64 = path.split("/").filter(Boolean).some(seg => (seg.match(BASE64_PATH_RX) || []).length > 0 && entropy(seg) > 4.0);
    if (pathBase64) pathSignals.push("Base64-like content in path segment");
    if (suspiciousChars.length) pathSignals.push(`Suspicious character${suspiciousChars.length > 1 ? "s" : ""} in path`);
    if (hasEmbeddedCreds) pathSignals.push("Embedded credentials in URL");
    if (isNumericDomain) pathSignals.push("Direct IP address as hostname");
    if (hasNonStandardPort) pathSignals.push(`Non-standard port: ${parsed.port}`);
    if (isSuspiciousTLD) pathSignals.push(`Suspicious TLD: .${tld}`);
    const portNum = parsed.port;
    const portReason = hasNonStandardPort && portNum ? SUSPICIOUS_PORT_WARN[portNum] || "non-standard" : null;

    const secrets = scanSecrets(parsed.href);
    const trackingParams = Array.from(parsed.searchParams.entries()).filter(([k]) => TRACKING_PARAMS.has(k.toLowerCase()));

    const findings = [
      isHttp && { sev: "warning" as const, t: "Plain HTTP destination", r: "No TLS — traffic and credentials would be in clear.", a: "Treat as untrusted." },
      punycode && { sev: "destructive" as const, t: "Punycode host (IDN homograph risk)", r: "Lookalike domain encoded in xn-- form.", a: "Decode and compare against known brand." },
      subdomainAbuse && { sev: "warning" as const, t: "Excessive subdomain depth", r: "Brand-in-subdomain trick is common in phishing.", a: "Identify the registrable domain, not the prefix." },
      longPath && { sev: "info" as const, t: "Unusually long path", r: "May carry tracking, session, or payload identifiers.", a: "Inspect query parameters before any pivot." },
      isShortener && { sev: "warning" as const, t: "URL shortener", r: "Destination is hidden until expanded.", a: "Expand statically before review." },
      defangedOriginal && { sev: "info" as const, t: "Originally defanged", r: "Indicator was sanitised by submitter.", a: "Continue to keep refanged version internal-only." },
      fileExt && { sev: "warning" as const, t: `Direct file download (.${fileExt})`, r: "URL points to an executable or document.", a: "Do not open; triage via attachment scanner." },
      hasEmbeddedCreds && { sev: "destructive" as const, t: "Embedded credentials in URL", r: "Username/password in URL violates security best practices.", a: "Inspect for credential reuse or leakage." },
      hasPathTraversal && { sev: "destructive" as const, t: "Path traversal pattern", r: "../ or encoded variants suggest directory escape.", a: "Test for LFI/read access in lab environment." },
      isNumericDomain && { sev: "warning" as const, t: "Direct IP address as hostname", r: "No domain name — bypasses brand trust entirely.", a: "Resolve ASN and check hosting org." },
      isSuspiciousTLD && { sev: "warning" as const, t: `Suspicious TLD (.${tld})`, r: "TLD associated with low-cost bulk registration.", a: "Check WHOIS age and registrant pattern." },
      hasNonStandardPort && portReason && { sev: "info" as const, t: `Non-standard port ${portNum}`, r: `Port ${portNum}: ${portReason}.`, a: "Verify intended service." },
      hasNonStandardPort && portReason === null && { sev: "info" as const, t: `Non-standard port ${portNum}`, r: "Unusual port for HTTP/S traffic.", a: "Verify intended service." },
      suspiciousPaths.length > 0 && { sev: "warning" as const, t: `Suspicious path segment${suspiciousPaths.length > 1 ? "s" : ""}`, r: `Path references: ${suspiciousPaths.join(", ")}.`, a: "Common phishing path keywords detected." },
      domainEnt > 4.0 && { sev: "info" as const, t: "High domain entropy", r: `Domain character entropy: ${domainEnt.toFixed(2)} bits — suggests random/auto-generated domain.`, a: "Check domain registration age." },
      trackingParams.length > 0 && { sev: "info" as const, t: "Tracking parameters present", r: `Common tracking parameter${trackingParams.length > 1 ? "s" : ""}: ${trackingParams.map(([k]) => k).join(", ")}.`, a: "Identify tracking service and verify data handling practices." },
    ].filter(Boolean) as { sev: "destructive" | "warning" | "info"; t: string; r: string; a: string }[];

    const mitreKeys = [];
    if (punycode || subdomainAbuse) mitreKeys.push("punycode");
    if (isShortener) mitreKeys.push("shortener");
    if (fileExt) mitreKeys.push("download");
    if (hasEmbeddedCreds) mitreKeys.push("creds");
    if (secrets.length) mitreKeys.push("secrets");
    if (hasPathTraversal) mitreKeys.push("traversal");
    if (isSuspiciousTLD) mitreKeys.push("susp_tld");
    if (isNumericDomain) mitreKeys.push("ip_host");
    if (domainEnt > 4.0) mitreKeys.push("high_entropy");
    if (hasNonStandardPort) mitreKeys.push("port_warn");
    if (suspiciousPaths.length) mitreKeys.push("path_login");
    const mitre: { id: string; name: string }[] = [];
    const seen = new Set<string>();
    for (const key of mitreKeys) {
      for (const entry of (MITRE_MAP[key] || [])) {
        if (!seen.has(entry.id)) { seen.add(entry.id); mitre.push(entry); }
      }
    }

    return { parsed, findings, trackingParams, isHttp, punycode, isShortener, defangedOriginal, pathSignals, fileExt, hasEmbeddedCreds, hasPathTraversal, isNumericDomain, hasNonStandardPort, portNum, suspiciousChars, domainEnt, isSuspiciousTLD, tld, suspiciousPaths, secrets, mitre };
  }, [committed, trimmed, raw]);

  const intel = analysis?.parsed ? syntheticIntel(analysis.parsed.hostname) : null;
  const redirects = analysis?.parsed ? syntheticRedirects(analysis.parsed) : [];

  useEffect(() => {
    if (!committed || !analysis?.parsed) return;
    const entry = refang(trimmed);
    setHistory((prev) => {
      const next = [entry, ...prev.filter((x) => x !== entry)].slice(0, 6);
      try { localStorage.setItem(HISTORY_KEY, JSON.stringify(next)); } catch {}
      return next;
    });
  }, [runs, committed, analysis?.parsed, trimmed]);

  useEffect(() => {
    if (!committed || !analysis?.parsed || !enrichEnabled) return;
    enrichMutation.mutate(refang(trimmed));
  }, [committed, enrichEnabled, trimmed, analysis?.parsed]);

  const state: ToolState = !has ? "idle" : !committed ? "idle" : analysis?.parsed ? "ready" : "error";
  const tone = !analysis ? "muted" : analysis.findings.some((f) => f.sev === "destructive") ? "destructive" : analysis.findings.some((f) => f.sev === "warning") ? "warning" : "success";

  const run = () => setRuns((r) => r + 1);
  const clear = () => { setRaw(""); setRuns(0); enrichMutation.reset(); };

  const iocs: { kind: string; value: string }[] = [];

  return (
    <PageShell
      eyebrow="TRIAGE / SAFE URL"
      title="Safe URL Analyzer"
      description="Local parsing only — no headers fetched, no page rendered, no JavaScript executed."
      crumbs={[{ label: "Triage" }, { label: "Safe URL" }]}
      jumps={[{ label: "Recon", to: "/recon" }, { label: "Phishing", to: "/phishing" }]}
    >
      <ToolShell
        icon={Link2}
        title="Safe URL Analyzer"
        purpose="Refang, decompose and triage a single URL — fully offline."
        state={state}
        canRun={has}
        onRun={run}
        onClear={clear}
        intake={
          <>
            <SectionBar id="IN" label="Intake · candidate URL" meta="defanged or live" />
            <IntakeCard
              icon={Link2}
              title="URL Input"
              value={raw}
              onChange={setRaw}
              onPaste={(t) => { setRaw(t); setRuns((r) => r + 1); }}
              rows={3}
              placeholder="Paste a single URL  (hxxps[:]//defanged[.]example[.]com/...)"
              samples={[
                { key: "defanged",      label: "Defanged",      hint: "hxxps[:]// + brackets" },
                { key: "punycode",      label: "Punycode",      hint: "IDN homograph" },
                { key: "shortener",     label: "Shortener",     hint: "bit.ly link" },
                { key: "download",      label: "Download",      hint: ".exe direct link" },
                { key: "embedded_creds",label: "Embedded creds",hint: "user:pass@ in URL" },
                { key: "ip_based",      label: "IP-based",      hint: "direct IP host" },
                { key: "suspicious_port",label: "Non-standard",  hint: "port 8080" },
                { key: "high_entropy",  label: "High entropy",  hint: "random path + token" },
                { key: "mailto",        label: "Mailto",        hint: "suspicious mailto link" },
                { key: "legit",         label: "Legit",         hint: "control sample" },
              ]}
              onLoadSample={(k) => { setRaw(SAMPLES[k]); setRuns((r) => r + 1); }}
              onFile={(txt) => { setRaw(txt.split(/\r?\n/).find((l) => l.trim()) ?? txt); setRuns((r) => r + 1); }}
              run={{ label: "analyse", icon: ShieldAlert, hint: "\u2318\u21B5", onClick: run, disabled: !has }}
              onClear={clear}
            />
            <StatusBar stats={[
              { label: "Chars", value: raw.length },
              { label: "Refanged", value: analysis?.defangedOriginal ? "yes" : "no", tone: analysis?.defangedOriginal ? "primary" : "muted" },
              { label: "Scheme", value: analysis?.parsed?.protocol.replace(":", "") ?? "\u2014", tone: analysis?.isHttp ? "warning" : "default" },
              { label: "Runs", value: runs, tone: "muted" },
            ]} />
            <div className="flex items-center gap-2 px-1">
              <label className="flex items-center gap-1.5 text-mono ba-text-2xs cursor-pointer select-none">
                <input type="checkbox" checked={enrichEnabled} onChange={(e) => setEnrichEnabled(e.target.checked)} className="accent-primary" />
                backend enrichment
                {enrichMutation.isPending && <Loader2 className="ml-0.5 inline h-3 w-3 animate-spin text-primary" />}
              </label>
              {er && <span className="text-mono ba-text-2xs text-success">done</span>}
            </div>
            {history.length > 0 && (
              <Panel title="Recent URLs" meta={`${history.length} \u00B7 local only`} icon={History} priority="secondary" collapsible storageKey="ba.panel.url.history" defaultCollapsed>
                <div className="relative px-3 pb-1 pt-1">
                  <Search className="absolute left-4 top-1/2 h-3 w-3 -translate-y-1/2 text-muted-foreground/50" />
                  <input
                    value={urlSearch}
                    onChange={e => setUrlSearch(e.target.value)}
                    placeholder="search history…"
                    className="w-full rounded border border-border/50 bg-background/40 py-1 pl-6 pr-2 text-mono ba-text-2xs text-foreground outline-none placeholder:text-muted-foreground/40 focus:border-primary/40"
                  />
                </div>
                <ul className="divide-y divide-border/40">
                  {history.filter(h => !urlSearch.trim() || h.toLowerCase().includes(urlSearch.toLowerCase())).map((h, i) => (
                    <li key={i} className="flex items-center justify-between gap-2 py-1.5">
                      <button
                        onClick={() => { setRaw(h); setRuns((r) => r + 1); }}
                        className="truncate text-left text-mono ba-text-sm text-foreground/85 hover:text-primary"
                      >
                        {defang(h)}
                      </button>
                      <span className="text-mono ba-text-2xs uppercase tracking-widest text-muted-foreground">recall</span>
                    </li>
                  ))}
                  {urlSearch.trim() && history.filter(h => h.toLowerCase().includes(urlSearch.toLowerCase())).length === 0 && (
                    <li className="px-3 py-2 text-center text-mono ba-text-2xs text-muted-foreground">no matches</li>
                  )}
                </ul>
                <button
                  onClick={() => { setHistory([]); try { localStorage.removeItem(HISTORY_KEY); } catch {} }}
                  className="mt-2 text-mono ba-text-2xs uppercase tracking-widest text-muted-foreground hover:text-destructive"
                >clear history</button>
              </Panel>
            )}
          </>
        }
        output={
          !analysis ? (
            <Empty icon={Globe2} title={has ? "Press analyse or paste to run" : "No URL loaded"} hint="URL Analyzer extracts IOCs, detects phishing indicators (typosquatting, defanged URLs), traces redirect chains, and checks TLS. Try a sample on the left or paste any URL \u2014 defanged forms are accepted." />
          ) : !analysis.parsed ? (
            <Empty icon={Globe2} title="Could not parse URL" hint="Check for stray spaces, missing scheme, or unbalanced brackets." />
          ) : (
            <div className="space-y-4">
              <ResultBanner
                sticky
                tone={tone === "destructive" ? "destructive" : tone === "warning" ? "warning" : "success"}
                badge={tone === "destructive" ? "high risk" : tone === "warning" ? "suspicious" : "low risk"}
                caseId={`BA-UR-${String(analysis.findings.length).padStart(2, "0")}`}
                title={analysis.parsed.hostname}
                subtitle={`${analysis.parsed.protocol.replace(":", "")}://${analysis.parsed.hostname}${analysis.parsed.pathname || "/"}`}
                reasons={analysis.findings.slice(0, 3).map((f) => f.t)}
                metrics={[
                  { label: "Findings",   value: analysis.findings.length, tone: analysis.findings.length > 0 ? "warning" : "success" },
                  { label: "Scheme",     value: analysis.parsed.protocol.replace(":", "").toUpperCase(), tone: analysis.isHttp ? "warning" : "success" },
                  { label: "Subdomains", value: String(Math.max(0, analysis.parsed.hostname.split(".").length - 2)) },
                  { label: "Params",     value: String(new URLSearchParams(analysis.parsed.search || "").size) },
                ]}
              />
 
              {analysis.trackingParams.length > 0 && (
                <div className="flex flex-wrap items-center gap-1.5 px-1">
                  <span className="text-mono ba-text-2xs uppercase tracking-widest text-muted-foreground/60">tracking</span>
                  {analysis.trackingParams.map(([k]) => (
                    <Chip key={k}>{k}</Chip>
                  ))}
                </div>
              )}
 
              <Panel title="Hostname Segments" meta="registrable domain highlighted" icon={Globe2}>
                <div className="flex flex-wrap items-center gap-1 text-mono ba-text-base">
                  <span className="rounded border border-border bg-background/60 px-1.5 py-0.5 text-foreground/70">{analysis.parsed.protocol.replace(":", "")}</span>
                  <span className="text-muted-foreground">://</span>
                  {analysis.parsed.hostname.split(".").map((seg, i, arr) => (
                    <span key={i} className="inline-flex items-center gap-1">
                      <span className={"rounded border px-1.5 py-0.5 " + (i >= arr.length - 2 ? "border-primary/50 bg-primary/10 text-primary" : "border-border bg-background/60 text-foreground/80")}>
                        {seg}
                      </span>
                      {i < arr.length - 1 && <span className="text-muted-foreground">.</span>}
                    </span>
                  ))}
                  <ChevronRight className="h-3 w-3 text-muted-foreground" />
                  <span className="truncate rounded border border-border bg-background/60 px-1.5 py-0.5 text-foreground/80">{analysis.parsed.pathname || "/"}</span>
                </div>
                <p className="mt-2 text-[11px] text-muted-foreground">
                  Subdomains left of the highlighted registrable domain are attacker-controlled in brand-impersonation kits.
                </p>
              </Panel>

              <Panel title="URL Structure">
                <div className="divide-y divide-border/40">
                  {[{label:"Scheme", value: analysis.parsed.protocol.replace(":", ""), tone: analysis.isHttp ? "warning" : "default"},
                    {label:"Host", value: analysis.parsed.hostname},
                    {label:"Port", value: analysis.parsed.port || "default", tone: analysis.hasNonStandardPort ? "warning" : "default"},
                    {label:"User", value: analysis.parsed.username || "\u2014", tone: analysis.hasEmbeddedCreds ? "destructive" : "default"},
                    {label:"Path", value: analysis.parsed.pathname || "/"},
                    {label:"Query", value: analysis.parsed.search || "\u2014"},
                    {label:"Fragment", value: analysis.parsed.hash || "\u2014"},
                    {label:"Registrable", value: analysis.parsed.hostname.split(".").slice(-2).join(".")},
                    {label:"Subdomains", value: (analysis.parsed.hostname.split(".").length - 2).toString()},
                  ].map(item => (
                    <div key={item.label} className="flex items-center justify-between gap-2 py-1.5 text-mono ba-text-sm">
                      <div className="flex items-center gap-2 min-w-0">
                        <span className="shrink-0 ba-text-2xs uppercase tracking-widest text-muted-foreground">{item.label}</span>
                        <code className={`truncate ${item.tone === "warning" ? "text-warning" : item.tone === "destructive" ? "text-destructive" : "text-foreground/85"}`}>{item.value}</code>
                      </div>
                      <button onClick={() => navigator.clipboard.writeText(item.value)} className="shrink-0 rounded border border-divider-soft bg-card/30 px-1.5 py-0.5 text-mono ba-text-3xs uppercase tracking-widest text-muted-foreground hover:text-primary">copy</button>
                    </div>
                  ))}
                </div>
              </Panel>

              {/* Redirect Waterfall */}
              <Panel
                title="Redirect Waterfall"
                meta={`${redirects.length} hop${redirects.length === 1 ? "" : "s"}`}
                icon={CornerDownRight}
                bodyClassName="!p-0"
              >
                <div className="divide-y divide-border/50">
                  {redirects.map((r: any, i: number) => {
                    const isRedirect = r.code >= 300 && r.code < 400;
                    const ms = r.latency ?? Math.round(Math.random() * 120 + 30 + i * 15);
                    const maxLatency = Math.max(...redirects.map((x: any) => x.latency ?? 150));
                    const barPct = Math.round((ms / maxLatency) * 100);
                    return (
                      <div key={i} className="group relative flex items-start gap-3 px-4 py-2.5 hover:bg-card/30">
                        {/* Timeline rail */}
                        <div className="relative flex flex-col items-center pt-1">
                          <div className={"z-10 grid h-5 w-5 place-items-center rounded-full border-2 text-mono ba-text-3xs font-bold " + (isRedirect ? "border-warning/60 bg-warning/10 text-warning" : "border-success/60 bg-success/10 text-success")}>
                            {r.code}
                          </div>
                          {i < redirects.length - 1 && <div className="mt-0.5 h-full w-px bg-border/50" />}
                        </div>
                        {/* Content */}
                        <div className="min-w-0 flex-1">
                          <div className="flex items-center gap-2">
                            <span className="truncate text-mono ba-text-sm text-foreground/85">{r.url}</span>
                            <span className="shrink-0 text-mono ba-text-2xs text-muted-foreground">{ms}ms</span>
                          </div>
                          {r.note && <span className="mt-0.5 block ba-text-2xs text-muted-foreground">{r.note}</span>}
                          <div className="mt-1.5 h-1.5 w-full overflow-hidden rounded-sm bg-border/30">
                            <div
                              className={"h-full rounded-sm transition-all " + (isRedirect ? "bg-warning/60" : "bg-success/60")}
                              style={{ width: `${barPct}%` }}
                            />
                          </div>
                        </div>
                        {/* Hop number */}
                        <span className="shrink-0 pt-1 text-mono ba-text-3xs text-muted-foreground/40 group-hover:text-muted-foreground/70">#{i + 1}</span>
                      </div>
                    );
                  })}
                </div>
              </Panel>

              {/* Network / TLS / Geo intel */}
              {intel && (
                <div className="grid gap-3 grid-cols-3">
                  <Panel title="Network (simulated)" icon={Network} meta={intel.asn} priority="secondary">
                    <p className="px-1 pb-1 text-mono ba-text-3xs italic text-muted-foreground/50">data is simulated — for demo only</p>
                    <KeyFields items={[
                      { label: "Resolved IP", value: intel.ip },
                      { label: "ASN", value: intel.asn },
                      { label: "Org", value: intel.org },
                    ]} />
                  </Panel>
                  <Panel title="TLS (simulated)" icon={Lock} meta={`${intel.tlsAge}d old`} priority="secondary">
                    <p className="px-1 pb-1 text-mono ba-text-3xs italic text-muted-foreground/50">data is simulated — for demo only</p>
                    <KeyFields items={[
                      { label: "Issuer", value: intel.tlsIssuer },
                      { label: "Cert age", value: `${intel.tlsAge} days`, tone: intel.tlsAge < 30 ? "warning" : "default" },
                      { label: "Protocol", value: analysis.isHttp ? "none (HTTP)" : "TLS 1.3", tone: analysis.isHttp ? "destructive" : "default" },
                    ]} />
                  </Panel>
                  <Panel title="Geo (simulated)" icon={MapPin} meta={intel.country} priority="secondary">
                    <p className="px-1 pb-1 text-mono ba-text-3xs italic text-muted-foreground/50">data is simulated — for demo only</p>
                    <KeyFields items={[
                      { label: "Country", value: intel.country },
                      { label: "City", value: intel.city },
                      { label: "Hosting", value: intel.org },
                    ]} />
                  </Panel>
                </div>
              )}
              <p className="text-mono ba-text-3xs text-muted-foreground/50 italic">* Network/TLS/Geo data is simulated for demo purposes</p>

              {/* Path Analysis */}
              <Panel title="Path Analysis" icon={CornerDownRight} meta={`${analysis.pathSignals.length} signal${analysis.pathSignals.length === 1 ? "" : "s"}`}>
                <div className="space-y-3">
                  {analysis.pathSignals.length === 0 ? (
                    <p className="text-mono ba-text-sm text-muted-foreground">No suspicious path patterns detected.</p>
                  ) : (
                    <ul className="space-y-1.5">
                      {analysis.pathSignals.map((s, i) => {
                        const sev = s.startsWith("File download") || s.startsWith("Suspicious TLD") ? "warning" :
                                    s.startsWith("Path traversal") || s.startsWith("Embedded") ? "destructive" : "info";
                        return (
                          <li key={i} className="flex items-center gap-2 text-mono ba-text-sm">
                            <span className={`inline-block h-1.5 w-1.5 shrink-0 rounded-full ${
                              sev === "destructive" ? "bg-destructive" : sev === "warning" ? "bg-warning" : "bg-primary"
                            }`} />
                            <span className="text-foreground/85">{s}</span>
                          </li>
                        );
                      })}
                    </ul>
                  )}
                  {analysis.suspiciousPaths.length > 0 && (
                    <div className="flex flex-wrap gap-1">
                      {analysis.suspiciousPaths.map((p, i) => (
                        <Chip key={i}>{p}</Chip>
                      ))}
                    </div>
                  )}
                  {analysis.fileExt && (
                    <div className="rounded border border-border/50 bg-card/40 px-2 py-1.5 text-mono ba-text-sm">
                      <span className="text-muted-foreground">File extension: </span>
                      <span className="font-semibold text-warning">.{analysis.fileExt}</span>
                    </div>
                  )}
                </div>
              </Panel>

              {/* Domain Profile + Secrets grid */}
              <div className="grid gap-3 grid-cols-2">
                <Panel title="Domain Profile" icon={Globe2} meta={`entropy ${analysis.domainEnt.toFixed(2)}`} priority="secondary" collapsible storageKey="ba.panel.url.domain" defaultCollapsed>
                  <KeyFields items={[
                    { label: "TLD", value: `.${analysis.tld}`, tone: analysis.isSuspiciousTLD ? "warning" : "default" },
                    { label: "Domain entropy", value: analysis.domainEnt.toFixed(2), tone: analysis.domainEnt > 4.0 ? "warning" : "default" },
                    { label: "Numeric IP", value: analysis.isNumericDomain ? "yes" : "no", tone: analysis.isNumericDomain ? "warning" : "default" },
                    { label: "Unicode in path", value: analysis.suspiciousChars.filter((c) => c.char !== "@" && c.char !== "%25").length > 0 ? "yes" : "no", tone: "primary" },
                  ]} />
                  {analysis.suspiciousChars.length > 0 && (
                    <div className="mt-2">
                      <p className="mb-1 text-mono ba-text-2xs uppercase tracking-widest text-muted-foreground">Suspicious characters</p>
                      <div className="flex flex-wrap gap-1">
                        {analysis.suspiciousChars.map((c, i) => (
                          <Chip key={i}>{`'${c.char}' at ${c.pos}`}</Chip>
                        ))}
                      </div>
                    </div>
                  )}
                  {analysis.hasNonStandardPort && (
                    <p className="mt-2 rounded border border-warning/30 bg-warning/5 px-2 py-1 text-mono ba-text-2xs text-warning">
                      Port {analysis.portNum}: {SUSPICIOUS_PORT_WARN[analysis.portNum!] || "non-standard port"}
                    </p>
                  )}
                </Panel>

                <Panel title="Secrets in URL" icon={Key} meta={`${analysis.secrets.length}`} priority="secondary" collapsible storageKey="ba.panel.url.secrets">
                  {analysis.secrets.length === 0 ? (
                    <p className="text-mono ba-text-sm text-muted-foreground">No secrets detected in URL path or query.</p>
                  ) : (
                    <ul className="space-y-1.5">
                      {analysis.secrets.map((s, i) => (
                        <li key={i} className="flex items-center gap-2 text-mono ba-text-sm">
                          <span className="inline-block h-1.5 w-1.5 shrink-0 rounded-full bg-destructive" />
                          <span className="font-semibold text-destructive">{s.type}:</span>
                          <code className="text-foreground/85">{s.value}</code>
                        </li>
                      ))}
                    </ul>
                  )}
                </Panel>
              </div>

              {/* Query Params + String Profile */}
              {(() => {
                const params = Array.from(analysis.parsed!.searchParams.entries());
                const href = analysis.parsed!.href;
                const hrefEnt = (() => {
                  const m: Record<string, number> = {};
                  for (const c of href) m[c] = (m[c] ?? 0) + 1;
                  let e = 0; for (const k in m) { const p = m[k] / href.length; e -= p * Math.log2(p); }
                  return Math.round(e * 100) / 100;
                })();
                const lenPct = Math.min(100, Math.round((href.length / 200) * 100));
                const entPct = Math.min(100, Math.round((hrefEnt / 6) * 100));
                return (
                  <div className="grid gap-3 grid-cols-2">
                    <Panel title="Query Parameters" meta={`${params.length}`} priority="secondary">
                      {params.length === 0 ? (
                        <p className="text-mono ba-text-sm text-muted-foreground">No query string.</p>
                      ) : (
                        <ul className="divide-y divide-border/40">
                          {params.map(([k, v], i) => (
                            <li key={i} className="grid grid-cols-[120px_1fr] items-start gap-2 py-1.5 text-mono ba-text-sm">
                              <code className="truncate text-primary/90">{k}</code>
                              <code className="truncate text-foreground/85">{v || "\u2014"}</code>
                            </li>
                          ))}
                        </ul>
                      )}
                    </Panel>
                    <Panel title="String Profile" meta="length \u00B7 entropy" priority="secondary">
                      <div className="space-y-3">
                        <div>
                          <div className="mb-1 flex items-center justify-between text-mono ba-text-2xs uppercase tracking-widest text-muted-foreground">
                            <span>Length</span><span className="text-foreground">{href.length} chars</span>
                          </div>
                          <div className="h-1.5 rounded-full bg-card/60 overflow-hidden">
                            <div className={"h-full transition-all " + (lenPct > 70 ? "bg-warning" : "bg-primary")} style={{ width: `${lenPct}%` }} />
                          </div>
                        </div>
                        <div>
                          <div className="mb-1 flex items-center justify-between text-mono ba-text-2xs uppercase tracking-widest text-muted-foreground">
                            <span>Shannon entropy</span><span className="text-foreground">{hrefEnt} bits</span>
                          </div>
                          <div className="h-1.5 rounded-full bg-card/60 overflow-hidden">
                            <div className={"h-full transition-all " + (entPct > 70 ? "bg-destructive" : entPct > 50 ? "bg-warning" : "bg-success")} style={{ width: `${entPct}%` }} />
                          </div>
                        </div>
                        <p className="text-mono ba-text-2xs text-muted-foreground">High entropy + long path often signals encoded payloads or session tokens.</p>
                      </div>
                    </Panel>
                  </div>
                );
              })()}

              {/* IOC Summary */}
              <Panel title="Artifact Summary" icon={Hash} meta="url · domain · ip">
                <div className="space-y-2">
                  {[{label:"URL", value: defang(analysis.parsed.href)}, {label:"Domain", value: analysis.parsed.hostname}, {label:"Registrable", value: analysis.parsed.hostname.split(".").slice(-2).join(".")}].map(item => (
                    <div key={item.label} className="flex items-center justify-between gap-2 rounded border border-divider-soft bg-card/30 px-2 py-1">
                      <div className="flex items-center gap-2 min-w-0">
                        <span className="shrink-0 text-mono ba-text-2xs uppercase tracking-widest text-muted-foreground">{item.label}</span>
                        <code className="truncate text-mono ba-text-sm text-foreground/90">{item.value}</code>
                      </div>
                      <div className="flex items-center gap-1 shrink-0">
                        <button onClick={() => { navigator.clipboard.writeText(item.value); }} className="rounded border border-divider-soft bg-card/30 px-1.5 py-0.5 text-mono ba-text-3xs uppercase tracking-widest text-muted-foreground hover:text-primary">copy</button>
                        <button onClick={() => { locker.add({ value: item.value, type: item.label === "URL" ? "url" : "domain", source: "/url" }); }} className="rounded border border-divider-soft bg-card/30 px-1.5 py-0.5 text-mono ba-text-3xs uppercase tracking-widest text-muted-foreground hover:text-primary">locker</button>
                      </div>
                    </div>
                  ))}
                </div>
              </Panel>

              {renderEnrichment(er)}

              {/* MITRE ATT&CK */}
              {analysis.mitre.length > 0 && (
                <Panel title="MITRE ATT&CK Mapping" icon={Crosshair} meta={`${analysis.mitre.length} technique${analysis.mitre.length === 1 ? "" : "s"}`} priority="secondary">
                  <div className="flex flex-wrap gap-2">
                    {analysis.mitre.map((m, i) => (
                      <span key={i} className="inline-flex items-center gap-1.5 rounded border border-divider-strong bg-card/40 px-2 py-1 text-mono ba-text-sm text-foreground/85">
                        <Bug className="h-3 w-3 text-destructive" />
                        <span className="font-semibold">{m.id}</span>
                        <span className="text-muted-foreground">:</span>
                        <span>{m.name}</span>
                      </span>
                    ))}
                  </div>
                </Panel>
              )}

              {/* Risk Signals */}
              <SectionBar id="EV" label="Risk signals" meta={`${analysis.findings.length} \u00B7 reason \u00B7 action`} priority="secondary" />
              <div className="grid gap-3 grid-cols-2">
                {analysis.findings.length === 0 ? <Empty title="No suspicious patterns" hint="URL Analyzer extracts IOCs, detects phishing indicators (typosquatting, defanged URLs), and traces redirect chains. Try a different URL or check the parsed components below." /> : analysis.findings.map((f, i) => (
                  <EvidenceCard key={i} severity={f.sev} title={f.t} reason={f.r} action={f.a} limitation="Heuristic \u2014 verify with passive DNS / TLS / WHOIS." />
                ))}
              </div>

              {/* Parsed URL */}
              <Panel title="Parsed URL" icon={Link2} meta="components">
                <KeyFields items={[
                  { label: "Scheme", value: analysis.parsed.protocol.replace(":", "") },
                  ...(analysis.parsed.hostname ? [{ label: "Host", value: analysis.parsed.hostname }] : []),
                  ...(analysis.parsed.port ? [{ label: "Port", value: analysis.parsed.port }] : []),
                  ...(analysis.parsed.pathname ? [{ label: "Path", value: analysis.parsed.pathname }] : []),
                  ...(analysis.parsed.search ? [{ label: "Query", value: analysis.parsed.search }] : []),
                  ...(analysis.parsed.hash ? [{ label: "Fragment", value: analysis.parsed.hash }] : []),
                  ...(analysis.parsed.username ? [{ label: "Username", value: analysis.parsed.username }] : []),
                  ...(analysis.parsed.password ? [{ label: "Password", value: analysis.parsed.password }] : []),
                ]} />
              </Panel>

              {/* Export + Handoff */}
              <div className="grid gap-4 grid-cols-[1fr_2fr]">
                <Panel title="Export Report" icon={Download} priority="secondary">
                  <button
                    onClick={() => {
                      const md = genMarkdownExport(analysis.parsed!, analysis.findings, analysis.secrets, analysis.mitre, analysis.pathSignals, analysis.fileExt, analysis.hasEmbeddedCreds, analysis.hasPathTraversal, analysis.isNumericDomain, analysis.hasNonStandardPort, analysis.portNum ?? "", analysis.suspiciousChars);
                      const blob = new Blob([md], { type: "text/markdown" });
                      const url = URL.createObjectURL(blob);
                      const a = document.createElement("a"); a.href = url; a.download = `url-report-${Date.now()}.md`; a.click();
                      URL.revokeObjectURL(url);
                    }}
                    className="group inline-flex w-full items-center justify-center gap-2 rounded border border-primary/50 bg-primary/10 px-4 py-2 text-mono ba-text-2xs uppercase tracking-widest text-primary transition-all hover:bg-primary/20"
                  >
                    <Download className="h-3.5 w-3.5" />
                    Download Markdown
                  </button>
                  <button
                    onClick={() => {
                      const json = genJsonExport(analysis.parsed!, analysis.findings, analysis.secrets, analysis.mitre, analysis.pathSignals, analysis.fileExt, analysis.hasEmbeddedCreds, analysis.hasPathTraversal, analysis.isNumericDomain, analysis.hasNonStandardPort, analysis.portNum ?? "", analysis.suspiciousChars);
                      const blob = new Blob([json], { type: "application/json" });
                      const url = URL.createObjectURL(blob);
                      const a = document.createElement("a"); a.href = url; a.download = `url-report-${Date.now()}.json`; a.click();
                      URL.revokeObjectURL(url);
                    }}
                    className="group inline-flex w-full items-center justify-center gap-2 rounded border border-border/50 bg-card/40 px-4 py-2 text-mono ba-text-2xs uppercase tracking-widest text-foreground/80 transition-all hover:border-primary/40 hover:text-primary"
                  >
                    <Download className="h-3.5 w-3.5" />
                    Download JSON
                  </button>
                  <p className="mt-2 text-[11px] text-muted-foreground">Includes all indicators, findings, secrets, and MITRE mapping.</p>
                </Panel>
                <SendToRow
                  targets={[
                    { label: "Recon & Exposure", to: "/recon", icon: Globe2, onClick: () => sendArtifact({ kind: "domain", value: analysis.parsed!.hostname, source: "/url" }) },
                    { label: "OSINT Toolkit", to: "/osint", icon: ShieldAlert, onClick: () => sendArtifact({ kind: "domain", value: analysis.parsed!.hostname, source: "/url" }) },
                    { label: "Detection", to: "/detection", icon: AlertTriangle, onClick: () => sendArtifact({ kind: "url", value: analysis.parsed!.href, source: "/url" }) },
                    { label: "Logs & Alerts", to: "/logs", icon: Database, onClick: () => sendArtifact({ kind: "url", value: analysis.parsed!.href, source: "/url" }) },
                    { label: "Case Notebook", to: "/case", icon: ArrowRight, onClick: () => sendArtifact({ kind: "url", value: analysis.parsed!.href, source: "/url" }) },
                  ]}
                />
              </div>
            </div>
          )
        }
      />
    </PageShell>
  );
}
