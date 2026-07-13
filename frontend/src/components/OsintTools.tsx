import { useEffect, useMemo, useState } from "react";
import { IntakeCard, SectionBar, Panel, SendToRow, Chip } from "@/components/soc";
import { StatusBar, VerdictBanner, MetricGrid, CollapsibleSection } from "@/components/output";
import { useOutputFilter, OutputFilterBar, OutputFilter } from "@/components/soc/OutputFilter";
import { PreviewBadge } from "@/components/PreviewBadge";
import { takePendingArtifact } from "@/lib/handoff";
import { emailOsint, socialLinksFinder, usernameOsint, getLocalOsintTools, runLocalOsintTool, runMaigret, runTheHarvester } from "@/api/backend";
import { useLocker } from "@/lib/locker";
import { Search, ExternalLink, Globe as Globe2, ArrowRight, Zap, Database, Terminal, ShieldAlert, Award, Network, ScrollText, KeyRound, History, Copy, Check, Pin, PinOff, Hash, AtSign, Server, FileText, ShieldCheck, Download } from "lucide-react";
import type { LucideIcon } from "lucide-react";
import { toast } from "sonner";

type Tool = { id: string; label: string; cat: string; href: (v: string) => string; supports: TargetKind[] };
type TargetKind = "domain" | "ipv4" | "email" | "hash" | "raw";

const TOOLS: Tool[] = [
  { id: "vt", label: "VirusTotal", cat: "Reputation",     supports: ["domain","ipv4","hash","raw"], href: (v) => `https://www.virustotal.com/gui/search/${encodeURIComponent(v)}` },
  { id: "abuseipdb", label: "AbuseIPDB", cat: "Reputation", supports: ["ipv4"], href: (v) => `https://www.abuseipdb.com/check/${encodeURIComponent(v)}` },
  { id: "otx", label: "AlienVault OTX", cat: "Reputation", supports: ["domain","ipv4","hash"], href: (v) => `https://otx.alienvault.com/browse/global/pulses?q=${encodeURIComponent(v)}` },
  { id: "urlscan", label: "urlscan.io", cat: "URL", supports: ["domain","raw"], href: (v) => `https://urlscan.io/search/#${encodeURIComponent(v)}` },
  { id: "shodan", label: "Shodan", cat: "Exposure", supports: ["domain","ipv4"], href: (v) => `https://www.shodan.io/search?query=${encodeURIComponent(v)}` },
  { id: "censys", label: "Censys", cat: "Exposure", supports: ["domain","ipv4"], href: (v) => `https://search.censys.io/search?q=${encodeURIComponent(v)}` },
  { id: "greynoise", label: "GreyNoise", cat: "Exposure", supports: ["ipv4"], href: (v) => `https://viz.greynoise.io/ip/${encodeURIComponent(v)}` },
  { id: "crtsh", label: "crt.sh", cat: "Certificates", supports: ["domain"], href: (v) => `https://crt.sh/?q=${encodeURIComponent(v)}` },
  { id: "viewdns", label: "ViewDNS reverse-ip", cat: "DNS", supports: ["domain","ipv4"], href: (v) => `https://viewdns.info/reverseip/?host=${encodeURIComponent(v)}` },
  { id: "securitytrails", label: "SecurityTrails", cat: "DNS", supports: ["domain","ipv4"], href: (v) => `https://securitytrails.com/list/apex_domain/${encodeURIComponent(v)}` },
  { id: "whoisxml", label: "WhoisXML", cat: "WHOIS", supports: ["domain"], href: (v) => `https://whois.whoisxmlapi.com/lookup?domain=${encodeURIComponent(v)}` },
  { id: "haveibeenpwned", label: "haveibeenpwned", cat: "Breach", supports: ["email"], href: (v) => `https://haveibeenpwned.com/account/${encodeURIComponent(v)}` },
  { id: "dehashed", label: "DeHashed", cat: "Breach", supports: ["email","domain"], href: (v) => `https://dehashed.com/search?query=${encodeURIComponent(v)}` },
  { id: "google", label: "Google dork", cat: "Search", supports: ["domain","email","raw"], href: (v) => `https://www.google.com/search?q=site%3A${encodeURIComponent(v)}` },
  { id: "github", label: "GitHub code", cat: "Search", supports: ["domain","email","raw","hash"], href: (v) => `https://github.com/search?q=${encodeURIComponent(v)}&type=code` },

  { id: "hunter", label: "Hunter.io", cat: "Discovery", supports: ["domain"], href: (v) => `https://hunter.io/search/${encodeURIComponent(v)}` },
  { id: "intelx", label: "IntelX", cat: "Discovery", supports: ["domain","email","raw"], href: (v) => `https://intelx.io/?s=${encodeURIComponent(v)}` },
  { id: "leakix", label: "LeakIX", cat: "Discovery", supports: ["domain","ipv4"], href: (v) => `https://leakix.net/search?q=${encodeURIComponent(v)}` },

  { id: "builtwith", label: "BuiltWith", cat: "Tech Stack", supports: ["domain"], href: (v) => `https://builtwith.com/${encodeURIComponent(v)}` },
  { id: "wappalyzer", label: "Wappalyzer", cat: "Tech Stack", supports: ["domain"], href: (v) => `https://www.wappalyzer.com/lookup/${encodeURIComponent(v)}` },

  { id: "dnsdumpster", label: "DNSDumpster", cat: "DNS", supports: ["domain"], href: (v) => `https://dnsdumpster.com/domain/${encodeURIComponent(v)}` },

  { id: "pulsedive", label: "Pulsedive", cat: "Threat Intel", supports: ["domain","ipv4","hash","raw"], href: (v) => `https://pulsedive.com/indicator/?query=${encodeURIComponent(v)}` },
  { id: "talos", label: "Talos Intelligence", cat: "Threat Intel", supports: ["domain","ipv4","hash"], href: (v) => `https://talosintelligence.com/reputation_center/lookup?search=${encodeURIComponent(v)}` },
  { id: "threatminer", label: "ThreatMiner", cat: "Threat Intel", supports: ["domain","ipv4","hash"], href: (v) => `https://www.threatminer.org/domain.php?q=${encodeURIComponent(v)}` },

  { id: "wayback", label: "Wayback Machine", cat: "Archive", supports: ["domain","raw"], href: (v) => `https://web.archive.org/web/*/${encodeURIComponent(v)}` },
  { id: "domaintools", label: "DomainTools", cat: "WHOIS", supports: ["domain","ipv4"], href: (v) => `https://whois.domaintools.com/${encodeURIComponent(v)}` },
  { id: "fofa", label: "FOFA", cat: "Exposure", supports: ["domain","ipv4"], href: (v) => `https://en.fofa.info/result?qbase64=${btoa(encodeURIComponent(v))}` },
  { id: "zoomeye", label: "ZoomEye", cat: "Exposure", supports: ["domain","ipv4"], href: (v) => `https://www.zoomeye.org/searchResult?q=${encodeURIComponent(v)}` },
];

const CAT_META: Record<string, { icon: LucideIcon; tone: "primary" | "warning" | "success" | "info" | "accent" }> = {
  Reputation:   { icon: ShieldAlert, tone: "warning" },
  URL:          { icon: Globe2,      tone: "primary" },
  Certificates: { icon: Award,       tone: "accent" },
  DNS:          { icon: ScrollText,  tone: "primary" },
  WHOIS:        { icon: ScrollText,  tone: "primary" },
  Breach:       { icon: KeyRound,    tone: "warning" },
  Search:       { icon: Search,      tone: "info" },
  Discovery:    { icon: Search,      tone: "primary" },
  "Tech Stack": { icon: Database,    tone: "accent" },
  "Threat Intel": { icon: ShieldAlert, tone: "warning" },
  Archive:      { icon: History,     tone: "info" },
  Exposure:     { icon: Globe2,      tone: "info" },
};

const KIND_META: Record<TargetKind, { icon: LucideIcon; label: string; tone: "primary"|"warning"|"info"|"success" }> = {
  domain: { icon: Globe2, label: "domain",  tone: "primary" },
  ipv4:   { icon: Server, label: "ipv4",    tone: "info"    },
  email:  { icon: AtSign, label: "email",   tone: "warning" },
  hash:   { icon: Hash,   label: "hash",    tone: "warning" },
  raw:    { icon: FileText,label: "raw",    tone: "primary" },
};

function classify(v: string): TargetKind {
  const t = v.trim();
  if (!t) return "raw";
  if (/^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/.test(t)) return "hash";
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(t)) return "ipv4";
  if (/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(t)) return "email";
  if (/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(t)) return "domain";
  return "raw";
}

function cliFor(kind: TargetKind, v: string): { label: string; cmd: string }[] {
  const target = v || "<target>";
  if (kind === "ipv4") return [
    { label: "Reverse DNS",    cmd: `dig -x ${target} +short` },
    { label: "WHOIS",          cmd: `whois ${target}` },
    { label: "Open ports",     cmd: `nmap -sS -Pn -T4 --top-ports 50 ${target}` },
    { label: "Full scan",      cmd: `nmap -sV -sC -A ${target}` },
    { label: "Masscan",        cmd: `sudo masscan ${target} --ports 1-65535 --rate=1000` },
    { label: "TLS banner",     cmd: `openssl s_client -connect ${target}:443 </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -dates` },
    { label: "Traceroute",     cmd: `mtr -rn -c 5 ${target}` },
  ];
  if (kind === "email") return [
    { label: "MX of domain",   cmd: `dig MX ${target.split("@")[1] ?? "domain.tld"} +short` },
    { label: "SPF lookup",     cmd: `dig TXT ${target.split("@")[1] ?? "domain.tld"} +short | grep -i spf` },
    { label: "Pwned check",    cmd: `curl -s "https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(target)}"` },
    { label: "theHarvester",   cmd: `theHarvester -d ${target.split("@")[1] ?? "domain.tld"} -b email` },
    { label: "h8mail",         cmd: `h8mail -t ${target}` },
  ];
  if (kind === "hash") return [
    { label: "VirusTotal",     cmd: `curl -sH "x-apikey: \$VT_API" "https://www.virustotal.com/api/v3/files/${target}"` },
    { label: "MalwareBazaar",  cmd: `curl -s -d "query=get_info&hash=${target}" https://mb-api.abuse.ch/api/v1/` },
    { label: "searchsploit",   cmd: `searchsploit ${target}` },
  ];
  return [
    { label: "DNS A",          cmd: `dig +short ${target}` },
    { label: "WHOIS",          cmd: `whois ${target}` },
    { label: "MX records",     cmd: `host -t MX ${target}` },
    { label: "HTTP headers",   cmd: `curl -sI https://${target}` },
    { label: "TLS chain",      cmd: `openssl s_client -connect ${target}:443 -servername ${target} </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -dates` },
    { label: "theHarvester",   cmd: `theHarvester -d ${target} -b all` },
    { label: "Amass enum",     cmd: `amass enum -d ${target}` },
    { label: "Sublist3r",      cmd: `sublist3r -d ${target}` },
    { label: "AssetFinder",    cmd: `assetfinder --subs-only ${target}` },
    { label: "WaybackURLs",    cmd: `waybackurls ${target}` },
    { label: "Gau",            cmd: `gau ${target}` },
    { label: "Katana",         cmd: `katana -u https://${target}` },
    { label: "WhatWeb",        cmd: `whatweb ${target}` },
    { label: "Nuclei",         cmd: `nuclei -u https://${target}` },
  ];
}

function HarvesterJsonSummary({ data }: { data: Record<string, unknown> }) {
  const emailCount = Array.isArray(data.emails) ? data.emails.length : Array.isArray(data.email) ? data.email.length : 0;
  const hostCount = Array.isArray(data.hosts) ? data.hosts.length : 0;
  const subdomainCount = Array.isArray(data.subdomains) ? data.subdomains.length : Array.isArray(data.hostnames) ? data.hostnames.length : 0;
  const items: { count: number; label: string; tone: string }[] = [];
  if (emailCount > 0) items.push({ count: emailCount, label: "emails", tone: "text-warning" });
  if (hostCount > 0) items.push({ count: hostCount, label: "hosts", tone: "text-info" });
  if (subdomainCount > 0) items.push({ count: subdomainCount, label: "subdomains", tone: "text-primary" });
  if (!items.length) return null;
  return (
    <div className="flex flex-wrap gap-1">
      {items.map((item) => (
        <span key={item.label} className={`rounded border border-divider-strong bg-card/40 px-2 py-1 text-mono ba-text-sm text-foreground/85 ${item.tone}`}>
          {item.count} {item.label}
        </span>
      ))}
    </div>
  );
}

function HarvesterExtractIocBtn({ data, locker: l }: { data: Record<string, unknown>; locker: ReturnType<typeof useLocker> }) {
  const emails = (Array.isArray(data.emails) ? data.emails : Array.isArray(data.email) ? data.email : []) as string[];
  const hosts = (Array.isArray(data.hosts) ? data.hosts : []) as string[];
  const subdomains = (Array.isArray(data.subdomains) ? data.subdomains : Array.isArray(data.hostnames) ? data.hostnames : []) as string[];
  return (
    <>
      {emails.length > 0 && <button onClick={() => { emails.forEach((item) => l.add({ value: item, type: "email", source: "/harvester" })); toast(`Added ${emails.length} emails to locker`); }} className="inline-flex items-center gap-1 rounded border border-border/50 bg-card/40 px-1.5 py-0.5 text-mono ba-text-3xs uppercase tracking-widest text-muted-foreground hover:bg-card/70 hover:text-foreground">+ emails ({emails.length})</button>}
      {hosts.length > 0 && <button onClick={() => { hosts.forEach((item) => l.add({ value: item, type: "unknown", source: "/harvester" })); toast(`Added ${hosts.length} hosts to locker`); }} className="inline-flex items-center gap-1 rounded border border-border/50 bg-card/40 px-1.5 py-0.5 text-mono ba-text-3xs uppercase tracking-widest text-muted-foreground hover:bg-card/70 hover:text-foreground">+ hosts ({hosts.length})</button>}
      {subdomains.length > 0 && <button onClick={() => { subdomains.forEach((item) => l.add({ value: item, type: "domain", source: "/harvester" })); toast(`Added ${subdomains.length} subdomains to locker`); }} className="inline-flex items-center gap-1 rounded border border-border/50 bg-card/40 px-1.5 py-0.5 text-mono ba-text-3xs uppercase tracking-widest text-muted-foreground hover:bg-card/70 hover:text-foreground">+ subdomains ({subdomains.length})</button>}
    </>
  );
}

export function OsintTools({ showSectionBars = true }: { showSectionBars?: boolean }) {
  const [v, setV] = useState("");
  const [history, setHistory] = useState<string[]>([]);
  const [pinned, setPinned] = useState<string[]>([]);
  const [copied, setCopied] = useState<string | null>(null);

  useEffect(() => {
    const h = takePendingArtifact();
    if (h?.value) setV(h.value);
    try {
      setHistory(JSON.parse(localStorage.getItem("ba.osint.history") || "[]"));
      setPinned(JSON.parse(localStorage.getItem("ba.osint.pinned")   || "[]"));
    } catch {}
  }, []);

  const { filterText, setFilterText, showFilter, setShowFilter, toggleFilter } = useOutputFilter();
  const [osintResult, setOsintResult] = useState<Record<string, unknown> | null>(null);
  const [lookupLoading, setLookupLoading] = useState(false);
  const [toolStatus, setToolStatus] = useState<Record<string, unknown> | null>(null);
  const [toolRunning, setToolRunning] = useState<string | null>(null);
  const [toolOutput, setToolOutput] = useState<Record<string, unknown> | null>(null);
  const [maigretResult, setMaigretResult] = useState<Record<string, unknown> | null>(null);
  const [maigretLoading, setMaigretLoading] = useState(false);
  const [theHarvesterResult, setTheHarvesterResult] = useState<Record<string, unknown> | null>(null);
  const [theHarvesterLoading, setTheHarvesterLoading] = useState(false);
  const [theHarvesterSource, setTheHarvesterSource] = useState("duckduckgo");
  const [searchsploitResult, setSearchsploitResult] = useState<Record<string, unknown> | null>(null);
  const [searchsploitLoading, setSearchsploitLoading] = useState(false);

  const locker = useLocker();

  useEffect(() => {
    getLocalOsintTools().then(setToolStatus).catch(() => {});
  }, []);

  async function runOsintLookup() {
    if (!v.trim()) return;
    setLookupLoading(true);
    setOsintResult(null);
    try {
      const res = kind === "email" ? await emailOsint(v) : kind === "domain" ? await socialLinksFinder(v) : await usernameOsint(v);
      setOsintResult(res);
    } catch { setOsintResult({ error: "API call failed" }); }
    finally { setLookupLoading(false); }
  }

  async function runTool(toolId: string) {
    setToolRunning(toolId);
    setToolOutput(null);
    try {
      const res = await runLocalOsintTool({ toolId, domain: v, source: "duckduckgo", limit: 50 });
      setToolOutput(res);
    } catch { setToolOutput({ error: "Tool execution failed" }); }
    finally { setToolRunning(null); }
  }

  async function runMaigretLookup() {
    if (!v.trim()) return;
    setMaigretLoading(true);
    setMaigretResult(null);
    try {
      const res = await runMaigret(v);
      setMaigretResult(res);
    } catch { setMaigretResult({ error: "Maigret lookup failed" }); }
    finally { setMaigretLoading(false); }
  }

  async function runTheHarvesterLookup() {
    if (!v.trim()) return;
    setTheHarvesterLoading(true);
    setTheHarvesterResult(null);
    try {
      const domain = kind === "email" ? v.split("@")[1] ?? v : v;
      const res = await runTheHarvester({ domain, source: theHarvesterSource, limit: 50, confirmPermission: false });
      setTheHarvesterResult(res);
    } catch { setTheHarvesterResult({ error: "theHarvester lookup failed" }); }
    finally { setTheHarvesterLoading(false); }
  }

  async function runSearchsploitLookup() {
    setSearchsploitLoading(true);
    setSearchsploitResult(null);
    try {
      const res = await runLocalOsintTool({ toolId: "searchsploit", domain: v, source: v, limit: 50 });
      setSearchsploitResult(res);
    } catch { setSearchsploitResult({ error: "searchsploit lookup failed" }); }
    finally { setSearchsploitLoading(false); }
  }

  const kind = classify(v);
  const ready = v.trim().length > 0;
  const cats = useMemo(() => Array.from(new Set(TOOLS.map((t) => t.cat))), []);
  const applicable = useMemo(() => TOOLS.filter((t) => t.supports.includes(kind)), [kind]);

  function commit(value: string) {
    const t = value.trim();
    if (!t) return;
    setHistory((prev) => {
      const next = [t, ...prev.filter((p) => p !== t)].slice(0, 8);
      try { localStorage.setItem("ba.osint.history", JSON.stringify(next)); } catch {}
      return next;
    });
  }
  function togglePin(t: string) {
    setPinned((prev) => {
      const next = prev.includes(t) ? prev.filter((p) => p !== t) : [t, ...prev].slice(0, 12);
      try { localStorage.setItem("ba.osint.pinned", JSON.stringify(next)); } catch {}
      return next;
    });
  }
  function openOne(tool: Tool) { window.open(tool.href(v), "_blank", "noopener"); commit(v); }
  function openAll() {
    if (!ready) return;
    if (applicable.length > 5 && !confirm(`Open ${applicable.length} tabs? This will open many browser tabs at once.`)) return;
    applicable.forEach((t) => window.open(t.href(v), "_blank", "noopener"));
    commit(v);
  }
  function copy(text: string, key: string) {
    navigator.clipboard?.writeText(text);
    setCopied(key);
    setTimeout(() => setCopied((c) => (c === key ? null : c)), 1100);
  }

  const cli = cliFor(kind, v);

  return (
    <>
      {showSectionBars && <SectionBar id="IN" label="Intake · target" meta="domain · IP · email · hash" />}
      <IntakeCard
        icon={Search}
        title="Target"
        value={v}
        onChange={setV}
        rows={2}
        placeholder="example.com · 198.51.100.1 · user@example.com · sha256…"
        samples={[
          { key: "d", label: "Domain", hint: "example.com" },
          { key: "i", label: "IPv4",   hint: "198.51.100.1" },
          { key: "e", label: "Email",  hint: "alice@example.com" },
          { key: "h", label: "SHA-256",hint: "44d88612fea8a8f3" },
        ]}
        onLoadSample={(k) => setV(
          k === "d" ? "example.com" :
          k === "i" ? "198.51.100.1" :
          k === "e" ? "alice@example.com" :
          "44d88612fea8a8f36de82e1278abb02f44d88612fea8a8f36de82e1278abb02f"
        )}
        run={{
          label: `open ${applicable.length} tabs`,
          icon: Zap,
          hint: applicable.length ? `${KIND_META[kind].label} pivots` : "no match",
          onClick: openAll,
          disabled: !ready || !applicable.length,
        }}
        onClear={() => setV("")}
        showCopy
      />

      <StatusBar stats={[
        { label: "Status",    value: ready ? "Ready" : "Idle", tone: ready ? "success" : "muted" },
        { label: "Detected",  value: KIND_META[kind].label, tone: (KIND_META[kind].tone === "info" ? "primary" : KIND_META[kind].tone) as "primary" | "warning" },
        { label: "Pivots",    value: `${applicable.length}/${TOOLS.length}` },
        { label: "History",   value: history.length },
        { label: "Pinned",    value: pinned.length, tone: pinned.length ? "primary" : "muted" },
        { label: "Auto-query",value: "off", tone: "muted" },
      ]} />

      {ready && (
        <>
          <VerdictBanner
            verdict={`${KIND_META[kind].label} · ${applicable.length} pivots`}
            tone="success"
            icon={ShieldCheck}
            details={[
              `${applicable.length} services match this target type`,
              `categories: ${Array.from(new Set(applicable.map((t) => t.cat))).join(", ")}`,
              "Click any service to inspect — no API call is made from BeyondLabs",
            ].filter(Boolean)}
          />
          <MetricGrid
            columns={4}
            metrics={[
              { label: "Categories", value: Array.from(new Set(applicable.map((t) => t.cat))).length, tone: "primary", icon: Network },
              { label: "Reputation", value: applicable.filter((t) => t.cat === "Reputation").length, tone: "warning" },
              { label: "Exposure", value: applicable.filter((t) => t.cat === "Exposure").length, tone: "info" },
              { label: "Other", value: applicable.filter((t) => !["Reputation", "Exposure"].includes(t.cat)).length },
              { label: "Detected", value: KIND_META[kind].label, tone: (KIND_META[kind].tone === "info" ? "primary" : KIND_META[kind].tone) as "primary" | "warning" },
              { label: "CLI cmds", value: cli.length },
              { label: "History", value: history.length },
              { label: "Pinned", value: pinned.length, tone: pinned.length > 0 ? "primary" : "default" },
            ]}
          />
        </>
      )}

      {(pinned.length > 0 || history.length > 0) && (
        <Panel icon={History} title="Recent & pinned targets" meta={`${pinned.length} pinned · ${history.length} recent`} actions={<PreviewBadge label="local only" />}>
          <div className="space-y-2.5">
            {pinned.length > 0 && (
              <div>
                <div className="mb-1 text-mono text-[10px] uppercase tracking-widest text-muted-foreground">Pinned</div>
                <div className="flex flex-wrap gap-1.5">
                  {pinned.map((p) => (
                    <TargetChip key={p} value={p} pinned onPick={setV} onPin={togglePin} />
                  ))}
                </div>
              </div>
            )}
            {history.length > 0 && (
              <div>
                <div className="mb-1 text-mono text-[10px] uppercase tracking-widest text-muted-foreground">Recent</div>
                <div className="flex flex-wrap gap-1.5">
                  {history.map((p) => (
                    <TargetChip key={p} value={p} pinned={pinned.includes(p)} onPick={setV} onPin={togglePin} />
                  ))}
                </div>
              </div>
            )}
          </div>
        </Panel>
      )}

      <div className="flex items-center gap-2">
        {showSectionBars && <SectionBar id="OT" label="Output · external pivots" meta={`${applicable.length} matching · ${cats.length} categories`} />}
        <button
          onClick={toggleFilter}
          className={"inline-flex shrink-0 items-center gap-1 rounded border px-2 py-1 text-mono text-[10px] uppercase tracking-widest transition-colors " + (showFilter ? "border-primary/50 bg-primary/10 text-primary" : "border-divider-strong text-muted-foreground hover:border-primary/40 hover:text-primary")}
          title="Toggle output filter (⌘F)"
        >
          <Search className="h-3 w-3" />
          filter
        </button>
      </div>

      {showFilter && (
        <OutputFilterBar
          filterText={filterText}
          onChange={setFilterText}
          onClear={() => setFilterText("")}
          onClose={() => { setShowFilter(false); setFilterText(""); }}
        />
      )}

      <OutputFilter query={filterText.toLowerCase()}>
      <CollapsibleSection id="PV" label="External Service Pivots" meta={`${applicable.length} services · ${cats.length} categories`} icon={ExternalLink}>
        <div className="grid gap-3 grid-cols-1 lg:grid-cols-2 xl:grid-cols-3">
          {cats.map((c) => {
            const items = TOOLS.filter((t) => t.cat === c);
            const meta = CAT_META[c] ?? { icon: Globe2, tone: "primary" as const };
            const matching = items.filter((t) => t.supports.includes(kind)).length;
            return (
              <Panel
                key={c}
                title={c}
                icon={meta.icon}
                meta={ready ? `${matching}/${items.length} match` : `${items.length} svc`}
                actions={<Chip tone={meta.tone}>{c.toLowerCase()}</Chip>}
              >
                <ul className="space-y-1.5">
                  {items.map((t) => {
                    const supported = t.supports.includes(kind);
                    const enabled = ready && supported;
                    return (
                      <li key={t.id}>
                        <div className={"group flex items-start justify-between gap-2 rounded border border-divider-strong bg-background/30 px-2.5 py-1.5 transition-all " + (enabled ? "hover:-translate-y-px hover:border-primary/50 hover:bg-primary/5" : "opacity-50")}>
                          <button
                            type="button"
                            disabled={!enabled}
                            onClick={() => openOne(t)}
                            className="flex min-w-0 flex-1 items-start gap-2 text-left disabled:cursor-not-allowed"
                            title={enabled ? `open ${t.label}` : !ready ? "Enter a target first" : `${t.label} does not support ${KIND_META[kind].label}`}
                          >
                            <ExternalLink className={"mt-[3px] h-3 w-3 shrink-0 " + (enabled ? "text-muted-foreground group-hover:text-primary" : "text-muted-foreground/60")} />
                            <div className="min-w-0">
                              <div className="text-mono text-[11.5px] text-foreground/90 group-hover:text-primary">{t.label}</div>
                            </div>
                          </button>
                          {!supported && ready && (
                            <span className="mt-0.5 rounded border border-divider-strong bg-background/60 px-1 py-px text-mono ba-text-3xs uppercase tracking-widest text-muted-foreground">n/a</span>
                          )}
                        </div>
                      </li>
                    );
                  })}
                </ul>
              </Panel>
            );
          })}
        </div>
      </CollapsibleSection>

      {showSectionBars && <SectionBar id="CL" label="Output · local CLI snippets" meta={`tuned for ${KIND_META[kind].label}`} />}

      <CollapsibleSection id="CLI" label="Suggested CLI Commands" meta={`${cli.length} commands`} icon={Terminal}>
        <Panel
          icon={Terminal}
          title="Suggested CLI"
          meta={`${cli.length} commands`}
          actions={
            <div className="flex items-center gap-1">
              <PreviewBadge label="copy & run locally" />
              <button
                onClick={() => copy(cli.map((l) => l.cmd).join("\n"), "all")}
                className="inline-flex items-center gap-1 rounded border border-border bg-background/60 px-1.5 py-0.5 text-mono text-[10px] uppercase tracking-widest text-muted-foreground hover:border-primary/40 hover:text-primary"
              >
                {copied === "all" ? <Check className="h-3 w-3 text-success" /> : <Copy className="h-3 w-3" />}
                {copied === "all" ? "copied" : "copy all"}
              </button>
            </div>
          }
        >
          <ul className="divide-y divide-border/40 overflow-hidden rounded border border-divider-strong bg-background/40">
            {cli.map((line, i) => (
              <li key={i} className="group grid grid-cols-[auto_1fr_auto] items-center gap-2 px-2 py-1.5">
                <span className="rounded border border-divider-strong bg-background/70 px-1 py-px text-mono ba-text-3xs uppercase tracking-widest text-muted-foreground">
                  {String(i + 1).padStart(2, "0")}
                </span>
                <div className="min-w-0">
                  <div className="truncate text-mono text-[10px] uppercase tracking-widest text-muted-foreground">{line.label}</div>
                  <div className={"truncate text-mono text-[11.5px] " + (ready ? "text-foreground/90" : "text-muted-foreground/60")}>
                    <span className="select-none text-muted-foreground/60">$ </span>{line.cmd}
                  </div>
                </div>
                <button
                  onClick={() => copy(line.cmd, `c-${i}`)}
                  disabled={!ready}
                  className="opacity-0 transition group-hover:opacity-100 disabled:opacity-30"
                  title="copy command"
                >
                  {copied === `c-${i}`
                    ? <Check className="h-3.5 w-3.5 text-success" />
                    : <Copy className="h-3.5 w-3.5 text-muted-foreground hover:text-primary" />}
                </button>
              </li>
            ))}
          </ul>
        </Panel>
      </CollapsibleSection>

      {showSectionBars && <SectionBar id="OL" label="Output · OSINT lookup" meta={`${kind} · ${v.trim() ? "ready" : "no target"}`} />}
      <Panel icon={Search} title="OSINT Lookup" meta={lookupLoading ? "loading..." : osintResult ? "done" : "idle"} actions={
        <div className="flex items-center gap-1">
          {osintResult && !lookupLoading && (
            <button onClick={() => { const json = JSON.stringify(osintResult, null, 2); const blob = new Blob([json], { type: "application/json" }); const url = URL.createObjectURL(blob); const a = document.createElement("a"); a.href = url; a.download = `osint-lookup-${v}.json`; a.click(); URL.revokeObjectURL(url); }} className="inline-flex items-center gap-1 rounded border border-border/50 bg-card/40 px-1.5 py-0.5 text-mono ba-text-3xs uppercase tracking-widest text-muted-foreground hover:bg-card/70 hover:text-foreground"><Download className="h-3 w-3" />json</button>
          )}
          <button onClick={runOsintLookup} disabled={!ready || lookupLoading} className="inline-flex items-center gap-1 rounded border border-border bg-background/60 px-2 py-0.5 text-mono text-[10px] uppercase tracking-widest text-muted-foreground hover:text-foreground disabled:opacity-40">
            {lookupLoading ? "looking up..." : "Run OSINT Lookup"}
          </button>
        </div>
      }>
        {!ready && <div className="text-mono ba-text-sm text-muted-foreground/70">Enter a target above to run an OSINT lookup — email → DNS posture, domain → social links, else → username platforms.</div>}
        {lookupLoading && <div className="text-mono ba-text-sm text-muted-foreground animate-pulse">Querying backend…</div>}
        {osintResult && !lookupLoading && (
          <div className="space-y-2">
            <div className="rounded border border-divider-strong bg-background/40 p-3">
              <pre className="max-h-48 overflow-auto text-mono ba-text-sm leading-relaxed text-foreground/90">{JSON.stringify(osintResult, null, 2)}</pre>
            </div>
            <div className="flex flex-wrap gap-1.5">
              <button onClick={() => { locker.add({ value: v, type: kind === "email" ? "email" : "domain", source: "/osint" }); toast(`Added ${v} to locker`); }} className="inline-flex items-center gap-1 rounded border border-border/50 bg-card/40 px-2 py-1 text-mono ba-text-3xs uppercase tracking-widest text-muted-foreground hover:bg-card/70 hover:text-foreground">+ locker target</button>
              {osintResult && Object.keys(osintResult).filter((k) => Array.isArray(osintResult[k])).map((k) => (
                <button key={k} onClick={() => { (osintResult[k] as string[]).forEach((item: string) => locker.add({ value: item, type: "unknown", source: "/osint" })); toast(`Added ${(osintResult[k] as string[]).length} ${k} to locker`); }} className="inline-flex items-center gap-1 rounded border border-border/50 bg-card/40 px-2 py-1 text-mono ba-text-3xs uppercase tracking-widest text-muted-foreground hover:bg-card/70 hover:text-foreground">+ {k} ({Array.isArray(osintResult[k]) ? (osintResult[k] as string[]).length : "?"})</button>
              ))}
            </div>
          </div>
        )}
      </Panel>

      {toolStatus && (toolStatus as any).runnable && (
        <Panel icon={Terminal} title="Local OSINT Tools" meta={`${(toolStatus as any).available_count ?? "?"}/${(toolStatus as any).total_count ?? "?"} available`} actions={<span className="text-mono ba-text-3xs uppercase tracking-widest text-muted-foreground">path check only</span>}>
          {toolOutput && (
            <div className="mb-3 rounded border border-primary/30 bg-primary/5 p-3">
              <div className="mb-1 text-mono text-[10px] uppercase tracking-widest text-primary">Last output</div>
              <pre className="max-h-48 overflow-auto text-mono ba-text-sm leading-relaxed text-foreground/90">{JSON.stringify(toolOutput, null, 2)}</pre>
            </div>
          )}
          <div className="grid gap-1.5 grid-cols-2">
            {Object.entries((toolStatus as any).runnable).map(([id, meta]: [string, any]) => (
              <div key={id} className={"flex items-center justify-between gap-2 rounded border px-2.5 py-1.5 " + (meta.available ? "border-divider-strong bg-background/30" : "border-divider-soft bg-background/10 opacity-50")}>
                <div className="min-w-0">
                  <div className="flex items-center gap-1.5">
                    <span className={"inline-block h-1.5 w-1.5 rounded-full " + (meta.available ? "bg-success" : "bg-muted-foreground/40")} />
                    <span className="text-mono ba-text-sm text-foreground/90">{meta.label}</span>
                  </div>
                  {meta.description && <div className="truncate text-mono ba-text-3xs text-muted-foreground">{meta.description}</div>}
                </div>
                <button onClick={() => runTool(id)} disabled={!meta.available || !ready || toolRunning === id} className="shrink-0 rounded border border-border bg-background/60 px-1.5 py-0.5 text-mono ba-text-3xs uppercase tracking-widest text-muted-foreground hover:text-foreground disabled:opacity-30">
                  {toolRunning === id ? "running…" : "run"}
                </button>
              </div>
            ))}
          </div>
        </Panel>
      )}

      {ready && kind !== "email" && kind !== "ipv4" && (
        <Panel icon={Search} title="Maigret username search" meta={maigretLoading ? "searching…" : maigretResult ? `${(maigretResult as any).sites_found ?? 0} sites` : "idle"} actions={
          <div className="flex items-center gap-1">
            {maigretResult && !maigretLoading && (
              <>
                <button onClick={() => { const json = JSON.stringify(maigretResult, null, 2); const blob = new Blob([json], { type: "application/json" }); const url = URL.createObjectURL(blob); const a = document.createElement("a"); a.href = url; a.download = `maigret-${v}.json`; a.click(); URL.revokeObjectURL(url); }} className="inline-flex items-center gap-1 rounded border border-border/50 bg-card/40 px-1.5 py-0.5 text-mono ba-text-3xs uppercase tracking-widest text-muted-foreground hover:bg-card/70 hover:text-foreground"><Download className="h-3 w-3" />json</button>
                <button onClick={() => { locker.add({ value: v, type: "unknown", source: "/maigret" }); toast(`Added ${v} to locker`); }} className="inline-flex items-center gap-1 rounded border border-border/50 bg-card/40 px-1.5 py-0.5 text-mono ba-text-3xs uppercase tracking-widest text-muted-foreground hover:bg-card/70 hover:text-foreground">+ locker</button>
              </>
            )}
            <button onClick={runMaigretLookup} disabled={maigretLoading} className="inline-flex items-center gap-1 rounded border border-border bg-background/60 px-2 py-0.5 text-mono text-[10px] uppercase tracking-widest text-muted-foreground hover:text-foreground disabled:opacity-40">
              {maigretLoading ? "searching…" : "Run Maigret"}
            </button>
          </div>
        }>
          {maigretResult && !maigretLoading && (
            <div className="space-y-2">
              <div className="flex items-center gap-2 text-mono ba-text-sm">
                <span className="text-muted-foreground">Status:</span>
                <span className={(maigretResult as any).status === "completed" ? "text-success" : "text-warning"}>{(maigretResult as any).status ?? "unknown"}</span>
                {(maigretResult as any).sites_found != null && (
                  <><span className="text-muted-foreground">· Sites:</span><span>{(maigretResult as any).sites_found}</span></>
                )}
              </div>
              {(maigretResult as any).notes && (
                <div className="text-mono text-[10px] text-muted-foreground">{(maigretResult as any).notes}</div>
              )}
              <div className="rounded border border-divider-strong bg-background/40 p-3">
                <pre className="max-h-48 overflow-auto text-mono ba-text-sm leading-relaxed text-foreground/90">{JSON.stringify(maigretResult, null, 2)}</pre>
              </div>
            </div>
          )}
          {!maigretResult && !maigretLoading && (
            <div className="text-mono ba-text-sm text-muted-foreground/70">Run maigret to search for this target across hundreds of social platforms.</div>
          )}
        </Panel>
      )}

      {(kind === "domain" || kind === "email") && (
        <>
          {showSectionBars && <SectionBar id="TH" label="Output · theHarvester" meta="domain intelligence" />}
          <Panel icon={Terminal} title="theHarvester" meta={theHarvesterLoading ? "running…" : theHarvesterResult ? "done" : "idle"} actions={
            <div className="flex items-center gap-1.5">
              {theHarvesterResult && !theHarvesterLoading && (
                <HarvesterExtractIocBtn data={theHarvesterResult} locker={locker} />
              )}
              <select
                value={theHarvesterSource}
                onChange={(e) => setTheHarvesterSource(e.target.value)}
                className="rounded border border-divider-strong bg-background/60 px-1.5 py-0.5 text-mono text-[10px] text-muted-foreground"
              >
                <option value="duckduckgo">DuckDuckGo</option>
                <option value="bing">Bing</option>
                <option value="google">Google</option>
                <option value="yahoo">Yahoo</option>
                <option value="baidu">Baidu</option>
                <option value="all">All sources</option>
              </select>
              <button onClick={runTheHarvesterLookup} disabled={!ready || theHarvesterLoading} className="inline-flex items-center gap-1 rounded border border-border bg-background/60 px-2 py-0.5 text-mono text-[10px] uppercase tracking-widest text-muted-foreground hover:text-foreground disabled:opacity-40">
                {theHarvesterLoading ? "running…" : "Run"}
              </button>
            </div>
          }>
            {theHarvesterResult && !theHarvesterLoading && (
              <div className="space-y-2">
                <div className="flex flex-wrap gap-1.5">
                  <button onClick={() => { const json = JSON.stringify(theHarvesterResult, null, 2); const blob = new Blob([json], { type: "application/json" }); const url = URL.createObjectURL(blob); const a = document.createElement("a"); a.href = url; a.download = `harvester-${v}.json`; a.click(); URL.revokeObjectURL(url); }} className="inline-flex items-center gap-1 rounded border border-border/50 bg-card/40 px-1.5 py-0.5 text-mono ba-text-3xs uppercase tracking-widest text-muted-foreground hover:bg-card/70 hover:text-foreground"><Download className="h-3 w-3" />json</button>
                  <HarvesterJsonSummary data={theHarvesterResult} />
                </div>
                <div className="rounded border border-divider-strong bg-background/40 p-3">
                  <pre className="max-h-48 overflow-auto text-mono ba-text-sm leading-relaxed text-foreground/90">{JSON.stringify(theHarvesterResult, null, 2)}</pre>
                </div>
              </div>
            )}
            {!theHarvesterResult && !theHarvesterLoading && (
              <div className="text-mono ba-text-sm text-muted-foreground/70">Run theHarvester to discover emails, subdomains, and hosts related to this target.</div>
            )}
          </Panel>
        </>
      )}

      {showSectionBars && <SectionBar id="SS" label="Output · searchsploit" meta="exploit & vulnerability database" />}
      <Panel icon={Terminal} title="SearchSploit" meta={searchsploitLoading ? "searching…" : searchsploitResult ? "done" : "idle"} actions={
        <div className="flex items-center gap-1">
          {searchsploitResult && !searchsploitLoading && (
            <>
              <button onClick={() => { const json = JSON.stringify(searchsploitResult, null, 2); const blob = new Blob([json], { type: "application/json" }); const url = URL.createObjectURL(blob); const a = document.createElement("a"); a.href = url; a.download = `searchsploit-${v}.json`; a.click(); URL.revokeObjectURL(url); }} className="inline-flex items-center gap-1 rounded border border-border/50 bg-card/40 px-1.5 py-0.5 text-mono ba-text-3xs uppercase tracking-widest text-muted-foreground hover:bg-card/70 hover:text-foreground"><Download className="h-3 w-3" />json</button>
              <button onClick={() => { locker.add({ value: v, type: kind === "hash" ? "sha256" : "unknown", source: "/searchsploit" }); toast(`Added ${v} to locker`); }} className="inline-flex items-center gap-1 rounded border border-border/50 bg-card/40 px-1.5 py-0.5 text-mono ba-text-3xs uppercase tracking-widest text-muted-foreground hover:bg-card/70 hover:text-foreground">+ locker</button>
            </>
          )}
          <button onClick={runSearchsploitLookup} disabled={!ready || searchsploitLoading} className="inline-flex items-center gap-1 rounded border border-border bg-background/60 px-2 py-0.5 text-mono text-[10px] uppercase tracking-widest text-muted-foreground hover:text-foreground disabled:opacity-40">
            {searchsploitLoading ? "searching…" : "Search Exploit-DB"}
          </button>
        </div>
      }>
        {searchsploitResult && !searchsploitLoading && (
          <div className="rounded border border-divider-strong bg-background/40 p-3">
            <pre className="max-h-48 overflow-auto text-mono ba-text-sm leading-relaxed text-foreground/90">{JSON.stringify(searchsploitResult, null, 2)}</pre>
          </div>
        )}
        {!searchsploitResult && !searchsploitLoading && (
          <div className="text-mono ba-text-sm text-muted-foreground/70">Search the Exploit Database for vulnerabilities related to this target. Supports CVE, software name, and keyword queries.</div>
        )}
      </Panel>

      <SendToRow targets={[
        { label: "Recon & Exposure", to: "/recon", icon: Globe2 },
        { label: "Nmap Runner", to: "/nmap", icon: Terminal },
        { label: "Detection", to: "/detection", icon: ArrowRight },
        { label: "Logs & Alerts", to: "/logs", icon: Database },
      ]} />
      </OutputFilter>
    </>
  );

  function TargetChip({ value, pinned, onPick, onPin }: { value: string; pinned: boolean; onPick: (v: string) => void; onPin: (v: string) => void }) {
    const k = classify(value);
    const Ico = KIND_META[k].icon;
    return (
      <span className="group inline-flex items-center gap-1 rounded border border-divider-strong bg-background/40 pl-1.5 pr-0.5 py-0.5 text-mono ba-text-sm hover:border-primary/50">
        <Ico className="h-3 w-3 text-muted-foreground" />
        <button onClick={() => onPick(value)} className="truncate max-w-[18ch] text-foreground/90 group-hover:text-primary" title={value}>{value}</button>
        <button onClick={() => onPin(value)} className="rounded p-0.5 text-muted-foreground hover:text-primary" title={pinned ? "unpin" : "pin"}>
          {pinned ? <Pin className="h-3 w-3" /> : <PinOff className="h-3 w-3" />}
        </button>
      </span>
    );
  }
}
