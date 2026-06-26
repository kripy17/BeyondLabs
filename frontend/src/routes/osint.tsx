import { createFileRoute } from "@tanstack/react-router";
import { useEffect, useMemo, useState } from "react";
import { PageShell } from "@/components/PageShell";
import { IntakeCard, StatusBar, ResultBanner, SectionBar, Panel, SendToRow, Chip } from "@/components/soc/Workspace";
import { PreviewBadge } from "@/components/PreviewBadge";
import { sendArtifact, takePendingArtifact } from "@/lib/handoff";
import {
  Search, ExternalLink, Globe2, ArrowRight, Zap, Database, Terminal,
  ShieldAlert, Award, Network, ScrollText, KeyRound, History, Copy, Check,
  Send, Pin, PinOff, Hash, AtSign, Server, FileText, Sparkles,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";

export const Route = createFileRoute("/osint")({ component: OsintPage });

type Tool = { id: string; label: string; cat: string; tagline: string; href: (v: string) => string; supports: TargetKind[] };
type TargetKind = "domain" | "ipv4" | "email" | "hash" | "raw";

const TOOLS: Tool[] = [
  { id: "vt", label: "VirusTotal", cat: "Reputation", tagline: "Hash / URL / IP reputation aggregate.", supports: ["domain","ipv4","hash","raw"], href: (v) => `https://www.virustotal.com/gui/search/${encodeURIComponent(v)}` },
  { id: "abuseipdb", label: "AbuseIPDB", cat: "Reputation", tagline: "IP abuse confidence score.", supports: ["ipv4"], href: (v) => `https://www.abuseipdb.com/check/${encodeURIComponent(v)}` },
  { id: "otx", label: "AlienVault OTX", cat: "Reputation", tagline: "Threat-intel pulses & indicators.", supports: ["domain","ipv4","hash"], href: (v) => `https://otx.alienvault.com/browse/global/pulses?q=${encodeURIComponent(v)}` },
  { id: "urlscan", label: "urlscan.io", cat: "URL", tagline: "Render & analyse a URL safely.", supports: ["domain","raw"], href: (v) => `https://urlscan.io/search/#${encodeURIComponent(v)}` },
  { id: "shodan", label: "Shodan", cat: "Exposure", tagline: "Internet-facing service map.", supports: ["domain","ipv4"], href: (v) => `https://www.shodan.io/search?query=${encodeURIComponent(v)}` },
  { id: "censys", label: "Censys", cat: "Exposure", tagline: "Host & certificate search.", supports: ["domain","ipv4"], href: (v) => `https://search.censys.io/search?q=${encodeURIComponent(v)}` },
  { id: "greynoise", label: "GreyNoise", cat: "Exposure", tagline: "Internet scanner / noise context.", supports: ["ipv4"], href: (v) => `https://viz.greynoise.io/ip/${encodeURIComponent(v)}` },
  { id: "crtsh", label: "crt.sh", cat: "Certificates", tagline: "CT log certificate history.", supports: ["domain"], href: (v) => `https://crt.sh/?q=${encodeURIComponent(v)}` },
  { id: "viewdns", label: "ViewDNS reverse-ip", cat: "DNS", tagline: "Find siblings on a shared host.", supports: ["domain","ipv4"], href: (v) => `https://viewdns.info/reverseip/?host=${encodeURIComponent(v)}` },
  { id: "securitytrails", label: "SecurityTrails", cat: "DNS", tagline: "Historic DNS & subdomain graph.", supports: ["domain","ipv4"], href: (v) => `https://securitytrails.com/list/apex_domain/${encodeURIComponent(v)}` },
  { id: "whoisxml", label: "WhoisXML", cat: "WHOIS", tagline: "Registration & registrar.", supports: ["domain"], href: (v) => `https://whois.whoisxmlapi.com/lookup?domain=${encodeURIComponent(v)}` },
  { id: "haveibeenpwned", label: "haveibeenpwned", cat: "Breach", tagline: "Account breach exposure.", supports: ["email"], href: (v) => `https://haveibeenpwned.com/account/${encodeURIComponent(v)}` },
  { id: "dehashed", label: "DeHashed", cat: "Breach", tagline: "Credential & breach search.", supports: ["email","domain"], href: (v) => `https://dehashed.com/search?query=${encodeURIComponent(v)}` },
  { id: "google", label: "Google dork", cat: "Search", tagline: "Indexed surface for a host.", supports: ["domain","email","raw"], href: (v) => `https://www.google.com/search?q=site%3A${encodeURIComponent(v)}` },
  { id: "github", label: "GitHub code", cat: "Search", tagline: "Leaked refs & config snippets.", supports: ["domain","email","raw","hash"], href: (v) => `https://github.com/search?q=${encodeURIComponent(v)}&type=code` },
];

const CAT_META: Record<string, { icon: LucideIcon; tone: "primary" | "warning" | "success" | "info" | "accent" }> = {
  Reputation:   { icon: ShieldAlert, tone: "warning" },
  URL:          { icon: Globe2,      tone: "primary" },
  Exposure:     { icon: Network,     tone: "info" },
  Certificates: { icon: Award,       tone: "accent" },
  DNS:          { icon: ScrollText,  tone: "primary" },
  WHOIS:        { icon: ScrollText,  tone: "primary" },
  Breach:       { icon: KeyRound,    tone: "warning" },
  Search:       { icon: Search,      tone: "info" },
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
    { label: "Reverse DNS",  cmd: `dig -x ${target} +short` },
    { label: "WHOIS",        cmd: `whois ${target}` },
    { label: "Open ports",   cmd: `nmap -sS -Pn -T4 --top-ports 50 ${target}` },
    { label: "TLS banner",   cmd: `openssl s_client -connect ${target}:443 </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -dates` },
    { label: "Traceroute",   cmd: `mtr -rn -c 5 ${target}` },
  ];
  if (kind === "email") return [
    { label: "MX of domain", cmd: `dig MX ${target.split("@")[1] ?? "domain.tld"} +short` },
    { label: "SPF lookup",   cmd: `dig TXT ${target.split("@")[1] ?? "domain.tld"} +short | grep -i spf` },
    { label: "Pwned check",  cmd: `curl -s "https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(target)}"` },
  ];
  if (kind === "hash") return [
    { label: "VirusTotal",   cmd: `curl -sH "x-apikey: $VT_API" "https://www.virustotal.com/api/v3/files/${target}"` },
    { label: "MalwareBazaar",cmd: `curl -s -d "query=get_info&hash=${target}" https://mb-api.abuse.ch/api/v1/` },
  ];
  return [
    { label: "DNS A",        cmd: `dig +short ${target}` },
    { label: "WHOIS",        cmd: `whois ${target}` },
    { label: "MX records",   cmd: `host -t MX ${target}` },
    { label: "HTTP headers", cmd: `curl -sI https://${target}` },
    { label: "TLS chain",    cmd: `openssl s_client -connect ${target}:443 -servername ${target} </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -dates` },
  ];
}

function OsintPage() {
  const [v, setV] = useState("");
  const [history, setHistory] = useState<string[]>([]);
  const [pinned, setPinned] = useState<string[]>([]);
  const [copied, setCopied] = useState<string | null>(null);

  // Inbound handoff
  useEffect(() => {
    const h = takePendingArtifact();
    if (h?.value) setV(h.value);
    try {
      setHistory(JSON.parse(localStorage.getItem("ba.osint.history") || "[]"));
      setPinned(JSON.parse(localStorage.getItem("ba.osint.pinned")   || "[]"));
    } catch {}
  }, []);

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
    applicable.forEach((t) => window.open(t.href(v), "_blank", "noopener"));
    commit(v);
  }
  function copy(text: string, key: string) {
    navigator.clipboard?.writeText(text);
    setCopied(key);
    setTimeout(() => setCopied((c) => (c === key ? null : c)), 1100);
  }

  const KindIcon = KIND_META[kind].icon;
  const cli = cliFor(kind, v);

  return (
    <PageShell
      eyebrow="RECON / OSINT"
      title="OSINT Toolkit"
      description="Curated jump-list of external lookups, pivots, and copy-paste CLI. Nothing is auto-queried — every link opens in a new tab."
      crumbs={[{ label: "Recon" }, { label: "OSINT" }]}
    >
      <SectionBar id="IN" label="Intake · target" meta="domain · IP · email · hash" />
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
          { key: "h", label: "SHA-256",hint: "a1b2…" },
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
        { label: "Detected",  value: KIND_META[kind].label, tone: (KIND_META[kind].tone === "info" ? "primary" : KIND_META[kind].tone) as any },
        { label: "Pivots",    value: `${applicable.length}/${TOOLS.length}` },
        { label: "History",   value: history.length },
        { label: "Pinned",    value: pinned.length, tone: pinned.length ? "primary" : "muted" },
        { label: "Auto-query",value: "off", tone: "muted" },
      ]} />

      {ready && (
        <ResultBanner
          badge={`pivot · ${KIND_META[kind].label}`}
          title={v}
          subtitle={`${applicable.length} services match this target type. Click any service to inspect — no API call is made from BeyondArch.`}
          metrics={[
            { label: "Categories",  value: Array.from(new Set(applicable.map((t) => t.cat))).length, tone: "primary" },
            { label: "Reputation",  value: applicable.filter((t) => t.cat === "Reputation").length, tone: "warning" },
            { label: "Exposure",    value: applicable.filter((t) => t.cat === "Exposure").length,   tone: "primary" },
            { label: "Other",       value: applicable.filter((t) => !["Reputation","Exposure"].includes(t.cat)).length },
          ]}
        />
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

      <SectionBar id="OT" label="Output · external pivots" meta={`${applicable.length} matching · ${cats.length} categories`} />
      <div className="grid gap-3 lg:grid-cols-2">
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
                      <div className={"group flex items-start justify-between gap-2 rounded border border-border/60 bg-background/30 px-2.5 py-1.5 transition-all " + (enabled ? "hover:-translate-y-px hover:border-primary/50 hover:bg-primary/5" : "opacity-50")}>
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
                            <div className="truncate text-mono text-[10px] text-muted-foreground">{t.tagline}</div>
                          </div>
                        </button>
                        {!supported && ready && (
                          <span className="mt-0.5 rounded border border-border/60 bg-background/60 px-1 py-px text-mono text-[9px] uppercase tracking-widest text-muted-foreground">n/a</span>
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

      <SectionBar id="CL" label="Output · local CLI snippets" meta={`tuned for ${KIND_META[kind].label}`} />
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
        <ul className="divide-y divide-border/40 overflow-hidden rounded border border-border/60 bg-background/40">
          {cli.map((line, i) => (
            <li key={i} className="group grid grid-cols-[auto_1fr_auto] items-center gap-2 px-2 py-1.5">
              <span className="rounded border border-border/60 bg-background/70 px-1 py-px text-mono text-[9px] uppercase tracking-widest text-muted-foreground">
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

      {ready && (
        <Panel icon={Sparkles} title="Send target to" meta="continue the investigation">
          <div className="grid gap-1.5 sm:grid-cols-2 lg:grid-cols-3">
            {[
              { label: "Safe URL Analyzer", to: "/url",       icon: Globe2,   kind: "url",    when: kind === "domain" || kind === "raw" },
              { label: "Phishing Analyzer", to: "/phishing",  icon: Send,     kind: "email",  when: kind === "email" },
              { label: "Recon & Exposure",  to: "/recon",     icon: Network,  kind: "domain", when: kind === "domain" || kind === "ipv4" },
              { label: "Nmap Runner",       to: "/nmap",      icon: Terminal, kind: "ipv4",   when: kind === "ipv4" || kind === "domain" },
              { label: "Detection",         to: "/detection", icon: ShieldAlert, kind: kind, when: true },
              { label: "Case Builder",      to: "/case",      icon: Database, kind: kind,     when: true },
            ].filter((t) => t.when).map((t) => (
              <button
                key={t.to}
                onClick={() => { sendArtifact({ kind: t.kind as string, value: v, source: "/osint" }); window.location.assign(t.to); }}
                className="group flex items-center justify-between gap-2 rounded border border-border/60 bg-background/40 px-2.5 py-1.5 text-left transition-all hover:-translate-y-px hover:border-primary/50 hover:bg-primary/5"
              >
                <span className="flex min-w-0 items-center gap-2">
                  <t.icon className="h-3.5 w-3.5 text-muted-foreground group-hover:text-primary" />
                  <span className="truncate text-mono text-[11.5px] text-foreground/90 group-hover:text-primary">{t.label}</span>
                </span>
                <ArrowRight className="h-3.5 w-3.5 text-muted-foreground group-hover:text-primary group-hover:translate-x-0.5 transition" />
              </button>
            ))}
          </div>
        </Panel>
      )}

      <SendToRow targets={[
        { label: "Recon & Exposure", to: "/recon", icon: Globe2 },
        { label: "Nmap Runner", to: "/nmap", icon: Terminal },
        { label: "Detection", to: "/detection", icon: ArrowRight },
        { label: "Logs & Alerts", to: "/logs", icon: Database },
      ]} />
    </PageShell>
  );

  function TargetChip({ value, pinned, onPick, onPin }: { value: string; pinned: boolean; onPick: (v: string) => void; onPin: (v: string) => void }) {
    const k = classify(value);
    const Ico = KIND_META[k].icon;
    return (
      <span className="group inline-flex items-center gap-1 rounded border border-border/60 bg-background/40 pl-1.5 pr-0.5 py-0.5 text-mono text-[11px] hover:border-primary/50">
        <Ico className="h-3 w-3 text-muted-foreground" />
        <button onClick={() => onPick(value)} className="truncate max-w-[18ch] text-foreground/90 group-hover:text-primary" title={value}>{value}</button>
        <button onClick={() => onPin(value)} className="rounded p-0.5 text-muted-foreground hover:text-primary" title={pinned ? "unpin" : "pin"}>
          {pinned ? <Pin className="h-3 w-3" /> : <PinOff className="h-3 w-3" />}
        </button>
      </span>
    );
  }
}
