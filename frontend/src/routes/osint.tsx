import { createFileRoute } from "@tanstack/react-router";
import { useEffect, useMemo, useState } from "react";
import { PageShell } from "@/components/PageShell";
import { Panel, SectionBar, Chip, SendToRow } from "@/components/soc";
import { Empty, MetricGrid, TwoColumnOutput, KeyFields, CollapsibleSection } from "@/components/output";
import { useLocker } from "@/lib/locker";
import { pushTimelineEvent } from "@/lib/timeline";
import { copyText } from "@/lib/copy";
import { toast } from "sonner";
import {
  Search, Globe, Mail, User, Phone, Copy, Check, ExternalLink,
  ShieldAlert, Database, Server, Hash, AlertTriangle, BookMarked,
  Download, Link, AtSign, Fingerprint, Linkedin, Bug,
} from "lucide-react";

export const Route = createFileRoute("/osint")({ component: OsintPage });

type OsintTab = "email" | "username" | "domain" | "phone" | "paste";

interface BreachEntry {
  name: string; date: string; data_classes: string[]; description: string;
}

const BREACH_DB: BreachEntry[] = [
  { name: "HaveIBeenPwned (simulated)", date: "2024-06", data_classes: ["Emails", "Passwords"], description: "Simulated breach lookup — check haveibeenpwned.com for real results" },
  { name: "Collection #1", date: "2019-01", data_classes: ["Emails", "Passwords"], description: "87GB credential stuffing list" },
  { name: "LinkedIn", date: "2021-06", data_classes: ["Emails", "Passwords"], description: "700M records scraped" },
  { name: "Facebook", date: "2021-04", data_classes: ["Phone numbers", "Emails", "Names"], description: "533M records leaked" },
];

const EMAIL_FORMATS = [
  { label: "Domain", regex: /@[\w.-]+\.\w+$/ },
  { label: "Common pattern", regex: /^[a-zA-Z][\w.+-]+@/ },
];

const USERNAME_PLATFORMS = [
  { name: "GitHub", icon: Bug, url: (u: string) => `https://github.com/${encodeURIComponent(u)}` },
  { name: "X / Twitter", icon: AtSign, url: (u: string) => `https://x.com/${encodeURIComponent(u)}` },
  { name: "LinkedIn", icon: Linkedin, url: (u: string) => `https://www.linkedin.com/in/${encodeURIComponent(u)}` },
  { name: "Reddit", icon: Globe, url: (u: string) => `https://reddit.com/user/${encodeURIComponent(u)}` },
  { name: "HackerNews", icon: Bug, url: (u: string) => `https://news.ycombinator.com/user?id=${encodeURIComponent(u)}` },
  { name: "Keybase", icon: Hash, url: (u: string) => `https://keybase.io/${encodeURIComponent(u)}` },
  { name: "Instagram", icon: Globe, url: (u: string) => `https://instagram.com/${encodeURIComponent(u)}` },
  { name: "Telegram", icon: Globe, url: (u: string) => `https://t.me/${encodeURIComponent(u)}` },
];

const DOMAIN_QUERIES = [
  { label: "VirusTotal", url: (d: string) => `https://www.virustotal.com/gui/domain/${encodeURIComponent(d)}` },
  { label: "urlscan.io", url: (d: string) => `https://urlscan.io/search/#${encodeURIComponent(d)}` },
  { label: "crt.sh", url: (d: string) => `https://crt.sh/?q=%25.${encodeURIComponent(d)}` },
  { label: "SecurityTrails", url: (d: string) => `https://securitytrails.com/domain/${encodeURIComponent(d)}/dns` },
  { label: "AlienVault OTX", url: (d: string) => `https://otx.alienvault.com/indicator/domain/${encodeURIComponent(d)}` },
  { label: "Shodan", url: (d: string) => `https://www.shodan.io/search?query=${encodeURIComponent(d)}` },
  { label: "DomainTools", url: (d: string) => `https://whois.domaintools.com/${encodeURIComponent(d)}` },
  { label: "Wayback Machine", url: (d: string) => `https://web.archive.org/web/*/${d}` },
  { label: "Talos Intel", url: (d: string) => `https://talosintelligence.com/reputation_center/lookup?search=${encodeURIComponent(d)}` },
  { label: "Pulsedive", url: (d: string) => `https://pulsedive.com/indicator/?query=${encodeURIComponent(d)}` },
];

const PASTE_SITES = [
  { name: "Pastebin", url: (q: string) => `https://pastebin.com/search?q=${encodeURIComponent(q)}` },
  { name: "Ghostbin", url: (q: string) => `https://ghostbin.com/search?q=${encodeURIComponent(q)}` },
  { name: "Rentry", url: (q: string) => `https://rentry.co/search?q=${encodeURIComponent(q)}` },
  { name: "GitHub Gist", url: (q: string) => `https://gist.github.com/search?q=${encodeURIComponent(q)}` },
  { name: "Google dork", url: (q: string) => `https://www.google.com/search?q=site%3Apastebin.com+${encodeURIComponent(q)}` },
];

const TAB_CONFIG: { id: OsintTab; label: string; icon: typeof Search }[] = [
  { id: "email", label: "Email", icon: Mail },
  { id: "username", label: "Username", icon: User },
  { id: "domain", label: "Domain / IP", icon: Globe },
  { id: "phone", label: "Phone", icon: Phone },
  { id: "paste", label: "Paste / Leak Search", icon: Database },
];

function guessType(value: string): string {
  if (/^[\w.+-]+@[\w-]+\.[\w.-]+$/.test(value)) return "email";
  if (/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/.test(value)) return "ip";
  if (/^\+?\d{7,15}$/.test(value.trim())) return "phone";
  if (/^[a-fA-F0-9]{32}$/.test(value.trim()) || /^[a-fA-F0-9]{40}$/.test(value.trim()) || /^[a-fA-F0-9]{64}$/.test(value.trim())) return "hash";
  if (/\.[a-zA-Z]{2,}$/.test(value)) return "domain";
  return "unknown";
}

function OsintPage() {
  const locker = useLocker();
  const [tab, setTab] = useState<OsintTab>("email");
  const [searchInput, setSearchInput] = useState("");
  const [searched, setSearched] = useState(false);
  const [copied, setCopied] = useState("");

  useEffect(() => {
    function handleKey(e: KeyboardEvent) {
      if (e.key === "Escape") { setSearchInput(""); setSearched(false); }
    }
    window.addEventListener("keydown", handleKey);
    return () => window.removeEventListener("keydown", handleKey);
  }, []);

  const domain = useMemo(() => {
    if (tab !== "email" || !searchInput) return null;
    const m = searchInput.match(/@([\w.-]+\.\w+)$/);
    return m ? m[1].toLowerCase() : null;
  }, [tab, searchInput]);

  const breaches = useMemo(() => {
    if (!searchInput || tab !== "email") return [];
    const domainPart = searchInput.split("@")[1]?.toLowerCase();
    if (!domainPart) return BREACH_DB;
    return BREACH_DB.filter((b) => b.name.toLowerCase().includes(domainPart) || b.name.toLowerCase().includes(searchInput.split("@")[0].toLowerCase()));
  }, [searchInput, tab]);

  function handleSearch() {
    if (!searchInput.trim()) return;
    setSearched(true);
    pushTimelineEvent({ source: "osint", verb: "searched", detail: `${tab}: ${searchInput}`, result: `${breaches.length} finds` });
  }

  function addToLocker(value: string) {
    locker.add({ value, type: guessType(value) as any, source: "/osint" });
    toast("Added to locker");
  }

  return (
    <PageShell
      eyebrow="TOOLS / OSINT"
      title="OSINT Investigation"
      description="Open-source intelligence lookups — email, username, domain, phone, and paste/leak search with external pivot links."
      crumbs={[{ label: "Tools" }, { label: "OSINT" }]}
    >
      <div className="flex items-center gap-2 mb-4">
        {TAB_CONFIG.map((t) => (
          <button key={t.id} onClick={() => { setTab(t.id); setSearched(false); }}
            className={"rounded border px-2.5 py-1.5 text-mono ba-text-2xs uppercase tracking-widest transition-colors " + (tab === t.id ? "border-primary bg-primary/15 text-primary" : "border-border bg-card/40 text-muted-foreground hover:text-foreground")}>
            <t.icon className="h-3 w-3 inline mr-1" /> {t.label}
          </button>
        ))}
      </div>

      <Panel title={`${TAB_CONFIG.find((t) => t.id === tab)?.label} Lookup`} icon={Search}>
        <div className="flex items-center gap-2">
          <div className="relative flex-1">
            <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
            <input
              value={searchInput}
              onChange={(e) => setSearchInput(e.target.value)}
              onKeyDown={(e) => { if (e.key === "Enter") handleSearch(); }}
              placeholder={
                tab === "email" ? "user@example.com" :
                tab === "username" ? "johndoe" :
                tab === "domain" ? "example.com or 8.8.8.8" :
                tab === "phone" ? "+1-555-123-4567" :
                "search query for paste sites"
              }
              className="w-full rounded border border-border bg-background/60 py-2 pl-8 pr-3 font-mono text-sm text-foreground outline-none placeholder:text-muted-foreground/60 focus:border-primary/50"
            />
          </div>
          <button onClick={handleSearch} disabled={!searchInput.trim()}
            className="inline-flex items-center gap-1 rounded border border-primary/40 bg-primary/10 px-3 py-2 text-mono ba-text-2xs uppercase tracking-widest text-primary hover:bg-primary/20 disabled:opacity-40">
            Search
          </button>
        </div>

        {!searched && !searchInput && (
          <div className="mt-3 flex flex-wrap gap-2">
            {tab === "email" && ["admin@example.org", "user@gmail.com", "test@evil-host.ru"].map((s) => (
              <button key={s} onClick={() => { setSearchInput(s); }} className="rounded border border-border/50 bg-card/30 px-2 py-0.5 font-mono text-[10px] text-muted-foreground hover:text-foreground">{s}</button>
            ))}
            {tab === "username" && ["johndoe", "admin", "security_researcher"].map((s) => (
              <button key={s} onClick={() => { setSearchInput(s); }} className="rounded border border-border/50 bg-card/30 px-2 py-0.5 font-mono text-[10px] text-muted-foreground hover:text-foreground">{s}</button>
            ))}
            {tab === "domain" && ["example.com", "185.220.101.44", "evil-payload.ru"].map((s) => (
              <button key={s} onClick={() => { setSearchInput(s); }} className="rounded border border-border/50 bg-card/30 px-2 py-0.5 font-mono text-[10px] text-muted-foreground hover:text-foreground">{s}</button>
            ))}
            {tab === "phone" && ["+1-555-123-4567", "+44 20 7123 4567"].map((s) => (
              <button key={s} onClick={() => { setSearchInput(s); }} className="rounded border border-border/50 bg-card/30 px-2 py-0.5 font-mono text-[10px] text-muted-foreground hover:text-foreground">{s}</button>
            ))}
          </div>
        )}
      </Panel>

      {/* ── Email Results ── */}
      {searched && tab === "email" && (
        <div className="space-y-4 mt-4">
          <MetricGrid
            columns={3}
            metrics={[
              { label: "Domain", value: domain || "—", tone: domain ? "primary" : "muted" },
              { label: "Breach Matches", value: String(breaches.length), tone: breaches.length > 0 ? "destructive" : "success" },
              { label: "Type", value: "Email", tone: "info" },
            ]}
          />

          <TwoColumnOutput
            ratio="1:1"
            left={
              <Panel title="Domain Information" icon={Globe}>
                {domain ? (
                  <KeyFields items={[
                    { label: "Domain", value: domain },
                    { label: "Mail Exchangers", value: "Check via MX lookup" },
                    { label: "SPF / DMARC", value: "Use external tools below" },
                  ]} />
                ) : (
                  <p className="text-mono text-sm text-muted-foreground">Could not extract domain from email</p>
                )}
                <div className="mt-3 flex flex-wrap gap-1.5">
                  {domain && DOMAIN_QUERIES.slice(0, 4).map((q) => (
                    <a key={q.label} href={q.url(domain)} target="_blank" rel="noopener noreferrer"
                      className="inline-flex items-center gap-1 rounded border border-border/50 bg-card/30 px-2 py-0.5 font-mono text-[10px] text-muted-foreground hover:text-primary">
                      <ExternalLink className="h-2.5 w-2.5" /> {q.label}
                    </a>
                  ))}
                </div>
              </Panel>
            }
            right={
              <Panel title="Actions" icon={Send}>
                <div className="flex flex-col gap-2">
                  <button onClick={() => { addToLocker(searchInput); }}
                    className="inline-flex items-center gap-1.5 rounded border border-primary/40 bg-primary/10 px-2.5 py-1.5 text-mono ba-text-2xs uppercase tracking-widest text-primary hover:bg-primary/20">
                    <BookMarked className="h-3 w-3" /> Add to locker
                  </button>
                  <button onClick={() => { copyText(searchInput); setCopied("email"); setTimeout(() => setCopied(""), 1200); }}
                    className="inline-flex items-center gap-1.5 rounded border border-primary/40 bg-primary/10 px-2.5 py-1.5 text-mono ba-text-2xs uppercase tracking-widest text-primary hover:bg-primary/20">
                    {copied === "email" ? <><Check className="h-3 w-3 text-success" /> copied</> : <><Copy className="h-3 w-3" /> Copy email</>}
                  </button>
                </div>
              </Panel>
            }
          />

          <Panel title="Breach Database Lookup" icon={ShieldAlert} meta={`${breaches.length} entries`}>
            {breaches.length > 0 ? (
              <div className="divide-y divide-border/50">
                {breaches.map((b, i) => (
                  <div key={i} className="flex items-start gap-3 px-3 py-2.5 hover:bg-card/30">
                    <div className="min-w-0 flex-1">
                      <div className="font-mono text-sm text-foreground/90">{b.name}</div>
                      <div className="mt-0.5 text-[11px] text-muted-foreground">{b.description}</div>
                      <div className="mt-1 flex flex-wrap gap-1">
                        {b.data_classes.map((dc) => (
                          <Chip key={dc} tone="destructive" priority="low">{dc}</Chip>
                        ))}
                      </div>
                    </div>
                    <button onClick={() => { locker.add({ value: b.name, type: "text", source: "/osint" }); toast(`Added ${b.name} to locker`); }}
                      className="shrink-0 rounded border border-border/50 bg-card/40 px-1.5 py-0.5 text-mono ba-text-2xs uppercase text-muted-foreground hover:text-foreground"
                      title="Add to locker">+</button>
                    <span className="shrink-0 font-mono text-[10px] text-muted-foreground">{b.date}</span>
                  </div>
                ))}
              </div>
            ) : (
              <div className="py-4 text-center text-mono text-sm text-muted-foreground">No breach records found for this email</div>
            )}
          </Panel>

          <SectionBar id="EXT" label="External Enrichment Links" meta="open in new tab" />
          <div className="flex flex-wrap gap-2">
            <a href={`https://haveibeenpwned.com/account/${encodeURIComponent(searchInput)}`} target="_blank" rel="noopener noreferrer"
              className="inline-flex items-center gap-1.5 rounded border border-warning/40 bg-warning/10 px-3 py-2 text-mono ba-text-2xs uppercase tracking-widest text-warning hover:bg-warning/20">
              <ExternalLink className="h-3 w-3" /> HaveIBeenPwned
            </a>
            <a href={`https://www.dehashed.com/search?query=${encodeURIComponent(searchInput)}`} target="_blank" rel="noopener noreferrer"
              className="inline-flex items-center gap-1.5 rounded border border-primary/40 bg-primary/10 px-3 py-2 text-mono ba-text-2xs uppercase tracking-widest text-primary hover:bg-primary/20">
              <ExternalLink className="h-3 w-3" /> DeHashed
            </a>
            <a href={`https://emailrep.io/${encodeURIComponent(searchInput)}`} target="_blank" rel="noopener noreferrer"
              className="inline-flex items-center gap-1.5 rounded border border-primary/40 bg-primary/10 px-3 py-2 text-mono ba-text-2xs uppercase tracking-widest text-primary hover:bg-primary/20">
              <ExternalLink className="h-3 w-3" /> EmailRep
            </a>
            <a href={`https://www.google.com/search?q=${encodeURIComponent(searchInput)}`} target="_blank" rel="noopener noreferrer"
              className="inline-flex items-center gap-1.5 rounded border border-border px-3 py-2 text-mono ba-text-2xs uppercase tracking-widest text-muted-foreground hover:text-foreground">
              <ExternalLink className="h-3 w-3" /> Google search
            </a>
          </div>

          <SendToRow targets={[
            { label: "Recon", to: "/recon", icon: Globe },
            { label: "Detection Editor", to: "/detection", icon: ShieldAlert },
            { label: "Case Notebook", to: "/case", icon: Database },
          ]} />
        </div>
      )}

      {/* ── Username Results ── */}
      {searched && tab === "username" && (
        <div className="space-y-4 mt-4">
          <SectionBar id="SM" label="Social Media / Platform Profiles" meta={`${USERNAME_PLATFORMS.length} platforms`} />
          <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 gap-2">
            {USERNAME_PLATFORMS.map((p) => (
              <a key={p.name} href={p.url(searchInput)} target="_blank" rel="noopener noreferrer"
                className="flex items-center gap-2 rounded border border-border hover:border-primary/40 bg-card/40 px-3 py-2.5 hover:bg-card/60 transition-colors group">
                <p.icon className="h-4 w-4 shrink-0 text-muted-foreground group-hover:text-primary" />
                <div className="min-w-0">
                  <div className="font-mono text-sm text-foreground/90 truncate">{p.name}</div>
                  <div className="font-mono text-[10px] text-muted-foreground truncate">@{searchInput}</div>
                </div>
                <ExternalLink className="h-3 w-3 ml-auto shrink-0 text-muted-foreground" />
              </a>
            ))}
          </div>

          <div className="flex items-center gap-2">
            <button onClick={() => { addToLocker(searchInput); }}
              className="inline-flex items-center gap-1.5 rounded border border-primary/40 bg-primary/10 px-3 py-2 text-mono ba-text-2xs uppercase tracking-widest text-primary hover:bg-primary/20">
              <BookMarked className="h-3 w-3" /> Add to locker
            </button>
            <button onClick={() => { copyText(searchInput); toast("Copied username"); }}
              className="inline-flex items-center gap-1.5 rounded border border-primary/40 bg-primary/10 px-3 py-2 text-mono ba-text-2xs uppercase tracking-widest text-primary hover:bg-primary/20">
              <Copy className="h-3 w-3" /> Copy
            </button>
          </div>

          <SendToRow targets={[
            { label: "Case Notebook", to: "/case", icon: Database },
            { label: "Detection Editor", to: "/detection", icon: ShieldAlert },
          ]} />
        </div>
      )}

      {/* ── Domain Results ── */}
      {searched && tab === "domain" && (
        <div className="space-y-4 mt-4">
          <MetricGrid
            columns={3}
            metrics={[
              { label: "Query", value: searchInput, tone: "primary" },
              { label: "Type", value: guessType(searchInput) === "ip" ? "IPv4" : "Domain", tone: "info" },
              { label: "IOC Type", value: guessType(searchInput), tone: "accent" },
            ]}
          />

          <Panel title="Actions" icon={Send}>
            <div className="flex items-center gap-2">
              <button onClick={() => { addToLocker(searchInput); }}
                className="inline-flex items-center gap-1.5 rounded border border-primary/40 bg-primary/10 px-3 py-2 text-mono ba-text-2xs uppercase tracking-widest text-primary hover:bg-primary/20">
                <BookMarked className="h-3 w-3" /> Add to locker
              </button>
              <button onClick={() => { copyText(searchInput); toast("Copied"); }}
                className="inline-flex items-center gap-1.5 rounded border border-primary/40 bg-primary/10 px-3 py-2 text-mono ba-text-2xs uppercase tracking-widest text-primary hover:bg-primary/20">
                <Copy className="h-3 w-3" /> Copy
              </button>
              <button onClick={() => {
                const text = `${searchInput}\n\nOSINT sources:\n${DOMAIN_QUERIES.map((q) => `- ${q.url(searchInput)}`).join("\n")}`;
                const blob = new Blob([text], { type: "text/markdown" });
                const url = URL.createObjectURL(blob);
                const a = document.createElement("a");
                a.href = url; a.download = `osint-${searchInput.replace(/[^a-zA-Z0-9]/g, "_")}.md`;
                a.click(); URL.revokeObjectURL(url);
              }} className="inline-flex items-center gap-1.5 rounded border border-primary/40 bg-primary/10 px-3 py-2 text-mono ba-text-2xs uppercase tracking-widest text-primary hover:bg-primary/20">
                <Download className="h-3 w-3" /> Export report
              </button>
            </div>
          </Panel>

          <SectionBar id="EXT" label="External Enrichment Links" meta={`${DOMAIN_QUERIES.length} sources`} />
          <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-5 gap-2">
            {DOMAIN_QUERIES.map((q) => (
              <a key={q.label} href={q.url(searchInput)} target="_blank" rel="noopener noreferrer"
                className="flex items-center gap-1.5 rounded border border-border bg-card/40 px-2.5 py-2 font-mono text-[10px] uppercase tracking-widest text-muted-foreground hover:border-primary/40 hover:text-primary transition-colors">
                <ExternalLink className="h-3 w-3 shrink-0" /> {q.label}
              </a>
            ))}
          </div>

          <SendToRow targets={[
            { label: "Recon", to: "/recon", icon: Globe },
            { label: "URL Analyzer", to: "/url", icon: Link },
            { label: "Hash Lookup", to: "/hash-lookup", icon: Hash },
            { label: "Case Notebook", to: "/case", icon: Database },
          ]} />
        </div>
      )}

      {/* ── Phone Results ── */}
      {searched && tab === "phone" && (
        <div className="space-y-4 mt-4">
          <MetricGrid
            columns={3}
            metrics={[
              { label: "Phone", value: searchInput, tone: "primary" },
              { label: "Format", value: /^\+/.test(searchInput.trim()) ? "International" : "Domestic", tone: "info" },
              { label: "Digits", value: String(searchInput.replace(/\D/g, "").length), tone: "primary" },
            ]}
          />

          <Panel title="Actions" icon={Send}>
            <div className="flex items-center gap-2">
              <button onClick={() => { addToLocker(searchInput); }}
                className="inline-flex items-center gap-1.5 rounded border border-primary/40 bg-primary/10 px-3 py-2 text-mono ba-text-2xs uppercase tracking-widest text-primary hover:bg-primary/20">
                <BookMarked className="h-3 w-3" /> Add to locker
              </button>
              <button onClick={() => { copyText(searchInput); toast("Copied"); }}
                className="inline-flex items-center gap-1.5 rounded border border-primary/40 bg-primary/10 px-3 py-2 text-mono ba-text-2xs uppercase tracking-widest text-primary hover:bg-primary/20">
                <Copy className="h-3 w-3" /> Copy
              </button>
            </div>
          </Panel>

          <SectionBar id="EXT" label="External Lookup Tools" meta="open in new tab" />
          <div className="flex flex-wrap gap-2">
            {[
              { label: "Truecaller", url: `https://www.truecaller.com/search/${encodeURIComponent(searchInput)}` },
              { label: "Numverify", url: `https://numverify.com/phone/${encodeURIComponent(searchInput)}` },
              { label: "FreeCarrierLookup", url: `https://freecarrierlookup.com/?number=${encodeURIComponent(searchInput)}` },
              { label: "SpyDialer", url: `https://www.spydialer.com/default.aspx?search=${encodeURIComponent(searchInput)}` },
            ].map((t) => (
              <a key={t.label} href={t.url} target="_blank" rel="noopener noreferrer"
                className="inline-flex items-center gap-1.5 rounded border border-primary/40 bg-primary/10 px-3 py-2 text-mono ba-text-2xs uppercase tracking-widest text-primary hover:bg-primary/20">
                <ExternalLink className="h-3 w-3" /> {t.label}
              </a>
            ))}
          </div>

          <SendToRow targets={[
            { label: "Case Notebook", to: "/case", icon: Database },
          ]} />
        </div>
      )}

      {/* ── Paste / Leak Search Results ── */}
      {searched && tab === "paste" && (
        <div className="space-y-4 mt-4">
          <SectionBar id="PS" label="Paste Site Search" meta={`${PASTE_SITES.length} sources`} />
          <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-5 gap-2">
            {PASTE_SITES.map((p) => (
              <a key={p.name} href={p.url(searchInput)} target="_blank" rel="noopener noreferrer"
                className="flex items-center gap-1.5 rounded border border-border bg-card/40 px-2.5 py-2 font-mono text-[10px] uppercase tracking-widest text-muted-foreground hover:border-primary/40 hover:text-primary transition-colors">
                <ExternalLink className="h-3 w-3 shrink-0" /> {p.name}
              </a>
            ))}
          </div>

          <div className="flex items-center gap-2">
            <button onClick={() => { addToLocker(searchInput); }}
              className="inline-flex items-center gap-1.5 rounded border border-primary/40 bg-primary/10 px-3 py-2 text-mono ba-text-2xs uppercase tracking-widest text-primary hover:bg-primary/20">
              <BookMarked className="h-3 w-3" /> Add to locker
            </button>
            <button onClick={() => { copyText(searchInput); toast("Copied"); }}
              className="inline-flex items-center gap-1.5 rounded border border-primary/40 bg-primary/10 px-3 py-2 text-mono ba-text-2xs uppercase tracking-widest text-primary hover:bg-primary/20">
              <Copy className="h-3 w-3" /> Copy
            </button>
          </div>

          <SendToRow targets={[
            { label: "Case Notebook", to: "/case", icon: Database },
            { label: "Recon", to: "/recon", icon: Globe },
          ]} />
        </div>
      )}

      {/* ── Empty state ── */}
      {!searched && (
        <Empty
          icon={Globe}
          title="Start an OSINT investigation"
          hint="Pick a tab above, enter your target (email, username, domain/IP, phone, or search query), and press Search."
        />
      )}
    </PageShell>
  );
}
