import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { useEffect, useMemo, useRef, useState, useCallback } from "react";
import { useMutation } from "@tanstack/react-query";
import { PageShell } from "@/components/PageShell";
import { IntakeCard, SendToRow, SectionBar, Panel, Chip } from "@/components/soc";
import { StatusBar, ResultBanner, EvidenceCard } from "@/components/output";
import {
  Zap, Terminal, ArrowRight, Mail, Link2,
  FileWarning, Activity, Globe, Hash, Crosshair, Network, Copy, Check,
  Sparkles, FileText, Workflow, AlertTriangle, ShieldAlert, Key, Download,
  Scan, Loader2,
} from "lucide-react";
import { SUSPICIOUS_TLDS, SHORTENERS, refang, defang, entropy, scanSecrets } from "@/lib/ioc-patterns";
import { useLocker, type LockerItem } from "@/lib/locker";
import { IocChip } from "@/components/IocChip";
import { copyText } from "@/lib/copy";
import { AttachButton } from "@/components/AttachButton";
import { CopyAsDropdown } from "@/components/CopyAsDropdown";
import { usePanelNav } from "@/lib/usePanelNav";
import { sendToCase } from "@/lib/handoff";
import { useRecentInputs } from "@/lib/use-recent-inputs";
import { analyzeFullEmail } from "@/api/phishing";
import { passiveRecon } from "@/api/recon";
import { pushTimelineEvent } from "@/lib/timeline";
import { mapMitre } from "@/api/detection";
import { toast } from "sonner";
import {
  SAMPLES, IOC_KIND_MAP, RX, RX_MAC, RX_B64, KIND_META,
  autoDetectInputType, collectSignals, scanCmdLines, collectMitre,
  genMarkdownExport, genJsonExport,
} from "@/data/parser";

export const Route = createFileRoute("/parser")({ component: ParserPage });

function ParserPage() {
  const [input, setInput] = useState("");
  const [tab, setTab] = useState<string>("ALL");
  const [focusedKind, setFocusedKind] = useState<string | null>(null);
  const [defanged, setDefanged] = useState(true);
  const [copied, setCopied] = useState<string>("");
  const [deepScanError, setDeepScanError] = useState<string | null>(null);
  const { items: recentItems, push: pushRecent, clear: clearRecent } = useRecentInputs("parser");
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
    onError: (e) => { setDeepScanError(`Deep scan failed: ${(e as Error).message}`); },
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
    const signals = collectSignals(t, iocs);
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

  useEffect(() => {
    if (!input.trim()) return;
    const timer = setTimeout(() => pushRecent(input), 2000);
    return () => clearTimeout(timer);
  }, [input, pushRecent]);

  const copy = (k: string, txt: string) => { try { copyText(txt); } catch {/* noop */} setCopied(k); setTimeout(() => setCopied(""), 1200); };

  const kinds = useMemo(() => result ? Object.entries(result.iocs).filter(([, v]) => v.length) : [], [result]);
  const visible = useMemo(() => result ? (tab === "ALL" ? kinds : kinds.filter(([k]) => k === tab)) : [], [result, tab, kinds]);
  const transform = defanged ? defang : refang;

  const flatIocs = useMemo(() => {
    return visible.flatMap(([kind, items]) =>
      (items as string[]).map((value) => ({ value, kind }))
    );
  }, [visible]);

  const navigate = useNavigate();
  const { selected: selectedIoc } = usePanelNav(flatIocs, {
    onCopy: (item) => {
      copyText(transform(item.value));
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

  const handleClear = useCallback(() => {
    setInput("");
    deepScanMutation.reset();
    setFocusedKind(null);
    toast("Cleared");
  }, [deepScanMutation]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") handleClear();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [handleClear]);

  const handleDeepScan = useCallback(() => {
    if (!result) return;
    setDeepScanError(null);
    deepScanMutation.mutate({
      inputText: input.trim(),
      hasDomains,
      hasIps,
      hasEmails,
    });
  }, [result, input, hasDomains, hasIps, hasEmails, deepScanMutation]);

  const OSINT_TOOLS_PER_KIND: Record<string, { label: string; url: (v: string) => string }[]> = {
    URL: [
      { label: "VirusTotal", url: (v) => `https://www.virustotal.com/gui/search/${encodeURIComponent(v)}` },
      { label: "urlscan.io", url: (v) => `https://urlscan.io/search/#${encodeURIComponent(v)}` },
    ],
    Domain: [
      { label: "VirusTotal", url: (v) => `https://www.virustotal.com/gui/domain/${encodeURIComponent(v)}` },
      { label: "crt.sh", url: (v) => `https://crt.sh/?q=${encodeURIComponent(v)}` },
      { label: "Shodan", url: (v) => `https://www.shodan.io/search?query=${encodeURIComponent(v)}` },
      { label: "SecurityTrails", url: (v) => `https://securitytrails.com/list/apex_domain/${encodeURIComponent(v)}` },
      { label: "ViewDNS", url: (v) => `https://viewdns.info/reverseip/?host=${encodeURIComponent(v)}` },
      { label: "DNSDumpster", url: (v) => `https://dnsdumpster.com/domain/${encodeURIComponent(v)}` },
      { label: "BuiltWith", url: (v) => `https://builtwith.com/${encodeURIComponent(v)}` },
      { label: "WhoisXML", url: (v) => `https://whois.whoisxmlapi.com/lookup?domain=${encodeURIComponent(v)}` },
      { label: "Pulsedive", url: (v) => `https://pulsedive.com/indicator/?query=${encodeURIComponent(v)}` },
      { label: "Talos", url: (v) => `https://talosintelligence.com/reputation_center/lookup?search=${encodeURIComponent(v)}` },
      { label: "Wayback", url: (v) => `https://web.archive.org/web/*/${encodeURIComponent(v)}` },
    ],
    IPv4: [
      { label: "VirusTotal", url: (v) => `https://www.virustotal.com/gui/ip-address/${encodeURIComponent(v)}` },
      { label: "AbuseIPDB", url: (v) => `https://www.abuseipdb.com/check/${encodeURIComponent(v)}` },
      { label: "Shodan", url: (v) => `https://www.shodan.io/host/${encodeURIComponent(v)}` },
      { label: "GreyNoise", url: (v) => `https://viz.greynoise.io/ip/${encodeURIComponent(v)}` },
      { label: "Censys", url: (v) => `https://search.censys.io/search?q=${encodeURIComponent(v)}` },
      { label: "LeakIX", url: (v) => `https://leakix.net/search?q=${encodeURIComponent(v)}` },
    ],
    MD5: [
      { label: "VirusTotal", url: (v) => `https://www.virustotal.com/gui/search/${encodeURIComponent(v)}` },
      { label: "AlienVault OTX", url: (v) => `https://otx.alienvault.com/browse/global/pulses?q=${encodeURIComponent(v)}` },
    ],
    SHA256: [
      { label: "VirusTotal", url: (v) => `https://www.virustotal.com/gui/search/${encodeURIComponent(v)}` },
      { label: "AlienVault OTX", url: (v) => `https://otx.alienvault.com/browse/global/pulses?q=${encodeURIComponent(v)}` },
    ],
    Email: [
      { label: "Have I Been Pwned", url: (v) => `https://haveibeenpwned.com/account/${encodeURIComponent(v)}` },
      { label: "DeHashed", url: (v) => `https://dehashed.com/search?query=${encodeURIComponent(v)}` },
      { label: "Hunter.io", url: (v) => `https://hunter.io/search/${encodeURIComponent(v)}` },
    ],
  };

  function iocOsintTools() {
    const groups: { kind: string; tools: { label: string; url: string }[] }[] = [];
    for (const [kind, items] of Object.entries(result?.iocs ?? {})) {
      const lookups = OSINT_TOOLS_PER_KIND[kind];
      if (lookups && items.length > 0) {
        const val = items[0] as string;
        groups.push({ kind, tools: lookups.map((t) => ({ label: t.label, url: t.url(val) })) });
      }
    }
    return groups;
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
          { key: "sysmon", label: "Sysmon EVTX", hint: "Event ID 1 process creation" },
        ]}
        onLoadSample={(k) => setInput(SAMPLES[k].text)}
        onFile={(txt) => setInput(txt)}
        run={{ label: "parse", icon: Zap, hint: "⌘↵", onClick: () => { /* auto-parsed */ }, disabled: !input.trim() }}
      />

      {recentItems.length > 0 && (
        <div className="flex flex-wrap items-center gap-1.5 rounded border border-border/50 bg-card/30 px-2.5 py-1.5">
          <span className="text-mono ba-text-3xs uppercase tracking-widest text-muted-foreground/70">recent</span>
          {recentItems.slice(0, 8).map((item, i) => (
            <button key={i} onClick={() => { setInput(item); pushRecent(item); }}
              className="max-w-[160px] truncate rounded border border-border/40 bg-background/40 px-1.5 py-0.5 text-mono ba-text-2xs text-muted-foreground transition-colors hover:border-primary/40 hover:text-primary"
              title={item}
            >{item.slice(0, 40)}{item.length > 40 ? "…" : ""}</button>
          ))}
          {recentItems.length > 8 && <span className="text-mono ba-text-3xs text-muted-foreground/50">+{recentItems.length - 8} more</span>}
          <button onClick={clearRecent} className="ml-auto text-mono ba-text-3xs uppercase tracking-widest text-muted-foreground/50 hover:text-destructive">clear</button>
        </div>
      )}

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
          <div className="pointer-events-none select-none">
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
          </div>

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

          {/* Suggested next steps — universal intake routing */}
          {(hasDomains || hasIps || hasEmails || result?.iocs.URL.length > 0 || result?.iocs.MD5.length > 0 || result?.iocs.SHA256.length > 0) && (
            <Panel title="Suggested next steps" icon={ArrowRight} meta="smart routing">
              <div className="flex flex-wrap gap-2">
                {hasIps && (
                  <Link to="/recon" className="inline-flex items-center gap-2 rounded-md border border-info/40 bg-info/10 px-3 py-2 text-mono text-[11px] uppercase tracking-widest text-info transition-colors hover:bg-info/20">
                    <Network className="h-3.5 w-3.5" /> Recon <span className="opacity-70">({result.iocs.IPv4.length} IP{result.iocs.IPv4.length === 1 ? "" : "s"})</span> <ArrowRight className="h-3 w-3" />
                  </Link>
                )}
                {hasDomains && (
                  <Link to="/recon" className="inline-flex items-center gap-2 rounded-md border border-info/40 bg-info/10 px-3 py-2 text-mono text-[11px] uppercase tracking-widest text-info transition-colors hover:bg-info/20">
                    <Globe className="h-3.5 w-3.5" /> Recon <span className="opacity-70">({result.iocs.Domain.length} domain{result.iocs.Domain.length === 1 ? "" : "s"})</span> <ArrowRight className="h-3 w-3" />
                  </Link>
                )}
                {result.iocs.URL.length > 0 && (
                  <Link to="/url" className="inline-flex items-center gap-2 rounded-md border border-warning/40 bg-warning/10 px-3 py-2 text-mono text-[11px] uppercase tracking-widest text-warning transition-colors hover:bg-warning/20">
                    <Link2 className="h-3.5 w-3.5" /> URL Analyzer <span className="opacity-70">({result.iocs.URL.length} URL{result.iocs.URL.length === 1 ? "" : "s"})</span> <ArrowRight className="h-3 w-3" />
                  </Link>
                )}
                {hasEmails && (
                  <Link to="/phishing" className="inline-flex items-center gap-2 rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-mono text-[11px] uppercase tracking-widest text-destructive transition-colors hover:bg-destructive/20">
                    <Mail className="h-3.5 w-3.5" /> Phishing Triage <span className="opacity-70">({result.iocs.Email.length} email{result.iocs.Email.length === 1 ? "" : "s"})</span> <ArrowRight className="h-3 w-3" />
                  </Link>
                )}
                {(result.iocs.MD5.length > 0 || result.iocs.SHA256.length > 0) && (
                  <Link to="/attachment" className="inline-flex items-center gap-2 rounded-md border border-accent/40 bg-accent/10 px-3 py-2 text-mono text-[11px] uppercase tracking-widest text-accent transition-colors hover:bg-accent/20">
                    <FileWarning className="h-3.5 w-3.5" /> Attachment Triage <span className="opacity-70">({result.iocs.MD5.length + result.iocs.SHA256.length} hash{(result.iocs.MD5.length + result.iocs.SHA256.length) === 1 ? "" : "es"})</span> <ArrowRight className="h-3 w-3" />
                  </Link>
                )}
                {result.iocs.ATTACK.length > 0 && (
                  <Link to="/mitre" className="inline-flex items-center gap-2 rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-mono text-[11px] uppercase tracking-widest text-destructive transition-colors hover:bg-destructive/20">
                    <Crosshair className="h-3.5 w-3.5" /> MITRE <span className="opacity-70">({result.iocs.ATTACK.length} technique{result.iocs.ATTACK.length === 1 ? "" : "s"})</span> <ArrowRight className="h-3 w-3" />
                  </Link>
                )}
              </div>
            </Panel>
          )}

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
          <Panel title="Findings & Signals" icon={AlertTriangle} meta={`${result.signals.length} total`}>
            {result.signals.length === 0 ? (
              <p className="text-mono ba-text-sm text-muted-foreground">No signals generated for this artifact.</p>
            ) : (
              <div className="space-y-2">
                {result.signals.map((sig, i) => (
                  <EvidenceCard key={i} severity={sig.severity} title={sig.title} reason={sig.reason} action={sig.action} />
                ))}
              </div>
            )}
          </Panel>

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
                    <code className="min-w-0 flex-1 truncate text-mono ba-text-sm text-foreground/90">{defanged ? defang(u.value) : refang(u.value)}</code>
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

          {/* OSINT Tools per IOC kind */}
          {result && (() => {
            const groups = iocOsintTools();
            if (groups.length === 0) return null;
            return (
              <div className="space-y-3">
                {groups.map((g) => (
                  <Panel key={g.kind} title={`${g.kind} OSINT tools`} icon={Globe} priority="secondary" collapsible storageKey={`ba.panel.parser.osint.${g.kind}`}>
                    <div className="flex flex-wrap gap-1.5">
                      {g.tools.map((t) => (
                        <a key={t.label} href={t.url} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 rounded border border-divider-strong bg-card/40 px-2.5 py-1 text-mono ba-text-2xs uppercase tracking-widest text-muted-foreground transition-colors hover:border-primary/50 hover:text-primary">
                          <Globe className="h-3 w-3" /> {t.label}
                        </a>
                      ))}
                    </div>
                  </Panel>
                ))}
              </div>
            );
          })()}

          {/* Deep Scan Results */}
          {deepScanError && (
            <div className="rounded border border-destructive/40 bg-destructive/5 p-3 text-mono ba-text-sm text-destructive">{deepScanError}</div>
          )}
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
                          <div className="flex items-center gap-1 opacity-0 transition-opacity group-hover:opacity-100">
                            <CopyAsDropdown value={it} label={it} />
                            <button onClick={() => copy(it, transform(it))}>
                              {copied === it ? <Check className="h-3 w-3 text-success" /> : <Copy className="h-3 w-3 text-muted-foreground hover:text-foreground" />}
                            </button>
                          </div>
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
              <button onClick={() => { copyText(reportMd); setCopied("report"); setTimeout(() => setCopied(""), 1200); }} className="group inline-flex w-full items-center justify-center gap-2 rounded border border-primary/30 bg-primary/5 px-4 py-2 text-mono ba-text-2xs uppercase tracking-widest text-primary transition-all hover:bg-primary/15">
                {copied === "report" ? <Check className="h-3.5 w-3.5 text-success" /> : <Copy className="h-3.5 w-3.5" />} {copied === "report" ? "Copied" : "Copy Summary"}
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

    </PageShell>
  );
}

const tabBtn = (active: boolean) =>
  "rounded border px-2 py-0.5 text-mono ba-text-2xs uppercase tracking-widest transition-colors " +
  (active ? "border-primary/60 bg-primary/15 text-primary" : "border-divider-strong bg-card/40 text-muted-foreground hover:text-foreground");

const toggleBtn = (active: boolean) =>
  "rounded border px-1.5 py-0.5 text-mono ba-text-2xs uppercase tracking-widest " +
  (active ? "border-primary/60 bg-primary/15 text-primary" : "border-divider-strong bg-card/40 text-muted-foreground hover:text-foreground");
