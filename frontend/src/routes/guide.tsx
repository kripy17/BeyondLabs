import { createFileRoute, Link } from "@tanstack/react-router";
import { useMemo, useState, useEffect, useCallback } from "react";
import { PageShell } from "@/components/PageShell";
import { SectionBar, Panel, Chip, SendToRow } from "@/components/soc";
import { VerdictBanner, MetricGrid } from "@/components/output";
import { useLocker, guessType } from "@/lib/locker";
import { toast } from "sonner";
import { BookOpen, ArrowRight, Database, ShieldAlert, Search, CircleCheck as CheckCircle2, Circle, TriangleAlert as AlertTriangle, ShieldOff, Mail, MailWarning as FileWarning, Activity, KeyRound, ListFilter as Filter, ShieldCheck, ShieldX, Globe2, User, Package, Lock, Radio, Hash, Download } from "lucide-react";

export const Route = createFileRoute("/guide")({ component: GuidePage });

type Severity = "P1" | "P2" | "P3";
type Playbook = {
  id: string; title: string; severity: Severity; eta: string; category: string;
  icon: typeof Mail; summary: string; attack: string[];
  steps: { text: string; pivot?: { to: string; label: string } }[];
};

const PLAYBOOKS: Playbook[] = [
  { id: "phish", title: "Phishing email reported", severity: "P2", eta: "15m", category: "Email", icon: Mail,
    summary: "User-reported lure: confirm verdict, scrub URLs, contain account exposure, document.",
    attack: ["T1566", "T1204"],
    steps: [
      { text: "Pause any new inbox rules and forwarders on the reporting account.", pivot: { to: "/logs", label: "Logs" } },
      { text: "Pull full message source including raw headers." },
      { text: "Run through Phishing Triage; capture verdict, reasons, and IOCs.", pivot: { to: "/phishing", label: "Phishing" } },
      { text: "Refang and review embedded URLs in Safe URL Analyzer.", pivot: { to: "/url", label: "URL" } },
      { text: "Pivot sender / reply-to / URL across mail and proxy logs.", pivot: { to: "/logs", label: "Logs" } },
      { text: "Notify the user; reset credentials and revoke sessions if they interacted." },
      { text: "Document the finding chain in the Case Notebook.", pivot: { to: "/case", label: "Case" } },
    ],
  },
  { id: "ssh", title: "SSH brute-force surge", severity: "P3", eta: "10m", category: "Network", icon: KeyRound,
    summary: "Spike in failed SSH attempts — confirm source, block, audit successes.",
    attack: ["T1110"],
    steps: [
      { text: "Confirm the source IP, geo, and target account list.", pivot: { to: "/osint", label: "OSINT" } },
      { text: "Block source at perimeter or fail2ban." },
      { text: "Audit for any successful logins from the same source over the last 30 days.", pivot: { to: "/siem", label: "SIEM" } },
      { text: "Reset credentials and revoke keys for any matched accounts." },
      { text: "Add a detection lead under T1110 if missing.", pivot: { to: "/detection", label: "Detection" } },
    ],
  },
  { id: "macro", title: "Macro-enabled attachment delivered", severity: "P2", eta: "20m", category: "Email", icon: FileWarning,
    summary: "Quarantine, hash, and contain before any user contact.",
    attack: ["T1204", "T1059"],
    steps: [
      { text: "Quarantine the message at the mail gateway." },
      { text: "Hash the file and pivot in Attachment Triage.", pivot: { to: "/attachment", label: "Attachment" } },
      { text: "Confirm no execution via EDR process trees.", pivot: { to: "/logs", label: "Logs" } },
      { text: "Block hash, sender, and URL across the stack." },
      { text: "Update macro policy if exposure is recurring." },
    ],
  },
  { id: "c2", title: "Outbound C2-like beacon", severity: "P1", eta: "30m", category: "Network", icon: Activity,
    summary: "Suspected command-and-control: cut traffic, snapshot, escalate.",
    attack: ["T1071", "T1571"],
    steps: [
      { text: "Capture host, user, destination, port, and beacon cadence." },
      { text: "Sever outbound traffic at proxy or firewall." },
      { text: "Snapshot endpoint memory if your EDR supports it." },
      { text: "Cross-check destination in Recon & Exposure.", pivot: { to: "/recon", label: "Recon" } },
      { text: "Open an incident review with the on-call lead.", pivot: { to: "/case", label: "Case" } },
    ],
  },
  { id: "ransomware-detected", title: "Ransomware detected on endpoint", severity: "P1", eta: "15 min", category: "Malware", icon: AlertTriangle, summary: "Endpoint alert: file encryption in progress, ransom note dropped, known ransomware family signature matched.", attack: ["T1486", "T1490", "T1070.004", "T1059.001"], steps: [
    { text: "Isolate affected host from network (disable NIC / VLAN quarantine)", pivot: { label: "Case Notebook", to: "/case" } },
    { text: "Capture memory image and relevant forensic artifacts before reboot" },
    { text: "Identify ransomware strain via ransom note content or extension pattern", pivot: { label: "Chef — Hash & triage", to: "/chef" } },
    { text: "Check lateral movement: scan SMB, RDP, WinRM connections from affected host", pivot: { label: "SIEM", to: "/siem" } },
    { text: "Check for volume shadow copy deletion (vssadmin, wmic)", pivot: { label: "Terminal — query", to: "/terminal" } },
    { text: "Collect sample: hash + submit to sandbox / threat intel", pivot: { label: "Attachment Analysis", to: "/attachment" } },
    { text: "Determine encryption scope: network shares, mapped drives, cloud sync folders" },
    { text: "Reset domain account passwords for affected user(s)" },
    { text: "Escalate to incident response lead with initial findings summary" },
  ] },
  { id: "data-exfil-suspected", title: "Data exfiltration via DNS tunneling", severity: "P1", eta: "20 min", category: "Network", icon: ShieldAlert, summary: "DNS query volume anomaly: high TXT record counts, queries to suspicious domains, base64-encoded subdomains.", attack: ["T1572", "T1048.003", "T1071.004", "T1560.001"], steps: [
    { text: "Review DNS logs: top queried domains, query volume spikes, unusual record types", pivot: { label: "SIEM", to: "/siem" } },
    { text: "Inspect suspicious subdomain labels for encoded data patterns (base64, hex)", pivot: { label: "Chef — Base64 decode", to: "/chef" } },
    { text: "Check source IP for associated C2 connections or beacon patterns" },
    { text: "Correlate with outbound traffic logs to same destination during the window", pivot: { label: "Nmap", to: "/nmap" } },
    { text: "Block DNS queries to identified malicious domains via firewall / DNS sinkhole", pivot: { label: "Terminal", to: "/terminal" } },
    { text: "Extract IOCs: domains, IPs, timestamps → locker", pivot: { label: "IOC Locker", to: "/detection" } },
    { text: "Create detection rule for identified DNS tunneling pattern", pivot: { label: "Detection", to: "/detection" } },
    { text: "Escalate: note exfil method, estimated volume, destination" },
  ] },
  { id: "lateral-movement-smb", title: "Lateral movement via SMB/WMI", severity: "P1", eta: "20 min", category: "Network", icon: ShieldX, summary: "Event log 4624: network logon from a sensitive host, followed by service creation (4697) on target systems.", attack: ["T1021.002", "T1021.006", "T1047", "T1570", "T1078"], steps: [
    { text: "Identify source host and target hosts from Event ID 4624 (Logon Type 3) correlation", pivot: { label: "SIEM", to: "/siem" } },
    { text: "Check for service install events (4697) or scheduled task creation on targets" },
    { text: "Review administrative share access (ADMIN$, IPC$, C$) on target systems" },
    { text: "Search for tools dropped on targets: PsExec, PowerShell, batch scripts", pivot: { label: "Terminal — find", to: "/terminal" } },
    { text: "Check source host for credential dumping tools or LSASS access events" },
    { text: "Create detection rule for lateral movement patterns", pivot: { label: "Detection", to: "/detection" } },
    { text: "Reset compromised account(s) and review privileged access" },
    { text: "Document full lateral movement chain for incident timeline" },
  ] },
  { id: "web-shell-detected", title: "Web shell uploaded to web server", severity: "P1", eta: "15 min", category: "Web", icon: Globe2, summary: "Web server alert: suspicious file upload (.asp, .jsp, .php) followed by process execution from web directory.", attack: ["T1505.003", "T1190", "T1106", "T1059", "T1036"], steps: [
    { text: "Isolate web server from network if active command execution is confirmed" },
    { text: "Identify uploaded file: path, name, creation time, owner", pivot: { label: "SIEM", to: "/siem" } },
    { text: "Analyze web shell code for persistence mechanisms, exfil functions, C2 endpoints", pivot: { label: "Chef — decode", to: "/chef" } },
    { text: "Check web server access logs for initial compromise vector (LFI, RFI, SQLi)", pivot: { label: "Investigation", to: "/parser" } },
    { text: "Review post-exploitation activity: lateral movement, data access, privilege escalation" },
    { text: "Hash the web shell file → check reputation", pivot: { label: "Attachment Analysis", to: "/attachment" } },
    { text: "Add web shell paths to WAF block rules / file integrity monitoring" },
    { text: "Escalate: note entry vector, web shell capabilities, dwell time" },
  ] },
  { id: "unauth-access-saas", title: "Unauthorized access detected — SaaS account", severity: "P2", eta: "10 min", category: "Identity", icon: User, summary: "Sign-in from unusual location/device: impossible travel alert, legacy auth protocol used, MFA prompt denied.", attack: ["T1078.004", "T1525", "T1110", "T1556.006", "T1563"], steps: [
    { text: "Verify alert with user: was this login expected? Contact via out-of-band channel" },
    { text: "Force sign-out all sessions for the affected account" },
    { text: "Revoke application-specific passwords and OAuth tokens" },
    { text: "Enable conditional access policy: require MFA + trusted location" },
    { text: "Check for mailbox rules created around the time of unauthorized access", pivot: { label: "SIEM", to: "/siem" } },
    { text: "Review audit logs for data download, forwarding, or sharing events" },
    { text: "Extract source IP → check reputation", pivot: { label: "Recon", to: "/recon" } },
    { text: "Document: access method, data exposed, remediation actions taken" },
  ] },
  { id: "supply-chain-compromise", title: "Supply chain compromise — dependency warning", severity: "P2", eta: "30 min", category: "Development", icon: Package, summary: "Alert: a direct or transitive dependency used in the software supply chain has a reported CVE with active exploitation.", attack: ["T1195.001", "T1195.002", "T1195.003", "T1526"], steps: [
    { text: "Identify the exact package, version, and CVE(s) from the advisory" },
    { text: "Map dependency usage: which products, environments, and pipelines depend on it" },
    { text: "Check if vulnerable function paths are actually called in your codebase" },
    { text: "Determine if the dependency (or its hash) appears in any deployed artifact", pivot: { label: "Attachment hash check", to: "/attachment" } },
    { text: "If active exploitation is confirmed: patch, rebuild, redeploy affected artifacts" },
    { text: "Add CVE to tracking: note impact scope and remediation timeline in case", pivot: { label: "Case Notebook", to: "/case" } },
    { text: "Re-evaluate dependency pinning, SBOM generation, and vulnerability scanning cadence" },
  ] },
  { id: "malicious-email-campaign", title: "Mass phishing campaign targeting org", severity: "P2", eta: "25 min", category: "Email", icon: Mail, summary: "Multiple users reporting similar phishing emails; threat intel feed confirms active campaign targeting the sector.", attack: ["T1566.001", "T1566.002", "T1598", "T1534"], steps: [
    { text: "Collect representative samples from 2-3 recipients (full .eml with headers)", pivot: { label: "Phishing Analysis", to: "/phishing" } },
    { text: "Extract campaign IOCs: sender domain, reply-to, links, attachments, hashes", pivot: { label: "Investigation", to: "/parser" } },
    { text: "Check if links point to known malicious infrastructure", pivot: { label: "URL Analysis", to: "/url" } },
    { text: "Hash attachments and check reputation", pivot: { label: "Attachment Analysis", to: "/attachment" } },
    { text: "Search SIEM for other recipients who may have received similar emails", pivot: { label: "SIEM", to: "/siem" } },
    { text: "Block sender domain, IPs, and URL patterns at email gateway" },
    { text: "Draft user-facing warning: what to look for, what to do if clicked" },
    { text: "Add campaign indicators to IOC Locker for ongoing monitoring", pivot: { label: "Detection", to: "/detection" } },
  ] },
  { id: "vpn-brute-force", title: "VPN credential brute force detected", severity: "P2", eta: "15 min", category: "Network", icon: Lock, summary: "Multiple failed authentication attempts against VPN gateway from diverse IPs, targeting valid and invalid usernames.", attack: ["T1110.001", "T1110.003", "T1110.004", "T1078"], steps: [
    { text: "Identify source IPs: aggregate failed auth attempts, check for distributed pattern", pivot: { label: "SIEM", to: "/siem" } },
    { text: "Check targeted usernames: are they valid employees or spray patterns?" },
    { text: "Temporarily block offending IP ranges at perimeter firewall (geo-block if applicable)" },
    { text: "Review successful logins from same IPs within the window" },
    { text: "Enable CAPTCHA or account lockout on VPN gateway if not already configured" },
    { text: "Check for successful authentication after brute force window (password spray success)", pivot: { label: "Case Notebook", to: "/case" } },
    { text: "Alert users whose accounts may have been compromised → force password reset" },
  ] },
  { id: "insider-data-download", title: "Insider: mass data download alert", severity: "P2", eta: "20 min", category: "Insider", icon: User, summary: "DLP alert: user downloaded >5 GB from internal document repository outside business hours.", attack: ["T1078", "T1530", "T1213", "T1567"], steps: [
    { text: "Verify with manager/supervisor: is this expected behavior for the user's role?" },
    { text: "Review download pattern: specific projects vs broad repository scrape", pivot: { label: "SIEM", to: "/siem" } },
    { text: "Check for associated activities: printing, USB mounting, external uploads" },
    { text: "Identify destination: download to managed device vs personal cloud storage" },
    { text: "If unauthorized: disable account, secure workstation, begin HR/legal escalation" },
    { text: "Document data types accessed, volume, and timeframe for incident record", pivot: { label: "Case Notebook", to: "/case" } },
  ] },
  { id: "c2-beacon-variant", title: "C2 beacon variant — periodic outbound", severity: "P1", eta: "25 min", category: "Network", icon: Radio, summary: "Outbound connection with regular interval (30-60s), JA3 hash matches known C2 framework, low-and-slow data transfer.", attack: ["T1071.001", "T1573", "T1571", "T1095", "T1041"], steps: [
    { text: "Capture PCAP: confirm beacon pattern (interval, jitter, packet size)", pivot: { label: "Terminal — tcpdump", to: "/terminal" } },
    { text: "Extract destination IPs and domains → check reputation", pivot: { label: "Recon", to: "/recon" } },
    { text: "Correlate with process creation events on the source host" },
    { text: "Identify parent process: Office app, browser, service, or script host" },
    { text: "Isolate: block destination at firewall, quarantine host" },
    { text: "Create Snort/Suricata rule for the beacon signature", pivot: { label: "Detection", to: "/detection" } },
    { text: "Extract IOCs for threat intel sharing", pivot: { label: "IOC Locker", to: "/detection" } },
    { text: "Escalate: note framework if identified, dwell time, data volume exfiltrated" },
  ] },
];

const SEV_COLOR: Record<Severity, "destructive" | "warning" | "default"> = { P1: "destructive", P2: "warning", P3: "default" };

function GuidePage() {
  const locker = useLocker();
  const [activeId, setActiveId] = useState<string>(PLAYBOOKS[0].id);
  const [query, setQuery] = useState("");
  const [sev, setSev] = useState<Severity | "ALL">("ALL");
  const [done, setDone] = useState<Record<string, Set<number>>>(() => {
    try {
      const raw = localStorage.getItem("ba.guide.done.v1");
      if (!raw) return {};
      const parsed = JSON.parse(raw) as Record<string, number[]>;
      return Object.fromEntries(
        Object.entries(parsed).map(([k, v]) => [k, new Set(v)])
      );
    } catch { return {}; }
  });

  useEffect(() => {
    const serialized = Object.fromEntries(
      Object.entries(done).map(([k, v]) => [k, [...v]])
    );
    localStorage.setItem("ba.guide.done.v1", JSON.stringify(serialized));
  }, [done]);

  const list = useMemo(() => PLAYBOOKS.filter((p) =>
    (sev === "ALL" || p.severity === sev) &&
    (!query.trim() || (p.title + " " + p.summary + " " + p.category).toLowerCase().includes(query.toLowerCase()))
  ), [query, sev]);

  const active = PLAYBOOKS.find((p) => p.id === activeId) ?? PLAYBOOKS[0];
  const activeDone = done[active.id] ?? new Set<number>();
  const progress = Math.round((activeDone.size / active.steps.length) * 100);

  const toggle = (i: number) => {
    setDone((d) => {
      const next = new Set(d[active.id] ?? []);
      next.has(i) ? next.delete(i) : next.add(i);
      return { ...d, [active.id]: next };
    });
  };

  const counts: Record<Severity, number> = { P1: 0, P2: 0, P3: 0 };
  PLAYBOOKS.forEach((p) => { counts[p.severity] += 1; });

  const handleClear = useCallback(() => {
    setQuery("");
    setSev("ALL");
    toast("Cleared");
  }, []);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") handleClear();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [handleClear]);

  const handleExtractIocs = () => {
    const text = PLAYBOOKS.map((p) => [p.title, p.summary, ...p.attack, ...p.steps.map((s) => s.text)].join(" ")).join(" ");
    const ipRx = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
    const domainRx = /[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+/gi;
    const ips = [...new Set(text.match(ipRx) ?? [])];
    const rawDomains = [...new Set(text.match(domainRx) ?? [])];
    const domains = rawDomains.filter((d) => !ips.includes(d) && guessType(d) === "domain");
    ips.forEach((v) => locker.add({ value: v, type: "ipv4", source: "/guide" }));
    domains.forEach((v) => locker.add({ value: v, type: "domain", source: "/guide" }));
    toast(`Extracted ${ips.length + domains.length} IOCs to locker`);
  };

  function handleExport() {
    const md = [
      `# SOC Playbook: ${active.title}`,
      "",
      `**Severity:** ${active.severity} &middot; **Category:** ${active.category} &middot; **ETA:** ${active.eta}`,
      `**MITRE:** ${active.attack.join(", ")}`,
      "",
      `**Summary:** ${active.summary}`,
      "",
      `## Steps (${activeDone.size}/${active.steps.length} done)`,
      "",
      ...active.steps.map((s, i) => `**${i + 1}.** ${s.text}${s.pivot ? ` &rarr; ${s.pivot.label}` : ""}`),
      "",
    ].join("\n");
    const blob = new Blob([md], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a"); a.href = url; a.download = `guide-${active.id}-${Date.now()}.md`; a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <PageShell
      eyebrow="DETECTION / GUIDE"
      title="SOC Playbook Guide"
      description="Bite-sized response playbooks — pick a scenario, work the steps, pivot into the right tool."
      crumbs={[{ label: "Detection" }, { label: "Guide" }]}
      actions={
        <div className="flex items-center gap-1.5">
          <button onClick={handleExport} className="inline-flex items-center gap-1 rounded border border-border px-2 py-0.5 text-mono ba-text-2xs uppercase text-muted-foreground hover:text-foreground">
            <Download className="h-3 w-3" /> md
          </button>
          <button onClick={handleExtractIocs} className="inline-flex items-center gap-1.5 rounded-md border border-primary/30 bg-primary/10 px-2.5 py-1.5 text-mono ba-text-2xs uppercase tracking-widest text-primary transition-colors hover:bg-primary/20" title="Extract IOCs from playbook content">
            <Hash className="h-3.5 w-3.5" /> extract iocs
          </button>
        </div>
      }
    >
      {/* Verdict Banner */}
      <VerdictBanner
        verdict={`${PLAYBOOKS.length} bundled playbooks`}
        tone="success"
        icon={ShieldCheck}
        details={[
          `${counts.P1} P1 critical · ${counts.P2} P2 high · ${counts.P3} P3 medium`,
          "Linear, actionable, and wired into the rest of the workbench",
        ]}
      />

      {/* Metrics */}
      <MetricGrid
        columns={4}
        metrics={[
          { label: "Total", value: PLAYBOOKS.length, tone: "primary", icon: BookOpen },
          { label: "P1 critical", value: counts.P1, tone: "destructive" },
          { label: "P2 high", value: counts.P2, tone: "warning" },
          { label: "P3 medium", value: counts.P3 },
        ]}
      />

      <SectionBar id="IN" label="Filter · pick a scenario" meta={`${list.length} match${list.length === 1 ? "" : "es"}`} />

      <div className="grid gap-3 grid-cols-[18rem_1fr]">
        {/* Left rail: search + severity filter + playbook list */}
        <div className="space-y-2">
          <Panel>
            <div className="flex items-center gap-2 rounded border border-divider-strong bg-background/60 px-2">
              <Search className="h-3.5 w-3.5 text-muted-foreground" />
              <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="search playbooks…" className="w-full bg-transparent py-1.5 text-mono ba-text-sm outline-none placeholder:text-muted-foreground/60" />
            </div>
            <div className="mt-2 flex items-center gap-1">
              <Filter className="h-3 w-3 text-muted-foreground" />
              {(["ALL", "P1", "P2", "P3"] as const).map((s) => (
                <button key={s} onClick={() => setSev(s)} className={"rounded border px-1.5 py-0.5 text-mono ba-text-2xs uppercase tracking-widest " + (sev === s ? "border-primary bg-primary/15 text-primary" : "border-divider-strong text-muted-foreground hover:text-foreground")}>{s.toLowerCase()}</button>
              ))}
            </div>
          </Panel>

          <Panel bodyClassName="p-1.5">
            <ul className="space-y-1">
              {list.map((p) => {
                const Icon = p.icon;
                const isActive = p.id === active.id;
                const pDone = done[p.id]?.size ?? 0;
                return (
                  <li key={p.id}>
                    <button
                      onClick={() => setActiveId(p.id)}
                      className={
                        "group flex w-full items-start gap-2 rounded-md border px-2 py-2 text-left transition-colors " +
                        (isActive ? "border-primary/50 bg-primary/10" : "border-transparent hover:border-border hover:bg-card/60")
                      }
                    >
                      <Icon className={"mt-0.5 h-3.5 w-3.5 shrink-0 " + (isActive ? "text-primary" : "text-muted-foreground")} />
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center justify-between gap-2">
                          <span className="truncate text-mono ba-text-sm uppercase tracking-widest text-foreground/90">{p.title}</span>
                          <Chip tone={SEV_COLOR[p.severity]}>{p.severity}</Chip>
                        </div>
                        <div className="mt-0.5 flex items-center gap-2 text-mono ba-text-2xs text-muted-foreground">
                          <span>{p.category}</span>
                          <span>·</span>
                          <span>~{p.eta}</span>
                          <span>·</span>
                          <span>{pDone}/{p.steps.length}</span>
                        </div>
                      </div>
                    </button>
                  </li>
                );
              })}
              {list.length === 0 && (
                <li className="px-3 py-6 text-center text-mono text-[10.5px] uppercase tracking-widest text-muted-foreground">no playbooks match</li>
              )}
            </ul>
          </Panel>
        </div>

        {/* Right: active playbook detail */}
        <div className="space-y-3">
          <Panel
            title={active.title}
            icon={BookOpen}
            meta={`${active.category} · ~${active.eta}`}
            actions={<Chip tone={SEV_COLOR[active.severity]}>{active.severity}</Chip>}
          >
            <p className="mb-3 ba-text-base leading-relaxed text-foreground/80">{active.summary}</p>

            {active.attack.length > 0 && (
              <div className="mb-3 flex flex-wrap items-center gap-1.5">
                <span className="text-mono text-[9.5px] uppercase tracking-widest text-muted-foreground">MITRE</span>
                {active.attack.map((id) => (
                  <Link key={id} to="/mitre"
                    className="inline-flex items-center gap-1 rounded border border-primary/40 bg-primary/10 px-1.5 py-0.5 text-mono ba-text-2xs uppercase tracking-widest text-primary hover:bg-primary/20"
                  >
                    {id}
                  </Link>
                ))}
              </div>
            )}

            <div className="mb-3 flex items-center gap-3">
              <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-border/40">
                <div className="h-full bg-primary transition-all" style={{ width: `${progress}%` }} />
              </div>
              <span className="text-mono ba-text-2xs uppercase tracking-widest text-muted-foreground">{activeDone.size}/{active.steps.length} done · {progress}%</span>
            </div>

            <ol className="space-y-1.5">
              {active.steps.map((s, i) => {
                const isDone = activeDone.has(i);
                return (
                  <li key={i} className={"group flex items-start gap-3 rounded border px-2.5 py-2 transition-colors " + (isDone ? "border-success/30 bg-success/5" : "border-border/50 bg-card/40 hover:border-primary/30")}>
                    <button onClick={() => toggle(i)} aria-label="toggle step" className="mt-0.5 shrink-0">
                      {isDone ? <CheckCircle2 className="h-4 w-4 text-success" /> : <Circle className="h-4 w-4 text-muted-foreground group-hover:text-primary" />}
                    </button>
                    <span className="mt-0.5 text-mono text-[10.5px] text-primary">{String(i + 1).padStart(2, "0")}</span>
                    <span className={"flex-1 ba-text-base leading-snug " + (isDone ? "text-muted-foreground line-through" : "text-foreground/90")}>{s.text}</span>
                    {s.pivot && (
                      <Link to={s.pivot.to} className="ml-2 inline-flex items-center gap-1 rounded border border-primary/40 bg-primary/10 px-1.5 py-0.5 text-mono ba-text-2xs uppercase tracking-widest text-primary opacity-80 hover:opacity-100">
                        {s.pivot.label} <ArrowRight className="h-3 w-3" />
                      </Link>
                    )}
                  </li>
                );
              })}
            </ol>
          </Panel>

          <div className="grid gap-3 grid-cols-2">
            <Panel title="Always" icon={CheckCircle2}>
              <ul className="space-y-1.5 ba-text-base text-foreground/85">
                <li className="flex items-start gap-2"><CheckCircle2 className="mt-0.5 h-3.5 w-3.5 shrink-0 text-success" /> Preserve evidence before remediation.</li>
                <li className="flex items-start gap-2"><CheckCircle2 className="mt-0.5 h-3.5 w-3.5 shrink-0 text-success" /> Log decisions in the Case Notebook with timestamps.</li>
                <li className="flex items-start gap-2"><CheckCircle2 className="mt-0.5 h-3.5 w-3.5 shrink-0 text-success" /> Pivot IOCs across at least two independent sources.</li>
              </ul>
            </Panel>
            <Panel title="Never" icon={ShieldOff}>
              <ul className="space-y-1.5 ba-text-base text-foreground/85">
                <li className="flex items-start gap-2"><AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-destructive" /> Open or detonate unknown files on your workstation.</li>
                <li className="flex items-start gap-2"><AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-destructive" /> Submit corporate samples to public sandboxes without approval.</li>
                <li className="flex items-start gap-2"><AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-destructive" /> Notify suspected insiders before evidence is preserved.</li>
              </ul>
            </Panel>
          </div>
        </div>
      </div>

      <SendToRow targets={[
        { label: "MITRE Coverage", to: "/mitre", icon: ArrowRight },
        { label: "Detection Editor", to: "/detection", icon: ShieldAlert },
        { label: "Case Notebook", to: "/case", icon: Database },
      ]} />
    </PageShell>
  );
}
