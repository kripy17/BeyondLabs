import { createFileRoute } from "@tanstack/react-router";
import { useEffect, useMemo, useState } from "react";
import { PageShell } from "@/components/PageShell";
import { Chip, SendToRow } from "@/components/soc";
import { Empty } from "@/components/output";
import { Search, Copy, Check, ChevronLeft, ChevronRight, Database } from "lucide-react";
import { toast } from "sonner";
import { pushTimelineEvent } from "@/lib/timeline";
import { useLocker } from "@/lib/locker";

export const Route = createFileRoute("/cve")({ component: CvePage });

type CveEntry = {
  id: string;
  description: string;
  cvss: number;
  epss: number;
  kev: boolean;
  exploit: { metasploit: boolean; nuclei: boolean; exploitDb: boolean };
  vendor: string;
  published: string;
  affected: string;
};

const CVE_DB: CveEntry[] = [
  { id: "CVE-2024-6387", description: "OpenSSH regreSSHion — remote unauthenticated code execution in sshd", cvss: 9.8, epss: 0.97, kev: true, exploit: { metasploit: true, nuclei: true, exploitDb: true }, vendor: "OpenSSH", published: "2024-07-01", affected: "OpenSSH 8.5p1-9.8p1" },
  { id: "CVE-2024-3094", description: "XZ Utils backdoor — supply chain compromise with RCE payload", cvss: 10.0, epss: 0.99, kev: true, exploit: { metasploit: false, nuclei: true, exploitDb: true }, vendor: "XZ Utils", published: "2024-03-29", affected: "XZ Utils 5.6.0, 5.6.1" },
  { id: "CVE-2024-21626", description: "runc container escape via leaked file descriptor", cvss: 8.6, epss: 0.85, kev: true, exploit: { metasploit: false, nuclei: true, exploitDb: true }, vendor: "runc", published: "2024-01-31", affected: "runc <1.1.12" },
  { id: "CVE-2023-44487", description: "HTTP/2 Rapid Reset Attack — DDoS via stream cancellation", cvss: 7.5, epss: 0.91, kev: true, exploit: { metasploit: false, nuclei: false, exploitDb: true }, vendor: "HTTP/2", published: "2023-10-10", affected: "Multiple implementations" },
  { id: "CVE-2023-34362", description: "MOVEit Transfer SQL injection leading to RCE", cvss: 9.1, epss: 0.98, kev: true, exploit: { metasploit: false, nuclei: true, exploitDb: true }, vendor: "Progress", published: "2023-06-09", affected: "MOVEit Transfer 2020.0-2023.0" },
  { id: "CVE-2023-35078", description: "Ivanti EPMM authentication bypass", cvss: 9.8, epss: 0.95, kev: true, exploit: { metasploit: false, nuclei: true, exploitDb: true }, vendor: "Ivanti", published: "2023-07-23", affected: "EPMM 11.10-11.12" },
  { id: "CVE-2024-27198", description: "JetBrains TeamCity authentication bypass", cvss: 9.8, epss: 0.96, kev: true, exploit: { metasploit: true, nuclei: true, exploitDb: true }, vendor: "JetBrains", published: "2024-03-04", affected: "TeamCity <2023.11.4" },
  { id: "CVE-2024-1709", description: "ConnectWise ScreenConnect authentication bypass", cvss: 9.8, epss: 0.94, kev: true, exploit: { metasploit: true, nuclei: true, exploitDb: true }, vendor: "ConnectWise", published: "2024-02-19", affected: "ScreenConnect 23.9.7-23.9.11" },
  { id: "CVE-2024-24919", description: "Check Point Security Gateway information disclosure", cvss: 8.6, epss: 0.82, kev: true, exploit: { metasploit: false, nuclei: true, exploitDb: true }, vendor: "Check Point", published: "2024-05-28", affected: "Security Gateway R81.20" },
  { id: "CVE-2023-46805", description: "Ivanti ICS authentication bypass chain", cvss: 9.0, epss: 0.93, kev: true, exploit: { metasploit: false, nuclei: true, exploitDb: true }, vendor: "Ivanti", published: "2024-01-10", affected: "ICS 9.x, 22.x" },
  { id: "CVE-2024-4577", description: "PHP CGI argument injection on Windows", cvss: 9.8, epss: 0.88, kev: true, exploit: { metasploit: true, nuclei: true, exploitDb: true }, vendor: "PHP", published: "2024-06-06", affected: "PHP 5.x-8.3 on Windows" },
  { id: "CVE-2024-38077", description: "Windows DCOM RCE with LDAP query", cvss: 9.0, epss: 0.65, kev: false, exploit: { metasploit: false, nuclei: false, exploitDb: true }, vendor: "Microsoft", published: "2024-07-09", affected: "Windows Server 2012-2022" },
  { id: "CVE-2024-21338", description: "Windows Kernel AppLocker bypass", cvss: 7.8, epss: 0.45, kev: false, exploit: { metasploit: false, nuclei: false, exploitDb: false }, vendor: "Microsoft", published: "2024-01-15", affected: "Windows 10-11, Server 2016-2022" },
  { id: "CVE-2024-4761", description: "Chrome V8 type confusion", cvss: 8.8, epss: 0.72, kev: true, exploit: { metasploit: false, nuclei: true, exploitDb: true }, vendor: "Google", published: "2024-05-15", affected: "Chrome <125.0.6422.60" },
  { id: "CVE-2023-46604", description: "Apache ActiveMQ RCE via serialization", cvss: 10.0, epss: 0.97, kev: true, exploit: { metasploit: true, nuclei: true, exploitDb: true }, vendor: "Apache", published: "2023-10-27", affected: "ActiveMQ <5.15.16, <5.16.7, <5.17.6, <5.18.3" },
  { id: "CVE-2023-38408", description: "OpenSSH PKCS#11 provider remote code execution", cvss: 8.1, epss: 0.55, kev: false, exploit: { metasploit: false, nuclei: false, exploitDb: true }, vendor: "OpenSSH", published: "2023-07-19", affected: "OpenSSH 9.3p1-9.3p2" },
  { id: "CVE-2024-27956", description: "WordPress Automatic Plugin SQL injection", cvss: 9.8, epss: 0.89, kev: true, exploit: { metasploit: true, nuclei: true, exploitDb: true }, vendor: "WordPress", published: "2024-03-14", affected: "WP Automatic <3.95.0" },
  { id: "CVE-2024-26234", description: "ProxyNotShell-style Proxy Server RCE", cvss: 9.0, epss: 0.75, kev: false, exploit: { metasploit: false, nuclei: false, exploitDb: true }, vendor: "Microsoft", published: "2024-03-05", affected: "Windows Proxy Server 2019-2022" },
  { id: "CVE-2024-21413", description: "Microsoft Outlook remote code execution via moniker link", cvss: 8.8, epss: 0.78, kev: true, exploit: { metasploit: false, nuclei: false, exploitDb: true }, vendor: "Microsoft", published: "2024-02-13", affected: "Outlook 2016-2021, Office 365" },
  { id: "CVE-2024-20656", description: "Windows Kerberos RCE via PAC", cvss: 9.0, epss: 0.58, kev: false, exploit: { metasploit: false, nuclei: false, exploitDb: false }, vendor: "Microsoft", published: "2024-01-09", affected: "Windows Server 2008-2022" },
  { id: "CVE-2023-22527", description: "Atlassian Confluence template injection RCE", cvss: 10.0, epss: 0.96, kev: true, exploit: { metasploit: true, nuclei: true, exploitDb: true }, vendor: "Atlassian", published: "2024-01-16", affected: "Confluence 8.5.0-8.5.3" },
  { id: "CVE-2024-0204", description: "GoAnywhere MFT authentication bypass", cvss: 9.8, epss: 0.92, kev: true, exploit: { metasploit: false, nuclei: true, exploitDb: true }, vendor: "F5", published: "2024-01-22", affected: "GoAnywhere MFT 7.x" },
  { id: "CVE-2024-23897", description: "Jenkins CLI arbitrary file read", cvss: 7.5, epss: 0.87, kev: true, exploit: { metasploit: true, nuclei: true, exploitDb: true }, vendor: "Jenkins", published: "2024-01-24", affected: "Jenkins <2.442, LTS <2.426.3" },
  { id: "CVE-2024-1504", description: "D-Link DIR-823G command injection", cvss: 9.8, epss: 0.63, kev: false, exploit: { metasploit: false, nuclei: true, exploitDb: true }, vendor: "D-Link", published: "2024-04-01", affected: "DIR-823G firmware <1.02" },
  { id: "CVE-2023-50164", description: "Apache Struts file upload RCE", cvss: 9.8, epss: 0.90, kev: true, exploit: { metasploit: true, nuclei: true, exploitDb: true }, vendor: "Apache", published: "2023-12-07", affected: "Struts 2.0.0-2.5.32, 6.0.0-6.3.0" },
  { id: "CVE-2024-0036", description: "Android Pixel battery metric disclosure", cvss: 5.5, epss: 0.15, kev: false, exploit: { metasploit: false, nuclei: false, exploitDb: false }, vendor: "Google", published: "2024-03-05", affected: "Android 14 Pixel <2024-03-05" },
  { id: "CVE-2024-29824", description: "Telerik UI Report Server authentication bypass", cvss: 9.8, epss: 0.71, kev: false, exploit: { metasploit: false, nuclei: true, exploitDb: true }, vendor: "Progress", published: "2024-04-15", affected: "Report Server 3.0.0-3.8.0" },
  { id: "CVE-2024-28255", description: "Microsoft Defender SmartScreen bypass", cvss: 5.4, epss: 0.52, kev: true, exploit: { metasploit: false, nuclei: false, exploitDb: true }, vendor: "Microsoft", published: "2024-03-12", affected: "Windows Defender 2024-02" },
  { id: "CVE-2024-21416", description: "Windows TCP/IP remote denial of service", cvss: 7.5, epss: 0.35, kev: false, exploit: { metasploit: false, nuclei: false, exploitDb: false }, vendor: "Microsoft", published: "2024-02-13", affected: "Windows 10-11, Server 2016-2022" },
  { id: "CVE-2024-27316", description: "Apache HTTP Server HTTP/2 denial of service", cvss: 7.5, epss: 0.28, kev: false, exploit: { metasploit: false, nuclei: false, exploitDb: false }, vendor: "Apache", published: "2024-04-04", affected: "httpd 2.4.55-2.4.58" },
];

function cvssColor(c: number): string {
  if (c >= 9) return "text-red-400";
  if (c >= 7) return "text-orange-400";
  if (c >= 4) return "text-yellow-400";
  return "text-green-400";
}

function cvssBg(c: number): string {
  if (c >= 9) return "bg-red-500/20 border-red-500/40";
  if (c >= 7) return "bg-orange-500/20 border-orange-500/40";
  if (c >= 4) return "bg-yellow-500/20 border-yellow-500/40";
  return "bg-green-500/20 border-green-500/40";
}

const PAGE_SIZE = 10;

function CvePage() {
  const locker = useLocker();
  const [query, setQuery] = useState("");
  const [selectedVendor, setSelectedVendor] = useState<string | null>(null);
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [sortBy, setSortBy] = useState<"cvss" | "epss" | "published">("cvss");
  const [page, setPage] = useState(0);
  const [copiedId, setCopiedId] = useState("");

  useEffect(() => {
    function handleKey(e: KeyboardEvent) {
      if (e.key === "Escape") { setQuery(""); setSelectedVendor(null); setSeverityFilter("all"); }
    }
    window.addEventListener("keydown", handleKey);
    return () => window.removeEventListener("keydown", handleKey);
  }, []);

  const vendors = useMemo(() => Array.from(new Set(CVE_DB.map((c) => c.vendor))).sort(), []);

  const filtered = useMemo(() => {
    let results = CVE_DB;
    if (query.trim()) {
      const q = query.toLowerCase();
      results = results.filter((c) => c.id.toLowerCase().includes(q) || c.description.toLowerCase().includes(q) || c.vendor.toLowerCase().includes(q));
    }
    if (selectedVendor) results = results.filter((c) => c.vendor === selectedVendor);
    if (severityFilter === "critical") results = results.filter((c) => c.cvss >= 9);
    else if (severityFilter === "high") results = results.filter((c) => c.cvss >= 7 && c.cvss < 9);
    else if (severityFilter === "medium") results = results.filter((c) => c.cvss >= 4 && c.cvss < 7);
    else if (severityFilter === "low") results = results.filter((c) => c.cvss < 4);

    results.sort((a, b) => {
      if (sortBy === "cvss") return b.cvss - a.cvss;
      if (sortBy === "epss") return b.epss - a.epss;
      return new Date(b.published).getTime() - new Date(a.published).getTime();
    });
    return results;
  }, [query, selectedVendor, severityFilter, sortBy]);

  const totalPages = Math.ceil(filtered.length / PAGE_SIZE);
  const paged = useMemo(() => filtered.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE), [filtered, page]);

  useEffect(() => { setPage(0); }, [query, selectedVendor, severityFilter, sortBy]);

  const stats = useMemo(() => ({
    total: CVE_DB.length,
    filtered: filtered.length,
    critical: filtered.filter((c) => c.cvss >= 9).length,
    kev: filtered.filter((c) => c.kev).length,
    exploitable: filtered.filter((c) => c.exploit.metasploit || c.exploit.nuclei || c.exploit.exploitDb).length,
  }), [filtered]);

  useEffect(() => {
    if (query || selectedVendor || severityFilter !== "all") pushTimelineEvent({ source: "cve", verb: "searched", detail: query || `filter: ${severityFilter}${selectedVendor ? ` vendor:${selectedVendor}` : ""}`, result: `${filtered.length} results` });
  }, [filtered]);

  return (
    <PageShell
      eyebrow="TOOLS / CVE"
      title="CVE Database"
      description="CVE lookup with EPSS + KEV badges, exploit availability, severity filter, and vendor filtering."
      crumbs={[{ label: "Tools" }, { label: "CVE" }]}
      meta={[
        { label: "showing", value: String(stats.filtered), tone: "primary" },
        { label: "critical", value: String(stats.critical), tone: "destructive" },
        { label: "kev", value: String(stats.kev), tone: "warning" },
      ]}
    >
      <div className="flex flex-wrap items-center gap-2 mb-3">
        <div className="relative flex-1 min-w-[200px] max-w-sm">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
          <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search CVE ID, description, or vendor…" className="w-full rounded border border-border bg-background/60 py-1.5 pl-8 pr-3 font-mono text-sm text-foreground outline-none placeholder:text-muted-foreground/60 focus:border-primary/50" />
        </div>
        <div className="flex items-center gap-1">
          {(["all", "critical", "high", "medium", "low"] as const).map((s) => (
            <button key={s} onClick={() => setSeverityFilter(s === "all" ? "all" : s)}
              className={"rounded border px-2 py-1 text-mono text-[10px] uppercase tracking-widest " + (severityFilter === s ? "border-primary bg-primary/15 text-primary" : "border-border text-muted-foreground hover:text-foreground")}>
              {s === "critical" ? "9+" : s === "high" ? "7-8.9" : s === "medium" ? "4-6.9" : s === "low" ? "<4" : "all"}
            </button>
          ))}
        </div>
        <select value={selectedVendor || ""} onChange={(e) => setSelectedVendor(e.target.value || null)} className="rounded border border-border bg-background/60 px-2 py-1.5 font-mono text-sm text-foreground outline-none focus:border-primary/50">
          <option value="">All vendors</option>
          {vendors.map((v) => <option key={v} value={v}>{v}</option>)}
        </select>
        <select value={sortBy} onChange={(e) => setSortBy(e.target.value as "cvss" | "epss" | "published")} className="rounded border border-border bg-background/60 px-2 py-1.5 font-mono text-sm text-foreground outline-none focus:border-primary/50">
          <option value="cvss">Sort: CVSS</option>
          <option value="epss">Sort: EPSS</option>
          <option value="published">Sort: Date</option>
        </select>
      </div>

      <div className="flex items-center gap-3 px-1 mb-2 text-mono text-[10px] text-muted-foreground">
        <span>{stats.filtered} of {stats.total} CVEs</span>
        <span className="text-border/60">·</span>
        <span className="text-destructive">{stats.critical} critical</span>
        <span className="text-border/60">·</span>
        <span className="text-warning">{stats.kev} KEV</span>
        <span className="text-border/60">·</span>
        <span>{stats.exploitable} with exploits</span>
      </div>

      <div className="space-y-2">
        {paged.map((cve) => (
          <div key={cve.id} className="rounded-lg border border-border/60 bg-card/40 p-4 transition-colors hover:border-primary/30">
            <div className="flex items-start justify-between gap-4">
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="font-mono text-sm font-bold text-primary">{cve.id}</span>
                  <button onClick={() => { locker.add({ value: cve.id, type: "cve", source: "/cve" }); toast("Added CVE to locker"); }}
                    className="grid h-5 w-5 place-items-center rounded text-muted-foreground hover:text-primary opacity-0 group-hover:opacity-100 transition-opacity" title="Add to locker">
                    <Database className="h-3 w-3" />
                  </button>
                  <button onClick={() => { navigator.clipboard.writeText(cve.id); setCopiedId(cve.id); setTimeout(() => setCopiedId(""), 1200); }}
                    className="grid h-5 w-5 place-items-center rounded text-muted-foreground hover:text-primary opacity-0 group-hover:opacity-100 transition-opacity"
                    title="Copy CVE ID">
                    {copiedId === cve.id ? <Check className="h-3 w-3 text-success" /> : <Copy className="h-3 w-3" />}
                  </button>
                  <Chip tone={cve.kev ? "destructive" : "default"}>{cve.kev ? "KEV" : "Known"}</Chip>
                  {cve.exploit.metasploit && <Chip tone="destructive">Metasploit</Chip>}
                  {cve.exploit.nuclei && <Chip tone="warning">Nuclei</Chip>}
                  {cve.exploit.exploitDb && <Chip tone="primary">EDB</Chip>}
                </div>
                <div className="mt-1 text-sm text-foreground/80">{cve.description}</div>
                <div className="mt-1.5 flex flex-wrap items-center gap-3 font-mono text-[11px] text-muted-foreground">
                  <span>{cve.vendor}</span>
                  <span>{cve.published}</span>
                  <span>{cve.affected}</span>
                </div>
              </div>
              <div className="flex flex-col items-end gap-2 shrink-0">
                <div className={`rounded-md border px-3 py-1 text-center ${cvssBg(cve.cvss)}`}>
                  <div className={`font-mono text-lg font-bold ${cvssColor(cve.cvss)}`}>{cve.cvss.toFixed(1)}</div>
                  <div className="font-mono text-[9px] uppercase tracking-widest text-muted-foreground">CVSS</div>
                </div>
                <div className="w-28">
                  <div className="flex items-center justify-between font-mono text-[9px] text-muted-foreground mb-0.5">
                    <span>EPSS</span><span>{(cve.epss * 100).toFixed(0)}%</span>
                  </div>
                  <div className="h-1.5 w-full rounded-full bg-border/50">
                    <div className={`h-1.5 rounded-full ${cve.epss >= 0.9 ? "bg-red-500" : cve.epss >= 0.7 ? "bg-orange-500" : cve.epss >= 0.4 ? "bg-yellow-500" : "bg-green-500"}`} style={{ width: `${cve.epss * 100}%` }} />
                  </div>
                </div>
              </div>
            </div>
          </div>
        ))}
        {filtered.length === 0 && <Empty icon={Search} title="No CVEs found" hint="Try a different search term, severity, or clear vendor filter." />}
      </div>

      {totalPages > 1 && (
        <div className="flex items-center justify-center gap-2 mt-4">
          <button onClick={() => setPage((p) => Math.max(0, p - 1))} disabled={page === 0}
            className="inline-flex items-center gap-1 rounded border border-border px-2 py-1 text-mono text-[10px] uppercase text-muted-foreground hover:text-foreground disabled:opacity-30">
            <ChevronLeft className="h-3 w-3" /> Prev
          </button>
          <span className="text-mono text-[11px] text-muted-foreground">
            Page {page + 1} of {totalPages}
          </span>
          <button onClick={() => setPage((p) => Math.min(totalPages - 1, p + 1))} disabled={page >= totalPages - 1}
            className="inline-flex items-center gap-1 rounded border border-border px-2 py-1 text-mono text-[10px] uppercase text-muted-foreground hover:text-foreground disabled:opacity-30">
            Next <ChevronRight className="h-3 w-3" />
          </button>
        </div>
      )}

      {filtered.length > 0 && stats.filtered > 0 && (
        <div className="mt-4">
          <SendToRow targets={[
            { label: "Detection Editor", to: "/detection", icon: Search },
            { label: "Case Notebook", to: "/case", icon: Database },
          ]} />
        </div>
      )}
    </PageShell>
  );
}
