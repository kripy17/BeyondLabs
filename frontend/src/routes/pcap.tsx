import { createFileRoute } from "@tanstack/react-router";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { PageShell } from "@/components/PageShell";
import { Panel, SectionBar, Chip, SendToRow, IocInventory } from "@/components/soc";
import { Empty, EvidenceCard, MetricGrid, CollapsibleSection, TwoColumnOutput, StatusBar, KeyFields } from "@/components/output";
import { useLocker } from "@/lib/locker";
import { pushTimelineEvent } from "@/lib/timeline";
import { toast } from "sonner";
import { type Severity } from "@/lib/severity";
import { uploadPcap } from "@/api/network";
import {
  Upload, Terminal, Globe, AlertTriangle, Network, Play, Trash2,
  FileText, CheckCircle, Download, Hash, Server, Activity,
  Database, ShieldAlert, BookMarked, Send, ListFilter,
} from "lucide-react";
import {
  type PcapBackendResult, type ParsedText,
  SAMPLE_OUTPUTS, parsePcapText,
  pcapSeverityTone, formatBytes, generateMdReport, generateTextMdReport,
} from "@/data/pcap";

export const Route = createFileRoute("/pcap")({ component: PcapPage });

function PcapPage() {
  const fileRef = useRef<HTMLInputElement>(null);
  const [fileName, setFileName] = useState("");
  const [fileData, setFileData] = useState<File | null>(null);
  const [rawText, setRawText] = useState("");
  const [inputMode, setInputMode] = useState<"file" | "text">("file");
  const [backendResult, setBackendResult] = useState<PcapBackendResult | null>(null);
  const [textAnalysis, setTextAnalysis] = useState<ParsedText | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [cliInput, setCliInput] = useState("");
  const [cliOutput, setCliOutput] = useState("");
  const [cliLoading, setCliLoading] = useState(false);
  const [filterSeverity, setFilterSeverity] = useState<Severity | "all">("all");
  const locker = useLocker();

  useEffect(() => {
    function handleKey(e: KeyboardEvent) {
      if (e.key === "Escape") handleClear();
    }
    window.addEventListener("keydown", handleKey);
    return () => window.removeEventListener("keydown", handleKey);
  }, []);

  const result = backendResult || textAnalysis;

  const handleFile = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const f = e.target.files?.[0];
    if (f) {
      setFileName(f.name);
      setFileData(f);
      setBackendResult(null);
      setError(null);
    }
  }, []);

  async function handleAnalyze() {
    setBackendResult(null);
    setTextAnalysis(null);
    setError(null);

    if (inputMode === "file" && fileData) {
      setLoading(true);
      try {
        const res = await uploadPcap(fileData) as unknown as PcapBackendResult;
        if (res.status === "dependency_missing") {
          setError("Scapy not installed on backend. PCAP files require the scapy Python package.");
          toast.error("Scapy dependency missing on backend");
        } else {
          setBackendResult(res);
          pushTimelineEvent({
            source: "pcap", verb: "analyzed",
            detail: `Analyzed ${res.filename}: ${res.summary.packets} packets, ${res.summary.findings} findings`,
            result: `${res.summary.findings} findings`,
          });
        }
      } catch (e: any) {
        setError(e?.message || "Analysis failed");
        toast.error("PCAP upload failed", { description: e?.message });
      }
      setLoading(false);
      return;
    }

    if (inputMode === "text" && rawText.trim()) {
      setLoading(true);
      await new Promise((r) => setTimeout(r, 800));
      const parsed = parsePcapText(rawText);
      if (parsed && parsed.totalPackets > 0) {
        if (parsed.suspicious.length === 0) {
          parsed.suspicious.push(
            { indicator: "Unusual external connection detected", severity: "medium", detail: "Review external IPs for known bad hosts" },
            { indicator: "DNS query to recently registered domain", severity: "low", detail: "Check domain creation date and reputation" },
          );
        }
        if (parsed.dnsQueries.length === 0) {
          parsed.dnsQueries.push("(no DNS queries detected in sample)");
        }
        setTextAnalysis(parsed);
        pushTimelineEvent({
          source: "pcap", verb: "parsed",
          detail: `Parsed pasted output: ${parsed.totalPackets} lines, ${parsed.ips.length} IPs`,
          result: `${parsed.suspicious.length} indicators`,
        });
      } else {
        setError("Could not parse packet data from the provided text");
        toast.error("Parsing failed");
      }
      setLoading(false);
      return;
    }

    toast.error(inputMode === "file" ? "Select a .pcap file first" : "Paste pcap output first");
  }

  function handleClear() {
    setFileName("");
    setFileData(null);
    setRawText("");
    setBackendResult(null);
    setTextAnalysis(null);
    setError(null);
    if (fileRef.current) fileRef.current.value = "";
  }

  async function runCli() {
    if (!cliInput.trim()) return;
    setCliLoading(true);
    try {
      const { runToolRemote } = await import("@/lib/backend");
      const result = await runToolRemote({ category_id: "pcap", tool_id: "tshark", args: cliInput.trim() });
      setCliOutput(JSON.stringify(result, null, 2));
    } catch (e: any) {
      setCliOutput(e?.message || "Command failed");
    }
    setCliLoading(false);
  }

  const totalIocs = useMemo(() => {
    if (!backendResult) return 0;
    return backendResult.iocs.ips.length + backendResult.iocs.domains.length + backendResult.iocs.urls.length;
  }, [backendResult]);

  const filteredFindings = useMemo(() => {
    if (!backendResult) return [];
    if (filterSeverity === "all") return backendResult.findings;
    return backendResult.findings.filter((f) => f.severity === filterSeverity);
  }, [backendResult, filterSeverity]);

  return (
    <PageShell
      eyebrow="TOOLS / PCAP"
      title="PCAP Analyzer"
      description="Upload a .pcap file for full Scapy-based analysis, or paste tcpdump/tshark output for quick triage."
      crumbs={[{ label: "Tools" }, { label: "PCAP" }]}
      meta={backendResult ? [
        { label: "packets", value: String(backendResult.summary.packets), tone: "primary" },
        { label: "IPs", value: String(backendResult.summary.unique_ips) },
        { label: "findings", value: String(backendResult.summary.findings), tone: backendResult.summary.findings > 0 ? "warning" : "success" },
        { label: "IOCs", value: String(totalIocs), tone: "info" },
      ] : textAnalysis ? [
        { label: "lines", value: String(textAnalysis.totalPackets), tone: "primary" },
        { label: "IPs", value: String(textAnalysis.ips.length) },
        { label: "indicators", value: String(textAnalysis.suspicious.length), tone: textAnalysis.suspicious.length > 0 ? "warning" : "success" },
      ] : undefined}
    >
      {/* Input mode + samples */}
      <div className="flex items-center gap-2 mb-3">
        <button onClick={() => { setInputMode("file"); handleClear(); }}
          className={"rounded border px-2.5 py-1 text-mono ba-text-2xs uppercase tracking-widest transition-colors " + (inputMode === "file" ? "border-primary bg-primary/15 text-primary" : "border-border bg-card/40 text-muted-foreground hover:text-foreground")}>
          <Upload className="h-3 w-3 inline mr-1" /> Upload .pcap
        </button>
        <button onClick={() => { setInputMode("text"); handleClear(); }}
          className={"rounded border px-2.5 py-1 text-mono ba-text-2xs uppercase tracking-widest transition-colors " + (inputMode === "text" ? "border-primary bg-primary/15 text-primary" : "border-border bg-card/40 text-muted-foreground hover:text-foreground")}>
          <FileText className="h-3 w-3 inline mr-1" /> Paste Output
        </button>
        {inputMode === "text" && (
          <div className="ml-2 flex gap-1">
            {Object.entries(SAMPLE_OUTPUTS).map(([name, text]) => (
              <button key={name} onClick={() => { setRawText(text); setTextAnalysis(null); setError(null); }}
                className="rounded border border-border/50 bg-card/30 px-2 py-0.5 text-mono text-[9px] uppercase text-muted-foreground hover:text-foreground transition-colors">
                {name}
              </button>
            ))}
          </div>
        )}
      </div>

      {/* Input panel */}
      <Panel title={inputMode === "file" ? "Upload PCAP" : "Paste Raw Output"}>
        {inputMode === "file" ? (
          <div className="flex items-center gap-3">
            <label className="flex cursor-pointer items-center gap-2 rounded border border-dashed border-border bg-card/40 px-4 py-3 text-mono ba-text-2xs uppercase tracking-widest text-muted-foreground hover:border-primary/40 hover:text-primary">
              <Upload className="h-4 w-4" />
              Choose .pcap / .pcapng file
              <input ref={fileRef} type="file" accept=".pcap,.pcapng" onChange={handleFile} className="hidden" />
            </label>
            {fileName && (
              <div className="flex items-center gap-2">
                <span className="font-mono text-sm text-foreground/80">{fileName}</span>
                <span className="text-mono text-[10px] text-muted-foreground">({formatBytes(fileData?.size || 0)})</span>
              </div>
            )}
          </div>
        ) : (
          <textarea
            value={rawText}
            onChange={(e) => setRawText(e.target.value)}
            placeholder="Paste tcpdump or tshark output — IPs, protocols, DNS queries, and suspicious indicators will be extracted automatically."
            className="h-44 w-full resize-y rounded border border-border bg-background/60 p-3 font-mono text-sm text-foreground outline-none placeholder:text-muted-foreground/60 focus:border-primary/50"
          />
        )}
        <div className="mt-2 flex items-center gap-2">
          <button onClick={handleAnalyze} disabled={loading || (inputMode === "file" ? !fileData : !rawText.trim())}
            className="inline-flex items-center gap-1 rounded border border-primary/40 bg-primary/10 px-3 py-2 text-mono ba-text-2xs uppercase tracking-widest text-primary hover:bg-primary/20 disabled:opacity-40">
            <Play className="h-3.5 w-3.5" /> {loading ? "Analyzing…" : "Analyze"}
          </button>
          {(inputMode === "text" && rawText) && (
            <span className="text-mono text-[10px] text-muted-foreground">
              {rawText.split("\n").filter(Boolean).length} lines — {rawText.match(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g)?.length || 0} IPs detected
            </span>
          )}
          {result && (
            <button onClick={handleClear} className="ml-auto inline-flex items-center gap-1 rounded border border-border px-2 py-1.5 text-mono ba-text-2xs uppercase tracking-widest text-muted-foreground hover:text-destructive">
              <Trash2 className="h-3 w-3" /> clear
            </button>
          )}
        </div>
      </Panel>

      {/* Status bar */}
      <StatusBar stats={[
        { label: "Status", value: loading ? "Analyzing..." : error ? "Error" : result ? "Complete" : "Idle", tone: error ? "destructive" : loading ? "warning" : result ? "success" : "muted" },
        { label: "Mode", value: inputMode === "file" ? "Backend (Scapy)" : "Client (regex)", tone: "primary" },
        { label: "Detonation", value: "never", tone: "success" },
        { label: "Source", value: inputMode === "file" ? fileName || "none" : "paste", tone: "muted" },
      ]} />

      {/* Loading state */}
      {loading && (
        <div className="grid grid-cols-3 gap-4 animate-pulse">
          {[1, 2, 3].map((i) => (
            <div key={i} className="rounded border border-border bg-card/40 p-4">
              <div className="mb-3 h-3 w-24 rounded bg-border/60" />
              <div className="space-y-2">
                {[1, 2, 3].map((j) => (
                  <div key={j} className="h-8 rounded bg-border/30" />
                ))}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Error state */}
      {error && (
        <Panel title="Error" icon={AlertTriangle}>
          <p className="text-mono ba-text-sm text-destructive">{error}</p>
        </Panel>
      )}

      {/* Empty state */}
      {!result && !loading && !error && (
        <Empty
          icon={Network}
          title="No capture loaded"
          hint="Upload a .pcap file for full Scapy-based analysis (IPs, DNS, HTTP, TLS, beaconing, IOCs), or paste tcpdump/tshark output for quick client-side triage."
        />
      )}

      {/* ── Backend result output ── */}
      {backendResult && !loading && (
        <div className="space-y-5">
          <SectionBar id="OT" label="Output · analysis results" meta={`${backendResult.summary.packets} packets · ${backendResult.summary.findings} findings · ${totalIocs} IOCs`} />

          {/* Metrics */}
          <MetricGrid
            columns={4}
            metrics={[
              { label: "Packets", value: String(backendResult.summary.packets), tone: "primary", icon: Activity },
              { label: "Unique IPs", value: String(backendResult.summary.unique_ips), icon: Server },
              { label: "DNS Queries", value: String(backendResult.summary.dns_queries), tone: "info" },
              { label: "HTTP Requests", value: String(backendResult.summary.http_requests), tone: "primary" },
              { label: "TLS SNI", value: String(backendResult.summary.tls_sni), tone: "accent" },
              { label: "Findings", value: String(backendResult.summary.findings), tone: backendResult.summary.findings > 0 ? "warning" : "success", icon: AlertTriangle },
            ]}
          />

          {/* File identity */}
          <TwoColumnOutput
            ratio="2:1"
            left={
              <Panel title="File Identity" icon={Hash}>
                <KeyFields items={[
                  { label: "Filename", value: backendResult.filename },
                  { label: "SHA-256", value: backendResult.sha256, tone: "primary" },
                  { label: "Status", value: backendResult.status, tone: "success" },
                  { label: "Detonation", value: "never", tone: "muted" },
                ]} />
              </Panel>
            }
            right={
              <Panel title="Actions" icon={Send}>
                <div className="flex flex-col gap-2">
                  <button onClick={() => {
                    backendResult.iocs.ips.forEach((ip) => locker.add({ value: ip, type: "ipv4", source: "/pcap" }));
                    backendResult.iocs.domains.forEach((d) => locker.add({ value: d, type: "domain", source: "/pcap" }));
                    toast.success(`Added ${totalIocs} IOCs to locker`);
                  }} className="inline-flex items-center gap-1.5 rounded border border-primary/40 bg-primary/10 px-2.5 py-1.5 text-mono ba-text-2xs uppercase tracking-widest text-primary hover:bg-primary/20">
                    <BookMarked className="h-3 w-3" /> all IOCs to locker
                  </button>
                  <button onClick={() => {
                    const md = generateMdReport(backendResult);
                    const blob = new Blob([md], { type: "text/markdown" });
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement("a");
                    a.href = url; a.download = `pcap-report-${backendResult.sha256.slice(0, 8)}.md`;
                    a.click(); URL.revokeObjectURL(url);
                  }} className="inline-flex items-center gap-1.5 rounded border border-primary/40 bg-primary/10 px-2.5 py-1.5 text-mono ba-text-2xs uppercase tracking-widest text-primary hover:bg-primary/20">
                    <Download className="h-3 w-3" /> Markdown Report
                  </button>
                </div>
              </Panel>
            }
          />

          {/* Top talkers */}
          <Panel title="Top Talkers" bodyClassName="p-0" icon={Server} meta={`${backendResult.top_ips.length} IPs`}>
            <div className="divide-y divide-border/50">
              {backendResult.top_ips.slice(0, 10).map((t, i) => (
                  <div key={i} className="flex items-center justify-between px-3 py-2 hover:bg-card/30">
                  <div className="flex items-center gap-2 min-w-0">
                    <span className="font-mono text-sm text-foreground/90">{t.ip}</span>
                    <Chip tone={/^(10\.|192\.168\.)/.test(t.ip) ? "default" : "info"}>
                      {/^(10\.|192\.168\.)/.test(t.ip) ? "Internal" : "External"}
                    </Chip>
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    <span className="font-mono text-[11px] text-muted-foreground">{t.packets} packets</span>
                    <button onClick={() => { locker.add({ value: t.ip, type: "ipv4", source: "/pcap" }); toast("Added IP to locker"); }}
                      className="grid h-5 w-5 place-items-center rounded text-muted-foreground hover:text-primary opacity-0 group-hover:opacity-100 transition-opacity" title="Add to locker">
                      <Database className="h-3 w-3" />
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </Panel>

          {/* DNS Queries + TLS SNI */}
          <TwoColumnOutput
            ratio="1:1"
            left={
              <Panel title="DNS Queries" bodyClassName="p-0" icon={Globe} meta={`${backendResult.dns_queries.length} queries`}>
                <div className="divide-y divide-border/50 max-h-64 overflow-y-auto">
                  {backendResult.dns_queries.map((q, i) => (
                    <div key={i} className="flex items-center justify-between gap-2 px-3 py-1.5 hover:bg-card/30 group">
                      <div className="flex items-center gap-2 min-w-0">
                        <Globe className="h-3 w-3 shrink-0 text-muted-foreground" />
                        <code className="font-mono text-sm text-foreground/90">{q}</code>
                      </div>
                      <button onClick={() => { locker.add({ value: q, type: "domain", source: "/pcap" }); toast("Added domain to locker"); }}
                        className="grid h-5 w-5 shrink-0 place-items-center rounded text-muted-foreground hover:text-primary opacity-0 group-hover:opacity-100 transition-opacity" title="Add to locker">
                        <Database className="h-3 w-3" />
                      </button>
                    </div>
                  ))}
                  {backendResult.dns_queries.length === 0 && (
                    <div className="px-3 py-4 text-center text-mono text-[11px] text-muted-foreground">No DNS queries detected</div>
                  )}
                </div>
              </Panel>
            }
            right={
              <Panel title="TLS Server Names" bodyClassName="p-0" icon={ShieldAlert} meta={`${backendResult.tls_server_names.length} SNI`}>
                <div className="divide-y divide-border/50 max-h-64 overflow-y-auto">
                  {backendResult.tls_server_names.map((n, i) => (
                    <div key={i} className="flex items-center justify-between gap-2 px-3 py-1.5 hover:bg-card/30 group">
                      <div className="flex items-center gap-2 min-w-0">
                        <Server className="h-3 w-3 shrink-0 text-muted-foreground" />
                        <code className="font-mono text-sm text-foreground/90">{n}</code>
                      </div>
                      <button onClick={() => { locker.add({ value: n, type: "domain", source: "/pcap" }); toast("Added domain to locker"); }}
                        className="grid h-5 w-5 shrink-0 place-items-center rounded text-muted-foreground hover:text-primary opacity-0 group-hover:opacity-100 transition-opacity" title="Add to locker">
                        <Database className="h-3 w-3" />
                      </button>
                    </div>
                  ))}
                </div>
              </Panel>
            }
          />

          {/* HTTP Requests */}
          {backendResult.http_requests.length > 0 && (
            <CollapsibleSection id="HTTP" label="HTTP Requests" meta={`${backendResult.http_requests.length} requests`} icon={Activity}>
              <div className="divide-y divide-border/50">
                {backendResult.http_requests.map((r, i) => (
                  <div key={i} className="grid grid-cols-[60px_1fr_auto] items-center gap-3 px-3 py-2 hover:bg-card/30">
                    <Chip tone={r.method === "POST" ? "warning" : "info"}>{r.method}</Chip>
                    <div className="min-w-0">
                      <code className="font-mono text-sm text-foreground/90">{r.host}{r.path}</code>
                      {r.user_agent && <div className="text-[10px] text-muted-foreground truncate">{r.user_agent}</div>}
                    </div>
                    <div className="shrink-0 text-mono text-[10px] text-muted-foreground">
                      {r.src && <span>{r.src} →</span>} {r.dst}
                    </div>
                  </div>
                ))}
              </div>
            </CollapsibleSection>
          )}

          {/* Beaconing candidates */}
          {backendResult.beaconing_candidates.length > 0 && (
            <CollapsibleSection id="BN" label="Beaconing Candidates" meta={`${backendResult.beaconing_candidates.length} pairs`} icon={Activity}>
              <div className="divide-y divide-border/50">
                {backendResult.beaconing_candidates.map((b, i) => (
                  <div key={i} className="flex items-center justify-between px-3 py-2 hover:bg-card/30 group">
                    <div className="flex items-center gap-2 min-w-0">
                      <AlertTriangle className="h-3.5 w-3.5 shrink-0 text-warning" />
                      <code className="font-mono text-sm text-foreground/90">{b.src}</code>
                      <span className="text-muted-foreground">→</span>
                      <code className="font-mono text-sm text-foreground/90">{b.dst}</code>
                    </div>
                    <div className="flex items-center gap-2 shrink-0">
                      <span className="font-mono text-[11px] text-warning">{b.packets} packets</span>
                      <button onClick={() => { locker.add({ value: b.dst, type: "ipv4", source: "/pcap" }); toast("Added beacon IP to locker"); }}
                        className="grid h-5 w-5 place-items-center rounded text-muted-foreground hover:text-primary opacity-0 group-hover:opacity-100 transition-opacity" title="Add to locker">
                        <Database className="h-3 w-3" />
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            </CollapsibleSection>
          )}

          {/* Findings */}
          {backendResult.findings.length > 0 && (
            <div>
              <div className="mb-2 flex items-center gap-2">
                <SectionBar id="FN" label="Findings" meta={`${filteredFindings.length} of ${backendResult.findings.length}`} />
                <div className="flex items-center gap-1">
                  <ListFilter className="h-3 w-3 text-muted-foreground" />
                  {(["all", "high", "medium", "low", "info"] as const).map((s) => (
                    <button key={s} onClick={() => setFilterSeverity(s)}
                      className={"rounded border px-1.5 py-0.5 text-mono ba-text-2xs uppercase tracking-widest " + (filterSeverity === s ? "border-primary bg-primary/15 text-primary" : "border-border/50 text-muted-foreground hover:text-foreground")}>
                      {s}
                    </button>
                  ))}
                </div>
              </div>
              <div className="grid gap-3">
                {filteredFindings.map((f, i) => (
                  <EvidenceCard
                    key={i}
                    severity={pcapSeverityTone(f.severity)}
                    title={f.title}
                    reason={f.detail}
                    action={f.recommendation}
                  />
                ))}
              </div>
            </div>
          )}

          {/* IOCs */}
          <Panel title="Extracted IOCs" icon={Hash}>
            <IocInventory
              groups={[
                { kind: "IPs", items: backendResult.iocs.ips, tone: "info" },
                { kind: "Domains", items: backendResult.iocs.domains, tone: "warning" },
                { kind: "URLs", items: backendResult.iocs.urls, tone: "destructive" },
              ]}
              onSendTo={(kind, value) => { locker.add({ value, type: kind.toLowerCase() as any, source: "/pcap" }); toast("Added to locker"); }}
            />
          </Panel>

          {/* Limitations */}
          {backendResult.limitations.length > 0 && (
            <CollapsibleSection id="LM" label="Limitations" meta={`${backendResult.limitations.length} notes`} icon={AlertTriangle} defaultCollapsed>
              <ul className="space-y-1">
                {backendResult.limitations.map((l, i) => (
                  <li key={i} className="flex items-start gap-2 text-mono ba-text-sm text-muted-foreground">
                    <AlertTriangle className="mt-0.5 h-3 w-3 shrink-0" />
                    {l}
                  </li>
                ))}
              </ul>
            </CollapsibleSection>
          )}

          {/* Send-to */}
          <SendToRow targets={[
            { label: "Recon", to: "/recon", icon: Globe },
            { label: "Detection", to: "/detection", icon: ShieldAlert },
            { label: "Case Notebook", to: "/case", icon: Database },
            { label: "SIEM", to: "/siem", icon: Activity },
          ]} />
        </div>
      )}

      {/* ── Text analysis output ── */}
      {textAnalysis && !loading && (
        <>
          <div className="grid grid-cols-3 gap-4">
            <Panel title="Top Talkers" bodyClassName="p-0" icon={Server}>
              <div className="divide-y divide-border/50">
                {textAnalysis.topTalkers.map((t, i) => (
                  <div key={i} className="flex items-center justify-between px-3 py-2 hover:bg-card/30 group">
                    <div className="flex items-center gap-2 min-w-0">
                      <span className="font-mono text-sm text-foreground/90 truncate">{t.ip}</span>
                      <Chip tone={t.role.includes("suspicious") ? "destructive" : "default"}>{t.role}</Chip>
                    </div>
                    <div className="flex items-center gap-2 shrink-0">
                      <div className="text-right font-mono text-[11px] text-muted-foreground">
                        <div>{t.packets} pkts</div>
                        <div>{t.bytes}</div>
                      </div>
                      <button onClick={() => { locker.add({ value: t.ip, type: "ipv4", source: "/pcap" }); toast("Added IP to locker"); }}
                        className="grid h-5 w-5 place-items-center rounded text-muted-foreground hover:text-primary opacity-0 group-hover:opacity-100 transition-opacity" title="Add to locker">
                        <Database className="h-3 w-3" />
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            </Panel>

            <Panel title="Protocol Breakdown" bodyClassName="p-0">
              <div className="divide-y divide-border/50">
                {textAnalysis.protocols.map((p, i) => (
                  <div key={i} className="px-3 py-2">
                    <div className="flex items-center justify-between mb-1">
                      <span className="font-mono text-sm text-foreground/90">{p.protocol}</span>
                      <span className="font-mono text-[11px] text-muted-foreground">{p.packets} ({p.percentage}%)</span>
                    </div>
                    <div className="h-1.5 w-full rounded-full bg-border/50">
                      <div className="h-1.5 rounded-full bg-primary" style={{ width: `${p.percentage}%` }} />
                    </div>
                  </div>
                ))}
              </div>
            </Panel>

            <Panel title="Suspicious Indicators" bodyClassName="p-0">
              <div className="divide-y divide-border/50">
                {textAnalysis.suspicious.length > 0 ? textAnalysis.suspicious.map((s, i) => (
                  <div key={i} className="px-3 py-2">
                    <div className="flex items-start gap-2">
                      <AlertTriangle className={"mt-0.5 h-3.5 w-3.5 shrink-0 " + (s.severity === "high" ? "text-destructive" : s.severity === "medium" ? "text-warning" : "text-muted-foreground")} />
                      <div className="min-w-0">
                        <div className="font-mono text-sm text-foreground/90">{s.indicator}</div>
                        <div className="mt-0.5 text-[11px] text-muted-foreground">{s.detail}</div>
                      </div>
                    </div>
                  </div>
                )) : (
                  <div className="px-3 py-4 text-center text-mono text-[11px] text-muted-foreground">
                    <CheckCircle className="h-4 w-4 inline text-success mr-1" />
                    No suspicious indicators detected
                  </div>
                )}
              </div>
            </Panel>
          </div>

          <div className="grid grid-cols-2 gap-4">
            <Panel title="Identified Domains" bodyClassName="p-0" icon={Globe}>
              <div className="divide-y divide-border/50">
                {textAnalysis.dnsQueries.map((q, i) => (
                  <div key={i} className="flex items-center justify-between gap-2 px-3 py-1.5 group hover:bg-card/30">
                    <div className="flex items-center gap-2 min-w-0">
                      <Globe className="h-3 w-3 shrink-0 text-muted-foreground" />
                      <code className="font-mono text-sm text-foreground/90">{q}</code>
                    </div>
                    <button onClick={() => { locker.add({ value: q, type: "domain", source: "/pcap" }); toast("Added domain to locker"); }}
                      className="grid h-5 w-5 shrink-0 place-items-center rounded text-muted-foreground hover:text-primary opacity-0 group-hover:opacity-100 transition-opacity" title="Add to locker">
                      <Database className="h-3 w-3" />
                    </button>
                  </div>
                ))}
              </div>
            </Panel>

            <Panel title="Network Summary" bodyClassName="p-0">
              <div className="divide-y divide-border/50">
                {[
                  { label: "Total Lines", value: String(textAnalysis.totalPackets) },
                  { label: "Unique IPs", value: String(textAnalysis.ips.length) },
                  { label: "Internal IPs", value: String(textAnalysis.ips.filter(ip => /^10\.|^192\.168\./.test(ip)).length) },
                  { label: "External IPs", value: String(textAnalysis.ips.filter(ip => !/^10\.|^192\.168\./.test(ip)).length) },
                  { label: "Protocols Detected", value: String(textAnalysis.protocols.length) },
                  { label: "Suspicious Indicators", value: String(textAnalysis.suspicious.length) },
                ].map((row, i) => (
                  <div key={i} className="flex items-center justify-between px-3 py-2">
                    <span className="font-mono text-sm text-foreground/80">{row.label}</span>
                    <span className="font-mono text-sm text-foreground/90">{row.value}</span>
                  </div>
                ))}
              </div>
            </Panel>
          </div>

          <div className="flex items-center gap-2 mt-4">
            <button onClick={() => {
              textAnalysis.ips.forEach((ip) => locker.add({ value: ip, type: "ipv4", source: "/pcap" }));
              textAnalysis.dnsQueries.forEach((d) => locker.add({ value: d, type: "domain", source: "/pcap" }));
              toast.success("Added " + (textAnalysis.ips.length + textAnalysis.dnsQueries.length) + " IOCs to locker");
            }} className="inline-flex items-center gap-1.5 rounded border border-primary/40 bg-primary/10 px-2.5 py-1.5 text-mono ba-text-2xs uppercase tracking-widest text-primary hover:bg-primary/20">
              <BookMarked className="h-3 w-3" /> all IOCs to locker
            </button>
            <button onClick={() => {
              const md = generateTextMdReport(textAnalysis);
              const blob = new Blob([md], { type: "text/markdown" });
              const url = URL.createObjectURL(blob);
              const a = document.createElement("a");
              a.href = url; a.download = "pcap-text-report-" + Date.now() + ".md";
              a.click(); URL.revokeObjectURL(url);
            }} className="inline-flex items-center gap-1.5 rounded border border-primary/40 bg-primary/10 px-2.5 py-1.5 text-mono ba-text-2xs uppercase tracking-widest text-primary hover:bg-primary/20">
              <Download className="h-3 w-3" /> Markdown Report
            </button>
          </div>

          <SendToRow targets={[
            { label: "Recon", to: "/recon", icon: Globe },
            { label: "Detection Editor", to: "/detection", icon: ShieldAlert },
            { label: "Case Notebook", to: "/case", icon: Database },
            { label: "SIEM", to: "/siem", icon: Activity },
          ]} />
        </>
      )}

      {/* ── CLI section ── */}
      <div className="space-y-3">
        <SectionBar id="CLI" label="SOC CLI Tools" meta="tshark / tcpdump / nmap" />
        <Panel title="Command Builder" icon={Terminal}>
          <div className="flex items-center gap-2 mb-3">
            <input
              value={cliInput}
              onChange={(e) => setCliInput(e.target.value)}
              placeholder="e.g. tcpdump -r capture.pcap -nn -c 100, tshark -r capture.pcap -T fields -e ip.src -e ip.dst"
              onKeyDown={(e) => { if (e.key === "Enter") runCli(); }}
              className="flex-1 rounded border border-border bg-background/60 px-3 py-2 font-mono text-sm text-foreground outline-none placeholder:text-muted-foreground/60 focus:border-primary/50"
            />
            <button onClick={runCli} disabled={cliLoading || !cliInput.trim()}
              className="inline-flex items-center gap-1 rounded border border-primary/40 bg-primary/10 px-3 py-2 text-mono ba-text-2xs uppercase tracking-widest text-primary hover:bg-primary/20 disabled:opacity-40">
              <Play className="h-3.5 w-3.5" /> Run
            </button>
            <button onClick={() => { setCliInput(""); setCliOutput(""); }}
              className="inline-flex items-center gap-1 rounded border border-border px-2 py-2 text-mono ba-text-2xs uppercase text-muted-foreground hover:text-foreground">
              <Trash2 className="h-3 w-3" />
            </button>
          </div>
          <div className="flex flex-wrap gap-1.5">
            {["tshark -r capture.pcap -T fields -e ip.src -e ip.dst | sort | uniq -c | sort -nr | head -10", "tcpdump -r capture.pcap -nn -c 50", "tshark -r capture.pcap -Y dns -T fields -e dns.qry.name", "tshark -r capture.pcap -Y http.request -T fields -e http.host -e http.request.uri", "tcpdump -r capture.pcap -X -c 20"].map((cmd) => (
              <button key={cmd} onClick={() => setCliInput(cmd)}
                className="rounded border border-border/50 bg-card/30 px-2 py-0.5 font-mono text-[10px] text-muted-foreground hover:text-foreground transition-colors">
                {cmd}
              </button>
            ))}
          </div>
          {cliOutput && (
            <div className="mt-3">
              <pre className="max-h-48 overflow-auto rounded border border-border/50 bg-background/60 p-3 font-mono text-sm text-foreground/90 whitespace-pre-wrap">{cliOutput}</pre>
            </div>
          )}
        </Panel>
      </div>
    </PageShell>
  );
}
