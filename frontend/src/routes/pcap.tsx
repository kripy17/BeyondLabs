import { createFileRoute } from "@tanstack/react-router";
import { useCallback, useState } from "react";
import { PageShell } from "@/components/PageShell";
import { Panel, SectionBar, Chip } from "@/components/soc";
import { Empty, KeyFields } from "@/components/output";
import { Upload, Terminal, Activity, Globe, Database, AlertTriangle, Wifi, BarChart3, Network, Play, Trash2 } from "lucide-react";
import { ExplainThisButton } from "@/components/ExplainThis";
import { toast } from "sonner";
import { runToolRemote } from "@/lib/backend";

export const Route = createFileRoute("/pcap")({ component: PcapPage });

type ProtoBreakdown = { protocol: string; packets: number; percentage: number };
type TopTalker = { ip: string; packets: number; bytes: string; role: string };
type Suspicious = { indicator: string; severity: "high" | "medium" | "low"; detail: string };

function mockAnalysis() {
  return {
    totalPackets: 14283 + Math.floor(Math.random() * 5000),
    duration: "2m 34s",
    topTalkers: [
      { ip: "192.168.1.100", packets: 5234, bytes: "3.2 MB", role: "Internal" },
      { ip: "185.220.101.44", packets: 2891, bytes: "1.8 MB", role: "External (suspicious)" },
      { ip: "8.8.8.8", packets: 1456, bytes: "234 KB", role: "DNS" },
      { ip: "203.0.113.55", packets: 892, bytes: "567 KB", role: "External" },
      { ip: "10.0.0.1", packets: 634, bytes: "89 KB", role: "Gateway" },
    ] as TopTalker[],
    protocols: [
      { protocol: "TCP", packets: 8234, percentage: 57.7 },
      { protocol: "UDP", packets: 4123, percentage: 28.9 },
      { protocol: "DNS", packets: 1234, percentage: 8.6 },
      { protocol: "ICMP", packets: 345, percentage: 2.4 },
      { protocol: "HTTP", parameters: 289, percentage: 2.0 },
      { protocol: "TLS", packets: 58, percentage: 0.4 },
    ] as ProtoBreakdown[],
    suspicious: [
      { indicator: "Connection to known malware C2 (185.220.101.44:4443)", severity: "high", detail: "Observed 2,891 packets to IP associated with Emotet infrastructure" },
      { indicator: "Non-standard TLS handshake (JA3: 6734f37431670b3ab4292b8f60f29984)", severity: "high", detail: "JA3 fingerprint matches Emotet/SocGholish malware family" },
      { indicator: "DNS query for suspicious domain (evil-payload[.]ru)", severity: "medium", detail: "Domain registered 3 days ago, no legitimate content" },
      { indicator: "Base64-encoded string in HTTP POST body", severity: "medium", detail: "Potential data exfiltration or encoded payload" },
      { indicator: "SMBv1 traffic detected", severity: "low", detail: "Legacy protocol should be disabled — potential for EternalBlue-style attacks" },
    ] as Suspicious[],
    dnsQueries: ["evil-payload.ru", "cdn.example-login.com", "update.telemetry.example", "google.com", "outlook.office365.com", "malware-distributor[.]top", "api.telemetry.example"],
    extractedFiles: ["payload.ps1 (suspicious)", "invoice.pdf (clean)", "screenshot.png (clean)", "config.json (suspicious)"],
  };
}

function PcapPage() {
  const [fileName, setFileName] = useState("");
  const [analysis, setAnalysis] = useState<ReturnType<typeof mockAnalysis> | null>(null);
  const [loading, setLoading] = useState(false);
  const [cliInput, setCliInput] = useState("");
  const [cliOutput, setCliOutput] = useState("");
  const [cliLoading, setCliLoading] = useState(false);

  const handleFile = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const f = e.target.files?.[0];
    if (f) { setFileName(f.name); handleAnalyze(); }
  }, []);

  function handleAnalyze() {
    setLoading(true);
    setTimeout(() => {
      setAnalysis(mockAnalysis());
      setLoading(false);
    }, 1200);
  }

  async function runCli() {
    if (!cliInput.trim()) return;
    setCliLoading(true);
    try {
      const result = await runToolRemote({ category_id: "pcap", tool_id: "tshark", args: cliInput.trim() });
      setCliOutput(JSON.stringify(result, null, 2));
    } catch (e: any) {
      setCliOutput(e?.message || "Command failed");
    }
    setCliLoading(false);
  }

  return (
    <PageShell
      eyebrow="TOOLS / PCAP"
      title="PCAP Analyzer"
      description="Quick pcap triage — top talkers, protocol breakdown, suspicious indicators, and integrated tshark/tcpdump CLI."
      crumbs={[{ label: "Tools" }, { label: "PCAP" }]}
      meta={analysis ? [
        { label: "packets", value: String(analysis.totalPackets), tone: "primary" },
        { label: "suspicious", value: String(analysis.suspicious.filter((s) => s.severity === "high").length), tone: "destructive" },
      ] : undefined}
    >
      <Panel title="Upload PCAP">
        <div className="flex items-center gap-3">
          <label className="flex cursor-pointer items-center gap-2 rounded border border-dashed border-border bg-card/40 px-4 py-3 text-mono ba-text-2xs uppercase tracking-widest text-muted-foreground hover:border-primary/40 hover:text-primary">
            <Upload className="h-4 w-4" />
            Choose .pcap / .pcapng file
            <input type="file" accept=".pcap,.pcapng" onChange={handleFile} className="hidden" />
          </label>
          {fileName && <span className="font-mono text-sm text-foreground/80">{fileName}</span>}
          <button onClick={handleAnalyze} disabled={loading}
            className="inline-flex items-center gap-1 rounded border border-primary/40 bg-primary/10 px-3 py-2 text-mono ba-text-2xs uppercase tracking-widest text-primary hover:bg-primary/20 disabled:opacity-40">
            <Play className="h-3.5 w-3.5" /> {loading ? "Analyzing…" : "Analyze"}
          </button>
        </div>
      </Panel>

      {loading && (
        <div className="flex items-center justify-center py-12">
          <div className="flex items-center gap-3 text-muted-foreground">
            <Activity className="h-5 w-5 animate-pulse" />
            <span className="font-mono text-sm">Analyzing packet capture…</span>
          </div>
        </div>
      )}

      {analysis && !loading && (
        <>
          <div className="grid grid-cols-3 gap-4">
            <Panel title="Top Talkers" bodyClassName="p-0">
              <div className="divide-y divide-border/50">
                {analysis.topTalkers.map((t, i) => (
                  <div key={i} className="flex items-center justify-between px-3 py-2">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-sm text-foreground/90">{t.ip}</span>
                      <Chip tone={t.role.includes("suspicious") ? "destructive" : "default"}>{t.role}</Chip>
                    </div>
                    <div className="text-right font-mono text-[11px] text-muted-foreground">
                      <div>{t.packets} pkts</div>
                      <div>{t.bytes}</div>
                    </div>
                  </div>
                ))}
              </div>
            </Panel>

            <Panel title="Protocol Breakdown" bodyClassName="p-0">
              <div className="divide-y divide-border/50">
                {analysis.protocols.map((p, i) => (
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

            <Panel title="Suspicious Indicators" bodyClassName="p-0"
              actions={
                <ExplainThisButton kind="pcap" input={analysis.suspicious.map(s => `${s.severity}: ${s.indicator} — ${s.detail}`).join("\n")} />
              }
            >
              <div className="divide-y divide-border/50">
                {analysis.suspicious.map((s, i) => (
                  <div key={i} className="px-3 py-2">
                    <div className="flex items-start gap-2">
                      <AlertTriangle className={"mt-0.5 h-3.5 w-3.5 shrink-0 " + (s.severity === "high" ? "text-destructive" : s.severity === "medium" ? "text-warning" : "text-muted-foreground")} />
                      <div className="min-w-0">
                        <div className="font-mono text-sm text-foreground/90">{s.indicator}</div>
                        <div className="mt-0.5 text-[11px] text-muted-foreground">{s.detail}</div>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </Panel>
          </div>

          <div className="grid grid-cols-2 gap-4">
            <Panel title="DNS Queries" bodyClassName="p-0">
              <div className="divide-y divide-border/50">
                {analysis.dnsQueries.map((q, i) => (
                  <div key={i} className="flex items-center gap-2 px-3 py-1.5">
                    <Globe className="h-3 w-3 shrink-0 text-muted-foreground" />
                    <code className="font-mono text-sm text-foreground/90">{q}</code>
                  </div>
                ))}
              </div>
            </Panel>
            <Panel title="Extracted Files" bodyClassName="p-0">
              <div className="divide-y divide-border/50">
                {analysis.extractedFiles.map((f, i) => (
                  <div key={i} className="flex items-center gap-2 px-3 py-1.5">
                    <Database className="h-3 w-3 shrink-0 text-muted-foreground" />
                    <span className={"font-mono text-sm " + (f.includes("suspicious") ? "text-destructive" : "text-foreground/90")}>{f}</span>
                  </div>
                ))}
              </div>
            </Panel>
          </div>
        </>
      )}

      {!analysis && !loading && (
        <Empty icon={Network} title="No capture loaded" hint="Upload a .pcap or .pcapng file above to begin analysis." />
      )}

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
