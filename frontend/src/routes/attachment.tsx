import { createFileRoute } from "@tanstack/react-router";
import { useRef, useState } from "react";
import { PageShell } from "@/components/PageShell";
import {
  StatusBar, ResultBanner, KeyFields, SectionBar,
  Panel, EvidenceCard, SendToRow, Empty, Chip, RiskScore,
  TwoColumnOutput, VerdictBanner, MetricGrid, CollapsibleSection,
} from "@/components/soc/Workspace";
import { MailWarning as FileWarning, Hash, Database, ArrowRight, ShieldAlert, ExternalLink, Upload, Eraser, Download, Sigma, Binary, TriangleAlert as AlertTriangle, ShieldCheck, ShieldX, Activity } from "lucide-react";
import { uploadMalwareFile } from "@/api/backend";

export const Route = createFileRoute("/attachment")({ component: AttachmentPage });

interface ApiResult {
  metadata: { filename: string; size_bytes: number; analyzed_at: string; safety_note: string };
  file_type: { filename: string; extension: string | null; magic_type: string };
  hashes: { md5: string; sha1: string; sha256: string; sha512: string };
  entropy: number;
  strings_preview: string[];
  suspicious_strings: { keyword: string; severity: string; detail: string }[];
  summary: { score: number; rating: string; total_findings: number; confidence: string; note?: string };
  findings: { severity: string; title: string; detail: string; recommendation: string }[];
}

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function AttachmentPage() {
  const fileRef = useRef<HTMLInputElement>(null);
  const [file, setFile] = useState<File | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ApiResult | null>(null);

  async function handleUpload() {
    if (!file) return;
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const res = await uploadMalwareFile(file);
      setResult(res as ApiResult);
    } catch (e: any) {
      setError(e?.message || "analysis failed");
    } finally {
      setLoading(false);
    }
  }

  function handleClear() {
    setFile(null);
    setResult(null);
    setError(null);
    if (fileRef.current) fileRef.current.value = "";
  }

  return (
    <PageShell
      eyebrow="TRIAGE / ATTACHMENT"
      title="Attachment Triage"
      description="Static review of file metadata, hashes, strings, and signals. Files are never executed."
      crumbs={[{ label: "Triage" }, { label: "Attachment" }]}
    >
      <SectionBar id="IN" label="Intake · file upload" meta={file ? file.name : "no file selected"} />

      <Panel title={file ? "File selected" : "Upload a file"} icon={FileWarning}>
        <div className="flex flex-wrap items-center gap-3">
          <input ref={fileRef} type="file" className="hidden" onChange={(e) => { setFile(e.target.files?.[0] || null); setResult(null); setError(null); }} />
          <button
            onClick={() => fileRef.current?.click()}
            className="inline-flex items-center gap-1.5 rounded border border-border bg-card/60 px-3 py-2 text-mono text-[11px] uppercase tracking-widest text-foreground/80 transition-colors hover:border-primary/40 hover:text-foreground"
          >
            <Upload className="h-3.5 w-3.5" /> Choose file
          </button>
          {file && (
            <>
              <span className="text-mono text-[11px] text-foreground/90">{file.name} ({formatSize(file.size)})</span>
              <button onClick={handleUpload} disabled={loading} className="inline-flex items-center gap-1.5 rounded border border-primary/40 bg-primary/10 px-2.5 py-1.5 text-mono text-[10px] uppercase tracking-widest text-primary transition-all hover:bg-primary/20 hover:shadow-[0_0_12px_-2px_hsl(var(--primary)/0.45)] disabled:opacity-50">
                {loading ? "Analyzing..." : "Analyze"}
              </button>
              <button onClick={handleClear} className="inline-flex items-center gap-1 rounded border border-border bg-card/60 px-2 py-1.5 text-mono text-[10px] uppercase tracking-widest text-muted-foreground transition-colors hover:border-destructive/40 hover:text-destructive">
                <Eraser className="h-3 w-3" /> clear
              </button>
            </>
          )}
        </div>
        {!file && <p className="mt-2 text-mono text-[10px] text-muted-foreground">Supports any file type. Max 15 MB for MVP.</p>}
      </Panel>

      <StatusBar stats={[
        { label: "Status", value: loading ? "Analyzing..." : error ? "Error" : result ? "Complete" : "Idle", tone: error ? "destructive" : loading ? "warning" : result ? "success" : "muted" },
        { label: "Detonation", value: "never", tone: "primary" },
        { label: "Upload", value: file ? "local only" : "none", tone: "muted" },
        { label: "Mode", value: "static review" },
      ]} />

      {!result && !loading && !error && !file && (
        <Empty icon={FileWarning} title="No file loaded" hint="Select a file above and click Analyze for static triage." />
      )}

      {loading && (
        <Panel title="Analysis in progress" icon={Sigma}>
          <p className="text-mono text-[11px] text-muted-foreground">Computing hashes, extracting strings, scanning for suspicious patterns...</p>
        </Panel>
      )}

      {error && (
        <Panel title="Error" icon={AlertTriangle}>
          <p className="text-mono text-[11px] text-destructive">{error}</p>
        </Panel>
      )}

      {result && !loading && (
        <div className="space-y-5">
          <SectionBar id="OT" label="Output · signals & findings" meta={`${result.summary.total_findings} findings · ${result.suspicious_strings.length} suspicious strings`} />

          {/* Verdict Banner */}
          <VerdictBanner
            verdict={result.summary.rating}
            tone={result.summary.score >= 70 ? "destructive" : result.summary.score >= 40 ? "warning" : "success"}
            icon={result.summary.score >= 70 ? ShieldX : result.summary.score >= 40 ? AlertTriangle : ShieldCheck}
            score={`${result.summary.score}/100`}
            details={[
              result.metadata.filename,
              `${result.file_type.magic_type} · ${formatSize(result.metadata.size_bytes)}`,
              result.suspicious_strings.length > 0 ? `${result.suspicious_strings.length} suspicious string(s)` : "",
              result.summary.note || "Static analysis only — no detonation performed.",
            ].filter(Boolean)}
          />

          {/* Metrics */}
          <MetricGrid
            columns={4}
            metrics={[
              { label: "Score", value: `${result.summary.score}/100`, tone: result.summary.score < 40 ? "success" : result.summary.score < 70 ? "warning" : "destructive", icon: Activity },
              { label: "Rating", value: result.summary.rating, tone: result.summary.rating === "High Risk" || result.summary.rating === "Known Malicious" ? "destructive" : result.summary.rating === "Suspicious" ? "warning" : "success" },
              { label: "Findings", value: result.summary.total_findings, tone: result.summary.total_findings > 0 ? "warning" : "default" },
              { label: "Entropy", value: result.entropy.toFixed(1), tone: result.entropy >= 7.2 ? "warning" : "default", icon: Binary },
              { label: "Size", value: formatSize(result.metadata.size_bytes) },
              { label: "Strings", value: result.strings_preview.length },
              { label: "Suspicious", value: result.suspicious_strings.length, tone: result.suspicious_strings.length > 0 ? "warning" : "default" },
              { label: "Detonation", value: "never", tone: "success" },
            ]}
          />

          <RiskScore
            score={result.summary.score}
            label="Risk Score"
            confidence={result.summary.confidence}
            tone={result.summary.score < 40 ? "success" : result.summary.score < 70 ? "warning" : "destructive"}
          />

          {/* Cryptographic Identity */}
          <Panel title="Cryptographic Identity" icon={Hash} meta="4 algorithms">
            <div className="grid gap-2 md:grid-cols-4">
              {([
                { algo: "MD5", value: result.hashes.md5, bits: 128, tone: "default" as const },
                { algo: "SHA-1", value: result.hashes.sha1, bits: 160, tone: "warning" as const },
                { algo: "SHA-256", value: result.hashes.sha256, bits: 256, tone: "success" as const },
                { algo: "SHA-512", value: result.hashes.sha512, bits: 512, tone: "primary" as const },
              ]).map((h) => (
                <button
                  key={h.algo}
                  onClick={() => navigator.clipboard.writeText(h.value)}
                  className="group rounded-md border border-border/60 bg-card/50 p-2.5 text-left transition-colors hover:border-primary/40 hover:bg-card/80"
                >
                  <div className="flex items-center justify-between">
                    <span className="text-mono text-[10px] uppercase tracking-widest text-muted-foreground">{h.algo}</span>
                    <Chip tone={h.tone}>{h.bits}-bit</Chip>
                  </div>
                  <code className="mt-1.5 block break-all text-mono text-[10.5px] leading-snug text-foreground/90 group-hover:text-primary">{h.value}</code>
                  <span className="mt-1 block text-mono text-[9.5px] uppercase tracking-widest text-muted-foreground opacity-0 transition-opacity group-hover:opacity-100">click to copy</span>
                </button>
              ))}
            </div>
          </Panel>

          {/* File Identity + External References side-by-side */}
          <TwoColumnOutput
            ratio="2:1"
            left={
              <Panel title="File Identity" icon={FileWarning} meta={result.file_type.magic_type}>
                <KeyFields items={[
                  { label: "Name", value: result.metadata.filename },
                  { label: "Type", value: result.file_type.magic_type, tone: "primary" },
                  { label: "Size", value: formatSize(result.metadata.size_bytes) },
                  { label: "Extension", value: result.file_type.extension || "—" },
                  { label: "Detonation", value: "never", tone: "muted" },
                ]} />
              </Panel>
            }
            right={
              <Panel title="External References" meta="manual reputation">
                <div className="flex flex-col gap-2">
                  <a className="inline-flex items-center gap-1 rounded border border-border bg-card/70 px-2 py-1.5 text-mono text-[10px] uppercase text-foreground/80 hover:text-primary" target="_blank" rel="noreferrer" href={`https://www.virustotal.com/gui/file/${result.hashes.sha256}`}><ExternalLink className="h-3 w-3" /> VirusTotal</a>
                  <a className="inline-flex items-center gap-1 rounded border border-border bg-card/70 px-2 py-1.5 text-mono text-[10px] uppercase text-foreground/80 hover:text-primary" target="_blank" rel="noreferrer" href={`https://bazaar.abuse.ch/sample/${result.hashes.sha256}/`}><ExternalLink className="h-3 w-3" /> MalwareBazaar</a>
                  <a className="inline-flex items-center gap-1 rounded border border-border bg-card/70 px-2 py-1.5 text-mono text-[10px] uppercase text-foreground/80 hover:text-primary" target="_blank" rel="noreferrer" href={`https://hybrid-analysis.com/search?query=${result.hashes.sha256}`}><ExternalLink className="h-3 w-3" /> Hybrid Analysis</a>
                </div>
              </Panel>
            }
          />

          {/* Suspicious Strings - collapsible */}
          {result.suspicious_strings.length > 0 && (
            <CollapsibleSection id="SS" label="Suspicious Strings" meta={`${result.suspicious_strings.length} keyword(s)`} icon={Binary}>
              <ul className="space-y-1">
                {result.suspicious_strings.map((s) => (
                  <li key={s.keyword} className="flex items-center justify-between gap-2 border-b border-border/40 py-1 text-mono text-[11px]">
                    <code className="truncate text-foreground/90">{s.keyword}</code>
                    <Chip tone={s.severity === "high" ? "destructive" : "warning"}>{s.severity}</Chip>
                  </li>
                ))}
              </ul>
            </CollapsibleSection>
          )}

          {/* Strings Preview - collapsible */}
          {result.strings_preview.length > 0 && (
            <Panel title="Strings Preview" icon={Binary} meta={`${result.strings_preview.length} shown`} collapsible defaultCollapsed={result.strings_preview.length > 20}>
              <div className="max-h-48 overflow-y-auto">
                <ul className="space-y-0.5">
                  {result.strings_preview.map((s, i) => (
                    <li key={i} className="border-b border-border/30 py-0.5 text-mono text-[10.5px] text-foreground/80">{s}</li>
                  ))}
                </ul>
              </div>
            </Panel>
          )}

          {/* Findings */}
          {result.findings.length > 0 && (
            <CollapsibleSection id="FN" label="Findings" meta={`${result.findings.length} total`} icon={AlertTriangle}>
              <div className="grid gap-3 md:grid-cols-2">
                {result.findings.map((f, i) => (
                  <EvidenceCard
                    key={i}
                    severity={f.severity === "high" ? "destructive" : f.severity === "medium" ? "warning" : "info"}
                    title={f.title}
                    reason={f.detail}
                    action={f.recommendation}
                    limitation="Static analysis indicator — requires analyst validation."
                  />
                ))}
              </div>
            </CollapsibleSection>
          )}

          {/* Export */}
          <Panel title="Export" icon={Download}>
            <div className="flex flex-wrap gap-2">
              <button
                onClick={() => {
                  const lines = [
                    `# Static Attachment Report`,
                    `**File:** \`${result.metadata.filename}\``,
                    `**Risk Score:** ${result.summary.score}/100`,
                    `**Rating:** ${result.summary.rating}`,
                    `**Generated:** ${new Date().toISOString()}`,
                    "", "## File Identity",
                    `- Type: ${result.file_type.magic_type}`,
                    `- Size: ${formatSize(result.metadata.size_bytes)}`,
                    `- Extension: ${result.file_type.extension || "—"}`,
                    `- Entropy: ${result.entropy}`,
                    "", "## Hashes",
                    `- MD5: ${result.hashes.md5}`,
                    `- SHA-1: ${result.hashes.sha1}`,
                    `- SHA-256: ${result.hashes.sha256}`,
                    `- SHA-512: ${result.hashes.sha512}`,
                  ];
                  if (result.suspicious_strings.length) {
                    lines.push("", "## Suspicious Strings", ...result.suspicious_strings.map((s) => `- [${s.severity.toUpperCase()}] ${s.keyword} — ${s.detail}`));
                  }
                  const md = lines.join("\n");
                  const blob = new Blob([md], { type: "text/markdown" });
                  const url = URL.createObjectURL(blob);
                  const a = document.createElement("a");
                  a.href = url; a.download = `attachment-report-${result.hashes.sha256.slice(0, 8)}.md`;
                  a.click(); URL.revokeObjectURL(url);
                }}
                className="inline-flex items-center gap-1.5 rounded border border-primary/40 bg-primary/10 px-2.5 py-1.5 text-mono text-[10px] uppercase tracking-widest text-primary transition-all hover:bg-primary/20 hover:shadow-[0_0_12px_-2px_hsl(var(--primary)/0.45)]"
              >
                <Download className="h-3 w-3" /> Download Markdown Report
              </button>
            </div>
          </Panel>

          <SendToRow targets={[
            { label: "Detection & MITRE", to: "/detection", icon: ShieldAlert },
            { label: "Logs & Alerts", to: "/logs", icon: Database },
            { label: "Case Notebook", to: "/case", icon: ArrowRight },
          ]} />
        </div>
      )}
    </PageShell>
  );
}
