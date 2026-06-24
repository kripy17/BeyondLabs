import { useRef, useState } from "react"
import {
  AlertTriangle,
  ArrowRight,
  Clipboard,
  Copy,
  Info,
  Database,
  Download,
  Eraser,
  FileSearch,
  FileText,
  Scan,
  Loader2,
  MailWarning,
  Radar,
  RefreshCw,
  Route,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react"
import { safeAnalyzeUrl } from "../../api/backend"
import SendToActions from "../../components/investigation/SendToActions"
import { copyText, downloadText } from "../../lib/domUtils"
import { WorkbenchHeader, WorkbenchPage } from "../../components/layout/WorkbenchShell"
import {
  PHISHING_SAMPLES,
  analyzeEmailLocal,
  mergeUrlMetadata,
  parseHeaderMap,
} from "../../lib/phishingTriageEngine"

const PENDING_KEY = "beyondarch.pendingArtifact"
const MODE_LABELS = {
  technical: "Technical Analysis",
  triage: "SOC Triage",
}

function readPendingArtifact() {
  try {
    const raw = window.localStorage.getItem(PENDING_KEY)
    if (!raw) return null
    window.localStorage.removeItem(PENDING_KEY)
    return JSON.parse(raw)
  } catch {
    return null
  }
}

function pendingArtifactToInput(artifact) {
  if (!artifact) return ""
  if (artifact.rawEmail) return String(artifact.rawEmail)
  if (artifact.email) return String(artifact.email)
  if (artifact.content) return String(artifact.content)
  if (artifact.body) return String(artifact.body)
  if (artifact.value) return String(artifact.value)
  return ""
}

function storePendingArtifact(payload) {
  try {
    window.localStorage.setItem(PENDING_KEY, JSON.stringify({ ...payload, created_at: new Date().toISOString() }))
  } catch {
    // Ignore storage failure.
  }
}

function safeValue(value, fallback = "N/A") {
  if (value === 0) return "0"
  if (value === false) return "false"
  if (typeof value === "object" && value !== null) return value
  if (Array.isArray(value)) return value.length ? value.join(", ") : fallback
  const text = String(value ?? "").trim()
  return text || fallback
}

function itemValue(item) {
  return item?.normalized || item?.value || item || ""
}

function truncateMiddle(value = "", limit = 96) {
  const text = String(value || "")
  if (text.length <= limit) return text
  const head = Math.ceil((limit - 3) / 2)
  const tail = Math.floor((limit - 3) / 2)
  return `${text.slice(0, head)}...${text.slice(-tail)}`
}

function emailDomainLabel(value = "") {
  return value.match(/@([^>\s]+)/)?.[1]?.replace(/[),.;]+$/g, "") || "N/A"
}

function authTone(value = "") {
  const clean = String(value || "").toLowerCase()
  if (["pass", "present"].includes(clean)) return "good"
  if (["fail", "softfail", "none", "missing"].includes(clean)) return "bad"
  if (["neutral", "unknown"].includes(clean)) return "warn"
  return "neutral"
}

function severityTone(severity = "") {
  const clean = String(severity).toLowerCase()
  if (["critical", "high"].includes(clean)) return "bad"
  if (["medium", "moderate"].includes(clean)) return "warn"
  if (["low"].includes(clean)) return "info"
  return "neutral"
}

function riskTone(score = 0) {
  if (score >= 85) return "bad"
  if (score >= 60) return "warn"
  if (score >= 30) return "info"
  return "good"
}

function compactIocText(result) {
  if (!result) return ""
  const lines = []
  if (result.iocs.urls.length) lines.push("URLs", ...result.iocs.urls.map((item) => item.defanged || item.normalized))
  if (result.iocs.domains.length) lines.push("Domains", ...result.iocs.domains.map(itemValue))
  if (result.iocs.ips.length) lines.push("IPs", ...result.iocs.ips.map(itemValue))
  if (result.iocs.hashes.length) lines.push("Hashes", ...result.iocs.hashes.map(itemValue))
  if (result.iocs.emails.length) lines.push("Emails", ...result.iocs.emails.map(itemValue))
  return lines.join("\n")
}

function attachmentText(result) {
  return (result?.attachments || [])
    .map((item) => [item.filename, ...(item.signals || [])].filter(Boolean).join(" — "))
    .join("\n")
}

function firstDomainFromResult(result) {
  return result?.iocs?.domains?.[0]?.normalized || result?.iocs?.domains?.[0]?.value || result?.url_enrichment?.[0]?.final_host || result?.urls?.[0]?.host || ""
}

function composeTriageSummary(result) {
  const p = result.professional || {}
  return p.analyst_summary || `${result.decision.disposition}. Primary concern: ${result.decision.primary_concern}. Next action: ${result.decision.next_action}`
}

function composePayload(result, rawInput, mode) {
  return {
    type: "email",
    title: result.headers?.subject || result.professional?.outcome || "Phishing triage result",
    value: rawInput,
    summary: mode === "triage" ? composeTriageSummary(result) : `${result.headers?.subject || "Email"} · SPF ${result.headers?.authentication?.spf}, DKIM ${result.headers?.authentication?.dkim}, DMARC ${result.headers?.authentication?.dmarc}.`,
    confidence: result.risk?.confidence || result.professional?.confidence || "unknown",
    tags: ["phishing", result.risk?.level || "email", mode],
    raw: result.markdown || rawInput,
  }
}

function NeoButton({ children, variant = "light", className = "", ...props }) {
  const variantAttr = variant === "primary" ? { "data-accent": "" } : variant === "danger" ? { "data-rose": "" } : {}
  return <button type="button" className={`p-btn ${className}`} {...variantAttr} {...props}>{children}</button>
}

function Badge({ children, tone = "neutral" }) {
  const toneAttr = tone === "bad" ? { "data-rose": "" } : tone === "good" ? { "data-emerald": "" } : tone === "violet" ? { "data-accent": "" } : {}
  return <span className="p-badge" {...toneAttr}>{children}</span>
}

function MetricCard({ label, value, tone = "neutral", helper }) {
  const toneAttr = tone === "bad" ? { "data-rose": "" } : tone === "violet" ? { "data-accent": "" } : {}
  return (
    <article className="p-metric" {...toneAttr}>
      <div className="p-metric-label">{label}</div>
      <div className="p-metric-value">{safeValue(value)}</div>
      {helper ? <div style={{ fontSize: "0.65rem", color: "var(--clr-text-sub)", marginTop: "0.15rem" }}>{helper}</div> : null}
    </article>
  )
}

function LoadingSkeleton() {
  return (
    <section className="p-skeleton">
      <div className="p-skeleton-verdict">
        <div className="p-skeleton-verdict-hd">
          <div className="p-skeleton-score" />
          <div className="p-skeleton-verdict-text">
            <div className="p-skeleton-line" style={{ width: "40%" }} />
            <div className="p-skeleton-line" style={{ width: "60%" }} />
          </div>
        </div>
      </div>
      <div className="p-skeleton-pair">
        <div className="p-skeleton-card">
          <div className="p-skeleton-card-hd"><div className="p-skeleton-line" style={{ width: "35%" }} /></div>
          <div className="p-skeleton-body">
            <div className="p-skeleton-line" style={{ width: "90%" }} />
            <div className="p-skeleton-line" style={{ width: "65%" }} />
            <div className="p-skeleton-line" style={{ width: "80%" }} />
          </div>
        </div>
        <div className="p-skeleton-card">
          <div className="p-skeleton-card-hd"><div className="p-skeleton-line" style={{ width: "30%" }} /></div>
          <div className="p-skeleton-body">
            <div className="p-skeleton-line" style={{ width: "75%" }} />
            <div className="p-skeleton-line" style={{ width: "55%" }} />
            <div className="p-skeleton-line" style={{ width: "85%" }} />
          </div>
        </div>
      </div>
      <div className="p-skeleton-card">
        <div className="p-skeleton-card-hd"><div className="p-skeleton-line" style={{ width: "40%" }} /></div>
        <div className="p-skeleton-body">
          <div className="p-skeleton-line" style={{ width: "95%" }} />
          <div className="p-skeleton-line" style={{ width: "60%" }} />
          <div className="p-skeleton-line" style={{ width: "80%" }} />
          <div className="p-skeleton-line" style={{ width: "45%" }} />
        </div>
      </div>
    </section>
  )
}

function EmptyPreview() {
  const cards = [
    ["Sender Identity", "From, Reply-To, Return-Path, display-name mismatches"],
    ["Header Authentication", "SPF, DKIM, DMARC, Received path, auth results"],
    ["Extracted URLs", "Visible text, actual href, defanged targets"],
    ["Lure Signals", "Urgency, credential request, brand impersonation"],
    ["Case Findings", "Report-ready summary, limitations, next steps"],
  ]
  return (
    <section>
      <p className="p-side-hd" style={{ border: "none", marginBottom: "0.5rem", fontSize: "0.65rem" }}>
        Awaiting Analysis — Expected Output Structure
      </p>
      <div className="p-expected-grid">
        {cards.map(([title, text]) => (
          <article key={title} className="p-expected-card p-card">
            <span>{title}</span>
            <p>{text}</p>
          </article>
        ))}
      </div>
    </section>
  )
}

function EmptyTriageState({ rawEmail, setRawEmail, mode, setMode, sampleKey, setSampleKey, loadSample, clearAll, loadFile, fileRef, runAnalysis, loadingMode, error, notice }) {
  const sampleOptions = Object.keys(PHISHING_SAMPLES)
  return (
    <>
      <div className="p-input-grid">
        <article className="p-card p-intake">
          <div className="p-intake-hd">
            <MailWarning />Phishing Triage Workbench
          </div>
          <div className="p-intake-body">
            <label>Artifact Input (Raw Headers, EML Content, or Proxy Logs)</label>
            <textarea
              value={rawEmail}
              onChange={(event) => setRawEmail(event.target.value)}
              placeholder={`Paste raw email content, headers, body text, or suspicious URLs here...\n\nExamples:\nReturn-Path: <spoofed@domain.com>\nReceived: from mail.attacker.xyz...\nSubject: Urgent Action Required: Account Locked`}
            />
          </div>
          <div className="p-intake-ft">
            <div className="p-intake-ft-left">
              <select value={sampleKey} onChange={(event) => setSampleKey(event.target.value)} aria-label="Sample lure">
                {sampleOptions.map((key) => <option key={key} value={key}>{key.replace(/([A-Z])/g, " $1").replace(/^./, (char) => char.toUpperCase())}</option>)}
              </select>
              <NeoButton variant="light" onClick={() => loadSample(sampleKey)}><FileText />Load sample</NeoButton>
              <NeoButton variant="light" onClick={clearAll}><Eraser />Clear</NeoButton>
            </div>
            <div className="p-intake-ft-right">
              <span style={{ fontSize: "0.65rem", fontFamily: "JetBrains Mono, monospace", color: "var(--clr-text-sub)", display: "flex", alignItems: "center", gap: "0.25rem" }}>
                <Info />Local-first secure sandbox
              </span>
              <NeoButton variant="primary" onClick={() => runAnalysis(mode)} disabled={Boolean(loadingMode)}>
                {loadingMode ? <Loader2 style={{ animation: "spin 1s linear infinite" }} /> : <Radar />}
                {loadingMode ? "Analyzing..." : "Analyze Email"}
              </NeoButton>
            </div>
          </div>
        </article>

        <aside style={{ display: "flex", flexDirection: "column", gap: "0.85rem" }}>
          <article className="p-side-card">
            <div className="p-side-hd"><ShieldCheck />Safety &amp; Logic</div>
            <div style={{ display: "flex", flexDirection: "column", gap: "0.75rem" }}>
              <div>
                <label style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "0.6rem", fontWeight: 700, textTransform: "uppercase", color: "var(--clr-text-sub)", display: "block", marginBottom: "0.35rem" }}>Analysis Mode</label>
                <select
                  value={mode}
                  onChange={(event) => setMode(event.target.value)}
                  style={{ width: "100%", border: "2px solid #000", padding: "0.35rem", fontFamily: "JetBrains Mono, monospace", fontSize: "0.7rem", background: "var(--p-card)", cursor: "pointer", boxShadow: "2px 2px 0 0 #000" }}
                >
                  <option value="triage">SOC Triage</option>
                  <option value="technical">Technical Analysis</option>
                </select>
              </div>
              <div style={{ display: "flex", flexDirection: "column", alignItems: "flex-start", gap: "0.3rem", padding: "0.45rem", border: "2px solid #000", background: "var(--p-surface)" }}>
                <label style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "0.68rem", fontWeight: 700, display: "flex", alignItems: "center", gap: "0.35rem", cursor: "pointer" }}>
                  <input type="checkbox" defaultChecked style={{ width: "1rem", height: "1rem", border: "2px solid #000" }} />
                  Scan URL Reputation
                </label>
                <label style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "0.68rem", fontWeight: 700, display: "flex", alignItems: "center", gap: "0.35rem", cursor: "pointer" }}>
                  <input type="checkbox" defaultChecked style={{ width: "1rem", height: "1rem", border: "2px solid #000" }} />
                  Verify DKIM/SPF
                </label>
              </div>
            </div>
          </article>

          <div className="p-side-card">
            <div className="p-side-hd"><Radar />Pipeline Status</div>
            <div style={{ display: "flex", flexDirection: "column", gap: "0.35rem" }}>
              <div style={{ display: "flex", justifyContent: "space-between", fontFamily: "JetBrains Mono, monospace", fontSize: "0.68rem" }}>
                <span>Parser Engine</span>
                <span style={{ display: "flex", alignItems: "center", gap: "0.3rem", fontWeight: 700, color: "#10b981" }}><span style={{ width: 6, height: 6, background: "#10b981", display: "inline-block" }} />READY</span>
              </div>
              <div style={{ display: "flex", justifyContent: "space-between", fontFamily: "JetBrains Mono, monospace", fontSize: "0.68rem" }}>
                <span>Local Engine</span>
                <span style={{ display: "flex", alignItems: "center", gap: "0.3rem", fontWeight: 700, color: "#a86100" }}><span style={{ width: 6, height: 6, background: "#a86100", display: "inline-block" }} />IDLE</span>
              </div>
            </div>
          </div>

          <div className="p-privacy-card">
            <strong>Local session only</strong>
            <p>Parsing runs locally first. External enrichment happens only when a workflow explicitly requests it.</p>
          </div>

          {(error || notice) ? <div className={`p-notice ${error ? 'p-notice' : ''}`} data-tone={error ? "error" : undefined}><AlertTriangle />{error || notice}</div> : null}
        </aside>
      </div>
      <EmptyPreview />
    </>
  )
}

function ResultHeader({ result, mode, setMode, runAnalysis, loadingMode, clearAll }) {
  return (
    <div className="p-result-hd">
      <div className="p-result-hd-left">
        <div className="p-result-hd-title">
          <span className="p-badge" data-accent>PHISHING</span>
          <h1>Investigation: #{result.decision?.attack_type?.slice(0, 3)?.toUpperCase() || "TRG"}-{result.risk.score || 0}-BA</h1>
        </div>
        <p style={{ fontSize: "0.78rem", color: "var(--clr-text-sub)", display: "flex", alignItems: "center", gap: "0.35rem" }}>
          Detected from manual intake · Risk: {result.risk.level} · Score: {result.risk.score}/100
        </p>
      </div>
      <div className="p-mode-tabs" role="tablist" aria-label="Result mode">
        <button type="button" data-active={mode === "triage" ? "" : undefined} onClick={() => setMode("triage")}>SOC Triage</button>
        <button type="button" data-active={mode === "technical" ? "" : undefined} onClick={() => setMode("technical")}>Technical Analysis</button>
      </div>
      <div className="p-result-hd-acts">
        <NeoButton variant="light" onClick={() => runAnalysis(mode)} disabled={Boolean(loadingMode)}>
          {loadingMode ? <Loader2 style={{ animation: "spin 1s linear infinite" }} /> : <RefreshCw />}
          Re-analyze
        </NeoButton>
        <NeoButton variant="danger" onClick={clearAll}><Eraser />Clear</NeoButton>
      </div>
    </div>
  )
}

function ResultMetrics({ result, mode }) {
  const auth = result.headers.authentication
  if (mode === "technical") {
    return (
      <section className="p-metric-row">
        <MetricCard label="Extracted URLs" value={result.iocs.urls.length} tone="violet" />
        <MetricCard label="Sender mismatches" value={result.sender_alignment.mismatches.length} tone={result.sender_alignment.mismatches.length ? "bad" : "good"} />
        <MetricCard label="Header issues" value={[auth.spf, auth.dkim, auth.dmarc].filter((value) => ["fail", "softfail", "none", "missing"].includes(String(value).toLowerCase())).length} tone="bad" />
        <MetricCard label="Total IOCs" value={result.iocs.urls.length + result.iocs.domains.length + result.iocs.ips.length + result.iocs.hashes.length + result.iocs.emails.length} tone="violet" />
        <MetricCard label="Attachments" value={result.attachments.length} tone={result.attachments.length ? "bad" : "neutral"} />
      </section>
    )
  }
  return (
    <section className="p-metric-row">
      <MetricCard label="Verdict" value={result.professional?.outcome || result.decision.disposition} tone={riskTone(result.risk.score)} />
      <MetricCard label="Confidence" value={result.risk.confidence || `${result.risk.confidence_score}%`} tone="violet" />
      <MetricCard label="Sender risk" value={result.sender_alignment.mismatches.length ? "Mismatch" : "Aligned"} tone={result.sender_alignment.mismatches.length ? "bad" : "good"} />
      <MetricCard label="URL risk" value={`${result.urls.length} URL(s)`} tone={result.urls.length ? "bad" : "neutral"} />
      <MetricCard label="Report ready" value="Yes" helper="Markdown export available" tone="good" />
    </section>
  )
}

function AuthResults({ result }) {
  const auth = result.headers.authentication
  const rows = [
    ["SPF", auth.spf, "Envelope sender authorization"],
    ["DKIM", auth.dkim, "Cryptographic signature state"],
    ["DMARC", auth.dmarc, "From-domain policy alignment"],
  ]
  return (
    <article className="p-card">
      <div className="p-card-hd"><ShieldCheck />Authentication Results</div>
      <div style={{ padding: "0.75rem" }}>
        {rows.map(([label, value]) => {
          const tone = authTone(value)
          return (
            <div key={label} className="p-auth-row" data-rose={tone === "bad" ? "" : undefined} data-emerald={tone === "good" ? "" : undefined}>
              <span style={{ fontWeight: 700 }}>{label}</span>
              <span>{String(value).toUpperCase()}</span>
            </div>
          )
        })}
      </div>
      <div style={{ padding: "0.5rem 0.75rem 0.75rem", fontFamily: "JetBrains Mono, monospace", fontSize: "0.82rem", color: "var(--clr-text-sub)", borderTop: "2px solid var(--p-line)" }}>
        <span style={{ display: "block", marginBottom: "0.25rem", fontWeight: 700, textTransform: "uppercase", fontSize: "0.78rem" }}>Received path verification</span>
        {result.headers.received.length ? (
          result.headers.received.slice(0, 3).map((line, index) => <div key={line} style={{ marginBottom: "0.15rem" }}>[{index}] {line}</div>)
        ) : <div>[local] No Received header hops parsed. Upload full EML for relay path verification.</div>}
      </div>
    </article>
  )
}

function SenderIdentity({ result }) {
  const mismatches = result.sender_alignment?.mismatches || []
  return (
    <article className="p-card">
      <div className="p-card-hd"><ShieldAlert />Sender Identity</div>
      <div className="p-field-grid">
        <div className="p-field-row">
          <span className="p-field-row-label">From</span>
          <span className="p-field-row-value">{result.headers.from || "—"}</span>
        </div>
        <div className="p-field-row">
          <span className="p-field-row-label">Subject</span>
          <span className="p-field-row-value" style={{ fontWeight: 600 }}>{result.headers.subject || "—"}</span>
        </div>
        <div className="p-field-row">
          <span className="p-field-row-label">Reply-To</span>
          <span className="p-field-row-value" data-rose={mismatches.some((item) => item.includes("Reply-To")) || undefined}>{result.headers.reply_to || "—"}</span>
        </div>
        <div className="p-field-row">
          <span className="p-field-row-label">Return-Path</span>
          <span className="p-field-row-value" data-rose={mismatches.some((item) => item.includes("Return-Path")) || undefined}>{result.headers.return_path || "—"}</span>
        </div>
        <div className="p-field-row">
          <span className="p-field-row-label">From domain</span>
          <span className="p-field-row-value">{emailDomainLabel(result.headers.from)}</span>
        </div>
        {result.headers.sending_ips?.length ? (
          <div className="p-mini-box">
            <strong style={{ display: "block", marginBottom: "0.15rem" }}>Originating infrastructure</strong>
            <span>IPs: {result.headers.sending_ips.map(itemValue).join(", ")}</span>
            {result.headers.sending_domains?.length ? <span>Domains: {result.headers.sending_domains.map(itemValue).join(", ")}</span> : null}
          </div>
        ) : null}
        {mismatches.length ? mismatches.slice(0, 4).map((item) => (
          <div key={item} className="p-auth-row" data-rose="">
            <span style={{ fontSize: "0.82rem" }}>{item}</span>
            <AlertTriangle style={{ width: "0.85rem", height: "0.85rem", flexShrink: 0 }} />
          </div>
        )) : null}
      </div>
    </article>
  )
}

function EvidenceContext({ result }) {
  const rows = result.professional?.evidence_rows?.length ? result.professional.evidence_rows : result.findings
  return (
    <article className="p-card" data-variant="evidence">
      <div className="p-card-hd"><FileSearch />Evidence Context</div>
      <div className="p-evidence-strip">
        {rows.slice(0, 10).map((item, index) => (
          <div key={`${item.signal || item.name}-${index}`} className="p-evidence-card" data-rose={severityTone(item.severity) === "bad" ? "" : undefined} data-gold={severityTone(item.severity) === "warn" ? "" : undefined} data-emerald={severityTone(item.severity) === "good" ? "" : undefined}>
            <div className="p-evidence-card-hd">
              <span className="p-evidence-ref">EV-{String(index + 1).padStart(3, "0")}</span>
              <Badge tone={severityTone(item.severity)}>{item.confidence || item.severity || "evidence"}</Badge>
            </div>
            <strong>{item.signal || item.name}</strong>
            <p style={{ fontSize: "0.7rem", color: "var(--clr-text-sub)", margin: "0.15rem 0 0" }}>{item.evidence || item.meaning || item.why}</p>
            {item.action ? <small style={{ fontSize: "0.8rem", color: "var(--p-gold)", marginTop: "0.15rem" }}>Action: {item.action}</small> : null}
          </div>
        ))}
      </div>
    </article>
  )
}

function UrlMetadataReview({ result, onSendArtifact }) {
  const enriched = result.url_enrichment || []
  const mismatches = result.body?.mismatched_links || []
  return (
    <article className="p-card">
      <div className="p-card-hd"><Scan />URL & Destination Review</div>
      <div style={{ padding: "0.75rem" }}>
        <div style={{ marginBottom: "0.75rem" }}>
          <span className="p-section-label">Extracted URL inventory</span>
          <div className="p-ioc-strip">
            {result.urls.length ? result.urls.map((url, index) => (
              <div key={`${url.normalized}-${index}`} className="p-ioc-card" data-accent>
                <span className="p-ioc-value">{url.defanged || url.normalized}</span>
                <span className="p-ioc-meta">Host: {url.host || "N/A"} · Root: {url.root_domain || "N/A"}</span>
                {(url.signals || []).slice(0, 3).map((signal) => <Badge key={signal.label} tone={severityTone(signal.severity)}>{signal.label}</Badge>)}
                <NeoButton variant="secondary" size="small" onClick={() => onSendArtifact?.("safe-url-analyzer", { type: "url", value: url.normalized })}>Send to Safe URL</NeoButton>
              </div>
            )) : <span style={{ fontSize: "0.7rem", color: "var(--clr-text-sub)" }}>No URL inventory extracted.</span>}
          </div>
        </div>
        <div>
          <span className="p-section-label">Guarded metadata / mismatch context</span>
          <div className="p-ioc-strip">
            {enriched.length ? enriched.map((item, index) => (
              <div key={`${item.original_url}-${index}`} className="p-ioc-card" data-rose={item.verdict === "malicious" ? "" : undefined} data-gold={item.verdict === "suspicious" ? "" : undefined}>
                <span className="p-ioc-value">{item.original_url || "N/A"}</span>
                <span className="p-ioc-meta">{item.verdict || "metadata"} → {item.final_url || item.final_host || "no final URL"}</span>
                <small>{item.blocked_reason || item.analysis?.category || item.title || "No additional destination metadata."}</small>
              </div>
            )) : <div className="p-ioc-card"><span className="p-ioc-value">Static-first</span><span className="p-ioc-meta">No guarded URL metadata was fetched for this mode or sample.</span><small>Use Safe URL Analyzer when destination metadata is required.</small></div>}
            {mismatches.map((item, index) => (
              <div key={`${item.href}-${index}`} className="p-ioc-card" data-rose>
                <span className="p-ioc-value">{item.text || "visible link"} → {item.href}</span>
                <span className="p-ioc-meta">Visible text and actual destination differ.</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </article>
  )
}

function EvidenceChainPanel({ result }) {
  const chain = result.evidence_chain || []
  return (
    <article className="p-card">
      <div className="p-card-hd"><Route />Evidence chain</div>
      <div className="p-chain-grid">
        {chain.length ? chain.map((stage, index) => (
          <div key={`${stage.stage}-${index}`} className="p-chain-node" data-rose={stage.state === "breach" ? "" : undefined} data-gold={stage.state === "suspicious" ? "" : undefined} data-emerald={stage.state === "clean" ? "" : undefined}>
            <span className="p-chain-step">{String(index + 1).padStart(2, "0")}</span>
            <span className="p-chain-label">{stage.stage}</span>
            <span className="p-chain-detail">{stage.detail}</span>
          </div>
        )) : <div style={{ padding: "0.75rem", fontSize: "0.7rem", color: "var(--clr-text-sub)" }}>No evidence chain generated.</div>}
      </div>
    </article>
  )
}

function GuidanceAndHunts({ result }) {
  const guidance = result.guidance || { immediate: [], investigation: [], containment: [] }
  const groups = [
    ["Immediate", guidance.immediate],
    ["Investigation", guidance.investigation],
    ["Containment", guidance.containment],
  ]
  return (
    <article className="p-card">
      <div className="p-card-hd"><ShieldCheck />Guidance & Hunts</div>
      <div style={{ padding: "0.75rem" }}>
        {groups.map(([title, items]) => items?.length ? (
          <div key={title} style={{ marginBottom: "0.5rem" }}>
            <span className="p-section-label">{title}</span>
            <ul className="p-signal-list">
              {items.map((item) => <li key={item}>{item}</li>)}
            </ul>
          </div>
        ) : null)}
      </div>
      {result.hunting_queries?.length ? (
        <details style={{ padding: "0.5rem 0.75rem 0.75rem", borderTop: "1px solid var(--p-line)" }}>
          <summary style={{ fontSize: "0.78rem", fontWeight: 600, cursor: "pointer", textTransform: "uppercase" }}>Generated hunting queries ({result.hunting_queries.length})</summary>
          <div style={{ marginTop: "0.35rem" }}>
            {result.hunting_queries.map((item) => (
              <div key={item.name} style={{ marginBottom: "0.35rem" }}>
                <strong style={{ fontSize: "0.8rem", display: "block" }}>{item.name}</strong>
                <pre style={{ fontSize: "0.82rem", margin: 0 }}>{item.query}</pre>
              </div>
            ))}
          </div>
        </details>
      ) : null}
      {result.classification?.limitations?.length ? (
        <div className="p-mini-box" style={{ margin: "0.5rem 0.75rem 0.75rem" }}>
          {(result.classification.limitations || []).map((item) => <span key={item}>• {item}</span>)}
        </div>
      ) : null}
    </article>
  )
}

function SenderMatrixPanel({ result }) {
  const rows = result.professional?.sender_matrix?.rows || []
  if (!rows.length) return null
  return (
    <article className="p-card">
      <div className="p-card-hd"><MailWarning />Sender & Identity Matrix</div>
      <div style={{ padding: "0.75rem" }}>
        {rows.map((row) => (
          <div key={row.field} className="p-auth-row" data-emerald={row.aligned ? "" : undefined} data-rose={!row.aligned ? "" : undefined}>
            <span style={{ fontWeight: 700 }}>{row.field}</span>
            <span>{row.value}</span>
            <small style={{ gridColumn: "1 / -1", fontSize: "0.78rem", color: "var(--clr-text-sub)" }}>{row.domain} · {row.meaning}</small>
          </div>
        ))}
      </div>
    </article>
  )
}

function PhishingEngineSnapshot({ result, mode }) {
  const auth = result.headers.authentication || {}
  const pro = result.professional || {}
  const urlRollup = pro.url_rollup || {}
  const sourceCount = result.risk?.independent_sources || pro.evidence_rows?.length || result.findings.length
  const gaps = pro.confidence_gaps || result.classification?.limitations || []
  const actions = [...(result.guidance?.immediate || []), ...(result.guidance?.investigation || [])].slice(0, 5)
  return (
    <article className="p-card" data-variant="engine">
      <div className="p-card-hd"><Database />Engine Output Snapshot</div>
      <div className="p-engine-grid">
        <div className="p-engine-cell">
          <span className="p-section-label">Message profile</span>
          <span style={{ fontWeight: 600, fontSize: "0.85rem" }}>{result.headers.subject || "No subject parsed"}</span>
          <small style={{ fontSize: "0.78rem", color: "var(--clr-text-sub)" }}>From: {result.headers.from || "N/A"} · Mode: {MODE_LABELS[mode]}</small>
        </div>
        <div className="p-engine-cell">
          <span className="p-section-label">Authentication</span>
          <span style={{ fontWeight: 600, fontSize: "0.85rem" }}>{auth.spf || "missing"} / {auth.dkim || "missing"} / {auth.dmarc || "missing"}</span>
          <small style={{ fontSize: "0.78rem", color: "var(--clr-text-sub)" }}>SPF · DKIM · DMARC</small>
        </div>
        <div className="p-engine-cell">
          <span className="p-section-label">Extraction</span>
          <span style={{ fontWeight: 600, fontSize: "0.85rem" }}>{result.iocs.urls.length} URLs · {result.iocs.domains.length} domains · {result.iocs.ips.length} IPs</span>
          <small style={{ fontSize: "0.78rem", color: "var(--clr-text-sub)" }}>{result.iocs.emails.length} emails · {result.iocs.hashes.length} hashes</small>
        </div>
        <div className="p-engine-cell">
          <span className="p-section-label">Decision basis</span>
          <span style={{ fontWeight: 600, fontSize: "0.85rem" }}>{result.risk.score}/100 · {result.risk.confidence}</span>
          <small style={{ fontSize: "0.78rem", color: "var(--clr-text-sub)" }}>{sourceCount} evidence source(s) · {urlRollup.summary || result.decision.reliability}</small>
        </div>
      </div>
      <div style={{ padding: "0.75rem", display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0.75rem", borderTop: "1px solid var(--p-line)" }}>
        <div>
          <span className="p-section-label">Next actions</span>
          <ul className="p-signal-list">{actions.length ? actions.map((item) => <li key={item}>{item}</li>) : <li style={{ listStyle: "none", padding: 0 }}>Review and preserve evidence</li>}</ul>
        </div>
        <div>
          <span className="p-section-label">Limitations</span>
          <ul className="p-signal-list">{gaps.length ? gaps.slice(0, 5).map((item) => <li key={item}>{item}</li>) : <li style={{ listStyle: "none", padding: 0 }}>No confidence gaps returned</li>}</ul>
        </div>
      </div>
    </article>
  )
}

function MessageStructurePanel({ result }) {
  const rows = [
    ["Subject", result.headers.subject],
    ["From", result.headers.from],
    ["Reply-To", result.headers.reply_to],
    ["Return-Path", result.headers.return_path],
    ["To", result.headers.to],
    ["Message-ID", result.headers.message_id],
    ["Authentication-Results", result.headers.authentication_results?.join(" | ")],
    ["Received-SPF", result.headers.received_spf?.join(" | ")],
    ["Received hops", result.headers.received?.length ? `${result.headers.received.length} hop(s)` : "None parsed"],
  ].filter(([, value]) => Array.isArray(value) ? value.length : Boolean(value))
  return (
    <article className="p-card">
      <div className="p-card-hd"><MailWarning />Message Structure</div>
      <div style={{ padding: "0.75rem" }}>
        {rows.map(([label, value]) => (
          <div key={label} className="p-field-row">
            <span className="p-field-row-label">{label}</span>
            <span className="p-field-row-value">{Array.isArray(value) ? value.join(" | ") : String(value)}</span>
          </div>
        ))}
      </div>
    </article>
  )
}

function ScoreBreakdownPanel({ result }) {
  const score = result.professional?.score_breakdown
  if (!score) return null
  const rows = score.rows || []
  const dampeners = score.dampeners || []
  return (
    <article className="p-card" data-variant="score">
      <div className="p-card-hd"><AlertTriangle />Risk Score Breakdown</div>
      <p style={{ padding: "0 0.75rem", fontSize: "0.85rem", color: "var(--clr-text-sub)", margin: "0.5rem 0" }}>{score.explanation}</p>
      <div style={{ padding: "0 0.75rem 0.75rem" }}>
        {rows.length ? rows.map((row, index) => (
          <div key={`${row.signal}-${index}`} className="p-score-row" data-rose={severityTone(row.severity) === "bad" ? "" : undefined} data-gold={severityTone(row.severity) === "warn" ? "" : undefined}>
            <span className="p-score-pts">+{row.points || 0}</span>
            <span className="p-score-signal">{row.signal}</span>
            <span className="p-score-note">{row.evidence}</span>
            {row.analyst_note ? <span className="p-score-note" style={{ color: "var(--clr-text-sub)" }}>{row.analyst_note}</span> : null}
          </div>
        )) : <span style={{ fontSize: "0.7rem", color: "var(--clr-text-sub)" }}>No weighted score drivers returned.</span>}
      </div>
      {dampeners.length ? (
        <div className="p-mini-box" style={{ margin: "0 0.75rem 0.75rem" }}>
          {dampeners.map((item) => <span key={item.signal}>{item.points} {item.signal}: {item.reason}</span>)}
        </div>
      ) : null}
    </article>
  )
}

function FullArtifactInventory({ result, onSendArtifact, onCopy }) {
  const groups = [
    ["URLs", result.iocs.urls],
    ["Domains", result.iocs.domains],
    ["IPs", result.iocs.ips],
    ["Emails", result.iocs.emails],
    ["Hashes", result.iocs.hashes],
    ["Attachments", result.attachments],
  ]
  return (
    <article className="p-card">
      <div className="p-card-hd"><Database />Artifact Inventory</div>
      <div className="p-ioc-col-grid">
        {groups.map(([label, items]) => (
          <div key={label} className="p-ioc-col">
            <div className="p-ioc-col-hd">
              <strong style={{ textTransform: "uppercase", fontSize: "0.78rem" }}>{label}</strong>
              <span className="p-badge" data-mono>{items.length}</span>
            </div>
            <div className="p-ioc-col-body">
              {items.length ? items.slice(0, 6).map((item) => {
                const value = typeof item === "string" ? item : item.defanged || item.normalized || item.filename || item
                const strVal = String(value || "")
                return (
                  <div key={`${label}-${strVal}`} className="p-ioc-col-row">
                    <code style={{ fontSize: "0.82rem", flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={strVal}>{truncateMiddle(strVal, 80)}</code>
                    <div style={{ display: "flex", gap: "0.15rem", flexShrink: 0 }}>
                      {onCopy ? <NeoButton variant="ghost" size="tiny" onClick={() => onCopy(strVal, `${label} artifact`)}><Copy /></NeoButton> : null}
                      {onSendArtifact ? <NeoButton variant="ghost" size="tiny" onClick={() => onSendArtifact("recon-exposure", { type: label.toLowerCase().slice(0, -1), value: strVal })}><ArrowRight /></NeoButton> : null}
                    </div>
                  </div>
                )
              }) : <em style={{ fontSize: "0.82rem", color: "var(--clr-text-sub)" }}>None extracted</em>}
            </div>
          </div>
        ))}
      </div>
    </article>
  )
}

function CompleteFindingRegister({ result, limit = null, title = "Finding register" }) {
  const rows = result.findings || []
  const visibleRows = limit ? rows.slice(0, limit) : rows
  return (
    <article className="p-card" data-variant="findings">
      <div className="p-card-hd"><AlertTriangle />{title}</div>
      <div className="p-evidence-strip">
        {visibleRows.length ? visibleRows.map((finding, index) => (
          <div key={`${finding.name}-${index}`} className="p-evidence-card" data-rose={severityTone(finding.severity) === "bad" ? "" : undefined} data-gold={severityTone(finding.severity) === "warn" ? "" : undefined}>
            <div className="p-evidence-card-hd">
              <span className="p-evidence-ref">F-{String(index + 1).padStart(2, "0")}</span>
              <Badge tone={severityTone(finding.severity)}>{finding.severity || "signal"}</Badge>
              {finding.source ? <small style={{ fontSize: "0.72rem", color: "var(--clr-text-sub)" }}>{finding.source}</small> : null}
            </div>
            <strong>{finding.name}</strong>
            <p style={{ fontSize: "0.7rem", color: "var(--clr-text-sub)", margin: "0.15rem 0 0" }}>{finding.evidence}</p>
            <div className="p-finding-details">
              <span><strong>Why</strong> {finding.why}</span>
              <span><strong>Action</strong> {finding.action}</span>
              {finding.score ? <span><strong>Score</strong> +{finding.score}</span> : null}
            </div>
          </div>
        )) : <span style={{ padding: "0.75rem", display: "block", fontSize: "0.7rem", color: "var(--clr-text-sub)" }}>No weighted findings were generated.</span>}
      </div>
      {limit && rows.length > limit ? <div style={{ padding: "0.5rem 0.75rem 0.75rem", fontSize: "0.78rem", color: "var(--clr-text-sub)" }}>+{rows.length - limit} more findings available in advanced details.</div> : null}
    </article>
  )
}

function FieldRow({ label, value, note, tone, mono }) {
  const color = tone === "bad" ? "var(--p-rose)" : tone === "good" ? "var(--p-emerald)" : tone === "warn" ? "var(--p-gold)" : undefined
  return (
    <div className="p-field-row">
      <span className="p-field-row-label">{label}</span>
      <span className="p-field-row-value" style={{ color, ...(mono ? { fontFamily: "JetBrains Mono, monospace", fontSize: "0.82rem" } : {}) }}>{value}</span>
      {note ? <span style={{ fontSize: "0.78rem", color: "var(--clr-text-sub)", gridColumn: "1 / -1", marginTop: "-0.2rem" }}>{note}</span> : null}
    </div>
  )
}

function TechnicalResults({ result, onSendArtifact, onCopy }) {
  const headerMap = parseHeaderMap(result.split.headers)
  return (
    <section className="p-results">
      <SectionDivider label="Engine output" />

      <div className="p-span-full">
        <PhishingEngineSnapshot result={result} mode="technical" />
      </div>

      <AuthResults result={result} />
      <SenderIdentity result={result} />

      <SectionDivider label="Message structure" />

      <div className="p-span-full">
        <MessageStructurePanel result={result} />
      </div>
      <div className="p-span-full">
        <UrlMetadataReview result={result} onSendArtifact={onSendArtifact} />
      </div>

      <SectionDivider label="Artifacts & findings" />

      <FullArtifactInventory result={result} onSendArtifact={onSendArtifact} onCopy={onCopy} />
      <SenderMatrixPanel result={result} />

      <div className="p-span-full">
        <CompleteFindingRegister result={result} limit={8} title="Prioritized findings" />
      </div>

      <EvidenceContext result={result} />
      <ScoreBreakdownPanel result={result} />

      <SectionDivider label="Actions" />

      <div className="p-span-full">
        <GuidanceAndHunts result={result} />
      </div>

      <article className="p-card p-span-full">
        <div className="p-card-hd"><Route />Technical pivots</div>
        <div className="p-actions-bar">
          <NeoButton variant="secondary" onClick={() => onCopy(compactIocText(result), "IOCs")}><Copy />Copy IOCs</NeoButton>
          <NeoButton variant="secondary" onClick={() => onSendArtifact("recon-exposure", { type: "domain", value: firstDomainFromResult(result) })}>Send domain to Recon</NeoButton>
          {result.urls?.[0]?.normalized ? <NeoButton variant="secondary" onClick={() => onSendArtifact("safe-url-analyzer", { type: "url", value: result.urls[0].normalized })}>Open URL Analyzer</NeoButton> : null}
          {result.attachments.length ? <NeoButton variant="secondary" onClick={() => onSendArtifact("attachment-triage", { type: "attachment-notes", value: attachmentText(result) })}>Send attachments</NeoButton> : null}
        </div>
      </article>

      <details className="p-card p-span-full">
        <summary style={{ padding: "0.85rem", fontWeight: 600, fontSize: "0.85rem", cursor: "pointer" }}>Advanced: findings, chain &amp; raw JSON</summary>
        <div style={{ borderTop: "2px solid var(--p-line)" }}>
          <CompleteFindingRegister result={result} title="Complete finding register" />
          <EvidenceChainPanel result={result} />
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0.5rem", padding: "0.85rem" }}>
            <pre style={{ fontSize: "0.72rem", maxHeight: "24rem", overflow: "auto", margin: 0 }}>{JSON.stringify(result, null, 2)}</pre>
            <pre style={{ fontSize: "0.72rem", maxHeight: "24rem", overflow: "auto", margin: 0 }}>{JSON.stringify(headerMap, null, 2)}</pre>
          </div>
        </div>
      </details>
    </section>
  )
}

function LureSignals({ result }) {
  const themes = result.body.themes || []
  const signals = themes.length ? themes.flatMap((theme) => theme.matches.map((match) => `${theme.theme}: ${match}`)) : []
  return (
    <article className="p-card">
      <div className="p-card-hd"><Radar />Lure Signals</div>
      <div className="p-field-grid">
        {signals.length ? signals.slice(0, 8).map((item) => (
          <div key={item} className="p-auth-row" data-rose>
            <AlertTriangle style={{ width: "0.75rem", height: "0.75rem", flexShrink: 0 }} />
            <span style={{ fontSize: "0.85rem" }}>{item}</span>
          </div>
        )) : <span style={{ padding: "0.75rem", fontSize: "0.82rem", color: "var(--clr-text-sub)" }}>No strong lure keyword extracted.</span>}
        <FieldRow label="Brand mentions" value={result.body.mentioned_brands?.join(", ") || "None extracted"} />
        <FieldRow label="Attachment mentions" value={result.body.attachment_mentions?.map(itemValue).join(", ") || "None extracted"} />
      </div>
    </article>
  )
}

function ImpactPanel({ result }) {
  const guidance = result.guidance || {}
  return (
    <article className="p-card">
      <div className="p-card-hd"><ShieldAlert />Impact Assessment</div>
      <div className="p-field-grid">
        <FieldRow label="What happened" value={result.decision.primary_concern} />
        <FieldRow label="Why it matters" value={result.professional?.confidence_reason || result.decision.reliability} />
        <FieldRow label="Next step" value={result.decision.next_action} />
        <div className="p-mini-box">
          <strong style={{ display: "block", marginBottom: "0.15rem" }}>Immediate handling</strong>
          {(guidance.immediate || []).slice(0, 3).map((item) => <span key={item}>• {item}</span>)}
        </div>
      </div>
    </article>
  )
}

function ReportReadySummary({ result, onCopy }) {
  return (
    <article className="p-card">
      <div className="p-card-hd" style={{ justifyContent: "space-between" }}>
        <span style={{ display: "flex", alignItems: "center", gap: "0.35rem" }}><FileText />Report-ready summary</span>
        <NeoButton variant="primary" onClick={() => onCopy(result.markdown, "Markdown report")}><Copy />Copy Markdown</NeoButton>
      </div>
      <pre style={{ padding: "0.85rem", fontSize: "0.85rem", lineHeight: "1.6", maxHeight: "20rem", overflow: "auto", margin: 0, borderTop: "2px solid var(--p-line)", borderBottom: "2px solid var(--p-line)" }}>{result.markdown}</pre>
      <div style={{ padding: "0.5rem 0.75rem", display: "flex", gap: "0.35rem" }}>
        <NeoButton variant="light" onClick={() => downloadText("phishing-triage-report.md", result.markdown, "text/markdown")}><Download />Download MD</NeoButton>
        <NeoButton variant="light" onClick={() => onCopy(JSON.stringify(result, null, 2), "JSON result")}><Clipboard />Copy JSON</NeoButton>
      </div>
    </article>
  )
}

function SectionDivider({ label }) {
  return (
    <div className="p-section-divider">
      <span>{label}</span>
    </div>
  )
}

function SocTriageResults({ result, onSendArtifact, onCopy, setPage, rawInput, mode }) {
  return (
    <section className="p-results">
      <article className="p-verdict-card p-span-full" data-rose={result.risk.score >= 60 ? "" : undefined} data-gold={result.risk.score >= 30 && result.risk.score < 60 ? "" : undefined} data-emerald={result.risk.score < 30 ? "" : undefined}>
        <div className="p-verdict-hd">
          <div className="p-verdict-hd-left">
            <span className="p-verdict-score">{result.risk.score}</span>
            <div className="p-verdict-text">
              <h2>Likely Phishing</h2>
              <p>Risk score: {result.risk.score}/100 · {result.risk.confidence} confidence</p>
            </div>
          </div>
          <Badge tone={riskTone(result.risk.score)}>SOC Triage</Badge>
        </div>
        <div className="p-verdict-body">
          {composeTriageSummary(result)}
        </div>
        <div className="p-verdict-stats">
          <span>Risk score: {result.risk.score}/100</span>
          <span>Confidence: {result.risk.confidence}</span>
          <span>Evidence sources: {result.risk.independent_sources}</span>
        </div>
      </article>

      <LureSignals result={result} />
      <ImpactPanel result={result} />

      <SectionDivider label="Engine output" />

      <div className="p-span-full">
        <PhishingEngineSnapshot result={result} mode="triage" />
      </div>

      <SectionDivider label="Artifacts & evidence" />

      <FullArtifactInventory result={result} onSendArtifact={onSendArtifact} onCopy={onCopy} />
      <EvidenceContext result={result} />

      <div className="p-span-full">
        <CompleteFindingRegister result={result} limit={8} title="Prioritized findings" />
      </div>

      <SectionDivider label="Actions & scoring" />

      <article className="p-card" data-variant="actions">
        <div className="p-actions-bar">
          <NeoButton variant="danger" onClick={() => onSendArtifact("recon-exposure", { type: "domain", value: firstDomainFromResult(result) })}>Flag domain</NeoButton>
          <NeoButton variant="light" onClick={() => setPage?.("case-timeline")}>Open Case</NeoButton>
          {result.urls?.[0]?.normalized ? <NeoButton variant="secondary" onClick={() => onSendArtifact("safe-url-analyzer", { type: "url", value: result.urls[0].normalized })}>URL Check</NeoButton> : null}
          <SendToActions payload={composePayload(result, rawInput, mode)} source="Phishing Triage" setPage={setPage} compact />
        </div>
      </article>
      <ScoreBreakdownPanel result={result} />

      <SectionDivider label="Guidance & report" />

      <div className="p-span-full">
        <GuidanceAndHunts result={result} />
      </div>

      <div className="p-span-full">
        <ReportReadySummary result={result} onCopy={onCopy} />
      </div>

      <details className="p-card p-span-full">
        <summary style={{ padding: "0.85rem", fontWeight: 600, fontSize: "0.85rem", cursor: "pointer" }}>Advanced: findings &amp; evidence chain</summary>
        <div style={{ borderTop: "2px solid var(--p-line)" }}>
          <CompleteFindingRegister result={result} title="Complete finding register" />
          <EvidenceChainPanel result={result} />
        </div>
      </details>
    </section>
  )
}

export default function PhishingTriagePage({ setPage }) {
  const [pendingArtifact] = useState(() => readPendingArtifact())
  const incomingArtifact = pendingArtifactToInput(pendingArtifact)
  const [rawEmail, setRawEmail] = useState(() => incomingArtifact)
  const [mode, setMode] = useState("triage")
  const [sampleKey, setSampleKey] = useState("credential")
  const [result, setResult] = useState(null)
  const [loadingMode, setLoadingMode] = useState(null)
  const [error, setError] = useState("")
  const [notice, setNotice] = useState(() => incomingArtifact ? `Loaded ${pendingArtifact?.type || "artifact"} from ${pendingArtifact?.source || "BeyondArch"}.` : "")
  const fileRef = useRef(null)

  function loadSample(name) {
    setRawEmail(PHISHING_SAMPLES[name] || PHISHING_SAMPLES.credential)
    setResult(null)
    setNotice("Sample loaded.")
    setError("")
  }

  async function loadFile(event) {
    const file = event.target.files?.[0]
    if (!file) return
    const text = await file.text()
    setRawEmail(text)
    setResult(null)
    setNotice(`${file.name} loaded.`)
    setError("")
    event.target.value = ""
  }

  async function runAnalysis(nextMode = mode) {
    if (!rawEmail.trim()) {
      setError("Paste or upload an email before analysis.")
      return
    }
    setLoadingMode(nextMode)
    setError("")
    setNotice("")
    try {
      let local = analyzeEmailLocal({ raw: rawEmail })
      if (nextMode === "triage" && local.urls.length) {
        const checks = await Promise.all(local.urls.slice(0, 3).map((url) => safeAnalyzeUrl({
          url: url.normalized,
          allow_live_fetch: true,
          max_redirects: 5,
          timeout_seconds: 8,
          allow_private_targets: false,
        }).catch((analysisError) => ({
          input: { original: url.normalized, normalized: url.normalized },
          verdict: "needs_review",
          evidence_level: "limited",
          live_result: { enabled: true, blocked_reason: analysisError?.message || "metadata check failed", redirect_chain: [] },
          static_result: { host: url.host, risk_signals: [] },
          analysis: { category: "metadata unavailable" },
        }))))
        local = mergeUrlMetadata(local, checks)
      }
      setMode(nextMode)
      setResult(local)
      setNotice(nextMode === "technical" ? "Technical analysis complete." : "SOC triage complete.")
    } catch (analysisError) {
      setError(analysisError?.message || "Email analysis failed.")
    } finally {
      setLoadingMode(null)
    }
  }

  function clearAll() {
    setRawEmail("")
    setResult(null)
    setError("")
    setNotice("Input cleared.")
  }

  function sendArtifact(page, artifact) {
    const value = artifact?.value ? String(artifact.value).trim() : ""
    if (value) storePendingArtifact({ ...artifact, value, source: "phishing-triage" })
    setPage?.(page)
  }

  const rawInput = rawEmail
  const onCopy = (content, label) => copyText(content, label, setNotice)

  return (
    <WorkbenchPage className="ba-phishing-triage-page">
      <WorkbenchHeader
        eyebrow="Phishing triage"
        title="Phishing Triage"
        subtitle="Review sender signals, email headers, link targets, language features, authentication results, and verdicts."
        icon={MailWarning}
        chips={[
          { label: "email analysis", tone: "info" },
          { label: mode === "technical" ? "technical mode" : "SOC triage", tone: mode === "technical" ? "warning" : "success" },
          { label: "local engine", tone: "local" },
        ]}
      />
      {!result ? (
        loadingMode ? <LoadingSkeleton /> : <EmptyTriageState
          rawEmail={rawEmail}
          setRawEmail={setRawEmail}
          mode={mode}
          setMode={setMode}
          sampleKey={sampleKey}
          setSampleKey={setSampleKey}
          loadSample={loadSample}
          clearAll={clearAll}
          loadFile={loadFile}
          fileRef={fileRef}
          runAnalysis={runAnalysis}
          loadingMode={loadingMode}
          error={error}
          notice={notice}
        />
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: "1.25rem" }}>
          <ResultHeader result={result} mode={mode} setMode={setMode} runAnalysis={runAnalysis} loadingMode={loadingMode} clearAll={clearAll} />
          <ResultMetrics result={result} mode={mode} />
          {(error || notice) ? <div className="p-notice" data-tone={error ? "error" : undefined}><Info />{error || notice}</div> : null}
          {mode === "technical" ? (
            <TechnicalResults result={result} onSendArtifact={sendArtifact} onCopy={onCopy} />
          ) : (
            <SocTriageResults result={result} onSendArtifact={sendArtifact} onCopy={onCopy} setPage={setPage} rawInput={rawInput} mode={mode} />
          )}
        </div>
      )}
    </WorkbenchPage>
  )
}
