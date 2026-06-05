import { useRef, useState } from "react"
import {
  AlertTriangle,
  CheckCircle2,
  Copy,
  Link2,
  Database,
  Download,
  Eraser,
  FileText,
  Loader2,
  MailWarning,
  Radar,
  RefreshCw,
  Route,
  Search,
  ShieldAlert,
  ShieldCheck,
  Upload,
} from "lucide-react"
import { safeAnalyzeUrl } from "../../api/backend"
import SendToActions from "../../components/investigation/SendToActions"
import { copyText, downloadText, stripDefang } from "../../lib/domUtils"
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

function stripProtocol(host = "") {
  return String(host).replace(/^https?:\/\//i, "").split(/[/?#]/)[0]
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
  return <button type="button" className={`pt-neo-button pt-neo-button-${variant} ${className}`} {...props}>{children}</button>
}

function Badge({ children, tone = "neutral" }) {
  return <span className={`pt-badge pt-badge-${tone}`}>{children}</span>
}

function MetricCard({ label, value, tone = "neutral", helper }) {
  return (
    <article className={`pt-metric pt-tone-${tone}`}>
      <span>{label}</span>
      <strong>{safeValue(value)}</strong>
      {helper ? <small>{helper}</small> : null}
    </article>
  )
}

function SectionHeader({ eyebrow, title, children, align = "left", icon: Icon }) {
  return (
    <header className={`pt-section-header pt-section-header-${align}`}>
      {eyebrow ? <span className="pt-eyebrow">{Icon ? <Icon className="h-4 w-4 text-cyan-400" /> : null}{eyebrow}</span> : null}
      <h2>{Icon ? <Icon className="h-4 w-4 text-cyan-400" /> : null}{title}</h2>
      {children ? <p>{children}</p> : null}
    </header>
  )
}

function FieldRow({ label, value, note, tone = "neutral", mono = false }) {
  return (
    <div className={`pt-field-row pt-tone-${tone}`}>
      <span>{label}</span>
      <strong className={mono ? "pt-mono" : ""}>{safeValue(value)}</strong>
      {note ? <small>{note}</small> : null}
    </div>
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
    <section className="pt-expected">
      <MailWarning className="h-10 w-10 text-zinc-500 mx-auto mb-2" />
      <SectionHeader eyebrow="Awaiting input" title="Expected Findings" align="center">
        Analysis output appears here after a raw email, header block, body, or URL list is reviewed.
      </SectionHeader>
      <div className="pt-expected-grid">
        {cards.map(([title, text]) => (
          <article key={title} className="pt-empty-card">
            <span>{title}</span>
            <p>{text}</p>
            <i />
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
      <section className="pt-page-intro">
        <SectionHeader eyebrow="Pipeline · Stage 02" title="Phishing Triage" align="left" icon={Radar}>
          Review suspicious emails, headers, URLs, sender clues, attachments, and lure language before routing evidence into a case.
        </SectionHeader>
      </section>
      <section className="pt-intake-grid">
        <article className="pt-panel pt-intake-panel">
          <div className="pt-panel-head">
            <div><MailWarning className="h-5 w-5" /><strong>Suspicious Email Intake</strong></div>
            <Badge tone="neutral">Ready</Badge>
          </div>
          <textarea
            value={rawEmail}
            onChange={(event) => setRawEmail(event.target.value)}
            placeholder={`Paste raw email content, headers, body text, or suspicious URLs here...\n\nExamples:\nReturn-Path: <spoofed@domain.com>\nReceived: from mail.attacker.xyz...\nSubject: Urgent Action Required: Account Locked`}
            className="pt-email-textarea"
          />
          <div className="pt-intake-actions">
            <div className="pt-sample-controls">
              <select value={sampleKey} onChange={(event) => setSampleKey(event.target.value)} aria-label="Sample lure">
                {sampleOptions.map((key) => <option key={key} value={key}>{key.replace(/([A-Z])/g, " $1").replace(/^./, (char) => char.toUpperCase())}</option>)}
              </select>
              <NeoButton variant="light" onClick={() => loadSample(sampleKey)}><FileText className="h-4 w-4" />Load sample</NeoButton>
              <NeoButton variant="light" onClick={clearAll}><Eraser className="h-4 w-4" />Clear</NeoButton>
            </div>
            <NeoButton variant="primary" onClick={() => runAnalysis(mode)} disabled={Boolean(loadingMode)}>
              {loadingMode ? <Loader2 className="h-4 w-4 animate-spin" /> : <Radar className="h-4 w-4" />}
              Analyze Email
            </NeoButton>
          </div>
        </article>

        <aside className="pt-side-stack">
          <article className="pt-panel pt-config-panel">
            <div className="pt-panel-title"><Upload className="h-4 w-4" />Import & Config</div>
            <button type="button" className="pt-dropzone" onClick={() => fileRef.current?.click()}>
              <Upload className="h-8 w-8" />
              <strong>Drop .eml, .msg, .txt, or headers</strong>
              <span>or click to browse</span>
            </button>
            <input ref={fileRef} type="file" className="hidden" accept=".eml,.msg,.txt,.text,.log,.csv" onChange={loadFile} />
            <div className="pt-mode-selector" role="radiogroup" aria-label="Analysis mode">
              <button type="button" className={mode === "triage" ? "is-active" : ""} onClick={() => setMode("triage")}>
                <ShieldAlert className="h-4 w-4" />
                <span><strong>SOC Triage</strong><small>Decision, response, report handoff.</small></span>
              </button>
              <button type="button" className={mode === "technical" ? "is-active" : ""} onClick={() => setMode("technical")}>
                <Search className="h-4 w-4" />
                <span><strong>Technical Analysis</strong><small>Headers, URLs, routing, IOCs.</small></span>
              </button>
            </div>
          </article>
          <article className="pt-privacy-card">
            <ShieldCheck className="h-5 w-5" />
            <strong>Local session only</strong>
            <p>Parsing runs locally first. External enrichment happens only when a workflow explicitly requests it.</p>
          </article>
          {(error || notice) ? <div className={`pt-notice ${error ? "pt-notice-error" : ""}`}>{error || notice}</div> : null}
        </aside>
      </section>
      <EmptyPreview />
    </>
  )
}

function ResultHeader({ result, mode, setMode, runAnalysis, loadingMode, clearAll }) {
  const subject = result.headers.subject || "Suspicious email artifact"
  return (
    <section className="pt-result-header">
      <div className="pt-artifact-title">
        <MailWarning className="h-6 w-6" />
        <div>
          <span>Current artifact</span>
          <h1>{subject}</h1>
          <p>Source: manual intake · Mode: {MODE_LABELS[mode]} · Risk: {result.risk.level} · Score: {result.risk.score}/100</p>
        </div>
      </div>
      <div className="pt-mode-tabs" role="tablist" aria-label="Result mode">
        <button type="button" className={mode === "triage" ? "is-active" : ""} onClick={() => setMode("triage")}>SOC Triage</button>
        <button type="button" className={mode === "technical" ? "is-active" : ""} onClick={() => setMode("technical")}>Technical Analysis</button>
      </div>
      <div className="pt-header-actions">
        <NeoButton variant="light" onClick={() => runAnalysis(mode)} disabled={Boolean(loadingMode)}>
          {loadingMode ? <Loader2 className="h-4 w-4 animate-spin" /> : <RefreshCw className="h-4 w-4" />}
          Re-analyze
        </NeoButton>
        <NeoButton variant="danger" onClick={clearAll}><Eraser className="h-4 w-4" />Clear</NeoButton>
      </div>
    </section>
  )
}

function ResultMetrics({ result, mode }) {
  const auth = result.headers.authentication
  if (mode === "technical") {
    return (
      <section className="pt-metric-grid pt-metric-grid-technical">
        <MetricCard label="Extracted URLs" value={result.iocs.urls.length} tone="violet" />
        <MetricCard label="Sender mismatches" value={result.sender_alignment.mismatches.length} tone={result.sender_alignment.mismatches.length ? "bad" : "good"} />
        <MetricCard label="Header issues" value={[auth.spf, auth.dkim, auth.dmarc].filter((value) => ["fail", "softfail", "none", "missing"].includes(String(value).toLowerCase())).length} tone="bad" />
        <MetricCard label="Total IOCs" value={result.iocs.urls.length + result.iocs.domains.length + result.iocs.ips.length + result.iocs.hashes.length + result.iocs.emails.length} tone="info" />
        <MetricCard label="Attachments" value={result.attachments.length} tone={result.attachments.length ? "warn" : "neutral"} />
      </section>
    )
  }
  return (
    <section className="pt-metric-grid pt-metric-grid-triage">
      <MetricCard label="Verdict" value={result.professional?.outcome || result.decision.disposition} tone={riskTone(result.risk.score)} />
      <MetricCard label="Confidence" value={result.risk.confidence || `${result.risk.confidence_score}%`} tone="info" />
      <MetricCard label="Sender risk" value={result.sender_alignment.mismatches.length ? "Mismatch" : "Aligned"} tone={result.sender_alignment.mismatches.length ? "bad" : "good"} />
      <MetricCard label="URL risk" value={`${result.urls.length} URL(s)`} tone={result.urls.length ? "warn" : "neutral"} />
      <MetricCard label="Report ready" value={<span><CheckCircle2 className="h-4 w-4 inline-block mr-1" />Yes</span>} tone="good" />
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
    <article className="pt-panel pt-auth-panel">
      <div className="pt-dark-head"><ShieldCheck className="h-4 w-4" />Authentication Results</div>
      <div className="pt-auth-grid">
        {rows.map(([label, value, note]) => <FieldRow key={label} label={label} value={value} note={note} tone={authTone(value)} />)}
      </div>
      <div className="pt-relay-path">
        <span>Received path verification</span>
        {result.headers.received.length ? (
          result.headers.received.slice(0, 5).map((line, index) => <p key={line}><b>[{index}]</b> {line}</p>)
        ) : <p><b>[local]</b> No Received header hops parsed. Upload full EML for relay path verification.</p>}
      </div>
    </article>
  )
}

function SenderIdentity({ result }) {
  return (
    <article className="pt-panel pt-identity-panel">
      <div className="pt-red-head"><ShieldAlert className="h-4 w-4" />Identity Anomaly</div>
      <div className="pt-card-body">
        <FieldRow label="Display From" value={result.headers.from} mono />
        <FieldRow label="Reply-To" value={result.headers.reply_to} tone={result.sender_alignment.mismatches.some((item) => item.includes("Reply-To")) ? "bad" : "neutral"} mono />
        <FieldRow label="Return-Path" value={result.headers.return_path} tone={result.sender_alignment.mismatches.some((item) => item.includes("Return-Path")) ? "warn" : "neutral"} mono />
        <FieldRow label="From domain" value={emailDomainLabel(result.headers.from)} mono />
        {result.headers.sending_ips.length || result.headers.sending_domains.length ? (
          <div className="pt-mini-box">
            <strong>Originating infrastructure</strong>
            <span>IPs: {result.headers.sending_ips.map(itemValue).join(", ") || "N/A"}</span>
            <span>Domains: {result.headers.sending_domains.map(itemValue).join(", ") || "N/A"}</span>
          </div>
        ) : null}
        {result.sender_alignment.mismatches.length ? (
          <ul className="pt-signal-list">
            {result.sender_alignment.mismatches.slice(0, 6).map((item) => <li key={item}><AlertTriangle className="h-4 w-4" />{item}</li>)}
          </ul>
        ) : null}
      </div>
    </article>
  )
}

function EvidenceContext({ result }) {
  const rows = result.professional?.evidence_rows?.length ? result.professional.evidence_rows : result.findings
  return (
    <article className="pt-panel pt-evidence-context">
      <div className="pt-panel-title"><FileText className="h-4 w-4" />Evidence Context</div>
      <div className="pt-evidence-list">
        {rows.slice(0, 10).map((item, index) => (
          <section key={`${item.signal || item.name}-${index}`} className={`pt-evidence-card pt-tone-${item.tone || severityTone(item.severity)}`}>
            <div>
              <span>EV-{String(index + 1).padStart(3, "0")}</span>
              <Badge tone={severityTone(item.severity)}>{item.confidence || item.severity || "evidence"}</Badge>
            </div>
            <strong>{item.signal || item.name}</strong>
            <p>{item.evidence || item.meaning || item.why}</p>
            {item.action ? <small>Action: {item.action}</small> : null}
          </section>
        ))}
      </div>
    </article>
  )
}


function UrlMetadataReview({ result, onSendArtifact }) {
  const enriched = result.url_enrichment || []
  const mismatches = result.body?.mismatched_links || []
  return (
    <article className="pt-panel pt-url-metadata-panel">
      <div className="pt-panel-title"><Link2 className="h-4 w-4" />URL and destination review</div>
      <div className="pt-url-review-grid">
        <section>
          <span className="pt-mini-title">Extracted URL inventory</span>
          <div className="pt-link-list pt-link-list-compact">
            {result.urls.length ? result.urls.map((url, index) => (
              <div key={`${url.normalized}-${index}`} className="pt-url-review-row">
                <strong>{url.defanged || url.normalized}</strong>
                <p>Host: {url.host || "N/A"} · Root: {url.root_domain || "N/A"} · Path: {url.path || "/"}</p>
                <div className="pt-inline-badges">{(url.signals || []).slice(0, 5).map((signal) => <Badge key={signal.label} tone={severityTone(signal.severity)}>{signal.label}</Badge>)}</div>
                <NeoButton variant="secondary" onClick={() => onSendArtifact?.("safe-url-analyzer", { type: "url", value: url.normalized })}>Send to Safe URL</NeoButton>
              </div>
            )) : <p className="pt-muted-box">No URL inventory extracted.</p>}
          </div>
        </section>
        <section>
          <span className="pt-mini-title">Guarded metadata / mismatch context</span>
          <div className="pt-metadata-list">
            {enriched.length ? enriched.map((item, index) => (
              <div key={`${item.original_url}-${index}`}>
                <strong>{item.verdict || "metadata"}</strong>
                <p>{item.original_url || "N/A"} → {item.final_url || item.final_host || "no final URL"}</p>
                <small>{item.blocked_reason || item.analysis?.category || item.title || "No additional destination metadata."}</small>
              </div>
            )) : <div><strong>Static-first</strong><p>No guarded URL metadata was fetched for this mode or sample.</p><small>Use Safe URL Analyzer when destination metadata is required.</small></div>}
            {mismatches.length ? mismatches.map((item, index) => (
              <div key={`${item.href}-${index}`}>
                <strong>Visible / href mismatch</strong>
                <p>{item.text || "visible link"} → {item.href}</p>
                <small>Visible text and actual destination differ.</small>
              </div>
            )) : null}
          </div>
        </section>
      </div>
    </article>
  )
}

function EvidenceChainPanel({ result }) {
  return (
    <article className="pt-panel pt-evidence-chain-panel">
      <div className="pt-panel-title"><Route className="h-4 w-4" />Evidence chain</div>
      <div className="pt-chain-grid">
        {(result.evidence_chain || []).map((stage, index) => (
          <section key={`${stage.stage}-${index}`} className={`pt-chain-card pt-chain-${stage.state || "unknown"}`}>
            <span>{String(index + 1).padStart(2, "0")}</span>
            <strong>{stage.stage}</strong>
            <p>{stage.detail}</p>
          </section>
        ))}
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
    <article className="pt-panel pt-guidance-panel">
      <div className="pt-panel-title"><ShieldCheck className="h-4 w-4" />Guidance, limitations, and hunts</div>
      <div className="pt-guidance-grid">
        {groups.map(([title, items]) => (
          <section key={title}>
            <span className="pt-mini-title">{title}</span>
            <ul>{(items || []).map((item) => <li key={item}>{item}</li>)}</ul>
          </section>
        ))}
      </div>
      <details className="pt-hunt-details">
        <summary>Generated hunting queries</summary>
        <div className="pt-hunt-list">
          {(result.hunting_queries || []).map((item) => (
            <section key={item.name}>
              <strong>{item.name}</strong>
              <pre>{item.query}</pre>
            </section>
          ))}
        </div>
      </details>
      <div className="pt-limitations">
        {(result.classification?.limitations || []).map((item) => <span key={item}>{item}</span>)}
      </div>
    </article>
  )
}

function SenderMatrixPanel({ result }) {
  const rows = result.professional?.sender_matrix?.rows || []
  if (!rows.length) return null
  return (
    <article className="pt-panel pt-sender-matrix-panel">
      <div className="pt-panel-title"><MailWarning className="h-4 w-4" />Sender and identity matrix</div>
      <div className="pt-sender-matrix-table">
        {rows.map((row) => (
          <section key={row.field} className={row.aligned ? "is-aligned" : "is-mismatch"}>
            <span>{row.field}</span>
            <strong>{row.value}</strong>
            <small>{row.domain} · {row.meaning}</small>
          </section>
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
    <article className="pt-panel pt-engine-snapshot">
      <div className="pt-panel-title"><FileText className="h-4 w-4" />Complete local phishing-engine output</div>
      <div className="pt-engine-grid">
        <section>
          <span>Message profile</span>
          <strong>{result.headers.subject || "No subject parsed"}</strong>
          <p>From: {result.headers.from || "N/A"}</p>
          <p>To: {result.headers.to || "N/A"}</p>
          <p>Mode: {MODE_LABELS[mode]}</p>
        </section>
        <section>
          <span>Authentication</span>
          <strong>{auth.spf || "missing"} / {auth.dkim || "missing"} / {auth.dmarc || "missing"}</strong>
          <p>SPF · DKIM · DMARC alignment and authentication result context.</p>
        </section>
        <section>
          <span>Extraction</span>
          <strong>{result.iocs.urls.length} URLs · {result.iocs.domains.length} domains · {result.iocs.ips.length} IPs</strong>
          <p>{result.iocs.emails.length} emails · {result.iocs.hashes.length} hashes · {result.attachments.length} attachment reference(s)</p>
        </section>
        <section>
          <span>Decision basis</span>
          <strong>{result.risk.score}/100 · {result.risk.confidence}</strong>
          <p>{sourceCount} evidence source(s). {urlRollup.summary || result.decision.reliability}</p>
        </section>
      </div>
      <div className="pt-engine-lists">
        <div>
          <h3>Recommended next actions</h3>
          <ul>{actions.length ? actions.map((item) => <li key={item}>{item}</li>) : <li>Review the original email and preserve evidence before handoff.</li>}</ul>
        </div>
        <div>
          <h3>Limitations / missing evidence</h3>
          <ul>{gaps.length ? gaps.slice(0, 5).map((item) => <li key={item}>{item}</li>) : <li>No additional confidence gaps were returned by the local engine.</li>}</ul>
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
    <article className="pt-panel pt-message-structure-panel">
      <div className="pt-panel-title"><MailWarning className="h-4 w-4" />Message structure and important fields</div>
      <div className="pt-message-table">
        {rows.map(([label, value]) => (
          <div key={label}>
            <span>{label}</span>
            <strong>{Array.isArray(value) ? value.join(" | ") : String(value)}</strong>
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
    <article className="pt-panel pt-score-panel">
      <div className="pt-panel-title"><AlertTriangle className="h-4 w-4" />Risk score breakdown</div>
      <p className="pt-score-explain">{score.explanation}</p>
      <div className="pt-score-grid">
        {rows.length ? rows.map((row, index) => (
          <section key={`${row.signal}-${index}`} className={`pt-score-row pt-tone-${severityTone(row.severity)}`}>
            <span>+{row.points || 0}</span>
            <strong>{row.signal}</strong>
            <p>{row.evidence}</p>
            <small>{row.analyst_note}</small>
          </section>
        )) : <p className="pt-muted-box">No weighted score drivers returned.</p>}
      </div>
      {dampeners.length ? <div className="pt-dampener-list">{dampeners.map((item) => <span key={item.signal}>{item.points} {item.signal}: {item.reason}</span>)}</div> : null}
    </article>
  )
}

function FullArtifactInventory({ result, onSendArtifact, onCopy }) {
  const groups = [
    ["URLs", result.iocs.urls.map((item) => item.defanged || item.normalized), "safe-url-analyzer", "url", "Send to URL Analyzer"],
    ["Domains", result.iocs.domains.map(itemValue), "recon-exposure", "domain", "Send to Recon"],
    ["IPs", result.iocs.ips.map(itemValue), "recon-exposure", "ip", "Send to Recon"],
    ["Emails", result.iocs.emails.map(itemValue), "phishing-triage", "email", "Send to Phishing"],
    ["Hashes", result.iocs.hashes.map(itemValue), "ids-builder", "hash", "Send to Tools"],
    ["Attachments", result.attachments.map((item) => [item.filename, ...(item.signals || [])].filter(Boolean).join(" · ")), "attachment-triage", "attachment-notes", "Send to Attachment"],
  ]
  return (
    <article className="pt-panel pt-full-inventory-panel">
      <div className="pt-panel-title"><Database className="h-4 w-4" />Full extracted artifact inventory</div>
      <div className="pt-full-inventory-grid">
        {groups.map(([label, items, target, type, actionLabel]) => (
          <section key={label} className={`pt-inventory-card pt-inventory-${String(label).toLowerCase().replace(/[^a-z0-9]+/g, "-")}`}>
            <div className="pt-inventory-head"><strong>{label}</strong><span>{items.length}</span></div>
            <div className="pt-inventory-items">
              {items.length ? items.slice(0, 8).map((item) => {
                const value = String(item || "")
                const routeValue = type === "url" ? stripDefang(value) : stripDefang(stripProtocol(value))
                return (
                  <div className="pt-artifact-row" key={`${label}-${value}`}>
                    <code className="pt-artifact-value" title={value}>{truncateMiddle(value, 180)}</code>
                    <div className="pt-artifact-actions">
                      {onCopy ? <button type="button" onClick={() => onCopy(value, `${label} artifact`)}>Copy</button> : null}
                      {target ? <button type="button" onClick={() => onSendArtifact?.(target, { type, value: routeValue })} title={actionLabel}>Send</button> : null}
                    </div>
                  </div>
                )
              }) : <em>None extracted</em>}
              {items.length > 8 ? <small className="pt-inventory-more">+{items.length - 8} more values kept in raw details</small> : null}
            </div>
          </section>
        ))}
      </div>
    </article>
  )
}

function CompleteFindingRegister({ result, limit = null, title = "Finding register" }) {
  const rows = result.findings || []
  const visibleRows = limit ? rows.slice(0, limit) : rows
  return (
    <article className="pt-panel pt-complete-register-panel">
      <div className="pt-panel-title"><AlertTriangle className="h-4 w-4" />{title}</div>
      <div className="pt-complete-register-grid">
        {visibleRows.length ? visibleRows.map((finding, index) => (
          <section key={`${finding.name}-${index}`} className={`pt-complete-finding pt-tone-${severityTone(finding.severity)}`}>
            <div><span>F-{String(index + 1).padStart(2, "0")}</span><Badge tone={severityTone(finding.severity)}>{finding.severity || "signal"}</Badge><small>{finding.source}</small></div>
            <strong>{finding.name}</strong>
            <p>{finding.evidence}</p>
            <dl>
              <div><dt>Why</dt><dd>{finding.why}</dd></div>
              <div><dt>Action</dt><dd>{finding.action}</dd></div>
              {finding.score ? <div><dt>Score</dt><dd>+{finding.score}</dd></div> : null}
            </dl>
          </section>
        )) : <p className="pt-muted-box">No weighted findings were generated.</p>}
      </div>
      {limit && rows.length > limit ? <p className="pt-more-note">+{rows.length - limit} more findings available in advanced details.</p> : null}
    </article>
  )
}

function TechnicalResults({ result, onSendArtifact, onCopy }) {
  const headerMap = parseHeaderMap(result.split.headers)
  return (
    <section className="pt-technical-output pt-output pt-output-technical">
      <div className="pt-output-lead">
        <SectionHeader eyebrow="Technical Analysis" title="Full phishing evidence review">
          Complete engine output grouped like the original workbench: identity/authentication, link review, artifact inventory, evidence context, score drivers, and technical pivots.
        </SectionHeader>
      </div>

      <PhishingEngineSnapshot result={result} mode="technical" />

      <div className="pt-output-layout pt-technical-layout">
        <main className="pt-output-main">
          <div className="pt-pair-grid">
            <AuthResults result={result} />
            <SenderIdentity result={result} />
          </div>
          <MessageStructurePanel result={result} />
          <UrlMetadataReview result={result} onSendArtifact={onSendArtifact} />
          <FullArtifactInventory result={result} onSendArtifact={onSendArtifact} onCopy={onCopy} />
          <EvidenceContext result={result} />
          <CompleteFindingRegister result={result} limit={8} title="Prioritized finding register" />
        </main>

        <aside className="pt-output-rail">
          <SenderMatrixPanel result={result} />
          <ScoreBreakdownPanel result={result} />
          <article className="pt-panel pt-action-panel pt-technical-actions">
            <div className="pt-panel-title"><Route className="h-4 w-4" />Technical pivots</div>
            <div className="pt-action-grid">
              <NeoButton variant="secondary" onClick={() => onCopy(compactIocText(result), "IOCs")}><Copy className="h-4 w-4" />Copy IOCs</NeoButton>
              <NeoButton variant="secondary" onClick={() => onSendArtifact("recon-exposure", { type: "domain", value: firstDomainFromResult(result) })}>Send domain to Recon</NeoButton>
              {result.urls?.[0]?.normalized ? <NeoButton variant="secondary" onClick={() => onSendArtifact("safe-url-analyzer", { type: "url", value: result.urls[0].normalized })}>Open URL Analyzer</NeoButton> : null}
              {result.attachments.length ? <NeoButton variant="secondary" onClick={() => onSendArtifact("attachment-triage", { type: "attachment-notes", value: attachmentText(result) })}>Send attachments</NeoButton> : null}
            </div>
          </article>
          <GuidanceAndHunts result={result} />
        </aside>
      </div>

      <details className="pt-panel pt-details-panel pt-advanced-evidence">
        <summary>Advanced evidence: complete finding register, chain, and raw parsed details</summary>
        <CompleteFindingRegister result={result} title="Complete finding register" />
        <EvidenceChainPanel result={result} />
        <div className="pt-raw-grid">
          <pre>{JSON.stringify(result, null, 2)}</pre>
          <pre>{JSON.stringify(headerMap, null, 2)}</pre>
        </div>
      </details>
    </section>
  )
}

function LureSignals({ result }) {
  const themes = result.body.themes || []
  const signals = themes.length ? themes.flatMap((theme) => theme.matches.map((match) => `${theme.theme}: ${match}`)) : ["No strong lure keyword extracted."]
  return (
    <article className="pt-panel pt-lure-panel">
      <div className="pt-panel-title"><Radar className="h-4 w-4" />Lure Signals</div>
      <ul className="pt-signal-list pt-signal-list-large">
        {signals.slice(0, 8).map((item) => <li key={item}><AlertTriangle className="h-4 w-4" />{item}</li>)}
      </ul>
      <FieldRow label="Brand mentions" value={result.body.mentioned_brands.join(", ") || "None extracted"} />
      <FieldRow label="Attachment mentions" value={result.body.attachment_mentions.map(itemValue).join(", ") || "None extracted"} />
    </article>
  )
}

function ImpactPanel({ result }) {
  const guidance = result.guidance || {}
  return (
    <article className="pt-panel pt-impact-panel">
      <div className="pt-panel-title"><ShieldAlert className="h-4 w-4" />Impact Assessment</div>
      <FieldRow label="What happened" value={result.decision.primary_concern} />
      <FieldRow label="Why it matters" value={result.professional?.confidence_reason || result.decision.reliability} />
      <FieldRow label="Next step" value={result.decision.next_action} />
      <div className="pt-mini-box">
        <strong>Immediate handling</strong>
        {(guidance.immediate || []).slice(0, 3).map((item) => <span key={item}>• {item}</span>)}
      </div>
    </article>
  )
}

function ReportReadySummary({ result, onCopy }) {
  return (
    <article className="pt-report-panel">
      <div className="pt-report-head">
        <div>
          <span>Report-ready summary</span>
          <h3>Case handoff package</h3>
        </div>
        <NeoButton variant="primary" onClick={() => onCopy(result.markdown, "Markdown report")}><Copy className="h-4 w-4" />Copy Markdown</NeoButton>
      </div>
      <pre>{result.markdown}</pre>
      <div className="pt-report-actions">
        <NeoButton variant="light" onClick={() => downloadText("phishing-triage-report.md", result.markdown, "text/markdown")}><Download className="h-4 w-4" />Download MD</NeoButton>
        <NeoButton variant="light" onClick={() => onCopy(JSON.stringify(result, null, 2), "JSON result")}><Copy className="h-4 w-4" />Copy JSON</NeoButton>
      </div>
    </article>
  )
}

function SocTriageResults({ result, onSendArtifact, onCopy, setPage, rawInput, mode }) {
  return (
    <section className="pt-soc-output pt-output pt-output-soc">
      <div className="pt-output-lead">
        <SectionHeader eyebrow="SOC Triage" title="Verdict, impact, and case handoff">
          Decision-focused view for L1/L2 response. The evidence depth remains available, but the layout prioritizes verdict, action, and case-ready handoff.
        </SectionHeader>
      </div>

      <div className="pt-output-layout pt-soc-layout">
        <main className="pt-output-main">
          <article className="pt-verdict-panel">
            <Badge tone={riskTone(result.risk.score)}>Likely phishing</Badge>
            <h2>Analyst Explanation</h2>
            <p>{composeTriageSummary(result)}</p>
            <div className="pt-verdict-meta">
              <span>Risk score: {result.risk.score}/100</span>
              <span>Confidence: {result.risk.confidence}</span>
              <span>Evidence sources: {result.risk.independent_sources}</span>
            </div>
          </article>

          <div className="pt-pair-grid">
            <LureSignals result={result} />
            <ImpactPanel result={result} />
          </div>

          <PhishingEngineSnapshot result={result} mode="triage" />
          <FullArtifactInventory result={result} onSendArtifact={onSendArtifact} onCopy={onCopy} />
          <EvidenceContext result={result} />
          <CompleteFindingRegister result={result} limit={8} title="Prioritized finding register" />
          <ReportReadySummary result={result} onCopy={onCopy} />
        </main>

        <aside className="pt-output-rail">
          <article className="pt-panel pt-action-panel pt-action-panel-strong">
            <div className="pt-panel-title"><ShieldAlert className="h-4 w-4" />Triage actions</div>
            <NeoButton variant="danger" onClick={() => onSendArtifact("recon-exposure", { type: "domain", value: firstDomainFromResult(result) })}>Flag domain for review</NeoButton>
            <NeoButton variant="light" onClick={() => setPage?.("case-timeline")}>Open Case Report</NeoButton>
            <NeoButton variant="secondary" onClick={() => result.urls?.[0]?.normalized && onSendArtifact("safe-url-analyzer", { type: "url", value: result.urls[0].normalized })}>Send to Safe URL</NeoButton>
            <SendToActions payload={composePayload(result, rawInput, mode)} source="Phishing Triage" setPage={setPage} compact />
          </article>
          <ScoreBreakdownPanel result={result} />
          <article className="pt-panel pt-recent-panel">
            <div className="pt-panel-title"><FileText className="h-4 w-4" />Evidence boundary</div>
            <p>{result.classification?.limitations?.[0] || result.risk.limitations}</p>
            <p>{result.classification?.limitations?.[1] || "Validate with mailbox, gateway, proxy, and user-report context."}</p>
          </article>
          <GuidanceAndHunts result={result} />
        </aside>
      </div>

      <details className="pt-panel pt-details-panel pt-advanced-evidence">
        <summary>Advanced evidence: complete finding register and evidence chain</summary>
        <CompleteFindingRegister result={result} title="Complete finding register" />
        <EvidenceChainPanel result={result} />
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
        <EmptyTriageState
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
        <>
          <ResultHeader result={result} mode={mode} setMode={setMode} runAnalysis={runAnalysis} loadingMode={loadingMode} clearAll={clearAll} />
          <ResultMetrics result={result} mode={mode} />
          {(error || notice) ? <div className={`pt-notice ${error ? "pt-notice-error" : ""}`}>{error || notice}</div> : null}
          {mode === "technical" ? (
            <TechnicalResults result={result} onSendArtifact={sendArtifact} onCopy={onCopy} />
          ) : (
            <SocTriageResults result={result} onSendArtifact={sendArtifact} onCopy={onCopy} setPage={setPage} rawInput={rawInput} mode={mode} />
          )}
        </>
      )}
    </WorkbenchPage>
  )
}
