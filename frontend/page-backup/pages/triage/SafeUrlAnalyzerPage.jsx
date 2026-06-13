import { useEffect, useMemo, useState } from "react"
import {
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  Clipboard,
  Code2,
  Copy,
  ExternalLink,
  FileJson,
  GitBranch,
  Globe,
  Globe2,
  Link2,
  Loader2,
  LockKeyhole,
  Radar,
  RefreshCcw,
  Search,
  SearchCheck,
  Shield,
  ShieldAlert,
  ShieldCheck,
  SlidersHorizontal,
  Sparkles,
  XCircle,
} from "lucide-react"
import { safeAnalyzeUrl } from "../../api/backend"
import SendToActions from "../../components/investigation/SendToActions"
import { WorkbenchHeader, WorkbenchPage } from "../../components/layout/WorkbenchShell"
import { buildFindingMarkdown, defangText, labelize } from "../../components/url/safeUrlUiUtils"
import { addTimelineArtifact } from "../../lib/timelineStore"
import { copyText, downloadText, refangText } from "../../lib/domUtils.js"

const RECENT_KEY = "beyondarch.safeUrlAnalyzer.recent"
const PENDING_KEY = "beyondarch.pendingArtifact"

const SAMPLE_URLS = {
  credential: "hxxps[:]//secure-gate.login-verify[.]com/oauth/reset?redirect_uri=aHR0cHM6Ly9taWNyb3NvZnQuY29tL2xvZ2lu&user=analyst@example.com",
  shortener: "https://bit.ly/example-login-check",
  punycode: "https://xn--microsft-login-9ib.example.com/security/verify",
  query: "https://account-security.example-login.com/auth?client_id=portal&redirect_uri=https%3A%2F%2Flogin.example.com%2Fsession&user=victim%40example.com",
  redirect: "https://example.com/redirect?next=https%3A%2F%2Fsecure-update.example-login.com%2Fauth",
  benign: "https://www.microsoft.com/en-us/security/business/identity-access/microsoft-entra-id",
}

function extractUrlCandidate(value = "") {
  const text = refangText(value).trim()
  const match = text.match(/https?:\/\/[^\s<>'")]+/i)
  if (match) return match[0]
  const compact = text.split(/\s+/)[0] || ""
  if (/^[a-z0-9.-]+\.[a-z]{2,}([/:?#].*)?$/i.test(compact)) return compact
  return ""
}

function tryUrl(value = "") {
  const candidate = extractUrlCandidate(value) || refangText(value).trim()
  if (!candidate) return null
  try {
    return new URL(candidate.includes("://") ? candidate : `https://${candidate}`)
  } catch {
    return null
  }
}

function artifactValue(artifact) {
  if (!artifact) return ""
  const candidates = [artifact.url, artifact.normalized, artifact.defanged, artifact.value, artifact.content, artifact.text, artifact.raw_input, artifact.raw]
  for (const candidate of candidates) {
    const url = extractUrlCandidate(candidate)
    if (url) return url
  }
  return ""
}

function readInitialArtifact() {
  try {
    const params = new URLSearchParams(window.location.search)
    const fromQuery = params.get("url")
    if (fromQuery) return { url: fromQuery, source: "query string" }

    const raw = window.localStorage.getItem(PENDING_KEY)
    if (!raw) return { url: "", source: "" }
    const pending = JSON.parse(raw)
    const url = artifactValue(pending)
    if (!url) return { url: "", source: "" }
    window.localStorage.removeItem(PENDING_KEY)
    return { url, source: pending?.source || "BeyondArch" }
  } catch {
    return { url: "", source: "" }
  }
}

function loadRecent() {
  try {
    const parsed = JSON.parse(window.localStorage.getItem(RECENT_KEY) || "[]")
    return Array.isArray(parsed) ? parsed.slice(0, 8) : []
  } catch {
    return []
  }
}

function storeRecent(item) {
  try {
    const existing = loadRecent().filter((entry) => entry.normalized !== item.normalized)
    const next = [item, ...existing].slice(0, 8)
    window.localStorage.setItem(RECENT_KEY, JSON.stringify(next))
    return next
  } catch {
    return []
  }
}

function modeLabel(mode) {
  if (mode === "compare") return "Compare sources"
  if (mode === "metadata") return "Local/backend checks"
  return "Static-first review"
}

function toneForVerdict(verdict) {
  if (verdict === "suspicious") return "rose"
  if (verdict === "low_risk") return "emerald"
  return "amber"
}

function toneForSeverity(severity) {
  if (severity === "high") return "rose"
  if (severity === "medium") return "amber"
  if (severity === "low") return "cyan"
  return "violet"
}

function allSignals(result) {
  return [...(result?.static_result?.risk_signals || []), ...(result?.live_result?.risk_signals || [])]
}

function topSignals(result, count = 8) {
  const order = { high: 0, medium: 1, low: 2, info: 3 }
  return allSignals(result).slice().sort((a, b) => (order[a?.severity] ?? 9) - (order[b?.severity] ?? 9)).slice(0, count)
}

function riskScore(result) {
  return Number.isFinite(result?.risk_score) ? result.risk_score : 0
}

function finalHost(result) {
  return result?.analysis?.destination_behavior?.final_host || result?.live_result?.final_host || result?.static_result?.host || "unresolved"
}

function rootDomain(result) {
  return result?.static_result?.root_domain || result?.static_result?.host || finalHost(result)
}

function redirectCount(result) {
  const chain = result?.live_result?.redirect_chain || []
  if (Number.isFinite(result?.analysis?.destination_behavior?.redirect_count)) return result.analysis.destination_behavior.redirect_count
  return Math.max(0, chain.length - 1)
}

function hasValue(value) {
  if (value === 0 || value === false) return true
  if (Array.isArray(value)) return value.length > 0
  const text = String(value ?? "").trim()
  return Boolean(text) && !["n/a", "unknown", "null", "undefined", "none"].includes(text.toLowerCase())
}

function valueRows(rows) {
  return rows.filter(([, value]) => hasValue(value))
}

function makeInventory(result) {
  const staticResult = result?.static_result || {}
  const live = result?.live_result || {}
  const queryParams = staticResult.query_params || []
  const iocs = staticResult.extracted_iocs || {}
  const chain = live.redirect_chain || []
  const urls = [
    result?.input?.normalized,
    result?.input?.refanged,
    live.final_url,
    ...chain.map((hop) => hop.url),
  ].filter(Boolean)
  const domains = [staticResult.host, staticResult.root_domain, live.final_host, ...chain.map((hop) => hop.host)].filter(Boolean)
  const ips = [
    ...(iocs.ip_addresses || []),
    ...(iocs.ips || []),
    ...(live.resolved_ips || []),
    ...chain.flatMap((hop) => hop.resolved_ips || []),
    ...chain.flatMap((hop) => hop.next_resolved_ips || []),
  ].filter(Boolean)
  const params = queryParams.map((param) => `${param.name}=${(param.values || []).join(", ")}`)
  const encodedStrings = (staticResult.decoded_query_hints || []).map((hint) => `${hint.parameter}: ${hint.preview}`)
  const keywords = (allSignals(result) || []).filter((signal) => ["credential_wording", "brand_terms", "brand_impersonation_mismatch"].includes(signal.id)).map((signal) => signal.evidence)
  const pathTokens = String(staticResult.path || "").split(/[/_.-]+/).filter((token) => token.length > 2)
  return [
    { key: "urls", title: "URLs", tone: "cyan", items: unique(urls), action: "Send URL" },
    { key: "domains", title: "Domains", tone: "emerald", items: unique(domains), action: "Send to Recon" },
    { key: "ips", title: "IPs", tone: "amber", items: unique(ips), action: "Send to Recon" },
    { key: "params", title: "Query parameters", tone: "violet", items: unique(params), action: "Decode" },
    { key: "redirects", title: "Redirect hosts", tone: "rose", items: unique(chain.map((hop) => hop.host || hop.location).filter(Boolean)), action: "Compare" },
    { key: "tokens", title: "Path tokens", tone: "cyan", items: unique(pathTokens), action: "Copy" },
    { key: "encoded", title: "Encoded strings", tone: "amber", items: unique(encodedStrings), action: "Send to CyberChef" },
    { key: "keywords", title: "Suspicious keywords", tone: "rose", items: unique(keywords), action: "Add finding" },
  ]
}

function unique(items) {
  return [...new Set(items.map((item) => String(item || "").trim()).filter(Boolean))]
}

function FieldRow({ label, value, mono = false, action }) {
  if (!hasValue(value)) return null
  return (
    <div className="url-field-row">
      <span>{label}</span>
      <code className={mono ? "is-mono" : ""}>{String(value)}</code>
      {action}
    </div>
  )
}

function StatusBadge({ children, tone = "neutral", icon: Icon }) {
  return (
    <span className={`url-badge is-${tone}`}>
      {Icon ? <Icon size={13} /> : null}
      {children}
    </span>
  )
}

function SectionHeader({ eyebrow, title, subtitle, icon: Icon, compact = false }) {
  return (
    <div className={`url-section-head ${compact ? "is-compact" : ""}`}>
      <div>
        {eyebrow && <p>{Icon ? <Icon size={14} /> : null}{eyebrow}</p>}
        <h2>{title}</h2>
        {subtitle && <span>{subtitle}</span>}
      </div>
    </div>
  )
}

function SummaryMetric({ label, value, tone = "neutral", detail }) {
  return (
    <article className={`url-metric-card is-${tone}`}>
      <span>{label}</span>
      <strong>{value}</strong>
      {detail && <small>{detail}</small>}
    </article>
  )
}

function ModeSelector({ mode, setMode }) {
  const modes = [
    { id: "static", title: "Static-first", detail: "No network request. Parse and score URL structure." },
    { id: "metadata", title: "Local/backend", detail: "Guarded DNS/HTTP/TLS metadata only." },
    { id: "compare", title: "Compare sources", detail: "Local parse, backend observations, heuristics, and limitations." },
  ]
  return (
    <div className="url-mode-grid" role="radiogroup" aria-label="URL analysis mode">
      {modes.map((item) => (
        <button key={item.id} type="button" className={mode === item.id ? "is-active" : ""} onClick={() => setMode(item.id)}>
          <strong>{item.title}</strong>
          <span>{item.detail}</span>
        </button>
      ))}
    </div>
  )
}

function SampleAndHelpers({ sampleType, setSampleType, onLoadSample, onDefang, onRefang, onDecode, onClear }) {
  return (
    <div className="url-helper-row">
      <select value={sampleType} onChange={(event) => setSampleType(event.target.value)} aria-label="Choose sample URL">
        <option value="credential">Credential phishing URL</option>
        <option value="shortener">Shortened URL</option>
        <option value="punycode">Punycode domain</option>
        <option value="query">Suspicious query parameters</option>
        <option value="redirect">Redirect chain</option>
        <option value="benign">Benign login URL</option>
      </select>
      <button type="button" onClick={onLoadSample}><Search className="h-4 w-4" /> Load sample</button>
      <button type="button" onClick={onDefang}><Shield className="h-4 w-4" /> Defang</button>
      <button type="button" onClick={onRefang}><Shield className="h-4 w-4" /> Refang</button>
      <button type="button" onClick={onDecode}><Code2 className="h-4 w-4" /> Decode</button>
      <button type="button" onClick={onClear}><XCircle className="h-4 w-4" /> Clear</button>
    </div>
  )
}

function UrlInputDesk({ url, setUrl, mode, setMode, sampleType, setSampleType, onLoadSample, onAnalyze, loading, error, notice, incomingSource, onDefang, onRefang, onDecode, onClear }) {
  return (
    <section className="url-input-desk url-paper-card">
      <div className="url-card-label">URL_REVIEW_DESK.md</div>
      <div className="url-input-head">
        <div>
          <p className="url-kicker"><Link2 size={14} className="inline mr-1" /> Safe link review</p>
          <h1>Safe URL Analyzer</h1>
          <span>Inspect suspicious links, redirects, host signals, and URL structure before routing evidence into a case.</span>
        </div>
        <div className="url-local-note"><LockKeyhole size={15} className="inline mr-1" /> local/session-first</div>
      </div>
      <textarea
        value={url}
        onChange={(event) => setUrl(event.target.value)}
        placeholder="Paste one or many URLs, defanged links, email-extracted links, shortened URLs, encoded URLs, or suspicious query strings…\n\nhxxps[:]//login-example[.]com/reset?id=1234\nhttps://bit.ly/example\nhttps://example.com/auth?redirect_uri=..."
        spellcheck={false}
      />
      <div className="url-input-actions">
        <SampleAndHelpers
          sampleType={sampleType}
          setSampleType={setSampleType}
          onLoadSample={onLoadSample}
          onDefang={onDefang}
          onRefang={onRefang}
          onDecode={onDecode}
          onClear={onClear}
        />
        <button type="button" className="url-primary-button" onClick={onAnalyze} disabled={loading}>
          {loading ? <Loader2 className="url-spin" size={17} /> : <SearchCheck size={17} />}
          {loading ? "Analyzing…" : "Analyze URL"}
        </button>
      </div>
      {incomingSource && <p className="url-inline-notice"><Sparkles size={14} className="inline mr-1" /> Loaded from {incomingSource}</p>}
      {notice && <p className="url-inline-notice"><CheckCircle2 size={14} className="inline mr-1" /> {notice}</p>}
      {error && <p className="url-inline-error"><AlertTriangle size={14} className="inline mr-1" /> {error}</p>}
      <ModeSelector mode={mode} setMode={setMode} />
    </section>
  )
}

function SafetyControls({ options, setOptions, mode }) {
  const rows = [
    ["noJs", "Do not execute JavaScript"],
    ["noDownloads", "Do not download files"],
    ["followRedirects", "Follow redirects safely"],
    ["headersOnly", "Capture headers only"],
    ["stopBeforeFinal", "Stop before final destination"],
  ]
  return (
    <aside className="url-side-stack">
      <section className="url-paper-card url-control-panel">
        <SectionHeader eyebrow="Safety mode" title={modeLabel(mode)} icon={SlidersHorizontal} compact />
        <div className="url-toggle-list">
          {rows.map(([key, label]) => (
            <label key={key}>
              <input type="checkbox" checked={Boolean(options[key])} onChange={(event) => setOptions((current) => ({ ...current, [key]: event.target.checked }))} />
              <span>{label}</span>
            </label>
          ))}
        </div>
      </section>
      <section className="url-paper-card url-privacy-panel">
        <div className="url-mini-icon is-violet"><LockKeyhole size={18} /></div>
        <h3>Local-first boundary</h3>
        <p>Static parsing runs locally. Backend metadata checks are explicit and do not render pages, execute JavaScript, submit forms, or download files.</p>
      </section>
      <section className="url-paper-card url-next-panel">
        <SectionHeader eyebrow="What happens next" title="Evidence path" icon={GitBranch} compact />
        <ol>
          <li>Normalize/refang safely</li>
          <li>Parse host, path, query, tokens</li>
          <li>Score suspicious URL signals</li>
          <li>Prepare pivots and report evidence</li>
        </ol>
      </section>
    </aside>
  )
}

function NormalizationPreview({ url }) {
  const parsed = tryUrl(url)
  const normalized = parsed?.href || "Waiting for URL"
  const rows = valueRows([
    ["Original input", url || "—"],
    ["Normalized URL", normalized],
    ["Defanged URL", parsed ? defangText(normalized) : "—"],
    ["Host", parsed?.hostname || "—"],
    ["Path", parsed?.pathname || "—"],
    ["Query", parsed?.search ? parsed.search.slice(1) : "—"],
  ])
  return (
    <section className="url-paper-card url-normalize-preview">
      <SectionHeader eyebrow="Preview" title="Normalization preview" subtitle="Shows how BeyondArch will treat the submitted link before analysis." icon={Clipboard} compact />
      <div className="url-field-table">
        {rows.map(([label, value]) => <FieldRow key={label} label={label} value={value} mono />)}
      </div>
    </section>
  )
}

function EmptyPreview() {
  const cards = [
    ["URL Structure", "Scheme, host, root domain, path, query parameters, encoding."],
    ["Redirect Chain", "Safe metadata steps when backend checks are enabled."],
    ["Domain Signals", "Root domain, TLS, DNS/HTTP observations, limitations."],
    ["HTTP Headers", "Headers only; no JS execution, rendering, or downloads."],
    ["Risk Findings", "Signals, evidence, confidence, suggested handoff."],
  ]
  return (
    <section className="url-empty-preview">
      <Globe className="h-10 w-10 text-zinc-500 mx-auto mb-4" />
      {cards.map(([title, detail], index) => (
        <article key={title} style={{ "--delay": `${index * 60}ms` }}>
          <span>{String(index + 1).padStart(2, "0")}</span>
          <strong>{title}</strong>
          <p>{detail}</p>
        </article>
      ))}
    </section>
  )
}

function EmptyState({ url, setUrl, mode, setMode, sampleType, setSampleType, onLoadSample, onAnalyze, loading, error, notice, incomingSource, options, setOptions, helpers }) {
  return (
    <div className="url-empty-layout">
      <div className="url-empty-main">
        <UrlInputDesk
          url={url}
          setUrl={setUrl}
          mode={mode}
          setMode={setMode}
          sampleType={sampleType}
          setSampleType={setSampleType}
          onLoadSample={onLoadSample}
          onAnalyze={onAnalyze}
          loading={loading}
          error={error}
          notice={notice}
          incomingSource={incomingSource}
          {...helpers}
        />
        <NormalizationPreview url={url} />
        <EmptyPreview />
      </div>
      <SafetyControls options={options} setOptions={setOptions} mode={mode} />
    </div>
  )
}

function ResultHeader({ result, mode, onAnalyze, onClear, loading }) {
  const staticResult = result?.static_result || {}
  const verdictTone = toneForVerdict(result?.verdict)
  return (
    <section className="url-result-hero url-paper-card">
      <div className="url-result-title">
        <p className="url-kicker"><Link2 size={14} className="inline mr-1" /> {modeLabel(mode)}</p>
        <h1>{staticResult.host || "URL Review"}</h1>
        <span>ID: BARCH-URL-{String(result?.checked_at || "LOCAL").replace(/\D/g, "").slice(-8) || "LOCAL"}</span>
      </div>
      <div className="url-target-card">
        <span className="url-mini-icon is-cyan"><Link2 size={20} /></span>
        <div>
          <small>Target artifact</small>
          <strong>{result?.input?.normalized || result?.input?.refanged || result?.input?.original}</strong>
          <dl>
            <div><dt>Host</dt><dd>{staticResult.host || "—"}</dd></div>
            <div><dt>Root domain</dt><dd>{staticResult.root_domain || "—"}</dd></div>
            <div><dt>Checked</dt><dd>{result?.checked_at ? new Date(result.checked_at).toLocaleString() : "local"}</dd></div>
          </dl>
        </div>
        <div className="url-risk-index">
          <span>Risk score</span>
          <strong className={`is-${verdictTone}`}>{riskScore(result)}/100</strong>
        </div>
      </div>
      <div className="url-result-actions">
        <StatusBadge tone={verdictTone} icon={result?.verdict === "low_risk" ? ShieldCheck : ShieldAlert}>{labelize(result?.verdict || "needs_review")}</StatusBadge>
        <button type="button" onClick={onAnalyze} disabled={loading}>{loading ? <Loader2 className="url-spin" size={15} /> : <RefreshCcw size={15} />} Re-analyze</button>
        <button type="button" onClick={onClear}>Clear</button>
      </div>
    </section>
  )
}

function SummaryRow({ result }) {
  const counts = result?.analysis?.severity_counts || {}
  return (
    <div className="url-summary-row">
      <SummaryMetric label="Verdict" value={labelize(result?.verdict || "needs_review")} tone={toneForVerdict(result?.verdict)} detail={result?.confidence || "local confidence"} />
      <SummaryMetric label="Host/domain" value={rootDomain(result)} tone="cyan" detail={finalHost(result)} />
      <SummaryMetric label="Redirects" value={redirectCount(result)} tone={redirectCount(result) ? "amber" : "emerald"} detail={result?.live_result?.enabled ? "metadata observed" : "not fetched"} />
      <SummaryMetric label="Signals" value={`${counts.high || 0}/${counts.medium || 0}/${counts.low || 0}`} tone={(counts.high || 0) ? "rose" : "violet"} detail="high / medium / low" />
      <SummaryMetric label="Report-ready" value="Yes" tone="emerald" detail="case finding available" />
    </div>
  )
}

function UrlStructurePanel({ result }) {
  const staticResult = result?.static_result || {}
  const rows = valueRows([
    ["Scheme", staticResult.scheme],
    ["Host", staticResult.host],
    ["Root domain", staticResult.root_domain],
    ["Port", staticResult.port],
    ["Path", staticResult.path],
    ["Query", staticResult.query],
    ["Fragment", staticResult.fragment],
    ["Defanged", defangText(result?.input?.normalized || "")],
    ["Decoded", decodeURIComponentSafe(result?.input?.normalized || "")],
  ])
  return (
    <section className="url-paper-card">
      <SectionHeader eyebrow="Static parser" title="URL structure" subtitle="Parsed components used for safe review and routing." icon={Code2} compact />
      <div className="url-field-table">
        {rows.map(([label, value]) => <FieldRow key={label} label={label} value={value} mono />)}
      </div>
    </section>
  )
}

function decodeURIComponentSafe(value) {
  try {
    const decoded = decodeURIComponent(value)
    return decoded !== value ? decoded : ""
  } catch {
    return ""
  }
}

function SuspiciousPatternPanel({ result }) {
  const signals = allSignals(result)
  return (
    <section className="url-paper-card">
      <SectionHeader eyebrow="Risk signals" title="Suspicious pattern review" subtitle="Every signal keeps evidence, reason, source, and confidence boundary visible." icon={AlertTriangle} compact />
      <div className="url-signal-list">
        {signals.length ? signals.map((signal, index) => (
          <article key={`${signal.id}-${index}`} className={`is-${toneForSeverity(signal.severity)}`}>
            <div>
              <StatusBadge tone={toneForSeverity(signal.severity)}>{signal.severity || "info"}</StatusBadge>
              <strong>{signal.label || labelize(signal.id || "signal")}</strong>
            </div>
            <p>{signal.why || signal.reason || "Signal requires analyst review."}</p>
            <code>{signal.evidence || "No evidence text provided"}</code>
            <small>Source: {signal.source === "safe_fetch" ? "backend metadata" : "local URL parser"}</small>
          </article>
        )) : (
          <article className="is-emerald"><div><StatusBadge tone="emerald">No high-risk local signal</StatusBadge><strong>No suspicious URL pattern found</strong></div><p>This does not prove safety; it only means the static parser did not observe strong local evidence.</p></article>
        )}
      </div>
    </section>
  )
}

function RedirectReview({ result }) {
  const live = result?.live_result || {}
  const chain = live.redirect_chain || []
  return (
    <section className="url-paper-card">
      <SectionHeader eyebrow="Destination" title="Redirect and metadata review" subtitle="Header/redirect metadata only. No browser rendering or JavaScript execution." icon={GitBranch} compact />
      {live.blocked_reason && <p className="url-warning-box"><AlertTriangle size={15} className="inline mr-1" /> {live.blocked_reason}</p>}
      {chain.length ? (
        <div className="url-redirect-chain">
          {chain.map((hop, index) => (
            <article key={`${hop.hop}-${hop.url}`}>
              <span>{String(hop.hop || index + 1).padStart(2, "0")}</span>
              <div>
                <strong>{hop.host || "unknown host"}</strong>
                <code>{hop.url}</code>
                <small>{hop.status_code || "blocked"} · {hop.notes || "Header metadata collected"}</small>
              </div>
            </article>
          ))}
        </div>
      ) : (
        <div className="url-empty-evidence">
          <strong>{live.enabled ? "No redirect chain collected" : "Static mode did not fetch redirects"}</strong>
          <p>Enable Local/backend checks or Compare Sources when redirect evidence would change the case decision.</p>
        </div>
      )}
    </section>
  )
}

function HostSignalPanel({ result }) {
  const live = result?.live_result || {}
  const staticResult = result?.static_result || {}
  const rows = valueRows([
    ["Domain", staticResult.host],
    ["Registrable domain", staticResult.root_domain],
    ["HTTP status", live.status_code],
    ["Final host", live.final_host],
    ["Page title", live.page_title],
    ["TLS subject", live.tls?.subject_common_name],
    ["TLS issuer", live.tls?.issuer_common_name || live.tls?.error],
    ["Server", live.headers?.server],
    ["Content type", live.headers?.["content-type"]],
    ["Set-Cookie present", live.headers?.["set-cookie_present"] || live.headers?.set_cookie_present],
  ])
  return (
    <section className="url-paper-card">
      <SectionHeader eyebrow="Host signals" title="Domain / HTTP / TLS observations" subtitle="Clearly separated from heuristic conclusions." icon={Globe2} compact />
      <div className="url-field-table">
        {rows.length ? rows.map(([label, value]) => <FieldRow key={label} label={label} value={value} mono />) : <div className="url-empty-evidence"><strong>No network metadata</strong><p>This run stayed static-first.</p></div>}
      </div>
    </section>
  )
}

function InventoryPanel({ result, onCopy, setNotice, onNavigate }) {
  const groups = makeInventory(result)
  return (
    <section className="url-paper-card url-inventory-panel">
      <SectionHeader eyebrow="Inventory" title="Full extracted URL artifact inventory" subtitle="Readable rows with copy and route actions. No narrow value pills." icon={Clipboard} compact />
      <div className="url-inventory-grid">
        {groups.map((group) => (
          <article key={group.key} className={`is-${group.tone}`}>
            <header><strong>{group.title}</strong><span>{group.items.length}</span></header>
            <div className="url-inventory-list">
              {group.items.length ? group.items.slice(0, 8).map((item) => (
                <div key={item}>
                  <code>{item}</code>
                  <button type="button" onClick={() => onCopy(item, setNotice, group.title)}>Copy</button>
                  {group.key === "domains" || group.key === "ips" ? <button type="button" onClick={() => onNavigate("recon-exposure", { type: group.key === "ips" ? "ip" : "domain", value: item, target: "recon-exposure" })}>Recon</button> : null}
                  {group.key === "urls" ? <button type="button" onClick={() => onNavigate("phishing-triage", { type: "url", value: item, target: "phishing-triage" })}>Phishing</button> : null}
                  {group.key === "encoded" || group.key === "params" ? <button type="button" onClick={() => onNavigate("cyberchef", { type: "text", value: item, target: "cyberchef" })}>CyberChef</button> : null}
                </div>
              )) : <p>None extracted.</p>}
            </div>
          </article>
        ))}
      </div>
    </section>
  )
}

function EvidenceCards({ result }) {
  const signals = topSignals(result, 6)
  return (
    <section className="url-paper-card">
      <SectionHeader eyebrow="Evidence" title="Evidence cards" subtitle="Case-ready findings with reason, limitation, and suggested action." icon={ShieldAlert} compact />
      <div className="url-evidence-grid">
        {signals.length ? signals.map((signal, index) => (
          <article key={`${signal.id}-${index}`} className={`is-${toneForSeverity(signal.severity)}`}>
            <header><span>EV-{String(index + 1).padStart(3, "0")}</span><StatusBadge tone={toneForSeverity(signal.severity)}>{signal.severity}</StatusBadge></header>
            <h3>{signal.label}</h3>
            <p>{signal.why || "Review this signal with case context."}</p>
            <code>{signal.evidence || signal.id}</code>
            <small>Suggested action: {actionForSignal(signal)}</small>
          </article>
        )) : <div className="url-empty-evidence"><strong>No evidence cards generated</strong><p>Run metadata checks or review the source context if the URL came from an email/report.</p></div>}
      </div>
    </section>
  )
}

function actionForSignal(signal) {
  const id = signal?.id || ""
  if (id.includes("brand") || id.includes("credential") || id.includes("email")) return "Send to Phishing Triage and add a report finding."
  if (id.includes("shortener") || id.includes("redirect")) return "Inspect redirect metadata and pivot both domains."
  if (id.includes("extension") || id.includes("download")) return "Do not download; use Attachment Triage/static review."
  if (id.includes("private") || id.includes("internal") || id.includes("blocked")) return "Keep block reason as evidence; do not retry without approval."
  return "Pivot host/root domain in Recon and logs."
}

function ReportReadySummary({ result }) {
  const signals = topSignals(result, 4)
  return (
    <section className="url-paper-card url-report-panel">
      <SectionHeader eyebrow="Case report" title="Report-ready URL finding" subtitle="Concise output for case notes or stakeholder review." icon={FileJson} compact />
      <div className="url-report-box">
        <p><strong>Finding:</strong> {result?.analysis?.conclusion || result?.summary || "URL review completed."}</p>
        <p><strong>Primary concern:</strong> {result?.analysis?.primary_concern || "No primary concern recorded."}</p>
        <p><strong>Evidence:</strong> {signals.length ? signals.map((signal) => signal.label).join("; ") : "No high-value local signal observed."}</p>
        <p><strong>Limitations:</strong> {(result?.analysis?.missing_evidence || result?.limitations || []).slice(0, 2).join(" ")}</p>
        <p><strong>Next step:</strong> {result?.analysis?.next_best_action || (result?.recommended_actions || [])[0] || "Pivot in Recon and case timeline."}</p>
      </div>
    </section>
  )
}

function VerdictRail({ result, markdown, rawJson, setNotice, onCopy, onNavigate, setPage }) {
  const scoreRows = result?.analysis?.score_breakdown || []
  const missing = result?.analysis?.missing_evidence || result?.limitations || []
  const normalized = result?.input?.normalized || ""
  return (
    <aside className="url-result-rail">
      <section className="url-paper-card url-score-card">
        <p>Risk index</p>
        <strong>{riskScore(result)}<span>/100</span></strong>
        <div><i style={{ width: `${Math.min(100, riskScore(result))}%` }} /></div>
        <small>{result?.analysis?.score_explanation || result?.summary}</small>
      </section>
      <section className="url-paper-card url-score-drivers">
        <SectionHeader eyebrow="Drivers" title="Score breakdown" icon={AlertTriangle} compact />
        {scoreRows.length ? scoreRows.slice(0, 6).map((row, index) => (
          <article key={`${row.signal}-${index}`}>
            <span>+{row.points}</span>
            <div><strong>{row.signal}</strong><p>{row.evidence}</p></div>
          </article>
        )) : <p>No strong risk drivers recorded.</p>}
      </section>
      <section className="url-paper-card url-action-panel">
        <SectionHeader eyebrow="Send to" title="Case handoff" icon={ArrowRight} compact />
        <SendToActions
          payload={{
            type: "url",
            title: `URL review: ${normalized}`,
            value: normalized,
            summary: `${result?.verdict || "needs_review"} · ${result?.analysis?.primary_concern || result?.analysis?.category || "URL evidence"}`,
            confidence: result?.confidence || result?.evidence_level || "unknown",
            tags: ["url", result?.verdict || "needs-review", result?.static_result?.root_domain || result?.static_result?.host || ""].filter(Boolean),
            raw: markdown || rawJson,
          }}
          source="Safe URL Analyzer"
          setPage={setPage}
        />
        <button type="button" onClick={() => onNavigate("recon-exposure", { type: "domain", value: rootDomain(result), target: "recon-exposure" })}><Radar size={15} /> Recon & Exposure</button>
        <button type="button" onClick={() => onNavigate("phishing-triage", { type: "url", value: normalized, target: "phishing-triage" })}><ShieldAlert size={15} /> Phishing Triage</button>
        <button type="button" onClick={() => onCopy(defangText(normalized), setNotice, "Defanged URL")}><Copy size={15} /> Copy defanged URL</button>
        <button type="button" onClick={() => {
          const entry = addTimelineArtifact({ title: `URL review: ${normalized}`, summary: result?.analysis?.conclusion || result?.summary || "URL evidence", source: "Safe URL Analyzer", raw: markdown || rawJson, tags: [result?.verdict || "url"] })
          setNotice(`Added to Case Timeline: ${entry.title}`)
        }}><GitBranch size={15} /> Add timeline note</button>
      </section>
      <section className="url-paper-card url-limitations-panel">
        <SectionHeader eyebrow="Boundary" title="Limitations" icon={LockKeyhole} compact />
        <ul>{missing.slice(0, 6).map((item) => <li key={item}>{item}</li>)}</ul>
      </section>
    </aside>
  )
}

function StaticResults({ result, markdown, rawJson, setNotice, onCopy, onNavigate, setPage }) {
  return (
    <div className="url-workspace-grid">
      <main className="url-workspace-main">
        <div className="url-two-up">
          <UrlStructurePanel result={result} />
          <HostSignalPanel result={result} />
        </div>
        <SuspiciousPatternPanel result={result} />
        <RedirectReview result={result} />
        <InventoryPanel result={result} onCopy={onCopy} setNotice={setNotice} onNavigate={onNavigate} />
        <EvidenceCards result={result} />
        <ReportReadySummary result={result} />
        <RawDetails rawJson={rawJson} />
      </main>
      <VerdictRail result={result} markdown={markdown} rawJson={rawJson} setNotice={setNotice} onCopy={onCopy} onNavigate={onNavigate} setPage={setPage} />
    </div>
  )
}

function CompareMatrix({ result }) {
  const live = result?.live_result || {}
  const staticResult = result?.static_result || {}
  const localSignals = result?.static_result?.risk_signals || []
  const networkSignals = live.risk_signals || []
  const rows = [
    ["Host", staticResult.host || "—", live.final_host || "not fetched", staticResult.host ? "agrees on submitted host" : "missing host"],
    ["Final destination", result?.input?.normalized || "—", live.final_url || "unknown", live.final_url ? "observed by backend metadata" : "not observed"],
    ["Redirects", "static cannot confirm", redirectCount(result), live.enabled ? "backend observed" : "not checked"],
    ["Risk signals", localSignals.length, networkSignals.length, allSignals(result).length ? "evidence present" : "no major signal"],
    ["Reputation", "not checked", "not checked", "external intel optional only"],
    ["TLS/cert", "not checked", live.tls?.issuer_common_name || live.tls?.error || "not checked", live.tls ? "backend observation" : "missing"],
  ]
  return (
    <section className="url-paper-card">
      <SectionHeader eyebrow="Compare sources" title="Source comparison matrix" subtitle="Local parse, backend observations, heuristics, and optional external intel are separated." icon={SlidersHorizontal} compact />
      <div className="url-comparison-table">
        <div className="url-comparison-head"><span>Question</span><span>Local parse</span><span>Backend DNS/HTTP/TLS</span><span>Assessment</span></div>
        {rows.map(([question, local, backend, assessment]) => (
          <div key={question}>
            <strong>{question}</strong><code>{String(local)}</code><code>{String(backend)}</code><span>{assessment}</span>
          </div>
        ))}
      </div>
    </section>
  )
}

function AgreementConflict({ result }) {
  const live = result?.live_result || {}
  const signals = allSignals(result)
  const agreements = [
    result?.static_result?.host && `Submitted host parsed as ${result.static_result.host}.`,
    signals.length && `${signals.length} combined signal(s) influenced the assessment.`,
    live.enabled && !live.blocked_reason && "Backend metadata completed without browser rendering or JavaScript execution.",
  ].filter(Boolean)
  const conflicts = [
    !live.enabled && "No backend metadata was collected, so redirect/final host cannot be confirmed.",
    live.blocked_reason && `Backend metadata blocked: ${live.blocked_reason}`,
    live.final_host && result?.static_result?.host && live.final_host !== result.static_result.host && `Final host differs from submitted host: ${result.static_result.host} → ${live.final_host}.`,
    "External reputation is not enabled, so vendor/blocklist consensus is unavailable.",
  ].filter(Boolean)
  return (
    <div className="url-two-up">
      <section className="url-paper-card url-agree-card">
        <SectionHeader eyebrow="Agreement" title="What sources support" icon={CheckCircle2} compact />
        <ul>{agreements.length ? agreements.map((item) => <li key={item}>{item}</li>) : <li>No strong agreement observed yet.</li>}</ul>
      </section>
      <section className="url-paper-card url-conflict-card">
        <SectionHeader eyebrow="Conflict" title="What remains uncertain" icon={XCircle} compact />
        <ul>{conflicts.map((item) => <li key={item}>{item}</li>)}</ul>
      </section>
    </div>
  )
}

function ConfidenceAssessment({ result }) {
  const gaps = result?.analysis?.missing_evidence || result?.limitations || []
  return (
    <section className="url-paper-card">
      <SectionHeader eyebrow="Confidence" title={`${labelize(result?.confidence || "medium")} confidence assessment`} subtitle={result?.analysis?.confidence_reason} icon={ShieldCheck} compact />
      <div className="url-confidence-grid">
        <article><strong>Source quality</strong><p>{result?.analysis?.mode || "static/local"}</p></article>
        <article><strong>Evidence level</strong><p>{result?.evidence_level || "heuristic"}</p></article>
        <article><strong>Decision boundary</strong><p>{(result?.analysis?.decision_boundaries || [])[0] || "This is a triage result, not final proof."}</p></article>
      </div>
      <ul className="url-compact-list">{gaps.slice(0, 4).map((gap) => <li key={gap}>{gap}</li>)}</ul>
    </section>
  )
}

function AnalystRecommendation({ result }) {
  return (
    <section className={`url-paper-card url-recommendation-card is-${toneForVerdict(result?.verdict)}`}>
      <SectionHeader eyebrow="Analyst recommendation" title={labelize(result?.verdict || "needs_review")} icon={Sparkles} compact />
      <p>{result?.analysis?.conclusion || result?.summary || "Review with case context."}</p>
      <div className="url-report-box">
        <p><strong>Do next:</strong> {result?.analysis?.next_best_action || "Pivot host/root domain in Recon and logs."}</p>
        <p><strong>Do not conclude:</strong> {(result?.analysis?.decision_boundaries || [])[0] || "Do not treat this as vendor reputation or proof of safety."}</p>
      </div>
    </section>
  )
}

function CompareResults({ result, markdown, rawJson, setNotice, onCopy, onNavigate, setPage }) {
  return (
    <div className="url-workspace-grid">
      <main className="url-workspace-main">
        <CompareMatrix result={result} />
        <AgreementConflict result={result} />
        <ConfidenceAssessment result={result} />
        <SuspiciousPatternPanel result={result} />
        <InventoryPanel result={result} onCopy={onCopy} setNotice={setNotice} onNavigate={onNavigate} />
        <AnalystRecommendation result={result} />
        <RawDetails rawJson={rawJson} />
      </main>
      <VerdictRail result={result} markdown={markdown} rawJson={rawJson} setNotice={setNotice} onCopy={onCopy} onNavigate={onNavigate} setPage={setPage} />
    </div>
  )
}

function RawDetails({ rawJson }) {
  return (
    <details className="url-paper-card url-raw-details">
      <summary><FileJson size={16} /> Raw details / parsed JSON</summary>
      <pre>{rawJson}</pre>
    </details>
  )
}

function RecentChecks({ items, onSelect }) {
  if (!items.length) return null
  return (
    <section className="url-recent-row">
      <span>Recent URL checks</span>
      {items.map((item) => (
        <button key={`${item.normalized}-${item.time}`} type="button" onClick={() => onSelect(item.normalized)}>
          <code>{item.normalized}</code>
          <small>{labelize(item.verdict || "review")}</small>
        </button>
      ))}
    </section>
  )
}

export default function SafeUrlAnalyzerPage({ setPage }) {
  const [initialArtifact] = useState(() => readInitialArtifact())
  const [url, setUrl] = useState(() => initialArtifact.url)
  const [analysisMode, setAnalysisMode] = useState("static")
  const [sampleType, setSampleType] = useState("credential")
  const [options, setOptions] = useState({ noJs: true, noDownloads: true, followRedirects: true, headersOnly: true, stopBeforeFinal: false })
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState("")
  const [notice, setNotice] = useState(() => initialArtifact.url ? `Loaded URL artifact from ${initialArtifact.source || "BeyondArch"}.` : "")
  const [recent, setRecent] = useState(() => loadRecent())

  const rawJson = useMemo(() => (result ? JSON.stringify(result, null, 2) : ""), [result])
  const markdown = useMemo(() => buildFindingMarkdown(result), [result])

  useEffect(() => {
    if (!notice) return undefined
    const timer = window.setTimeout(() => setNotice(""), 2600)
    return () => window.clearTimeout(timer)
  }, [notice])

  async function run() {
    const trimmed = extractUrlCandidate(url) || refangText(url).trim()
    if (!trimmed) {
      setError("Paste a URL before running analysis.")
      return
    }
    setLoading(true)
    setError("")
    setNotice("")
    try {
      const data = await safeAnalyzeUrl({
        url: trimmed,
        allow_live_fetch: analysisMode === "metadata" || analysisMode === "compare",
        max_redirects: options.followRedirects ? 5 : 0,
        timeout_seconds: 8,
        allow_private_targets: false,
      })
      setResult(data)
      setRecent(storeRecent({ normalized: data.input?.normalized || trimmed, verdict: data.verdict, confidence: data.confidence, mode: analysisMode, time: new Date().toISOString() }))
      setNotice(`${modeLabel(analysisMode)} complete`)
    } catch (analysisError) {
      setError(analysisError?.message || "URL analysis failed.")
    } finally {
      setLoading(false)
    }
  }

  function loadSample() {
    setUrl(SAMPLE_URLS[sampleType] || SAMPLE_URLS.credential)
    setResult(null)
    setError("")
    setNotice("Sample loaded")
  }

  function clearAll() {
    setUrl("")
    setResult(null)
    setError("")
    setNotice("URL cleared")
  }

  function selectRecent(nextUrl) {
    setUrl(nextUrl)
    setResult(null)
    setError("")
    setNotice("Recent URL loaded")
  }

  function navigateWithArtifact(page, artifact = {}) {
    const value = artifact.value || result?.input?.normalized || extractUrlCandidate(url) || url.trim()
    const payload = {
      type: artifact.type || "url",
      value,
      content: artifact.content,
      label: artifact.label,
      suggested_recipe: artifact.suggested_recipe,
      defanged: defangText(value),
      source: "safe-url-analyzer",
      target: artifact.target || page,
      host: result?.live_result?.final_host || result?.static_result?.host || "",
      root_domain: result?.static_result?.root_domain || "",
      checked_at: result?.checked_at || new Date().toISOString(),
      source_artifact: artifact.source_artifact,
    }
    try {
      window.localStorage.setItem(PENDING_KEY, JSON.stringify(payload))
    } catch {
      // localStorage can be unavailable in strict private contexts.
    }
    setPage?.(page)
  }

  const helpers = {
    onDefang: () => setUrl((current) => defangText(current || "")),
    onRefang: () => setUrl((current) => refangText(current || "")),
    onDecode: () => setUrl((current) => decodeURIComponentSafe(current || "") || current),
    onClear: clearAll,
  }

  return (
    <WorkbenchPage className="ba-workbench ba-safe-url-page">
      <WorkbenchHeader
        eyebrow="URL analysis"
        title="Safe URL Analyzer"
        subtitle="Analyze links with static-first checks, redirect context, metadata extraction, and safe-browsing comparison."
        icon={Link2}
        chips={[
          { label: "static-first", tone: "local" },
          { label: analysisMode === "compare" ? "compare mode" : "single analysis", tone: analysisMode === "compare" ? "warning" : "info" },
          { label: "local-only", tone: "success" },
        ]}
      />
      {!result ? (
        <>
          <EmptyState
            url={url}
            setUrl={setUrl}
            mode={analysisMode}
            setMode={setAnalysisMode}
            sampleType={sampleType}
            setSampleType={setSampleType}
            onLoadSample={loadSample}
            onAnalyze={run}
            loading={loading}
            error={error}
            notice={notice}
            incomingSource={initialArtifact.url ? initialArtifact.source : ""}
            options={options}
            setOptions={setOptions}
            helpers={helpers}
          />
          <RecentChecks items={recent} onSelect={selectRecent} />
        </>
      ) : (
        <>
          <ResultHeader result={result} mode={analysisMode} onAnalyze={run} onClear={clearAll} loading={loading} />
          <SummaryRow result={result} />
          {analysisMode === "compare" ? (
            <CompareResults result={result} markdown={markdown} rawJson={rawJson} setNotice={setNotice} onCopy={copyText} onNavigate={navigateWithArtifact} setPage={setPage} />
          ) : (
            <StaticResults result={result} markdown={markdown} rawJson={rawJson} setNotice={setNotice} onCopy={copyText} onNavigate={navigateWithArtifact} setPage={setPage} />
          )}
          <div className="url-floating-actions">
            <button type="button" onClick={() => copyText(markdown, setNotice, "Markdown report")}><Clipboard size={16} /> Copy report</button>
            <button type="button" onClick={() => downloadText("safe-url-analysis.json", rawJson, "application/json")}><FileJson size={16} /> Export JSON</button>
            <button type="button" onClick={() => window.open(`https://transparencyreport.google.com/safe-browsing/search?url=${encodeURIComponent(result?.input?.normalized || "")}`, "_blank", "noopener,noreferrer")}><ExternalLink size={16} /> External check</button>
          </div>
        </>
      )}
    </WorkbenchPage>
  )
}
