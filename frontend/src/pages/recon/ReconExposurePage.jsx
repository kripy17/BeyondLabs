import { useMemo, useState } from "react"
import {
  Clipboard,
  Copy,
  Download,
  FileText,
  Globe,
  Network,
  Radar,
  Route,
  Search,
  Shield,
  ShieldAlert,
  ShieldCheck,
  TerminalSquare,
} from "lucide-react"
import { runReconDnsLookup, runReconWebExposure } from "../../api/backend"
import SendToActions from "../../components/investigation/SendToActions"
import AnalystOutputCard from "../../components/investigation/AnalystOutputCard"
import { WorkbenchHeader, WorkbenchPage, WorkbenchPanel } from "../../components/layout/WorkbenchShell"
import { CompactValueGrid, EvidenceList, ExternalReconLinks, QueryCards } from "../../components/recon/ReconUi"
import { addTimelineArtifact } from "../../lib/timelineStore"
import { downloadText } from "../../lib/domUtils"
import {
  buildExternalReconLinks,
  buildSocQueries,
  computeExposureScore,
  createReconReport,
  dnsRecordRows,
  extractReconIndicators,
  generateExposureReport,
  getTargetValue,
  localReconFindings,
  normalizeTargetInput,
  summarizeRecon,
  targetSnapshotFields,
  webSummaryFields,
} from "../../lib/reconTargetEngine"

const PENDING_KEY = "beyondarch.pendingArtifact"
const ALLOWED_SOURCES = new Set([
  "smart-parser",
  "phishing-triage",
  "safe-url-analyzer",
  "attachment-triage",
  "logs-alerts",
  "cyberchef",
  "detection-mitre",
  "soc-guide",
])

function getPendingReconArtifact() {
  try {
    const raw = localStorage.getItem(PENDING_KEY)
    if (!raw) return { value: "", source: "" }
    const artifact = JSON.parse(raw)
    const target = artifact?.target || artifact?.page
    if (target && target !== "recon-exposure") return { value: "", source: "" }
    if (artifact?.source && !ALLOWED_SOURCES.has(artifact.source)) return { value: "", source: "" }
    const value = artifact?.value || artifact?.content || artifact?.text || artifact?.raw_input || artifact?.host || artifact?.domain || artifact?.ip || artifact?.url || ""
    if (!value) return { value: "", source: "" }
    localStorage.removeItem(PENDING_KEY)
    return { value: String(value), source: artifact?.source || "workflow handoff" }
  } catch {
    return { value: "", source: "" }
  }
}

function storeArtifact({ type, value, target, source = "recon-exposure", content }) {
  localStorage.setItem(PENDING_KEY, JSON.stringify({
    type,
    value,
    content: content || value,
    target,
    page: target,
    source,
    created_at: new Date().toISOString(),
  }))
}

function IndicatorGroups({ indicators, onCopy, onRoute }) {
  const groups = [
    ["URLs", indicators.urls, "url"],
    ["Domains", indicators.domains, "domain"],
    ["IPs", indicators.ips, "ip"],
    ["CIDRs", indicators.cidrs, "cidr"],
    ["Emails", indicators.emails, "email"],
    ["ASNs", indicators.asns, "domain"],
    ["Hashes", indicators.hashes, "hash"],
  ].filter(([, values]) => values?.length)
  if (!groups.length) return <p className="ba-empty-state">No extra indicators extracted from the current input.</p>
  return (
    <div className="grid gap-3 md:grid-cols-2">
      {groups.map(([label, values, type]) => (
        <article key={label} className="rounded-xl border border-white/10 bg-black/40 p-3">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <p className="text-xs font-black uppercase tracking-[0.14em] text-zinc-400">{label} · {values.length}</p>
            <button className="text-xs font-bold text-cyan-100 hover:text-cyan-50" onClick={() => onCopy(values.join("\n"), label)}>Copy</button>
          </div>
          <div className="mt-2 flex flex-wrap gap-2">
            {values.slice(0, 10).map((value) => (
              <button
                key={`${label}-${value}`}
                className="break-all rounded-lg border border-cyan-400/15 bg-cyan-400/10 px-2 py-1 text-left font-mono text-xs text-cyan-50 hover:border-cyan-300/50"
                onClick={() => onRoute(type, value)}
                title="Send this indicator to the best next workflow"
              >
                {value}
              </button>
            ))}
            {values.length > 10 ? <span className="rounded-lg border border-white/10 bg-black/40 px-2 py-1 text-xs text-zinc-300">+{values.length - 10} more</span> : null}
          </div>
        </article>
      ))}
    </div>
  )
}

function DnsResults({ result }) {
  if (!result) return null
  const rows = dnsRecordRows(result)
  const errors = result?.dns?.errors || result?.reverse_dns?.errors || {}
  return (
    <div className="space-y-3">
      {rows.length ? (
        <div className="overflow-auto rounded-xl border border-white/10">
          <table className="w-full min-w-[680px] text-left text-sm">
            <thead className="bg-black/40 text-xs uppercase tracking-[0.14em] text-zinc-400">
              <tr><th className="p-3">Record</th><th className="p-3">Values</th></tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <tr key={row.type} className="border-t border-white/10">
                  <td className="p-3 font-black text-zinc-100">{row.type}</td>
                  <td className="p-3 font-mono text-xs text-zinc-200">{row.records.map((record) => <div key={record} className="break-all py-0.5">{record}</div>)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : <p className="ba-empty-state">DNS/PTR completed, but no record values were returned.</p>}
      {Object.keys(errors).length ? (
        <details className="rounded-xl border border-amber-400/20 bg-amber-400/8 p-3">
          <summary className="cursor-pointer text-sm font-black text-amber-100">Resolver notes</summary>
          <pre className="mt-3 whitespace-pre-wrap rounded-lg bg-black/40 p-3 text-xs text-zinc-100">{JSON.stringify(errors, null, 2)}</pre>
        </details>
      ) : null}
    </div>
  )
}

function WebResults({ result }) {
  if (!result?.review) return null
  const review = result.review
  const http = review.http || {}
  const tls = review.tls || {}
  const cookies = review.cookies || []
  return (
    <div className="space-y-3">
      <CompactValueGrid fields={webSummaryFields(result)} />
      {http.redirect_chain?.length ? (
        <details className="rounded-xl border border-white/10 bg-black/40 p-3">
          <summary className="cursor-pointer text-sm font-black text-zinc-100">Redirect chain · {http.redirect_chain.length} hop(s)</summary>
          <div className="mt-3 overflow-auto rounded-xl border border-white/10">
            <table className="w-full min-w-[720px] text-left text-sm">
              <thead className="bg-black/40 text-xs uppercase tracking-[0.14em] text-zinc-400"><tr><th className="p-3">Hop</th><th className="p-3">Status</th><th className="p-3">URL</th><th className="p-3">Location</th></tr></thead>
              <tbody>{http.redirect_chain.map((hop, index) => <tr key={`${hop.url}-${index}`} className="border-t border-white/10"><td className="p-3">{index + 1}</td><td className="p-3">{hop.status_code}</td><td className="break-all p-3 font-mono text-xs">{hop.url}</td><td className="break-all p-3 font-mono text-xs">{hop.location}</td></tr>)}</tbody>
            </table>
          </div>
        </details>
      ) : null}
      {cookies.length ? (
        <details className="rounded-xl border border-white/10 bg-black/40 p-3">
          <summary className="cursor-pointer text-sm font-black text-zinc-100">Cookie metadata · {cookies.length}</summary>
          <div className="mt-3 grid gap-2 md:grid-cols-2">
            {cookies.map((cookie) => <article key={cookie.name} className="rounded-xl border border-white/10 bg-black/40 p-3"><p className="font-black text-zinc-100">{cookie.name}</p><p className="mt-1 text-xs text-zinc-300">Secure: {String(cookie.secure)} · HttpOnly: {String(cookie.httponly)} · SameSite: {String(cookie.samesite)}</p></article>)}
          </div>
        </details>
      ) : null}
      {tls.error ? <p className="rounded-xl border border-amber-400/20 bg-amber-400/10 p-3 text-sm text-amber-100">TLS note: {tls.error}</p> : null}
    </div>
  )
}

function MetadataCheckPanel({ timeout, setTimeoutValue, dnsLoading, httpLoading, runDns, runHttp, runBoth, dnsResult, webExposure }) {
  return (
    <WorkbenchPanel className="space-y-4">
      <div className="ba-output-section-head">
        <div>
          <p className="ba-output-section-eyebrow"><Shield className="mr-1.5 inline h-3.5 w-3.5" />Authorized metadata checks</p>
          <h2 className="ba-output-section-title">Run backend DNS / HTTP / TLS only when needed</h2>
          <p className="mt-1 max-w-3xl text-sm leading-6 text-zinc-300">Static parsing is local. These buttons call the local backend to observe resolver, HTTP, redirect, TLS, and header metadata for authorized targets.</p>
        </div>
        <div className="flex flex-wrap items-center gap-2 text-sm text-zinc-300">
          <span className="ba-chip ba-status-info">timeout {timeout}s</span>
          <label className="flex items-center gap-2 rounded-xl border border-white/10 bg-black/40 px-3 py-2">
            Timeout
            <input type="number" min="2" max="15" value={timeout} onChange={(event) => setTimeoutValue(event.target.value)} className="w-16 rounded-lg border border-white/10 bg-black/40 px-2 py-1 text-sm text-zinc-100 outline-none" />
          </label>
        </div>
      </div>
      <div className="grid gap-3 md:grid-cols-3">
        <button className="ba-button-secondary rounded-xl px-3 py-3 text-sm font-bold disabled:opacity-50" disabled={dnsLoading} onClick={runDns}><Network className="mr-2 inline h-4 w-4" />{dnsLoading ? "Running DNS…" : dnsResult ? "Refresh DNS / PTR" : "Run DNS / PTR"}</button>
        <button className="ba-button-secondary rounded-xl px-3 py-3 text-sm font-bold disabled:opacity-50" disabled={httpLoading} onClick={runHttp}><ShieldCheck className="mr-2 inline h-4 w-4" />{httpLoading ? "Running HTTP…" : webExposure ? "Refresh HTTP / TLS" : "Run HTTP / TLS"}</button>
        <button className="ba-button-primary rounded-xl px-3 py-3 text-sm font-black disabled:opacity-50" disabled={dnsLoading || httpLoading} onClick={runBoth}><Radar className="mr-2 inline h-4 w-4" />Run both checks</button>
      </div>
    </WorkbenchPanel>
  )
}

export default function ReconExposurePage({ setPage }) {
  const pending = useMemo(() => getPendingReconArtifact(), [])
  const [targetInput, setTargetInput] = useState(pending.value)
  const [inputCollapsed, setInputCollapsed] = useState(Boolean(pending.value))
  const [dnsLoading, setDnsLoading] = useState(false)
  const [httpLoading, setHttpLoading] = useState(false)
  const [timeout, setTimeoutValue] = useState(8)
  const [dnsResult, setDnsResult] = useState(null)
  const [webExposure, setWebExposure] = useState(null)
  const [notice, setNotice] = useState(pending.value ? `Loaded from ${pending.source || "workflow handoff"}.` : "")
  const [showExposureReport, setShowExposureReport] = useState(false)

  const normalized = useMemo(() => normalizeTargetInput(targetInput), [targetInput])
  const primary = normalized.primary
  const indicators = useMemo(() => extractReconIndicators(targetInput, normalized), [targetInput, normalized])
  const targetValue = getTargetValue(primary)
  const localFindings = useMemo(() => localReconFindings(primary, indicators), [primary, indicators])
  const backendFindings = useMemo(() => (webExposure?.review?.findings || []).map((item) => ({
    severity: String(item.severity || "info").toLowerCase(),
    signal: item.title,
    evidence: item.evidence,
    meaning: "Authorized HTTP/TLS metadata review produced this exposure signal.",
    action: item.recommendation,
    source: item.source || "HTTP/TLS check",
  })), [webExposure])
  const findings = useMemo(() => [...localFindings, ...backendFindings], [localFindings, backendFindings])
  const exposureScore = useMemo(() => computeExposureScore(findings), [findings])
  const exposureReport = useMemo(() => generateExposureReport({
    findings,
    target: primary?.host || primary?.normalized || targetValue,
    domain: primary?.root_domain,
  }), [findings, primary, targetValue])
  const summary = useMemo(() => summarizeRecon(primary, dnsResult, webExposure, findings), [primary, dnsResult, webExposure, findings])
  const decisionFields = useMemo(() => {
    const http = webExposure?.review?.http || {}
    const checks = [dnsResult ? "DNS/PTR" : "", webExposure ? "HTTP/TLS" : ""].filter(Boolean).join(" + ")
    return [
      ["Target", primary?.host || primary?.normalized],
      ["Type", primary?.type],
      ["Checks", checks || "static profile only"],
      ["HTTP status", http.status_code],
      ["Redirect hops", Array.isArray(http.redirect_chain) && http.redirect_chain.length ? Math.max(0, http.redirect_chain.length - 1) : ""],
      ["Evidence items", findings.length ? findings.length : ""],
    ]
  }, [primary, dnsResult, webExposure, findings])
  const snapshotFields = useMemo(() => targetSnapshotFields(primary, indicators), [primary, indicators])
  const externalLinks = useMemo(() => buildExternalReconLinks(primary, indicators), [primary, indicators])
  const socQueries = useMemo(() => buildSocQueries(primary, indicators), [primary, indicators])
  const report = useMemo(() => createReconReport({ primary, indicators, findings, dnsResult, webExposure }), [primary, indicators, findings, dnsResult, webExposure])
  const hasTarget = Boolean(targetInput.trim() && primary?.type && primary.type !== "empty" && primary.type !== "unknown")
  const indicatorText = [...indicators.urls, ...indicators.domains, ...indicators.ips, ...indicators.cidrs, ...indicators.emails, ...(indicators.asns || []), ...(indicators.hashes || [])].join("\n")

  async function copy(text, label = "Value") {
    if (!text) return
    await navigator.clipboard.writeText(text)
    setNotice(`${label} copied.`)
  }

  function loadSample() {
    setTargetInput("https://login-microsoft-security.example/verify/account-update.php?email=krish@example.com")
    setInputCollapsed(false)
    setDnsResult(null)
    setWebExposure(null)
    setNotice("Sample target loaded. Build the static profile or run backend checks explicitly.")
  }

  function clearTarget() {
    setTargetInput("")
    setInputCollapsed(false)
    setDnsResult(null)
    setWebExposure(null)
    setNotice("Target cleared.")
  }

  function handleTargetChange(value) {
    setTargetInput(value)
    setDnsResult(null)
    setWebExposure(null)
  }

  function buildStaticProfile() {
    if (!targetValue) {
      setNotice("Paste a URL, domain, IP, CIDR, email, or IOC list first.")
      return
    }
    setInputCollapsed(true)
    setNotice("Static target profile ready. Backend DNS/HTTP checks have not been run.")
  }

  async function runDns({ quiet = false } = {}) {
    if (!targetValue) {
      if (!quiet) setNotice("Load a domain, URL, or IP target first.")
      return null
    }
    setInputCollapsed(true)
    setDnsLoading(true)
    if (!quiet) setNotice("Running authorized DNS/PTR metadata check...")
    try {
      const response = await runReconDnsLookup({ target: targetValue, confirmPermission: true })
      setDnsResult(response)
      if (!quiet) setNotice("DNS/PTR metadata updated.")
      return response
    } catch (error) {
      setDnsResult(null)
      setNotice(`DNS/PTR check unavailable: ${error.message}`)
      return null
    } finally {
      setDnsLoading(false)
    }
  }

  async function runHttp({ quiet = false } = {}) {
    if (!targetValue) {
      if (!quiet) setNotice("Load a domain, URL, or IP target first.")
      return null
    }
    setInputCollapsed(true)
    setHttpLoading(true)
    if (!quiet) setNotice("Running authorized HTTP/TLS metadata check...")
    try {
      const response = await runReconWebExposure({ target: targetValue, confirmPermission: true, timeoutSeconds: timeout })
      setWebExposure(response)
      if (!quiet) setNotice("HTTP/TLS metadata updated.")
      return response
    } catch (error) {
      setWebExposure(null)
      setNotice(`HTTP/TLS check unavailable: ${error.message}`)
      return null
    } finally {
      setHttpLoading(false)
    }
  }

  async function runBothChecks() {
    if (!targetValue) {
      setNotice("Paste a URL, domain, IP, CIDR, email, or IOC list first.")
      return
    }
    setInputCollapsed(true)
    setDnsResult(null)
    setWebExposure(null)
    setNotice("Running authorized DNS/PTR and HTTP/TLS metadata checks...")
    await Promise.all([runDns({ quiet: true }), runHttp({ quiet: true })])
    setNotice("Backend metadata checks updated.")
  }

  function routeTo(page, artifact) {
    storeArtifact(artifact)
    setPage?.(page)
  }

  function routeIndicator(type, value) {
    if (type === "url") routeTo("safe-url-analyzer", { type: "url", value, target: "safe-url-analyzer" })
    else if (type === "email") routeTo("phishing-triage", { type: "email", value, target: "phishing-triage" })
    else routeTo("recon-exposure", { type, value, target: "recon-exposure" })
  }

  return (
    <WorkbenchPage className="ba-recon-page">
      <WorkbenchHeader
        eyebrow="Reconnaissance"
        title="Recon & Exposure"
        subtitle="Normalize URLs, domains, IPs, CIDRs, and IOC lists. Build a local profile first, then run authorized backend DNS/HTTP/TLS checks only when needed."
        icon={Radar}
        chips={[
          { label: "local profile", tone: "local" },
          { label: "DNS / HTTP / TLS", tone: "info" },
          { label: "authorized targets", tone: "warning" },
        ]}
        actions={(
          <div className="flex flex-wrap gap-2">
            <button className="ba-button-secondary rounded-xl px-3 py-2 text-sm font-bold" onClick={loadSample}><FileText className="mr-2 inline h-4 w-4" />Sample</button>
            <button className="ba-button-secondary rounded-xl px-3 py-2 text-sm font-bold" onClick={clearTarget}>Clear</button>
          </div>
        )}
      />
      <WorkbenchPanel className="space-y-4">
        {!inputCollapsed || !hasTarget ? (
          <section className="ba-intake-card">
            <label className="block space-y-2">
              <span className="ba-field-label">Target input</span>
              <textarea value={targetInput} onChange={(event) => handleTargetChange(event.target.value)} placeholder="Paste URL, domain, IP, CIDR, email, or mixed IOC list..." className="ba-intake-textarea min-h-44" />
            </label>
            <aside className="ba-intake-actions">
              <p className="ba-action-kicker">Analysis controls</p>
              <p className="ba-safety-note">Static profile is local-only. DNS/HTTP/TLS checks are explicit backend actions.</p>
              <div className="grid gap-2">
                <button className="ba-button-primary rounded-xl px-4 py-3 text-sm font-black" onClick={buildStaticProfile}><Radar className="mr-2 inline h-4 w-4" />Build static profile</button>
                <button className="ba-button-secondary rounded-xl px-3 py-2 text-sm font-bold disabled:opacity-50" disabled={dnsLoading} onClick={() => runDns()}><Network className="mr-2 inline h-4 w-4" />Run DNS / PTR</button>
                <button className="ba-button-secondary rounded-xl px-3 py-2 text-sm font-bold disabled:opacity-50" disabled={httpLoading} onClick={() => runHttp()}><ShieldCheck className="mr-2 inline h-4 w-4" />Run HTTP / TLS</button>
                {indicatorText ? <button className="ba-button-secondary rounded-xl px-3 py-2 text-sm font-bold" onClick={() => copy(indicatorText, "Indicators")}><Copy className="mr-2 inline h-4 w-4" />Copy indicators</button> : null}
              </div>
            </aside>
          </section>
        ) : (
          <div className="rounded-2xl border border-cyan-400/15 bg-cyan-400/5 p-3">
            <div className="ba-output-section-head">
              <div>
                <p className="ba-output-section-eyebrow" style={{ color: "var(--clr-accent)" }}>Target loaded</p>
                <h2 className="ba-output-section-title">{primary.host || primary.normalized}</h2>
                <p className="mt-1 text-sm text-zinc-300">{primary.type}{primary.root_domain ? ` · ${primary.root_domain}` : ""}</p>
              </div>
              <div className="flex flex-wrap gap-2">
                <button className="ba-button-secondary rounded-xl px-3 py-2 text-sm font-bold" onClick={() => setInputCollapsed(false)}>Edit target</button>
                {indicatorText ? <button className="ba-button-secondary rounded-xl px-3 py-2 text-sm font-bold" onClick={() => copy(indicatorText, "Indicators")}>Copy IOCs</button> : null}
              </div>
            </div>
          </div>
        )}
        {notice ? <p className="ba-info-banner text-sm">{notice}</p> : null}
      </WorkbenchPanel>

      {hasTarget && inputCollapsed ? (
        <>
          <WorkbenchPanel className="space-y-4 ba-readable-panel">
            <div className="ba-output-section-head">
              <div>
                <p className="ba-output-section-eyebrow" style={{ color: "var(--clr-accent)" }}><Globe className="mr-1.5 inline h-3.5 w-3.5" />Infrastructure brief</p>
                <h2 className="ba-output-section-title">{summary.decision}</h2>
                <p className="mt-1 max-w-4xl text-sm leading-6 text-zinc-200">{summary.concern}</p>
              </div>
              <span className="ba-chip ba-status-info">{dnsLoading || httpLoading ? "checks running" : dnsResult || webExposure ? "backend evidence added" : "static profile"}</span>
            </div>
            <CompactValueGrid fields={decisionFields} />
            <div className="rounded-xl border border-cyan-400/20 bg-cyan-400/7 p-3">
              <p className="text-xs font-black uppercase tracking-[0.14em] text-cyan-100">Next best action</p>
              <p className="mt-1 text-sm font-bold leading-6 text-zinc-50">{summary.nextAction}</p>
            </div>
          </WorkbenchPanel>

          <AnalystOutputCard
            title="Recon output quality"
            verdict={summary.decision}
            confidence={dnsResult || webExposure ? "backend metadata available" : "static profile"}
            summary={summary.concern}
            evidence={findings.slice(0, 5).map((item) => `${item.title}: ${item.evidence || item.detail || item.action}`)}
            limitations={[dnsResult || webExposure ? "Backend checks are point-in-time observations." : "No backend DNS/HTTP/TLS check has been run yet.", "Manual authorization and scope confirmation are still required before active scanning."]}
            nextActions={[summary.nextAction, "Send target to Nmap only if it is explicitly in scope.", "Export DNS/HTTP/TLS evidence to the case report."]}
            metrics={[
              ["Target", primary.host || primary.normalized],
              ["Indicators", Object.values(indicators).reduce((count, values) => count + (values?.length || 0), 0)],
              ["Findings", findings.length],
            ]}
          />

          <WorkbenchPanel className="space-y-4">
            <div className="ba-output-section-head">
              <div>
                <p className="ba-output-section-eyebrow"><Search className="mr-1.5 inline h-3.5 w-3.5" />Target snapshot</p>
                <h2 className="ba-output-section-title">Normalized infrastructure view</h2>
              </div>
              <div className="flex flex-wrap gap-2">
                {primary.type === "url" ? <button className="ba-button-secondary rounded-xl px-3 py-2 text-sm font-bold" onClick={() => routeTo("safe-url-analyzer", { type: "url", value: primary.original || primary.normalized, target: "safe-url-analyzer" })}><Route className="mr-2 inline h-4 w-4" />Safe URL</button> : null}
                <button className="ba-button-secondary rounded-xl px-3 py-2 text-sm font-bold" onClick={() => routeTo("nmap-runner", { type: "target", value: targetValue, target: "nmap-runner" })}><TerminalSquare className="mr-2 inline h-4 w-4" />Nmap</button>
                <button className="ba-button-secondary rounded-xl px-3 py-2 text-sm font-bold" onClick={() => routeTo("osint-tools", { type: "target", value: primary.root_domain || targetValue, target: "osint-tools" })}><Search className="mr-2 inline h-4 w-4" />OSINT</button>
                <button className="ba-button-secondary rounded-xl px-3 py-2 text-sm font-bold" onClick={() => routeTo("cyberchef", { type: "target", value: targetInput, target: "cyberchef" })}>CyberChef</button>
                <button className="ba-button-secondary rounded-xl px-3 py-2 text-sm font-bold" onClick={() => routeTo("detection-mitre", { type: "recon-finding", value: report, content: report, target: "detection-mitre" })}>Detection</button>
                <button className="ba-button-secondary rounded-xl px-3 py-2 text-sm font-bold" onClick={() => routeTo("smart-parser", { type: "recon-profile", value: report, content: report, target: "smart-parser" })}>Parser</button>
                <button className="ba-button-secondary rounded-xl px-3 py-2 text-sm font-bold" onClick={() => {
                  const entry = addTimelineArtifact({ title: `Recon profile: ${primary.host || primary.normalized}`, summary: summary.concern || summary.decision, source: "Recon & Exposure", raw: report, tags: [primary.type || "target"] })
                  setNotice(`Added to Case Timeline: ${entry.title}`)
                }}>Timeline</button>
              </div>
            </div>
            <SendToActions
              source="Recon & Exposure"
              setPage={setPage}
              payload={{
                type: primary.type || "target",
                title: `Recon profile: ${primary.host || primary.normalized}`,
                value: primary.original || primary.normalized || targetValue,
                summary: summary.concern || summary.decision,
                raw: report,
                tags: ["recon", primary.type || "target", ...(indicators.domains || []).slice(0, 2)],
                confidence: dnsResult || webExposure ? "medium" : "local-static",
              }}
            />
            <CompactValueGrid fields={snapshotFields} />
            <IndicatorGroups indicators={indicators} onCopy={copy} onRoute={routeIndicator} />
          </WorkbenchPanel>

          <MetadataCheckPanel timeout={timeout} setTimeoutValue={setTimeoutValue} dnsLoading={dnsLoading} httpLoading={httpLoading} runDns={() => runDns()} runHttp={() => runHttp()} runBoth={runBothChecks} dnsResult={dnsResult} webExposure={webExposure} />

          {findings.length ? (
            <WorkbenchPanel className="space-y-4">
              <div className="ba-output-section-head">
                <div>
                  <p className="ba-output-section-eyebrow"><ShieldAlert className="mr-1.5 inline h-3.5 w-3.5" />Evidence & findings</p>
                  <h2 className="ba-output-section-title">What actually matters</h2>
                </div>
                <span className="ba-chip ba-status-info">{findings.length} item(s)</span>
              </div>
              <div className="space-y-3 rounded-xl border border-white/10 bg-black/40 p-4">
                <div className="flex items-center justify-between">
                  <p className="text-xs font-black uppercase tracking-[0.14em] text-zinc-400">Exposure Score</p>
                  <span className={`rounded-full px-2.5 py-0.5 text-xs font-black uppercase tracking-wider ${
                    exposureScore.level === "high" ? "bg-red-500/20 text-red-300" :
                    exposureScore.level === "medium" ? "bg-amber-500/20 text-amber-300" :
                    exposureScore.level === "low" ? "bg-yellow-500/20 text-yellow-300" :
                    "bg-blue-500/20 text-blue-300"
                  }`}>{exposureScore.level}</span>
                </div>
                <div className="relative h-2.5 overflow-hidden rounded-full bg-zinc-800">
                  <div className={`h-full rounded-full transition-all duration-300 ${
                    exposureScore.level === "high" ? "bg-red-500" :
                    exposureScore.level === "medium" ? "bg-amber-500" :
                    exposureScore.level === "low" ? "bg-yellow-500" :
                    "bg-blue-500"
                  }`} style={{ width: `${exposureScore.score}%` }} />
                </div>
                <div className="flex items-center justify-between text-xs text-zinc-400">
                  <span>{exposureScore.score}/100</span>
                  {exposureScore.breakdown.length > 0 && (
                    <span>{exposureScore.breakdown.length} contributing factor(s)</span>
                  )}
                </div>
              </div>
              <EvidenceList findings={findings} />
              <div className="flex flex-wrap gap-2">
                <button className="ba-button-secondary rounded-xl px-3 py-2 text-sm font-bold" onClick={() => setShowExposureReport(!showExposureReport)}>
                  <FileText className="mr-2 inline h-4 w-4" />{showExposureReport ? "Hide" : "Generate"} Exposure Report
                </button>
                {showExposureReport && (
                  <button className="ba-button-secondary rounded-xl px-3 py-2 text-sm font-bold" onClick={async () => { await navigator.clipboard.writeText(exposureReport); setNotice("Exposure report copied.") }}>
                    <Clipboard className="mr-2 inline h-4 w-4" />Copy report
                  </button>
                )}
              </div>
              {showExposureReport && (
                <pre className="max-h-80 overflow-auto whitespace-pre-wrap rounded-xl border border-white/10 bg-black/40 p-4 text-sm leading-6 text-zinc-100">{exposureReport}</pre>
              )}
            </WorkbenchPanel>
          ) : null}

          {dnsResult ? <WorkbenchPanel className="space-y-3"><div className="ba-output-section-head"><p className="ba-output-section-eyebrow"><TerminalSquare className="mr-1.5 inline h-3.5 w-3.5" />DNS / PTR result</p><h2 className="ba-output-section-title">Resolved records</h2></div><DnsResults result={dnsResult} /></WorkbenchPanel> : null}
          {webExposure ? <WorkbenchPanel className="space-y-3"><div className="ba-output-section-head"><p className="ba-output-section-eyebrow"><Globe className="mr-1.5 inline h-3.5 w-3.5" />HTTP / TLS result</p><h2 className="ba-output-section-title">Observed web metadata</h2></div><WebResults result={webExposure} /></WorkbenchPanel> : null}

          <details className="ba-final-details ba-workbench-panel">
            <summary>SOC hunt pivots · starter queries</summary>
            <p className="text-sm leading-6 text-zinc-300">Starter queries are local suggestions for SIEM review. Adjust index, sourcetype, and field names to your environment.</p>
            <div className="mt-3"><QueryCards queries={socQueries} onCopy={copy} /></div>
          </details>

          <details className="ba-final-details ba-workbench-panel">
            <summary>External recon shortcuts · manual research links</summary>
            <p className="text-sm leading-6 text-zinc-300">These buttons open third-party tools in a new tab. BeyondArch does not query them automatically.</p>
            <div className="mt-3"><ExternalReconLinks links={externalLinks} /></div>
          </details>

          <details className="ba-final-details ba-workbench-panel">
            <summary>Report & raw details</summary>
            <div className="mt-4 flex flex-wrap gap-2">
              <button className="ba-button-secondary rounded-xl px-3 py-2 text-sm font-bold" onClick={() => copy(report, "Recon report")}><Clipboard className="mr-2 inline h-4 w-4" />Copy report</button>
              <button className="ba-button-secondary rounded-xl px-3 py-2 text-sm font-bold" onClick={() => downloadText("recon-exposure-report.md", report, "text/markdown")}><Download className="mr-2 inline h-4 w-4" />Export MD</button>
              <button className="ba-button-secondary rounded-xl px-3 py-2 text-sm font-bold" onClick={() => copy(JSON.stringify({ target: primary, indicators, findings, dnsResult, webExposure }, null, 2), "Recon JSON")}><Copy className="mr-2 inline h-4 w-4" />Copy JSON</button>
            </div>
            <pre className="mt-4 max-h-80 overflow-auto whitespace-pre-wrap rounded-xl border border-white/10 bg-black/40 p-4 text-sm leading-6 text-zinc-100">{report}</pre>
            <details className="ba-final-details" style={{ marginTop: ".65rem" }}>
              <summary>Advanced raw details</summary>
              <pre className="mt-3 max-h-80 overflow-auto whitespace-pre-wrap rounded-lg bg-black/40 p-3 text-xs text-zinc-100">{JSON.stringify({ target: primary, indicators, dnsResult, webExposure }, null, 2)}</pre>
            </details>
          </details>
        </>
      ) : (
        <WorkbenchPanel className="flex flex-col items-center gap-3 py-6 text-center">
          <Search className="h-8 w-8 text-zinc-500" />
          <p className="ba-empty-state">Paste a target, then click <strong>Build static profile</strong> or an explicit backend check. No scan or metadata lookup runs automatically.</p>
        </WorkbenchPanel>
      )}
    </WorkbenchPage>
  )
}
