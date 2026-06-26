import { useMemo, useState } from "react"
import {
  AlertTriangle, CheckCircle2, Copy, Download, FileText, Play, Radar, RefreshCcw, Route, ShieldCheck, TerminalSquare,
} from "lucide-react"
import { runReconNmapCustom, runReconNmapScan } from "../../api/backend"
import { WorkbenchHeader, WorkbenchPage, WorkbenchPanel } from "../../components/layout/WorkbenchShell"
import SendToActions from "../../components/investigation/SendToActions"
import AnalystOutputCard from "../../components/investigation/AnalystOutputCard"
import { NmapMetricGrid, NmapServiceTable, NmapTerminalPane } from "../../components/nmap/NmapUi"
import { addTimelineArtifact } from "../../lib/timelineStore"
import { copyText, downloadText } from "../../lib/domUtils"
import { useSessionState } from "../../lib/useSessionState"
import {
  buildExposureFindings,
  buildNmapSocQueries,
  buildNmapSummary,
  createNmapReport,
  NMAP_PROFILES,
  parseNmapPorts,
} from "../../lib/nmapProfileEngine"

const PENDING_KEY = "beyondarch.pendingArtifact"
const DEFAULT_CUSTOM_COMMAND = "nmap -Pn -T3 --top-ports 100 scanme.nmap.org"

const SCAN_PROFILE_METADATA = {
  quick_tcp: { purpose: "Top 100 TCP port discovery — initial exposure snapshot", risk: "Low", outputType: "Service and port table" },
  service_version: { purpose: "Service and version identification for open ports", risk: "Low", outputType: "Detailed service inventory" },
  aggressive_inventory: { purpose: "Full -A scan with version, scripts, OS detection", risk: "Moderate — intrusive scan", outputType: "Detailed service inventory" },
  web_exposure: { purpose: "HTTP/HTTPS service fingerprinting and TLS metadata inspection", risk: "Low", outputType: "Web server and header details" },
  windows_smb: { purpose: "SMB protocol enumeration and Windows service exposure", risk: "Moderate — SMB may trigger detection", outputType: "SMB service details" },
  linux_ssh: { purpose: "SSH service and administrative surface review", risk: "Low", outputType: "SSH configuration details" },
  mail_server: { purpose: "Mail server protocol exposure review", risk: "Low", outputType: "Mail service details" },
}

const HANDOFF_SOURCES = new Set([
  "recon-exposure",
  "smart-parser",
  "safe-url-analyzer",
  "phishing-triage",
  "attachment-triage",
  "logs-alerts",
  "detection-mitre",
  "soc-guide",
  "cyberchef",
])

function generateScanSummary(profileId = "", result = "") {
  const meta = SCAN_PROFILE_METADATA[profileId] || { purpose: "Custom scan", risk: "Unknown", outputType: "Raw output" }
  const lines = [
    `## Nmap Scan Assessment`,
    ``,
    `**Profile:** ${profileId}`,
    `**Purpose:** ${meta.purpose}`,
    `**Risk Level:** ${meta.risk}`,
    `**Output Type:** ${meta.outputType}`,
    `**Output Size:** ${result.length} character(s)`,
    ``,
    `**Analyst Recommendation:**`,
    `- ${meta.risk === "Moderate" || meta.risk.startsWith("Moderate") ? "Correlate scan findings with authorized testing scope. Beacon or alert triage may be triggered by this scan type." : "Low-risk discovery scan. Review results as part of standard reconnaissance workflow."}`,
    ``,
    `**Limitations:** This scan was executed from the local environment. Results may differ from external perspective. No stealth, proxying, or evasion techniques are applied beyond the selected profile.`,
  ]
  return lines.join("\n")
}

function getPendingNmapArtifact() {
  try {
    const raw = localStorage.getItem(PENDING_KEY)
    if (!raw) return { value: "", source: "" }
    const artifact = JSON.parse(raw)
    const target = artifact?.target || artifact?.page
    if (target && target !== "nmap-runner") return { value: "", source: "" }
    if (artifact?.source && !HANDOFF_SOURCES.has(artifact.source)) return { value: "", source: "" }
    const value = artifact?.value || artifact?.host || artifact?.domain || artifact?.ip || artifact?.url || artifact?.content || artifact?.text || artifact?.raw_input || ""
    if (!value) return { value: "", source: "" }
    localStorage.removeItem(PENDING_KEY)
    return { value: normalizeTarget(value), source: artifact?.source || "workflow handoff" }
  } catch {
    return { value: "", source: "" }
  }
}

function normalizeTarget(value = "") {
  return String(value || "").trim().replace(/^https?:\/\//i, "").split(/[/?#]/)[0].replace(/[,;]+$/, "")
}

function storeArtifact({ type, value, target, source = "nmap-runner", content }) {
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

function ScanModeSelector({ mode, setMode }) {
  const modes = [
    ["profile", "Guided profile", "Allowlisted backend scan profile."],
    ["custom", "Bounded custom", "Single nmap command validated by backend."],
  ]
  return (
    <div className="grid gap-2 sm:grid-cols-2">
      {modes.map(([id, label, detail]) => (
        <button
          key={id}
          type="button"
          className={`rounded-xl border px-4 py-3 text-left transition ${mode === id ? "border-cyan-300/50 bg-cyan-400/12 text-cyan-50" : "border-white/10 bg-black/40 text-zinc-300 hover:border-white/10"}`}
          onClick={() => setMode(id)}
        >
          <span className="block text-sm font-black">{label}</span>
          <span className="mt-1 block text-xs leading-5">{detail}</span>
        </button>
      ))}
    </div>
  )
}

function ProfileHint({ selected }) {
  if (!selected) return null
  return (
    <div className="rounded-xl border border-white/10 bg-black/40 p-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="text-sm font-black text-zinc-50">{selected.label}</p>
        <span className="rounded-full border border-cyan-400/20 bg-cyan-400/10 px-2 py-1 text-[0.68rem] font-black uppercase tracking-[0.14em] text-cyan-100">{selected.bestFor}</span>
      </div>
      <p className="mt-2 text-sm leading-6 text-zinc-300">{selected.detail}</p>
    </div>
  )
}

function ScanBrief({ summary, findings, onDownload, onCopy, onRoute, onTimeline, setPage, report, profileMeta, onGenerateAssessment, showAssessment, assessmentValue }) {
  return (
    <section className="space-y-3 rounded-2xl border border-white/10 bg-black/40 p-4">
      <div className="ba-output-section-head">
        <div>
          <p className="ba-output-section-eyebrow" style={{ color: "var(--clr-accent)" }}>Scan brief</p>
          <h2 className="ba-output-section-title">{summary.decision}</h2>
          <p className="mt-1 max-w-3xl text-sm leading-6 text-zinc-300">{summary.primaryExposure}</p>
        </div>
        <span className="rounded-full border border-white/10 bg-black/40 px-3 py-1 text-xs font-black uppercase tracking-[0.14em] text-zinc-300">{summary.runnerStatus}</span>
      </div>
      {profileMeta ? (
        <div className="flex flex-wrap gap-2 rounded-xl border border-white/10 bg-black/40 px-3 py-2 text-xs leading-5 text-zinc-300">
          <span><span className="font-bold text-zinc-50">Purpose:</span> {profileMeta.purpose}</span>
          <span className="text-zinc-600">|</span>
          <span><span className="font-bold text-zinc-50">Risk:</span> {profileMeta.risk}</span>
          <span className="text-zinc-600">|</span>
          <span><span className="font-bold text-zinc-50">Output:</span> {profileMeta.outputType}</span>
        </div>
      ) : null}
      <NmapMetricGrid fields={[
        ["Target", summary.target],
        ["Profile", summary.profile],
        ["Open services", summary.openCount],
        ["Next action", summary.nextAction],
      ]} />
      <AnalystOutputCard
        title="Scan output quality"
        verdict={summary.decision}
        confidence={summary.runnerStatus || "backend runner"}
        summary={summary.primaryExposure}
        evidence={findings.slice(0, 5).map((finding) => `${finding.title}: ${finding.evidence}`)}
        limitations={["Nmap output is valid only for the scan time, profile, and authorized scope.", "Open services are exposure signals, not compromise evidence by themselves."]}
        nextActions={[summary.nextAction, "Review service banners and versions before reporting risk.", "Send relevant ports/services to Recon, SIEM, or Detection notes."]}
        metrics={[
          ["Target", summary.target],
          ["Open services", summary.openCount],
          ["Profile", summary.profile],
        ]}
      />
      {findings.length ? (
        <div className="grid gap-2 md:grid-cols-2">
              {findings.slice(0, 4).map((finding) => (
            <article key={finding.title} className="rounded-xl border border-white/10 bg-black/40 p-3">
              <div className="flex flex-wrap items-center gap-2">
                <span className={`rounded-full px-2 py-1 text-[0.68rem] font-black uppercase tracking-[0.12em] ${finding.severity === "high" ? "border border-rose-400/30 bg-rose-400/10 text-rose-100" : finding.severity === "medium" ? "border border-amber-400/30 bg-amber-400/10 text-amber-100" : "border border-white/10 bg-black/40 text-zinc-300"}`}>{finding.severity}</span>
                <h3 className="text-sm font-black text-zinc-50">{finding.title}</h3>
                {finding.mitre ? <span className="rounded-full border border-cyan-400/20 bg-cyan-400/10 px-2 py-0.5 text-[0.65rem] font-bold text-cyan-100">{finding.mitre}</span> : null}
              </div>
              <p className="mt-2 font-mono text-xs leading-5 text-zinc-300">{finding.evidence}</p>
              <p className="mt-2 text-xs leading-5 text-zinc-400">{finding.action}</p>
            </article>
          ))}
        </div>
      ) : null}
      <div className="flex flex-wrap gap-2">
        <button type="button" className="ba-button-secondary rounded-xl px-3 py-2 text-sm font-bold" onClick={onCopy}><Copy className="mr-2 inline h-4 w-4" />Copy report</button>
        <button type="button" className="ba-button-secondary rounded-xl px-3 py-2 text-sm font-bold" onClick={onDownload}><Download className="mr-2 inline h-4 w-4" />Download report</button>
        <button type="button" className="ba-button-secondary rounded-xl px-3 py-2 text-sm font-bold" onClick={() => onRoute("recon-exposure")}><Route className="mr-2 inline h-4 w-4" />Recon</button>
        <button type="button" className="ba-button-secondary rounded-xl px-3 py-2 text-sm font-bold" onClick={() => onRoute("detection-mitre")}><ShieldCheck className="mr-2 inline h-4 w-4" />Detection</button>
        <button type="button" className="ba-button-secondary rounded-xl px-3 py-2 text-sm font-bold" onClick={onTimeline}>Timeline</button>
        <button type="button" className="ba-button-secondary rounded-xl px-3 py-2 text-sm font-bold" onClick={onGenerateAssessment}><FileText className="mr-2 inline h-4 w-4" />{showAssessment ? "Hide" : "Generate"} Assessment</button>
      </div>
      {showAssessment && assessmentValue ? (
        <pre className="overflow-auto whitespace-pre-wrap rounded-xl bg-black/60 p-3 font-mono text-xs leading-5 text-cyan-100">{assessmentValue}</pre>
      ) : null}
      <SendToActions
        payload={{ type: "nmap_scan", title: `Nmap scan: ${summary.target}`, value: report, summary: summary.primaryExposure, tags: ["nmap", "recon", "services"] }}
        source="Nmap Runner"
        setPage={setPage}
        compact
      />
    </section>
  )
}

function QueryPivots({ queries, onSend }) {
  if (!queries.length) return null
  return (
    <details className="ba-final-details">
      <summary>SOC pivots from open services</summary>
      <div className="mt-3 grid gap-3 md:grid-cols-2">
        {queries.map((item) => (
          <article key={item.label} className="rounded-xl border border-white/10 bg-black/40 p-3">
            <div className="flex items-center justify-between gap-2">
              <h3 className="text-sm font-black text-zinc-50">{item.label}</h3>
              <button type="button" className="text-xs font-bold text-cyan-100 hover:text-cyan-50" onClick={() => copyText(item.query, () => {}, "Query")}>Copy</button>
            </div>
            <pre className="mt-2 overflow-auto whitespace-pre-wrap rounded-lg bg-black/60 p-3 font-mono text-xs leading-5 text-cyan-100">{item.query}</pre>
            <button type="button" className="mt-2 text-xs font-bold text-cyan-100 hover:text-cyan-50" onClick={() => onSend(item.query)}>Send to SIEM</button>
          </article>
        ))}
      </div>
    </details>
  )
}

export default function NmapRunnerPage({ setPage }) {
  const pending = useMemo(() => getPendingNmapArtifact(), [])
  const [target, setTarget] = useState(pending.value || "")
  const [profileId, setProfileId] = useSessionState("nmap.profileId", "quick_tcp")
  const [mode, setMode] = useSessionState("nmap.mode", "profile")
  const [customCommand, setCustomCommand] = useState(pending.value ? `nmap -Pn -T3 --top-ports 100 ${pending.value}` : DEFAULT_CUSTOM_COMMAND)
  const [allowPrivate, setAllowPrivate] = useState(false)
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const [notice, setNotice] = useState(pending.source ? `Loaded target from ${pending.source}. Confirm scope before scanning.` : "")
  const [samplesOpen, setSamplesOpen] = useState(false)
  const [showAssessment, setShowAssessment] = useState(false)

  const selectedProfile = useMemo(() => NMAP_PROFILES.find((profile) => profile.id === profileId) || NMAP_PROFILES[0], [profileId])
  const targetValue = useMemo(() => normalizeTarget(target), [target])
  const ports = useMemo(() => parseNmapPorts(result), [result])
  const scan = result?.scan || result || null
  const summary = useMemo(() => buildNmapSummary({ target: targetValue, profile: selectedProfile, result, ports }), [targetValue, selectedProfile, result, ports])
  const findings = useMemo(() => buildExposureFindings(ports), [ports])
  const queries = useMemo(() => buildNmapSocQueries(targetValue, ports), [targetValue, ports])
  const report = useMemo(() => createNmapReport({ summary, ports }), [summary, ports])
  const rawOutput = useMemo(() => {
    if (!scan) return ""
    return [scan.command ? `$ ${scan.command}` : "", scan.stdout || "", scan.stderr ? `\n[stderr]\n${scan.stderr}` : ""].filter(Boolean).join("\n")
  }, [scan])
  const assessmentValue = useMemo(() => generateScanSummary(selectedProfile?.id || profileId, rawOutput), [selectedProfile, profileId, rawOutput])

  function loadSample() {
    setTarget("scanme.nmap.org")
    setCustomCommand("nmap -Pn -T3 --top-ports 100 scanme.nmap.org")
    setProfileId("quick_tcp")
    setMode("profile")
    setNotice("Sample target loaded. Use only for testing the workflow.")
    setSamplesOpen(false)
  }

  function resetPage() {
    setTarget("")
    setCustomCommand(DEFAULT_CUSTOM_COMMAND)
    setProfileId("quick_tcp")
    setMode("profile")
    setAllowPrivate(false)
    setResult(null)
    setNotice("")
  }

  async function runScan() {
    const targetForScan = normalizeTarget(target)
    if (mode === "profile" && !targetForScan) {
      setNotice("Enter a target host, domain, or IP.")
      return
    }
    if (mode === "custom" && !customCommand.trim()) {
      setNotice("Enter a bounded nmap command.")
      return
    }
    setLoading(true)
    setResult(null)
    setNotice("Running Nmap through the local backend runner...")
    try {
      const response = mode === "custom"
        ? await runReconNmapCustom({ command: customCommand, confirmPermission: true, allowPrivate })
        : await runReconNmapScan({ target: targetForScan, mode: profileId, confirmPermission: true, allowPrivate })
      setResult(response)
      setNotice(response?.scan?.error || response?.error ? "Nmap completed with runner notes." : "Nmap scan completed.")
    } catch (error) {
      setResult({ scan: { success: false, error: error.message } })
      setNotice(`Nmap failed: ${error.message}`)
    } finally {
      setLoading(false)
    }
  }

  function routeTo(page, artifact) {
    storeArtifact(artifact)
    setPage?.(page)
  }

  function routeReport(page) {
    const value = report || rawOutput || targetValue
    const artifact = {
      type: page === "detection-mitre" ? "nmap-finding" : "nmap-scan",
      value,
      content: value,
      target: page,
    }
    routeTo(page, artifact)
  }

  function routePort(port, page = "recon-exposure") {
    const value = targetValue || summary.target || ""
    const content = `${value}:${port.port}/${port.protocol} ${port.service}\n${port.exposureNote || ""}\n${port.suggestedAction || ""}`
    routeTo(page, { type: "service-exposure", value, content, target: page })
  }

  return (
    <WorkbenchPage className="ba-nmap-page">
      <WorkbenchHeader
        eyebrow="Network scanning"
        title="Nmap Runner"
        subtitle="Run bounded Nmap profiles through the local backend, then review parsed services, terminal output, exposure notes, and SOC pivots."
        icon={TerminalSquare}
        chips={[
          { label: "authorized targets", tone: "warning" },
          { label: "local backend", tone: "local" },
          { label: "bounded profiles", tone: "info" },
        ]}
        actions={(
          <div className="flex flex-wrap gap-2">
            <button type="button" className="ba-button-secondary rounded-xl px-3 py-2 text-sm font-bold" onClick={() => setSamplesOpen((value) => !value)}><FileText className="mr-2 inline h-4 w-4" />Sample</button>
            <button type="button" className="ba-button-secondary rounded-xl px-3 py-2 text-sm font-bold" onClick={resetPage}><RefreshCcw className="mr-2 inline h-4 w-4" />Reset</button>
          </div>
        )}
      />
      <WorkbenchPanel className="space-y-4">
        {samplesOpen ? (
          <div className="rounded-xl border border-white/10 bg-black/40 p-3">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <p className="text-sm font-black text-zinc-50">Workflow sample</p>
                <p className="text-xs leading-5 text-zinc-400">Loads scanme.nmap.org for UI testing. Use only where scanning is permitted.</p>
              </div>
              <button type="button" className="ba-button-secondary rounded-xl px-3 py-2 text-sm font-bold" onClick={loadSample}>Load sample target</button>
            </div>
          </div>
        ) : null}

        <section className="grid gap-4 xl:grid-cols-[1.05fr_0.95fr]">
          <div className="space-y-3 rounded-2xl border border-white/10 bg-black/40 p-4">
            <ScanModeSelector mode={mode} setMode={setMode} />
            {mode === "profile" ? (
              <div className="grid gap-3 md:grid-cols-[1fr_0.85fr]">
                <label className="block space-y-2">
                  <span className="ba-field-label">Target host / domain / IP</span>
                  <input className="ba-input" value={target} onChange={(event) => setTarget(event.target.value)} placeholder="example.com or 192.0.2.10" />
                </label>
                <label className="block space-y-2">
                  <span className="ba-field-label">Scan profile</span>
                  <select className="ba-input" value={profileId} onChange={(event) => setProfileId(event.target.value)}>
                    {NMAP_PROFILES.map((profile) => <option key={profile.id} value={profile.id}>{profile.label}</option>)}
                  </select>
                </label>
                <div className="md:col-span-2"><ProfileHint selected={selectedProfile} /></div>
              </div>
            ) : (
              <label className="block space-y-2">
                <span className="ba-field-label">Bounded custom nmap command</span>
                <textarea className="ba-input min-h-32 font-mono text-sm" value={customCommand} onChange={(event) => setCustomCommand(event.target.value)} placeholder={DEFAULT_CUSTOM_COMMAND} />
                <p className="text-xs leading-5 text-zinc-400">Backend blocks shell chaining, broad target lists, spoofing/evasion flags, and unsafe NSE categories.</p>
              </label>
            )}
          </div>

          <aside className="space-y-3 rounded-2xl border border-white/10 bg-black/40 p-4">
            <div className="ba-output-section-head"><p className="ba-output-section-eyebrow" style={{ color: "var(--clr-accent)" }}><TerminalSquare size={14} className="inline mr-1" />Run controls</p><h2 className="ba-output-section-title">Bounded backend scan</h2><p className="mt-1 text-sm leading-6 text-zinc-300">Active scanning is limited to safe Nmap profiles and bounded custom commands. Use only on authorized targets.</p></div>
            <label className="flex gap-3 rounded-xl border border-white/10 bg-black/40 p-3 text-sm text-zinc-200">
              <input type="checkbox" className="mt-1" checked={allowPrivate} onChange={(event) => setAllowPrivate(event.target.checked)} />
              <span>Allow private/local lab targets.</span>
            </label>
            <button type="button" className="ba-button-primary w-full rounded-xl px-4 py-3 text-sm font-black disabled:opacity-50" disabled={loading} onClick={runScan}>
              <Play className="mr-2 inline h-4 w-4" />{loading ? "Running Nmap…" : mode === "custom" ? "Run bounded custom scan" : "Run guided scan"}
            </button>
            {notice ? <p className="rounded-xl border border-white/10 bg-black/40 p-3 text-sm leading-6 text-zinc-300">{notice}</p> : null}
            <div className="rounded-xl border border-amber-400/20 bg-amber-400/8 p-3 text-xs leading-5 text-amber-100">
              <AlertTriangle className="mr-2 inline h-4 w-4" />No brute force, exploit checks, spoofing, or unbounded target lists are allowed through this runner.
            </div>
          </aside>
        </section>
      </WorkbenchPanel>

      <WorkbenchPanel className="space-y-4 ba-readable-panel">
        {result ? (
          <ScanBrief
            summary={summary}
            findings={findings}
            onCopy={() => copyText(report, setNotice, "Nmap report")}
            onDownload={() => downloadText("beyondarch-nmap-scan.md", report, "text/markdown")}
            onRoute={routeReport}
            onTimeline={() => {
              const entry = addTimelineArtifact({ title: `Nmap scan: ${summary.target}`, summary: `${summary.openCount} open service(s) · ${summary.primaryExposure}`, source: "Nmap Runner", raw: report, tags: [summary.profile || "nmap"] })
              setNotice(`Added to Case Timeline: ${entry.title}`)
            }}
            setPage={setPage}
            report={report}
            profileMeta={SCAN_PROFILE_METADATA[selectedProfile?.id || profileId]}
            onGenerateAssessment={() => setShowAssessment((v) => !v)}
            showAssessment={showAssessment}
            assessmentValue={assessmentValue}
          />
        ) : (
          <section className="rounded-2xl border border-white/10 bg-black/40 p-4">
            <div className="flex flex-wrap items-center gap-3 text-sm text-zinc-300">
              <CheckCircle2 className="h-5 w-5 text-emerald-300" />
              <span>Ready for a bounded backend scan. Choose a guided profile or custom command, then run through the local backend.</span>
            </div>
          </section>
        )}

        <div className="grid gap-4 xl:grid-cols-[0.96fr_1.04fr]">
          <section className="rounded-2xl border border-white/10 bg-black/40 p-4">
            <div className="mb-3 ba-output-section-head">
              <div>
                <p className="ba-output-section-eyebrow"><Radar size={14} className="inline mr-1" />Parsed output</p>
                <h3 className="ba-output-section-title">Open ports, services, versions</h3>
              </div>
              {ports.length ? <span className="rounded-full border border-cyan-400/20 bg-cyan-400/10 px-3 py-1 text-xs font-black text-cyan-100">{ports.length} open</span> : null}
            </div>
            <NmapServiceTable ports={ports} onSend={routePort} />
          </section>
          <NmapTerminalPane raw={rawOutput} />
        </div>

        <QueryPivots queries={queries} onSend={(query) => routeTo("siem", { type: "hunt-query", value: query, content: query, target: "siem" })} />

        {result ? (
          <details className="ba-final-details" style={{ marginTop: ".65rem" }}>
            <summary>Raw runner details</summary>
            <pre className="mt-3 max-h-96 overflow-auto whitespace-pre-wrap rounded-xl bg-black/60 p-3 font-mono text-xs leading-5 text-zinc-200">{JSON.stringify(result, null, 2)}</pre>
          </details>
        ) : null}
      </WorkbenchPanel>
    </WorkbenchPage>
  )
}
