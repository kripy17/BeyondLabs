import { Fragment, useMemo, useRef, useState } from "react"
import { ChevronDown, ChevronRight, Database, Download, FileText, Minus, Plus, Search, Upload, X } from "lucide-react"
import { analyzeSiemText, uploadSiemLog } from "../../api/backend"
import { normalizeEvent } from "../../lib/siemQuery"
import SendToActions from "../../components/investigation/SendToActions"
import AnalystOutputCard from "../../components/investigation/AnalystOutputCard"
import { WorkbenchHeader, WorkbenchPage } from "../../components/layout/WorkbenchShell"
import { downloadText } from "../../lib/domUtils.js"
import { useSessionState } from "../../lib/useSessionState"

const FIELD_PRIORITY = ["timestamp", "_time", "date", "date_hour", "date_minute", "time_bucket", "severity", "sourcetype", "event_type", "source_ip", "destination_ip", "src_ip", "dst_ip", "user", "host", "process_name", "status_code", "action", "outcome"]

const SIEM_EVENT_MITRE = {
  process_start: "T1059",
  process_stop: "",
  process_create: "T1059",
  network_connection: "T1071",
  dns_query: "T1071.004",
  url_request: "T1071.001",
  windows_event: "",
  cloudtrail_event: "T1078",
  edr: "T1059",
  proxy: "T1071.001",
  auth: "T1110",
  dns: "T1071.004",
}

const SIEM_SOURCETYPE_TACTIC = {
  process_start: "Execution",
  process_create: "Execution",
  network_connection: "Command and Control",
  dns_query: "Command and Control",
  url_request: "Command and Control",
  auth: "Credential Access",
  firewall: "Discovery",
  cloudtrail_event: "Initial Access",
  windows: "Persistence",
  edr: "Execution",
  proxy: "Command and Control",
}

function mitreTacticCoverage(events = []) {
  const tactics = {}
  for (const e of events) {
    const key = e.event_type || e.sourcetype || ""
    const tid = SIEM_EVENT_MITRE[key] || ""
    const tactic = SIEM_SOURCETYPE_TACTIC[key] || ""
    if (tid) {
      if (!tactics[tactic]) tactics[tactic] = { tactic, techniques: new Set(), count: 0 }
      tactics[tactic].techniques.add(tid)
      tactics[tactic].count++
    }
  }
  return Object.values(tactics).sort((a, b) => b.count - a.count).map((t) => ({ ...t, techniques: [...t.techniques] }))
}
const DEFAULT_TABLE_COLUMNS = ["timestamp", "host", "source_ip", "sourcetype", "event_type", "user", "message"]

const SAMPLE_LOGS = [
  '2026-05-14T09:10:12Z auth sshd[2031]: Failed password for admin from 203.0.113.44 port 55120 ssh2',
  '2026-05-14T09:10:18Z auth sshd[2034]: Failed password for root from 203.0.113.44 port 55122 ssh2',
  '2026-05-14T09:11:02Z auth sshd[2038]: Accepted publickey for ubuntu from 10.10.5.21 port 50118 ssh2',
  '198.51.100.23 - - [14/May/2026:09:12:44 +0000] "GET /login.php HTTP/1.1" 200 1842 "-" "Mozilla/5.0"',
  '198.51.100.23 - - [14/May/2026:09:12:48 +0000] "POST /login.php HTTP/1.1" 302 421 "https://example.com/login.php" "Mozilla/5.0"',
  '{"timestamp":"2026-05-14T09:13:11Z","sourcetype":"edr","event_type":"process_start","severity":"high","host":"WS-17","user":"aparete","process_name":"powershell.exe","command_line":"powershell -nop -w hidden -enc SQBFAFgA","source_ip":"10.10.5.17","message":"Encoded PowerShell execution observed"}',
  '{"timestamp":"2026-05-14T09:14:02Z","sourcetype":"proxy","event_type":"url_request","severity":"medium","host":"WS-17","user":"aparete","source_ip":"10.10.5.17","url":"http://noterock.xyz/tracker/index.php","uri_path":"/tracker/index.php","action":"allowed","message":"Suspicious URL request from workstation"}',
  '{"timestamp":"2026-05-14T09:15:00Z","sourcetype":"dns","event_type":"dns_query","severity":"low","host":"WS-17","source_ip":"10.10.5.17","domain":"evil-c2.example.com","query_type":"A","rcode":"NXDOMAIN","message":"DNS NXDOMAIN response for suspicious domain"}',
  '{"timestamp":"2026-05-14T09:16:00Z","sourcetype":"windows","event_type":"windows_event","severity":"high","host":"DC-01","user":"admin","EventID":"4732","message":"A member was added to a security-enabled local group. Member: CN=krish,CN=Users,DC=corp,DC=local Group: Domain Admins"}',
  '{"timestamp":"2026-05-14T09:17:00Z","sourcetype":"cloudtrail","event_type":"cloudtrail_event","severity":"medium","host":"AWS","user":"admin","eventName":"ConsoleLogin","sourceIPAddress":"8.8.8.8","awsRegion":"us-east-1","message":"ConsoleLogin on signin.amazonaws.com by admin"}',
].join("\n")

function copy(text) {
  navigator.clipboard?.writeText(String(text || ""))
}

function readInitialPrefill() {
  try {
    const direct = window.localStorage.getItem("beyondarch.siem.prefill") || ""
    if (direct) {
      window.localStorage.removeItem("beyondarch.siem.prefill")
      return direct
    }
    const raw = window.localStorage.getItem("beyondarch.pendingArtifact")
    if (!raw) return ""
    const pending = JSON.parse(raw)
    const target = String(pending?.target || pending?.page || pending?.destination || "").toLowerCase()
    const shouldLoad = target.includes("siem") || target.includes("logs") || pending?.type === "siem" || pending?.type === "log" || pending?.type === "event"
    if (!shouldLoad) return ""
    window.localStorage.removeItem("beyondarch.pendingArtifact")
    const value = pending?.content || pending?.text || pending?.raw_input || pending?.value || pending?.query || pending?.rule || pending?.event
    if (typeof value === "string") return value
    return value ? JSON.stringify(value, null, 2) : ""
  } catch {
    return ""
  }
}

function sendArtifact(setPage, page, payload) {
  try {
    window.localStorage.setItem("beyondarch.pendingArtifact", JSON.stringify({
      ...payload,
      target: page,
      source: "SIEM Workspace",
      created_at: new Date().toISOString(),
    }))
  } catch {
    // localStorage may be unavailable.
  }
  setPage?.(page)
}

function rowsToCsv(rows = []) {
  if (!rows.length) return ""
  const headers = Array.from(new Set(rows.flatMap((row) => Object.keys(row))))
  const esc = (value) => `"${String(value ?? "").replaceAll('"', '""')}"`
  return [headers.map(esc).join(","), ...rows.map((row) => headers.map((h) => esc(row[h])).join(","))].join("\n")
}

function buildDefaultColumns(events = []) {
  const available = new Set(events.flatMap((row) => Object.entries(row).filter(([, value]) => visibleValue(Array.isArray(value) ? value.join(", ") : typeof value === "object" && value ? JSON.stringify(value) : value)).map(([key]) => key)))
  const defaults = DEFAULT_TABLE_COLUMNS.filter((field) => available.has(field))
  if (!defaults.includes("message") && available.has("headline")) defaults.push("headline")
  return defaults.length ? defaults : ["message"]
}

function columnLabel(field) {
  if (field === "timestamp") return "_time"
  if (field === "message") return "event"
  return field
}

function fieldValue(event, field) {
  const value = event?.[field]
  if (Array.isArray(value)) return value.join(", ")
  if (value && typeof value === "object") return JSON.stringify(value)
  return String(value ?? "")
}

function visibleValue(value) {
  if (value === undefined || value === null) return ""
  const text = String(value).trim()
  if (!text || text === "N/A" || text === "unknown" || text === "[]" || text === "{}") return ""
  return text
}

function severityClass(value = "") {
  const severity = String(value).toLowerCase()
  if (severity.includes("critical") || severity.includes("high")) return "ba-status-danger"
  if (severity.includes("medium")) return "ba-status-warning"
  if (severity.includes("low")) return "ba-status-info"
  return "ba-status-local"
}

function severityRank(value = "") {
  return { critical: 5, high: 4, medium: 3, low: 2, info: 1 }[String(value).toLowerCase()] || 0
}

function valueMatches(row, field, expected) {
  const actual = fieldValue(row, field).toLowerCase()
  return actual === String(expected).toLowerCase() || actual.includes(String(expected).toLowerCase())
}

function applyFilters(events = [], filters = [], text = "", range = "all") {
  const needle = text.trim().toLowerCase()
  const scoped = applyRelativeRange(events, range)
  return scoped.filter((row) => {
    const filterMatch = filters.every((filter) => valueMatches(row, filter.field, filter.value))
    if (!filterMatch) return false
    if (!needle) return true
    return Object.values(row).some((value) => String(Array.isArray(value) ? value.join(" ") : value ?? "").toLowerCase().includes(needle))
  })
}

function applyRelativeRange(events = [], range = "all") {
  if (range === "all") return events
  const minutes = { "15m": 15, "1h": 60, "24h": 1440 }[range]
  if (!minutes) return events
  const parsed = events.map((event) => Date.parse(event.timestamp)).filter((value) => !Number.isNaN(value))
  if (!parsed.length) return events
  const max = Math.max(...parsed)
  const min = max - minutes * 60 * 1000
  return events.filter((event) => {
    const t = Date.parse(event.timestamp)
    return Number.isNaN(t) || t >= min
  })
}

function buildTimeBuckets(events = []) {
  const bucket = new Map()
  events.forEach((event) => {
    const label = event.time_bucket && event.time_bucket !== "unknown" ? event.time_bucket : event.date_hour ? `${event.date_hour}:00` : "No time"
    bucket.set(label, (bucket.get(label) || 0) + 1)
  })
  return [...bucket.entries()].sort((a, b) => String(a[0]).localeCompare(String(b[0]))).slice(-24)
}

function buildFieldSummary(events = []) {
  const values = new Map()
  events.forEach((event) => {
    Object.entries(event).forEach(([key, value]) => {
      if (["raw", "message", "headline", "iocs", "why_it_matters", "next_check"].includes(key)) return
      const clean = visibleValue(Array.isArray(value) ? value.join(", ") : typeof value === "object" && value ? JSON.stringify(value) : value)
      if (!clean) return
      if (!values.has(key)) values.set(key, new Map())
      const bucket = values.get(key)
      bucket.set(clean, (bucket.get(clean) || 0) + 1)
    })
  })
  return [...values.entries()].map(([field, bucket]) => ({
    field,
    count: [...bucket.values()].reduce((sum, count) => sum + count, 0),
    top: [...bucket.entries()].sort((a, b) => b[1] - a[1]).slice(0, 8),
  })).sort((a, b) => {
    const ai = FIELD_PRIORITY.indexOf(a.field)
    const bi = FIELD_PRIORITY.indexOf(b.field)
    if (ai !== -1 || bi !== -1) return (ai === -1 ? 999 : ai) - (bi === -1 ? 999 : bi)
    return b.count - a.count
  })
}

function summarizeDataset(events = [], rows = [], detections = []) {
  const fields = buildFieldSummary(events)
  const top = (field) => fields.find((item) => item.field === field)?.top?.[0]?.[0] || ""
  const times = events.map((event) => Date.parse(event.timestamp)).filter((value) => !Number.isNaN(value))
  const highEvents = events.filter((event) => severityRank(event.severity) >= 4).length
  return {
    total: events.length,
    matched: rows.length,
    detections: detections.length,
    highEvents,
    topSource: top("source_ip") || top("host") || top("user"),
    topType: top("event_type") || top("sourcetype"),
    timeRange: times.length ? `${new Date(Math.min(...times)).toLocaleString()} → ${new Date(Math.max(...times)).toLocaleString()}` : "",
  }
}

function makeMarkdown({ filters, keyword, events, rows, detections }) {
  const filterText = filters.length ? filters.map((item) => `${item.field}=${item.value}`).join(", ") : "none"
  return [
    "# BeyondArch SIEM Workspace Export",
    "",
    `Dataset events: ${events.length}`,
    `Matched rows: ${rows.length}`,
    `Active filters: ${filterText}`,
    `Keyword: ${keyword || "none"}`,
    `Detections: ${detections.length}`,
    "",
    "## Detection summary",
    ...(detections.length ? detections.slice(0, 10).map((item) => {
      const mitre = item.mitre_candidates?.length ? ` [${item.mitre_candidates.join(", ")}]` : ""
      return `- **${item.severity?.toUpperCase?.() || "INFO"}** ${item.title}: ${item.detail || item.recommendation || "Review matched events."}${mitre}`
    }) : ["- No detections generated from this dataset."]),
    "",
    "## Matched events",
    ...rows.slice(0, 75).map((row) => `- ${row.timestamp || "-"} [${row.severity || "info"}] ${row.headline || row.message || row.raw}`),
  ].join("\n")
}

function filterId(field, value) {
  return `${field}:${String(value)}`
}

function generateSiemNarrative(dataset, events, detections) {
  if (!dataset?.total) return "No data to summarize."
  const highCount = dataset.highEvents || 0
  const uniqueSources = [...new Set(events.map((e) => e.source_ip || e.host || "").filter(Boolean))].length
  const uniqueTypes = [...new Set(events.map((e) => e.event_type || e.sourcetype || "").filter(Boolean))].length
  const lines = [
    `## SIEM Dataset Summary`,
    ``,
    `**Time Range:** ${dataset.timeRange || "N/A"}`,
    `**Total Events:** ${dataset.total}`,
    `**Matched Events:** ${dataset.matched}`,
    `**Unique Sources:** ${uniqueSources}`,
    `**Event Types:** ${uniqueTypes}`,
    `**High-Severity Events:** ${highCount}`,
    `**Detections Generated:** ${dataset.detections}`,
    ``,
  ]
  if (detections.length) {
    lines.push(
      `### Detection Findings`,
      ``,
      ...detections.slice(0, 8).map((d, i) => {
        const m = d.mitre_candidates?.length ? ` [${d.mitre_candidates.join(", ")}]` : ""
        return `${i + 1}. **${d.severity?.toUpperCase() || "INFO"}** ${d.title}${m} — ${d.detail || d.recommendation || ""}`
      }),
      ``
    )
  }
  lines.push(
    `### Analyst Notes`,
    ``,
    highCount >= 3
      ? "**Alert:** High concentration of high-severity events warrants immediate review. Correlate sources and timelines for incident declaration."
      : highCount >= 1
      ? "**Note:** Isolated high-severity events present. Validate against surrounding context before escalation."
      : "**Note:** No high-severity events in this dataset. Proceed with standard triage workflow.",
    uniqueSources <= 2 && dataset.total > 10
      ? "**Observation:** Low source diversity suggests targeted activity from a small number of hosts or IPs."
      : "",
  ).filter(Boolean)
  return lines.join("\n")
}

export default function SiemWorkspacePage({ setPage }) {
  const [text, setText] = useState(() => readInitialPrefill())
  const [file, setFile] = useState(null)
  const [result, setResult] = useState(null)
  const [filters, setFilters] = useSessionState("siem.filters", [])
  const [keyword, setKeyword] = useSessionState("siem.keyword", "")
  const [timeRange, setTimeRange] = useSessionState("siem.timeRange", "all")
  const [loading, setLoading] = useState(false)
  const [notice, setNotice] = useState("")
  const [modal, setModal] = useState(null)
  const [selectedColumns, setSelectedColumns] = useState(DEFAULT_TABLE_COLUMNS)
  const fileRef = useRef(null)

  const events = useMemo(() => (result?.events || []).map(normalizeEvent), [result])
  const detections = useMemo(() => result?.detections || result?.alerts || [], [result])
  const shownRows = useMemo(() => applyFilters(events, filters, keyword, timeRange).slice(0, 500), [events, filters, keyword, timeRange])
  const fieldSummary = useMemo(() => buildFieldSummary(events), [events])
  const timeBuckets = useMemo(() => buildTimeBuckets(shownRows), [shownRows])
  const dataset = useMemo(() => summarizeDataset(events, shownRows, detections), [events, shownRows, detections])
  const markdown = useMemo(() => makeMarkdown({ filters, keyword, events, rows: shownRows, detections }), [filters, keyword, events, shownRows, detections])

  async function normalizeDataset() {
    if (!text.trim() && !file) {
      setNotice("Paste logs, choose a file, or load the sample dataset first.")
      return
    }
    setLoading(true)
    setNotice("")
    try {
      const data = file ? await uploadSiemLog(file) : await analyzeSiemText(text)
      const normalizedEvents = (data.events || []).map(normalizeEvent)
      setResult({ ...data, events: normalizedEvents })
      setSelectedColumns(buildDefaultColumns(normalizedEvents))
      setFilters([])
      setKeyword("")
      setTimeRange("all")
      setNotice(`Dataset normalized: ${normalizedEvents.length} event(s) loaded.`)
    } catch (error) {
      setNotice(error.message)
    } finally {
      setLoading(false)
    }
  }

  function addFilter(field, value) {
    const clean = visibleValue(value)
    if (!clean) return
    setFilters((current) => {
      const id = filterId(field, clean)
      if (current.some((item) => item.id === id)) return current
      return [...current, { id, field, value: clean }]
    })
  }

  function removeFilter(id) {
    setFilters((current) => current.filter((item) => item.id !== id))
  }

  function addColumn(field) {
    if (!field) return
    setSelectedColumns((current) => {
      if (current.includes(field)) return current
      const withoutMessage = current.filter((item) => item !== "message" && item !== "headline")
      const tail = current.find((item) => item === "message" || item === "headline")
      return tail ? [...withoutMessage, field, tail] : [...current, field]
    })
  }

  function removeColumn(field) {
    setSelectedColumns((current) => {
      const next = current.filter((item) => item !== field)
      return next.length ? next : ["message"]
    })
  }

  function clearDataset() {
    setText("")
    setFile(null)
    setResult(null)
    setFilters([])
    setKeyword("")
    setTimeRange("all")
    setSelectedColumns(DEFAULT_TABLE_COLUMNS)
    setNotice("Dataset cleared.")
  }

  return (
    <WorkbenchPage className="ba-siem-final">
      <WorkbenchHeader
        eyebrow="SIEM"
        title="SIEM Workspace"
        subtitle="Normalize local logs, search like a small SIEM, click fields to filter, and inspect events without sending telemetry to a cloud service."
        icon={Search}
        chips={[
          { label: "local analysis", tone: "local" },
          { label: "field search", tone: "info" },
          { label: "no cloud", tone: "success" },
        ]}
        actions={result ? (
          <div className="ba-siem-final-actions ba-siem-hero-actions">
            <button onClick={() => setPage?.("logs-alerts")}>Logs & Alerts</button>
            <button onClick={() => sendArtifact(setPage, "detection-mitre", { type: "siem_summary", content: markdown })}>Detection & MITRE</button>
            <button onClick={() => downloadText("beyondarch-siem-summary.md", markdown, "text/markdown")}><Download size={16} /> Export</button>
            <SendToActions payload={{ type: "siem_summary", title: `SIEM result set: ${events.length} events`, value: markdown, summary: `${detections.length} detection lead(s), ${shownRows.length} visible event(s).`, tags: ["siem", "events"] }} source="SIEM Workspace" setPage={setPage} compact />
          </div>
        ) : null}
      />
      <section className="ba-siem-final-panel ba-siem-intake-final ba-siem-intake-compact">
        <div className="ba-siem-intake-main">
          <div className="ba-siem-intake-editor">
            <div className="ba-siem-final-section-head">
              <div><p className="ba-eyebrow">Intake</p><h2>Load telemetry</h2><p>Paste syslog, web logs, JSON lines, endpoint alerts, firewall records, or exported SIEM events.</p></div>
            </div>
            <textarea value={text} onChange={(event) => setText(event.target.value)} placeholder="Paste logs here, then click Normalize dataset. Nothing runs automatically while you type." />
          </div>
          <aside className="ba-siem-intake-controls">
            <div className="ba-siem-intake-status">
              <span>Input</span>
              <strong>{file ? file.name : `${text.split(/\n/).filter(Boolean).length} pasted line(s)`}</strong>
              <small>Local parsing first; backend normalization only runs after you click Normalize.</small>
            </div>
            <div className="ba-siem-final-actions">
              <button onClick={() => fileRef.current?.click()}><Upload size={16} /> Choose file</button>
              <input ref={fileRef} className="hidden" type="file" onChange={(event) => setFile(event.target.files?.[0] || null)} />
              <button onClick={() => copy(text)}>Copy input</button>
              <button onClick={clearDataset}>Clear</button>
              <button className="ba-primary-action" onClick={normalizeDataset}>{loading ? "Normalizing…" : "Normalize dataset"}</button>
            </div>
            <details className="ba-siem-mini-details">
              <summary><FileText size={15} /> Load sample dataset</summary>
              <p>Uses mixed auth, web, EDR, and proxy events for SIEM table testing.</p>
              <button onClick={() => setText(SAMPLE_LOGS)}>Use SIEM sample</button>
            </details>
          </aside>
        </div>
      </section>

      {notice ? <p className="ba-info-banner text-sm">{notice}</p> : null}

      {!result ? (
        <section className="ba-siem-empty-final ba-siem-empty-compact">
          <Database size={24} />
          <div>
            <h2>Normalize telemetry to open the SIEM table</h2>
            <p>Field facets, clickable filters, event expansion, detections, and exports appear after a dataset is loaded.</p>
          </div>
        </section>
      ) : (
        <>
          <AnalystOutputCard
            title="SIEM output quality"
            verdict={detections.length ? `${detections.length} detection lead(s)` : "normalized events"}
            confidence="local normalization"
            summary={`${shownRows.length} visible event(s) from ${dataset.total} normalized record(s). Use filters and expansions to validate context before reporting.`}
            evidence={detections.slice(0, 5).map((item) => `${item.title || "Detection lead"}: ${item.detail || item.recommendation || "Review matching events."}`)}
            limitations={["This SIEM view normalizes pasted/local files only; it is not connected to live Splunk/Elastic/Wazuh telemetry.", "Field names and detections depend on the provided sample/log format."]}
            nextActions={["Expand representative events before adding findings.", "Send matched rows to Logs & Alerts for explanation.", "Export CSV/JSON when you need evidence snapshots."]}
            metrics={[
              ["Visible events", shownRows.length],
              ["Total events", dataset.total],
              ["Fields", fieldSummary.length],
            ]}
          />

          <section className="ba-siem-splunk-layout">
            <aside className="ba-siem-fields-rail">
              <div className="ba-siem-fields-rail-head">
                <div><p className="ba-eyebrow">Fields</p><h2>Fields</h2></div>
                <button onClick={() => { setFilters([]); setKeyword("") }}>Reset</button>
              </div>
              <FieldRail fields={fieldSummary} addFilter={addFilter} filters={filters} selectedColumns={selectedColumns} addColumn={addColumn} removeColumn={removeColumn} />
            </aside>

            <main className="ba-siem-results-workspace">
              <section className="ba-siem-results-panel">
                <div className="ba-siem-results-toolbar">
                  <div>
                    <p className="ba-eyebrow">Search results</p>
                    <h2>{shownRows.length} event{shownRows.length === 1 ? "" : "s"}</h2>
                  </div>
                  <div className="ba-siem-results-meta">
                    <span>{dataset.total} total</span>
                    <span>{fieldSummary.length} fields</span>
                    {detections.length ? <span>{detections.length} detection leads</span> : null}
                    {dataset.timeRange ? <span>{dataset.timeRange}</span> : null}
                  </div>
                  <div className="ba-siem-final-actions"><button onClick={() => downloadText("siem-results.csv", rowsToCsv(shownRows), "text/csv")}>CSV</button><button onClick={() => copy(JSON.stringify(shownRows, null, 2))}>JSON</button></div>
                </div>
                <SiemSummaryPanel dataset={dataset} events={events} detections={detections} />
                <div className="ba-siem-time-controls">
                  <div className="ba-siem-time-histogram">
                    {timeBuckets.map(([label, count]) => <button key={label} onClick={() => addFilter("time_bucket", label)} title={`${label}: ${count} event(s)`}><i style={{ height: `${Math.max(12, Math.min(100, count / Math.max(...timeBuckets.map(([, c]) => c), 1) * 100))}%` }} /><span>{label}</span></button>)}
                  </div>
                  <div className="ba-siem-time-range">
                    {[ ["all", "All time"], ["15m", "Last 15m"], ["1h", "Last 1h"], ["24h", "Last 24h"] ].map(([value, label]) => <button key={value} className={timeRange === value ? "is-active" : ""} onClick={() => setTimeRange(value)}>{label}</button>)}
                  </div>
                </div>
                <div className="ba-siem-event-search">
                  <Search size={16} />
                  <input value={keyword} onChange={(event) => setKeyword(event.target.value)} placeholder="Search within events: powershell, 198.51.100.23, noterock.xyz" />
                </div>
                {filters.length || keyword || timeRange !== "all" ? <ActiveFilters filters={filters} keyword={keyword} range={timeRange} removeFilter={removeFilter} clearKeyword={() => setKeyword("")} clearRange={() => setTimeRange("all")} /> : null}
                <EventTable rows={shownRows} addFilter={addFilter} columns={selectedColumns} removeColumn={removeColumn} setPage={setPage} />
              </section>
            </main>
          </section>

          {events.length ? (
            <details className="ba-siem-final-panel ba-siem-details-final" open>
              <summary><span><FileText size={16} /> ATT&CK tactic coverage</span><b>{mitreTacticCoverage(events).length} tactic(s)</b></summary>
              {(() => {
                const coverage = mitreTacticCoverage(events)
                return coverage.length ? (
                  <div className="ba-siem-tactic-grid">
                    {coverage.map((t) => (
                      <article key={t.tactic}>
                        <strong>{t.tactic}</strong>
                        <span className={`ba-chip ${t.count >= 3 ? "ba-status-danger" : t.count >= 2 ? "ba-status-warning" : "ba-status-info"}`}>{t.count}</span>
                        <small>{t.techniques.join(", ")}</small>
                      </article>
                    ))}
                  </div>
                ) : <p className="p-4 text-xs text-zinc-500">No event types matched known MITRE mappings.</p>
              })()}
            </details>
          ) : null}

          {detections.length ? (
            <details className="ba-siem-final-panel ba-siem-details-final">
              <summary><span><FileText size={16} /> Detection leads</span><b>{detections.length} leads</b></summary>
              <div className="ba-siem-detection-leads">
                {detections.slice(0, 8).map((item, index) => (
                  <article key={`${item.title || "lead"}-${index}`}>
                    <div className="ba-siem-detection-head">
                      <strong>{item.title || "Detection lead"}</strong>
                      <span className={`ba-chip ${severityClass(item.severity)}`}>{item.severity || "info"}</span>
                    </div>
                    <p>{item.detail || item.recommendation || "Review matching events and validate context."}</p>
                    {item.evidence ? <details className="ba-siem-detection-evidence"><summary>Evidence</summary><pre>{JSON.stringify(item.evidence, null, 2)}</pre></details> : null}
                    {item.mitre_candidates?.length ? <div className="ba-siem-detection-mitre"><span>MITRE:</span> {item.mitre_candidates.map((m) => <span key={m} className="ba-chip ba-status-info">{m}</span>)}</div> : null}
                    {item.recommendation ? <p className="ba-siem-detection-recommendation"><strong>Next step:</strong> {item.recommendation}</p> : null}
                  </article>
                ))}
              </div>
            </details>
          ) : null}

          <details className="ba-siem-final-panel ba-siem-details-final">
            <summary><span><FileText size={16} /> Send matched events</span><b>triage</b></summary>
            <div className="ba-siem-send-triage">
              <p>Send the currently matched event set to another page for explanation, mapping, command review, or report-ready triage.</p>
              <div className="ba-siem-final-actions">
                <button onClick={() => { try { window.localStorage.setItem("beyondarch.logs.prefill", shownRows.slice(0, 25).map((row) => row.raw || row.message || JSON.stringify(row)).join("\n")) } catch {
                  // localStorage may be unavailable.
                } setPage?.("logs-alerts") }}>Logs & Alerts</button>
                <button onClick={() => sendArtifact(setPage, "detection-mitre", { type: "siem_events", content: shownRows.slice(0, 25).map((row) => row.raw || row.message || JSON.stringify(row)).join("\n") })}>Detection & MITRE</button>
                <button onClick={() => sendArtifact(setPage, "soc-guide", { type: "siem_events", content: shownRows.slice(0, 10).map((row) => row.raw || row.message || JSON.stringify(row)).join("\n") })}>SOC Guide</button>
                <button onClick={() => sendArtifact(setPage, "smart-parser", { type: "siem_events", content: shownRows.slice(0, 10).map((row) => row.raw || row.message || JSON.stringify(row)).join("\n") })}>Smart Parser</button>
              </div>
            </div>
          </details>
        </>
      )}
      {modal ? <SiemModal modal={modal} close={() => setModal(null)} /> : null}
    </WorkbenchPage>
  )
}

function SiemSummaryPanel({ dataset, events, detections }) {
  const [show, setShow] = useState(false)
  const narrative = useMemo(() => generateSiemNarrative(dataset, events, detections), [dataset, events, detections])
  const [copied, setCopied] = useState(false)
  return (
    <div style={{ marginTop: "0.75rem" }}>
      <button className="ba-btn" onClick={() => setShow(!show)} style={{ fontSize: "0.7rem", padding: "0.3rem 0.6rem" }}>
        {show ? "Hide" : "Generate"} SIEM Summary
      </button>
      {show ? (
        <div style={{ marginTop: "0.5rem", padding: "0.75rem", background: "var(--bg-card)", border: "1px solid var(--bd)", borderRadius: "4px" }}>
          <pre style={{ whiteSpace: "pre-wrap", fontSize: "0.7rem", lineHeight: 1.6, fontFamily: "JetBrains Mono, monospace", margin: 0 }}>{narrative}</pre>
          <button
            style={{ marginTop: "0.5rem", fontSize: "0.65rem", padding: "0.25rem 0.5rem", cursor: "pointer" }}
            onClick={() => { navigator.clipboard?.writeText(narrative); setCopied(true); setTimeout(() => setCopied(false), 2000) }}
          >
            {copied ? "Copied!" : "Copy Summary"}
          </button>
        </div>
      ) : null}
    </div>
  )
}

function ActiveFilters({ filters, keyword, range = "all", removeFilter, clearKeyword, clearRange }) {
  return (
    <div className="ba-siem-active-filters">
      <span>Active filters</span>
      {filters.map((filter) => <button key={filter.id} onClick={() => removeFilter(filter.id)}>{filter.field}: {filter.value}<X size={13} /></button>)}
      {keyword ? <button onClick={clearKeyword}>keyword: {keyword}<X size={13} /></button> : null}
      {range !== "all" ? <button onClick={clearRange}>time: {range}<X size={13} /></button> : null}
    </div>
  )
}

function FieldRail({ fields, addFilter, filters = [], selectedColumns = [], addColumn, removeColumn }) {
  const [fieldSearch, setFieldSearch] = useState("")
  const [openField, setOpenField] = useState(() => fields[0]?.field || "")
  const activeIds = new Set(filters.map((item) => item.id))
  const selectedSet = new Set(selectedColumns)
  const needle = fieldSearch.trim().toLowerCase()
  const matches = (item) => !needle || item.field.toLowerCase().includes(needle) || item.top.some(([value]) => String(value).toLowerCase().includes(needle))
  const visibleFields = fields.filter(matches)
  const selectedFields = selectedColumns.map((field) => visibleFields.find((item) => item.field === field) || fields.find((item) => item.field === field)).filter(Boolean)
  const selectedNames = new Set(selectedFields.map((item) => item.field))
  const interestingFields = visibleFields.filter((item) => !selectedNames.has(item.field)).slice(0, 24)

  const renderField = (item, selected = false) => {
    const isOpen = openField === item.field
    const topValues = item.top.slice(0, isOpen ? 8 : 3)
    const max = Math.max(...topValues.map(([, count]) => count), 1)
    return (
      <section key={item.field} className={`ba-siem-splunk-field ${isOpen ? "is-open" : ""} ${selected ? "is-selected" : ""}`}>
        <div className="ba-siem-splunk-field-row">
          <button type="button" onClick={() => setOpenField(isOpen ? "" : item.field)} title={`Show values for ${item.field}`}>
            <span className="ba-siem-splunk-caret">{isOpen ? <ChevronDown size={14} /> : <ChevronRight size={14} />}</span>
            <span className="ba-siem-splunk-field-name">{item.field}</span>
            <small>{item.count}</small>
          </button>
          {selected ? <button className="ba-siem-column-icon" onClick={() => removeColumn?.(item.field)} title={`Remove ${item.field} from columns`} aria-label={`Remove ${item.field} from columns`}><Minus size={14} /></button> : <button className="ba-siem-column-icon" onClick={() => addColumn?.(item.field)} title={`Add ${item.field} to columns`} aria-label={`Add ${item.field} to columns`}><Plus size={14} /></button>}
        </div>
        {isOpen ? (
          <div className="ba-siem-splunk-values">
            {topValues.map(([value, count]) => {
              const active = activeIds.has(filterId(item.field, value))
              return (
                <button key={value} className={active ? "is-active" : ""} onClick={() => addFilter(item.field, value)} title={`${item.field}=${value}`}>
                  <span className="ba-siem-splunk-value-text">{value}</span>
                  <span className="ba-siem-splunk-value-bar"><i style={{ width: `${Math.max(10, Math.round((count / max) * 100))}%` }} /></span>
                  <small>{count}</small>
                </button>
              )
            })}
          </div>
        ) : null}
      </section>
    )
  }

  return (
    <div className="ba-siem-splunk-fields">
      <label className="ba-siem-field-search">
        <Search size={14} />
        <input value={fieldSearch} onChange={(event) => setFieldSearch(event.target.value)} placeholder="Find fields" />
      </label>
      <div className="ba-siem-splunk-field-group">
        <div className="ba-siem-splunk-group-title"><span>Selected fields</span><small>{selectedFields.length}</small></div>
        {selectedFields.length ? selectedFields.map((item) => renderField(item, true)) : <p>No selected fields.</p>}
      </div>
      <div className="ba-siem-splunk-field-group">
        <div className="ba-siem-splunk-group-title"><span>Interesting fields</span><small>{interestingFields.length}</small></div>
        {interestingFields.length ? interestingFields.map((item) => renderField(item, selectedSet.has(item.field))) : <p>No additional fields matched.</p>}
      </div>
    </div>
  )
}

function EventTable({ rows, addFilter, columns = [], removeColumn, setPage }) {
  const [expanded, setExpanded] = useState("")
  const available = new Set(rows.flatMap((row) => Object.entries(row).filter(([, value]) => visibleValue(Array.isArray(value) ? value.join(", ") : typeof value === "object" && value ? JSON.stringify(value) : value)).map(([key]) => key)))
  const fields = columns.filter((field) => available.has(field))
  const visibleFields = fields.length ? fields : ["message"]
  if (!rows.length) return <p className="ba-empty-state">No events matched the active filters.</p>
  return (
    <div className="ba-siem-splunk-table-shell">
      <table className="ba-siem-splunk-table">
        <thead>
          <tr>{visibleFields.map((field) => <th key={field}><span>{columnLabel(field)}</span>{field !== "message" && field !== "headline" ? <button onClick={(event) => { event.stopPropagation(); removeColumn?.(field) }} aria-label={`Remove ${field} column`}><X size={12} /></button> : null}</th>)}</tr>
        </thead>
        <tbody>
          {rows.slice(0, 500).map((row, index) => {
            const rowKey = row.id || row.event_id || `event-${index}`
            const isExpanded = expanded === rowKey
            return (
              <Fragment key={rowKey}>
                <tr className={`severity-${String(row.severity || "info").toLowerCase()} ${isExpanded ? "is-expanded" : ""}`} onClick={() => setExpanded(isExpanded ? "" : rowKey)}>
                  {visibleFields.map((field) => (
                    <td key={field} className={field === "message" || field === "headline" ? "is-event" : ""}>
                      {field === "severity" ? <button className={`ba-chip ${severityClass(row.severity)}`} onClick={(event) => { event.stopPropagation(); addFilter("severity", row.severity) }}>{row.severity || "info"}</button> : clickableCell(field, row, addFilter)}
                    </td>
                  ))}
                </tr>
                {isExpanded ? (
                  <tr className="ba-siem-expanded-row">
                    <td colSpan={visibleFields.length}>
                      <SplunkEventExpanded event={row} addFilter={addFilter} setPage={setPage} />
                    </td>
                  </tr>
                ) : null}
              </Fragment>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

function SplunkEventExpanded({ event, addFilter, setPage }) {
  const entries = Object.entries(event)
    .filter(([key, value]) => !["raw", "iocs", "why_it_matters", "next_check"].includes(key) && visibleValue(Array.isArray(value) ? value.join(", ") : typeof value === "object" && value ? JSON.stringify(value) : value))
    .sort(([a], [b]) => {
      const order = ["timestamp", "severity", "sourcetype", "event_type", "source_ip", "src_ip", "destination_ip", "dst_ip", "user", "host", "process_name", "status_code", "action", "outcome", "message"]
      const ai = order.indexOf(a)
      const bi = order.indexOf(b)
      return (ai === -1 ? 999 : ai) - (bi === -1 ? 999 : bi)
    })
  return (
    <div className="ba-siem-event-expanded">
      {event.timestamp ? <div className="ba-siem-expanded-time"><span>_time</span><b>{event.timestamp}</b></div> : null}
      <div className="ba-siem-expanded-raw">{event.raw || event.message || event.headline || "No raw event text available."}</div>
      <div className="ba-siem-expanded-actions">
        <button onClick={(click) => { click.stopPropagation(); sendArtifact(setPage, "logs-alerts", { type: "siem_event", content: event.raw || event.message || JSON.stringify(event, null, 2) }) }}>Logs & Alerts</button>
        <button onClick={(click) => { click.stopPropagation(); sendArtifact(setPage, "detection-mitre", { type: "siem_event", content: event.raw || event.message || JSON.stringify(event, null, 2) }) }}>Detection & MITRE</button>
        <button onClick={(click) => { click.stopPropagation(); sendArtifact(setPage, "soc-guide", { type: "siem_event", content: event.command_line || event.message || event.raw || JSON.stringify(event, null, 2) }) }}>SOC Guide</button>
        <button onClick={(click) => { click.stopPropagation(); sendArtifact(setPage, "smart-parser", { type: "siem_event", content: event.raw || event.message || JSON.stringify(event, null, 2) }) }}>Smart Parser</button>
        <SendToActions
          payload={{ type: "siem_event", title: event.event_type || event.headline || "SIEM event", value: event.raw || event.message || JSON.stringify(event, null, 2), summary: event.headline || event.message || event.raw, severity: event.severity, tags: [event.sourcetype, event.event_type, event.severity].filter(Boolean) }}
          source="SIEM Workspace"
          setPage={setPage}
          compact
        />
      </div>
      <div className="ba-siem-expanded-fields">
        {entries.map(([key]) => (
          <button key={key} onClick={(click) => { click.stopPropagation(); addFilter(key, fieldValue(event, key)) }}>
            <span>{columnLabel(key)}</span>
            <b>{fieldValue(event, key)}</b>
          </button>
        ))}
      </div>
    </div>
  )
}

function clickableCell(field, row, addFilter) {
  const value = fieldValue(row, field)
  if (!["sourcetype", "event_type", "source_ip", "src_ip", "destination_ip", "dst_ip", "user", "host", "process_name", "status_code", "action", "outcome"].includes(field) || !visibleValue(value)) return value
  return <button className="ba-siem-cell-filter" onClick={(event) => { event.stopPropagation(); addFilter(field, value) }}>{value}</button>
}

function SiemModal({ modal, close }) {
  return (
    <div className="ba-siem-modal-backdrop" role="dialog" aria-modal="true" aria-label={modal.title} onMouseDown={close}>
      <section className="ba-siem-modal" onMouseDown={(event) => event.stopPropagation()}>
        <header>
          <div><p className="ba-eyebrow">Details</p><h2>{modal.title}</h2>{modal.subtitle ? <p>{modal.subtitle}</p> : null}</div>
          <button onClick={close} aria-label="Close"><X size={18} /></button>
        </header>
        <pre>{JSON.stringify(modal.data, null, 2)}</pre>
        <footer><button onClick={() => copy(JSON.stringify(modal.data, null, 2))}>Copy JSON</button><button onClick={close}>Close</button></footer>
      </section>
    </div>
  )
}
