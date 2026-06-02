import { useEffect, useMemo, useState } from "react"
import { Clipboard, Download, FileJson, FileText, GitBranch, Lightbulb, NotebookPen, Plus, ShieldCheck, Trash2 } from "lucide-react"
import { downloadText, escapeHtml } from "../../lib/domUtils"
import SendToActions from "../../components/investigation/SendToActions"
import { WorkbenchHeader, WorkbenchPage, WorkbenchPanel } from "../../components/layout/WorkbenchShell"
import {
  INVESTIGATION_EVENT,
  addAnalystNote,
  addHypothesis,
  addTimelineEvent,
  clearInvestigationData,
  consumePendingArtifact,
  exportInvestigationJson,
  importInvestigationJson,
  investigationMarkdown,
  loadInvestigationState,
  saveInvestigationState,
} from "../../lib/investigationStore"

function reportHtml(markdown = "") {
  const body = escapeHtml(markdown)
    .replace(/^# (.+)$/gm, "<h1>$1</h1>")
    .replace(/^## (.+)$/gm, "<h2>$1</h2>")
    .replace(/^### (.+)$/gm, "<h3>$1</h3>")
    .replace(/^- (.+)$/gm, "<p class=\"bullet\">• $1</p>")
    .replace(/```text\n([\s\S]*?)```/g, "<pre>$1</pre>")
    .replace(/\n{2,}/g, "<br />")
  return `<!doctype html><html><head><meta charset="utf-8"/><title>BeyondArch Case Report</title><style>body{margin:0;background:#050505;color:#f5f5f5;font-family:Inter,system-ui,sans-serif;line-height:1.6;padding:40px}main{max-width:920px;margin:auto}h1{font-size:34px}h2{margin-top:32px;border-top:1px solid #27272a;padding-top:20px}h3{color:#a5f3fc}pre{white-space:pre-wrap;background:#0a0a0a;border:1px solid #27272a;border-radius:14px;padding:16px;overflow:auto}.bullet{margin:.25rem 0;color:#d4d4d8}</style></head><body><main>${body}</main></body></html>`
}

function artifactToEvent(artifact) {
  if (!artifact) return null
  return {
    type: artifact.type || "evidence",
    title: artifact.title || `${artifact.source || "BeyondArch"} artifact`,
    summary: artifact.summary || artifact.description || "Imported from another BeyondArch workspace.",
    source: artifact.source || "BeyondArch",
    tags: artifact.tags || [artifact.type || "artifact"].filter(Boolean),
    raw: artifact.value || artifact.content || artifact.text || artifact.raw || "",
  }
}

function useInvestigationState() {
  const [state, setState] = useState(() => loadInvestigationState())
  useEffect(() => {
    function refresh(event) {
      setState(event.detail?.state || loadInvestigationState())
    }
    window.addEventListener(INVESTIGATION_EVENT, refresh)
    window.addEventListener("storage", refresh)
    return () => {
      window.removeEventListener(INVESTIGATION_EVENT, refresh)
      window.removeEventListener("storage", refresh)
    }
  }, [])
  return [state, setState]
}

function StatCard({ icon: Icon, label, value }) {
  return (
    <article className="ba-case-stat">
      <Icon className="h-4 w-4" />
      <span>{label}</span>
      <strong>{value}</strong>
    </article>
  )
}

function Empty({ icon: Icon, children }) {
  return (
    <div className="flex flex-col items-center gap-3 py-8 text-center">
      {Icon ? <Icon className="h-8 w-8 text-zinc-500" /> : null}
      <p className="ba-empty-state">{children}</p>
    </div>
  )
}

export default function InvestigationTimelinePage({ setPage }) {
  const [state] = useInvestigationState()
  const [initialNotice] = useState(() => {
    const pending = artifactToEvent(consumePendingArtifact(["case-timeline", "timeline"]))
    if (!pending) return ""
    const added = addTimelineEvent(pending)
    return `Imported timeline event: ${added.title}`
  })
  const [notice, setNotice] = useState(initialNotice)
  const [activeTab, setActiveTab] = useState("timeline")
  const [timelineForm, setTimelineForm] = useState({ title: "", summary: "", raw: "", type: "evidence", severity: "info", tags: "" })
  const [noteForm, setNoteForm] = useState({ title: "", note: "", tags: "" })
  const [hypothesisForm, setHypothesisForm] = useState({ title: "", confidence: "medium", supporting: "", contradicting: "" })
  const [importText, setImportText] = useState("")


  const markdown = useMemo(() => investigationMarkdown(state), [state])
  const counts = {
    artifacts: state.artifacts?.length || 0,
    timeline: state.timeline?.length || 0,
    notes: state.notes?.length || 0,
    hypotheses: state.hypotheses?.length || 0,
    findings: state.findings?.length || 0,
  }
  const reportReadiness = [
    { label: "Artifacts captured", ready: counts.artifacts > 0, hint: counts.artifacts ? `${counts.artifacts} saved` : "Add at least one IOC or evidence item" },
    { label: "Timeline present", ready: counts.timeline > 0, hint: counts.timeline ? `${counts.timeline} event(s)` : "Send tool results or add a manual event" },
    { label: "Findings documented", ready: counts.findings > 0, hint: counts.findings ? `${counts.findings} finding(s)` : "Mark at least one finding before export" },
    { label: "Analyst context", ready: counts.notes + counts.hypotheses > 0, hint: counts.notes + counts.hypotheses ? "Notes/hypotheses included" : "Add a note or hypothesis for review context" },
  ]

  async function copy(content, label) {
    if (!content) return
    await navigator.clipboard.writeText(content)
    setNotice(`${label} copied.`)
  }

  function addManualTimeline() {
    if (!timelineForm.title.trim() && !timelineForm.raw.trim()) {
      setNotice("Add a title or evidence text first.")
      return
    }
    const added = addTimelineEvent({
      title: timelineForm.title || "Manual analyst event",
      summary: timelineForm.summary || timelineForm.raw.slice(0, 240),
      raw: timelineForm.raw,
      type: timelineForm.type,
      severity: timelineForm.severity,
      source: "Manual analyst entry",
      tags: timelineForm.tags.split(",").map((item) => item.trim()).filter(Boolean),
    })
    setTimelineForm({ title: "", summary: "", raw: "", type: "evidence", severity: "info", tags: "" })
    setNotice(`Added timeline event: ${added.title}`)
  }

  function addManualNote() {
    if (!noteForm.note.trim() && !noteForm.title.trim()) {
      setNotice("Add a note first.")
      return
    }
    const note = addAnalystNote({
      title: noteForm.title || "Analyst note",
      note: noteForm.note,
      tags: noteForm.tags.split(",").map((item) => item.trim()).filter(Boolean),
      source: "Manual analyst entry",
    })
    setNoteForm({ title: "", note: "", tags: "" })
    setNotice(`Added note: ${note.title}`)
  }

  function addManualHypothesis() {
    if (!hypothesisForm.title.trim()) {
      setNotice("Add a hypothesis title first.")
      return
    }
    const hypothesis = addHypothesis({
      title: hypothesisForm.title,
      confidence: hypothesisForm.confidence,
      supporting: hypothesisForm.supporting.split("\n").map((item) => item.trim()).filter(Boolean),
      contradicting: hypothesisForm.contradicting.split("\n").map((item) => item.trim()).filter(Boolean),
      source: "Manual analyst entry",
    })
    setHypothesisForm({ title: "", confidence: "medium", supporting: "", contradicting: "" })
    setNotice(`Added hypothesis: ${hypothesis.title}`)
  }

  function removeItem(collection, id) {
    const next = { ...loadInvestigationState(), [collection]: (loadInvestigationState()[collection] || []).filter((item) => item.id !== id) }
    saveInvestigationState(next)
    setNotice("Item removed.")
  }

  function clearCase() {
    if (!window.confirm("Clear the shared investigation store? This removes artifacts, timeline, notes, hypotheses, and findings.")) return
    clearInvestigationData()
    setNotice("Investigation store cleared.")
  }

  function exportJson() {
    downloadText("beyondarch-case-export.json", JSON.stringify(exportInvestigationJson(), null, 2), "application/json")
    setNotice("JSON case export created.")
  }

  function exportHtml() {
    downloadText("beyondarch-case-report.html", reportHtml(markdown), "text/html")
    setNotice("HTML report export created.")
  }

  function applyImport() {
    try {
      importInvestigationJson(JSON.parse(importText))
      setImportText("")
      setNotice("Case import applied.")
    } catch (error) {
      setNotice(error.message || "Could not import case JSON.")
    }
  }

  return (
    <WorkbenchPage className="ba-case-workspace">
      <WorkbenchHeader
        eyebrow="Investigation workspace"
        title="Case Timeline & Report"
        subtitle="Collect artifacts, timeline events, analyst notes, hypotheses, and findings from every BeyondArch module. Export a case-ready Markdown or JSON handoff."
        icon={FileText}
        chips={[{ label: "shared store", tone: "local" }, { label: `${counts.timeline} timeline`, tone: "info" }, { label: `${counts.findings} findings`, tone: "warning" }]}
        actions={(
          <div className="flex flex-wrap gap-2">
            <button type="button" className="ba-button-secondary" onClick={() => copy(markdown, "Case Markdown")}>Copy Markdown</button>
            <button type="button" className="ba-button-primary" onClick={() => downloadText("beyondarch-case-report.md", markdown)}>Export Markdown</button>
          </div>
        )}
      />

      {notice ? <WorkbenchPanel soft className="ba-info-banner text-sm">{notice}</WorkbenchPanel> : null}

      <section className="ba-case-stat-grid">
        <StatCard icon={FileText} label="Artifacts" value={counts.artifacts} />
        <StatCard icon={GitBranch} label="Timeline" value={counts.timeline} />
        <StatCard icon={NotebookPen} label="Notes" value={counts.notes} />
        <StatCard icon={Lightbulb} label="Hypotheses" value={counts.hypotheses} />
        <StatCard icon={ShieldCheck} label="Findings" value={counts.findings} />
      </section>

      <div className="ba-case-tabs" role="tablist" aria-label="Investigation views">
        {["timeline", "notes", "hypotheses", "findings", "report", "backup"].map((tab) => (
          <button key={tab} type="button" className={activeTab === tab ? "is-active" : ""} onClick={() => setActiveTab(tab)}>{tab}</button>
        ))}
      </div>

      {activeTab === "timeline" && (
        <div className="grid gap-4 xl:grid-cols-[0.9fr_1.1fr]">
          <WorkbenchPanel className="space-y-3">
            <p className="ba-output-section-eyebrow">Add timeline event</p>
            <input value={timelineForm.title} onChange={(event) => setTimelineForm((data) => ({ ...data, title: event.target.value }))} placeholder="Title, e.g. Suspicious redirect observed" className="ba-input" />
            <div className="grid gap-3 md:grid-cols-2">
              <select value={timelineForm.type} onChange={(event) => setTimelineForm((data) => ({ ...data, type: event.target.value }))} className="ba-input">{["evidence", "hypothesis", "action", "containment", "recovery", "note"].map((item) => <option key={item} value={item}>{item}</option>)}</select>
              <select value={timelineForm.severity} onChange={(event) => setTimelineForm((data) => ({ ...data, severity: event.target.value }))} className="ba-input">{["info", "low", "medium", "high", "critical"].map((item) => <option key={item} value={item}>{item}</option>)}</select>
            </div>
            <textarea value={timelineForm.summary} onChange={(event) => setTimelineForm((data) => ({ ...data, summary: event.target.value }))} placeholder="Short analyst summary..." className="ba-input min-h-20" />
            <textarea value={timelineForm.raw} onChange={(event) => setTimelineForm((data) => ({ ...data, raw: event.target.value }))} placeholder="Raw evidence, URL, log line, hash, command, or notes..." className="ba-input ba-mono-input min-h-32" />
            <input value={timelineForm.tags} onChange={(event) => setTimelineForm((data) => ({ ...data, tags: event.target.value }))} placeholder="Tags: phishing, url, auth" className="ba-input" />
            <button type="button" className="ba-button-primary" onClick={addManualTimeline}><Plus className="mr-2 inline h-4 w-4" />Add timeline event</button>
          </WorkbenchPanel>

          <WorkbenchPanel className="space-y-3">
            <div className="ba-case-list-head"><p className="ba-panel-kicker">Timeline entries</p><span>{counts.timeline} saved</span></div>
            <div className="space-y-3">
              {state.timeline?.map((entry) => (
                <article key={entry.id} className="ba-case-card">
                  <div className="ba-case-card-head">
                    <div><h3>{entry.title}</h3><p>{entry.time}</p></div>
                    <button type="button" className="ba-mini-danger" onClick={() => removeItem("timeline", entry.id)}>Remove</button>
                  </div>
                  <div className="ba-chip-row"><span className="ba-chip ba-status-local">{entry.type}</span><span className="ba-chip ba-status-info">{entry.source}</span><span className="ba-chip">{entry.severity}</span>{entry.tags?.map((tag) => <span key={tag} className="ba-chip">{tag}</span>)}</div>
                  {entry.summary ? <p className="ba-case-summary">{entry.summary}</p> : null}
                  {entry.raw ? <details className="ba-raw-details"><summary>Raw evidence</summary><pre>{entry.raw}</pre></details> : null}
                  <SendToActions payload={entry} source="Case Timeline" setPage={setPage} compact />
                </article>
              ))}
              {!state.timeline?.length ? <Empty icon={GitBranch}>No timeline events yet. Use a Send-to action from another module or add one manually above.</Empty> : null}
            </div>
          </WorkbenchPanel>
        </div>
      )}

      {activeTab === "notes" && (
        <div className="grid gap-4 xl:grid-cols-[0.85fr_1.15fr]">
          <WorkbenchPanel className="space-y-3">
            <p className="ba-output-section-eyebrow">Add analyst note</p>
            <input className="ba-input" value={noteForm.title} onChange={(event) => setNoteForm((data) => ({ ...data, title: event.target.value }))} placeholder="Note title" />
            <textarea className="ba-input min-h-40" value={noteForm.note} onChange={(event) => setNoteForm((data) => ({ ...data, note: event.target.value }))} placeholder="Observation, decision, open question, or triage note..." />
            <input className="ba-input" value={noteForm.tags} onChange={(event) => setNoteForm((data) => ({ ...data, tags: event.target.value }))} placeholder="Tags" />
            <button type="button" className="ba-button-primary" onClick={addManualNote}>Add note</button>
          </WorkbenchPanel>
          <WorkbenchPanel className="space-y-3">
            {state.notes?.map((note) => <article key={note.id} className="ba-case-card"><div className="ba-case-card-head"><div><h3>{note.title}</h3><p>{note.source} · {note.createdAt}</p></div><button type="button" className="ba-mini-danger" onClick={() => removeItem("notes", note.id)}>Remove</button></div><p className="ba-case-summary">{note.note}</p><SendToActions payload={{ ...note, value: note.note }} source="Analyst Notes" setPage={setPage} compact /></article>)}
            {!state.notes?.length ? <Empty icon={NotebookPen}>No analyst notes saved yet. Add observations, decisions, and open questions above.</Empty> : null}
          </WorkbenchPanel>
        </div>
      )}

      {activeTab === "hypotheses" && (
        <div className="grid gap-4 xl:grid-cols-[0.85fr_1.15fr]">
          <WorkbenchPanel className="space-y-3">
            <p className="ba-output-section-eyebrow">Add hypothesis</p>
            <input className="ba-input" value={hypothesisForm.title} onChange={(event) => setHypothesisForm((data) => ({ ...data, title: event.target.value }))} placeholder="Hypothesis, e.g. Credential phishing attempt" />
            <select className="ba-input" value={hypothesisForm.confidence} onChange={(event) => setHypothesisForm((data) => ({ ...data, confidence: event.target.value }))}>{["low", "medium", "high", "unknown"].map((item) => <option key={item} value={item}>{item}</option>)}</select>
            <textarea className="ba-input min-h-28" value={hypothesisForm.supporting} onChange={(event) => setHypothesisForm((data) => ({ ...data, supporting: event.target.value }))} placeholder="Supporting evidence, one per line" />
            <textarea className="ba-input min-h-24" value={hypothesisForm.contradicting} onChange={(event) => setHypothesisForm((data) => ({ ...data, contradicting: event.target.value }))} placeholder="Contradicting evidence, one per line" />
            <button type="button" className="ba-button-primary" onClick={addManualHypothesis}>Add hypothesis</button>
          </WorkbenchPanel>
          <WorkbenchPanel className="space-y-3">
            {state.hypotheses?.map((item) => <article key={item.id} className="ba-case-card"><div className="ba-case-card-head"><div><h3>{item.title}</h3><p>{item.status} · confidence {item.confidence}</p></div><button type="button" className="ba-mini-danger" onClick={() => removeItem("hypotheses", item.id)}>Remove</button></div>{item.supporting?.length ? <ul className="ba-case-list">{item.supporting.map((row) => <li key={row}>{row}</li>)}</ul> : null}<SendToActions payload={{ ...item, value: item.supporting?.join("\n") || item.title }} source="Hypothesis Tracker" setPage={setPage} compact /></article>)}
            {!state.hypotheses?.length ? <Empty icon={Lightbulb}>No hypotheses saved yet. Record suspicions and supporting evidence above.</Empty> : null}
          </WorkbenchPanel>
        </div>
      )}

      {activeTab === "findings" && (
        <WorkbenchPanel className="space-y-3">
          {state.findings?.map((finding) => <article key={finding.id} className="ba-case-card"><div className="ba-case-card-head"><div><h3>{finding.title}</h3><p>{finding.source} · severity {finding.severity} · confidence {finding.confidence}</p></div><button type="button" className="ba-mini-danger" onClick={() => removeItem("findings", finding.id)}>Remove</button></div><p className="ba-case-summary">{finding.summary}</p><SendToActions payload={finding} source="Case Findings" setPage={setPage} compact /></article>)}
          {!state.findings?.length ? <Empty icon={ShieldCheck}>No findings saved yet. Use Send-to actions from tool results to capture evidence here.</Empty> : null}
        </WorkbenchPanel>
      )}

      {activeTab === "report" && (
        <div className="grid gap-4 xl:grid-cols-[0.78fr_1.22fr]">
          <WorkbenchPanel className="space-y-3">
            <p className="ba-output-section-eyebrow">Report readiness</p>
            <div className="ba-report-readiness-grid">
              {reportReadiness.map((item) => (
                <article key={item.label} className={item.ready ? "is-ready" : ""}>
                  <strong>{item.label}</strong>
                  <span>{item.hint}</span>
                </article>
              ))}
            </div>
            <div className="ba-report-export-grid">
              <button type="button" className="ba-button-primary" onClick={() => downloadText("beyondarch-case-report.md", markdown)}><Download className="mr-2 inline h-4 w-4" />Markdown</button>
              <button type="button" className="ba-button-secondary" onClick={exportHtml}><FileText className="mr-2 inline h-4 w-4" />HTML</button>
              <button type="button" className="ba-button-secondary" onClick={exportJson}><FileJson className="mr-2 inline h-4 w-4" />JSON backup</button>
              <button type="button" className="ba-button-secondary" onClick={() => copy(markdown, "Case Markdown")}><Clipboard className="mr-2 inline h-4 w-4" />Copy</button>
            </div>
            <p className="ba-safety-note">Exports may contain sensitive client or lab artifacts. Review before sharing or uploading to GitHub.</p>
          </WorkbenchPanel>
          <WorkbenchPanel className="space-y-3">
            <div className="ba-case-list-head"><p className="ba-output-section-eyebrow">Generated Markdown report</p><span>{markdown.length.toLocaleString()} chars</span></div>
            <textarea className="ba-input ba-mono-input min-h-[28rem]" value={markdown} readOnly />
          </WorkbenchPanel>
        </div>
      )}

      {activeTab === "backup" && (
        <div className="grid gap-4 xl:grid-cols-2">
          <WorkbenchPanel className="space-y-3">
            <p className="ba-output-section-eyebrow">Export / clear</p>
            <button type="button" className="ba-button-primary" onClick={exportJson}><FileJson className="mr-2 inline h-4 w-4" />Export JSON backup</button>
            <button type="button" className="ba-button-secondary" onClick={() => copy(JSON.stringify(exportInvestigationJson(), null, 2), "Case JSON")}>Copy JSON</button>
            <button type="button" className="ba-mini-danger ba-danger-wide" onClick={clearCase}><Trash2 className="mr-2 inline h-4 w-4" />Clear shared case data</button>
          </WorkbenchPanel>
          <WorkbenchPanel className="space-y-3">
            <p className="ba-output-section-eyebrow">Import JSON backup</p>
            <textarea className="ba-input ba-mono-input min-h-52" value={importText} onChange={(event) => setImportText(event.target.value)} placeholder="Paste beyondarch_investigation_export JSON..." />
            <button type="button" className="ba-button-secondary" disabled={!importText.trim()} onClick={applyImport}>Apply import</button>
          </WorkbenchPanel>
        </div>
      )}

      {activeTab === "backup" && (
        <details className="ba-workbench-panel mt-4 p-4">
          <summary className="cursor-pointer text-lg font-black text-zinc-50">Full raw state (debug view)</summary>
          <pre className="mt-3 max-h-96 overflow-auto whitespace-pre-wrap rounded-xl border border-white/10 bg-black/40 p-4 text-xs leading-5 text-zinc-100">{JSON.stringify(loadInvestigationState(), null, 2)}</pre>
        </details>
      )}
    </WorkbenchPage>
  )
}
