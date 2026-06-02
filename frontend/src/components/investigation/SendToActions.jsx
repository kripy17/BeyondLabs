import { useState } from "react"
import { BookMarked, ChevronDown, FileText, GitBranch, Lightbulb, NotebookPen, Route, Search, ShieldCheck } from "lucide-react"
import {
  addAnalystNote,
  addArtifact,
  addFinding,
  addHypothesis,
  addTimelineEvent,
  routeArtifactToPage,
} from "../../lib/investigationStore"

function normalizePayload(payload = {}, source = "BeyondArch") {
  const value = payload.value || payload.content || payload.raw || payload.text || payload.summary || payload.title || ""
  return {
    ...payload,
    value: String(value || ""),
    source: payload.source || payload.sourceTool || source,
    title: payload.title || payload.label || `${source} artifact`,
    summary: payload.summary || payload.description || String(value || "").slice(0, 260),
    tags: Array.isArray(payload.tags) ? payload.tags : [payload.type || "artifact"].filter(Boolean),
  }
}

const DESTINATIONS = [
  { id: "timeline", label: "Timeline", icon: GitBranch, priority: true },
  { id: "finding", label: "Finding", icon: ShieldCheck, priority: true },
  { id: "report", label: "Report", icon: BookMarked, priority: true },
  { id: "note", label: "Note", icon: NotebookPen },
  { id: "hypothesis", label: "Hypothesis", icon: Lightbulb },
]

const PIVOTS = [
  { id: "safe-url-analyzer", label: "URL Analyzer", icon: Search, match: /url|link|domain/i },
  { id: "recon-exposure", label: "Recon", icon: Search, match: /domain|ip|url|host|target/i },
  { id: "logs-alerts", label: "Logs", icon: FileText, match: /log|event|alert|json/i },
  { id: "phishing-triage", label: "Phishing", icon: FileText, match: /email|phish|header|sender/i },
  { id: "cyberchef", label: "Decode", icon: Route, match: /base64|jwt|token|defang|text/i },
]

export default function SendToActions({ payload = {}, source = "BeyondArch", setPage, compact = false, pivots = true, onDone }) {
  const [notice, setNotice] = useState("")
  const [expanded, setExpanded] = useState(false)
  const item = normalizePayload(payload, source)
  const typeText = `${item.type || ""} ${item.title || ""} ${item.tags?.join(" ") || ""} ${item.value || ""}`
  const visiblePivots = pivots ? PIVOTS.filter((pivot) => pivot.match.test(typeText)).slice(0, 3) : []
  const primaryDestinations = DESTINATIONS.filter((destination) => destination.priority)
  const secondaryDestinations = DESTINATIONS.filter((destination) => !destination.priority)
  const hasMore = secondaryDestinations.length || visiblePivots.length

  function done(message) {
    setNotice(message)
    onDone?.(message)
  }

  function handle(destination) {
    if (destination === "timeline") {
      const entry = addTimelineEvent({ ...item, raw: item.value, source, type: item.type || "evidence" })
      done(`Added to timeline: ${entry.title}`)
    }
    if (destination === "note") {
      const note = addAnalystNote({ title: item.title, note: item.summary || item.value, source, tags: item.tags })
      done(`Added note: ${note.title}`)
    }
    if (destination === "finding") {
      const finding = addFinding({ title: item.title, summary: item.summary || item.value, source, tags: item.tags, raw: item.value })
      done(`Added finding: ${finding.title}`)
    }
    if (destination === "hypothesis") {
      const hypothesis = addHypothesis({ title: item.title?.startsWith("Hypothesis") ? item.title : `Hypothesis: ${item.title}`, supporting: [item.summary || item.value].filter(Boolean), source, confidence: item.confidence || "unknown" })
      done(`Added hypothesis: ${hypothesis.title}`)
    }
    if (destination === "report") {
      const artifact = addArtifact({ value: item.value || item.summary || item.title, type: item.type || "report_item", title: item.title, source, findings: item.detected || [] })
      addFinding({ title: item.title, summary: item.summary || item.value, source, tags: item.tags, raw: item.value })
      done(`Added report evidence: ${artifact.title}`)
    }
  }

  function pivot(page) {
    routeArtifactToPage(item, page)
    setPage?.(page)
    done(`Sent to ${page.replaceAll("-", " ")}.`)
  }

  return (
    <div className={`ba-sendto ${compact ? "ba-sendto-compact" : ""}`}>
      <div className="ba-sendto-actions" aria-label="Send to investigation actions">
        {primaryDestinations.map((destination) => {
          const Icon = destination.icon
          return (
            <button key={destination.id} type="button" onClick={() => handle(destination.id)}>
              <Icon className="h-3.5 w-3.5" />
              <span>{destination.label}</span>
            </button>
          )
        })}
        {hasMore ? (
          <button type="button" className="ba-sendto-more-button" aria-expanded={expanded} onClick={() => setExpanded((current) => !current)}>
            <ChevronDown className="h-3.5 w-3.5" />
            <span>{expanded ? "Hide" : "More"}</span>
          </button>
        ) : null}
      </div>
      {expanded ? (
        <div className="ba-sendto-more" aria-label="More send destinations">
          {secondaryDestinations.map((destination) => {
            const Icon = destination.icon
            return (
              <button key={destination.id} type="button" onClick={() => handle(destination.id)}>
                <Icon className="h-3.5 w-3.5" />
                <span>{destination.label}</span>
              </button>
            )
          })}
          {visiblePivots.map((pivotItem) => {
            const Icon = pivotItem.icon
            return (
              <button key={pivotItem.id} type="button" onClick={() => pivot(pivotItem.id)}>
                <Icon className="h-3.5 w-3.5" />
                <span>{pivotItem.label}</span>
              </button>
            )
          })}
        </div>
      ) : null}
      {notice ? <p className="ba-sendto-notice">{notice}</p> : null}
    </div>
  )
}
