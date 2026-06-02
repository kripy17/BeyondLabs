import { detectArtifacts, normalizeArtifactPayload } from "./artifactDetection"

export const INVESTIGATION_STORE_KEY = "beyondarch.investigation.v1"
export const INVESTIGATION_SESSION_KEY = "beyondarch.investigation.session.v1"
export const INVESTIGATION_STORAGE_MODE_KEY = "beyondarch.investigation.storageMode.v1"
export const INVESTIGATION_EVENT = "beyondarch:investigation-updated"
export const PENDING_ARTIFACT_KEY = "beyondarch.pendingArtifact"

export const STORAGE_MODES = [
  { value: "none", label: "Do not store analyzed data", description: "Keep only transient in-memory data until reload." },
  { value: "session", label: "Store during current browser session", description: "Restore while the tab/session is open. Default privacy-balanced mode." },
  { value: "local", label: "Store locally and restore after browser restart", description: "Persist artifacts, timeline, notes, hypotheses, and report data in browser storage." },
]

const DEFAULT_STATE = {
  version: 1,
  updatedAt: null,
  artifacts: [],
  timeline: [],
  notes: [],
  hypotheses: [],
  findings: [],
  reportSections: [],
  recentActions: [],
}

let memoryState = { ...DEFAULT_STATE }
let memoryMode = "session"
let memoryPendingArtifact = null

function clone(value) {
  return JSON.parse(JSON.stringify(value))
}

function safeParse(raw, fallback) {
  try {
    const parsed = raw ? JSON.parse(raw) : fallback
    return parsed ?? fallback
  } catch {
    return fallback
  }
}

function getStoreForMode(mode = getStorageMode()) {
  if (typeof window === "undefined") return null
  if (mode === "local") return window.localStorage
  if (mode === "session") return window.sessionStorage
  return null
}

function normalizeState(raw = {}) {
  return {
    ...DEFAULT_STATE,
    ...raw,
    artifacts: Array.isArray(raw.artifacts) ? raw.artifacts : [],
    timeline: Array.isArray(raw.timeline) ? raw.timeline : [],
    notes: Array.isArray(raw.notes) ? raw.notes : [],
    hypotheses: Array.isArray(raw.hypotheses) ? raw.hypotheses : [],
    findings: Array.isArray(raw.findings) ? raw.findings : [],
    reportSections: Array.isArray(raw.reportSections) ? raw.reportSections : [],
    recentActions: Array.isArray(raw.recentActions) ? raw.recentActions : [],
  }
}

function dispatch(state = loadInvestigationState()) {
  if (typeof window === "undefined") return
  window.dispatchEvent(new CustomEvent(INVESTIGATION_EVENT, { detail: { state } }))
}

export function getStorageMode() {
  if (typeof window === "undefined") return memoryMode
  const saved = window.localStorage.getItem(INVESTIGATION_STORAGE_MODE_KEY)
  if (["none", "session", "local"].includes(saved)) return saved
  return "session"
}

export function setStorageMode(mode = "session") {
  const nextMode = ["none", "session", "local"].includes(mode) ? mode : "session"
  const current = loadInvestigationState()
  memoryMode = nextMode
  if (typeof window !== "undefined") {
    window.localStorage.setItem(INVESTIGATION_STORAGE_MODE_KEY, nextMode)
    window.sessionStorage.removeItem(INVESTIGATION_SESSION_KEY)
    window.localStorage.removeItem(INVESTIGATION_STORE_KEY)
  }
  saveInvestigationState(current, nextMode)
  dispatch(loadInvestigationState())
  return nextMode
}

export function loadInvestigationState() {
  const mode = getStorageMode()
  const store = getStoreForMode(mode)
  if (!store) return normalizeState(memoryState)
  const key = mode === "local" ? INVESTIGATION_STORE_KEY : INVESTIGATION_SESSION_KEY
  const stored = normalizeState(safeParse(store.getItem(key), DEFAULT_STATE))
  return stored
}

export function saveInvestigationState(nextState, mode = getStorageMode()) {
  const normalized = normalizeState({ ...nextState, updatedAt: new Date().toISOString() })
  memoryState = normalized
  const store = getStoreForMode(mode)
  if (store) {
    const key = mode === "local" ? INVESTIGATION_STORE_KEY : INVESTIGATION_SESSION_KEY
    store.setItem(key, JSON.stringify(normalized))
  }
  dispatch(normalized)
  return normalized
}

function mutate(updater, action = "updated investigation") {
  const state = loadInvestigationState()
  const next = updater(clone(state)) || state
  next.recentActions = [{ id: globalThis.crypto?.randomUUID?.() || `action-${Date.now()}`, action, at: new Date().toISOString() }, ...(next.recentActions || [])].slice(0, 25)
  return saveInvestigationState(next)
}

export function addArtifact(payload = {}) {
  const artifact = normalizeArtifactPayload(payload)
  mutate((state) => {
    const key = `${artifact.type}:${artifact.value}`.toLowerCase()
    const exists = state.artifacts.some((item) => `${item.type}:${item.value}`.toLowerCase() === key)
    if (!exists) state.artifacts.unshift(artifact)
    return state
  }, `added artifact: ${artifact.title}`)
  return artifact
}

export function addTimelineEvent(payload = {}) {
  const event = {
    id: payload.id || globalThis.crypto?.randomUUID?.() || `timeline-${Date.now()}`,
    time: payload.time || payload.timestamp || new Date().toISOString(),
    type: payload.type || "evidence",
    title: payload.title || "Untitled timeline event",
    summary: payload.summary || payload.description || "",
    source: payload.source || payload.sourceTool || "BeyondArch",
    severity: payload.severity || "info",
    tags: Array.isArray(payload.tags) ? payload.tags : [],
    linkedArtifacts: Array.isArray(payload.linkedArtifacts) ? payload.linkedArtifacts : [],
    includeInReport: payload.includeInReport !== false,
    raw: payload.raw || payload.value || payload.content || "",
    createdAt: new Date().toISOString(),
  }
  mutate((state) => {
    state.timeline.unshift(event)
    state.timeline = state.timeline.slice(0, 300)
    return state
  }, `added timeline event: ${event.title}`)
  return event
}

export function addAnalystNote(payload = {}) {
  const note = {
    id: payload.id || globalThis.crypto?.randomUUID?.() || `note-${Date.now()}`,
    title: payload.title || "Analyst note",
    note: payload.note || payload.summary || payload.value || "",
    source: payload.source || payload.sourceTool || "BeyondArch",
    tags: Array.isArray(payload.tags) ? payload.tags : [],
    pinned: Boolean(payload.pinned),
    includeInReport: payload.includeInReport !== false,
    createdAt: new Date().toISOString(),
  }
  mutate((state) => {
    state.notes.unshift(note)
    return state
  }, `added note: ${note.title}`)
  return note
}

export function addHypothesis(payload = {}) {
  const hypothesis = {
    id: payload.id || globalThis.crypto?.randomUUID?.() || `hypothesis-${Date.now()}`,
    title: payload.title || payload.hypothesis || "Investigation hypothesis",
    status: payload.status || "open",
    confidence: payload.confidence || "unknown",
    supporting: Array.isArray(payload.supporting) ? payload.supporting : payload.supporting ? [payload.supporting] : [],
    contradicting: Array.isArray(payload.contradicting) ? payload.contradicting : [],
    source: payload.source || "BeyondArch",
    includeInReport: payload.includeInReport !== false,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  }
  mutate((state) => {
    state.hypotheses.unshift(hypothesis)
    return state
  }, `added hypothesis: ${hypothesis.title}`)
  return hypothesis
}

export function addFinding(payload = {}) {
  const finding = {
    id: payload.id || globalThis.crypto?.randomUUID?.() || `finding-${Date.now()}`,
    title: payload.title || "Investigation finding",
    summary: payload.summary || payload.description || payload.value || "",
    severity: payload.severity || payload.risk || "medium",
    confidence: payload.confidence || "unknown",
    source: payload.source || payload.sourceTool || "BeyondArch",
    tags: Array.isArray(payload.tags) ? payload.tags : [],
    includeInReport: payload.includeInReport !== false,
    raw: payload.raw || payload.content || payload.value || "",
    createdAt: new Date().toISOString(),
  }
  mutate((state) => {
    state.findings.unshift(finding)
    return state
  }, `added finding: ${finding.title}`)
  return finding
}

export function storePendingArtifact(payload = {}, target = payload.target || payload.page || "smart-parser") {
  const pending = {
    ...payload,
    target,
    page: target,
    value: payload.value || payload.content || payload.text || payload.raw || "",
    content: payload.content || payload.value || payload.text || payload.raw || "",
    createdAt: new Date().toISOString(),
  }
  memoryPendingArtifact = pending
  if (typeof window === "undefined") return pending

  const mode = getStorageMode()
  try {
    window.sessionStorage.removeItem(PENDING_ARTIFACT_KEY)
    window.localStorage.removeItem(PENDING_ARTIFACT_KEY)
    if (mode === "session") window.sessionStorage.setItem(PENDING_ARTIFACT_KEY, JSON.stringify(pending))
    if (mode === "local") window.localStorage.setItem(PENDING_ARTIFACT_KEY, JSON.stringify(pending))
  } catch {
    // Storage may be disabled; in-memory routing still works inside the active app session.
  }
  return pending
}

export function consumePendingArtifact(targets = []) {
  const allowed = Array.isArray(targets) ? targets : [targets]
  const mode = getStorageMode()
  const readPending = () => {
    if (mode === "none") return memoryPendingArtifact
    if (typeof window === "undefined") return memoryPendingArtifact
    const store = mode === "local" ? window.localStorage : window.sessionStorage
    return safeParse(store.getItem(PENDING_ARTIFACT_KEY), null) || memoryPendingArtifact
  }
  const pending = readPending()
  if (!pending) return null
  if (allowed.length && pending.target && !allowed.includes(pending.target) && !allowed.includes(pending.page)) return null
  memoryPendingArtifact = null
  if (typeof window !== "undefined") {
    window.sessionStorage.removeItem(PENDING_ARTIFACT_KEY)
    window.localStorage.removeItem(PENDING_ARTIFACT_KEY)
  }
  return pending
}

export function routeArtifactToPage(payload = {}, target = "smart-parser") {
  const value = payload.value || payload.content || payload.text || payload.raw || ""
  const artifact = addArtifact({ value, type: payload.type || "text", source: payload.source || "BeyondArch", title: payload.title || "Routed artifact" })
  storePendingArtifact({ ...payload, ...artifact, value, target }, target)
  return artifact
}

export function clearInvestigationData() {
  memoryState = { ...DEFAULT_STATE }
  if (typeof window !== "undefined") {
    window.sessionStorage.removeItem(INVESTIGATION_SESSION_KEY)
    window.localStorage.removeItem(INVESTIGATION_STORE_KEY)
    window.sessionStorage.removeItem(PENDING_ARTIFACT_KEY)
    window.localStorage.removeItem(PENDING_ARTIFACT_KEY)
  }
  dispatch(DEFAULT_STATE)
}

export function storageCounts() {
  const state = loadInvestigationState()
  return {
    artifacts: state.artifacts.length,
    timeline: state.timeline.length,
    notes: state.notes.length,
    hypotheses: state.hypotheses.length,
    findings: state.findings.length,
    reportSections: state.reportSections.length,
  }
}

export function exportInvestigationJson() {
  return {
    type: "beyondarch_investigation_export",
    version: 1,
    storageMode: getStorageMode(),
    exportedAt: new Date().toISOString(),
    warning: "May contain analyst artifacts, IOCs, notes, hypotheses, and findings. Review before sharing.",
    data: loadInvestigationState(),
  }
}

export function importInvestigationJson(payload) {
  if (!payload || typeof payload !== "object") throw new Error("Import must be a JSON object.")
  const data = payload.type === "beyondarch_investigation_export" ? payload.data : payload
  const next = saveInvestigationState(normalizeState(data || {}))
  return next
}

export function investigationMarkdown(state = loadInvestigationState()) {
  const safe = normalizeState(state)
  const lines = [
    "# BeyondArch Case Report",
    "",
    `Generated: ${new Date().toISOString()}`,
    "",
    "## Summary",
    `This local case contains ${safe.artifacts.length} artifact(s), ${safe.timeline.length} timeline event(s), ${safe.findings.length} finding(s), ${safe.notes.length} note(s), and ${safe.hypotheses.length} hypothesis item(s).`,
    "",
    "## Artifacts",
  ]

  if (!safe.artifacts.length) lines.push("No artifacts saved.")
  safe.artifacts.forEach((item, index) => {
    lines.push(`### ${index + 1}. ${item.title || item.type || "Artifact"}`)
    lines.push(`- Type: ${item.type || "unknown"}`)
    lines.push(`- Source: ${item.source || "BeyondArch"}`)
    lines.push(`- Confidence: ${item.confidence || "unknown"}`)
    lines.push("")
    if (item.value) lines.push("```text", String(item.value).slice(0, 3000), "```", "")
  })

  lines.push("## Timeline")
  if (!safe.timeline.length) lines.push("No timeline events saved.")
  safe.timeline.filter((item) => item.includeInReport !== false).forEach((item, index) => {
    lines.push(`### ${index + 1}. ${item.title}`)
    lines.push(`- Time: ${item.time || "N/A"}`)
    lines.push(`- Type: ${item.type || "evidence"}`)
    lines.push(`- Source: ${item.source || "BeyondArch"}`)
    lines.push(`- Severity: ${item.severity || "info"}`)
    if (item.tags?.length) lines.push(`- Tags: ${item.tags.join(", ")}`)
    if (item.summary) lines.push("", item.summary)
    if (item.raw) lines.push("", "```text", String(item.raw).slice(0, 3000), "```")
    lines.push("")
  })

  lines.push("## Findings")
  if (!safe.findings.length) lines.push("No findings saved.")
  safe.findings.filter((item) => item.includeInReport !== false).forEach((item, index) => {
    lines.push(`### ${index + 1}. ${item.title}`)
    lines.push(`- Severity: ${item.severity || "medium"}`)
    lines.push(`- Confidence: ${item.confidence || "unknown"}`)
    lines.push(`- Source: ${item.source || "BeyondArch"}`)
    if (item.summary) lines.push("", item.summary)
    lines.push("")
  })

  lines.push("## Hypotheses")
  if (!safe.hypotheses.length) lines.push("No hypotheses saved.")
  safe.hypotheses.filter((item) => item.includeInReport !== false).forEach((item, index) => {
    lines.push(`### ${index + 1}. ${item.title}`)
    lines.push(`- Status: ${item.status}`)
    lines.push(`- Confidence: ${item.confidence}`)
    if (item.supporting?.length) lines.push("- Supporting evidence:", ...item.supporting.map((entry) => `  - ${entry}`))
    if (item.contradicting?.length) lines.push("- Contradicting evidence:", ...item.contradicting.map((entry) => `  - ${entry}`))
    lines.push("")
  })

  lines.push("## Analyst Notes")
  if (!safe.notes.length) lines.push("No analyst notes saved.")
  safe.notes.filter((item) => item.includeInReport !== false).forEach((item, index) => {
    lines.push(`### ${index + 1}. ${item.title}`)
    lines.push(`- Source: ${item.source}`)
    if (item.tags?.length) lines.push(`- Tags: ${item.tags.join(", ")}`)
    lines.push("", item.note || "", "")
  })

  lines.push("## Recommendations", "- Validate all local heuristic findings before escalation.", "- Preserve original artifacts and timestamps outside the browser if the case is operationally important.", "- Use external reputation sources only when allowed by scope and privacy requirements.", "")
  return lines.join("\n")
}

export function detectAndStore(value = "", source = "Universal Intake") {
  const findings = detectArtifacts(value)
  const artifact = addArtifact({ value, source, findings })
  return { artifact, findings }
}
