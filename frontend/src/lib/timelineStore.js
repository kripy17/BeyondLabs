import { addTimelineEvent, getStorageMode } from "./investigationStore"
export const CASE_TIMELINE_KEY = "beyondarch.caseTimeline.v1"

function safeParse(value, fallback) {
  try { return value ? JSON.parse(value) : fallback } catch { return fallback }
}

function getStore() {
  if (typeof window === "undefined") return null
  const mode = getStorageMode()
  if (mode === "local") return window.localStorage
  if (mode === "session") return window.sessionStorage
  return null
}

let memoryCache = null

function getStoreOrMemory() {
  const store = getStore()
  if (store) return store
  return {
    getItem() { return memoryCache },
    setItem(_, val) { memoryCache = val },
    removeItem() { memoryCache = null },
  }
}

export function loadTimeline() {
  if (typeof window === "undefined") return []
  const store = getStore()
  if (!store) return memoryCache ? JSON.parse(memoryCache) : []
  const entries = safeParse(store.getItem(CASE_TIMELINE_KEY), [])
  return Array.isArray(entries) ? entries : []
}

export function saveTimeline(entries) {
  const clean = Array.isArray(entries) ? entries : []
  const store = getStoreOrMemory()
  store.setItem(CASE_TIMELINE_KEY, JSON.stringify(clean))
  return clean
}

export function addTimelineEntry(entry = {}) {
  const entries = loadTimeline()
  const next = {
    id: entry.id || (globalThis.crypto?.randomUUID?.() || `entry-${Date.now()}`),
    time: entry.time || new Date().toISOString(),
    type: entry.type || "evidence",
    title: entry.title || "Untitled evidence",
    summary: entry.summary || "",
    source: entry.source || "BeyondArch",
    tags: Array.isArray(entry.tags) ? entry.tags : [],
    raw: entry.raw || entry.value || "",
    created_at: new Date().toISOString(),
  }
  saveTimeline([next, ...entries].slice(0, 250))
  try {
    addTimelineEvent({
      id: next.id,
      time: next.time,
      type: next.type,
      title: next.title,
      summary: next.summary,
      source: next.source,
      tags: next.tags,
      raw: next.raw,
    })
  } catch {
    // Legacy timeline should continue even if the shared investigation store is unavailable.
  }
  return next
}

export function timelineMarkdown(entries = loadTimeline()) {
  return [
    "# BeyondArch Investigation Timeline",
    "",
    ...entries.map((entry, index) => [
      `## ${index + 1}. ${entry.title}`,
      `- Time: ${entry.time || "N/A"}`,
      `- Type: ${entry.type || "evidence"}`,
      `- Source: ${entry.source || "BeyondArch"}`,
      entry.tags?.length ? `- Tags: ${entry.tags.join(", ")}` : "- Tags: none",
      "",
      entry.summary || "No summary recorded.",
      entry.raw ? `\n\`\`\`text\n${String(entry.raw).slice(0, 4000)}\n\`\`\`` : "",
    ].join("\n")),
  ].join("\n")
}

export function addTimelineArtifact({ title, summary, source, raw, type = "evidence", tags = [] } = {}) {
  return addTimelineEntry({
    title: title || `${source || "BeyondArch"} finding`,
    summary: summary || "Analyst-marked evidence from a BeyondArch workspace.",
    source: source || "BeyondArch",
    raw: raw || "",
    type,
    tags,
  })
}
