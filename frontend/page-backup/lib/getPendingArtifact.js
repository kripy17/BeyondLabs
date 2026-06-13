export function getPendingArtifactInfo() {
  try {
    const raw = localStorage.getItem("beyondarch.pendingArtifact")
    if (!raw) return null
    const artifact = JSON.parse(raw)
    const value = artifact?.value || artifact?.host || artifact?.domain || artifact?.ip || artifact?.url || artifact?.content || artifact?.text || artifact?.raw_input || ""
    if (!value) return null
    return {
      value: String(value).slice(0, 120),
      source: artifact?.source || artifact?.page || "unknown",
      target: artifact?.target || artifact?.page,
    }
  } catch {
    return null
  }
}
