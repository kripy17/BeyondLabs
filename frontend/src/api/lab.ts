import { getJson, postJson } from "../lib/apiClient"

export function analyzePowerShell(command: string) {
  return postJson("/api/lab/powershell/analyze", { command })
}

export function lookupWindowsEvent(eventId: string) {
  return postJson("/api/lab/windows-events/lookup", { event_id: eventId })
}

export function analyzeWindowsEventText(text: string) {
  return postJson("/api/lab/windows-events/analyze-text", { text })
}

export function listWindowsEvents() {
  return getJson("/api/lab/windows-events")
}
