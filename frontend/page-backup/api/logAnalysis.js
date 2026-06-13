import { postJson } from "../lib/apiClient"

export function analyzeLinuxAuthLogs(text) {
  return postJson("/api/log-analysis/linux-auth", { text })
}

export function analyzeWebAccessLogs(text) {
  return postJson("/api/log-analysis/web-access", { text })
}
