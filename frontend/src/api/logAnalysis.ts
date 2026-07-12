import { postJson } from "../lib/apiClient"

export function analyzeLinuxAuthLogs(text: string) {
  return postJson("/api/log-analysis/linux-auth", { text })
}

export function analyzeWebAccessLogs(text: string) {
  return postJson("/api/log-analysis/web-access", { text })
}
