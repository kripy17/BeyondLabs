import { postJson } from "../lib/apiClient"

export function extractIocs(text: string, refangFirst = true) {
  return postJson("/api/soc/extract-iocs", { text, refang_first: refangFirst })
}

export function identifyHash(hashValue: string) {
  return postJson("/api/soc/hash/identify", { hash_value: hashValue })
}

export function generateHashes(text: string) {
  return postJson("/api/soc/hash/generate", { text })
}

export function parseLogs(text: string) {
  return postJson("/api/soc/logs/parse", { text })
}

export function parseUserAgent(userAgent: string) {
  return postJson("/api/soc/user-agent/parse", { user_agent: userAgent })
}

export function triageAlert(title: string, description: string, rawLog: string) {
  return postJson("/api/soc/alert/triage", { title, description, raw_log: rawLog })
}
