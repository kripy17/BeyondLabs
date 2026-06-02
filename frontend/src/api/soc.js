import { postJson } from "../lib/apiClient"

export function extractIocs(text, refangFirst = true) {
  return postJson("/api/soc/extract-iocs", { text, refang_first: refangFirst })
}

export function identifyHash(hashValue) {
  return postJson("/api/soc/hash/identify", { hash_value: hashValue })
}

export function generateHashes(text) {
  return postJson("/api/soc/hash/generate", { text })
}

export function parseLogs(text) {
  return postJson("/api/soc/logs/parse", { text })
}

export function parseUserAgent(userAgent) {
  return postJson("/api/soc/user-agent/parse", { user_agent: userAgent })
}

export function triageAlert(title, description, rawLog) {
  return postJson("/api/soc/alert/triage", { title, description, raw_log: rawLog })
}
