const URL_PATTERN = /\b(?:https?:\/\/|hxxps?:\/\/|www\.)[^\s<>'"`]+/gi
const IPV4_PATTERN = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g
const HASH_PATTERN = /\b(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b/g
const JWT_PATTERN = /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g
const EMAIL_HEADER_PATTERN = /^\s*(?:From|To|Subject|Reply-To|Return-Path|Received|Authentication-Results|Received-SPF|DKIM-Signature|Message-ID):\s*.+$/gim
const EMAIL_ADDRESS_PATTERN = /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi
const DOMAIN_PATTERN = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|co|in|edu|gov|mil|biz|info|dev|app|cloud|site|online|xyz|top|shop|me|ai|uk|us|ru|cn|de|jp|fr|au|ca|ir|br|nl|tech|security|login|support)\b/gi
const BASE64_PATTERN = /\b(?:[A-Za-z0-9+/]{32,}={0,2}|[A-Za-z0-9_-]{32,})\b/g
const LOG_PATTERN = /(?:failed password|accepted password|authentication failure|event[_ ]?id|src_ip|dst_ip|source_ip|destination_ip|status=|\bGET\s+\/|\bPOST\s+\/|sshd\[|suricata|zeek|firewall|blocked|denied|allowed)/i
const JSON_HINT_PATTERN = /^\s*(?:\{[\s\S]*\}|\[[\s\S]*\])\s*$/
const FILE_PATTERN = /\b[\w .-]+\.(?:exe|dll|ps1|vbs|js|jar|docm|xlsm|pdf|zip|rar|7z|eml|msg|pcap|log|json|csv|txt)\b/gi

const ROUTE_BY_TYPE = {
  url: "safe-url-analyzer",
  domain: "recon-exposure",
  ip: "recon-exposure",
  hash: "attachment-triage",
  jwt: "cyber-utilities",
  base64: "cyberchef",
  email: "phishing-triage",
  email_address: "phishing-triage",
  log: "logs-alerts",
  json: "logs-alerts",
  file: "attachment-triage",
  text: "smart-parser",
}

const LABEL_BY_TYPE = {
  url: "URL",
  domain: "Domain",
  ip: "IP address",
  hash: "Hash",
  jwt: "JWT",
  base64: "Base64-like blob",
  email: "Email/header text",
  email_address: "Email address",
  log: "Log event",
  json: "JSON event",
  file: "File name",
  text: "Raw artifact",
}

function unique(values = []) {
  const seen = new Set()
  return values
    .map((value) => String(value || "").trim().replace(/[),.;]+$/g, ""))
    .filter(Boolean)
    .filter((value) => {
      const key = value.toLowerCase()
      if (seen.has(key)) return false
      seen.add(key)
      return true
    })
}

export function refangArtifact(value = "") {
  return String(value || "")
    .replace(/\bhxxps\b/gi, "https")
    .replace(/\bhxxp\b/gi, "http")
    .replace(/\[\s*:\s*\]|\(\s*:\s*\)/g, ":")
    .replace(/\[\s*\.\s*\]|\(\s*\.\s*\)/g, ".")
    .replace(/\s+dot\s+/gi, ".")
    .replace(/\[\s*@\s*\]|\(\s*@\s*\)/g, "@")
    .replace(/\s+at\s+/gi, "@")
}

export function defangArtifact(value = "") {
  return String(value || "")
    .replace(/https?:\/\//gi, (match) => match.toLowerCase().replace("http", "hxxp"))
    .replace(/\./g, "[.]")
}

function safeJson(text) {
  try {
    const parsed = JSON.parse(text)
    if (parsed && typeof parsed === "object") return parsed
  } catch {
    return null
  }
  return null
}

function pushFinding(findings, type, values, extra = {}) {
  const cleanValues = unique(values)
  if (!cleanValues.length) return
  findings.push({
    id: `${type}-${findings.length + 1}`,
    type,
    label: LABEL_BY_TYPE[type] || type,
    count: cleanValues.length,
    values: cleanValues.slice(0, 12),
    primaryValue: cleanValues[0],
    action: ROUTE_BY_TYPE[type] || "smart-parser",
    confidence: extra.confidence || "high",
    reason: extra.reason || `${LABEL_BY_TYPE[type] || type} pattern detected`,
    ...extra,
  })
}

export function detectArtifacts(input = "") {
  const original = String(input || "")
  const text = original.trim()
  if (!text) return []

  const refanged = refangArtifact(text)
  const findings = []

  pushFinding(findings, "url", refanged.match(URL_PATTERN) || [], { reason: "URL or defanged URL detected" })
  pushFinding(findings, "ip", refanged.match(IPV4_PATTERN) || [], { reason: "IPv4 address detected" })
  pushFinding(findings, "hash", text.match(HASH_PATTERN) || [], { reason: "MD5/SHA1/SHA256-length hash detected" })
  pushFinding(findings, "jwt", text.match(JWT_PATTERN) || [], { reason: "JWT-like token detected" })
  pushFinding(findings, "email", text.match(EMAIL_HEADER_PATTERN) || [], { reason: "Email header fields detected" })
  pushFinding(findings, "email_address", text.match(EMAIL_ADDRESS_PATTERN) || [], { reason: "Email address detected" })
  pushFinding(findings, "file", text.match(FILE_PATTERN) || [], { reason: "File name or extension detected" })

  const domains = unique(refanged.match(DOMAIN_PATTERN) || [])
    .filter((domain) => !/^www\.$/i.test(domain))
    .filter((domain) => !findings.some((finding) => finding.type === "url" && finding.values.some((url) => url.toLowerCase().includes(domain.toLowerCase()))))
  pushFinding(findings, "domain", domains, { reason: "Standalone domain detected" })

  const json = JSON_HINT_PATTERN.test(text) ? safeJson(text) : null
  if (json) pushFinding(findings, "json", [text.slice(0, 500)], { confidence: "medium", reason: "Valid JSON object/array detected", parsed: json })

  if (LOG_PATTERN.test(text)) {
    const firstLine = text.split(/\r?\n/).find((line) => LOG_PATTERN.test(line)) || text.slice(0, 500)
    pushFinding(findings, "log", [firstLine], { confidence: "medium", reason: "Log/event keywords detected" })
  }

  const base64Matches = unique(text.match(BASE64_PATTERN) || [])
    .filter((value) => !findings.some((finding) => finding.values.includes(value)))
    .filter((value) => /[A-Za-z]/.test(value) && /\d/.test(value))
    .filter((value) => value.length >= 32 && value.length <= 4096)
  if (base64Matches.length) pushFinding(findings, "base64", base64Matches.slice(0, 6), { confidence: "medium", reason: "Long encoded-looking blob detected" })

  if (!findings.length && text.length > 12) {
    pushFinding(findings, "text", [text.slice(0, 240)], { confidence: "low", reason: "No strong artifact pattern matched; route to parser" })
  }

  return findings
}

export function summarizeArtifacts(findings = []) {
  if (!findings.length) return "No artifacts detected yet."
  return findings.map((finding) => `${finding.count} ${finding.label}${finding.count === 1 ? "" : "s"}`).join(" · ")
}

export function firstArtifactRoute(findings = []) {
  return findings.find((finding) => finding.action)?.action || "smart-parser"
}

export function normalizeArtifactPayload({ value = "", type = "text", source = "BeyondArch", title = "", findings = [] } = {}) {
  const clean = String(value || "").trim()
  const detected = findings.length ? findings : detectArtifacts(clean)
  const primary = detected.find((finding) => finding.type !== "text") || detected[0]
  return {
    id: globalThis.crypto?.randomUUID?.() || `artifact-${Date.now()}`,
    type: primary?.type || type,
    title: title || primary?.label || LABEL_BY_TYPE[type] || "Artifact",
    value: clean,
    content: clean,
    source,
    confidence: primary?.confidence || "unknown",
    detected,
    tags: detected.map((finding) => finding.type).filter(Boolean),
    createdAt: new Date().toISOString(),
  }
}
