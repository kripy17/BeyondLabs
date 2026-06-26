import { useMemo, useRef, useState } from "react"
import {
  AlertTriangle,
  ArrowUpRight,
  CheckCircle2,
  ChevronRight,
  Clipboard,
  Copy,
  Database,
  Download,
  Edit,
  Eraser,
  FileSearch,
  Fingerprint,
  Flag,
  Globe,
  Info,
  RefreshCcw,
  Scan,
  Server,
  Shield,
  Upload,
  Zap,
} from "lucide-react"
import { WorkbenchPage } from "../../components/layout/WorkbenchShell"
import { scanSecrets } from "../../lib/securityTextAnalysis"
import { copyText, downloadText } from "../../lib/domUtils.js"

const MAX_INPUT_CHARS = 260000

const TYPE_META = {
  "Sigma-like Detection Rule": { family: "Detection Rule", priority: 1 },
  "YARA-like Detection Rule": { family: "Detection Rule", priority: 1 },
  "Snort/Suricata Detection Rule": { family: "Detection Rule", priority: 1 },
  "ATT&CK Mapping": { family: "Detection Rule", priority: 1 },
  "Email / Phishing": { family: "Email / Phishing", priority: 2 },
  "Email Headers": { family: "Email / Phishing", priority: 2 },
  "Suspicious Email Body": { family: "Email / Phishing", priority: 2 },
  "URL-heavy Email Content": { family: "Email / Phishing", priority: 2 },
  "Linux Auth Log": { family: "Log / Alert", priority: 3 },
  "Windows Event Log": { family: "Log / Alert", priority: 3 },
  "Suricata EVE Network Alert": { family: "Network / Firewall / Proxy", priority: 3 },
  "Web Access Log": { family: "Network / Firewall / Proxy", priority: 3 },
  "Zeek-like Network Log": { family: "Network / Firewall / Proxy", priority: 3 },
  "Firewall/Proxy Log": { family: "Network / Firewall / Proxy", priority: 3 },
  "EDR/SIEM Alert Text": { family: "Log / Alert", priority: 3 },
  "User-Agent Strings": { family: "Network / Firewall / Proxy", priority: 3 },
  "Endpoint Command Line": { family: "Endpoint / Command Line", priority: 4 },
  "PowerShell EncodedCommand": { family: "Endpoint / Command Line", priority: 4 },
  "Suspicious Script/LOLBin Command": { family: "Endpoint / Command Line", priority: 4 },
  "Windows File Path": { family: "Endpoint / Command Line", priority: 4 },
  "Registry Path Artifact": { family: "Endpoint / Command Line", priority: 4 },
  "Base64-looking Payload": { family: "Endpoint / Command Line", priority: 4 },
  "JWT / Token Artifact": { family: "Endpoint / Command Line", priority: 4 },
  "Pasted Code / Secret Findings": { family: "Unknown / Mixed Artifact", priority: 4 },
  "URL": { family: "URL / Domain / IP / Recon Target", priority: 5 },
  "Domain": { family: "URL / Domain / IP / Recon Target", priority: 5 },
  "IPv4": { family: "URL / Domain / IP / Recon Target", priority: 5 },
  "IPv6": { family: "URL / Domain / IP / Recon Target", priority: 5 },
  "CIDR": { family: "URL / Domain / IP / Recon Target", priority: 5 },
  "HTTP Headers": { family: "URL / Domain / IP / Recon Target", priority: 5 },
  "DNS Records": { family: "URL / Domain / IP / Recon Target", priority: 5 },
  "WHOIS/RDAP Text": { family: "URL / Domain / IP / Recon Target", priority: 5 },
  "TLS/Certificate Text": { family: "URL / Domain / IP / Recon Target", priority: 5 },
  "IOC List": { family: "IOC / Indicator List", priority: 6 },
  "Mixed Indicator List": { family: "IOC / Indicator List", priority: 6 },
  "File Hash Indicators": { family: "IOC / Indicator List", priority: 6 },
  "Defanged Indicators": { family: "IOC / Indicator List", priority: 6 },
  "Analyst Notes / Timeline": { family: "Analyst Notes / Report Draft", priority: 7 },
  "Analyst Notes / Unknown Text": { family: "Unknown / Mixed Artifact", priority: 8 },
}

const TYPE_MITRE_MAP = {
  "Sigma-like Detection Rule": "T1059",
  "YARA-like Detection Rule": "T1204",
  "Snort/Suricata Detection Rule": "T1204",
  "ATT&CK Mapping": "T1592",
  "Email / Phishing": "T1566",
  "Linux Auth Log": "T1110",
  "Windows Event Log": "T1078",
  "Web Access Log": "T1071",
  "Firewall/Proxy Log": "T1046",
  "DNS Records": "T1071.004",
  "IOC List": "T1595",
  "Endpoint Command Line": "T1059",
  "PowerShell EncodedCommand": "T1059.001",
  "Base64-looking Payload": "T1059.001",
  "Analyst Notes / Unknown Text": "T1592",
  "Analyst Notes / Timeline": "T1592",
}

const TYPE_CONFIDENCE_WEIGHTS = {
  "Sigma-like Detection Rule": { weight: 0.95, base: "High confidence — structured rule format" },
  "YARA-like Detection Rule": { weight: 0.95, base: "High confidence — structured rule format" },
  "Snort/Suricata Detection Rule": { weight: 0.95, base: "High confidence — structured rule format" },
  "ATT&CK Mapping": { weight: 0.85, base: "Good confidence — MITRE format detected" },
  "Email / Phishing": { weight: 0.85, base: "Good confidence — email structure detected" },
  "Email Headers": { weight: 0.9, base: "High confidence — RFC 5322 header format" },
  "Linux Auth Log": { weight: 0.85, base: "Good confidence — syslog auth pattern" },
  "Windows Event Log": { weight: 0.85, base: "Good confidence — Windows event structure" },
  "Web / Proxy Log": { weight: 0.8, base: "Moderate confidence — web log pattern" },
  "DNS Log": { weight: 0.8, base: "Moderate confidence — DNS query pattern" },
  "Firewall / Netflow": { weight: 0.75, base: "Moderate confidence — netflow format" },
  "IOC List": { weight: 0.7, base: "Moderate confidence — indicator pattern match" },
  "Malware": { weight: 0.65, base: "Low-Moderate confidence — heuristic match" },
  "Threat Intel": { weight: 0.7, base: "Moderate confidence — intel format match" },
  "Base64 / Encoded": { weight: 0.75, base: "Moderate confidence — encoding detection" },
}

function generateParseSummary(result) {
  if (!result) return "No types detected."
  const primary = result.primaryType
  const secondaryTypes = (result.secondaryTypes || []).map(t => t.type)
  const output = JSON.stringify(result, null, 2)
  const confidence = TYPE_CONFIDENCE_WEIGHTS[primary] || { weight: 0.5, base: "Low confidence — generic pattern match" }
  const lines = [
    `## Parse Results Summary`,
    ``,
    `**Detected Type:** ${primary}`,
    `**Confidence:** ${Math.round(confidence.weight * 100)}% — ${confidence.base}`,
    `**Additional Matches:** ${secondaryTypes.join(", ") || "None"}`,
    `**Output Size:** ${output.length} character(s)`,
    ``,
    `**Analyst Note:** This content was parsed by local pattern detection only. No execution, sandbox analysis, or threat intelligence enrichment was performed. Validate parsed fields against source context.`,
  ]
  return lines.join("\n")
}

const SAMPLE_INPUTS = {
  phishing: {
    label: "Raw phishing email",
    text: [
      "From: Security Team <security-alert@example-login.com>",
      "To: user@example.org",
      "Subject: Password reset required",
      "Authentication-Results: mx.example.org; spf=fail smtp.mailfrom=example-login.com; dkim=fail; dmarc=fail",
      "Received: from mail.example-login.com (203.0.113.44) by mx.example.org",
      "",
      "Please verify your account at hxxps[:]//login.example-login[.]com/reset?id=1234",
    ].join("\n"),
  },
  headers: {
    label: "Email headers only",
    text: [
      "From: security@example.com",
      "To: user@example.org",
      "Subject: Urgent password reset",
      "Return-Path: bounce@example-login.com",
      "Reply-To: support@example-login.com",
      "Received-SPF: fail",
      "Authentication-Results: spf=fail dkim=none dmarc=fail",
    ].join("\n"),
  },
  iocs: {
    label: "Mixed IOC list",
    text: [
      "hxxps[:]//phish.example[.]com/login",
      "example[.]net",
      "198[.]51[.]100[.]23",
      "44d88612fea8a8f36de82e1278abb02f",
      "3395856ce81f2b7382dee72602f798b642f14140",
      "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
      "CVE-2024-12345",
      "T1566.002",
    ].join("\n"),
  },
  linux: {
    label: "Linux SSH auth log",
    text: [
      "Apr 25 10:10:10 arch sshd[123]: Failed password for invalid user admin from 8.8.8.8 port 4444 ssh2",
      "Apr 25 10:11:44 arch sshd[124]: Accepted password for root from 1.1.1.1 port 55910 ssh2",
    ].join("\n"),
  },
  windows: {
    label: "Windows Event 4688",
    text: [
      "Event ID: 4688",
      "Provider: Microsoft-Windows-Security-Auditing",
      "New Process Name: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
      "Command Line: powershell.exe -NoP -EncodedCommand SQBFAFgA",
      "Account Name: krish",
    ].join("\n"),
  },
  suricata: {
    label: "Suricata EVE JSON",
    text: JSON.stringify({
      timestamp: "2026-04-25T10:12:00.123456Z",
      event_type: "alert",
      src_ip: "198.51.100.23",
      dest_ip: "10.0.0.5",
      alert: {
        signature: "ET WEB_SERVER Possible SQL Injection Attempt",
        category: "Web Application Attack",
        severity: 2,
      },
    }, null, 2),
  },
  access: {
    label: "Web access log with SQLi",
    text: '198.51.100.23 - - [25/Apr/2026:10:12:00 +0530] "GET /../../etc/passwd HTTP/1.1" 404 123 "-" "sqlmap/1.7"',
  },
  powershell: {
    label: "PowerShell EncodedCommand",
    text: "powershell.exe -NoP -W Hidden -EncodedCommand SQBFAFgA",
  },
  secrets: {
    label: "Code with possible secrets",
    text: [
      "const apiKey = \"AIzaSyD-exampleexampleexampleexample123456\"",
      "GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz1234567890",
      "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
    ].join("\n"),
  },
  sigma: {
    label: "Sigma-like rule",
    text: [
      "title: Suspicious PowerShell Encoded Command",
      "id: 6f1f0c20-1111-4444-8888-123456789abc",
      "logsource:",
      "  product: windows",
      "  category: process_creation",
      "detection:",
      "  selection:",
      "    CommandLine|contains: '-EncodedCommand'",
      "  condition: selection",
      "tags:",
      "  - attack.t1059.001",
    ].join("\n"),
  },
  notes: {
    label: "Analyst notes / timeline",
    text: [
      "10:04 - User reported suspicious password reset email.",
      "10:08 - Extracted URL hxxps[:]//login.example[.]com/reset",
      "Finding: Sender domain does not match expected organization.",
      "Next step: collect headers and draft user-facing summary.",
    ].join("\n"),
  },
}

const ROUTES = {
  phishing: { label: "Phishing Triage", page: "phishing-triage" },
  safeUrl: { label: "Safe URL Analyzer", page: "safe-url-analyzer" },
  recon: { label: "Recon & Exposure", page: "recon-exposure" },
  logs: { label: "Logs & Alerts", page: "logs-alerts" },
  attachment: { label: "Attachment Triage", page: "attachment-triage" },
  cyberchef: { label: "CyberChef", page: "cyberchef" },
  detection: { label: "Detection & MITRE", page: "detection-mitre" },
}

function uniq(items) {
  const seen = new Set()
  return items.filter((item) => {
    const key = String(item.normalized || item.value || item).toLowerCase()
    if (seen.has(key)) return false
    seen.add(key)
    return true
  })
}

function refang(value = "") {
  return value
    .replace(/\bhxxps\b/gi, "https")
    .replace(/\bhxxp\b/gi, "http")
    .replace(/\[\s*:\s*\]/g, ":")
    .replace(/\(\s*:\s*\)/g, ":")
    .replace(/\[\s*\.\s*\]/g, ".")
    .replace(/\(\s*\.\s*\)/g, ".")
    .replace(/\s+dot\s+/gi, ".")
    .replace(/\[\s*@\s*\]/g, "@")
    .replace(/\s+at\s+/gi, "@")
}

function addScore(scores, key, points, reason) {
  scores[key] = scores[key] || { score: 0, reasons: [] }
  scores[key].score += points
  if (reason) scores[key].reasons.push(reason)
}

function typeMeta(type) {
  return TYPE_META[type] || { family: "Unknown / Mixed Artifact", priority: 8 }
}

function mitreForType(type) {
  return TYPE_MITRE_MAP[type] || null
}

function parseJsonLines(text) {
  const trimmed = text.trim()
  if (!trimmed) return []

  const parsed = []
  try {
    parsed.push(JSON.parse(trimmed))
    return parsed
  } catch {
    // Continue with line-delimited JSON attempts.
  }

  for (const line of trimmed.split("\n")) {
    const clean = line.trim()
    if (!clean.startsWith("{") || !clean.endsWith("}")) continue
    try {
      parsed.push(JSON.parse(clean))
    } catch {
      // Invalid JSON lines are ignored, not fatal.
    }
  }
  return parsed
}

function extractHeaders(text) {
  const fields = {}
  for (const line of text.split(/\r?\n/)) {
    const match = line.match(/^([A-Za-z][A-Za-z0-9-]{1,60}):\s*(.+)$/)
    if (!match) continue
    const key = match[1].toLowerCase()
    const value = match[2].trim()
    if (!fields[key]) fields[key] = []
    fields[key].push(value)
  }
  return fields
}

function extractKeyValues(text) {
  const values = {}
  for (const line of text.split(/\r?\n/)) {
    const match = line.match(/^\s*([A-Za-z0-9_. -]{2,60})\s*[:=]\s*(.+?)\s*$/)
    if (!match) continue
    const key = match[1].trim().toLowerCase().replace(/\s+/g, "_")
    const value = match[2].trim()
    if (!values[key]) values[key] = []
    values[key].push(value)
  }
  return values
}

function extractUserAgents(text) {
  const matches = text.match(/(?:Mozilla\/5\.0[^\n"]*|curl\/[^\s"]+|python-requests\/[^\s"]+|sqlmap\/[^\s"]+|Go-http-client\/[^\s"]+|PowerShell\/[^\s"]+)/gi) || []
  return uniq(matches.map((value) => ({ value, normalized: value })))
}

function extractCommandFields(text) {
  const commandPattern = /\b(?:powershell(?:\.exe)?|pwsh(?:\.exe)?|cmd(?:\.exe)?|rundll32(?:\.exe)?|regsvr32(?:\.exe)?|mshta(?:\.exe)?|wscript(?:\.exe)?|cscript(?:\.exe)?|certutil(?:\.exe)?|bitsadmin(?:\.exe)?|bash|sh|msbuild|installutil|csc\.exe|regini|pcalua|cmstp|msiexec|hh\.exe|forfiles)\b[^\n\r]*/gi
  const commands = uniq((text.match(commandPattern) || []).map((value) => ({ value: value.trim(), normalized: value.trim() })))
  const primaryCommand = commands[0]?.normalized || ""
  return {
    commands,
    interpreter: primaryCommand.match(/^\S+/)?.[0] || "",
    hasEncodedCommand: /-enc(?:odedcommand)?\b/i.test(text),
    hasHiddenWindow: /(?:-w(?:indowstyle)?\s+hidden|\/b\b)/i.test(text),
    hasNoProfile: /-nop(?:rofile)?\b/i.test(text),
    hasDownloadCradle: /\b(iwr|invoke-webrequest|wget|curl|downloadstring|webclient|bitsadmin|certutil\s+-urlcache)\b/i.test(text),
    hasLolbin: /\b(rundll32|regsvr32|mshta|wscript|cscript|certutil|bitsadmin|msbuild|installutil|csc\.exe|regini|pcalua|cmstp|msiexec|hh\.exe|forfiles)\b/i.test(text),
    hasAmsiBypass: /(?:amsi|bypass|disable\s*amsi|amsiutils|amsi\.scanbuffer)/i.test(text),
    hasDownloadExecute: /\b(iwr\s+.*\s*\|?\s*iex|curl\s+.*\s*\|?\s*iex|wget\s+.*\s*\|?\s*iex|(?:invoke-webrequest|wget|curl)\s+.*-outfile|start-bits transfer\s+.*-destination|certutil\s+-urlcache.*-f\s+|bitsadmin\s+\/transfer\s+).*\.(?:exe|ps1|dll|bat|vbs)/im.test(text),
    hasPipePowerShell: /(?:\||%)\s*(?:\{|\.\s*\()\s*(?:powershell|pwsh|iex|invoke|invoke-expression)/im.test(text) || /\|\s*(?:powershell|pwsh)\s+-\s*/im.test(text),
    base64Blobs: uniq((text.match(/\b[A-Za-z0-9+/]{24,}={0,2}\b/g) || []).map((value) => ({ value, normalized: value }))).slice(0, 10),
  }
}

function extractLogFields(text, jsonObjects) {
  const fields = {}
  const sshMatch = text.match(/sshd\[\d+\]:\s+(Failed|Accepted)\s+password(?:\s+for(?:\s+invalid user)?\s+(\S+))?.*?\s+from\s+(\d{1,3}(?:\.\d{1,3}){3})\s+port\s+(\d+)/i)
  if (sshMatch) {
    fields.linux_auth = {
      action: sshMatch[1],
      user: sshMatch[2] || "unknown",
      source_ip: sshMatch[3],
      source_port: sshMatch[4],
    }
  }

  const webMatch = text.match(/^(\d{1,3}(?:\.\d{1,3}){3})\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"([A-Z]+)\s+([^"]+?)\s+HTTP\/[^"]+"\s+(\d{3})\s+(\d+|-)\s+"([^"]*)"\s+"([^"]*)"/m)
  if (webMatch) {
    fields.web_access = {
      source_ip: webMatch[1],
      timestamp: webMatch[2],
      method: webMatch[3],
      path: webMatch[4],
      status: webMatch[5],
      bytes: webMatch[6],
      referer: webMatch[7],
      user_agent: webMatch[8],
    }
  }

  const alertObject = jsonObjects.find((item) => item?.event_type === "alert" || item?.alert)
  if (alertObject) {
    fields.alert = {
      event_type: alertObject.event_type,
      timestamp: alertObject.timestamp,
      src_ip: alertObject.src_ip,
      dest_ip: alertObject.dest_ip,
      signature: alertObject.alert?.signature,
      category: alertObject.alert?.category,
      severity: alertObject.alert?.severity,
    }
  }

  return fields
}

function extractRuleFields(text) {
  const fields = {}
  const title = text.match(/^title:\s*(.+)$/im)?.[1]
  const id = text.match(/^id:\s*(.+)$/im)?.[1]
  const condition = text.match(/^\s*condition:\s*(.+)$/im)?.[1]
  const product = text.match(/^\s*product:\s*(.+)$/im)?.[1]
  if (title || id || condition || product) fields.sigma = { title, id, product, condition }

  const yara = text.match(/\brule\s+([A-Za-z0-9_]+)\s*\{/)
  if (yara) fields.yara = { rule_name: yara[1] }

  const snort = text.match(/^(alert|drop|reject|pass)\s+(tcp|udp|icmp|ip)\s+(.+)$/im)
  if (snort) fields.ids_rule = { action: snort[1], protocol: snort[2], rule: snort[0] }

  return fields
}

const SUSPICIOUS_TLDS = new Set(["tk", "ml", "ga", "cf", "gq", "pw", "su", "ru", "cn", "top", "xyz", "click", "download", "review", "work", "date", "men", "loan", "win", "bid", "trade", "webcam", "rest", "science", "gdn", "accountant", "bank", "bonus", "cash", "chase", "claim", "credit", "crypto", "free", "gift", "help", "host", "info", "life", "link", "live", "love", "money", "online", "party", "pro", "racing", "renovation", "review", "sale", "sex", "site", "software", "studio", "stream", "support", "tech", "top", "trade", "vip", "wang", "webcam", "website", "win", "work", "xyz"])

const SHORTENER_DOMAINS = new Set(["bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "buff.ly", "shorturl.at", "is.gd", "cli.gs", "pic.gd", "bc.vc", "tiny.cc", "lc.chat", "tr.im", "t.co", "x.co", "budurl.com", "snipurl.com", "shorte.st", "adf.ly", "tiny.ie", "bl.ink", "youtu.be", "rb.gy", "cutt.ly", "t2m.io", "short.link", "lnkd.in"])

const SUSPICIOUS_PATH_KEYWORDS = ["login", "verify", "reset", "update", "confirm", "authenticate", "secure", "account", "signin", "sign-in", "auth", "validate", "password", "recovery", "challenge", "2fa", "mfa", "wallet", "claim", "bonus", "reward", "support", "help", "download", "free", "promo"]

function analyzeUrls(iocUrls) {
  return iocUrls.map((item) => {
    const url = item.normalized
    try {
      const parsed = new URL(url)
      const hostname = parsed.hostname
      const path = parsed.pathname
      const depth = path.split("/").filter(Boolean).length
      const tld = hostname.split(".").pop()?.toLowerCase() || ""
      const isSuspiciousTld = SUSPICIOUS_TLDS.has(tld)
      const isIpHosted = /^\d{1,3}(?:\.\d{1,3}){3}$/.test(hostname)
      const hasSuspiciousPath = SUSPICIOUS_PATH_KEYWORDS.some((kw) => path.toLowerCase().includes(kw))
      const isShortener = SHORTENER_DOMAINS.has(hostname)
      const port = parsed.port || (parsed.protocol === "https:" ? "443" : "80")
      const searchParams = parsed.search || ""
      const entropy = shannonEntropy(path)
      const hasPort = Boolean(parsed.port)
      const hasCredentials = Boolean(parsed.username)

      return {
        ...item,
        analysis: { depth, hostname, tld, isSuspiciousTld, isIpHosted, hasSuspiciousPath, isShortener, port, searchParams, entropy, hasPort, hasCredentials },
      }
    } catch {
      return { ...item, analysis: null }
    }
  })
}

function shannonEntropy(str) {
  const counts = new Map()
  for (const char of str) counts.set(char, (counts.get(char) || 0) + 1)
  let entropy = 0
  for (const count of counts.values()) {
    const p = count / str.length
    if (p > 0) entropy -= p * Math.log2(p)
  }
  return Math.round(entropy * 100) / 100
}

function extractIocs(text) {
  const normalizedText = refang(text)
  const originalAndRefanged = `${text}\n${normalizedText}`
  const urlPattern = /\bhttps?:\/\/[^\s"'<>]+/gi
  const emailPattern = /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi
  const ipv4Pattern = /\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b/g
  const ipv6Pattern = /\b(?:[a-f0-9]{1,4}:){2,7}[a-f0-9]{1,4}\b/gi
  const cidrPattern = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\/(?:[0-9]|[12][0-9]|3[0-2])\b/g
  const hashPattern = /\b[a-f0-9]{32}\b|\b[a-f0-9]{40}\b|\b[a-f0-9]{64}\b/gi
  const cvePattern = /\bCVE-\d{4}-\d{4,7}\b/gi
  const attackPattern = /\bT\d{4}(?:\.\d{3})?\b/gi
  const eventIdPattern = /\b(?:Event\s*ID|EventID|event_id|eventcode|event.code)\D{0,8}(\d{3,5})\b/gi
  const asnPattern = /\bAS\d{1,6}\b/gi
  const macPattern = /\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b/g
  const btcPattern = /\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b/g
  const ethPattern = /\b0x[a-fA-F0-9]{40}\b/g
  const phonePattern = /\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{2,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}\b/g

  const urls = uniq((originalAndRefanged.match(urlPattern) || []).map((value) => ({
    value,
    normalized: refang(value).replace(/[),.;]+$/g, ""),
  })))
  const emails = uniq((originalAndRefanged.match(emailPattern) || []).map((value) => ({ value, normalized: refang(value) })))
  const ipv4 = uniq((originalAndRefanged.match(ipv4Pattern) || []).map((value) => ({ value, normalized: refang(value) })))
  const ipv6 = uniq((normalizedText.match(ipv6Pattern) || []).map((value) => ({ value, normalized: value })))
  const cidrs = uniq((normalizedText.match(cidrPattern) || []).map((value) => ({ value, normalized: value })))
  const hashMatches = uniq((normalizedText.match(hashPattern) || []).map((value) => ({ value: value.toLowerCase(), normalized: value.toLowerCase() })))
  const md5 = hashMatches.filter((item) => item.normalized.length === 32)
  const sha1 = hashMatches.filter((item) => item.normalized.length === 40)
  const sha256 = hashMatches.filter((item) => item.normalized.length === 64)
  const cves = uniq((normalizedText.match(cvePattern) || []).map((value) => ({ value: value.toUpperCase(), normalized: value.toUpperCase() })))
  const attack = uniq((normalizedText.match(attackPattern) || []).map((value) => ({ value: value.toUpperCase(), normalized: value.toUpperCase() })))

  const domainCandidates = []
  for (const url of urls) {
    try {
      domainCandidates.push(new URL(url.normalized).hostname)
    } catch {
      // Ignore malformed URL fragments.
    }
  }
  const domainPattern = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,24})\b/gi
  domainCandidates.push(...(normalizedText.match(domainPattern) || []))
  const domains = uniq(domainCandidates
    .map((value) => value.toLowerCase().replace(/^[.@]+|[),.;:]+$/g, ""))
    .filter((value) => value && !value.includes("@") && !/^(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}$/.test(value))
    .map((value) => ({ value, normalized: value })))

  const eventIds = []
  let eventMatch = eventIdPattern.exec(normalizedText)
  while (eventMatch) {
    eventIds.push({ value: eventMatch[1], normalized: eventMatch[1] })
    eventMatch = eventIdPattern.exec(normalizedText)
  }
  eventIds.push(...(normalizedText.match(/\b(?:4624|4625|4688|4672|1102|7045|4768|4769|4104)\b/g) || []).map((value) => ({ value, normalized: value })))

  const asns = uniq((originalAndRefanged.match(asnPattern) || []).map((value) => ({
    value: value.toUpperCase(),
    normalized: value.toUpperCase(),
  })))

  const macs = uniq((originalAndRefanged.match(macPattern) || []).map((value) => ({
    value: value.toLowerCase(),
    normalized: value.toLowerCase(),
  })))

  const btcAddresses = uniq((originalAndRefanged.match(btcPattern) || []).map((value) => ({ value, normalized: value })))
  const ethAddresses = uniq((originalAndRefanged.match(ethPattern) || []).map((value) => ({ value, normalized: value })))

  const phones = uniq((originalAndRefanged.match(phonePattern) || []).map((value) => ({
    value,
    normalized: value.replace(/[-.\s]/g, ""),
  }))).filter((item) => item.normalized.length >= 7 && item.normalized.length <= 15)

  const urlAnalysis = analyzeUrls(urls)

  return {
    urls,
    urlAnalysis,
    domains,
    ipv4,
    ipv6,
    cidrs,
    emails,
    hashes: { md5, sha1, sha256 },
    cves,
    attackTechniques: attack,
    windowsEventIds: uniq(eventIds),
    asns,
    macAddresses: macs,
    btcAddresses,
    ethAddresses,
    phones,
  }
}

function countIocs(iocs) {
  return iocs.urls.length
    + iocs.domains.length
    + iocs.ipv4.length
    + iocs.ipv6.length
    + iocs.cidrs.length
    + iocs.emails.length
    + iocs.hashes.md5.length
    + iocs.hashes.sha1.length
    + iocs.hashes.sha256.length
    + iocs.cves.length
    + iocs.attackTechniques.length
    + iocs.windowsEventIds.length
    + iocs.asns.length
    + iocs.macAddresses.length
    + iocs.btcAddresses.length
    + iocs.ethAddresses.length
    + iocs.phones.length
}

function addSignal(signals, level, title, detail, mitreId) {
  signals.push({ level, title, detail, mitreId: mitreId || "" })
}

function buildSignals({ text, normalized, headers, iocs, urlAnalysis, commandFields, logFields, ruleFields, userAgents, secrets }) {
  const signals = []
  const lower = normalized.toLowerCase()
  const fromDomain = headers.from?.[0]?.match(/@([^>\s]+)/)?.[1]?.toLowerCase()
  const replyDomain = headers["reply-to"]?.[0]?.match(/@([^>\s]+)/)?.[1]?.toLowerCase()
  const returnPathDomain = headers["return-path"]?.[0]?.match(/@([^>\s]+)/)?.[1]?.toLowerCase()

  if (/spf=fail|dkim=fail|dkim=none|dmarc=fail|received-spf:\s*fail/i.test(normalized)) {
    addSignal(signals, "Needs Review", "Email authentication failure present", "SPF/DKIM/DMARC failure or none was observed in headers.")
  }
  if (/urgent|password reset|verify|account update|immediately|click here/i.test(normalized)) {
    addSignal(signals, "Suspicious", "Urgent account-action language", "Email or notes contain reset/verify/update wording.")
  }
  if (headers.from?.length && headers["reply-to"]?.length && fromDomain && replyDomain && fromDomain !== replyDomain) {
    addSignal(signals, "Needs Review", "Reply-To domain differs from From", `${fromDomain} differs from ${replyDomain}.`)
  }
  if (headers.from?.length && headers["return-path"]?.length && fromDomain && returnPathDomain && fromDomain !== returnPathDomain) {
    addSignal(signals, "Needs Review", "Return-Path domain differs from From", `${fromDomain} differs from ${returnPathDomain}.`)
  }
  if (iocs.urls.length) addSignal(signals, "Informational", "URL content present", `${iocs.urls.length} URL(s) extracted for safe review.`)
  if (/hxxp|hxxps|\[\.\]|\[:\]|\[@\]|\(\s*\.\s*\)/i.test(text)) addSignal(signals, "Informational", "Defanged content present", "Indicators appear intentionally defanged.")

  for (const ua of urlAnalysis) {
    if (!ua.analysis) continue
    const a = ua.analysis
    if (a.isIpHosted) addSignal(signals, "Needs Review", "URL uses IP host", a.hostname)
    if (a.hasSuspiciousPath) addSignal(signals, "Suspicious", "URL contains account-action keyword", ua.normalized)
    if (a.isSuspiciousTld) addSignal(signals, "Needs Review", "Suspicious URL TLD", `${a.hostname} uses ${a.tld} TLD`)
    if (a.isShortener) addSignal(signals, "Suspicious", "Shortened URL detected", `${a.hostname} is a known shortener`)
    if (a.entropy > 4) addSignal(signals, "Informational", "High-entropy URL path", `Path entropy ${a.entropy} in ${ua.normalized}`)
    if (a.hasPort && a.port !== "443" && a.port !== "80") addSignal(signals, "Informational", "Non-standard URL port", `${a.hostname}:${a.port}`)
    if (a.hasCredentials) addSignal(signals, "Needs Review", "URL contains embedded credentials", ua.normalized)
    if (/%[0-9a-f]{2}/i.test(ua.value)) addSignal(signals, "Informational", "URL encoded characters present", "CyberChef may help decode safely.")
  }

  if (/failed password/i.test(normalized)) addSignal(signals, "Suspicious", "Failed login observed", "Authentication log includes failed password activity.")
  if (/invalid user/i.test(normalized)) addSignal(signals, "Suspicious", "Invalid username attempt", "SSH/auth log references an invalid user.")
  if (/accepted password/i.test(normalized)) addSignal(signals, "Needs Review", "Successful login observed", "Review whether this login followed failures or used a privileged account.")
  if (/\b(root|administrator|admin)\b/i.test(normalized)) addSignal(signals, "Needs Review", "Privileged account referenced", "Privileged account activity should be correlated.")
    if (/(\/\.\.\/|\.\.\/|\/etc\/passwd|union\s+select|select.+from|<script|%27|%22|["']\s*or\s+["']|["']\s*and\s+["'])/i.test(normalized)) addSignal(signals, "Suspicious", "Web attack pattern in path or query", "Traversal, SQLi, or script-like content appears in text.")
  if (/['"]\s*\}\s*\)?\s*;?\s*<\/?script/i.test(normalized)) addSignal(signals, "Suspicious", "Reflected XSS pattern", "Possible cross-site scripting attack signature.")
  if (/\$\{|#\{|template|render|eval\(/i.test(normalized) && /path|param|input|query/i.test(normalized)) addSignal(signals, "Needs Review", "SSTI or injection pattern", "Server-side template injection may be present.")
  if (/\b(401|403|404|500|502|503)\b/.test(normalized) && logFields.web_access) addSignal(signals, "Informational", "HTTP error status observed", `Status ${logFields.web_access.status} was parsed from access log.`)
  if (userAgents.some((item) => /sqlmap|curl|python-requests|wget|nikto|nmap|masscan|zgrab/i.test(item.normalized))) addSignal(signals, "Suspicious", "Automation or scanning user-agent", "User-Agent suggests scripted or security-tool traffic.")
  if (/\b4688\b/.test(normalized)) addSignal(signals, "Informational", "Windows process creation event", "Event ID 4688 indicates process creation telemetry.")
  if (/\b7045\b/.test(normalized)) addSignal(signals, "Needs Review", "Windows service creation event", "Event ID 7045 can indicate service installation.")
  if (/\b1102\b/.test(normalized)) addSignal(signals, "Needs Review", "Windows audit log cleared event", "Event ID 1102 should be reviewed promptly.")
  if (/\b4768\b/.test(normalized)) addSignal(signals, "Needs Review", "Kerberos TGT request", "Event 4768 indicates Kerberos authentication ticket request.")
  if (/\b4769\b/.test(normalized)) addSignal(signals, "Needs Review", "Kerberos service ticket request", "Event 4769 can indicate Kerberoasting activity.")
  if (/\b4104\b/.test(normalized)) addSignal(signals, "Informational", "PowerShell script block logging", "Event 4104 captures PowerShell script block execution.")
  if (/sudo[: ]|su\s+-|su\s+\w+/i.test(normalized) && /failed|authentication failure/i.test(normalized)) addSignal(signals, "Suspicious", "Privilege escalation failure", "Failed sudo/su attempt suggests privilege escalation.")
  if (/ssh\s+(?:-i\s+\S+|key|authorized_keys)/i.test(normalized)) addSignal(signals, "Informational", "SSH key reference detected", "Key-based SSH authentication referenced.")

  if (commandFields.hasEncodedCommand) addSignal(signals, "Needs Review", "PowerShell EncodedCommand", "Decode safely; do not execute.")
  if (commandFields.hasHiddenWindow) addSignal(signals, "Suspicious", "Hidden window flag", "Command line requests hidden execution.")
  if (commandFields.hasNoProfile) addSignal(signals, "Suspicious", "NoProfile flag", "PowerShell profile loading is disabled.")
  if (commandFields.hasDownloadCradle) addSignal(signals, "Needs Review", "Download cradle keyword", "Command includes web retrieval or download keywords.")
  if (commandFields.hasLolbin) addSignal(signals, "Needs Review", "LOLBin-style utility", "Command references a Windows living-off-the-land binary.")
  if (commandFields.hasAmsiBypass) addSignal(signals, "Suspicious", "AMSI bypass pattern detected", "Command line contains AMSI bypass keywords.")
  if (commandFields.hasDownloadExecute) addSignal(signals, "Needs Review", "Suspicious download-execute pattern", "Command retrieves and likely runs remote content.")
  if (commandFields.hasPipePowerShell) addSignal(signals, "Needs Review", "Pipe to PowerShell detected", "Output piped to PowerShell can indicate fileless execution.")
  if (commandFields.base64Blobs.length) addSignal(signals, "Informational", "Base64-looking blob", "CyberChef can decode safely for review.")
  if (/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(normalized.trim())) addSignal(signals, "Needs Review", "JWT-like token", "Decode header and payload safely; local parsing does not verify trust.")
  if (secrets.length) addSignal(signals, "Needs Review", "Secret-like pattern detected", `${secrets.length} local secret finding(s). Rotate if confirmed exposed.`)

  if (ruleFields.sigma) addSignal(signals, "Informational", "Sigma structure detected", "Rule includes Sigma-like title/logsource/detection fields.")
  if (ruleFields.yara) addSignal(signals, "Informational", "YARA structure detected", "Rule-like YARA syntax is present.")
  if (ruleFields.ids_rule) addSignal(signals, "Informational", "Snort/Suricata rule syntax detected", "Network IDS rule structure is present.")
  if (iocs.attackTechniques.length) addSignal(signals, "Informational", "ATT&CK technique IDs present", iocs.attackTechniques.map((item) => item.normalized).join(", "))
  if (/encodedcommand|powershell|cmdline|commandline/i.test(lower) && ruleFields.sigma) addSignal(signals, "Suspicious", "Rule hunts command-line behavior", "Detection content references suspicious command-line patterns.")

  return uniq(signals.map((signal) => ({
    ...signal,
    value: `${signal.level}:${signal.title}:${signal.detail}`,
    normalized: `${signal.level}:${signal.title}:${signal.detail}`,
  }))).map(({ level, title, detail }) => ({ level, title, detail }))
}

function detectArtifact(text) {
  const limited = text.slice(0, MAX_INPUT_CHARS)
  const normalized = refang(limited)
  const lower = normalized.toLowerCase()
  const lines = normalized.split(/\r?\n/).filter((line) => line.trim())
  const headers = extractHeaders(normalized)
  const iocs = extractIocs(limited)
  const jsonObjects = parseJsonLines(normalized)
  const keyValues = extractKeyValues(normalized)
  const userAgents = extractUserAgents(normalized)
  const commandFields = extractCommandFields(normalized)
  const secrets = scanSecrets(normalized)
  const logFields = extractLogFields(normalized, jsonObjects)
  const ruleFields = extractRuleFields(normalized)
  const scores = {}
  const fields = { key_values: keyValues }
  const warnings = []

  if (text.length > MAX_INPUT_CHARS) {
    warnings.push(`Input was limited to the first ${MAX_INPUT_CHARS.toLocaleString()} characters for browser responsiveness.`)
  }

  const hasEmailHeaders = ["from", "to", "subject", "received", "authentication-results"].some((key) => headers[key]?.length)
  if (headers.from?.length || headers.to?.length || headers.subject?.length) {
    addScore(scores, "Email / Phishing", 35, "Found From/To/Subject style email headers.")
    fields.email = {
      sender: headers.from?.[0],
      recipient: headers.to?.[0],
      subject: headers.subject?.[0],
      reply_to: headers["reply-to"]?.[0],
      return_path: headers["return-path"]?.[0],
      received: headers.received || [],
    }
  }
  if (headers.received?.length) addScore(scores, "Email / Phishing", 25, "Found Received header chain.")
  if (hasEmailHeaders && iocs.urls.length) addScore(scores, "Email / Phishing", 15, "Found URL content within email-like text.")
  if (headers["authentication-results"]?.length || headers["received-spf"]?.length || /\b(spf|dkim|dmarc)=(pass|fail|softfail|neutral|none)\b/i.test(normalized)) {
    addScore(scores, "Email Headers", 35, "Found SPF/DKIM/DMARC authentication signals.")
    fields.email = {
      ...(fields.email || {}),
      authentication: headers["authentication-results"] || [],
      received_spf: headers["received-spf"] || [],
    }
  }
  if (!hasEmailHeaders && /dear .*?(user|customer|member)|verify your account|password reset|click (here|the link)/i.test(normalized)) {
    addScore(scores, "Suspicious Email Body", 45, "Found email body language commonly seen in user-reported messages.")
  }
  if ((hasEmailHeaders || lower.includes("subject:")) && iocs.urls.length) addScore(scores, "URL-heavy Email Content", 25, "Found URLs alongside email-like content.")

  if (iocs.urls.length === 1 && lines.length <= 3) addScore(scores, "URL", 75, "Input is primarily a single URL.")
  if (iocs.domains.length === 1 && lines.length <= 3 && !iocs.urls.length && !iocs.emails.length) addScore(scores, "Domain", 75, "Input is primarily a single domain.")
  if (iocs.ipv4.length === 1 && lines.length <= 3 && !iocs.urls.length) addScore(scores, "IPv4", 75, "Input is primarily a single IPv4 address.")
  if (iocs.ipv6.length === 1 && lines.length <= 3) addScore(scores, "IPv6", 70, "Input is primarily a single IPv6 address.")
  if (iocs.cidrs.length) addScore(scores, "CIDR", 70, "Found CIDR network notation.")
  if (/^HTTP\/\d\.\d\s+\d{3}|^(GET|POST|PUT|DELETE|HEAD|OPTIONS)\s+/m.test(normalized) || /^(host|user-agent|accept|content-type|authorization):/im.test(normalized)) {
    addScore(scores, "HTTP Headers", 55, "Found HTTP request/response header structure.")
  }
  if (/-----BEGIN CERTIFICATE-----|issuer:|subject:|not before|not after|x509|sha256 fingerprint/i.test(normalized)) {
    addScore(scores, "TLS/Certificate Text", 55, "Found certificate-like fields or PEM markers.")
  }
  if (/\b(IN|A|AAAA|CNAME|MX|TXT|NS|SOA)\b.*\b(?:TTL|answer|record)\b/i.test(normalized) || /\b(v=spf1|_dmarc|TXT)\b/i.test(normalized)) {
    addScore(scores, "DNS Records", 50, "Found DNS record-like syntax.")
  }
  if (/\b(registrar|registrant|rdap|whois server|creation date|updated date|name server)\b/i.test(normalized)) {
    addScore(scores, "WHOIS/RDAP Text", 50, "Found WHOIS/RDAP registration fields.")
  }

  if (/sshd\[\d+\]:|failed password|accepted password|invalid user/i.test(normalized)) {
    addScore(scores, "Linux Auth Log", 90, "Found SSH authentication log format.")
  }
  if (/\bEvent\s*ID\b|\bProvider Name\b|Microsoft-Windows-Security-Auditing|\b(?:4624|4625|4688|4672|1102|7045)\b/.test(normalized)) {
    addScore(scores, "Windows Event Log", 85, "Found Windows Event ID or Security Auditing fields.")
  }
  if (jsonObjects.some((item) => item?.event_type === "alert" || item?.alert || item?.src_ip || item?.dest_ip)) {
    addScore(scores, "Suricata EVE Network Alert", 90, "Found JSON alert fields used by Suricata/EVE.")
  }
  if (/\[\*\*\].+\[\*\*\]|sid:\d+|classtype:|priority:/i.test(normalized)) {
    addScore(scores, "EDR/SIEM Alert Text", 70, "Found Snort/Suricata alert or rule markers.")
  }
  if (/^\d+\.\d+\.\d+\.\d+\s+\S+\s+\S+\s+\[[^\]]+\]\s+"(?:GET|POST|PUT|DELETE|HEAD)\s+/m.test(normalized)) {
    addScore(scores, "Web Access Log", 85, "Found common web access log format.")
  }
  if (/\b#fields\b|\bid\.orig_h\b|\bid\.resp_h\b|\bconn\b|\bdns\b|\bzeek\b/i.test(normalized)) {
    addScore(scores, "Zeek-like Network Log", 70, "Found Zeek field names or log markers.")
  }
  if (/Mozilla\/5\.0|curl\/|python-requests|sqlmap|Chrome\/|Safari\/|Firefox\//i.test(normalized) && lines.length <= 6) {
    addScore(scores, "User-Agent Strings", 55, "Found user-agent tokens.")
  }
  if (/\b(action=|src=|dst=|src_ip=|dst_ip=|sourcetype=proxy|proxy|firewall|allowed|blocked|deny)\b/i.test(normalized)) {
    addScore(scores, "Firewall/Proxy Log", 60, "Found firewall/proxy style network fields.")
  }
  if (/\b(alert|severity|signature|rule|src_ip|dst_ip|source ip|destination ip)\b/i.test(normalized)) {
    addScore(scores, "EDR/SIEM Alert Text", 45, "Found alert or network security field names.")
  }

  if (commandFields.commands.length) addScore(scores, "Endpoint Command Line", 75, "Found command interpreter or command-line artifact.")
  if (commandFields.hasEncodedCommand) addScore(scores, "PowerShell EncodedCommand", 90, "Found PowerShell EncodedCommand flag.")
  if (commandFields.hasLolbin) addScore(scores, "Suspicious Script/LOLBin Command", 80, "Found living-off-the-land utility usage.")
  if (/\b[A-Z]:\\(?:Windows|Users|ProgramData|Program Files|Temp|AppData)\\[^\r\n]+/i.test(normalized)) addScore(scores, "Windows File Path", 60, "Found Windows file path artifact for endpoint review.")
  if (/\b(?:HKLM|HKCU|HKCR|HKU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)\\[^\r\n]+/i.test(normalized)) addScore(scores, "Registry Path Artifact", 60, "Found Windows registry path artifact for endpoint review.")
  if (commandFields.base64Blobs.length && !commandFields.hasEncodedCommand) addScore(scores, "Base64-looking Payload", 45, "Found base64-looking content.")
  if (/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(normalized.trim())) addScore(scores, "JWT / Token Artifact", 75, "Found three Base64URL-like token segments.")
  if (secrets.length) addScore(scores, "Pasted Code / Secret Findings", Math.min(95, 55 + (secrets.length * 10)), "Found local secret-like patterns or high-entropy strings.")

  if (countIocs(iocs) >= 3 && lines.length >= 2) addScore(scores, "IOC List", 70, "Found multiple indicators across one or more lines.")
  if (iocs.hashes.md5.length || iocs.hashes.sha1.length || iocs.hashes.sha256.length) addScore(scores, "File Hash Indicators", 65, "Found MD5/SHA1/SHA256 length hashes.")
  if (/hxxp|hxxps|\[\.\]|\[:\]|\[@\]/i.test(text)) addScore(scores, "Defanged Indicators", 65, "Found defanged indicator syntax.")
  if (countIocs(iocs) > 4 && (iocs.urls.length || iocs.domains.length) && (iocs.ipv4.length || iocs.hashes.sha256.length || iocs.hashes.md5.length)) {
    addScore(scores, "Mixed Indicator List", 70, "Found mixed indicator families.")
  }

  if (/title:\s*.+\n(?:id:|logsource:|detection:|condition:)/i.test(normalized)) addScore(scores, "Sigma-like Detection Rule", 95, "Found Sigma rule structure.")
  if (/\brule\s+\w+\s*\{|strings:\s*|condition:\s*/i.test(normalized) && /\$[a-z0-9_]+\s*=/i.test(normalized)) addScore(scores, "YARA-like Detection Rule", 85, "Found YARA rule markers.")
  if (/^(alert|drop|reject|pass)\s+(tcp|udp|icmp|ip)\s+/im.test(normalized)) addScore(scores, "Snort/Suricata Detection Rule", 90, "Found network IDS rule syntax.")
  if (iocs.attackTechniques.length || /\battack\.t\d{4}/i.test(normalized)) addScore(scores, "ATT&CK Mapping", 65, "Found ATT&CK technique IDs.")

  if (/^\d{1,2}:\d{2}\s+-|^\d{4}-\d{2}-\d{2}|finding:|observation:|recommendation:|next step:/im.test(normalized)) {
    addScore(scores, "Analyst Notes / Timeline", 55, "Found timeline, finding, observation, or next-step note structure.")
  }

  if (!Object.keys(scores).length) {
    addScore(scores, "Analyst Notes / Unknown Text", 20, "No strong artifact pattern matched; treating as analyst notes for review.")
    warnings.push("Classification needs analyst review before routing.")
  }

  if (commandFields.commands.length) fields.command_line = commandFields
  if (secrets.length) fields.secrets = secrets
  if (Object.keys(logFields).length) fields.logs = logFields
  if (Object.keys(ruleFields).length) fields.rule = ruleFields
  if (userAgents.length) fields.user_agents = userAgents.map((item) => item.normalized)

  const ranked = Object.entries(scores)
    .map(([type, data]) => {
      const meta = typeMeta(type)
      return {
        type,
        family: meta.family,
        priority: meta.priority,
        score: Math.min(100, data.score),
        rankScore: Math.min(100, data.score) + ((9 - meta.priority) * 8),
        reasons: uniq(data.reasons.map((reason) => ({ value: reason, normalized: reason }))).map((item) => item.value),
      }
    })
    .sort((a, b) => b.rankScore - a.rankScore)

  const primary = ranked[0]
  const secondary = ranked.slice(1, 5)
  const routeKeys = suggestRoutes(primary.type, secondary.map((item) => item.type), iocs, normalized)
  const signals = buildSignals({ text: limited, normalized, headers, iocs, urlAnalysis: iocs.urlAnalysis, commandFields, logFields, ruleFields, userAgents, secrets })
  const guidance = buildGuidance({
    primaryType: primary.type,
    family: primary.family,
    fields,
    iocs,
    signals,
    routes: routeKeys.map((key) => ROUTES[key]).filter(Boolean),
  })

  return {
    primaryType: primary.type,
    artifactFamily: primary.family,
    reasons: primary.reasons,
    secondaryTypes: secondary,
    extracted: iocs,
    fields,
    signals,
    guidance,
    normalizedArtifacts: buildNormalizedArtifacts(iocs),
    warnings,
    suggestedRoutes: routeKeys.map((key) => ROUTES[key]).filter(Boolean),
    parsedMeta: {
      line_count: lines.length,
      character_count: text.length,
      processed_character_count: limited.length,
      json_objects_detected: jsonObjects.length,
      header_fields_detected: Object.keys(headers).length,
      method: "deterministic_browser_parser",
      source: "local_browser",
      external_lookup: false,
      execution: false,
      limitations: "Pattern-based classification. Analyst review is required before taking action.",
    },
  }
}

function buildGuidance({ primaryType, family, fields, iocs, signals, routes }) {
  const routeText = routes[0]?.label || "the recommended module"
  const l1 = [
    `Treat this as ${primaryType} in the ${family} family.`,
    `Open ${routeText} next for deeper analysis.`,
    "Copy the detected type, key artifacts, source/method, and limitations into the ticket.",
  ]
  const l2 = [
    "Preserve original artifact text and timestamps before enrichment.",
    "Use normalized IOCs for pivots, but keep originals for evidence.",
  ]

  if (family === "Email / Phishing") {
    l1.push("Review sender, recipient, subject, reply-to, return-path, and authentication results first.")
    l1.push("Extract URLs for safe review; do not click links from the original message.")
    l2.push("Pivot on sender domain, reply-to, return-path, URL domains, and Received IPs.")
    l2.push("Compare SPF, DKIM, and DMARC alignment before escalating.")
    l2.push("Search mailbox and proxy logs for the same subject, sender, URL, or domain.")
  }

  if (family === "Log / Alert" || family === "Network / Firewall / Proxy") {
    l1.push("Identify source, destination, user, host, action, status, and timestamp.")
    l1.push("Open Logs & Alerts and preserve the raw log line or alert JSON.")
    l2.push("Search the same source IP, user, host, and event IDs across at least a 24 hour window.")
    l2.push("Look for successful activity after failures, privilege changes, and repeated paths or signatures.")
    if (fields.logs?.web_access) l2.push("Pivot on path, status code, source IP, and user-agent.")
  }

  if (family === "Endpoint / Command Line") {
    l1.push("Do not execute the command. Keep analysis static.")
    l1.push("Open CyberChef for safe decoding or Logs & Alerts for process/event context.")
    l2.push("Decode EncodedCommand or base64 safely, then review parent process, user, host, and network connections.")
    l2.push("Consider ATT&CK command/scripting mapping such as T1059 when relevant.")
  }

  if (family === "Detection Rule") {
    l1.push("Confirm the rule type, detection condition, log source, and referenced fields.")
    l1.push("Open Detection & MITRE for mapping and detection notes.")
    l2.push("Review ATT&CK tags, command-line keywords, required telemetry, and false-positive conditions.")
    l2.push("Turn useful test observations into report notes instead of treating the rule as evidence by itself.")
  }

  if (family === "IOC / Indicator List" || family === "URL / Domain / IP / Recon Target") {
    l1.push("Group URLs, domains, IPs, hashes, and CVEs before routing.")
    l1.push("Open Recon & Exposure for scoped target review or Attachment Triage for hashes.")
    l2.push("Pivot on URL hostnames, registrable domains, source IPs, file hashes, and related CVEs.")
    l2.push("Document whether indicators were defanged and preserve the normalized/refanged form.")
  }

  if (family === "Analyst Notes / Report Draft" || family === "Unknown / Mixed Artifact") {
    l1.push("Identify concrete facts, timestamps, affected users, systems, and open questions.")
    l1.push("Copy the analyst summary or export Markdown if this is already a narrative or timeline.")
    l2.push("Separate observations from hypotheses, then build a timeline with source references.")
  }

  if (signals.some((signal) => signal.level === "Needs Review")) {
    l1.push("Escalate for review if the Needs Review signals align with asset criticality or user impact.")
  }
  if (iocs.attackTechniques.length) {
    l2.push("Use ATT&CK IDs as mapping candidates, not final attribution.")
  }

  return {
    l1: uniq(l1.map((item) => ({ value: item, normalized: item }))).map((item) => item.value),
    l2: uniq(l2.map((item) => ({ value: item, normalized: item }))).map((item) => item.value),
  }
}

function buildNormalizedArtifacts(iocs) {
  return {
    urls: iocs.urls.map((item) => item.normalized),
    domains: iocs.domains.map((item) => item.normalized),
    ips: [...iocs.ipv4, ...iocs.ipv6].map((item) => item.normalized),
    cidrs: iocs.cidrs.map((item) => item.normalized),
    emails: iocs.emails.map((item) => item.normalized),
    hashes: {
      md5: iocs.hashes.md5.map((item) => item.normalized),
      sha1: iocs.hashes.sha1.map((item) => item.normalized),
      sha256: iocs.hashes.sha256.map((item) => item.normalized),
    },
    cves: iocs.cves.map((item) => item.normalized),
    attackTechniques: iocs.attackTechniques.map((item) => item.normalized),
    windowsEventIds: iocs.windowsEventIds.map((item) => item.normalized),
    asns: iocs.asns.map((item) => item.normalized),
    macAddresses: iocs.macAddresses.map((item) => item.normalized),
    btcAddresses: iocs.btcAddresses.map((item) => item.normalized),
    ethAddresses: iocs.ethAddresses.map((item) => item.normalized),
    phones: iocs.phones.map((item) => item.normalized),
  }
}

function suggestRoutes(primaryType, secondaryTypes, iocs, text) {
  const haystack = [primaryType, ...secondaryTypes].join(" ").toLowerCase()
  const routes = []
  const add = (key) => {
    if (!routes.includes(key)) routes.push(key)
  }

  if (/email|phishing|authentication header/.test(haystack)) add("phishing")
  if (/url|link/.test(haystack) || iocs.urls.length) add("safeUrl")
  if (/url|domain|ipv4|ipv6|cidr|dns|whois|rdap|certificate|recon/.test(haystack) || iocs.urls.length || iocs.domains.length || iocs.ipv4.length || iocs.ipv6.length || iocs.cidrs.length) add("recon")
  if (/log|alert|event|zeek|suricata|access|user-agent|firewall|proxy|endpoint|command|powershell/.test(haystack)) add("logs")
  if (/hash/.test(haystack) || iocs.hashes.md5.length || iocs.hashes.sha1.length || iocs.hashes.sha256.length) add("attachment")
  if (/sigma|yara|snort|mitre|attack|detection/.test(haystack) || iocs.attackTechniques.length) add("detection")
  if (/base64|encodedcommand|powershell|jwt|token|secret|api key|cmd\.exe|rundll32|regsvr32|mshta|wscript|cscript|hxxp|\\u[0-9a-f]{4}|%[0-9a-f]{2}/i.test(`${haystack}\n${text}`)) add("cyberchef")
  if (/notes|timeline|finding|report/.test(haystack)) add("detection")

  return routes.slice(0, 4)
}

function toMarkdown(result) {
  if (!result) return ""
  const lines = [
    "# Artifact Intake Result",
    "",
    `- Detected type: ${result.primaryType}`,
    `- Artifact family: ${result.artifactFamily}`,
    `- Source: ${result.parsedMeta.source}`,
    `- Method: ${result.parsedMeta.method}`,
    "",
    "## Reasons",
    ...result.reasons.map((reason) => `- ${reason}`),
    "",
    "## Extracted IOCs",
  ]

  for (const [label, values] of Object.entries(flattenIocGroups(result.extracted))) {
    if (!values.length) continue
    lines.push(`- ${label}: ${values.map((item) => item.normalized || item.value).join(", ")}`)
  }

  lines.push("", "## Suggested Next Steps")
  result.suggestedRoutes.forEach((route) => lines.push(`- ${route.label}`))
  lines.push("", "## Signals")
  result.signals.forEach((signal) => lines.push(`- ${signal.level}: ${signal.title} - ${signal.detail}`))
  if (result.fields.secrets?.length) {
    lines.push("", "## Secret Findings")
    result.fields.secrets.forEach((item) => lines.push(`- Line ${item.line}: ${item.type} - ${item.preview}`))
  }
  lines.push("", "## L1 Triage Guidance")
  result.guidance.l1.forEach((item) => lines.push(`- ${item}`))
  lines.push("", "## L2 Pivot Ideas")
  result.guidance.l2.forEach((item) => lines.push(`- ${item}`))
  lines.push("", "## Limitations")
  lines.push(`- ${result.parsedMeta.limitations}`)
  result.warnings.forEach((warning) => lines.push(`- ${warning}`))
  return lines.join("\n")
}

function flattenIocGroups(iocs) {
  return {
    URLs: iocs.urls,
    Domains: iocs.domains,
    IPv4: iocs.ipv4,
    IPv6: iocs.ipv6,
    CIDR: iocs.cidrs,
    Emails: iocs.emails,
    MD5: iocs.hashes.md5,
    SHA1: iocs.hashes.sha1,
    SHA256: iocs.hashes.sha256,
    CVEs: iocs.cves,
    "ATT&CK": iocs.attackTechniques,
    "Windows Event IDs": iocs.windowsEventIds,
    "AS Numbers": iocs.asns,
    "MAC Addresses": iocs.macAddresses,
    "BTC Addresses": iocs.btcAddresses,
    "ETH Addresses": iocs.ethAddresses,
    Phones: iocs.phones,
  }
}

function flatIocRows(iocs) {
  const rows = []
  for (const item of iocs.urls) rows.push({ type: 'URL', value: item.normalized, context: 'Extracted from URL' })
  for (const item of iocs.domains) rows.push({ type: 'Domain', value: item.normalized, context: 'Referenced host' })
  for (const item of iocs.ipv4) rows.push({ type: 'IP', value: item.normalized, context: 'IPv4 address' })
  for (const item of iocs.ipv6) rows.push({ type: 'IP', value: item.normalized, context: 'IPv6 address' })
  for (const item of iocs.cidrs) rows.push({ type: 'CIDR', value: item.normalized, context: 'Network range' })
  for (const item of iocs.emails) rows.push({ type: 'Email', value: item.normalized, context: 'Email address' })
  for (const item of iocs.hashes.md5) rows.push({ type: 'MD5', value: item.normalized, context: 'File hash' })
  for (const item of iocs.hashes.sha1) rows.push({ type: 'SHA1', value: item.normalized, context: 'File hash' })
  for (const item of iocs.hashes.sha256) rows.push({ type: 'SHA256', value: item.normalized, context: 'File hash' })
  for (const item of iocs.cves) rows.push({ type: 'CVE', value: item.normalized, context: 'Vulnerability reference' })
  for (const item of iocs.attackTechniques) rows.push({ type: 'ATT&CK', value: item.normalized, context: 'Technique mapping' })
  for (const item of iocs.windowsEventIds) rows.push({ type: 'Event ID', value: item.normalized, context: 'Windows event' })
  for (const item of iocs.asns) rows.push({ type: 'ASN', value: item.normalized, context: 'Autonomous system' })
  for (const item of iocs.macAddresses) rows.push({ type: 'MAC', value: item.normalized, context: 'Hardware address' })
  for (const item of iocs.btcAddresses) rows.push({ type: 'BTC', value: item.normalized, context: 'Bitcoin address' })
  for (const item of iocs.ethAddresses) rows.push({ type: 'ETH', value: item.normalized, context: 'Ethereum address' })
  for (const item of iocs.phones) rows.push({ type: 'Phone', value: item.normalized, context: 'Phone number' })
  return rows
}

function analystSummary(result) {
  if (!result) return ""
  const count = countIocs(result.extracted)
  return `${result.primaryType} detected; ${count} IOC${count === 1 ? "" : "s"} extracted for local analyst review.`
}

const PENDING_ARTIFACT_KEY = "beyondarch.pendingArtifact"

function storePendingArtifact(payload) {
  try {
    window.localStorage.setItem(PENDING_ARTIFACT_KEY, JSON.stringify({
      ...payload,
      created_at: new Date().toISOString(),
    }))
  } catch {
    // localStorage may be unavailable in private contexts.
  }
}

function readIncomingArtifact() {
  try {
    const raw = window.sessionStorage.getItem(PENDING_ARTIFACT_KEY) || window.localStorage.getItem(PENDING_ARTIFACT_KEY)
    if (!raw) return null
    const artifact = JSON.parse(raw)
    const isForSmartParser = artifact?.target === "smart-parser" || artifact?.page === "smart-parser"
    if (!isForSmartParser || !(artifact.value || artifact.content || artifact.text || artifact.raw_input)) return null
    window.sessionStorage.removeItem(PENDING_ARTIFACT_KEY)
    window.localStorage.removeItem(PENDING_ARTIFACT_KEY)
    return {
      ...artifact,
      value: String(artifact.value || artifact.content || artifact.text || artifact.raw_input || ""),
    }
  } catch {
    return null
  }
}

function parseInitialIncomingArtifact(artifact) {
  if (!artifact?.value) return { result: null, error: "" }
  try {
    return { result: detectArtifact(artifact.value), error: "" }
  } catch (err) {
    return { result: null, error: err.message || "Loaded artifact could not be parsed automatically." }
  }
}

/* ── Stitch-inspired rendering components ──*/


/* ── Input page ──────────────────────────────────────────────── */

function SInput({ input, setInput, fileRef, handleFile, loadSample, parseError, notice, runParse, copyText, setNotice, clearInput, parsing }) {
  const textareaRef = useRef(null)
  const [cursorLine, setCursorLine] = useState(1)
  const [isFocused, setIsFocused] = useState(false)
  const lineCount = input ? input.split('\n').length : 1
  const lineNumbers = Array.from({ length: Math.max(25, lineCount + 5) }, (_, i) => i + 1)
  const showEmpty = !isFocused && input.length === 0
  const wordCount = input ? input.trim().split(/\s+/).filter(Boolean).length : 0
  const charCount = input.length

  function updateCursorLine(el) {
    const line = el.value.substr(0, el.selectionStart).split('\n').length
    setCursorLine(line)
  }

  function handleChange(event) {
    setInput(event.target.value)
    updateCursorLine(event.target)
  }

  function handleSelect(event) {
    updateCursorLine(event.target)
  }

  return (
    <div className="sp-workbench">
      {notice ? <div className="sp-notice"><Info size={12} />{notice}</div> : null}
      {parseError ? <div className="sp-notice sp-notice-error"><AlertTriangle size={12} />{parseError}</div> : null}

      <div className="sp-area">
        <div className="sp-term">
          <div className="sp-term-hd">
            <div className="sp-term-hd-l">
              <div className="sp-badge sp-badge-grn">
                <div className="sp-badge-dot sp-dot-grn" />
                <span>READY</span>
              </div>

              <span className="sp-term-hd-label">INPUT_TERMINAL</span>
            </div>
            <div className="sp-term-hd-r">
              <button type="button" className="sp-term-btn" onClick={() => copyText(input, setNotice, "Input")}>
                <Copy size={11} />COPY
              </button>
              <button type="button" className="sp-term-btn sp-term-btn-rose" onClick={clearInput}>
                <Eraser size={11} />CLEAR
              </button>
            </div>
          </div>
          <div className="sp-term-body">
            <div className="sp-scanline" />
            <div className={"sp-radar" + (showEmpty ? "" : " is-hidden")}>
              <div className="sp-radar-rings">
                <div className="sp-radar-ring" />
                <div className="sp-radar-ring" />
                <div className="sp-radar-ring" />
                <div className="sp-radar-axis" />
                <div className="sp-radar-axis-v" />
                <div className="sp-radar-sweep" />
                <div className="sp-radar-center">
                  <div className="sp-radar-center-inner"><Fingerprint size={28} /></div>
                </div>
              </div>
            </div>
            <div className="sp-lines">
              {lineNumbers.slice(0, 50).map((n) => (
                <div key={n} className={n === cursorLine ? "is-active" : ""}>{String(n).padStart(2, '0')}</div>
              ))}
            </div>
            <div className="sp-textarea-wrap">
              <textarea
                ref={textareaRef}
                className="sp-textarea"
                value={input}
                onChange={handleChange}
                onKeyUp={handleSelect}
                onClick={handleSelect}
                onFocus={() => setIsFocused(true)}
                onBlur={() => setIsFocused(false)}
                placeholder="[System Ready] Paste raw artifact data, logs, or execution traces here..."
              />
              <span className="sp-blink" />
            </div>
          </div>
          <div className="sp-term-ft">
            <span>WORDS: {wordCount} &middot; CHARS: {charCount}</span>
          </div>
        </div>

        <div className="sp-sidebar">
          <div className="sp-sidebar-sec">
            <h3 className="sp-sidebar-hd"><span className="sp-dot-blue" />CONTEXT LOADER</h3>
            <div className="sp-select-wrap">
              <select onChange={(event) => { if (event.target.value) loadSample(event.target.value); event.target.value = "" }} defaultValue="">
                <option value="" disabled>Select Sample Pipeline...</option>
                {Object.entries(SAMPLE_INPUTS).map(([key, sample]) => (
                  <option key={key} value={key}>{sample.label}</option>
                ))}
              </select>
              <span className="sp-select-arrow">v</span>
            </div>
          </div>
          <div className="sp-sidebar-sec">
            <h3 className="sp-sidebar-hd"><span className="sp-dot-cyan" />EXECUTION CORE</h3>
            <div className="sp-core-btns">
              <button type="button" className="sp-parse-btn" onClick={() => runParse()} disabled={parsing}>
                {parsing ? <RefreshCcw size={16} className="sp-spin" /> : <Zap size={16} />}{parsing ? "PARSING..." : "PARSE ARTIFACT"}
              </button>
              <button type="button" className="sp-file-btn" onClick={() => fileRef.current?.click()}>
                <span><Upload size={13} /> IMPORT FILE</span>
                <ChevronRight size={13} className="sp-file-btn-arrow" />
              </button>
            </div>
            <input ref={fileRef} type="file" className="hidden" onChange={handleFile} />
          </div>
          <div className="sp-sidebar-sec sp-sidebar-sec-last">
            <div className="sp-integrity-box">
              <p>Analysis performed locally.<br />No data exfiltration detected.</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

/* ── Results components ─────────────────────────────────────── */

function SVerdict({ result, input }) {
  const firstLine = (input || '').split('\n')[0].trim().slice(0, 60)
  const primaryType = result.primaryType
  const confidenceMeta = TYPE_CONFIDENCE_WEIGHTS[primaryType] || { weight: 0.5, base: "Low confidence — generic pattern match" }
  const confidencePct = Math.round(confidenceMeta.weight * 100)
  const confidenceBarColor = confidencePct >= 85 ? '#22c55e' : confidencePct >= 70 ? '#eab308' : '#ef4444'

  function vectorFromType(type) {
    const t = (type || '').toLowerCase()
    if (t.includes('email')) return 'Phishing'
    if (t.includes('url')) return 'Web'
    if (t.includes('ip')) return 'Network'
    if (t.includes('hash') || t.includes('md5') || t.includes('sha')) return 'File'
    return type || 'Artifact'
  }

  return (
    <div className="st-hero st-hero-animate">
      <div className="st-hero-watermark"><AlertTriangle /></div>
      <div className="st-hero-body">
          <div className="st-hero-eyebrow">
            <span className="st-hero-badge">VERDICT</span>
            <span className="st-hero-attr">
              Confidence: {confidencePct}%
            </span>
          </div>
          <h1 className="st-hero-title">{primaryType} Analysis</h1>
          <div className="st-hero-meta">
            <div className="st-hero-meta-item">
              <span className="st-hero-meta-lbl">Threat Family</span>
              <span className="st-hero-meta-val">{result.artifactFamily || primaryType}</span>
            </div>
            <div className="st-hero-meta-item">
              <span className="st-hero-meta-lbl">Primary Vector</span>
              <span className="st-hero-meta-val">{vectorFromType(primaryType)}</span>
            </div>
            {mitreForType(primaryType) ? (
              <div className="st-hero-meta-item">
                <span className="st-hero-meta-lbl">MITRE ATT&CK</span>
                <span className="st-hero-meta-val">
                  <span className="ba-chip ba-status-info">MITRE: {mitreForType(primaryType)}</span>
                </span>
              </div>
            ) : null}
            <div className="st-hero-meta-item">
              <span className="st-hero-meta-lbl">Analyzed Artifact</span>
              <span className="st-hero-meta-val">{firstLine || '—'}</span>
            </div>
          </div>
          <div className="st-hero-confidence-bar" style={{
            marginTop: '0.75rem',
            height: '4px',
            borderRadius: '2px',
            background: 'rgba(255,255,255,0.1)',
            overflow: 'hidden',
          }}>
            <div style={{
              width: `${confidencePct}%`,
              height: '100%',
              background: confidenceBarColor,
              borderRadius: '2px',
              transition: 'width 0.6s ease',
            }} />
          </div>
        </div>
    </div>
  )
}

function SFindings({ signals }) {
  if (!signals?.length) return null
  function findingMeta(level) {
    const l = (level || '').toLowerCase()
    if (l === 'suspicious') return { sev: 'rose', badge: 'ATT&CK', severity: 'CRITICAL', source: 'ATT&CK_ENGINE' }
    if (l === 'needs review' || l === 'needs_review') return { sev: 'amber', badge: 'HEURISTIC', severity: 'HIGH', source: 'HEURISTIC_SCAN' }
    return { sev: 'cyan', badge: 'STATIC', severity: 'INFO', source: 'STATIC_ANALYSIS' }
  }
  return (
    <div className="st-seg st-hero-animate" style={{ animationDelay: '0.2s' }}>
      <div className="st-seg-hd">
        <div className="st-seg-hd-l"><Scan />EXECUTIVE SUMMARY // KEY FINDINGS</div>
      </div>
      <div className="st-findings" style={{ padding: '0.65rem' }}>
        {signals.slice(0, 5).map((signal, i) => {
          const meta = findingMeta(signal.level)
          return (
            <div key={i} className="st-finding" data-sev={meta.sev}>
              <div className="st-finding-hdr">
                <div className="st-finding-hdr-l">
                  <span className="st-finding-badge"><Shield />{meta.badge}</span>
                  <span className="st-finding-id">{meta.badge === 'ATT&CK' ? 'T' + String(1566 + i) : meta.badge === 'HEURISTIC' ? 'PROC_EXEC' : 'SIG_DET'}</span>
                </div>
                <span className="st-finding-id-right">ID: FND-{String(i + 1).padStart(3, '0')}</span>
              </div>
              <h3 className="st-finding-title">{signal.title}</h3>
              {signal.detail && <p className="st-finding-desc">{signal.detail}</p>}
              <div className="st-finding-footer">
                <div className="st-finding-footer-item">
                  <span className="st-finding-footer-lbl">SOURCE</span>
                  <span className="st-finding-footer-val">{signal.source || meta.source}</span>
                </div>
                <div className="st-finding-footer-item">
                  <span className="st-finding-footer-lbl">SEVERITY</span>
                  <span className="st-finding-footer-val">{meta.severity}</span>
                </div>
                {signal.mitreId ? (
                  <div className="st-finding-footer-item">
                    <span className="st-finding-footer-lbl">MITRE</span>
                    <span className="st-finding-footer-val">{signal.mitreId}</span>
                  </div>
                ) : null}
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}

function SSecrets({ items }) {
  if (!items?.length) return null
  return (
    <div className="s-panel">
      <div className="s-panel-hd">
        <div className="s-panel-hd-left"><Shield />Secret Findings</div>
        <span className="s-panel-count">{items.length} potential</span>
      </div>
      <div className="s-sec-list">
        {items.slice(0, 15).map((item, index) => (
          <div key={`${item.type}-${index}`} className="s-sec-item" data-conf={item.confidence?.toLowerCase() || "low"}>
            <div className="s-sec-hdr">
              <span className="s-sec-type">{item.type}</span>
              <span className="s-sec-conf" data-conf={item.confidence?.toLowerCase() || "low"}>{item.confidence}</span>
            </div>
            <div className="s-sec-preview">{item.preview}</div>
            <div className="s-sec-line">Line {item.line}</div>
            {item.remediation ? <div className="s-sec-fix">{item.remediation}</div> : null}
          </div>
        ))}
        {items.length > 15 ? <div className="s-ioc-more">+{items.length - 15} more</div> : null}
      </div>
    </div>
  )
}

const LEDGER_CATEGORIES = [
  { label: 'IP ADDRESSES', icon: Server, types: ['IP', 'CIDR'], sev: 'rose' },
  { label: 'DOMAINS', icon: Globe, types: ['Domain'], sev: 'amber' },
  { label: 'URLs', icon: Globe, types: ['URL'], sev: 'rose' },
  { label: 'FILE HASHES', icon: Fingerprint, types: ['MD5', 'SHA1', 'SHA256'], sev: 'amber' },
  { label: 'REFERENCES', icon: FileSearch, types: ['CVE', 'ATT&CK', 'Event ID', 'Email'], sev: 'cyan' },
  { label: 'NETWORK', icon: Server, types: ['ASN', 'MAC'], sev: 'amber' },
  { label: 'WALLET / PHONE', icon: Database, types: ['BTC', 'ETH', 'Phone'], sev: 'cyan' },
]

function SIocCards({ result, onCopy }) {
  const rows = useMemo(() => flatIocRows(result.extracted), [result])
  const total = countIocs(result.extracted)
  if (!rows.length) return null

  return (
    <div className="st-seg st-hero-animate" style={{ animationDelay: '0.3s' }}>
      <div className="st-seg-hd">
        <div className="st-seg-hd-l"><Database />CLASSIFIED EVIDENCE LEDGER</div>
        <div className="st-seg-hd-r">
          <span className="st-panel-count">{total} indicators total</span>
        </div>
      </div>
      <div className="st-ledger">
        <div className="st-ledger-grid">
          {LEDGER_CATEGORIES.map((cat) => {
            const items = rows.filter((r) => cat.types.includes(r.type))
            if (!items.length) return null
            const Icon = cat.icon
            return (
              <div key={cat.label} className="st-cat-panel">
                <div className="st-cat-hd">
                  <div className="st-cat-hd-l">
                    <Icon />
                    <span className="st-cat-hd-lbl">{cat.label}</span>
                  </div>
                  <span className="st-cat-count">{String(items.length).padStart(2, '0')}/{String(items.length).padStart(2, '0')}</span>
                </div>
                <div className="st-cat-body">
                  {items.map((row, i) => {
                    const isHash = ['MD5','SHA1','SHA256'].includes(row.type)
                    return (
                    <div key={i} className="st-cat-item" data-sev={cat.sev}>
                      {isHash ? (
                        <div className="st-cat-item-stacked" style={{ flex: 1, minWidth: 0, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
                          <span className="st-cat-item-type">{row.type}</span>
                          <span className="st-cat-item-val">{row.value}</span>
                        </div>
                      ) : (
                        <>
                          <span className="st-cat-item-val">{row.value}</span>
                          <span className="st-cat-item-badge">{row.type}</span>
                        </>
                      )}
                      <button type="button" className="st-cat-copy" onClick={() => onCopy(row.value, row.type)} title="Copy">
                        <Clipboard />
                      </button>
                    </div>
                    )
                  })}
                </div>
              </div>
            )
          })}
        </div>
      </div>
    </div>
  )
}

function SMitreCoverage({ result }) {
  const allTypes = [result.primaryType, ...(result.secondaryTypes || []).map(t => t.type)]
  const mitreIds = [...new Set(allTypes.map(mitreForType).filter(Boolean))]
  if (!mitreIds.length) return null

  return (
    <div className="st-seg st-hero-animate" style={{ animationDelay: '0.15s' }}>
      <div className="st-seg-hd">
        <div className="st-seg-hd-l"><Shield />MITRE ATT&CK COVERAGE</div>
      </div>
      <div className="st-mitre-summary" style={{ padding: '0.65rem', display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
        {mitreIds.map(id => (
          <span key={id} className="ba-chip ba-status-info">MITRE: {id}</span>
        ))}
      </div>
    </div>
  )
}

/* ── Right rail components ──────────────────────────────────── */

function SMetaPanel({ result }) {
  const meta = result.parsedMeta || {}
  const warnings = result.warnings || []
  return (
    <div className="s-meta">
      <div className="s-meta-hd"><Database />Parse Info</div>
      <div className="s-meta-body">
        <div className="s-meta-row">
          <span className="s-meta-label">Method</span>
          <span className="s-meta-value">{meta.method || "—"}</span>
        </div>
        <div className="s-meta-row">
          <span className="s-meta-label">Source</span>
          <span className="s-meta-value">{meta.source || "—"}</span>
        </div>
        <div className="s-meta-row">
          <span className="s-meta-label">Lines</span>
          <span className="s-meta-value">{meta.line_count || 0}</span>
        </div>
        <div className="s-meta-row">
          <span className="s-meta-label">Chars</span>
          <span className="s-meta-value">{meta.character_count?.toLocaleString() || 0}</span>
        </div>
        <div className="s-meta-row">
          <span className="s-meta-label">JSON objs</span>
          <span className="s-meta-value">{meta.json_objects_detected || 0}</span>
        </div>
        <div className="s-meta-row">
          <span className="s-meta-label">Header flds</span>
          <span className="s-meta-value">{meta.header_fields_detected || 0}</span>
        </div>
        {warnings.length ? warnings.map((w) => (
          <div key={w} className="s-meta-warn"><AlertTriangle /> {w}</div>
        )) : null}
      </div>
    </div>
  )
}

function SRouteCards({ result, setPage }) {
  const routes = result.suggestedRoutes || []
  if (!routes.length) return null

  function handleRoute(route) {
    const payload = {
      target: route.page, page: route.page, type: route.page,
      value: result.primaryType,
      source: "artifact-intake",
      detected_type: result.primaryType,
      normalized_artifacts: result.normalizedArtifacts,
    }
    storePendingArtifact(payload)
    setPage?.(route.page)
  }

  return (
    <div className="s-routes">
      <div className="s-routes-hd"><Flag />Suggested Routes</div>
      <div className="s-routes-body">
        {routes.map((route) => (
          <div key={route.page} className="s-route-item" onClick={() => handleRoute(route)}>
            <ArrowUpRight />
            <span className="s-route-lbl">{route.label}</span>
            <span className="s-route-arrow">→</span>
          </div>
        ))}
      </div>
    </div>
  )
}

/* ── Main column components ─────────────────────────────────── */

function SGuidance({ result }) {
  const has = (result.guidance?.l1?.length || result.guidance?.l2?.length)
  if (!has) return null
  return (
    <div className="s-guide">
      <div className="s-guide-hd"><Info />Analyst Response Guide</div>
      <div className="s-guide-body">
        {result.guidance?.l1?.length ? (
          <div className="s-g-item" data-lvl="l1">
            <div className="s-g-lvl">L1 — Containment</div>
            {result.guidance.l1.map((item) => <p key={item}>{item}</p>)}
          </div>
        ) : null}
        {result.guidance?.l2?.length ? (
          <div className="s-g-item" data-lvl="l2">
            <div className="s-g-lvl">L2 — Investigation</div>
            {result.guidance.l2.map((item) => <p key={item}>{item}</p>)}
          </div>
        ) : null}
      </div>
    </div>
  )
}

function SExport({ result, markdown, json, onCopy }) {
  return (
    <div className="s-export">
      <details>
        <summary>Export</summary>
        <div className="s-export-body">
          <p>{analystSummary(result)} {result.parsedMeta?.limitations || ""}</p>
          <div className="s-export-checks">
            <span><CheckCircle2 />IOCs normalized</span>
            <span><CheckCircle2 />Duplicates removed</span>
            <span><CheckCircle2 />Local only</span>
          </div>
          <div className="s-export-acts">
            <button type="button" className="s-btn" onClick={() => onCopy(markdown, "Markdown report")}><Copy />Copy MD</button>
            <button type="button" className="s-btn" onClick={() => onCopy(json, "Parsed JSON")}><Copy />Copy JSON</button>
            <button type="button" className="s-btn" onClick={() => downloadText("artifact-intake-result.md", markdown, "text/markdown")}><Download />Download MD</button>
            <button type="button" className="s-btn" onClick={() => downloadText("artifact-intake-result.json", json, "application/json")}><Download />Download JSON</button>
          </div>
        </div>
      </details>
    </div>
  )
}

function SActions({ input, setInput, runParse, onCopy, clearInput }) {
  const [editing, setEditing] = useState(false)
  const [editText, setEditText] = useState(input)
  return (
    <div className="s-actions">
      <div className="s-actions-bar">
        <button type="button" className="s-btn" onClick={() => onCopy(input, "Artifact input")}><Copy />COPY</button>
        <button type="button" className="s-btn" onClick={() => { setEditing(!editing); if (!editing) setEditText(input) }}>
          <Edit />{editing ? "CANCEL" : "REPHRASE"}
        </button>
        <button type="button" className="s-btn" onClick={clearInput}><Eraser />CLEAR</button>
      </div>
      {editing ? (
        <div className="s-rephrase">
          <textarea
            className="s-rephrase-input"
            value={editText}
            onChange={(e) => setEditText(e.target.value)}
            rows={8}
            placeholder="Edit the artifact input and re-parse..."
          />
          <button type="button" className="s-btn" onClick={() => { setInput(editText); runParse(editText); setEditing(false) }}>
            <Zap />RE-PARSE
          </button>
        </div>
      ) : null}
    </div>
  )
}

/* ── Main page component ────────────────────────────────────── */

export default function SmartParserPage({ setPage }) {
  const [incomingArtifact] = useState(() => readIncomingArtifact())
  const [initialParse] = useState(() => parseInitialIncomingArtifact(incomingArtifact))
  const [input, setInput] = useState(() => incomingArtifact?.value || "")
  const [result, setResult] = useState(() => initialParse.result)
  const [notice, setNotice] = useState(() => incomingArtifact ? `Loaded ${incomingArtifact.type || "artifact"} from ${incomingArtifact.source || "another BeyondArch tool"}.` : "")
  const [parseError, setParseError] = useState(() => initialParse.error)
  const [parsing, setParsing] = useState(false)
  const [showSummary, setShowSummary] = useState(false)
  const fileRef = useRef(null)

  const markdown = useMemo(() => toMarkdown(result), [result])
  const json = useMemo(() => result ? JSON.stringify(result, null, 2) : "", [result])
  const hasResult = Boolean(result)

  function loadSample(key) {
    const sample = SAMPLE_INPUTS[key]
    if (!sample) return
    setInput(sample.text)
    setResult(null)
    setParseError("")
    setNotice(`${sample.label} sample loaded. Click Parse Artifact to analyze it.`)
  }

  function runParse(nextInput = input) {
    const text = nextInput.trim()
    setNotice("")
    setParseError("")
    if (!text) {
      setResult(null)
      setNotice("Paste an artifact or load a sample to parse.")
      return
    }
    setParsing(true)
    setTimeout(() => {
      try {
        setResult(detectArtifact(nextInput))
        setNotice("")
      } catch (err) {
        setResult(null)
        setParseError(err.message || "Parser failed. The artifact may be malformed or unsupported.")
      }
      setParsing(false)
    }, 300)
  }

  async function handleFile(event) {
    const file = event.target.files?.[0]
    if (!file) return
    const isTextLike = /text|json|xml|csv|yaml|javascript|x-shellscript/i.test(file.type) || /\.(txt|log|json|jsonl|xml|csv|yml|yaml|eml|headers)$/i.test(file.name)
    if (!isTextLike) {
      setNotice("Only text-like files are accepted. Nothing was executed or uploaded.")
      event.target.value = ""
      return
    }
    const text = await file.text()
    setInput(text)
    runParse(text)
    event.target.value = ""
  }

  function clearInput() {
    setInput("")
    setResult(null)
    setParseError("")
    setNotice("")
    requestAnimationFrame(() => document.querySelector(".ba-app")?.scrollTo(0, 0))
  }

  return (
    <WorkbenchPage className={"sp-page" + (!hasResult ? " sp-page-input" : "")}>
      <div className="sp-hero">
        <div className="sp-hero-row">
          <div className="sp-hero-main">
            <div className="sp-hero-title-row">
              <FileSearch className="sp-hero-icon" />
              <h1 className="sp-hero-title">Smart <span className="sp-hero-accent">INTAKE</span></h1>
            </div>
            <p className="sp-hero-sub">Local artifact parser for triage, extraction, and indicator discovery.</p>
          </div>
          <div className="sp-hero-badge">
            <div className="sp-hero-led" />
            <span>LOCAL-FIRST INTEGRITY ACTIVE</span>
          </div>
        </div>
      </div>
      {!hasResult ? (
        <SInput
          input={input} setInput={setInput} fileRef={fileRef} handleFile={handleFile}
          loadSample={loadSample} parseError={parseError} notice={notice}
          runParse={runParse} copyText={copyText} setNotice={setNotice} clearInput={clearInput}
          parsing={parsing}
        />
      ) : (
        <div className="s-output">
          {notice ? <div className="s-notice"><Info />{notice}</div> : null}
          {parseError ? <div className="s-notice" data-tone="error"><AlertTriangle />{parseError}</div> : null}
          <SActions input={input} setInput={setInput} runParse={runParse} onCopy={copyText} clearInput={clearInput} />
          <SVerdict result={result} input={input} />
          <SMitreCoverage result={result} />
          <div className="s-summary-toggle" style={{ padding: '0 0.5rem' }}>
            <button
              type="button"
              className="ba-btn ba-btn-sm"
              onClick={() => setShowSummary(v => !v)}
              style={{ fontSize: '0.75rem' }}
            >
              {showSummary ? 'Hide Summary' : 'Generate Summary'}
            </button>
            {showSummary ? (
              <pre className="s-summary-content" style={{
                marginTop: '0.5rem',
                padding: '0.75rem',
                background: 'rgba(0,0,0,0.25)',
                border: '1px solid rgba(255,255,255,0.08)',
                borderRadius: '6px',
                fontSize: '0.8rem',
                lineHeight: '1.5',
                whiteSpace: 'pre-wrap',
                fontFamily: 'inherit',
                color: 'rgba(255,255,255,0.85)',
              }}>{generateParseSummary(result)}</pre>
            ) : null}
          </div>
          <SFindings signals={result.signals} />
          <SIocCards result={result} onCopy={copyText} />
          <div className="s-grid">
            <div className="s-main">
              <SSecrets items={result.fields?.secrets} />
              <SGuidance result={result} />
              <SExport result={result} markdown={markdown} json={json} onCopy={copyText} />
            </div>
            <div className="s-rail">
              <SRouteCards result={result} setPage={setPage} />
              <SMetaPanel result={result} />
            </div>
          </div>
        </div>
      )}
    </WorkbenchPage>
  )
}
