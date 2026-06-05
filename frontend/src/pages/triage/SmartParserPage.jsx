import { useMemo, useRef, useState } from "react"
import {
  AlertTriangle,
  BookOpen,
  Braces,
  CheckCircle2,
  Clipboard,
  Copy,
  Cpu,
  Database,
  Download,
  Eraser,
  FileInput,
  FileSearch,
  FileText,
  FolderOpen,
  Info,
  Mail,
  RefreshCcw,
  Route,
  Scan,
  Search,
  ShieldCheck,
  Tags,
  TerminalSquare,
  Upload,
  Zap,
} from "lucide-react"
import { WorkbenchHeader, WorkbenchPage } from "../../components/layout/WorkbenchShell"
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
  const commandPattern = /\b(?:powershell(?:\.exe)?|pwsh(?:\.exe)?|cmd(?:\.exe)?|rundll32(?:\.exe)?|regsvr32(?:\.exe)?|mshta(?:\.exe)?|wscript(?:\.exe)?|cscript(?:\.exe)?|certutil(?:\.exe)?|bitsadmin(?:\.exe)?|bash|sh)\b[^\n\r]*/gi
  const commands = uniq((text.match(commandPattern) || []).map((value) => ({ value: value.trim(), normalized: value.trim() })))
  const primaryCommand = commands[0]?.normalized || ""
  return {
    commands,
    interpreter: primaryCommand.match(/^\S+/)?.[0] || "",
    hasEncodedCommand: /-enc(?:odedcommand)?\b/i.test(text),
    hasHiddenWindow: /(?:-w(?:indowstyle)?\s+hidden|\/b\b)/i.test(text),
    hasNoProfile: /-nop(?:rofile)?\b/i.test(text),
    hasDownloadCradle: /\b(iwr|invoke-webrequest|wget|curl|downloadstring|webclient|bitsadmin|certutil\s+-urlcache)\b/i.test(text),
    hasLolbin: /\b(rundll32|regsvr32|mshta|wscript|cscript|certutil|bitsadmin)\b/i.test(text),
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

  return {
    urls,
    domains,
    ipv4,
    ipv6,
    cidrs,
    emails,
    hashes: { md5, sha1, sha256 },
    cves,
    attackTechniques: attack,
    windowsEventIds: uniq(eventIds),
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
}

function addSignal(signals, level, title, detail) {
  signals.push({ level, title, detail })
}

function buildSignals({ text, normalized, headers, iocs, commandFields, logFields, ruleFields, userAgents, secrets }) {
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
  if (/hxxp|hxxps|\[\.\]|\[:\]/i.test(text)) addSignal(signals, "Informational", "Defanged content present", "Indicators appear intentionally defanged.")

  for (const url of iocs.urls) {
    try {
      const parsed = new URL(url.normalized)
      if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(parsed.hostname)) addSignal(signals, "Needs Review", "URL uses IP host", parsed.hostname)
      if (/(login|reset|verify|update|account|secure)/i.test(parsed.href)) addSignal(signals, "Suspicious", "URL contains account-action keyword", parsed.href)
      if (parsed.search.length > 80) addSignal(signals, "Suspicious", "Long URL query string", "Long query strings can carry tokens or tracking data.")
      if (/%[0-9a-f]{2}/i.test(url.value)) addSignal(signals, "Informational", "URL encoded characters present", "CyberChef may help decode safely.")
    } catch {
      // Ignore malformed URL fragments.
    }
  }

  if (/failed password/i.test(normalized)) addSignal(signals, "Suspicious", "Failed login observed", "Authentication log includes failed password activity.")
  if (/invalid user/i.test(normalized)) addSignal(signals, "Suspicious", "Invalid username attempt", "SSH/auth log references an invalid user.")
  if (/accepted password/i.test(normalized)) addSignal(signals, "Needs Review", "Successful login observed", "Review whether this login followed failures or used a privileged account.")
  if (/\b(root|administrator|admin)\b/i.test(normalized)) addSignal(signals, "Needs Review", "Privileged account referenced", "Privileged account activity should be correlated.")
  if (/(\/\.\.\/|\.\.\/|\/etc\/passwd|union\s+select|select.+from|<script|%27|%22)/i.test(normalized)) addSignal(signals, "Suspicious", "Web attack pattern in path or query", "Traversal, SQLi, or script-like content appears in text.")
  if (/\b(401|403|404)\b/.test(normalized) && logFields.web_access) addSignal(signals, "Informational", "HTTP error status observed", `Status ${logFields.web_access.status} was parsed from access log.`)
  if (userAgents.some((item) => /sqlmap|curl|python-requests|wget/i.test(item.normalized))) addSignal(signals, "Suspicious", "Automation or scanning user-agent", "User-Agent suggests scripted or security-tool traffic.")
  if (/\b4688\b/.test(normalized)) addSignal(signals, "Informational", "Windows process creation event", "Event ID 4688 indicates process creation telemetry.")
  if (/\b7045\b/.test(normalized)) addSignal(signals, "Needs Review", "Windows service creation event", "Event ID 7045 can indicate service installation.")
  if (/\b1102\b/.test(normalized)) addSignal(signals, "Needs Review", "Windows audit log cleared event", "Event ID 1102 should be reviewed promptly.")

  if (commandFields.hasEncodedCommand) addSignal(signals, "Needs Review", "PowerShell EncodedCommand", "Decode safely; do not execute.")
  if (commandFields.hasHiddenWindow) addSignal(signals, "Suspicious", "Hidden window flag", "Command line requests hidden execution.")
  if (commandFields.hasNoProfile) addSignal(signals, "Suspicious", "NoProfile flag", "PowerShell profile loading is disabled.")
  if (commandFields.hasDownloadCradle) addSignal(signals, "Needs Review", "Download cradle keyword", "Command includes web retrieval or download keywords.")
  if (commandFields.hasLolbin) addSignal(signals, "Needs Review", "LOLBin-style utility", "Command references a Windows living-off-the-land binary.")
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
  const signals = buildSignals({ text: limited, normalized, headers, iocs, commandFields, logFields, ruleFields, userAgents, secrets })
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
  }
}

const PRIMARY_IOC_TITLES = ["URLs", "Domains", "IPv4", "IPv6", "CIDR", "Emails", "MD5", "SHA1", "SHA256", "CVEs", "ATT&CK", "Windows Event IDs"]

function nonEmptyIocEntries(groups = {}, allowed = PRIMARY_IOC_TITLES) {
  return Object.entries(groups).filter(([title, items]) => allowed.includes(title) && Array.isArray(items) && items.length > 0)
}

function iocGroupSummary(entries = []) {
  if (!entries.length) return "No indicators extracted"
  return entries.map(([title, items]) => `${items.length} ${title}`).join(" · ")
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

function artifactRouteForTitle(title) {
  const normalized = String(title || "").toLowerCase()
  if (normalized.includes("url")) return { page: "safe-url-analyzer", label: "URL Analyzer", type: "url" }
  if (normalized.includes("domain")) return { page: "recon-exposure", label: "Recon", type: "domain" }
  if (normalized.includes("ipv") || normalized.includes("cidr")) return { page: "recon-exposure", label: "Recon", type: "ip" }
  if (normalized.includes("md5") || normalized.includes("sha")) return { page: "attachment-triage", label: "Attachment", type: "hash" }
  if (normalized.includes("attack")) return { page: "detection-mitre", label: "Detection", type: "attack_technique" }
  if (normalized.includes("event")) return { page: "soc-guide", label: "SOC Guide", type: "event_id" }
  if (normalized.includes("email")) return { page: "phishing-triage", label: "Phishing", type: "email" }
  return { page: "cyberchef", label: "CyberChef", type: "text" }
}

function displayValue(item) {
  return item?.normalized || item?.value || String(item || "")
}

function compact(value = "", limit = 110) {
  const text = String(value || "").trim()
  if (text.length <= limit) return text
  return `${text.slice(0, Math.floor(limit / 2))}…${text.slice(-Math.floor(limit / 2))}`
}

function artifactCounts(result) {
  if (!result) return []
  const groups = flattenIocGroups(result.extracted)
  return Object.entries(groups)
    .filter(([, items]) => Array.isArray(items) && items.length)
    .map(([label, items]) => ({ label, count: items.length }))
}

function pickRouteValue(route, result, input) {
  if (!result) return { type: "text", value: input }
  const iocs = result.extracted
  if (route.page === "phishing-triage") return { type: "email", value: input }
  if (route.page === "safe-url-analyzer") return { type: "url", value: displayValue(iocs.urls[0]) }
  if (route.page === "recon-exposure") {
    const value = displayValue(iocs.domains[0]) || displayValue(iocs.ipv4[0]) || displayValue(iocs.ipv6[0]) || displayValue(iocs.urls[0])
    return { type: iocs.domains[0] ? "domain" : iocs.ipv4[0] || iocs.ipv6[0] ? "ip" : "url", value }
  }
  if (route.page === "attachment-triage") {
    const value = displayValue(iocs.hashes.sha256[0]) || displayValue(iocs.hashes.sha1[0]) || displayValue(iocs.hashes.md5[0]) || input
    return { type: "hash", value }
  }
  if (route.page === "detection-mitre") return { type: "detection_text", value: input }
  if (route.page === "logs-alerts") return { type: "log_text", value: input }
  if (route.page === "cyberchef") {
    const encoded = result.fields.command_line?.base64Blobs?.[0]?.normalized || result.extracted.urls?.[0]?.normalized || input
    return { type: "text", value: encoded }
  }
  return { type: "text", value: input }
}

function routeReason(route, result) {
  const family = result?.artifactFamily || "artifact"
  const reasons = {
    "phishing-triage": "Email headers/body detected; run sender, auth, URL, and lure analysis.",
    "safe-url-analyzer": "URL artifacts found; inspect destination behavior and guarded metadata.",
    "recon-exposure": "Domain/IP/URL targets found; pivot into DNS, HTTP, TLS, and exposure checks.",
    "logs-alerts": "Log or alert-like text found; parse entities, timeline, and detection signals.",
    "attachment-triage": "Hash or file indicator found; triage as a possible attachment/file artifact.",
    "detection-mitre": "Rule, ATT&CK, or detection text found; map and validate detection logic.",
    cyberchef: "Encoded, defanged, or transformable text found; decode safely without execution.",
  }
  return reasons[route.page] || `Route this ${family} into ${route.label}.`
}

function SmartParserSamples({ onLoadSample }) {
  const sampleGroups = [
    ["phishing", "Phishing email"],
    ["headers", "Email headers"],
    ["iocs", "IOC list"],
    ["windows", "Windows 4688"],
    ["suricata", "Suricata EVE"],
    ["powershell", "PowerShell"],
    ["sigma", "Sigma rule"],
    ["secrets", "Secrets"],
  ]
  const [sampleKey, setSampleKey] = useState("phishing")

  return (
    <div className="ai-sample-picker" aria-label="Sample artifact loader">
      <button type="button" onClick={() => onLoadSample(sampleKey)}>
        <FileText className="h-4 w-4" />Load sample
      </button>
      <select value={sampleKey} onChange={(event) => setSampleKey(event.target.value)} aria-label="Choose sample artifact">
        {sampleGroups.map(([key, label]) => (
          <option key={key} value={key}>{label}</option>
        ))}
      </select>
    </div>
  )
}

function UploadDropzone({ fileRef, onFile }) {
  return (
    <section className="ai-upload-card">
      <header>
        <Upload className="h-4 w-4" />
        <strong>Direct Import</strong>
      </header>
      <button type="button" className="ai-dropzone" onClick={() => fileRef.current?.click()}>
        <Upload className="h-8 w-8" />
        <strong>Drop file or click to browse</strong>
        <span>EML, MSG, TXT, LOG, JSON, CSV</span>
      </button>
      <input ref={fileRef} type="file" className="hidden" onChange={onFile} />
    </section>
  )
}

function EmptyIntakeDesk({ input, setInput, fileRef, handleFile, loadSample, parseError, notice, runParse, copyText, setNotice, clearInput }) {
  return (
    <div className="ai-empty-workspace">
      <section className="ai-intake-desk">
        <FileSearch className="h-10 w-10 text-zinc-500 mx-auto" />
        <div className="ai-desk-label"><Tags className="h-4 w-4 text-cyan-400" /> INTAKE_DESK.md</div>
        <textarea
          value={input}
          onChange={(event) => setInput(event.target.value)}
          placeholder="Paste an email, URL, IOC list, log snippet, Sigma rule, Suricata EVE JSON, command line, or analyst notes..."
          aria-label="Artifact input"
        />
        <div className="ai-intake-actions-row ai-intake-main-actions">
          <button type="button" className="ai-primary-action" onClick={() => runParse()}>
            Parse Artifact <Zap className="h-5 w-5" />
          </button>
          <SmartParserSamples onLoadSample={loadSample} />
          <button type="button" onClick={() => copyText(input, setNotice, "Input")}><Clipboard className="h-4 w-4" />Copy input</button>
          <button type="button" onClick={clearInput}><Eraser className="h-4 w-4" />Clear</button>
          <span><ShieldCheck className="h-4 w-4" />local_session_only</span>
        </div>
      </section>

      <aside className="ai-intake-side">
        <UploadDropzone fileRef={fileRef} onFile={handleFile} />
        <p className="ai-privacy-note"><ShieldCheck className="h-4 w-4" /> Privacy mode enabled. Parsing happens locally in the browser session.</p>
        <section className="ai-intake-guide-card">
          <header><Info className="h-4 w-4" /><strong>What happens next</strong></header>
          <ul>
            <li>Normalize pasted evidence without external calls.</li>
            <li>Group URLs, domains, IPs, hashes, headers, commands, and notes.</li>
            <li>Prepare send-to actions for triage, recon, detection, and case reporting.</li>
          </ul>
        </section>
      </aside>

      {notice ? <p className="ai-inline-notice"><Info className="h-4 w-4" />{notice}</p> : null}
      {parseError ? <p className="ai-inline-error"><AlertTriangle className="h-4 w-4" />{parseError}</p> : null}
    </div>
  )
}

function SourcePreviewHeader({ result, input, onReparse, onClear }) {
  const counts = artifactCounts(result)
  return (
    <section className="ai-current-artifact">
      <div className="ai-artifact-icon"><FileInput className="h-6 w-6" /></div>
      <div>
        <p className="ai-eyebrow">Current Artifact</p>
        <h2>{result.primaryType}</h2>
        <p>Source: Manual Intake · Size: {Math.max(1, Math.round(input.length / 1024))}kb · {iocGroupSummary(counts.map((item) => [item.label, Array(item.count)]))}</p>
      </div>
      <div className="ai-current-actions">
        <button type="button" onClick={onReparse}><RefreshCcw className="h-4 w-4" />Re-parse</button>
        <button type="button" onClick={onClear}><Eraser className="h-4 w-4" />Clear</button>
      </div>
    </section>
  )
}

function ExtractionSummary({ result }) {
  const groups = flattenIocGroups(result.extracted)
  const tiles = [
    { label: "Total Artifacts", count: countIocs(result.extracted), tone: "neutral" },
    { label: "URLs", count: groups.URLs.length, tone: "rose" },
    { label: "Domains", count: groups.Domains.length, tone: "cyan" },
    { label: "IPs", count: groups.IPv4.length + groups.IPv6.length + groups.CIDR.length, tone: "amber" },
    { label: "Hashes", count: groups.MD5.length + groups.SHA1.length + groups.SHA256.length, tone: "emerald" },
  ]

  return (
    <section className="ai-summary-grid" aria-label="Extraction summary">
      {tiles.map((tile) => (
        <article key={tile.label} data-tone={tile.tone}>
          <span>{tile.label}</span>
          <strong>{String(tile.count).padStart(2, "0")}</strong>
        </article>
      ))}
    </section>
  )
}

function confidenceForType(title, result) {
  if (title === "URLs") return result.signals.some((signal) => /url/i.test(signal.title)) ? 94 : 86
  if (title === "Domains") return 88
  if (title.includes("IPv") || title === "CIDR") return 100
  if (title.includes("SHA") || title === "MD5") return 100
  if (title === "Emails") return 92
  return Math.max(70, Math.min(98, result.secondaryTypes?.[0]?.score || 84))
}

function toneForTitle(title) {
  const lower = title.toLowerCase()
  if (lower.includes("url")) return "rose"
  if (lower.includes("domain")) return "cyan"
  if (lower.includes("ipv") || lower.includes("cidr")) return "amber"
  if (lower.includes("md5") || lower.includes("sha")) return "emerald"
  if (lower.includes("email")) return "violet"
  if (lower.includes("attack") || lower.includes("event")) return "violet"
  return "neutral"
}

function routeIconForTitle(title) {
  const target = artifactRouteForTitle(title)
  const icons = {
    "safe-url-analyzer": ShieldCheck,
    "recon-exposure": Search,
    "attachment-triage": FileSearch,
    "detection-mitre": TerminalSquare,
    "phishing-triage": Mail,
    "soc-guide": BookOpen,
    cyberchef: Braces,
  }
  return icons[target.page] || Route
}


function ParserOutputQuality({ result }) {
  const groups = flattenIocGroups(result.extracted)
  const evidenceUsed = [
    ...result.reasons,
    ...(result.secondaryTypes || []).flatMap((item) => item.reasons || []),
  ].slice(0, 7)
  const recommended = result.guidance?.l1?.slice(0, 5) || []
  const limitation = result.parsedMeta?.limitations || "Pattern-based classification. Analyst review is required before taking action."
  return (
    <section className="ai-output-quality">
      <header className="ai-subsection-title"><Cpu className="h-5 w-5" /><FileSearch className="h-5 w-5" />Parser output quality</header>
      <div className="ai-quality-grid">
        <article>
          <span>Detected family</span>
          <strong>{result.artifactFamily}</strong>
          <p>{result.primaryType}</p>
        </article>
        <article>
          <span>Evidence count</span>
          <strong>{countIocs(result.extracted)}</strong>
          <p>{nonEmptyIocEntries(groups).length} artifact group(s)</p>
        </article>
        <article>
          <span>Confidence basis</span>
          <strong>{result.reasons?.length || 1} signal(s)</strong>
          <p>{result.parsedMeta.source} · external lookup: no</p>
        </article>
        <article>
          <span>Limitations</span>
          <strong>Analyst review</strong>
          <p>{limitation}</p>
        </article>
      </div>
      <div className="ai-quality-columns">
        <div>
          <h3>Evidence used</h3>
          <ul>{evidenceUsed.length ? evidenceUsed.map((item) => <li key={item}>{item}</li>) : <li>No high-confidence evidence explanation was generated.</li>}</ul>
        </div>
        <div>
          <h3>Recommended next actions</h3>
          <ul>{recommended.length ? recommended.map((item) => <li key={item}>{item}</li>) : <li>Review the source artifact and add analyst context before routing.</li>}</ul>
        </div>
      </div>
    </section>
  )
}

function ImportantFieldsPanel({ result }) {
  const email = result.fields?.email || {}
  const logs = result.fields?.logs || {}
  const command = result.fields?.command_line || {}
  const rule = result.fields?.rule || {}
  const kvRaw = result.fields?.key_values || []
  const kv = Array.isArray(kvRaw)
    ? kvRaw
    : Object.entries(kvRaw || {}).map(([key, value]) => ({ key, value }))
  const rows = [
    ["Primary type", result.primaryType],
    ["Artifact family", result.artifactFamily],
    ["Subject", email.subject],
    ["From", email.sender],
    ["To", email.recipient],
    ["Reply-To", email.reply_to],
    ["Return-Path", email.return_path],
    ["Authentication", [...(email.authentication || []), ...(email.received_spf || [])].join(" | ")],
    ["Log source", logs.source || logs.sourcetype || logs.event_type],
    ["Command", command.commands?.[0]],
    ["Rule title", rule.title],
    ["Key-values", kv.slice(0, 5).map((item) => `${item.key}=${item.value}`).join(" · ")],
  ].filter(([, value]) => Array.isArray(value) ? value.length : Boolean(value))
  if (!rows.length) return null
  return (
    <section className="ai-important-fields">
      <header className="ai-subsection-title"><Clipboard className="h-5 w-5" />Important fields</header>
      <div className="ai-fields-table">
        {rows.map(([label, value]) => (
          <div key={label}>
            <span>{label}</span>
            <strong>{Array.isArray(value) ? value.join(", ") : String(value)}</strong>
          </div>
        ))}
      </div>
    </section>
  )
}

function GroupedArtifactInventory({ result, setPage, onCopy }) {
  const groups = nonEmptyIocEntries(flattenIocGroups(result.extracted))
  if (!groups.length) return null
  function sendArtifact(title, value) {
    const target = artifactRouteForTitle(title)
    storePendingArtifact({ target: target.page, page: target.page, type: target.type, value, source: "artifact-intake", detected_type: result.primaryType, normalized_artifacts: result.normalizedArtifacts })
    setPage?.(target.page)
  }
  return (
    <section className="ai-grouped-inventory">
      <header className="ai-subsection-title"><Database className="h-5 w-5" />Extracted artifact inventory</header>
      <div className="ai-inventory-grid">
        {groups.map(([title, items]) => (
            <article key={title} data-tone={toneForTitle(title)}>
              <div className="ai-inventory-head">
                <strong>{title}</strong>
                <span>{items.length}</span>
              </div>
              <div className="ai-inventory-list">
                {items.slice(0, 10).map((item) => {
                  const value = displayValue(item)
                  return (
                    <div key={value}>
                      <code>{compact(value, 180)}</code>
                      <div>
                        <button type="button" onClick={() => onCopy(value, title)}>Copy</button>
                        <button type="button" onClick={() => sendArtifact(title, value)}>Send</button>
                      </div>
                    </div>
                  )
                })}
                {items.length > 10 ? <em>+{items.length - 10} more extracted value(s)</em> : null}
              </div>
            </article>
        ))}
      </div>
    </section>
  )
}

function ParserSignalsPanel({ result }) {
  const signals = result.signals || []
  if (!signals.length && !result.warnings?.length) return null
  return (
    <section className="ai-signals-panel">
      <header className="ai-subsection-title"><Scan className="h-5 w-5" /><AlertTriangle className="h-5 w-5" />Signals, warnings, and guidance</header>
      <div className="ai-signals-grid">
        {signals.slice(0, 10).map((signal, index) => (
          <article key={`${signal.title}-${index}`} data-level={signal.level || "Info"}>
            <span>{signal.level || "Signal"}</span>
            <strong>{signal.title}</strong>
            <p>{signal.detail}</p>
          </article>
        ))}
        {(result.warnings || []).map((warning) => (
          <article key={warning} data-level="Needs Review">
            <span>Warning</span>
            <strong>Analyst review required</strong>
            <p>{warning}</p>
          </article>
        ))}
      </div>
      <div className="ai-guidance-blocks">
        <div><h3>L1 handling</h3><ul>{result.guidance.l1.map((item) => <li key={item}>{item}</li>)}</ul></div>
        <div><h3>L2 pivots</h3><ul>{result.guidance.l2.map((item) => <li key={item}>{item}</li>)}</ul></div>
      </div>
    </section>
  )
}

function EvidenceExtractionGrid({ result, setPage, onCopy }) {
  const groups = flattenIocGroups(result.extracted)
  const entries = nonEmptyIocEntries(groups)
  const visibleEntries = entries.flatMap(([title, items]) => items.slice(0, 3).map((item, index) => ({ title, item, index }))).slice(0, 8)

  if (!visibleEntries.length) {
    return (
      <section className="ai-evidence-grid-shell">
        <header className="ai-subsection-title"><Database className="h-5 w-5" />Evidence Extraction Grid</header>
        <div className="ai-empty-result-card">
          <AlertTriangle className="h-7 w-7" />
          <strong>No concrete indicators extracted</strong>
          <p>The parser classified the text, but did not find URLs, domains, IPs, hashes, emails, CVEs, or ATT&CK IDs. Treat it as analyst notes and review manually.</p>
        </div>
      </section>
    )
  }

  function sendArtifact(title, value) {
    const target = artifactRouteForTitle(title)
    storePendingArtifact({
      target: target.page,
      page: target.page,
      type: target.type,
      value,
      source: "artifact-intake",
      detected_type: result.primaryType,
      normalized_artifacts: result.normalizedArtifacts,
    })
    setPage?.(target.page)
  }

  return (
    <section className="ai-evidence-grid-shell">
      <header className="ai-subsection-title"><Database className="h-5 w-5" />Evidence Extraction Grid</header>
      <div className="ai-evidence-grid">
        {visibleEntries.map(({ title, item, index }) => {
          const value = displayValue(item)
          const target = artifactRouteForTitle(title)
          const ToneIcon = routeIconForTitle(title)
          return (
            <article key={`${title}-${value}-${index}`} className="ai-evidence-card" data-tone={toneForTitle(title)}>
              <div className="ai-evidence-card-top">
                <span>{title}</span>
                <div>
                  <small>Confidence</small>
                  <strong>{confidenceForType(title, result)}%</strong>
                </div>
              </div>
              <p>{compact(value, 130)}</p>
              <div className="ai-evidence-meta">
                <span>source: parsed artifact</span>
                <span>type: {target.type}</span>
              </div>
              <div className="ai-evidence-actions">
                <button type="button" onClick={() => sendArtifact(title, value)} title={`Send to ${target.label}`}><ToneIcon className="h-4 w-4" /></button>
                <button type="button" onClick={() => onCopy(value, title)} title="Copy value"><Copy className="h-4 w-4" /></button>
                <button type="button" onClick={() => sendArtifact(title, value)} title="Open workspace"><Route className="h-4 w-4" /></button>
                <button type="button" onClick={() => onCopy(`${title}: ${value}`, "Evidence note")} title="Copy note"><FolderOpen className="h-4 w-4" /></button>
              </div>
            </article>
          )
        })}
      </div>
    </section>
  )
}

function CompactInputPanel({ input, setInput, runParse, clearInput }) {
  return (
    <details className="ai-compact-input">
      <summary>Source artifact preview</summary>
      <textarea value={input} onChange={(event) => setInput(event.target.value)} />
      <div>
        <button type="button" onClick={() => runParse()}><RefreshCcw className="h-4 w-4" />Re-parse edited input</button>
        <button type="button" onClick={clearInput}><Eraser className="h-4 w-4" />Clear and reset</button>
      </div>
    </details>
  )
}

function ReportReadyPanel({ result, markdown, json, onCopy }) {
  const summary = analystSummary(result)
  return (
    <section className="ai-report-ready">
      <div>
        <header>
          <FileText className="h-5 w-5" />
          <h2>Report-Ready Findings Summary</h2>
        </header>
        <p>{summary} {result.parsedMeta.limitations}</p>
        <div className="ai-report-badges">
          <span><CheckCircle2 className="h-4 w-4" />IOCs normalized</span>
          <span><CheckCircle2 className="h-4 w-4" />Duplicates removed</span>
          <span><CheckCircle2 className="h-4 w-4" />External lookups disabled</span>
        </div>
      </div>
      <div className="ai-report-actions">
        <button type="button" onClick={() => onCopy(markdown, "Markdown report")}><Copy className="h-4 w-4" />Copy Markdown</button>
        <button type="button" onClick={() => onCopy(json, "Parsed JSON")}><Copy className="h-4 w-4" />Copy JSON</button>
        <button type="button" onClick={() => downloadText("artifact-intake-result.md", markdown, "text/markdown")}><Download className="h-4 w-4" />Download MD</button>
        <button type="button" onClick={() => downloadText("artifact-intake-result.json", json, "application/json")}><Download className="h-4 w-4" />Download JSON</button>
      </div>
    </section>
  )
}

function RecommendedHandoff({ result, input, setPage }) {
  const routes = result.suggestedRoutes?.slice(0, 4) || []
  if (!routes.length) return null

  function openRoute(route) {
    const picked = pickRouteValue(route, result, input)
    storePendingArtifact({
      ...picked,
      target: route.page,
      page: route.page,
      source: "artifact-intake",
      raw_input: input,
      detected_type: result.primaryType,
      normalized_artifacts: result.normalizedArtifacts,
    })
    setPage?.(route.page)
  }

  return (
    <section className="ai-handoff-grid">
      {routes.map((route, index) => {
        const picked = pickRouteValue(route, result, input)
        return (
          <article key={route.page}>
            <span>{index === 0 ? "Recommended" : "Route option"}</span>
            <h3>{route.label}</h3>
            <p>{routeReason(route, result)}</p>
            {picked.value ? <code>{compact(picked.value, 80)}</code> : null}
            <button type="button" onClick={() => openRoute(route)}><Route className="h-4 w-4" />Open with artifact</button>
          </article>
        )
      })}
    </section>
  )
}

export default function SmartParserPage({ setPage }) {
  const [incomingArtifact] = useState(() => readIncomingArtifact())
  const [initialParse] = useState(() => parseInitialIncomingArtifact(incomingArtifact))
  const [input, setInput] = useState(() => incomingArtifact?.value || "")
  const [result, setResult] = useState(() => initialParse.result)
  const [notice, setNotice] = useState(() => incomingArtifact ? `Loaded ${incomingArtifact.type || "artifact"} from ${incomingArtifact.source || "another BeyondArch tool"}.` : "")
  const [parseError, setParseError] = useState(() => initialParse.error)
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
    try {
      setResult(detectArtifact(nextInput))
      setNotice("Parse complete. Extracted artifacts are ready for review and handoff.")
    } catch (err) {
      setResult(null)
      setParseError(err.message || "Parser failed. The artifact may be malformed or unsupported.")
    }
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
    setNotice("Input cleared.")
  }

  return (
    <WorkbenchPage className="ba-artifact-intake-page">
      <WorkbenchHeader
        eyebrow="Artifact intake"
        title="Artifact Intake"
        subtitle="Detect artifact type, extract useful values, and route evidence into the BeyondArch local analysis pipeline."
        icon={FileSearch}
        chips={[
          { label: "local parser", tone: "local" },
          { label: "type detection", tone: "info" },
          { label: "handoff ready", tone: "success" },
        ]}
      />

      {!hasResult ? (
        <EmptyIntakeDesk
          input={input}
          setInput={setInput}
          fileRef={fileRef}
          handleFile={handleFile}
          loadSample={loadSample}
          parseError={parseError}
          notice={notice}
          runParse={runParse}
          copyText={copyText} setNotice={setNotice}
          clearInput={clearInput}
        />
      ) : (
        <div className="ai-results-workspace">
          <SourcePreviewHeader result={result} input={input} onReparse={() => runParse()} onClear={clearInput} />
          <ExtractionSummary result={result} />
          {notice ? <p className="ai-inline-notice"><Info className="h-4 w-4" />{notice}</p> : null}
          {parseError ? <p className="ai-inline-error"><AlertTriangle className="h-4 w-4" />{parseError}</p> : null}

          <div className="ai-results-main-grid ai-results-main-grid">
            <section className="ai-results-overview">
              <ParserOutputQuality result={result} />
              <ImportantFieldsPanel result={result} />
            </section>

            <GroupedArtifactInventory result={result} setPage={setPage} onCopy={copyText} />

            <section className="ai-results-review-grid">
              <div className="ai-results-review-main">
                <EvidenceExtractionGrid result={result} input={input} setPage={setPage} onCopy={copyText} />
                <ParserSignalsPanel result={result} />
              </div>
              <aside className="ai-results-review-side">
                <RecommendedHandoff result={result} input={input} setPage={setPage} />
              </aside>
            </section>

            <details className="ai-advanced-output">
              <summary>Advanced source preview and export</summary>
              <CompactInputPanel input={input} setInput={setInput} runParse={runParse} clearInput={clearInput} />
              <ReportReadyPanel result={result} markdown={markdown} json={json} onCopy={copyText} />
            </details>
          </div>
        </div>
      )}
    </WorkbenchPage>
  )
}
