import { useMemo, useRef, useState } from "react"
import {
  Clipboard,
  Download,
  FileText,
  Route,
  Upload,
} from "lucide-react"
import SendToActions from "../../components/investigation/SendToActions"
import AnalystOutputCard from "../../components/investigation/AnalystOutputCard"
import { downloadText } from "../../lib/domUtils"
import { useSessionState } from "../../lib/useSessionState"
import { WorkbenchHeader, WorkbenchPage, WorkbenchPanel } from "../../components/layout/WorkbenchShell"
import { explainLogEvent } from "../../lib/logEventExplainer"

const SAMPLES = {
  linux_ssh: {
    label: "Linux SSH failed + accepted",
    text: [
      "Apr 25 10:10:10 arch sshd[123]: Failed password for invalid user admin from 8.8.8.8 port 4444 ssh2",
      "Apr 25 10:10:20 arch sshd[124]: Failed password for root from 8.8.8.8 port 4445 ssh2",
      "Apr 25 10:11:00 arch sshd[125]: Accepted password for root from 8.8.8.8 port 4446 ssh2",
    ].join("\n"),
  },
  windows_4688: {
    label: "Windows 4688 EncodedCommand",
    text: [
      "EventID: 4688",
      "New Process Name: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
      "Command Line: powershell.exe -NoP -W Hidden -EncodedCommand SQBFAFgA",
      "Subject User Name: krish",
      "Computer: DESKTOP-01",
    ].join("\n"),
  },
  windows_1102: {
    label: "Windows 1102 log cleared",
    text: ["EventID: 1102", "The audit log was cleared.", "Subject User Name: admin", "Computer: WIN-SRV-01"].join("\n"),
  },
  web_access: {
    label: "Web traversal + sqlmap",
    text: '1.2.3.4 - - [25/Apr/2026:10:12:00 +0530] "GET /../../etc/passwd HTTP/1.1" 404 123 "-" "sqlmap/1.7"',
  },
  suricata: {
    label: "Suricata EVE alert",
    text: '{"timestamp":"2026-04-25T10:12:00.000000+0530","event_type":"alert","src_ip":"1.2.3.4","src_port":4444,"dest_ip":"10.0.0.5","dest_port":80,"proto":"TCP","alert":{"signature":"ET WEB_SERVER Possible SQL Injection Attempt","category":"Web Application Attack","severity":2}}',
  },
  firewall: {
    label: "Firewall deny",
    text: "2026-04-25T10:12:00Z firewall action=deny src_ip=1.2.3.4 src_port=4444 dst_ip=10.0.0.5 dst_port=3389 proto=tcp",
  },
  edr: {
    label: "Generic EDR alert",
    text: "Severity: High\nHost: DESKTOP-01\nUser: krish\nAlert: Suspicious PowerShell execution\nProcess: powershell.exe\nCommandLine: powershell.exe -NoP -W Hidden -EncodedCommand SQBFAFgA\nAction: blocked",
  },
  user_agent: {
    label: "User-Agent list",
    text: ["sqlmap/1.7", "curl/8.4.0", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36", "python-requests/2.31"].join("\n"),
  },
}

const WINDOWS_EVENT_LABELS = {
  4624: "Successful logon",
  4625: "Failed logon",
  4672: "Special privileges assigned",
  4688: "Process creation",
  4720: "User created",
  4726: "User deleted",
  4732: "User added to group",
  7045: "Service installed",
  1102: "Audit log cleared",
}

const HIGH_RISK_PORTS = new Set(["22", "23", "3389", "445", "135", "139", "1433", "3306", "5432", "6379", "9200", "27017"])
const LOLBINS = ["powershell", "cmd", "wscript", "cscript", "mshta", "rundll32", "regsvr32", "certutil", "bitsadmin", "schtasks", "net", "net1", "whoami"]
const SUSPICIOUS_FLAGS = ["-encodedcommand", "-nop", "-w hidden", "/c", "/download", "invoke-webrequest", "iex"]
const WEB_ATTACK_PATTERNS = [
  ["Path traversal", /\.\.\/|\.\.%2f|\/etc\/passwd/i, "High"],
  ["SQL injection pattern", /union\s+select|or\s+1=1|sqlmap/i, "High"],
  ["XSS pattern", /<script|javascript:/i, "Medium"],
  ["Admin path access", /\/(?:admin|login|wp-admin|phpmyadmin)\b/i, "Medium"],
  ["Sensitive file extension", /\.(?:php|aspx|jsp|bak|zip|sql|env)(?:\?|$|\/)/i, "Medium"],
]


const QUERY_PROFILES = {
  web: {
    label: "Web access",
    description: "HTTP access logs, reverse proxy logs, WAF hits, and app gateway telemetry.",
    fields: [
      ["src_ip", "Source IP"], ["method", "Method"], ["path", "Path contains"], ["status", "Status"], ["user_agent", "User agent"], ["time", "Time window"],
    ],
    defaults: { method: "GET", status: "500", path: "/admin" },
  },
  auth: {
    label: "Auth logs",
    description: "Linux sshd, Windows logon, VPN, IAM, and identity provider events.",
    fields: [
      ["username", "Username"], ["src_ip", "Source IP"], ["result", "Result"], ["service", "Service"], ["host", "Host"], ["time", "Time window"],
    ],
    defaults: { result: "failed", service: "sshd" },
  },
  dns: {
    label: "DNS logs",
    description: "Resolver, DNS firewall, and passive DNS query telemetry.",
    fields: [
      ["query", "Query/domain"], ["record_type", "Record type"], ["rcode", "Response code"], ["client_ip", "Client IP"], ["time", "Time window"],
    ],
    defaults: { record_type: "A", rcode: "NXDOMAIN" },
  },
  firewall: {
    label: "Firewall",
    description: "Network firewall, cloud security group, IDS flow, and deny/allow records.",
    fields: [
      ["src_ip", "Source IP"], ["dst_ip", "Destination IP"], ["dst_port", "Destination port"], ["action", "Action"], ["protocol", "Protocol"], ["time", "Time window"],
    ],
    defaults: { action: "deny", protocol: "tcp", dst_port: "3389" },
  },
  proxy: {
    label: "Proxy",
    description: "URL filtering, web proxy, secure web gateway, and egress traffic logs.",
    fields: [
      ["user", "User"], ["src_ip", "Source IP"], ["url", "URL contains"], ["domain", "Domain"], ["category", "Category"], ["action", "Action"],
    ],
    defaults: { action: "allowed", category: "uncategorized" },
  },
  json: {
    label: "Generic JSON",
    description: "Structured EDR, cloud, application, or custom JSON events.",
    fields: [
      ["field", "Field"], ["value", "Value"], ["severity", "Severity"], ["host", "Host"], ["user", "User"], ["time", "Time window"],
    ],
    defaults: { severity: "high" },
  },
}

function escapeQueryValue(value = "") {
  return String(value).replaceAll('"', '\\"').trim()
}

function queryParts(fields = {}) {
  return Object.entries(fields).filter(([, value]) => String(value || "").trim()).map(([key, value]) => [key, escapeQueryValue(value)])
}

function buildQueries(profile, fields = {}) {
  const parts = queryParts(fields)
  const spl = parts.length ? `index=* sourcetype=${profile} ${parts.map(([key, value]) => `${key}="${value}"`).join(" ")}` : `index=* sourcetype=${profile}`
  const kql = parts.length ? parts.map(([key, value]) => `${key}: "${value}"`).join(" and ") : "*"
  const sigmaCondition = parts.length ? parts.map(([key]) => key).join(" and ") : "selection"
  const sigma = [
    "selection:",
    ...(parts.length ? parts.map(([key, value]) => `  ${key}|contains: "${value}"`) : ["  message|exists: true"]),
    `condition: ${sigmaCondition}`,
  ].join("\n")
  const sql = parts.length ? `SELECT * FROM logs WHERE ${parts.map(([key, value]) => `${key} LIKE '%${value.replaceAll("'", "''")}%'`).join(" AND ")};` : "SELECT * FROM logs LIMIT 100;"
  return { spl, kql, sigma, sql }
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

function severityWeight(severity = "") {
  return { Critical: 5, High: 4, Medium: 3, Low: 2, Info: 1 }[severity] || 0
}

function severityClass(severity = "") {
  if (["Critical", "High"].includes(severity)) return "ba-status-danger"
  if (severity === "Medium") return "ba-status-warning"
  if (severity === "Low") return "ba-status-info"
  return "ba-status-local"
}

function addSignal(signals, event, { title, severity = "Info", evidence, why, action, mitre = [] }) {
  signals.push({
    title,
    severity,
    evidence: evidence || event.message || event.raw || "Observed in provided logs.",
    why,
    recommended_action: action,
    event_id: event.id,
    source: event.source,
    mitre,
  })
}

function extractEntities(text = "", events = []) {
  const combined = text
  const ips = uniq((combined.match(/\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b/g) || []).map((value) => ({ value, normalized: value })))
  const urls = uniq((combined.match(/\bhttps?:\/\/[^\s"'<>]+/gi) || []).map((value) => ({ value, normalized: value.replace(/[),.;]+$/g, "") })))
  const emails = uniq((combined.match(/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi) || []).map((value) => ({ value, normalized: value.toLowerCase() })))
  const hashes = uniq((combined.match(/\b[a-f0-9]{32}\b|\b[a-f0-9]{40}\b|\b[a-f0-9]{64}\b/gi) || []).map((value) => ({ value, normalized: value.toLowerCase() })))
  const processLike = new Set((combined.match(/\b[a-z0-9_.-]+\.(?:exe|dll|ps1|bat|cmd|scr|vbs|js|hta)\b/gi) || []).map((value) => value.toLowerCase()))
  const paths = uniq([
    ...(combined.match(/(?:GET|POST|PUT|DELETE|HEAD)\s+(\S+)/gi) || []).map((value) => value.replace(/^(?:GET|POST|PUT|DELETE|HEAD)\s+/i, "")),
    ...(combined.match(/\/(?:[A-Za-z0-9._~!$&'()*+,;=:@%-]+\/?)+/g) || []),
  ].filter((value) => value.startsWith("/") && !/^\/(?:bin|usr|opt|var|etc)\b/.test(value) && !/^\/\d+(?:\.\d+)+$/.test(value)).map((value) => ({ value, normalized: value.replace(/[),.;]+$/g, "") })))
  const domains = uniq([
    ...urls.map((url) => {
      try { return new URL(url.normalized).hostname } catch { return "" }
    }),
    ...(combined.match(/\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b/gi) || []),
  ].filter((item) => item && !item.includes("@") && !/\.(?:php|aspx|jsp|env|bak|zip|sql|exe|dll|ps1|bat|cmd|scr|vbs|js|hta)$/i.test(item) && !processLike.has(item.toLowerCase())).map((value) => ({ value, normalized: value.toLowerCase() })))
  const eventIds = uniq((combined.match(/\b(?:4624|4625|4672|4688|4720|4726|4732|7045|1102)\b/g) || []).map((value) => ({ value, normalized: value })))
  const statusCodes = uniq(events.map((event) => event.status_code).filter(Boolean).map((value) => ({ value, normalized: String(value) })))
  const rawUsers = [
    ...events.map((event) => event.user).filter(Boolean),
    ...(combined.match(/\b(?:invalid user|for|useradd|new user|Subject User Name:|User:)\s+([A-Za-z0-9._-]+)/gi) || []).map((value) => value.split(/\s+/).pop()),
  ]
  const users = uniq(rawUsers.filter((value) => value && !["from", "user", "invalid"].includes(value.toLowerCase())).map((value) => ({ value, normalized: value })))
  const hosts = uniq(events.map((event) => event.host).filter(Boolean).map((value) => ({ value, normalized: value })))
  const processNames = uniq([
    ...events.map((event) => event.process_name).filter(Boolean),
    ...processLike,
  ].filter(Boolean).map((value) => ({ value, normalized: value })))
  const commandLines = uniq([
    ...events.map((event) => event.command_line).filter(Boolean),
    ...(combined.match(/\/(?:bin|usr\/bin|sbin|usr\/sbin)\/[A-Za-z0-9._-]+(?:\s+[^\n]+)?/g) || []),
  ].map((value) => ({ value, normalized: value })))
  const userAgents = uniq(events.map((event) => event.user_agent).filter(Boolean).map((value) => ({ value, normalized: value })))
  const cves = uniq((combined.match(/\bCVE-\d{4}-\d{4,7}\b/gi) || []).map((value) => ({ value, normalized: value.toUpperCase() })))
  const techniques = uniq((combined.match(/\bT\d{4}(?:\.\d{3})?\b/g) || []).map((value) => ({ value, normalized: value })))

  return { ips, urls, domains, paths, emails, hashes, users, hosts, process_names: processNames, command_lines: commandLines, event_ids: eventIds, status_codes: statusCodes, user_agents: userAgents, cves, attack_ids: techniques }
}

function parseKeyValueLine(line) {
  const fields = {}
  for (const match of line.matchAll(/([A-Za-z_][\w.-]*)=(?:"([^"]*)"|([^\s]+))/g)) fields[match[1].toLowerCase()] = match[2] || match[3]
  return fields
}

function parseJsonLine(line, index) {
  try {
    const obj = JSON.parse(line)
    if (!obj || typeof obj !== "object") return null
    const alert = obj.alert || {}
    return {
      id: `event-${index}`,
      timestamp: obj.timestamp || obj["@timestamp"] || "",
      event_type: obj.event_type === "alert" || obj.alert ? "suricata_eve_alert" : obj.event_type || "json_event",
      source: obj.alert ? "Suricata/EVE JSON" : "Structured JSON",
      severity: alert.severity ? (Number(alert.severity) <= 1 ? "High" : Number(alert.severity) === 2 ? "Medium" : "Low") : obj.severity || "Info",
      host: obj.host || obj.hostname || obj.computer || "",
      user: obj.user || obj.username || "",
      src_ip: obj.src_ip || obj.source_ip || obj.client_ip || "",
      dst_ip: obj.dest_ip || obj.dst_ip || obj.destination_ip || "",
      src_port: obj.src_port || "",
      dst_port: obj.dest_port || obj.dst_port || "",
      protocol: obj.proto || obj.protocol || "",
      action: obj.action || obj.flow?.action || "",
      process_name: obj.process_name || obj.process || "",
      command_line: obj.command_line || obj.CommandLine || "",
      file_name: obj.file_name || obj.file || "",
      hash: obj.hash || obj.sha256 || obj.md5 || "",
      url: obj.url || obj.http?.url || "",
      domain: obj.domain || obj.dns?.rrname || "",
      event_id: obj.EventID || obj.event_id || "",
      signature: alert.signature || obj.signature || obj.rule || "",
      category: alert.category || obj.category || "",
      message: alert.signature || obj.message || obj.alert || line,
      raw: line,
    }
  } catch {
    return null
  }
}

function parseLinuxAuth(line, index) {
  if (!/\bsshd\b|sudo:|su:|CRON|systemd|useradd|new user/i.test(line)) return null
  const isoPrefix = line.match(/^(\d{4}-\d{2}-\d{2}T[^\s]+)\s+(\S+)?/)
  const timestamp = line.match(/^([A-Z][a-z]{2}\s+\d{1,2}\s+\d\d:\d\d:\d\d)/)?.[1] || isoPrefix?.[1] || ""
  const host = line.match(/^[A-Z][a-z]{2}\s+\d{1,2}\s+\d\d:\d\d:\d\d\s+(\S+)/)?.[1] || (/^(auth|secure|sshd)$/i.test(isoPrefix?.[2] || "") ? "" : isoPrefix?.[2] || "")
  const srcIp = line.match(/\bfrom\s+((?:\d{1,3}\.){3}\d{1,3})\b/)?.[1] || ""
  const port = line.match(/\bport\s+(\d+)\b/)?.[1] || ""
  const invalidUser = line.match(/invalid user\s+(\S+)/i)?.[1] || ""
  const user = invalidUser || line.match(/\b(?:for|user)\s+(\S+)/i)?.[1] || line.match(/sudo:\s+(\S+)/i)?.[1] || ""
  const accepted = /Accepted password|Accepted publickey/i.test(line)
  const failed = /Failed password/i.test(line)
  const sudoCommand = line.match(/COMMAND=(.+)$/i)?.[1] || ""
  const accountCreated = /new user|useradd/i.test(line)
  return {
    id: `event-${index}`,
    timestamp,
    event_type: failed ? "linux_ssh_failed_login" : accepted ? "linux_ssh_accepted_login" : accountCreated ? "linux_user_created" : /sudo:/i.test(line) ? "linux_sudo" : /su:/i.test(line) ? "linux_su" : "linux_auth",
    source: "Linux/Auth",
    severity: accountCreated ? "High" : failed || invalidUser ? "Medium" : accepted ? "Info" : /sudo:/i.test(line) ? "Medium" : "Low",
    host,
    user: accountCreated ? (line.match(/(?:new user|useradd)\s+([A-Za-z0-9._-]+)/i)?.[1] || user) : user,
    src_ip: srcIp,
    src_port: port,
    action: failed ? "failed" : accepted ? "accepted" : "",
    command_line: sudoCommand,
    message: line,
    raw: line,
  }
}

function parseWindowsBlock(block, index) {
  const eventId = block.match(/(?:EventID|Event ID|Id)\s*[:=]\s*(\d{4})/i)?.[1] || block.match(/<EventID[^>]*>(\d{4})<\/EventID>/i)?.[1] || ""
  if (!eventId && !/\b(?:4624|4625|4672|4688|4720|4726|4732|7045|1102)\b/.test(block)) return null
  const id = eventId || block.match(/\b(?:4624|4625|4672|4688|4720|4726|4732|7045|1102)\b/)?.[0] || ""
  const user = block.match(/Subject User Name\s*[:=]\s*([^\r\n]+)/i)?.[1]?.trim() || block.match(/Account Name\s*[:=]\s*([^\r\n]+)/i)?.[1]?.trim() || ""
  const host = block.match(/Computer\s*[:=]\s*([^\r\n]+)/i)?.[1]?.trim() || block.match(/ComputerName\s*[:=]\s*([^\r\n]+)/i)?.[1]?.trim() || ""
  const processName = block.match(/New Process Name\s*[:=]\s*([^\r\n]+)/i)?.[1]?.trim() || block.match(/Process(?: Name)?\s*[:=]\s*([^\r\n]+)/i)?.[1]?.trim() || ""
  const commandLine = block.match(/Command Line\s*[:=]\s*([^\r\n]+)/i)?.[1]?.trim() || block.match(/CommandLine\s*[:=]\s*([^\r\n]+)/i)?.[1]?.trim() || ""
  const sourceIp = block.match(/Source Network Address\s*[:=]\s*([^\r\n]+)/i)?.[1]?.trim() || ""
  return {
    id: `event-${index}`,
    timestamp: block.match(/(?:TimeCreated|Time|Date)\s*[:=]\s*([^\r\n]+)/i)?.[1]?.trim() || "",
    event_type: `windows_event_${id}`,
    source: "Windows Event",
    severity: ["1102", "7045"].includes(id) ? "High" : id === "4625" ? "Medium" : "Info",
    host,
    user,
    src_ip: sourceIp,
    event_id: id,
    process_name: processName.split("\\").pop() || processName,
    command_line: commandLine,
    message: WINDOWS_EVENT_LABELS[id] || "Windows event observed",
    raw: block,
  }
}

function parseWebAccess(line, index) {
  const match = line.match(/^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"(\S+)\s+([^"]+?)\s+HTTP\/[^"]+"\s+(\d{3})\s+(\S+)(?:\s+"([^"]*)"\s+"([^"]*)")?/)
  const prefixed = line.match(/^(\d{4}-\d{2}-\d{2}T[^\s]+)\s+\S+\s+\S+:\s+(\d{1,3}(?:\.\d{1,3}){3})\s+\S+\s+\S+\s+"(\S+)\s+([^"]+?)\s+HTTP\/[^"]+"\s+(\d{3})\s+(\S+)(?:\s+"([^"]*)"\s+"([^"]*)")?/)
  const m = match || prefixed
  if (!m) return null
  const timestamp = match ? m[2] : m[1]
  const srcIp = match ? m[1] : m[2]
  const method = match ? m[3] : m[3]
  const path = match ? m[4] : m[4]
  const status = match ? m[5] : m[5]
  const userAgent = match ? m[8] || "" : m[8] || ""
  return {
    id: `event-${index}`,
    timestamp,
    event_type: "web_access",
    source: "Web Access",
    severity: Number(status) >= 500 ? "Medium" : Number(status) >= 400 ? "Low" : "Info",
    src_ip: srcIp,
    action: method,
    url: path,
    domain: "",
    status_code: status,
    user_agent: userAgent,
    message: `${method} ${path} ${status}`,
    raw: line,
  }
}

function parseFirewall(line, index) {
  const fields = parseKeyValueLine(line)
  if (!Object.keys(fields).length || !/(src|dst|action|proto|firewall|proxy|allow|deny|block)/i.test(line)) return null
  return {
    id: `event-${index}`,
    timestamp: line.match(/\b\d{4}-\d{2}-\d{2}T[^\s]+/)?.[0] || "",
    event_type: "network_firewall_proxy",
    source: /proxy/i.test(line) ? "Proxy" : "Network/Firewall",
    severity: /deny|block/i.test(fields.action || line) ? "Low" : "Info",
    src_ip: fields.src_ip || fields.src || fields.source || "",
    dst_ip: fields.dst_ip || fields.dst || fields.dest || fields.destination || "",
    src_port: fields.src_port || fields.sport || "",
    dst_port: fields.dst_port || fields.dport || "",
    protocol: fields.proto || fields.protocol || "",
    action: fields.action || "",
    url: fields.url || "",
    domain: fields.domain || fields.host || "",
    user_agent: fields.user_agent || fields.ua || "",
    message: line,
    raw: line,
  }
}

function parseGenericAlert(text, index) {
  if (!/(severity|alert|rule\s*[:=]|process\s*[:=]|commandline|command line|malware|quarantine|blocked|credential theft|lateral movement|suspicious execution|encodedcommand|winword\.exe\s*->\s*powershell\.exe)/i.test(text)) return null
  const field = (name) => text.match(new RegExp(`${name}\\\\s*[:=]\\\\s*([^\\r\\n]+)`, "i"))?.[1]?.trim() || ""
  return {
    id: `event-${index}`,
    timestamp: field("timestamp") || field("time") || "",
    event_type: "generic_edr_siem_alert",
    source: "EDR/SIEM Generic",
    severity: /critical/i.test(text) ? "Critical" : /high/i.test(text) ? "High" : /medium/i.test(text) ? "Medium" : "Info",
    host: field("host") || field("computer"),
    user: field("user") || field("username"),
    process_name: field("process").split("\\").pop(),
    command_line: field("commandline") || field("command line"),
    file_name: field("file"),
    hash: field("hash") || field("sha256") || field("md5"),
    action: field("action"),
    message: field("alert") || field("title") || field("rule") || "Generic alert text",
    raw: text,
  }
}

function parseUserAgentLine(line, index) {
  if (!line.trim() || /\s-\s-\s\[/.test(line) || line.includes("EventID")) return null
  if (!/(mozilla|curl|wget|python-requests|sqlmap|nikto|nmap|powershell|webclient|bot|crawler|spider)/i.test(line)) return null
  return {
    id: `event-${index}`,
    event_type: "user_agent",
    source: "User-Agent",
    severity: /sqlmap|nikto|nmap|curl|wget|python-requests|powershell|webclient/i.test(line) ? "Medium" : "Info",
    user_agent: line.trim(),
    message: line.trim(),
    raw: line,
  }
}

function parseInput(text = "") {
  const events = []
  const lines = text.split(/\r?\n/).filter((line) => line.trim())

  lines.forEach((line, index) => {
    const json = parseJsonLine(line.trim(), index)
    if (json) { events.push(json); return }
    const linux = parseLinuxAuth(line, index)
    if (linux) { events.push(linux); return }
    const web = parseWebAccess(line, index)
    if (web) { events.push(web); return }
    const firewall = parseFirewall(line, index)
    if (firewall) { events.push(firewall); return }
    const userAgent = parseUserAgentLine(line, index)
    if (userAgent) events.push(userAgent)
  })

  const blocks = text.split(/\n\s*\n/).filter((block) => block.trim())
  blocks.forEach((block, index) => {
    const windows = parseWindowsBlock(block, events.length + index)
    if (windows && !events.some((event) => event.raw === windows.raw)) events.push(windows)
    const generic = parseGenericAlert(block, events.length + index + 1000)
    if (generic && !events.some((event) => event.raw === generic.raw)) events.push(generic)
  })

  if (!events.length && text.trim()) {
    events.push({
      id: "event-0",
      event_type: "mixed_unknown_text",
      source: "Mixed/Unknown",
      severity: "Info",
      message: "Unstructured text parsed for entities only.",
      raw: text,
    })
  }
  return events
}

function classify(text, events) {
  const sources = new Set(events.map((event) => event.source))
  const reasons = []
  let primary = "Mixed / Unknown Text"
  let family = "Unknown / Mixed Artifact"
  let score = 25
  if (sources.size > 1) {
    primary = "Mixed Logs / Alerts"
    const families = []
    if (sources.has("Linux/Auth")) families.push("Linux Auth")
    if (sources.has("Web Access")) families.push("Web Access")
    if (sources.has("EDR/SIEM Generic")) families.push("Alert Text")
    if (sources.has("Windows Event")) families.push("Windows Event")
    if (sources.has("Suricata/EVE JSON")) families.push("Network Alert")
    if (sources.has("Network/Firewall") || sources.has("Proxy")) families.push("Network/Firewall")
    family = families.join(", ") || "Mixed"
    score = 90
    reasons.push(`${sources.size} log/alert families were parsed from the provided input.`)
  }
  else if (sources.has("Suricata/EVE JSON")) { primary = "Suricata / EVE Alert"; family = "Network Alert"; score = 95; reasons.push("Structured JSON alert fields were parsed.") }
  else if (sources.has("Windows Event")) { primary = "Windows Event / Endpoint Alert"; family = "Windows Event"; score = 90; reasons.push("Windows Event ID structure was observed.") }
  else if (sources.has("Linux/Auth")) { primary = "Linux Auth / SSH Log"; family = "Linux/Auth"; score = 88; reasons.push("sshd/auth log structure was observed.") }
  else if (sources.has("Web Access")) { primary = "Web Access Log"; family = "Web"; score = 86; reasons.push("Apache/Nginx-style access log format was parsed.") }
  else if (sources.has("Network/Firewall") || sources.has("Proxy")) { primary = "Network / Firewall / Proxy Log"; family = "Network"; score = 78; reasons.push("Network key-value fields were parsed.") }
  else if (sources.has("EDR/SIEM Generic")) { primary = "EDR / SIEM Alert Text"; family = "EDR/SIEM"; score = 72; reasons.push("Alert-style fields or severity keywords were observed.") }
  else if (sources.has("User-Agent")) { primary = "User-Agent List"; family = "User-Agent"; score = 70; reasons.push("User-Agent strings were detected.") }
  else if (text.trim()) reasons.push("No strong log structure was detected; entities are still extracted.")

  const secondary = [...sources].filter((source) => source !== "Mixed/Unknown")
  return {
    primary_type: primary,
    artifact_family: family,
    secondary_types: primary === "Mixed Logs / Alerts" ? family.split(", ").filter(Boolean) : secondary,
    confidence_score: Math.min(100, score + Math.min(8, events.length)),
    confidence_label: score >= 80 ? "High" : score >= 55 ? "Medium" : "Low",
    reasons,
    limitations: [
      "Local deterministic parser over user-provided text only.",
      "No live SIEM, external enrichment, or reputation lookup was used.",
      "Candidate mappings and signals need analyst validation.",
    ],
  }
}

function detectSignals(events) {
  const signals = []
  const failedByIp = {}
  const acceptedByIp = {}
  const statusCounts = {}
  const signatureCounts = {}

  for (const event of events) {
    const raw = `${event.raw || ""} ${event.message || ""} ${event.command_line || ""}`.toLowerCase()
    if (event.event_type === "linux_ssh_failed_login") {
      addSignal(signals, event, { title: "Failed SSH login", severity: "Medium", evidence: event.message, why: "Failed logins can indicate credential guessing or user error.", action: "Review source IP, username, and failure volume." })
      if (/invalid user/i.test(event.raw)) addSignal(signals, event, { title: "Invalid user attempt", severity: "Medium", evidence: event.raw, why: "Invalid usernames often appear in SSH guessing activity.", action: "Check repeated source IPs and targeted accounts." })
      if (/for root/i.test(event.raw)) addSignal(signals, event, { title: "Root login attempt", severity: "High", evidence: event.raw, why: "Root login attempts are high-risk authentication events.", action: "Verify SSH policy and source IP context." })
      failedByIp[event.src_ip] = (failedByIp[event.src_ip] || 0) + 1
    }
    if (event.event_type === "linux_ssh_accepted_login") {
      addSignal(signals, event, { title: "Accepted SSH login", severity: event.user === "root" ? "High" : "Info", evidence: event.message, why: "Successful remote logins need ownership/context validation.", action: "Confirm expected user, source IP, and change window." })
      acceptedByIp[event.src_ip] = (acceptedByIp[event.src_ip] || 0) + 1
    }
    if (/sudo:|su:/i.test(event.raw)) addSignal(signals, event, { title: "Privilege command activity", severity: "Medium", evidence: event.raw, why: "sudo/su activity can be normal but should align with expected admin behavior.", action: "Verify user and command context.", mitre: ["T1548"] })
    if (event.event_type === "linux_user_created") addSignal(signals, event, { title: "Local account created", severity: "High", evidence: event.raw, why: "New account creation after suspicious access can indicate persistence or unauthorized administration.", action: "Validate account owner and creation source.", mitre: ["T1136"] })

    if (event.source === "Windows Event") {
      const id = String(event.event_id)
      if (id === "4625") addSignal(signals, event, { title: "Windows failed logon", severity: "Medium", evidence: event.raw, why: "Failed logons may indicate password guessing or access issues.", action: "Review account, host, logon type, and source." })
      if (id === "4624") addSignal(signals, event, { title: "Windows successful logon", severity: "Info", evidence: event.raw, why: "Successful logons are context-dependent.", action: "Verify expected user, host, and logon type." })
      if (id === "4672") addSignal(signals, event, { title: "Special privileges assigned", severity: "Medium", evidence: event.raw, why: "Privileged logons deserve review in suspicious timelines.", action: "Confirm admin activity was expected." })
      if (id === "4688") addSignal(signals, event, { title: "Windows process creation", severity: "Info", evidence: event.command_line || event.raw, why: "Process creation provides endpoint execution context.", action: "Review parent/child process if available.", mitre: ["T1059"] })
      if (id === "7045") addSignal(signals, event, { title: "Service installed", severity: "High", evidence: event.raw, why: "New service installation can indicate persistence.", action: "Escalate if unexpected and review service binary/path.", mitre: ["T1543"] })
      if (id === "1102") addSignal(signals, event, { title: "Audit log cleared", severity: "Critical", evidence: event.raw, why: "Audit log clearing can indicate defense evasion.", action: "Escalate and preserve host evidence.", mitre: ["T1070.001"] })
    }

    if (event.command_line || event.process_name) {
      const command = `${event.process_name || ""} ${event.command_line || ""}`.toLowerCase()
      LOLBINS.filter((name) => command.includes(name)).forEach((name) => addSignal(signals, event, { title: `LOLBin or script interpreter observed: ${name}`, severity: ["powershell", "mshta", "rundll32", "regsvr32", "certutil", "bitsadmin"].includes(name) ? "Medium" : "Low", evidence: event.command_line || event.process_name, why: "Built-in tools can be used legitimately or abused.", action: "Review parent process, user, host, and command intent.", mitre: ["T1059"] }))
      SUSPICIOUS_FLAGS.filter((flag) => command.includes(flag)).forEach((flag) => addSignal(signals, event, { title: `Suspicious command flag: ${flag}`, severity: flag.includes("encoded") ? "High" : "Medium", evidence: event.command_line, why: "Command flags can indicate hidden, encoded, or download behavior.", action: "Send encoded/obfuscated strings to CyberChef and review endpoint context.", mitre: flag.includes("encoded") ? ["T1027", "T1059"] : ["T1059"] }))
    }

    if (event.source === "Web Access") {
      WEB_ATTACK_PATTERNS.forEach(([title, pattern, severity]) => {
        if (pattern.test(event.url || event.raw)) addSignal(signals, event, { title, severity, evidence: event.raw, why: "The HTTP request contains a deterministic web attack/review pattern.", action: "Review request context, source IP, and server response." })
      })
      if (/sqlmap|nikto|nmap|curl|wget|python-requests/i.test(event.user_agent)) addSignal(signals, event, { title: "Suspicious automation user-agent", severity: "Medium", evidence: event.user_agent, why: "Security tools and scripted clients can indicate scanning or testing.", action: "Confirm whether traffic was authorized." })
      statusCounts[event.status_code] = (statusCounts[event.status_code] || 0) + 1
    }

    if (event.source === "Network/Firewall" || event.source === "Proxy") {
      if (/deny|block/i.test(event.action || event.raw)) addSignal(signals, event, { title: "Denied network connection", severity: "Low", evidence: event.raw, why: "Denied traffic may indicate scanning, misconfiguration, or policy enforcement.", action: "Review source, destination, and volume." })
      if (HIGH_RISK_PORTS.has(String(event.dst_port))) addSignal(signals, event, { title: "High-risk destination port", severity: "Medium", evidence: `${event.dst_ip}:${event.dst_port}`, why: "Administrative/database ports require context and access control review.", action: "Validate exposure and approved use." })
      if (event.url && /^\d{1,3}(?:\.\d{1,3}){3}/.test(event.url)) addSignal(signals, event, { title: "Outbound URL uses IP literal", severity: "Low", evidence: event.url, why: "IP-literal destinations can reduce domain-based visibility.", action: "Pivot destination in Recon & Exposure." })
    }

    if (event.source === "Suricata/EVE JSON") {
      addSignal(signals, event, { title: "Suricata alert signature", severity: event.severity, evidence: event.signature || event.message, why: "A network detection alert was present in provided EVE JSON.", action: "Review signature, category, source/destination, and packet context." })
      if (event.signature) signatureCounts[event.signature] = (signatureCounts[event.signature] || 0) + 1
    }

    if (event.source === "EDR/SIEM Generic") {
      if (["High", "Critical"].includes(event.severity)) addSignal(signals, event, { title: "High-severity alert text", severity: event.severity, evidence: event.message, why: "The provided alert text contains high/critical severity.", action: "Validate scope, impacted host, user, and action taken." })
      if (/malware|quarantine|credential|lateral|blocked|suspicious/i.test(raw)) addSignal(signals, event, { title: "EDR/SIEM keyword signal", severity: "Medium", evidence: event.raw, why: "Security alert keywords were observed in the provided text.", action: "Review vendor event details and endpoint evidence." })
    }
  }

  Object.entries(failedByIp).forEach(([ip, count]) => {
    if (count >= 2) signals.push({ title: "Multiple SSH failures from same IP", severity: "High", evidence: `${count} failures from ${ip}`, why: "Repeated failures from one source can indicate guessing activity.", recommended_action: "Search same source IP over a broader time window.", source: "Linux/Auth", mitre: ["T1110"] })
    if (acceptedByIp[ip]) signals.push({ title: "Successful login after failures", severity: "Critical", evidence: `${ip} had failures followed by accepted login`, why: "Success after failures is an escalation-worthy authentication pattern.", recommended_action: "Escalate, verify account owner, source IP, and session activity.", source: "Linux/Auth", mitre: ["T1110"] })
    if (acceptedByIp[ip]) signals.push({ title: "Valid account used after failures", severity: "High", evidence: `${ip} authenticated after failed attempts`, why: "A valid account may have been used after password guessing or credential testing.", recommended_action: "Review session activity and account owner validation.", source: "Linux/Auth", mitre: ["T1078"] })
  })
  Object.entries(statusCounts).forEach(([status, count]) => {
    if (["401", "403", "404"].includes(status) && count >= 3) signals.push({ title: `Repeated HTTP ${status}`, severity: "Low", evidence: `${count} events`, why: "Repeated denial/not-found responses can indicate probing.", recommended_action: "Group by source IP and path.", source: "Web Access", mitre: [] })
  })
  Object.entries(signatureCounts).forEach(([signature, count]) => {
    if (count > 1) signals.push({ title: "Repeated alert signature", severity: "Medium", evidence: `${signature}: ${count} times`, why: "Repeated signatures can indicate ongoing activity or noisy detection.", recommended_action: "Group by source, destination, and time.", source: "Suricata/EVE JSON", mitre: [] })
  })
  return signals.sort((a, b) => severityWeight(b.severity) - severityWeight(a.severity))
}

function mitreCandidates(signals) {
  const candidates = []
  const add = (id, name, evidence) => {
    if (!candidates.some((item) => item.id === id)) candidates.push({ id, name, evidence, wording: "Candidate mapping. Needs analyst validation." })
  }
  signals.forEach((signal) => {
    if (signal.mitre?.includes("T1059")) add("T1059", "Command and Scripting Interpreter", signal.title)
    if (signal.mitre?.includes("T1027")) add("T1027", "Obfuscated Files or Information", signal.title)
    if (signal.mitre?.includes("T1543")) add("T1543", "Create or Modify System Process", signal.title)
    if (signal.mitre?.includes("T1070.001")) add("T1070.001", "Clear Windows Event Logs", signal.title)
    if (signal.mitre?.includes("T1110")) add("T1110", "Brute Force", signal.title)
    if (signal.mitre?.includes("T1078")) add("T1078", "Valid Accounts", signal.title)
    if (signal.mitre?.includes("T1548")) add("T1548", "Abuse Elevation Control Mechanism", signal.title)
    if (signal.mitre?.includes("T1136")) add("T1136", "Create Account", signal.title)
    if (/web|path traversal|sql injection|admin path|automation user-agent|probing/i.test(`${signal.source} ${signal.title}`)) add("T1595", "Active Scanning", signal.title)
  })
  return candidates
}

function buildTimeline(events) {
  const withIndex = events.map((event, index) => ({ ...event, order: index }))
  const dated = withIndex.filter((event) => event.timestamp)
  const undated = withIndex.filter((event) => !event.timestamp)
  const sorted = [...dated].sort((a, b) => timelineSortKey(a.timestamp) - timelineSortKey(b.timestamp))
  return {
    mode: dated.length ? "timestamp" : "input_order",
    confidence: dated.length === events.length ? "High" : dated.length ? "Medium" : "Low",
    first_seen: sorted[0]?.timestamp || "",
    last_seen: sorted.at(-1)?.timestamp || "",
    events: [...sorted, ...undated],
  }
}

function timelineSortKey(timestamp = "") {
  const currentYear = new Date().getFullYear()
  const syslog = timestamp.match(/^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d\d):(\d\d):(\d\d)$/)
  if (syslog) return Date.parse(`${syslog[1]} ${syslog[2]} ${currentYear} ${syslog[3]}:${syslog[4]}:${syslog[5]}`)
  const web = timestamp.match(/^(\d{1,2})\/([A-Z][a-z]{2})\/(\d{4}):(\d\d):(\d\d):(\d\d)/)
  if (web) return Date.parse(`${web[2]} ${web[1]} ${web[3]} ${web[4]}:${web[5]}:${web[6]}`)
  const parsed = Date.parse(timestamp)
  return Number.isNaN(parsed) ? Number.MAX_SAFE_INTEGER : parsed
}

function guidance(classification, signals, entities) {
  const high = signals.some((signal) => ["Critical", "High"].includes(signal.severity))
  const hasCommand = entities.command_lines.length > 0
  const hasUrls = entities.urls.length || entities.domains.length
  return {
    l1: [
      "Identify affected host, user, source IP, destination, event ID, and action from the normalized events.",
      "Verify whether observed login, process, network action, or alert was expected.",
      high ? "Escalate high/critical signals such as log clearing, service install, encoded PowerShell, or success after failures." : "Continue triage and preserve raw log context with the ticket.",
      "Add key IPs, domains, URLs, usernames, hashes, event IDs, and top signals to the ticket.",
      hasUrls ? "Route suspicious URLs/domains/IPs to Recon & Exposure." : "Document that no URL/domain pivot was extracted if confirmed.",
      hasCommand ? "Send encoded or obfuscated command lines to CyberChef." : "If command lines are absent, note the visibility limitation.",
    ],
    l2: [
      "Search the same source IP, user, host, event ID, or signature across a broader time range.",
      "Check successful logins after failed attempts and correlate with session/process activity.",
      "Review process tree, parent process, user context, and network connections for endpoint events.",
      "Correlate firewall, proxy, DNS, and EDR logs for extracted domains, URLs, and IPs.",
      "Build or tune detection logic for repeated patterns and route candidates to Detection & MITRE.",
      "Copy Markdown or export JSON with timeline, evidence, limitations, and disposition.",
      "Validate parser output with source telemetry owner where needed.",
    ],
  }
}

function buildReport(result) {
  if (!result) return ""
  const lines = [
    "# Logs & Alerts Triage Report",
    "",
    "## Summary",
    `- Primary type: ${result.classification.primary_type}`,
    `- Parser basis: ${result.classification.reasons.join("; ") || "local deterministic parsing"}`,
    `- Event count: ${result.events.length}`,
    `- Signal count: ${result.signals.length}`,
    "",
    "## Input Type / Detection Evidence",
    ...result.classification.reasons.map((item) => `- ${item}`),
    "",
    "## Key Entities",
    `- IPs: ${result.entities.ips.map((item) => item.normalized).join(", ") || "None"}`,
    `- URLs: ${result.entities.urls.map((item) => item.normalized).join(", ") || "None"}`,
    `- Domains: ${result.entities.domains.map((item) => item.normalized).join(", ") || "None"}`,
    `- Users: ${result.entities.users.map((item) => item.normalized).join(", ") || "None"}`,
    `- Event IDs: ${result.entities.event_ids.map((item) => item.normalized).join(", ") || "None"}`,
    "",
    "## Suspicious Signals",
    ...(result.signals.length ? result.signals.map((item) => `- ${item.severity}: ${item.title} - ${item.evidence}`) : ["- No suspicious deterministic signals identified."]),
    "",
    "## Timeline",
    `- Timeline mode: ${result.timeline.mode}`,
    ...result.timeline.events.slice(0, 20).map((event) => `- ${event.timestamp || `Input row ${event.order + 1}`}: ${event.event_type} - ${event.message}`),
    "",
    "## MITRE Candidates",
    ...(result.mitre.length ? result.mitre.map((item) => `- ${item.id} ${item.name}: ${item.evidence}. ${item.wording}`) : ["- No candidate mappings generated."]),
    "",
    "## L1 Triage Actions",
    ...result.guidance.l1.map((item) => `- ${item}`),
    "",
    "## L2 Pivot Ideas",
    ...result.guidance.l2.map((item) => `- ${item}`),
    "",
    "## Limitations",
    ...result.classification.limitations.map((item) => `- ${item}`),
    "",
    "## Recommended Disposition",
    result.signals.some((item) => ["Critical", "High"].includes(item.severity)) ? "- Escalate for analyst review and correlate with authoritative telemetry." : "- Continue review and document evidence before closure.",
  ]
  return lines.join("\n")
}

function incidentSummary(result) {
  if (!result) return ""
  const hasSuccessAfterFailure = result.signals.some((signal) => signal.title === "Successful login after failures")
  const hasSudo = result.events.some((event) => event.event_type === "linux_sudo" || event.event_type === "linux_su")
  const hasAccount = result.events.some((event) => event.event_type === "linux_user_created" || event.event_id === "4720")
  const hasWeb = result.signals.some((signal) => /Path traversal|SQL injection|Admin path|automation/i.test(signal.title))
  if (hasSuccessAfterFailure || hasSudo || hasAccount || hasWeb) {
    return [
      hasSuccessAfterFailure ? "Possible SSH compromise sequence detected: failed attempts were followed by a successful login." : null,
      hasSudo ? "Privilege escalation activity appears in the same log set." : null,
      hasAccount ? "Account creation was observed and needs ownership validation." : null,
      hasWeb ? "Web logs also show sensitive path probing or scanner-style activity." : null,
    ].filter(Boolean).join(" ")
  }
  const top = result.signals[0]
  return top ? `${top.title} observed in provided logs. Review entities, timeline, and source context before disposition.` : "No strong incident sequence was detected by local rules. Review parsed events and limitations."
}

function maxSeverity(signals = []) {
  return signals.map((signal) => signal.severity).sort((a, b) => severityWeight(b) - severityWeight(a))[0] || "Info"
}

function entityCount(entities = {}) {
  return Object.values(entities).reduce((sum, values) => sum + values.length, 0)
}

function detectionCategory(signal) {
  const haystack = `${signal.source} ${signal.title}`.toLowerCase()
  if (/ssh|login|logon|auth|valid account|brute|password/.test(haystack)) return "Authentication"
  if (/account|user created|group/.test(haystack)) return "Account Changes"
  if (/web|path|sql|xss|admin|automation|http|probing/.test(haystack)) return "Web Probing"
  if (/alert|edr|siem|suricata|signature/.test(haystack)) return "Alert Text"
  return "Other"
}

function groupedDetections(signals = []) {
  const grouped = new Map()
  signals.forEach((signal) => {
    let key = `${detectionCategory(signal)}:${signal.title}`
    if (signal.title === "Failed SSH login" || signal.title === "Invalid user attempt" || signal.title === "Root login attempt") {
      const ip = signal.evidence.match(/\bfrom\s+((?:\d{1,3}\.){3}\d{1,3})\b/)?.[1] || signal.evidence.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/)?.[0] || "unknown"
      key = `Authentication:SSH failures:${ip}`
    }
    if (!grouped.has(key)) grouped.set(key, { ...signal, category: detectionCategory(signal), examples: [], count: 0 })
    const item = grouped.get(key)
    item.count += 1
    item.examples.push(signal.evidence)
    if (severityWeight(signal.severity) > severityWeight(item.severity)) item.severity = signal.severity
    if (key.includes("SSH failures")) item.title = `Multiple failed SSH attempts from ${key.split(":").at(-1)}`
  })
  return [...grouped.values()].sort((a, b) => severityWeight(b.severity) - severityWeight(a.severity))
}

function mitreDetails(result) {
  if (!result) return []
  const base = [...result.mitre]
  const add = (id, name, evidence, confidence = "Medium", why = "") => {
    if (!base.some((item) => item.id === id)) base.push({ id, name, evidence, confidence, why, wording: "Candidate mapping. Needs analyst validation." })
  }
  if (result.signals.some((signal) => signal.title === "Successful login after failures")) add("T1078", "Valid Accounts", "Successful SSH login after failures", "Medium", "A valid account appears to have been used after failed access attempts.")
  if (result.events.some((event) => event.event_type === "linux_sudo" || event.event_type === "linux_su")) add("T1548", "Abuse Elevation Control Mechanism", "sudo/su activity", "Medium", "Privilege-related commands were observed in the provided logs.")
  if (result.events.some((event) => event.event_type === "linux_user_created")) add("T1136", "Create Account", "new user creation", "Medium", "A local account creation event was observed.")
  return base.map((item) => ({ confidence: item.confidence || "Medium", why: item.why || `Local evidence supports a candidate mapping to ${item.id}.`, ...item }))
}

function analyzeLogs(text) {
  const events = parseInput(text)
  const classification = classify(text, events)
  const entities = extractEntities(text, events)
  const signals = detectSignals(events)
  const timeline = buildTimeline(events)
  const mitre = mitreCandidates(signals)
  const result = {
    source: "user_provided_logs",
    method: "deterministic_local_log_alert_parser",
    classification,
    events,
    entities,
    signals,
    timeline,
    mitre,
    guidance: guidance(classification, signals, entities),
    checked_at: new Date().toISOString(),
  }
  return { ...result, markdown: buildReport(result) }
}

function readLogsPrefill() {
  try {
    const legacy = window.localStorage.getItem("beyondarch.logs.prefill") || ""
    if (legacy) {
      window.localStorage.removeItem("beyondarch.logs.prefill")
      return { value: legacy, source: "SIEM Workspace" }
    }

    const raw = window.localStorage.getItem("beyondarch.pendingArtifact")
    if (!raw) return { value: "", source: "" }
    const artifact = JSON.parse(raw)
    const target = String(artifact?.target || artifact?.page || "").toLowerCase()
    const type = String(artifact?.type || "").toLowerCase()
    const shouldLoad = target === "logs-alerts" || ["log", "logs", "alert", "event", "siem_event", "siem_events", "log_text", "spl-query", "cyberchef-output"].some((token) => type.includes(token))
    if (!shouldLoad) return { value: "", source: "" }
    const value = artifact?.content || artifact?.text || artifact?.raw_input || artifact?.value || artifact?.query || artifact?.event || artifact?.rule || ""
    if (!value) return { value: "", source: "" }
    window.localStorage.removeItem("beyondarch.pendingArtifact")
    return { value: typeof value === "string" ? value : JSON.stringify(value, null, 2), source: artifact?.source || "workflow handoff" }
  } catch {
    return { value: "", source: "" }
  }
}

function visible(value) {
  if (value === undefined || value === null) return ""
  const text = String(value).trim()
  if (!text || text === "N/A" || text === "unknown" || text === "[]" || text === "{}") return ""
  return text
}

function primaryEvent(result) {
  if (!result?.events?.length) return null
  const sorted = [...result.events].sort((a, b) => severityWeight(b.severity) - severityWeight(a.severity))
  return sorted[0]
}

function buildTriageBrief(result, detections) {
  if (!result) return []
  const event = primaryEvent(result)
  const top = detections[0]
  return [
    ["What happened", incidentSummary(result)],
    ["Primary type", result.classification.primary_type],
    ["Severity", maxSeverity(result.signals)],
    ["Source type", event?.source || result.classification.primary_type],
    ["Affected host", event?.host],
    ["User", event?.user],
    ["Source IP", event?.src_ip || event?.source_ip],
    ["Destination", event?.dst_ip || event?.destination_ip || event?.domain || event?.url],
    ["Event ID / Signature", event?.event_id || event?.signature],
    ["Top signal", top?.title],
  ].filter(([, value]) => visible(value))
}

function sendPending(type, value, source = "logs-alerts", target = "") {
  try {
    window.localStorage.setItem("beyondarch.pendingArtifact", JSON.stringify({
      type,
      value,
      content: value,
      source,
      target,
      created_at: new Date().toISOString(),
    }))
  } catch {
    // Ignore localStorage restrictions.
  }
}

function EntityGroup({ title, values = [], onOpen }) {
  const shown = values.filter((item) => visible(item.normalized || item.value || item)).slice(0, 12)
  if (!shown.length) return null
  return (
    <article className="ba-log-entity-group">
      <div><h3>{title}</h3><span>{shown.length}</span></div>
      <div className="ba-log-entity-list">
        {shown.map((item, index) => {
          const value = item.normalized || item.value || item
          return <button key={`${value}-${index}`} onClick={() => onOpen?.(value)}>{value}</button>
        })}
      </div>
    </article>
  )
}

function TriageFieldTable({ rows }) {
  return (
    <div className="ba-log-field-table">
      {rows.map(([label, value]) => <div key={label}><span>{label}</span><b>{value}</b></div>)}
    </div>
  )
}

function DetectionList({ detections = [] }) {
  if (!detections.length) return <p className="ba-empty-state">No high-signal detection explanation was generated. Review parsed fields and raw context.</p>
  return (
    <div className="ba-log-detection-list">
      {detections.slice(0, 8).map((detection) => (
        <article key={`${detection.title}-${detection.evidence}`}>
          <span className={`ba-chip ${severityClass(detection.severity)}`}>{detection.severity}</span>
          <div>
            <h3>{detection.title}</h3>
            <p>{detection.why || detection.evidence}</p>
            {detection.recommended_action ? <strong>{detection.recommended_action}</strong> : null}
          </div>
          <small>{detection.count} hit{detection.count === 1 ? "" : "s"}</small>
        </article>
      ))}
    </div>
  )
}

function EventMiniTable({ events = [], setPage }) {
  if (!events.length) return null
  function sendEvent(event, page) {
    sendPending("log_event", event.raw || event.message || JSON.stringify(event, null, 2), "logs-alerts", page)
    setPage?.(page)
  }
  return (
    <div className="ba-log-events-mini">
      <table>
        <thead><tr><th>Time</th><th>Type</th><th>Host</th><th>User</th><th>Source</th><th>Message</th><th>Actions</th></tr></thead>
        <tbody>
          {events.slice(0, 20).map((event, index) => (
            <tr key={event.id || index}>
              <td>{event.timestamp || "—"}</td>
              <td>{event.event_type || "event"}</td>
              <td>{event.host || "—"}</td>
              <td>{event.user || "—"}</td>
              <td>{event.src_ip || event.source || "—"}</td>
              <td>{event.message || event.raw}</td>
              <td>
                <div className="ba-log-row-actions">
                  <button onClick={() => sendEvent(event, "detection-mitre")}>Detection</button>
                  <button onClick={() => sendEvent(event, "soc-guide")}>SOC Guide</button>
                  <button onClick={() => sendEvent(event, "smart-parser")}>Parser</button>
                </div>
                <SendToActions
                  payload={{ type: "log_event", title: event.event_type || "Normalized log event", value: event.raw || event.message || JSON.stringify(event), summary: event.message || event.raw, severity: event.severity, tags: [event.source, event.severity].filter(Boolean) }}
                  source="Logs & Alerts"
                  setPage={setPage}
                  compact
                />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function RouteActions({ result, text, setPage, copy, report }) {
  const firstUrl = result?.entities?.urls?.[0]?.normalized
  const firstDomain = result?.entities?.domains?.[0]?.normalized
  const firstIp = result?.entities?.ips?.[0]?.normalized
  const command = result?.entities?.command_lines?.[0]?.normalized
  return (
    <div className="ba-log-actions">
      <button onClick={() => { try { window.localStorage.setItem("beyondarch.siem.prefill", text) } catch { /* localStorage may be unavailable. */ } setPage?.("siem") }}><Route size={15} /> Send to SIEM</button>
      {firstUrl ? <button onClick={() => { sendPending("url", firstUrl, "logs-alerts", "safe-url-analyzer"); setPage?.("safe-url-analyzer") }}>URL Analyzer</button> : null}
      {firstDomain || firstIp ? <button onClick={() => { sendPending(firstDomain ? "domain" : "ip", firstDomain || firstIp, "logs-alerts", "recon-exposure"); setPage?.("recon-exposure") }}>Recon</button> : null}
      {command ? <button onClick={() => { sendPending("command", command, "logs-alerts", "soc-guide"); setPage?.("soc-guide") }}>SOC Guide</button> : null}
      <button onClick={() => { sendPending("log_text", text, "logs-alerts", "detection-mitre"); setPage?.("detection-mitre") }}>Detection & MITRE</button>
      <button onClick={() => copy(report, "Report")}><Clipboard size={15} /> Copy report</button>
      <SendToActions
        payload={{ type: "log", title: incidentSummary(result), value: report || text, summary: result.classification?.reasons?.[0] || "Logs & Alerts triage evidence", severity: maxSeverity(result.signals), tags: ["logs", result.classification?.primary_type || "event", maxSeverity(result.signals)] }}
        source="Logs & Alerts"
        setPage={setPage}
        compact
      />
    </div>
  )
}


function LogEventExplainerPanel({ explanation, copy }) {
  if (!explanation) return null
  const tone = ["Critical", "High"].includes(explanation.severity) ? "ba-status-danger" : explanation.severity === "Medium" ? "ba-status-warning" : "ba-status-info"
  return (
    <WorkbenchPanel className="ba-log-explainer-panel">
      <div className="ba-log-explainer-head">
        <div>
          <p className="ba-eyebrow">Log Event Explainer</p>
          <h2>{explanation.title}</h2>
          <p>{explanation.whatHappened}</p>
        </div>
        <span className={`ba-chip ${tone}`}>{explanation.severity} · {explanation.confidence} confidence</span>
      </div>
      <div className="ba-log-explainer-grid">
        <section>
          <h3>Important fields</h3>
          <dl>{explanation.fields.map(([label, value]) => <div key={label}><dt>{label}</dt><dd>{value}</dd></div>)}</dl>
        </section>
        <section>
          <h3>Why it matters</h3>
          <ul>{explanation.whyItMatters.map((item) => <li key={item}>{item}</li>)}</ul>
        </section>
        <section>
          <h3>Suggested pivots</h3>
          <ul>{explanation.pivots.map((item) => <li key={item}>{item}</li>)}</ul>
        </section>
        <section>
          <h3>False-positive notes</h3>
          <ul>{explanation.falsePositiveNotes.map((item) => <li key={item}>{item}</li>)}</ul>
        </section>
      </div>
      <details className="ba-log-explainer-details">
        <summary>Queries, MITRE candidates, and limitations</summary>
        {explanation.querySuggestions.length ? <div><h3>Query starters</h3>{explanation.querySuggestions.map((query) => <pre key={query}>{query}</pre>)}</div> : null}
        {explanation.mitre.length ? <p><strong>MITRE candidates:</strong> {explanation.mitre.join(", ")}</p> : <p><strong>MITRE candidates:</strong> Not enough evidence for a confident technique mapping.</p>}
        <ul>{explanation.limitations.map((item) => <li key={item}>{item}</li>)}</ul>
        <button type="button" className="ba-button-secondary" onClick={() => copy(JSON.stringify(explanation, null, 2), "Explainer")}>Copy explainer JSON</button>
      </details>
    </WorkbenchPanel>
  )
}

function LogQueryBuilder({ copy, setNotice }) {
  const [profile, setProfile] = useState("web")
  const [fields, setFields] = useState(() => ({ ...QUERY_PROFILES.web.defaults }))
  const spec = QUERY_PROFILES[profile] || QUERY_PROFILES.web
  const queries = useMemo(() => buildQueries(profile, fields), [fields, profile])

  function chooseProfile(nextProfile) {
    setProfile(nextProfile)
    setFields({ ...(QUERY_PROFILES[nextProfile]?.defaults || {}) })
  }

  function setField(key, value) {
    setFields((current) => ({ ...current, [key]: value }))
  }

  async function copyQuery(label, value) {
    await copy(value, label)
    setNotice?.(`${label} copied.`)
  }

  return (
    <WorkbenchPanel className="ba-log-query-builder">
      <div className="ba-query-builder-head">
        <div>
          <p className="ba-eyebrow">Query Builder</p>
          <h2>Build log-type-aware queries</h2>
          <p>{spec.description}</p>
        </div>
        <div className="ba-query-profile-row">
          {Object.entries(QUERY_PROFILES).map(([key, item]) => (
            <button key={key} type="button" className={profile === key ? "is-active" : ""} onClick={() => chooseProfile(key)}>{item.label}</button>
          ))}
        </div>
      </div>

      <div className="ba-query-builder-grid">
        <section className="ba-query-field-grid">
          {spec.fields.map(([key, label]) => (
            <label key={key}>
              <span>{label}</span>
              <input value={fields[key] || ""} onChange={(event) => setField(key, event.target.value)} placeholder={key} />
            </label>
          ))}
        </section>
        <section className="ba-query-output-grid">
          {Object.entries(queries).map(([label, value]) => (
            <article key={label}>
              <div><strong>{label.toUpperCase()}</strong><button type="button" onClick={() => copyQuery(label.toUpperCase(), value)}>Copy</button></div>
              <pre>{value}</pre>
            </article>
          ))}
        </section>
      </div>
    </WorkbenchPanel>
  )
}

export default function LogsAlertsPage({ setPage }) {
  const initialPrefill = useMemo(() => readLogsPrefill(), [])
  const [text, setText] = useSessionState("logs-alerts.text", initialPrefill.value)
  const [prefillSource, setPrefillSource] = useState(initialPrefill.source)
  const [result, setResult] = useState(null)
  const [notice, setNotice] = useState(initialPrefill.source ? `Loaded from ${initialPrefill.source}.` : "")
  const fileRef = useRef(null)

  const detections = useMemo(() => groupedDetections(result?.signals || []), [result])
  const mitre = useMemo(() => mitreDetails(result), [result])
  const report = result?.markdown || ""
  const brief = useMemo(() => buildTriageBrief(result, detections), [result, detections])
  const explanation = useMemo(() => (result ? explainLogEvent(text, result) : null), [result, text])

  function run() {
    if (!text.trim()) {
      setResult(null)
      setNotice("Paste an alert or short log snippet before triage.")
      return
    }
    const next = analyzeLogs(text)
    setResult(next)
    setNotice(`Alert triage complete: ${next.events.length} event(s), ${next.signals.length} signal(s), ${entityCount(next.entities)} extracted item(s).`)
  }

  async function copy(content, label) {
    if (!content) return
    await navigator.clipboard.writeText(content)
    setNotice(`${label} copied.`)
  }

  async function loadFile(event) {
    const file = event.target.files?.[0]
    if (!file) return
    const content = await file.text()
    setText(content)
    setPrefillSource("")
    setNotice(`${file.name} loaded locally as text.`)
    event.target.value = ""
  }

  function clearAll() {
    setText("")
    setResult(null)
    setPrefillSource("")
    setNotice("Input cleared.")
  }

  const entityGroups = result ? [
    ["IPs", result.entities.ips, (value) => { sendPending("ip", value, "logs-alerts", "recon-exposure"); setPage?.("recon-exposure") }],
    ["Domains", result.entities.domains, (value) => { sendPending("domain", value, "logs-alerts", "recon-exposure"); setPage?.("recon-exposure") }],
    ["URLs", result.entities.urls, (value) => { sendPending("url", value, "logs-alerts", "safe-url-analyzer"); setPage?.("safe-url-analyzer") }],
    ["Users", result.entities.users],
    ["Hosts", result.entities.hosts],
    ["Processes", result.entities.process_names, (value) => { sendPending("process", value, "logs-alerts", "soc-guide"); setPage?.("soc-guide") }],
    ["Commands", result.entities.command_lines, (value) => { sendPending("command", value, "logs-alerts", "soc-guide"); setPage?.("soc-guide") }],
    ["Hashes", result.entities.hashes, (value) => { sendPending("hash", value, "logs-alerts", "attachment-triage"); setPage?.("attachment-triage") }],
    ["Event IDs", result.entities.event_ids, (value) => { sendPending("event_id", value, "logs-alerts", "soc-guide"); setPage?.("soc-guide") }],
  ] : []

  return (
    <WorkbenchPage className="ba-logs-triage">
      <WorkbenchHeader
        eyebrow="Logs & Alerts"
        title="Single Alert Triage"
        subtitle="Explain one alert, short log block, EDR event, firewall alert, Suricata event, or suspicious snippet. Use SIEM Workspace for large dataset search."
        icon={FileText}
        chips={[
          { label: "local parser", tone: "local" },
          { label: "single alert", tone: "info" },
          { label: "MITRE candidates", tone: "warning" },
        ]}
        actions={result ? <RouteActions result={result} text={text} setPage={setPage} copy={copy} report={report} /> : null}
      />
      <WorkbenchPanel className="ba-log-intake">
        <div className="ba-log-input-card">
          <div className="ba-log-input-title"><p className="ba-eyebrow">Intake</p><h2>Alert or short log block</h2><span>{text.split(/\n/).filter(Boolean).length} line(s)</span></div>
          <textarea value={text} onChange={(event) => { setText(event.target.value); setPrefillSource("") }} placeholder="Paste one focused alert, EDR record, firewall alert, Suricata event, Windows event, Linux auth line, or short related log block." />
        </div>
        <aside className="ba-log-controls">
          <div><p className="ba-eyebrow">Controls</p><h3>Local parser</h3><p>Use this for focused alert triage. Large datasets should go to SIEM Workspace.</p></div>
          <div className="ba-log-control-buttons">
            <button className="ba-primary-action" onClick={run}>Analyze alert</button>
            <button onClick={() => fileRef.current?.click()}><Upload size={15} /> Load file</button>
            <input ref={fileRef} type="file" className="hidden" onChange={loadFile} />
            <button onClick={clearAll}>Clear</button>
          </div>
          <details className="ba-log-samples">
            <summary><FileText size={15} /> Samples</summary>
            <div>{Object.entries(SAMPLES).map(([key, sample]) => <button key={key} onClick={() => { setText(sample.text); setPrefillSource(""); setResult(null); setNotice(`${sample.label} sample loaded.`) }}>{sample.label}</button>)}</div>
          </details>
        </aside>
      </WorkbenchPanel>

      {notice ? <p className="ba-info-banner text-sm">{notice}</p> : null}
      {prefillSource ? <p className="ba-log-source-banner">Loaded from {prefillSource}. Review the text, then analyze.</p> : null}

      {!result ? (
        <section className="ba-log-empty-compact">
          <FileText size={22} />
          <span>Paste a focused alert or load a sample to generate fields, detections, entities, and routing actions.</span>
        </section>
      ) : (
        <>
          <section className="ba-log-decision">
            <div><p className="ba-output-section-eyebrow" style={{ color: "var(--neo-cyan)" }}>Triage summary</p><h2>{incidentSummary(result)}</h2><p>{result.classification.reasons[0] || "Local parser identified event structure and extracted useful fields."}</p></div>
            <span className={`ba-chip ${severityClass(maxSeverity(result.signals))}`}>{maxSeverity(result.signals)}</span>
          </section>

          <AnalystOutputCard
            title="Log output quality"
            verdict={maxSeverity(result.signals)}
            confidence={explanation?.confidence || "local parser"}
            summary={explanation?.whatHappened || incidentSummary(result)}
            evidence={result.signals.slice(0, 5).map((signal) => `${signal.title}: ${signal.evidence}`)}
            limitations={result.classification.limitations || ["Focused parser output. Correlate with full SIEM telemetry before closure."]}
            nextActions={[...(explanation?.pivots || []).slice(0, 3), ...(result.guidance?.l1 || []).slice(0, 2)]}
            metrics={[
              ["Events", result.events.length],
              ["Signals", result.signals.length],
              ["MITRE candidates", mitre.length],
            ]}
          />

          <LogEventExplainerPanel explanation={explanation} copy={copy} />

          <LogQueryBuilder copy={copy} setNotice={setNotice} />

          <div className="grid gap-4 lg:grid-cols-2">
            <WorkbenchPanel>
              <div className="ba-output-section-head"><p className="ba-output-section-eyebrow">Parsed details</p><h2 className="ba-output-section-title">Important fields</h2></div>
              <TriageFieldTable rows={brief} />
            </WorkbenchPanel>
            <WorkbenchPanel>
              <div className="ba-output-section-head"><p className="ba-output-section-eyebrow">Detection explanation</p><h2 className="ba-output-section-title">Why it matters</h2></div>
              <DetectionList detections={detections} />
            </WorkbenchPanel>
          </div>

          <WorkbenchPanel>
            <div className="ba-output-section-head"><p className="ba-output-section-eyebrow">Related entities</p><h2 className="ba-output-section-title">Extracted pivots</h2></div>
            <div className="ba-log-entities-grid">{entityGroups.map(([title, values, onOpen]) => <EntityGroup key={title} title={title} values={values} onOpen={onOpen} />)}</div>
          </WorkbenchPanel>

          <WorkbenchPanel>
            <div className="ba-output-section-head"><p className="ba-output-section-eyebrow">Events</p><h2 className="ba-output-section-title">Normalized event view</h2></div>
            <EventMiniTable events={result.events} setPage={setPage} />
          </WorkbenchPanel>

          {mitre.length ? (
            <details className="ba-final-details ba-workbench-panel">
              <summary>MITRE candidates · {mitre.length}</summary>
              <div className="ba-log-mitre-list">{mitre.map((item) => <article key={item.id}><b>{item.id}</b><span>{item.name}</span><p>{item.evidence}</p></article>)}</div>
            </details>
          ) : null}

          <details className="ba-final-details ba-workbench-panel">
            <summary>Report & raw details</summary>
            <div className="ba-log-report"><button className="ba-button-secondary rounded-xl px-3 py-2 text-sm font-bold" onClick={() => copy(report, "Report")}><Clipboard className="mr-2 inline h-4 w-4" />Copy report</button><button className="ba-button-secondary rounded-xl px-3 py-2 text-sm font-bold" onClick={() => downloadText("logs-alerts-triage.md", report, "text/markdown")}><Download size={15} /> Download MD</button><pre className="mt-3">{report}</pre><pre className="mt-3">{JSON.stringify(result, null, 2)}</pre></div>
          </details>
        </>
      )}
    </WorkbenchPage>
  )
}
