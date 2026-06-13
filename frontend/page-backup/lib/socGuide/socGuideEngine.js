const WINDOWS_QUICK_GROUPS = [
  {
    id: "auth",
    label: "Authentication",
    ids: ["4624", "4625", "4634", "4647", "4648", "4672", "4771", "4776", "4778", "4779"],
  },
  {
    id: "process",
    label: "Process / execution",
    ids: ["4688", "4697", "4698", "4702", "7045", "1102"],
  },
  {
    id: "account",
    label: "Account changes",
    ids: ["4720", "4722", "4725", "4726", "4728", "4732", "4738", "4740"],
  },
  {
    id: "object",
    label: "Object / share access",
    ids: ["4656", "4657", "4662", "4663", "5140", "5145", "5156", "5157"],
  },
  {
    id: "sysmon",
    label: "Sysmon core",
    ids: ["sysmon:1", "sysmon:3", "sysmon:7", "sysmon:10", "sysmon:11", "sysmon:13", "sysmon:22"],
  },
]

export const EVENT_QUICK_GROUPS = WINDOWS_QUICK_GROUPS

export const SPL_OBJECTIVES = [
  {
    id: "windows_event",
    label: "Windows Event ID hunt",
    short: "Find specific EventCode activity and key fields.",
    defaults: {
      index: "main",
      sourcetype: "WinEventLog:Security",
      eventCode: "4688",
      keyword: "",
      field: "host",
      value: "",
      groupBy: "host,user,EventCode",
      tableFields: "_time,host,user,EventCode,New_Process_Name,Creator_Process_Name,CommandLine",
      limit: "100",
      time: "24h",
    },
    notes: [
      "Use this when you remember the Event ID and need a starter hunt quickly.",
      "Tune field names to your Splunk TA or normalized dataset.",
      "For process execution, correlate 4688 with Sysmon EventCode=1 when available.",
    ],
  },
  {
    id: "failed_logons",
    label: "Failed logon / spray review",
    short: "Group authentication failures by source, account, and host.",
    defaults: {
      index: "main",
      sourcetype: "WinEventLog:Security",
      eventCode: "4625",
      keyword: "",
      field: "Source_Network_Address",
      value: "",
      groupBy: "Source_Network_Address,Account_Name,host",
      tableFields: "_time,host,Account_Name,Failure_Reason,Source_Network_Address,Logon_Type",
      limit: "30",
      time: "24h",
    },
    notes: [
      "Differentiate password spraying from one-account brute force by grouping source and account together.",
      "Check for EventCode=4624 success after the failures.",
      "Confirm whether failures are from stale service credentials before escalating.",
    ],
  },
  {
    id: "powershell",
    label: "Suspicious PowerShell",
    short: "Look for encoded commands, bypass flags, and download cradles.",
    defaults: {
      index: "main",
      sourcetype: "WinEventLog:Security OR sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
      eventCode: "4688 OR 1",
      keyword: "powershell OR EncodedCommand OR DownloadString OR IEX",
      field: "process_name",
      value: "powershell.exe",
      groupBy: "host,user,parent_process",
      tableFields: "_time,host,user,parent_process,process_name,CommandLine,DestinationIp,QueryName",
      limit: "100",
      time: "24h",
    },
    notes: [
      "Office spawning PowerShell, hidden windows, and policy bypass flags are strong triage leads.",
      "Decode EncodedCommand before deciding severity.",
      "Pivot to DNS and network events if a download or callback is visible.",
    ],
  },
  {
    id: "service_persistence",
    label: "Service / scheduled task persistence",
    short: "Review new services and task creation/update activity.",
    defaults: {
      index: "main",
      sourcetype: "WinEventLog:Security OR WinEventLog:System",
      eventCode: "4697 OR 4698 OR 4702 OR 7045",
      keyword: "",
      field: "host",
      value: "",
      groupBy: "host,user,EventCode",
      tableFields: "_time,host,user,EventCode,Service_Name,Service_File_Name,Task_Name,CommandLine",
      limit: "100",
      time: "7d",
    },
    notes: [
      "Review binary paths, arguments, and account context.",
      "Check whether creation time aligns with an approved install or change window.",
      "Follow the creating process and prior logon events on the same host.",
    ],
  },
  {
    id: "network_ioc",
    label: "Network IOC pivot",
    short: "Search IP/domain/URL indicators across proxy, DNS, firewall, and Sysmon.",
    defaults: {
      index: "main",
      sourcetype: "proxy OR dns OR firewall OR sysmon",
      eventCode: "",
      keyword: "",
      field: "dest_ip OR DestinationIp OR query OR url",
      value: "",
      groupBy: "src_ip,dest_ip,url,query,host",
      tableFields: "_time,host,src_ip,dest_ip,DestinationIp,query,url,user,process_name",
      limit: "100",
      time: "24h",
    },
    notes: [
      "Start with the exact IOC, then broaden to domain, host, or subnet as needed.",
      "For Sysmon, correlate EventCode=3 network connections with EventCode=22 DNS queries.",
      "A hit is not automatically malicious; confirm context and user/process behavior.",
    ],
  },
]

const POWER_SHELL_TOKENS = [
  { match: /-enc\b|-encodedcommand\b/i, label: "EncodedCommand", severity: "medium", meaning: "Command content is base64-encoded, commonly used for obfuscation or compact execution." },
  { match: /iex\b|invoke-expression/i, label: "Invoke-Expression", severity: "high", meaning: "Executes a string as code. Often used in download cradle patterns." },
  { match: /downloadstring|downloadfile|invoke-webrequest|iwr\b|curl\b|wget\b/i, label: "Network download", severity: "medium", meaning: "Attempts to retrieve remote content or a payload." },
  { match: /executionpolicy\s+bypass|-ep\s+bypass/i, label: "Execution policy bypass", severity: "medium", meaning: "Attempts to bypass local PowerShell script execution controls." },
  { match: /windowstyle\s+hidden|-w\s+hidden/i, label: "Hidden window", severity: "medium", meaning: "Tries to reduce user visibility during execution." },
  { match: /frombase64string/i, label: "Base64 decoding", severity: "medium", meaning: "Decodes embedded base64 content inside the command." },
  { match: /new-object\s+net\.webclient|system\.net\.webclient/i, label: "WebClient object", severity: "medium", meaning: "Creates a .NET web client used to download remote content." },
]

const WINDOWS_CMD_TOKENS = [
  { match: /certutil/i, label: "certutil", severity: "medium", meaning: "Certificate utility that can also download or decode files." },
  { match: /bitsadmin/i, label: "bitsadmin", severity: "medium", meaning: "Background transfer utility sometimes abused for payload download." },
  { match: /schtasks/i, label: "schtasks", severity: "medium", meaning: "Creates or modifies scheduled tasks, often relevant for persistence." },
  { match: /reg\s+(add|delete|query)/i, label: "registry command", severity: "medium", meaning: "Reads or modifies registry keys. Check autoruns and security settings." },
  { match: /net\s+user|net\s+localgroup/i, label: "account/group command", severity: "medium", meaning: "Changes or enumerates local users or groups." },
  { match: /wmic\b/i, label: "wmic", severity: "medium", meaning: "WMI command-line usage. Can indicate admin activity or lateral movement." },
  { match: /rundll32|regsvr32|mshta|wscript|cscript/i, label: "LOLBas execution", severity: "medium", meaning: "Windows living-off-the-land binary execution path." },
]

const UNIX_TOKENS = [
  { match: /\bsudo\b/i, label: "sudo", severity: "info", meaning: "Runs a command with elevated privileges." },
  { match: /\bchmod\s+\+x|\bchmod\s+777/i, label: "chmod permission change", severity: "medium", meaning: "Changes file permissions; +x or 777 can enable execution or broad access." },
  { match: /\bcurl\b|\bwget\b/i, label: "download command", severity: "medium", meaning: "Retrieves remote content. Check destination URL and follow-on execution." },
  { match: /\bbash\s+-c|\bsh\s+-c/i, label: "shell execution", severity: "medium", meaning: "Executes a string through a shell." },
  { match: /\bnc\b|\bnetcat\b|\/dev\/tcp/i, label: "network shell utility", severity: "high", meaning: "Can be used for network testing, data transfer, or reverse shell behavior." },
  { match: /\bcrontab\b|\/etc\/cron/i, label: "cron persistence", severity: "medium", meaning: "Reads or modifies scheduled jobs." },
  { match: /\bbase64\s+-d|\bxxd\b|\bopenssl\b/i, label: "decode/transform", severity: "info", meaning: "Transforms encoded data. Useful for scripts, payloads, or secrets." },
]

const URL_RE = /https?:\/\/[^\s'"<>]+/gi
const IP_RE = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g
const HASH_RE = /\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b/g

export function buildSplQuery(config) {
  const filters = []
  const index = config.index?.trim() ? `index=${config.index.trim()}` : ""
  const sourcetype = config.sourcetype?.trim() ? `sourcetype=${wrapIfNeeded(config.sourcetype.trim())}` : ""
  const eventCode = config.eventCode?.trim() ? eventCodeFilter(config.eventCode.trim()) : ""
  const keyword = config.keyword?.trim() ? `(${config.keyword.trim()})` : ""
  const fieldValue = config.field?.trim() && config.value?.trim() ? fieldFilter(config.field.trim(), config.value.trim()) : ""
  filters.push(index, sourcetype, eventCode, keyword, fieldValue)
  const search = filters.filter(Boolean).join(" ").trim() || "search *"
  const tableFields = config.tableFields?.trim() || "_time,host,user,EventCode,message"
  const limit = Number.parseInt(config.limit, 10) || 100
  const groupBy = config.groupBy?.trim()
  const parts = [search]
  if (groupBy) {
    parts.push(`stats count by ${groupBy}`)
    parts.push("sort -count")
    parts.push(`head ${limit}`)
  } else {
    parts.push(`table ${tableFields}`)
    parts.push(`head ${limit}`)
  }
  return parts.join(" | ")
}

export function explainSplQuery(query) {
  const parts = String(query || "").split("|").map((part) => part.trim()).filter(Boolean)
  if (!parts.length) return []
  return parts.map((part, index) => {
    const lower = part.toLowerCase()
    if (index === 0) return { title: "Base search", detail: "Defines the index, sourcetype, EventCode, keyword, or field filters used to retrieve candidate events." }
    if (lower.startsWith("stats")) return { title: "Aggregation", detail: "Groups matching events so repeated sources, users, hosts, or techniques stand out." }
    if (lower.startsWith("sort")) return { title: "Sorting", detail: "Ranks the result set, usually by highest count or newest activity." }
    if (lower.startsWith("head") || lower.startsWith("limit")) return { title: "Result cap", detail: "Limits the visible result set so the query remains readable during triage." }
    if (lower.startsWith("table")) return { title: "Output fields", detail: "Keeps the fields that are most useful for analyst review." }
    if (lower.startsWith("where")) return { title: "Condition", detail: "Adds a conditional filter after events are retrieved." }
    return { title: `Pipeline step ${index + 1}`, detail: "Custom SPL step. Review field names against your local dataset before relying on results." }
  })
}

export function analyzeCommandLocally(command) {
  const text = String(command || "").trim()
  const lowered = text.toLowerCase()
  const shell = detectShell(text)
  const tokenSource = shell === "PowerShell" ? POWER_SHELL_TOKENS : shell === "Windows CMD" ? WINDOWS_CMD_TOKENS : UNIX_TOKENS
  const observations = tokenSource.filter((item) => item.match.test(text)).map((item) => ({
    label: item.label,
    severity: item.severity,
    detail: item.meaning,
  }))

  const urls = unique(text.match(URL_RE) || [])
  const ips = unique(text.match(IP_RE) || []).filter(isReasonableIp)
  const hashes = unique(text.match(HASH_RE) || [])
  const decoded = extractPowershellEncoded(text)
  if (decoded) {
    observations.push({ label: "Decoded PowerShell content", severity: "medium", detail: "An encoded command was decoded locally for safer review." })
  }

  const summary = summarizeCommand(shell, lowered, observations, urls, ips)
  return {
    shell,
    summary,
    observations,
    decoded,
    artifacts: { urls, ips, hashes },
    nextSteps: buildCommandNextSteps(shell, observations, urls, ips, hashes),
  }
}

function detectShell(text) {
  const lower = text.toLowerCase()
  if (lower.includes("powershell") || lower.includes("pwsh") || /\b(get-|set-|new-|invoke-|start-|stop-)/i.test(text) || /-enc\b|-encodedcommand\b/i.test(text)) return "PowerShell"
  if (lower.includes("cmd.exe") || /\b(certutil|bitsadmin|schtasks|reg\s+add|net\s+user|wmic|rundll32|regsvr32|mshta)\b/i.test(text)) return "Windows CMD"
  if (/\b(sudo|bash|sh|curl|wget|chmod|crontab|grep|awk|sed|nc|python3?)\b/i.test(text)) return "Linux / shell"
  return "Unknown shell"
}

function summarizeCommand(shell, lowered, observations, urls, ips) {
  if (!lowered) return "Paste a command to generate a rough analyst explanation."
  if (observations.some((item) => item.severity === "high")) return `${shell} command with high-interest execution or network behavior. Review before running anywhere.`
  if (urls.length || ips.length) return `${shell} command with network indicators. Check destination context and follow-on execution.`
  if (observations.length) return `${shell} command with ${observations.length} notable behavior marker${observations.length === 1 ? "" : "s"}.`
  return `${shell} command. No obvious suspicious token was identified by the local rough explainer.`
}

function buildCommandNextSteps(shell, observations, urls, ips, hashes) {
  const steps = ["Do not execute unknown commands during triage.", "Confirm where the command was observed: endpoint log, email, script, shell history, or alert."]
  if (shell === "PowerShell") steps.push("Decode EncodedCommand content and inspect parent process, user, host, and network follow-on.")
  if (urls.length || ips.length) steps.push("Pivot URL/IP/domain indicators to Safe URL Analyzer or Recon & Exposure.")
  if (hashes.length) steps.push("Send hashes to Attachment Triage or IOC review.")
  if (observations.some((item) => item.label.toLowerCase().includes("scheduled") || item.label.toLowerCase().includes("cron"))) steps.push("Check persistence locations and creation time against expected admin activity.")
  return steps
}

function extractPowershellEncoded(text) {
  const match = text.match(/-(?:enc|encodedcommand|e)\s+([A-Za-z0-9+/=]+)/i)
  if (!match) return ""
  try {
    const binary = window.atob(match[1])
    const utf16 = binaryToUtf16(binary)
    const utf8 = decodeURIComponent(binary.split("").map((char) => `%${char.charCodeAt(0).toString(16).padStart(2, "0")}`).join(""))
    return utf16.split(String.fromCharCode(0)).join("").trim().length >= utf8.trim().length ? utf16 : utf8
  } catch {
    return ""
  }
}

function binaryToUtf16(binary) {
  let output = ""
  for (let index = 0; index < binary.length; index += 2) {
    output += String.fromCharCode(binary.charCodeAt(index) | ((binary.charCodeAt(index + 1) || 0) << 8))
  }
  return output
}

function eventCodeFilter(value) {
  if (/\s+OR\s+/i.test(value)) return `EventCode IN (${value.split(/\s+OR\s+/i).map((item) => item.trim()).filter(Boolean).join(",")})`
  if (value.includes(",")) return `EventCode IN (${value.split(",").map((item) => item.trim()).filter(Boolean).join(",")})`
  return `EventCode=${value}`
}

function fieldFilter(field, value) {
  if (field.includes(" OR ")) {
    return `(${field.split(/\s+OR\s+/i).map((part) => `${part.trim()}=${quoteValue(value)}`).join(" OR ")})`
  }
  return `${field}=${quoteValue(value)}`
}

function quoteValue(value) {
  if (/^[\w.*:-]+$/.test(value)) return value
  return `"${value.replace(/"/g, '\\"')}"`
}

function wrapIfNeeded(value) {
  return value.includes(" OR ") ? `(${value})` : value
}

function unique(items) {
  return [...new Set(items.map((item) => item.replace(/[),.;]+$/g, "")))]
}

function isReasonableIp(ip) {
  return ip.split(".").every((part) => Number(part) >= 0 && Number(part) <= 255)
}
