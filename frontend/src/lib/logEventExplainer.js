export function explainLogEvent(text = "", result = null) {
  const raw = String(text || "")
  const lower = raw.toLowerCase()
  const events = Array.isArray(result?.events) ? result.events : []
  const signals = Array.isArray(result?.signals) ? result.signals : []
  const entities = result?.entities || {}
  const topEvent = events[0] || {}
  const severity = signals.find((item) => ["Critical", "High"].includes(item.severity))?.severity || signals[0]?.severity || topEvent.severity || "Info"

  const detectedType = topEvent.event_type || result?.classification?.primary_type || detectType(lower)

  const fields = [
    ["Event type", detectedType],
    ["Severity", severity],
    ["Source", topEvent.source || "local parser"],
    ["Host", topEvent.host],
    ["User", topEvent.user],
    ["Source IP", topEvent.src_ip || entities.ips?.[0]?.normalized],
    ["Destination", topEvent.dst_ip || topEvent.domain || entities.domains?.[0]?.normalized],
  ].filter(([, value]) => value)

  const whatHappened = result?.classification?.reasons?.[0]
    || topEvent.message
    || topEvent.raw
    || inferSummary(lower)

  const whyItMatters = signals.length
    ? signals.slice(0, 4).map((signal) => signal.why || signal.title).filter(Boolean)
    : inferWhy(lower)

  const pivots = buildPivots(entities, lower)
  const falsePositiveNotes = buildFalsePositiveNotes(lower, severity)
  const querySuggestions = buildQueries(topEvent, entities, lower)
  const mitre = [...new Set(signals.flatMap((signal) => signal.mitre || []).map((item) => typeof item === "string" ? item : item.id).filter(Boolean))]

  return {
    title: topEvent.event_type ? `Explain: ${labelize(topEvent.event_type)}` : "Log Event Explainer",
    severity,
    confidence: events.length || signals.length ? "medium" : "low",
    whatHappened,
    fields,
    whyItMatters,
    pivots,
    falsePositiveNotes,
    querySuggestions,
    mitre,
    limitations: [
      "This is a local, rule-based explanation, not proof of compromise.",
      "Validate with surrounding events, asset context, and approved telemetry.",
    ],
  }
}

function labelize(value = "") {
  return String(value).replaceAll("_", " ").replace(/\b\w/g, (letter) => letter.toUpperCase())
}

function detectType(lower) {
  if (/sshd|failed password|accepted password/.test(lower)) return "auth log"
  if (/eventid|event id|4688|4625|1102/.test(lower)) return "windows event"
  if (/get\s+\/|post\s+\/|http\/1\./.test(lower)) return "web access log"
  if (/firewall|action=deny|action=allow/.test(lower)) return "firewall log"
  if (/suricata|event_type":"alert/.test(lower)) return "ids alert"
  return "generic log event"
}

function inferSummary(lower) {
  if (/failed password/.test(lower)) return "Authentication failures were observed. Review source, account, timing, and whether a successful login followed."
  if (/accepted password/.test(lower)) return "A successful authentication event was observed. Validate whether the user, source, and timing are expected."
  if (/encodedcommand|-enc\b/.test(lower)) return "A command line contains encoded content, commonly used by both administrators and attackers to hide PowerShell behavior."
  if (/1102|audit log was cleared/.test(lower)) return "Audit log clearing was observed. This can indicate anti-forensics when not tied to approved administration."
  if (/sqlmap|union select|\.\.\//.test(lower)) return "The request contains web attack indicators such as automated scanning, SQL injection, or traversal patterns."
  if (/action=deny|blocked|denied/.test(lower)) return "A network/security control denied or blocked activity. Treat it as a pivot for source and destination context."
  return "A log event was parsed locally. Review the important fields, extracted entities, and suggested pivots before concluding."
}

function inferWhy(lower) {
  const notes = []
  if (/failed password|4625/.test(lower)) notes.push("Repeated authentication failures can indicate password spraying, brute force, or misuse of exposed services.")
  if (/accepted password|4624/.test(lower)) notes.push("A successful login becomes important when it follows failures, comes from an unusual IP, or uses a privileged account.")
  if (/powershell|encodedcommand|-nop|-w hidden/.test(lower)) notes.push("Suspicious command-line flags can indicate script execution, payload staging, or defense evasion.")
  if (/sqlmap|union select|\.\.\//.test(lower)) notes.push("Web attack strings can indicate automated scanning or exploitation attempts against exposed applications.")
  if (/3389|445|22|23/.test(lower)) notes.push("Sensitive service ports should be reviewed for exposure, allow/deny behavior, and expected access paths.")
  return notes.length ? notes : ["The event may be benign or suspicious depending on asset role, user context, source reputation, and nearby events."]
}

function first(items = []) {
  return items.find((item) => item?.normalized || item?.value)?.normalized || items.find((item) => item?.normalized || item?.value)?.value || ""
}

function buildPivots(entities, lower) {
  const pivots = []
  if (first(entities.ips)) pivots.push(`Search source/destination IP ${first(entities.ips)} in SIEM and firewall/proxy logs.`)
  if (first(entities.domains)) pivots.push(`Pivot domain ${first(entities.domains)} in DNS, proxy, URL, and endpoint telemetry.`)
  if (first(entities.users)) pivots.push(`Review user ${first(entities.users)} for recent failures, successful logins, MFA prompts, and endpoint activity.`)
  if (first(entities.hosts)) pivots.push(`Check host ${first(entities.hosts)} for related process, network, and authentication events.`)
  if (/powershell|cmd|bash|sh\b/.test(lower)) pivots.push("Look for parent process, encoded content, downloaded files, and network connections from the same process tree.")
  if (/get\s+\/|post\s+\//.test(lower)) pivots.push("Review HTTP status, user agent, referrer, request path, and nearby requests from the same client.")
  return pivots.length ? pivots : ["Search the extracted entities in SIEM and add relevant findings to the case timeline."]
}

function buildFalsePositiveNotes(lower, severity) {
  const notes = ["Known scanners, patching systems, vulnerability tools, backups, and admin scripts can generate similar activity."]
  if (/sqlmap|nikto|curl|python-requests/.test(lower)) notes.push("Security testing tools may be authorized; validate source IP ownership and test window before escalation.")
  if (/powershell/.test(lower)) notes.push("PowerShell is often legitimate; suspiciousness depends on flags, encoded content, parent process, and destination behavior.")
  if (/failed password|4625/.test(lower)) notes.push("Failed logins may be user error unless volume, source, or account targeting is unusual.")
  if (["Critical", "High"].includes(severity)) notes.push("High severity still requires environment validation before containment actions.")
  return notes
}

function buildQueries(event = {}, entities = {}, lower = "") {
  const queries = []
  const ip = event.src_ip || event.dst_ip || first(entities.ips)
  const user = event.user || first(entities.users)
  const host = event.host || first(entities.hosts)
  const domain = event.domain || first(entities.domains)
  const path = first(entities.paths)
  if (ip) queries.push(`SPL: index=* (${`src_ip="${ip}" OR dest_ip="${ip}" OR client_ip="${ip}"`})`)
  if (user) queries.push(`KQL: user.name : "${user}" or username : "${user}"`)
  if (host) queries.push(`SPL: index=* host="${host}" OR Computer="${host}"`)
  if (domain) queries.push(`KQL: url.domain : "${domain}" or dns.question.name : "${domain}"`)
  if (path) queries.push(`SPL: index=web uri_path="${path}" OR url="*${path}*"`)
  if (/failed password|4625/.test(lower)) queries.push("SPL: index=auth (\"Failed password\" OR EventCode=4625) | stats count by user, src_ip")
  if (/powershell|4688/.test(lower)) queries.push("KQL: process.name : \"powershell.exe\" and process.command_line : (*EncodedCommand* or *NoP*)")
  return queries.slice(0, 6)
}
