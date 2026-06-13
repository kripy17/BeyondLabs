export const DEFAULT_IDS_RULE = {
  engine: "snort",
  action: "alert",
  protocol: "tcp",
  src_ip: "any",
  src_port: "any",
  direction: "->",
  dst_ip: "any",
  dst_port: "80",
  msg: "Possible suspicious HTTP activity",
  content: "union select",
  pcre: "",
  flow: "to_server,established",
  classtype: "web-application-attack",
  priority: "2",
  sid: "1000001",
  rev: "1",
  extra_options: "",
  nocase: true,
  http_uri: true,
  http_header: false,
}

export const IDS_TEMPLATE_LIBRARY = [
  {
    id: "sql-injection-url",
    name: "SQL injection URL pattern",
    description: "Looks for a common SQLi keyword in the HTTP request URI.",
    tags: ["web", "http_uri", "sqli"],
    data: {
      engine: "snort",
      action: "alert",
      protocol: "tcp",
      src_ip: "any",
      src_port: "any",
      direction: "->",
      dst_ip: "any",
      dst_port: "80",
      msg: "Possible SQL injection attempt in URI",
      content: "union select",
      pcre: "",
      flow: "to_server,established",
      classtype: "web-application-attack",
      priority: "1",
      sid: "1000001",
      rev: "1",
      extra_options: "",
      nocase: true,
      http_uri: true,
      http_header: false,
    },
  },
  {
    id: "xss-probe",
    name: "XSS probe",
    description: "Flags simple script-tag probing in HTTP URI traffic.",
    tags: ["web", "http_uri", "xss"],
    data: {
      engine: "snort",
      action: "alert",
      protocol: "tcp",
      src_ip: "any",
      src_port: "any",
      direction: "->",
      dst_ip: "any",
      dst_port: "80",
      msg: "Possible XSS probe in URI",
      content: "<script",
      pcre: "",
      flow: "to_server,established",
      classtype: "web-application-attack",
      priority: "2",
      sid: "1000002",
      rev: "1",
      extra_options: "",
      nocase: true,
      http_uri: true,
      http_header: false,
    },
  },
  {
    id: "powershell-download",
    name: "Suspicious PowerShell download",
    description: "Draft network rule for PowerShell download command fragments in payload or proxy traffic.",
    tags: ["powershell", "payload", "execution"],
    data: {
      engine: "suricata",
      action: "alert",
      protocol: "tcp",
      src_ip: "any",
      src_port: "any",
      direction: "->",
      dst_ip: "any",
      dst_port: "any",
      msg: "Possible PowerShell download command over network",
      content: "DownloadString",
      pcre: "",
      flow: "to_server,established",
      classtype: "trojan-activity",
      priority: "1",
      sid: "1000003",
      rev: "1",
      extra_options: "",
      nocase: true,
      http_uri: false,
      http_header: false,
    },
  },
  {
    id: "web-shell-path",
    name: "Web shell path probe",
    description: "Looks for common shell file names requested from a web server.",
    tags: ["web", "shell", "http_uri"],
    data: {
      engine: "snort",
      action: "alert",
      protocol: "tcp",
      src_ip: "any",
      src_port: "any",
      direction: "->",
      dst_ip: "any",
      dst_port: "80",
      msg: "Possible web shell path probe",
      content: "cmd.php",
      pcre: "/(cmd|shell|webshell|upload)\\.php/i",
      flow: "to_server,established",
      classtype: "web-application-attack",
      priority: "1",
      sid: "1000004",
      rev: "1",
      extra_options: "",
      nocase: true,
      http_uri: true,
      http_header: false,
    },
  },
  {
    id: "credential-post",
    name: "Possible credential post",
    description: "Flags password-like parameter strings in HTTP client-to-server traffic.",
    tags: ["credentials", "http", "post"],
    data: {
      engine: "suricata",
      action: "alert",
      protocol: "tcp",
      src_ip: "any",
      src_port: "any",
      direction: "->",
      dst_ip: "any",
      dst_port: "80",
      msg: "Possible credential parameter in HTTP request",
      content: "password=",
      pcre: "",
      flow: "to_server,established",
      classtype: "policy-violation",
      priority: "2",
      sid: "1000005",
      rev: "1",
      extra_options: "",
      nocase: true,
      http_uri: false,
      http_header: false,
    },
  },
  {
    id: "scanner-user-agent",
    name: "Suspicious user-agent",
    description: "Detects a scanner-style User-Agent string in HTTP headers.",
    tags: ["recon", "scanner", "http_header"],
    data: {
      engine: "snort",
      action: "alert",
      protocol: "tcp",
      src_ip: "any",
      src_port: "any",
      direction: "->",
      dst_ip: "any",
      dst_port: "80",
      msg: "Suspicious scanner user-agent",
      content: "sqlmap",
      pcre: "",
      flow: "to_server,established",
      classtype: "attempted-recon",
      priority: "2",
      sid: "1000006",
      rev: "1",
      extra_options: "",
      nocase: true,
      http_uri: false,
      http_header: true,
    },
  },
  {
    id: "dns-tunneling-query",
    name: "DNS tunneling-like query",
    description: "Draft heuristic for long encoded-looking DNS query fragments.",
    tags: ["dns", "exfiltration", "heuristic"],
    data: {
      engine: "suricata",
      action: "alert",
      protocol: "dns",
      src_ip: "any",
      src_port: "any",
      direction: "->",
      dst_ip: "any",
      dst_port: "53",
      msg: "Possible DNS tunneling style query",
      content: "",
      pcre: "/[A-Za-z0-9+\\/_-]{45,}\\./",
      flow: "to_server",
      classtype: "policy-violation",
      priority: "2",
      sid: "1000007",
      rev: "1",
      extra_options: "",
      nocase: false,
      http_uri: false,
      http_header: false,
    },
  },
  {
    id: "malware-callback-uri",
    name: "Malware callback URI",
    description: "Looks for a simple beacon/callback URI fragment in client-to-server traffic.",
    tags: ["callback", "c2", "http_uri"],
    data: {
      engine: "suricata",
      action: "alert",
      protocol: "tcp",
      src_ip: "$HOME_NET",
      src_port: "any",
      direction: "->",
      dst_ip: "$EXTERNAL_NET",
      dst_port: "80",
      msg: "Possible malware callback URI",
      content: "/gate.php",
      pcre: "",
      flow: "to_server,established",
      classtype: "trojan-activity",
      priority: "1",
      sid: "1000008",
      rev: "1",
      extra_options: "",
      nocase: true,
      http_uri: true,
      http_header: false,
    },
  },
]

export function normalizeIdsPayload(payload = {}) {
  return {
    ...DEFAULT_IDS_RULE,
    ...payload,
    engine: String(payload.engine || DEFAULT_IDS_RULE.engine).toLowerCase(),
    action: String(payload.action || DEFAULT_IDS_RULE.action).toLowerCase(),
    protocol: String(payload.protocol || DEFAULT_IDS_RULE.protocol).toLowerCase(),
    src_ip: String(payload.src_ip || DEFAULT_IDS_RULE.src_ip).trim() || "any",
    src_port: String(payload.src_port || DEFAULT_IDS_RULE.src_port).trim() || "any",
    direction: payload.direction === "<>" ? "<>" : "->",
    dst_ip: String(payload.dst_ip || DEFAULT_IDS_RULE.dst_ip).trim() || "any",
    dst_port: String(payload.dst_port || DEFAULT_IDS_RULE.dst_port).trim() || "any",
    msg: String(payload.msg || DEFAULT_IDS_RULE.msg).trim() || "BeyondArch generated IDS rule",
    content: String(payload.content || ""),
    pcre: String(payload.pcre || ""),
    flow: String(payload.flow || ""),
    classtype: String(payload.classtype || ""),
    priority: String(payload.priority || ""),
    sid: String(payload.sid || ""),
    rev: String(payload.rev || ""),
    extra_options: String(payload.extra_options || ""),
    nocase: Boolean(payload.nocase),
    http_uri: Boolean(payload.http_uri),
    http_header: Boolean(payload.http_header),
  }
}

export function templatesFromBackend(response) {
  const raw = response?.templates || response?.data || response || {}
  const backendTemplates = Object.entries(raw).map(([id, item]) => ({
    id,
    name: item?.name || id.replaceAll("_", " "),
    description: item?.description || "Backend IDS template.",
    tags: item?.tags || ["backend"],
    data: normalizeIdsPayload(item?.data || {}),
  }))
  const merged = [...IDS_TEMPLATE_LIBRARY]
  backendTemplates.forEach((template) => {
    if (!merged.some((item) => item.id === template.id || item.name.toLowerCase() === template.name.toLowerCase())) {
      merged.push(template)
    }
  })
  return merged
}

export function copyText(text, label = "content", setNotice) {
  if (!text) return
  navigator.clipboard?.writeText(String(text))
  setNotice?.(`${label} copied.`)
}

export function downloadText(filename, content, type = "text/plain") {
  const blob = new Blob([content], { type })
  const url = URL.createObjectURL(blob)
  const link = document.createElement("a")
  link.href = url
  link.download = filename
  link.click()
  URL.revokeObjectURL(url)
}

export function buildIdsMarkdown({ rule, result, review, mode }) {
  const warnings = uniqueStrings([...(result?.warnings || []), ...(review?.warnings || [])])
  const explanation = result?.explanation || []
  return [
    "# BeyondArch IDS Rule Review",
    "",
    `Mode: ${mode === "explain" ? "Explain existing rule" : "Build from fields"}`,
    "",
    "## Rule",
    "",
    "```snort",
    rule || "No rule available.",
    "```",
    "",
    "## Explanation",
    "",
    ...listLines(explanation.length ? explanation : ["No explanation generated yet."]),
    "",
    "## Warnings / Review Notes",
    "",
    ...listLines(warnings.length ? warnings : ["No blocking warning detected by the local reviewer."]),
    "",
    "## Coverage",
    "",
    ...listLines(review?.coverage || []),
    "",
    "## Tuning Needed",
    "",
    ...listLines(review?.tuning || []),
    "",
    "## False-Positive Risk",
    "",
    ...listLines(review?.falsePositive || []),
    "",
    "## MITRE / Detection Context",
    "",
    ...listLines((review?.mitre || []).map((item) => `${item.id} ${item.name} — ${item.tactic}. ${item.reason}`)),
    "",
    "Draft only. Validate with Snort or Suricata in a lab before production use.",
  ].join("\n")
}

export function reviewIdsRule({ payload = {}, rule = "", result = null }) {
  const normalized = normalizeIdsPayload(payload)
  const warnings = []
  const coverage = []
  const tuning = []
  const falsePositive = []
  const mitre = []
  const lowerRule = String(rule || "").toLowerCase()
  const content = normalized.content.trim()
  const pcre = normalized.pcre.trim()
  const sid = String(normalized.sid || "").trim()
  const rev = String(normalized.rev || "").trim()

  if (!sid || !/^[0-9]+$/.test(sid)) warnings.push("Missing or non-numeric SID. Use a local SID such as 1000001.")
  if (sid && /^[0-9]+$/.test(sid) && Number(sid) < 1000000) warnings.push("SID appears below the local-rule range. Prefer SID >= 1000000 for local drafts.")
  if (!rev || !/^[0-9]+$/.test(rev)) warnings.push("Missing or non-numeric rev. Increment rev whenever rule logic changes.")
  if (!content && !pcre && !/content:|pcre:/i.test(rule)) warnings.push("No content or PCRE match found. This rule may be too broad.")
  if (/\bany\s+any\s+->\s+any\s+any\b/i.test(rule) || (normalized.src_ip === "any" && normalized.src_port === "any" && normalized.dst_ip === "any" && normalized.dst_port === "any")) {
    warnings.push("Traffic scope is very broad: any any -> any any. Narrow network variables, ports, or direction where possible.")
  }
  if (!normalized.flow && !/\bflow:/i.test(rule)) tuning.push("Add flow such as to_server,established for most HTTP/client-to-server rules.")
  if (pcre && !/^\/.+\/[A-Za-z]*$/.test(pcre)) warnings.push("PCRE does not look like the usual /pattern/modifiers form. Validate syntax with the target IDS engine.")
  if ((normalized.http_uri || normalized.http_header || /http_uri|http\.uri|http_header|http\.header/i.test(rule)) && !["tcp", "http"].includes(normalized.protocol)) {
    warnings.push("HTTP modifiers are usually expected with TCP/HTTP traffic. Check protocol and port selection.")
  }
  if (content && content.length < 4) falsePositive.push("Content match is short. Short strings usually create noisy alerts unless paired with flow, buffers, or PCRE.")
  if (/admin|login|password|cmd|shell|union|select|script|sqlmap|downloadstring|powershell|gate\.php|dns|tunnel/i.test(`${content} ${pcre} ${normalized.msg} ${rule}`)) {
    coverage.push(`Covers ${normalized.protocol.toUpperCase()} traffic using ${content ? "literal content" : "PCRE"} matching${normalized.flow ? ` with flow '${normalized.flow}'` : ""}.`)
  } else {
    coverage.push("Coverage depends on the selected content/PCRE marker. Confirm it appears in the intended packet field.")
  }
  if (normalized.http_uri || /http_uri|http\.uri/i.test(rule)) coverage.push("HTTP URI-focused rule. Useful for path/query probes but may miss encoded or fragmented variants.")
  if (normalized.http_header || /http_header|http\.header/i.test(rule)) coverage.push("HTTP header-focused rule. Useful for user-agent or header marker detections.")
  if (!falsePositive.length) falsePositive.push("Review benign application paths, scanners, monitoring checks, and admin tooling before promotion.")
  tuning.push("Replay known-benign traffic and a controlled positive sample before moving this rule into an active ruleset.")
  tuning.push("Keep the rule message, classtype, priority, SID, and revision aligned with your SOC naming and severity model.")

  if (/union select|sql injection|sqli/i.test(lowerRule)) mitre.push(candidate("T1190", "Exploit Public-Facing Application", "Initial Access", "SQLi-like web exploitation indicator."))
  if (/<script|xss/i.test(lowerRule)) mitre.push(candidate("T1190", "Exploit Public-Facing Application", "Initial Access", "XSS-style probing against a public web application."))
  if (/sqlmap|nikto|scanner|user-agent|nmap/i.test(lowerRule)) mitre.push(candidate("T1046", "Network Service Discovery", "Discovery", "Scanner-style behavior or tool fingerprint."))
  if (/powershell|downloadstring|encodedcommand/i.test(lowerRule)) mitre.push(candidate("T1059.001", "PowerShell", "Execution", "PowerShell command or download behavior."))
  if (/dns|tunnel|base64|[a-z0-9+/_-]{40,}/i.test(lowerRule)) mitre.push(candidate("T1071.004", "DNS", "Command and Control", "DNS application-layer protocol usage that may need C2/exfil review."))
  if (/callback|gate\.php|beacon|c2|command and control/i.test(lowerRule)) mitre.push(candidate("T1071.001", "Web Protocols", "Command and Control", "HTTP callback or beacon-like pattern."))
  if (!mitre.length) mitre.push(candidate("T1082", "System Information Discovery", "Discovery", "Generic placeholder only. Confirm behavior before assigning ATT&CK mapping."))

  return {
    warnings: uniqueStrings([...(result?.warnings || []), ...warnings]),
    coverage: uniqueStrings(coverage),
    tuning: uniqueStrings(tuning),
    falsePositive: uniqueStrings(falsePositive),
    mitre: uniqueById(mitre),
  }
}

export function makeDetectionPrefill({ rule, result, review }) {
  const explanation = result?.explanation || []
  return [
    "IDS rule review from BeyondArch",
    "",
    rule || "No rule available.",
    "",
    "Detection notes:",
    ...listLines(explanation.slice(0, 4)),
    "",
    "Candidate MITRE hints:",
    ...listLines((review?.mitre || []).map((item) => `${item.id} ${item.name} (${item.tactic}) - ${item.reason}`)),
    "",
    "Validation required: confirm telemetry source, replay benign and positive samples, review false positives, and validate in Snort/Suricata before production use.",
  ].join("\n")
}

function candidate(id, name, tactic, reason) {
  return { id, name, tactic, reason, certainty: "candidate" }
}

function listLines(items) {
  return (items || []).map((item) => `- ${item}`)
}

function uniqueStrings(items) {
  return [...new Set((items || []).filter(Boolean).map((item) => String(item).trim()).filter(Boolean))]
}

function uniqueById(items) {
  const seen = new Set()
  return (items || []).filter((item) => {
    if (seen.has(item.id)) return false
    seen.add(item.id)
    return true
  })
}
