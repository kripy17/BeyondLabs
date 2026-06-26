export const NMAP_PROFILES = [
  {
    id: "aggressive_inventory",
    label: "Service, version & OS (-A)",
    detail: "Runs Nmap -A with conservative timing against the top 100 ports to collect service versions, default scripts, traceroute/OS hints where available.",
    bestFor: "Full authorized inventory snapshot",
  },
  {
    id: "quick_tcp",
    label: "Quick TCP triage",
    detail: "Top 100 TCP ports with conservative timing. Best first pass for owned hosts.",
    bestFor: "Initial exposure snapshot",
  },
  {
    id: "service_version",
    label: "Service/version review",
    detail: "Adds service and version detection for open services discovered during triage.",
    bestFor: "Follow-up inventory",
  },
  {
    id: "web_exposure",
    label: "Web exposure ports",
    detail: "HTTP/HTTPS-oriented ports with safe HTTP/TLS metadata scripts.",
    bestFor: "Web surface review",
  },
  {
    id: "windows_smb",
    label: "Windows / SMB review",
    detail: "SMB, RDP, and WinRM exposure review for authorized Windows assets.",
    bestFor: "Windows asset exposure",
  },
  {
    id: "linux_ssh",
    label: "Linux / SSH review",
    detail: "SSH-focused review for Linux hosts and administrative exposure.",
    bestFor: "Linux admin surface",
  },
  {
    id: "mail_server",
    label: "Mail server exposure",
    detail: "SMTP, IMAP, and POP service review for owned mail infrastructure.",
    bestFor: "Mail infrastructure",
  },
]

const WEB_SERVICES = new Set(["http", "https", "http-proxy", "ssl/http", "http-alt", "https-alt"])
const ADMIN_SERVICES = new Set(["ssh", "ms-wbt-server", "rdp", "telnet", "winrm", "vnc", "xrdp"])
const WINDOWS_SERVICES = new Set(["microsoft-ds", "netbios-ssn", "msrpc", "ldap", "kerberos-sec", "kpasswd5"])
const DATABASE_SERVICES = new Set(["mysql", "postgresql", "ms-sql-s", "mongodb", "redis", "elasticsearch", "cassandra", "oracle", "mariadb"])
const MAIL_SERVICES = new Set(["smtp", "submission", "smtps", "pop3", "pop3s", "imap", "imaps"])
const DNS_SERVICES = new Set(["domain", "dns"])

export function parseNmapPorts(data) {
  const stdout = data?.scan?.stdout || data?.stdout || data?.raw_output || ""
  if (!stdout) return []
  const ports = []
  try {
    const xml = new DOMParser().parseFromString(stdout, "application/xml")
    xml.querySelectorAll("port").forEach((node) => {
      const state = node.querySelector("state")?.getAttribute("state") || "unknown"
      if (state !== "open") return
      const service = node.querySelector("service")
      ports.push({
        port: node.getAttribute("portid") || "",
        protocol: node.getAttribute("protocol") || "",
        state,
        service: service?.getAttribute("name") || "unknown",
        product: service?.getAttribute("product") || "",
        version: service?.getAttribute("version") || "",
        extrainfo: service?.getAttribute("extrainfo") || "",
      })
    })
  } catch {
    // DOMParser fallback below handles normal nmap output.
  }
  if (ports.length) return enrichPorts(ports)

  stdout.split(/\n+/).forEach((line) => {
    const trimmed = line.trim()
    const match = trimmed.match(/^(\d+)\/(tcp|udp)\s+(open|filtered|closed)\s+(\S+)(?:\s+(.*))?$/i)
    if (match && match[3].toLowerCase() === "open") {
      ports.push({
        port: match[1],
        protocol: match[2].toLowerCase(),
        state: match[3].toLowerCase(),
        service: match[4].toLowerCase(),
        product: match[5] || "",
        version: "",
        extrainfo: "",
      })
    }
  })
  return enrichPorts(ports)
}

function enrichPorts(ports) {
  return ports.map((port) => {
    const service = String(port.service || "unknown").toLowerCase()
    const portNumber = Number(port.port)
    const category = classifyService(service, portNumber)
    return {
      ...port,
      category,
      exposureNote: exposureNote(category, service, portNumber),
      suggestedAction: suggestedAction(category, service, portNumber),
    }
  })
}

export function classifyService(service, portNumber) {
  if (WEB_SERVICES.has(service) || [80, 443, 8080, 8443, 8000, 3000, 5000, 9000].includes(portNumber)) return "web"
  if (ADMIN_SERVICES.has(service) || [22, 23, 3389, 5900, 5985, 5986].includes(portNumber)) return "remote-admin"
  if (WINDOWS_SERVICES.has(service) || [135, 139, 445, 389, 636, 88].includes(portNumber)) return "windows-directory"
  if (DATABASE_SERVICES.has(service) || [1433, 1521, 3306, 5432, 6379, 27017, 9200].includes(portNumber)) return "database"
  if (MAIL_SERVICES.has(service) || [25, 110, 143, 465, 587, 993, 995].includes(portNumber)) return "mail"
  if (DNS_SERVICES.has(service) || portNumber === 53) return "dns"
  return "service"
}

function exposureNote(category, service, portNumber) {
  const notes = {
    web: "Web surface reachable. Review HTTP/TLS headers, redirects, and exposed paths.",
    "remote-admin": "Remote administration surface. Confirm exposure is expected and access-controlled.",
    "windows-directory": "Windows/domain service exposure. Validate internal scope and access controls.",
    database: "Database-like service exposed. Confirm it is not internet-facing unless intentionally published.",
    mail: "Mail service exposed. Review mail posture, TLS, and relay/auth expectations.",
    dns: "DNS service exposed. Check recursion, zone-transfer posture, and expected authoritative role.",
    service: "Open service needs asset-owner context and service inventory validation.",
  }
  return notes[category] || `Open ${service || "service"} on ${portNumber}. Validate expected exposure.`
}

function suggestedAction(category, service, portNumber) {
  const actions = {
    web: "Send host to Recon & Exposure for HTTP/TLS review.",
    "remote-admin": "Confirm asset ownership, expected exposure, MFA/VPN requirements, and source restrictions.",
    "windows-directory": "Validate this is internal/owned scope before any further enumeration.",
    database: "Escalate if exposed externally; check firewall and asset inventory.",
    mail: "Review MX/TLS/SPF/DMARC posture and confirm service role.",
    dns: "Run DNS posture checks and confirm recursion/authoritative behavior.",
    service: "Document service, version, owner, and expected business purpose.",
  }
  return actions[category] || `Review ${service || portNumber} with the asset owner.`
}

export function buildNmapSummary({ target, profile, result, ports }) {
  const scan = result?.scan || result || {}
  const openCount = ports.length
  const categories = new Set(ports.map((port) => port.category))
  const command = scan.command || ""
  let primaryExposure = "No open services parsed yet."
  let nextAction = "Run an authorized scan, then review open services before further pivots."

  if (scan.error) {
    primaryExposure = scan.error
    nextAction = "Fix the runner issue or adjust scope before retrying."
  } else if (openCount) {
    if (categories.has("remote-admin")) primaryExposure = "Remote administration surface is reachable (MITRE T1021)."
    else if (categories.has("database")) primaryExposure = "Database-like service exposure observed (MITRE T1213)."
    else if (categories.has("web")) primaryExposure = "Web service exposure observed (MITRE T1071.001)."
    else if (categories.has("windows-directory")) primaryExposure = "Windows/domain service exposure detected (MITRE T1021.002)."
    else if (categories.has("dns")) primaryExposure = "DNS service reachable (MITRE T1071.004)."
    else primaryExposure = `${openCount} open service(s) parsed from Nmap output.`
    nextAction = categories.has("web")
      ? "Send web host to Recon & Exposure for HTTP/TLS review, then document expected exposure."
      : "Validate services against asset inventory and expected business exposure."
  }

  return {
    decision: scan.error ? "Scan did not complete" : result ? "Scan summary ready" : "Ready for authorized scan",
    target,
    profile: profile?.label || scan.mode_label || scan.mode,
    command,
    openCount,
    primaryExposure,
    nextAction,
    runnerStatus: scan.success === false ? "runner issue" : result ? "scan completed" : "not run",
  }
}

const SERVICE_MITRE = {
  "remote-admin": { id: "T1021", name: "Remote Services", detail: "SSH, RDP, VNC, WinRM — remote access services enable lateral movement if compromised." },
  database: { id: "T1213", name: "Data from Information Repositories", detail: "Database-like services exposed to the network may allow data access if misconfigured." },
  "windows-directory": { id: "T1021.002", name: "SMB/Windows Admin Shares", detail: "Windows directory services are common lateral movement and enumeration vectors." },
  web: { id: "T1071.001", name: "Web Protocols", detail: "Web services are the primary C2 and data exfiltration channel for most threats." },
  mail: { id: "T1071.003", name: "Mail Protocols", detail: "Mail services expose SMTP/POP/IMAP which can be abused for relay, phishing, or data exfiltration." },
  dns: { id: "T1071.004", name: "DNS", detail: "DNS services may be abused for exfiltration, tunneling, or C2 if misconfigured." },
  service: { id: "T1046", name: "Network Service Discovery", detail: "Open services increase the attack surface available for discovery and exploitation." },
}

export function buildExposureFindings(ports = []) {
  const findings = []
  const byCategory = ports.reduce((acc, port) => {
    acc[port.category] ||= []
    acc[port.category].push(port)
    return acc
  }, {})
  if (byCategory["remote-admin"]?.length) {
    const hasRdP = byCategory["remote-admin"].some((p) => Number(p.port) === 3389)
    const hasSsh = byCategory["remote-admin"].some((p) => Number(p.port) === 22)
    const mitre = SERVICE_MITRE["remote-admin"]
    findings.push({ severity: "high", title: "Remote administration exposure", evidence: formatPorts(byCategory["remote-admin"]), action: `Confirm expected exposure, access path, MFA/VPN requirements${hasRdP ? ", and RDP Network Level Authentication (NLA)" : ""}${hasSsh ? ", and SSH key-based auth vs password" : ""}.`, mitre: `${mitre.id} ${mitre.name}` })
  }
  if (byCategory.database?.length) {
    const mitre = SERVICE_MITRE.database
    const hasMySql = byCategory.database.some((p) => Number(p.port) === 3306)
    const hasMsSql = byCategory.database.some((p) => Number(p.port) === 1433)
    findings.push({ severity: "high", title: "Database-like service reachable", evidence: formatPorts(byCategory.database), action: `Confirm the service is not internet-facing${hasMySql ? " without MySQL ACLs" : ""}${hasMsSql ? " without firewall-restricted SQL Server access" : ""}.`, mitre: `${mitre.id} ${mitre.name}` })
  }
  if (byCategory["windows-directory"]?.length) {
    const mitre = SERVICE_MITRE["windows-directory"]
    const hasSmb = byCategory["windows-directory"].some((p) => Number(p.port) === 445 || p.service === "microsoft-ds")
    findings.push({ severity: "medium", title: "Windows/domain service exposure", evidence: formatPorts(byCategory["windows-directory"]), action: `${hasSmb ? "SMB exposed may allow null session, enum, or relay if unpatched. " : ""}Validate scope and ownership before deeper enumeration.`, mitre: `${mitre.id} ${mitre.name}` })
  }
  if (byCategory.web?.length) {
    const mitre = SERVICE_MITRE.web
    const ports = byCategory.web.map((p) => Number(p.port))
    findings.push({ severity: "medium", title: "Web surface reachable", evidence: formatPorts(byCategory.web), action: `Review HTTP/TLS metadata${ports.includes(443) ? ", certificate validity/issuer" : ""}${ports.includes(80) ? ", and HTTP→HTTPS redirect" : ""} and exposed paths.`, mitre: `${mitre.id} ${mitre.name}` })
  }
  if (byCategory.mail?.length) {
    const mitre = SERVICE_MITRE.mail
    findings.push({ severity: "medium", title: "Mail service exposure", evidence: formatPorts(byCategory.mail), action: "Review MX/SPF/DMARC/TLS posture and confirm relay/auth expectations.", mitre: `${mitre.id} ${mitre.name}` })
  }
  if (byCategory.dns?.length) {
    const mitre = SERVICE_MITRE.dns
    findings.push({ severity: "medium", title: "DNS service reachable", evidence: formatPorts(byCategory.dns), action: "Check recursion/authoritative role through DNS posture tooling and zone-transfer vulnerability.", mitre: `${mitre.id} ${mitre.name}` })
  }
  const unknown = byCategory.service || []
  if (unknown.length) {
    const mitre = SERVICE_MITRE.service
    findings.push({ severity: "info", title: "Other service exposure", evidence: formatPorts(unknown), action: "Document owner, service purpose, and expected exposure.", mitre: `${mitre.id} ${mitre.name}` })
  }
  return findings
}

function formatPorts(ports = []) {
  return ports.map((port) => `${port.port}/${port.protocol} ${port.service}`).join(", ")
}

export function buildNmapSocQueries(target = "", ports = []) {
  const host = target || "target"
  const openPorts = ports.map((port) => port.port).filter(Boolean)
  const portList = openPorts.join(" OR ")
  return [
    { label: "Firewall / NetFlow", query: `dest_ip="${host}"${portList ? ` AND dest_port IN (${openPorts.join(",")})` : ""}` },
    { label: "EDR network", query: `netconn.remote_ip="${host}"${portList ? ` AND netconn.remote_port IN (${openPorts.join(",")})` : ""}` },
    { label: "Asset inventory", query: `host="${host}" OR ip="${host}"` },
    { label: "Broad SIEM pivot", query: portList ? `"${host}" AND (${portList})` : `"${host}"` },
  ]
}

export function createNmapReport({ summary, ports }) {
  const lines = [
    "# Nmap Scan Summary",
    "",
    summary.target ? `- Target: ${summary.target}` : "",
    summary.profile ? `- Profile: ${summary.profile}` : "",
    summary.command ? `- Command: ${summary.command}` : "",
    `- Open services parsed: ${summary.openCount || 0}`,
    summary.primaryExposure ? `- Summary: ${summary.primaryExposure}` : "",
    "",
    "## Open services",
    ...(ports.length ? ports.map((port) => {
      const detail = [port.product, port.version, port.extrainfo].filter(Boolean).join(" ")
      return `- ${port.port}/${port.protocol} ${port.service}${detail ? ` ${detail}` : ""}`
    }) : ["- No open services parsed from the available output."]),
    "",
    "## Notes",
    "- Nmap output depends on network reachability, profile selection, timing, and target firewall behavior.",
    "- This workflow does not exploit services or validate vulnerabilities.",
  ]
  return lines.filter(Boolean).join("\n")
}
