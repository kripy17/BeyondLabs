const SHORTENERS = new Set(["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly", "rebrand.ly", "lnkd.in", "shorturl.at"])
const RISKY_URL_WORDS = ["login", "verify", "reset", "update", "secure", "account", "password", "invoice", "payment", "wallet", "mfa", "signin", "auth"]
const DOWNLOAD_EXTENSIONS = ["exe", "scr", "js", "vbs", "ps1", "hta", "zip", "rar", "7z", "iso", "img", "apk", "dmg", "docm", "xlsm", "html"]
const PRIVATE_HOSTS = new Set(["localhost", "metadata.google.internal"])

export function refang(value = "") {
  return String(value)
    .replace(/\bhxxps\b/gi, "https")
    .replace(/\bhxxp\b/gi, "http")
    .replace(/\[\s*:\s*\]/g, ":")
    .replace(/\[\s*\.\s*\]/g, ".")
    .replace(/\(\s*\.\s*\)/g, ".")
    .replace(/\[\s*@\s*\]/g, "@")
}

export function rootDomain(host = "") {
  const clean = String(host).toLowerCase().replace(/^\.+|\.+$/g, "")
  const parts = clean.split(".").filter(Boolean)
  if (parts.length <= 2) return parts.join(".")
  return parts.slice(-2).join(".")
}

export function isIPv4(value = "") {
  return /^(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}$/.test(String(value))
}

export function isIPv6(value = "") {
  const clean = String(value)
  return clean.includes(":") && /^[0-9a-f:]+$/i.test(clean)
}

export function classifyIp(value = "") {
  if (!isIPv4(value)) return isIPv6(value) ? "IPv6" : ""
  const [a, b] = value.split(".").map(Number)
  if (a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)) return "private"
  if (a === 127) return "loopback"
  if (a === 169 && b === 254) return "link-local"
  if (a === 0 || a >= 224) return "reserved"
  return "public"
}

export function splitTargets(value = "") {
  return String(value).split(/[\n,]+/).map((item) => item.trim()).filter(Boolean)
}

function normalizeOne(rawValue = "") {
  const original = String(rawValue).trim()
  const normalized = refang(original)
  const defanged = normalized !== original
  const warnings = []
  if (!original) return { original, normalized, type: "empty", warnings: ["No target provided."] }

  if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalized)) {
    const domain = normalized.split("@").pop().toLowerCase()
    return { original, normalized, type: "email", host: domain, root_domain: rootDomain(domain), defanged, warnings }
  }

  const cidr = normalized.match(/^(.+)\/(\d{1,3})$/)
  if (cidr && isIPv4(cidr[1])) {
    const prefix = Number(cidr[2])
    const size = prefix >= 0 && prefix <= 32 ? 2 ** (32 - prefix) : null
    if (size && size > 256) warnings.push(`Large CIDR scope estimate: ${size.toLocaleString()} addresses.`)
    return { original, normalized, type: "cidr", host: cidr[1], ip_scope: classifyIp(cidr[1]), scope_size: size, defanged, warnings }
  }

  if (isIPv4(normalized) || isIPv6(normalized)) {
    return { original, normalized, type: isIPv4(normalized) ? "ipv4" : "ipv6", host: normalized, ip_scope: classifyIp(normalized), defanged, warnings }
  }

  const hasScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(normalized)
  try {
    const url = new URL(hasScheme ? normalized : `https://${normalized}`)
    const host = url.hostname.toLowerCase()
    const queryKeys = []
    url.searchParams.forEach((_, key) => queryKeys.push(key))
    const looksLikeUrl = hasScheme || url.pathname !== "/" || url.search || url.hash
    return {
      original,
      normalized: hasScheme ? normalized : host,
      type: looksLikeUrl ? "url" : "domain",
      scheme: hasScheme ? url.protocol.replace(":", "") : "",
      host,
      root_domain: rootDomain(host),
      port: url.port,
      path: url.pathname,
      query: url.search,
      fragment: url.hash,
      query_keys: [...new Set(queryKeys)],
      ip_scope: isIPv4(host) ? classifyIp(host) : "",
      defanged,
      warnings,
    }
  } catch {
    return {
      original,
      normalized,
      type: /^[A-Za-z0-9._-]{2,80}$/.test(normalized) ? "keyword" : "unknown",
      warnings: ["Target could not be parsed as a URL, domain, IP, CIDR, or email."],
      defanged,
    }
  }
}

export function normalizeTargetInput(input = "") {
  const items = splitTargets(input)
  const normalizedItems = items.length ? items.map(normalizeOne) : [normalizeOne(input)]
  return { primary: normalizedItems[0], items: normalizedItems, mixed: normalizedItems.length > 1 }
}

function cleanIndicator(value = "") {
  return String(value).replace(/[),.;\]]+$/g, "")
}

function uniq(items = []) {
  return [...new Set(items.map((item) => String(item || "").trim()).filter(Boolean))]
}

export function extractReconIndicators(input = "", normalized = normalizeTargetInput(input)) {
  const text = refang(input)
  const urls = uniq([
    ...(text.match(/\bhttps?:\/\/[^\s"'<>]+/gi) || []).map(cleanIndicator),
    ...normalized.items.filter((item) => item.type === "url" && item.normalized).map((item) => item.original.startsWith("http") ? item.original : item.normalized),
  ])
  const emails = uniq(text.match(/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi) || [])
  const ips = uniq(text.match(/\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b/g) || [])
  const cidrs = uniq(text.match(/\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\/(?:[0-9]|[12]\d|3[0-2])\b/g) || [])
  const domains = []
  urls.forEach((url) => {
    try { domains.push(new URL(url).hostname.toLowerCase()) } catch { /* ignore */ }
  })
  emails.forEach((email) => domains.push(email.split("@").pop().toLowerCase()))
  normalized.items.forEach((item) => {
    if (item.host && !isIPv4(item.host) && !isIPv6(item.host)) domains.push(item.host)
    if (item.root_domain) domains.push(item.root_domain)
  })
  domains.push(...(text.match(/\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b/gi) || []).map((item) => item.toLowerCase()))
  return { urls, domains: uniq(domains).filter((domain) => !domain.includes("@")), ips, cidrs, emails }
}

export function getTargetValue(target) {
  if (!target) return ""
  if (["url", "domain", "email"].includes(target.type)) return target.host || target.root_domain || target.normalized
  return target.host || target.normalized || ""
}

export function targetSnapshotFields(primary, indicators) {
  const fields = [
    ["Target", primary?.normalized],
    ["Type", primary?.type],
    ["Host", primary?.host],
    ["Root domain", primary?.root_domain],
    ["IP scope", primary?.ip_scope],
    ["Path", primary?.path && primary.path !== "/" ? primary.path : ""],
    ["Query keys", (primary?.query_keys || []).join(", ")],
    ["Extracted URLs", indicators.urls.length ? indicators.urls.length : ""],
    ["Extracted domains", indicators.domains.length ? indicators.domains.length : ""],
    ["Extracted IPs", indicators.ips.length ? indicators.ips.length : ""],
  ]
  return fields.filter(([, value]) => value !== undefined && value !== null && String(value).trim() && String(value).trim() !== "0")
}

export function localReconFindings(primary, indicators) {
  if (!primary || primary.type === "empty") return []
  const findings = []
  const host = primary.host || ""
  const haystack = `${host} ${primary.path || ""} ${primary.query || ""}`.toLowerCase()
  const words = RISKY_URL_WORDS.filter((word) => haystack.includes(word))
  const extension = (primary.path || "").split(".").pop()?.toLowerCase()

  if (primary.defanged) findings.push({ severity: "info", signal: "Defanged target normalized", evidence: primary.normalized, meaning: "The target was shared in analyst-safe form.", action: "Use normalized value for backend checks, but avoid browsing directly.", source: "local parser" })
  if (PRIVATE_HOSTS.has(host) || ["private", "loopback", "link-local", "reserved"].includes(primary.ip_scope)) findings.push({ severity: "high", signal: "Private/internal target", evidence: host || primary.normalized, meaning: "This may be internal scope and should not be sent to public tools automatically.", action: "Confirm ownership and keep checks local unless explicitly approved.", source: "local parser" })
  if (SHORTENERS.has(host)) findings.push({ severity: "medium", signal: "Shortener-like host", evidence: host, meaning: "Shorteners obscure final destination.", action: "Use Safe URL Analyzer or external URL sandbox/reputation manually.", source: "local parser" })
  if (words.length) findings.push({ severity: "low", signal: "Security/account wording", evidence: words.join(", "), meaning: "Security/account terms can be normal for portals or suspicious in phishing contexts.", action: "Correlate with email context or Safe URL Analyzer.", source: "local parser" })
  if (primary.port && !["80", "443", "8080", "8443"].includes(primary.port)) findings.push({ severity: "low", signal: "Non-standard port", evidence: primary.port, meaning: "Non-standard ports may represent admin panels, staging systems, or unusual services.", action: "Check ownership before active scanning.", source: "local parser" })
  if (DOWNLOAD_EXTENSIONS.includes(extension)) findings.push({ severity: "medium", signal: "Download/script-like path", evidence: primary.path, meaning: "The URL path references a file type often needing careful triage.", action: "Analyze any downloaded artifact in Attachment Triage only after safe acquisition.", source: "local parser" })
  if (indicators.domains.length > 1) findings.push({ severity: "info", signal: "Multiple domains in input", evidence: indicators.domains.slice(0, 5).join(", "), meaning: "This may represent a small IOC set rather than a single target.", action: "Run checks on the primary target first, then pivot related domains as needed.", source: "local parser" })
  return findings
}

export function summarizeRecon(primary, dnsResult, webExposure, findings) {
  if (!primary || primary.type === "empty") return {
    decision: "No target loaded",
    concern: "Paste a URL, domain, IP, CIDR, email, or IOC list.",
    nextAction: "Analyze a target to build an infrastructure profile.",
    basis: ["No active checks have run."],
  }
  const high = findings.filter((item) => item.severity === "high").length
  const medium = findings.filter((item) => item.severity === "medium").length
  const checks = []
  if (dnsResult) checks.push("DNS/PTR checked")
  if (webExposure) checks.push("HTTP/TLS checked")
  const webFindings = webExposure?.review?.findings || []
  const status = webExposure?.review?.http?.status_code
  const redirectCount = webExposure?.review?.http?.redirect_chain?.length || 0
  const missingSecurityHeaders = webFindings.filter((item) => /header missing/i.test(item.title || "")).length

  let decision = "Infrastructure profile ready"
  let concern = "No high-severity local infrastructure signal is visible yet."
  let nextAction = "Run DNS/PTR and HTTP/TLS checks if authorized, then pivot target in SOC telemetry."
  if (high) {
    decision = "Review target scope before external action"
    concern = "Private/internal or high-risk scope signal is present."
    nextAction = "Confirm ownership and keep enrichment local unless explicitly approved."
  } else if (webFindings.some((item) => String(item.severity).toLowerCase() === "high")) {
    decision = "Exposure needs review"
    concern = "HTTP/TLS check found high-impact exposure signals."
    nextAction = "Validate web finding with owner context and preserve evidence."
  } else if (medium || missingSecurityHeaders >= 3) {
    decision = "Needs configuration review"
    concern = "The target has configuration or structure signals worth validating."
    nextAction = "Review DNS, HTTP headers, TLS, and ownership before remediation."
  } else if (!dnsResult && !webExposure) {
    decision = "Local target profile only"
    concern = "No active DNS or HTTP/TLS evidence has been collected."
    nextAction = "Run authorized DNS/PTR or HTTP/TLS checks, or use external recon shortcuts manually."
  }

  return {
    decision,
    concern,
    nextAction,
    basis: [
      `Target type: ${primary.type}`,
      checks.length ? `Checks run: ${checks.join(" + ")}` : "Checks run: local parsing only",
      status ? `HTTP status observed: ${status}` : "HTTP status not checked",
      redirectCount ? `Redirect hops observed: ${redirectCount}` : "No redirect evidence collected",
      findings.length ? `${findings.length} evidence item(s) available` : "No evidence items yet",
    ],
  }
}

export function dnsRecordRows(dnsResult) {
  const recordSource = dnsResult?.dns?.records || dnsResult?.reverse_dns?.records || {}
  return Object.entries(recordSource)
    .filter(([, records]) => Array.isArray(records) && records.length)
    .map(([type, records]) => ({ type, records }))
}

export function webSummaryFields(webExposure) {
  const review = webExposure?.review || {}
  const http = review.http || {}
  const tls = review.tls || {}
  const issuer = tls.issuer?.organizationName || tls.issuer?.commonName || ""
  return [
    ["Base URL", review.base_url],
    ["HTTP status", http.status_code],
    ["Final URL", http.final_url],
    ["Redirect hops", Array.isArray(http.redirect_chain) && http.redirect_chain.length ? http.redirect_chain.length : ""],
    ["Server", http.server],
    ["Content type", http.content_type],
    ["TLS issuer", issuer],
    ["TLS expiry", tls.not_after],
    ["TLS days left", tls.days_remaining !== undefined && tls.days_remaining !== null ? tls.days_remaining : ""],
  ].filter(([, value]) => value !== undefined && value !== null && String(value).trim() !== "")
}

export function buildSocQueries(primary, indicators) {
  const host = primary?.host || primary?.root_domain || indicators.domains[0] || "example.com"
  const root = primary?.root_domain || host
  const ip = primary?.type?.startsWith("ipv") ? primary.normalized : indicators.ips[0]
  const url = primary?.type === "url" ? primary.original || primary.normalized : indicators.urls[0]
  const values = uniq([host, root, ...(indicators.domains || []), ...(indicators.ips || [])]).slice(0, 8)
  return [
    { label: "Proxy / web gateway", query: url ? `url="*${host}*" OR url_domain="${root}"` : `url_domain="${root}" OR url="*${root}*"` },
    { label: "DNS telemetry", query: ip ? `answer="${ip}" OR query="${root}"` : `query="${root}" OR query="*.${root}"` },
    { label: "Firewall / NetFlow", query: ip ? `dest_ip="${ip}" OR remote_ip="${ip}"` : `dest_domain="${root}" OR tls.sni="${root}"` },
    { label: "Email body / href search", query: values.map((value) => `"${value}"`).join(" OR ") },
    { label: "Splunk broad pivot", query: `(index=proxy OR index=dns OR index=email OR index=firewall) (${values.map((value) => `"${value}"`).join(" OR ")})` },
  ].filter((item) => item.query && !item.query.includes("undefined"))
}

function encode(value) {
  return encodeURIComponent(value || "")
}

export function buildExternalReconLinks(primary, indicators) {
  const host = primary?.host || indicators.domains[0] || ""
  const root = primary?.root_domain || host
  const ip = primary?.type?.startsWith("ipv") ? primary.normalized : indicators.ips[0] || ""
  const value = ip || host || root || primary?.normalized || ""
  const url = primary?.type === "url" ? primary.normalized || primary.original : indicators.urls[0]
  const links = []
  if (root) {
    links.push(
      { group: "DNS", label: "nslookup.io", href: `https://www.nslookup.io/domains/${encode(root)}/dns-records/`, note: "DNS record view" },
      { group: "DNS", label: "DNSChecker", href: `https://dnschecker.org/#A/${encode(root)}`, note: "Global DNS propagation" },
      { group: "Exposure", label: "crt.sh", href: `https://crt.sh/?q=${encode(root)}`, note: "Certificate transparency" },
      { group: "Whois", label: "Whois.com", href: `https://www.whois.com/whois/${encode(root)}`, note: "WHOIS lookup" },
      { group: "Whois", label: "DomainTools Whois", href: `https://whois.domaintools.com/${encode(root)}`, note: "DomainTools WHOIS" },
      { group: "Whois", label: "ViewDNS Reverse IP", href: `https://viewdns.info/reverseip/?host=${encode(root)}&t=1`, note: "Co-hosting pivot" },
      { group: "DNS", label: "DNSDumpster", href: `https://dnsdumpster.com/`, note: "Manual DNS map" },
      { group: "DNS", label: "dmarcian DMARC tools", href: `https://dmarcian.com/dmarc-tools/`, note: "DMARC/SPF helper" },
    )
  }
  if (value) {
    links.push(
      { group: "Exposure", label: "Shodan", href: `https://www.shodan.io/search?query=${encode(value)}`, note: "Public internet exposure" },
      { group: "Exposure", label: "Censys", href: `https://search.censys.io/search?resource=hosts&q=${encode(value)}`, note: "Host/cert exposure" },
      { group: "Exposure", label: "Criminal IP", href: `https://www.criminalip.io/`, note: "Manual IP/domain search" },
      { group: "Exposure", label: "HackerTarget", href: `https://hackertarget.com/`, note: "Online network tools" },
    )
  }
  if (ip) {
    links.push(
      { group: "Reputation", label: "AbuseIPDB", href: `https://www.abuseipdb.com/check/${encode(ip)}`, note: "IP abuse reports" },
      { group: "Reputation", label: "IPinfo", href: `https://ipinfo.io/${encode(ip)}`, note: "ASN/geolocation" },
      { group: "Reputation", label: "IPLocation", href: `https://www.iplocation.net/ip-lookup`, note: "Manual IP lookup" },
      { group: "Reputation", label: "Talos reputation", href: `https://talosintelligence.com/reputation_center/lookup?search=${encode(ip)}`, note: "Cisco reputation" },
    )
  }
  if (url || root) {
    const submitted = url || `https://${root}`
    links.push(
      { group: "URL", label: "urlscan.io", href: `https://urlscan.io/search/#${encode(submitted)}`, note: "URL scan/search" },
      { group: "Reputation", label: "VirusTotal", href: `https://www.virustotal.com/gui/search/${encode(submitted)}`, note: "URL/domain reputation" },
      { group: "Reputation", label: "URLVoid", href: `https://www.urlvoid.com/scan/${encode(root || host)}/`, note: "URL reputation summary" },
      { group: "Reputation", label: "Google Safe Browsing", href: `https://transparencyreport.google.com/safe-browsing/search?url=${encode(submitted)}`, note: "Known unsafe URL check" },
      { group: "Reputation", label: "URLhaus", href: `https://urlhaus.abuse.ch/browse.php?search=${encode(root || host)}`, note: "Malware URL exchange" },
      { group: "Reputation", label: "CheckPhish", href: `https://checkphish.bolster.ai/`, note: "Manual phishing check" },
      { group: "URL", label: "SecurityHeaders", href: `https://securityheaders.com/?q=${encode(root || host)}&followRedirects=on`, note: "HTTP security headers" },
      { group: "URL", label: "WebCheck", href: `https://web-check.xyz/check/${encode(root || host)}`, note: "Website metadata" },
    )
  }
  return links
}

export function createReconReport({ primary, indicators, findings, dnsResult, webExposure }) {
  const lines = [
    "# Recon & Exposure Finding",
    "",
    "## Target",
    `- Target: ${primary?.normalized || "Not provided"}`,
    primary?.type ? `- Type: ${primary.type}` : "",
    primary?.host ? `- Host: ${primary.host}` : "",
    primary?.root_domain ? `- Root domain: ${primary.root_domain}` : "",
    "",
    "## Evidence summary",
    ...(findings.length ? findings.map((item) => `- ${item.severity.toUpperCase()}: ${item.signal} — ${item.evidence}`) : ["- No notable exposure evidence recorded yet."]),
    "",
    "## Extracted indicators",
    indicators.urls.length ? `- URLs: ${indicators.urls.join(", ")}` : "",
    indicators.domains.length ? `- Domains: ${indicators.domains.join(", ")}` : "",
    indicators.ips.length ? `- IPs: ${indicators.ips.join(", ")}` : "",
    indicators.cidrs.length ? `- CIDRs: ${indicators.cidrs.join(", ")}` : "",
    indicators.emails.length ? `- Emails: ${indicators.emails.join(", ")}` : "",
    "",
    "## Checks performed",
    dnsResult ? "- DNS/PTR metadata checked through local backend." : "- DNS/PTR backend check not run.",
    webExposure ? "- HTTP/TLS metadata checked through local backend." : "- HTTP/TLS backend check not run.",

    "",
    "## Limitations",
    "- Local parsing does not prove ownership, exposure, or maliciousness.",
    "- External recon links are manual analyst shortcuts and were not queried automatically.",
    "- Nmap and OSINT collection are separate workflows and should only be used within authorized scope.",
  ]
  return lines.filter(Boolean).join("\n")
}
