const SHORTENERS = new Set(["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly", "rebrand.ly", "lnkd.in", "shorturl.at", "rb.gy", "bl.ink", "shorte.st", "soo.gd"])
const SUSPICIOUS_TLDS = new Set(["tk", "ml", "ga", "cf", "gq", "xyz", "top", "work", "click", "loan", "download", "review", "stream", "trade", "win", "date", "men", "mom", "bid", "sbs", "rest"])
const SENSITIVE_QUERY_KEYS = ["token", "session", "auth", "key", "secret", "code", "password", "passwd", "reset", "jwt", "otp", "2fa", "verification", "login", "email", "userid"]
const RISKY_URL_WORDS = ["login", "verify", "reset", "update", "secure", "account", "password", "invoice", "payment", "wallet", "mfa", "signin", "auth"]
const DOWNLOAD_EXTENSIONS = ["exe", "scr", "js", "vbs", "ps1", "hta", "zip", "rar", "7z", "iso", "img", "apk", "dmg", "docm", "xlsm", "html"]
const PRIVATE_HOSTS = new Set(["localhost", "metadata.google.internal"])
const KNOWN_BRANDS = [
  { name: "google", domains: ["google.com", "gmail.com"] },
  { name: "facebook", domains: ["facebook.com", "fb.com"] },
  { name: "microsoft", domains: ["microsoft.com", "office.com", "outlook.com"] },
  { name: "apple", domains: ["apple.com", "icloud.com"] },
  { name: "amazon", domains: ["amazon.com", "aws.amazon.com"] },
  { name: "paypal", domains: ["paypal.com"] },
  { name: "netflix", domains: ["netflix.com"] },
  { name: "linkedin", domains: ["linkedin.com"] },
  { name: "github", domains: ["github.com"] },
  { name: "twitter", domains: ["twitter.com", "x.com"] },
  { name: "dropbox", domains: ["dropbox.com"] },
  { name: "adobe", domains: ["adobe.com"] },
  { name: "yahoo", domains: ["yahoo.com"] },
  { name: "instagram", domains: ["instagram.com"] },
]

function typoDomainCheck(host = "", primary) {
  if (!host || primary?.type === "email" || primary?.type === "ipv4" || primary?.type === "ipv6") return ""
  const root = rootDomain(host)
  const label = root.split(".")[0] || ""
  const normalized = label.replace(/0/g, "o").replace(/1/g, "l").replace(/3/g, "e").replace(/5/g, "s").replace(/@/g, "a").replace(/-/g, "")
  for (const brand of KNOWN_BRANDS) {
    if (brand.domains.includes(root)) continue
    const brandLabel = brand.name.toLowerCase()
    if (normalized.length < 5 || brandLabel.length < 5) continue
    if (normalized !== brandLabel && (normalized.includes(brandLabel) || levenshtein(normalized, brandLabel) <= 2)) return `${brand.name} (${root} resembles ${brand.domains[0]})`
  }
  return ""
}

function levenshtein(a = "", b = "") {
  const m = a.length; const n = b.length; const d = Array.from({ length: m + 1 }, () => Array(n + 1).fill(0))
  for (let i = 0; i <= m; i++) d[i][0] = i
  for (let j = 0; j <= n; j++) d[0][j] = j
  for (let j = 1; j <= n; j++) for (let i = 1; i <= m; i++) d[i][j] = a[i - 1] === b[j - 1] ? d[i - 1][j - 1] : Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + 1)
  return d[m][n]
}

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
  const asns = uniq(text.match(/\bAS\d{1,6}\b/gi) || [])
  const hashes = uniq(text.match(/\b[a-f0-9]{32}\b|\b[a-f0-9]{40}\b|\b[a-f0-9]{64}\b/gi) || [])
  const macAddresses = uniq(text.match(/\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b/g) || [])
  const filePaths = uniq(text.match(/[A-Za-z]:\\[^\r\n"'<>|]+|\/(?:usr|tmp|var|home|etc)\/[^\s"'<>]+/g) || [])
  const registryPaths = uniq(text.match(/HK(?:LM|CU|CR|U|CC)\\[^\r\n"']+/gi) || [])
  const base64Blobs = [...new Set(text.match(/\b[A-Za-z0-9+/]{40,}={0,2}\b/g) || [])].slice(0, 20)
  return { urls, domains: uniq(domains).filter((domain) => !domain.includes("@")), ips, cidrs, emails, asns, hashes: hashes.slice(0, 30), mac_addresses: macAddresses.slice(0, 20), file_paths: filePaths.slice(0, 15), registry_paths: registryPaths.slice(0, 10), base64_blobs: base64Blobs }
}

export function getTargetValue(target) {
  if (!target) return ""
  if (["url", "domain", "email"].includes(target.type)) return target.host || target.root_domain || target.normalized
  return target.host || target.normalized || ""
}

export function targetSnapshotFields(primary, indicators) {
  const hostParts = (primary?.host || "").split(".")
  const tld = hostParts.length > 1 ? hostParts[hostParts.length - 1].toLowerCase() : ""
  const fields = [
    ["Target", primary?.normalized],
    ["Type", primary?.type],
    ["Host", primary?.host],
    ["Root domain", primary?.root_domain],
    ["TLD", tld],
    ["IP scope", primary?.ip_scope],
    ["Port", primary?.port || ""],
    ["Path", primary?.path && primary.path !== "/" ? primary.path : ""],
    ["Path depth", primary?.path ? primary.path.split("/").filter(Boolean).length : ""],
    ["Query keys", (primary?.query_keys || []).join(", ")],
    ["Defanged?", primary?.defanged ? "Yes" : ""],
    ["Extracted URLs", indicators.urls.length ? indicators.urls.length : ""],
    ["Extracted domains", indicators.domains.length ? indicators.domains.length : ""],
    ["Extracted IPs", indicators.ips.length ? indicators.ips.length : ""],
    ["Extracted ASNs", indicators.asns?.length ? indicators.asns.length : ""],
    ["Extracted hashes", indicators.hashes?.length ? indicators.hashes.length : ""],
  ]
  return fields.filter(([, value]) => value !== undefined && value !== null && String(value).trim() && String(value).trim() !== "0")
}

const RECON_FINDING_MITRE = {
  "Defanged target normalized": "",
  "Private/internal target": "T1590.001",
  "Suspicious TLD": "T1595",
  "Shortener-like host": "T1566.002",
  "IP-hosted URL": "T1590.002",
  "Security/account wording": "T1591",
  "Non-standard port": "T1046",
  "Download/script-like path": "T1204.002",
  "Deep URL path": "",
  "Sensitive query parameter": "T1590",
  "Multiple domains in input": "T1580",
  "ASN references found": "T1590.001",
  "Typo-squatting domain": "T1595.002",
  "Uncommon TLD for root domain": "T1595",
  "Service-prefixed hostname": "",
  "CDN or reverse-proxy host": "T1590.002",
}

function mapReconToMitre(findings = []) {
  for (const f of findings) {
    f.mitre_id = RECON_FINDING_MITRE[f.signal] || ""
  }
  return findings
}

export function localReconFindings(primary, indicators) {
  if (!primary || primary.type === "empty") return []
  const findings = []
  const host = primary.host || ""
  const haystack = `${host} ${primary.path || ""} ${primary.query || ""}`.toLowerCase()
  const words = RISKY_URL_WORDS.filter((word) => haystack.includes(word))
  const extension = (primary.path || "").split(".").pop()?.toLowerCase()
  const hostParts = host.split(".")
  const tld = hostParts.length > 1 ? hostParts[hostParts.length - 1].toLowerCase() : ""

  if (primary.defanged) findings.push({ severity: "info", signal: "Defanged target normalized", evidence: primary.normalized, meaning: "The target was shared in analyst-safe form.", action: "Use normalized value for backend checks, but avoid browsing directly.", source: "local parser" })
  if (PRIVATE_HOSTS.has(host) || ["private", "loopback", "link-local", "reserved"].includes(primary.ip_scope)) findings.push({ severity: "high", signal: "Private/internal target", evidence: host || primary.normalized, meaning: "This may be internal scope and should not be sent to public tools automatically.", action: "Confirm ownership and keep checks local unless explicitly approved.", source: "local parser" })
  if (SUSPICIOUS_TLDS.has(tld)) findings.push({ severity: "medium", signal: "Suspicious TLD", evidence: `.${tld}`, meaning: "Free/promiscuous TLDs are disproportionately used for phishing, malware, and spam.", action: "Vet domain registration context before trusting.", source: "local parser" })
  if (SHORTENERS.has(host)) findings.push({ severity: "medium", signal: "Shortener-like host", evidence: host, meaning: "Shorteners obscure final destination.", action: "Use Safe URL Analyzer or external URL sandbox/reputation manually.", source: "local parser" })
  if (isIPv4(host)) findings.push({ severity: "low", signal: "IP-hosted URL", evidence: host, meaning: "Literal IP in the URL bypasses domain reputation and can indicate direct server access.", action: "Check IP scope and correlate with netflow/proxy logs.", source: "local parser" })
  if (words.length) findings.push({ severity: "low", signal: "Security/account wording", evidence: words.join(", "), meaning: "Security/account terms can be normal for portals or suspicious in phishing contexts.", action: "Correlate with email context or Safe URL Analyzer.", source: "local parser" })
  if (primary.port && !["80", "443", "8080", "8443"].includes(primary.port)) findings.push({ severity: "low", signal: "Non-standard port", evidence: primary.port, meaning: "Non-standard ports may represent admin panels, staging systems, or unusual services.", action: "Check ownership before active scanning.", source: "local parser" })
  if (DOWNLOAD_EXTENSIONS.includes(extension)) findings.push({ severity: "medium", signal: "Download/script-like path", evidence: primary.path, meaning: "The URL path references a file type often needing careful triage.", action: "Analyze any downloaded artifact in Attachment Triage only after safe acquisition.", source: "local parser" })
  const pathDepth = primary.path ? primary.path.split("/").filter(Boolean).length : 0
  if (pathDepth >= 5) findings.push({ severity: "info", signal: "Deep URL path", evidence: `${pathDepth} segments`, meaning: "Deep paths can indicate dynamic application routing or obfuscation.", action: "Review path tokens for suspicious patterns.", source: "local parser" })
  if (primary.query_keys && primary.query_keys.some((key) => SENSITIVE_QUERY_KEYS.includes(key.toLowerCase()))) findings.push({ severity: "low", signal: "Sensitive query parameter", evidence: primary.query_keys.filter((key) => SENSITIVE_QUERY_KEYS.includes(key.toLowerCase())).join(", "), meaning: "URLs with sensitive query parameters may expose data in logs or referrers.", action: "Check if URL was shared securely; token/session material should be rotated.", source: "local parser" })
  if (indicators.domains.length > 1) findings.push({ severity: "info", signal: "Multiple domains in input", evidence: indicators.domains.slice(0, 5).join(", "), meaning: "This may represent a small IOC set rather than a single target.", action: "Run checks on the primary target first, then pivot related domains as needed.", source: "local parser" })
  if (indicators.asns?.length) findings.push({ severity: "info", signal: "ASN references found", evidence: indicators.asns.join(", "), meaning: "BGP AS numbers provide infrastructure ownership context.", action: "Correlate ASNs with known hosting providers or threat actor infrastructure.", source: "local parser" })
  const similarBrand = typoDomainCheck(host, primary)
  if (similarBrand) findings.push({ severity: "high", signal: "Typo-squatting domain", evidence: similarBrand, meaning: "The domain visually resembles a known brand which could indicate typosquatting, phishing, or brand impersonation.", action: "Verify domain registration and compare with legitimate brand domain ownership.", source: "local parser" })
  if (tld && !["com", "net", "org", "io", "co", "app", "dev", "gov", "edu", "mil", "biz", "info"].includes(tld) && /^(?:[a-z]{2,6})$/.test(tld) && host.split(".").length === 2) findings.push({ severity: "low", signal: "Uncommon TLD for root domain", evidence: `.${tld}`, meaning: "Less common TLDs for a bare domain can indicate cheap registration or low-verification hosting.", action: "Check domain age, registrar, and WHOIS for context.", source: "local parser" })
  if (/^(?:www|mail|smtp|pop|imap|ns\d|ftp|webmail|cdn|api|vpn|remote|owa|autodiscover)\./i.test(host)) findings.push({ severity: "info", signal: "Service-prefixed hostname", evidence: host, meaning: "Common service prefixes may indicate this is a specific function host rather than a root domain.", action: "Use root domain for broader recon context.", source: "local parser" })
  if (/\.cdn\.|\.cloudfront\.|cloudflare|akamai|fastly|cloudfront/i.test(host)) findings.push({ severity: "info", signal: "CDN or reverse-proxy host", evidence: host, meaning: "Behind a CDN, the real origin IP may be hidden. Direct IP enumeration may not reach the server.", action: "Use passive DNS or certificate transparency for origin discovery if needed.", source: "local parser" })
  mapReconToMitre(findings)
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
    { label: "EDR process / network", query: ip ? `(process_name="*${root}*" OR remote_ip="${ip}" OR tls_sni="${root}")` : `(process_name="*${root}*" OR tls_sni="${root}")` },
    { label: "Authentication logs", query: `(src_ip="${ip}" OR dest_host="${root}") AND (auth OR login OR "failed" OR "success")` },
    { label: "Splunk broad pivot", query: `(index=proxy OR index=dns OR index=email OR index=firewall OR index=windows) (${values.map((value) => `"${value}"`).join(" OR ")})` },
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
      { group: "DNS", label: "MXToolbox", href: `https://mxtoolbox.com/DNSLookup.aspx?domain=${encode(root)}`, note: "DNS suite" },
      { group: "DNS", label: "DNSlytics", href: `https://dnslytics.com/domain/${encode(root)}`, note: "DNS history" },
      { group: "Exposure", label: "crt.sh", href: `https://crt.sh/?q=${encode(root)}`, note: "Certificate transparency" },
      { group: "Exposure", label: "FullHunt", href: `https://fullhunt.io/domain/${encode(root)}`, note: "Attack surface search" },
      { group: "Whois", label: "Whois.com", href: `https://www.whois.com/whois/${encode(root)}`, note: "WHOIS lookup" },
      { group: "Whois", label: "DomainTools Whois", href: `https://whois.domaintools.com/${encode(root)}`, note: "DomainTools WHOIS" },
      { group: "Whois", label: "WhoisXML", href: `https://www.whoisxmlapi.com/whoisserver/WhoisService.jsp?domainName=${encode(root)}`, note: "WhoisXML lookup" },
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
      { group: "Exposure", label: "Greynoise", href: `https://viz.greynoise.io/query?gnql=${encode(value)}`, note: "Internet noise scanner" },
      { group: "Exposure", label: "HackerTarget", href: `https://hackertarget.com/`, note: "Online network tools" },
      { group: "Exposure", label: "LeakIX", href: `https://leakix.net/search?scope=leak&q=${encode(root || value)}`, note: "Open port/leak search" },
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
    indicators.asns?.length ? `- ASNs: ${indicators.asns.join(", ")}` : "",
    indicators.hashes?.length ? `- Hashes: ${indicators.hashes.join(", ")}` : "",
    "",
    "## Checks performed",
    dnsResult ? "- DNS/PTR metadata checked through local backend." : "- DNS/PTR backend check not run.",
    webExposure ? "- HTTP/TLS metadata checked through local backend." : "- HTTP/TLS backend check not run.",

    "",
    "## Limitations",
    "- Local parsing does not prove ownership, exposure, or maliciousness.",
    "- External recon links are manual analyst shortcuts and were not queried automatically.",
    "- Nmap and OSINT collection are separate workflows and should only be used within authorized scope.",
    "- New IOC types (ASN, hashes, MAC, file/registry paths) are extracted from input text but not resolved or enriched.",
    "- DNS and HTTP/TLS checks are point-in-time and may not reflect current infrastructure state.",
  ]
  return lines.filter(Boolean).join("\n")
}

const EXPOSURE_SEVERITY_WEIGHTS = {
  subdomain_takeover: { weight: 30, label: "Subdomain takeover risk" },
  open_port: { weight: 20, label: "Exposed service port" },
  sensitive_endpoint: { weight: 25, label: "Sensitive endpoint exposed" },
  tech_stack: { weight: 10, label: "Technology stack disclosure" },
  email_spoof: { weight: 20, label: "Email spoofing vulnerability" },
  typo_squat: { weight: 15, label: "Typo-squatting risk" },
  cdn_proxy: { weight: 10, label: "CDN/proxy fingerprint" },
  uncommon_tld: { weight: 5, label: "Uncommon TLD" },
  service_prefix: { weight: 5, label: "Service-prefixed hostname" },
}

export function computeExposureScore(findings = []) {
  if (!findings.length) return { score: 0, level: "none", breakdown: [] }
  const breakdown = []
  let total = 0
  for (const f of findings) {
    const signal = String(f.signal || f.type || "").toLowerCase().replace(/\s+/g, "_")
    const match = Object.entries(EXPOSURE_SEVERITY_WEIGHTS).find(([k]) => signal.includes(k))
    if (match) {
      breakdown.push({ finding: match[1].label, score: match[1].weight, signal: f.signal || f.type })
      total += match[1].weight
    }
  }
  const score = Math.min(total, 100)
  const level = score >= 60 ? "high" : score >= 35 ? "medium" : score >= 10 ? "low" : "info"
  return { score, level, breakdown }
}

export function generateExposureReport(results = {}) {
  const findings = results.findings || []
  const score = computeExposureScore(findings)
  const target = results.target || results.domain || results.ip || "unknown target"
  const lines = [
    `## Exposure Assessment Report`,
    ``,
    `**Target:** ${target}`,
    `**Exposure Score:** ${score.score}/100 (${score.level.toUpperCase()})`,
    `**Findings:** ${findings.length} issue(s) identified`,
    ``,
    `### Key Findings`,
    ...(score.breakdown.length ? score.breakdown.map((b) => `- ${b.finding} [score: ${b.score}]`) : ["- No significant exposure signals detected."]),
    ``,
    `### Analyst Recommendation`,
    score.level === "high"
      ? "- High exposure risk. Prioritize remediation: validate subdomain ownership, review open ports, and assess sensitive endpoint exposure."
      : score.level === "medium"
      ? "- Moderate exposure. Schedule review within standard triage. Address highest-weight findings first."
      : "- Low exposure. Log for awareness; no immediate remediation required.",
    ``,
    `**Limitations:** This assessment is based on passive/static analysis only. No active scanning, credential validation, or threat intelligence correlation was performed.`,
  ]
  return lines.join("\n")
}
