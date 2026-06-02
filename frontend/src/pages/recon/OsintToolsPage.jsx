import { useMemo, useState } from "react"
import { ArrowRightLeft, Clipboard, ExternalLink, FileText, Play, RefreshCcw, Search, ShieldCheck, Terminal, Trash2, Wrench } from "lucide-react"
import { getLocalOsintTools, runLocalOsintTool } from "../../api/backend"
import { WorkbenchHeader, WorkbenchPage, WorkbenchPanel } from "../../components/layout/WorkbenchShell"
import SendToActions from "../../components/investigation/SendToActions"
import AnalystOutputCard from "../../components/investigation/AnalystOutputCard"
import { addTimelineArtifact } from "../../lib/timelineStore"
import { copyText } from "../../lib/domUtils.js"

const PENDING_KEY = "beyondarch.pendingArtifact"

const LOCAL_RUNNERS = [
  { id: "dns_basic", label: "DNS baseline", type: "built-in", binary: "dig", detail: "A, AAAA, CNAME, NS, SOA, MX, and TXT records." },
  { id: "dig_mx_txt", label: "Mail posture", type: "built-in", binary: "dig", detail: "MX, SPF, DMARC, TXT, and NS posture." },
  { id: "http_headers", label: "HTTP headers", type: "built-in", binary: "curl", detail: "Headers and redirects only; no browser rendering." },
  { id: "tls_cert", label: "TLS certificate", type: "built-in", binary: "openssl", detail: "TLS handshake and certificate preview." },
  { id: "whois", label: "WHOIS", type: "optional", binary: "whois", detail: "Registration metadata through local whois." },
  { id: "theharvester", label: "theHarvester", type: "optional", binary: "theharvester", detail: "Passive email/host/subdomain collection." },
  { id: "subfinder", label: "Subfinder", type: "optional", binary: "subfinder", detail: "Passive subdomain enumeration." },
  { id: "amass", label: "Amass passive", type: "optional", binary: "amass", detail: "Passive subdomain enumeration." },
  { id: "assetfinder", label: "Assetfinder", type: "optional", binary: "assetfinder", detail: "Subdomain discovery from public sources." },
]

const HARVESTER_SOURCES = ["duckduckgo", "bing", "crtsh", "hackertarget", "rapiddns", "baidu"]

function cleanHost(value = "") {
  return String(value || "")
    .trim()
    .replace(/^https?:\/\//i, "")
    .replace(/^www\./i, "")
    .split(/[/?#]/)[0]
    .split(":")[0]
}

function readPendingArtifact() {
  try {
    const raw = localStorage.getItem(PENDING_KEY)
    return raw ? JSON.parse(raw) : null
  } catch {
    return null
  }
}

function targetFromArtifact(artifact) {
  if (!artifact) return ""
  return cleanHost(artifact.host || artifact.domain || artifact.hostname || artifact.value || artifact.content || artifact.text || artifact.raw_input || "")
}

function searchUrl(base, value) {
  return `${base}${encodeURIComponent(value)}`
}

function setPendingArtifact(payload) {
  try {
    localStorage.setItem(PENDING_KEY, JSON.stringify({ ts: Date.now(), source: "OSINT Tools", ...payload }))
  } catch {
    // Ignore blocked storage.
  }
}

function targetProfile({ domain, brand, username, email }) {
  const host = cleanHost(domain)

  const rows = []
  if (host) rows.push(["Target", host], ["Infrastructure lane", "DNS, certificates, headers, exposure, reputation pivots"])
  if (brand?.trim()) rows.push(["Brand", brand.trim()], ["Brand lane", "Impersonation, fake support pages, phishing lures"])
  if (username?.trim()) rows.push(["Username", username.trim()], ["Account lane", "Profile reuse, repos, forums, paste sites"])
  if (email?.trim()) rows.push(["Email", email.trim()], ["Email lane", "Public mentions, breach context, mail posture"])
  return rows
}

function makeExternalGroups({ domain, brand, username, email }) {
  const host = cleanHost(domain) || "example.com"
  const keyword = brand?.trim() || host
  const user = username?.trim() || "example-user"
  const mail = email?.trim() || `security@${host}`
  return [
    { title: "Search & dorks", purpose: "Public-web queries, indexed files, login surfaces, and document discovery.", links: [
      ["Google site", `https://www.google.com/search?q=${encodeURIComponent(`site:${host}`)}`],
      ["DuckDuckGo", searchUrl("https://duckduckgo.com/?q=", host)],
      ["Bing", searchUrl("https://www.bing.com/search?q=", host)],
      ["DorkSearch", searchUrl("https://dorksearch.com/?q=", `site:${host}`)],
      ["GHDB", searchUrl("https://www.exploit-db.com/google-hacking-database?gsearch=", host)],
      ["PublicWWW", searchUrl("https://publicwww.com/websites/", host)],
    ] },
    { title: "DNS / Whois / certs", purpose: "DNS records, certificate transparency, ownership, reverse IP, and mail posture.", links: [
      ["nslookup.io", `https://www.nslookup.io/domains/${encodeURIComponent(host)}/dns-records/`],
      ["DNSChecker", searchUrl("https://dnschecker.org/all-dns-records-of-domain.php?query=", host)],
      ["crt.sh", `https://crt.sh/?q=${encodeURIComponent(host)}`],
      ["Whois.com", `https://www.whois.com/whois/${encodeURIComponent(host)}`],
      ["ViewDNS reverse IP", `https://viewdns.info/reverseip/?host=${encodeURIComponent(host)}&t=1`],
      ["DNSDumpster", "https://dnsdumpster.com/"],
      ["dmarcian", `https://dmarcian.com/domain-checker/?domain=${encodeURIComponent(host)}`],
    ] },
    { title: "Exposure & technology", purpose: "Indexed public services, headers, technologies, and visible attack surface.", links: [
      ["Shodan", searchUrl("https://www.shodan.io/search?query=", host)],
      ["Censys", searchUrl("https://search.censys.io/search?resource=hosts&q=", host)],
      ["Criminal IP", searchUrl("https://www.criminalip.io/asset/search?query=", host)],
      ["SecurityHeaders", `https://securityheaders.com/?q=${encodeURIComponent(host)}&followRedirects=on`],
      ["WebCheck", `https://web-check.xyz/check/${encodeURIComponent(host)}`],
      ["BuiltWith", `https://builtwith.com/${encodeURIComponent(host)}`],
      ["IPinfo", searchUrl("https://ipinfo.io/", host)],
    ] },
    { title: "Reputation / URL checks", purpose: "Manual reputation pivots. BeyondArch does not query these automatically.", links: [
      ["VirusTotal domain", `https://www.virustotal.com/gui/domain/${encodeURIComponent(host)}`],
      ["urlscan.io", searchUrl("https://urlscan.io/search/#", `domain:${host}`)],
      ["URLVoid", `https://www.urlvoid.com/scan/${encodeURIComponent(host)}/`],
      ["Talos", searchUrl("https://talosintelligence.com/reputation_center/lookup?search=", host)],
      ["Google Safe Browsing", "https://transparencyreport.google.com/safe-browsing/search"],
      ["URLhaus", searchUrl("https://urlhaus.abuse.ch/browse.php?search=", host)],
      ["AbuseIPDB", searchUrl("https://www.abuseipdb.com/check/", host)],
    ] },
    { title: "People / brand / accounts", purpose: "Username reuse, email context, brand abuse, public contacts, and profile pivots.", links: [
      ["WhatsMyName", searchUrl("https://whatsmyname.app/?q=", user)],
      ["InstantUsername", `https://instantusername.com/#/${encodeURIComponent(user)}`],
      ["Have I Been Pwned", searchUrl("https://haveibeenpwned.com/account/", mail)],
      ["EmailRep", searchUrl("https://emailrep.io/", mail)],
      ["Hunter.io", searchUrl("https://hunter.io/search/", host)],
      ["Phonebook.cz", searchUrl("https://phonebook.cz/search?q=", host)],
      ["Brand phishing search", `https://www.google.com/search?q=${encodeURIComponent(`"${keyword}" phishing OR "verify your account"`)}`],
    ] },
    { title: "Archives & history", purpose: "Historical pages, old exposed files, domain history, and change context.", links: [
      ["Wayback Machine", `https://web.archive.org/web/*/${encodeURIComponent(host)}/*`],
      ["Archive.today", `https://archive.is/${encodeURIComponent(host)}`],
      ["Ghostarchive", "https://ghostarchive.org/"],
      ["Google cache/search", `https://www.google.com/search?q=${encodeURIComponent(`cache:${host}`)}`],
    ] },
  ]
}

function makeQueryPacks({ domain, brand, username, email }) {
  const host = cleanHost(domain) || "example.com"
  const keyword = brand?.trim() || host
  const user = username?.trim() || "example-user"
  const mail = email?.trim() || `security@${host}`
  return [
    { title: "Domain footprint", queries: [`site:${host}`, `site:${host} -www`, `"${host}" -site:${host}`, `site:${host} inurl:login OR inurl:admin OR inurl:portal OR inurl:dashboard`] },
    { title: "Docs and exposed files", queries: [`site:${host} filetype:pdf OR filetype:docx OR filetype:xlsx`, `site:${host} filetype:env OR filetype:log OR filetype:bak`, `site:${host} intitle:"index of"`, `site:${host} "confidential" OR "internal use only"`] },
    { title: "Brand abuse / phishing", queries: [`"${keyword}" phishing`, `"${keyword}" "verify your account"`, `"${keyword}" "password reset"`, `"${keyword}" "security alert" -site:${host}`] },
    { title: "Code and secrets exposure", queries: [`"${host}" site:github.com OR site:gitlab.com`, `"${host}" "api_key" OR "token" OR "secret"`, `"@${host}" "password" OR "credential"`, `"${host}" site:gist.github.com OR site:pastebin.com`] },
    { title: "Email and mail posture", queries: [`"${mail}"`, `"@${host}"`, `"${host}" MX SPF DMARC`, `"_dmarc.${host}" OR "v=DMARC1"`] },
    { title: "Username / account reuse", queries: [`"${user}" github OR gitlab OR bitbucket`, `"${user}" site:pastebin.com OR site:gist.github.com`, `"${user}" "${host}"`, `"${user}" reddit OR twitter OR linkedin OR instagram`] },
    { title: "Support / exposed business surface", queries: [`site:${host} support OR helpdesk OR ticket OR status`, `site:${host} "vpn" OR "sso" OR "okta" OR "citrix"`, `site:${host} "jira" OR "confluence" OR "gitlab"`, `site:${host} "privacy" OR "terms" OR "security"`] },
    { title: "Historical and archive pivots", queries: [`web.archive.org ${host}`, `"${host}" "cached"`, `"${host}" "old" OR "backup" OR "archive"`, `"${keyword}" "domain" "changed"`] },
  ]
}

function CompactProfile({ rows }) {
  if (!rows.length) return null
  return <div className="grid gap-2 md:grid-cols-2 xl:grid-cols-4">{rows.map(([k, v]) => <div key={`${k}-${v}`} className="rounded-xl border border-white/10 bg-black/25 p-3"><p className="text-[0.65rem] font-black uppercase tracking-[0.14em] text-cyan-200">{k}</p><p className="mt-1 text-sm font-bold text-zinc-100">{v}</p></div>)}</div>
}

function ToolPicker({ status, runners, selected, onSelect, refreshStatus, loadingStatus }) {
  const runnable = status?.runnable || {}
  const checked = Boolean(status)
  const available = runners.filter((runner) => Boolean(runnable?.[runner.id]?.available)).length
  return <section className="space-y-3 rounded-2xl border border-white/10 bg-black/40 p-4">
    <div className="flex flex-wrap items-center justify-between gap-3">
      <div>
        <p className="text-xs font-black uppercase tracking-[0.14em] text-cyan-200">Local helpers</p>
        <h2 className="text-lg font-black text-zinc-50">Explicit backend runs</h2>
        <p className="mt-1 text-xs leading-5 text-zinc-400">No passive enum helper runs until you click Run.</p>
      </div>
      <button className="ba-button-secondary rounded-xl px-3 py-2 text-sm font-bold" onClick={refreshStatus}>
        <RefreshCcw className="mr-2 inline h-4 w-4" />{loadingStatus ? "Checking…" : checked ? `${available}/${runners.length} ready` : "Check tools"}
      </button>
    </div>
    <div className="grid gap-2 sm:grid-cols-2 xl:grid-cols-3">{runners.map((runner) => {
      const ready = checked ? Boolean(runnable?.[runner.id]?.available) : null
      return <button key={runner.id} type="button" onClick={() => onSelect(runner.id)} className={`rounded-xl border p-3 text-left transition ${selected === runner.id ? "border-cyan-300/60 bg-cyan-400/10" : "border-white/10 bg-black/40 hover:border-white/10"}`}>
        <div className="flex items-center justify-between gap-2"><span className="text-sm font-black text-zinc-100">{runner.label}</span><span className={`rounded-full border px-2 py-0.5 text-[0.65rem] font-black uppercase tracking-[0.12em] ${ready === true ? "border-emerald-300/40 text-emerald-200" : ready === false ? "border-amber-300/40 text-amber-200" : "border-white/10 text-zinc-500"}`}>{ready === true ? "ready" : ready === false ? "missing" : runner.type}</span></div>
        <p className="mt-1 text-xs leading-5 text-zinc-400">{runner.detail}</p>
      </button>
    })}</div>
  </section>
}

function ToolInventorySummary({ status }) {
  const categories = status?.categories || {}
  const entries = Object.entries(categories)
  if (!entries.length) return null
  return <section className="rounded-2xl border border-white/10 bg-black/40 p-4">
    <div className="flex flex-wrap items-center justify-between gap-3">
      <div>
        <p className="text-xs font-black uppercase tracking-[0.14em] text-cyan-200">Optional tool inventory</p>
        <h3 className="text-lg font-black text-zinc-50">Same categories as installer and doctor</h3>
      </div>
      <span className="rounded-full border border-white/10 px-2 py-1 text-xs font-black text-zinc-300">{status.available_count}/{status.total_count} runnable helpers</span>
    </div>
    <div className="mt-3 grid gap-3 lg:grid-cols-2">
      {entries.map(([category, tools]) => {
        const ready = tools.filter((tool) => tool.available).length
        return <details key={category} className="rounded-xl border border-white/10 bg-black/20 p-3">
          <summary className="cursor-pointer list-none">
            <div className="flex items-center justify-between gap-3">
              <strong className="text-sm font-black text-zinc-100">{category}</strong>
              <span className="rounded-full border border-white/10 px-2 py-0.5 text-[0.65rem] font-black uppercase tracking-[0.12em] text-zinc-300">{ready}/{tools.length}</span>
            </div>
          </summary>
          <div className="mt-3 flex flex-wrap gap-2">
            {tools.map((tool) => <span key={tool.id} className={`rounded-lg border px-2 py-1 text-xs font-bold ${tool.available ? "border-emerald-300/30 text-emerald-100" : "border-amber-300/25 text-amber-100"}`}>{tool.command}</span>)}
          </div>
        </details>
      })}
    </div>
  </section>
}

function TerminalOutput({ result }) {
  const text = result ? [result.command || result.command_preview || "", result.install_hint ? `# ${result.install_hint}` : "", result.stdout || "", result.stderr ? `\n[stderr]\n${result.stderr}` : "", result.error ? `\n[error]\n${result.error}` : ""].filter(Boolean).join("\n") : "Run a backend helper to view command output."
  return <details className="rounded-2xl border border-emerald-400/15 bg-black p-4 shadow-[inset_0_0_32px_rgba(16,185,129,0.08)]"><summary className="cursor-pointer list-none"><div className="flex items-center justify-between gap-3"><div className="flex items-center gap-2"><Terminal className="h-4 w-4 text-emerald-300" /><span className="text-sm font-black text-zinc-100">Terminal log</span></div><span className="font-mono text-[0.65rem] font-bold uppercase tracking-[0.16em] text-emerald-300">collapsed</span></div></summary><pre className="mt-3 max-h-[24rem] overflow-auto whitespace-pre-wrap border-t border-emerald-400/10 pt-3 font-mono text-xs leading-5 text-emerald-300">{text}</pre></details>
}

function QueryPack({ packs, setNotice }) {
  return <div className="grid gap-3 lg:grid-cols-2">{packs.map((pack, index) => (
    <details key={pack.title} open={index === 0} className="rounded-2xl border border-white/10 bg-black/40 p-4">
      <summary className="cursor-pointer list-none">
        <div className="flex items-center justify-between gap-3">
          <div><h3 className="text-sm font-black text-zinc-50">{pack.title}</h3><p className="mt-1 text-xs text-zinc-400">{pack.queries.length} prepared search strings</p></div>
          <span className="rounded-full border border-white/10 px-2 py-1 text-xs font-black text-zinc-300">{pack.queries.length}</span>
        </div>
      </summary>
      <div className="mt-3 space-y-2">
        <button className="ba-button-ghost rounded-lg px-2 py-1 text-xs font-bold" onClick={() => copyText(pack.queries.join("\n"), setNotice, "Queries copied")}><Clipboard className="mr-1 inline h-3.5 w-3.5" />Copy pack</button>
        {pack.queries.map((query) => <code key={query} className="block rounded-xl border border-white/10 bg-black/40 p-3 text-xs leading-5 text-zinc-200">{query}</code>)}
      </div>
    </details>
  ))}</div>
}

function ExternalReconLinks({ groups }) {
  return <div className="grid gap-3 lg:grid-cols-2">{groups.map((group) => (
    <details key={group.title} className="rounded-2xl border border-white/10 bg-black/40 p-4">
      <summary className="cursor-pointer list-none">
        <div className="flex items-start justify-between gap-3">
          <div><p className="text-xs font-black uppercase tracking-[0.14em] text-cyan-200">{group.title}</p><p className="mt-1 text-sm leading-6 text-zinc-300">{group.purpose}</p></div>
          <span className="rounded-full border border-white/10 px-2 py-1 text-xs font-black text-zinc-300">{group.links.length}</span>
        </div>
      </summary>
      <div className="mt-4 flex flex-wrap gap-2">{group.links.map(([label, href]) => <a key={`${group.title}-${label}`} className="rounded-xl border border-white/10 bg-black/40 px-3 py-2 text-sm font-bold text-zinc-200 hover:border-cyan-300/50 hover:text-cyan-100" href={href} target="_blank" rel="noreferrer">{label}<ExternalLink className="ml-2 inline h-3.5 w-3.5" /></a>)}</div>
    </details>
  ))}</div>
}

export default function OsintToolsPage({ setPage }) {
  const pending = useMemo(() => readPendingArtifact(), [])
  const [domain, setDomain] = useState(() => targetFromArtifact(pending))
  const [brand, setBrand] = useState(pending?.brand || "")
  const [username, setUsername] = useState(pending?.username || "")
  const [email, setEmail] = useState(pending?.email || "")
  const [source, setSource] = useState("duckduckgo")
  const [limit, setLimit] = useState(50)
  const [runner, setRunner] = useState("dns_basic")
  const [status, setStatus] = useState(null)
  const [loadingStatus, setLoadingStatus] = useState(false)
  const [running, setRunning] = useState(false)
  const [result, setResult] = useState(null)
  const [notice, setNotice] = useState("")
  const [loadedFrom, setLoadedFrom] = useState(() => {
    const target = targetFromArtifact(pending)
    return target || pending?.brand || pending?.username || pending?.email ? pending?.source || "another workspace" : ""
  })
  const [workspaceBuilt, setWorkspaceBuilt] = useState(false)

  const hasInput = Boolean(cleanHost(domain) || brand.trim() || username.trim() || email.trim())
  const queryPacks = useMemo(() => makeQueryPacks({ domain, brand, username, email }), [domain, brand, username, email])
  const externalGroups = useMemo(() => makeExternalGroups({ domain, brand, username, email }), [domain, brand, username, email])
  const profileRows = useMemo(() => targetProfile({ domain, brand, username, email }), [domain, brand, username, email])
  const selectedRunner = LOCAL_RUNNERS.find((item) => item.id === runner) || LOCAL_RUNNERS[0]
  const host = cleanHost(domain)

  const osintSummary = useMemo(() => {
    const target = host || brand || username || email || "OSINT target"
    const queryText = queryPacks.flatMap((pack) => [`# ${pack.title}`, ...pack.queries]).join("\n")
    return {
      type: host ? "domain" : "osint_context",
      title: `OSINT workspace: ${target}`,
      value: [host, brand, username, email].filter(Boolean).join("\n") || target,
      summary: `Manual OSINT query packs and pivots prepared for ${target}.`,
      raw: queryText,
      tags: ["osint", host ? "domain" : "identity"],
    }
  }, [brand, email, host, queryPacks, username])

  async function refreshStatus() {
    setLoadingStatus(true)
    try { setStatus(await getLocalOsintTools()) } catch (error) { setNotice(`Tool status failed: ${error.message}`) } finally { setLoadingStatus(false) }
  }

  function loadSample() {
    setDomain("example.com")
    setBrand("Example Brand")
    setUsername("example-user")
    setEmail("security@example.com")
    setWorkspaceBuilt(false)
    setNotice("Sample target loaded. Click Build workspace before generating pivots.")
  }

  function clearWorkspace() {
    setDomain("")
    setBrand("")
    setUsername("")
    setEmail("")
    setResult(null)
    setNotice("")
    setLoadedFrom("")
    setWorkspaceBuilt(false)
  }

  async function runBackendTool() {
    if (!host) { setNotice("Enter a domain first."); return }
    setRunning(true)
    setNotice(`Running ${selectedRunner.label}...`)
    try {
      const response = await runLocalOsintTool({ toolId: runner, domain: host, source, limit, confirmPermission: true })
      setResult(response)
      setNotice(response?.error ? `${selectedRunner.label} returned a note.` : `${selectedRunner.label} finished.`)
    } catch (error) {
      setResult({ error: error.message, command_preview: selectedRunner.label })
      setNotice(`Local helper failed: ${error.message}`)
    } finally {
      setRunning(false)
    }
  }

  function sendTarget(page) {
    if (!host) { setNotice("Enter a domain/host first."); return }
    setPendingArtifact({ target: page, page, type: "domain", value: host, domain: host, brand, username, email })
    setPage?.(page)
  }

  return <WorkbenchPage className="ba-osint-page">
      <WorkbenchHeader
        eyebrow="OSINT tools"
        title="OSINT Research Workspace"
        subtitle="Build query packs, manual research pivots, and explicit local helper runs for authorized public-footprint investigation."
        icon={Search}
        chips={[
          { label: "manual research", tone: "info" },
          { label: "local helpers", tone: "local" },
          { label: "query packs", tone: "warning" },
        ]}
        actions={(
          <details className="rounded-xl border border-white/10 bg-black/40 px-3 py-2 text-sm">
            <summary className="cursor-pointer list-none font-black text-zinc-200"><FileText className="mr-2 inline h-4 w-4" />Sample</summary>
            <button className="mt-3 ba-button-secondary rounded-xl px-3 py-2 text-sm font-bold" onClick={loadSample}>Load sample target</button>
          </details>
        )}
      />
      <WorkbenchPanel className="space-y-4">
        {loadedFrom ? <p className="rounded-xl border border-cyan-300/20 bg-cyan-400/10 p-3 text-sm font-bold text-cyan-100">Loaded from {loadedFrom}</p> : null}
      <section className="grid gap-4 rounded-2xl border border-white/10 bg-black/40 p-4 xl:grid-cols-[1fr_18rem]">
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
          <label className="block space-y-2 xl:col-span-2"><span className="ba-field-label">Primary domain / target</span><input className="ba-input text-base" value={domain} onChange={(e) => { setDomain(e.target.value); setWorkspaceBuilt(false) }} placeholder="example.com" /></label>
          <label className="block space-y-2"><span className="ba-field-label">Brand / keyword</span><input className="ba-input" value={brand} onChange={(e) => { setBrand(e.target.value); setWorkspaceBuilt(false) }} placeholder="Optional brand" /></label>
          <label className="block space-y-2"><span className="ba-field-label">Email</span><input className="ba-input" value={email} onChange={(e) => { setEmail(e.target.value); setWorkspaceBuilt(false) }} placeholder="security@example.com" /></label>
          <label className="block space-y-2"><span className="ba-field-label">Username / handle</span><input className="ba-input" value={username} onChange={(e) => { setUsername(e.target.value); setWorkspaceBuilt(false) }} placeholder="Optional username" /></label>
        </div>
        <div className="space-y-2 rounded-xl border border-white/10 bg-black/25 p-3">
          <p className="text-xs font-black uppercase tracking-[0.14em] text-cyan-200">Actions</p>
          <button className="ba-button-primary w-full rounded-xl px-3 py-2 text-sm font-black" disabled={!hasInput} onClick={() => { setWorkspaceBuilt(true); setNotice("Workspace built from current target fields. No external lookup ran automatically.") }}><Search className="mr-2 inline h-4 w-4" />Build workspace</button>
          <button className="ba-button-secondary w-full rounded-xl px-3 py-2 text-sm font-bold" onClick={() => host ? copyText(host, setNotice, "Target copied") : setNotice("No target to copy.")}><Clipboard className="mr-2 inline h-4 w-4" />Copy target</button>
          <button className="ba-button-ghost w-full rounded-xl px-3 py-2 text-sm font-bold" onClick={clearWorkspace}><Trash2 className="mr-2 inline h-4 w-4" />Clear</button>
        </div>
      </section>
      {notice ? <p className="rounded-xl border border-white/10 bg-black/40 p-3 text-sm text-zinc-300">{notice}</p> : null}
    </WorkbenchPanel>

    {hasInput && workspaceBuilt ? <>
      <WorkbenchPanel className="space-y-4">
        <div className="ba-output-section-head">
          <div><p className="ba-output-section-eyebrow" style={{ color: "var(--neo-cyan)" }}>Research brief</p><h2 className="ba-output-section-title">Target context</h2></div>
          <div className="flex flex-wrap gap-2">
            <button className="ba-button-secondary rounded-xl px-3 py-2 text-sm font-bold" onClick={() => sendTarget("recon-exposure")}><ArrowRightLeft className="mr-2 inline h-4 w-4" />Recon</button>
            <button className="ba-button-secondary rounded-xl px-3 py-2 text-sm font-bold" onClick={() => sendTarget("safe-url-analyzer")}><ArrowRightLeft className="mr-2 inline h-4 w-4" />Safe URL</button>
            <button className="ba-button-secondary rounded-xl px-3 py-2 text-sm font-bold" onClick={() => sendTarget("smart-parser")}><ArrowRightLeft className="mr-2 inline h-4 w-4" />Parser</button>
            <button className="ba-button-secondary rounded-xl px-3 py-2 text-sm font-bold" onClick={() => sendTarget("cyberchef")}><ArrowRightLeft className="mr-2 inline h-4 w-4" />CyberChef</button>
            <button className="ba-button-secondary rounded-xl px-3 py-2 text-sm font-bold" onClick={() => {
              const entry = addTimelineArtifact({ title: `OSINT workspace: ${host || brand || username || email}`, summary: `Manual OSINT query packs prepared for ${host || brand || username || email}.`, source: "OSINT Tools", raw: queryPacks.flatMap((pack) => [`# ${pack.title}`, ...pack.queries]).join("\n"), tags: ["osint", host ? "domain" : "identity"] })
              setNotice(`Added to Case Timeline: ${entry.title}`)
            }}>Timeline</button>
          </div>
        </div>
        <CompactProfile rows={profileRows} />
        <AnalystOutputCard
          title="OSINT output quality"
          verdict="manual research workspace"
          confidence="no automatic external lookup"
          summary={`Generated manual research pivots for ${host || brand || username || email}. Use links and helper output as documented research paths, not reputation verdicts.`}
          evidence={[`${queryPacks.length} query pack(s) prepared`, `${externalGroups.length} external pivot group(s) available`, result ? `${selectedRunner.label} helper has output` : "No backend helper output yet"]}
          limitations={["Manual external links are not queried automatically by BeyondArch.", "Backend helpers are point-in-time observations and may require installed local tools.", "Public OSINT context should be verified before adding findings."]}
          nextActions={["Copy relevant query packs into notes.", "Run backend helper only for authorized targets.", "Send confirmed domains/IPs to Recon or Safe URL Analyzer."]}
          metrics={[
            ["Target", host || brand || username || email],
            ["Query packs", queryPacks.length],
            ["Helper", result ? selectedRunner.label : "not run"],
          ]}
        />
        <SendToActions payload={osintSummary} source="OSINT Tools" setPage={setPage} compact />
      </WorkbenchPanel>

      <details className="ba-workbench-panel p-4">
        <summary className="cursor-pointer text-lg font-black text-zinc-50">Raw details & analysis state</summary>
        <pre className="mt-3 max-h-80 overflow-auto whitespace-pre-wrap rounded-xl border border-white/10 bg-black/40 p-4 text-xs leading-5 text-zinc-100">{JSON.stringify({ target: { domain, brand, username, email }, status: status ? { available_count: status.available_count, total_count: status.total_count } : null, result: result || null }, null, 2)}</pre>
      </details>

      <WorkbenchPanel className="space-y-4">
        <div className="ba-output-section-head">
          <div><p className="ba-output-section-eyebrow" style={{ color: "var(--neo-cyan)" }}>Research board</p><h2 className="ba-output-section-title">Query packs and manual pivots</h2><p className="mt-1 text-sm leading-6 text-zinc-300">One workspace for manual dorks, reputation pivots, cert/DNS lookups, brand checks, and identity research. Nothing is queried automatically.</p></div>
          <button className="ba-button-secondary rounded-xl px-3 py-2 text-sm font-bold" onClick={() => copyText(queryPacks.flatMap((pack) => [`# ${pack.title}`, ...pack.queries, ""]).join("\n"), setNotice, "All query packs copied")}><Clipboard className="mr-2 inline h-4 w-4" />Copy all queries</button>
        </div>
        <div className="grid gap-4 2xl:grid-cols-[1fr_0.92fr]">
          <section className="space-y-3 rounded-2xl border border-white/10 bg-black/40 p-4">
            <div><p className="text-xs font-black uppercase tracking-[0.14em] text-zinc-400">Generated search strings</p><h3 className="text-lg font-black text-zinc-50">Query packs</h3></div>
            <QueryPack packs={queryPacks} setNotice={setNotice} />
          </section>
          <section className="space-y-3 rounded-2xl border border-white/10 bg-black/40 p-4">
            <div><p className="text-xs font-black uppercase tracking-[0.14em] text-zinc-400">Manual pivots</p><h3 className="text-lg font-black text-zinc-50">External research links</h3></div>
            <ExternalReconLinks groups={externalGroups} />
          </section>
        </div>
      </WorkbenchPanel>

      <WorkbenchPanel className="space-y-4">
        <div className="ba-output-section-head">
          <div><p className="ba-output-section-eyebrow" style={{ color: "var(--neo-cyan)" }}>Backend helpers</p><h2 className="ba-output-section-title">Terminal-assisted OSINT</h2><p className="mt-1 text-sm leading-6 text-zinc-300">Optional local wrappers for DNS, mail posture, headers, TLS, WHOIS, and passive enum tools. Use only for authorized targets.</p></div>
          <span className="rounded-full border border-amber-300/25 bg-amber-400/10 px-3 py-1 text-xs font-black uppercase tracking-[0.14em] text-amber-100"><ShieldCheck className="mr-1 inline h-3.5 w-3.5" />Explicit run only</span>
        </div>
        <div className="grid gap-4 xl:grid-cols-[1fr_0.9fr]">
          <div className="space-y-4">
            <ToolPicker status={status} runners={LOCAL_RUNNERS} selected={runner} onSelect={setRunner} refreshStatus={refreshStatus} loadingStatus={loadingStatus} />
            <ToolInventorySummary status={status} />
            <section className="space-y-3 rounded-2xl border border-white/10 bg-black/40 p-4">
              <div className="flex items-start gap-3"><Wrench className="mt-1 h-5 w-5 text-cyan-200" /><div><h3 className="text-lg font-black text-zinc-50">{selectedRunner.label}</h3><p className="text-sm leading-6 text-zinc-300">{selectedRunner.detail}</p></div></div>
              {runner === "theharvester" ? <div className="grid gap-3 sm:grid-cols-2"><label className="block space-y-2"><span className="ba-field-label">Source</span><select className="ba-input" value={source} onChange={(e) => setSource(e.target.value)}>{HARVESTER_SOURCES.map((item) => <option key={item} value={item}>{item}</option>)}</select></label><label className="block space-y-2"><span className="ba-field-label">Limit</span><input className="ba-input" type="number" min="10" max="200" value={limit} onChange={(e) => setLimit(Number(e.target.value) || 50)} /></label></div> : null}
              <button className="ba-button-primary w-full rounded-xl px-4 py-3 text-sm font-black disabled:opacity-50" disabled={running || !host} onClick={runBackendTool}><Play className="mr-2 inline h-4 w-4" />{running ? "Running…" : `Run ${selectedRunner.label}`}</button>
            </section>
          </div>
          <div className="space-y-3">
            <div className="rounded-2xl border border-white/10 bg-black/40 p-4"><p className="text-xs font-black uppercase tracking-[0.14em] text-cyan-200">Helper result</p><p className="mt-2 text-sm leading-6 text-zinc-300">{result ? (result.error ? "Helper returned an error or install hint." : `${selectedRunner.label} completed. Review terminal details if needed.`) : "Run a helper only if local backend evidence is needed."}</p></div>
            <TerminalOutput result={result} />
          </div>
        </div>
      </WorkbenchPanel>
    </> : <WorkbenchPanel className="space-y-4">
        <div className="rounded-2xl border border-white/10 bg-black/40 p-6 text-center">
          <Search className="mx-auto h-10 w-10 text-zinc-500" />
          <h3 className="mt-4 text-lg font-black text-zinc-50">No workspace built yet</h3>
          <p className="mt-2 text-sm leading-6 text-zinc-300">Enter a domain, brand, username, or email above, then click <strong>Build workspace</strong> to generate query packs, research links, and helper tools. Nothing is looked up or generated automatically.</p>
          <div className="mt-4 flex flex-wrap justify-center gap-2">
            <span className="rounded-lg border border-white/10 bg-black/40 px-3 py-1.5 text-xs font-bold text-zinc-300">Query packs</span>
            <span className="rounded-lg border border-white/10 bg-black/40 px-3 py-1.5 text-xs font-bold text-zinc-300">External links</span>
            <span className="rounded-lg border border-white/10 bg-black/40 px-3 py-1.5 text-xs font-bold text-zinc-300">DNS helpers</span>
          </div>
        </div>
      </WorkbenchPanel>}
  </WorkbenchPage>
}
