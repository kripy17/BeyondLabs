import { Clipboard, ExternalLink } from "lucide-react"

export function CompactValueGrid({ fields = [], className = "" }) {
  const visible = fields.filter(([, value]) => value !== undefined && value !== null && String(value).trim() !== "" && String(value).trim() !== "0")
  if (!visible.length) return null
  return (
    <div className={`ba-url-compact-value-grid ${className}`}>
      {visible.map(([label, value]) => (
        <article key={`${label}-${value}`}>
          <p>{label}</p>
          <strong>{String(value)}</strong>
        </article>
      ))}
    </div>
  )
}

export function EvidenceList({ findings = [], compact = false }) {
  if (!findings.length) return <p className="ba-empty-state">No notable evidence recorded yet.</p>
  const tagClass = (severity = "") => {
    const lower = severity.toLowerCase()
    if (lower === "high") return "ba-tag-rose"
    if (lower === "medium") return "ba-tag-amber"
    if (lower === "low") return "ba-tag-emerald"
    return "ba-tag-zinc"
  }
  return (
    <div className={compact ? "grid gap-2" : "grid gap-3 md:grid-cols-2"}>
      {findings.map((item, index) => (
        <article key={`${item.signal}-${index}`} className="ba-card">
          <div className="flex flex-wrap items-center gap-2">
            <span className={tagClass(item.severity)}>{item.severity}</span>
            {item.source ? <span className="ba-tag-zinc">{item.source}</span> : null}
          </div>
          <h3 className="mt-2 text-sm font-black text-zinc-50">{item.signal}</h3>
          {item.evidence ? <p className="mt-1 break-all font-mono text-xs text-zinc-200">{item.evidence}</p> : null}
          {item.meaning ? <p className="mt-2 text-xs leading-5 text-zinc-300">{item.meaning}</p> : null}
          {item.action ? <p className="mt-2 text-xs font-bold leading-5 text-cyan-100">{item.action}</p> : null}
        </article>
      ))}
    </div>
  )
}

const EXTERNAL_RECON_GROUPS = [
  ["DNS", "DNS records, propagation, mail posture, and public DNS mapping."],
  ["Whois", "Ownership, registration, reverse-IP, and related domain context."],
  ["Exposure", "Public internet exposure search engines and certificate transparency pivots."],
  ["Reputation", "Manual reputation and abuse checks. No automatic API queries are made."],
  ["URL", "URL-specific metadata, security headers, and safe website review shortcuts."],
]

export function ExternalReconLinks({ links = [] }) {
  if (!links.length) return null
  const grouped = links.reduce((acc, link) => {
    acc[link.group] ||= []
    acc[link.group].push(link)
    return acc
  }, {})
  const orderedGroups = EXTERNAL_RECON_GROUPS
    .map(([group, description]) => ({ group, description, items: grouped[group] || [] }))
    .filter((entry) => entry.items.length)
  return (
    <div className="space-y-3">
      {orderedGroups.map(({ group, description, items }) => (
        <section key={group} className="ba-card">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div>
              <p className="ba-output-section-eyebrow" style={{ color: "var(--clr-accent)" }}>{group}</p>
              <p className="mt-1 text-xs leading-5 text-zinc-400">{description}</p>
            </div>
            <span className="ba-tag-zinc">{items.length}</span>
          </div>
          <div className="mt-3 grid gap-2 md:grid-cols-2 xl:grid-cols-3">
            {items.map((item) => (
              <a key={`${item.label}-${item.href}`} href={item.href} target="_blank" rel="noreferrer" className="rounded-xl border border-cyan-400/15 bg-cyan-400/7 p-3 text-sm text-zinc-100 transition hover:border-cyan-300/40 hover:bg-cyan-400/12">
                <span className="flex items-center justify-between gap-2 font-black text-cyan-50">{item.label}<ExternalLink className="h-3.5 w-3.5" /></span>
                <span className="mt-1 block text-xs leading-5 text-zinc-300">{item.note}</span>
              </a>
            ))}
          </div>
        </section>
      ))}
    </div>
  )
}

export function QueryCards({ queries = [], onCopy }) {
  if (!queries.length) return null
  return (
    <div className="grid gap-2 md:grid-cols-2">
      {queries.map((item) => (
        <article key={item.label} className="ba-ds-panel p-3">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <p className="text-xs font-black uppercase tracking-[0.14em] text-zinc-400">{item.label}</p>
            <button className="text-xs font-bold text-cyan-100 hover:text-cyan-50" onClick={() => onCopy?.(item.query, item.label)}><Clipboard className="mr-1 inline h-3.5 w-3.5" />Copy</button>
          </div>
          <code className="mt-2 block break-all rounded-lg bg-black/40 p-2 text-xs leading-5 text-zinc-100">{item.query}</code>
        </article>
      ))}
    </div>
  )
}
