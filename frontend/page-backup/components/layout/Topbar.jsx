import { useEffect, useMemo, useRef, useState } from "react"
import { createPortal } from "react-dom"
import { useNavigate } from "react-router-dom"
import { motion, AnimatePresence } from "framer-motion"
import {
  Activity,
  AlertTriangle,
  ArrowRight,
  BookOpen,
  CheckCircle2,
  Clock3,
  Code2,
  Command,
  Database,
  FileText,
  GitBranch,
  Lightbulb,
  NotebookPen,
  Search,
  Settings,
  ShieldCheck,
  Sparkles,
  TerminalSquare,
  User,
  X,
} from "lucide-react"
import { getJson } from "../../lib/apiClient"
import { useInvestigation } from "../../context/InvestigationContext"
import ThemeSwitcher from "./ThemeSwitcher"
import { KNOWLEDGE_BASE } from "../../lib/localKnowledgeBase"
import { ROUTE_MAP } from "../../lib/navigation"

function getActiveGroup(groups, page) {
  if (page === "home" || page === "beyondarch") return "home"
  if (page === "settings") return "settings"
  return groups.find((group) => group.items.some((item) => item.page === page))?.id || ""
}

function labelStatus(status) {
  if (status === "online") return "online"
  if (status === "checking") return "checking"
  return "offline"
}

function CommandPalette({ open, query, setQuery, options, onChoose, onClose }) {
  const inputRef = useRef(null)
  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase()
    const source = needle
      ? options.filter((item) => (item.searchText || `${item.label} ${item.group || ""} ${item.description || ""} ${item.page || ""}`).toLowerCase().includes(needle))
      : options
    return source.slice(0, 14)
  }, [options, query])

  useEffect(() => {
    if (open) window.setTimeout(() => inputRef.current?.focus(), 20)
  }, [open])

  if (!open) return null

  return createPortal(
    <AnimatePresence>
      {open && (
        <div className="ba-command-overlay" role="dialog" aria-modal="true" aria-label="BeyondArch command palette">
          <motion.button
            className="ba-command-backdrop" type="button" aria-label="Close command palette" onClick={onClose}
            initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
            transition={{ duration: 0.15 }}
          />
          <motion.section
            className="ba-command-panel"
            initial={{ opacity: 0, scale: 0.96, y: -8 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.96, y: -8 }}
            transition={{ duration: 0.2, ease: "easeOut" }}
          >
            <div className="ba-command-input-row">
              <Command className="h-5 w-5" />
              <input
                ref={inputRef}
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                placeholder="Search tools, artifacts, commands…"
                onKeyDown={(event) => {
                  if (event.key === "Escape") onClose()
                  if (event.key === "Enter" && filtered[0]) onChoose(filtered[0])
                }}
              />
              <button type="button" onClick={onClose} aria-label="Close command palette"><X className="h-4 w-4" /></button>
            </div>
            <div className="ba-command-results">
              {filtered.length ? filtered.map((item) => {
                const Icon = item.icon || Sparkles
                return (
                  <button key={`${item.kind || "item"}-${item.group || "main"}-${item.page || item.id || item.label}`} type="button" onClick={() => onChoose(item)}>
                    <span className="ba-command-result-icon"><Icon className="h-4 w-4" /></span>
                    <span>
                      <strong>{item.label}</strong>
                      <small>{item.group ? `${item.group} · ` : ""}{item.description}</small>
                    </span>
                    {item.kind ? <em>{item.kind}</em> : null}
                    <ArrowRight className="h-4 w-4" />
                  </button>
                )
              }) : <p className="ba-command-empty">No result. Try "URL", "Phishing", "Logs", "Nmap", "Timeline", or a saved artifact.</p>}
            </div>
            <div className="ba-command-footer"><span>Ctrl K</span><span>Enter opens first result</span><span>Esc closes</span></div>
          </motion.section>
        </div>
      )}
    </AnimatePresence>,
    document.body,
  )
}

function NavDropdown({ group, onChoose, onClose, page, anchor }) {
  const ref = useRef(null)

  useEffect(() => {
    function handlePointerDown(event) {
      if (ref.current && !ref.current.contains(event.target)) onClose()
    }
    function closeOnLayoutChange() {
      onClose()
    }
    window.addEventListener("pointerdown", handlePointerDown)
    window.addEventListener("resize", closeOnLayoutChange)
    window.addEventListener("scroll", closeOnLayoutChange, true)
    return () => {
      window.removeEventListener("pointerdown", handlePointerDown)
      window.removeEventListener("resize", closeOnLayoutChange)
      window.removeEventListener("scroll", closeOnLayoutChange, true)
    }
  }, [onClose])

  return createPortal(
    <AnimatePresence>
      {group && anchor && (() => {
        const w = Math.min(440, Math.max(320, window.innerWidth - 24))
        const l = Math.min(Math.max(anchor.left + anchor.width / 2, w / 2 + 12), window.innerWidth - w / 2 - 12)
        const t = Math.max(anchor.bottom + 12, 62)
        return (
          <div className="ba-nav-layer">
            <motion.section
              ref={ref} className="ba-nav-dropdown ba-topbar-dropdown-portal"
              initial={{ opacity: 0, y: -6, scale: 0.97 }}
              animate={{ opacity: 1, y: 0, scale: 1 }}
              exit={{ opacity: 0, y: -6, scale: 0.97 }}
              transition={{ duration: 0.18, ease: "easeOut" }}
              style={{ "--ba-menu-left": `${l}px`, "--ba-menu-top": `${t}px`, "--ba-menu-width": `${w}px` }}
            >
            <div className="ba-nav-dropdown-head">
              <strong>{group.label}</strong>
              <span>{group.description}</span>
            </div>
            <div className="ba-nav-dropdown-list">
              {group.items.map((item) => {
                const Icon = item.icon || Sparkles
                const active = page === item.page
                return (
                  <button key={item.page} type="button" className={active ? "is-active" : ""} aria-label={`Open ${item.label}`} onClick={() => onChoose(item.page)}>
                    <span><Icon className="h-4 w-4" /></span>
                    <span><strong>{item.label}</strong><small>{item.description}</small></span>
                    {active ? <CheckCircle2 className="h-4 w-4" /> : <ArrowRight className="h-4 w-4" />}
                  </button>
                )
              })}
            </div>
          </motion.section>
        </div>
      )
      })()}
    </AnimatePresence>,
    document.body,
  )
}

function StatusPopover({ open, backendStatus, toolStatus, onRefresh, onSettings }) {
  return (
    <AnimatePresence>
      {open && (
        <motion.section
          className="ba-status-popover" aria-label="System status"
          initial={{ opacity: 0, scale: 0.95, y: -4 }}
          animate={{ opacity: 1, scale: 1, y: 0 }}
          exit={{ opacity: 0, scale: 0.95, y: -4 }}
          transition={{ duration: 0.15, ease: "easeOut" }}
        >
          <div className="ba-status-head">
            <div><strong>Runtime</strong><span>Backend and local tool checks</span></div>
            <button type="button" onClick={onRefresh}>Refresh</button>
          </div>
          <div className="ba-status-grid">
            <article>
              <span className={`ba-status-led ba-status-${backendStatus}`}>{backendStatus === "online" ? <CheckCircle2 className="h-4 w-4" /> : <Activity className="h-4 w-4" />}</span>
              <div><strong>Backend</strong><small>{labelStatus(backendStatus)} /health</small></div>
            </article>
            <article>
              <span className={`ba-status-led ba-status-${toolStatus.status}`}>{toolStatus.status === "offline" ? <AlertTriangle className="h-4 w-4" /> : <TerminalSquare className="h-4 w-4" />}</span>
              <div><strong>Local tools</strong><small>{toolStatus.total ? `${toolStatus.available}/${toolStatus.total} available` : labelStatus(toolStatus.status)}</small></div>
            </article>
          </div>
          <button type="button" className="ba-status-settings" onClick={onSettings}><Settings className="h-4 w-4" /> Diagnostics</button>
        </motion.section>
      )}
    </AnimatePresence>
  )
}

export default function Topbar({ page, groups = [], options = [] }) {
  const [openGroup, setOpenGroup] = useState(null)
  const [anchor, setAnchor] = useState(null)
  const [commandOpen, setCommandOpen] = useState(false)
  const [query, setQuery] = useState("")
  const [backendStatus, setBackendStatus] = useState("checking")
  const [toolStatus, setToolStatus] = useState({ status: "checking", available: 0, total: 0 })
  const [statusOpen, setStatusOpen] = useState(false)
  const [userOpen, setUserOpen] = useState(false)
  const navigate = useNavigate()
  const navRef = useRef(null)

  const activeGroup = getActiveGroup(groups, page)
  const currentGroup = groups.find((group) => group.id === openGroup)
  const { state } = useInvestigation()


  const commandItems = useMemo(() => {
    const routeItems = options.map((item) => ({
      ...item,
      kind: item.group ? "module" : "nav",
      searchText: `${item.label} ${item.group || ""} ${item.description || ""} ${item.tags?.join(" ") || ""} ${item.page || ""}`,
    }))

    const actionItems = [
      { id: "action-intake", kind: "action", label: "Paste artifact into Intake", page: "smart-parser", group: "Action", icon: Sparkles, description: "Start analysis from a URL, IP, domain, hash, email, log, JSON, or encoded blob." },
      { id: "action-case", kind: "action", label: "Open case timeline and report", page: "case-timeline", group: "Action", icon: Clock3, description: "Review artifacts, timeline events, notes, hypotheses, findings, and report export." },
      { id: "action-settings-storage", kind: "action", label: "Change investigation storage", page: "settings", group: "Action", icon: Database, description: "Control whether analyzed data is stored for this session or restored after restart." },
      { id: "action-logs", kind: "action", label: "Explain a log event", page: "logs-alerts", group: "Action", icon: FileText, description: "Paste web, auth, DNS, firewall, proxy, or JSON logs for explanation and query building." },
      { id: "action-knowledge", kind: "action", label: "Search local knowledge base", page: "soc-guide", group: "Action", icon: BookOpen, description: "Open built-in SOC references, playbooks, and detection guidance." },
    ]

    const caseItems = [
      ...(state.artifacts || []).slice(0, 8).map((item) => ({ id: item.id, kind: "artifact", label: item.title || item.type || "Saved artifact", page: "case-timeline", group: "Saved artifact", icon: Database, description: `${item.type || "artifact"} ${String(item.value || "").slice(0, 120)}` })),
      ...(state.timeline || []).slice(0, 6).map((item) => ({ id: item.id, kind: "timeline", label: item.title || "Timeline event", page: "case-timeline", group: "Timeline", icon: GitBranch, description: `${item.severity || "info"} ${item.source || "BeyondArch"} ${item.summary || ""}` })),
      ...(state.findings || []).slice(0, 6).map((item) => ({ id: item.id, kind: "finding", label: item.title || "Finding", page: "case-timeline", group: "Finding", icon: ShieldCheck, description: `${item.severity || "medium"} ${item.confidence || "unknown"} confidence ${item.summary || ""}` })),
      ...(state.notes || []).slice(0, 4).map((item) => ({ id: item.id, kind: "note", label: item.title || "Analyst note", page: "case-timeline", group: "Note", icon: NotebookPen, description: item.note || item.summary || "Saved analyst note" })),
      ...(state.hypotheses || []).slice(0, 4).map((item) => ({ id: item.id, kind: "hypothesis", label: item.title || "Hypothesis", page: "case-timeline", group: "Hypothesis", icon: Lightbulb, description: `${item.status || "open"} ${item.confidence || "unknown"} confidence` })),
    ].map((item) => ({ ...item, searchText: `${item.label} ${item.group} ${item.description} ${item.kind}` }))

    const kbItems = KNOWLEDGE_BASE.map((entry) => ({
      id: entry.id,
      kind: "knowledge",
      label: entry.title,
      page: "soc-guide",
      group: `Knowledge ${entry.category}`,
      icon: BookOpen,
      description: entry.summary,
      searchText: `${entry.category} ${entry.title} ${entry.summary} ${entry.tags.join(" ")} ${entry.steps.join(" ")}`,
    }))

    return [...actionItems, ...routeItems, ...caseItems, ...kbItems]
  }, [options, state])

  function choose(nextPageOrItem) {
    const nextPage = typeof nextPageOrItem === "string" ? nextPageOrItem : nextPageOrItem?.page
    if (!nextPage) return
    navigate(ROUTE_MAP[nextPage] || "/")
    setOpenGroup(null)
    setAnchor(null)
    setCommandOpen(false)
    setStatusOpen(false)
    setUserOpen(false)
    setQuery("")
  }

  async function refreshStatus() {
    setBackendStatus("checking")
    setToolStatus((current) => ({ ...current, status: "checking" }))
    try {
      await getJson("/health", 2500)
      setBackendStatus("online")
    } catch {
      setBackendStatus("offline")
    }

    try {
      const payload = await getJson("/api/osint/local-tools", 3500)
      const tools = Array.isArray(payload?.tools) ? payload.tools : Array.isArray(payload) ? payload : Object.values(payload?.tools || {})
      const available = tools.filter((tool) => tool.available || tool.installed || tool.status === "available").length
      setToolStatus({ status: "online", available, total: tools.length })
    } catch {
      setToolStatus({ status: "offline", available: 0, total: 0 })
    }
  }

  useEffect(() => {
    const first = window.setTimeout(refreshStatus, 0)
    const id = window.setInterval(refreshStatus, 45000)
    return () => {
      window.clearTimeout(first)
      window.clearInterval(id)
    }
  }, [])

  useEffect(() => {
    function handleKeydown(event) {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") {
        event.preventDefault()
        setCommandOpen(true)
      }
      if (event.key === "Escape") {
        setOpenGroup(null)
        setAnchor(null)
        setCommandOpen(false)
        setStatusOpen(false)
      }
    }
    function openPalette() {
      setCommandOpen(true)
    }
    window.addEventListener("keydown", handleKeydown)
    window.addEventListener("beyondarch:open-command-palette", openPalette)
    return () => {
      window.removeEventListener("keydown", handleKeydown)
      window.removeEventListener("beyondarch:open-command-palette", openPalette)
    }
  }, [])

  useEffect(() => {
    function handlePointerDown(event) {
      if (event.target.closest?.(".ba-nav-layer")) return
      if (navRef.current && !navRef.current.contains(event.target)) {
        setOpenGroup(null)
        setAnchor(null)
        setStatusOpen(false)
      }
    }
    window.addEventListener("pointerdown", handlePointerDown)
    return () => window.removeEventListener("pointerdown", handlePointerDown)
  }, [])

  const liveOnline = backendStatus === "online"

  return (
    <header className="cyber-header" ref={navRef} aria-label="BeyondArch navigation">
      <div style={{
        display: "flex", justifyContent: "space-between", alignItems: "center",
        width: "100%", maxWidth: "1520px", margin: "0 auto",
        padding: "1rem 1.6rem",
      }}>
        {/* Left: brand + search */}
        <div style={{ display: "flex", alignItems: "center", gap: "3rem" }}>
          <button
            type="button"
            onClick={() => choose("home")}
            aria-label="BeyondArch local SOC workbench"
            style={{
              display: "flex", alignItems: "center", gap: ".75rem",
              background: "transparent", border: "none", cursor: "pointer",
              fontFamily: "inherit", padding: 0,
            }}
          >
            <Code2 className="cyber-brand-icon" style={{ fontSize: "1.875rem", color: "var(--clr-border)", filter: "drop-shadow(0 0 8px var(--clr-border))" }} />
            <span style={{ fontSize: "1.5rem", fontWeight: 950, letterSpacing: "-0.05em", textTransform: "uppercase", color: "var(--clr-text)" }}>
              BEYOND<span style={{ color: "var(--clr-border)", filter: "drop-shadow(0 0 5px var(--clr-border))" }}>ARCH</span>
            </span>
          </button>

          {/* Search bar — hidden below md */}
          <button
            type="button"
            onClick={() => setCommandOpen(true)}
            aria-label="Open command palette"
            className="hidden md:flex cyber-search"
            style={{
              alignItems: "center", gap: ".75rem",
              padding: ".375rem 1rem",
            }}
          >
            <Search style={{ fontSize: ".88rem", color: "var(--clr-accent)", fontWeight: 700 }} />
            <span style={{ fontSize: ".75rem", fontWeight: 700, color: "var(--clr-text-sub)" }}>Search tools, artifacts, commands…</span>
            <kbd style={{
              fontFamily: '"JetBrains Mono", ui-monospace, monospace',
              fontSize: ".65rem", color: "var(--clr-bg)",
              background: "var(--clr-accent)",
              border: "none",
              padding: ".125rem .5rem",
              fontWeight: 700,
            }}>CTRL K</kbd>
          </button>
        </div>

        {/* Center: nav links — hidden below lg */}
        <nav
          aria-label="Workspace groups"
          style={{
            alignItems: "center", gap: "2.5rem",
          }}
          className="hidden lg:flex"
        >
          {groups.map((group) => {
            const active = activeGroup === group.id
            return (
              <button
                key={group.id}
                type="button"
                onClick={(event) => {
                  const nextOpen = openGroup === group.id ? null : group.id
                  setOpenGroup(nextOpen)
                  setAnchor(nextOpen ? event.currentTarget.getBoundingClientRect() : null)
                }}
                style={{
                  background: "transparent", border: "none", cursor: "pointer",
                  color: active ? "var(--clr-text)" : "var(--clr-accent)",
                  fontSize: ".75rem", fontWeight: 950,
                  fontFamily: '"JetBrains Mono", ui-monospace, monospace',
                  textTransform: "uppercase", letterSpacing: ".1em",
                  padding: 0,
                  transition: "all 140ms ease",
                  filter: active ? "drop-shadow(0 0 8px var(--clr-accent))" : "none",
                }}
                onMouseEnter={e => { if (!active) { e.currentTarget.style.color = "var(--clr-text)"; e.currentTarget.style.filter = "drop-shadow(0 0 8px var(--clr-accent))" } }}
                onMouseLeave={e => { if (!active) { e.currentTarget.style.color = "var(--clr-accent)"; e.currentTarget.style.filter = "none" } }}
              >
                {group.label}
              </button>
            )
          })}
        </nav>

        {/* Right: Live_Core + buttons */}
        <div style={{ display: "flex", alignItems: "center", gap: "1rem" }}>
          <div style={{ position: "relative" }}>
            <button
              type="button"
              onClick={() => setStatusOpen((v) => !v)}
              aria-label="Open runtime status"
              className="cyber-live-btn"
              style={{
                display: "flex", alignItems: "center", gap: ".5rem",
                padding: ".375rem 1rem",
                border: liveOnline ? "var(--border-w) solid var(--clr-accent)" : "var(--border-w) solid var(--clr-border)",
              }}
            >
              <div className="status-led animate-pulse-fast" style={{ backgroundColor: liveOnline ? "var(--clr-accent)" : "var(--clr-border-30)", color: liveOnline ? "var(--clr-accent)" : "var(--clr-border-30)", borderColor: liveOnline ? "var(--clr-accent)" : "var(--clr-border-30)" }} />
              <span style={{ fontFamily: '"JetBrains Mono", ui-monospace, monospace', fontSize: ".7rem", fontWeight: 950, letterSpacing: ".1em", textTransform: "uppercase", color: liveOnline ? "var(--clr-accent)" : "var(--clr-text-sub)" }}>
                {liveOnline ? "ONLINE" : "OFFLINE"}
              </span>
            </button>
            <StatusPopover open={statusOpen} backendStatus={backendStatus} toolStatus={toolStatus} onRefresh={refreshStatus} onSettings={() => choose("settings")} />
          </div>

          <ThemeSwitcher />

          <div style={{ position: "relative" }}>
            <button
              type="button"
              aria-label="User menu"
              title="User menu"
              onClick={() => setUserOpen((v) => !v)}
              className="cyber-btn"
              style={{ width: "40px", height: "40px", flexShrink: 0 }}
            >
              <User className="h-4 w-4" />
            </button>
            <AnimatePresence>
              {userOpen && (
                <motion.div
                  initial={{ opacity: 0, scale: 0.95, y: -4 }}
                  animate={{ opacity: 1, scale: 1, y: 0 }}
                  exit={{ opacity: 0, scale: 0.95, y: -4 }}
                  transition={{ duration: 0.15, ease: "easeOut" }}
                  style={{
                    position: "absolute", top: "100%", right: 0, zIndex: 200,
                    minWidth: "10rem", marginTop: ".35rem", padding: ".25rem",
                    background: "var(--clr-bg)", border: "var(--border-w) solid var(--clr-border)",
                    borderRadius: "14px", boxShadow: "var(--shadow-card), var(--shadow-glow)",
                  }}
                >
                  <button
                    type="button"
                    onClick={() => { choose("settings"); setUserOpen(false) }}
                    style={{
                      display: "flex", alignItems: "center", gap: ".5rem",
                      width: "100%", padding: ".45rem .65rem",
                      border: "none", cursor: "pointer", fontFamily: "inherit",
                      background: "transparent", color: "var(--clr-text-sub)",
                      fontSize: ".78rem", fontWeight: 700, textAlign: "left", borderRadius: "10px",
                    }}
                    onMouseEnter={e => { e.currentTarget.style.background = "var(--clr-hover)"; e.currentTarget.style.color = "var(--clr-text)" }}
                    onMouseLeave={e => { e.currentTarget.style.background = "transparent"; e.currentTarget.style.color = "var(--clr-text-sub)" }}
                  >
                    <Settings className="h-4 w-4" />
                    <span>Settings</span>
                  </button>
                </motion.div>
              )}
            </AnimatePresence>
          </div>

        </div>
      </div>
      <CommandPalette open={commandOpen} query={query} setQuery={setQuery} options={commandItems} onChoose={choose} onClose={() => setCommandOpen(false)} />
      <NavDropdown group={currentGroup} onChoose={choose} onClose={() => { setOpenGroup(null); setAnchor(null) }} page={page} anchor={anchor} />
    </header>
  )
}
