import { useEffect, useMemo, useRef, useState } from "react"
import { createPortal } from "react-dom"
import { useNavigate } from "react-router-dom"
import {
  Activity,
  AlertTriangle,
  ArrowRight,
  BookOpen,
  CheckCircle2,
  ChevronDown,
  Clock3,
  Command,
  Database,
  FileText,
  GitBranch,
  Keyboard,
  Lightbulb,
  NotebookPen,
  Search,
  Settings,
  ShieldCheck,
  Sparkles,
  Sun,
  TerminalSquare,
  X,
  Moon,
} from "lucide-react"
import { getJson } from "../../lib/apiClient"
import { loadThemePreference, saveThemePreference } from "../../lib/theme"
import { useInvestigation } from "../../context/InvestigationContext"
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
    <div className="ba-command-overlay" role="dialog" aria-modal="true" aria-label="BeyondArch command palette">
      <button className="ba-command-backdrop" type="button" aria-label="Close command palette" onClick={onClose} />
      <section className="ba-command-panel">
        <div className="ba-command-input-row">
          <Command className="h-5 w-5" />
          <input
            ref={inputRef}
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Search tools, actions, timeline, reports…"
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
          }) : <p className="ba-command-empty">No result. Try “URL”, “Phishing”, “Logs”, “Nmap”, “Timeline”, or a saved artifact.</p>}
        </div>
        <div className="ba-command-footer"><span>Ctrl K</span><span>Enter opens first result</span><span>Esc closes</span></div>
      </section>
    </div>,
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

  if (!group || !anchor) return null

  const width = Math.min(440, Math.max(320, window.innerWidth - 24))
  const left = Math.min(Math.max(anchor.left + anchor.width / 2, width / 2 + 12), window.innerWidth - width / 2 - 12)
  const top = Math.max(anchor.bottom + 12, 62)

  return createPortal(
    <div className="ba-nav-layer">
      <section ref={ref} className="ba-nav-dropdown ba-topbar-dropdown-portal" style={{ "--ba-menu-left": `${left}px`, "--ba-menu-top": `${top}px`, "--ba-menu-width": `${width}px` }}>
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
      </section>
    </div>,
    document.body,
  )
}

function StatusChip({ backendStatus, toolStatus, onOpen }) {
  const online = backendStatus === "online"
  const toolOnline = toolStatus.status === "online"
  const toolsLabel = toolOnline && toolStatus.total ? `${toolStatus.available}/${toolStatus.total} tools available` : "tool status available in diagnostics"
  return (
    <button type="button" className={`ba-runtime-chip ${online ? "is-online" : "is-offline"}`} onClick={onOpen} aria-label={`Open runtime status, ${labelStatus(backendStatus)}, ${toolsLabel}`}>
      <span className="ba-runtime-dot" />
      <span>{online ? "Backend" : `Backend ${labelStatus(backendStatus)}`}</span>
    </button>
  )
}

function StatusPopover({ open, backendStatus, toolStatus, onRefresh, onSettings }) {
  if (!open) return null

  return (
    <section className="ba-status-popover" aria-label="System status">
      <div className="ba-status-head">
        <div><strong>Runtime status</strong><span>Local backend and tool checks</span></div>
        <button type="button" onClick={onRefresh}>Refresh</button>
      </div>
      <div className="ba-status-grid">
        <article>
          <span className={`ba-status-led ba-status-${backendStatus}`}>{backendStatus === "online" ? <CheckCircle2 className="h-4 w-4" /> : <Activity className="h-4 w-4" />}</span>
          <div><strong>Backend</strong><small>{labelStatus(backendStatus)} · /health</small></div>
        </article>
        <article>
          <span className={`ba-status-led ba-status-${toolStatus.status}`}>{toolStatus.status === "offline" ? <AlertTriangle className="h-4 w-4" /> : <TerminalSquare className="h-4 w-4" />}</span>
          <div><strong>Local tools</strong><small>{toolStatus.total ? `${toolStatus.available}/${toolStatus.total} available` : labelStatus(toolStatus.status)}</small></div>
        </article>
      </div>
      <button type="button" className="ba-status-settings" onClick={onSettings}><Settings className="h-4 w-4" /> Open diagnostics</button>
    </section>
  )
}

export default function Topbar({ page, groups = [], options = [], onOpenHelp }) {
  const helpRef = useRef(onOpenHelp)
  useEffect(() => { helpRef.current = onOpenHelp }, [onOpenHelp])
  const [openGroup, setOpenGroup] = useState(null)
  const [anchor, setAnchor] = useState(null)
  const [commandOpen, setCommandOpen] = useState(false)
  const [query, setQuery] = useState("")
  const [backendStatus, setBackendStatus] = useState("checking")
  const [toolStatus, setToolStatus] = useState({ status: "checking", available: 0, total: 0 })
  const [statusOpen, setStatusOpen] = useState(false)
  const [theme, setTheme] = useState(() => loadThemePreference())
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
      ...(state.artifacts || []).slice(0, 8).map((item) => ({ id: item.id, kind: "artifact", label: item.title || item.type || "Saved artifact", page: "case-timeline", group: "Saved artifact", icon: Database, description: `${item.type || "artifact"} · ${String(item.value || "").slice(0, 120)}` })),
      ...(state.timeline || []).slice(0, 6).map((item) => ({ id: item.id, kind: "timeline", label: item.title || "Timeline event", page: "case-timeline", group: "Timeline", icon: GitBranch, description: `${item.severity || "info"} · ${item.source || "BeyondArch"} · ${item.summary || ""}` })),
      ...(state.findings || []).slice(0, 6).map((item) => ({ id: item.id, kind: "finding", label: item.title || "Finding", page: "case-timeline", group: "Finding", icon: ShieldCheck, description: `${item.severity || "medium"} · ${item.confidence || "unknown"} confidence · ${item.summary || ""}` })),
      ...(state.notes || []).slice(0, 4).map((item) => ({ id: item.id, kind: "note", label: item.title || "Analyst note", page: "case-timeline", group: "Note", icon: NotebookPen, description: item.note || item.summary || "Saved analyst note" })),
      ...(state.hypotheses || []).slice(0, 4).map((item) => ({ id: item.id, kind: "hypothesis", label: item.title || "Hypothesis", page: "case-timeline", group: "Hypothesis", icon: Lightbulb, description: `${item.status || "open"} · ${item.confidence || "unknown"} confidence` })),
    ].map((item) => ({ ...item, searchText: `${item.label} ${item.group} ${item.description} ${item.kind}` }))

    const kbItems = KNOWLEDGE_BASE.map((entry) => ({
      id: entry.id,
      kind: "knowledge",
      label: entry.title,
      page: "soc-guide",
      group: `Knowledge · ${entry.category}`,
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
      if (event.key === "?" || (event.shiftKey && event.key === "/")) {
        event.preventDefault()
        helpRef.current?.()
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
  useEffect(() => {
    function handleThemeChange(event) {
      setTheme(event.detail?.theme || loadThemePreference())
    }
    window.addEventListener("beyondarch-theme-change", handleThemeChange)
    window.addEventListener("storage", handleThemeChange)
    return () => {
      window.removeEventListener("beyondarch-theme-change", handleThemeChange)
      window.removeEventListener("storage", handleThemeChange)
    }
  }, [])

  function toggleTheme() {
    setTheme(saveThemePreference(theme === "dark" ? "light" : "dark"))
  }

  return (
    <header className="ba-topbar-shell" ref={navRef} aria-label="BeyondArch navigation">
      <div className="ba-topbar">
        <button type="button" className="ba-topbar-brand" aria-label="BeyondArch local SOC workbench" onClick={() => choose("home")}>
          <span><ShieldCheck className="h-4 w-4" /></span>
          <strong>BeyondArch</strong>
        </button>

        <button type="button" className="ba-command-trigger" onClick={() => setCommandOpen(true)} aria-label="Open command palette">
          <Search className="h-4 w-4" />
          <span>Search logs, IPs, hashes...</span>
          <kbd>Ctrl K</kbd>
          <span className="ba-shortcut-hint">Press <kbd>?</kbd> for shortcuts</span>
        </button>

        <nav className="ba-topbar-nav" aria-label="Workspace groups">
          {groups.map((group) => {
            const active = activeGroup === group.id
            return (
              <button
                key={group.id}
                type="button"
                className={active ? "is-active" : ""}
                aria-label={`Open ${group.label} workspaces`}
                aria-expanded={openGroup === group.id}
                onClick={(event) => {
                  const nextOpen = openGroup === group.id ? null : group.id
                  setOpenGroup(nextOpen)
                  setAnchor(nextOpen ? event.currentTarget.getBoundingClientRect() : null)
                }}
              >
                <span>{group.label}</span>
                <ChevronDown className="h-3.5 w-3.5" />
              </button>
            )
          })}
        </nav>

        <div className="ba-topbar-actions">
          {onOpenHelp && <button type="button" className="ba-icon-button" aria-label="Keyboard shortcuts" title="Keyboard shortcuts (? keys)" onClick={onOpenHelp}><Keyboard className="h-4 w-4" /></button>}
          <StatusChip backendStatus={backendStatus} toolStatus={toolStatus} onOpen={() => setStatusOpen((value) => !value)} />
          <button
            type="button"
            className="ba-icon-button ba-theme-toggle"
            aria-label="Toggle light and dark mode"
            title={theme === "dark" ? "Switch to light mode" : "Switch to dark mode"}
            onClick={toggleTheme}
          >
            {theme === "dark" ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
          </button>
          <button
            type="button"
            className={`ba-icon-button ba-settings-button ${page === "settings" ? "is-active" : ""}`}
            aria-label="Open Settings"
            title="Settings"
            onClick={() => choose("settings")}
          >
            <Settings className="h-4 w-4" />
          </button>
          <StatusPopover open={statusOpen} backendStatus={backendStatus} toolStatus={toolStatus} onRefresh={refreshStatus} onSettings={() => choose("settings")} />
        </div>
      </div>
      <CommandPalette open={commandOpen} query={query} setQuery={setQuery} options={commandItems} onChoose={choose} onClose={() => setCommandOpen(false)} />
      <NavDropdown group={currentGroup} onChoose={choose} onClose={() => { setOpenGroup(null); setAnchor(null) }} page={page} anchor={anchor} />
    </header>
  )
}
