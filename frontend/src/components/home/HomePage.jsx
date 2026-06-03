import { useEffect, useRef, useState } from "react"
import { useNavigate } from "react-router-dom"
import {
  ArrowRight,
  BarChart3,
  BookOpen,
  CheckCircle2,
  ChefHat,
  Clock,
  Database,
  FileJson,
  FileSearch,
  FileText,
  GitBranch,
  Globe2,
  Link2,
  LockKeyhole,
  MailWarning,
  Paperclip,
  Radar,
  Search,
  ShieldAlert,
  ShieldCheck,
  TerminalSquare,
  Zap,
} from "lucide-react"
import { useInvestigation } from "../../context/InvestigationContext"
import { getJson } from "../../lib/apiClient"
import { navigateToPage } from "../../lib/navigation"

const QUICK_TOOLS = [
  { label: "Artifact Intake",   page: "smart-parser",       icon: FileSearch,    tone: "rose"    },
  { label: "Phishing Triage",   page: "phishing-triage",    icon: MailWarning,   tone: "emerald" },
  { label: "URL Analyzer",      page: "safe-url-analyzer",  icon: Link2,         tone: "cyan"    },
  { label: "Recon & Exposure",  page: "recon-exposure",     icon: Radar,         tone: "violet"  },
  { label: "Logs & SIEM",       page: "logs-alerts",        icon: BarChart3,     tone: "amber"   },
  { label: "Case & Report",     page: "case-timeline",      icon: FileText,      tone: "blue"    },
]

const PIPELINE_STEPS = [
  { id: "intake",      label: "Intake",      title: "Artifact Intake",     page: "smart-parser",      icon: FileSearch,    tone: "rose",    stageKey: "artifacts"  },
  { id: "phishing",   label: "Phishing",    title: "Phishing Triage",     page: "phishing-triage",   icon: MailWarning,   tone: "emerald", stageKey: null         },
  { id: "url",        label: "URL",         title: "URL Analyzer",        page: "safe-url-analyzer", icon: Link2,         tone: "cyan",    stageKey: null         },
  { id: "attachment", label: "Attachment",  title: "Attachment Triage",   page: "attachment-triage", icon: Paperclip,     tone: "amber",   stageKey: null         },
  { id: "recon",      label: "Recon",       title: "Recon & Exposure",    page: "recon-exposure",    icon: Radar,         tone: "violet",  stageKey: null         },
  { id: "siem",       label: "SIEM",        title: "Logs & Alerts",       page: "logs-alerts",       icon: BarChart3,     tone: "blue",    stageKey: "timeline"   },
  { id: "detection",  label: "Detection",   title: "Detection & MITRE",   page: "detection-mitre",   icon: Globe2,        tone: "indigo",  stageKey: null         },
  { id: "report",     label: "Report",      title: "Case & Report",       page: "case-timeline",     icon: FileText,      tone: "violet",  stageKey: "findings"   },
]

const WORKSPACE_GROUPS = [
  {
    id: "triage", label: "Triage", tone: "rose",
    description: "Artifact intake, phishing review, URL checks, and attachment triage.",
    tools: [
      { label: "Artifact Intake",    page: "smart-parser",      icon: FileSearch,  tags: ["intake", "ioc", "parse"]    },
      { label: "Phishing Triage",    page: "phishing-triage",   icon: MailWarning, tags: ["email", "headers", "spf"]   },
      { label: "URL Analyzer",       page: "safe-url-analyzer", icon: Link2,       tags: ["url", "redirect", "static"] },
      { label: "Attachment Triage",  page: "attachment-triage", icon: Paperclip,   tags: ["file", "hash", "strings"]   },
    ],
  },
  {
    id: "recon", label: "Recon", tone: "emerald",
    description: "Authorized target context, local probes, and exposure checks.",
    tools: [
      { label: "Recon & Exposure",   page: "recon-exposure",    icon: Radar,          tags: ["dns", "tls", "http"]     },
      { label: "OSINT Tools",        page: "osint-tools",       icon: Search,         tags: ["osint", "pivot", "open"] },
      { label: "Nmap Runner",        page: "nmap-runner",       icon: TerminalSquare, tags: ["nmap", "ports", "local"] },
    ],
  },
  {
    id: "siem", label: "SIEM", tone: "cyan",
    description: "Event search, alert parsing, and evidence correlation.",
    tools: [
      { label: "SIEM Workspace",     page: "siem",              icon: BarChart3,   tags: ["events", "search", "spl"] },
      { label: "Logs & Alerts",      page: "logs-alerts",       icon: Database,    tags: ["logs", "parse", "alert"]  },
    ],
  },
  {
    id: "tools", label: "Tools", tone: "amber",
    description: "Analyst transforms, helper utilities, and rule drafting.",
    tools: [
      { label: "CyberChef",          page: "cyberchef",         icon: ChefHat,     tags: ["decode", "hash", "codec"] },
      { label: "Detection Builder",  page: "ids-builder",       icon: ShieldCheck, tags: ["ids", "rules", "sigma"]   },
    ],
  },
  {
    id: "detection", label: "Detection", tone: "violet",
    description: "MITRE mapping, SOC guidance, and investigation handoff.",
    tools: [
      { label: "Detection & MITRE",  page: "detection-mitre",   icon: Globe2,      tags: ["mitre", "att&ck", "ttp"]  },
      { label: "SOC Guide",          page: "soc-guide",         icon: BookOpen,    tags: ["guide", "spl", "events"]  },
      { label: "Case & Report",      page: "case-timeline",     icon: FileText,    tags: ["timeline", "case", "md"]  },
    ],
  },
]

const SOCIAL_LINKS = [
  { label: "GitHub",     value: "kripy17",    href: "https://github.com/kripy17"                    },
  { label: "LinkedIn",   value: "kripy17",    href: "https://www.linkedin.com/in/kripy17"           },
  { label: "TryHackMe",  value: "kri.py17",  href: "https://tryhackme.com/p/kri.py17"              },
]

const ANALYST_NOTES = [
  {
    label: "Static-first triage",
    title: "Do the safe review before touching external enrichment.",
    body: "Start with local parsing, URL decomposition, headers, and IOC extraction. Escalate only when the evidence needs a live lookup.",
    tone: "cyan",
  },
  {
    label: "Evidence handoff",
    title: "Keep source, confidence, and limitation attached.",
    body: "Every finding should carry where it came from, how confident it is, and what still needs analyst validation.",
    tone: "violet",
  },
  {
    label: "Report rhythm",
    title: "Only promote useful observations into the case package.",
    body: "Move artifacts through timeline, notes, findings, and final report without duplicating noisy workspace metrics.",
    tone: "emerald",
  },
]


function countState(state) {
  return {
    artifacts: state.artifacts?.length || 0,
    timeline:  state.timeline?.length  || 0,
    notes:     state.notes?.length     || 0,
    findings:  state.findings?.length  || 0,
    hypotheses:state.hypotheses?.length|| 0,
  }
}

function getActiveStep(counts) {
  if (counts.findings > 0)  return "report"
  if (counts.timeline > 0)  return "siem"
  if (counts.artifacts > 0) return "phishing"
  return "intake"
}

function relativeTime(iso) {
  if (!iso) return null
  const diff = Date.now() - new Date(iso).getTime()
  const mins = Math.floor(diff / 60000)
  const hrs  = Math.floor(diff / 3600000)
  const days = Math.floor(diff / 86400000)
  if (mins < 2)  return "just now"
  if (mins < 60) return `${mins}m ago`
  if (hrs  < 24) return `${hrs}h ago`
  return `${days}d ago`
}

function truncate(str = "", max = 52) {
  const s = String(str)
  return s.length > max ? s.slice(0, max - 1) + "…" : s
}

function storageLabelFromMode(mode) {
  if (mode === "local")   return "local restore"
  if (mode === "none")    return "storage off"
  return "session-only"
}


function useNeoReveal() {
  useEffect(() => {
    const els = Array.from(document.querySelectorAll("[data-neo-reveal]"))
    if (!els.length) return undefined
    const reduceMotion = window.matchMedia?.("(prefers-reduced-motion: reduce)")?.matches
    if (reduceMotion || !("IntersectionObserver" in window)) {
      els.forEach((el) => el.classList.add("is-visible"))
      return undefined
    }
    const observer = new IntersectionObserver(
      (entries) => entries.forEach((e) => { if (e.isIntersecting) { e.target.classList.add("is-visible"); observer.unobserve(e.target) } }),
      { threshold: 0.12, rootMargin: "0px 0px -40px 0px" },
    )
    els.forEach((el) => observer.observe(el))
    return () => observer.disconnect()
  }, [])
}


function AnimatedCount({ value, className }) {
  const [display, setDisplay] = useState(0)
  const prev = useRef(0)
  useEffect(() => {
    if (value === prev.current) return
    const start = prev.current
    const end = value
    prev.current = end
    if (start === end) return
    const dur = Math.min(600, Math.abs(end - start) * 80)
    const startTime = performance.now()
    function tick(now) {
      const t = Math.min(1, (now - startTime) / dur)
      const eased = 1 - Math.pow(1 - t, 3)
      setDisplay(Math.round(start + (end - start) * eased))
      if (t < 1) requestAnimationFrame(tick)
    }
    requestAnimationFrame(tick)
  }, [value])
  return <span className={className}>{display}</span>
}


function QuickLaunchStrip({ navigate }) {
  return (
    <nav className="neo-quick-launch neo-reveal" data-neo-reveal aria-label="Quick launch tools">
      <span className="neo-ql-label">Quick launch</span>
      <div className="neo-ql-track">
        {QUICK_TOOLS.map((tool, i) => {
          const Icon = tool.icon
          return (
            <button
              key={tool.page}
              type="button"
              className="neo-ql-btn"
              data-tone={tool.tone}
              style={{ "--neo-delay": `${i * 55}ms` }}
              onClick={() => navigateToPage(navigate, tool.page)}
            >
              <Icon className="h-4 w-4" aria-hidden="true" />
              {tool.label}
            </button>
          )
        })}
      </div>
    </nav>
  )
}


function HeroSection({ navigate, counts, updatedAt }) {
  const hasActiveCase = counts.artifacts > 0 || counts.timeline > 0
  const lastSeen = relativeTime(updatedAt)

  return (
    <section id="home-hero" className="neo-hero neo-reveal" data-neo-reveal aria-labelledby="neo-hero-title">
      <div className="neo-hero-card">

        <span className="neo-corner neo-corner-tl" aria-hidden="true" />
        <span className="neo-corner neo-corner-br" aria-hidden="true" />

        <div className="neo-hero-utility" aria-hidden="true">
          <span>local://intake</span>
          <span>static-first</span>
          <span>case-ready</span>
          <span>no cloud</span>
        </div>

        <div className="neo-hero-copy">
          <span className="neo-label">Incident response framework</span>

          <div className="neo-hero-runner" aria-hidden="true">
            <span>parse</span><i /><span>triage</span><i /><span>correlate</span><i /><span>package</span>
          </div>

          <h1 id="neo-hero-title">
            Turn suspicious artifacts<br />into case-ready evidence.
          </h1>

          <p>
            BeyondArch connects artifact intake, phishing triage, URL analysis, recon, SIEM, detection
            engineering, and report export into one local SOC workbench.
          </p>

          <div className="neo-hero-pills" aria-label="Feature coverage">
            {["Email Headers", "DNS Lookup", "IOC Pivot", "MITRE Map", "Log Parser", "Case Report"].map((tag, i) => (
              <span key={tag} style={{ "--neo-delay": `${i * 70}ms` }}>{tag}</span>
            ))}
          </div>

          <div className="neo-actions">
            <button type="button" className="neo-btn is-primary" onClick={() => navigateToPage(navigate, "smart-parser")}>
              Start with Artifact Intake <ArrowRight className="h-4 w-4" />
            </button>
            <button type="button" className="neo-btn" onClick={() => navigateToPage(navigate, "case-timeline")}>
              Open Case & Report <GitBranch className="h-4 w-4" />
            </button>
          </div>
        </div>

        <div className="neo-hero-signal" aria-label="Investigation path">
          <article><strong>01</strong><span>Extract artifacts</span></article>
          <i aria-hidden="true" />
          <article><strong>02</strong><span>Score signals</span></article>
          <i aria-hidden="true" />
          <article><strong>03</strong><span>Package evidence</span></article>
        </div>

        {hasActiveCase && (
          <div className="neo-resume-banner" role="status">
            <span className="neo-resume-dot" aria-hidden="true" />
            <span>
              Active investigation &mdash;&nbsp;
              <strong>{counts.artifacts}</strong> artifact{counts.artifacts !== 1 ? "s" : ""},&nbsp;
              <strong>{counts.timeline}</strong> event{counts.timeline !== 1 ? "s" : ""},&nbsp;
              <strong>{counts.findings}</strong> finding{counts.findings !== 1 ? "s" : ""}
              {lastSeen ? <em> · {lastSeen}</em> : null}
            </span>
            <button type="button" onClick={() => navigateToPage(navigate, "case-timeline")}>
              Resume <ArrowRight className="h-3.5 w-3.5" />
            </button>
          </div>
        )}
      </div>
    </section>
  )
}


function CaseScopePanel({ navigate, counts, storageLabel, backendStatus, updatedAt }) {
  const hasData = counts.artifacts + counts.timeline + counts.notes + counts.findings > 0
  const [activeNote, setActiveNote] = useState(0)
  const [isPaused, setIsPaused] = useState(false)
  const pointerStart = useRef(null)
  const note = ANALYST_NOTES[activeNote]

  useEffect(() => {
    if (isPaused) return undefined
    const id = window.setInterval(() => setActiveNote((i) => (i + 1) % ANALYST_NOTES.length), 5600)
    return () => window.clearInterval(id)
  }, [isPaused])

  function stepNote(dir) { setActiveNote((i) => (i + dir + ANALYST_NOTES.length) % ANALYST_NOTES.length) }
  function handlePointerUp(e) {
    if (pointerStart.current === null) return
    const delta = e.clientX - pointerStart.current
    pointerStart.current = null
    if (Math.abs(delta) < 34) return
    stepNote(delta < 0 ? 1 : -1)
  }

  const statusLabel = backendStatus === "checking" ? "starting" : backendStatus

  return (
    <section className="neo-case-scope neo-reveal" data-neo-reveal aria-label="Case scope and workspace status">

      <article className="neo-case-terminal">
        <header>
          <span><i /><i /><i /></span>
          <strong>beyondarch — live case console</strong>
          <em>{storageLabel}</em>
        </header>

        {hasData ? (
          <div className="neo-terminal-lines">
            <p><b>$</b> workspace.load() <span>→ case://local</span></p>
            <p>
              <span>→</span> storage <strong>{storageLabel}</strong>
              &nbsp;· backend <strong className={`is-${statusLabel}`}>{statusLabel}</strong>
            </p>

            <div className="neo-terminal-meter" aria-label="Case counters">
              {[
                ["artifacts", counts.artifacts],
                ["timeline",  counts.timeline],
                ["notes",     counts.notes],
                ["findings",  counts.findings],
              ].map(([key, val]) => (
                <span key={key}>
                  <small>{key}</small>
                  <AnimatedCount value={val} />
                </span>
              ))}
            </div>

            {updatedAt && (
              <p className="neo-terminal-ts">
                <span>→</span> last updated <strong>{relativeTime(updatedAt)}</strong>
              </p>
            )}

            <div className="neo-terminal-actions">
              <button type="button" onClick={() => navigateToPage(navigate, "case-timeline")} className="neo-term-btn is-primary">
                <FileText className="h-4 w-4" /> Resume case
              </button>
              <button type="button" onClick={() => navigateToPage(navigate, "smart-parser")} className="neo-term-btn">
                <FileSearch className="h-4 w-4" /> Add evidence
              </button>
            </div>
          </div>
        ) : (
          <div className="neo-terminal-lines neo-terminal-empty">
            <p><b>$</b> workspace.load() <span className="neo-blink">_</span></p>
            <p><span>→</span> no active investigation found</p>
            <p><span>→</span> storage <strong>{storageLabel}</strong> · backend <strong className={`is-${statusLabel}`}>{statusLabel}</strong></p>
            <div className="neo-empty-hint">
              <Zap className="h-4 w-4" aria-hidden="true" />
              <span>Start by pasting any suspicious artifact below.</span>
            </div>
            <button type="button" onClick={() => navigateToPage(navigate, "smart-parser")} className="neo-term-btn is-primary">
              <FileSearch className="h-4 w-4" /> Start with Artifact Intake
            </button>
          </div>
        )}
      </article>

      <article
        className="neo-analyst-carousel"
        data-tone={note.tone}
        onMouseEnter={() => setIsPaused(true)}
        onMouseLeave={() => setIsPaused(false)}
        onFocus={() => setIsPaused(true)}
        onBlur={() => setIsPaused(false)}
        onPointerDown={(e) => { pointerStart.current = e.clientX }}
        onPointerUp={handlePointerUp}
        aria-label="Analyst workflow notes"
      >
        <div className="neo-quote-mark" aria-hidden="true">"</div>
        <small>{note.label}</small>
        <h3>{note.title}</h3>
        <p>{note.body}</p>
        <div className="neo-analyst-carousel-controls">
          <button type="button" onClick={() => stepNote(-1)} aria-label="Previous note">←</button>
          <div>
            {ANALYST_NOTES.map((n, i) => (
              <button
                key={n.label}
                type="button"
                className={i === activeNote ? "is-active" : ""}
                onClick={() => setActiveNote(i)}
                aria-label={`Note ${i + 1}`}
              />
            ))}
          </div>
          <button type="button" onClick={() => stepNote(1)} aria-label="Next note">→</button>
        </div>
      </article>

    </section>
  )
}


function InvestigationPipeline({ navigate, counts }) {
  const activeStep = getActiveStep(counts)

  return (
    <section id="home-pipeline" className="neo-section neo-pipeline neo-reveal" data-neo-reveal aria-labelledby="neo-pipeline-title">
      <div className="neo-section-heading">
        <span className="neo-section-kicker"><GitBranch className="h-4 w-4" aria-hidden="true" /> Investigation pipeline</span>
        <h2 id="neo-pipeline-title">Full Investigation Workflow</h2>
        <p>Eight connected stages from raw artifact intake to a structured case handoff. The highlighted stage is your recommended next step.</p>
      </div>

      <div className="neo-pipeline-track" aria-label="Investigation stages" role="list">
        {PIPELINE_STEPS.map((step, i) => {
          const Icon = step.icon
          const isDone = step.stageKey && counts[step.stageKey] > 0
          const isActive = step.id === activeStep
          return (
            <button
              key={step.id}
              type="button"
              className={`neo-pipeline-step${isDone ? " is-done" : ""}${isActive ? " is-active" : ""}`}
              data-tone={step.tone}
              style={{ "--neo-delay": `${i * 60}ms` }}
              onClick={() => navigateToPage(navigate, step.page)}
              role="listitem"
              aria-label={`${step.title}${isDone ? " — complete" : isActive ? " — recommended next" : ""}`}
            >
              <article>
                <div className="neo-step-num">{String(i + 1).padStart(2, "0")}</div>
                {isDone && <span className="neo-step-done-badge" aria-hidden="true">✓</span>}
                {isActive && !isDone && <span className="neo-step-active-badge" aria-hidden="true">Next</span>}
                <div className="neo-step-icon"><Icon className="h-5 w-5" /></div>
                <span className="neo-step-label">{step.label}</span>
                <small className="neo-step-title">{step.title}</small>
              </article>
            </button>
          )
        })}
      </div>

      <div className="neo-pipeline-rail" aria-hidden="true" />
    </section>
  )
}


function WorkspaceLibrary({ navigate }) {
  const [activeIdx, setActiveIdx] = useState(0)
  const [isPaused, setIsPaused] = useState(false)

  useEffect(() => {
    if (isPaused) return undefined
    const id = window.setInterval(() => setActiveIdx((i) => (i + 1) % WORKSPACE_GROUPS.length), 5200)
    return () => window.clearInterval(id)
  }, [isPaused])

  const group = WORKSPACE_GROUPS[activeIdx]
  const primary   = group.tools[0]
  const secondary = group.tools[1]

  return (
    <section id="home-library" className="neo-section neo-library neo-reveal" data-neo-reveal aria-labelledby="neo-library-title">
      <div className="neo-section-heading">
        <span className="neo-section-kicker"><Database className="h-4 w-4" aria-hidden="true" /> Module deck</span>
        <h2 id="neo-library-title">Workspace Library</h2>
        <p>All BeyondArch workspaces grouped by stage. Hover to pause the cycle.</p>
        <small>Auto-cycle · hover to pause</small>
      </div>

      <div
        className={`neo-workspace-stage tone-${group.id}`}
        data-paused={isPaused ? "true" : "false"}
        onMouseEnter={() => setIsPaused(true)}
        onMouseLeave={() => setIsPaused(false)}
        onFocus={() => setIsPaused(true)}
        onBlur={() => setIsPaused(false)}
      >
        <div className="neo-workspace-progress" aria-hidden="true">
          <span key={group.id} />
        </div>

        <nav className="neo-workspace-tabs" aria-label="Workspace categories">
          {WORKSPACE_GROUPS.map((g, i) => (
            <button
              key={g.id}
              type="button"
              className={i === activeIdx ? "is-active" : ""}
              onClick={() => setActiveIdx(i)}
              aria-current={i === activeIdx ? "true" : undefined}
            >
              <span className={`neo-tab-dot tone-${g.id}`} aria-hidden="true" />
              <strong>{g.label}</strong>
              <ArrowRight className="h-3.5 w-3.5" aria-hidden="true" />
            </button>
          ))}
        </nav>

        <div className="neo-workspace-display" key={group.id}>

          <article className="neo-workspace-card is-primary">
            <div className="neo-card-kicker">
              <span>{group.label}</span>
              <button type="button" onClick={() => navigateToPage(navigate, primary.page)} aria-label={`Open ${primary.label}`}>
                <ArrowRight className="h-5 w-5" />
              </button>
            </div>
            {(() => { const Icon = primary.icon; return <Icon className="neo-card-icon h-6 w-6" /> })()}
            <h3>{primary.label}</h3>
            <p>{group.description}</p>
            <div className="neo-card-meta">
              <span><small>Stage</small><strong>{group.label}</strong></span>
              <span><small>Case handoff</small><strong>Enabled</strong></span>
            </div>
            <div className="neo-card-tags">
              {primary.tags.map((t) => <em key={t}>{t}</em>)}
            </div>
          </article>

          {secondary && (
            <button type="button" className="neo-workspace-card is-side" onClick={() => navigateToPage(navigate, secondary.page)}>
              {(() => { const Icon = secondary.icon; return <Icon className="h-5 w-5" /> })()}
              <h3>{secondary.label}</h3>
              <p>{group.tools.length > 1 ? "Continue the investigation with this linked workspace." : group.description}</p>
              <div className="neo-card-tags">
                {secondary.tags.slice(0, 2).map((t) => <em key={t}>{t}</em>)}
              </div>
            </button>
          )}

          <div className="neo-tool-grid" aria-label={`All ${group.label} tools`}>
            {group.tools.map((tool) => {
              const Icon = tool.icon
              return (
                <button key={tool.page} type="button" className="neo-tool-mini" onClick={() => navigateToPage(navigate, tool.page)}>
                  <Icon className="h-4 w-4" aria-hidden="true" />
                  <strong>{tool.label}</strong>
                  <div className="neo-card-tags">
                    {tool.tags.slice(0, 2).map((t) => <em key={t}>{t}</em>)}
                  </div>
                </button>
              )
            })}
          </div>

        </div>
      </div>
    </section>
  )
}


const EXAMPLE_ARTIFACTS = [
  { type: "url",    value: "hxxps://secure-login-update[.]com/auth/v2/", source: "Phishing Triage"  },
  { type: "domain", value: "secure-login-update[.]com",                  source: "Artifact Intake"  },
  { type: "ip",     value: "198[.]51[.]100[.]23",                        source: "Recon & Exposure" },
]
const EXAMPLE_FINDINGS = [
  { title: "Sender domain mismatch", severity: "high",   source: "Phishing Triage", summary: "From: display doesn't match envelope sender."    },
  { title: "Suspicious redirect chain", severity: "medium", source: "URL Analyzer",   summary: "Final host differs from visible link text."      },
]
const EXAMPLE_TIMELINE = [
  { title: "Artifact submitted",         source: "Artifact Intake",  type: "evidence" },
  { title: "URL triage scored risk: 74", source: "Safe URL Analyzer",type: "finding"  },
  { title: "Case finding added",         source: "Phishing Triage",  type: "finding"  },
]

function SeverityDot({ severity }) {
  return <span className={`neo-sev-dot sev-${severity}`} aria-label={severity} />
}


function LiveCasePreview({ navigate, state, counts }) {
  const hasRealData = counts.artifacts + counts.findings + counts.timeline > 0
  const artifacts = hasRealData ? state.artifacts.slice(0, 3) : EXAMPLE_ARTIFACTS
  const findings  = hasRealData ? state.findings.slice(0, 2)  : EXAMPLE_FINDINGS
  const timeline  = hasRealData ? state.timeline.slice(0, 3)  : EXAMPLE_TIMELINE

  return (
    <section id="home-case" className="neo-section neo-live-case neo-reveal" data-neo-reveal aria-labelledby="neo-case-title">
      <div className="neo-section-heading">
        <span className="neo-section-kicker"><FileJson className="h-4 w-4" aria-hidden="true" /> Case report preview</span>
        <h2 id="neo-case-title">
          {hasRealData ? "Your Active Investigation" : "Forensic Evidence Package"}
        </h2>
        <p>
          {hasRealData
            ? `${counts.artifacts} artifacts · ${counts.timeline} events · ${counts.findings} findings · ${counts.notes} notes`
            : "Structured evidence preview. Run a triage to populate this with real data."}
        </p>
      </div>

      <div className={`neo-case-console${!hasRealData ? " is-example" : ""}`}>

        <header className="neo-case-console-head">
          <div className="neo-output-dots" aria-hidden="true"><span /><span /><span /></div>
          <strong>{hasRealData ? "case_report.live.json" : "case_report.example.json"}</strong>
          {!hasRealData && <span className="neo-example-badge">EXAMPLE OUTPUT</span>}
          {hasRealData  && <span className="neo-live-badge"><span className="neo-live-dot" />LIVE</span>}
        </header>

        <div className="neo-case-risk-strip">
          <div className="neo-risk-left">
            <span className="neo-risk-badge">{hasRealData ? "ACTIVE CASE" : "PROBABLE PHISHING"}</span>
            <div className="neo-score-ring" aria-label="Risk score">
              <strong>{hasRealData ? counts.findings * 10 + counts.artifacts * 3 : 74}</strong>
              <span>score</span>
            </div>
          </div>
          <div className="neo-risk-meta">
            <dl>
              <div><dt>Artifacts</dt><dd><AnimatedCount value={hasRealData ? counts.artifacts : 3} /></dd></div>
              <div><dt>Timeline events</dt><dd><AnimatedCount value={hasRealData ? counts.timeline : 3} /></dd></div>
              <div><dt>Findings</dt><dd><AnimatedCount value={hasRealData ? counts.findings : 2} /></dd></div>
              <div><dt>Report-ready</dt><dd>{hasRealData ? (counts.findings > 0 ? "Yes" : "Partial") : "Yes"}</dd></div>
            </dl>
          </div>
        </div>

        <div className="neo-case-body">

          <section className="neo-case-col">
            <div className="neo-case-col-head"><FileSearch className="h-4 w-4" aria-hidden="true" />Artifacts</div>
            <div className="neo-case-items">
              {artifacts.map((a, i) => (
                <div key={i} className={`neo-case-item type-${a.type || "artifact"}`}>
                  <em>{a.type || "artifact"}</em>
                  <code title={a.value}>{truncate(a.value, 40)}</code>
                  <small>{a.source}</small>
                </div>
              ))}
            </div>
          </section>

          <section className="neo-case-col">
            <div className="neo-case-col-head"><Clock className="h-4 w-4" aria-hidden="true" />Timeline</div>
            <div className="neo-case-items">
              {timeline.map((t, i) => (
                <div key={i} className={`neo-case-item type-${t.type || "evidence"}`}>
                  <em>{t.type || "evidence"}</em>
                  <strong title={t.title}>{truncate(t.title, 38)}</strong>
                  <small>{t.source}</small>
                </div>
              ))}
            </div>
          </section>

          <section className="neo-case-col">
            <div className="neo-case-col-head"><ShieldAlert className="h-4 w-4" aria-hidden="true" />Findings</div>
            <div className="neo-case-items">
              {findings.map((f, i) => (
                <div key={i} className={`neo-case-item type-finding`}>
                  <div className="neo-finding-head">
                    <SeverityDot severity={f.severity || "medium"} />
                    <em>{f.severity || "medium"}</em>
                  </div>
                  <strong title={f.title}>{truncate(f.title, 36)}</strong>
                  <small>{f.source}</small>
                </div>
              ))}
              {findings.length === 0 && (
                <div className="neo-case-empty-col">
                  <span>No findings yet — run triage tools and promote signals to findings.</span>
                </div>
              )}
            </div>
          </section>

        </div>

        <div className="neo-case-cta">
          <button type="button" className="neo-evidence-action" onClick={() => navigateToPage(navigate, "case-timeline")}>
            {hasRealData ? "Open Case & Report" : "Start an Investigation"} <ArrowRight className="h-4 w-4" />
          </button>
          {hasRealData && (
            <button type="button" className="neo-evidence-action is-secondary" onClick={() => navigateToPage(navigate, "smart-parser")}>
              Add more evidence
            </button>
          )}
        </div>

      </div>
    </section>
  )
}


function LocalFirstBanner({ navigate }) {
  return (
    <section id="home-local" className="neo-section neo-assurance neo-reveal" data-neo-reveal aria-labelledby="neo-assurance-title">
      <div className="neo-section-heading" style={{ textAlign: "left", margin: "0 0 1.45rem" }}>
        <span className="neo-section-kicker"><LockKeyhole className="h-4 w-4" aria-hidden="true" /> Local handoff</span>
        <h2 id="neo-assurance-title">Local-first analysis,<br />cleaner report handoff.</h2>
        <p>Keep evidence on your machine, then move only useful findings into a structured case package.</p>
      </div>

      <div className="neo-assurance-grid">
        <article className="neo-assurance-card is-local">
          <div>
            <span className="neo-mini-label"><LockKeyhole className="h-4 w-4" /> Local First</span>
            <h3>Your data stays on your machine.</h3>
            <p>BeyondArch runs in your local environment. External lookups are explicit — nothing leaves without your intent.</p>
            <ul>
              <li><CheckCircle2 className="h-4 w-4" /> Session-only storage by default</li>
              <li><CheckCircle2 className="h-4 w-4" /> Local parsing before enrichment</li>
              <li><CheckCircle2 className="h-4 w-4" /> External services remain optional</li>
            </ul>
          </div>
          <aside className="neo-visual-card is-lock" aria-hidden="true">
            <LockKeyhole className="h-10 w-10" />
            <span>session-only</span>
          </aside>
        </article>

        <article className="neo-assurance-card is-export">
          <aside className="neo-visual-card is-report" aria-hidden="true">
            <span /><span /><span /><strong />
          </aside>
          <div>
            <span className="neo-mini-label is-cyan"><FileText className="h-4 w-4" /> Seamless Export</span>
            <h3>From analysis to report in seconds.</h3>
            <p>Compile findings, timeline events, notes, hypotheses, and artifact details into Markdown or HTML for stakeholder review.</p>
            <button type="button" onClick={() => navigateToPage(navigate, "case-timeline")}>
              Open Case & Report <ArrowRight className="h-4 w-4" />
            </button>
          </div>
        </article>
      </div>
    </section>
  )
}


function Footer({ navigate }) {
  const year = new Date().getFullYear()

  const cols = [
    {
      title: "Workspaces",
      items: [
        { label: "Artifact Intake",   action: "smart-parser"      },
        { label: "Phishing Triage",   action: "phishing-triage"   },
        { label: "URL Analyzer",      action: "safe-url-analyzer" },
        { label: "Recon & Exposure",  action: "recon-exposure"    },
      ],
    },
    {
      title: "Detection",
      items: [
        { label: "SIEM Workspace",    action: "siem"              },
        { label: "Detection & MITRE", action: "detection-mitre"   },
        { label: "SOC Guide",         action: "soc-guide"         },
        { label: "IDS Builder",       action: "ids-builder"       },
      ],
    },
    {
      title: "Case",
      items: [
        { label: "Case & Report",     action: "case-timeline"     },
        { label: "Settings",          action: "settings"          },
        { label: "GitHub",            href:   "https://github.com/kripy17"       },
      ],
    },
  ]

  return (
    <footer className="neo-footer neo-reveal" data-neo-reveal>
      <div className="neo-footer-main">
        <div className="neo-footer-brand">
          <span><ShieldCheck className="h-5 w-5" /></span>
          <div>
            <strong>BeyondArch</strong>
            <small>Local SOC workbench — triage, correlation, evidence, reports.</small>
          </div>
        </div>

        <div className="neo-footer-columns">
          {cols.map((col) => (
            <nav key={col.title} aria-label={`${col.title} links`}>
              <strong>{col.title}</strong>
              {col.items.map((item) =>
                item.href ? (
                  <a key={item.label} href={item.href} target="_blank" rel="noreferrer">{item.label}</a>
                ) : (
                  <button key={item.label} type="button" onClick={() => navigateToPage(navigate, item.action)}>{item.label}</button>
                )
              )}
            </nav>
          ))}
        </div>

        <nav className="neo-footer-social" aria-label="Profile links">
          {SOCIAL_LINKS.map((link) => (
            <a key={link.label} href={link.href} target="_blank" rel="noreferrer">
              {link.label}<small>{link.value}</small>
            </a>
          ))}
        </nav>
      </div>

      <div className="neo-footer-bottom">
        <span>© {year} BeyondArch Security · kripy17</span>
        <span>Local-first SOC workbench · no account layer</span>
        <a href="https://github.com/kripy17/BeyondArch" target="_blank" rel="noreferrer">
          View on GitHub →
        </a>
      </div>
    </footer>
  )
}


export default function HomePage() {
  const navigate = useNavigate()
  useNeoReveal()
  const { state, storageMode } = useInvestigation()
  const counts       = countState(state)
  const storageLabel = storageLabelFromMode(storageMode)
  const [backendStatus, setBackendStatus] = useState("checking")

  useEffect(() => {
    let cancelled = false
    async function ping() {
      setBackendStatus("checking")
      try {
        await getJson("/health", 2200)
        if (!cancelled) setBackendStatus("online")
      } catch {
        if (!cancelled) setBackendStatus("offline")
      }
    }
    ping()
    const id = window.setInterval(ping, 60000)
    return () => { cancelled = true; window.clearInterval(id) }
  }, [])

  return (
    <main className="ba-command-deck neo-command-deck" aria-label="BeyondArch homepage">
      <HeroSection          navigate={navigate} counts={counts} updatedAt={state.updatedAt} />
      <QuickLaunchStrip     navigate={navigate} />
      <CaseScopePanel       navigate={navigate} counts={counts} storageLabel={storageLabel} backendStatus={backendStatus} updatedAt={state.updatedAt} />
      <InvestigationPipeline navigate={navigate} counts={counts} />
      <WorkspaceLibrary     navigate={navigate} />
      <LiveCasePreview      navigate={navigate} state={state} counts={counts} />
      <LocalFirstBanner     navigate={navigate} />
      <Footer               navigate={navigate} />
    </main>
  )
}