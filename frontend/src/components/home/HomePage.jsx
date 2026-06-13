import { useNavigate } from "react-router-dom"
import { motion } from "framer-motion"
import {
  BarChart3, BookOpen, ChefHat, Clock3, FileSearch, FileText,
  Globe2, Inbox, Layers3, Link2, MailWarning, Paperclip, Plus,
  Radar, Search, ShieldCheck, TerminalSquare,
  Activity, ArrowRight,
} from "lucide-react"
import { navigateToPage } from "../../lib/navigation"

const containerVariants = {
  hidden: {},
  visible: { transition: { staggerChildren: 0.08 } },
}

const itemVariants = {
  hidden: { opacity: 0, y: 24 },
  visible: { opacity: 1, y: 0, transition: { duration: 0.45, ease: "easeOut" } },
}

const PIPELINE = [
  { id: "intake",  label: "INTAKE",  icon: Inbox,        page: "smart-parser" },
  { id: "phish",   label: "PHISH",   icon: MailWarning,  page: "phishing-triage" },
  { id: "url-prc", label: "URL SCAN", icon: Link2,        page: "safe-url-analyzer" },
  { id: "attach",  label: "ATTACH",  icon: Paperclip,    page: "attachment-triage" },
  { id: "recon",   label: "RECON",   icon: Radar,        page: "recon-exposure" },
  { id: "siem",    label: "SIEM",    icon: BarChart3,    page: "siem" },
  { id: "detect",  label: "DETECT",  icon: ShieldCheck,  page: "detection-mitre" },
  { id: "report",  label: "REPORT",  icon: FileText,     page: "case-timeline" },
]

const SECTORS = [
  {
    id: "triage", label: "THREAT TRIAGE",
    items: [
      { label: "Smart Parser",    page: "smart-parser",      icon: FileSearch,   desc: "Import, parse, and normalize IOCs, forensic artifacts, and security logs.",            btn: "Open",   gl: false, ac: "border" },
      { label: "Phishing Triage",   page: "phishing-triage",   icon: MailWarning,  desc: "Analyze SMTP headers, authenticate SPF/DKIM/DMARC, and score phishing risk.", btn: "Launch", gl: false, ac: "border" },
      { label: "URL Analyzer",      page: "safe-url-analyzer", icon: Link2,        desc: "Extract URLs, follow redirect chains, and check threats via blocklists.", btn: "Analyze", gl: false, ac: "border" },
      { label: "Attachment Triage", page: "attachment-triage", icon: Paperclip,    desc: "Scan file hashes, extract embedded strings, and detect malicious indicators.",       btn: "Scan",   gl: false, ac: "border" },
    ],
  },
  {
    id: "recon", label: "RECONNAISSANCE",
    items: [
      { label: "Recon & Exposure",  page: "recon-exposure",    icon: Radar,          desc: "Map external footprint — subdomains, certificates, exposed ports, and cloud assets.",                      btn: "Open",   gl: false, ac: "border" },
      { label: "OSINT Tools",       page: "osint-tools",       icon: Search,         desc: "Query WHOIS, DNS, Shodan, and other passive intelligence sources.",                     btn: "Launch", gl: false, ac: "border" },
      { label: "Nmap Runner",       page: "nmap-runner",       icon: TerminalSquare, desc: "Execute port scans, service detection, and network topology mapping.",            btn: "Scan",   gl: false, ac: "border" },
    ],
  },
  {
    id: "siem", label: "SIEM & ANALYTICS",
    items: [
      { label: "SIEM Workspace",    page: "siem",              icon: BarChart3,      desc: "Search logs, correlate events, and pivot through incident timelines.",         btn: "Connect", gl: true, ac: "border" },
      { label: "Logs & Alerts",     page: "logs-alerts",       icon: Layers3,        desc: "Review alert logs, triage findings, and route events to investigations.",          btn: "View",    gl: true, ac: "border" },
    ],
  },
  {
    id: "tools", label: "TOOLS",
    items: [
      { label: "CyberChef",         page: "cyberchef",         icon: ChefHat,        desc: "Encode, decode, encrypt, decrypt, and transform data with the Cyber Swiss Army Knife.",       btn: "Execute", gl: false, ac: "accent" },
      { label: "Detection Workspace", page: "ids-builder",       icon: ShieldCheck,    desc: "Write, test, and export Sigma and YARA detection rules.",                           btn: "Compile", gl: false, ac: "accent" },
    ],
  },
  {
    id: "detection", label: "DETECTION",
    items: [
      { label: "Detection & MITRE", page: "detection-mitre",   icon: Globe2,         desc: "Map detections to MITRE ATT&CK techniques and track coverage gaps.",              btn: "Matrix", gl: true, ac: "accent" },
      { label: "SOC Guide",         page: "soc-guide",         icon: BookOpen,       desc: "Access IR runbooks, playbooks, and escalation procedures for incident response.",  btn: "Guides", gl: true, ac: "accent" },
      { label: "Case & Report",     page: "case-timeline",     icon: Clock3,       desc: "Compile investigation findings, attach evidence, and generate case reports.",      btn: "Portal", gl: true, ac: "accent" },
    ],
  },
]

function btnClass(ac) {
  if (ac === "attention") return "cyber-btn-yellow"
  if (ac === "border") return "cyber-btn-pink"
  return ""
}

function Card({ m, navigate }) {
  const I = m.icon
  const glow = m.gl ? "card-glow" : ""
  const bCls = btnClass(m.ac)
  return (
    <motion.div variants={itemVariants} className={`cyber-card ${glow} card-body`}>
      <div className="card-header">
        <I className="h-6 w-6 card-icon" />
        <h3 className="card-title">{m.label}</h3>
      </div>
      <p className="card-desc">{m.desc}</p>
      <div className="card-footer">
        <button type="button" className={`cyber-btn ${bCls} card-action-btn`} onClick={() => navigateToPage(navigate, m.page)}>{m.btn}</button>
      </div>
    </motion.div>
  )
}

function SectBar({ label, dashed }) {
  return (
    <div className="sect-bar">
      <h2 className="sect-label sect-label-h2">{label}</h2>
      <div className="cyber-divider flex-grow" style={dashed ? { background: "linear-gradient(90deg, var(--clr-border), transparent)" } : {}} />
    </div>
  )
}

export default function HomePage() {
  const navigate = useNavigate()

  return (
    <>
    <main className="ba-home-main">
      {/* ── Hero ── */}
      <section className="hero-section animate-fade-in-up" style={{ marginBottom: "2rem" }}>
        <div className="hero-grid" style={{ position: "relative", paddingBottom: "1.5rem", borderBottom: `2px solid var(--clr-border)` }}>
          <div className="hero-glow" style={{ position: "absolute", bottom: 0, left: 0, width: "100%", height: "1px", boxShadow: "0 0 15px var(--clr-border), 0 0 30px var(--clr-accent-30)", background: "linear-gradient(90deg, transparent, var(--clr-border), var(--clr-accent), transparent)" }} />
          <div className="flex flex-col lg:flex-row justify-between items-start gap-6">
            <div className="hero-text-col">
              <div className="flex items-center gap-3 flex-wrap">
                <div className="hero-badge" style={{ display: "inline-flex", alignItems: "center", gap: ".5rem", background: "var(--clr-accent)", padding: ".25rem .75rem" }}>
                  <Activity className="h-3 w-3" style={{ color: "var(--clr-bg)" }} />
                  <span className="badge-text">STATION_ALPHA</span>
                </div>
                <div className="hero-status" style={{ display: "inline-flex", alignItems: "center", gap: ".4rem", padding: ".25rem .6rem", border: `1px solid var(--clr-border-30)` }}>
                  <div className="status-led status-led-cobalt animate-pulse" />
                  <span className="status-text">SYSTEM_NOMINAL</span>
                </div>
              </div>
              <h1 className="hero-title-text">
                SOC{" "}
                <span className="hero-highlight" style={{ background: "var(--clr-accent)", color: "var(--clr-bg)", padding: "0 .5rem" }}>WORKBENCH</span>
              </h1>
              <p className="hero-subtitle">
                Local-first forensics // tactical command deck
              </p>
            </div>
            <button type="button" className="cyber-btn hero-cta cta-btn" onClick={() => navigateToPage(navigate, "smart-parser")}>
              <Plus className="h-5 w-5" /> NEW SESSION <ArrowRight className="h-4 w-4" />
            </button>
          </div>
        </div>
      </section>

      {/* ── Pipeline ── */}
      <section className="animate-fade-in-up stagger-1" style={{ marginBottom: "3rem" }}>
        <div className="pipeline-head-row">
          <span className="pipeline-label-text">Investigation Pipeline</span>
          <div className="cyber-divider flex-grow" style={{ borderTop: "2px dashed var(--clr-border)", height: 0, background: "transparent" }} />
        </div>
        <div className="grid grid-cols-4 md:grid-cols-8 gap-3">
          {PIPELINE.map(p => {
            const I = p.icon
            return (
              <button key={p.id} type="button" className="cyber-card card-glow pipeline-btn pipeline-btn-inner"
                onClick={() => navigateToPage(navigate, p.page)}>
                <I className="h-6 w-6 pipeline-icon" />
                <span className="pipeline-btn-label">{p.label}</span>
              </button>
            )
          })}
        </div>
      </section>

      {/* ── Command Deck ── */}
      <div style={{ display: "flex", flexDirection: "column", gap: "2.5rem" }}>
        {/* TRIAGE */}
        <motion.section
          initial="hidden" whileInView="visible" viewport={{ once: true, margin: "-60px" }}
          variants={containerVariants}
          className="sector-section"
        >
          <SectBar label={SECTORS[0].label} />
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
            {SECTORS[0].items.map(m => <Card key={m.page} m={m} navigate={navigate} />)}
          </div>
        </motion.section>

        {/* RECONNAISSANCE */}
        <motion.section
          initial="hidden" whileInView="visible" viewport={{ once: true, margin: "-60px" }}
          variants={containerVariants}
          className="sector-section"
        >
          <SectBar label={SECTORS[1].label} />
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
            {SECTORS[1].items.map(m => <Card key={m.page} m={m} navigate={navigate} />)}
          </div>
        </motion.section>

        {/* SIEM & ANALYTICS */}
        <motion.section
          initial="hidden" whileInView="visible" viewport={{ once: true, margin: "-60px" }}
          variants={containerVariants}
          className="sector-section"
        >
          <SectBar label={SECTORS[2].label} dashed />
          <div className="grid grid-cols-2 gap-6">
            {SECTORS[2].items.map(m => <Card key={m.page} m={m} navigate={navigate} />)}
          </div>
        </motion.section>

        {/* TOOLS */}
        <motion.section
          initial="hidden" whileInView="visible" viewport={{ once: true, margin: "-60px" }}
          variants={containerVariants}
          className="sector-section"
        >
          <SectBar label={SECTORS[3].label} />
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
            {SECTORS[3].items.map(m => <Card key={m.page} m={m} navigate={navigate} />)}
          </div>
        </motion.section>

        {/* DETECTION */}
        <motion.section
          initial="hidden" whileInView="visible" viewport={{ once: true, margin: "-60px" }}
          variants={containerVariants}
          className="sector-section"
        >
          <SectBar label={SECTORS[4].label} dashed />
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
            {SECTORS[4].items.map(m => <Card key={m.page} m={m} navigate={navigate} />)}
          </div>
        </motion.section>
      </div>

    </main>
      <footer className="cyber-footer" style={{ width: "100%" }}>
        <div className="footer-terminal footer-inner">
          <span className="status-led status-led-cobalt animate-pulse" style={{ flexShrink: 0 }} />
          <span className="footer-brand">BEYONDARCH://terminal</span>
          <span className="footer-prompt">$</span>
          <span className="footer-terminal-text" style={{ color: "var(--clr-text-sub)" }}>session encrypted · local-first · SOC workbench v2.0</span>
          <span className="terminal-cursor" style={{ color: "var(--clr-accent)" }}>▌</span>
        </div>
      </footer>
    </>
  )
}
