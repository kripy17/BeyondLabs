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
      { label: "Artifact Intake",    page: "smart-parser",      icon: FileSearch,   desc: "Import, parse, and normalize IOCs, forensic artifacts, and security logs.",            btn: "Open",   gl: false, ac: "border" },
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
    <motion.div variants={itemVariants} className={`cyber-card ${glow}`} style={{ display: "flex", flexDirection: "column", padding: "1.5rem" }}>
      <div style={{ display: "flex", alignItems: "center", gap: ".75rem", marginBottom: "1rem", borderBottom: `1px solid var(--clr-border-30)`, paddingBottom: ".5rem" }}>
        <I className="h-6 w-6" style={{ color: "var(--clr-accent)" }} />
        <h3 style={{ fontFamily: '"Space Grotesk", sans-serif', fontWeight: 950, textTransform: "uppercase", letterSpacing: "-.02em", lineHeight: 1, color: "var(--clr-text)", fontSize: "1.25rem", margin: 0 }}>{m.label}</h3>
      </div>
      <p className="card-desc" style={{ color: "var(--clr-text-sub)", fontWeight: 700, lineHeight: 1.6, flex: 1, fontSize: ".88rem", margin: "0 0 1.5rem 0" }}>{m.desc}</p>
      <div style={{ borderTop: `1px solid var(--clr-border-30)`, paddingTop: "1rem" }}>
        <button type="button" className={`cyber-btn ${bCls}`} style={{ fontSize: ".65rem", padding: ".625rem", width: "100%", fontFamily: '"JetBrains Mono", ui-monospace, monospace', textTransform: "uppercase" }} onClick={() => navigateToPage(navigate, m.page)}>{m.btn}</button>
      </div>
    </motion.div>
  )
}

function SectBar({ label, dashed }) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: "1rem" }}>
      <h2 className="sect-label" style={{ fontFamily: '"Space Grotesk", sans-serif', fontSize: "1.5rem", fontWeight: 950, letterSpacing: ".2em", textTransform: "uppercase", color: "var(--clr-bg)", margin: 0, background: "var(--clr-accent)", padding: ".25rem 1rem" }}>{label}</h2>
      <div className="cyber-divider flex-grow" style={dashed ? { background: "linear-gradient(90deg, var(--clr-border), transparent)" } : {}} />
    </div>
  )
}

export default function HomePage() {
  const navigate = useNavigate()

  return (
    <>
    <main style={{ flex: 1, maxWidth: "1520px", margin: "0 auto", width: "100%", padding: "2.5rem 1.6rem" }}>
      {/* ── Hero ── */}
      <section className="hero-section animate-fade-in-up" style={{ marginBottom: "2rem" }}>
        <div className="hero-grid" style={{ position: "relative", paddingBottom: "1.5rem", borderBottom: `2px solid var(--clr-border)` }}>
          <div className="hero-glow" style={{ position: "absolute", bottom: 0, left: 0, width: "100%", height: "1px", boxShadow: "0 0 15px var(--clr-border), 0 0 30px var(--clr-accent-30)", background: "linear-gradient(90deg, transparent, var(--clr-border), var(--clr-accent), transparent)" }} />
          <div className="flex flex-col lg:flex-row justify-between items-start gap-6">
            <div style={{ display: "flex", flexDirection: "column", gap: "1rem", position: "relative", zIndex: 10 }}>
              <div className="flex items-center gap-3 flex-wrap">
                <div className="hero-badge" style={{ display: "inline-flex", alignItems: "center", gap: ".5rem", background: "var(--clr-accent)", padding: ".25rem .75rem" }}>
                  <Activity className="h-3 w-3" style={{ color: "var(--clr-bg)" }} />
                  <span style={{ fontSize: ".7rem", letterSpacing: ".2em", fontWeight: 950, fontFamily: '"JetBrains Mono", ui-monospace, monospace', color: "var(--clr-bg)" }}>STATION_ALPHA</span>
                </div>
                <div className="hero-status" style={{ display: "inline-flex", alignItems: "center", gap: ".4rem", padding: ".25rem .6rem", border: `1px solid var(--clr-border-30)` }}>
                  <div className="status-led status-led-cobalt animate-pulse" />
                  <span style={{ fontSize: ".6rem", color: "var(--clr-text-sub)", fontWeight: 950, letterSpacing: ".12em", fontFamily: '"JetBrains Mono", ui-monospace, monospace' }}>SYSTEM_NOMINAL</span>
                </div>
              </div>
              <h1 className="hero-title lg:text-7xl" style={{ fontFamily: '"Space Grotesk", sans-serif', fontSize: "3rem", fontWeight: 950, textTransform: "uppercase", lineHeight: 1, color: "var(--clr-text)", margin: 0, letterSpacing: ".1em" }}>
                SOC{" "}
                <span className="hero-highlight" style={{ background: "var(--clr-accent)", color: "var(--clr-bg)", padding: "0 .5rem" }}>WORKBENCH</span>
              </h1>
              <p style={{ fontSize: ".8rem", color: "var(--clr-text-sub)", fontFamily: '"JetBrains Mono", ui-monospace, monospace', letterSpacing: ".06em", textTransform: "uppercase", margin: 0, fontWeight: 700 }}>
                Local-first forensics // tactical command deck
              </p>
            </div>
            <button type="button" className="cyber-btn hero-cta" style={{ fontSize: ".88rem", padding: "1rem 2.5rem", fontFamily: '"JetBrains Mono", ui-monospace, monospace', fontWeight: 950, background: "var(--clr-accent)", color: "var(--clr-bg)", borderColor: "var(--clr-accent)" }} onClick={() => navigateToPage(navigate, "smart-parser")}>
              <Plus className="h-5 w-5" /> NEW SESSION <ArrowRight className="h-4 w-4" />
            </button>
          </div>
        </div>
      </section>

      {/* ── Pipeline ── */}
      <section className="animate-fade-in-up stagger-1" style={{ marginBottom: "3rem" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "1rem", marginBottom: "2rem" }}>
          <span className="sect-label" style={{ fontFamily: '"JetBrains Mono", ui-monospace, monospace', fontSize: ".88rem", fontWeight: 950, letterSpacing: ".12em", textTransform: "uppercase", color: "var(--clr-bg)", background: "var(--clr-accent)", padding: ".25rem 1rem" }}>Investigation Pipeline</span>
          <div className="cyber-divider flex-grow" style={{ borderTop: "2px dashed var(--clr-border)", height: 0, background: "transparent" }} />
        </div>
        <div className="grid grid-cols-4 md:grid-cols-8 gap-3">
          {PIPELINE.map(p => {
            const I = p.icon
            return (
              <button key={p.id} type="button" className="cyber-card card-glow pipeline-btn" style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: ".5rem", padding: "1.25rem .75rem", cursor: "pointer", fontFamily: "inherit", textAlign: "center" }}
                onClick={() => navigateToPage(navigate, p.page)}>
                <I className="h-6 w-6" style={{ color: "var(--clr-accent)", filter: "drop-shadow(0 0 5px var(--clr-accent))" }} />
                <span style={{ fontFamily: '"JetBrains Mono", ui-monospace, monospace', fontSize: ".7rem", fontWeight: 950, letterSpacing: ".12em", color: "var(--clr-text-sub)" }}>{p.label}</span>
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
          style={{ display: "flex", flexDirection: "column", gap: "1.5rem" }}
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
          style={{ display: "flex", flexDirection: "column", gap: "1.5rem" }}
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
          style={{ display: "flex", flexDirection: "column", gap: "1.5rem" }}
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
          style={{ display: "flex", flexDirection: "column", gap: "1.5rem" }}
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
          style={{ display: "flex", flexDirection: "column", gap: "1.5rem" }}
        >
          <SectBar label={SECTORS[4].label} dashed />
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
            {SECTORS[4].items.map(m => <Card key={m.page} m={m} navigate={navigate} />)}
          </div>
        </motion.section>
      </div>

    </main>
      <footer className="cyber-footer" style={{ width: "100%" }}>
        <div className="footer-terminal" style={{ fontFamily: '"JetBrains Mono", ui-monospace, monospace', fontSize: ".65rem", fontWeight: 700, padding: ".65rem 1.6rem", display: "flex", alignItems: "center", gap: "1rem", maxWidth: "1520px", margin: "0 auto" }}>
          <span className="status-led status-led-cobalt animate-pulse" style={{ flexShrink: 0 }} />
          <span style={{ color: "var(--clr-accent)", letterSpacing: ".08em", flexShrink: 0 }}>BEYONDARCH://terminal</span>
          <span style={{ color: "var(--clr-text-sub)", flexShrink: 0 }}>$</span>
          <span className="footer-terminal-text" style={{ color: "var(--clr-text-sub)" }}>session encrypted · local-first · SOC workbench v2.0</span>
          <span className="terminal-cursor" style={{ color: "var(--clr-accent)" }}>▌</span>
        </div>
      </footer>
    </>
  )
}
