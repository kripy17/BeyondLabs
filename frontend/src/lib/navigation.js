import {
  BarChart3,
  BookOpen,
  ChefHat,
  Clock3,
  FileSearch,
  Globe2,
  Home,
  Layers3,
  Link2,
  MailWarning,
  Paperclip,
  Radar,
  Search,
  Settings,
  ShieldCheck,
  TerminalSquare,
  Wrench,
} from "lucide-react"

export const WORKSPACES = [
  {
    id: "triage",
    label: "Triage",
    icon: ShieldCheck,
    description: "Smart parser, phishing review, URL checks, and attachment triage.",
    items: [
      { label: "Smart Parser", page: "smart-parser", icon: FileSearch, description: "Paste any artifact and route indicators to the right workflow.", tags: ["intake", "ioc"] },
      { label: "Phishing Triage", page: "phishing-triage", icon: MailWarning, description: "Review sender signals, headers, links, language, and verdicts.", tags: ["email", "headers"] },
      { label: "Safe URL Analyzer", page: "safe-url-analyzer", icon: Link2, description: "Analyze links safely with static-first checks and redirect context.", tags: ["url", "redirect"] },
      { label: "Attachment Triage", page: "attachment-triage", icon: Paperclip, description: "Inspect file names, hashes, strings, extensions, and risky metadata.", tags: ["file", "hash"] },
    ],
  },
  {
    id: "recon",
    label: "Recon",
    icon: Radar,
    description: "Authorized target context, local probes, and exposure checks.",
    items: [
      { label: "Recon & Exposure", page: "recon-exposure", icon: Radar, description: "Run DNS, HTTP, TLS, and exposure review from one workspace.", tags: ["dns", "tls"] },
      { label: "OSINT Tools", page: "osint-tools", icon: Search, description: "Open analyst pivots and document external research paths.", tags: ["osint", "pivot"] },
      { label: "Nmap Runner", page: "nmap-runner", icon: TerminalSquare, description: "Execute authorized local Nmap profiles and capture output.", tags: ["nmap", "local"] },
    ],
  },
  {
    id: "operations",
    label: "SIEM",
    icon: BarChart3,
    description: "Event search, alert parsing, and evidence correlation.",
    items: [
      { label: "SIEM Workspace", page: "siem", icon: BarChart3, description: "Search local events with Splunk-style field filtering and expansion.", tags: ["events", "search"] },
      { label: "Logs & Alerts", page: "logs-alerts", icon: Layers3, description: "Parse logs into entities, detections, summaries, and report notes.", tags: ["logs", "alerts"] },
    ],
  },
  {
    id: "tools",
    label: "Tools",
    icon: Wrench,
    description: "Analyst transforms, helper utilities, and rule drafting.",
    items: [
      { label: "CyberChef", page: "cyberchef", icon: ChefHat, description: "Decode, encode, hash, defang, refang, inspect JWTs, timestamps, and transform artifacts.", tags: ["decode", "hash", "utility", "codec"] },
      { label: "Detection Workspace", page: "ids-builder", icon: ShieldCheck, description: "Draft detection rules, build log queries, and hand off rule evidence.", tags: ["ids", "rules", "query", "detection"] },
    ],
  },
  {
    id: "detection",
    label: "Detection",
    icon: Globe2,
    description: "MITRE mapping, SOC guidance, and investigation handoff.",
    items: [
      { label: "Detection & MITRE", page: "detection-mitre", icon: Globe2, description: "Map observed behavior to ATT&CK-style reasoning and detections.", tags: ["mitre", "attack"] },
      { label: "SOC Guide", page: "soc-guide", icon: BookOpen, description: "Lookup event IDs, explain commands, and build SPL-like queries.", tags: ["guide", "spl"] },
      { label: "Case & Report", page: "case-timeline", icon: Clock3, description: "Track evidence, hypotheses, notes, findings, and report exports.", tags: ["timeline", "case", "report"] },
    ],
  },
]

export const STANDALONE = [
  { label: "Home", page: "home", icon: Home },
  { label: "Settings", page: "settings", icon: Settings },
]

export const ALL_WORKSPACES = [
  ...STANDALONE.map(s => ({ ...s, description: s.label === "Home" ? "BeyondArch product home" : "Theme, diagnostics, backend status, and local data" })),
  ...WORKSPACES.flatMap((group) => group.items.map((item) => ({ ...item, group: group.label, groupId: group.id }))),
]

export const ROUTE_MAP = {
  "smart-parser": "/triage/smart-parser",
  "phishing-triage": "/triage/phishing-triage",
  "safe-url-analyzer": "/triage/safe-url-analyzer",
  "attachment-triage": "/triage/attachment-triage",
  "recon-exposure": "/recon/exposure",
  "osint-tools": "/recon/osint",
  "nmap-runner": "/recon/nmap",
  siem: "/siem/workspace",
  "logs-alerts": "/siem/logs",
  cyberchef: "/tools/cyberchef",
  "ids-builder": "/tools/ids-builder",
  "detection-mitre": "/detection/mitre",
  "soc-guide": "/detection/soc-guide",
  "case-timeline": "/detection/case-timeline",
  settings: "/settings",
  home: "/",
}

export const ROUTE_TO_PAGE = Object.fromEntries(
  Object.entries(ROUTE_MAP).map(([k, v]) => [v, k])
)

Object.assign(ROUTE_TO_PAGE, {
  "/smart-parser": "smart-parser",
  "/phishing-triage": "phishing-triage",
  "/safe-url-analyzer": "safe-url-analyzer",
  "/attachment-triage": "attachment-triage",
  "/recon-exposure": "recon-exposure",
  "/osint-tools": "osint-tools",
  "/nmap-runner": "nmap-runner",
  "/logs-alerts": "logs-alerts",
  "/detection-mitre": "detection-mitre",
  "/soc-guide": "soc-guide",
  "/case-timeline": "case-timeline",
  "/cyberchef": "cyberchef",
  "/ids-builder": "ids-builder",
})

export function navigateToPage(navigate, page) {
  const path = ROUTE_MAP[page] || "/"
  navigate(path)
}
