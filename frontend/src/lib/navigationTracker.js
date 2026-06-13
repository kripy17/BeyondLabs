const VISITED_KEY = "beyondarch.visitedPages.v1"
const MAX_VISITED = 12

const PAGE_LABELS = {
  "smart-parser": "Smart Parser",
  "phishing-triage": "Phishing Triage",
  "safe-url-analyzer": "URL Analyzer",
  "attachment-triage": "Attachment Triage",
  "recon-exposure": "Recon & Exposure",
  "osint-tools": "OSINT Tools",
  "nmap-runner": "Nmap Runner",
  siem: "SIEM Workspace",
  "logs-alerts": "Logs & Alerts",
  cyberchef: "CyberChef",
  "ids-builder": "IDS Builder",
  "detection-mitre": "Detection & MITRE",
  "soc-guide": "SOC Guide",
  "case-timeline": "Case & Report",
  settings: "Settings",
}

export function recordPageVisit(page) {
  if (!page || page === "home") return
  try {
    const raw = sessionStorage.getItem(VISITED_KEY)
    const visited = raw ? JSON.parse(raw) : []
    const next = [{ page, time: Date.now() }, ...visited.filter((e) => e.page !== page)].slice(0, MAX_VISITED)
    sessionStorage.setItem(VISITED_KEY, JSON.stringify(next))
  } catch {} // eslint-disable-line no-empty
}

export function getRecentPages(count = 5) {
  try {
    const raw = sessionStorage.getItem(VISITED_KEY)
    if (!raw) return []
    const visited = JSON.parse(raw)
    return visited.slice(0, count).map((e) => ({
      page: e.page,
      label: PAGE_LABELS[e.page] || e.page,
      time: e.time,
    }))
  } catch {
    return []
  }
}
