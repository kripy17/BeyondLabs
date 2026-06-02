import { useMemo, useState } from "react"
import { Clipboard, Download, FileText, FlaskConical, Plus, Send, ShieldCheck } from "lucide-react"
import SendToActions from "../../components/investigation/SendToActions"
import AnalystOutputCard from "../../components/investigation/AnalystOutputCard"
import { WorkbenchHeader, WorkbenchPage, WorkbenchPanel } from "../../components/layout/WorkbenchShell"
import { DETECTION_LAB_SAMPLES, runDetectionLab } from "../../lib/detectionLabEngine"
import { addTimelineEntry } from "../../lib/timelineStore"
import { downloadText } from "../../lib/domUtils.js"

const PENDING_ARTIFACT_KEY = "beyondarch.pendingArtifact"
const DETECTION_PREFILL_KEY = "beyondarch.detection.prefill"
const IDS_PREFILL_KEY = "beyondarch.ids.prefill"

const TABS = [
  { id: "overview", label: "Overview" },
  { id: "events", label: "Events" },
  { id: "mitre", label: "MITRE Mapping" },
  { id: "drafts", label: "Detection Drafts" },
  { id: "lab", label: "Detection Lab" },
  { id: "review", label: "Testing & Review" },
  { id: "raw", label: "Raw Details" },
]

const SAMPLES = {
  ssh_compromise: {
    label: "SSH compromise sequence",
    text: [
      "Apr 25 22:14:03 web01 sshd[1201]: Failed password for invalid user admin from 198.51.100.23 port 50111 ssh2",
      "Apr 25 22:14:08 web01 sshd[1202]: Failed password for admin from 198.51.100.23 port 50112 ssh2",
      "Apr 25 22:14:15 web01 sshd[1203]: Failed password for root from 198.51.100.23 port 50113 ssh2",
      "Apr 25 22:14:22 web01 sshd[1204]: Accepted password for root from 198.51.100.23 port 50114 ssh2",
      "Apr 25 22:16:10 web01 sudo: root : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/bash",
      "Apr 25 22:17:44 web01 useradd[1210]: new user: name=backupadmin, UID=1002, GID=1002",
      '198.51.100.23 - - [25/Apr/2026:22:18:07 +0530] "GET /.env HTTP/1.1" 404 123 "-" "curl/8.4.0"',
      '198.51.100.23 - - [25/Apr/2026:22:20:31 +0530] "GET /wp-login.php HTTP/1.1" 404 123 "-" "sqlmap/1.7"',
    ].join("\n"),
  },
  powershell: {
    label: "PowerShell encoded command",
    text: "powershell.exe -NoP -W Hidden -EncodedCommand SQBFAFgA",
  },
  web: {
    label: "Web probing",
    text: '1.2.3.4 - - [25/Apr/2026:10:12:00 +0530] "GET /../../etc/passwd HTTP/1.1" 404 123 "-" "sqlmap/1.7"',
  },
  sigma: {
    label: "Sigma draft",
    text: "title: Suspicious PowerShell EncodedCommand\nlogsource:\n  product: windows\ndetection:\n  selection:\n    CommandLine|contains: '-EncodedCommand'\n  condition: selection",
  },
}

const LOCAL_RULES = [
  { id: "AUTH-001", name: "Multiple SSH failures from same IP", category: "Authentication", severity: "High", technique: "T1110", tactic: "Credential Access" },
  { id: "AUTH-002", name: "Successful login after failures", category: "Authentication", severity: "Critical", technique: "T1078", tactic: "Defense Evasion / Persistence" },
  { id: "AUTH-003", name: "Sudo root shell after suspicious login", category: "Privilege", severity: "High", technique: "T1548", tactic: "Privilege Escalation" },
  { id: "ACCT-001", name: "New user creation after privileged activity", category: "Account Changes", severity: "High", technique: "T1136", tactic: "Persistence" },
  { id: "WEB-001", name: "Sensitive path probing", category: "Web", severity: "Medium", technique: "T1046", tactic: "Discovery" },
  { id: "WEB-002", name: "Scanner user-agent detected", category: "Web", severity: "Medium", technique: "T1046", tactic: "Discovery" },
  { id: "WIN-001", name: "PowerShell encoded or hidden execution", category: "Endpoint", severity: "High", technique: "T1059.001", tactic: "Execution" },
  { id: "WIN-002", name: "Windows audit log cleared", category: "Endpoint", severity: "Critical", technique: "T1070.001", tactic: "Defense Evasion" },
  { id: "WIN-003", name: "Windows service installed", category: "Endpoint", severity: "High", technique: "T1543", tactic: "Persistence" },
]

const MITRE_INFO = {
  T1110: { name: "Brute Force", tactic: "Credential Access" },
  T1078: { name: "Valid Accounts", tactic: "Defense Evasion / Persistence" },
  T1548: { name: "Abuse Elevation Control Mechanism", tactic: "Privilege Escalation" },
  T1136: { name: "Create Account", tactic: "Persistence" },
  T1046: { name: "Network Service Discovery", tactic: "Discovery" },
  "T1059.001": { name: "PowerShell", tactic: "Execution" },
  "T1070.001": { name: "Clear Windows Event Logs", tactic: "Defense Evasion" },
  T1543: { name: "Create or Modify System Process", tactic: "Persistence" },
}

function consumeDetectionIntake() {
  try {
    const direct = window.localStorage.getItem(DETECTION_PREFILL_KEY) || ""
    if (direct) {
      window.localStorage.removeItem(DETECTION_PREFILL_KEY)
      return { text: direct, notice: "Loaded context from IDS Rule Builder." }
    }

    const raw = window.localStorage.getItem(PENDING_ARTIFACT_KEY)
    if (!raw) return { text: "", notice: "" }
    const artifact = JSON.parse(raw)
    if (artifact?.target && artifact.target !== "detection-mitre") return { text: "", notice: "" }
    const value = artifact?.value ? String(artifact.value) : ""
    if (!value.trim()) return { text: "", notice: "" }
    window.localStorage.removeItem(PENDING_ARTIFACT_KEY)
    const source = artifact.source || "BeyondArch"
    return { text: value, notice: `Loaded ${artifact.type || "artifact"} from ${source}.` }
  } catch {
    return { text: "", notice: "" }
  }
}

function uniq(items) {
  const seen = new Set()
  return items.filter((item) => {
    const key = String(item.id || item.value || item).toLowerCase()
    if (seen.has(key)) return false
    seen.add(key)
    return true
  })
}

function severityWeight(severity = "") {
  return { Critical: 5, High: 4, Medium: 3, Low: 2, Info: 1 }[severity] || 0
}

function severityClass(severity = "") {
  if (["Critical", "High"].includes(severity)) return "ba-status-danger"
  if (severity === "Medium") return "ba-status-warning"
  if (severity === "Low") return "ba-status-info"
  return "ba-status-local"
}

function parseTime(line) {
  return line.match(/^([A-Z][a-z]{2}\s+\d{1,2}\s+\d\d:\d\d:\d\d)/)?.[1] || line.match(/\[([^\]]+)\]/)?.[1] || ""
}

function parseEvent(line, index) {
  const srcIp = line.match(/\bfrom\s+((?:\d{1,3}\.){3}\d{1,3})\b/)?.[1] || line.match(/^((?:\d{1,3}\.){3}\d{1,3})\b/)?.[1] || ""
  const user = line.match(/invalid user\s+(\S+)/i)?.[1] || line.match(/Failed password for\s+(\S+)/i)?.[1] || line.match(/Accepted password for\s+(\S+)/i)?.[1] || line.match(/name=([A-Za-z0-9._-]+)/)?.[1] || line.match(/Subject User Name:\s*(\S+)/i)?.[1] || ""
  const host = line.match(/^[A-Z][a-z]{2}\s+\d{1,2}\s+\d\d:\d\d:\d\d\s+(\S+)/)?.[1] || line.match(/Computer:\s*(\S+)/i)?.[1] || ""
  const path = line.match(/"\w+\s+([^"\s]+)\s+HTTP/i)?.[1] || ""
  let summary = line
  let type = "generic"
  if (/Failed password/i.test(line)) { type = "ssh_failure"; summary = `Failed SSH login for ${user || "unknown user"}` }
  else if (/Accepted password/i.test(line)) { type = "ssh_success"; summary = `Successful SSH login for ${user || "unknown user"}` }
  else if (/sudo:|COMMAND=\/bin\/bash|su:/i.test(line)) { type = "sudo"; summary = "Sudo/root shell activity" }
  else if (/useradd|new user/i.test(line)) { type = "account_create"; summary = `New user created${user ? `: ${user}` : ""}` }
  else if (/sqlmap|\/\.env|\/admin|\/wp-login|\/etc\/passwd|\.\.\//i.test(line)) { type = "web_probe"; summary = `Web probing${path ? `: ${path}` : ""}` }
  else if (/powershell|encodedcommand|-nop|-w hidden/i.test(line)) { type = "powershell"; summary = "PowerShell encoded/hidden execution" }
  else if (/EventID:\s*1102|audit log was cleared/i.test(line)) { type = "log_clear"; summary = "Windows audit log cleared" }
  else if (/EventID:\s*7045|Service Name|Service File Name/i.test(line)) { type = "service_install"; summary = "Windows service installed" }
  return { id: `evt-${index}`, time: parseTime(line), source_ip: srcIp, user, host, path, raw: line, type, summary, matchedRules: [], techniques: [] }
}

function buildRuleMatches(events) {
  const failuresByIp = {}
  const successByIp = {}
  events.forEach((event) => {
    if (event.type === "ssh_failure" && event.source_ip) failuresByIp[event.source_ip] = (failuresByIp[event.source_ip] || 0) + 1
    if (event.type === "ssh_success" && event.source_ip) successByIp[event.source_ip] = (successByIp[event.source_ip] || 0) + 1
  })
  const matched = []
  const add = (ruleId, evidenceEvents, status = "Candidate match") => {
    const rule = LOCAL_RULES.find((item) => item.id === ruleId)
    if (!rule || !evidenceEvents.length) return
    matched.push({ ...rule, status, evidence: evidenceEvents.map((event) => event.raw).slice(0, 5), count: evidenceEvents.length })
    evidenceEvents.forEach((event) => {
      event.matchedRules.push(rule.id)
      event.techniques.push(rule.technique)
    })
  }
  Object.entries(failuresByIp).forEach(([ip, count]) => {
    if (count >= 2) add("AUTH-001", events.filter((event) => event.type === "ssh_failure" && event.source_ip === ip))
    if (count >= 2 && successByIp[ip]) add("AUTH-002", events.filter((event) => ["ssh_failure", "ssh_success"].includes(event.type) && event.source_ip === ip))
  })
  add("AUTH-003", events.filter((event) => event.type === "sudo"))
  add("ACCT-001", events.filter((event) => event.type === "account_create"))
  add("WEB-001", events.filter((event) => event.type === "web_probe" && /\/\.env|\/admin|\/wp-login|\/etc\/passwd|\.\.\//i.test(event.raw)))
  add("WEB-002", events.filter((event) => event.type === "web_probe" && /sqlmap|nikto|curl|python-requests/i.test(event.raw)))
  add("WIN-001", events.filter((event) => event.type === "powershell"))
  add("WIN-002", events.filter((event) => event.type === "log_clear"))
  add("WIN-003", events.filter((event) => event.type === "service_install"))
  return uniq(matched)
}

function mapMitreFromRules(rules) {
  return uniq(rules.map((rule) => {
    const info = MITRE_INFO[rule.technique] || { name: "Candidate technique", tactic: rule.tactic }
    return {
      id: rule.technique,
      tactic: info.tactic,
      name: info.name,
      evidenceStrength: severityWeight(rule.severity) >= 4 ? "Stronger candidate" : "Needs validation",
      evidence: `${rule.id} ${rule.name}: ${rule.evidence[0] || "local rule evidence"}`,
      why: `${rule.name} produced a local behavior match that can support ${rule.technique} as a candidate mapping.`,
      missing: "Validate event source, user context, host role, timeline order, and surrounding telemetry before treating this as confirmed ATT&CK mapping.",
    }
  }))
}

function analyzeEvidence(text) {
  const lines = text.split(/\r?\n/).map((line) => line.trim()).filter(Boolean)
  const events = lines.map(parseEvent)
  const rules = buildRuleMatches(events)
  const mitre = mapMitreFromRules(rules)
  const severity = rules.map((rule) => rule.severity).sort((a, b) => severityWeight(b) - severityWeight(a))[0] || "Info"
  const summary = rules.some((rule) => rule.id === "AUTH-002")
    ? "Possible SSH compromise sequence detected. Multiple failed SSH logins were followed by successful login, sudo/root shell activity, and possible account or web probing activity."
    : rules.length
      ? `${rules[0].name} detected from local evidence. Review matched events and validate telemetry context.`
      : "No strong local detection rule matched. Add more event context or test draft logic."
  return {
    source: "user_provided_evidence",
    method: "local_static_detection_engineering",
    checked_at: new Date().toISOString(),
    events,
    rules,
    mitre,
    severity,
    verdict: rules.some((rule) => ["Critical", "High"].includes(rule.severity)) ? "Needs analyst review" : "Local review",
    evidenceLevel: rules.length >= 2 ? "Multiple supporting signals" : rules.length ? "Single supporting signal" : "Insufficient evidence",
    summary,
  }
}

function sigmaDraft(result) {
  const has = (id) => result.rules.some((rule) => rule.id === id)
  if (has("AUTH-002")) return [
    "title: SSH Failures Followed By Successful Login",
    "id: 00000000-0000-4000-8000-000000000111",
    "status: experimental",
    "description: Draft detection for repeated SSH failures followed by a successful login from the same source.",
    "author: BeyondArch analyst",
    "logsource:",
    "  product: linux",
    "  service: auth",
    "detection:",
    "  selection_fail:",
    "    message|contains: 'Failed password'",
    "  selection_success:",
    "    message|contains: 'Accepted password'",
    "  condition: selection_fail and selection_success",
    "fields:",
    "  - src_ip",
    "  - user",
    "  - host",
    "  - message",
    "falsepositives:",
    "  - User password mistakes",
    "  - Authorized testing",
    "level: high",
    "tags:",
    "  - attack.t1110",
    "  - attack.t1078",
  ].join("\n")
  if (has("WIN-001")) return "title: Suspicious PowerShell Encoded Or Hidden Execution\nstatus: experimental\nlogsource:\n  product: windows\n  category: process_creation\ndetection:\n  selection:\n    Image|endswith: '\\\\powershell.exe'\n    CommandLine|contains:\n      - '-EncodedCommand'\n      - '-NoP'\n      - '-W Hidden'\n  condition: selection\nfields:\n  - Image\n  - CommandLine\n  - User\n  - Computer\nfalsepositives:\n  - Administrative scripts\nlevel: high\ntags:\n  - attack.t1059.001\n  - attack.t1027"
  if (has("WEB-001") || has("WEB-002")) return "title: Suspicious Web Path Or Scanner User Agent\nstatus: experimental\nlogsource:\n  category: webserver\ndetection:\n  selection_path:\n    url|contains:\n      - '/.env'\n      - '/etc/passwd'\n      - '/wp-login.php'\n  selection_agent:\n    user_agent|contains:\n      - 'sqlmap'\n  condition: 1 of selection_*\nfields:\n  - src_ip\n  - url\n  - user_agent\nfalsepositives:\n  - Authorized web scans\nlevel: medium\ntags:\n  - attack.t1046"
  return "title: Local Detection Candidate\nstatus: experimental\nlogsource:\n  product: unknown\ndetection:\n  selection:\n    message|contains: suspicious\n  condition: selection\nfalsepositives:\n  - Unknown\nlevel: low"
}

function wazuhDraft(result) {
  const first = result.rules[0]
  if (!first) return "<!-- No Wazuh-style draft generated. Add matched evidence first. -->"
  return [
    '<group name="beyondarch_local,detection_engineering,">',
    `  <rule id="100${first.id.replace(/\D/g, "").padStart(3, "0")}" level="${first.severity === "Critical" ? 12 : first.severity === "High" ? 10 : 7}">`,
    `    <description>${first.name} - draft only, validate before production use</description>`,
    `    <group>${first.category.toLowerCase().replace(/\s+/g, "_")},attack.${first.technique.toLowerCase()},</group>`,
    "    <options>no_full_log</options>",
    "  </rule>",
    "</group>",
  ].join("\n")
}

function idsDraft(result) {
  if (!result.rules.some((rule) => rule.id.startsWith("WEB"))) return "No IDS draft generated. Network/web evidence is required."
  return 'alert http any any -> any any (msg:"BeyondArch suspicious web probing draft"; content:"sqlmap"; nocase; http_user_agent; classtype:web-application-attack; sid:1000001; rev:1;)'
}

function detectionReview(result, tests) {
  const issues = []
  const suggestions = []
  const coverage = []
  const sigma = sigmaDraft(result)
  const check = (pass, issue, suggestion) => {
    if (!pass) { issues.push(issue); suggestions.push(suggestion) }
  }
  check(/title:/i.test(sigma), "Missing clear title.", "Add a concise behavior-focused title.")
  check(/logsource:/i.test(sigma), "Missing logsource.", "Define product/service/category before production conversion.")
  check(/fields:/i.test(sigma), "Missing triage fields.", "List fields such as src_ip, user, host, message, command line, or URL.")
  check(/condition:/i.test(sigma), "Missing condition logic.", "Define exact selections and condition logic.")
  check(/falsepositives:/i.test(sigma), "Missing false-positive notes.", "Document admin/testing/maintenance false positives.")
  check(/attack\./i.test(sigma), "Missing ATT&CK candidate tags.", "Tag candidates only when evidence supports the behavior.")
  check(tests.length > 0, "No local test cases saved.", "Add positive and negative sample events before relying on the draft.")
  check(result.rules.length > 0, "No matched local rule evidence.", "Add more specific evidence before drafting production detections.")
  if (result.events.length) coverage.push(`${result.events.length} parsed event${result.events.length === 1 ? "" : "s"}`)
  if (result.rules.length) coverage.push(`${result.rules.length} candidate behavior match${result.rules.length === 1 ? "" : "es"}`)
  if (result.mitre.length) coverage.push(`${result.mitre.length} ATT&CK mapping hint${result.mitre.length === 1 ? "" : "s"}`)
  if (!coverage.length) coverage.push("Insufficient coverage from current evidence")
  return { issues, suggestions, coverage, missing_fields: issues.filter((item) => /field|logsource|condition|test/i.test(item)) }
}

function simulate(ruleText = "", sample = "") {
  const needles = [...ruleText.matchAll(/'([^']{3,80})'|"([^"]{3,80})"/g)].map((match) => match[1] || match[2])
  const matched = needles.filter((needle) => sample.toLowerCase().includes(needle.toLowerCase()))
  return {
    matched: matched.length > 0,
    matched_terms: matched,
    missing_fields: ["normalized parser fields may differ from draft field names"],
    false_positive_risk: matched.length === 1 ? "Medium" : "Low",
    note: "Lightweight local keyword simulation only; not a full Sigma/Wazuh/IDS engine.",
  }
}

function markdownReport(result) {
  const sigma = sigmaDraft(result)
  return [
    "# Detection Engineering Summary",
    "",
    `- Verdict: ${result.verdict}`,
    `- Severity: ${result.severity}`,
    `- Evidence level: ${result.evidenceLevel}`,
    `- Events: ${result.events.length}`,
    `- Matched rules: ${result.rules.length}`,
    `- ATT&CK candidates: ${result.mitre.length}`,
    "",
    "## Analyst Summary",
    result.summary,
    "",
    "## Matched Behavior",
    ...(result.rules.length ? result.rules.map((rule) => `- ${rule.id} ${rule.name}: ${rule.severity}; ${rule.technique}`) : ["- None"]),
    "",
    "## ATT&CK Candidate Hints",
    ...(result.mitre.length ? result.mitre.map((item) => `- ${item.id} ${item.name} (${item.evidenceStrength}): ${item.evidence}`) : ["- None"]),
    "",
    "## Sigma Draft",
    "```yaml",
    sigma,
    "```",
    "",
    "## Limitations",
    "- Local/static analysis only. No live Wazuh/SIEM/agent telemetry is connected.",
    "- ATT&CK mappings are evidence-based candidates, not confirmed attribution.",
    "- Draft detections require engineering review and testing before production.",
  ].join("\n")
}

function Field({ label, value }) {
  return (
    <div className="rounded-xl border border-white/10 bg-black/40 p-3">
      <p className="text-xs font-black uppercase tracking-[0.14em] text-zinc-400">{label}</p>
      <p className="mt-1 whitespace-pre-wrap break-all text-sm text-zinc-100">{value || "N/A"}</p>
    </div>
  )
}

function DraftPanel({ title, value, ext, onCopy }) {
  return (
    <WorkbenchPanel className="space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <p className="text-xs font-black uppercase tracking-[0.14em] text-zinc-400">{title}</p>
          <p className="mt-1 text-xs text-amber-100">Draft only. Validate before production use.</p>
        </div>
        <div className="flex gap-2">
          <button className="ba-button-ghost rounded-lg px-2 py-1 text-xs font-bold" onClick={() => onCopy(value, title)}>Copy</button>
          <button className="ba-button-ghost rounded-lg px-2 py-1 text-xs font-bold" onClick={() => downloadText(`detection-draft.${ext}`, value, "text/plain")}>Export</button>
        </div>
      </div>
      <pre className="max-h-[520px] overflow-auto whitespace-pre-wrap rounded-xl border border-white/10 bg-black/40 p-3 text-xs text-zinc-100">{value}</pre>
    </WorkbenchPanel>
  )
}

import { useSessionState } from "../../lib/useSessionState"

export default function DetectionMitrePage({ setPage }) {
  const [intake] = useState(() => consumeDetectionIntake())
  const [input, setInput] = useState(intake.text)
  const [result, setResult] = useState(null)
  const [tab, setTab] = useSessionState("detection-mitre.tab", "overview")
  const [inputOpen, setInputOpen] = useState(true)
  const [notice, setNotice] = useState(intake.notice)
  const [filters, setFilters] = useState({ severity: "all", group: "all", technique: "all", srcIp: "", user: "", host: "", search: "" })
  const [tester, setTester] = useState("")
  const [testerRule, setTesterRule] = useState("")
  const [tests, setTests] = useState([])
  const [labRule, setLabRule] = useState(DETECTION_LAB_SAMPLES.powershell.rule)
  const [labLogs, setLabLogs] = useState(DETECTION_LAB_SAMPLES.powershell.logs)

  const sigma = result ? sigmaDraft(result) : ""
  const wazuh = result ? wazuhDraft(result) : ""
  const ids = result ? idsDraft(result) : ""
  const review = useMemo(() => result ? detectionReview(result, tests) : { issues: [], suggestions: [], coverage: [], missing_fields: [] }, [result, tests])
  const testerResult = useMemo(() => simulate(testerRule || sigma, tester), [testerRule, sigma, tester])
  const markdown = result ? markdownReport(result) : ""
  const labResult = useMemo(() => runDetectionLab(labRule, labLogs), [labRule, labLogs])

  const filteredEvents = useMemo(() => {
    if (!result) return []
    return result.events.filter((event) => {
      const haystack = JSON.stringify(event).toLowerCase()
      if (filters.search && !haystack.includes(filters.search.toLowerCase())) return false
      if (filters.srcIp && event.source_ip !== filters.srcIp) return false
      if (filters.user && event.user !== filters.user) return false
      if (filters.host && event.host !== filters.host) return false
      if (filters.technique !== "all" && !event.techniques.includes(filters.technique)) return false
      if (filters.group !== "all" && !event.matchedRules.some((ruleId) => result.rules.find((rule) => rule.id === ruleId)?.category === filters.group)) return false
      if (filters.severity !== "all" && !event.matchedRules.some((ruleId) => result.rules.find((rule) => rule.id === ruleId)?.severity === filters.severity)) return false
      return true
    })
  }, [result, filters])

  function run() {
    if (!input.trim()) {
      setNotice("Paste evidence before analysis.")
      return
    }
    const next = analyzeEvidence(input)
    setResult(next)
    setTab("overview")
    setInputOpen(false)
    setNotice("Local detection analysis completed. No live Wazuh/SIEM connection was used.")
  }

  async function copy(content, label) {
    if (!content) return
    await navigator.clipboard.writeText(content)
    setNotice(`${label} copied.`)
  }

  function clearAll() {
    setInput("")
    setResult(null)
    setInputOpen(true)
    setTab("overview")
    setNotice("Evidence cleared.")
  }

  function addTest() {
    if (!tester.trim()) {
      setNotice("Paste test event text first.")
      return
    }
    setTests((items) => [...items, { id: crypto.randomUUID(), text: tester, result: testerResult }])
    setNotice("Local rule test saved.")
  }

  function sendResultToTimeline() {
    if (!result) return
    const entry = addTimelineEntry({
      type: "detection",
      title: result.rules[0]?.name || "Detection review",
      summary: result.summary,
      source: "Detection & MITRE",
      tags: [result.severity, ...result.mitre.map((item) => item.id)].filter(Boolean),
      raw: markdown || input,
    })
    setNotice(`Added to Case Timeline: ${entry.title}`)
    setPage?.("case-timeline")
  }

  function sendLabToTimeline() {
    const entry = addTimelineEntry({
      type: "detection_lab",
      title: labRule.match(/title:\s*(.+)/i)?.[1]?.trim() || "Detection Lab test",
      summary: `${labResult.coverage}. ATT&CK hints: ${labResult.attack.join(", ") || "none"}.`,
      source: "Detection Lab",
      tags: ["sigma", "test", ...labResult.attack],
      raw: `Rule:\n${labRule}\n\nSample logs:\n${labLogs}\n\nMatches:\n${labResult.matches.map((item) => item.line).join("\n")}`,
    })
    setNotice(`Added Detection Lab result to Case Timeline: ${entry.title}`)
    setPage?.("case-timeline")
  }

  function sendToIdsBuilder() {
    const value = ids && !ids.startsWith("No IDS draft") ? ids : sigma
    try {
      window.localStorage.setItem(IDS_PREFILL_KEY, value)
      window.localStorage.setItem(PENDING_ARTIFACT_KEY, JSON.stringify({
        target: "ids-builder",
        type: ids && !ids.startsWith("No IDS draft") ? "ids_rule" : "detection_draft",
        value,
        source: "Detection & MITRE",
        created_at: new Date().toISOString(),
      }))
      setNotice("Detection draft sent to IDS Rule Builder.")
      setPage?.("ids-builder")
    } catch {
      setNotice("Could not write Detection Workspace handoff to local storage.")
    }
  }

  const sourceIps = [...new Set(result?.events.map((event) => event.source_ip).filter(Boolean) || [])]
  const users = [...new Set(result?.events.map((event) => event.user).filter(Boolean) || [])]
  const hosts = [...new Set(result?.events.map((event) => event.host).filter(Boolean) || [])]
  const groups = [...new Set(result?.rules.map((rule) => rule.category) || [])]
  const techniques = [...new Set(result?.mitre.map((item) => item.id) || [])]

  return (
    <WorkbenchPage className="ba-detection-page ba-page-enter">
      <WorkbenchHeader
        eyebrow="Detection workspace"
        title="Detection & MITRE"
        subtitle="Map local evidence to candidate ATT&CK techniques, draft detections, and review tuning notes without claiming certainty."
        icon={ShieldCheck}
        chips={[{ label: "local analysis", tone: "local" }, { label: "candidate mapping", tone: "warning" }, { label: "draft rules", tone: "info" }]}
      />

      <WorkbenchPanel className="space-y-3">
        {result && !inputOpen ? (
          <div className="ba-output-section-head">
            <div>
              <p className="ba-output-section-eyebrow">Evidence loaded</p>
              <h2 className="ba-output-section-title">{result.events.length} events · {result.rules.length} behavior matches · {result.mitre.length} ATT&CK hints</h2>
              <p className="mt-1 text-sm text-zinc-400">ATT&CK hints are evidence-based candidates, not confirmed attribution.</p>
            </div>
            <div className="flex flex-wrap gap-2">
              <button className="ba-button-secondary rounded-xl px-3 py-2 text-sm font-bold" onClick={() => setInputOpen(true)}>Expand input</button>
              <button className="ba-button-secondary rounded-xl px-3 py-2 text-sm font-bold" onClick={run}>Re-analyze</button>
              <button className="ba-button-secondary rounded-xl px-3 py-2 text-sm font-bold" onClick={clearAll}>Clear</button>
              <button className="ba-button-secondary rounded-xl px-3 py-2 text-sm font-bold" onClick={() => copy(input, "Evidence")}><Clipboard className="mr-2 inline h-4 w-4" />Copy evidence</button>
            </div>
          </div>
        ) : (
          <div className="grid gap-4 xl:grid-cols-[1.35fr_0.65fr]">
            <label className="space-y-2">
              <span className="ba-field-label">Evidence input</span>
              <textarea value={input} onChange={(event) => setInput(event.target.value)} placeholder="Paste alert text, log lines, EDR notes, IDS rule context, incident summary, Sigma draft, or detection evidence..." className="ba-compact-evidence-input min-h-44 w-full resize-y rounded-xl border border-white/10 bg-black/40 p-4 font-mono text-sm text-zinc-100 outline-none placeholder:text-zinc-600" />
            </label>
            <div className="space-y-3 rounded-2xl border border-white/10 bg-black/40 p-4">
              <div>
                <p className="text-sm font-black text-zinc-100">Analysis controls</p>
                <p className="mt-1 text-xs leading-5 text-zinc-400">Use local static logic for behavior hints, draft rules, and review notes.</p>
              </div>
              <select className="w-full rounded-xl border border-white/10 bg-black/40 px-3 py-2 text-sm font-bold text-zinc-100" defaultValue="" onChange={(event) => { if (event.target.value) { setInput(SAMPLES[event.target.value].text); setNotice(`${SAMPLES[event.target.value].label} sample loaded.`); event.target.value = "" } }}>
                <option value="">Load sample...</option>
                {Object.entries(SAMPLES).map(([key, sample]) => <option key={key} value={key}>{sample.label}</option>)}
              </select>
              <div className="grid gap-2">
                <button className="ba-button-primary rounded-xl px-4 py-2 text-sm font-black" onClick={run}><ShieldCheck className="mr-2 inline h-4 w-4" />Analyze evidence</button>
                <button className="ba-button-secondary rounded-xl px-4 py-2 text-sm font-bold" onClick={() => copy(input, "Evidence")}><Clipboard className="mr-2 inline h-4 w-4" />Copy evidence</button>
                <button className="ba-button-secondary rounded-xl px-4 py-2 text-sm font-bold" onClick={clearAll}>Clear</button>
              </div>
            </div>
          </div>
        )}
        {notice ? <p className="ba-info-banner text-sm">{notice}</p> : null}
      </WorkbenchPanel>

      <nav className="ba-tab-row flex flex-wrap gap-2">
        {TABS.map((item) => <button key={item.id} className={`ba-tab-button ${tab === item.id ? "is-active" : ""}`} onClick={() => setTab(item.id)}>{item.label}</button>)}
      </nav>

      {!result ? (
        <div className="ba-start-hint">
          <FileText className="h-5 w-5" />
          <span>Paste evidence or load a sample to generate behavior matches, ATT&CK candidate hints, draft detections, and review notes.</span>
        </div>
      ) : null}

      {result && tab === "overview" ? (
        <>
        <AnalystOutputCard
          title="Detection output quality"
          verdict={result.verdict}
          confidence={result.evidenceLevel}
          summary={result.summary}
          evidence={result.rules.slice(0, 5).map((rule) => `${rule.name}: ${rule.evidence || rule.technique}`)}
          limitations={["ATT&CK mappings are behavior candidates, not attribution.", "No live Wazuh/SIEM/agent telemetry is connected.", ...(review.gaps || []).slice(0, 3)]}
          nextActions={["Validate candidate mappings against source telemetry and timeline.", "Review draft rules before use in production.", "Add only validated mappings/findings to the case report."]}
          metrics={[
            ["Events", result.events.length],
            ["Behavior matches", result.rules.length],
            ["ATT&CK hints", result.mitre.length],
          ]}
        />
        <div className="grid gap-4 xl:grid-cols-[0.95fr_1.05fr]">
          <WorkbenchPanel className="space-y-3">
            <p className="text-xs font-black uppercase tracking-[0.14em] text-zinc-400">Detection review</p>
            <div className="grid gap-3 md:grid-cols-2">
              <Field label="Disposition" value={result.verdict} />
              <Field label="Severity" value={result.severity} />
              <Field label="Evidence level" value={result.evidenceLevel} />
              <Field label="Event count" value={result.events.length} />
              <Field label="Behavior matches" value={result.rules.length} />
              <Field label="ATT&CK hints" value={result.mitre.length} />
            </div>
            <section className="rounded-xl border border-white/10 bg-black/40 p-3">
              <p className="text-xs font-black uppercase tracking-[0.14em] text-zinc-400">Analyst summary</p>
              <p className="mt-2 text-sm leading-6 text-zinc-100">{result.summary}</p>
              <p className="mt-2 text-xs leading-5 text-amber-100">ATT&CK hints are evidence-based candidates. Validate with source telemetry, host role, user context, and timeline before reporting.</p>
            </section>
          </WorkbenchPanel>
          <WorkbenchPanel className="space-y-3">
            <p className="text-xs font-black uppercase tracking-[0.14em] text-zinc-400">Top matched behavior</p>
            <div className="grid gap-2 md:grid-cols-2">
              {result.rules.slice(0, 6).map((rule) => <Field key={rule.id} label={`${rule.id} · ${rule.severity}`} value={`${rule.name}\n${rule.technique}`} />)}
              {!result.rules.length ? <p className="ba-empty-state md:col-span-2">No local behavior rule matched. Add richer evidence or use Testing & Review.</p> : null}
            </div>
            <div className="grid gap-2 md:grid-cols-2">
              {review.coverage.map((item) => <p key={item} className="rounded-xl border border-cyan-400/20 bg-cyan-400/10 p-3 text-sm text-cyan-100">{item}</p>)}
            </div>
            <div className="flex flex-wrap gap-2">
              <button className="ba-button-primary rounded-xl px-3 py-2 text-sm font-bold" onClick={() => setTab("events")}>Review events</button>
              <button className="ba-button-secondary rounded-xl px-3 py-2 text-sm font-bold" onClick={() => setTab("mitre")}>MITRE hints</button>
              <button className="ba-button-secondary rounded-xl px-3 py-2 text-sm font-bold" onClick={() => setTab("drafts")}>Draft rules</button>
              <button className="ba-button-secondary rounded-xl px-3 py-2 text-sm font-bold" onClick={() => setTab("review")}>Testing & review</button>
              <button className="ba-button-secondary rounded-xl px-3 py-2 text-sm font-bold" onClick={sendResultToTimeline}><Plus className="mr-2 inline h-4 w-4" />Add to timeline</button>
            </div>
            <SendToActions
              source="Detection & MITRE"
              setPage={setPage}
              payload={{
                type: "detection_review",
                title: result.rules[0]?.name || "Detection review",
                value: markdown || input,
                summary: result.summary,
                raw: markdown || input,
                severity: result.severity,
                confidence: result.evidenceLevel,
                tags: ["detection", "mitre", ...result.mitre.map((item) => item.id)],
              }}
            />
          </WorkbenchPanel>
        </div>
        </>
      ) : null}

      {result && tab === "events" ? (
        <WorkbenchPanel className="space-y-3">
          <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
            <input value={filters.search} onChange={(event) => setFilters((data) => ({ ...data, search: event.target.value }))} placeholder="Text search" className="rounded-xl border border-white/10 bg-black/40 px-3 py-2 text-sm text-zinc-100 outline-none placeholder:text-zinc-600" />
            <select value={filters.severity} onChange={(event) => setFilters((data) => ({ ...data, severity: event.target.value }))} className="rounded-xl border border-white/10 bg-black/40 px-3 py-2 text-sm text-zinc-100"><option value="all">All severities</option>{["Critical", "High", "Medium", "Low", "Info"].map((item) => <option key={item} value={item}>{item}</option>)}</select>
            <select value={filters.group} onChange={(event) => setFilters((data) => ({ ...data, group: event.target.value }))} className="rounded-xl border border-white/10 bg-black/40 px-3 py-2 text-sm text-zinc-100"><option value="all">All groups</option>{groups.map((item) => <option key={item} value={item}>{item}</option>)}</select>
            <select value={filters.technique} onChange={(event) => setFilters((data) => ({ ...data, technique: event.target.value }))} className="rounded-xl border border-white/10 bg-black/40 px-3 py-2 text-sm text-zinc-100"><option value="all">All techniques</option>{techniques.map((item) => <option key={item} value={item}>{item}</option>)}</select>
            <select value={filters.srcIp} onChange={(event) => setFilters((data) => ({ ...data, srcIp: event.target.value }))} className="rounded-xl border border-white/10 bg-black/40 px-3 py-2 text-sm text-zinc-100"><option value="">Any source IP</option>{sourceIps.map((item) => <option key={item} value={item}>{item}</option>)}</select>
            <select value={filters.user} onChange={(event) => setFilters((data) => ({ ...data, user: event.target.value }))} className="rounded-xl border border-white/10 bg-black/40 px-3 py-2 text-sm text-zinc-100"><option value="">Any user</option>{users.map((item) => <option key={item} value={item}>{item}</option>)}</select>
            <select value={filters.host} onChange={(event) => setFilters((data) => ({ ...data, host: event.target.value }))} className="rounded-xl border border-white/10 bg-black/40 px-3 py-2 text-sm text-zinc-100"><option value="">Any host</option>{hosts.map((item) => <option key={item} value={item}>{item}</option>)}</select>
          </div>
          <div className="overflow-auto rounded-xl border border-white/10">
            <table className="w-full min-w-[980px] text-left text-sm">
              <thead className="bg-black/40 text-xs uppercase tracking-[0.12em] text-zinc-400"><tr>{["Time", "Severity", "Rule", "Technique", "Source IP", "User", "Host", "Event Summary"].map((head) => <th key={head} className="p-2">{head}</th>)}</tr></thead>
              <tbody className="divide-y divide-white/10 text-zinc-200">
                {filteredEvents.map((event) => {
                  const rule = result.rules.find((item) => item.id === event.matchedRules[0])
                  return <tr key={event.id} className="hover:bg-black/40"><td className="p-2 whitespace-nowrap">{event.time || "-"}</td><td className="p-2"><span className={`ba-chip ${severityClass(rule?.severity)}`}>{rule?.severity || "Info"}</span></td><td className="p-2">{event.matchedRules.join(", ") || "-"}</td><td className="p-2">{event.techniques.join(", ") || "-"}</td><td className="p-2">{event.source_ip || "-"}</td><td className="p-2">{event.user || "-"}</td><td className="p-2">{event.host || "-"}</td><td className="p-2"><details><summary className="max-w-lg cursor-pointer truncate">{event.summary}</summary><p className="mt-2 break-all text-xs text-zinc-400">{event.raw}</p></details></td></tr>
                })}
              </tbody>
            </table>
          </div>
        </WorkbenchPanel>
      ) : null}

      {result && tab === "mitre" ? (
        <WorkbenchPanel className="space-y-3">
          <div className="rounded-xl border border-amber-400/20 bg-amber-400/10 p-3 text-sm text-amber-100">ATT&CK hints are evidence-based candidates, not confirmed attribution. Treat these as mapping prompts for analyst validation.</div>
          <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
            {result.mitre.map((item) => <article key={item.id} className="rounded-xl border border-white/10 bg-black/40 p-3"><div className="flex flex-wrap gap-2"><span className="ba-chip ba-status-info">{item.tactic}</span><span className="ba-chip ba-status-warning">{item.evidenceStrength}</span></div><h3 className="mt-3 font-black text-zinc-100">{item.id} {item.name}</h3><p className="mt-2 text-sm text-zinc-300">{item.evidence}</p><p className="mt-2 text-xs text-zinc-400">{item.why}</p><p className="mt-2 text-xs text-amber-100">{item.missing}</p><label className="mt-3 flex items-center gap-2 text-xs text-zinc-300"><input type="checkbox" />Analyst validated</label></article>)}
            {!result.mitre.length ? <p className="ba-empty-state md:col-span-2 xl:col-span-3">No ATT&CK candidate hints were generated from this evidence.</p> : null}
          </div>
        </WorkbenchPanel>
      ) : null}

      {result && tab === "drafts" ? (
        <div className="grid gap-4 xl:grid-cols-[1fr_1fr_0.7fr]">
          <DraftPanel title="Sigma Draft" value={sigma} ext="yml" onCopy={copy} />
          <DraftPanel title="Wazuh-style Draft" value={wazuh} ext="xml" onCopy={copy} />
          <WorkbenchPanel className="space-y-3">
            <p className="text-xs font-black uppercase tracking-[0.14em] text-zinc-400">IDS / Snort / Suricata</p>
            <h3 className="text-lg font-black text-zinc-100">Send to IDS Rule Builder</h3>
            <p className="text-sm leading-6 text-zinc-300">IDS signatures need protocol fields, ports, content matches, SIDs, flow options, and engine-specific validation. Use the dedicated IDS page for that workflow.</p>
            <pre className="max-h-44 overflow-auto whitespace-pre-wrap rounded-xl border border-white/10 bg-black/40 p-3 text-xs text-zinc-100">{ids}</pre>
            <button type="button" className="ba-button-primary rounded-xl px-3 py-2 text-sm font-black" onClick={sendToIdsBuilder}><Send className="mr-2 inline h-4 w-4" />Open IDS Rule Builder</button>
            <button type="button" className="ba-button-secondary rounded-xl px-3 py-2 text-sm font-bold" onClick={() => copy(markdown, "Detection summary")}>Copy summary</button>
          </WorkbenchPanel>
        </div>
      ) : null}


      {tab === "lab" ? (
        <div className="grid gap-4 xl:grid-cols-[0.9fr_1.1fr]">
          <WorkbenchPanel className="space-y-3">
            <div className="ba-output-section-head">
              <div>
                <p className="ba-output-section-eyebrow" style={{ color: "var(--neo-cyan)" }}>Detection Lab</p>
                <h2 className="ba-output-section-title">Test Sigma-style logic against sample logs</h2>
                <p className="mt-1 text-sm text-zinc-400">Lightweight local testing only. This is not a full SIEM rule compiler.</p>
              </div>
              <select className="rounded-xl border border-white/10 bg-black/40 px-3 py-2 text-sm text-zinc-100" defaultValue="" onChange={(event) => { const sample = DETECTION_LAB_SAMPLES[event.target.value]; if (sample) { setLabRule(sample.rule); setLabLogs(sample.logs); setNotice(`${sample.label} Detection Lab sample loaded.`); event.target.value = "" } }}>
                <option value="">Load lab sample...</option>
                {Object.entries(DETECTION_LAB_SAMPLES).map(([key, sample]) => <option key={key} value={key}>{sample.label}</option>)}
              </select>
            </div>
            <label className="space-y-2 block"><span className="ba-field-label">Sigma-style rule draft</span><textarea value={labRule} onChange={(event) => setLabRule(event.target.value)} className="min-h-72 w-full rounded-xl border border-white/10 bg-black/40 p-3 font-mono text-xs text-zinc-100 outline-none" /></label>
            <label className="space-y-2 block"><span className="ba-field-label">Positive / negative sample logs</span><textarea value={labLogs} onChange={(event) => setLabLogs(event.target.value)} className="min-h-44 w-full rounded-xl border border-white/10 bg-black/40 p-3 font-mono text-xs text-zinc-100 outline-none" /></label>
          </WorkbenchPanel>
          <WorkbenchPanel className="space-y-3">
            <div className="grid gap-3 md:grid-cols-3">
              <Field label="Coverage" value={labResult.coverage} />
              <Field label="Matched terms" value={labResult.terms.slice(0, 5).join(", ") || "None"} />
              <Field label="ATT&CK hints" value={labResult.attack.join(", ") || "None"} />
            </div>
            <section className="rounded-xl border border-white/10 bg-black/40 p-3">
              <p className="text-xs font-black uppercase tracking-[0.14em] text-zinc-400">Matched sample events</p>
              <div className="mt-3 space-y-2">
                {labResult.matches.slice(0, 8).map((match) => <p key={match.id} className="rounded-xl border border-cyan-400/20 bg-cyan-400/10 p-3 font-mono text-xs text-cyan-50">{match.line}</p>)}
                {!labResult.matches.length ? <p className="ba-empty-state">No sample log lines matched the current rule terms.</p> : null}
              </div>
            </section>
            <div className="grid gap-3 md:grid-cols-2">
              <DraftPanel title="Splunk SPL" value={labResult.spl} ext="spl" onCopy={copy} />
              <DraftPanel title="Elastic KQL" value={labResult.kql} ext="kql" onCopy={copy} />
            </div>
            <details className="ba-final-details">
              <summary>Review notes, false positives, and Wazuh-style draft</summary>
              <div className="mt-3 grid gap-3">
                {labResult.review.map((item) => <p key={item} className="rounded-xl border border-amber-400/20 bg-amber-400/10 p-3 text-sm text-amber-100">{item}</p>)}
                {labResult.falsePositiveNotes.map((item) => <p key={item} className="rounded-xl border border-white/10 bg-black/40 p-3 text-sm text-zinc-300">False-positive note: {item}</p>)}
                <pre className="max-h-56 overflow-auto whitespace-pre-wrap rounded-xl border border-white/10 bg-black/30 p-3 text-xs text-zinc-100">{labResult.wazuh}</pre>
              </div>
            </details>
            <div className="flex flex-wrap gap-2">
              <button className="ba-button-primary rounded-xl px-3 py-2 text-sm font-bold" onClick={() => copy(labResult.spl, "SPL")}>Copy SPL</button>
              <button className="ba-button-secondary rounded-xl px-3 py-2 text-sm font-bold" onClick={sendLabToTimeline}><Plus className="mr-2 inline h-4 w-4" />Add lab result to timeline</button>
            </div>
          </WorkbenchPanel>
        </div>
      ) : null}

      {result && tab === "review" ? (
        <div className="grid gap-4 xl:grid-cols-[0.9fr_1.1fr]">
          <WorkbenchPanel className="space-y-3">
            <p className="text-xs font-black uppercase tracking-[0.14em] text-zinc-400">Detection review notes</p>
            <div className="grid gap-2">
              {review.coverage.map((item) => <p key={item} className="rounded-xl border border-cyan-400/20 bg-cyan-400/10 p-3 text-sm text-cyan-100">Coverage: {item}</p>)}
              {review.issues.map((item) => <p key={item} className="rounded-xl border border-amber-400/20 bg-amber-400/10 p-3 text-sm text-amber-100">Tuning needed: {item}</p>)}
              {!review.issues.length ? <p className="rounded-xl border border-emerald-400/20 bg-emerald-400/10 p-3 text-sm text-emerald-100">No obvious static review gaps found. Still validate against positive and negative test events.</p> : null}
            </div>
            <details className="ba-final-details">
              <summary>Suggestions and missing fields</summary>
              <div className="mt-3 grid gap-2 md:grid-cols-2">
                <div>{review.suggestions.map((item) => <p key={item} className="mb-2 rounded-xl border border-white/10 bg-black/40 p-3 text-sm text-zinc-300">{item}</p>)}</div>
                <div>{review.missing_fields.map((item) => <p key={item} className="mb-2 rounded-xl border border-white/10 bg-black/40 p-3 text-sm text-zinc-300">{item}</p>)}</div>
              </div>
            </details>
          </WorkbenchPanel>
          <WorkbenchPanel className="space-y-3">
            <p className="text-xs font-black uppercase tracking-[0.14em] text-zinc-400">Local rule tester</p>
            <textarea value={testerRule} onChange={(event) => setTesterRule(event.target.value)} placeholder="Optional: paste regex, Sigma draft, Wazuh-style draft, or detection logic. If empty, generated Sigma is used." className="min-h-28 rounded-xl border border-white/10 bg-black/40 p-3 font-mono text-sm text-zinc-100 outline-none placeholder:text-zinc-600" />
            <textarea value={tester} onChange={(event) => setTester(event.target.value)} placeholder="Paste log lines or event text to test locally..." className="min-h-28 rounded-xl border border-white/10 bg-black/40 p-3 font-mono text-sm text-zinc-100 outline-none placeholder:text-zinc-600" />
            <div className="flex flex-wrap gap-2"><button className="ba-button-primary rounded-xl px-3 py-2 text-sm font-bold" onClick={addTest}><FlaskConical className="mr-2 inline h-4 w-4" />Save test result</button><span className={`ba-chip ${testerResult.matched ? "ba-status-local" : "ba-status-warning"}`}>{testerResult.matched ? "Matched" : "No match"}</span></div>
            <div className="grid gap-3 md:grid-cols-2"><Field label="Matched terms" value={testerResult.matched_terms.join(", ") || "None"} /><Field label="Missing fields" value={testerResult.missing_fields.join(", ")} /><Field label="False-positive risk" value={testerResult.false_positive_risk} /><Field label="Simulation note" value={testerResult.note} /></div>
          </WorkbenchPanel>
        </div>
      ) : null}

      {result && tab === "raw" ? (
        <WorkbenchPanel className="space-y-3">
          <details className="ba-final-details"><summary>Raw evidence</summary><pre className="mt-3 max-h-72 overflow-auto whitespace-pre-wrap text-xs text-zinc-100">{input}</pre></details>
          <details className="ba-final-details"><summary>Raw parsed output</summary><pre className="mt-3 max-h-96 overflow-auto whitespace-pre-wrap text-xs text-zinc-100">{JSON.stringify({ ...result, review, tests }, null, 2)}</pre></details>
          <details className="ba-final-details"><summary>Parser metadata</summary><pre className="mt-3 max-h-72 overflow-auto whitespace-pre-wrap text-xs text-zinc-100">{JSON.stringify({ source: result.source, method: result.method, checked_at: result.checked_at }, null, 2)}</pre></details>
          <div className="flex flex-wrap gap-2"><button className="ba-button-secondary rounded-xl px-3 py-2 text-sm font-bold" onClick={() => copy(markdown, "Markdown summary")}><Clipboard className="mr-2 inline h-4 w-4" />Copy Markdown</button><button className="ba-button-secondary rounded-xl px-3 py-2 text-sm font-bold" onClick={() => downloadText("detection-engineering-result.json", JSON.stringify({ ...result, review, tests }, null, 2), "application/json")}><Download className="mr-2 inline h-4 w-4" />Export JSON</button></div>
        </WorkbenchPanel>
      ) : null}
    </WorkbenchPage>
  )
}
