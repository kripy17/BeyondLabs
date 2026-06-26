import { useMemo, useState } from "react"
import { Clipboard, Download, FileText, FlaskConical, Plus, Send, ShieldCheck } from "lucide-react"
import SendToActions from "../../components/investigation/SendToActions"
import AnalystOutputCard from "../../components/investigation/AnalystOutputCard"
import { WorkbenchHeader, WorkbenchPage, WorkbenchPanel } from "../../components/layout/WorkbenchShell"
import { DETECTION_LAB_SAMPLES, runDetectionLab } from "../../lib/detectionLabEngine"
import { addTimelineEntry } from "../../lib/timelineStore"
import { downloadText } from "../../lib/domUtils.js"

const DETECTION_PATTERN_WEIGHTS = {
  persistence: { weight: 25, label: "Persistence mechanism" },
  credential_access: { weight: 25, label: "Credential access behavior" },
  lateral_movement: { weight: 20, label: "Lateral movement indicator" },
  defense_evasion: { weight: 20, label: "Defense evasion detected" },
  execution: { weight: 15, label: "Execution of suspicious commands" },
  discovery: { weight: 10, label: "Discovery / reconnaissance" },
  command_and_control: { weight: 20, label: "Command and control behavior" },
  exfiltration: { weight: 25, label: "Data exfiltration indicator" },
  privilege_escalation: { weight: 20, label: "Privilege escalation" },
  initial_access: { weight: 15, label: "Initial access vector" },
}

const PATTERN_KEYWORDS = {
  persistence: [/run\s*key/i, /currentversion\\run/i, /schtasks/i, /scheduled\s*task/i, /service\s*install/i, /useradd/i, /create\s*account/i, /bitsadmin/i, /start-bitstransfer/i, /T1547/i, /T1136/i, /T1053/i, /T1543/i, /backupsvc/i, /registry\s*run/i],
  credential_access: [/lsass/i, /procdump/i, /minidump/i, /credential\s*dump/i, /comsvcs\.dll/i, /taskkill.*lsass/i, /T1003/i],
  lateral_movement: [/wmic\s*\/node/i, /wmiprvse/i, /logon\s*type:\s*10/i, /mstsc/i, /rdp\s*logon/i, /T1021/i, /lateral\s*movement/i],
  defense_evasion: [/encodedcommand/i, /-w\s+hidden/i, /-nop\b/i, /log\s*clear/i, /wevtutil/i, /indicator\s*removal/i, /rundll32/i, /regsvr32/i, /mshta/i, /lolbin/i, /T1070/i, /T1218/i, /clear-eventlog/i, /fsutil.*delete/i],
  execution: [/powershell/i, /cmd\.exe/i, /process\s*create/i, /T1059/i, /T1047/i, /wmic\s+process/i],
  discovery: [/whoami/i, /ipconfig/i, /netstat/i, /nslookup/i, /net\s+group/i, /net\s+user/i, /systeminfo/i, /tasklist/i, /T1082/i, /dir\s+c:\\\\users/i],
  command_and_control: [/dns\s*query.*evil/i, /evil\.xyz/i, /outbound\s*connection/i, /\bc2\b/i, /beacon/i, /T1071/i, /longsubdomain/i, /\.xyz.*response/i],
  exfiltration: [/exfil/i, /outbound\s*data/i, /large\s*transfer/i, /T1048/i, /data.*transfer.*out/i],
  privilege_escalation: [/sudo/i, /\/bin\/bash/i, /SeTcbPrivilege/i, /T1548/i],
  initial_access: [/sqlmap/i, /\/etc\/passwd/i, /\/wp-login/i, /\.\.\//i, /web\s*probe/i, /T1190/i, /nikto/i],
}

function computeDetectionPriority(text) {
  const matched_patterns = []
  let score = 0
  Object.entries(DETECTION_PATTERN_WEIGHTS).forEach(([pattern, config]) => {
    const keywords = PATTERN_KEYWORDS[pattern]
    if (!keywords) return
    const matched = keywords.some((regex) => regex.test(text))
    if (matched) {
      score += config.weight
      matched_patterns.push({ pattern, score: config.weight, label: config.label })
    }
  })
  score = Math.min(score, 100)
  let priority = "low"
  if (score >= 75) priority = "critical"
  else if (score >= 50) priority = "high"
  else if (score >= 25) priority = "medium"
  const totalPatterns = Object.keys(DETECTION_PATTERN_WEIGHTS).length
  const confidence = Math.round((matched_patterns.length / totalPatterns) * 100) / 100
  return { score, priority, matched_patterns, confidence }
}

function generateDetectionNarrative(text, priority) {
  const { score, priority: level, matched_patterns } = priority
  const patternList = matched_patterns.map((p) => p.label).join(", ")
  const narrative = []
  narrative.push(`Detection Priority: ${level.toUpperCase()} (${score}/100)`)
  narrative.push(`Confidence: ${Math.round(priority.confidence * 100)}% (${matched_patterns.length} behavior patterns matched)`)
  if (matched_patterns.length > 0) {
    narrative.push(``)
    narrative.push(`The observed events indicate: ${patternList}.`)
  }
  if (matched_patterns.length > 0) {
    narrative.push(``)
    narrative.push(`Recommended actions:`)
    const recs = []
    const names = matched_patterns.map((p) => p.pattern)
    if (names.includes("credential_access")) recs.push("Isolate affected hosts and initiate credential rotation")
    if (names.includes("persistence")) recs.push("Review registry Run keys, scheduled tasks, and service configurations")
    if (names.includes("lateral_movement")) recs.push("Segment affected hosts and review lateral connections")
    if (names.includes("defense_evasion")) recs.push("Review event logs for gaps and enable enhanced logging")
    if (names.includes("command_and_control")) recs.push("Block outbound connections to suspicious destinations and review DNS logs")
    if (names.includes("exfiltration")) recs.push("Monitor outbound data transfers and review data loss prevention controls")
    if (names.includes("execution")) recs.push("Review process creation events and restrict script execution policies")
    if (names.includes("discovery")) recs.push("Review reconnaissance patterns and restrict administrative tool usage")
    if (names.includes("privilege_escalation")) recs.push("Review privilege assignments and audit elevation events")
    if (names.includes("initial_access")) recs.push("Review ingress vectors and patch exposed services")
    recs.forEach((rec) => narrative.push(`- ${rec}`))
  }
  return narrative.join("\n")
}

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
  persistence_run_key: {
    label: "Registry Run key persistence",
    text: [
      'EventID: 13, Image: C:\\Windows\\System32\\reg.exe, TargetObject: HKU\\S-1-5-21-...\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\BackupSvc, Details: C:\\Users\\Public\\svchost.exe',
      'EventID: 4688, Image: C:\\Windows\\System32\\reg.exe, CommandLine: reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v BackupSvc /t REG_SZ /d "C:\\Users\\Public\\svchost.exe"',
      'EventID: 1, Image: C:\\Users\\Public\\svchost.exe, CommandLine: "C:\\Users\\Public\\svchost.exe" -silent, User: DESKTOP-01\\jdoe',
    ].join("\n"),
  },
  credential_dumping: {
    label: "Credential dumping (LSASS)",
    text: [
      'EventID: 10, Image: C:\\Tools\\procdump64.exe, TargetImage: lsass.exe, GrantedAccess: 0x1FFFFF, User: DESKTOP-01\\admin',
      'EventID: 1, Image: C:\\Windows\\System32\\rundll32.exe, CommandLine: rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump "C:\\Users\\admin\\lsass.dmp" full, User: DESKTOP-01\\admin',
      'EventID: 4688, Image: C:\\Windows\\System32\\cmd.exe, CommandLine: "C:\\Windows\\System32\\cmd.exe" /c taskkill /f /im lsass.exe',
    ].join("\n"),
  },
  wmi_lateral: {
    label: "WMI lateral movement",
    text: [
      'EventID: 4688, Image: C:\\Windows\\System32\\wbem\\WMIC.exe, CommandLine: wmic /node:SRV-DB-02 process call create "powershell -enc SQBFAFgA", User: CORP\\jdoe',
      'EventID: 1, Image: C:\\Windows\\System32\\wbem\\WmiPrvSE.exe, CommandLine: C:\\Windows\\System32\\wbem\\wmiprvse.exe, User: CORP\\jdoe',
      'EventID: 4624, Account Name: jdoe, Source Network Address: 10.0.0.10, Logon Type: 3, Computer: SRV-DB-02',
    ].join("\n"),
  },
  discovery: {
    label: "Host discovery sweep",
    text: [
      '4688: cmd.exe /c whoami, User: DESKTOP-01\\jdoe',
      '4688: cmd.exe /c ipconfig /all, User: DESKTOP-01\\jdoe',
      '4688: cmd.exe /c net group "Domain Admins" /domain, User: DESKTOP-01\\jdoe',
      '4688: cmd.exe /c nslookup dc01.corp.local, User: DESKTOP-01\\jdoe',
      '4688: cmd.exe /c netstat -ano, User: DESKTOP-01\\jdoe',
      '4688: cmd.exe /c dir C:\\Users\\admin\\Desktop, User: DESKTOP-01\\jdoe',
    ].join("\n"),
  },
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
  windows_events: {
    label: "Windows Event Log (Sysmon)",
    text: [
      'LogName: Security, EventID: 4625, Account Name: Administrator, Source Workstation: WIN10-DESKTOP, Source Network Address: 10.0.0.55',
      'LogName: Security, EventID: 4624, Account Name: Administrator, Source Network Address: 10.0.0.55',
      'LogName: Security, EventID: 4672, Account Name: Administrator, Privileges: SeTcbPrivilege',
      'LogName: Sysmon, EventID: 1, Image: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe, CommandLine: powershell -NoP -W Hidden -EncodedCommand SQBFAFgA, User: ADMIN\\Administrator',
    ].join("\n"),
  },
  cloudtrail: {
    label: "AWS CloudTrail sample",
    text: [
      '2026-04-25T10:00:00Z arn:aws:iam::123456789012:user/admin AwsApiCall ConsoleLogin us-east-1 sourceIP 198.51.100.23',
      '2026-04-25T10:05:00Z arn:aws:iam::123456789012:user/admin AwsApiCall CreateUser us-east-1 sourceIP 198.51.100.23',
      '2026-04-25T10:06:00Z arn:aws:iam::123456789012:user/admin AwsApiCall AttachUserPolicy us-east-1 sourceIP 198.51.100.23',
      '2026-04-25T10:10:00Z arn:aws:iam::123456789012:user/admin AwsApiCall CreateAccessKey us-east-1 sourceIP 198.51.100.23',
    ].join("\n"),
  },
  lateral_rdp: {
    label: "RDP lateral movement",
    text: [
      'EventID: 4624, Account Name: jdoe, Source Network Address: 10.0.0.10, Logon Type: 10, Computer: SRV-DB-01',
      'EventID: 4624, Account Name: jdoe, Source Network Address: 10.0.0.10, Logon Type: 10, Computer: SRV-APP-01',
      'EventID: 4624, Account Name: jdoe, Source Network Address: 10.0.0.10, Logon Type: 10, Computer: SRV-DC-01',
      'EventID: 4648, Account Name: jdoe, Target Server: SRV-DC-01, Process Name: C:\\Windows\\System32\\mstsc.exe',
    ].join("\n"),
  },
  c2_dns: {
    label: "DNS C2 beacon",
    text: [
      'DNS Query: abcdef12345.longsubdomain.evil.xyz Type: A Source: 10.0.0.55 Response: 198.51.100.99',
      'DNS Query: fedcba54321.longsubdomain.evil.xyz Type: A Source: 10.0.0.55 Response: 198.51.100.99',
      'DNS Query: a1b2c3d4.longsubdomain.evil.xyz Type: A Source: 10.0.0.55 Response: 198.51.100.99',
      'Outbound Connection: 10.0.0.55:49152 -> 198.51.100.99:443 Protocol: TCP Bytes: 1024',
    ].join("\n"),
  },
}

const LOCAL_RULES = [
  { id: "AUTH-001", name: "Multiple SSH failures from same IP", category: "Authentication", severity: "High", technique: "T1110", tactic: "Credential Access" },
  { id: "AUTH-002", name: "Successful login after failures", category: "Authentication", severity: "Critical", technique: "T1078", tactic: "Defense Evasion / Persistence" },
  { id: "AUTH-003", name: "Sudo root shell after suspicious login", category: "Privilege", severity: "High", technique: "T1548", tactic: "Privilege Escalation" },
  { id: "ACCT-001", name: "New user creation after privileged activity", category: "Account Changes", severity: "High", technique: "T1136", tactic: "Persistence" },
  { id: "ACCT-002", name: "Scheduled task or cron created", category: "Account Changes", severity: "High", technique: "T1053.005", tactic: "Persistence" },
  { id: "WEB-001", name: "Sensitive path probing", category: "Web", severity: "Medium", technique: "T1046", tactic: "Discovery" },
  { id: "WEB-002", name: "Scanner user-agent detected", category: "Web", severity: "Medium", technique: "T1046", tactic: "Discovery" },
  { id: "WEB-003", name: "SQL injection or path traversal probe", category: "Web", severity: "High", technique: "T1190", tactic: "Initial Access" },
  { id: "WIN-001", name: "PowerShell encoded or hidden execution", category: "Endpoint", severity: "High", technique: "T1059.001", tactic: "Execution" },
  { id: "WIN-002", name: "Windows audit log cleared", category: "Endpoint", severity: "Critical", technique: "T1070.001", tactic: "Defense Evasion" },
  { id: "WIN-003", name: "Windows service installed", category: "Endpoint", severity: "High", technique: "T1543.003", tactic: "Persistence" },
  { id: "WIN-004", name: "Scheduled task created via schtasks", category: "Endpoint", severity: "High", technique: "T1053.005", tactic: "Persistence" },
  { id: "WIN-005", name: "Remote desktop connection from suspicious host", category: "Endpoint", severity: "Medium", technique: "T1021.001", tactic: "Lateral Movement" },
  { id: "WIN-006", name: "Credential dumping via LSASS", category: "Endpoint", severity: "Critical", technique: "T1003.001", tactic: "Credential Access" },
  { id: "WIN-007", name: "Registry Run key added", category: "Endpoint", severity: "High", technique: "T1547.001", tactic: "Persistence" },
  { id: "WIN-008", name: "WMI process creation", category: "Endpoint", severity: "Medium", technique: "T1047", tactic: "Execution" },
  { id: "WIN-009", name: "LOLBin execution", category: "Endpoint", severity: "Medium", technique: "T1218", tactic: "Defense Evasion" },
  { id: "WIN-010", name: "System discovery commands", category: "Endpoint", severity: "Low", technique: "T1082", tactic: "Discovery" },
  { id: "WIN-011", name: "Indicator removal via file deletion", category: "Endpoint", severity: "High", technique: "T1070.004", tactic: "Defense Evasion" },
  { id: "WIN-012", name: "BITS job creation", category: "Endpoint", severity: "Medium", technique: "T1197", tactic: "Defense Evasion" },
  { id: "NET-001", name: "Outbound connection to known-bad IP", category: "Network", severity: "Critical", technique: "T1071.001", tactic: "Command and Control" },
  { id: "NET-002", name: "DNS query to suspicious domain", category: "Network", severity: "High", technique: "T1071.004", tactic: "Command and Control" },
  { id: "DATA-001", name: "Large outbound data transfer", category: "Data", severity: "High", technique: "T1048", tactic: "Exfiltration" },
  { id: "DATA-002", name: "Sensitive file accessed by non-owner", category: "Data", severity: "Medium", technique: "T1005", tactic: "Collection" },
  { id: "CLOUD-001", name: "Console login from unusual location", category: "Cloud", severity: "High", technique: "T1078", tactic: "Defense Evasion" },
  { id: "CLOUD-002", name: "IAM policy modification", category: "Cloud", severity: "High", technique: "T1098", tactic: "Persistence" },
]

const MITRE_INFO = {
  T1110: { name: "Brute Force", tactic: "Credential Access" },
  T1078: { name: "Valid Accounts", tactic: "Defense Evasion / Persistence" },
  T1548: { name: "Abuse Elevation Control Mechanism", tactic: "Privilege Escalation" },
  T1136: { name: "Create Account", tactic: "Persistence" },
  T1046: { name: "Network Service Discovery", tactic: "Discovery" },
  "T1059.001": { name: "PowerShell", tactic: "Execution" },
  "T1070.001": { name: "Clear Windows Event Logs", tactic: "Defense Evasion" },
  "T1543.003": { name: "Create or Modify System Process", tactic: "Persistence" },
  "T1053.005": { name: "Scheduled Task", tactic: "Persistence" },
  "T1021.001": { name: "Remote Desktop Protocol", tactic: "Lateral Movement" },
  "T1071.001": { name: "Web Protocols", tactic: "Command and Control" },
  "T1071.004": { name: "DNS", tactic: "Command and Control" },
  T1190: { name: "Exploit Public-Facing Application", tactic: "Initial Access" },
  T1048: { name: "Exfiltration Over Alternative Protocol", tactic: "Exfiltration" },
  T1005: { name: "Data from Local System", tactic: "Collection" },
  T1098: { name: "Account Manipulation", tactic: "Persistence" },
  "T1003.001": { name: "LSASS Memory", tactic: "Credential Access" },
  "T1547.001": { name: "Registry Run Keys / Startup Folder", tactic: "Persistence" },
  T1047: { name: "Windows Management Instrumentation", tactic: "Execution" },
  T1218: { name: "Signed Binary Proxy Execution", tactic: "Defense Evasion" },
  T1082: { name: "System Information Discovery", tactic: "Discovery" },
  "T1070.004": { name: "Indicator Removal: File Deletion", tactic: "Defense Evasion" },
  T1197: { name: "BITS Jobs", tactic: "Defense Evasion" },
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
  return line.match(/^([A-Z][a-z]{2}\s+\d{1,2}\s+\d\d:\d\d:\d\d)/)?.[1] || line.match(/\[([^\]]+)\]/)?.[1] || line.match(/^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)/)?.[1] || ""
}

function parseEvent(line, index) {
  const srcIp = line.match(/\bfrom\s+((?:\d{1,3}\.){3}\d{1,3})\b/)?.[1] || line.match(/^((?:\d{1,3}\.){3}\d{1,3})\b/)?.[1] || line.match(/Source Network Address:\s*((?:\d{1,3}\.){3}\d{1,3})/i)?.[1] || line.match(/sourceIP\s+((?:\d{1,3}\.){3}\d{1,3})/i)?.[1] || line.match(/Source:\s*((?:\d{1,3}\.){3}\d{1,3})/i)?.[1] || ""
  const user = line.match(/invalid user\s+(\S+)/i)?.[1] || line.match(/Failed password for\s+(\S+)/i)?.[1] || line.match(/Accepted password for\s+(\S+)/i)?.[1] || line.match(/name=([A-Za-z0-9._-]+)/)?.[1] || line.match(/Subject User Name:\s*(\S+)/i)?.[1] || line.match(/Account Name:\s*(\S+)/i)?.[1] || line.match(/arn:.*?:user\/(\S+)/i)?.[1] || ""
  const host = line.match(/^[A-Z][a-z]{2}\s+\d{1,2}\s+\d\d:\d\d:\d\d\s+(\S+)/)?.[1] || line.match(/Computer:\s*(\S+)/i)?.[1] || ""
  const path = line.match(/"\w+\s+([^"\s]+)\s+HTTP/i)?.[1] || ""
  const destIp = line.match(/->\s*((?:\d{1,3}\.){3}\d{1,3})/)?.[1] || ""
  const dnsQuery = line.match(/DNS Query:\s*(\S+)/i)?.[1] || ""
  let summary = line
  let type = "generic"
  if (/Failed password/i.test(line)) { type = "ssh_failure"; summary = `Failed SSH login for ${user || "unknown user"}` }
  else if (/Accepted password/i.test(line)) { type = "ssh_success"; summary = `Successful SSH login for ${user || "unknown user"}` }
  else if (/sudo:|COMMAND=\/bin\/bash|su:/i.test(line)) { type = "sudo"; summary = "Sudo/root shell activity" }
  else if (/useradd|new user/i.test(line)) { type = "account_create"; summary = `New user created${user ? `: ${user}` : ""}` }
  else if (/EventID:\s*4625/i.test(line)) { type = "win_logon_fail"; summary = "Windows logon failure" }
  else if (/EventID:\s*4624/i.test(line) && /Logon Type:\s*10/i.test(line)) { type = "rdp_logon"; summary = `RDP logon from ${srcIp || "unknown"}` }
  else if (/EventID:\s*4624/i.test(line)) { type = "win_logon"; summary = "Windows logon success" }
  else if (/EventID:\s*4672/i.test(line)) { type = "win_privilege"; summary = "Special privilege assigned to logon" }
  else if (/EventID:\s*4648/i.test(line)) { type = "win_cred_use"; summary = "Explicit credential usage attempted" }
  else if (/EventID:\s*1\b.*CommandLine.*powershell/i.test(line)) { type = "powershell"; summary = "PowerShell execution (Sysmon EventID 1)" }
  else if (/schtasks|schtasks\.exe|Task Scheduler/i.test(line)) { type = "scheduled_task"; summary = "Scheduled task created" }
  else if (/EventID:\s*7045|Service Name/i.test(line)) { type = "service_install"; summary = "Windows service installed" }
  else if (/EventID:\s*1102|audit log was cleared/i.test(line)) { type = "log_clear"; summary = "Windows audit log cleared" }
  else if (/sqlmap|\/\.env|\/admin|\/wp-login|\/etc\/passwd|\.\.\//i.test(line)) { type = "web_probe"; summary = `Web probing${path ? `: ${path}` : ""}` }
  else if (/union select|sql injection|' or '1'='1/i.test(line)) { type = "web_sqli"; summary = "SQL injection probe detected" }
  else if (/powershell|encodedcommand|-nop|-w hidden/i.test(line)) { type = "powershell"; summary = "PowerShell encoded/hidden execution" }
  else if (/ConsoleLogin|CreateUser|AttachUserPolicy|CreateAccessKey/i.test(line)) { type = "cloud_admin"; summary = `Cloud admin action: ${line.match(/(ConsoleLogin|CreateUser|AttachUserPolicy|CreateAccessKey)/i)?.[1] || "api_call"}` }
  else if (/DNS Query.*evil|\.xyz|\.top|\.club\b|longsubdomain/i.test(line)) { type = "dns_c2"; summary = `DNS query to suspicious domain: ${dnsQuery}` }
  else if (/Outbound Connection.*->/i.test(line)) { type = "outbound_c2"; summary = `Outbound connection to ${destIp}` }
  else if (/EventID:\s*(1|13)\b.*lsass\.exe|lsass.*MiniDump|procdump.*lsass/i.test(line)) { type = "credential_dumping"; summary = "Possible LSASS credential dumping" }
  else if (/EventID:\s*13\b.*CurrentVersion\\Run|reg add.*CurrentVersion\\Run/i.test(line)) { type = "run_key"; summary = "Registry Run key added" }
  else if (/WMIC|wmic |WmiPrvSE/i.test(line)) { type = "wmi"; summary = "WMI process execution" }
  else if (/rundll32.*javascript|mshta.*http|regsvr32.*http|cscript.*\.wsf|LOLBin/i.test(line)) { type = "lolbin"; summary = "LOLBin proxy execution" }
  else if (/whoami|ipconfig|netstat|nslookup|net\s+group|net\s+user|systeminfo|tasklist/i.test(line)) { type = "discovery"; summary = "Host discovery command" }
  else if (/EventID:\s*1102|fsutil.*delete|del\s+\.log|wevtutil.*cl|Clear-EventLog|\.evtx.*delete/i.test(line)) { type = "indicator_removal"; summary = "Possible log or indicator deletion" }
  else if (/bitsadmin|Start-BitsTransfer/i.test(line)) { type = "bits"; summary = "BITS job activity" }
  return { id: `evt-${index}`, time: parseTime(line), source_ip: srcIp, user, host, path, dest_ip: destIp, dns_query: dnsQuery, raw: line, type, summary, matchedRules: [], techniques: [] }
}

function buildRuleMatches(events) {
  const failuresByIp = {}
  const successByIp = {}
  const rdpByUser = {}
  const cloudActionsByIp = {}
  const dnsBySrc = {}
  events.forEach((event) => {
    if ((event.type === "ssh_failure" || event.type === "win_logon_fail") && event.source_ip) failuresByIp[event.source_ip] = (failuresByIp[event.source_ip] || 0) + 1
    if ((event.type === "ssh_success" || event.type === "win_logon") && event.source_ip) successByIp[event.source_ip] = (successByIp[event.source_ip] || 0) + 1
    if (event.type === "rdp_logon" && event.user) rdpByUser[event.user] = (rdpByUser[event.user] || 0) + 1
    if (event.type === "cloud_admin" && event.source_ip) cloudActionsByIp[event.source_ip] = (cloudActionsByIp[event.source_ip] || 0) + 1
    if (event.type === "dns_c2" && event.source_ip) dnsBySrc[event.source_ip] = (dnsBySrc[event.source_ip] || 0) + 1
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
    if (count >= 2) add("AUTH-001", events.filter((event) => (event.type === "ssh_failure" || event.type === "win_logon_fail") && event.source_ip === ip))
    if (count >= 2 && successByIp[ip]) add("AUTH-002", events.filter((event) => ["ssh_failure", "win_logon_fail", "ssh_success", "win_logon"].includes(event.type) && event.source_ip === ip))
  })
  add("AUTH-003", events.filter((event) => event.type === "sudo"))
  add("ACCT-001", events.filter((event) => event.type === "account_create"))
  add("ACCT-002", events.filter((event) => event.type === "scheduled_task"))
  add("WEB-001", events.filter((event) => event.type === "web_probe" && /\/\.env|\/admin|\/wp-login|\/etc\/passwd|\.\.\//i.test(event.raw)))
  add("WEB-002", events.filter((event) => event.type === "web_probe" && /sqlmap|nikto|curl|python-requests/i.test(event.raw)))
  add("WEB-003", events.filter((event) => event.type === "web_sqli"))
  add("WIN-001", events.filter((event) => event.type === "powershell"))
  add("WIN-002", events.filter((event) => event.type === "log_clear"))
  add("WIN-003", events.filter((event) => event.type === "service_install"))
  add("WIN-004", events.filter((event) => event.type === "scheduled_task"))
  add("WIN-006", events.filter((event) => event.type === "credential_dumping"))
  add("WIN-007", events.filter((event) => event.type === "run_key"))
  add("WIN-008", events.filter((event) => event.type === "wmi"))
  add("WIN-009", events.filter((event) => event.type === "lolbin"))
  add("WIN-010", events.filter((event) => event.type === "discovery"))
  add("WIN-011", events.filter((event) => event.type === "indicator_removal"))
  add("WIN-012", events.filter((event) => event.type === "bits"))
  Object.entries(rdpByUser).forEach(([user, count]) => {
    if (count >= 2) add("WIN-005", events.filter((event) => event.type === "rdp_logon" && event.user === user))
  })
  add("NET-001", events.filter((event) => event.type === "outbound_c2"))
  add("NET-002", events.filter((event) => event.type === "dns_c2"))
  add("CLOUD-001", events.filter((event) => event.type === "cloud_admin"))
  Object.entries(cloudActionsByIp).forEach(([ip, count]) => {
    if (count >= 2) add("CLOUD-002", events.filter((event) => event.type === "cloud_admin" && event.source_ip === ip))
  })
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
  const priority = computeDetectionPriority(text)
  let summary = rules.some((rule) => rule.id === "AUTH-002")
    ? "Possible SSH compromise sequence detected. Multiple failed SSH logins were followed by successful login, sudo/root shell activity, and possible account or web probing activity."
    : rules.some((rule) => rule.id === "WIN-006")
    ? "Credential dumping indicators detected. LSASS process access or MiniDump extraction observed. Immediate forensic collection recommended."
    : rules.some((rule) => rule.id === "WIN-007")
    ? "Registry Run key modification detected. This persistence mechanism can survive reboots and load malicious code at user logon."
    : rules.some((rule) => rule.id === "WIN-008")
    ? "WMI remote or lateral execution detected. WmiPrvSE.exe spawning child processes may indicate lateral movement."
    : rules.some((rule) => rule.id === "WIN-009")
    ? "LOLBin proxy execution detected. A signed Microsoft binary was used to load remote or script content, bypassing application whitelisting."
    : rules.some((rule) => rule.id === "WIN-010")
    ? "Host discovery command sequence detected. Commands like whoami, ipconfig, netstat, and net group are commonly used for situational awareness."
    : rules.some((rule) => rule.id === "WIN-011")
    ? "Indicator removal detected. Log files or event logs may have been cleared or deleted to hinder forensic analysis."
    : rules.some((rule) => rule.id === "WIN-012")
    ? "BITS job activity detected. BITS can be abused for stealthy file download or data exfiltration."
    : rules.length
      ? `${rules[0].name} detected from local evidence. Review matched events and validate telemetry context.`
      : "No strong local detection rule matched. Add more event context or test draft logic."
  return {
    priority,
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
  if (has("CLOUD-001") || has("CLOUD-002")) return "title: Suspicious Cloud IAM Activity\nstatus: experimental\nlogsource:\n  product: cloud\ndetection:\n  selection:\n    event_name|contains:\n      - 'ConsoleLogin'\n      - 'CreateUser'\n      - 'CreateAccessKey'\n      - 'AttachUserPolicy'\n  condition: selection\nfields:\n  - user_identity\n  - source_ip\n  - event_name\n  - aws_region\nfalsepositives:\n  - Authorized admin activity\n  - Automation scripts\nlevel: high\ntags:\n  - attack.t1078\n  - attack.t1098"
  if (has("NET-001") || has("NET-002")) return "title: Suspicious DNS Or Outbound C2\nstatus: experimental\nlogsource:\n  category: network\ndetection:\n  selection:\n    destination|endswith:\n      - '.xyz'\n      - '.top'\n    dns_query|re: '[a-z0-9]{20,}\\.'\n  condition: selection\nfields:\n  - src_ip\n  - destination\n  - dns_query\n  - protocol\nfalsepositives:\n  - CDN traffic\n  - Authorized external access\n  - Long legitimate hostnames\nlevel: high\ntags:\n  - attack.t1071.001\n  - attack.t1071.004"
  if (has("WIN-006")) return "title: Suspicious LSASS Process Access\nstatus: experimental\nlogsource:\n  product: windows\n  service: sysmon\ndetection:\n  selection:\n    EventID: 10\n    TargetImage|endswith: '\\lsass.exe'\n    GrantedAccess: '0x1FFFFF'\n  condition: selection\nfields:\n  - Image\n  - TargetImage\n  - GrantedAccess\n  - User\n  - Computer\nfalsepositives:\n  - AV or EDR products\n  - Microsoft support tools\n  - Password change notifications\nlevel: critical\ntags:\n  - attack.t1003.001\n  - attack.t1055"
  if (has("WIN-007")) return "title: Suspicious Registry Run Key Modification\nstatus: experimental\nlogsource:\n  product: windows\n  service: sysmon\ndetection:\n  selection:\n    EventID: 13\n    TargetObject|contains: '\\CurrentVersion\\Run'\n  condition: selection\nfields:\n  - Image\n  - TargetObject\n  - Details\n  - User\nfalsepositives:\n  - Software installers\n  - Driver packages\nlevel: high\ntags:\n  - attack.t1547.001"
  if (has("WIN-008")) return "title: WMI Process Creation\nstatus: experimental\nlogsource:\n  product: windows\n  service: sysmon\ndetection:\n  selection:\n    EventID: 1\n    ParentImage|endswith: '\\WmiPrvSE.exe'\n  condition: selection\nfields:\n  - Image\n  - CommandLine\n  - User\n  - Computer\nfalsepositives:\n  - Legitimate WMI management\n  - SCCM or deployment agents\nlevel: high\ntags:\n  - attack.t1047"
  if (has("WIN-009")) return "title: Suspicious LOLBin Proxy Execution\nstatus: experimental\nlogsource:\n  product: windows\n  service: sysmon\ndetection:\n  selection:\n    Image|endswith:\n      - '\\rundll32.exe'\n      - '\\mshta.exe'\n      - '\\regsvr32.exe'\n    CommandLine|contains:\n      - 'http'\n      - 'https'\n  condition: selection\nfields:\n  - Image\n  - CommandLine\n  - ParentImage\n  - User\nfalsepositives:\n  - Web-based admin tools\n  - Browser helper objects\nlevel: medium\ntags:\n  - attack.t1218"
  if (has("WIN-010")) return "title: Host Discovery Command Sequence\nstatus: experimental\nlogsource:\n  product: windows\n  category: process_creation\ndetection:\n  selection:\n    Image|endswith:\n      - '\\whoami.exe'\n      - '\\ipconfig.exe'\n      - '\\netstat.exe'\n      - '\\nslookup.exe'\n      - '\\systeminfo.exe'\n      - '\\tasklist.exe'\n    CommandLine|contains:\n      - 'all'\n      - 'ano'\n      - 'group'\n  condition: selection\nfields:\n  - Image\n  - CommandLine\n  - User\n  - Computer\nfalsepositives:\n  - IT troubleshooting\n  - Admin scripts\nlevel: low\ntags:\n  - attack.t1082\n  - attack.t1016\n  - attack.t1049"
  if (has("WIN-011")) return "title: Windows Event Log Or File Deletion\nstatus: experimental\nlogsource:\n  product: windows\n  service: security\ndetection:\n  selection:\n    EventID:\n      - 1102\n      - 104\n    CommandLine|contains:\n      - 'wevtutil cl'\n      - 'fsutil'\n      - 'del'\n      - 'Clear-EventLog'\n  condition: selection\nfields:\n  - SubjectUserName\n  - Computer\n  - CommandLine\nfalsepositives:\n  - Authorized log rotation\nlevel: high\ntags:\n  - attack.t1070.001\n  - attack.t1070.004"
  return "title: Local Detection Candidate\nstatus: experimental\nlogsource:\n  product: unknown\ndetection:\n  selection:\n    message|contains: suspicious\n  condition: selection\nfalsepositives:\n  - Unknown\nlevel: low"
}

function kqlDraft(result) {
  const has = (id) => result.rules.some((rule) => rule.id === id)
  const authQuery = "SigninLogs\n| where ResultType != \"0\"\n| summarize FailureCount = count() by UserPrincipalName, IPAddress = IPAddress\n| where FailureCount >= 5"
  const psQuery = "DeviceProcessEvents\n| where FileName == \"powershell.exe\" and ProcessCommandLine has_any (\"-EncodedCommand\", \"-NoP\", \"-W Hidden\")\n| project Timestamp, DeviceName, AccountName, ProcessCommandLine"
  const cloudQuery = "CloudTrail\n| where EventName in (\"ConsoleLogin\", \"CreateUser\", \"CreateAccessKey\", \"AttachUserPolicy\")\n| project EventTime, EventName, UserIdentityArn, SourceIPAddress, AwsRegion"
  const netQuery = "OutboundNetworkConnections\n| where RemoteIPType == \"External\" and RemotePort != 443\n| summarize Count = count() by DeviceName, RemoteIP, RemotePort"
  const lsassQuery = "DeviceProcessEvents\n| where FileName in (\"procdump64.exe\", \"rundll32.exe\") and ProcessCommandLine contains \"lsass\"\n| project Timestamp, DeviceName, AccountName, ProcessCommandLine"
  const regRunQuery = "DeviceRegistryEvents\n| where RegistryKey contains \"CurrentVersion\\\\Run\"\n| project Timestamp, DeviceName, AccountName, RegistryKey, RegistryValueData"
  const wmiQuery = "DeviceProcessEvents\n| where InitiatingProcessFileName == \"WmiPrvSE.exe\"\n| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine"
  const lolbinQuery = "DeviceProcessEvents\n| where FileName in (\"rundll32.exe\", \"mshta.exe\", \"regsvr32.exe\", \"cscript.exe\") and ProcessCommandLine contains \"http\"\n| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine"
  if (has("WIN-001")) return psQuery
  if (has("AUTH-001") || has("AUTH-002")) return authQuery + "\n\n// Or for failed logins:\n" + "SecurityEvent\n| where EventID == 4625\n| summarize FailureCount = count() by Account, IpAddress\n| where FailureCount >= 3"
  if (has("CLOUD-001") || has("CLOUD-002")) return cloudQuery
  if (has("NET-001") || has("NET-002")) return netQuery
  if (has("WIN-006")) return lsassQuery
  if (has("WIN-007")) return regRunQuery
  if (has("WIN-008")) return wmiQuery
  if (has("WIN-009")) return lolbinQuery
  return "// No KQL draft generated. Add matched evidence first."
}

function splDraft(result) {
  const has = (id) => result.rules.some((rule) => rule.id === id)
  const authSpl = `index=auth sourcetype=linux_secure "Failed password"\n| stats count by src_ip, user\n| where count >= 3`
  const psSpl = `index=windows source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1\n| search Image=*\\\\powershell.exe CommandLine=*-EncodedCommand* OR CommandLine=*-NoP* OR CommandLine=*-W Hidden*\n| table _time, Computer, User, CommandLine`
  const cloudSpl = `index=cloud sourcetype=aws:cloudtrail\n| search EventName IN ("ConsoleLogin","CreateUser","CreateAccessKey","AttachUserPolicy")\n| table _time, userIdentity.arn, eventName, sourceIPAddress, awsRegion`
  const netSpl = `index=network sourcetype=stream:dns\n| search query=*.xyz OR query=*.top OR query=*.ru\n| stats count by src_ip, query\n| where count > 1`
  const lsassSpl = `index=windows source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=10 TargetImage=*\\\\lsass.exe\n| search GrantedAccess=0x1FFFFF\n| table _time, Computer, User, Image, TargetImage, GrantedAccess`
  const regRunSpl = `index=windows source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=13\n| search TargetObject=*\\\\CurrentVersion\\\\Run*\n| table _time, Computer, User, Image, TargetObject, Details`
  const wmiSpl = `index=windows source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1\n| search ParentImage=*\\\\WmiPrvSE.exe\n| table _time, Computer, User, Image, CommandLine, ParentImage`
  if (has("WIN-001")) return psSpl
  if (has("AUTH-001") || has("AUTH-002")) return authSpl
  if (has("CLOUD-001") || has("CLOUD-002")) return cloudSpl
  if (has("NET-001") || has("NET-002")) return netSpl
  if (has("WIN-006")) return lsassSpl
  if (has("WIN-007")) return regRunSpl
  if (has("WIN-008")) return wmiSpl
  return "| No Splunk SPL draft generated. Add matched evidence first."
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
  const has = (id) => result.rules.some((rule) => rule.id === id)
  if (has("WEB-001") || has("WEB-003")) return 'alert http any any -> any any (msg:"BeyondArch suspicious web probing draft"; content:"sqlmap"; nocase; http_user_agent; content:"/etc/passwd"; nocase; http_uri; classtype:web-application-attack; sid:1000001; rev:1;)'
  if (has("NET-001")) return 'alert tcp $HOME_NET any -> $EXTERNAL_NET !443 (msg:"BeyondArch outbound C2 candidate"; flow:to_server; classtype:trojan-activity; sid:1000002; rev:1;)'
  if (has("NET-002")) return 'alert udp any any -> any 53 (msg:"BeyondArch suspicious DNS query candidate"; content:"|00 00 01 00 01|"; distance:1; within:12; classtype:bad-unknown; sid:1000003; rev:1;)'
  if (has("WIN-008")) return 'alert tcp $HOME_NET any -> $HOME_NET 135 (msg:"BeyondArch WMI lateral movement candidate"; flow:to_server; classtype:network-scan; sid:1000004; rev:1;)'
  return "No IDS draft generated. Network/web evidence is required."
}

function detectionReview(result, tests) {
  const issues = []
  const suggestions = []
  const coverage = []
  const sigma = sigmaDraft(result)
  const kql = kqlDraft(result)
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
  check(!kql.startsWith("//"), "No KQL draft generated.", "Review KQL format for Microsoft Sentinel or Azure Defender use.")
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
  const kql = kqlDraft(result)
  const spl = splDraft(result)
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
    "## KQL Draft (Microsoft Sentinel)",
    "```kql",
    kql,
    "```",
    "",
    "## Splunk SPL Draft",
    "```spl",
    spl,
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
  const [narrative, setNarrative] = useState("")

  const sigma = result ? sigmaDraft(result) : ""
  const wazuh = result ? wazuhDraft(result) : ""
  const ids = result ? idsDraft(result) : ""
  const kql = result ? kqlDraft(result) : ""
  const spl = result ? splDraft(result) : ""
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
    setNarrative("")
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
        {result.priority ? (
          <div className="grid gap-4 xl:grid-cols-[1fr_1fr]">
            <WorkbenchPanel className="space-y-3">
              <div className="flex items-center justify-between">
                <p className="text-xs font-black uppercase tracking-[0.14em] text-zinc-400">Priority score</p>
                <span className={`rounded-full px-3 py-1 text-xs font-black ${
                  result.priority.score >= 75 ? "bg-red-500/20 text-red-300" :
                  result.priority.score >= 50 ? "bg-amber-500/20 text-amber-300" :
                  result.priority.score >= 25 ? "bg-yellow-500/20 text-yellow-300" :
                  "bg-emerald-500/20 text-emerald-300"
                }`}>{result.priority.priority.toUpperCase()}</span>
              </div>
              <div className="flex items-end justify-between">
                <span className="text-2xl font-black text-zinc-100">{result.priority.score}<span className="text-base font-bold text-zinc-500">/100</span></span>
                <span className="text-xs text-zinc-500">{Math.round(result.priority.confidence * 100)}% confidence</span>
              </div>
              <div className="h-2.5 overflow-hidden rounded-full bg-black/60">
                <div className="h-full rounded-full transition-all" style={{
                  width: `${result.priority.score}%`,
                  background: result.priority.score >= 75 ? "#ef4444" :
                              result.priority.score >= 50 ? "#f59e0b" :
                              result.priority.score >= 25 ? "#eab308" : "#22c55e",
                }} />
              </div>
              {result.priority.matched_patterns.length > 0 ? (
                <div className="flex flex-wrap gap-1.5">
                  {result.priority.matched_patterns.map((p) => (
                    <span key={p.pattern} className={`rounded-full px-2 py-0.5 text-[0.68rem] font-bold ${
                      p.score >= 20 ? "bg-red-500/15 text-red-300" :
                      p.score >= 15 ? "bg-amber-500/15 text-amber-300" :
                      "bg-zinc-500/15 text-zinc-300"
                    }`}>{p.label} ({p.score})</span>
                  ))}
                </div>
              ) : <p className="text-xs text-zinc-500">No weighted patterns matched</p>}
            </WorkbenchPanel>
            <WorkbenchPanel className="space-y-3">
              <div className="flex items-center justify-between">
                <p className="text-xs font-black uppercase tracking-[0.14em] text-zinc-400">Analyst narrative</p>
                <button className="ba-button-ghost rounded-lg px-2 py-1 text-xs font-bold" onClick={() => setNarrative(narrative ? "" : generateDetectionNarrative(input, result.priority))}>{narrative ? "Clear" : "Generate Narrative"}</button>
              </div>
              {narrative ? (
                <div className="relative">
                  <pre className="max-h-48 overflow-auto whitespace-pre-wrap rounded-xl border border-white/10 bg-black/40 p-3 text-sm leading-6 text-zinc-100">{narrative}</pre>
                  <button className="absolute right-2 top-2 ba-button-ghost rounded-lg px-2 py-1 text-xs font-bold" onClick={() => copy(narrative, "Narrative")}><Clipboard className="inline h-3 w-3" /></button>
                </div>
              ) : <p className="text-sm leading-6 text-zinc-500">Generate a SOC-ready narrative summary of the detection priority, matched patterns, and recommended actions.</p>}
            </WorkbenchPanel>
          </div>
        ) : null}
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
          {result.mitre.length >= 2 ? <details className="rounded-xl border border-white/10 bg-black/40 p-3"><summary className="cursor-pointer text-xs font-black uppercase tracking-[0.14em] text-zinc-400">Technique chain mapping</summary><div className="mt-3 space-y-2">{[...new Set(result.mitre.flatMap((item) => item.tactic.split(" / ")))].map((tactic) => <div key={tactic} className="rounded-lg border border-amber-400/15 bg-amber-400/8 px-3 py-2"><p className="text-xs font-bold text-amber-100">{tactic}</p><div className="mt-1 flex flex-wrap gap-2">{result.mitre.filter((item) => item.tactic.includes(tactic)).map((item) => <span key={item.id} className="rounded-full border border-cyan-400/20 bg-cyan-400/10 px-2 py-0.5 text-[0.68rem] font-bold text-cyan-100">{item.id}</span>)}</div></div>)}</div></details> : null}
        </WorkbenchPanel>
      ) : null}

      {result && tab === "drafts" ? (
        <div className="grid gap-4 xl:grid-cols-[1fr_1fr_1fr]">
          <DraftPanel title="Sigma Draft" value={sigma} ext="yml" onCopy={copy} />
          <DraftPanel title="KQL Draft (Microsoft Sentinel)" value={kql} ext="kql" onCopy={copy} />
          <DraftPanel title="Splunk SPL Draft" value={spl} ext="spl" onCopy={copy} />
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
                <p className="ba-output-section-eyebrow" style={{ color: "var(--clr-accent)" }}>Detection Lab</p>
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
              <DraftPanel title="YARA Rule" value={labResult.yara} ext="yar" onCopy={copy} />
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
