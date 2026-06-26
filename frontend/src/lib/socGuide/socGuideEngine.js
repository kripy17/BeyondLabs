const WINDOWS_QUICK_GROUPS = [
  {
    id: "auth",
    label: "Authentication",
    ids: ["4624", "4625", "4634", "4647", "4648", "4672", "4771", "4776", "4778", "4779"],
  },
  {
    id: "process",
    label: "Process / execution",
    ids: ["4688", "4697", "4698", "4702", "7045", "1102"],
  },
  {
    id: "account",
    label: "Account changes",
    ids: ["4720", "4722", "4725", "4726", "4728", "4732", "4738", "4740"],
  },
  {
    id: "object",
    label: "Object / share access",
    ids: ["4656", "4657", "4662", "4663", "5140", "5145", "5156", "5157"],
  },
  {
    id: "sysmon",
    label: "Sysmon core",
    ids: ["sysmon:1", "sysmon:3", "sysmon:7", "sysmon:10", "sysmon:11", "sysmon:13", "sysmon:22"],
  },
]

export const EVENT_QUICK_GROUPS = WINDOWS_QUICK_GROUPS

export const EVENT_MITRE_MAP = {
  "4624": { id: "T1078", name: "Valid Accounts", detail: "Successful logon — review for unusual source, off-hours, or spray-break patterns." },
  "4625": { id: "T1110", name: "Brute Force", detail: "Failed logons indicate password spray or brute-force attempts." },
  "4648": { id: "T1078", name: "Valid Accounts", detail: "Explicit credential use — review for pass-the-hash or lateral movement indicators." },
  "4672": { id: "T1068", name: "Exploitation for Privilege Escalation", detail: "Special privileges assigned to new logon — elevated session context." },
  "4688": { id: "T1059", name: "Command and Scripting Interpreter", detail: "Process creation event — review parent, command line, and user." },
  "4697": { id: "T1543", name: "Create or Modify System Process", detail: "Service creation — persistence or lateral movement vector." },
  "4698": { id: "T1053.005", name: "Scheduled Task/Job", detail: "Scheduled task creation — persistence mechanism." },
  "4702": { id: "T1053.005", name: "Scheduled Task/Job", detail: "Scheduled task updated — persistence modification." },
  "7045": { id: "T1543.003", name: "Windows Service", detail: "New service installed — common lateral movement or persistence target." },
  "1102": { id: "T1070.001", name: "Indicator Removal", detail: "Security audit log cleared — anti-forensics indicator." },
  "4720": { id: "T1136", name: "Create Account", detail: "New user account created — unauthorized or backdoor account." },
  "4722": { id: "T1098", name: "Account Manipulation", detail: "User account enabled — review context and requester." },
  "4725": { id: "T1098", name: "Account Manipulation", detail: "User account disabled — review for offboarding or compromise." },
  "4726": { id: "T1098", name: "Account Manipulation", detail: "User account deleted — review context and timing." },
  "4740": { id: "T1110", name: "Brute Force", detail: "Account lockout — indicates repeated failed authentication attempts." },
  "4771": { id: "T1558", name: "Steal or Forge Kerberos Tickets", detail: "Kerberos pre-authentication failure — ticket-related issue." },
  "4776": { id: "T1110", name: "Brute Force", detail: "Credential validation failure — NTLM authentication attempt." },
  "sysmon:1": { id: "T1059", name: "Command and Scripting Interpreter", detail: "Sysmon process creation — child/parent relationship and command-line context." },
  "sysmon:3": { id: "T1071", name: "Application Layer Protocol", detail: "Sysmon network connection — review destination, process, and port." },
  "sysmon:7": { id: "T1095", name: "Non-Application Layer Protocol", detail: "Sysmon module load — DLL injection or reflective loading indicator." },
  "sysmon:10": { id: "T1055", name: "Process Injection", detail: "Sysmon process access — potential process injection or LSASS dumping." },
  "sysmon:11": { id: "T1027", name: "Obfuscated Files or Information", detail: "Sysmon file creation — payload drop or staged content." },
  "sysmon:13": { id: "T1564", name: "Hide Artifacts", detail: "Sysmon registry modification — persistence via Run key or similar." },
  "sysmon:22": { id: "T1071.004", name: "DNS", detail: "Sysmon DNS query — domain generation algorithm or C2 callback." },
}

export const SPL_OBJECTIVES = [
  {
    id: "windows_event",
    label: "Windows Event ID hunt",
    short: "Find specific EventCode activity and key fields.",
    defaults: {
      index: "main",
      sourcetype: "WinEventLog:Security",
      eventCode: "4688",
      keyword: "",
      field: "host",
      value: "",
      groupBy: "host,user,EventCode",
      tableFields: "_time,host,user,EventCode,New_Process_Name,Creator_Process_Name,CommandLine",
      limit: "100",
      time: "24h",
    },
    notes: [
      "Use this when you remember the Event ID and need a starter hunt quickly.",
      "Tune field names to your Splunk TA or normalized dataset.",
      "For process execution, correlate 4688 with Sysmon EventCode=1 when available.",
    ],
  },
  {
    id: "failed_logons",
    label: "Failed logon / spray review",
    short: "Group authentication failures by source, account, and host.",
    defaults: {
      index: "main",
      sourcetype: "WinEventLog:Security",
      eventCode: "4625",
      keyword: "",
      field: "Source_Network_Address",
      value: "",
      groupBy: "Source_Network_Address,Account_Name,host",
      tableFields: "_time,host,Account_Name,Failure_Reason,Source_Network_Address,Logon_Type",
      limit: "30",
      time: "24h",
    },
    notes: [
      "Differentiate password spraying from one-account brute force by grouping source and account together.",
      "Check for EventCode=4624 success after the failures.",
      "Confirm whether failures are from stale service credentials before escalating.",
    ],
  },
  {
    id: "powershell",
    label: "Suspicious PowerShell",
    short: "Look for encoded commands, bypass flags, and download cradles.",
    defaults: {
      index: "main",
      sourcetype: "WinEventLog:Security OR sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
      eventCode: "4688 OR 1",
      keyword: "powershell OR EncodedCommand OR DownloadString OR IEX",
      field: "process_name",
      value: "powershell.exe",
      groupBy: "host,user,parent_process",
      tableFields: "_time,host,user,parent_process,process_name,CommandLine,DestinationIp,QueryName",
      limit: "100",
      time: "24h",
    },
    notes: [
      "Office spawning PowerShell, hidden windows, and policy bypass flags are strong triage leads.",
      "Decode EncodedCommand before deciding severity.",
      "Pivot to DNS and network events if a download or callback is visible.",
    ],
  },
  {
    id: "service_persistence",
    label: "Service / scheduled task persistence",
    short: "Review new services and task creation/update activity.",
    defaults: {
      index: "main",
      sourcetype: "WinEventLog:Security OR WinEventLog:System",
      eventCode: "4697 OR 4698 OR 4702 OR 7045",
      keyword: "",
      field: "host",
      value: "",
      groupBy: "host,user,EventCode",
      tableFields: "_time,host,user,EventCode,Service_Name,Service_File_Name,Task_Name,CommandLine",
      limit: "100",
      time: "7d",
    },
    notes: [
      "Review binary paths, arguments, and account context.",
      "Check whether creation time aligns with an approved install or change window.",
      "Follow the creating process and prior logon events on the same host.",
    ],
  },
  {
    id: "network_ioc",
    label: "Network IOC pivot",
    short: "Search IP/domain/URL indicators across proxy, DNS, firewall, and Sysmon.",
    defaults: {
      index: "main",
      sourcetype: "proxy OR dns OR firewall OR sysmon",
      eventCode: "",
      keyword: "",
      field: "dest_ip OR DestinationIp OR query OR url",
      value: "",
      groupBy: "src_ip,dest_ip,url,query,host",
      tableFields: "_time,host,src_ip,dest_ip,DestinationIp,query,url,user,process_name",
      limit: "100",
      time: "24h",
    },
    notes: [
      "Start with the exact IOC, then broaden to domain, host, or subnet as needed.",
      "For Sysmon, correlate EventCode=3 network connections with EventCode=22 DNS queries.",
      "A hit is not automatically malicious; confirm context and user/process behavior.",
    ],
  },
  {
    id: "dns_anomalies",
    label: "DNS anomaly / C2 beacon",
    short: "Find suspicious DNS queries, high query volumes, and rare domains.",
    defaults: {
      index: "main",
      sourcetype: "dns OR sysmon",
      eventCode: "22",
      keyword: "",
      field: "query",
      value: "",
      groupBy: "query,src_ip,host",
      tableFields: "_time,host,src_ip,query,QueryStatus,DestinationIp,process_name",
      limit: "50",
      time: "24h",
    },
    notes: [
      "Focus on NXDOMAIN spikes, long subdomains, DGA-like patterns, and rare TLDs.",
      "Correlate with process execution and network connections on the same host.",
      "DGA detection: check entropy, consonant/vowel ratio, and registration age if possible.",
    ],
  },
  {
    id: "cloudtrail",
    label: "CloudTrail / cloud IAM audit",
    short: "Review AWS CloudTrail for console logins, IAM changes, and privilege escalation.",
    defaults: {
      index: "main",
      sourcetype: "cloudtrail OR aws:cloudtrail",
      eventCode: "",
      keyword: "",
      field: "userIdentity.arn OR eventName OR sourceIPAddress",
      value: "",
      groupBy: "userIdentity.arn,eventName,sourceIPAddress",
      tableFields: "_time,userIdentity.arn,eventName,sourceIPAddress,awsRegion,userAgent,errorCode",
      limit: "100",
      time: "7d",
    },
    notes: [
      "ConsoleLogin from unexpected regions, new IAM user creation, and policy changes are priority alerts.",
      "Check for PassRole or CreatePolicyVersion before escalation chains.",
      "Disable logging or delete log group events require immediate triage.",
    ],
  },
  {
    id: "lateral_movement",
    label: "Lateral movement / remote access",
    short: "Hunt for RDP, WinRM, PsExec, SMB, and remote service creation.",
    defaults: {
      index: "main",
      sourcetype: "WinEventLog:Security OR WinEventLog:System OR sysmon",
      eventCode: "4624 OR 4648 OR 5140 OR 5145 OR 7045 OR 3",
      keyword: "rdp|winrm|psexec|admin$|IPC$|3389",
      field: "Source_Network_Address OR Target_Logon_Id OR Relative_Target_Name",
      value: "",
      groupBy: "Source_Network_Address,Account_Name,host",
      tableFields: "_time,host,Account_Name,Source_Network_Address,Logon_Type,Process_Name,Relative_Target_Name",
      limit: "100",
      time: "24h",
    },
    notes: [
      "Logon Type 3 (network), 10 (remote), and 7 (unlock) combined with service creation indicate lateral movement.",
      "Correlate 4624 + 7045 on the same host within minutes.",
      "RDP inbound from non-admin jump boxes or external IPs is suspicious.",
    ],
  },
  {
    id: "auth_anomalies",
    label: "Auth anomalies / impossible travel",
    short: "Detect logon pattern anomalies, off-hours access, and unusual source geography.",
    defaults: {
      index: "main",
      sourcetype: "WinEventLog:Security OR azure:signin OR cloudtrail",
      eventCode: "4624 OR 4625",
      keyword: "",
      field: "Account_Name OR Source_Network_Address",
      value: "",
      groupBy: "Account_Name,Source_Network_Address,Logon_Type",
      tableFields: "_time,host,Account_Name,Source_Network_Address,Logon_Type,Process_Name,Target_Domain",
      limit: "100",
      time: "24h",
    },
    notes: [
      "Group by account + source IP to find spray and brute-force patterns.",
      "Off-hours logins for normally 9-5 accounts warrant additional context.",
      "Check for success after repeated failures (the spray-break pattern).",
    ],
  },
]

const POWER_SHELL_TOKENS = [
  { match: /-enc\b|-encodedcommand\b/i, label: "EncodedCommand", severity: "medium", meaning: "Command content is base64-encoded, commonly used for obfuscation or compact execution.", mitre: "T1027" },
  { match: /iex\b|invoke-expression/i, label: "Invoke-Expression", severity: "high", meaning: "Executes a string as code. Often used in download cradle patterns.", mitre: "T1059.001" },
  { match: /downloadstring|downloadfile|invoke-webrequest|iwr\b|curl\b|wget\b/i, label: "Network download", severity: "medium", meaning: "Attempts to retrieve remote content or a payload.", mitre: "T1105" },
  { match: /executionpolicy\s+bypass|-ep\s+bypass/i, label: "Execution policy bypass", severity: "medium", meaning: "Attempts to bypass local PowerShell script execution controls.", mitre: "T1562.001" },
  { match: /windowstyle\s+hidden|-w\s+hidden/i, label: "Hidden window", severity: "medium", meaning: "Tries to reduce user visibility during execution.", mitre: "T1564.003" },
  { match: /frombase64string/i, label: "Base64 decoding", severity: "medium", meaning: "Decodes embedded base64 content inside the command.", mitre: "T1027" },
  { match: /new-object\s+net\.webclient|system\.net\.webclient/i, label: "WebClient object", severity: "medium", meaning: "Creates a .NET web client used to download remote content.", mitre: "T1105" },
  { match: /add-mpypreference|set-mppreference|disable-realtime/i, label: "Defender tamper", severity: "high", meaning: "Attempts to disable or modify Windows Defender real-time protection.", mitre: "T1562.001" },
  { match: /bypass.*amsi|amsiutils|amsi.*scanbuff/i, label: "AMSI bypass", severity: "critical", meaning: "Attempts to bypass the Anti-Malware Scan Interface (AMSI).", mitre: "T1562.001" },
  { match: /invoke-mimikatz|invoke-thehash|out-minidump/i, label: "Credential dumping", severity: "critical", meaning: "Credential dumping or LSASS manipulation.", mitre: "T1003.001" },
  { match: /send-keys|mouse_move|get-keystrokes|start-keylogger/i, label: "Keylogger", severity: "critical", meaning: "Keystroke logging or user interaction capture.", mitre: "T1056.001" },
  { match: /start-process.*-credential|invoke-command.*-computername|enter-pssession/i, label: "Remote execution", severity: "high", meaning: "Runs commands or processes on remote systems.", mitre: "T1021.006" },
  { match: /get-wmiobject|invoke-wmimethod|gwmi\b/i, label: "WMI usage", severity: "medium", meaning: "WMI query or execution — can indicate reconnaissance or lateral movement.", mitre: "T1047" },
  { match: /register-scheduledjob|new-jobtrigger/i, label: "Scheduled job creation", severity: "high", meaning: "Creates a scheduled job via PowerShell.", mitre: "T1053.005" },
  { match: /set-itemproperty.*run|new-itemproperty.*run/i, label: "Registry Run key", severity: "high", meaning: "Adds a persistence Run key via the registry.", mitre: "T1547.001" },
]

const WINDOWS_CMD_TOKENS = [
  { match: /certutil/i, label: "certutil", severity: "medium", meaning: "Certificate utility that can also download or decode files.", mitre: "T1105" },
  { match: /bitsadmin/i, label: "bitsadmin", severity: "medium", meaning: "Background transfer utility sometimes abused for payload download.", mitre: "T1105" },
  { match: /schtasks/i, label: "schtasks", severity: "medium", meaning: "Creates or modifies scheduled tasks, often relevant for persistence.", mitre: "T1053.005" },
  { match: /reg\s+(add|delete|query)/i, label: "registry command", severity: "medium", meaning: "Reads or modifies registry keys. Check autoruns and security settings.", mitre: "T1012" },
  { match: /net\s+user|net\s+localgroup/i, label: "account/group command", severity: "medium", meaning: "Changes or enumerates local users or groups.", mitre: "T1087.001" },
  { match: /wmic\b/i, label: "wmic", severity: "medium", meaning: "WMI command-line usage. Can indicate admin activity or lateral movement.", mitre: "T1047" },
  { match: /rundll32|regsvr32|mshta|wscript|cscript/i, label: "LOLBas execution", severity: "medium", meaning: "Windows living-off-the-land binary execution path.", mitre: "T1218" },
  { match: /powershell.*-ex\s+bypass|powershell.*-w\s+hidden|pwsh\.exe/i, label: "PowerShell launcher", severity: "medium", meaning: "Launches PowerShell with bypass or hidden flags from CMD.", mitre: "T1059.001" },
  { match: /msbuild|installutil|csc\.exe|regini|pcalua|cmstp|msiexec|hh\.exe|forfiles/i, label: "LOLBin (extended)", severity: "medium", meaning: "Windows executable that can be abused for code execution or bypass.", mitre: "T1218" },
  { match: /net\s+(share|view|use)/i, label: "share command", severity: "medium", meaning: "Enumerates or mounts network shares — lateral movement or data access.", mitre: "T1135" },
  { match: /icacls|cacls/i, label: "permission change", severity: "medium", meaning: "Modifies file or directory permissions.", mitre: "T1222" },
  { match: /wevtutil.*cl|wevtutil.*clear/i, label: "log clear", severity: "high", meaning: "Clears Windows event logs — anti-forensics indicator.", mitre: "T1070.001" },
  { match: /vssadmin.*delete|wmic.*shadowcopy/i, label: "shadow copy deletion", severity: "high", meaning: "Deletes volume shadow copies — ransomware or anti-forensics.", mitre: "T1490" },
  { match: /bcdedit.*delete|bcdedit.*ignore/i, label: "boot config change", severity: "high", meaning: "Modifies boot configuration — disable recovery or safe mode.", mitre: "T1490" },
]

const UNIX_TOKENS = [
  { match: /\bsudo\b/i, label: "sudo", severity: "info", meaning: "Runs a command with elevated privileges.", mitre: "T1548" },
  { match: /\bchmod\s+\+x|\bchmod\s+777/i, label: "chmod permission change", severity: "medium", meaning: "Changes file permissions; +x or 777 can enable execution or broad access.", mitre: "T1222" },
  { match: /\bcurl\b|\bwget\b/i, label: "download command", severity: "medium", meaning: "Retrieves remote content. Check destination URL and follow-on execution.", mitre: "T1105" },
  { match: /\bbash\s+-c|\bsh\s+-c/i, label: "shell execution", severity: "medium", meaning: "Executes a string through a shell.", mitre: "T1059.004" },
  { match: /\bnc\b|\bnetcat\b|\/dev\/tcp/i, label: "network shell utility", severity: "high", meaning: "Can be used for network testing, data transfer, or reverse shell behavior.", mitre: "T1572" },
  { match: /\bcrontab\b|\/etc\/cron/i, label: "cron persistence", severity: "medium", meaning: "Reads or modifies scheduled jobs.", mitre: "T1053.003" },
  { match: /\bbase64\s+-d|\bxxd\b|\bopenssl\b/i, label: "decode/transform", severity: "info", meaning: "Transforms encoded data. Useful for scripts, payloads, or secrets.", mitre: "T1027" },
  { match: /\bpython3?\s+-c|\bperl\s+-e|\bruby\s+-e/i, label: "inline script execution", severity: "medium", meaning: "Runs inline script code in an interpreter.", mitre: "T1059.006" },
  { match: /\bscp\b|\brsync\b|\bsftp\b/i, label: "file transfer", severity: "medium", meaning: "Copies files over SSH — data exfiltration or tool staging.", mitre: "T1048" },
  { match: /\bssh\s+-R|\bssh\s+-L|\bssh\s+-D/i, label: "SSH tunnel", severity: "high", meaning: "Creates an SSH tunnel for port forwarding or proxying.", mitre: "T1572" },
  { match: /\bjournalctl.*--vacuum|rm\s+-f\s+\/var\/log/i, label: "log deletion", severity: "high", meaning: "Removes or truncates system logs — anti-forensics.", mitre: "T1070.002" },
  { match: /\bdmesg.*-c|echo\s+>.*\/dev\/kmsg/i, label: "kernel log clear", severity: "medium", meaning: "Clears kernel ring buffer messages.", mitre: "T1070.002" },
  { match: /\buseradd\b|\badduser\b|\bgroupadd\b/i, label: "user/group creation", severity: "medium", meaning: "Creates a new system user or group — potential backdoor account.", mitre: "T1136" },
  { match: /\busermod\s+-aG\s+sudo|\bgpasswd/i, label: "privilege escalation", severity: "high", meaning: "Modifies user group membership or password — privilege escalation.", mitre: "T1098" },
  { match: /\bsshd\s+-o\s+PermitRootLogin/i, label: "SSH root access", severity: "high", meaning: "Configures SSH to allow root login — persistence or backdoor.", mitre: "T1098" },
]

const URL_RE = /https?:\/\/[^\s'"<>]+/gi
const IP_RE = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g
const HASH_RE = /\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b/g

export function buildSplQuery(config) {
  const filters = []
  const index = config.index?.trim() ? `index=${config.index.trim()}` : ""
  const sourcetype = config.sourcetype?.trim() ? `sourcetype=${wrapIfNeeded(config.sourcetype.trim())}` : ""
  const eventCode = config.eventCode?.trim() ? eventCodeFilter(config.eventCode.trim()) : ""
  const keyword = config.keyword?.trim() ? `(${config.keyword.trim()})` : ""
  const fieldValue = config.field?.trim() && config.value?.trim() ? fieldFilter(config.field.trim(), config.value.trim()) : ""
  filters.push(index, sourcetype, eventCode, keyword, fieldValue)
  const search = filters.filter(Boolean).join(" ").trim() || "search *"
  const tableFields = config.tableFields?.trim() || "_time,host,user,EventCode,message"
  const limit = Number.parseInt(config.limit, 10) || 100
  const groupBy = config.groupBy?.trim()
  const parts = [search]
  if (groupBy) {
    parts.push(`stats count by ${groupBy}`)
    parts.push("sort -count")
    parts.push(`head ${limit}`)
  } else {
    parts.push(`table ${tableFields}`)
    parts.push(`head ${limit}`)
  }
  return parts.join(" | ")
}

export function explainSplQuery(query) {
  const parts = String(query || "").split("|").map((part) => part.trim()).filter(Boolean)
  if (!parts.length) return []
  return parts.map((part, index) => {
    const lower = part.toLowerCase()
    if (index === 0) return { title: "Base search", detail: "Defines the index, sourcetype, EventCode, keyword, or field filters used to retrieve candidate events." }
    if (lower.startsWith("stats")) return { title: "Aggregation", detail: "Groups matching events so repeated sources, users, hosts, or techniques stand out." }
    if (lower.startsWith("sort")) return { title: "Sorting", detail: "Ranks the result set, usually by highest count or newest activity." }
    if (lower.startsWith("head") || lower.startsWith("limit")) return { title: "Result cap", detail: "Limits the visible result set so the query remains readable during triage." }
    if (lower.startsWith("table")) return { title: "Output fields", detail: "Keeps the fields that are most useful for analyst review." }
    if (lower.startsWith("where")) return { title: "Condition", detail: "Adds a conditional filter after events are retrieved." }
    return { title: `Pipeline step ${index + 1}`, detail: "Custom SPL step. Review field names against your local dataset before relying on results." }
  })
}

export function analyzeCommandLocally(command) {
  const text = String(command || "").trim()
  const lowered = text.toLowerCase()
  const shell = detectShell(text)
  const tokenSource = shell === "PowerShell" ? POWER_SHELL_TOKENS : shell === "Windows CMD" ? WINDOWS_CMD_TOKENS : UNIX_TOKENS
  const observations = tokenSource.filter((item) => item.match.test(text)).map((item) => ({
    label: item.label,
    severity: item.severity,
    detail: item.meaning,
    mitre: item.mitre,
  }))

  const urls = unique(text.match(URL_RE) || [])
  const ips = unique(text.match(IP_RE) || []).filter(isReasonableIp)
  const hashes = unique(text.match(HASH_RE) || [])
  const decoded = extractPowershellEncoded(text)
  if (decoded) {
    observations.push({ label: "Decoded PowerShell content", severity: "medium", detail: "An encoded command was decoded locally for safer review.", mitre: "T1027" })
  }

  const summary = summarizeCommand(shell, lowered, observations, urls, ips)
  return {
    shell,
    summary,
    observations,
    decoded,
    artifacts: { urls, ips, hashes },
    nextSteps: buildCommandNextSteps(shell, observations, urls, ips, hashes),
  }
}

function detectShell(text) {
  const lower = text.toLowerCase()
  if (lower.includes("powershell") || lower.includes("pwsh") || /\b(get-|set-|new-|invoke-|start-|stop-)/i.test(text) || /-enc\b|-encodedcommand\b/i.test(text)) return "PowerShell"
  if (lower.includes("cmd.exe") || /\b(certutil|bitsadmin|schtasks|reg\s+add|net\s+user|wmic|rundll32|regsvr32|mshta)\b/i.test(text)) return "Windows CMD"
  if (/\b(sudo|bash|sh|curl|wget|chmod|crontab|grep|awk|sed|nc|python3?)\b/i.test(text)) return "Linux / shell"
  return "Unknown shell"
}

function summarizeCommand(shell, lowered, observations, urls, ips) {
  if (!lowered) return "Paste a command to generate a rough analyst explanation."
  if (observations.some((item) => item.severity === "high")) return `${shell} command with high-interest execution or network behavior. Review before running anywhere.`
  if (urls.length || ips.length) return `${shell} command with network indicators. Check destination context and follow-on execution.`
  if (observations.length) return `${shell} command with ${observations.length} notable behavior marker${observations.length === 1 ? "" : "s"}.`
  return `${shell} command. No obvious suspicious token was identified by the local rough explainer.`
}

function buildCommandNextSteps(shell, observations, urls, ips, hashes) {
  const steps = ["Do not execute unknown commands during triage.", "Confirm where the command was observed: endpoint log, email, script, shell history, or alert."]
  if (shell === "PowerShell") steps.push("Decode EncodedCommand content and inspect parent process, user, host, and network follow-on.")
  if (urls.length || ips.length) steps.push("Pivot URL/IP/domain indicators to Safe URL Analyzer or Recon & Exposure.")
  if (hashes.length) steps.push("Send hashes to Attachment Triage or IOC review.")
  if (observations.some((item) => item.label.toLowerCase().includes("scheduled") || item.label.toLowerCase().includes("cron"))) steps.push("Check persistence locations and creation time against expected admin activity.")
  return steps
}

function extractPowershellEncoded(text) {
  const match = text.match(/-(?:enc|encodedcommand|e)\s+([A-Za-z0-9+/=]+)/i)
  if (!match) return ""
  try {
    const binary = window.atob(match[1])
    const utf16 = binaryToUtf16(binary)
    const utf8 = decodeURIComponent(binary.split("").map((char) => `%${char.charCodeAt(0).toString(16).padStart(2, "0")}`).join(""))
    return utf16.split(String.fromCharCode(0)).join("").trim().length >= utf8.trim().length ? utf16 : utf8
  } catch {
    return ""
  }
}

function binaryToUtf16(binary) {
  let output = ""
  for (let index = 0; index < binary.length; index += 2) {
    output += String.fromCharCode(binary.charCodeAt(index) | ((binary.charCodeAt(index + 1) || 0) << 8))
  }
  return output
}

function eventCodeFilter(value) {
  if (/\s+OR\s+/i.test(value)) return `EventCode IN (${value.split(/\s+OR\s+/i).map((item) => item.trim()).filter(Boolean).join(",")})`
  if (value.includes(",")) return `EventCode IN (${value.split(",").map((item) => item.trim()).filter(Boolean).join(",")})`
  return `EventCode=${value}`
}

function fieldFilter(field, value) {
  if (field.includes(" OR ")) {
    return `(${field.split(/\s+OR\s+/i).map((part) => `${part.trim()}=${quoteValue(value)}`).join(" OR ")})`
  }
  return `${field}=${quoteValue(value)}`
}

function quoteValue(value) {
  if (/^[\w.*:-]+$/.test(value)) return value
  return `"${value.replace(/"/g, '\\"')}"`
}

function wrapIfNeeded(value) {
  return value.includes(" OR ") ? `(${value})` : value
}

function unique(items) {
  return [...new Set(items.map((item) => item.replace(/[),.;]+$/g, "")))]
}

function isReasonableIp(ip) {
  return ip.split(".").every((part) => Number(part) >= 0 && Number(part) <= 255)
}
