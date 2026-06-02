export const KNOWLEDGE_BASE = [
  {
    id: "phishing-triage",
    category: "Phishing",
    title: "Phishing email triage checklist",
    summary: "Review sender alignment, authentication, URLs, attachments, language, and user impact before deciding.",
    tags: ["email", "triage", "spf", "dkim", "dmarc"],
    steps: [
      "Check From, Reply-To, Return-Path, and Message-ID domains for mismatch.",
      "Review SPF, DKIM, and DMARC results, but do not treat pass/fail as a complete verdict.",
      "Extract URLs and compare visible text, href destination, redirects, and final domain.",
      "Look for credential-theft language, urgency, invoice/payment lures, and attachment pressure.",
      "Record evidence and limitations in the case timeline/report.",
    ],
    pivots: ["Safe URL Analyzer", "Recon & Exposure", "Case Timeline", "Report Builder"],
  },
  {
    id: "url-analysis",
    category: "URLs & Domains",
    title: "Safe URL analysis workflow",
    summary: "Analyze structure first, then optional guarded metadata only when scope allows.",
    tags: ["url", "redirect", "defang", "domain"],
    steps: [
      "Refang only inside the tool and keep report output defanged.",
      "Check scheme, host, root domain, path, query parameters, and encoded blobs.",
      "Review redirect count, status chain, content type, headers, and TLS context if metadata mode is allowed.",
      "Pivot domains/IPs into DNS, proxy, firewall, and endpoint logs.",
      "Use third-party reputation only when privacy/scope permits.",
    ],
    pivots: ["Safe URL Analyzer", "Recon & Exposure", "Logs & Alerts"],
  },
  {
    id: "auth-logs",
    category: "Logs",
    title: "Authentication log investigation",
    summary: "Failed and successful logons become meaningful when correlated by source, account, host, and time.",
    tags: ["auth", "4624", "4625", "sshd", "vpn"],
    steps: [
      "Group failed logins by user, source IP, and time window.",
      "Look for success after failures, privileged accounts, impossible travel, or unusual hosts.",
      "Check MFA, VPN, EDR, and endpoint process activity around the same time.",
      "Document whether the pattern is spray, brute force, user error, or expected admin behavior.",
    ],
    pivots: ["Logs & Alerts", "SIEM Workspace", "Timeline"],
  },
  {
    id: "web-logs",
    category: "Logs",
    title: "Web access log review",
    summary: "Focus on method, path, status, user agent, source, referrer, and repeated paths.",
    tags: ["web", "http", "proxy", "waf"],
    steps: [
      "Identify scanner strings, traversal attempts, SQLi/XSS patterns, and admin-path access.",
      "Compare status codes with volume and response sizes.",
      "Pivot source IP and user agent across nearby requests.",
      "Confirm whether the request reached the app or was blocked upstream.",
    ],
    pivots: ["Query Builder", "SIEM Workspace", "Recon"],
  },
  {
    id: "windows-events",
    category: "Windows",
    title: "Windows Event IDs worth knowing",
    summary: "Common IDs: 4624 success, 4625 failure, 4672 privileged logon, 4688 process creation, 7045 service install, 1102 audit log cleared.",
    tags: ["windows", "sysmon", "eventid"],
    steps: [
      "Treat Event IDs as telemetry, not conclusions.",
      "For 4688/Sysmon 1, review parent process, command line, user, path, and hashes.",
      "For 1102, validate admin maintenance versus anti-forensics.",
      "For 7045, review service path, user, host role, and nearby network activity.",
    ],
    pivots: ["SOC Guide", "Detection & MITRE", "Report"],
  },
  {
    id: "detection-rules",
    category: "Detection",
    title: "Detection rule quality checklist",
    summary: "A useful rule describes behavior, maps evidence, avoids broad false positives, and includes test data.",
    tags: ["sigma", "suricata", "snort", "mitre"],
    steps: [
      "State the behavior and attacker technique you are trying to detect.",
      "Use specific fields and conditions instead of one broad keyword where possible.",
      "Document false positives and required log source.",
      "Test against sample benign and suspicious events before adding to a report.",
      "Map to MITRE only when there is evidence for the technique.",
    ],
    pivots: ["Detection Workspace", "Detection & MITRE", "Logs & Alerts"],
  },
  {
    id: "local-first",
    category: "Privacy",
    title: "Local-first investigation handling",
    summary: "Keep sensitive artifacts local unless the case scope permits external enrichment.",
    tags: ["privacy", "storage", "case"],
    steps: [
      "Use session-only storage by default for sensitive analysis.",
      "Clear local investigation data before switching cases or using shared machines.",
      "Defang URLs in notes and reports.",
      "Export JSON/Markdown only when the output is safe to store outside the browser.",
    ],
    pivots: ["Settings", "Case Timeline", "Report Export"],
  },
]

export function searchKnowledgeBase(query = "", category = "all") {
  const needle = String(query || "").trim().toLowerCase()
  return KNOWLEDGE_BASE.filter((entry) => {
    const matchesCategory = category === "all" || entry.category === category
    const haystack = `${entry.category} ${entry.title} ${entry.summary} ${entry.tags.join(" ")} ${entry.steps.join(" ")}`.toLowerCase()
    return matchesCategory && (!needle || haystack.includes(needle))
  })
}

export const KNOWLEDGE_CATEGORIES = ["all", ...Array.from(new Set(KNOWLEDGE_BASE.map((entry) => entry.category)))]
