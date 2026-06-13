export function defangText(value = "") {
  return String(value)
    .replace(/https:\/\//gi, "hxxps[:]//")
    .replace(/http:\/\//gi, "hxxp[:]//")
    .replace(/@/g, "[@]")
    .replace(/\./g, "[.]")
}

export function labelize(value = "") {
  return String(value)
    .replace(/_/g, " ")
    .replace(/\b\w/g, (letter) => letter.toUpperCase())
}

function safeCount(items) {
  return Array.isArray(items) ? items.length : 0
}

export function iocCount(result) {
  const iocs = result?.static_result?.extracted_iocs || {}
  return safeCount(iocs.urls) + safeCount(iocs.domains) + safeCount(iocs.ips) + safeCount(iocs.emails)
}

export function buildFindingMarkdown(result) {
  if (!result) return ""
  const staticResult = result.static_result || {}
  const iocs = staticResult.extracted_iocs || {}
  const signals = staticResult.risk_signals || []
  return [
    "### Safe URL Analyzer Finding",
    `Verdict: ${labelize(result.verdict)}`,
    `URL: ${defangText(result.input?.normalized || result.input?.original || "")}`,
    `Host: ${staticResult.host || "N/A"}`,
    `Root domain: ${staticResult.root_domain || "N/A"}`,
    "",
    "Analyst decision:",
    result.analysis?.conclusion || result.summary || "N/A",
    "",
    "Primary concern:",
    result.analysis?.primary_concern || "N/A",
    "",
    "Evidence scope:",
    result.analysis?.mode === "static_plus_safe_fetch" ? "Static URL structure + guarded Safe Fetch metadata" : "Static URL structure only; no network request made",
    "",
    "Key signals:",
    ...((result.analysis?.strongest_evidence || signals).length ? (result.analysis?.strongest_evidence || signals).slice(0, 8).map((signal) => `- ${signal.label}: ${signal.evidence || "observed"}`) : ["- No major local URL signals detected"]),
    "",
    "Extracted indicators:",
    `- URLs: ${(iocs.urls || []).map(defangText).join(", ") || "None"}`,
    `- Domains: ${(iocs.domains || []).join(", ") || "None"}`,
    `- IPs: ${(iocs.ips || []).join(", ") || "None"}`,
    `- Emails: ${(iocs.emails || []).join(", ") || "None"}`,
    "",
    "Recommended actions:",
    `- ${result.analysis?.next_best_action || "Review case context and pivot extracted indicators."}`,
    ...((result.recommended_actions || []).slice(0, 5).map((action) => `- ${action}`)),
    "",
    "Limitations:",
    ...((result.analysis?.missing_evidence || result.limitations || []).slice(0, 5).map((item) => `- ${item}`)),
  ].join("\n")
}
