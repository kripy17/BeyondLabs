const URL_SHORTENERS = new Set([
  "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly", "rebrand.ly", "shorturl.at", "s.id", "lnkd.in", "rb.gy",
])

const SUSPICIOUS_TLDS = new Set(["zip", "mov", "top", "xyz", "tk", "gq", "cf", "ml", "quest", "click", "rest", "support", "cam", "country"])
const PAYLOAD_EXTENSIONS = new Set(["exe", "scr", "js", "jse", "vbs", "vbe", "jar", "iso", "img", "lnk", "hta", "ps1", "bat", "cmd", "msi", "apk"])
const SUSPICIOUS_EXTENSIONS = new Set([...PAYLOAD_EXTENSIONS, "zip", "rar", "7z", "docm", "xlsm", "pptm", "html", "htm"])

const PHISHING_RISK_WEIGHTS = {
  authFail: { weight: 25, label: "Authentication failure (SPF/DKIM/DMARC)" },
  brandImpersonation: { weight: 20, label: "Brand impersonation detected" },
  urgencyCta: { weight: 15, label: "Urgency or pressure tactic" },
  credentialRequest: { weight: 15, label: "Credential harvesting language" },
  suspiciousTld: { weight: 10, label: "Suspicious sender domain TLD" },
  zeroWidthChars: { weight: 10, label: "Zero-width character obfuscation" },
  suspiciousAttachment: { weight: 10, label: "Suspicious attachment type" },
  urlShortener: { weight: 8, label: "URL shortener used" },
  domainMismatch: { weight: 8, label: "Reply-To domain mismatch" },
  payloadExtension: { weight: 8, label: "Payload file extension in URL" },
  formHijack: { weight: 12, label: "Form submits to external domain" },
  trackingPixel: { weight: 5, label: "Tracking pixel present" },
}

function computeRiskScore(result) {
  const breakdown = []
  let score = 0

  const auth = result.headers?.authentication || {}
  const authFails = [auth.spf, auth.dkim, auth.dmarc].filter((v) => ["fail", "softfail"].includes(v)).length
  const authMissing = [auth.spf, auth.dkim, auth.dmarc].filter((v) => ["none", "missing", "neutral"].includes(v)).length
  if (authFails > 0) {
    const pct = Math.min(1, authFails / 3)
    const points = Math.round(PHISHING_RISK_WEIGHTS.authFail.weight * pct)
    score += points
    breakdown.push({ factor: "authFail", score: points, label: PHISHING_RISK_WEIGHTS.authFail.label })
  } else if (authMissing > 0) {
    const points = Math.round(PHISHING_RISK_WEIGHTS.authFail.weight * 0.4)
    score += points
    breakdown.push({ factor: "authFail", score: points, label: `${PHISHING_RISK_WEIGHTS.authFail.label} (missing data)` })
  }

  const brands = result.body?.mentioned_brands || []
  const brandFindings = (result.findings || []).filter((f) => f.category === "brand_impersonation" || /brand/i.test(f.name))
  if (brands.length > 0 || brandFindings.length > 0) {
    const points = PHISHING_RISK_WEIGHTS.brandImpersonation.weight
    score += points
    breakdown.push({ factor: "brandImpersonation", score: points, label: PHISHING_RISK_WEIGHTS.brandImpersonation.label })
  }

  const themes = result.body?.themes || []
  const urgencyThemes = themes.filter((t) => /urgent|immediate|action required|deadline|suspended|limited|expir|warning|alert|unauthorized/i.test(t.theme || t))
  if (urgencyThemes.length > 0) {
    const points = Math.min(PHISHING_RISK_WEIGHTS.urgencyCta.weight, Math.round(PHISHING_RISK_WEIGHTS.urgencyCta.weight * (0.5 + urgencyThemes.length * 0.15)))
    score += points
    breakdown.push({ factor: "urgencyCta", score: points, label: PHISHING_RISK_WEIGHTS.urgencyCta.label })
  }

  const credentialThemes = themes.filter((t) => /credential|password|login|sign.?in|verify|account|unusual.?sign|security.?question/i.test(t.theme || t))
  if (credentialThemes.length > 0 || (result.findings || []).some((f) => /credential|password|login/i.test(f.name))) {
    const points = PHISHING_RISK_WEIGHTS.credentialRequest.weight
    score += points
    breakdown.push({ factor: "credentialRequest", score: points, label: PHISHING_RISK_WEIGHTS.credentialRequest.label })
  }

  const urls = result.urls || []
  const suspiciousTldUrls = urls.filter((u) => SUSPICIOUS_TLDS.has((u.host || "").split(".").pop()))
  if (suspiciousTldUrls.length > 0) {
    const points = Math.round(PHISHING_RISK_WEIGHTS.suspiciousTld.weight * Math.min(1, suspiciousTldUrls.length * 0.4))
    score += points
    breakdown.push({ factor: "suspiciousTld", score: points, label: PHISHING_RISK_WEIGHTS.suspiciousTld.label })
  }

  if (result.body?.has_zero_width) {
    score += PHISHING_RISK_WEIGHTS.zeroWidthChars.weight
    breakdown.push({ factor: "zeroWidthChars", score: PHISHING_RISK_WEIGHTS.zeroWidthChars.weight, label: PHISHING_RISK_WEIGHTS.zeroWidthChars.label })
  }

  const attachments = result.attachments || []
  const suspiciousAttachments = attachments.filter((a) => a.signals && a.signals.length > 0)
  if (suspiciousAttachments.length > 0) {
    const points = Math.min(PHISHING_RISK_WEIGHTS.suspiciousAttachment.weight, Math.round(suspiciousAttachments.length * PHISHING_RISK_WEIGHTS.suspiciousAttachment.weight * 0.6))
    score += points
    breakdown.push({ factor: "suspiciousAttachment", score: points, label: PHISHING_RISK_WEIGHTS.suspiciousAttachment.label })
  }

  const shortenerUrls = urls.filter((u) => URL_SHORTENERS.has(u.host))
  if (shortenerUrls.length > 0) {
    const points = Math.round(PHISHING_RISK_WEIGHTS.urlShortener.weight * Math.min(1, shortenerUrls.length * 0.4))
    score += points
    breakdown.push({ factor: "urlShortener", score: points, label: PHISHING_RISK_WEIGHTS.urlShortener.label })
  }

  const mismatches = result.sender_alignment?.mismatches || []
  if (mismatches.length > 0) {
    score += PHISHING_RISK_WEIGHTS.domainMismatch.weight
    breakdown.push({ factor: "domainMismatch", score: PHISHING_RISK_WEIGHTS.domainMismatch.weight, label: PHISHING_RISK_WEIGHTS.domainMismatch.label })
  }

  const payloadUrls = urls.filter((u) => PAYLOAD_EXTENSIONS.has((u.path || "").split(".").pop()))
  if (payloadUrls.length > 0) {
    const points = Math.round(PHISHING_RISK_WEIGHTS.payloadExtension.weight * Math.min(1, payloadUrls.length * 0.5))
    score += points
    breakdown.push({ factor: "payloadExtension", score: points, label: PHISHING_RISK_WEIGHTS.payloadExtension.label })
  }

  const forms = result.body?.forms || []
  const externalForms = forms.filter((f) => f.action_domain && f.action_domain !== "(same page)" && f.has_submit)
  if (externalForms.length > 0) {
    const points = Math.min(PHISHING_RISK_WEIGHTS.formHijack.weight, Math.round(PHISHING_RISK_WEIGHTS.formHijack.weight * (0.5 + externalForms.length * 0.2)))
    score += points
    breakdown.push({ factor: "formHijack", score: points, label: PHISHING_RISK_WEIGHTS.formHijack.label })
  }

  const pixels = result.body?.tracking_pixels || []
  if (pixels.length > 0) {
    const points = Math.min(PHISHING_RISK_WEIGHTS.trackingPixel.weight, Math.round(pixels.length * 2))
    score += points
    breakdown.push({ factor: "trackingPixel", score: points, label: PHISHING_RISK_WEIGHTS.trackingPixel.label })
  }

  score = Math.min(100, score)

  const level = score >= 80 ? "critical" : score >= 55 ? "high" : score >= 30 ? "medium" : "low"

  const signalCount = breakdown.length
  const confidence = signalCount >= 5 ? "high" : signalCount >= 3 ? "medium" : "low"

  return { score, level, breakdown, confidence }
}

function generateProfessionalReport(result) {
  const riskScore = result.risk?.score ?? 0
  const riskLevel = result.risk?.level ?? "low"
  const breakdown = result.risk?.breakdown ?? []
  const confidence = result.risk?.confidence ?? "low"
  const topEv = result.risk?.top_evidence || []
  const findings = result.findings || []

  const outcome = riskScore >= 80 ? "Suspicious" : riskScore >= 30 ? "Requires Further Investigation" : "Benign"

  const keySignals = (breakdown.length > 0 ? breakdown : topEv.slice(0, 5)).map((item) => ({
    signal: item.label || item.name || item.factor,
    severity: item.score >= 15 ? "High" : item.score >= 8 ? "Medium" : "Low",
  }))

  const highCount = keySignals.filter((s) => s.severity === "High").length
  const mediumCount = keySignals.filter((s) => s.severity === "Medium").length
  const totalCount = findings.length

  let summary
  if (outcome === "Suspicious") {
    summary = `The analyzed artifact exhibits ${highCount} high-severity signal(s) among ${totalCount} total findings, with a weighted risk score of ${riskScore}/100 (${riskLevel}). The primary concerns involve ${keySignals.slice(0, 3).map((s) => s.signal.toLowerCase()).join(", ")}. Immediate escalation and mail/proxy log scoping are recommended.`
  } else if (outcome === "Requires Further Investigation") {
    summary = `The analyzed artifact displays ${mediumCount} medium-severity signal(s) with a risk score of ${riskScore}/100 (${riskLevel}). While no single piece of evidence is conclusive, the signal combination warrants analyst review. Correlate sender, subject, and URL domains against mail logs before dispositioning.`
  } else {
    summary = `The analyzed artifact returned a risk score of ${riskScore}/100 (${riskLevel}) with minimal actionable signals. No strong phishing indicators were detected through local triage. Request original headers and user-report context if this was submitted as suspicious.`
  }

  const recActions = []
  if (riskScore >= 80) recActions.push("Escalate immediately to Tier 2 with all evidence and the original message.")
  if (riskScore >= 55) recActions.push("Scope sender, subject, and URL root domains in proxy/mail logs for related messages.")
  if (topEv.some((f) => /credential|password|login/i.test(f.name))) recActions.push("Search for credential-harvesting infrastructure (landing page, phishing kit) via urlscan/VirusTotal.")
  if (result.urls?.length) recActions.push("Pivot extracted URLs/domains in SIEM and threat intelligence platforms.")
  if (findings.some((f) => /attachment/i.test(f.name))) recActions.push("Route attachment hash/filename to static analysis; do not open directly.")
  recActions.push("Document findings in the case timeline with top evidence and next-action notes.")
  if (riskScore < 30) recActions.push("If user-reported, confirm no other users received the same message before closing.")

  return {
    analyst_summary: summary,
    outcome,
    confidence,
    key_signals: keySignals,
    recommendation: recActions.join(" "),
    triage_notes: `Score: ${riskScore}/100 (${riskLevel}). Sources: ${result.risk?.independent_sources || breakdown.length}. Top: ${keySignals.slice(0, 3).map((s) => s.signal).join("; ") || "None"}. ${result.risk?.limitations || ""}`,
  }
}

const BRAND_DOMAIN_MAP = {
  microsoft: ["microsoft.com", "office.com", "office365.com", "live.com", "outlook.com", "sharepoint.com"],
  outlook: ["microsoft.com", "office.com", "outlook.com"],
  office365: ["microsoft.com", "office.com"],
  teams: ["microsoft.com", "teams.microsoft.com"],
  onedrive: ["microsoft.com", "onedrive.live.com"],
  sharepoint: ["microsoft.com", "sharepoint.com"],

  google: ["google.com", "gmail.com", "googlemail.com"],
  gmail: ["google.com", "gmail.com"],
  drive: ["google.com", "drive.google.com"],
  workspace: ["google.com"],

  paypal: ["paypal.com"],
  apple: ["apple.com", "icloud.com"],
  icloud: ["apple.com", "icloud.com"],
  amazon: ["amazon.com", "amazon.in"],
  aws: ["amazon.com", "aws.amazon.com"],
  linkedin: ["linkedin.com"],
  github: ["github.com"],
  docusign: ["docusign.com", "docusign.net"],
  dropbox: ["dropbox.com"],
  chase: ["chase.com"],
  wells: ["wellsfargo.com"],
  wellsfargo: ["wellsfargo.com"],
  bankofamerica: ["bankofamerica.com"],
  "bank of america": ["bankofamerica.com"],
  netflix: ["netflix.com"],
  adp: ["adp.com"],
  oracle: ["oracle.com"],
  salesforce: ["salesforce.com"],
  zoom: ["zoom.us"],
  facebook: ["facebook.com", "fb.com"],
  instagram: ["instagram.com"],
  twitter: ["twitter.com", "x.com"],
  x: ["x.com"],
  whatsapp: ["whatsapp.com"],
  discord: ["discord.com"],
  slack: ["slack.com"],
}

function detectForms(bodyText) {
  const forms = []
  const formRegex = /<form\s[^>]*action=["']([^"']*)["'][^>]*>/gi
  let match
  while ((match = formRegex.exec(bodyText)) !== null) {
    const action = match[1]
    const hasSubmit = /<input[^>]*type=["']submit["']|<button[^>]*type=["']submit["']/i.test(bodyText)
    let actionDomain
    try { actionDomain = new URL(action).hostname } catch { actionDomain = action ? action : "(same page)" }
    forms.push({ action, action_domain: actionDomain, has_submit: hasSubmit })
  }
  return forms
}

function detectTrackingPixels(bodyText) {
  const pixels = []
  const imgRegex = /<img\s[^>]*src=["']([^"']+)["'][^>]*>/gi
  let match
  while ((match = imgRegex.exec(bodyText)) !== null) {
    const tag = match[0]
    const src = match[1]
    const isPixel = /[?&]type=pixel|pixel\.|1x1|\bwidth\s*=\s*["']?1["']?\b|\bheight\s*=\s*["']?1["']?\b/i.test(tag)
    const isTracking = /utm_|analytics|tracking|beacon|pixel|open\.gif|p\.gif|trk/i.test(src)
    if (isPixel || isTracking) {
      pixels.push({ src: src.slice(0, 200), type: isPixel ? "tracking_pixel" : "tracking_image" })
    }
  }
  return pixels
}

function detectSocialEngineeringCta(text = "") {
  const urgencyPatterns = [
    { pattern: /\b(?:immediately|right\s+away|asap|urgent)\b/i, label: "immediate action", severity: "Medium" },
    { pattern: /\b(?:before\s+it('s| is)?\s+too\s+late|last\s+(?:warning|notice)|final\s+(?:notice|reminder))\b/i, label: "final deadline", severity: "High" },
    { pattern: /\b(?:limited\s+time|within\s+\d+\s+(?:hour|day|minute)|expir(?:e|ing|ation))\b/i, label: "limited time", severity: "Medium" },
    { pattern: /\b(?:suspended|disabled|locked|terminated|closed)\b/i, label: "account threat", severity: "High" },
    { pattern: /\b(?:confirm\s+(?:now|immediately)|validate\s+(?:now|your)|approve\s+(?:now|immediately))\b/i, label: "forced action", severity: "Medium" },
    { pattern: /\b(?:unauthorized|security\s+breach|compromised|suspicious\s+(?:activity|login|sign.in))\b/i, label: "security threat", severity: "Critical" },
    { pattern: /\b(?:click\s+(?:here|below|now|this\s+link)|tap\s+(?:here|now)|open\s+attachment)\b/i, label: "directed action", severity: "Low" },
  ]
  return urgencyPatterns.filter((item) => item.pattern.test(text))
}

function detectZeroWidthChars(text) {
  const zwChars = text.match(/[\u200b-\u200d\u2060-\u2064\ufeff]/g)
  if (!zwChars) return []
  const types = new Set()
  for (const char of zwChars) {
    const code = char.charCodeAt(0).toString(16)
    types.add(`U+${code.toUpperCase()}`)
  }
  return [...types]
}

function hasHtmlContent(text) {
  return /<html|<head|<body|<div|<span|<a\s|<img|<table|<form|<!DOCTYPE/i.test(text)
}

function extractPlainText(htmlText) {
  return htmlText
    .replace(/<style[^>]*>[^<]*<\/style>/gi, "")
    .replace(/<script[^>]*>[^<]*<\/script>/gi, "")
    .replace(/<[^>]+>/g, " ")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#x27;/g, "'")
    .replace(/&#x2F;/g, "/")
    .replace(/\s+/g, " ")
    .trim()
}

function detectBrandImpersonation(htmlLinks, bodyText) {
  const lower = bodyText.toLowerCase()
  const hits = []
  for (const [brand, legitDomains] of Object.entries(BRAND_DOMAIN_MAP)) {
    if (!lower.includes(brand)) continue
    for (const link of htmlLinks) {
      let linkDomain = ""
      try { linkDomain = new URL(link.href).hostname.toLowerCase() } catch { continue }
      const isLegit = legitDomains.some((d) => linkDomain === d || linkDomain.endsWith("." + d))
      if (!isLegit) {
        hits.push({ brand, brand_term: brand, actual_domain: linkDomain, link_text: link.text, href: link.href })
      }
    }
  }
  return hits
}

const BRAND_PROFILES = [
  { name: "Microsoft", terms: ["microsoft", "office365", "office 365", "outlook", "onedrive", "sharepoint", "teams"], roots: ["microsoft.com", "office.com", "office365.com", "live.com", "outlook.com", "sharepoint.com"] },
  { name: "Google", terms: ["google", "gmail", "drive", "workspace", "g suite"], roots: ["google.com", "gmail.com", "googlemail.com"] },
  { name: "PayPal", terms: ["paypal"], roots: ["paypal.com"] },
  { name: "Apple", terms: ["apple", "icloud"], roots: ["apple.com", "icloud.com"] },
  { name: "Amazon", terms: ["amazon", "aws"], roots: ["amazon.com", "amazon.in", "aws.amazon.com"] },
  { name: "LinkedIn", terms: ["linkedin"], roots: ["linkedin.com"] },
  { name: "GitHub", terms: ["github"], roots: ["github.com"] },
  { name: "DocuSign", terms: ["docusign"], roots: ["docusign.com", "docusign.net"] },
  { name: "Dropbox", terms: ["dropbox"], roots: ["dropbox.com"] },
  { name: "Banking", terms: ["bank", "netbanking", "sbi", "hdfc", "icici", "axis"], roots: ["sbi.co.in", "hdfcbank.com", "icicibank.com", "axisbank.com"] },
]

const PHISHING_KEYWORDS = {
  urgency: ["urgent", "immediately", "today", "expire", "expired", "final notice", "within 24 hours", "limited time", "suspended", "locked", "disabled", "termination"],
  credential: ["password", "verify your account", "login", "sign in", "signin", "account verification", "reset", "mfa", "2fa", "authentication", "secure message", "mailbox", "quota"],
  payment: ["invoice", "payment", "wire", "wallet", "bank", "payroll", "refund", "remittance", "purchase order", "po attached", "overdue"],
  delivery: ["delivery", "shipping", "package", "tracking", "courier"],
  hr: ["benefits", "hr", "payroll", "document shared", "policy update", "employee", "salary"],
  action: ["click here", "open attachment", "download", "review document", "confirm", "validate", "approve", "view document"],
}

export const PHISHING_SAMPLES = {
  m365: [
    "From: Microsoft Security <security@microsoft-support.example>",
    "Reply-To: support-reset@example-login.com",
    "Return-Path: bounce@example-login.com",
    "To: user@example.org",
    "Subject: Urgent password reset required",
    "Received-SPF: fail",
    "Authentication-Results: spf=fail dkim=none dmarc=fail",
    "",
    "Your account password will expire today. Verify your account immediately:",
    "https://example-login.com/secure/reset?user=user@example.org",
  ].join("\n"),
  credential: [
    "From: Account Security <security@micros0ft-login.example>",
    "Reply-To: verify@example-login.com",
    "Return-Path: bounce@example-login.com",
    "To: user@example.org",
    "Subject: Microsoft 365 account verification required",
    "Authentication-Results: spf=fail dkim=none dmarc=fail",
    "",
    "Your mailbox access will be suspended today.",
    "Verify your account password immediately at hxxps[:]//account-security[.]example-login[.]com/login?user=user@example.org",
    "Attachment: Microsoft_Account_Verification.html",
  ].join("\n"),
  headerOnly: [
    "From: Billing Desk <billing@vendor-example.com>",
    "Reply-To: payments@example-payments.com",
    "Return-Path: bounce@example-payments.com",
    "To: finance@example.org",
    "Subject: Invoice remittance update",
    "Received: from unknown (8.8.8.8) by mail.example.org;",
    "Received-SPF: fail",
    "Authentication-Results: spf=fail dkim=none dmarc=fail",
    "Message-ID: malformed-id",
  ].join("\n"),

  qrPayroll: [
    "From: HR Benefits <benefits@hr-payroll.example>",
    "Reply-To: payroll-update@example-payments.com",
    "To: employee@example.org",
    "Subject: Salary account verification pending",
    "Authentication-Results: spf=softfail dkim=none dmarc=fail",
    "",
    "Your salary deposit is on hold until the payroll portal is verified.",
    "Open the QR portal or visit hxxps[:]//payroll-verify[.]example-login[.]com/session?id=7788",
    "Attachment: Payroll_Update_QR.pdf",
  ].join("\n"),
  deliveryAttachment: [
    "From: Courier Notice <tracking@delivery-support.example>",
    "To: user@example.org",
    "Subject: Failed delivery - customs form attached",
    "Authentication-Results: spf=fail dkim=none dmarc=fail",
    "",
    "We could not deliver your package. Open the attached customs form to reschedule delivery.",
    "Attachment: customs_form.iso",
    "URL: hxxp[:]//198[.]51[.]100[.]23/reschedule",
  ].join("\n"),
  spearLink: [
    "From: CTO Office <cto@company-partner.example>",
    "Reply-To: cto-office@partner-login.com",
    "To: engineering@example.org",
    "Subject: Shared design doc for Q3 planning",
    "Authentication-Results: spf=pass dkim=none dmarc=none",
    "",
    "Hey team, I've shared the Q3 architecture doc for review.",
    "Click the link to access: hxxps[:]//docs[.]partner-login[.]com/share/doc?id=abc123&action=view",
    "It's time-sensitive — please review before EOD tomorrow.",
  ].join("\n"),
  giftcard: [
    "From: Rewards Center <rewards@promotions-rewards.example>",
    "Reply-To: verify@prize-claim.com",
    "To: user@example.org",
    "Subject: You won a $500 gift card!",
    "Authentication-Results: spf=softfail dkim=none dmarc=fail",
    "",
    "Congratulations! You have been selected for a $500 gift card.",
    "Claim your prize before it expires: hxxps[:]//claim-prize[.]reward-verify[.]com/claim?id=9876",
    "Limited time only — act now!",
  ].join("\n"),
  azureCloud: [
    "From: Microsoft Online Services <alerts@microsoft-verification.example>",
    "Reply-To: secure@azure-verify.com",
    "To: admin@example.org",
    "Subject: Suspicious sign-in activity on your Azure account",
    "Authentication-Results: spf=fail dkim=none dmarc=fail",
    "",
    "We detected unusual sign-in attempts to your Azure subscription.",
    "Review and secure your account immediately: hxxps[:]//azure[.]security-verify[.]example/login?token=abc123",
    "Your account will be suspended if no action is taken within 48 hours.",
    "Microsoft Azure Security Team",
  ].join("\n"),
  becInvoice: [
    "From: Vendor Accounts <accounts@vendor-payments.example>",
    "Reply-To: new-bank-details@example-finance.com",
    "To: finance@example.org",
    "Subject: Updated bank details for pending invoice",
    "Authentication-Results: spf=pass dkim=none dmarc=none",
    "",
    "Please use the updated bank account below for invoice INV-2044. Kindly process today to avoid delay.",
    "Attachment: INV-2044.docm",
  ].join("\n"),
}

function uniq(items) {
  const seen = new Set()
  return items.filter((item) => {
    const key = String(item.normalized || item.value || item).toLowerCase()
    if (!key || seen.has(key)) return false
    seen.add(key)
    return true
  })
}

export function refang(value = "") {
  return value
    .replace(/\bhxxps\b/gi, "https")
    .replace(/\bhxxp\b/gi, "http")
    .replace(/\[\s*:\s*\]/g, ":")
    .replace(/\[\s*\.\s*\]/g, ".")
    .replace(/\(\s*\.\s*\)/g, ".")
    .replace(/\{\s*\.\s*\}/g, ".")
    .replace(/\[\s*@\s*\]/g, "@")
    .replace(/\[at\]/gi, "@")
}

function defang(value = "") {
  return String(value)
    .replace(/https:\/\//gi, "hxxps[:];//".replace(";", ""))
    .replace(/http:\/\//gi, "hxxp[:];//".replace(";", ""))
    .replace(/\./g, "[.]")
    .replace(/@/g, "[@]")
}

function rootDomain(host = "") {
  const clean = host.toLowerCase().replace(/^www\./, "").replace(/[),.;]+$/g, "")
  if (!clean || /^\d{1,3}(?:\.\d{1,3}){3}$/.test(clean)) return clean
  const parts = clean.split(".").filter(Boolean)
  if (parts.length <= 2) return clean
  if (["co", "com", "net", "org", "gov", "ac", "edu"].includes(parts.at(-2)) && parts.at(-1)?.length === 2) return parts.slice(-3).join(".")
  return parts.slice(-2).join(".")
}

function domainFromEmail(value = "") {
  return value.match(/@([^>\s]+)/)?.[1]?.toLowerCase().replace(/[),.;]+$/g, "") || ""
}

function cleanHeaderAddress(value = "") {
  return value.replace(/^<|>$/g, "").trim()
}

export function parseHeaderMap(headers = "") {
  const map = {}
  let current = ""
  for (const rawLine of headers.split(/\r?\n/)) {
    if (/^\s/.test(rawLine) && current) {
      map[current][map[current].length - 1] += ` ${rawLine.trim()}`
      continue
    }
    const match = rawLine.match(/^([A-Za-z][A-Za-z0-9-]{1,80}):\s*(.*)$/)
    if (!match) continue
    current = match[1].toLowerCase()
    if (!map[current]) map[current] = []
    map[current].push(match[2].trim())
  }
  return map
}

function isLikelyEmailHeaderBlock(text = "") {
  const headerNames = new Set(["from", "to", "cc", "bcc", "subject", "reply-to", "return-path", "message-id", "date", "received", "authentication-results", "received-spf", "dkim-signature", "content-type", "content-disposition", "mime-version", "user-agent", "x-mailer"])
  const matchedNames = new Set()
  for (const rawLine of text.split(/\r?\n/)) {
    const match = rawLine.match(/^([A-Za-z][A-Za-z0-9-]{1,80}):\s*(.*)$/)
    if (match && headerNames.has(match[1].toLowerCase())) matchedNames.add(match[1].toLowerCase())
  }
  return matchedNames.size >= 2 || matchedNames.has("from") || matchedNames.has("authentication-results") || matchedNames.has("received-spf")
}

export function splitRawEmail(raw = "", fallbackHeaders = "", fallbackBody = "") {
  if (raw.trim()) {
    const parts = raw.replace(/\r\n/g, "\n").split(/\n\s*\n/)
    if (parts.length > 1 && isLikelyEmailHeaderBlock(parts[0])) {
      return { headers: parts[0], body: parts.slice(1).join("\n\n") }
    }
    return isLikelyEmailHeaderBlock(raw) ? { headers: raw, body: "" } : { headers: "", body: raw }
  }
  return { headers: fallbackHeaders, body: fallbackBody }
}

function parseEmails(text = "") {
  return uniq((text.match(/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi) || []).map((value) => ({ value, normalized: refang(value) })))
}

function extractUrls(text = "") {
  const combined = `${text}\n${refang(text)}`
  const rawUrls = combined.match(/\bhttps?:\/\/[^\s"'<>]+/gi) || []
  const htmlLinks = []
  const linkPattern = /<a\s+[^>]*href=["']([^"']+)["'][^>]*>(.*?)<\/a>/gis
  let match = linkPattern.exec(text)
  while (match) {
    const href = refang(match[1]).replace(/[),.;]+$/g, "")
    const visibleText = match[2].replace(/<[^>]+>/g, "").trim()
    htmlLinks.push({ href, text: visibleText })
    rawUrls.push(match[1])
    match = linkPattern.exec(text)
  }

  const urls = uniq(rawUrls.map((value) => {
    const normalized = refang(value).replace(/[),.;]+$/g, "")
    try {
      const parsed = new URL(normalized)
      const host = parsed.hostname.toLowerCase()
      return {
        value,
        normalized,
        defanged: defang(normalized),
        host,
        root_domain: rootDomain(host),
        path: parsed.pathname,
        query: parsed.search,
        protocol: parsed.protocol,
      }
    } catch {
      return { value, normalized, defanged: defang(normalized), host: "", root_domain: "", path: "", query: "", protocol: "" }
    }
  }))
  return { urls, htmlLinks }
}

function extractIocs(text = "") {
  const normalized = refang(text)
  const { urls, htmlLinks } = extractUrls(text)
  const emails = parseEmails(`${text}\n${normalized}`)
  const ips = uniq((`${text}\n${normalized}`.match(/\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b/g) || []).map((value) => ({ value, normalized: value })))
  const hashes = uniq((normalized.match(/\b[a-f0-9]{32}\b|\b[a-f0-9]{40}\b|\b[a-f0-9]{64}\b/gi) || []).map((value) => ({ value: value.toLowerCase(), normalized: value.toLowerCase() })))
  const domains = []
  urls.forEach((url) => { if (url.host) domains.push(url.host) })
  domains.push(...(normalized.match(/\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b/gi) || []))
  const domainItems = uniq(domains.map((value) => ({ value: value.toLowerCase(), normalized: value.toLowerCase() })).filter((item) => !item.normalized.includes("@") && !item.normalized.endsWith(".php") && !item.normalized.endsWith(".html")))
  return { urls, htmlLinks, domains: domainItems, ips, emails, hashes }
}

function analyzeHeaders(headerText) {
  const headers = parseHeaderMap(headerText)
  const from = headers.from?.[0] || ""
  const replyTo = headers["reply-to"]?.[0] || ""
  const returnPath = headers["return-path"]?.[0] || ""
  const authText = [
    ...(headers["authentication-results"] || []),
    ...(headers["received-spf"] || []),
    ...(headers["dkim-signature"] || []),
    ...(headers["arc-authentication-results"] || []),
  ].join(" ")
  const received = headers.received || []
  const sendingIps = uniq(received.flatMap((line) => line.match(/\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b/g) || []).map((value) => ({ value, normalized: value })))
  const sendingDomains = uniq(received.flatMap((line) => line.match(/\b(?:[a-z0-9-]+\.)+[a-z]{2,24}\b/gi) || []).map((value) => ({ value: value.toLowerCase(), normalized: value.toLowerCase() })))
  const auth = {
    spf: /spf=fail|received-spf:\s*fail|^fail\b/i.test(authText) ? "fail" : /spf=softfail/i.test(authText) ? "softfail" : /spf=neutral/i.test(authText) ? "neutral" : /spf=pass/i.test(authText) ? "pass" : authText ? "unknown" : "missing",
    dkim: /dkim=fail/i.test(authText) ? "fail" : /dkim=none/i.test(authText) ? "none" : /dkim=pass/i.test(authText) ? "pass" : headers["dkim-signature"]?.length ? "present" : "missing",
    dmarc: /dmarc=fail/i.test(authText) ? "fail" : /dmarc=none/i.test(authText) ? "none" : /dmarc=pass/i.test(authText) ? "pass" : authText ? "unknown" : "missing",
  }
  const fromDomain = domainFromEmail(cleanHeaderAddress(from))
  const replyToDomain = domainFromEmail(cleanHeaderAddress(replyTo))
  const returnPathDomain = domainFromEmail(cleanHeaderAddress(returnPath))
  return {
    fields: {
      from,
      to: headers.to?.[0] || "",
      cc: headers.cc?.[0] || "",
      subject: headers.subject?.[0] || "",
      reply_to: replyTo,
      return_path: returnPath,
      message_id: headers["message-id"]?.[0] || "",
      date: headers.date?.[0] || "",
      user_agent: headers["user-agent"]?.[0] || headers["x-mailer"]?.[0] || "",
      received,
      sending_ips: sendingIps,
      sending_domains: sendingDomains,
      authentication_results: headers["authentication-results"] || [],
      received_spf: headers["received-spf"] || [],
      dkim_signature_present: Boolean(headers["dkim-signature"]?.length),
      authentication: auth,
      domains: { from: fromDomain, reply_to: replyToDomain, return_path: returnPathDomain },
    },
    headers,
  }
}

function analyzeBody(bodyText, iocs) {
  const body = bodyText.toLowerCase()
  const themes = []
  for (const [theme, phrases] of Object.entries(PHISHING_KEYWORDS)) {
    const matches = phrases.filter((phrase) => body.includes(phrase))
    if (matches.length) themes.push({ theme, matches })
  }
  const attachmentMentions = uniq((bodyText.match(/\b[\w .-]+\.(?:exe|scr|js|vbs|jar|iso|img|lnk|hta|ps1|bat|cmd|zip|rar|7z|docm|xlsm|docx|xlsx|pdf|html|htm)\b/gi) || []).map((value) => ({ value: value.trim(), normalized: value.trim() })))
  const mismatchedLinks = iocs.htmlLinks.filter((link) => {
    if (!/^https?:\/\//i.test(link.text)) return false
    try { return new URL(link.text).hostname !== new URL(link.href).hostname } catch { return false }
  })
  const mentionedBrands = BRAND_PROFILES.filter((brand) => brand.terms.some((term) => body.includes(term))).map((brand) => brand.name)
  const hasHtml = hasHtmlContent(bodyText)
  const forms = hasHtml ? detectForms(bodyText) : []
  const trackingPixels = hasHtml ? detectTrackingPixels(bodyText) : []
  const zeroWidthChars = detectZeroWidthChars(bodyText)
  const plainText = hasHtml ? extractPlainText(bodyText) : bodyText
  const htmlOnlyNoText = hasHtml && !plainText.trim()
  const brandImpersonation = hasHtml ? detectBrandImpersonation(iocs.htmlLinks, bodyText) : []
  return {
    themes,
    mentioned_brands: [...new Set(mentionedBrands)],
    attachment_mentions: attachmentMentions,
    mismatched_links: mismatchedLinks,
    obfuscation: /hxxp|%[0-9a-f]{2}|\\u[0-9a-f]{4}|base64|atob\(/i.test(bodyText),
    has_html: hasHtml,
    html_only_no_text: htmlOnlyNoText,
    forms_detected: forms,
    tracking_images: trackingPixels,
    zero_width_chars: zeroWidthChars,
    brand_impersonation: brandImpersonation,
  }
}

function extractAttachmentMentions(text = "") {
  const filenameMatches = text.match(/\b[\w .-]+\.(?:exe|scr|js|vbs|jar|iso|img|lnk|hta|ps1|bat|cmd|zip|rar|7z|docm|xlsm|docx|xlsx|pdf|html|htm)\b/gi) || []
  const headerFilenames = []
  const filenamePattern = /filename\*?=(?:"([^"]+)"|([^;\r\n]+))/gi
  let match = filenamePattern.exec(text)
  while (match) {
    headerFilenames.push(match[1] || match[2])
    match = filenamePattern.exec(text)
  }
  return uniq([...filenameMatches, ...headerFilenames].map((value) => ({ value: value.trim(), normalized: value.trim().replace(/^["']|["']$/g, "") })))
}

function addFinding(findings, { name, severity = "Info", evidence = "", why = "", action = "", score = 0, source = "local", category = "signal", mitre_id = "" }) {
  findings.push({ name, severity, evidence, why, action, score, source, category, mitre_id })
}

const FINDING_MITRE_MAP = {
  "SPF fail": "T1566.002",
  "SPF softfail": "T1566.002",
  "SPF none": "T1566.002",
  "SPF neutral": "T1566.002",
  "DKIM fail": "T1566.002",
  "DKIM none": "T1566.002",
  "DMARC fail": "T1566.002",
  "DMARC none": "T1566.002",
  "Reply-To domain mismatch": "T1566.002",
  "Return-Path domain mismatch": "T1566.002",
  "Social-engineering pressure": "T1566.001",
  "Visible link and href mismatch": "T1566.002",
  "Form in email body": "T1566.001",
  "Brand impersonation": "T1566.002",
  "Brand mentioned without matching sender/link domain": "T1566.002",
  "Defanged/encoded content": "T1027",
  "Zero-width Unicode characters detected": "T1027",
  "HTML-only email with no visible text": "T1027",
  "Tracking pixels detected": "T1078.003",
  "Missing Message-ID": "",
  "Malformed Message-ID": "",
}

function mapFindingsToMitre(findings = []) {
  for (const finding of findings) {
    if (finding.mitre_id) continue
    finding.mitre_id = FINDING_MITRE_MAP[finding.name] || ""
  }
  return findings
}

function typoBrandSignal(domain = "") {
  const label = rootDomain(domain).split(".")[0] || domain.split(".")[0] || ""
  const normalized = label.replace(/0/g, "o").replace(/1/g, "l").replace(/3/g, "e").replace(/5/g, "s").replace(/@/g, "a")
  for (const brand of BRAND_PROFILES) {
    for (const term of brand.terms) {
      const plain = term.replace(/\s+/g, "").toLowerCase()
      if (plain.length < 5) continue
      if (normalized.includes(plain) && !brand.roots.includes(rootDomain(domain))) return brand.name
    }
  }
  return ""
}

function matchingBrandProfile(text = "") {
  const lower = text.toLowerCase()
  return BRAND_PROFILES.filter((brand) => brand.terms.some((term) => lower.includes(term)))
}

function analyzeUrls(iocs, contextText, fromRoot) {
  const brandsInEmail = matchingBrandProfile(contextText)
  return iocs.urls.map((url) => {
    const signals = []
    const tld = url.host.split(".").pop()
    const joined = `${url.host}${url.path}${url.query}`
    if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(url.host)) signals.push({ label: "IP address used as URL host", severity: "High", score: 18 })
    if (url.host.startsWith("xn--") || url.host.includes(".xn--")) signals.push({ label: "Punycode/IDN hostname", severity: "High", score: 18 })
    if (SUSPICIOUS_TLDS.has(tld)) signals.push({ label: `Frequently abused or risky TLD: .${tld}`, severity: "Medium", score: 9 })
    if (URL_SHORTENERS.has(url.host)) signals.push({ label: "URL shortener hides final destination", severity: "High", score: 18 })
    if (/(login|verify|reset|update|secure|account|password|invoice|payment|wallet|mfa|signin|authentication)/i.test(joined)) signals.push({ label: "Credential/payment wording in URL", severity: "Medium", score: 10 })
    if (url.query.length > 80) signals.push({ label: "Long tracking or tokenized query", severity: "Low", score: 5 })
    if (/%[0-9a-f]{2}/i.test(url.value)) signals.push({ label: "Encoded URL characters", severity: "Low", score: 4 })
    if (iocs.emails.some((email) => url.normalized.includes(email.normalized))) signals.push({ label: "Recipient email embedded in URL", severity: "High", score: 18 })
    const extension = (url.path.match(/\.([a-z0-9]{2,5})$/i)?.[1] || "").toLowerCase()
    if (SUSPICIOUS_EXTENSIONS.has(extension)) signals.push({ label: `Suspicious link target extension: .${extension}`, severity: PAYLOAD_EXTENSIONS.has(extension) ? "High" : "Medium", score: PAYLOAD_EXTENSIONS.has(extension) ? 18 : 10 })
    const typoBrand = typoBrandSignal(url.host)
    if (typoBrand) signals.push({ label: `Possible ${typoBrand} typosquat/homograph`, severity: "High", score: 20 })
    for (const brand of brandsInEmail) {
      if (!brand.roots.includes(url.root_domain) && brand.terms.some((term) => joined.toLowerCase().includes(term.replace(/\s+/g, "")))) {
        signals.push({ label: `${brand.name} wording on non-${brand.name} domain`, severity: "High", score: 20 })
      }
    }
    if (fromRoot && url.root_domain && fromRoot !== url.root_domain) signals.push({ label: "URL domain differs from sender domain", severity: "Medium", score: 8 })
    return { ...url, signals }
  })
}

function analyzeAttachments(items) {
  return items.map((item) => {
    const lower = item.normalized.toLowerCase()
    const parts = lower.split(".")
    const ext = parts.at(-1) || ""
    const signals = []
    if (SUSPICIOUS_EXTENSIONS.has(ext)) signals.push(`Suspicious extension: .${ext}`)
    if (parts.length > 2) signals.push("Double extension pattern")
    if (["zip", "rar", "7z", "iso", "img"].includes(ext)) signals.push("Archive or disk image")
    if (["docm", "xlsm", "pptm"].includes(ext)) signals.push("Macro-enabled Office file")
    if (["html", "htm"].includes(ext)) signals.push("HTML attachment can host credential forms")
    return { filename: item.normalized, extension: ext, signals }
  })
}

function buildRisk(findings, context) {
  const base = Math.min(100, findings.reduce((sum, finding) => sum + (finding.score || 0), 0))
  const independentSources = new Set(findings.filter((finding) => finding.score > 0).map((finding) => finding.source)).size
  const score = Math.min(100, base + (independentSources >= 3 ? 8 : independentSources >= 2 ? 4 : 0))
  const level = score >= 85 ? "Critical" : score >= 60 ? "High" : score >= 30 ? "Medium" : "Low"
  const confidenceScore = Math.min(100,
    25 +
    (context.headersPresent ? 15 : 0) +
    (context.bodyPresent ? 15 : 0) +
    (context.authPresent ? 12 : 0) +
    (context.urlMetadataCount ? 18 : 0) +
    (independentSources >= 2 ? 12 : 0) +
    (findings.length >= 4 ? 8 : 0),
  )
  const confidence = confidenceScore >= 78 ? "High" : confidenceScore >= 52 ? "Medium" : "Low"
  return {
    level,
    score,
    confidence,
    confidence_score: confidenceScore,
    independent_sources: independentSources,
    top_evidence: findings.filter((finding) => finding.score > 0).sort((a, b) => b.score - a.score).slice(0, 8),
    limitations: "Local deterministic assessment with guarded URL metadata. It is not a replacement for mail gateway verdicts, user click telemetry, endpoint/proxy logs, or vendor reputation.",
  }
}

function determineAttackType(result) {
  const findingNames = result.findings.map((finding) => finding.name.toLowerCase()).join(" | ")
  const themes = result.body.themes.map((item) => item.theme)
  if (findingNames.includes("attachment") || result.attachments.some((item) => item.signals.length)) return "Payload / attachment delivery"
  if (themes.includes("payment")) return "Payment fraud / BEC-style lure"
  if (themes.includes("credential") || findingNames.includes("credential") || findingNames.includes("recipient email embedded")) return "Credential harvesting"
  if (findingNames.includes("brand") || result.body.mentioned_brands.length) return "Brand impersonation"
  if (themes.includes("delivery")) return "Delivery scam / tracking lure"
  return result.urls.length ? "Suspicious link-based email" : "Suspicious email content"
}

function determineDisposition(risk, attackType) {
  if (risk.score >= 85) return `Escalate immediately: ${attackType}`
  if (risk.score >= 60) return `Escalate for analyst review: ${attackType}`
  if (risk.score >= 30) return `Needs review: ${attackType}`
  return "Low signal from local triage"
}

function bestNextAction(result) {
  const names = result.findings.map((finding) => finding.name.toLowerCase()).join(" | ")
  if (names.includes("recipient email embedded") || names.includes("credential")) return "Scope mailbox/proxy logs for clicks, preserve the URL, and prepare credential-phishing containment if a user interacted."
  if (names.includes("attachment")) return "Do not open the attachment. Route filename/hash to Attachment Triage and search mailboxes for the same attachment name/hash."
  if (names.includes("dmarc") || names.includes("spf") || names.includes("reply-to")) return "Validate sender authenticity through mail gateway logs, SPF/DKIM/DMARC alignment, and Reply-To/Return-Path consistency."
  if (result.urls.length) return "Pivot sender, subject, URL, final URL, and root domains in mailbox, DNS, and proxy logs."
  return "Collect the full original message with headers and correlate sender/subject across mail logs before disposition."
}

function buildEvidenceChain(result) {
  const auth = result.headers.authentication
  const linkRisk = result.urls.reduce((count, url) => count + url.signals.length, 0) + (result.url_enrichment || []).reduce((count, item) => count + (item.signals?.length || 0), 0)
  return [
    {
      stage: "Sender identity",
      state: result.sender_alignment.mismatches.length ? "warning" : "ok",
      detail: result.sender_alignment.mismatches[0] || "No major sender-domain mismatch detected from available fields.",
    },
    {
      stage: "Authentication",
      state: [auth.spf, auth.dkim, auth.dmarc].some((value) => ["fail", "none", "missing", "softfail"].includes(value)) ? "warning" : "ok",
      detail: `SPF ${auth.spf}, DKIM ${auth.dkim}, DMARC ${auth.dmarc}`,
    },
    {
      stage: "Link destination",
      state: linkRisk ? "warning" : result.urls.length ? "unknown" : "empty",
      detail: result.urls.length ? `${result.urls.length} link(s), ${linkRisk} URL signal(s).` : "No URLs found in the provided artifact.",
    },
    {
      stage: "Payload path",
      state: result.attachments.some((item) => item.signals.length) ? "warning" : result.attachments.length ? "unknown" : "empty",
      detail: result.attachments.length ? `${result.attachments.length} attachment reference(s).` : "No attachment references extracted.",
    },
    {
      stage: "User pressure",
      state: result.body.themes.length ? "warning" : "unknown",
      detail: result.body.themes.length ? result.body.themes.map((item) => item.theme).join(", ") : "No strong social-engineering theme found.",
    },
  ]
}

function buildGuidance(result) {
  const sender = result.headers.from || result.headers.domains.from || "sender"
  const subject = result.headers.subject || "subject"
  const domains = result.iocs.domains.map((item) => item.normalized).filter(Boolean)
  const urls = result.iocs.urls.map((item) => item.normalized).filter(Boolean)
  const finalUrls = (result.url_enrichment || []).map((item) => item.final_url).filter(Boolean)
  const indicators = [...urls, ...finalUrls, ...domains]
  return {
    immediate: [
      result.risk.score >= 60 ? "Escalate with top evidence and preserve the original message." : "Do not close as benign solely from local triage; correlate with mail/proxy context.",
      "Do not click links or open attachments from the submitted message.",
      indicators.length ? "Copy defanged URLs/domains into the case ticket." : "Request the full original email if URLs/headers are missing.",
    ],
    investigation: [
      `Search mail logs for sender: ${sender}`,
      `Search mail logs for subject: ${subject}`,
      domains.length ? `Search DNS/proxy logs for: ${domains.slice(0, 5).join(", ")}` : "If links are missing, inspect the original HTML body or attachment references.",
      result.headers.authentication.dmarc !== "pass" ? "Review SPF/DKIM/DMARC alignment and sending infrastructure." : "Authentication passed where observed; still review link/content intent because authentication alone does not prove safety.",
    ],
    containment: [
      result.risk.score >= 60 ? "Consider quarantine/removal for matching messages after scope confirmation." : "Avoid broad containment until scope and business context are confirmed.",
      result.urls.length ? "Block or monitor URL/root domains only after approval or external corroboration." : "No URL block candidate was extracted.",
      result.attachments.length ? "Submit attachments to static triage/sandbox process if files are available." : "No attachment containment candidate was extracted.",
    ],
  }
}

function buildHuntingQueries(result) {
  const senderAddress = result.headers.from.match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i)?.[0] || ""
  const subject = result.headers.subject || ""
  const domains = result.iocs.domains.map((item) => item.normalized).filter(Boolean).slice(0, 8)
  const urls = result.iocs.urls.map((item) => item.normalized).filter(Boolean).slice(0, 5)
  const urlDomains = domains.length ? `dynamic([${domains.map((item) => `"${item}"`).join(", ")}])` : "dynamic([])"
  const urlList = urls.length ? `dynamic([${urls.map((item) => `"${item}"`).join(", ")}])` : "dynamic([])"
  const hasAttachments = result.attachments.length > 0
  const attachmentNames = result.attachments.map((item) => item.filename).filter(Boolean).slice(0, 5)
  const queries = [
    {
      name: "M365: similar emails by sender/subject",
      query: `EmailEvents\n| where SenderFromAddress =~ "${senderAddress}" or Subject has "${subject.replaceAll('"', "'")}"\n| project Timestamp, NetworkMessageId, RecipientEmailAddress, SenderFromAddress, Subject, DeliveryAction, ThreatTypes`,
    },
    {
      name: "M365: URL/domain scope",
      query: `let domains = ${urlDomains};\nlet urls = ${urlList};\nEmailUrlInfo\n| where Url has_any (urls) or UrlDomain in~ (domains)\n| project Timestamp, NetworkMessageId, Url, UrlDomain`,
    },
    {
      name: "Proxy/DNS pivot ideas",
      query: domains.length ? domains.map((domain) => `RemoteUrl contains "${domain}" OR DnsQuery contains "${domain}"`).join("\n") : "No URL domains extracted. Re-check original HTML/body or attachment references.",
    },
  ]
  if (domains.length) {
    queries.push({
      name: "Sysmon/EDR: network connections to suspicious domains",
      query: `DeviceNetworkEvents\n| where RemoteUrl has_any (${domains.map((item) => `"${item}"`).join(", ")})\n| project Timestamp, DeviceName, RemoteUrl, RemoteIP, RemotePort, Protocol`,
    })
    queries.push({
      name: "DNS query log pivot",
      query: domains.map((domain) => `(QueryName contains "${domain}" OR QueryResults contains "${domain}")`).join(" OR "),
    })
  }
  if (hasAttachments && attachmentNames.length) {
    queries.push({
      name: "Sysmon/EDR: file creation from attachment names",
      query: `DeviceFileEvents\n| where FileName has_any (${attachmentNames.map((item) => `"${item}"`).join(", ")})\n| project Timestamp, DeviceName, FileName, FolderPath, SHA256`,
    })
  }
  queries.push({
    name: "Sentinel: mail/sign-in correlation",
    query: `EmailEvents\n| where SenderFromAddress =~ "${senderAddress}" or Subject has "${subject.replaceAll('"', "'")}"\n| join kind=inner (\n  SigninLogs\n  | where ResultType != "0"\n) on $left.RecipientEmailAddress == $right.UserPrincipalName\n| project Timestamp, UserPrincipalName, AppDisplayName, AuthenticationRequirement, RiskLevelDuringSignIn`,
  })
  return queries
}


function buildRelayPath(headers = {}) {
  const received = headers.received || []
  return received.slice(0, 8).map((line, index) => {
    const ip = line.match(/\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b/)?.[0] || ""
    const from = line.match(/from\s+([^\s;]+)/i)?.[1]?.replace(/[(),;]/g, "") || "unknown"
    const by = line.match(/\sby\s+([^\s;]+)/i)?.[1]?.replace(/[(),;]/g, "") || "unknown"
    const withValue = line.match(/\swith\s+([^\s;]+)/i)?.[1]?.replace(/[(),;]/g, "") || ""
    return {
      hop: index + 1,
      from,
      by,
      with: withValue,
      ip,
      raw: line,
      note: ip ? "Sender path observable" : "No public IP extracted from this hop",
    }
  })
}

function severityTone(severity = "Info") {
  const value = severity.toLowerCase()
  if (["critical", "high"].includes(value)) return "rose"
  if (value === "medium") return "amber"
  if (value === "low") return "cyan"
  return "slate"
}

function weightForSeverity(severity = "Info") {
  const value = severity.toLowerCase()
  if (value === "critical") return 30
  if (value === "high") return 22
  if (value === "medium") return 12
  if (value === "low") return 5
  return 0
}

function buildScoreBreakdown(result) {
  const rows = (result.risk.top_evidence || []).slice(0, 10).map((finding) => ({
    signal: finding.name,
    points: finding.score || weightForSeverity(finding.severity),
    severity: finding.severity,
    source: finding.source,
    evidence: finding.evidence,
    analyst_note: finding.why,
    mitre_id: finding.mitre_id || "",
  }))
  const positive = rows.reduce((sum, item) => sum + Number(item.points || 0), 0)
  const dampeners = []
  if (result.headers.authentication?.spf === "pass") dampeners.push({ signal: "SPF passed", points: -4, reason: "Sender authentication partly lowers spoofing evidence, but does not validate links/content." })
  if (result.headers.authentication?.dkim === "pass") dampeners.push({ signal: "DKIM passed", points: -4, reason: "DKIM confirms message integrity for a domain, not that the email is safe." })
  if (!result.urls.length) dampeners.push({ signal: "No URL extracted", points: -8, reason: "Link-based phishing evidence is lower without URL evidence." })
  if (!result.attachments.length) dampeners.push({ signal: "No attachment reference", points: -4, reason: "Payload-delivery evidence is lower without attachment evidence." })
  return {
    positive_points: positive,
    dampeners,
    rows,
    explanation: rows.length
      ? `The score is driven mainly by ${rows.slice(0, 3).map((item) => item.signal.toLowerCase()).join(", ")}.`
      : "No strong local evidence changed the score; request full headers or the original EML if this was user-reported.",
  }
}

function buildUrlRollup(result) {
  const urls = result.urls || []
  const enriched = result.url_enrichment || []
  const highRisk = enriched.filter((item) => item.verdict === "suspicious").length
  const metadataBlocked = enriched.filter((item) => item.blocked_reason).length
  const mismatches = result.body?.mismatched_links?.length || 0
  const finalHosts = uniq(enriched.map((item) => item.final_host).filter(Boolean)).map((host) => ({ value: host, normalized: host }))
  const originalDomains = uniq(urls.map((item) => item.root_domain || item.host).filter(Boolean)).map((domain) => ({ value: domain, normalized: domain }))
  const finalDomainChanged = enriched.filter((item) => {
    const original = rootDomain(urls.find((url) => url.normalized === item.original_url)?.host || "")
    const final = rootDomain(item.final_host || "")
    return original && final && original !== final
  }).length
  return {
    total: urls.length,
    high_risk: highRisk,
    metadata_checked: enriched.length,
    metadata_blocked: metadataBlocked,
    visible_href_mismatches: mismatches,
    original_domains: originalDomains,
    final_hosts: finalHosts,
    final_domain_changed: finalDomainChanged,
    summary: urls.length
      ? `${urls.length} URL(s) extracted; ${enriched.length} enriched with guarded metadata; ${highRisk} suspicious metadata result(s); ${mismatches} visible/href mismatch(es).`
      : "No URL evidence was extracted from the submitted content.",
  }
}

function buildSenderMatrix(result) {
  const fromDomain = result.sender_alignment?.from_domain || domainFromEmail(result.headers.from) || ""
  const replyDomain = result.sender_alignment?.reply_to_domain || domainFromEmail(result.headers.reply_to) || ""
  const returnDomain = result.sender_alignment?.return_path_domain || domainFromEmail(result.headers.return_path) || ""
  const urlDomains = result.sender_alignment?.url_domains || []
  const brand = result.body?.mentioned_brands?.join(", ") || "None detected"
  const rows = [
    { field: "Header From", value: result.headers.from || "N/A", domain: fromDomain || "N/A", aligned: true, meaning: "Visible sender identity." },
    { field: "Reply-To", value: result.headers.reply_to || "N/A", domain: replyDomain || "N/A", aligned: !replyDomain || !fromDomain || rootDomain(replyDomain) === rootDomain(fromDomain), meaning: "Where replies would go." },
    { field: "Return-Path", value: result.headers.return_path || "N/A", domain: returnDomain || "N/A", aligned: !returnDomain || !fromDomain || rootDomain(returnDomain) === rootDomain(fromDomain), meaning: "Envelope/bounce identity." },
    { field: "URL domains", value: urlDomains.map((item) => item.normalized).join(", ") || "None", domain: urlDomains.length ? `${urlDomains.length} domain(s)` : "N/A", aligned: !urlDomains.some((item) => fromDomain && rootDomain(item.normalized) !== rootDomain(fromDomain)), meaning: "Where links point." },
    { field: "Visible brand", value: brand, domain: "content", aligned: !result.findings.some((finding) => finding.category === "brand_impersonation"), meaning: "Brand being invoked by the message." },
  ]
  const poorCount = rows.filter((row) => row.aligned === false).length
  return {
    rating: poorCount >= 3 ? "Poor" : poorCount >= 1 ? "Mixed" : "Mostly aligned or insufficient data",
    rows,
  }
}

function buildProfessionalAssessment(result) {
  const auth = result.headers.authentication || {}
  const urlCount = result.urls?.length || 0
  const attachmentCount = result.attachments?.length || 0
  const top = result.risk.top_evidence || []
  const headerProblems = [auth.spf, auth.dkim, auth.dmarc].filter((value) => ["fail", "softfail", "none", "missing", "neutral"].includes(value)).length
  const alignmentProblems = result.sender_alignment?.mismatches?.length || 0
  const urlSignals = (result.urls || []).reduce((sum, item) => sum + (item.signals?.length || 0), 0)
  const metadataSignals = (result.url_enrichment || []).reduce((sum, item) => sum + (item.signals?.length || 0), 0)
  const strongSignals = top.filter((item) => ["High", "Critical"].includes(item.severity)).length

  const outcome = result.risk.score >= 85
    ? "Probable phishing / malicious email"
    : result.risk.score >= 60
      ? "Likely phishing"
      : result.risk.score >= 30
        ? "Suspicious / needs review"
        : "Insufficient local evidence"

  const strongest = top.slice(0, 3).map((item) => item.name.toLowerCase())
  const analystSummary = strongest.length
    ? `${outcome}. The strongest evidence is ${strongest.join(", ")}. Recommended action is to scope sender, subject, URL domains, and user-click telemetry before broad blocking.`
    : `${outcome}. The artifact does not contain enough strong local evidence for a confident phishing verdict; request the original EML/full headers and user report context.`

  const coverage = [
    { label: "Headers", status: result.split.headers.trim() ? "available" : "missing", detail: result.split.headers.trim() ? "Sender, routing, and authentication fields parsed." : "No full headers were provided.", tone: result.split.headers.trim() ? "emerald" : "amber" },
    { label: "Auth", status: headerProblems ? "issues" : "clean/unknown", detail: `SPF ${auth.spf}, DKIM ${auth.dkim}, DMARC ${auth.dmarc}`, tone: headerProblems ? "amber" : "emerald" },
    { label: "Alignment", status: alignmentProblems ? "mismatch" : "no major mismatch", detail: alignmentProblems ? result.sender_alignment.mismatches.slice(0, 2).join("; ") : "Reply-To, Return-Path, and From alignment did not produce a major mismatch.", tone: alignmentProblems ? "amber" : "emerald" },
    { label: "Links", status: urlCount ? `${urlCount} found` : "none", detail: urlSignals || metadataSignals ? `${urlSignals} structural and ${metadataSignals} metadata URL signal(s).` : "No strong link evidence from submitted content.", tone: urlSignals || metadataSignals ? "rose" : "slate" },
    { label: "Attachments", status: attachmentCount ? `${attachmentCount} reference(s)` : "none", detail: attachmentCount ? "Attachment names/extensions need static triage if file is available." : "No attachment filename/reference was extracted.", tone: attachmentCount ? "amber" : "slate" },
  ]

  const confidenceGaps = []
  if (!result.split.headers.trim()) confidenceGaps.push("Full original headers were not provided; SPF/DKIM/DMARC and relay path may be incomplete.")
  if (!result.url_enrichment?.length && result.urls?.length) confidenceGaps.push("URL destination metadata was not enriched or failed for the extracted links.")
  if (!result.attachments?.length) confidenceGaps.push("No attachment file was submitted; attachment names alone cannot confirm payload behavior.")
  confidenceGaps.push("No external reputation, mailbox click telemetry, endpoint alerts, or vendor gateway verdicts are included locally.")

  const evidenceRows = top.slice(0, 10).map((finding) => ({
    signal: finding.name,
    severity: finding.severity,
    source: finding.source,
    evidence: finding.evidence,
    meaning: finding.why,
    action: finding.action,
    tone: severityTone(finding.severity),
    points: finding.score || weightForSeverity(finding.severity),
    mitre_id: finding.mitre_id || "",
  }))

  const externalVerification = [
    "Check extracted URLs/domains in urlscan, VirusTotal, Google Safe Browsing, URLhaus, PhishTank/OpenPhish, Talos/Spamhaus, or the mail gateway if policy allows.",
    "Compare sender/authentication with Google/Microsoft/MXToolbox-style header views and gateway verdicts.",
    "Search M365/Defender/SIEM for same sender, subject, URL root domain, final host, attachment filename, and recipient clicks.",
    "If any user clicked, review sign-in activity, MFA prompts, browser history, and endpoint telemetry before closing.",
  ]

  const urlRollup = buildUrlRollup(result)
  const senderMatrix = buildSenderMatrix(result)
  const scoreBreakdown = buildScoreBreakdown(result)
  const containmentDecision = result.risk.score >= 75
    ? "Quarantine matching messages after scope confirmation; block or monitor extracted URL/root domains according to policy."
    : result.risk.score >= 40
      ? "Hold for analyst review; avoid permanent blocking until destination/reputation/user-click context is confirmed."
      : "Do not broad-block from this local result alone; use monitoring/search pivots first."

  return {
    outcome,
    analyst_summary: analystSummary,
    confidence_reason: `Evidence strength is ${result.risk.confidence.toLowerCase()} because ${result.risk.independent_sources || 0} evidence source(s) contributed and ${strongSignals} high-weight signal(s) were found.`,
    coverage,
    evidence_rows: evidenceRows,
    confidence_gaps: confidenceGaps,
    external_verification: externalVerification,
    relay_path: buildRelayPath(result.headers),
    url_rollup: urlRollup,
    sender_matrix: senderMatrix,
    score_breakdown: scoreBreakdown,
    containment_decision: containmentDecision,
  }
}

function buildReport(result) {
  if (!result) return ""
  const pro = result.professional || {}
  const scoreRows = pro.score_breakdown?.rows || []
  const bodyAnalysis = result.body || {}
  const urlRollup = pro.url_rollup || {}
  const lines = [
    "# BeyondArch Phishing Triage Report",
    "",
    "## Analyst Decision",
    `- Disposition: ${pro.outcome || result.decision.disposition}`,
    `- Risk: ${result.risk.level} (${result.risk.score}/100)`,
    `- Evidence level: ${result.risk.confidence} (${result.risk.confidence_score}/100)`,
    `- Attack Type: ${result.decision.attack_type}`,
    `- Primary Concern: ${result.decision.primary_concern}`,
    `- Next Action: ${result.decision.next_action}`,
    `- Containment Logic: ${pro.containment_decision || "Scope first, then contain based on corroborated evidence."}`,
    "",
    "## Analyst Summary",
    pro.analyst_summary || result.decision.next_action,
    "",
    "## Score Drivers",
    ...(scoreRows.length ? scoreRows.map((row) => `- +${row.points} [${row.severity}] ${row.signal}: ${row.evidence} ${row.mitre_id ? `(${row.mitre_id})` : ""}`) : ["- No high-weight score drivers found."]),
    ...(pro.score_breakdown?.dampeners?.length ? ["", "## Score Dampeners", ...pro.score_breakdown.dampeners.map((row) => `- ${row.points} ${row.signal}: ${row.reason}`)] : []),
    "",
    "## Sender / Header Metadata",
    `- From: ${result.headers.from || "N/A"}`,
    `- Reply-To: ${result.headers.reply_to || "N/A"}`,
    `- Return-Path: ${result.headers.return_path || "N/A"}`,
    `- To: ${result.headers.to || "N/A"}`,
    `- Subject: ${result.headers.subject || "N/A"}`,
    `- SPF/DKIM/DMARC: ${result.headers.authentication.spf}/${result.headers.authentication.dkim}/${result.headers.authentication.dmarc}`,
    `- Sender Alignment: ${pro.sender_matrix?.rating || "N/A"}`,
    "",
    "## Body Intelligence",
    `- HTML Content: ${bodyAnalysis.has_html ? "Yes" : "No"}`,
    `- Forms Detected: ${(bodyAnalysis.forms_detected || []).length}`,
    `- Tracking Images: ${(bodyAnalysis.tracking_images || []).length}`,
    `- Zero-Width Chars: ${(bodyAnalysis.zero_width_chars || []).join(", ") || "None"}`,
    `- Brand Impersonations: ${(bodyAnalysis.brand_impersonation || []).length}`,
    `- Link/URL Mismatches: ${(bodyAnalysis.mismatched_links || []).length}`,
    `- Obfuscated Content: ${bodyAnalysis.obfuscation ? "Yes" : "No"}`,
    "",
    "## URL Rollup",
    `- URLs extracted: ${urlRollup.total || 0}`,
    `- URL metadata checked: ${urlRollup.metadata_checked || 0}`,
    `- Suspicious metadata results: ${urlRollup.high_risk || 0}`,
    `- Visible/href mismatches: ${urlRollup.visible_href_mismatches || 0}`,
    `- Final domain changes: ${urlRollup.final_domain_changed || 0}`,
    ...(result.urls.length ? result.urls.map((url) => `- ${url.defanged} (${url.signals.map((signal) => signal.label).join("; ") || "no local URL signal"})`) : ["- None extracted."]),
    ...(result.url_enrichment?.length ? ["", "## Guarded Destination Metadata", ...result.url_enrichment.map((item) => `- ${item.original_url} -> ${item.final_url || "N/A"} | ${item.verdict} | ${item.title || "no title"}`)] : []),
    "",
    "## Recommended Actions",
    ...result.guidance.immediate.map((item) => `- ${item}`),
    ...result.guidance.investigation.map((item) => `- ${item}`),
    ...result.guidance.containment.map((item) => `- ${item}`),
    "",
    "## Generated Hunt Queries",
    ...result.hunting_queries.flatMap((item) => [`### ${item.name}`, "```", item.query, "```"]),
    "",
    "## Missing Evidence / Not Verified",
    ...((pro.confidence_gaps || []).map((item) => `- ${item}`)),
    "",
    "## Limitations",
    `- ${result.risk.limitations}`,
    "- No attachment execution, JavaScript rendering, credential submission, or file download was performed.",
    "- Vendor reputation and user-click telemetry are not included unless reviewed separately.",
  ]
  return lines.join("\n")
}

export function analyzeEmailLocal({ raw = "", headers = "", body = "" }) {
  const split = splitRawEmail(raw, headers, body)
  const combined = `${split.headers}\n\n${split.body}`
  const headerAnalysis = analyzeHeaders(split.headers)
  const iocsRaw = extractIocs(combined)
  const fromDomain = headerAnalysis.fields.domains.from
  const fromRoot = rootDomain(fromDomain)
  const bodyAnalysis = analyzeBody(split.body, iocsRaw)
  const urls = analyzeUrls(iocsRaw, combined, fromRoot)
  const attachmentMentions = extractAttachmentMentions(combined)
  const attachments = analyzeAttachments(uniq([...bodyAnalysis.attachment_mentions, ...attachmentMentions]))
  const findings = []
  const replyRoot = rootDomain(headerAnalysis.fields.domains.reply_to)
  const returnRoot = rootDomain(headerAnalysis.fields.domains.return_path)
  const urlDomains = uniq(urls.map((url) => ({ value: url.root_domain || url.host, normalized: url.root_domain || url.host })).filter((item) => item.normalized))
  const hasHeaderSubmission = Boolean(split.headers.trim())
  const auth = headerAnalysis.fields.authentication

  for (const [key, value] of Object.entries(auth)) {
    if (!hasHeaderSubmission && value === "missing") continue
    if (["fail", "softfail", "neutral", "none", "missing"].includes(value)) {
      addFinding(findings, { name: `${key.toUpperCase()} ${value}`, severity: value === "fail" ? "High" : "Medium", evidence: `${key}=${value}`, why: "Email authentication failure or absence increases spoofing risk.", action: "Review authentication alignment and mail gateway verdicts.", score: value === "fail" ? 18 : 10, source: "headers", category: "authentication", mitre_id: "T1566.002" })
    }
  }
  if (replyRoot && fromRoot && replyRoot !== fromRoot) addFinding(findings, { name: "Reply-To domain mismatch", severity: "High", evidence: `${fromRoot} -> ${replyRoot}`, why: "Replies would go to a different domain than the visible sender.", action: "Validate whether this Reply-To domain is expected for the sender.", score: 16, source: "headers", category: "alignment", mitre_id: "T1566.002" })
  if (returnRoot && fromRoot && returnRoot !== fromRoot) addFinding(findings, { name: "Return-Path domain mismatch", severity: "Medium", evidence: `${fromRoot} -> ${returnRoot}`, why: "Return-Path mismatch can indicate third-party sending or spoofing.", action: "Compare envelope sender with known sender infrastructure.", score: 10, source: "headers", category: "alignment" })
  if (!headerAnalysis.fields.message_id && split.headers.trim()) addFinding(findings, { name: "Missing Message-ID", severity: "Low", evidence: "Message-ID header absent", why: "Normal mail commonly includes Message-ID.", action: "Review raw source and gateway metadata.", score: 4, source: "headers", category: "metadata" })
  if (headerAnalysis.fields.message_id && !/^<[^@\s]+@[^>\s]+>$/.test(headerAnalysis.fields.message_id)) addFinding(findings, { name: "Malformed Message-ID", severity: "Low", evidence: headerAnalysis.fields.message_id, why: "Malformed IDs can indicate unusual mail generation.", action: "Compare against gateway metadata.", score: 4, source: "headers", category: "metadata" })

  if (bodyAnalysis.themes.length) addFinding(findings, { name: "Social-engineering pressure", severity: "Medium", evidence: bodyAnalysis.themes.map((item) => `${item.theme}: ${item.matches.join(", ")}`).join("; "), why: "Phishing commonly combines urgency, credential, payment, delivery, or HR lures.", action: "Validate business context and user intent.", score: Math.min(24, bodyAnalysis.themes.length * 7), source: "body", category: "language", mitre_id: "T1566.001" })
  if (bodyAnalysis.mismatched_links.length) addFinding(findings, { name: "Visible link and href mismatch", severity: "High", evidence: `${bodyAnalysis.mismatched_links.length} mismatched HTML link(s)`, why: "Visible link text pointing elsewhere is a strong deception pattern.", action: "Review link destinations through Safe URL Analyzer only.", score: 20, source: "body", category: "link_deception", mitre_id: "T1566.002" })
  if (bodyAnalysis.obfuscation) addFinding(findings, { name: "Defanged/encoded content", severity: "Medium", evidence: "Defang or encoding markers observed", why: "Obfuscation can hide link destination or payload details.", action: "Decode safely in CyberChef; do not browse directly.", score: 8, source: "body", category: "obfuscation" })
  if (bodyAnalysis.has_html && bodyAnalysis.html_only_no_text) addFinding(findings, { name: "HTML-only email with no visible text", severity: "Medium", evidence: "HTML content without readable plain text", why: "HTML-only emails with hidden text can be used to bypass text-based filters.", action: "Inspect the HTML source for hidden text or obfuscated content.", score: 10, source: "body", category: "html_structure" })
  if (bodyAnalysis.forms_detected.length) {
    for (const form of bodyAnalysis.forms_detected.slice(0, 3)) {
      addFinding(findings, { name: "Form in email body", severity: "High", evidence: `Form submits to ${form.action_domain}`, why: "Legitimate organizations do not embed login forms in email.", action: "Do not interact with the form; it is likely credential harvesting.", score: 22, source: "body", category: "credential_harvesting", mitre_id: "T1566.001" })
    }
  }
  if (bodyAnalysis.tracking_images.length) addFinding(findings, { name: "Tracking pixels detected", severity: "Low", evidence: `${bodyAnalysis.tracking_images.length} tracking image(s)`, why: "Sender can know you opened the email via remote image loading.", action: "Review raw HTML; disable remote image loading by default.", score: 4, source: "body", category: "privacy" })
  if (bodyAnalysis.zero_width_chars.length) addFinding(findings, { name: "Zero-width Unicode characters detected", severity: "Medium", evidence: `Found zero-width chars: ${bodyAnalysis.zero_width_chars.join(", ")}`, why: "Zero-width characters can hide text from scanners.", action: "Inspect the email source for hidden Unicode characters.", score: 8, source: "body", category: "obfuscation" })
  const urgencyCtaSignals = detectSocialEngineeringCta(split.body)
  if (urgencyCtaSignals.length) {
    const maxSeverity = urgencyCtaSignals.reduce((best, item) => item.severity === "Critical" || (best === "Critical") ? "Critical" : item.severity === "High" || best === "High" ? "High" : "Medium", urgencyCtaSignals[0].severity)
    addFinding(findings, { name: `Social-engineering CTA: ${urgencyCtaSignals.map((item) => item.label).join(", ")}`, severity: maxSeverity, evidence: urgencyCtaSignals.map((item) => item.label).join(", "), why: "CTA language pushes the recipient toward immediate action without critical evaluation.", action: "Derive the expected action from the CTA and validate it against business process.", score: urgencyCtaSignals.some((item) => item.severity === "Critical") ? 22 : maxSeverity === "High" ? 16 : 8, source: "body", category: "language", mitre_id: "T1566.001" })
  }
  if (bodyAnalysis.brand_impersonation.length) {
    for (const bi of bodyAnalysis.brand_impersonation.slice(0, 5)) {
      addFinding(findings, { name: "Brand impersonation", severity: "High", evidence: `Text mentions "${bi.brand}" but links to ${bi.actual_domain}`, why: "Brand mentioned in text links to an unrelated domain.", action: "Verify domain ownership; do not click.", score: 22, source: "body", category: "brand_impersonation", mitre_id: "T1566.002" })
    }
  }
  if (bodyAnalysis.mentioned_brands.length) {
    const brandRoots = BRAND_PROFILES.filter((brand) => bodyAnalysis.mentioned_brands.includes(brand.name)).flatMap((brand) => brand.roots)
    const hasLegitRoot = [fromRoot, ...urlDomains.map((item) => item.normalized)].some((domain) => brandRoots.includes(domain))
    if (!hasLegitRoot) addFinding(findings, { name: "Brand mentioned without matching sender/link domain", severity: "High", evidence: bodyAnalysis.mentioned_brands.join(", "), why: "Brand lures on unrelated domains are common in credential phishing.", action: "Verify sender/domain ownership before trusting the email.", score: 20, source: "correlation", category: "brand_impersonation", mitre_id: "T1566.002" })
  }

  urls.forEach((url) => url.signals.forEach((signal) => addFinding(findings, { name: signal.label, severity: signal.severity, evidence: url.normalized, why: "URL structure contains a deterministic review signal.", action: "Pivot on URL/root domain in logs and Safe URL Analyzer.", score: signal.score, source: "url", category: "url" })))
  attachments.forEach((attachment) => attachment.signals.forEach((signal) => addFinding(findings, { name: "Attachment indicator", severity: signal.includes("HTML") || signal.includes("Macro") || signal.includes("Suspicious") ? "High" : "Medium", evidence: `${attachment.filename}: ${signal}`, why: "Attachment references can lead to credential capture or payload delivery.", action: "Route to Attachment Triage; do not execute.", score: 16, source: "attachment", category: "attachment" })))

  mapFindingsToMitre(findings)

  const alignment = {
    from_domain: fromDomain,
    reply_to_domain: headerAnalysis.fields.domains.reply_to,
    return_path_domain: headerAnalysis.fields.domains.return_path,
    url_domains: urlDomains,
    mismatches: [
      replyRoot && fromRoot && replyRoot !== fromRoot ? `Reply-To ${replyRoot} differs from From ${fromRoot}` : null,
      returnRoot && fromRoot && returnRoot !== fromRoot ? `Return-Path ${returnRoot} differs from From ${fromRoot}` : null,
      ...urlDomains.filter((item) => fromRoot && item.normalized !== fromRoot).map((item) => `URL domain ${item.normalized} differs from From ${fromRoot}`),
    ].filter(Boolean),
  }

  const risk = buildRisk(findings, {
    headersPresent: Boolean(split.headers.trim()),
    bodyPresent: Boolean(split.body.trim()),
    authPresent: Boolean(headerAnalysis.fields.authentication_results.length || headerAnalysis.fields.received_spf.length),
    urlMetadataCount: 0,
  })

  const partial = {
    source: "local_browser",
    method: "phishing_triage_local_plus_guarded_url_metadata",
    split,
    headers: headerAnalysis.fields,
    raw_headers: headerAnalysis.headers,
    body: bodyAnalysis,
    urls,
    sender_alignment: alignment,
    attachments,
    iocs: {
      urls,
      domains: urlDomains,
      ips: iocsRaw.ips,
      emails: iocsRaw.emails,
      hashes: iocsRaw.hashes,
    },
    findings,
    url_enrichment: [],
    risk,
  }
  const attackType = determineAttackType(partial)
  const decision = {
    attack_type: attackType,
    disposition: determineDisposition(risk, attackType),
    primary_concern: risk.top_evidence[0]?.name || "No strong signal detected locally",
    next_action: bestNextAction(partial),
    reliability: `Evidence strength is ${risk.confidence.toLowerCase()} because the analysis used ${risk.independent_sources || 1} independent local evidence source(s).`,
  }
  const result = {
    ...partial,
    decision,
    evidence_chain: buildEvidenceChain(partial),
    guidance: buildGuidance(partial),
    hunting_queries: buildHuntingQueries(partial),
    classification: {
      primary_type: split.headers.trim() ? "Email / Phishing" : "Body-only suspicious content",
      confidence_label: risk.confidence,
      limitations: [
        "No attachment execution, JavaScript rendering, credential submission, or automatic file download was performed.",
        "Vendor reputation and user-click telemetry are not included unless reviewed separately.",
      ],
    },
  }
  const computedRisk = computeRiskScore(result)
  result.risk.score = computedRisk.score
  result.risk.level = computedRisk.level
  result.risk.breakdown = computedRisk.breakdown
  result.risk.confidence = computedRisk.confidence
  result.professional = generateProfessionalReport(result)
  return { ...result, markdown: buildReport(result) }
}

export function mergeUrlMetadata(baseResult, urlResults = []) {
  if (!baseResult) return baseResult
  const findings = [...baseResult.findings]
  const enrichment = urlResults.filter(Boolean).map((item) => {
    const staticSignals = item.static_result?.risk_signals || []
    const liveSignals = item.live_result?.risk_signals || []
    const signals = [...staticSignals, ...liveSignals]
    return {
      original_url: item.input?.normalized || item.input?.refanged || item.input?.original || "",
      final_url: item.live_result?.final_url || item.input?.normalized || "",
      final_host: item.live_result?.final_host || item.static_result?.host || "",
      verdict: item.verdict,
      confidence: item.confidence,
      title: item.live_result?.page_title || "",
      status: item.live_result?.redirect_chain?.at(-1)?.status_code || "",
      content_type: item.live_result?.headers?.["content-type"] || "",
      server: item.live_result?.headers?.server || "",
      blocked_reason: item.live_result?.blocked_reason || null,
      signals,
      analysis: item.analysis || {},
      raw: item,
    }
  })

  enrichment.forEach((item) => {
    if (item.blocked_reason) addFinding(findings, { name: "URL metadata probe blocked", severity: "High", evidence: item.blocked_reason, why: "The link resolved to a destination blocked by the safety model.", action: "Do not retry unless internal assessment is approved.", score: 18, source: "safe_fetch", category: "url_metadata" })
    if (item.verdict === "suspicious") addFinding(findings, { name: "Destination metadata increased URL risk", severity: "High", evidence: `${item.final_host || item.original_url}: ${item.analysis?.category || "suspicious URL evidence"}`, why: "Guarded metadata observed risk signals beyond simple text parsing.", action: "Pivot original and final hosts in DNS/proxy/mail logs.", score: 18, source: "safe_fetch", category: "url_metadata" })
    if (item.title && /(download|verify|password|account|sign in|login|grand theft|free|invoice|payment)/i.test(item.title)) addFinding(findings, { name: "Lure-like page title observed", severity: "Medium", evidence: item.title, why: "Limited title extraction suggests the destination page theme may match a lure.", action: "Capture title as metadata evidence; do not browse directly.", score: 10, source: "safe_fetch", category: "url_metadata" })
    const redirectChanged = item.raw?.analysis?.strongest_evidence?.some((signal) => signal.id === "redirect_domain_change")
    if (redirectChanged) addFinding(findings, { name: "Redirect destination changed root domain", severity: "Medium", evidence: item.final_url, why: "Redirects can hide the true landing page behind a benign-looking or shortened link.", action: "Pivot both original and final root domains.", score: 10, source: "safe_fetch", category: "url_metadata" })
  })

  const risk = buildRisk(findings, {
    headersPresent: Boolean(baseResult.split.headers.trim()),
    bodyPresent: Boolean(baseResult.split.body.trim()),
    authPresent: Boolean(baseResult.headers.authentication_results.length || baseResult.headers.received_spf.length),
    urlMetadataCount: enrichment.length,
  })
  const enriched = { ...baseResult, findings, url_enrichment: enrichment, risk }
  const attackType = determineAttackType(enriched)
  const decision = {
    attack_type: attackType,
    disposition: determineDisposition(risk, attackType),
    primary_concern: risk.top_evidence[0]?.name || baseResult.decision.primary_concern,
    next_action: bestNextAction(enriched),
    reliability: `Evidence strength is ${risk.confidence.toLowerCase()} because the triage used local email evidence${enrichment.length ? ` plus guarded metadata for ${enrichment.length} URL(s)` : ""}.`,
  }
  const result = {
    ...enriched,
    decision,
    evidence_chain: buildEvidenceChain(enriched),
    guidance: buildGuidance(enriched),
    hunting_queries: buildHuntingQueries(enriched),
  }
  result.professional = buildProfessionalAssessment(result)
  return { ...result, markdown: buildReport(result) }
}
