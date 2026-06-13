import { useMemo, useRef, useState } from "react"
import {
  ChefHat,
  Clipboard,
  Database,
  Download,
  ExternalLink,
  FileSearch,
  FileText,
  ShieldAlert,
  ShieldCheck,
  Upload,
} from "lucide-react"
import SendToActions from "../../components/investigation/SendToActions"
import AnalystOutputCard from "../../components/investigation/AnalystOutputCard"
import { WorkbenchHeader, WorkbenchPage, WorkbenchPanel } from "../../components/layout/WorkbenchShell"
import { addTimelineArtifact } from "../../lib/timelineStore"
import { downloadText, normalizeHash } from "../../lib/domUtils.js"

const HASH_ALGOS = ["MD5", "SHA1", "SHA256", "SHA384", "SHA512"]
const SUBTLE_ALGOS = { SHA1: "SHA-1", SHA256: "SHA-256", SHA384: "SHA-384", SHA512: "SHA-512" }
const SUSPICIOUS_EXTENSIONS = new Set(["exe", "scr", "js", "vbs", "jar", "hta", "ps1", "bat", "cmd", "lnk"])
const EXECUTABLE_EXTENSIONS = new Set(["exe", "dll", "scr", "com", "msi"])
const SCRIPT_EXTENSIONS = new Set(["js", "vbs", "hta", "ps1", "bat", "cmd", "wsf", "wsh"])
const MACRO_EXTENSIONS = new Set(["docm", "xlsm", "pptm"])
const ARCHIVE_EXTENSIONS = new Set(["zip", "rar", "7z", "iso", "img"])
const COMMAND_TERMS = ["powershell", "cmd.exe", "wscript", "cscript", "mshta", "rundll32", "regsvr32", "certutil", "bitsadmin", "curl", "wget", "encodedcommand"]
const OFFICE_TERMS = ["AutoOpen", "Document_Open", "CreateObject", "WScript", "Shell", "PowerShell"]
const PDF_TERMS = ["/JavaScript", "/OpenAction", "/AA", "/Launch", "/EmbeddedFile"]
const API_TERMS = ["VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread", "WinExec", "ShellExecute", "GetProcAddress", "LoadLibrary"]
const STATIC_RULES = [
  { name: "PowerShell download cradle", severity: "High", category: "Static Rule", pattern: /(?:IEX|Invoke-Expression|DownloadString|Net\.WebClient|Invoke-WebRequest)/i, action: "Send the command/string to SOC Guide or CyberChef for decoding and behavior review." },
  { name: "Office macro auto-execution", severity: "High", category: "Static Rule", pattern: /(?:AutoOpen|Document_Open|Workbook_Open|CreateObject\("?WScript\.Shell)/i, action: "Review macro streams statically. Do not enable macros." },
  { name: "PE injection-style API cluster", severity: "Medium", category: "Static Rule", pattern: /(?=.*VirtualAlloc)(?=.*WriteProcessMemory|.*CreateRemoteThread|.*LoadLibrary)/is, action: "Treat as a PE/malware-analysis pivot and validate imports/sections statically." },
  { name: "HTML credential harvester", severity: "High", category: "Static Rule", pattern: /<form[\s\S]{0,800}(?:password|login|signin|credential)/i, action: "Route form action URL to Safe URL Analyzer and Phishing Triage." },
  { name: "PDF launch or embedded file behavior", severity: "High", category: "Static Rule", pattern: /\/(?:OpenAction|Launch|EmbeddedFile|JavaScript|AA)\b/i, action: "Inspect PDF structure with static tooling before opening." },
]

const SAMPLE_TEXT = [
  "Filename: Microsoft_Account_Verification.html",
  "<html><body>",
  "<h1>Microsoft 365 account verification required</h1>",
  '<form action="hxxps://login-microsoft-security[.]example/submit" method="post">',
  '<input type="email" name="user">',
  '<input type="password" name="password">',
  '<input type="hidden" name="session" value="ab92kdsk_live_token_7788">',
  "</form>",
  '<script>window.location="http://198.51.100.23/account/reset"; document.cookie="sessionid=abc123";</script>',
  "</body></html>",
].join("\n")

function bytesToHex(bytes) {
  return [...new Uint8Array(bytes)].map((byte) => byte.toString(16).padStart(2, "0")).join("")
}

function rotateLeft(value, shift) {
  return (value << shift) | (value >>> (32 - shift))
}

function md5Bytes(inputBytes) {
  const bytes = inputBytes instanceof Uint8Array ? inputBytes : new Uint8Array(inputBytes)
  const bitLength = bytes.length * 8
  const paddedLength = (((bytes.length + 8) >> 6) + 1) * 64
  const padded = new Uint8Array(paddedLength)
  padded.set(bytes)
  padded[bytes.length] = 0x80
  const view = new DataView(padded.buffer)
  view.setUint32(paddedLength - 8, bitLength, true)
  view.setUint32(paddedLength - 4, Math.floor(bitLength / 0x100000000), true)

  let a0 = 0x67452301
  let b0 = 0xefcdab89
  let c0 = 0x98badcfe
  let d0 = 0x10325476
  const s = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21]
  const k = Array.from({ length: 64 }, (_, i) => Math.floor(Math.abs(Math.sin(i + 1)) * 0x100000000))

  for (let offset = 0; offset < paddedLength; offset += 64) {
    const m = Array.from({ length: 16 }, (_, i) => view.getUint32(offset + i * 4, true))
    let a = a0; let b = b0; let c = c0; let d = d0
    for (let i = 0; i < 64; i += 1) {
      let f; let g
      if (i < 16) { f = (b & c) | (~b & d); g = i }
      else if (i < 32) { f = (d & b) | (~d & c); g = (5 * i + 1) % 16 }
      else if (i < 48) { f = b ^ c ^ d; g = (3 * i + 5) % 16 }
      else { f = c ^ (b | ~d); g = (7 * i) % 16 }
      const temp = d
      d = c
      c = b
      b = (b + rotateLeft((a + f + k[i] + m[g]) >>> 0, s[i])) >>> 0
      a = temp
    }
    a0 = (a0 + a) >>> 0
    b0 = (b0 + b) >>> 0
    c0 = (c0 + c) >>> 0
    d0 = (d0 + d) >>> 0
  }
  const out = new ArrayBuffer(16)
  const outView = new DataView(out)
  ;[a0, b0, c0, d0].forEach((word, index) => outView.setUint32(index * 4, word, true))
  return bytesToHex(out)
}

function md5(input) {
  return md5Bytes(new TextEncoder().encode(input))
}

async function digestText(text, algo) {
  if (algo === "MD5") return md5(text)
  const bytes = new TextEncoder().encode(text)
  const digest = await crypto.subtle.digest(SUBTLE_ALGOS[algo], bytes)
  return bytesToHex(digest)
}

async function digestBuffer(buffer, algo) {
  if (algo === "MD5") return md5Bytes(new Uint8Array(buffer))
  const digest = await crypto.subtle.digest(SUBTLE_ALGOS[algo], buffer)
  return bytesToHex(digest)
}

function identifyHashValue(value) {
  const raw = value.trim()
  const clean = normalizeHash(raw)
  if (!raw) return null
  if (/^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{20,}$/.test(raw)) return { input: raw, normalized: raw, type: "bcrypt", confidence: raw.length >= 55 ? "High" : "Medium", reason: "bcrypt prefix and cost format." }
  if (/^\$argon2(?:id|i|d)\$/.test(raw)) return { input: raw, normalized: raw, type: "Argon2", confidence: "High", reason: "Argon2 modular crypt prefix." }
  if (/^\$1\$/.test(raw)) return { input: raw, normalized: raw, type: "Unix md5crypt", confidence: "High", reason: "$1$ Unix crypt prefix." }
  if (/^\$5\$/.test(raw)) return { input: raw, normalized: raw, type: "Unix sha256crypt", confidence: "High", reason: "$5$ Unix crypt prefix." }
  if (/^\$6\$/.test(raw)) return { input: raw, normalized: raw, type: "Unix sha512crypt", confidence: "High", reason: "$6$ Unix crypt prefix." }
  if (/^pbkdf2/i.test(raw) || /^\$pbkdf2/.test(raw)) return { input: raw, normalized: raw, type: "PBKDF2-like", confidence: "Medium", reason: "PBKDF2-like prefix/format." }
  if (/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(raw)) return { input: raw, normalized: raw, type: "JWT/base64-looking", confidence: "Medium", reason: "Three base64url-looking segments." }
  if (!/^[a-f0-9]+$/i.test(clean)) return { input: raw, normalized: raw, type: "unknown/invalid", confidence: "Low", reason: "Value is not a recognized hash format." }
  const lengths = { 32: "MD5 or NTLM-like", 40: "SHA1", 56: "SHA224", 64: "SHA256", 96: "SHA384", 128: "SHA512" }
  return {
    input: raw,
    normalized: clean,
    type: lengths[clean.length] || "unknown hex",
    confidence: lengths[clean.length] ? (clean.length === 32 ? "Medium" : "High") : "Low",
    reason: lengths[clean.length] ? `${clean.length} hex characters.` : `${clean.length} hex characters does not match a common raw hash length.`,
  }
}

function extensionOf(name = "") {
  return name.toLowerCase().split(".").pop() || ""
}

function magicType(hex = "") {
  if (hex.startsWith("4d5a")) return "Windows PE executable"
  if (hex.startsWith("25504446")) return "PDF"
  if (hex.startsWith("504b0304")) return "ZIP/Office archive"
  if (hex.startsWith("7f454c46")) return "ELF executable"
  if (hex.startsWith("52617221")) return "RAR archive"
  if (hex.startsWith("377abcaf271c")) return "7z archive"
  if (hex.startsWith("d0cf11e0")) return "Legacy Office/OLE"
  return "Unknown/Plain text"
}

function entropy(bytes = new Uint8Array()) {
  if (!bytes.length) return 0
  const counts = new Array(256).fill(0)
  bytes.forEach((byte) => { counts[byte] += 1 })
  return counts.reduce((sum, count) => {
    if (!count) return sum
    const p = count / bytes.length
    return sum - p * Math.log2(p)
  }, 0)
}

function extractStringsFromBytes(bytes) {
  const chunks = []
  let current = ""
  for (const byte of bytes) {
    if (byte >= 32 && byte <= 126) current += String.fromCharCode(byte)
    else {
      if (current.length >= 4) chunks.push(current)
      current = ""
    }
  }
  if (current.length >= 4) chunks.push(current)
  return chunks.slice(0, 2000)
}

function extractIocs(text = "") {
  const refangedText = text.replace(/hxxps?:\/\//gi, (value) => value.toLowerCase().startsWith("hxxps") ? "https://" : "http://").replace(/\[\.\]/g, ".")
  const urls = [...new Set(refangedText.match(/\bhttps?:\/\/[^\s"'<>]+/gi) || [])]
  const defangedUrls = [...new Set(text.match(/\bhxxps?:\/\/[^\s"'<>]+|\bhttps?:\/\/[^\s"'<>]*\[\.\][^\s"'<>]*/gi) || [])]
  const ips = [...new Set(text.match(/\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b/g) || [])]
  const emails = [...new Set(text.match(/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi) || [])]
  const hashes = [...new Set(text.match(/\b[a-f0-9]{32}\b|\b[a-f0-9]{40}\b|\b[a-f0-9]{64}\b/gi) || [])]
  const domains = [...new Set([
    ...urls.map((url) => { try { return new URL(url).hostname } catch { return "" } }),
    ...(refangedText.match(/\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b/gi) || []),
  ].filter(Boolean).map((item) => item.toLowerCase()))]
  const filePaths = [...new Set(text.match(/[A-Za-z]:\\[^\r\n"'<>|]+|\/(?:usr|tmp|var|home|etc)\/[^\s"'<>]+/g) || [])]
  const registryPaths = [...new Set(text.match(/HK(?:LM|CU|CR|U|CC)\\[^\r\n"']+/gi) || [])]
  const paths = [...new Set(urls.map((url) => { try { return new URL(url).pathname } catch { return "" } }).filter((item) => item && item !== "/"))]
  const fileNames = [...new Set(text.match(/\b[\w .-]+\.(?:html?|js|vbs|hta|ps1|bat|cmd|exe|scr|lnk|zip|rar|7z|docm|xlsm|pdf)\b/gi) || [])].map((item) => item.trim())
  const formActions = [...new Set([...text.matchAll(/<form[^>]+action=["']?([^"'\s>]+)/gi)].map((match) => match[1].replace(/^hxxp/i, "http").replace(/\[\.\]/g, ".")))]
  const redirects = [...new Set([...text.matchAll(/(?:location|href|url)\s*=\s*["']?([^"'\s;>]+)/gi)].map((match) => match[1].replace(/^hxxp/i, "http").replace(/\[\.\]/g, ".")))]
  const base64Blobs = [...new Set(text.match(/\b[A-Za-z0-9+/]{40,}={0,2}\b/g) || [])].slice(0, 20)
  return { urls, defanged_urls: defangedUrls, domains, ips, emails, hashes, file_names: fileNames, paths, form_actions: formActions, redirects, file_paths: filePaths, registry_paths: registryPaths, base64_blobs: base64Blobs }
}

function containsWordish(text, term) {
  const escaped = term.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")
  return new RegExp(`(?:^|[^A-Za-z0-9_])${escaped}(?:$|[^A-Za-z0-9_])`, "i").test(text)
}

function finding(title, category, severity, evidence, why, action, limitation = "Local static signal; analyst review required.") {
  return { title, category, severity, evidence: String(evidence || "N/A"), why, recommended_action: action, limitation }
}

function severityClass(severity = "") {
  if (["Critical", "High"].includes(severity)) return "ba-status-danger"
  if (severity === "Medium") return "ba-status-warning"
  if (severity === "Low") return "ba-status-info"
  return "ba-status-local"
}

function analyzeStatic({ fileMeta, stringsText, entropyValue }) {
  const findings = []
  const ext = fileMeta?.extension || ""
  const filename = fileMeta?.name || ""
  const lower = stringsText.toLowerCase()
  const iocs = extractIocs(stringsText)
  if (SUSPICIOUS_EXTENSIONS.has(ext)) findings.push(finding("Suspicious attachment extension", "Static File", "High", filename, "Script, shortcut, or executable extensions are higher-risk in email/file triage.", "Do not execute. Preserve and escalate for static analysis."))
  if (EXECUTABLE_EXTENSIONS.has(ext)) findings.push(finding("Executable attachment", "Static File", "High", filename, "Executable attachments can run code if opened.", "Keep isolated and validate delivery/source context."))
  if (SCRIPT_EXTENSIONS.has(ext)) findings.push(finding("Script attachment", "Static File", "High", filename, "Script files can execute commands or download content.", "Review strings and route command text to CyberChef."))
  if (MACRO_EXTENSIONS.has(ext)) findings.push(finding("Macro-enabled Office document", "Static File", "High", filename, "Macro-enabled Office files can contain VBA execution logic.", "Do not open with macros enabled. Review in a safe static workflow."))
  if (ARCHIVE_EXTENSIONS.has(ext)) findings.push(finding("Archive or disk image attachment", "Static File", "Medium", filename, "Archives and disk images can hide nested payloads.", "Inspect contents with safe tooling before opening."))
  if (ext === "lnk") findings.push(finding("Windows shortcut attachment", "Static File", "High", filename, "Shortcut files can launch commands or remote resources.", "Extract shortcut metadata statically."))
  if ((filename.match(/\./g) || []).length >= 2) findings.push(finding("Double extension pattern", "Static File", "Medium", filename, "Double extensions can disguise file type.", "Compare extension, MIME guess, and magic bytes."))
  if (fileMeta?.magic_type && fileMeta.magic_type !== "Unknown/Plain text" && ext && !fileMeta.magic_type.toLowerCase().includes(ext) && !(fileMeta.magic_type.includes("ZIP") && ["zip", "docx", "xlsx", "pptx", "docm", "xlsm", "pptm"].includes(ext))) {
    findings.push(finding("Extension and magic mismatch needs review", "Static File", "Medium", `${ext} vs ${fileMeta.magic_type}`, "Mismatch can indicate renaming or container formats.", "Validate file type with multiple static indicators."))
  }
  if (entropyValue >= 7.2) findings.push(finding("High entropy", "Entropy", "Medium", entropyValue.toFixed(2), "High entropy can indicate compression, encryption, packing, or normal binary data.", "Review file type and strings before drawing conclusions."))
  if (entropyValue > 0 && entropyValue < 3.2) findings.push(finding("Low entropy", "Entropy", "Info", entropyValue.toFixed(2), "Low entropy often appears in plain or structured content.", "Review extracted strings and metadata."))

  PDF_TERMS.filter((term) => stringsText.includes(term)).forEach((term) => findings.push(finding("PDF active content indicator", "Static Strings", "High", term, "PDF actions can trigger scripting, launches, or embedded file behavior.", "Review PDF structure statically; do not open interactively.")))
  OFFICE_TERMS.filter((term) => containsWordish(stringsText, term)).forEach((term) => findings.push(finding("Office/VBA-like string", "Static Strings", "Medium", term, "VBA automation terms can indicate macro behavior.", "Review macro streams with static tooling if present.")))
  COMMAND_TERMS.filter((term) => stringsText.toLowerCase().includes(term.toLowerCase())).forEach((term) => findings.push(finding("Suspicious command keyword", "Static Strings", term === "encodedcommand" ? "High" : "Medium", term, "Command keywords can indicate script or LOLBin behavior.", "Send command text to CyberChef and review behavior notes.")))
  API_TERMS.filter((term) => stringsText.includes(term)).forEach((term) => findings.push(finding("Suspicious Windows API string", "Static Strings", "Medium", term, "Process/memory API strings can appear in tooling or malware.", "Correlate with file type, imports, and context.")))
  STATIC_RULES.filter((rule) => rule.pattern.test(stringsText)).forEach((rule) => findings.push(finding(rule.name, rule.category, rule.severity, rule.pattern.toString(), "A local static malware/attachment rule matched this artifact content. This is a review signal, not a verdict.", rule.action)))
  if (/<form\b/i.test(stringsText) && /password/i.test(stringsText)) findings.push(finding("HTML credential form detected", "Credential Phishing", "High", "<form> with credential fields", "HTML forms that request credentials are common in credential-harvesting attachments.", "Review form action and route extracted URLs/domains to Recon & Exposure."))
  if (/<input[^>]+type=["']?password/i.test(stringsText)) findings.push(finding("Password input field detected", "Credential Phishing", "High", "input type=password", "Password collection inside an attachment is a high-risk phishing signal.", "Preserve evidence and escalate if delivered by email."))
  if (iocs.form_actions.length) findings.push(finding("External form action URL detected", "Credential Phishing", "High", iocs.form_actions.join(", "), "Submitted credentials may be sent to an external endpoint.", "Do not submit data. Pivot destination in Recon & Exposure."))
  if (/microsoft|office\s*365|m365|account verification|verify your account/i.test(stringsText)) findings.push(finding("Microsoft 365 impersonation wording", "Social Engineering", "Medium", "Microsoft/account verification wording", "Brand/account verification wording can support credential-harvest lures.", "Compare sender and landing page ownership before disposition."))
  if (iocs.urls.some((url) => { try { return /\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b/.test(new URL(url).hostname) } catch { return false } })) findings.push(finding("IP address used in redirect URL", "Network Indicator", "Medium", iocs.urls.filter((url) => /\d+\.\d+\.\d+\.\d+/.test(url)).join(", "), "IP-hosted redirects can indicate suspicious infrastructure or throwaway hosting.", "Pivot IP address in Recon & Exposure."))
  if (/cookie|session(?:id)?|csrf|auth[_-]?token/i.test(stringsText)) findings.push(finding("Cookie/session string detected", "Static Strings", "Medium", "cookie/session/token wording", "Session and token strings may indicate credential capture, tracking, or web workflow logic.", "Review exact context and avoid submitting credentials."))
  if (/\b(?:api[_-]?key|secret|token|session|password)[A-Za-z0-9_.:-]{8,}|\b[A-Za-z0-9_-]{24,}\b/.test(lower)) findings.push(finding("Secret-like token pattern detected", "Static Strings", "Medium", "secret/token-like string", "Secret-like values can be lures, embedded configuration, or accidental exposure.", "Redact in tickets unless needed as evidence."))
  if (iocs.defanged_urls.length || /\[\.\]|hxxps?:\/\//i.test(stringsText)) findings.push(finding("Defanged URL/domain detected", "IOCs", "Info", iocs.defanged_urls.join(", ") || "defang marker", "Defanged indicators are often copied from reports or triage notes.", "Refang only in local tools; do not browse automatically."))
  if (iocs.urls.length || iocs.domains.length || iocs.ips.length) findings.push(finding("Embedded network indicator", "IOCs", "Medium", [...iocs.urls, ...iocs.domains, ...iocs.ips].slice(0, 5).join(", "), "Embedded network observables can support phishing or malware pivots.", "Route URLs/domains/IPs to Recon & Exposure."))
  if (iocs.base64_blobs.length) findings.push(finding("Base64-looking blob", "Static Strings", "Low", `${iocs.base64_blobs.length} blob(s)`, "Encoded blobs may hide scripts, commands, or data.", "Decode only with safe local tools such as CyberChef."))
  return findings
}

function riskFromFindings(findings) {
  const weights = { Critical: 35, High: 18, Medium: 9, Low: 4, Info: 1 }
  const score = Math.min(100, findings.reduce((sum, item) => sum + (weights[item.severity] || 0), 0))
  const level = findings.some((item) => item.severity === "Critical") && score >= 85 ? "Critical" : score >= 60 ? "High" : score >= 30 ? "Medium" : "Low"
  return { score, level, note: "Static risk only. This is not a confirmed malware verdict." }
}

function buildReport(state) {
  const lines = [
    "# Attachment Static Triage Report",
    "",
    "## Executive Summary",
    state.summary,
    "",
    "## Input Summary",
    `- Static verdict: ${state.verdict}`,
    `- Static risk: ${state.risk.level} (${state.risk.score}/100)`,
    `- Input type: ${state.inputType}`,
    `- Likely type: ${state.likelyType}`,
    `- Safety mode: Static only`,
    "",
    "## Static Findings",
    ...(state.findings.length ? state.findings.map((item) => `- ${item.severity}: ${item.title} - ${item.evidence}`) : ["- No local static findings recorded."]),
    "",
    "## Extracted IOCs",
    `- URLs: ${state.iocs.urls.join(", ") || "None"}`,
    `- Defanged URLs: ${state.iocs.defanged_urls.join(", ") || "None"}`,
    `- Domains: ${state.iocs.domains.join(", ") || "None"}`,
    `- IPs: ${state.iocs.ips.join(", ") || "None"}`,
    `- Form actions: ${state.iocs.form_actions.join(", ") || "None"}`,
    `- Redirects: ${state.iocs.redirects.join(", ") || "None"}`,
    `- File names: ${state.iocs.file_names.join(", ") || "None"}`,
    "",
    "## Hash Summary",
    ...(Object.entries(state.fileHashes || {}).length ? Object.entries(state.fileHashes).map(([key, value]) => `- ${key}: ${value}`) : ["- No uploaded file hashes generated."]),
    ...(state.hashIds.length ? state.hashIds.map((item) => `- Pasted: ${item.input}: ${item.type} (${item.confidence} evidence)`) : ["- No pasted hashes identified."]),
    "",
    "## Recommended Actions",
    "- Preserve original attachment/hash and do not execute the file.",
    "- Route URLs, domains, and IPs to Recon & Exposure.",
    "- Add relevant indicators and top findings to the analyst report.",
    "- Correlate file name, hash, sender, and URL indicators across mailbox, EDR, proxy, and DNS logs.",
    "- Treat static risk as a review signal, not a confirmed malware verdict.",
    "",
    "## Limitations",
    "- No file execution, macro execution, detonation, upload, online cracking, reputation, or remote lookup was performed.",
    "- Static findings do not confirm malware. Analyst review is required.",
  ]
  return lines.join("\n")
}

function Field({ label, value, mono = false }) {
  if (value === undefined || value === null || value === "" || value === "N/A" || value === "None") return null
  return (
    <div className="rounded-xl border border-white/10 bg-black/40 p-3">
      <p className="text-[10px] font-black uppercase tracking-[0.14em] text-zinc-400">{label}</p>
      <p className={`mt-1 break-all text-sm text-zinc-100 ${mono ?"font-mono" : ""}`}>{value}</p>
    </div>
  )
}

function FindingCard({ item }) {
  return (
    <article className="rounded-xl border border-white/10 bg-black/40 p-3">
      <div className="mb-2 flex flex-wrap gap-2">
        <span className={`ba-chip ${severityClass(item.severity)}`}>{item.severity}</span>
        <span className="ba-chip ba-status-info">{item.category}</span>
      </div>
      <h3 className="font-bold text-zinc-100">{item.title}</h3>
      <p className="mt-1 break-all text-sm text-zinc-300">{item.evidence}</p>
      <p className="mt-2 text-xs text-zinc-400">{item.why}</p>
      <p className="mt-2 text-xs font-semibold text-cyan-100">{item.recommended_action}</p>
    </article>
  )
}

function countIocs(iocs = {}) {
  return ["urls", "defanged_urls", "domains", "ips", "emails", "hashes", "file_names", "paths", "form_actions", "redirects"].reduce((sum, key) => sum + (iocs[key]?.length || 0), 0)
}

function compactIocEntries(iocs = {}) {
  return [
    ["URLs", iocs.urls, true],
    ["Defanged URLs", iocs.defanged_urls, true],
    ["Domains", iocs.domains, true],
    ["IPs", iocs.ips, true],
    ["Emails", iocs.emails, false],
    ["Hashes", iocs.hashes, false],
    ["File names", iocs.file_names, false],
    ["Paths", iocs.paths, false],
    ["Form actions", iocs.form_actions, true],
    ["Redirects", iocs.redirects, true],
  ].filter(([, values]) => Array.isArray(values) && values.length > 0)
}

function compactSummaryParts(parts = []) {
  const filtered = parts.filter(Boolean)
  return filtered.length ? filtered.join(" · ") : "No extracted indicators"
}

function staticVerdict(risk) {
  if (risk.score >= 60) return "Suspicious"
  if (risk.score >= 30) return "Needs Review"
  return "Low Static Signal"
}

function likelyInputType(fileMeta, pastedText, hashInput) {
  if (fileMeta) return "Uploaded file"
  if (pastedText.trim()) return "Pasted attachment text"
  if (hashInput.trim()) return "Hash / filename check"
  return "No input"
}

function likelyStaticType(fileMeta, stringsText, findings) {
  const lower = stringsText.toLowerCase()
  if (findings.some((item) => item.title === "HTML credential form detected")) return "HTML credential phishing attachment"
  if (/<html|<script|<form|type=["']?password/i.test(stringsText)) return "HTML / script-like text"
  if (fileMeta?.magic_type && fileMeta.magic_type !== "Unknown/Plain text") return fileMeta.magic_type
  if (lower.includes("powershell") || lower.includes("encodedcommand")) return "Script or command text"
  return fileMeta ? "Unknown static file" : "Text/hash input"
}

function analystSummary({ findings, iocs, likelyType, risk }) {
  if (findings.some((item) => item.title === "HTML credential form detected")) {
    return "This pasted attachment text resembles an HTML credential-harvesting page using brand/account-verification wording, password fields, external submit or redirect URLs, and session/secret-like strings."
  }
  if (risk.score >= 60) return `Static analysis found high-risk signals in ${likelyType}. Review top evidence, extracted IOCs, and preserve the original artifact.`
  if (countIocs(iocs)) return `Static analysis extracted indicators from ${likelyType}. No external reputation was queried; analyst review is still required.`
  return "Static analysis did not identify high-risk local signals from the provided input. Review limitations and source context before closing."
}

function groupStrings(stringsText, iocs) {
  const lines = stringsText.split(/\r?\n/).map((line) => line.trim()).filter(Boolean)
  const matching = (regex) => [...new Set(lines.filter((line) => regex.test(line)).slice(0, 80))]
  return {
    "Credential terms": matching(/password|credential|login|verify|account|username|email/i),
    "Brand terms": matching(/microsoft|office\s*365|m365|onedrive|sharepoint|security/i),
    "Session / cookie / secret-like strings": matching(/cookie|session|token|secret|csrf|api[_-]?key|auth/i),
    "Network indicators": [...new Set([...iocs.urls, ...iocs.defanged_urls, ...iocs.domains, ...iocs.ips])],
    "Script indicators": matching(/<script|javascript|window\.location|document\.cookie|eval\(|atob\(/i),
    "HTML/form indicators": matching(/<form|<input|action=|method=|type=["']?password/i),
  }
}

function ReportSection({ title, children }) {
  return (
    <section className="rounded-xl border border-white/10 bg-black/40 p-3">
      <p className="text-xs font-black uppercase tracking-[0.14em] text-zinc-400">{title}</p>
      <div className="mt-2 text-sm leading-6 text-zinc-200">{children}</div>
    </section>
  )
}

function IocGroup({ title, values, actionLabel, onCopy, onRoute }) {
  if (!values?.length) return null
  return (
    <section className="rounded-xl border border-white/10 bg-black/40 p-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="font-bold text-zinc-100">{title} <span className="text-zinc-500">({values.length})</span></p>
        <div className="flex gap-2">
          <button className="ba-button-ghost rounded-lg px-2 py-1 text-xs font-bold" onClick={() => onCopy(values.join("\n"), title)}>Copy</button>
          {onRoute && <button className="ba-button-ghost rounded-lg px-2 py-1 text-xs font-bold" onClick={onRoute}>{actionLabel || "Send"}</button>}
        </div>
      </div>
      <div className="mt-2 flex flex-wrap gap-2">{values.length ? values.slice(0, 18).map((value) => <span key={`${title}-${value}`} className="break-all rounded-lg border border-white/10 bg-black/40 px-2 py-1 font-mono text-xs text-zinc-200">{value}</span>) : <span className="text-sm text-zinc-500">None</span>}</div>
    </section>
  )
}

export default function AttachmentTriagePage({ setPage }) {
  const PENDING_KEY = "beyondarch.pendingArtifact"
  const [initialArtifact] = useState(() => {
    try {
      const raw = localStorage.getItem(PENDING_KEY)
      if (!raw) return null
      const artifact = JSON.parse(raw)
      const value = artifact?.value ?? artifact?.content ?? artifact?.text ?? artifact?.raw_input ?? artifact?.filename ?? artifact?.name ?? artifact?.hash
      const isTargeted = artifact?.target === "attachment-triage" || artifact?.page === "attachment-triage"
      const acceptedSource = ["smart-parser", "phishing-triage", "safe-url-analyzer", "cyberchef", "detection-mitre", "logs-alerts", "attachment-triage"].includes(artifact?.source)
      const acceptedType = ["hash", "attachment", "attachment_text", "attachment-notes", "file_text", "file", "filename", "text", "html", "script", "mime", "strings", "url", "safe-url-finding", "command"].includes(artifact?.type)
      if (!value || (!isTargeted && !acceptedSource && !acceptedType)) return null
      localStorage.removeItem(PENDING_KEY)
      return { ...artifact, value: String(value) }
    } catch {
      return null
    }
  })
  const [fileMeta, setFileMeta] = useState(null)
  const [fileHashes, setFileHashes] = useState({})
  const [fileText, setFileText] = useState("")
  const [strings, setStrings] = useState([])
  const [entropyValue, setEntropyValue] = useState(0)
  const [pastedText, setPastedText] = useState(() => initialArtifact && initialArtifact.type !== "hash" && initialArtifact.type !== "filename" ? String(initialArtifact.value) : "")
  const [hashInput, setHashInput] = useState(() => ["hash", "filename"].includes(initialArtifact?.type) ? String(initialArtifact.value) : "")
  const [mode, setMode] = useState(() => ["hash", "filename"].includes(initialArtifact?.type) ? "hash" : initialArtifact ? "text" : "file")
  const [generatedHashes, setGeneratedHashes] = useState({})
  const [notice, setNotice] = useState(() => initialArtifact ? `Loaded ${initialArtifact.type || "artifact"} from ${initialArtifact.source || "another BeyondArch page"}.` : "")
  const [analyzed, setAnalyzed] = useState(false)
  const [inputOpen, setInputOpen] = useState(true)
  const [stringFilter, setStringFilter] = useState("Priority")
  const fileRef = useRef(null)

  const hashIds = useMemo(() => hashInput.split(/\r?\n|,/).map((item) => identifyHashValue(item)).filter(Boolean), [hashInput])
  const stringsText = `${fileText}\n${pastedText}\n${strings.join("\n")}`
  const iocs = useMemo(() => extractIocs(stringsText), [stringsText])
  const entropyNote = entropyValue >= 7.2 ? "High entropy can indicate compression, encryption, packing, or normal binary data." : entropyValue >= 4.2 ? "Medium entropy is common for normal binary or structured content." : entropyValue > 0 ? "Low entropy often indicates plain or structured text." : ""
  const findings = useMemo(() => analyzeStatic({ fileMeta, stringsText, entropyValue }), [fileMeta, stringsText, entropyValue])
  const risk = useMemo(() => riskFromFindings(findings), [findings])
  const inputType = likelyInputType(fileMeta, pastedText, hashInput)
  const likelyType = likelyStaticType(fileMeta, stringsText, findings)
  const verdict = staticVerdict(risk)
  const summary = analystSummary({ findings, iocs, likelyType, risk })
  const stringGroups = useMemo(() => groupStrings(stringsText, iocs), [stringsText, iocs])
  const visibleStringGroups = Object.entries(stringGroups).filter(([name, values]) => values.length > 0 && (stringFilter === "All" || name.toLowerCase().includes(stringFilter.toLowerCase()) || (stringFilter === "Priority" && /credential|brand|session|script|form|network/i.test(name))))
  const activeIocGroups = useMemo(() => compactIocEntries(iocs), [iocs])
  const allHashes = useMemo(() => {
    const values = [
      ...Object.entries(fileHashes).map(([algo, value]) => ({ algo, value, source: "uploaded file" })),
      ...Object.entries(generatedHashes).map(([algo, value]) => ({ algo, value, source: fileMeta ? "uploaded file" : "pasted attachment text" })),
      ...hashIds.filter((item) => !/unknown|invalid/i.test(item.type)).map((item) => ({ algo: item.type, value: item.normalized, source: "provided hash" })),
      ...(iocs.hashes || []).map((value) => ({ algo: identifyHashValue(value)?.type || "hash", value: normalizeHash(value), source: "extracted string" })),
    ]
    const seen = new Set()
    return values.filter((item) => item.value && !seen.has(item.value) && seen.add(item.value))
  }, [fileHashes, generatedHashes, hashIds, iocs.hashes, fileMeta])
  const iocText = ["urls", "defanged_urls", "domains", "ips", "emails", "hashes", "file_names", "paths", "form_actions", "redirects"].flatMap((key) => iocs[key] || []).join("\n")
  const reportState = { fileMeta, fileHashes, hashIds, generatedHashes, entropyValue, entropyNote, strings, iocs, findings, risk, verdict, inputType, likelyType, summary, source: "user_provided_attachment_or_hash", method: "local_static_analysis", checked_at: new Date().toISOString(), limitations: ["No execution, detonation, upload, online reputation, online cracking, credential stuffing, login attempts, exploit generation, or external lookup was performed."] }
  const markdown = buildReport(reportState)
  const topFindings = findings.slice(0, 6)
  const recommendedAction = findings.some((item) => item.title === "HTML credential form detected" || item.title === "Password input field detected")
    ? "Preserve the sample, avoid opening it interactively, pivot form-action domains, and search mailbox/proxy logs for matching delivery or clicks."
    : risk.score >= 60
      ? "Preserve the artifact and pivot hashes, filenames, URLs, domains, and sender context before blocking or escalating."
      : countIocs(iocs)
        ? "Review extracted indicators and pivot them in Recon, mailbox, DNS, proxy, or EDR logs."
        : "Keep as low static signal unless source context, delivery path, or user action indicates risk."
  const primaryConcern = topFindings[0]?.title || (allHashes.length ? "Hash-only artifact requires external/contextual verification" : "No high-value static signal observed")
  const loadedSummary = `${fileMeta ? fileMeta.name : likelyType} · ${compactSummaryParts([
    iocs.urls.length + iocs.defanged_urls.length ? `${iocs.urls.length + iocs.defanged_urls.length} URLs` : "",
    iocs.domains.length ? `${iocs.domains.length} domains` : "",
    iocs.ips.length ? `${iocs.ips.length} IPs` : "",
    allHashes.length ? `${allHashes.length} hashes` : "",
    iocs.file_names.length ? `${iocs.file_names.length} file names` : "",
  ])}`

  async function handleFile(file) {
    if (!file) return
    const buffer = await file.arrayBuffer()
    const bytes = new Uint8Array(buffer)
    const magic = bytesToHex(bytes.slice(0, 16))
    const text = new TextDecoder("latin1").decode(bytes.slice(0, Math.min(bytes.length, 2_000_000)))
    const extracted = extractStringsFromBytes(bytes)
    const hashes = {}
    for (const algo of HASH_ALGOS) hashes[algo] = await digestBuffer(buffer, algo)
    setFileMeta({
      name: file.name,
      extension: extensionOf(file.name),
      size: `${file.size.toLocaleString()} bytes`,
      mime: file.type || "browser did not provide MIME",
      magic,
      magic_type: magicType(magic),
      last_modified: file.lastModified ? new Date(file.lastModified).toISOString() : "",
    })
    setFileHashes(hashes)
    setFileText(text)
    setStrings(extracted)
    setEntropyValue(entropy(bytes))
    setAnalyzed(true)
    setInputOpen(false)
    setMode("file")
    setNotice("")
  }

  async function runAnalysis() {
    if (!fileMeta && !pastedText.trim() && !hashInput.trim()) {
      setNotice("Upload a file, paste attachment content, or enter a hash/filename before analysis.")
      return
    }
    if (!fileMeta && pastedText.trim()) {
      const hashes = {}
      for (const algo of ["MD5", "SHA1", "SHA256"]) hashes[algo] = await digestText(pastedText, algo)
      setGeneratedHashes(hashes)
    }
    setAnalyzed(true)
    setInputOpen(false)
    setNotice("")
  }

  async function copy(content, label) {
    if (!content) return
    await navigator.clipboard.writeText(content)
    setNotice(`${label} copied.`)
  }

  function storePendingArtifact(payload) {
    localStorage.setItem(PENDING_KEY, JSON.stringify({ ...payload, source: "attachment-triage", created_at: new Date().toISOString() }))
  }

  function sendToCyberChef(value, suggestedRecipe = ["extract-iocs"]) {
    if (!value) { setNotice("No value available to send to CyberChef."); return }
    storePendingArtifact({ type: "text", value, target: "cyberchef", suggested_recipe: suggestedRecipe })
    setPage?.("cyberchef")
  }

  function sendToRecon(value, type = "artifact") {
    if (!value) { setNotice("No indicator available to send to Recon."); return }
    storePendingArtifact({ type, value, target: "recon-exposure" })
    setPage?.("recon-exposure")
  }

  function sendToPage(page, payload) {
    if (!payload?.value && !payload?.content) { setNotice("No artifact available to send."); return }
    storePendingArtifact({ ...payload, target: page })
    setPage?.(page)
  }

  function routeIocGroup(title, value) {
    const lower = title.toLowerCase()
    if (lower.includes("url") || lower.includes("form") || lower.includes("redirect")) return sendToPage("safe-url-analyzer", { type: "url", value })
    if (lower.includes("domain")) return sendToRecon(value, "domain")
    if (lower.includes("ip")) return sendToRecon(value, "ip")
    if (lower.includes("hash")) return sendToPage("detection-mitre", { type: "hash", value, content: `Attachment hash indicator: ${value}` })
    if (lower.includes("email")) return sendToPage("phishing-triage", { type: "email", value })
    return sendToCyberChef(value, ["extract-iocs"])
  }

  function clearAll() {
    setFileMeta(null)
    setFileHashes({})
    setFileText("")
    setStrings([])
    setEntropyValue(0)
    setPastedText("")
    setHashInput("")
    setGeneratedHashes({})
    setAnalyzed(false)
    setInputOpen(true)
    setMode("file")
    setNotice("Workspace cleared.")
  }


  const firstUrl = [...iocs.urls, ...iocs.defanged_urls, ...iocs.form_actions, ...iocs.redirects].find(Boolean)
  const firstDomain = iocs.domains?.find(Boolean)
  const firstIp = iocs.ips?.find(Boolean)
  const firstHash = allHashes[0]?.value || iocs.hashes?.[0]
  const firstCommand = stringsText.split(/\r?\n/).find((line) => COMMAND_TERMS.some((term) => line.toLowerCase().includes(term.toLowerCase())))
  const looksCredentialAttachment = findings.some((item) => item.title === "HTML credential form detected" || item.title === "Password input field detected")
  const attachmentIdentityFields = [
    ["Filename", fileMeta?.name],
    ["Extension", fileMeta?.extension ? `.${fileMeta.extension}` : ""],
    ["Detected type", fileMeta?.magic_type],
    ["MIME", fileMeta?.mime],
    ["Size", fileMeta?.size],
    ["Entropy", entropyValue ? entropyValue.toFixed(3) : ""],
    ["Input", inputType],
    ["SHA256", fileHashes.SHA256 || generatedHashes.SHA256],
  ].filter(([, value]) => value && value !== "N/A")

  return (
    <WorkbenchPage className="ba-attachment-page">
      <WorkbenchHeader
        eyebrow="Attachment triage"
        title="Attachment Triage"
        subtitle="Inspect file names, hashes, strings, extensions, and risky metadata. Static/local review only — no execution or upload."
        icon={ChefHat}
        chips={[
          { label: "no execution", tone: "danger" },
          { label: "static analysis", tone: "info" },
          { label: "local only", tone: "local" },
        ]}
      />
      <WorkbenchPanel className="space-y-3">
        {analyzed && !inputOpen ? (
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <p className="text-xs font-black uppercase tracking-[0.14em] text-zinc-400">Attachment Triage</p>
              <h2 className="text-lg font-bold text-zinc-100">{loadedSummary}</h2>
              <p className="mt-1 text-sm text-zinc-300">Static/local review only. No execution, detonation, upload, or reputation lookup was performed.</p>
            </div>
            <div className="flex flex-wrap gap-2">
              <button className="ba-button-secondary rounded-xl px-3 py-2 text-sm font-bold" onClick={() => setInputOpen(true)}>Edit input</button>
              <button className="ba-button-secondary rounded-xl px-3 py-2 text-sm font-bold" onClick={runAnalysis}>Re-analyze</button>
              <button className="ba-button-secondary rounded-xl px-3 py-2 text-sm font-bold" onClick={clearAll}>Clear</button>
              {!!iocText && <button className="ba-button-secondary rounded-xl px-3 py-2 text-sm font-bold" onClick={() => copy(iocText, "Extracted IOCs")}>Copy IOCs</button>}
            </div>
          </div>
        ) : (
          <>
            <div className="flex flex-wrap items-end justify-between gap-3">
              <div>
                <p className="text-xs font-black uppercase tracking-[0.14em] text-cyan-300">Attachment Triage</p>
                <h2 className="text-xl font-black text-zinc-100">Static attachment review</h2>
                <p className="mt-1 text-sm text-zinc-300">Review files, pasted attachment bodies, hashes, filenames, strings, and MIME fragments without executing them.</p>
              </div>
              <div className="flex flex-wrap gap-2">
                <span className="ba-chip ba-status-local">NO EXECUTION</span>
                <span className="ba-chip ba-status-info">LOCAL ONLY</span>
                <span className="ba-chip ba-status-warning">STATIC SIGNALS</span>
              </div>
            </div>

            <section className="rounded-2xl border border-white/10 bg-black/40 p-4">
              <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_320px]">
                <div className="space-y-3">
                  <div className="flex flex-wrap gap-2">
                    {[
                      ["file", "File upload"],
                      ["text", "Pasted attachment / strings"],
                      ["hash", "Hash / filename check"],
                    ].map(([id, label]) => (
                      <button key={id} className={`ba-tab-button ${mode === id ? "is-active" : ""}`} onClick={() => setMode(id)}>{label}</button>
                    ))}
                  </div>

                  {mode === "file" && (
                    <div className="rounded-xl border border-white/10 bg-black/40 p-3">
                      <div className="flex flex-wrap items-center justify-between gap-3">
                        <div>
                          <p className="text-xs font-black uppercase tracking-[0.14em] text-zinc-400">File input</p>
                          <p className="mt-1 text-sm text-zinc-300">Upload is read locally in the browser for hashes, magic bytes, strings, and entropy.</p>
                        </div>
                        <button className="ba-button-primary rounded-xl px-3 py-2 text-sm font-bold" onClick={() => fileRef.current?.click()}><Upload className="mr-2 inline h-4 w-4" />Choose file</button>
                      </div>
                      {fileMeta ? <div className="mt-3 grid gap-2 sm:grid-cols-3"><Field label="Name" value={fileMeta.name} /><Field label="Detected type" value={`${fileMeta.magic_type} · .${fileMeta.extension || "unknown"}`} /><Field label="Size" value={fileMeta.size} /></div> : <p className="mt-3 text-sm text-zinc-400">No file selected. You can still paste notes, strings, filenames, hashes, or MIME snippets below.</p>}
                      <textarea value={pastedText} onChange={(event) => setPastedText(event.target.value)} placeholder="Optional notes, MIME headers, extracted strings, filename, or email context..." className="mt-3 min-h-36 w-full resize-y rounded-xl border border-white/10 bg-black/40 p-3 font-mono text-sm text-zinc-100 outline-none placeholder:text-zinc-600" />
                    </div>
                  )}

                  {mode === "text" && (
                    <textarea value={pastedText} onChange={(event) => setPastedText(event.target.value)} placeholder="Paste attachment HTML, script text, MIME body, extracted strings, commands, URLs, or file notes..." className="min-h-72 w-full resize-y rounded-xl border border-white/10 bg-black/40 p-4 font-mono text-sm text-zinc-100 outline-none placeholder:text-zinc-600" />
                  )}

                  {mode === "hash" && (
                    <textarea value={hashInput} onChange={(event) => setHashInput(event.target.value)} placeholder="Paste one or more hashes, filenames, or file indicators. Example: invoice.docm, setup.hta, 44d88612fea8a8f36de82e1278abb02f..." className="min-h-52 w-full resize-y rounded-xl border border-white/10 bg-black/40 p-4 font-mono text-sm text-zinc-100 outline-none placeholder:text-zinc-600" />
                  )}

                  <input ref={fileRef} type="file" className="hidden" onChange={(event) => { handleFile(event.target.files?.[0]); event.target.value = "" }} />
                </div>

                <aside className="space-y-3 rounded-xl border border-white/10 bg-black/40 p-3">
                  <div>
                    <p className="text-xs font-black uppercase tracking-[0.14em] text-zinc-400"><ShieldCheck size={13} className="inline mr-1" />Controls</p>
                    <p className="mt-1 text-sm text-zinc-300">Static triage only. Use pivots after review; do not open or execute unknown files.</p>
                  </div>
                  <button className="ba-button-primary w-full rounded-xl px-4 py-2 text-sm font-black" onClick={runAnalysis}>Analyze attachment</button>
                  <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-1">
                    <button className="ba-button-secondary rounded-xl px-3 py-2 text-sm font-bold" onClick={() => fileRef.current?.click()}><Upload className="mr-2 inline h-4 w-4" />Upload file</button>
                    <button className="ba-button-secondary rounded-xl px-3 py-2 text-sm font-bold" onClick={() => { setMode("text"); setPastedText(SAMPLE_TEXT); setHashInput(""); setNotice("Sample HTML attachment loaded.") }}><FileText className="mr-2 inline h-4 w-4" />Load sample</button>
                    <button className="ba-button-secondary rounded-xl px-3 py-2 text-sm font-bold" onClick={clearAll}>Clear</button>
                  </div>
                  <div className="grid gap-2">
                    <Field label="Input mode" value={mode === "file" ? "File upload" : mode === "hash" ? "Hash / filename" : "Pasted text"} />
                    <Field label="Current input" value={inputType} />
                    <Field label="Local hashes" value={fileHashes.SHA256 || generatedHashes.SHA256 ? "Available after analysis" : "Generated after analysis"} />
                  </div>
                </aside>
              </div>
            </section>
          </>
        )}
        {notice && <p className="ba-info-banner text-sm">{notice}</p>}
      </WorkbenchPanel>

      {analyzed && (
        <>
          <WorkbenchPanel className="space-y-4">
            <section className="rounded-2xl border border-white/10 bg-black/40 p-4">
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div>
                  <p className="text-xs font-black uppercase tracking-[0.14em] text-cyan-300"><ShieldAlert size={13} className="inline mr-1" />Attachment verdict</p>
                  <h2 className="mt-1 text-2xl font-black text-zinc-100">{verdict}</h2>
                  <p className="mt-2 max-w-5xl text-sm leading-6 text-zinc-200">{summary}</p>
                </div>
                <span className={`ba-chip ${severityClass(risk.level)}`}>Static review: {risk.level} concern</span>
              </div>

              <div className="mt-4 grid gap-3 lg:grid-cols-4">
                <Field label="Likely type" value={likelyType} />
                <Field label="Primary concern" value={primaryConcern} />
                <Field label="Best next action" value={recommendedAction} />
                <Field label="Boundary" value="Static review only" />
              </div>

              {!!attachmentIdentityFields.length && (
                <details className="mt-4 rounded-xl border border-white/10 bg-black/40 p-3">
                  <summary className="cursor-pointer text-sm font-bold text-zinc-100"><FileSearch size={14} className="inline mr-1" />Attachment identity and local metadata</summary>
                  <div className="mt-3 overflow-hidden rounded-xl border border-white/10">
                    <table className="w-full text-left text-sm">
                      <tbody className="divide-y divide-white/10">
                        {attachmentIdentityFields.map(([label, value]) => (
                          <tr key={label}>
                            <th className="w-44 bg-black/40 p-2 text-xs font-black uppercase tracking-[0.12em] text-zinc-400">{label}</th>
                            <td className="break-all p-2 font-mono text-zinc-100">{value}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </details>
              )}

              <div className="mt-4 flex flex-wrap gap-2">
                {!!firstUrl && <button className="ba-button-secondary rounded-xl px-3 py-2 text-sm font-bold" onClick={() => sendToPage("safe-url-analyzer", { type: "url", value: firstUrl })}>URL Analyzer</button>}
                {!!(firstDomain || firstIp) && <button className="ba-button-secondary rounded-xl px-3 py-2 text-sm font-bold" onClick={() => sendToRecon(firstDomain || firstIp, firstDomain ? "domain" : "ip")}>Recon pivot</button>}
                {!!firstCommand && <button className="ba-button-secondary rounded-xl px-3 py-2 text-sm font-bold" onClick={() => sendToPage("soc-guide", { type: "command", value: firstCommand })}>Explain command</button>}
                {!!stringsText.trim() && <button className="ba-button-secondary rounded-xl px-3 py-2 text-sm font-bold" onClick={() => sendToCyberChef(stringsText, ["extract-iocs"])}><ChefHat className="mr-2 inline h-4 w-4" />CyberChef</button>}
                {!!(firstHash || summary) && <button className="ba-button-secondary rounded-xl px-3 py-2 text-sm font-bold" onClick={() => sendToPage("detection-mitre", { type: "attachment-static-finding", value: firstHash || primaryConcern, content: markdown })}>Detection & MITRE</button>}
                {looksCredentialAttachment && <button className="ba-button-secondary rounded-xl px-3 py-2 text-sm font-bold" onClick={() => sendToPage("phishing-triage", { type: "attachment-notes", value: stringsText || markdown })}>Phishing Triage</button>}
                {!!iocText && <button className="ba-button-secondary rounded-xl px-3 py-2 text-sm font-bold" onClick={() => copy(iocText, "Extracted indicators")}>Copy IOCs</button>}
                <button className="ba-button-secondary rounded-xl px-3 py-2 text-sm font-bold" onClick={() => {
                  const entry = addTimelineArtifact({ title: `Attachment review: ${likelyType}`, summary: `${risk.level} concern · ${primaryConcern}`, source: "Attachment Triage", raw: markdown, tags: [risk.level, likelyType] })
                  setNotice(`Added to Case Timeline: ${entry.title}`)
                }}>Add to timeline</button>
              </div>

              <div className="mt-4">
                <SendToActions
                  source="Attachment Triage"
                  setPage={setPage}
                  payload={{
                    type: "attachment_static_review",
                    title: `Attachment review: ${likelyType}`,
                    value: firstHash || firstUrl || primaryConcern,
                    summary: `${risk.level} concern · ${summary}`,
                    raw: markdown,
                    tags: ["attachment", risk.level, likelyType, ...(allHashes.length ? ["hash"] : [])],
                    severity: risk.level,
                    confidence: "local-static",
                  }}
                />
              </div>

              <div className="mt-4">
                <AnalystOutputCard
                  title="Attachment output quality"
                  verdict={verdict}
                  confidence="local static review"
                  summary={summary}
                  evidence={topFindings.slice(0, 5).map((item) => `${item.title}: ${item.evidence}`)}
                  limitations={[risk.note, ...(reportState.limitations || [])]}
                  nextActions={[recommendedAction, "Preserve the original attachment/hash and do not execute it.", "Pivot extracted IOCs across mailbox, proxy, DNS, and endpoint logs."]}
                  metrics={[
                    ["Risk score", `${risk.score}/100`],
                    ["Findings", findings.length],
                    ["IOCs", Object.values(iocs).flat().length],
                  ]}
                />
              </div>

              <details className="mt-4 rounded-xl border border-white/10 bg-black/40 p-3">
                <summary className="cursor-pointer text-sm font-bold text-zinc-100">Review scoring details</summary>
                <div className="mt-3 grid gap-3 md:grid-cols-3">
                  <Field label="Static concern" value={risk.level} />
                  <Field label="Numeric review score" value={`${risk.score}/100`} />
                  <Field label="Limitation" value={risk.note} />
                </div>
              </details>
            </section>
          </WorkbenchPanel>

          <WorkbenchPanel className="space-y-3">
            <div className="ba-output-section-head">
              <div><p className="ba-output-section-eyebrow"><FileSearch size={14} className="inline mr-1" />Key evidence</p><h2 className="ba-output-section-title">Signals that matter first</h2></div>
              <span className={`ba-chip ${severityClass(risk.level)}`}>{findings.length} static findings</span>
            </div>
            {topFindings.length ? <div className="ba-output-grid ba-output-grid-2">{topFindings.map((item, index) => <FindingCard key={`${item.title}-${index}`} item={item} />)}</div> : <p className="ba-empty-state"><FileSearch size={16} className="inline mr-1 text-zinc-400" />No security-relevant local findings identified for this input.</p>}
            {findings.length > topFindings.length && <details className="rounded-xl border border-white/10 bg-black/40 p-3"><summary className="cursor-pointer text-sm font-bold text-zinc-100">Show all findings ({findings.length})</summary><div className="mt-3 ba-output-grid ba-output-grid-2">{findings.map((item, index) => <FindingCard key={`${item.title}-all-${index}`} item={item} />)}</div></details>}
          </WorkbenchPanel>

          {!!activeIocGroups.length && (
            <WorkbenchPanel className="space-y-3">
              <div className="ba-output-section-head"><div><p className="ba-output-section-eyebrow"><Database size={14} className="inline mr-1" />Extracted IOCs</p><h2 className="ba-output-section-title">Routeable indicators and relations</h2></div><button className="ba-button-secondary rounded-xl px-3 py-2 text-sm font-bold" onClick={() => copy(iocText, "All IOCs")}>Copy all</button></div>
              <div className="grid gap-3 md:grid-cols-2">
                {activeIocGroups.map(([title, values]) => {
                  const lower = title.toLowerCase()
                  const actionLabel = lower.includes("url") || lower.includes("form") || lower.includes("redirect") ? "URL Analyzer" : lower.includes("domain") || lower.includes("ip") ? "Recon" : lower.includes("hash") ? "Detection" : lower.includes("email") ? "Phishing" : "CyberChef"
                  return <IocGroup key={title} title={title} values={values} actionLabel={actionLabel} onCopy={copy} onRoute={() => routeIocGroup(title, values[0])} />
                })}
              </div>
            </WorkbenchPanel>
          )}

          <WorkbenchPanel className="space-y-3">
            <details className="rounded-xl border border-white/10 bg-black/40 p-3">
              <summary className="cursor-pointer text-sm font-bold text-zinc-100"><Database size={14} className="inline mr-1" />Manual hash pivots{allHashes.length ? ` (${allHashes.length})` : ""}</summary>
              <p className="mt-2 text-sm text-zinc-400">These are shortcut links only. BeyondArch did not perform reputation API checks or upload the artifact.</p>
              {allHashes.length > 0 ? (
                <div className="mt-3 overflow-auto rounded-xl border border-white/10">
                  <table className="w-full min-w-[760px] text-left text-sm">
                    <thead className="bg-black/40 text-xs uppercase tracking-[0.12em] text-zinc-400"><tr><th className="p-2">Hash</th><th className="p-2">Type</th><th className="p-2">Source</th><th className="p-2">Actions</th></tr></thead>
                    <tbody className="divide-y divide-white/10 text-zinc-200">
                      {allHashes.slice(0, 12).map((item) => <tr key={`${item.algo}-${item.value}`}><td className="break-all p-2 font-mono text-xs text-zinc-100">{item.value}</td><td className="p-2">{item.algo}</td><td className="p-2">{item.source}</td><td className="p-2"><div className="flex flex-wrap gap-2"><button className="ba-button-ghost rounded-lg px-2 py-1 text-xs font-bold" onClick={() => copy(item.value, "Hash")}>Copy</button><button className="ba-button-ghost rounded-lg px-2 py-1 text-xs font-bold" onClick={() => sendToPage("detection-mitre", { type: "hash", value: item.value, content: `Attachment hash: ${item.value}` })}>Detection</button><a className="ba-button-ghost rounded-lg px-2 py-1 text-xs font-bold" target="_blank" rel="noreferrer" href={`https://www.virustotal.com/gui/file/${encodeURIComponent(item.value)}`}>VirusTotal <ExternalLink className="ml-1 inline h-3 w-3" /></a>{/^[a-f0-9]{64}$/i.test(item.value) && <a className="ba-button-ghost rounded-lg px-2 py-1 text-xs font-bold" target="_blank" rel="noreferrer" href={`https://bazaar.abuse.ch/sample/${encodeURIComponent(item.value)}/`}>MalwareBazaar <ExternalLink className="ml-1 inline h-3 w-3" /></a>}<a className="ba-button-ghost rounded-lg px-2 py-1 text-xs font-bold" target="_blank" rel="noreferrer" href={`https://hybrid-analysis.com/search?query=${encodeURIComponent(item.value)}`}>Hybrid Analysis <ExternalLink className="ml-1 inline h-3 w-3" /></a></div></td></tr>)}
                    </tbody>
                  </table>
                </div>
              ) : <p className="mt-2 text-sm text-zinc-500">No hashes available yet.</p>}
            </details>

            {!!visibleStringGroups.length && (
              <details className="rounded-xl border border-white/10 bg-black/40 p-3">
                <summary className="cursor-pointer text-sm font-bold text-zinc-100"><FileText size={14} className="inline mr-1" />String review and extracted text groups</summary>
                <div className="mt-3 flex flex-wrap gap-2">
                  {["Priority", "All", "URLs", "Secrets", "Credentials", "Brand terms", "Scripts"].map((filter) => <button key={filter} className={`ba-tab-button ${stringFilter === filter ? "is-active" : ""}`} onClick={() => setStringFilter(filter)}>{filter}</button>)}
                  <button className="ba-button-secondary rounded-xl px-3 py-2 text-sm font-bold" onClick={() => sendToCyberChef(stringsText, ["extract-iocs"])}><ChefHat className="mr-2 inline h-4 w-4" />CyberChef</button>
                </div>
                <div className="mt-3 grid gap-3 md:grid-cols-2">
                  {visibleStringGroups.map(([name, values]) => <IocGroup key={name} title={name} values={values} actionLabel={/script|command/i.test(name) ? "SOC Guide" : /network|url|domain/i.test(name) ? "Route" : "CyberChef"} onCopy={copy} onRoute={() => /script|command/i.test(name) ? sendToPage("soc-guide", { type: "command", value: values[0] }) : routeIocGroup(name, values[0])} />)}
                </div>
                <details className="mt-3 rounded-xl border border-white/10 bg-black/40 p-3"><summary className="cursor-pointer text-sm font-bold text-zinc-100">Full extracted strings / raw text</summary><pre className="mt-3 max-h-96 overflow-auto whitespace-pre-wrap text-xs text-zinc-100">{strings.slice(0, 2000).join("\n") || fileText || pastedText || hashInput}</pre></details>
              </details>
            )}

            <section className="rounded-xl border border-cyan-400/15 bg-cyan-400/5 p-3">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div>
                  <p className="text-sm font-bold text-zinc-100">Need hash generation or compare?</p>
                  <p className="mt-1 text-xs leading-5 text-zinc-400">Hashing/encoding utilities now live in CyberChef so attachment triage stays focused on static review.</p>
                </div>
                <button className="ba-button-secondary rounded-xl px-3 py-2 text-sm font-bold" onClick={() => sendToCyberChef(pastedText || stringsText || hashInput, ["sha256"])}><ChefHat className="mr-2 inline h-4 w-4" />Open in CyberChef</button>
              </div>
            </section>

            <details className="rounded-xl border border-white/10 bg-black/40 p-3">
              <summary className="cursor-pointer text-sm font-bold text-zinc-100"><Download size={14} className="inline mr-1" />Report and export</summary>
              <div className="mt-3 flex flex-wrap gap-2">
                <button className="ba-button-secondary rounded-xl px-3 py-2 text-sm font-bold" onClick={() => copy(markdown, "Markdown report")}><Clipboard className="mr-2 inline h-4 w-4" />Copy Markdown</button>
                <button className="ba-button-secondary rounded-xl px-3 py-2 text-sm font-bold" onClick={() => copy(JSON.stringify(reportState, null, 2), "JSON report")}><Clipboard className="mr-2 inline h-4 w-4" />Copy JSON</button>
                <button className="ba-button-secondary rounded-xl px-3 py-2 text-sm font-bold" onClick={() => downloadText("attachment-triage-report.md", markdown, "text/markdown")}><Download className="mr-2 inline h-4 w-4" />Export Markdown</button>
                <button className="ba-button-secondary rounded-xl px-3 py-2 text-sm font-bold" onClick={() => downloadText("attachment-triage-result.json", JSON.stringify(reportState, null, 2), "application/json")}><Download className="mr-2 inline h-4 w-4" />Export JSON</button>
              </div>
              <div className="mt-3 grid gap-3 lg:grid-cols-2"><ReportSection title="Executive summary">{summary}</ReportSection><ReportSection title="Recommended actions"><ul><li>- Preserve original attachment/hash and do not execute it.</li><li>- Pivot hashes, filenames, URLs, domains, and IPs across mailbox, EDR, proxy, and DNS logs.</li><li>- Use external links only for manual reputation verification; no API lookup was performed.</li><li>- Document limitations and treat static risk as requiring analyst review.</li></ul></ReportSection></div>
            </details>
            <details className="rounded-xl border border-white/10 bg-black/40 p-3"><summary className="cursor-pointer text-sm font-bold text-zinc-100">Advanced raw details</summary><pre className="mt-3 max-h-96 overflow-auto whitespace-pre-wrap text-xs text-zinc-100">{JSON.stringify(reportState, null, 2)}</pre></details>
          </WorkbenchPanel>
        </>
      )}
    </WorkbenchPage>
  )
}
