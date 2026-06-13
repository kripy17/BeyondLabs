/**
 * domUtils.js — shared browser utility functions
 * Extracted from duplicate definitions across 11+ page files.
 * Import with: import { downloadText, copyText } from "@/lib/domUtils"
 * (or adjust relative path per file depth)
 */

/**
 * Trigger a browser file download with text content.
 * @param {string} filename
 * @param {string} content
 * @param {string} [type]
 */
export function downloadText(filename, content, type = "text/plain") {
  const blob = new Blob([content], { type })
  const url = URL.createObjectURL(blob)
  const link = document.createElement("a")
  link.href = url
  link.download = filename
  link.click()
  URL.revokeObjectURL(url)
}

/**
 * Copy text to clipboard and optionally set a notice string.
 * Signature matches the most common usage: copyText(value, setNotice, label)
 * @param {string} text
 * @param {Function|null} setNotice  — setState setter, called with "label copied."
 * @param {string} [label]
 */
export async function copyText(text, setNotice, label = "Copied") {
  if (!text) return
  await navigator.clipboard.writeText(String(text))
  setNotice?.(`${label} copied.`)
}

/**
 * Escape HTML special characters.
 * @param {string} value
 * @returns {string}
 */
export function escapeHtml(value = "") {
  return String(value).replace(
    /[&<>"']/g,
    (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;" }[char] || char)
  )
}

/**
 * Normalise a hash string (lowercase, strip whitespace).
 * @param {string} value
 * @returns {string}
 */
export function normalizeHash(value = "") {
  return value.trim().replace(/\s+/g, "").toLowerCase()
}

export function stripDefang(value = "") {
  return String(value)
    .replace(/hxxps/gi, "https")
    .replace(/hxxp/gi, "http")
    .replace(/\[:\]/g, ":")
    .replace(/\[\.\]/g, ".")
    .replace(/\[@\]/g, "@")
}

export function refangText(value = "") {
  return stripDefang(value)
}

