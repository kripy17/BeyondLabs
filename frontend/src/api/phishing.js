import { postJson } from "../lib/apiClient"

export function analyzePhishingHeaders(headers) {
  return postJson("/api/phishing/analyze-headers", { headers })
}

export function analyzePhishingBody(body, refangFirst = true) {
  return postJson("/api/phishing/analyze-body", { body, refang_first: refangFirst })
}

export function analyzeFullEmail(headers, body, refangFirst = true) {
  return postJson("/api/phishing/analyze-email", { headers, body, refang_first: refangFirst })
}

export function analyzeAttachments(filenames, hashes) {
  return postJson("/api/phishing/analyze-attachments", { filenames, hashes })
}
