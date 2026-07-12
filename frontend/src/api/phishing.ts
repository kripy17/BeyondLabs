import { postJson } from "../lib/apiClient"

export function analyzePhishingHeaders(headers: string) {
  return postJson("/api/phishing/analyze-headers", { headers })
}

export function analyzePhishingBody(body: string, refangFirst = true) {
  return postJson("/api/phishing/analyze-body", { body, refang_first: refangFirst })
}

export function analyzeFullEmail(headers: string, body: string, refangFirst = true) {
  return postJson("/api/phishing/analyze-email", { headers, body, refang_first: refangFirst })
}

export function analyzeAttachments(filenames: string[], hashes: string[]) {
  return postJson("/api/phishing/analyze-attachments", { filenames, hashes })
}
