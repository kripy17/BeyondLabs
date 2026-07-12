import { uploadFile, postJson } from "../lib/apiClient"

export async function uploadMalwareFile(file: File) {
  return uploadFile("/api/malware/static-file", file)
}

export function lookupMalwareHash(hashValue: string) {
  return postJson("/api/malware/hash/reputation", { hash_value: hashValue })
}

export function analyzeStrings(text: string, source = "pasted_text") {
  return postJson("/api/malware/strings/analyze", { text, source })
}
