import { uploadFile, postJson } from "../lib/apiClient"

export async function uploadPcap(file) {
  return uploadFile("/api/network/pcap/analyze", file)
}

export function analyzeSiemText(text) {
  return postJson("/api/siem/analyze", { text })
}

export async function uploadSiemLog(file) {
  return uploadFile("/api/siem/upload", file)
}
