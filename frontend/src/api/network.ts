import { uploadFile, postJson } from "../lib/apiClient"

export async function uploadPcap(file: File) {
  return uploadFile("/api/network/pcap/analyze", file)
}

export function analyzeSiemText(text: string) {
  return postJson("/api/siem/analyze", { text })
}

export async function uploadSiemLog(file: File) {
  return uploadFile("/api/siem/upload", file)
}
