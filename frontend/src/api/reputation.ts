import { postJson } from "../lib/apiClient"

export function checkIpReputation(ip: string) {
  return postJson("/api/reputation/ip", { ip })
}

export function checkDomainReputation(domain: string) {
  return postJson("/api/reputation/domain", { domain })
}

export function checkUrlReputation(url: string) {
  return postJson("/api/reputation/url", { url })
}

export async function enrichReputation(indicator: string, indicatorType: string) {
  return postJson("/api/reputation/enrich", {
    indicator,
    indicator_type: indicatorType,
  })
}
