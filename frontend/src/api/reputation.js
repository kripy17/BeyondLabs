import { postJson } from "../lib/apiClient"

export function checkIpReputation(ip) {
  return postJson("/api/reputation/ip", { ip })
}

export function checkDomainReputation(domain) {
  return postJson("/api/reputation/domain", { domain })
}

export function checkUrlReputation(url) {
  return postJson("/api/reputation/url", { url })
}

export async function enrichReputation(indicator, indicatorType) {
  return postJson("/api/reputation/enrich", {
    indicator,
    indicator_type: indicatorType,
  })
}
