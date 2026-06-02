import { getJson, postJson } from "../lib/apiClient"

export function usernameOsint(username) {
  return postJson("/api/osint/username", { username })
}

export function emailOsint(email) {
  return postJson("/api/osint/email", { email })
}

export function socialLinksFinder(website) {
  return postJson("/api/osint/social-links", { website })
}

export function getLocalOsintTools() {
  return getJson("/api/osint/local-tools")
}

export function runTheHarvester({ domain, source = "duckduckgo", limit = 50, confirmPermission = false }) {
  return postJson("/api/osint/theharvester", {
    domain,
    source,
    limit: Number(limit || 50),
    confirm_permission: Boolean(confirmPermission),
  }, 140000)
}

export function runLocalOsintTool({ toolId, domain, source = "duckduckgo", limit = 50, confirmPermission = false }) {
  return postJson("/api/osint/run-tool", {
    tool_id: toolId,
    domain,
    source,
    limit: Number(limit || 50),
    confirm_permission: Boolean(confirmPermission),
  }, 140000)
}
