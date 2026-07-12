import { getJson, postJson } from "../lib/apiClient"

export function usernameOsint(username: string) {
  return postJson("/api/osint/username", { username })
}

export function emailOsint(email: string) {
  return postJson("/api/osint/email", { email })
}

export function socialLinksFinder(website: string) {
  return postJson("/api/osint/social-links", { website })
}

export function getLocalOsintTools() {
  return getJson("/api/osint/local-tools")
}

export function runTheHarvester({
  domain,
  source = "duckduckgo",
  limit = 50,
  confirmPermission = false,
}: {
  domain: string
  source?: string
  limit?: number
  confirmPermission?: boolean
}) {
  return postJson("/api/osint/theharvester", {
    domain,
    source,
    limit: Number(limit || 50),
    confirm_permission: Boolean(confirmPermission),
  }, 140000)
}

export function runLocalOsintTool({
  toolId,
  domain,
  source = "duckduckgo",
  limit = 50,
  confirmPermission = false,
}: {
  toolId: string
  domain: string
  source?: string
  limit?: number
  confirmPermission?: boolean
}) {
  return postJson("/api/osint/run-tool", {
    tool_id: toolId,
    domain,
    source,
    limit: Number(limit || 50),
    confirm_permission: Boolean(confirmPermission),
  }, 140000)
}

export function runMaigret(username: string) {
  return postJson("/api/osint/maigret", { username }, 180000)
}

export function getHackingtoolCategories() {
  return getJson("/api/hackingtool/categories")
}

export function runHackingtoolTool({
  categoryId,
  toolId,
  target = "",
  args = "",
}: {
  categoryId: string
  toolId: string
  target?: string
  args?: string
}) {
  return postJson("/api/hackingtool/run", {
    category_id: categoryId,
    tool_id: toolId,
    target,
    args,
  }, 180000)
}
