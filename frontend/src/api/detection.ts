import { getJson, postJson } from "../lib/apiClient"

export function mapMitre(text: string) {
  return postJson("/api/detection/mitre/map", { text })
}

export function generateSigmaRule(
  title: string,
  description: string,
  severity: string,
  logsourceType: string | null,
) {
  return postJson("/api/detection/sigma/generate", {
    title,
    description,
    severity,
    logsource_type: logsourceType || null,
  })
}

export function getIdsRuleTemplates() {
  return getJson("/api/detection/ids/templates")
}

export function buildIdsRule(payload: Record<string, unknown>) {
  return postJson("/api/detection/ids/build", payload)
}

export function explainIdsRule(rule: string) {
  return postJson("/api/detection/ids/explain", { rule })
}
