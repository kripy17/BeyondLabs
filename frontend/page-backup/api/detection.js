import { getJson, postJson } from "../lib/apiClient"

export function mapMitre(text) {
  return postJson("/api/detection/mitre/map", { text })
}

export function generateSigmaRule(title, description, severity, logsourceType) {
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

export function buildIdsRule(payload) {
  return postJson("/api/detection/ids/build", payload)
}

export function explainIdsRule(rule) {
  return postJson("/api/detection/ids/explain", { rule })
}
