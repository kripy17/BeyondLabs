export const CYBERCHEF_HANDOFF_TARGETS = {
  smartParser: { label: "Artifact Intake", page: "smart-parser", target: "smart-parser" },
  phishing: { label: "Phishing Triage", page: "phishing-triage", target: "phishing-triage" },
  recon: { label: "Recon & Exposure", page: "recon-exposure", target: "recon-exposure" },
  logs: { label: "Logs & Alerts", page: "logs-alerts", target: "logs-alerts" },
  detection: { label: "Detection & MITRE", page: "detection-mitre", target: "detection-mitre" },
}

export function buildCyberChefHandoff({ value, target, recipe = [], iocSummary = {} }) {
  return {
    type: "cyberchef-output",
    value,
    source: "CyberChef",
    target,
    recipe,
    ioc_summary: iocSummary,
    created_at: new Date().toISOString(),
  }
}
