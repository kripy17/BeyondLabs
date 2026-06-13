import { postJson } from "../lib/apiClient"

export function generateMarkdownReport(title, summary, sections, recommendations, analyst) {
  return postJson("/api/reports/markdown", {
    title,
    summary,
    sections,
    recommendations,
    analyst,
  })
}
