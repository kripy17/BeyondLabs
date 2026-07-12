import { postJson } from "../lib/apiClient"

export function generateMarkdownReport(
  title: string,
  summary: string,
  sections: string[],
  recommendations: string[],
  analyst: string,
) {
  return postJson("/api/reports/markdown", {
    title,
    summary,
    sections,
    recommendations,
    analyst,
  })
}
