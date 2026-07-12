import { getJson, postJson } from "../lib/apiClient"

export function listChecklists() {
  return getJson("/api/checklists")
}

export function getChecklist(checklistId: string) {
  return getJson(`/api/checklists/${checklistId}`)
}

export function generateChecklistReport(
  checklistId: string,
  checkedStepIds: string[],
  severity: string,
  analyst: string,
  notes: string,
) {
  return postJson(`/api/checklists/${checklistId}/report`, {
    checked_step_ids: checkedStepIds,
    severity,
    analyst,
    notes,
  })
}
