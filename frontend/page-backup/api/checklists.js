import { getJson, postJson } from "../lib/apiClient"

export function listChecklists() {
  return getJson("/api/checklists")
}

export function getChecklist(checklistId) {
  return getJson(`/api/checklists/${checklistId}`)
}

export function generateChecklistReport(checklistId, checkedStepIds, severity, analyst, notes) {
  return postJson(`/api/checklists/${checklistId}/report`, {
    checked_step_ids: checkedStepIds,
    severity,
    analyst,
    notes,
  })
}
