from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.services.checklist_playbooks import (
    list_checklists,
    get_checklist,
    build_checklist_report,
)


router = APIRouter()


class ChecklistReportRequest(BaseModel):
    checked_step_ids: list[str] = []
    severity: str = "medium"
    analyst: str = ""
    notes: str = ""


@router.get("")
def checklist_list():
    return {
        "checklists": list_checklists()
    }


@router.get("/{checklist_id}")
def checklist_detail(checklist_id: str):
    checklist = get_checklist(checklist_id)

    if not checklist:
        raise HTTPException(status_code=404, detail="Checklist not found")

    return checklist


@router.post("/{checklist_id}/report")
def checklist_report(checklist_id: str, request: ChecklistReportRequest):
    report = build_checklist_report(
        checklist_id=checklist_id,
        checked_step_ids=request.checked_step_ids,
        severity=request.severity,
        analyst=request.analyst,
        notes=request.notes,
    )

    if report.get("error"):
        raise HTTPException(status_code=404, detail=report["error"])

    return report
