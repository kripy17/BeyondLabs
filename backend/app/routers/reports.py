from pydantic import BaseModel, Field
from fastapi import APIRouter

from app.services.report_builder import build_markdown_report


router = APIRouter()


class ReportSection(BaseModel):
    title: str = Field(..., min_length=1)
    content: str | list[str] = ""


class MarkdownReportRequest(BaseModel):
    title: str = Field(..., min_length=1)
    summary: str = ""
    sections: list[ReportSection] = []
    recommendations: list[str] = []
    analyst: str = ""


@router.post("/markdown")
def markdown_report(request: MarkdownReportRequest):
    return build_markdown_report(
        title=request.title,
        summary=request.summary,
        sections=[section.model_dump() for section in request.sections],
        recommendations=request.recommendations,
        analyst=request.analyst,
    )
