from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.services.email_header_analyzer import analyze_email_headers
from app.services.email_body_analyzer import analyze_email_body
from app.services.phishing_combined_analyzer import analyze_full_email
from app.services.attachment_analyzer import analyze_attachments


router = APIRouter()


class HeaderAnalysisRequest(BaseModel):
    headers: str = Field(..., min_length=1)


class BodyAnalysisRequest(BaseModel):
    body: str = Field(..., min_length=1)
    refang_first: bool = True


class FullEmailAnalysisRequest(BaseModel):
    headers: str = ""
    body: str = ""
    refang_first: bool = True


class AttachmentAnalysisRequest(BaseModel):
    filenames: list[str] = Field(default_factory=list)
    hashes: list[str] = Field(default_factory=list)


@router.post("/analyze-headers")
def analyze_headers(request: HeaderAnalysisRequest):
    return analyze_email_headers(request.headers)


@router.post("/analyze-body")
def analyze_body(request: BodyAnalysisRequest):
    return analyze_email_body(
        body=request.body,
        refang_first=request.refang_first,
    )


@router.post("/analyze-email")
def analyze_email(request: FullEmailAnalysisRequest):
    if not request.headers.strip() and not request.body.strip():
        raise HTTPException(status_code=400, detail="Provide headers, body, or both.")

    return analyze_full_email(
        headers=request.headers,
        body=request.body,
        refang_first=request.refang_first,
    )


@router.post("/analyze-attachments")
def analyze_attachment_indicators(request: AttachmentAnalysisRequest):
    if not request.filenames and not request.hashes:
        raise HTTPException(status_code=400, detail="Provide filenames, hashes, or both.")

    return analyze_attachments(
        filenames=request.filenames,
        hashes=request.hashes,
    )
