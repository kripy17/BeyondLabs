from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.services.safe_url_analyzer import safe_analyze_url

router = APIRouter()


class SafeUrlAnalyzeRequest(BaseModel):
    url: str = Field(..., min_length=1)
    allow_live_fetch: bool = False
    max_redirects: int = Field(default=5, ge=0, le=10)
    timeout_seconds: int = Field(default=8, ge=2, le=20)
    allow_private_targets: bool = False


@router.post("/safe-analyze")
def safe_analyze_url_endpoint(request: SafeUrlAnalyzeRequest):
    return safe_analyze_url(
        url=request.url,
        allow_live_fetch=request.allow_live_fetch,
        max_redirects=request.max_redirects,
        timeout_seconds=request.timeout_seconds,
        allow_private_targets=request.allow_private_targets,
    )
