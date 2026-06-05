from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.services.log_specialists import analyze_linux_auth_logs, analyze_web_access_logs

router = APIRouter()


class LogTextRequest(BaseModel):
    text: str = Field(..., min_length=1)


@router.post("/linux-auth")
def linux_auth_analysis(request: LogTextRequest):
    return analyze_linux_auth_logs(request.text)


@router.post("/web-access")
def web_access_analysis(request: LogTextRequest):
    return analyze_web_access_logs(request.text)
