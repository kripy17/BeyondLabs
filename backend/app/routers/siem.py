from fastapi import APIRouter, File, HTTPException, UploadFile
from pydantic import BaseModel, Field

from app.services.mini_siem import analyze_logs_siem


router = APIRouter()

MAX_LOG_UPLOAD_SIZE = 5 * 1024 * 1024


class SiemTextRequest(BaseModel):
    text: str = Field(..., min_length=1)


@router.post("/analyze")
def analyze_pasted_logs(request: SiemTextRequest):
    return analyze_logs_siem(request.text)


@router.post("/upload")
async def analyze_uploaded_log(file: UploadFile = File(...)):
    data = await file.read()

    if not data:
        raise HTTPException(status_code=400, detail="Uploaded log file is empty.")

    if len(data) > MAX_LOG_UPLOAD_SIZE:
        raise HTTPException(status_code=413, detail="Log file too large. Limit is 5 MB for MVP.")

    text = data.decode("utf-8", errors="replace")

    return analyze_logs_siem(text)
