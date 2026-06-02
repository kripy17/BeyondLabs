from fastapi import APIRouter, File, HTTPException, UploadFile

from app.services.network_traffic import analyze_pcap


router = APIRouter()

MAX_PCAP_SIZE = 25 * 1024 * 1024


@router.post("/pcap/analyze")
async def pcap_analyze(file: UploadFile = File(...)):
    data = await file.read()

    if not data:
        raise HTTPException(status_code=400, detail="Uploaded PCAP is empty.")

    if len(data) > MAX_PCAP_SIZE:
        raise HTTPException(status_code=413, detail="PCAP too large. Limit is 25 MB for MVP.")

    return analyze_pcap(file.filename or "uploaded.pcap", data)
