import asyncio
import json

from fastapi import APIRouter, File, HTTPException, Request, UploadFile
from fastapi.responses import StreamingResponse

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


@router.post("/nmap/stream")
async def nmap_stream(request: Request):
    body = await request.json()
    target = body.get("target", "")
    mode = body.get("mode", "quick")
    flags = body.get("flags", "")

    from app.services.nmap_runner import build_nmap_command

    cmd = build_nmap_command(target, mode, flags)

    async def event_generator():
        yield f"data: {json.dumps({'type': 'start', 'command': cmd})}\n\n"

        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        async for line in proc.stdout:
            text = line.decode(errors="replace").rstrip()
            if text:
                yield f"data: {json.dumps({'type': 'stdout', 'line': text})}\n\n"

        await proc.wait()

        if proc.returncode != 0:
            stderr = (await proc.stderr.read()).decode(errors="replace")
            yield f"data: {json.dumps({'type': 'error', 'message': stderr})}\n\n"
        else:
            yield f"data: {json.dumps({'type': 'done', 'returncode': proc.returncode})}\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        }
    )
