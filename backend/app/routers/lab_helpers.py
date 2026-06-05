from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.services.powershell_decoder import analyze_powershell
from app.services.windows_event_helper import analyze_event_text, list_events, lookup_event

router = APIRouter()


class PowerShellRequest(BaseModel):
    command: str = Field(..., min_length=1)


class EventLookupRequest(BaseModel):
    event_id: str = Field(..., min_length=1)


class EventTextRequest(BaseModel):
    text: str = Field(..., min_length=1)


@router.post("/powershell/analyze")
def powershell_analyze(request: PowerShellRequest):
    return analyze_powershell(request.command)


@router.get("/windows-events")
def windows_events_list():
    return {
        "events": list_events()
    }


@router.post("/windows-events/lookup")
def windows_event_lookup(request: EventLookupRequest):
    return lookup_event(request.event_id)


@router.post("/windows-events/analyze-text")
def windows_event_text(request: EventTextRequest):
    return analyze_event_text(request.text)
