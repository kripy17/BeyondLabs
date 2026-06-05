from typing import Literal

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.services.parser import normalize_target

router = APIRouter()


class ReconIntelRequest(BaseModel):
    target: str = Field(..., min_length=2, max_length=255)
    mode: Literal["backend"] = "backend"


@router.post("/plan")
def recon_intelligence_plan(request: ReconIntelRequest):
    normalized = normalize_target(request.target)
    host = normalized["host"]
    root = normalized["root_domain_guess"]

    local_observations = [
        {
            "name": "Target normalization",
            "type": "local deterministic",
            "value": f'{normalized["type"]}: {host}',
        },
        {
            "name": "Root domain",
            "type": "heuristic / inferred",
            "value": root,
        },
        {
            "name": "Safe default",
            "type": "workflow guardrail",
            "value": "Online source links and active scanning are disabled.",
        },
    ]

    return {
        "target": normalized,
        "mode": request.mode,
        "local_observations": local_observations,
        "source_groups": {},
        "google_dorks": [],
        "workflow": [
            "Normalize the target and document authorized scope.",
            "Extract domains, IPs, paths, and related notes from user-provided evidence.",
            "Keep DNS, WHOIS/RDAP, HTTP/TLS, URL fetch, and online pivots disabled.",
            "Send reviewed notes to Reports or Detection & MITRE.",
        ],
        "compare_guidance": ["Online source comparison is disabled in the current local-only architecture."],
        "warning": "No online lookup, source pivot, URL fetch, or active scan was performed.",
    }
