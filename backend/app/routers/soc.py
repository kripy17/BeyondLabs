from typing import Literal

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.services.ioc_extractor import extract_iocs, defang_text, refang_text
from app.services.hash_analyzer import identify_hash, generate_hashes, compare_hash
from app.services.soc_analysis import parse_logs, parse_user_agent, triage_alert


router = APIRouter()


class IocExtractRequest(BaseModel):
    text: str = Field(..., min_length=1)
    refang_first: bool = True


class TransformRequest(BaseModel):
    text: str = Field(..., min_length=1)
    action: Literal["defang", "refang"] = "defang"


class HashIdentifyRequest(BaseModel):
    hash_value: str = Field(..., min_length=1)


class HashGenerateRequest(BaseModel):
    text: str = Field(..., min_length=1)


class HashCompareRequest(BaseModel):
    text: str = Field(..., min_length=1)
    expected_hash: str = Field(..., min_length=1)


class LogParseRequest(BaseModel):
    text: str = Field(..., min_length=1)


class UserAgentRequest(BaseModel):
    user_agent: str = Field(..., min_length=1)


class AlertTriageRequest(BaseModel):
    title: str = Field(..., min_length=1)
    description: str = ""
    raw_log: str = ""


@router.post("/extract-iocs")
def extract_ioc_endpoint(request: IocExtractRequest):
    return extract_iocs(text=request.text, refang_first=request.refang_first)


@router.post("/transform")
def transform_text_endpoint(request: TransformRequest):
    output = defang_text(request.text) if request.action == "defang" else refang_text(request.text)
    return {"action": request.action, "input": request.text, "output": output}


@router.post("/hash/identify")
def identify_hash_endpoint(request: HashIdentifyRequest):
    return identify_hash(request.hash_value)


@router.post("/hash/generate")
def generate_hashes_endpoint(request: HashGenerateRequest):
    return {"input": request.text, "hashes": generate_hashes(request.text)}


@router.post("/hash/compare")
def compare_hash_endpoint(request: HashCompareRequest):
    return compare_hash(text=request.text, expected_hash=request.expected_hash)


@router.post("/logs/parse")
def parse_logs_endpoint(request: LogParseRequest):
    return parse_logs(request.text)


@router.post("/user-agent/parse")
def parse_user_agent_endpoint(request: UserAgentRequest):
    return parse_user_agent(request.user_agent)


@router.post("/alert/triage")
def triage_alert_endpoint(request: AlertTriageRequest):
    return triage_alert(
        title=request.title,
        description=request.description,
        raw_log=request.raw_log,
    )
