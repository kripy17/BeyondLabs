from typing import Literal

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.services.detection_engineering import build_sigma_rule, map_to_mitre
from app.services.ids_rule_builder import build_ids_rule, explain_ids_rule, ids_rule_templates

router = APIRouter()


class MitreMapRequest(BaseModel):
    text: str = Field(..., min_length=1)


class SigmaRuleRequest(BaseModel):
    title: str = Field(..., min_length=1)
    description: str = Field(..., min_length=1)
    severity: Literal["informational", "low", "medium", "high", "critical"] = "medium"
    logsource_type: str | None = None


class IdsRuleBuildRequest(BaseModel):
    engine: str = "snort"
    action: str = "alert"
    protocol: str = "tcp"
    src_ip: str = "any"
    src_port: str = "any"
    direction: str = "->"
    dst_ip: str = "any"
    dst_port: str = "80"
    msg: str = "BeyondLabs generated IDS rule"
    content: str = ""
    pcre: str = ""
    flow: str = ""
    classtype: str = "trojan-activity"
    priority: str = "2"
    sid: str = "1000001"
    rev: str = "1"
    extra_options: str = ""
    nocase: bool = False
    http_uri: bool = False
    http_header: bool = False


class IdsRuleExplainRequest(BaseModel):
    rule: str = Field(..., min_length=1)


@router.post("/mitre/map")
def mitre_map(request: MitreMapRequest):
    return map_to_mitre(request.text)


@router.post("/sigma/generate")
def sigma_generate(request: SigmaRuleRequest):
    return build_sigma_rule(
        title=request.title,
        description=request.description,
        severity=request.severity,
        logsource_type=request.logsource_type,
    )


@router.get("/ids/templates")
def ids_templates():
    return ids_rule_templates()


@router.post("/ids/build")
def ids_build(request: IdsRuleBuildRequest):
    return build_ids_rule(request.model_dump())


@router.post("/ids/explain")
def ids_explain(request: IdsRuleExplainRequest):
    return explain_ids_rule(request.rule)
