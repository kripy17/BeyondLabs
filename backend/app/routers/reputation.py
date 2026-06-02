from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.services.reputation import (
    analyze_ip_reputation,
    analyze_domain_reputation,
    analyze_url_reputation,
    enrich_indicator_reputation,
)


router = APIRouter()


class IpReputationRequest(BaseModel):
    ip: str = Field(..., min_length=1)


class DomainReputationRequest(BaseModel):
    domain: str = Field(..., min_length=1)


class UrlReputationRequest(BaseModel):
    url: str = Field(..., min_length=1)


class EnrichReputationRequest(BaseModel):
    indicator: str = Field(..., min_length=1)
    indicator_type: str = Field(..., min_length=1)


@router.post("/ip")
def ip_reputation(request: IpReputationRequest):
    return analyze_ip_reputation(request.ip)


@router.post("/domain")
def domain_reputation(request: DomainReputationRequest):
    return analyze_domain_reputation(request.domain)


@router.post("/url")
def url_reputation(request: UrlReputationRequest):
    return analyze_url_reputation(request.url)


@router.post("/enrich")
async def enrich_reputation(request: EnrichReputationRequest):
    return await enrich_indicator_reputation(
        indicator=request.indicator,
        indicator_type=request.indicator_type,
    )
