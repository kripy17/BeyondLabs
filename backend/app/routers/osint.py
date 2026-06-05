import asyncio

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.services.osint_tools import (
    email_osint,
    local_osint_tool_status,
    run_local_osint_tool,
    run_theharvester,
    social_links_finder,
    username_osint,
)

router = APIRouter()


class UsernameRequest(BaseModel):
    username: str = Field(..., min_length=1)


class EmailRequest(BaseModel):
    email: str = Field(..., min_length=3)


class SocialLinksRequest(BaseModel):
    website: str = Field(..., min_length=3)


class TheHarvesterRequest(BaseModel):
    domain: str = Field(..., min_length=3, max_length=255)
    source: str = Field(default="duckduckgo", min_length=2, max_length=40)
    limit: int = Field(default=50, ge=10, le=200)
    confirm_permission: bool = False


class LocalOsintToolRequest(BaseModel):
    tool_id: str = Field(..., min_length=2, max_length=40)
    domain: str = Field(..., min_length=3, max_length=255)
    source: str = Field(default="duckduckgo", min_length=2, max_length=40)
    limit: int = Field(default=50, ge=10, le=200)
    confirm_permission: bool = False


@router.post("/username")
async def username_lookup(request: UsernameRequest):
    return await asyncio.to_thread(username_osint, request.username)


@router.post("/email")
async def email_lookup(request: EmailRequest):
    return await asyncio.to_thread(email_osint, request.email)


@router.post("/social-links")
async def social_links_lookup(request: SocialLinksRequest):
    return await asyncio.to_thread(social_links_finder, request.website)


@router.get("/local-tools")
async def local_tools():
    return await asyncio.to_thread(local_osint_tool_status)


@router.post("/theharvester")
async def theharvester_lookup(request: TheHarvesterRequest):
    return await asyncio.to_thread(
        run_theharvester,
        domain=request.domain,
        source=request.source,
        limit=request.limit,
        confirm_permission=request.confirm_permission,
    )


@router.post("/run-tool")
async def run_local_tool(request: LocalOsintToolRequest):
    return await asyncio.to_thread(
        run_local_osint_tool,
        tool_id=request.tool_id,
        domain=request.domain,
        source=request.source,
        limit=request.limit,
        confirm_permission=request.confirm_permission,
    )
