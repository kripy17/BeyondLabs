from typing import Literal

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.services.dns_lookup import lookup_dns, lookup_reverse_dns
from app.services.http_probe import probe_http
from app.services.nmap_runner import run_custom_nmap_command, run_nmap_scan
from app.services.parser import normalize_target
from app.services.ssl_lookup import get_ssl_certificate
from app.services.web_exposure import run_web_exposure_review
from app.services.whois_rdap import whois_lookup, rdap_lookup

router = APIRouter()


class ReconRequest(BaseModel):
    target: str = Field(..., min_length=3, max_length=255)
    fetch_mode: Literal["no_fetch", "head_only", "get_headers"] = "head_only"
    follow_redirects: bool = False
    timeout_seconds: int = Field(default=8, ge=2, le=15)
    fetch_web_files: bool = False


class NmapRequest(BaseModel):
    target: str = Field(..., min_length=3, max_length=1000)
    mode: Literal[
        "aggressive_inventory",
        "quick_tcp",
        "top100",
        "full_tcp",
        "service_version",
        "service",
        "os_detection",
        "udp_focused",
        "web_exposure",
        "internal_inventory",
        "windows_smb",
        "linux_ssh",
        "mail_server",
        "dns_exposure",
        "safe_scripts",
    ] = "quick_tcp"
    confirm_permission: bool = False
    allow_private: bool = False




class NmapCustomRequest(BaseModel):
    command: str = Field(..., min_length=4, max_length=1200)
    confirm_permission: bool = False
    allow_private: bool = False


class WebExposureRequest(BaseModel):
    target: str = Field(..., min_length=3, max_length=255)
    confirm_permission: bool = False
    timeout_seconds: int = Field(default=8, ge=2, le=15)


class DnsReconRequest(BaseModel):
    target: str = Field(..., min_length=3, max_length=255)
    confirm_permission: bool = False



def _backend_meta(method: str, limitations: str) -> dict:
    return {
        "source": "local backend",
        "method": method,
        "limitations": limitations,
    }


@router.post("/passive")
async def passive_recon(request: ReconRequest):
    normalized = normalize_target(request.target)
    hostname = normalized.get("hostname")
    root_domain = normalized.get("root_domain") or hostname

    dns_result = lookup_dns(root_domain) if normalized.get("type") == "domain" and root_domain else None
    whois_result = await whois_lookup(root_domain) if normalized.get("type") == "domain" and root_domain else None
    rdap_result = await rdap_lookup(hostname) if normalized.get("type") == "ip" and hostname else None
    http_result = probe_http(hostname, request.fetch_mode, request.follow_redirects, request.timeout_seconds) if hostname else None
    ssl_result = get_ssl_certificate(hostname) if hostname and request.fetch_mode != "no_fetch" else None

    return {
        "target": normalized,
        "dns": dns_result,
        "http": http_result,
        "whois": whois_result,
        "rdap": rdap_result,
        "ssl": ssl_result,
        "web_files": None,
        "collection_method": {
            "mode": request.fetch_mode,
            "follow_redirects": request.follow_redirects,
            "javascript_execution": False,
            "cookies": False,
            "timeout_seconds": request.timeout_seconds,
            "body_download": False,
            "max_response_bytes": 0,
            "limitations": "Safe backend metadata collection only. No JavaScript, browser rendering, scraping, brute force, exploit checks, or external reputation lookup.",
        },
        "warning": "Backend metadata lookup completed.",
    }


@router.post("/dns")
async def dns_recon(request: DnsReconRequest):
    if not request.confirm_permission:
        raise HTTPException(status_code=400, detail="Confirm authorization before running backend DNS/RDAP checks.")

    normalized = normalize_target(request.target)
    hostname = normalized.get("hostname")
    root_domain = normalized.get("root_domain") or hostname

    if not hostname:
        raise HTTPException(status_code=400, detail="A domain, URL, or IP target is required.")

    dns_result = None
    reverse_dns_result = None
    whois_result = None
    rdap_result = None

    if normalized.get("type") == "domain":
        dns_result = lookup_dns(root_domain)
        whois_result = await whois_lookup(root_domain)
    else:
        reverse_dns_result = lookup_reverse_dns(hostname)
        rdap_result = await rdap_lookup(hostname)

    return {
        "target": normalized,
        "dns": dns_result,
        "reverse_dns": reverse_dns_result,
        "whois": whois_result,
        "rdap": rdap_result,
        "meta": _backend_meta(
            "dnspython DNS/PTR lookup with WHOIS/RDAP",
            "Availability depends on network, resolver, registry, and target type. No external reputation, scraping, brute force, or exploit checks are performed.",
        ),
        "warning": "Authorized DNS/RDAP metadata lookup completed. Validate records against asset ownership and expected providers.",
    }


@router.post("/nmap")
def nmap_scan(request: NmapRequest):
    if not request.confirm_permission:
        raise HTTPException(
            status_code=400,
            detail="You must confirm that you own or have permission to scan this target."
        )

    normalized = normalize_target(request.target)
    scan_target = normalized["hostname"]

    result = run_nmap_scan(
        target=scan_target,
        mode=request.mode,
        allow_private=request.allow_private,
    )

    return {
        "target": normalized,
        "scan": result,
        "warning": "Only scan targets you own or have permission to test.",
    }


@router.post("/nmap-custom")
def nmap_custom_scan(request: NmapCustomRequest):
    if not request.confirm_permission:
        raise HTTPException(
            status_code=400,
            detail="You must confirm that you own or have permission to scan this target."
        )

    result = run_custom_nmap_command(
        command=request.command,
        allow_private=request.allow_private,
    )

    return {
        "target": {"type": "custom", "original": request.command},
        "scan": result,
        "warning": "Custom nmap is still bounded: no shell chaining, evasion/spoofing flags, unsafe script categories, or broad target lists.",
    }


@router.post("/web-exposure")
def web_exposure(request: WebExposureRequest):
    if not request.confirm_permission:
        raise HTTPException(
            status_code=400,
            detail="You must confirm that you own or have permission to assess this target."
        )

    normalized = normalize_target(request.target)
    scan_target = normalized["hostname"]

    try:
        result = run_web_exposure_review(
            target=scan_target,
            confirm_permission=request.confirm_permission,
            timeout_seconds=request.timeout_seconds,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return {
        "target": normalized,
        "review": result,
        "warning": "Authorized live checks only. No exploit scanning, brute force, external reputation, or CVE lookup was performed.",
    }
