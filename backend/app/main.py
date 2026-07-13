import time as _time
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.routers import (
    checklists,
    detection,
    hackingtool,
    lab_helpers,
    log_analysis,
    malware,
    network,
    osint,
    phishing,
    recon,
    recon_intel,
    reports,
    reputation,
    siem,
    soc,
    url,
    utils,
)

_start_time = _time.time()


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncGenerator[None, None]:
    yield


app = FastAPI(
    title="BeyondLabs API",
    description="Security Operations Toolkit backend for recon, SOC tools, phishing analysis, OSINT, and utilities.",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def root():
    return {
        "name": "BeyondLabs API",
        "status": "running",
        "message": "Security Operations Toolkit backend",
    }


@app.get("/health")
def health():
    return {
        "status": "ok",
        "version": "0.1.0",
        "uptime_s": round(_time.time() - _start_time, 1),
    }


ROUTERS = [
    (recon.router, "/api/recon", "Recon"),
    (soc.router, "/api/soc", "SOC Toolkit"),
    (phishing.router, "/api/phishing", "Phishing"),
    (url.router, "/api/url", "Safe URL Analyzer"),
    (utils.router, "/api/utils", "Cyber Utilities"),
    (osint.router, "/api/osint", "OSINT"),
    (checklists.router, "/api/checklists", "Checklists"),
    (reports.router, "/api/reports", "Reports"),
    (reputation.router, "/api/reputation", "Reputation"),
    (malware.router, "/api/malware", "Malware Triage"),
    (siem.router, "/api/siem", "Mini SIEM"),
    (lab_helpers.router, "/api/lab", "Lab Helpers"),
    (log_analysis.router, "/api/log-analysis", "Log Analysis"),
    (detection.router, "/api/detection", "Detection Engineering"),
    (network.router, "/api/network", "Network Traffic"),
    (recon_intel.router, "/api/recon-intel", "Recon Intelligence"),
    (hackingtool.router, "/api/hackingtool", "Hacking Tools"),
]

for router, prefix, tag in ROUTERS:
    app.include_router(router, prefix=prefix, tags=[tag])
