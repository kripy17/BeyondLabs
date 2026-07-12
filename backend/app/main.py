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

app = FastAPI(
    title="BeyondLabs API",
    description="Security Operations Toolkit backend for recon, SOC tools, phishing analysis, OSINT, and utilities.",
    version="0.1.0",
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
        "message": "Security Operations Toolkit backend"
    }


@app.get("/health")
def health():
    return {
        "status": "ok"
    }


app.include_router(recon.router, prefix="/api/recon", tags=["Recon"])
app.include_router(soc.router, prefix="/api/soc", tags=["SOC Toolkit"])
app.include_router(phishing.router, prefix="/api/phishing", tags=["Phishing"])

app.include_router(url.router, prefix="/api/url", tags=["Safe URL Analyzer"])

app.include_router(utils.router, prefix="/api/utils", tags=["Cyber Utilities"])

app.include_router(osint.router, prefix="/api/osint", tags=["OSINT"])

app.include_router(checklists.router, prefix="/api/checklists", tags=["Checklists"])

app.include_router(reports.router, prefix="/api/reports", tags=["Reports"])

app.include_router(reputation.router, prefix="/api/reputation", tags=["Reputation"])

app.include_router(malware.router, prefix="/api/malware", tags=["Malware Triage"])

app.include_router(siem.router, prefix="/api/siem", tags=["Mini SIEM"])

app.include_router(lab_helpers.router, prefix="/api/lab", tags=["Lab Helpers"])

app.include_router(log_analysis.router, prefix="/api/log-analysis", tags=["Log Analysis"])

app.include_router(detection.router, prefix="/api/detection", tags=["Detection Engineering"])

app.include_router(network.router, prefix="/api/network", tags=["Network Traffic"])


app.include_router(recon_intel.router, prefix="/api/recon-intel", tags=["Recon Intelligence"])

app.include_router(hackingtool.router, prefix="/api/hackingtool", tags=["Hacking Tools"])
