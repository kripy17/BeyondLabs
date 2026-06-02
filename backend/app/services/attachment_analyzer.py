import re

RISKY_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".com", ".pif",
    ".js", ".jse", ".vbs", ".vbe", ".wsf",
    ".ps1", ".psm1", ".hta", ".jar", ".msi",
    ".lnk", ".iso", ".img",
}

MACRO_EXTENSIONS = {
    ".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".potm"
}

ARCHIVE_EXTENSIONS = {
    ".zip", ".rar", ".7z", ".gz", ".tar", ".bz2", ".xz"
}

COMMON_SAFE_EXTENSIONS = {
    ".pdf", ".txt", ".csv", ".jpg", ".jpeg", ".png",
    ".docx", ".xlsx", ".pptx"
}

HASH_LENGTHS = {
    32: "MD5",
    40: "SHA1",
    64: "SHA256",
    128: "SHA512",
}

HEX_RE = re.compile(r"^[a-fA-F0-9]+$")


def get_extension(filename: str) -> str:
    name = filename.strip().lower()
    if "." not in name:
        return ""
    return "." + name.rsplit(".", 1)[1]


def detect_double_extension(filename: str) -> bool:
    lower = filename.strip().lower()
    return bool(
        re.search(
            r"\.(pdf|doc|docx|xls|xlsx|ppt|pptx|jpg|jpeg|png|txt)\."
            r"(exe|scr|js|vbs|bat|cmd|ps1|hta|jar|lnk)$",
            lower,
        )
    )


def identify_hash(value: str) -> dict:
    clean = value.strip()

    if not clean:
        return {
            "value": value,
            "valid": False,
            "type": "unknown",
        }

    if not HEX_RE.match(clean):
        return {
            "value": value,
            "valid": False,
            "type": "unknown",
            "reason": "Non-hex characters detected.",
        }

    hash_type = HASH_LENGTHS.get(len(clean), "unknown")

    return {
        "value": clean.lower(),
        "valid": hash_type != "unknown",
        "type": hash_type,
        "length": len(clean),
    }


def analyze_filename(filename: str) -> dict:
    ext = get_extension(filename)
    findings = []

    if not ext:
        findings.append({
            "severity": "low",
            "title": "No file extension",
            "detail": "Filename has no visible extension.",
            "recommendation": "Verify file type using hash/static analysis before opening.",
        })

    if ext in RISKY_EXTENSIONS:
        findings.append({
            "severity": "high",
            "title": "Risky executable/script extension",
            "detail": f"Detected extension: {ext}",
            "recommendation": "Do not open. Analyze in a safe sandbox or approved malware workflow.",
        })

    if ext in MACRO_EXTENSIONS:
        findings.append({
            "severity": "high",
            "title": "Macro-enabled Office document",
            "detail": f"Detected macro-capable extension: {ext}",
            "recommendation": "Do not enable macros. Treat as suspicious unless verified.",
        })

    if ext in ARCHIVE_EXTENSIONS:
        findings.append({
            "severity": "medium",
            "title": "Archive file",
            "detail": f"Detected archive extension: {ext}",
            "recommendation": "Inspect archive contents safely before extraction.",
        })

    if detect_double_extension(filename):
        findings.append({
            "severity": "high",
            "title": "Double extension detected",
            "detail": "Filename appears to hide a risky extension behind a safe-looking one.",
            "recommendation": "Treat as suspicious and do not open directly.",
        })

    if ext in COMMON_SAFE_EXTENSIONS and not findings:
        findings.append({
            "severity": "info",
            "title": "Common file extension",
            "detail": f"Detected extension: {ext}",
            "recommendation": "Still verify sender and context before opening.",
        })

    return {
        "filename": filename,
        "extension": ext or None,
        "double_extension": detect_double_extension(filename),
        "findings": findings,
    }


def score_findings(findings: list[dict]) -> int:
    score = 100
    penalties = {
        "high": 30,
        "medium": 15,
        "low": 7,
        "info": 0,
    }

    for finding in findings:
        score -= penalties.get(finding.get("severity"), 0)

    return max(score, 0)


def rating_from_score(score: int, findings: list[dict]) -> str:
    if any(f.get("severity") == "high" for f in findings):
        return "High Risk"
    if score >= 80:
        return "Low Risk"
    if score >= 55:
        return "Suspicious"
    return "High Risk"


def analyze_attachments(filenames: list[str], hashes: list[str] | None = None) -> dict:
    hashes = hashes or []

    analyzed_files = [analyze_filename(name) for name in filenames]
    analyzed_hashes = [identify_hash(value) for value in hashes]

    all_findings = []
    for item in analyzed_files:
        for finding in item["findings"]:
            finding_copy = dict(finding)
            finding_copy["filename"] = item["filename"]
            all_findings.append(finding_copy)

    invalid_hashes = [h for h in analyzed_hashes if not h["valid"]]

    for h in invalid_hashes:
        all_findings.append({
            "severity": "low",
            "title": "Invalid or unknown hash format",
            "detail": f"Hash value could not be confidently identified: {h.get('value')}",
            "recommendation": "Verify the hash value and algorithm.",
        })

    score = score_findings(all_findings)

    return {
        "summary": {
            "score": score,
            "rating": rating_from_score(score, all_findings),
            "total_files": len(filenames),
            "total_hashes": len(hashes),
            "total_findings": len(all_findings),
        },
        "files": analyzed_files,
        "hashes": analyzed_hashes,
        "findings": all_findings,
        "safety_note": "BeyondArch only analyzes attachment indicators. It does not execute files or open macros.",
    }
