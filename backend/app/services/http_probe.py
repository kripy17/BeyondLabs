import httpx


def collection_method(
    mode: str = "head_only",
    follow_redirects: bool = False,
    timeout_seconds: int = 8,
) -> dict:
    return {
        "mode": mode,
        "follow_redirects": follow_redirects,
        "javascript_execution": False,
        "cookies": False,
        "timeout_seconds": timeout_seconds,
        "body_download": False,
        "max_response_bytes": 0,
        "limitations": (
            "No HTTP request was made. Results are limited to non-HTTP context."
            if mode == "no_fetch"
            else "Backend HTTP probing collects status and headers only. It does not execute JavaScript, store cookies, or download response bodies."
        ),
    }


def probe_http(
    hostname: str,
    mode: str = "head_only",
    follow_redirects: bool = False,
    timeout_seconds: int = 8,
) -> dict:
    if mode == "no_fetch":
        return {
            "skipped": True,
            "reason": "Backend HTTP probing is disabled for this request.",
            "collection_method": collection_method(mode, follow_redirects, timeout_seconds),
        }

    method = "HEAD" if mode == "head_only" else "GET"
    urls = [
        f"https://{hostname}",
        f"http://{hostname}",
    ]

    for url in urls:
        try:
            response = httpx.request(
                method,
                url,
                timeout=max(2, min(timeout_seconds, 15)),
                follow_redirects=follow_redirects,
                headers={
                    "User-Agent": "ReconScope/1.0 Defensive Security Scanner"
                }
            )

            return {
                "url": str(response.url),
                "status_code": response.status_code,
                "server": response.headers.get("server"),
                "content_type": response.headers.get("content-type"),
                "powered_by": response.headers.get("x-powered-by"),
                "headers": dict(response.headers),
                "collection_method": collection_method(mode, follow_redirects, timeout_seconds),
            }

        except Exception:
            continue

    return {
        "error": "Could not connect over HTTP or HTTPS",
        "collection_method": collection_method(mode, follow_redirects, timeout_seconds),
    }
