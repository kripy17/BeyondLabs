import httpx


def fetch_file(url: str, follow_redirects: bool = False, timeout_seconds: int = 8) -> dict:
    try:
        response = httpx.request(
            "GET",
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
            "content_type": response.headers.get("content-type"),
            "found": response.status_code == 200,
            "preview": response.text[:1500],
            "collection_method": {
                "mode": "get_limited_body",
                "follow_redirects": follow_redirects,
                "javascript_execution": False,
                "cookies": False,
                "timeout_seconds": timeout_seconds,
                "body_download": True,
                "max_response_bytes": 1500,
                "limitations": "Only robots.txt/sitemap.xml preview text is collected. JavaScript is never executed and cookies are not stored.",
            },
        }

    except Exception as e:
        return {
            "url": url,
            "found": False,
            "error": str(e),
            "collection_method": {
                "mode": "get_limited_body",
                "follow_redirects": follow_redirects,
                "javascript_execution": False,
                "cookies": False,
                "timeout_seconds": timeout_seconds,
                "body_download": True,
                "max_response_bytes": 1500,
                "limitations": "Only robots.txt/sitemap.xml preview text would be collected if reachable.",
            },
        }


def fetch_web_files(hostname: str, follow_redirects: bool = False, timeout_seconds: int = 8) -> dict:
    return {
        "robots_txt": fetch_file(f"https://{hostname}/robots.txt", follow_redirects, timeout_seconds),
        "sitemap_xml": fetch_file(f"https://{hostname}/sitemap.xml", follow_redirects, timeout_seconds),
    }
