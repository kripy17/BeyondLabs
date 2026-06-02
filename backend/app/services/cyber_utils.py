import base64
import json
from datetime import datetime, timezone
from urllib.parse import quote, unquote, urlparse, parse_qs


def base64_encode(text: str) -> dict:
    encoded = base64.b64encode(text.encode("utf-8")).decode("utf-8")
    return {
        "input": text,
        "output": encoded,
    }


def base64_decode(text: str) -> dict:
    try:
        decoded = base64.b64decode(text.strip(), validate=True).decode("utf-8", errors="replace")
        return {
            "valid": True,
            "input": text,
            "output": decoded,
        }
    except Exception as e:
        return {
            "valid": False,
            "input": text,
            "error": str(e),
        }


def url_encode(text: str) -> dict:
    return {
        "input": text,
        "output": quote(text, safe=""),
    }


def url_decode(text: str) -> dict:
    return {
        "input": text,
        "output": unquote(text),
    }


def parse_url(url: str) -> dict:
    parsed = urlparse(url if "://" in url else f"http://{url}")

    return {
        "original": url,
        "scheme": parsed.scheme,
        "hostname": parsed.hostname,
        "port": parsed.port,
        "path": parsed.path,
        "query": parsed.query,
        "query_params": parse_qs(parsed.query),
        "fragment": parsed.fragment,
    }


def decode_base64url(value: str):
    padding = "=" * (-len(value) % 4)
    decoded = base64.urlsafe_b64decode(value + padding)

    try:
        return json.loads(decoded.decode("utf-8"))
    except Exception:
        return decoded.decode("utf-8", errors="replace")


def unix_to_iso(value):
    try:
        timestamp = int(value)
        dt = datetime.fromtimestamp(timestamp, tz=timezone.utc)
        return dt.isoformat()
    except Exception:
        return None


def decode_jwt(token: str) -> dict:
    parts = token.strip().split(".")

    if len(parts) != 3:
        return {
            "valid_format": False,
            "error": "JWT must contain header, payload, and signature parts.",
        }

    header_raw, payload_raw, signature = parts

    try:
        header = decode_base64url(header_raw)
        payload = decode_base64url(payload_raw)

        readable_claims = {}

        if isinstance(payload, dict):
            for key in ["iat", "nbf", "exp"]:
                if key in payload:
                    readable_claims[key] = unix_to_iso(payload[key])

        return {
            "valid_format": True,
            "header": header,
            "payload": payload,
            "signature_present": bool(signature),
            "readable_claims": readable_claims,
            "warning": "This only decodes the JWT. It does not verify the signature or trustworthiness.",
        }

    except Exception as e:
        return {
            "valid_format": False,
            "error": str(e),
        }


def convert_timestamp(value: str) -> dict:
    cleaned = value.strip()

    # Unix timestamp to ISO
    if cleaned.isdigit():
        timestamp = int(cleaned)

        # Handle milliseconds
        if timestamp > 9999999999:
            timestamp = timestamp / 1000

        dt = datetime.fromtimestamp(timestamp, tz=timezone.utc)

        return {
            "input": value,
            "detected_type": "unix",
            "utc": dt.isoformat(),
            "unix_seconds": int(timestamp),
        }

    # ISO/date string to Unix
    try:
        normalized = cleaned.replace("Z", "+00:00")
        dt = datetime.fromisoformat(normalized)

        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)

        return {
            "input": value,
            "detected_type": "datetime",
            "utc": dt.astimezone(timezone.utc).isoformat(),
            "unix_seconds": int(dt.timestamp()),
        }

    except Exception as e:
        return {
            "input": value,
            "detected_type": "unknown",
            "error": str(e),
        }
