import json
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def run_maigret_search(username: str, timeout: int = 120) -> dict:
    username = username.strip().lstrip("@")
    if not username:
        return {"error": "No username provided", "username": username}

    with tempfile.TemporaryDirectory() as tmpdir:
        output_path = Path(tmpdir) / "maigret_output.json"
        try:
            cmd = [
                "maigret", username,
                "--json", str(output_path),
                "--timeout", "15",
                "--no-color",
                "--no-progress",
            ]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )

            sites = {}
            if output_path.exists():
                raw = output_path.read_text()
                sites = json.loads(raw) if raw.strip() else {}

            stderr_summary = result.stderr.strip() if result.stderr else ""

            return {
                "username": username,
                "status": "completed" if result.returncode == 0 else "partial",
                "sites_found": len(sites),
                "sites": sites,
                "notes": stderr_summary[:500] if stderr_summary else "Maigret search completed.",
                "checked_at": utc_now(),
            }

        except subprocess.TimeoutExpired:
            return {
                "username": username,
                "status": "timeout",
                "sites_found": 0,
                "sites": {},
                "notes": f"Maigret timed out after {timeout}s. Try a more specific username.",
                "checked_at": utc_now(),
            }
        except FileNotFoundError:
            return {
                "username": username,
                "status": "error",
                "sites_found": 0,
                "sites": {},
                "notes": "Maigret CLI not found. Install with: pip install maigret",
                "checked_at": utc_now(),
            }
        except Exception as e:
            return {
                "username": username,
                "status": "error",
                "sites_found": 0,
                "sites": {},
                "notes": f"Maigret error: {str(e)}",
                "checked_at": utc_now(),
            }
