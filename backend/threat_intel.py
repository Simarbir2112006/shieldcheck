from __future__ import annotations

import asyncio
import os
from pathlib import Path
from typing import Any

import httpx
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
SAFE_BROWSING_API_KEY = os.getenv("SAFE_BROWSING_API_KEY")

VT_BASE_URL = "https://www.virustotal.com/api/v3"
SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

_POLL_ATTEMPTS = 3
_POLL_DELAY_SECONDS = 2
_REQUEST_TIMEOUT = 15.0


async def check_virustotal(url: str) -> dict[str, Any]:
    """
    Note: the analysis ID used to poll GET /analyses/{id} is the opaque id
    VirusTotal returns in the POST /urls response body (data.id) — it is
    NOT the base64-encoded URL. (The base64-encoded URL is a *different*
    identifier, used only for the separate GET /urls/{id} endpoint, which
    looks up a URL object's last known scan rather than a fresh analysis.)
    """
    try:
        if not VIRUSTOTAL_API_KEY:
            raise RuntimeError("VIRUSTOTAL_API_KEY is not set")

        headers = {"x-apikey": VIRUSTOTAL_API_KEY}

        async with httpx.AsyncClient(timeout=_REQUEST_TIMEOUT) as client:
            submit_resp = await client.post(
                f"{VT_BASE_URL}/urls",
                headers=headers,
                data={"url": url},
            )
            submit_resp.raise_for_status()
            analysis_id = submit_resp.json()["data"]["id"]

            vt_cached = False
            data = None
            for attempt in range(_POLL_ATTEMPTS):
                analysis_resp = await client.get(
                    f"{VT_BASE_URL}/analyses/{analysis_id}",
                    headers=headers,
                )
                analysis_resp.raise_for_status()
                data = analysis_resp.json()
                status = data["data"]["attributes"]["status"]
                if status == "queued" and attempt < _POLL_ATTEMPTS - 1:
                    await asyncio.sleep(_POLL_DELAY_SECONDS)
                    continue
                vt_cached = status == "completed"
                break

            stats = data["data"]["attributes"]["stats"]
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total = sum(stats.values())
            vt_score = (malicious + suspicious) / total if total else 0.0

            return {
                "vt_score": vt_score,
                "vt_malicious": malicious,
                "vt_total": total,
                "vt_cached": vt_cached,
            }
    except Exception as e:
        return {
            "vt_score": 0.0,
            "vt_malicious": 0,
            "vt_total": 0,
            "vt_error": str(e),
        }


async def check_safe_browsing(url: str) -> dict[str, Any]:
    try:
        if not SAFE_BROWSING_API_KEY:
            raise RuntimeError("SAFE_BROWSING_API_KEY is not set")

        body = {
            "client": {"clientId": "shieldcheck", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION",
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }

        async with httpx.AsyncClient(timeout=_REQUEST_TIMEOUT) as client:
            resp = await client.post(
                SAFE_BROWSING_URL,
                params={"key": SAFE_BROWSING_API_KEY},
                json=body,
            )
            resp.raise_for_status()
            data = resp.json()

        matches = data.get("matches", [])
        if matches:
            return {"sb_flagged": True, "sb_threat_type": matches[0].get("threatType")}
        return {"sb_flagged": False, "sb_threat_type": None}
    except Exception as e:
        return {"sb_flagged": False, "sb_error": str(e)}
