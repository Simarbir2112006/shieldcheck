"""FastAPI app exposing the ShieldCheck scan endpoint."""

from __future__ import annotations

import csv
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

import scanner

app = FastAPI(title="ShieldCheck")

SCAN_LOG_PATH = Path(__file__).resolve().parent / "scan_log.csv"
SCAN_LOG_FIELDS = [
    "timestamp",
    "url",
    "email_provided",
    "score",
    "verdict",
    "heuristics_score",
    "vt_malicious",
    "vt_total",
    "sb_flagged",
    "llm_score",
    "llm_signals",
    "detection_note",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ScanRequest(BaseModel):
    url: str
    email_text: str | None = None


def _log_scan(url: str, email_text: str | None, result: dict[str, Any]) -> None:
    try:
        signals = result["signals"]
        llm = signals.get("llm")
        row = {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "url": url,
            "email_provided": bool(email_text),
            "score": result["score"],
            "verdict": result["verdict"],
            "heuristics_score": signals["heuristics"]["score"],
            "vt_malicious": signals["virustotal"]["vt_malicious"],
            "vt_total": signals["virustotal"]["vt_total"],
            "sb_flagged": signals["safe_browsing"]["sb_flagged"],
            "llm_score": llm["llm_score"] if llm else "",
            "llm_signals": "|".join(llm["llm_signals"]) if llm else "",
            "detection_note": result.get("detection_note", ""),
        }
        file_exists = os.path.exists(SCAN_LOG_PATH)
        with open(SCAN_LOG_PATH, "a", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=SCAN_LOG_FIELDS)
            if not file_exists:
                writer.writeheader()
            writer.writerow(row)
    except Exception:
        pass


@app.post("/scan")
async def scan_endpoint(request: ScanRequest):
    result = await scanner.scan(request.url, request.email_text)
    _log_scan(request.url, request.email_text, result)
    return result


@app.get("/health")
async def health():
    return {"status": "ok"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
