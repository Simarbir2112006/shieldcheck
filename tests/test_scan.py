"""Hits POST /scan (in-process, no server needed) and prints the full response."""

import csv
import json
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))

import heuristics  # noqa: E402
import llm_analysis  # noqa: E402
import threat_intel  # noqa: E402
from main import app, SCAN_LOG_PATH  # noqa: E402


@pytest.mark.asyncio
async def test_scan_safe_url():
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post("/scan", json={"url": "https://google.com"})
    assert resp.status_code == 200
    data = resp.json()
    print(json.dumps(data, indent=2))
    assert data["verdict"] == "safe"


@pytest.mark.asyncio
async def test_scan_dangerous_url(monkeypatch):
    # This URL is a synthetic example that was never actually deployed or
    # crawled, so real VirusTotal/Safe Browsing lookups correctly return "no
    # data" for it rather than "malicious" -- and heuristics alone are capped
    # at 40% of the score, so no URL can hit the "dangerous" band on
    # heuristics alone. Mock the threat-intel layer to simulate a URL that
    # heuristics AND external intel agree is malicious, so this test
    # exercises the scanner's aggregation/verdict logic deterministically.
    monkeypatch.setattr(
        threat_intel,
        "check_virustotal",
        AsyncMock(return_value={"vt_score": 0.8, "vt_malicious": 40, "vt_total": 50, "vt_cached": True}),
    )
    monkeypatch.setattr(
        threat_intel,
        "check_safe_browsing",
        AsyncMock(return_value={"sb_flagged": True, "sb_threat_type": "SOCIAL_ENGINEERING"}),
    )

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post(
            "/scan",
            json={"url": "http://paypal-login.suspicious-update.tk/verify"},
        )
    assert resp.status_code == 200
    data = resp.json()
    print(json.dumps(data, indent=2))
    assert data["verdict"] == "dangerous"


@pytest.mark.asyncio
async def test_scan_local_agreement_floors_score(monkeypatch):
    # Both local layers (heuristics + LLM) strongly agree it's phishing, but
    # threat intel has no data on it yet (brand-new/unlisted domain). The
    # override rule should floor the score at 70 regardless of the
    # threat-intel weight, and attach a detection_note explaining why.
    monkeypatch.setattr(
        heuristics,
        "predict",
        MagicMock(return_value={"score": 0.9997, "features": {}, "top_signals": []}),
    )
    monkeypatch.setattr(
        llm_analysis,
        "analyze",
        AsyncMock(
            return_value={
                "llm_score": 0.95,
                "llm_signals": ["urgent_language", "credential_request"],
                "llm_summary": "This looks like a phishing attempt.",
            }
        ),
    )
    monkeypatch.setattr(
        threat_intel,
        "check_virustotal",
        AsyncMock(return_value={"vt_score": 0.0, "vt_malicious": 0, "vt_total": 0, "vt_cached": False}),
    )
    monkeypatch.setattr(
        threat_intel,
        "check_safe_browsing",
        AsyncMock(return_value={"sb_flagged": False, "sb_threat_type": None}),
    )

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post(
            "/scan",
            json={
                "url": "http://brand-new-phishing-domain.tk/verify",
                "email_text": "Dear Customer, your account is suspended. Enter your OTP now.",
            },
        )
    assert resp.status_code == 200
    data = resp.json()
    print(json.dumps(data, indent=2))
    assert data["score"] >= 70.0
    assert "detection_note" in data


@pytest.mark.asyncio
async def test_scan_strong_llm_signal_floors_score_on_clean_url(monkeypatch):
    # The URL itself looks clean and threat intel has nothing on it, but the
    # LLM finds strong phishing signals in the email content the user pasted
    # in. The LLM-alone floor rule should still push this to "suspicious".
    monkeypatch.setattr(
        heuristics,
        "predict",
        MagicMock(return_value={"score": 0.001, "features": {}, "top_signals": []}),
    )
    monkeypatch.setattr(
        llm_analysis,
        "analyze",
        AsyncMock(
            return_value={
                "llm_score": 0.92,
                "llm_signals": ["urgent_language", "credential_request", "impersonation"],
                "llm_summary": "This email shows strong signs of phishing.",
            }
        ),
    )
    monkeypatch.setattr(
        threat_intel,
        "check_virustotal",
        AsyncMock(return_value={"vt_score": 0.0, "vt_malicious": 0, "vt_total": 0, "vt_cached": False}),
    )
    monkeypatch.setattr(
        threat_intel,
        "check_safe_browsing",
        AsyncMock(return_value={"sb_flagged": False, "sb_threat_type": None}),
    )

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post(
            "/scan",
            json={
                "url": "https://www.some-clean-looking-site.com",
                "email_text": "Dear Customer, your account is suspended. Enter your OTP now.",
            },
        )
    assert resp.status_code == 200
    data = resp.json()
    print(json.dumps(data, indent=2))
    assert data["score"] >= 40.0
    assert data["verdict"] != "safe"


@pytest.fixture
def clean_scan_log():
    if SCAN_LOG_PATH.exists():
        SCAN_LOG_PATH.unlink()
    yield
    if SCAN_LOG_PATH.exists():
        SCAN_LOG_PATH.unlink()


@pytest.mark.asyncio
async def test_scan_logger_writes_csv(monkeypatch, clean_scan_log):
    monkeypatch.setattr(
        threat_intel,
        "check_virustotal",
        AsyncMock(return_value={"vt_score": 0.8, "vt_malicious": 40, "vt_total": 50, "vt_cached": True}),
    )
    monkeypatch.setattr(
        threat_intel,
        "check_safe_browsing",
        AsyncMock(return_value={"sb_flagged": True, "sb_threat_type": "SOCIAL_ENGINEERING"}),
    )

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.post(
            "/scan",
            json={"url": "http://paypal-login.suspicious-update.tk/verify"},
        )
    assert resp.status_code == 200
    data = resp.json()

    assert SCAN_LOG_PATH.exists()
    with open(SCAN_LOG_PATH, newline="") as f:
        rows = list(csv.DictReader(f))
    assert len(rows) == 1
    assert rows[0]["verdict"] == data["verdict"]
    assert rows[0]["url"] == "http://paypal-login.suspicious-update.tk/verify"
