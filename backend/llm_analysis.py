"""
Note on model choice: the originally requested "gemini-1.5-flash" has been
retired and 404s against the current API. This uses "gemini-flash-lite-latest"
instead of the plain "gemini-flash-latest" alias: the latter currently
resolves to "gemini-3.8-flash", a newer preview-tier model whose free tier
is capped at 20 requests/day (confirmed via a live 429 RESOURCE_EXHAUSTED
response) -- unusable for anything beyond a couple of manual tests. The
"flash-lite" line is built for higher-volume free-tier use, matching the
original "fast, free tier" intent much more closely.

Note on SDK choice: the legacy `google-generativeai` package is fully
deprecated ("no longer receiving updates or bug fixes" per its own runtime
warning). This uses the current `google-genai` package instead.
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from typing import Any

from google import genai
from google.genai import types
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

GOOGLE_AI_KEY = os.getenv("GOOGLE_AI_STUDIO_KEY")
MODEL_NAME = "gemini-flash-lite-latest"

_FALLBACK_RESULT = {
    "llm_score": 0.0,
    "llm_signals": [],
    "llm_summary": "Analysis unavailable.",
}

SYSTEM_PROMPT = """You are a cybersecurity analyst specializing in phishing detection for small
businesses. Analyze the following email text and return ONLY a JSON object
with no markdown, no explanation, just raw JSON.

Return this exact structure:
{
  "llm_score": <float 0.0 to 1.0, where 1.0 = definitely phishing>,
  "llm_signals": [<list of strings, each a specific red flag you found>],
  "llm_summary": "<one sentence plain-English verdict for a non-technical user>"
}

Score guide:
0.0-0.3: Looks legitimate
0.3-0.6: Suspicious, some red flags
0.6-0.8: Likely phishing
0.8-1.0: Almost certainly phishing

Signals to look for (include only those present):
- urgent_language: "act now", "account suspended", "immediate action"
- sender_spoofing: display name doesn't match email domain
- credential_request: asks for password, OTP, card number
- payment_urgency: unpaid invoice, GST penalty, fine threatened
- suspicious_link: URL in email doesn't match claimed sender
- generic_greeting: "Dear Customer" instead of recipient's name
- prize_scam: lottery, prize, gift card offer
- impersonation: claims to be HDFC, SBI, GST portal, PayPal, etc.
"""

_client: genai.Client | None = None


def _get_client() -> genai.Client:
    global _client
    if _client is None:
        if not GOOGLE_AI_KEY:
            raise RuntimeError("GOOGLE_AI_STUDIO_KEY is not set")
        _client = genai.Client(api_key=GOOGLE_AI_KEY)
    return _client


def _parse_response(text: str) -> dict[str, Any]:
    text = text.strip()
    if text.startswith("```"):
        text = text.strip("`")
        if text.lower().startswith("json"):
            text = text[4:]
    parsed = json.loads(text)
    return {
        "llm_score": float(parsed["llm_score"]),
        "llm_signals": list(parsed["llm_signals"]),
        "llm_summary": str(parsed["llm_summary"]),
    }


async def _call_gemini(email_text: str, retry_note: str | None = None) -> str:
    client = _get_client()
    prompt = SYSTEM_PROMPT
    if retry_note:
        prompt += f"\n\nIMPORTANT: {retry_note}"
    prompt += f"\n\nEmail text to analyze:\n---\n{email_text}\n---"

    response = await client.aio.models.generate_content(
        model=MODEL_NAME,
        contents=prompt,
        config=types.GenerateContentConfig(response_mime_type="application/json"),
    )
    return response.text


async def analyze(email_text: str) -> dict[str, Any]:
    """
    Retries once on failure. A JSON-parsing failure retries with an added
    note to return raw JSON; any other failure (e.g. a transient 5xx from
    Gemini being overloaded) retries the same prompt unchanged, since a
    formatting note wouldn't address a server error.
    """
    retry_note = None
    try:
        raw = await _call_gemini(email_text)
        return _parse_response(raw)
    except (json.JSONDecodeError, KeyError, TypeError, ValueError):
        retry_note = "return ONLY raw JSON, no markdown fences"
    except Exception:
        # Likely a transient 5xx/rate-limit from the free-tier API; give it
        # a moment before the retry instead of hammering it again instantly.
        await asyncio.sleep(2)

    try:
        raw = await _call_gemini(email_text, retry_note=retry_note)
        return _parse_response(raw)
    except Exception:
        return dict(_FALLBACK_RESULT)
