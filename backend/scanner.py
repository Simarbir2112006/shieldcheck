"""Orchestrates the heuristics, threat-intel, and LLM detection layers."""

from __future__ import annotations

import asyncio
from typing import Any

import heuristics
import llm_analysis
import threat_intel


def _verdict_for(score: float) -> tuple[str, str]:
    if score < 40:
        return "safe", "Looks clean. No signals detected."
    if score < 75:
        return "suspicious", "Proceed with caution. Verify before clicking."
    return "dangerous", "High risk. Do not open. Report this."


async def scan(url: str, email_text: str | None = None) -> dict[str, Any]:
    loop = asyncio.get_running_loop()

    tasks = [
        loop.run_in_executor(None, heuristics.predict, url),
        threat_intel.check_virustotal(url),
        threat_intel.check_safe_browsing(url),
    ]
    if email_text:
        tasks.append(llm_analysis.analyze(email_text))

    results = await asyncio.gather(*tasks)
    heuristics_result, vt_result, sb_result = results[0], results[1], results[2]
    llm_result = results[3] if email_text else None

    heuristics_score = heuristics_result["score"]
    vt_score = vt_result["vt_score"]
    sb_flagged = sb_result["sb_flagged"]
    llm_score = llm_result["llm_score"] if llm_result else 0.0

    if email_text and llm_score > 0.60:
        # Strong LLM signal on user-supplied email content is more
        # trustworthy here than VT/SB, which have no data on fresh
        # campaigns -- weight the semantic analysis more heavily.
        score = (
            heuristics_score * 0.30
            + vt_score * 0.25
            + (1.0 if sb_flagged else 0.0) * 0.10
            + llm_score * 0.35
        ) * 100
    elif email_text:
        score = (
            heuristics_score * 0.35
            + vt_score * 0.40
            + (1.0 if sb_flagged else 0.0) * 0.15
            + llm_score * 0.10
        ) * 100
    else:
        score = (
            heuristics_score * 0.40
            + vt_score * 0.45
            + (1.0 if sb_flagged else 0.0) * 0.15
        ) * 100

    detection_note = None

    # A strong standalone LLM signal on user-supplied email content floors
    # the score at 40 (minimum "suspicious"), even if the URL itself looks
    # clean and threat intel has nothing on it.
    if email_text and llm_score > 0.85 and score < 40.0:
        score = 40.0
        detection_note = (
            "Strong phishing signals detected in email content. Treat this "
            "email with caution regardless of URL reputation."
        )

    # If both local detection layers strongly agree it's phishing, floor the
    # score at 70 so it's at minimum "suspicious" even without threat intel
    # confirmation. VT/SB data can still push it above 75 into "dangerous".
    # This takes priority over the LLM-alone floor above when both fire.
    if heuristics_score > 0.85 and llm_score > 0.70 and score < 70.0:
        score = 70.0
        detection_note = (
            "Flagged by local ML and LLM analysis. Threat intel has no "
            "data yet (possibly a new campaign)."
        )

    verdict, verdict_message = _verdict_for(score)

    result = {
        "url": url,
        "score": score,
        "verdict": verdict,
        "verdict_message": verdict_message,
        "signals": {
            "heuristics": heuristics_result,
            "virustotal": vt_result,
            "safe_browsing": sb_result,
            "llm": llm_result,
        },
    }
    if detection_note:
        result["detection_note"] = detection_note
    return result
