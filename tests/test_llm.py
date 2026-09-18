"""Hits the real Gemini API via llm_analysis.analyze() with fabricated emails."""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))

from llm_analysis import analyze  # noqa: E402

PHISHING_EMAIL = """\
Subject: URGENT: Your HDFC Account Has Been Suspended

Dear Customer,

We have detected unusual activity on your HDFC Bank account and it has been
temporarily SUSPENDED for your protection. You must verify your identity
within 24 hours or your account will be permanently blocked.

Click here to verify now: http://hdfc-bank-verify.secure-update.tk/login

You will need to enter your Net Banking password and the OTP sent to your
registered mobile number to restore access.

Act now to avoid permanent suspension.

HDFC Bank Security Team
"""

LEGITIMATE_EMAIL = """\
Subject: Quick sync tomorrow?

Hi Priya,

Do you have 30 minutes tomorrow afternoon to go over the Q3 roadmap doc
before we share it with the wider team? I'm free after 2pm, but happy to
work around your schedule.

I'll send a calendar invite once we settle on a time.

Thanks,
Raj
"""


@pytest.mark.asyncio
async def test_analyze_phishing_email():
    result = await analyze(PHISHING_EMAIL)
    print(json.dumps(result, indent=2))
    assert result["llm_score"] > 0.6


@pytest.mark.asyncio
async def test_analyze_legitimate_email():
    result = await analyze(LEGITIMATE_EMAIL)
    print(json.dumps(result, indent=2))
    assert result["llm_score"] < 0.4
