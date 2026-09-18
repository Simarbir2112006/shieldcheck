# ShieldCheck

**Phishing and scam detection for small businesses in India.**

Paste a suspicious URL or email and get a plain-English verdict in under 5 seconds. No technical knowledge required.

🔗 **[Live Demo](https://shieldcheck-lime.vercel.app)**

---

## The Problem

Small businesses in India are the #1 target for phishing attacks — fake GST notices, HDFC/SBI impersonation, UPI fraud, bogus vendor invoices. They have no IT team to ask. ShieldCheck gives them a 30-second answer.

---

## How It Works

ShieldCheck runs every URL and email through four independent detection layers, then combines them into a single calibrated risk score (0–100):

| Layer | What it does | Weight |
|---|---|---|
| **URL Heuristics** | LightGBM classifier trained on PhishTank + OpenPhish. 18 URL-level features: domain entropy, typosquatting distance, redirect depth, HTTPS presence, subdomain count. | 30–45% |
| **VirusTotal** | Checks against 90+ antivirus engines via the VT API. | 25–40% |
| **Google Safe Browsing** | Reputation lookup against Google's threat database. | 10–15% |
| **LLM Analysis** | Gemini analyzes email text for urgency language, sender spoofing, credential harvesting, and impersonation signals. | 10–35% (when email provided) |

**Calibration decisions:**
- If both the ML classifier and LLM independently flag high risk (heuristics > 0.85, LLM > 0.70), the score is floored at 70 ("suspicious") even without threat intel confirmation — to catch fresh phishing campaigns that haven't hit VirusTotal yet.
- If the LLM detects strong email-based phishing signals (LLM > 0.85) with email provided, score is floored at 40 — email analysis takes precedence over a clean URL reputation.
- These floors reflect a deliberate false-negative vs false-positive tradeoff: for small businesses, a missed phishing attack is far more costly than a false alarm.

---

## Architecture

```
frontend/index.html          # Single-file HTML/CSS/JS, no build step
backend/
  main.py                    # FastAPI app, /scan endpoint
  scanner.py                 # Score aggregation + calibration logic
  heuristics.py              # LightGBM feature extraction + inference
  virustotal.py              # VT API client
  safe_browsing.py           # Google Safe Browsing client
  llm_analysis.py            # Gemini API client
  model/                     # Trained LightGBM model + scaler
tests/
  test_heuristics.py
  test_virustotal.py
  test_safe_browsing.py
  test_llm.py
  test_scan.py               # End-to-end pipeline tests (6 tests)
```

**Stack:** FastAPI · LightGBM · Google Gemini · VirusTotal API · Google Safe Browsing API · Vanilla JS · Deployed on Render + Vercel

---

## Running Locally

**Prerequisites:** Python 3.10+, API keys for VirusTotal, Google AI (Gemini), and Google Safe Browsing.

```bash
git clone https://github.com/YOUR_USERNAME/shieldcheck.git
cd shieldcheck

# Backend
cd backend
pip install -r requirements.txt
cp ../.env.example .env   # Fill in your API keys
uvicorn main:app --reload --port 8000

# Frontend (separate terminal)
cd ../frontend
# Update BACKEND_URL in index.html to http://localhost:8000
open index.html           # or xdg-open on Linux
```

---

## API

```
POST /scan
Content-Type: application/json

{
  "url": "https://example.com",
  "email_text": "Dear customer, your account is suspended..."  // optional
}
```

Response:
```json
{
  "url": "https://example.com",
  "score": 72.4,
  "verdict": "suspicious",
  "verdict_message": "Proceed with caution. Verify before clicking.",
  "detection_note": "Flagged by local ML and LLM analysis...",
  "signals": {
    "heuristics": { "score": 0.91, "top_signals": ["..."] },
    "virustotal": { "vt_malicious": 0, "vt_total": 90 },
    "safe_browsing": { "sb_flagged": false },
    "llm": { "llm_score": 0.95, "llm_signals": ["..."], "llm_summary": "..." }
  }
}
```

---

## Tests

```bash
cd backend
pytest tests/ -v
```

All 6 tests cover: URL heuristics, VirusTotal parsing, Safe Browsing flagging, LLM phishing detection, end-to-end pipeline scoring, and the two calibration floor rules.

---

## Environment Variables

See `.env.example` for required keys:

| Variable | Where to get it |
|---|---|
| `VT_API_KEY` | [virustotal.com](https://www.virustotal.com) — free tier |
| `GOOGLE_AI_KEY` | [aistudio.google.com](https://aistudio.google.com) — free tier |
| `SAFE_BROWSING_KEY` | [Google Cloud Console](https://console.cloud.google.com) — free |

---

## License

MIT © 2026 Simarbir Singh Sandhu
