# ShieldCheck

**Phishing and scam detection for small businesses in India.**

Paste a suspicious URL or email and get a plain-English verdict in under 5 seconds. No technical knowledge required.

🔗 **[Live Demo](https://shieldcheck-lime.vercel.app)**

---

## The Problem

Small businesses in India are the #1 target for phishing attacks — fake GST notices, HDFC/SBI impersonation, UPI fraud, bogus vendor invoices. They have no IT team to ask. They either click (bad) or ignore legitimate emails (also bad). ShieldCheck gives them a 30-second answer.

---

## How It Works

ShieldCheck runs every URL and email through four independent detection layers, then combines them into a single calibrated risk score (0–100):

| Layer | What it does | Weight |
|---|---|---|
| **URL Heuristics** | LightGBM classifier trained on PhishTank + OpenPhish. 18 URL-level features: domain entropy, typosquatting distance, redirect depth, HTTPS presence, subdomain count. | 30–45% |
| **VirusTotal** | Checks against 90+ antivirus engines via the VT API. | 25–40% |
| **Google Safe Browsing** | Reputation lookup against Google's threat database. | 10–15% |
| **LLM Analysis** | Gemini analyzes email text for urgency language, sender spoofing, credential harvesting, and impersonation signals. | 10–35% (when email provided) |

Verdicts are returned as:

| Score | Verdict |
|---|---|
| 0–39 | ✅ Looks Safe |
| 40–74 | ⚠️ Suspicious — Proceed with Caution |
| 75–100 | 🚨 Dangerous — Do Not Click |

---

## Architecture

```
frontend/index.html          # Single-file HTML/CSS/JS, no build step
backend/
  main.py                    # FastAPI app, /scan endpoint + CSV scan logger
  scanner.py                 # Score aggregation + calibration logic
  heuristics.py              # LightGBM feature extraction + inference
  threat_intel.py            # VirusTotal + Google Safe Browsing clients
  llm_analysis.py            # Gemini API client
  model/                     # Trained LightGBM model + scaler
tests/
  test_heuristics.py
  test_virustotal.py
  test_safe_browsing.py
  test_llm.py
  test_scan.py               # End-to-end pipeline tests (7 tests)
```

**Stack:** FastAPI · LightGBM · Google Gemini · VirusTotal API · Google Safe Browsing API · Vanilla JS · Deployed on Render + Vercel

---

## Detection Pipeline — Design Decisions

These are the non-obvious decisions made during development and the reasoning behind each.

### 1. Why four layers instead of just VirusTotal?

VirusTotal and Google Safe Browsing have no data on fresh phishing campaigns — a brand-new domain registered this morning returns zero hits on both. This is the most dangerous case for small businesses, who are frequently targeted by campaigns that haven't hit threat intel feeds yet. The LightGBM heuristics layer and Gemini LLM layer operate entirely on the URL and email content itself, with no dependency on reputation databases. They catch what VT/SB miss.

### 2. Calibration floor rules

Two explicit floor rules override the weighted score when local detection layers strongly agree:

**Floor 1 — Heuristics + LLM agreement:**
If `heuristics_score > 0.85` AND `llm_score > 0.70`, the score is floored at 70 ("suspicious") regardless of VT/SB data. Both independent local layers agree this is high risk. A `detection_note` is added to the response: *"Flagged by local ML and LLM analysis. Threat intel has no data yet (possibly a new campaign)."*

**Floor 2 — Strong LLM signal on email:**
If email text is provided AND `llm_score > 0.85`, the score is floored at 40 ("suspicious") regardless of URL reputation. When a user hands you an email for analysis and the LLM is highly confident it's phishing, a clean URL reputation is not sufficient to call it safe.

**The tradeoff:** Both floors deliberately bias toward false positives over false negatives. For small businesses, a missed phishing attack (credential theft, financial fraud) is far more costly than a false alarm on a legitimate email. Alert fatigue is a secondary concern here.

### 3. Email-aware weight rebalancing

When email text is provided and `llm_score > 0.60`, the layer weights shift:

| Mode | Heuristics | VirusTotal | Safe Browsing | LLM |
|---|---|---|---|---|
| URL only | 40% | 45% | 15% | — |
| URL + email (LLM < 0.60) | 35% | 40% | 15% | 10% |
| URL + email (LLM > 0.60) | 30% | 25% | 10% | 35% |

When the LLM finds strong phishing signals in the email content, it earns more weight. Threat intel APIs are demoted because they're less informative than explicit semantic evidence in the email itself.

### 4. Why LightGBM for URL heuristics?

LightGBM trains fast, handles tabular features well, and is interpretable via SHAP — the top 5 features driving each prediction are returned in the API response as `top_signals`. This lets users and developers understand why a URL was flagged, not just that it was flagged. Explainability is a first-class requirement for any security tool used by non-technical users.

### 5. Why Gemini over GPT-4 or Claude?

Gemini Flash Lite has a higher free-tier rate limit than alternatives, which matters at the current scale. The model is prompted to return structured JSON directly via `response_mime_type="application/json"`, which eliminates markdown fence parsing issues. The prompt includes a retry-once mechanism: on JSON parse failure, it retries with an explicit "return raw JSON only" note. On second failure, it returns a safe fallback `{"llm_score": 0.0, "llm_signals": [], "llm_summary": "Analysis unavailable."}` — a logging failure should never crash the endpoint.

### 6. CSV scan logger

Every successful `/scan` call appends a row to `scan_log.csv` with timestamp, URL, score, verdict, and all signal values. The logger is wrapped in `try/except` — a logging failure never surfaces to the user. This generates the operational data needed to track real usage, tune weights over time, and validate model performance in production.

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
  "detection_note": "Flagged by local ML and LLM analysis. Threat intel has no data yet (possibly a new campaign).",
  "signals": {
    "heuristics": {
      "score": 0.91,
      "top_signals": ["https_present (raises risk)", "levenshtein_min (raises risk, value=5)"]
    },
    "virustotal": { "vt_malicious": 0, "vt_total": 90, "vt_cached": false },
    "safe_browsing": { "sb_flagged": false, "sb_threat_type": null },
    "llm": {
      "llm_score": 0.95,
      "llm_signals": ["urgent_language", "credential_request", "impersonation"],
      "llm_summary": "This email is impersonating HDFC Bank to steal your OTP."
    }
  }
}
```

---

## Running Locally

**Prerequisites:** Python 3.10+, API keys for VirusTotal, Google AI (Gemini), and Google Safe Browsing.

```bash
git clone https://github.com/Simarbir2112006/shieldcheck.git
cd shieldcheck

# Backend
cd backend
pip install -r requirements.txt
cp ../.env.example .env   # Fill in your API keys
uvicorn main:app --reload --port 8000

# Frontend (separate terminal)
cd ../frontend
# Update BACKEND_URL in index.html to http://localhost:8000
xdg-open index.html       # or: open index.html on Mac
```

---

## Tests

```bash
cd backend
pytest tests/ -v
```

7 tests covering: URL heuristics, VirusTotal response parsing, Safe Browsing flagging, LLM phishing detection, end-to-end pipeline scoring, both calibration floor rules, and CSV scan logger output.

---

## Environment Variables

See `.env.example` for required keys:

| Variable | Where to get it |
|---|---|
| `VT_API_KEY` | [virustotal.com](https://www.virustotal.com) — free tier, 500 req/day |
| `GOOGLE_AI_STUDIO_KEY` | [aistudio.google.com](https://aistudio.google.com) — free tier |
| `SAFE_BROWSING_API_KEY` | [Google Cloud Console](https://console.cloud.google.com) — free |

---

## Deployment

- **Backend:** Render (free tier) — spins down after 15 min inactivity; first request after cold start takes ~30s
- **Frontend:** Vercel (free tier) — always on, globally distributed

---

## License

MIT © 2026 Simarbir Singh Sandhu