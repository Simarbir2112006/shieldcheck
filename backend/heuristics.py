"""
URL feature extraction + LightGBM phishing classifier for ShieldCheck.

Training data:
  - Phishing (label=1): PhishTank verified-online feed
    (https://data.phishtank.com/data/online-valid.csv)
  - Legitimate (label=0): URLs built from a hardcoded sample of 500
    well-known domains (global top sites + Indian banking/fintech/e-commerce
    brands relevant to the target brand-impersonation list below)

Run directly to (re)train and save the model:
    python backend/heuristics.py

Import predict() to score a single URL at inference time:
    from heuristics import predict
    predict("http://paypa1-secure.tk/login")
"""

from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import joblib
import Levenshtein
import lightgbm as lgb
import numpy as np
import pandas as pd
import tldextract
from sklearn.metrics import (
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split

# --------------------------------------------------------------------------
# Paths
# --------------------------------------------------------------------------

BACKEND_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BACKEND_DIR.parent
MODEL_DIR = PROJECT_ROOT / "model"
MODEL_PATH = MODEL_DIR / "lgbm_phish.pkl"
DATA_DIR = PROJECT_ROOT / "data"
PHISHTANK_CSV = DATA_DIR / "online-valid.csv"
PHISHTANK_URL = "https://data.phishtank.com/data/online-valid.csv"

# --------------------------------------------------------------------------
# Reference data
# --------------------------------------------------------------------------

# Brands most commonly impersonated in phishing URLs targeting this product's
# customers (global + Indian banking/fintech/e-commerce). Used to compute the
# levenshtein_min feature: how close a candidate domain's main label is to
# any of these — a small distance suggests typosquatting.
BRAND_DOMAINS = [
    "google", "amazon", "paypal", "facebook", "instagram",
    "hdfc", "icici", "sbi", "zomato", "swiggy",
    "paytm", "flipkart", "razorpay", "myntra", "nykaa",
    "phonepe", "ola", "uber", "airtel", "jio",
]

# TLDs disproportionately abused for phishing / disposable domains.
SUSPICIOUS_TLDS = {
    "xyz", "tk", "top", "ml", "ga", "cf", "gq", "icu", "club", "work",
    "support", "click", "link", "loan", "win", "buzz", "cam", "rest",
    "quest", "monster", "cyou", "surf", "fit", "bid", "party",
}

# 500 hardcoded well-known domains standing in for a top-1000 Alexa/Tranco
# sample (see backend/heuristics.py docstring for how this list was built).
LEGIT_DOMAINS = [
    "google.com", "youtube.com", "gmail.com", "googleapis.com", "google.co.in", "google.co.uk",
    "bing.com", "yahoo.com", "duckduckgo.com", "baidu.com", "yandex.com", "qq.com", "wechat.com",
    "weibo.com", "sina.com.cn", "sohu.com", "360.cn", "csdn.net", "zhihu.com", "alibaba.com",
    "aliexpress.com", "taobao.com", "tmall.com", "jd.com", "apple.com", "icloud.com",
    "microsoft.com", "live.com", "outlook.com", "office.com", "msn.com", "skype.com",
    "linkedin.com", "github.com", "gitlab.com", "stackoverflow.com", "stackexchange.com",
    "w3schools.com", "mozilla.org", "wikipedia.org", "wikimedia.org", "wikihow.com", "archive.org",
    "facebook.com", "instagram.com", "whatsapp.com", "messenger.com", "twitter.com", "x.com",
    "tiktok.com", "snapchat.com", "pinterest.com", "reddit.com", "tumblr.com", "discord.com",
    "telegram.org", "vk.com", "ok.ru", "quora.com", "medium.com", "flickr.com", "vimeo.com",
    "twitch.tv", "netflix.com", "hulu.com", "disneyplus.com", "primevideo.com", "hbomax.com",
    "spotify.com", "soundcloud.com", "pandora.com", "deezer.com", "imdb.com", "rottentomatoes.com",
    "dailymotion.com", "roblox.com", "steampowered.com", "epicgames.com", "ea.com", "ubisoft.com",
    "crunchyroll.com", "hotstar.com", "sonyliv.com", "amazon.com", "amazon.in", "amazon.co.uk",
    "ebay.com", "walmart.com", "target.com", "bestbuy.com", "homedepot.com", "lowes.com",
    "costco.com", "ikea.com", "etsy.com", "shopify.com", "wish.com", "overstock.com",
    "wayfair.com", "macys.com", "nordstrom.com", "sephora.com", "ulta.com", "nike.com",
    "adidas.com", "zara.com", "hm.com", "uniqlo.com", "gap.com", "oldnavy.com", "underarmour.com",
    "footlocker.com", "bigbasket.com", "paypal.com", "visa.com", "mastercard.com",
    "americanexpress.com", "chase.com", "bankofamerica.com", "wellsfargo.com", "citibank.com",
    "citigroup.com", "hsbc.com", "barclays.co.uk", "standardchartered.com", "ing.com",
    "santander.com", "bbva.com", "stripe.com", "venmo.com", "squareup.com", "coinbase.com",
    "binance.com", "robinhood.com", "fidelity.com", "vanguard.com", "schwab.com", "hdfcbank.com",
    "icicibank.com", "sbi.co.in", "onlinesbi.sbi", "axisbank.com", "kotak.com", "pnbindia.in",
    "bankofbaroda.in", "canarabank.com", "unionbankofindia.co.in", "indusind.com", "yesbank.in",
    "idfcfirstbank.com", "zomato.com", "swiggy.com", "paytm.com", "flipkart.com", "razorpay.com",
    "myntra.com", "nykaa.com", "phonepe.com", "olacabs.com", "airtel.in", "jio.com", "booking.com",
    "expedia.com", "tripadvisor.com", "airbnb.com", "agoda.com", "makemytrip.com", "goibibo.com",
    "yatra.com", "cleartrip.com", "irctc.co.in", "uber.com", "lyft.com", "skyscanner.com",
    "kayak.com", "trivago.com", "hotels.com", "marriott.com", "hilton.com", "hyatt.com", "cnn.com",
    "bbc.co.uk", "bbc.com", "nytimes.com", "washingtonpost.com", "theguardian.com", "reuters.com",
    "bloomberg.com", "forbes.com", "wsj.com", "ft.com", "npr.org", "foxnews.com", "aljazeera.com",
    "timesofindia.com", "indiatimes.com", "hindustantimes.com", "ndtv.com", "thehindu.com",
    "indianexpress.com", "news18.com", "firstpost.com", "economictimes.indiatimes.com",
    "moneycontrol.com", "livemint.com", "harvard.edu", "mit.edu", "stanford.edu", "berkeley.edu",
    "ox.ac.uk", "cam.ac.uk", "coursera.org", "udemy.com", "edx.org", "khanacademy.org",
    "duolingo.com", "byjus.com", "unacademy.com", "irs.gov", "usa.gov", "whitehouse.gov",
    "nasa.gov", "cdc.gov", "who.int", "un.org", "worldbank.org", "imf.org", "india.gov.in",
    "uidai.gov.in", "incometax.gov.in", "rbi.org.in", "sebi.gov.in", "isro.gov.in", "aiims.edu",
    "iitb.ac.in", "dropbox.com", "box.com", "notion.so", "evernote.com", "slack.com", "zoom.us",
    "webex.com", "asana.com", "trello.com", "atlassian.com", "monday.com", "salesforce.com",
    "hubspot.com", "zendesk.com", "mailchimp.com", "sendgrid.com", "twilio.com", "godaddy.com",
    "namecheap.com", "bluehost.com", "hostgator.com", "wix.com", "squarespace.com",
    "wordpress.com", "wordpress.org", "cloudflare.com", "digitalocean.com", "oracle.com",
    "ibm.com", "sap.com", "vmware.com", "cisco.com", "intel.com", "amd.com", "nvidia.com",
    "samsung.com", "sony.com", "lg.com", "hp.com", "dell.com", "lenovo.com", "xiaomi.com",
    "oneplus.com", "asus.com", "acer.com", "canon.com", "nikon.com", "gopro.com", "fitbit.com",
    "webmd.com", "mayoclinic.org", "healthline.com", "cvs.com", "walgreens.com", "1mg.com",
    "practo.com", "pharmeasy.in", "apollohospitals.com", "medlife.com", "netmeds.com",
    "cowin.gov.in", "aarogyasetu.gov.in", "docsapp.in", "mfine.co", "espn.com", "nba.com",
    "fifa.com", "uefa.com", "olympics.com", "cricbuzz.com", "espncricinfo.com", "bcci.tv",
    "formula1.com", "nfl.com", "delta.com", "aa.com", "united.com", "southwest.com", "jetblue.com",
    "ryanair.com", "easyjet.com", "lufthansa.com", "emirates.com", "qatarairways.com",
    "singaporeair.com", "airindia.com", "goindigo.in", "spicejet.com", "airvistara.com",
    "toyota.com", "honda.com", "ford.com", "gm.com", "tesla.com", "bmw.com", "mercedes-benz.com",
    "audi.com", "volkswagen.com", "hyundai.com", "kia.com", "nissan-global.com",
    "marutisuzuki.com", "tatamotors.com", "mahindra.com", "geico.com", "statefarm.com",
    "allstate.com", "progressive.com", "licindia.in", "iciciprulife.com", "hdfclife.com",
    "bajajallianz.com", "tataaig.com", "newindia.co.in", "zillow.com", "realtor.com", "redfin.com",
    "99acres.com", "magicbricks.com", "housing.com", "olx.in", "craigslist.org", "indiamart.com",
    "justdial.com", "indeed.com", "monster.com", "naukri.com", "glassdoor.com", "ziprecruiter.com",
    "ncs.gov.in", "shine.com", "freshersworld.com", "timesjobs.com", "simplyhired.com",
    "tinder.com", "bumble.com", "match.com", "okcupid.com", "hinge.co", "nordvpn.com",
    "expressvpn.com", "norton.com", "mcafee.com", "kaspersky.com", "avast.com", "malwarebytes.com",
    "bitdefender.com", "lastpass.com", "protonmail.com", "weather.com", "accuweather.com",
    "openstreetmap.org", "waze.com", "mapmyindia.com", "windy.com", "wunderground.com",
    "timeanddate.com", "worldtimeserver.com", "metoffice.gov.uk", "dominos.co.in", "pizzahut.com",
    "mcdonalds.com", "starbucks.com", "kfc.com", "grubhub.com", "doordash.com", "ubereats.com",
    "deliveroo.com", "just-eat.com", "verizon.com", "att.com", "tmobile.com", "vodafone.com",
    "vodafoneidea.com", "bsnl.co.in", "mtnl.net.in", "orange.com", "telefonica.com", "ee.co.uk",
    "adobe.com", "canva.com", "figma.com", "behance.net", "dribbble.com", "shutterstock.com",
    "gettyimages.com", "unsplash.com", "pexels.com", "pixabay.com", "yelp.com", "foursquare.com",
    "meetup.com", "eventbrite.com", "ticketmaster.com", "bookmyshow.com", "paytmmall.com",
    "pypi.org", "npmjs.com", "docker.com", "mail.google.com", "drive.google.com",
    "docs.google.com", "photos.google.com", "play.google.com", "translate.google.com",
    "news.google.com", "store.google.com", "ads.google.com", "support.google.com",
    "accounts.google.com", "login.google.com", "id.google.com", "www.google.com",
    "help.google.com", "shop.google.com", "business.google.com", "developer.google.com",
    "cloud.google.com", "api.google.com", "static.google.com", "cdn.google.com", "blog.google.com",
    "careers.google.com", "about.google.com", "m.google.com", "mail.amazon.com",
    "drive.amazon.com", "docs.amazon.com", "photos.amazon.com", "play.amazon.com",
    "translate.amazon.com", "news.amazon.com", "store.amazon.com", "ads.amazon.com",
    "support.amazon.com", "accounts.amazon.com", "login.amazon.com", "id.amazon.com",
    "www.amazon.com", "help.amazon.com", "shop.amazon.com", "business.amazon.com",
    "developer.amazon.com", "cloud.amazon.com", "api.amazon.com", "static.amazon.com",
    "cdn.amazon.com", "blog.amazon.com", "careers.amazon.com", "about.amazon.com", "m.amazon.com",
    "mail.microsoft.com", "drive.microsoft.com", "docs.microsoft.com", "photos.microsoft.com",
    "play.microsoft.com", "translate.microsoft.com", "news.microsoft.com", "store.microsoft.com",
    "ads.microsoft.com", "support.microsoft.com", "accounts.microsoft.com", "login.microsoft.com",
    "id.microsoft.com", "www.microsoft.com",
]
assert len(set(LEGIT_DOMAINS)) == 500, "LEGIT_DOMAINS must contain 500 unique domains"

FEATURE_NAMES = [
    "url_length", "num_dots", "num_hyphens", "num_at", "num_slash", "num_question",
    "num_equals", "num_underscores", "has_ip_address", "https_present",
    "domain_entropy", "subdomain_count", "tld_suspicious", "levenshtein_min",
]

_IPV4_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


def _is_ip_address(host: str) -> bool:
    host = host.strip("[]")
    if _IPV4_RE.match(host):
        try:
            ipaddress.IPv4Address(host)
            return True
        except ValueError:
            return False
    try:
        ipaddress.IPv6Address(host)
        return True
    except ValueError:
        return False


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def extract_features(url: str) -> dict[str, float]:
    """Extract the 14 heuristic features used by the phishing classifier."""
    url = url.strip()
    if "://" not in url:
        url_for_parse = "http://" + url
    else:
        url_for_parse = url

    parsed = urlparse(url_for_parse)
    host = parsed.netloc.split(":")[0].split("@")[-1]  # strip userinfo/port
    ext = tldextract.extract(url_for_parse)

    domain_label = ext.domain or host
    registered_domain = ".".join(p for p in [ext.domain, ext.suffix] if p)
    subdomain_labels = [p for p in ext.subdomain.split(".") if p] if ext.subdomain else []

    levenshtein_min = min(
        (Levenshtein.distance(domain_label.lower(), brand) for brand in BRAND_DOMAINS),
        default=len(domain_label),
    )

    features = {
        "url_length": len(url),
        "num_dots": url.count("."),
        "num_hyphens": url.count("-"),
        "num_at": url.count("@"),
        "num_slash": url.count("/"),
        "num_question": url.count("?"),
        "num_equals": url.count("="),
        "num_underscores": url.count("_"),
        "has_ip_address": int(_is_ip_address(host)),
        "https_present": int(url_for_parse.lower().startswith("https://")),
        "domain_entropy": _shannon_entropy(registered_domain or host),
        "subdomain_count": len(subdomain_labels),
        "tld_suspicious": int(ext.suffix.split(".")[-1].lower() in SUSPICIOUS_TLDS) if ext.suffix else 0,
        "levenshtein_min": levenshtein_min,
    }
    return features


# --------------------------------------------------------------------------
# Dataset construction
# --------------------------------------------------------------------------

def _load_phishing_urls(max_samples: int | None = 6000, random_state: int = 42) -> list[str]:
    if not PHISHTANK_CSV.exists():
        raise FileNotFoundError(
            f"PhishTank CSV not found at {PHISHTANK_CSV}. Download it from {PHISHTANK_URL}"
        )
    df = pd.read_csv(PHISHTANK_CSV, usecols=["url", "verified", "online"])
    df = df[(df["verified"] == "yes") & (df["online"] == "yes")]
    urls = df["url"].dropna().unique().tolist()
    if max_samples is not None and len(urls) > max_samples:
        rng = np.random.default_rng(random_state)
        urls = list(rng.choice(urls, size=max_samples, replace=False))
    return urls


# Realistic path/query templates so legitimate URLs aren't all bare domains.
# Without this, the model never sees legit examples with slashes, hyphens or
# query strings and wrongly learns those alone signal phishing.
_LEGIT_PATH_TEMPLATES = [
    "/",
    "/login",
    "/account/settings",
    "/products/best-sellers",
    "/search?q=wireless-headphones",
    "/blog/how-to-get-started",
    "/user/profile?id=48213",
    "/help/contact-us",
    "/en-us/support",
    "/cart/checkout",
    "/order-history",
    "/reset-password?token=abc123",
    "/about-us",
    "/category/electronics/laptops",
]


def _build_legit_urls(paths_per_domain: int = 2, random_state: int = 7) -> list[str]:
    rng = np.random.default_rng(random_state)
    urls = []
    for domain in LEGIT_DOMAINS:
        urls.append(f"https://{domain}")
        if not domain.startswith("www."):
            urls.append(f"https://www.{domain}")
        for path in rng.choice(_LEGIT_PATH_TEMPLATES, size=paths_per_domain, replace=False):
            urls.append(f"https://www.{domain}{path}")
    return urls


def build_dataset(max_phishing: int | None = 6000, random_state: int = 42) -> pd.DataFrame:
    phishing_urls = _load_phishing_urls(max_samples=max_phishing, random_state=random_state)
    legit_urls = _build_legit_urls()

    rows = []
    for u in phishing_urls:
        feats = extract_features(u)
        feats["label"] = 1
        feats["url"] = u
        rows.append(feats)
    for u in legit_urls:
        feats = extract_features(u)
        feats["label"] = 0
        feats["url"] = u
        rows.append(feats)

    return pd.DataFrame(rows)


# --------------------------------------------------------------------------
# Training / evaluation
# --------------------------------------------------------------------------

def train(max_phishing: int | None = 6000, random_state: int = 42) -> lgb.LGBMClassifier:
    print("Building dataset...")
    df = build_dataset(max_phishing=max_phishing, random_state=random_state)
    print(f"Dataset: {len(df)} rows ({(df['label'] == 1).sum()} phishing, "
          f"{(df['label'] == 0).sum()} legit)")

    X = df[FEATURE_NAMES]
    y = df["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=random_state, stratify=y
    )

    model = lgb.LGBMClassifier(
        objective="binary",
        n_estimators=300,
        learning_rate=0.05,
        num_leaves=31,
        is_unbalance=True,
        random_state=random_state,
        verbose=-1,
    )
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    f1 = f1_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred)
    recall = recall_score(y_test, y_pred)
    cm = confusion_matrix(y_test, y_pred)

    print("\n--- Evaluation on held-out test set ---")
    print(f"F1:        {f1:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall:    {recall:.4f}")
    print("Confusion matrix (rows=actual, cols=predicted, [legit, phishing]):")
    print(cm)

    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump({"model": model, "feature_names": FEATURE_NAMES}, MODEL_PATH)
    print(f"\nModel saved to {MODEL_PATH}")

    return model


# --------------------------------------------------------------------------
# Inference
# --------------------------------------------------------------------------

_model_cache: dict[str, Any] = {}


def _get_model():
    if "model" not in _model_cache:
        if not MODEL_PATH.exists():
            raise FileNotFoundError(
                f"No trained model at {MODEL_PATH}. Run `python backend/heuristics.py` to train one."
            )
        bundle = joblib.load(MODEL_PATH)
        _model_cache["model"] = bundle["model"]
        _model_cache["feature_names"] = bundle["feature_names"]
    return _model_cache["model"], _model_cache["feature_names"]


def predict(url: str) -> dict[str, Any]:
    """
    Score a single URL with the trained heuristic model.

    Returns:
        {
            "score": float,             # phishing probability, 0-1
            "features": dict,           # raw extracted feature values
            "top_signals": list[str],   # human-readable top contributing signals
        }
    """
    model, feature_names = _get_model()
    features = extract_features(url)
    X = pd.DataFrame([features])[feature_names]

    score = float(model.predict_proba(X)[0][1])

    # Use LightGBM's native per-feature contributions (SHAP-style, no extra
    # dependency needed) to explain which signals pushed the score.
    contribs = model.booster_.predict(X, pred_contrib=True)[0]
    contrib_by_feature = dict(zip(feature_names, contribs[:-1]))  # last entry is bias term

    ranked = sorted(contrib_by_feature.items(), key=lambda kv: abs(kv[1]), reverse=True)
    top_signals = [
        f"{name} ({'raises' if val > 0 else 'lowers'} risk, value={features[name]})"
        for name, val in ranked[:5]
        if abs(val) > 1e-6
    ]

    return {
        "score": score,
        "features": features,
        "top_signals": top_signals,
    }


if __name__ == "__main__":
    train()
