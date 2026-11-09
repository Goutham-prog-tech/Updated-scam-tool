# AI Scam Awareness Tool

A bilingual (English / Telugu) web app that checks a suspicious message (typed, pasted, or read from screenshots) and shows which common scam warning signs it contains, why they are dangerous, and what to do next. It never says "100% scam": it reports *potential scam indicators* because no classifier is perfect.

## Features
- Weighted rule engine (English, Telugu, Hindi/Hinglish) + machine-learning score (TF-IDF + Logistic Regression)
- Messages up to 5000 characters; screenshots are read on the user's own device (OCR) and never uploaded
- Risk meter, reasons, recommended actions, and the national Cyber Crime Helpline (1930, cybercrime.gov.in)
- Voice assistant (English / Telugu / Hindi, male or female voice) that reads the warning aloud
- Language chooser, light (default) / dark / high-contrast themes, text-size settings; clean, flat, mobile-first layout
- Risk indicator stays pinned at the top of the results while scrolling
- Male voice is deep/bass in every language (lowered pitch when the device has no real male voice)
- Security: strict nonce-based Content-Security-Policy, HSTS, cross-site POST (CSRF) blocking, spoof-proof rate limiting, JSON-only input validation, whitelists, generic error pages, request-size limits

## Run on your computer
```
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python train_model.py
python app.py
```
Then open http://127.0.0.1:5000

## Security settings (environment variables)
| Variable | Meaning |
|---|---|
| TRUSTED_PROXIES | Proxies in front of the app (Render = 1, default). Use 0 when running locally without a proxy. |
| ALLOWED_HOSTS | Optional, e.g. `yourapp.onrender.com`. Requests for any other host name are rejected. |
| RATE_LIMIT | Requests per minute per visitor (default 120). |

No website can be made 100% unhackable. This one is hardened against the common attacks; keep dependencies updated.

## Deploy (Render)
- Build command: `pip install -r requirements.txt && python train_model.py`
- Start command: `gunicorn app:app`

## Project structure
| Path | Purpose |
|---|---|
| app.py | Flask server, routes, security headers, rate limiting |
| analyzer.py | Rule engine, scoring, language detection |
| train_model.py | Trains the ML model from data/messages.csv |
| templates/index.html | Web page (HTML + CSS + JavaScript) |
| static/ | Fonts and the in-browser OCR engine |
| ocr_lang/ | OCR language data (English, Telugu, Hindi) |

This tool is an awareness aid and can make mistakes. Always verify suspicious messages independently.
