import os
import secrets
import threading
import time
from collections import defaultdict, deque

from flask import Flask, jsonify, make_response, render_template, request, send_from_directory
from werkzeug.middleware.proxy_fix import ProxyFix

from analyzer import analyze

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OCR_LANG_DIR = os.path.join(BASE_DIR, "ocr_lang")
OCR_FILES = {"eng.traineddata.gz", "tel.traineddata.gz", "hin.traineddata.gz"}

app = Flask(__name__)

# Behind Render (or any reverse proxy) the real visitor address comes from the proxy, not from a header
# the visitor can forge. TRUSTED_PROXIES = how many proxies sit in front of the app (Render: 1).
TRUSTED_PROXIES = int(os.environ.get("TRUSTED_PROXIES", "1"))
if TRUSTED_PROXIES > 0:
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=TRUSTED_PROXIES, x_proto=1, x_host=0)

# Optional: set ALLOWED_HOSTS="yourapp.onrender.com,localhost" to reject requests for any other Host name.
ALLOWED_HOSTS = {h.strip().lower() for h in os.environ.get("ALLOWED_HOSTS", "").split(",") if h.strip()}

ALLOWED_LANGS = {"en", "te", "hi"}
MAX_LENGTH = 5000                                  # maximum characters analysed per message
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024       # reject request bodies larger than 64 KB
app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 604800   # browsers keep fonts / scripts for 7 days

# ---------- simple rate limiter (per visitor, in memory) ----------
# Many users can share one public IP (college Wi-Fi), so the default is generous.
RATE_LIMIT = int(os.environ.get("RATE_LIMIT", "120"))   # requests allowed ...
RATE_WINDOW = 60                                         # ... per this many seconds
_hits = defaultdict(deque)
_lock = threading.Lock()


def client_ip():
    return request.remote_addr or "unknown"


def is_rate_limited(ip):
    now = time.time()
    with _lock:
        q = _hits[ip]
        while q and now - q[0] > RATE_WINDOW:
            q.popleft()
        if len(q) >= RATE_LIMIT:
            return True
        q.append(now)
        if len(_hits) > 5000:          # keep memory small
            for key in [k for k, v in _hits.items() if not v or now - v[-1] > RATE_WINDOW]:
                del _hits[key]
        return False


# ---------- request checks ----------
@app.before_request
def guard_request():
    if ALLOWED_HOSTS and request.host.split(":")[0].lower() not in ALLOWED_HOSTS:
        return jsonify(error="bad_host"), 400
    if request.method == "POST":
        # block cross-site POSTs (CSRF): browsers always send Sec-Fetch-Site / Origin on them
        site = request.headers.get("Sec-Fetch-Site")
        if site and site not in ("same-origin", "none"):
            return jsonify(error="forbidden"), 403
        origin = request.headers.get("Origin")
        if origin and origin.split("://", 1)[-1].lower() != request.host.lower():
            return jsonify(error="forbidden"), 403


# ---------- security headers ----------
@app.after_request
def add_security_headers(resp):
    h = resp.headers
    h["X-Content-Type-Options"] = "nosniff"
    h["X-Frame-Options"] = "DENY"
    h["Referrer-Policy"] = "no-referrer"
    h["Permissions-Policy"] = ("camera=(), microphone=(), geolocation=(), payment=(), usb=(), "
                               "serial=(), accelerometer=(), gyroscope=(), magnetometer=(), interest-cohort=()")
    h["Cross-Origin-Opener-Policy"] = "same-origin"
    h["Cross-Origin-Resource-Policy"] = "same-origin"
    h["X-Permitted-Cross-Domain-Policies"] = "none"
    h["X-DNS-Prefetch-Control"] = "off"
    if request.headers.get("X-Forwarded-Proto", request.scheme) == "https":
        h["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
    if request.path.startswith("/api/"):
        h["Cache-Control"] = "no-store"
        # JSON and error responses: nothing at all may load from them
        h.setdefault("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'")
    return resp


def csp(nonce):
    # images are read in the browser (OCR), so the page needs blob: images and a same-origin worker
    return (
        "default-src 'none'; "
        f"script-src 'nonce-{nonce}' 'self' 'wasm-unsafe-eval'; "
        f"style-src 'nonce-{nonce}'; "
        "font-src 'self'; "
        "connect-src 'self' blob: data:; "
        "img-src 'self' data: blob:; "
        "worker-src 'self' blob:; "
        "manifest-src 'none'; media-src 'self' data:; "
        "base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'; "
        "upgrade-insecure-requests"
    )


# ---------- routes ----------
@app.route("/")
def home():
    nonce = secrets.token_urlsafe(16)
    resp = make_response(render_template("index.html", nonce=nonce))
    resp.headers["Content-Security-Policy"] = csp(nonce)
    resp.headers["Cache-Control"] = "no-cache"
    return resp


@app.route("/ocr-data/<path:name>")
def ocr_data(name):
    if name not in OCR_FILES:
        return jsonify(error="not_found"), 404
    # language files for the in-browser image reader (served as plain bytes on purpose,
    # so the browser does not try to un-gzip them a second time)
    return send_from_directory(OCR_LANG_DIR, name, mimetype="application/octet-stream")


@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    if is_rate_limited(client_ip()):
        return jsonify(error="rate_limited"), 429
    if not request.is_json:
        return jsonify(error="bad_request"), 415
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify(error="bad_request"), 400
    message = data.get("message", "")
    if not isinstance(message, str):
        return jsonify(error="bad_request"), 400
    message = message.replace("\x00", "")[:MAX_LENGTH]
    lang = data.get("lang", "en")
    if lang not in ALLOWED_LANGS:
        lang = "en"
    return jsonify(analyze(message, lang))


# ---------- safe error pages (no technical details leaked) ----------
@app.errorhandler(404)
def not_found(e):
    return jsonify(error="not_found"), 404


@app.errorhandler(405)
def not_allowed(e):
    return jsonify(error="method_not_allowed"), 405


@app.errorhandler(413)
def too_large(e):
    return jsonify(error="too_large"), 413


@app.errorhandler(400)
def bad_request(e):
    return jsonify(error="bad_request"), 400


@app.errorhandler(Exception)
def any_error(e):
    code = getattr(e, "code", 500)
    if not isinstance(code, int) or code < 400:
        code = 500
    return jsonify(error="server_error" if code >= 500 else "request_error"), code


if __name__ == "__main__":
    # host 0.0.0.0 lets other devices on the same Wi-Fi open it
    app.run(host="0.0.0.0", port=5000, debug=False)
