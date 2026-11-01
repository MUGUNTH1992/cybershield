"""CyberShield: a rule-based cybersecurity awareness demonstration."""
from __future__ import annotations

import ipaddress
import os
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from flask import Flask, jsonify, render_template, request

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get("CYBERSHIELD_DB", BASE_DIR / "instance" / "cybershield.sqlite3"))
MAX_URL_LENGTH = 2048
SUSPICIOUS_WORDS = {"login", "verify", "account", "secure", "bank", "wallet", "password", "update", "confirm", "free", "prize", "urgent", "signin"}
KNOWN_SUFFIXES = {"com", "org", "net", "edu", "gov", "io", "co", "in", "uk", "dev", "app", "info", "biz", "xyz", "top", "site", "online", "ru", "cn"}

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16_384


def connect_db() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with connect_db() as db:
        db.execute("""CREATE TABLE IF NOT EXISTS activity (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            kind TEXT NOT NULL CHECK(kind IN ('url_scan','password_check')),
            classification TEXT NOT NULL,
            created_at TEXT NOT NULL
        )""")


def analyze_url(raw: str) -> dict:
    """Classify URL syntax only. Never performs DNS, HTTP, or external calls."""
    value = raw.strip()
    if not value:
        raise ValueError("Enter a URL to analyze.")
    if len(value) > MAX_URL_LENGTH:
        raise ValueError(f"URL must be {MAX_URL_LENGTH} characters or fewer.")
    if any(ord(ch) < 32 or ch.isspace() for ch in value):
        raise ValueError("URL cannot contain spaces or control characters.")
    candidate = value if re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", value) else "https://" + value
    try:
        parts = urlsplit(candidate)
        host = (parts.hostname or "").rstrip(".").lower()
        port = parts.port
    except ValueError:
        raise ValueError("Enter a valid URL with a recognizable hostname.") from None
    if parts.scheme.lower() not in {"http", "https"}:
        raise ValueError("Only HTTP and HTTPS URLs can be analyzed.")
    if not host or "." not in host and host != "localhost":
        raise ValueError("Enter a complete domain name, such as example.com.")
    if parts.username is not None or parts.password is not None:
        raise ValueError("URLs containing embedded credentials are not accepted.")

    reasons: list[str] = []
    score = 0
    if parts.scheme.lower() == "http":
        reasons.append("Uses HTTP, so the connection is not encrypted.")
        score += 2
    try:
        ipaddress.ip_address(host.strip("[]"))
        reasons.append("Uses a direct IP address instead of a domain name.")
        score += 3
    except ValueError:
        labels = host.split(".")
        suffix = labels[-1]
        if suffix not in KNOWN_SUFFIXES:
            reasons.append("Uses an uncommon or unrecognized top-level domain.")
            score += 2
        if len(host) > 45 or any(len(label) > 25 for label in labels):
            reasons.append("The hostname is unusually long.")
            score += 1
        if host.count("-") >= 3:
            reasons.append("The hostname contains an unusually high number of hyphens.")
            score += 2
    if len(parts.netloc.split("@")[0]) > 0 and "@" in parts.netloc:
        reasons.append("Contains an @ symbol that can obscure the actual destination.")
        score += 3
    if port and port not in {80, 443}:
        reasons.append("Uses a nonstandard network port.")
        score += 1
    full = (host + parts.path + " " + parts.query).lower()
    matched = sorted(word for word in SUSPICIOUS_WORDS if re.search(rf"(?<![a-z]){re.escape(word)}(?![a-z])", full))
    if matched:
        reasons.append("Contains potentially deceptive terms: " + ", ".join(matched) + ".")
        score += min(3, len(matched))
    if host.count(".") >= 4:
        reasons.append("Has an unusually deep subdomain structure.")
        score += 1
    if not reasons:
        reasons.append("No common suspicious patterns were found by these basic rules.")
    classification = "high_risk" if score >= 6 else "suspicious" if score >= 2 else "safe"
    labels = {"high_risk": "High Risk", "suspicious": "Suspicious", "safe": "Safe"}
    return {"classification": classification, "label": labels[classification], "score": min(score, 10), "reasons": reasons, "normalized_host": host}


def record(kind: str, classification: str) -> None:
    with connect_db() as db:
        db.execute("INSERT INTO activity(kind, classification, created_at) VALUES (?, ?, ?)",
                   (kind, classification, datetime.now(timezone.utc).isoformat(timespec="seconds")))


def dashboard_data() -> dict:
    with connect_db() as db:
        rows = db.execute("SELECT kind, classification, COUNT(*) AS n FROM activity GROUP BY kind, classification").fetchall()
        recent = db.execute("SELECT kind, classification, created_at FROM activity ORDER BY id DESC LIMIT 8").fetchall()
    totals = {(r["kind"], r["classification"]): r["n"] for r in rows}
    return {"total_scans": sum(n for (k, _), n in totals.items() if k == "url_scan"),
            "safe_urls": totals.get(("url_scan", "safe"), 0),
            "suspicious_urls": totals.get(("url_scan", "suspicious"), 0) + totals.get(("url_scan", "high_risk"), 0),
            "password_assessments": sum(n for (k, _), n in totals.items() if k == "password_check"),
            "recent_activity": [dict(r) for r in recent]}


@app.get("/")
def index():
    return render_template("index.html", dashboard=dashboard_data())


@app.get("/api/dashboard")
def api_dashboard():
    return jsonify(dashboard_data())


@app.post("/api/analyze-url")
def api_analyze_url():
    data = request.get_json(silent=True) if request.is_json else request.form
    if not isinstance(data, dict) and not hasattr(data, "get"):
        return jsonify(error="Send a URL in the request body."), 400
    try:
        result = analyze_url(data.get("url", ""))
    except (ValueError, TypeError) as exc:
        return jsonify(error=str(exc)), 400
    record("url_scan", result["classification"])
    return jsonify(result)


@app.post("/api/password-assessment")
def api_password_assessment():
    """Record an assessment count only; intentionally ignore all request content."""
    record("password_check", "assessed")
    return jsonify({"recorded": True, "message": "Assessment counted. Password content was not received or stored."}), 200


@app.get("/health")
def health():
    return jsonify(status="ok")


with app.app_context():
    init_db()

if __name__ == "__main__":
    app.run(debug=False)
