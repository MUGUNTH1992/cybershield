# CyberShield – Cybersecurity Awareness & Threat Detection System

A beginner-friendly cybersecurity awareness micro-project built with Python Flask, SQLite, HTML, CSS, and JavaScript.

## Features

- Dashboard counts URL scans, safe results, flagged results, and password checks.
- Rule-based URL analyzer inspects visible URL syntax only. It never resolves DNS, opens a URL, or calls a threat-intelligence service.
- Browser-only password strength assessment for length, letter case, digits, and special characters. Password text is not transmitted or stored.
- Cybersecurity awareness cards covering phishing, browsing, and password hygiene.
- Responsive layout for desktop and mobile.
- SQLite activity history stores event type, classification, and timestamp only. It deliberately omits URL and password content.
- Input validation, accessible status announcements, and a small automated test suite.

## Requirements

- Python 3.10 or newer
- Flask 3.x (see `requirements.txt`)

## Run locally

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Open <http://127.0.0.1:5000>. The SQLite database is created in `instance/cybershield.sqlite3` on first run. Set `CYBERSHIELD_DB` to choose another database path.

## Run tests

```bash
pip install -r requirements.txt
python -m unittest discover -s tests -v
```

Tests cover the landing page, health endpoint, URL classifications, input validation, dashboard counts, and the absence of submitted secrets from stored history.

## API

| Method | Route | Purpose |
|---|---|---|
| GET | `/` | Dashboard UI |
| GET | `/health` | Liveness response |
| GET | `/api/dashboard` | Aggregate counts and recent activity |
| POST | `/api/analyze-url` | Analyze `{ "url": "https://example.com" }` |
| POST | `/api/password-assessment` | Increment an anonymous count; request body is ignored |

URL analyzer responses include `classification` (`safe`, `suspicious`, or `high_risk`), an explanatory label, a capped educational score, and reasons. Any such classifier can be wrong. A `Safe` result means only that these limited rules found no obvious warning sign; it is not a safety guarantee. HTTPS alone also does not prove that a site is trustworthy.

## Privacy and security notes

- Password analysis runs in browser JavaScript. The only network request made for a password check is an empty `POST` used to count an assessment; no password value is included.
- The backend assessment endpoint ignores its request body and stores only an aggregate event row.
- URL analysis is local string parsing. Submitted URLs are never fetched or resolved.
- URL activity history omits the URL. The browser does send the URL to this project's own Flask endpoint for analysis.
- This is an educational demonstration, not antivirus, a security scanner, or a substitute for professional threat intelligence.
- For a public deployment, use a production WSGI server, HTTPS, appropriate rate limiting, and a reviewed privacy policy.

## Project structure

```text
CyberShield/
├── app.py
├── requirements.txt
├── README.md
├── LICENSE
├── .gitignore
├── templates/
│   └── index.html
├── static/
│   ├── app.js
│   └── style.css
├── tests/
│   └── test_app.py
└── report/
    └── CyberShield_Project_Report.pdf
```

See `report/CyberShield_Project_Report.pdf` for the academic project report.

## License

Released under the MIT License. See `LICENSE`.
