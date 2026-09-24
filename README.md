# 🛡️ Prototype Safety Check

Check if a user-made and deployed prototype is safe or not.

Paste a **deployed link** (live URL like `https://my-app.vercel.app`) and get a
**Safe / Risky / Critical** report with reasons + fixes.
Repo links (GitHub / GitLab / source code) are **not** scanned.

## ✨ Features

- 🌐 Web UI with AI-neon dark theme — paste link, scan, view report
- 📊 Verdict engine: Safe / Risky / Critical + score (FAIL = 2 pts, WARNING = 1 pt)
- 🛠️ Fix suggestion for every failing check
- 🕘 Re-scan history (stored in `history.json`)
- 🖨️ Print / Save-as-PDF + ⬇️ JSON report download
- 💻 CLI (`python scanner.py <url>`) and JSON API (`GET /api/scan?url=...`)
- ⚡ High-efficiency engine (`fast_scanner.py`) — parallel TLS/DNS probes,
  pooled connections, 5-min cache + concurrent bulk scan (up to 20 URLs):
  Web UI toggle, `POST /bulk`, `GET /api/scan_fast?url=...`,
  `POST /api/scan_bulk {"urls": [...]}`, CLI `python fast_scanner.py <url...>`

## 🔍 What it checks

1. **SQL Injection (SQLi)**
   - Exposed DB error strings, input params / forms, client-built query hints.
   - Passive only — no payloads are ever sent.

2. **Cross-Site Scripting (XSS)**
   - Reflected input, missing `Content-Security-Policy`, missing
     `X-Content-Type-Options` / `X-Frame-Options` / `Referrer-Policy`,
     unsafe `innerHTML` / `eval` / `document.write` sinks in inline JS.

3. **Malware and Viruses**
   - Obfuscated script patterns (`eval(atob(...))`), hidden iframes,
     forced downloads / executable links, scripts from IP or shady-TLD hosts.

4. **Phishing and Spoofing**
   - Punycode / IP hosts, `@` tricks, excessive subdomains, brand-keyword
     squatting, fake login forms, missing HTTPS, SPF/DMARC hints (via DNS-over-HTTPS).

5. **Denial of Service (DoS / DDoS) exposure**
   - Slow responses, missing rate-limit headers, no CDN/WAF hints,
     oversized / uncompressed payloads. Single GET only — no load testing.

6. **Man-in-the-Middle (MitM)**
   - HTTPS enforcement + HTTP→HTTPS redirect, HSTS, TLS version,
     HTTPS→HTTP downgrades, mixed content, `Secure` cookie flags.

## 🚫 What it does NOT do

- No repo / source code scanning
- No active exploitation (no SQLi payloads, no XSS firing, no DoS attack)
- No login bypass, no brute-force
- Only passive + safe light checks

⚠️ Only scan prototypes you own or have permission to test.

## ▶️ Run locally

```bash
pip install -r requirements.txt

# Web UI
python app.py
# open http://127.0.0.1:5000

# CLI
python scanner.py https://my-prototype.vercel.app

# JSON API (with server running)
# GET /api/scan?url=https://my-prototype.vercel.app
```

## 🚀 Deploy (Render)

This is a Python Flask backend — deploy on **Render** or **Railway**
(not Vercel/Netlify, which are static-only).

- Build command: `pip install -r requirements.txt`
- Start command: `gunicorn app:app --bind 0.0.0.0:$PORT --workers 2 --timeout 60`
- `render.yaml` + `Procfile` are already included, so Render auto-detects them.

## 🗂️ Project structure

```
app.py            # Flask web UI + API (landing, scanner, report, bulk, history, api pages)
scanner.py        # Passive scanner (all 6 check categories)
fast_scanner.py   # High-efficiency engine: parallel probes + bulk scan_urls()
templates/
  landing.html    # Opening page (hero)
  base.html       # Shared official layout (header/nav/footer/theme)
  scanner.html    # Scan submission page
  report.html     # Single-URL examination report page
  bulk.html       # Bulk examination outcome page
  history.html    # Register of examinations page
  api.html        # Machine interface docs page
requirements.txt  # requests, flask, gunicorn
Procfile          # web: gunicorn app:app ...
render.yaml       # Render deploy config
history.json      # created at runtime (last 20 scans)
LICENSE           # MIT
```

## 📁 Example report

```
Input: https://my-prototype.vercel.app
Output:
- HTTPS: PASS
- HSTS: FAIL - missing Strict-Transport-Security
- XSS: WARNING - CSP missing
- SQLi: PASS - no DB errors exposed
- Malware: PASS - no known bad signatures
- Verdict: Risky (2 issues to fix)
```

## 📄 License

MIT — see [LICENSE](LICENSE).
