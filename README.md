# Prototype Safety Check

Check if a user-made and deployed prototype is safe or not.

This tool only checks **deployed links** (live URLs like `https://my-app.vercel.app`).
It does **not** check repo links (GitHub / GitLab / source code).

## What it checks

1. **SQL Injection (SQLi)**
   - Checks for exposed input params, error messages, insecure query patterns in responses.

2. **Cross-Site Scripting (XSS)**
   - Checks for reflected input, missing `Content-Security-Policy`, missing `X-XSS-Protection`, unsafe `innerHTML` usage in client JS.

3. **Malware and Viruses**
   - Checks URL against safe-browsing / blocklists, scans for suspicious scripts, iframes, obfuscated JS, forced downloads.

4. **Phishing and Spoofing**
   - Checks domain spoof signals, missing SPF/DKIM/DMARC hints, misleading brand keywords, no HTTPS, fake login forms.

5. **Denial of Service (DoS / DDoS) exposure**
   - Checks for missing rate-limit headers, slow responses, no CDN / WAF headers, oversized assets that amplify abuse.

6. **Man-in-the-Middle (MitM)**
   - Checks HTTPS enforcement, HSTS, TLS version, insecure redirects (https -> http), mixed-content, missing `Secure` cookies.

## How to use

1. Deploy your prototype (Vercel, Netlify, Render, etc.)
2. Paste the deployed link into the checker
3. Get a Safety Report: Safe / Risky / Critical + reasons + fixes

Example:
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

## What it does NOT do

- No repo / source code scanning
- No active exploitation (no real SQLi payload attack, no DoS attack)
- No login bypass, no brute-force
- Only passive + safe light checks with user permission

Only scan prototypes you own or have permission to test.

## Run it

```bash
pip install -r requirements.txt

# Option 1: Web UI (paste link + report + history)
python app.py
# open http://127.0.0.1:5000

# Option 2: CLI
python scanner.py https://my-prototype.vercel.app

# Option 3: JSON API
# GET /api/scan?url=https://my-prototype.vercel.app
```

Print / Save-as-PDF is built into the report page (browser print).
Re-scan history is stored in `history.json`. Each finding includes a fix suggestion.

## Project status

Working prototype: passive scanner + web UI + CLI + API done.

Future scope:
- PDF report export (1-click, currently via browser print)
- Safe-browsing API integration (needs API key)
- Fix suggestions with code snippets per framework
