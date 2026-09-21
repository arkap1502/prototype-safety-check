"""
Prototype Safety Check - passive scanner for deployed links (live URLs).
Only scans prototypes you own or have permission to test.
No active exploitation: single GET + safe header/TLS/DNS checks only.
"""
import re
import ssl
import socket
import time
from html.parser import HTMLParser
from urllib.parse import urlparse, parse_qsl, urljoin

import requests


REPO_HOSTS = {
    "github.com", "www.github.com",
    "gitlab.com", "www.gitlab.com",
    "bitbucket.org", "www.bitbucket.org",
    "raw.githubusercontent.com",
    "gist.github.com",
}

DB_ERROR_SIGNATURES = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "mysqli",
    "ora-01756", "ora-00933", "oracle error",
    "pg_query()", "postgresql", "psql:",
    "sqlite3::", "sqlite error",
    "odbc sql server driver",
    "sqlstate",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "microsoft ole db provider for sql server",
    "jdbc", "sql exception",
]

UNSAFE_JS_PATTERNS = [
    (r"\.innerHTML\s*=", "innerHTML assignment - can lead to XSS if fed with user input"),
    (r"\.outerHTML\s*=", "outerHTML assignment"),
    (r"document\.write\s*\(", "document.write() with dynamic data"),
    (r"document\.writeln\s*\(", "document.writeln() with dynamic data"),
    (r"\beval\s*\(", "eval() on strings"),
    (r"new\s+Function\s*\(", "new Function() constructor"),
    (r"setTimeout\s*\(\s*[\"']", "setTimeout with string code"),
    (r"setInterval\s*\(\s*[\"']", "setInterval with string code"),
    (r"location\.hash", "use of location.hash without sanitization"),
]

MALWARE_JS_PATTERNS = [
    (r"eval\s*\(\s*atob\s*\(", "eval(atob(...)) - classic obfuscated payload pattern"),
    (r"eval\s*\(\s*unescape\s*\(", "eval(unescape(...)) - obfuscation pattern"),
    (r"String\.fromCharCode\s*\(.{40,}", "long String.fromCharCode blob - possible obfuscation"),
    (r"document\.createElement\s*\(\s*['\"]iframe['\"]", "dynamic iframe creation"),
    (r"window\.location\s*=\s*['\"]http", "JS forced redirect to http URL"),
]

SUSPICIOUS_TLDS = (".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".xyz", ".buzz", ".work")

BRAND_KEYWORDS = [
    "paypal", "apple", "google", "microsoft", "amazon", "netflix",
    "bank", "verify", "secure-login", "account-update", "wallet",
    "metamask", "binance", "facebook", "instagram",
]

OFFICIAL_BRAND_DOMAINS = {
    "paypal": ["paypal.com"],
    "apple": ["apple.com", "icloud.com"],
    "google": ["google.com", "gmail.com", "youtube.com"],
    "microsoft": ["microsoft.com", "live.com", "outlook.com", "office.com"],
    "amazon": ["amazon.com"],
    "netflix": ["netflix.com"],
    "facebook": ["facebook.com", "fb.com"],
    "instagram": ["instagram.com"],
}


class _LinkParser(HTMLParser):
    """Tiny stdlib HTML parser: collects forms, scripts, iframes, links, mixed content."""

    def __init__(self, base_url=""):
        super().__init__()
        self.base_url = base_url
        self.forms = []          # {action, method, has_password, inputs}
        self.scripts = []        # {src, inline}
        self.iframes = []        # {src, attrs}
        self.links = []          # hrefs
        self.http_resources = []  # http:// resources found on page
        self.password_fields = 0
        self.text_inputs = 0
        self._in_script = False
        self._script_buf = ""
        self._script_src = ""

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        tag = tag.lower()
        if tag == "form":
            self.forms.append({
                "action": a.get("action", ""),
                "method": (a.get("method", "get") or "get").upper(),
                "has_password": False,
                "inputs": 0,
            })
        elif tag == "input":
            t = (a.get("type", "text") or "text").lower()
            if self.forms:
                self.forms[-1]["inputs"] += 1
            if t == "password":
                self.password_fields += 1
                if self.forms:
                    self.forms[-1]["has_password"] = True
            elif t in ("text", "search", "email", "url", ""):
                self.text_inputs += 1
        elif tag == "script":
            src = a.get("src", "")
            self._in_script = True
            self._script_buf = ""
            self._script_src = src
            if src:
                self.scripts.append({"src": src, "inline": ""})
                if src.lower().startswith("http://"):
                    self.http_resources.append(src)
        elif tag == "iframe":
            self.iframes.append({"src": a.get("src", ""), "attrs": a})
        elif tag in ("img", "link", "source", "video", "audio"):
            for key in ("src", "href"):
                v = a.get(key, "")
                if v.lower().startswith("http://"):
                    self.http_resources.append(v)
        elif tag == "a":
            href = a.get("href", "")
            if href:
                self.links.append(href)

    def handle_data(self, data):
        if self._in_script and not self._script_src:
            self._script_buf += data

    def handle_endtag(self, tag):
        if tag.lower() == "script" and self._in_script:
            self._in_script = False
            if not self._script_src:
                self.scripts.append({"src": "", "inline": self._script_buf})
            self._script_buf = ""
            self._script_src = ""


def is_repo_link(url: str) -> bool:
    try:
        host = (urlparse(url).hostname or "").lower()
    except Exception:
        return False
    return host in REPO_HOSTS


def normalize_url(raw: str) -> str:
    raw = (raw or "").strip()
    if not raw:
        raise ValueError("Empty URL. Paste a deployed link like https://my-app.vercel.app")
    if not re.match(r"^https?://", raw, re.I):
        raw = "https://" + raw
    u = urlparse(raw)
    if u.scheme not in ("http", "https"):
        raise ValueError("Only http(s) URLs are supported.")
    if not u.hostname:
        raise ValueError("Invalid URL.")
    if is_repo_link(raw):
        raise ValueError(
            "Repo links (GitHub/GitLab/Bitbucket) are not supported. "
            "Paste the deployed live link instead (e.g. https://my-app.vercel.app)."
        )
    return raw


def _get_header(headers, name):
    for k, v in headers.items():
        if k.lower() == name.lower():
            return v
    return None


def fetch_target(url, timeout=15):
    """Single passive GET. Returns dict with response + meta. No payloads sent."""
    headers = {
        "User-Agent": "PrototypeSafetyCheck/1.0 (+passive security scan; owner-permission only)",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }
    t0 = time.time()
    resp = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)
    elapsed = time.time() - t0
    redirect_chain = [f"{h.status_code} {h.url}" for h in resp.history] + [f"{resp.status_code} {resp.url}"]
    downgrade = False
    prev_https = urlparse(url).scheme == "https"
    for h in list(resp.history) + [resp]:
        loc = h.url
        scheme = urlparse(loc).scheme
        if prev_https and scheme == "http":
            downgrade = True
        prev_https = (scheme == "https")
    return {
        "resp": resp,
        "elapsed": elapsed,
        "body": resp.text or "",
        "headers": dict(resp.headers or {}),
        "cookies": resp.cookies,
        "final_url": resp.url,
        "status_code": resp.status_code,
        "redirect_chain": redirect_chain,
        "https_downgrade": downgrade,
    }


def check_http_redirect_to_https(parsed):
    """Best-effort: does http://host redirect to https? One lightweight request."""
    if parsed.scheme != "https":
        return None
    host = parsed.hostname or ""
    path = parsed.path or "/"
    http_url = f"http://{host}{path}"
    try:
        r = requests.get(
            http_url, timeout=8, allow_redirects=False,
            headers={"User-Agent": "PrototypeSafetyCheck/1.0"},
        )
        loc = r.headers.get("Location", "")
        if r.status_code in (301, 302, 307, 308) and loc.startswith("https://"):
            return True
        return False
    except Exception:
        return None


def get_tls_info(hostname, port=443, timeout=8):
    """Passive TLS handshake only. Returns {version, cipher, error}."""
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                return {
                    "version": ssock.version(),
                    "cipher": (ssock.cipher() or [None])[0],
                    "error": None,
                }
    except Exception as e:  # noqa: BLE001 - report as data
        return {"version": None, "cipher": None, "error": str(e)[:200]}


def dns_txt_lookup(name, timeout=8):
    """DNS TXT via Google DNS-over-HTTPS (no extra deps). Returns list of strings."""
    try:
        r = requests.get(
            "https://dns.google/resolve",
            params={"name": name, "type": "TXT"},
            timeout=timeout,
        )
        data = r.json()
        out = []
        for ans in data.get("Answer", []) or []:
            d = ans.get("data", "")
            if d:
                out.append(d.strip('"'))
        return out
    except Exception:
        return []


def scan_url(raw_url: str) -> dict:
    url = normalize_url(raw_url)
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    query_params = parse_qsl(parsed.query, keep_blank_values=True)

    try:
        fetched = fetch_target(url)
    except requests.exceptions.SSLError as e:
        return _error_report(url, f"TLS/SSL error: weak cert or insecure TLS. {str(e)[:200]}")
    except requests.exceptions.ConnectionError as e:
        return _error_report(url, f"Could not connect to {host}. Is the deployment live? ({str(e)[:150]})")
    except requests.exceptions.Timeout:
        return _error_report(url, f"Connection to {host} timed out after 15s (possible DoS exposure / slow server).")
    except ValueError as e:
        return _error_report(raw_url, str(e))
    except Exception as e:  # noqa: BLE001
        return _error_report(url, f"Fetch failed: {str(e)[:200]}")

    resp = fetched["resp"]
    body = fetched["body"]
    headers = fetched["headers"]
    body_low = body.lower()

    parser = _LinkParser(base_url=fetched["final_url"])
    try:
        parser.feed(body[:500_000])  # cap parse size
    except Exception:
        pass

    findings = []

    def add(category, name, status, detail, fix):
        findings.append({
            "category": category, "name": name, "status": status,
            "detail": detail, "fix": fix,
        })

    is_https = urlparse(fetched["final_url"]).scheme == "https"

    # ---------------- 6. MitM ----------------
    if not is_https and parsed.scheme == "http":
        add("MitM", "HTTPS enforced", "FAIL",
            f"Site is served over plain HTTP ({fetched['final_url']}). Traffic can be intercepted.",
            "Deploy with HTTPS (Vercel/Netlify/Render give free TLS). Redirect all HTTP to HTTPS.")
    else:
        redir = check_http_redirect_to_https(parsed)
        if redir is True:
            add("MitM", "HTTPS enforced", "PASS", "HTTP redirects to HTTPS.", "Keep the redirect + enable HSTS.")
        elif redir is False:
            add("MitM", "HTTPS enforced", "WARNING",
                "HTTPS works but plain-HTTP did not redirect to HTTPS in our probe.",
                "Add a 301 redirect from http:// to https:// on your host.")
        else:
            add("MitM", "HTTPS enforced", "PASS", "Final URL is HTTPS.", "Add HSTS + HTTP→HTTPS redirect.")

    hsts = _get_header(headers, "Strict-Transport-Security")
    if is_https and not hsts:
        add("MitM", "HSTS header", "FAIL",
            "Missing Strict-Transport-Security header - first-visit downgrade possible.",
            "Send: Strict-Transport-Security: max-age=31536000; includeSubDomains")
    elif is_https:
        add("MitM", "HSTS header", "PASS", f"HSTS present: {hsts[:80]}", "No action needed.")
    else:
        add("MitM", "HSTS header", "FAIL", "No HSTS because site is HTTP.",
            "Enable HTTPS first, then add HSTS.")

    tls = get_tls_info(host) if is_https else {"version": None, "cipher": None, "error": "skipped (HTTP)"}
    if tls["version"] in ("TLSv1.2", "TLSv1.3"):
        add("MitM", "TLS version", "PASS", f"Negotiated {tls['version']} ({tls['cipher']}).", "No action needed.")
    elif is_https:
        add("MitM", "TLS version", "WARNING",
            f"Could not confirm modern TLS ({tls.get('error') or tls.get('version')}).",
            "Ensure host allows only TLS 1.2+. Disable TLS 1.0/1.1 in host settings.")

    if is_https and parser.http_resources:
        sample = parser.http_resources[0][:100]
        add("MitM", "Mixed content", "WARNING",
            f"{len(parser.http_resources)} resource(s) loaded over http:// (e.g. {sample}).",
            "Serve all images/scripts/CSS over https:// or relative URLs.")
    else:
        add("MitM", "Mixed content", "PASS", "No http:// sub-resources detected.", "No action needed.")

    insecure_cookies = []
    for c in fetched["cookies"]:
        if is_https and not c.secure:
            insecure_cookies.append(c.name)
    raw_set_cookie = _get_header(headers, "Set-Cookie") or ""
    if insecure_cookies:
        add("MitM", "Secure cookies", "WARNING",
            f"Cookie(s) without Secure flag: {', '.join(insecure_cookies[:5])}.",
            "Set cookies with Secure; HttpOnly; SameSite=Lax (or Strict).")
    elif raw_set_cookie and is_https and "secure" not in raw_set_cookie.lower():
        add("MitM", "Secure cookies", "WARNING",
            "Set-Cookie present without Secure flag.",
            "Set cookies with Secure; HttpOnly; SameSite=Lax.")
    else:
        add("MitM", "Secure cookies", "PASS", "No insecure cookies observed.", "No action needed.")

    if fetched["https_downgrade"]:
        add("MitM", "Redirect safety", "FAIL",
            "Redirect chain downgrades HTTPS → HTTP.",
            "Fix redirects so every hop stays on HTTPS.")
    else:
        add("MitM", "Redirect safety", "PASS",
            "No HTTPS→HTTP downgrade in redirect chain.", "No action needed.")

    # ---------------- 2. XSS ----------------
    csp = _get_header(headers, "Content-Security-Policy")
    if not csp:
        add("XSS", "Content-Security-Policy", "WARNING",
            "Missing Content-Security-Policy header - XSS impact is much higher.",
            "Add e.g. Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'.")
    else:
        weak = "'unsafe-inline'" in csp and "'unsafe-eval'" in csp
        add("XSS", "Content-Security-Policy", "WARNING" if weak else "PASS",
            f"CSP present: {csp[:120]}",
            "Tighten CSP (avoid 'unsafe-inline'/'unsafe-eval') if flagged." if weak else "No action needed.")

    xcto = _get_header(headers, "X-Content-Type-Options")
    xfo = _get_header(headers, "X-Frame-Options")
    refpol = _get_header(headers, "Referrer-Policy")
    missing = [n for n, v in [("X-Content-Type-Options", xcto), ("X-Frame-Options", xfo),
                              ("Referrer-Policy", refpol)] if not v]
    if missing:
        add("XSS", "Anti-XSS/clickjacking headers", "WARNING",
            f"Missing: {', '.join(missing)}.",
            "Send X-Content-Type-Options: nosniff, X-Frame-Options: DENY (or frame-ancestors in CSP), Referrer-Policy: no-referrer.")
    else:
        add("XSS", "Anti-XSS/clickjacking headers", "PASS",
            "X-Content-Type-Options, X-Frame-Options, Referrer-Policy present.", "No action needed.")

    reflected = [v for _, v in query_params if v and len(v) >= 3 and v in body]
    if reflected:
        add("XSS", "Reflected input", "WARNING",
            f"Query value(s) reflected verbatim in HTML (e.g. {reflected[0][:40]}). Test with benign text; ensure output-encoding.",
            "HTML-escape all user input on render; prefer textContent over innerHTML; keep CSP.")
    else:
        add("XSS", "Reflected input", "PASS",
            "No verbatim reflection of query values detected (passive check only).",
            "Still escape all user input; keep CSP.")

    sink_hits = []
    for s in parser.scripts:
        if not s["inline"]:
            continue
        for pat, label in UNSAFE_JS_PATTERNS:
            if re.search(pat, s["inline"]):
                sink_hits.append(label)
    sink_hits = sorted(set(sink_hits))
    if sink_hits:
        add("XSS", "Unsafe JS sinks", "WARNING",
            f"Found: {'; '.join(sink_hits[:4])}.",
            "Avoid innerHTML/eval/document.write with user data. Use textContent, DOMPurify, framework escaping.")
    else:
        add("XSS", "Unsafe JS sinks", "PASS", "No obvious innerHTML/eval/document.write sinks in inline JS.", "No action needed.")

    # ---------------- 1. SQLi (passive only) ----------------
    db_hit = next((s for s in DB_ERROR_SIGNATURES if s in body_low), None)
    if db_hit:
        add("SQLi", "DB error exposure", "FAIL",
            f"Response contains DB error text ({db_hit!r}) - leaks backend detail.",
            "Disable verbose DB errors in production; return generic 500; use parameterized queries/ORM.")
    else:
        add("SQLi", "DB error exposure", "PASS", "No known DB error strings in response.", "Keep errors generic in prod.")

    if query_params or parser.text_inputs or any(f["inputs"] for f in parser.forms):
        n = len(query_params)
        add("SQLi", "Input surface", "WARNING" if n else "PASS",
            f"URL has {n} query param(s); page has {parser.text_inputs} text input(s), {len(parser.forms)} form(s). "
            "Inputs are entry points - review server-side handling (passive check, no payloads sent).",
            "Use parameterized queries/ORM, validate + allow-list input, least-privilege DB user, WAF.")
    else:
        add("SQLi", "Input surface", "PASS", "No query params or text inputs observed.", "No action needed.")

    risky_sql_js = re.search(r"(SELECT|INSERT|UPDATE|DELETE)\b.{0,80}(\+|\$\{|`)", body, re.I)
    if risky_sql_js:
        add("SQLi", "Client-side query hints", "WARNING",
            "JS/HTML hints at string-built SQL or URL-built queries.",
            "Never build SQL client-side; move queries server-side with bound parameters.")
    else:
        add("SQLi", "Client-side query hints", "PASS", "No obvious client-built SQL patterns.", "No action needed.")

    # ---------------- 3. Malware ----------------
    mal_hits = []
    for s in parser.scripts:
        code = s["inline"] or ""
        for pat, label in MALWARE_JS_PATTERNS:
            if re.search(pat, code, re.I | re.S):
                mal_hits.append(label)
        if code and len(code) > 8000 and len(re.findall(r"[A-Za-z0-9+/=]{200,}", code)) > 3:
            mal_hits.append("large base64-like blobs in inline JS")
    mal_hits = sorted(set(mal_hits))
    hidden_iframes = [i for i in parser.iframes
                      if any(k in str(i["attrs"]).lower() for k in ("width=\"0\"", "height=\"0\"", "display:none", "visibility:hidden"))]
    if mal_hits:
        add("Malware", "Suspicious scripts", "FAIL",
            f"Found: {'; '.join(mal_hits[:4])}. Verify each script is yours.",
            "Remove unknown scripts; pin deps; use SRI (integrity=) + CSP; rescan.")
    else:
        add("Malware", "Suspicious scripts", "PASS", "No classic obfuscation/forced-redirect patterns.", "Keep deps pinned + CSP.")

    if hidden_iframes or any("display:none" in b.lower() and "<iframe" in b.lower() for b in [body_low]):
        add("Malware", "Hidden iframes", "FAIL",
            f"{len(hidden_iframes) or 1} hidden iframe pattern(s) detected.",
            "Remove hidden third-party iframes you did not add; check for compromise.")
    else:
        add("Malware", "Hidden iframes", "PASS", "No hidden iframes detected.", "No action needed.")

    dl = (_get_header(headers, "Content-Disposition") or "").lower()
    exe_links = [h for h in parser.links if re.search(r"\.(exe|scr|bat|msi|dll|ps1)(\?|#|$)", h, re.I)]
    if "attachment" in dl or exe_links:
        add("Malware", "Forced downloads", "WARNING",
            f"Page triggers download ({dl[:60]}) or links executables: {exe_links[0][:80] if exe_links else dl[:60]}.",
            "Only offer downloads you intend; serve with correct types; sign binaries; warn users.")
    else:
        add("Malware", "Forced downloads", "PASS", "No forced downloads/executable links seen.", "No action needed.")

    ext_ips, ext_shady = [], []
    for s in parser.scripts:
        src = s["src"]
        if not src:
            continue
        try:
            sh = urlparse(urljoin(fetched["final_url"], src)).hostname or ""
        except Exception:
            continue
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", sh):
            ext_ips.append(src[:80])
        if sh.lower().endswith(SUSPICIOUS_TLDS):
            ext_shady.append(src[:80])
    if ext_ips or ext_shady:
        add("Malware", "Shady external hosts", "WARNING",
            f"Scripts from IP/shady-TLD hosts: {(ext_ips + ext_shady)[0][:80]}.",
            "Self-host or allow-list CDNs; add SRI + CSP script-src.")
    else:
        add("Malware", "Shady external hosts", "PASS", "No scripts from IP or shady-TLD hosts.", "No action needed.")

    # ---------------- 4. Phishing / spoofing ----------------
    puny = "xn--" in host
    is_ip = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host))
    at_sign = "@" in url
    subdots = host.count(".")
    hyphens = host.count("-")
    long_url = len(url) > 120
    spoof_signals = []
    if puny:
        spoof_signals.append("punycode (xn--) - possible lookalike domain")
    if is_ip:
        spoof_signals.append("bare IP as host - unusual for legit prototypes")
    if at_sign:
        spoof_signals.append("'@' in URL - can mask real host")
    if subdots >= 4:
        spoof_signals.append(f"{subdots} dots - excessive subdomains")
    if hyphens >= 3:
        spoof_signals.append(f"{hyphens} hyphens - typo-squat style")
    if long_url:
        spoof_signals.append(f"very long URL ({len(url)} chars)")
    if spoof_signals:
        add("Phishing", "Domain spoof signals", "WARNING",
            "; ".join(spoof_signals) + ".",
            "Use a short clean domain; avoid punycode/IP hosts for demos.")
    else:
        add("Phishing", "Domain spoof signals", "PASS", "No obvious spoof signals in domain/URL.", "No action needed.")

    brand_hit = next((b for b in BRAND_KEYWORDS if b in host or b in url.lower()), None)
    if brand_hit:
        allowed = OFFICIAL_BRAND_DOMAINS.get(brand_hit, [])
        official = any(host == d or host.endswith("." + d) for d in allowed)
        if not official:
            add("Phishing", "Brand-keyword check", "WARNING",
                f"URL contains brand-like keyword {brand_hit!r} on non-official domain {host}.",
                "Avoid brand names in demo domains/paths; make clear it is a prototype.")
        else:
            add("Phishing", "Brand-keyword check", "PASS", "Brand keyword on official domain.", "No action needed.")
    else:
        add("Phishing", "Brand-keyword check", "PASS", "No misleading brand keywords.", "No action needed.")

    login_forms = [f for f in parser.forms if f["has_password"]]
    if login_forms:
        f0 = login_forms[0]
        act = f0["action"]
        abs_act = urljoin(fetched["final_url"], act) if act else fetched["final_url"]
        external = urlparse(abs_act).hostname != urlparse(fetched["final_url"]).hostname
        if not is_https:
            add("Phishing", "Login-form safety", "FAIL",
                "Password field served over HTTP - credentials can be stolen.",
                "Serve login only over HTTPS; post to same origin; add CSRF protection.")
        elif external:
            add("Phishing", "Login-form safety", "WARNING",
                f"Login posts to external host ({abs_act[:80]}).",
                "Post logins to same origin over HTTPS; explain why if external.")
        else:
            add("Phishing", "Login-form safety", "PASS",
                "Login form posts same-origin over HTTPS.", "Keep HTTPS + CSRF tokens + rate limits.")
    else:
        add("Phishing", "Login-form safety", "PASS", "No password fields detected.", "No action needed.")

    if not is_https:
        add("Phishing", "Trust basics (HTTPS)", "FAIL",
            "No HTTPS - browsers flag as Not Secure; high phishing resemblance.",
            "Enable HTTPS on your host (free on Vercel/Netlify/Render).")
    else:
        add("Phishing", "Trust basics (HTTPS)", "PASS", "HTTPS present.", "No action needed.")

    # Email-auth hints via DoH (best effort, informational)
    try:
        root = ".".join(host.split(".")[-2:]) if "." in host else host
        spf = dns_txt_lookup(root)
        dmarc = dns_txt_lookup(f"_dmarc.{root}")
        has_spf = any("v=spf1" in s for s in spf)
        has_dmarc = any("DMARC" in s or "v=DMARC" in s for s in dmarc)
        if not has_spf or not has_dmarc:
            missing = [k for k, v in [("SPF", has_spf), ("DMARC", has_dmarc)] if not v]
            add("Phishing", "Email-auth hints", "WARNING",
                f"No { '/'.join(missing)} record visible for {root} (via DNS-over-HTTPS).",
                "If you send mail from this domain, publish SPF + DKIM + DMARC to resist spoofing.")
        else:
            add("Phishing", "Email-auth hints", "PASS", f"SPF+DMARC visible for {root}.", "No action needed.")
    except Exception:
        add("Phishing", "Email-auth hints", "PASS", "Skipped (DNS unavailable).", "Publish SPF/DKIM/DMARC if you send mail.")

    # ---------------- 5. DoS exposure ----------------
    rt = fetched["elapsed"]
    if rt > 5:
        add("DoS", "Response time", "FAIL",
            f"GET took {rt:.1f}s - slow origins are easier to exhaust.",
            "Profile slow route; cache; paginate; put CDN in front.")
    elif rt > 2.5:
        add("DoS", "Response time", "WARNING",
            f"GET took {rt:.1f}s - slower than ideal.",
            "Enable caching/CDN; compress; optimize queries.")
    else:
        add("DoS", "Response time", "PASS", f"GET took {rt:.2f}s.", "No action needed.")

    rl_headers = [k for k in headers if "ratelimit" in k.lower() or k.lower() in
                  ("retry-after", "x-throttle", "x-quota", "x-ratelimit-limit")]
    if not rl_headers:
        add("DoS", "Rate-limit hints", "WARNING",
            "No RateLimit headers seen (single passive GET only; real limits may still exist).",
            "Add rate limiting (host/WAF/middleware); return 429 + Retry-After; throttle login/API.")
    else:
        add("DoS", "Rate-limit hints", "PASS", f"Rate-limit headers: {', '.join(rl_headers[:3])}.", "No action needed.")

    waf_signals = []
    srv = (_get_header(headers, "Server") or "").lower()
    for k, v in headers.items():
        kl, vl = k.lower(), str(v).lower()
        if kl in ("cf-ray", "cf-mitigated", "x-amz-cf-id", "x-vercel-cache", "x-vercel-id",
                  "x-netlify-id", "x-akamai", "x-fastly", "x-waf", "x-firewall", "x-sucuri"):
            waf_signals.append(k)
        if "cloudflare" in vl or "akamai" in vl or "fastly" in vl:
            waf_signals.append(f"{k}={v}"[:60])
    if "cloudflare" in srv or "vercel" in srv or "netlify" in srv or "akamai" in srv:
        waf_signals.append(f"Server={srv}"[:60])
    if not waf_signals:
        add("DoS", "CDN/WAF hints", "WARNING",
            "No CDN/WAF headers detected - origin may be directly exposed.",
            "Put CDN/WAF in front (Cloudflare/Vercel/Netlify); hide origin IP; enable bot checks.")
    else:
        add("DoS", "CDN/WAF hints", "PASS", f"CDN/WAF hints: {', '.join(waf_signals[:3])}.", "No action needed.")

    size = len(body.encode("utf-8", "ignore"))
    ce = (_get_header(headers, "Content-Encoding") or "").lower()
    cc = _get_header(headers, "Cache-Control") or ""
    if size > 2_000_000:
        add("DoS", "Payload weight", "FAIL",
            f"HTML is {size/1e6:.1f} MB - heavy pages amplify bandwidth abuse.",
            "Code-split; lazy-load; compress (gzip/br); cache static assets.")
    elif size > 800_000:
        add("DoS", "Payload weight", "WARNING",
            f"HTML is {size/1e3:.0f} KB" + (", no compression" if not ce else f" ({ce})") + ".",
            "Compress + cache; split bundles.")
    elif not ce and size > 100_000:
        add("DoS", "Payload weight", "WARNING",
            f"{size/1e3:.0f} KB with no Content-Encoding.",
            "Enable gzip/brotli + Cache-Control.")
    else:
        add("DoS", "Payload weight", "PASS",
            f"HTML {size/1e3:.0f} KB" + (f", {ce}" if ce else "") + (", cached" if cc else "") + ".",
            "No action needed.")

    # ---------------- verdict ----------------
    fails = [f for f in findings if f["status"] == "FAIL"]
    warns = [f for f in findings if f["status"] == "WARNING"]
    score = len(fails) * 2 + len(warns)

    critical_names = {
        ("MitM", "HTTPS enforced"), ("MitM", "Redirect safety"),
        ("SQLi", "DB error exposure"),
        ("Malware", "Suspicious scripts"), ("Malware", "Hidden iframes"),
        ("Phishing", "Login-form safety"), ("Phishing", "Trust basics (HTTPS)"),
        ("DoS", "Response time"),
    }
    critical = [f for f in fails if (f["category"], f["name"]) in critical_names]

    if critical or len(fails) >= 3 or score >= 8:
        verdict, level = "Critical", "critical"
    elif fails or warns:
        verdict, level = "Risky", "risky"
    else:
        verdict, level = "Safe", "safe"

    summary = {
        "target": url,
        "final_url": fetched["final_url"],
        "host": host,
        "status_code": fetched["status_code"],
        "response_time_s": round(rt, 2),
        "server": _get_header(headers, "Server") or "unknown",
        "content_kb": round(size / 1024, 1),
        "redirect_chain": fetched["redirect_chain"],
        "tls": tls,
        "verdict": verdict,
        "level": level,
        "score": score,
        "fails": len(fails),
        "warnings": len(warns),
        "passes": len(findings) - len(fails) - len(warns),
        "findings": findings,
        "note": "Passive checks only (1 GET + TLS/DNS probes). No payloads, no login bypass, no DoS sent.",
    }
    return summary


def _error_report(url, message: str) -> dict:
    return {
        "target": url, "final_url": url, "host": urlparse(url).hostname or url,
        "status_code": None, "response_time_s": None, "server": "unknown",
        "content_kb": 0, "redirect_chain": [], "tls": {},
        "verdict": "Error", "level": "error", "score": 0,
        "fails": 0, "warnings": 0, "passes": 0,
        "findings": [{"category": "General", "name": "Fetch", "status": "FAIL",
                      "detail": message, "fix": "Check the URL is a live deployed link (not a repo link)."}],
        "note": "Scan did not complete.",
    }


if __name__ == "__main__":
    import json
    import sys
    if len(sys.argv) < 2:
        print("Usage: python scanner.py https://my-app.vercel.app")
        sys.exit(1)
    try:
        report = scan_url(sys.argv[1])
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(2)

    def _safe(s):
        # Windows consoles (cp1252) can't print arrows/em-dashes; strip to ascii-safe
        try:
            return str(s).encode("ascii", "replace").decode("ascii")
        except Exception:
            return str(s)

    print(_safe(f"\nTarget : {report['target']}"))
    print(_safe(f"Final  : {report.get('final_url')}"))
    print(_safe(f"Verdict: {report['verdict']} "
          f"({report['fails']} FAIL, {report['warnings']} WARN, {report['passes']} PASS)\n"))
    for f in report["findings"]:
        mark = {"PASS": "[PASS]", "WARNING": "[WARN]", "FAIL": "[FAIL]"}.get(f["status"], f["status"])
        print(_safe(f"{mark} [{f['category']}] {f['name']}: {f['detail']}"))
        if f["status"] != "PASS":
            print(_safe(f"       Fix: {f['fix']}"))
    if len(sys.argv) > 2 and sys.argv[2] == "--json":
        print(json.dumps(report, indent=2, default=str))
