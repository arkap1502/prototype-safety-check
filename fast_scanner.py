"""
High-efficiency URL scanner for Prototype Safety Check.

Why it's faster than scanner.scan_url:
  1. Connection reuse - one shared requests.Session with pooled HTTPAdapter
     (no new TCP/TLS handshake per probe).
  2. Parallel I/O - after the single page GET, the 4 independent network
     probes (http->https redirect check, TLS handshake, SPF TXT, DMARC TXT)
     run concurrently in a ThreadPoolExecutor instead of sequentially.
     Sequential:  T_fetch + T_redir + T_tls + T_spf + T_dmarc
     Fast:        T_fetch + max(T_redir, T_tls, T_spf, T_dmarc)
  3. Bulk mode - scan_urls() scans N URLs concurrently with a worker pool.
  4. Short TTL cache - repeat scans of the same URL within 5 min return
     instantly without any network I/O.

Still passive only: 1 GET per URL + safe header/TLS/DNS probes. No payloads.
Only scan URLs you own or have permission to test.
"""
import re
import ssl
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, parse_qsl, urljoin

import requests
from requests.adapters import HTTPAdapter

from scanner import (
    normalize_url,
    _get_header,
    _LinkParser,
    _error_report,
    DB_ERROR_SIGNATURES,
    UNSAFE_JS_PATTERNS,
    MALWARE_JS_PATTERNS,
    SUSPICIOUS_TLDS,
    BRAND_KEYWORDS,
    OFFICIAL_BRAND_DOMAINS,
)

UA = "PrototypeSafetyCheck/1.1-fast (+passive security scan; owner-permission only)"

# ---- shared session (connection pooling) ----
_SESSION = None


def get_session():
    """Singleton Session with pooled connections. Thread-safe for GET use."""
    global _SESSION
    if _SESSION is None:
        s = requests.Session()
        adapter = HTTPAdapter(pool_connections=20, pool_maxsize=20, max_retries=1)
        s.mount("http://", adapter)
        s.mount("https://", adapter)
        s.headers.update({"User-Agent": UA})
        _SESSION = s
    return _SESSION


# ---- individual probes (each is one network round-trip) ----

def _probe_fetch(url, timeout=12):
    t0 = time.time()
    resp = get_session().get(
        url, timeout=timeout, allow_redirects=True,
        headers={"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
    )
    elapsed = time.time() - t0
    redirect_chain = [f"{h.status_code} {h.url}" for h in resp.history] + [f"{resp.status_code} {resp.url}"]
    downgrade = False
    prev_https = urlparse(url).scheme == "https"
    for h in list(resp.history) + [resp]:
        scheme = urlparse(h.url).scheme
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


def _probe_http_redirect(parsed, timeout=6):
    """Best-effort: does http://host redirect to https? Returns True/False/None."""
    if parsed.scheme != "https":
        return None
    host = parsed.hostname or ""
    path = parsed.path or "/"
    try:
        r = get_session().get(
            f"http://{host}{path}", timeout=timeout, allow_redirects=False,
        )
        loc = r.headers.get("Location", "")
        if r.status_code in (301, 302, 307, 308) and loc.startswith("https://"):
            return True
        return False
    except Exception:
        return None


def _probe_tls(hostname, port=443, timeout=6):
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


def _probe_txt(name, timeout=6):
    try:
        r = get_session().get(
            "https://dns.google/resolve",
            params={"name": name, "type": "TXT"},
            timeout=timeout,
        )
        out = []
        for ans in r.json().get("Answer", []) or []:
            d = ans.get("data", "")
            if d:
                out.append(d.strip('"'))
        return out
    except Exception:
        return []


# ---- tiny TTL cache ----

_CACHE = {}  # url -> (timestamp, report)
CACHE_TTL = 300  # seconds


def _cache_get(url):
    item = _CACHE.get(url)
    if item and (time.time() - item[0]) < CACHE_TTL:
        rep = dict(item[1])
        rep["cached"] = True
        return rep
    return None


def _cache_put(url, report):
    if len(_CACHE) > 200:  # simple eviction
        _CACHE.pop(next(iter(_CACHE)))
    _CACHE[url] = (time.time(), report)


def clear_cache():
    _CACHE.clear()


# ---- fast single-URL scan ----

def fast_scan_url(raw_url: str, timeout=12, use_cache=True) -> dict:
    """High-efficiency passive scan of one URL. Same report shape as scan_url
    plus extra keys: engine='fast', scan_time_s, cached."""
    t_start = time.time()
    url = normalize_url(raw_url)

    if use_cache:
        hit = _cache_get(url)
        if hit is not None:
            hit["scan_time_s"] = round(time.time() - t_start, 2)
            return hit

    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    query_params = parse_qsl(parsed.query, keep_blank_values=True)

    try:
        fetched = _probe_fetch(url, timeout=timeout)
    except requests.exceptions.SSLError as e:
        return _error_report(url, f"TLS/SSL error: weak cert or insecure TLS. {str(e)[:200]}")
    except requests.exceptions.ConnectionError as e:
        return _error_report(url, f"Could not connect to {host}. Is the deployment live? ({str(e)[:150]})")
    except requests.exceptions.Timeout:
        return _error_report(url, f"Connection to {host} timed out after {timeout}s.")
    except ValueError as e:
        return _error_report(raw_url, str(e))
    except Exception as e:  # noqa: BLE001
        return _error_report(url, f"Fetch failed: {str(e)[:200]}")

    is_https = urlparse(fetched["final_url"]).scheme == "https"
    root = ".".join(host.split(".")[-2:]) if "." in host else host

    # --- run the 4 independent probes CONCURRENTLY (the whole speedup) ---
    redir, tls, spf, dmarc = None, None, [], []
    with ThreadPoolExecutor(max_workers=4) as ex:
        f_redir = ex.submit(_probe_http_redirect, parsed)
        f_tls = ex.submit(_probe_tls, host) if is_https else None
        f_spf = ex.submit(_probe_txt, root)
        f_dmarc = ex.submit(_probe_txt, f"_dmarc.{root}")
        redir = f_redir.result()
        tls = f_tls.result() if f_tls else {"version": None, "cipher": None, "error": "skipped (HTTP)"}
        spf = f_spf.result()
        dmarc = f_dmarc.result()

    resp_body = fetched["body"]
    headers = fetched["headers"]
    body_low = resp_body.lower()

    parser = _LinkParser(base_url=fetched["final_url"])
    try:
        parser.feed(resp_body[:500_000])
    except Exception:
        pass

    findings = []

    def add(category, name, status, detail, fix):
        findings.append({
            "category": category, "name": name, "status": status,
            "detail": detail, "fix": fix,
        })

    # ---------------- MitM ----------------
    if not is_https and parsed.scheme == "http":
        add("MitM", "HTTPS enforced", "FAIL",
            f"Site is served over plain HTTP ({fetched['final_url']}). Traffic can be intercepted.",
            "Deploy with HTTPS (Vercel/Netlify/Render give free TLS). Redirect all HTTP to HTTPS.")
    else:
        if redir is True:
            add("MitM", "HTTPS enforced", "PASS", "HTTP redirects to HTTPS.", "Keep the redirect + enable HSTS.")
        elif redir is False:
            add("MitM", "HTTPS enforced", "WARNING",
                "HTTPS works but plain-HTTP did not redirect to HTTPS in our probe.",
                "Add a 301 redirect from http:// to https:// on your host.")
        else:
            add("MitM", "HTTPS enforced", "PASS", "Final URL is HTTPS.", "Add HSTS + HTTP->HTTPS redirect.")

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

    insecure_cookies = [c.name for c in fetched["cookies"] if is_https and not c.secure]
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
            "Redirect chain downgrades HTTPS -> HTTP.",
            "Fix redirects so every hop stays on HTTPS.")
    else:
        add("MitM", "Redirect safety", "PASS",
            "No HTTPS->HTTP downgrade in redirect chain.", "No action needed.")

    # ---------------- XSS ----------------
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

    reflected = [v for _, v in query_params if v and len(v) >= 3 and v in resp_body]
    if reflected:
        add("XSS", "Reflected input", "WARNING",
            f"Query value(s) reflected verbatim in HTML (e.g. {reflected[0][:40]}). Test with benign text; ensure output-encoding.",
            "HTML-escape all user input on render; prefer textContent over innerHTML; keep CSP.")
    else:
        add("XSS", "Reflected input", "PASS",
            "No verbatim reflection of query values detected (passive check only).",
            "Still escape all user input; keep CSP.")

    sink_hits = set()
    for s in parser.scripts:
        if not s["inline"]:
            continue
        for pat, label in UNSAFE_JS_PATTERNS:
            if re.search(pat, s["inline"]):
                sink_hits.add(label)
    sink_hits = sorted(sink_hits)
    if sink_hits:
        add("XSS", "Unsafe JS sinks", "WARNING",
            f"Found: {'; '.join(sink_hits[:4])}.",
            "Avoid innerHTML/eval/document.write with user data. Use textContent, DOMPurify, framework escaping.")
    else:
        add("XSS", "Unsafe JS sinks", "PASS", "No obvious innerHTML/eval/document.write sinks in inline JS.", "No action needed.")

    # ---------------- SQLi (passive only) ----------------
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

    risky_sql_js = re.search(r"(SELECT|INSERT|UPDATE|DELETE)\b.{0,80}(\+|\$\{|`)", resp_body, re.I)
    if risky_sql_js:
        add("SQLi", "Client-side query hints", "WARNING",
            "JS/HTML hints at string-built SQL or URL-built queries.",
            "Never build SQL client-side; move queries server-side with bound parameters.")
    else:
        add("SQLi", "Client-side query hints", "PASS", "No obvious client-built SQL patterns.", "No action needed.")

    # ---------------- Malware ----------------
    mal_hits = set()
    for s in parser.scripts:
        code = s["inline"] or ""
        for pat, label in MALWARE_JS_PATTERNS:
            if re.search(pat, code, re.I | re.S):
                mal_hits.add(label)
        if code and len(code) > 8000 and len(re.findall(r"[A-Za-z0-9+/=]{200,}", code)) > 3:
            mal_hits.add("large base64-like blobs in inline JS")
    mal_hits = sorted(mal_hits)
    hidden_iframes = [i for i in parser.iframes
                      if any(k in str(i["attrs"]).lower() for k in ('width="0"', 'height="0"', "display:none", "visibility:hidden"))]
    if mal_hits:
        add("Malware", "Suspicious scripts", "FAIL",
            f"Found: {'; '.join(list(mal_hits)[:4])}. Verify each script is yours.",
            "Remove unknown scripts; pin deps; use SRI (integrity=) + CSP; rescan.")
    else:
        add("Malware", "Suspicious scripts", "PASS", "No classic obfuscation/forced-redirect patterns.", "Keep deps pinned + CSP.")

    if hidden_iframes or ("display:none" in body_low and "<iframe" in body_low):
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

    # ---------------- Phishing ----------------
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

    has_spf = any("v=spf1" in s for s in spf)
    has_dmarc = any("DMARC" in s or "v=DMARC" in s for s in dmarc)
    if not has_spf or not has_dmarc:
        missing_mail = [k for k, v in [("SPF", has_spf), ("DMARC", has_dmarc)] if not v]
        add("Phishing", "Email-auth hints", "WARNING",
            f"No {'/'.join(missing_mail)} record visible for {root} (via DNS-over-HTTPS).",
            "If you send mail from this domain, publish SPF + DKIM + DMARC to resist spoofing.")
    else:
        add("Phishing", "Email-auth hints", "PASS", f"SPF+DMARC visible for {root}.", "No action needed.")

    # ---------------- DoS ----------------
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

    size = len(resp_body.encode("utf-8", "ignore"))
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

    # ---------------- verdict (same engine as scanner.py) ----------------
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
        "note": "Passive checks only (1 GET + parallel TLS/DNS probes). No payloads, no login bypass, no DoS sent.",
        "engine": "fast",
        "scan_time_s": round(time.time() - t_start, 2),
        "cached": False,
    }
    if use_cache:
        _cache_put(url, summary)
    return summary


# ---- bulk concurrent scan ----

def scan_urls(raw_urls, max_workers=8, timeout=12, use_cache=True) -> dict:
    """Scan many URLs concurrently. Returns {"results": [...], "summary": {...}}.

    - Dedupes + caps at 20 URLs per batch (abuse guard).
    - Each URL gets the full fast_scan_url report.
    - Errors per-URL never abort the batch.
    """
    seen, urls = set(), []
    for u in raw_urls or []:
        u = (u or "").strip()
        if u and u not in seen:
            seen.add(u)
            urls.append(u)
    urls = urls[:20]
    if not urls:
        raise ValueError("No URLs given. Pass one URL per line.")

    t0 = time.time()
    reports = [None] * len(urls)
    workers = max(1, min(max_workers, len(urls)))
    with ThreadPoolExecutor(max_workers=workers) as ex:
        fut_to_idx = {ex.submit(fast_scan_url, u, timeout, use_cache): i
                      for i, u in enumerate(urls)}
        for fut in as_completed(fut_to_idx):
            i = fut_to_idx[fut]
            try:
                reports[i] = fut.result()
            except ValueError as e:
                reports[i] = _error_report(urls[i], str(e))
            except Exception as e:  # noqa: BLE001 - per-URL isolation
                reports[i] = _error_report(urls[i], f"Scan failed: {str(e)[:200]}")

    counts = {"Safe": 0, "Risky": 0, "Critical": 0, "Error": 0}
    for r in reports:
        counts[r.get("verdict", "Error")] = counts.get(r.get("verdict", "Error"), 0) + 1

    return {
        "results": reports,
        "summary": {
            "total": len(reports),
            "counts": counts,
            "total_time_s": round(time.time() - t0, 2),
            "engine": "fast-bulk",
        },
    }


if __name__ == "__main__":
    import json
    import sys
    if len(sys.argv) < 2:
        print("Usage: python fast_scanner.py https://url1 [https://url2 ...] [--json]")
        sys.exit(1)
    args = [a for a in sys.argv[1:] if a != "--json"]
    as_json = "--json" in sys.argv
    if len(args) == 1:
        rep = fast_scan_url(args[0])
        print(f"Target : {rep['target']}  |  Verdict: {rep['verdict']} "
              f"({rep['fails']} FAIL, {rep['warnings']} WARN, {rep['passes']} PASS) "
              f"in {rep.get('scan_time_s')}s [fast engine]")
        if as_json:
            print(json.dumps(rep, indent=2, default=str))
    else:
        batch = scan_urls(args)
        for r in batch["results"]:
            print(f"{r.get('verdict', '?'):8}  {r.get('target')}  "
                  f"({r.get('fails', 0)}F/{r.get('warnings', 0)}W in {r.get('scan_time_s', '?')}s)")
        print(f"\nBatch: {batch['summary']}")
        if as_json:
            print(json.dumps(batch, indent=2, default=str))
